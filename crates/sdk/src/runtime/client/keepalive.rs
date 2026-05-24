//! Keepalive sender task (client side).
//!
//! Sends encrypted keepalive packets at a fixed interval.
//!
//! ## Zero-allocation hot path
//!
//! ```text
//! timer tick
//!   → noise_encrypt(DataClientBody::KeepAlive) — CIPHER_POOL, no alloc after warmup
//!   → encode_into_slice                         — stack encode_buf, no alloc
//!   → transport.send                            — direct UDP write
//! ```

use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::warn;

use crate::gateway::transport::ClientTransport;
use crate::protocol::{DataClientBody, Packet, SessionId};
use crate::runtime::client::{AWAIT_STATE_DELAY, MAX_PACKET_SIZE};
use crate::runtime::crypto::noise_encrypt;
use crate::runtime::error::RuntimeError;
use crate::runtime::state::RuntimeState;
use crate::time::micros_since_start;

pub(super) async fn keepalive_sender(
    state_tx: watch::Sender<RuntimeState>,
    transport: Arc<dyn ClientTransport>,
    duration: Duration,
) {
    let mut state_rx = state_tx.subscribe();
    let mut encode_buf = [0u8; MAX_PACKET_SIZE + 64];
    let mut keepalive_timer = tokio::time::interval(duration);
    let mut state_wait_timer = tokio::time::interval(AWAIT_STATE_DELAY);

    let mut is_connected = false;
    let mut sid = SessionId::default();
    let mut transport_state = None;

    loop {
        // Check for state changes without blocking.
        match state_rx.has_changed() {
            Ok(true) => {
                state_rx.mark_unchanged();
                match state_rx.borrow().deref() {
                    RuntimeState::Error(_) => break,
                    RuntimeState::Connecting => {
                        is_connected = false;
                        transport_state = None;
                    }
                    RuntimeState::Connected((payload, ts)) => {
                        sid = payload.sid;
                        transport_state = Some(ts.clone());
                        is_connected = true;
                    }
                    _ => {}
                }
            }
            Err(_) => break,
            Ok(false) => {}
        }

        if !is_connected {
            state_wait_timer.tick().await;
            continue;
        }

        tokio::select! {
            _ = state_rx.changed() => {
                state_rx.mark_changed(); // re-process on next loop iteration
            }
            _ = keepalive_timer.tick() => {
                let Some(ref s) = transport_state else { continue; };
                match noise_encrypt(&DataClientBody::KeepAlive(micros_since_start()), s) {
                    Err(e) => {
                        if state_tx.send(RuntimeState::Error(
                            RuntimeError::Unexpected(format!("failed to encrypt keepalive: {}", e))
                        )).is_err() { break; }
                    }
                    Ok(encrypted) => {
                        let pkt = Packet::DataClient { sid, encrypted };
                        match bincode::encode_into_slice(
                            &pkt,
                            &mut encode_buf,
                            bincode::config::standard(),
                        ) {
                            Err(e) => warn!("keepalive encode failed: {}", e),
                            Ok(n) => {
                                if let Err(e) = transport.send(&encode_buf[..n]).await {
                                    warn!("keepalive send error, reconnecting: {}", e);
                                    if state_tx.send(RuntimeState::Connecting).is_err() { break; }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
