//! Merged network-read + encrypt + UDP-send task (client side).
//!
//! Replaces `network_receiver` + `data_tun_executor` + `transport_sender`.
//!
//! ## Zero-allocation hot path
//!
//! ```text
//! network.recv → stack buffer (no alloc)
//!   → BufPool::copy_to_bytes   — no alloc after warmup
//!   → noise_encrypt             — CIPHER_POOL, no alloc after warmup
//!   → encode_into_slice         — stack encode_buf, no alloc
//!   → transport.send            — direct UDP write
//! ```

use std::ops::Deref;
use std::sync::Arc;

use tokio::sync::watch;
use tracing::warn;

use crate::gateway::{network::Network, transport::ClientTransport};
use crate::protocol::{DataClientBody, Packet, SessionId};
use crate::runtime::buf_pool::BufPool;
use crate::runtime::client::{AWAIT_STATE_DELAY, MAX_PACKET_SIZE};
use crate::runtime::crypto::noise_encrypt;
use crate::runtime::error::RuntimeError;
use crate::runtime::state::RuntimeState;

pub(super) async fn tun_encrypt_forward(
    state_tx: watch::Sender<RuntimeState>,
    network: Arc<dyn Network>,
    transport: Arc<dyn ClientTransport>,
) {
    let mut state_rx = state_tx.subscribe();
    let mut buf = [0u8; MAX_PACKET_SIZE];
    let mut encode_buf = [0u8; MAX_PACKET_SIZE + 64];
    let mut pool = BufPool::new(MAX_PACKET_SIZE);
    let mut state_wait_timer = tokio::time::interval(AWAIT_STATE_DELAY);

    let mut is_connected = false;
    let mut sid = SessionId::default();
    let mut transport_state = None;

    loop {
        // Pause reading until connected to avoid encrypting with stale state.
        if !is_connected {
            match state_rx.has_changed() {
                Ok(false) => {
                    state_wait_timer.tick().await;
                    continue;
                }
                Err(_) => break,
                Ok(true) => {}
            }
        }

        tokio::select! {
            _ = state_rx.changed() => {
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
            result = network.recv(&mut buf) => match result {
                Err(e) => {
                    let state = RuntimeState::Error(RuntimeError::IO(
                        format!("failed to receive network: {}", e)
                    ));
                    if state_tx.send(state).is_err() { break; }
                }
                Ok(n) => {
                    if n == 0 {
                        warn!("received network packet with 0 bytes, dropping");
                        continue;
                    }
                    if n >= buf.len() {
                        warn!("received network packet >= {} bytes, possible truncation", buf.len());
                        continue;
                    }
                    let Some(ref s) = transport_state else {
                        warn!("received tun packet before connected state, dropping");
                        continue;
                    };
                    // Copy raw IP packet into pool buffer (zero-alloc in steady state).
                    let packet_bytes = pool.copy_to_bytes(&buf[..n]);
                    match noise_encrypt(&DataClientBody::Packet(packet_bytes), s) {
                        Err(e) => {
                            if state_tx.send(RuntimeState::Error(
                                RuntimeError::Unexpected(format!("failed to encrypt data: {}", e))
                            )).is_err() { break; }
                        }
                        Ok(encrypted) => {
                            let pkt = Packet::DataClient { sid, encrypted };
                            match bincode::encode_into_slice(
                                &pkt,
                                &mut encode_buf,
                                bincode::config::standard(),
                            ) {
                                Err(e) => warn!("encode failed: {}", e),
                                Ok(n) => {
                                    if let Err(e) = transport.send(&encode_buf[..n]).await {
                                        warn!("transport send error, reconnecting: {}", e);
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
}
