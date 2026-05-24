//! Merged network-read + encrypt + UDP-send task (client side).
//!
//! Replaces `network_receiver` + `data_tun_executor` + `transport_sender`.
//!
//! ## Zero-allocation hot path
//!
//! ```text
//! network.recv → buf (stack)
//!   → write_ip_packet_plain  — PLAIN_BUF (thread-local), Copy 1
//!   → noise write_message    — AEAD encrypt into encode_buf (stack), Copy 2
//!   → transport.send         — direct UDP write, no intermediate buffers
//! ```

use std::ops::Deref;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use tokio::sync::watch;
use tracing::warn;

use crate::gateway::{network::Network, transport::ClientTransport};
use crate::protocol::SessionId;
use crate::runtime::client::{AWAIT_STATE_DELAY, MAX_PACKET_SIZE};
use crate::runtime::crypto::encode_data_client_packet;
use crate::runtime::error::RuntimeError;
use crate::runtime::state::{ClientSession, RuntimeState};

pub(super) async fn tun_encrypt_forward<T: ClientTransport, N: Network>(
    state_tx: watch::Sender<RuntimeState>,
    network: Arc<N>,
    transport: Arc<T>,
) {
    let mut state_rx = state_tx.subscribe();
    let mut buf = [0u8; MAX_PACKET_SIZE];
    let mut encode_buf = [0u8; MAX_PACKET_SIZE + 64];
    let mut state_wait_timer = tokio::time::interval(AWAIT_STATE_DELAY);

    let mut is_connected = false;
    let mut sid = SessionId::default();
    let mut transport_state: Option<ClientSession> = None;

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
                    RuntimeState::Connected((payload, session)) => {
                        sid = payload.sid;
                        transport_state = Some(session.clone());
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
                    let Some(ref session) = transport_state else {
                        warn!("received tun packet before connected state, dropping");
                        continue;
                    };
                    let nonce = session.send_nonce.fetch_add(1, Ordering::Relaxed);
                    match encode_data_client_packet(&buf[..n], sid, &session.noise, nonce, &mut encode_buf) {
                        Err(e) => {
                            if state_tx.send(RuntimeState::Error(
                                RuntimeError::Unexpected(format!("failed to encrypt data: {}", e))
                            )).is_err() { break; }
                        }
                        Ok(total) => {
                            if let Err(e) = transport.send(&encode_buf[..total]).await {
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
