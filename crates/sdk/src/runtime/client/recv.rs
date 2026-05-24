//! Merged UDP-receive + decrypt + network-send task (client side).
//!
//! Replaces `transport_receiver` + `data_udp_executor` + `network_sender`.
//!
//! ## Zero-allocation hot path
//!
//! ```text
//! transport.recv → stack buffer (no alloc)
//!   → PacketRef::from_bytes      — borrows ciphertext from stack (no alloc)
//!   → noise_decrypt_data_server  — decrypts into PLAIN_BUF, copies payload
//!                                   into task-local BufPool (no alloc after warmup)
//!   → network.send(&bytes)       — writes directly (no intermediate channel)
//! ```

use std::ops::Deref;
use std::sync::Arc;

use tokio::sync::watch;
use tracing::{info, warn};

use crate::gateway::{network::Network, transport::ClientTransport};
use crate::protocol::PacketRef;
use crate::runtime::buf_pool::BufPool;
use crate::runtime::client::{AWAIT_STATE_DELAY, MAX_PACKET_SIZE};
use crate::runtime::crypto::{DataServerAction, noise_decrypt_data_server};
use crate::runtime::state::{ClientSession, RuntimeState};
use crate::time::{format_duration_millis, micros_since_start};

pub(super) async fn recv_decrypt_forward<T: ClientTransport, N: Network>(
    state_tx: watch::Sender<RuntimeState>,
    transport: Arc<T>,
    network: Arc<N>,
    tun_mtu: u16,
) {
    let mut state_rx = state_tx.subscribe();
    let mut buf = [0u8; MAX_PACKET_SIZE];
    let mut net_pool = BufPool::new(tun_mtu as usize + 32);
    let mut state_wait_timer = tokio::time::interval(AWAIT_STATE_DELAY);

    let mut is_connected = false;
    let mut transport_state: Option<ClientSession> = None;

    loop {
        // Pause receiving until connected to avoid processing stale data.
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
                    RuntimeState::Connected((_, session)) => {
                        transport_state = Some(session.clone());
                        is_connected = true;
                    }
                    _ => {}
                }
            }
            result = transport.recv(&mut buf) => match result {
                Err(e) => {
                    warn!("transport recv error, reconnecting: {}", e);
                    if state_tx.send(RuntimeState::Connecting).is_err() { break; }
                }
                Ok(n) => {
                    if n == 0 || n >= buf.len() {
                        warn!("dropping transport packet (size {})", n);
                        continue;
                    }
                    let Some(ref session) = transport_state else {
                        warn!("received data before connected state, dropping");
                        continue;
                    };
                    match PacketRef::from_bytes(&buf[..n]) {
                        None => warn!("failed to parse transport packet"),
                        Some(PacketRef::DataServer { nonce, ciphertext }) => {
                            let nonce_ok = session.recv_window
                                .lock()
                                .unwrap()
                                .check_and_update(nonce);
                            if !nonce_ok {
                                warn!("replay/stale nonce {} from server", nonce);
                                continue;
                            }
                            match noise_decrypt_data_server(ciphertext, &session.noise, &mut net_pool, nonce) {
                                Err(e) => warn!("decrypt failed: {}", e),
                                Ok(DataServerAction::Forward(bytes)) => {
                                    if let Err(e) = network.send(&bytes).await {
                                        warn!("network send failed: {}", e);
                                    }
                                }
                                Ok(DataServerAction::KeepAlive(ts)) => {
                                    info!("keepalive rtt: {}", format_duration_millis(ts, micros_since_start()));
                                }
                                Ok(DataServerAction::Disconnect(code)) => {
                                    warn!("server disconnect code {}", code);
                                    if state_tx.send(RuntimeState::Connecting).is_err() { break; }
                                }
                            }
                        }
                        Some(PacketRef::HandshakeResponder(data)) => {
                            // Connector handles handshake separately; here we just drop it.
                            let _ = data;
                        }
                        Some(_) => warn!("unexpected packet variant on client"),
                    }
                }
            }
        }
    }
}
