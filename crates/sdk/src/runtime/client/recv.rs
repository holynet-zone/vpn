//! Merged UDP-receive + decrypt + network-send task (client side).
//!
//! ## Batched, zero-allocation hot path
//!
//! ```text
//! transport.recv       → first UDP datagram (awaited)
//!   then drain: transport.try_recv → all already-queued datagrams (no wait)
//!   for each DataServer datagram:
//!     → PacketRef::from_bytes            — borrows ciphertext (no alloc)
//!     → noise_decrypt_data_server_into   — decrypts into the next batch buffer
//!   → network.send_multiple             — one GRO-merged TUN write for the batch
//! ```

use std::ops::Deref;
use std::sync::Arc;

use tokio::sync::watch;
use tracing::{info, warn};

use crate::gateway::{
    network::{GRO_BUF_CAP, GroState, Network, TUN_BATCH_SIZE, TUN_SEND_OFFSET},
    transport::ClientTransport,
};
use crate::protocol::PacketRef;
use crate::runtime::client::{AWAIT_STATE_DELAY, MAX_PACKET_SIZE};
use crate::runtime::crypto::{DataServerActionRef, noise_decrypt_data_server_into};
use crate::runtime::state::{ClientSession, RuntimeState};
use crate::time::{format_duration_millis, micros_since_start};

pub(super) async fn recv_decrypt_forward<T: ClientTransport, N: Network>(
    state_tx: watch::Sender<RuntimeState>,
    transport: Arc<T>,
    network: Arc<N>,
) {
    let mut state_rx = state_tx.subscribe();
    let mut buf = [0u8; MAX_PACKET_SIZE];
    // Batch of decrypted IP packets awaiting one GRO-merged TUN write.
    let seg = network.mtu() as usize + 128 + TUN_SEND_OFFSET;
    // Pre-reserve a full GSO super-frame per entry so tun-rs' GRO merge coalesces
    // in place without reallocating (see GRO_BUF_CAP).
    let mut tun_bufs: Vec<Vec<u8>> = (0..TUN_BATCH_SIZE)
        .map(|_| {
            let mut v = Vec::with_capacity(GRO_BUF_CAP);
            v.resize(seg, 0);
            v
        })
        .collect();
    let mut gro = GroState::new();
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

        // Await either a state change or the first datagram.
        let mut n = tokio::select! {
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
                continue;
            }
            result = transport.recv(&mut buf) => match result {
                Err(e) => {
                    warn!("transport recv error, reconnecting: {}", e);
                    if state_tx.send(RuntimeState::Connecting).is_err() { break; }
                    continue;
                }
                Ok(n) => n,
            }
        };

        let Some(session) = transport_state.clone() else {
            warn!("received data before connected state, dropping");
            continue;
        };

        let mut batch_len = 0usize;
        let mut reconnect = false;

        // Drain loop: first datagram, then any others already queued (no wait).
        loop {
            if n == 0 || n >= buf.len() {
                warn!("dropping transport packet (size {})", n);
            } else {
                match PacketRef::from_bytes(&buf[..n]) {
                    None => warn!("failed to parse transport packet"),
                    Some(PacketRef::DataServer { nonce, ciphertext }) => {
                        let nonce_ok = session
                            .recv_window
                            .lock()
                            .unwrap()
                            .check_and_update(nonce);
                        if !nonce_ok {
                            warn!("replay/stale nonce {} from server", nonce);
                        } else {
                            tun_bufs[batch_len].resize(seg, 0);
                            // Base ptr captured before decrypt (resize never reallocs) to
                            // locate the IP packet in the frame without re-borrowing.
                            let base = tun_bufs[batch_len].as_ptr() as usize;
                            let dec = noise_decrypt_data_server_into(
                                ciphertext,
                                &session.noise,
                                &mut tun_bufs[batch_len][TUN_SEND_OFFSET..],
                                nonce,
                            );
                            match dec {
                                Err(e) => warn!("decrypt failed: {}", e),
                                Ok(DataServerActionRef::Forward(packet)) => {
                                    // `packet` points at the IP packet inside the decrypted
                                    // frame, past the variant+len header — shift it to
                                    // TUN_SEND_OFFSET for the single-offset send_multiple.
                                    let start = packet.as_ptr() as usize - base;
                                    let len = packet.len();
                                    tun_bufs[batch_len].copy_within(start..start + len, TUN_SEND_OFFSET);
                                    tun_bufs[batch_len].truncate(TUN_SEND_OFFSET + len);
                                    batch_len += 1;
                                }
                                Ok(DataServerActionRef::KeepAlive(ts)) => {
                                    info!("keepalive rtt: {}", format_duration_millis(ts, micros_since_start()));
                                }
                                Ok(DataServerActionRef::Disconnect(code)) => {
                                    warn!("server disconnect code {}", code);
                                    reconnect = true;
                                }
                            }
                        }
                    }
                    Some(PacketRef::HandshakeResponder(data)) => {
                        // Connector handles handshake separately; drop it here.
                        let _ = data;
                    }
                    Some(_) => warn!("unexpected packet variant on client"),
                }
            }

            if reconnect || batch_len >= TUN_BATCH_SIZE {
                break;
            }
            match transport.try_recv(&mut buf) {
                Ok(n2) => n = n2,
                Err(_) => break,
            }
        }

        // Flush decrypted packets received so far, even if a disconnect followed.
        if batch_len > 0
            && let Err(e) = network
                .send_multiple(&mut gro, &mut tun_bufs[..batch_len], TUN_SEND_OFFSET)
                .await
        {
            warn!("network send failed: {}", e);
        }

        if reconnect && state_tx.send(RuntimeState::Connecting).is_err() {
            break;
        }
    }
}
