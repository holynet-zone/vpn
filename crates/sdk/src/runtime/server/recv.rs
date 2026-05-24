//! Merged UDP-receive + decrypt + TUN-forward task (server side).
//!
//! Replaces the former `transport_listener` + `data_transport_executor` pair.
//!
//! ## Zero-allocation hot path
//!
//! ```text
//! UDP recv → stack buffer (no alloc)
//!   → PacketRef::from_bytes   — borrows ciphertext from stack (no alloc)
//!   → noise_decrypt_data_client — decrypts into PLAIN_BUF, copies payload
//!                                  into task-local BufPool (no alloc after warmup)
//!   → tun.send(&bytes)        — writes directly, no intermediate channel
//! ```
//!
//! Keepalive responses are encrypted and encoded inline using a task-local
//! `encode_buf` array (no heap allocation after the first iteration).

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use tokio::sync::{mpsc, watch};
use tracing::{debug, error, info, warn};
use tun_rs::AsyncDevice;

use super::session::{Session, Sessions};
use crate::gateway::transport::Transport;
use crate::protocol::{DataServerBody, EncryptedHandshake, Packet, PacketRef, SessionId};
use crate::runtime::buf_pool::BufPool;
use crate::runtime::crypto::{noise_decrypt_data_client, noise_encrypt, DataClientAction};
use crate::time::sec_since_start;

/// Combined receive → decrypt → forward task.
///
/// Reads encrypted UDP datagrams, decrypts them, and:
/// - **Data packets** → written directly to `tun`.
/// - **Keepalive** → response encrypted and sent back inline.
/// - **Handshakes** → forwarded to `handshake_tx` (rare, may allocate).
pub(super) async fn recv_decrypt_forward<T: Transport>(
    mut stop: watch::Receiver<bool>,
    transport: Arc<T>,
    tun: Arc<AsyncDevice>,
    sessions: Sessions,
    handshake_tx: mpsc::Sender<(EncryptedHandshake, SocketAddr)>,
    inf_sessions_timeout: bool,
    tun_mtu: u16,
) {
    let mut udp_buf = [0u8; 65536];
    let mut encode_buf = [0u8; 65600]; // for keepalive response encoding, reused in-place
    let mut tun_pool = BufPool::new(tun_mtu as usize + 32);
    // Per-task 1-entry session cache: eliminates DashMap lookup on every
    // packet when a single client dominates the worker's receive queue.
    let mut cached_session: Option<(SessionId, Arc<Session>)> = None;

    loop {
        tokio::select! {
            _ = stop.changed() => break,
            result = transport.recv_from(&mut udp_buf) => match result {
                Err(e) => warn!("transport recv error: {}", e),
                Ok((n, addr)) => {
                    if n == 0 || n >= udp_buf.len() {
                        warn!("dropping packet from {} (size {})", addr, n);
                        continue;
                    }
                    match PacketRef::from_bytes(&udp_buf[..n]) {
                        None => warn!("failed to parse packet from {}", addr),
                        Some(PacketRef::HandshakeInitial(data)) => {
                            // Handshakes are rare — allocation here is acceptable.
                            let hs = data.to_vec().into();
                            if let Err(e) = handshake_tx.send((hs, addr)).await {
                                error!("handshake_tx closed: {}", e);
                            }
                        }
                        Some(PacketRef::DataClient { sid, nonce, ciphertext }) => {
                            // Per-task session cache: on cache hit avoid DashMap entirely.
                            // On miss: one DashMap lookup then cache the Arc.
                            let session = match &cached_session {
                                Some((cached_sid, s)) if *cached_sid == sid => {
                                    if !inf_sessions_timeout {
                                        s.last_seen.store(sec_since_start(), Ordering::Relaxed);
                                    }
                                    s.clone()
                                }
                                _ => {
                                    let Some(s) = sessions.get_by_sid(&sid) else {
                                        warn!("[{}] data for unknown session {}", addr, sid);
                                        continue;
                                    };
                                    if !inf_sessions_timeout {
                                        s.last_seen.store(sec_since_start(), Ordering::Relaxed);
                                    }
                                    cached_session = Some((sid, s.clone()));
                                    s
                                }
                            };

                            // Replay window check under lock, before decryption.
                            let nonce_ok = session.recv_window
                                .lock()
                                .unwrap()
                                .check_and_update(nonce);
                            if !nonce_ok {
                                warn!("[{}] replay/stale nonce {} for sid {}", addr, nonce, sid);
                                continue;
                            }

                            match noise_decrypt_data_client(ciphertext, &session.state, &mut tun_pool, nonce) {
                                Err(e) => warn!("[{}] decrypt failed (sid {}): {}", addr, sid, e),
                                Ok(DataClientAction::Forward(bytes)) => {
                                    if session.sock_addr() != addr {
                                        debug!("[{}] addr changed for sid {}", addr, sid);
                                        session.set_sock_addr(addr);
                                    }
                                    if let Err(e) = tun.send(&bytes).await {
                                        error!("tun send error: {}", e);
                                    }
                                }
                                Ok(DataClientAction::KeepAlive(client_ts)) => {
                                    info!("[{}] keepalive from sid {}", addr, sid);
                                    if session.sock_addr() != addr {
                                        debug!("[{}] addr changed for sid {}", addr, sid);
                                        session.set_sock_addr(addr);
                                    }
                                    let send_nonce = session.send_nonce.fetch_add(1, Ordering::Relaxed);
                                    match noise_encrypt(&DataServerBody::KeepAlive(client_ts), &session.state, send_nonce) {
                                        Err(e) => error!("[{}] keepalive encrypt failed: {}", addr, e),
                                        Ok(encrypted) => {
                                            let pkt = Packet::DataServer { nonce: send_nonce, encrypted };
                                            match bincode::encode_into_slice(
                                                &pkt,
                                                &mut encode_buf,
                                                bincode::config::standard(),
                                            ) {
                                                Err(e) => error!("[{}] encode failed: {}", addr, e),
                                                Ok(n) => {
                                                    if let Err(e) = transport.send_to(&encode_buf[..n], &addr).await {
                                                        error!("[{}] keepalive send failed: {}", addr, e);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Some(_) => warn!("[{}] unexpected packet variant", addr),
                    }
                }
            }
        }
    }
    debug!("recv_decrypt_forward stopped");
}
