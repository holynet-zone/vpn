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

use tokio::sync::{mpsc, watch};
use tracing::{debug, error, info, warn};
use tun_rs::AsyncDevice;

use super::session::Sessions;
use crate::gateway::transport::Transport;
use crate::protocol::{EncryptedHandshake, PacketRef, Packet, DataServerBody};
use crate::runtime::buf_pool::BufPool;
use crate::runtime::crypto::{
    noise_decrypt_data_client, noise_encrypt, DataClientAction,
};

/// Combined receive → decrypt → forward task.
///
/// Reads encrypted UDP datagrams, decrypts them, and:
/// - **Data packets** → written directly to `tun`.
/// - **Keepalive** → response encrypted and sent back inline.
/// - **Handshakes** → forwarded to `handshake_tx` (rare, may allocate).
pub(super) async fn recv_decrypt_forward(
    mut stop: watch::Receiver<bool>,
    transport: Arc<dyn Transport>,
    tun: Arc<AsyncDevice>,
    sessions: Sessions,
    handshake_tx: mpsc::Sender<(EncryptedHandshake, SocketAddr)>,
    inf_sessions_timeout: bool,
) {
    let mut udp_buf = [0u8; 65536];
    let mut encode_buf = [0u8; 65600]; // for keepalive response encoding, reused in-place
    let mut tun_pool = BufPool::new(65536);

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
                        Some(PacketRef::DataClient { sid, ciphertext }) => {
                            let Some(session) = sessions.get_by_sid(&sid) else {
                                warn!("[{}] data for unknown session {}", addr, sid);
                                continue;
                            };

                            match noise_decrypt_data_client(ciphertext, &session.state, &mut tun_pool) {
                                Err(e) => warn!("[{}] decrypt failed (sid {}): {}", addr, sid, e),
                                Ok(DataClientAction::Forward(bytes)) => {
                                    if !inf_sessions_timeout { sessions.touch(sid); }
                                    if session.sock_addr() != addr {
                                        debug!("[{}] addr changed for sid {}", addr, sid);
                                        sessions.update_sock_addr(sid, addr);
                                    }
                                    if let Err(e) = tun.send(&bytes).await {
                                        error!("tun send error: {}", e);
                                    }
                                }
                                Ok(DataClientAction::KeepAlive(client_ts)) => {
                                    info!("[{}] keepalive from sid {}", addr, sid);
                                    if !inf_sessions_timeout { sessions.touch(sid); }
                                    if session.sock_addr() != addr {
                                        debug!("[{}] addr changed for sid {}", addr, sid);
                                        sessions.update_sock_addr(sid, addr);
                                    }
                                    match noise_encrypt(&DataServerBody::KeepAlive(client_ts), &session.state) {
                                        Err(e) => error!("[{}] keepalive encrypt failed: {}", addr, e),
                                        Ok(encrypted) => {
                                            let pkt = Packet::DataServer(encrypted);
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
