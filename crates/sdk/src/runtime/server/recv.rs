//! Merged UDP-receive + decrypt + TUN-forward task (server side).
//!
//! ## Batched, zero-allocation hot path
//!
//! ```text
//! transport.recv_from  → first UDP datagram (awaited)
//!   then drain: transport.try_recv_from → all already-queued datagrams (no wait)
//!   for each DataClient datagram:
//!     → PacketRef::from_bytes            — borrows ciphertext (no alloc)
//!     → noise_decrypt_data_client_into   — decrypts straight into the next
//!                                          batch buffer at TUN_SEND_OFFSET
//!   → network.send_multiple             — one GRO-merged TUN write for the batch
//! ```
//!
//! The drain never blocks (only pulls datagrams already in the socket buffer),
//! so a single-packet flow adds zero latency, while a bulk stream coalesces many
//! packets into one TUN write. Keepalives and handshakes are handled inline.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use tokio::sync::{mpsc, watch};
use tracing::{debug, error, info, warn};

use super::session::{Session, Sessions};
use crate::gateway::network::{GRO_BUF_CAP, GroState, Network, TUN_BATCH_SIZE, TUN_SEND_OFFSET};
use crate::gateway::transport::Transport;
use crate::protocol::{DataServerBody, EncryptedHandshake, PacketRef, SessionId};
use crate::runtime::crypto::{
    DataClientActionRef, encode_data_server_frame, noise_decrypt_data_client_into, noise_encrypt,
};
use crate::time::sec_since_start;

const LEASE_UNAVAILABLE: u8 = 1;

pub(super) fn lease_reply(sessions: &Sessions, session: &Session, sid: SessionId) -> DataServerBody {
    let ip = match session.holy_ip.get() {
        Some(ip) => Some(*ip),
        None => match sessions.next_holy_ip_sticky(&session.peer_pk) {
            Some(ip) if sessions.assign_holy_ip(&sid, ip) => Some(ip),
            _ => None,
        },
    };
    match ip {
        Some(ip) => DataServerBody::LeaseGrant(ip),
        None => DataServerBody::Disconnect(LEASE_UNAVAILABLE),
    }
}

/// Combined receive → decrypt → forward task.
///
/// Reads encrypted UDP datagrams, decrypts them, and:
/// - **Data packets** → batched and written to `network` via `send_multiple`.
/// - **Keepalive** → response encrypted and sent back inline.
/// - **Handshakes** → forwarded to `handshake_tx` (rare, may allocate).
pub(super) async fn recv_decrypt_forward<T: Transport, N: Network>(
    mut stop: watch::Receiver<bool>,
    transport: Arc<T>,
    network: Arc<N>,
    sessions: Sessions,
    handshake_tx: mpsc::Sender<(EncryptedHandshake, SocketAddr)>,
    inf_sessions_timeout: bool,
) {
    let mut udp_buf = [0u8; 65536];
    let mut encode_buf = [0u8; 65600]; // for keepalive response encoding, reused in-place
    // Batch of decrypted IP packets awaiting one GRO-merged TUN write. Each buffer
    // holds its packet at [TUN_SEND_OFFSET..]; reused every iteration.
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
    // Per-task 1-entry session cache: eliminates DashMap lookup on every packet
    // when a single client dominates the worker's receive queue.
    let mut cached_session: Option<(SessionId, Arc<Session>)> = None;

    loop {
        // Await the first datagram (or a stop signal).
        let (mut n, mut addr) = tokio::select! {
            _ = stop.changed() => break,
            result = transport.recv_from(&mut udp_buf) => match result {
                Err(e) => { warn!("transport recv error: {}", e); continue; }
                Ok(v) => v,
            }
        };

        // Number of decrypted IP packets queued for the batched TUN write.
        let mut batch_len = 0usize;

        // Drain loop: process the first datagram, then any others already queued.
        loop {
            if n == 0 || n >= udp_buf.len() {
                warn!("dropping packet from {} (size {})", addr, n);
            } else {
                match PacketRef::from_bytes(&udp_buf[..n]) {
                    None => warn!("failed to parse packet from {}", addr),

                    Some(PacketRef::HandshakeInitial(hs_data)) => {
                        let hs = hs_data.to_vec().into();
                        if let Err(e) = handshake_tx.send((hs, addr)).await {
                            error!("handshake_tx closed: {}", e);
                        }
                    }

                    Some(PacketRef::DataClient {
                        sid,
                        nonce,
                        ciphertext,
                    }) => {
                        // Per-task session cache: on hit avoid DashMap entirely.
                        let session = match &cached_session {
                            Some((cs, s)) if *cs == sid => {
                                if !inf_sessions_timeout {
                                    s.last_seen.store(sec_since_start(), Ordering::Relaxed);
                                }
                                Some(s.clone())
                            }
                            _ => match sessions.get_by_sid(&sid) {
                                Some(s) => {
                                    if !inf_sessions_timeout {
                                        s.last_seen.store(sec_since_start(), Ordering::Relaxed);
                                    }
                                    cached_session = Some((sid, s.clone()));
                                    Some(s)
                                }
                                None => {
                                    warn!("[{}] data for unknown session {}", addr, sid);
                                    None
                                }
                            },
                        };

                        if let Some(session) = session {
                            // Replay window check under lock, before decryption.
                            let nonce_ok =
                                session.recv_window.lock().unwrap().check_and_update(nonce);
                            if !nonce_ok {
                                warn!("[{}] replay/stale nonce {} for sid {}", addr, nonce, sid);
                            } else {
                                // Decrypt straight into the next batch buffer, at the
                                // reserved offset so send_multiple can prepend the
                                // virtio header in place.
                                tun_bufs[batch_len].resize(seg, 0);
                                // Base ptr captured before decrypt (resize never reallocs:
                                // capacity stays >= seg), used to locate the IP packet
                                // inside the decrypted frame without re-borrowing the buf.
                                let base = tun_bufs[batch_len].as_ptr() as usize;
                                let dec = noise_decrypt_data_client_into(
                                    ciphertext,
                                    &session.state,
                                    &mut tun_bufs[batch_len][TUN_SEND_OFFSET..],
                                    nonce,
                                );
                                match dec {
                                    Err(e) => {
                                        warn!("[{}] decrypt failed (sid {}): {}", addr, sid, e)
                                    }
                                    Ok(DataClientActionRef::Forward(packet)) => {
                                        // `packet` points at the IP packet inside the
                                        // decrypted frame (past the variant+len header),
                                        // so it does not start at TUN_SEND_OFFSET. Shift
                                        // it there — send_multiple uses one global offset.
                                        let start = packet.as_ptr() as usize - base;
                                        let len = packet.len();
                                        tun_bufs[batch_len]
                                            .copy_within(start..start + len, TUN_SEND_OFFSET);
                                        tun_bufs[batch_len].truncate(TUN_SEND_OFFSET + len);
                                        if session.sock_addr() != addr {
                                            debug!("[{}] addr changed for sid {}", addr, sid);
                                            session.set_sock_addr(addr);
                                        }
                                        batch_len += 1;
                                    }
                                    Ok(DataClientActionRef::KeepAlive(client_ts)) => {
                                        info!("[{}] keepalive from sid {}", addr, sid);
                                        if session.sock_addr() != addr {
                                            debug!("[{}] addr changed for sid {}", addr, sid);
                                            session.set_sock_addr(addr);
                                        }
                                        let send_nonce =
                                            session.send_nonce.fetch_add(1, Ordering::Relaxed);
                                        match noise_encrypt(
                                            &DataServerBody::KeepAlive(client_ts),
                                            &session.state,
                                            send_nonce,
                                        ) {
                                            Err(e) => {
                                                error!("[{}] keepalive encrypt failed: {}", addr, e)
                                            }
                                            Ok(encrypted) => {
                                                let m = encode_data_server_frame(
                                                    send_nonce,
                                                    &encrypted,
                                                    &mut encode_buf,
                                                );
                                                if let Err(e) =
                                                    transport.send_to(&encode_buf[..m], &addr).await
                                                {
                                                    error!(
                                                        "[{}] keepalive send failed: {}",
                                                        addr, e
                                                    );
                                                }
                                            }
                                        }
                                    }
                                    Ok(DataClientActionRef::LeaseRequest) => {
                                        if session.sock_addr() != addr {
                                            session.set_sock_addr(addr);
                                        }
                                        let reply = lease_reply(&sessions, &session, sid);
                                        let send_nonce =
                                            session.send_nonce.fetch_add(1, Ordering::Relaxed);
                                        match noise_encrypt(&reply, &session.state, send_nonce) {
                                            Err(e) => {
                                                error!("[{}] lease encrypt failed: {}", addr, e)
                                            }
                                            Ok(encrypted) => {
                                                let m = encode_data_server_frame(
                                                    send_nonce,
                                                    &encrypted,
                                                    &mut encode_buf,
                                                );
                                                if let Err(e) =
                                                    transport.send_to(&encode_buf[..m], &addr).await
                                                {
                                                    error!("[{}] lease send failed: {}", addr, e);
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

            // Opportunistically pull the next already-queued datagram. Never wait:
            // WouldBlock (empty socket) or batch-full ends the drain and flushes.
            if batch_len >= TUN_BATCH_SIZE {
                break;
            }
            match transport.try_recv_from(&mut udp_buf) {
                Ok((n2, addr2)) => {
                    n = n2;
                    addr = addr2;
                }
                Err(_) => break,
            }
        }

        // Flush the decrypted batch to the TUN in one GRO-merged write.
        if batch_len > 0
            && let Err(e) = network
                .send_multiple(&mut gro, &mut tun_bufs[..batch_len], TUN_SEND_OFFSET)
                .await
        {
            error!("network send_multiple error: {}", e);
        }
    }
    debug!("recv_decrypt_forward stopped");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::PublicKey;
    use crate::protocol::Alg;
    use crate::runtime::crypto::make_noise_pair_for_test;

    #[test]
    fn lease_reply_assigns_and_is_idempotent() {
        let sessions = Sessions::new(&"10.0.0.0".parse().unwrap(), 24);
        let (_client, server_state) = make_noise_pair_for_test();
        let addr = "127.0.0.1:1".parse().unwrap();
        let sid = sessions.next_session_id().unwrap();
        let pk = PublicKey::try_from([9u8; 32].as_slice()).unwrap();
        sessions.add(sid, addr, Alg::ChaCha20Poly1305, server_state, pk);

        let session = sessions.get_by_sid(&sid).unwrap();
        let ip = match lease_reply(&sessions, &session, sid) {
            DataServerBody::LeaseGrant(ip) => ip,
            _ => panic!("expected lease grant"),
        };
        assert!(sessions.is_holy_ip_allocated(&ip));
        assert_eq!(session.holy_ip.get(), Some(&ip));

        match lease_reply(&sessions, &session, sid) {
            DataServerBody::LeaseGrant(ip2) => assert_eq!(ip2, ip),
            _ => panic!("expected lease grant"),
        }
    }
}
