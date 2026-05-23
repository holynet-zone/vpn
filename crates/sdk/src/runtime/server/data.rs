use std::net::SocketAddr;

use tokio::sync::mpsc;
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use crate::protocol::{DataClientBody, DataServerBody, EncryptedData, Packet, SessionId};
use crate::runtime::crypto::{noise_decrypt, noise_encrypt};
use super::session::{HolyIp, Sessions};

pub(super) async fn data_transport_executor(
    mut stop: watch::Receiver<bool>,
    mut queue: mpsc::Receiver<(SessionId, EncryptedData, SocketAddr)>,
    transport_tx: mpsc::Sender<(Packet, SocketAddr)>,
    tun_tx: mpsc::Sender<Vec<u8>>,
    sessions: Sessions,
    inf_sessions_timeout: bool,
) {
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            data = queue.recv() => match data {
                Some((sid, encrypted, addr)) => match sessions.get_by_sid(&sid) {
                    Some(session) => match noise_decrypt::<DataClientBody>(&encrypted, &session.state) {
                        Ok(body) => match body {
                            DataClientBody::KeepAlive(client_time) => {
                                info!("[{}] keepalive from sid {}", addr, sid);
                                if session.sock_addr() != addr {
                                    debug!("[{}] address changed from {} to {}", sid, session.sock_addr(), addr);
                                    sessions.update_sock_addr(sid, addr);
                                }
                                match noise_encrypt(&DataServerBody::KeepAlive(client_time), &session.state) {
                                    Ok(value) => {
                                        if !inf_sessions_timeout {
                                            sessions.touch(sid);
                                        }
                                        if let Err(e) = transport_tx.send((Packet::DataServer(value), addr)).await {
                                            error!("failed to send keepalive response: {}", e);
                                        }
                                    }
                                    Err(e) => error!("[{}] failed to encode keepalive response: {}", addr, e),
                                }
                            }
                            DataClientBody::Packet(data) => {
                                if !inf_sessions_timeout {
                                    sessions.touch(sid);
                                }
                                if session.sock_addr() != addr {
                                    debug!("[{}] address changed from {} to {}", sid, session.sock_addr(), addr);
                                    sessions.update_sock_addr(sid, addr);
                                }
                                if let Err(err) = tun_tx.send(data).await {
                                    error!("[{}] failed to forward data to tun: {}", addr, err);
                                }
                            }
                        },
                        Err(err) => warn!("[{}] failed to decrypt data (sid: {}): {}", addr, sid, err),
                    },
                    None => warn!("[{}] received data for unknown session {}", addr, sid),
                },
                None => {
                    debug!("data_transport_executor channel closed");
                    break;
                }
            }
        }
    }
}

pub(super) async fn data_tun_executor(
    mut stop: watch::Receiver<bool>,
    mut queue: mpsc::Receiver<(Vec<u8>, HolyIp)>,
    transport_tx: mpsc::Sender<(Packet, SocketAddr)>,
    sessions: Sessions,
) {
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            data = queue.recv() => match data {
                Some((packet, holy_ip)) => match sessions.get_by_holy_ip(&holy_ip) {
                    Some(session) => {
                        match noise_encrypt(&DataServerBody::Packet(packet), &session.state) {
                            Ok(body) => {
                                if let Err(e) = transport_tx.send((Packet::DataServer(body), session.sock_addr())).await {
                                    error!("failed to send server data packet: {}", e);
                                }
                            }
                            Err(err) => warn!(
                                "[{}] failed to encode tun packet (sid: {}): {}",
                                session.sock_addr(), session.id, err
                            ),
                        }
                    }
                    None => warn!("[{}] received tun packet for unknown session", holy_ip),
                },
                None => {
                    debug!("data_tun_executor channel closed");
                    break;
                }
            }
        }
    }
}
