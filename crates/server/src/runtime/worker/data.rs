use std::net::SocketAddr;
use snow::StatelessTransportState;
use tokio::sync::broadcast::Receiver;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use shared::protocol::{EncryptedData, Packet, DataClientBody, DataServerBody};
use shared::session::SessionId;
use super::super::{
    error::RuntimeError,
    session::Sessions
};
use super::HolyIp;

fn decode_body(encrypted: &EncryptedData, state: &StatelessTransportState) -> anyhow::Result<DataClientBody> {
    let mut buffer = [0u8; 65536];
    let len = state.read_message(0, encrypted, &mut buffer)?;
    match bincode::serde::decode_from_slice(
        &buffer[..len],
        bincode::config::standard()
    ) {
        Ok((obj, _)) => Ok(obj),
        Err(err) => Err(anyhow::anyhow!(err))
    }
}

fn encode_body(body: &DataServerBody, state: &StatelessTransportState) -> anyhow::Result<EncryptedData> {
    let mut buffer = [0u8; 65536];
    let len = state.write_message(
        0,
        &bincode::serde::encode_to_vec(
            body,
            bincode::config::standard()
        )?,
        &mut buffer
    )?;
    Ok(buffer[..len].to_vec().into())
}

pub(super) async fn data_udp_executor(
    mut stop: Receiver<RuntimeError>,
    mut queue: mpsc::Receiver<(SessionId, EncryptedData, SocketAddr)>,
    udp_tx: mpsc::Sender<(Packet, SocketAddr)>,
    tun_tx: mpsc::Sender<Vec<u8>>,
    sessions: Sessions,
) {
    loop {
        tokio::select! {
            _ = stop.recv() => break,
            data = queue.recv() => match data {
                Some((sid, encrypypted, addr)) => match sessions.get(&sid).await {
                    Some(session) => match session.state {
                        Some(state) => match decode_body(&encrypypted, &state) {
                            Ok(body) => match body {
                                DataClientBody::KeepAlive(client_time) => {
                                    info!("[{}] received keepalive packet from sid {}", addr, sid);
                                    match encode_body(&DataServerBody::KeepAlive(client_time), &state) {
                                        Ok(value) => {
                                            if let Err(e) = udp_tx.send((Packet::DataServer(value), addr)).await {
                                                error!("failed to send server data packet to udp queue: {}", e);
                                            }
                                        },
                                        Err(e) => {
                                            error!("[{}] failed to encode keepalive data packet: {}", addr, e);
                                        }
                                    }
                                },
                                DataClientBody::Payload(data) => {
                                    // sessions. - check HolyIp in sessions
                                    if let Err(err) = tun_tx.send(data.0).await {
                                        error!("[{}] failed to send data to tun queue: {}", addr, err);
                                    }
                                },
                                DataClientBody::Disconnect => {
                                    sessions.release(sid).await;
                                    info!("[{}] received disconnect packet from sid {}", addr, sid);
                                },
                            },
                            Err(err) => warn!("[{}] failed to decrypt data packet (sid: {}): {}", addr, sid, err)
                        },
                        None => warn!("[{}] received data packet for session with unset state {}", addr, sid)
                    },
                    None => warn!("[{}] received data packet for unknown session {}", addr, sid)
                },
                None => {
                    error!("data_udp_executor channel is closed");
                    break
                }
            }
        }
    }
}

pub(super) async fn data_tun_executor(
    mut stop: Receiver<RuntimeError>,
    mut queue: mpsc::Receiver<(Vec<u8>, HolyIp)>,
    udp_tx: mpsc::Sender<(Packet, SocketAddr)>,
    sessions: Sessions,
) {
    loop {
        tokio::select! {
            _ = stop.recv() => break,
            data = queue.recv() => match data {
                Some((packet, holy_ip)) => match sessions.get(&holy_ip).await {
                    Some(session) => match session.state {
                        Some(state) => match encode_body(&DataServerBody::Payload(packet.into()), &state) {
                            Ok(body) => {
                                if let Err(e) = udp_tx.send((Packet::DataServer(body), session.sock_addr)).await {
                                    error!("failed to send server data packet to udp queue: {}", e);
                                }
                            },
                            Err(err) => warn!("[{}] failed to encode tun data packet (sid: {}): {}", session.sock_addr, session.id, err)
                        },
                        None => warn!("[{}] received tun data packet for session with unset state (sid: {})", session.sock_addr, session.id)
                    },
                    None => warn!("[{}] received data packet for unknown session", holy_ip)
                },
                None => {
                    error!("data_tun_executor channel is closed");
                    break
                }
            }
        }
    }
}
