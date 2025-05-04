use std::net::SocketAddr;
use snow::StatelessTransportState;
use tokio::sync::broadcast::Receiver;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

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
    let mut temp_buffer = [0u8; 65536];
    let encoded_len= bincode::serde::encode_into_slice(
        body,
        &mut temp_buffer,
        bincode::config::standard()
    )?;


    let mut encrypted_buffer = [0u8; 65536];
    let encrypted_len = state.write_message(
        0,
        &temp_buffer[..encoded_len],
        &mut encrypted_buffer
    )?;

    Ok(encrypted_buffer[..encrypted_len].to_vec().into())
}

pub(super) async fn data_transport_executor(
    mut stop: Receiver<RuntimeError>,
    mut queue: mpsc::Receiver<(SessionId, EncryptedData, SocketAddr)>,
    transport_tx: mpsc::Sender<(Packet, SocketAddr)>,
    tun_tx: mpsc::Sender<Vec<u8>>,
    sessions: Sessions,
    inf_sessions_timeout: bool,
) {
    loop {
        tokio::select! {
            _ = stop.recv() => break,
            data = queue.recv() => match data {
                Some((sid, encrypypted, addr)) => match sessions.get(&sid) {
                    Some(session) => match decode_body(&encrypypted, &session.state) {
                        Ok(body) => match body {
                            DataClientBody::KeepAlive(client_time) => {
                                info!("[{}] received keepalive packet from sid {}", addr, sid);
                                if session.sock_addr() != addr {
                                    debug!("[{}] changed address from {} to {}", sid, session.sock_addr(), addr);
                                    sessions.update_sock_addr(sid, addr);
                                }
                                match encode_body(&DataServerBody::KeepAlive(client_time), &session.state) {
                                    Ok(value) => {
                                        if !inf_sessions_timeout {
                                            sessions.touch(sid)
                                        }
                                        if let Err(e) = transport_tx.send((Packet::DataServer(value), addr)).await {
                                            error!("failed to send server data packet to transport queue: {}", e);
                                        }
                                    },
                                    Err(e) => {
                                        error!("[{}] failed to encode keepalive data packet: {}", addr, e);
                                    }
                                }
                            },
                            DataClientBody::Payload(data) => {
                                // sessions. - check HolyIp in sessions
                                if !inf_sessions_timeout {
                                    sessions.touch(sid)
                                }
                                if session.sock_addr() != addr {
                                    debug!("[{}] changed address from {} to {}", sid, session.sock_addr(), addr);
                                    sessions.update_sock_addr(sid, addr);
                                }
                                if let Err(err) = tun_tx.send(data.0).await {
                                    error!("[{}] failed to send data to tun queue: {}", addr, err);
                                }
                            }
                        },
                        Err(err) => warn!("[{}] failed to decrypt data packet (sid: {}): {}", addr, sid, err)
                    },
                    None => warn!("[{}] received data packet for unknown session {}", addr, sid)
                },
                None => {
                    error!("data_transport_executor channel is closed");
                    break
                }
            }
        }
    }
}

pub(super) async fn data_tun_executor(
    mut stop: Receiver<RuntimeError>,
    mut queue: mpsc::Receiver<(Vec<u8>, HolyIp)>,
    transport_tx: mpsc::Sender<(Packet, SocketAddr)>,
    sessions: Sessions,
) {
    loop {
        tokio::select! {
            _ = stop.recv() => break,
            data = queue.recv() => match data {
                Some((packet, holy_ip)) => match sessions.get(&holy_ip) {
                    Some(session) => match encode_body(&DataServerBody::Payload(packet.into()), &session.state) {
                        Ok(body) => {
                            if let Err(e) = transport_tx.send((Packet::DataServer(body), session.sock_addr())).await {
                                error!("failed to send server data packet to transport queue: {}", e);
                            }
                        },
                        Err(err) => warn!("[{}] failed to encode tun data packet (sid: {}): {}", session.sock_addr(), session.id, err)
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
