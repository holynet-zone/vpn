use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use snow::StatelessTransportState;
use tokio::sync::broadcast::Receiver;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use shared::server;
use shared::{
    client
};
use shared::server::packet::{DataBody, DataPacket, Packet};
use super::super::{
    error::RuntimeError,
    session::Sessions
};
use shared::server::packet::KeepAliveBody;
use super::HolyIp;

fn decode_from_packet(packet: &client::packet::DataPacket, state: &StatelessTransportState) -> anyhow::Result<client::packet::DataBody> {
    let mut buffer = [0u8; 65536];
    state.read_message(0, &packet.enc_body, &mut buffer)?;
    bincode::deserialize(&buffer).map_err(|e| anyhow::anyhow!(e))
}

fn encode_to_packet(body: &DataBody, state: &StatelessTransportState) -> anyhow::Result<DataPacket> {
    let mut buffer = [0u8; 65536];
    let len = state.write_message(0, &bincode::serialize(body)?, &mut buffer)?;
    Ok(DataPacket {
        enc_body: buffer[..len].to_vec()
    })
}

pub(super) async fn data_udp_executor(
    mut stop: Receiver<RuntimeError>,
    mut queue: mpsc::Receiver<(client::packet::DataPacket, SocketAddr)>,
    udp_tx: mpsc::Sender<(server::packet::Packet, SocketAddr)>,
    tun_tx: mpsc::Sender<Vec<u8>>,
    sessions: Sessions,
) {
    loop {
        tokio::select! {
            _ = stop.recv() => break,
            data = queue.recv() => match data {
                Some((enc_packet, addr)) => match sessions.get(&enc_packet.sid).await {
                    Some(session) => match session.state {
                        Some(state) => match decode_from_packet(&enc_packet, &state) {
                            Ok(body) => {
                                match body {
                                    DataBody::KeepAlive(ref body) => {
                                        info!("[{}] received keepalive packet from sid {} owd {}", addr, enc_packet.sid, body.owd());
                                        let resp = DataBody::KeepAlive(KeepAliveBody::new(body.client_time));
                                        match encode_to_packet(&resp, &state) {
                                            Ok(value) => {
                                                if let Err(e) = udp_tx.send((server::packet::Packet::Data(value), addr)).await {
                                                    error!("failed to send server data packet to udp queue: {}", e);
                                                }
                                            },
                                            Err(e) => {
                                                error!("[{}] failed to encode keepalive data packet: {}", addr, e);
                                            }
                                        }
                                    },
                                    DataBody::Payload(data) => {
                                        // sessions. - check HolyIp in sessions
                                        if let Err(err) tun_tx.send(data).await {
                                            error!("[{}] failed to send data to tun queue: {}", addr, err);
                                        }
                                    },
                                    DataBody::Disconnect(code) => {
                                        sessions.release(enc_packet.sid).await;
                                        info!("[{}] received disconnect packet from sid {}, code: ", addr, enc_packet.sid);
                                    },
                                }
                            },
                            Err(err) => warn!("[{}] failed to decrypt data packet (sid: {}): {}", addr, enc_packet.sid, err)
                        },
                        None => warn!("[{}] received data packet for session with unset state {}", addr, enc_packet.sid)
                    },
                    None => warn!("[{}] received data packet for unknown session {}", addr, enc_packet.sid)
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
                        Some(state) => match encode_to_packet(&DataBody::Payload(packet), &state) {
                            Ok(body) => {
                                let resp = Packet::Data(body);
                                if let Err(e) = udp_tx.send((resp, session.sock_addr)).await {
                                    error!("failed to send server data packet to udp queue: {}", e);
                                }
                            },
                            Err(err) => warn!("[{}] failed to encode tun data packet (sid: {}): {}", session.sock_addr, session.id, err)
                        },
                        None => warn!("[{}] received tun data packet for session with unset state (sid: {})", session.sock_addr, session.id)
                    },
                    None => warn!("[{}] received data packet for unknown session {}", holy_ip)
                },
                None => {
                    error!("data_tun_executor channel is closed");
                    break
                }
            }
        }
    }
}