use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use snow::StatelessTransportState;
use tokio::sync::broadcast::Receiver;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use crate::{client, server};
use crate::client::packet::DataBody;
use crate::server::error::RuntimeError;
use crate::server::packet::KeepAliveBody;
use crate::server::request::Request;
use crate::server::response::Response;
use crate::server::session::Sessions;


fn decode_packet(packet: &client::packet::DataPacket, state: &StatelessTransportState) -> anyhow::Result<DataBody> {
    let mut buffer = [0u8; 65536];
    state.read_message(0, &packet.enc_body, &mut buffer)?;
    bincode::deserialize(&buffer).map_err(|e| anyhow::anyhow!(e))
}

pub(super) async fn data_executor(
    mut stop: Receiver<RuntimeError>,
    mut queue: mpsc::Receiver<(client::packet::DataPacket, SocketAddr)>,
    udp_tx: mpsc::Sender<(server::packet::Packet, SocketAddr)>,
    sessions: Sessions,
    handler: Option<Arc<dyn Fn(Request) -> Pin<Box<dyn Future<Output = Response> + Send>> + Send + Sync>>
) {
    loop {
        tokio::select! {
            _ = stop.recv() => break,
            data = queue.recv() => match data {
                Some((enc_packet, addr)) => match sessions.get(&enc_packet.sid).await {
                    Some(session) => match session.state {
                        Some(state) => match decode_packet(&enc_packet, &state) {
                            Ok(body) => {
                                // Handle keepalive packets ========================================
                                match body {
                                    client::packet::DataBody::KeepAlive(ref body) => {
                                        info!("[{}] received keepalive packet from sid {} owd {}", addr, enc_packet.sid, body.owd());
                                        let resp = server::packet::DataBody::KeepAlive(KeepAliveBody::new(body.client_time));
                                        match server::packet::DataPacket::from_body(&resp, &state) {
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
                                    client::packet::DataBody::Disconnect => {
                                        sessions.release(enc_packet.sid).await;
                                        info!("[{}] received disconnect packet from sid {}", addr, enc_packet.sid);
                                    },
                                    _ => {}
                                }
                                // Handle custom ===================================================
                                match handler.as_ref() {
                                    Some(handler) => match handler(Request {
                                            ip: addr.ip(),
                                            sid: enc_packet.sid,
                                            sessions: sessions.clone(),  // arc cloning
                                            body
                                        }).await {
                                        Response::Data(body) => match server::packet::DataPacket::from_body(&body, &state) {
                                            Ok(value) => {
                                                if let Err(e) = udp_tx.send((server::packet::Packet::Data(value), addr)).await {
                                                    error!("failed to send server data packet to udp queue: {}", e);
                                                }
                                            },
                                            Err(e) => {
                                                error!("[{}] failed to encode data packet: {}", addr, e);
                                            }
                                        },
                                        Response::Close => {
                                            sessions.release(enc_packet.sid).await; // todo if session already closed??
                                            info!("session {} closed by handler", enc_packet.sid);
                                        },
                                        Response::None => {}
                                    },
                                    None => warn!("[{}] received data packet for session {} but no handler is set", addr, enc_packet.sid)
                                }
                            },
                            Err(err) => warn!("[{}] failed to decrypt data packet (sid: {}): {}", addr, enc_packet.sid, err)
                        },
                        None => warn!("[{}] received data packet for session with unset state {}", addr, enc_packet.sid)
                    },
                    None => warn!("[{}] received data packet for unknown session {}", addr, enc_packet.sid)
                },
                None => {
                    error!("data_executor channel is closed");
                    break
                }
            }
        }
    }
}