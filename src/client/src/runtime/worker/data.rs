
use snow::StatelessTransportState;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast::{Receiver, Sender};
use tokio::sync::{broadcast, mpsc};
use tracing::{error, info, warn};
use shared::client::packet::{DataBody, DataPacket, KeepAliveBody, Packet};
use shared::server;
use shared::session::SessionId;
use crate::runtime::error::RuntimeError;


fn decrypt_body(
    enc_packet: &server::packet::DataPacket,
    state: &StatelessTransportState
) -> anyhow::Result<server::packet::DataBody> {
    let mut buffer = [0u8; 65536];
    state.read_message(0, &enc_packet.enc_body, &mut buffer)?;
    bincode::deserialize(&buffer).map_err(|e| anyhow::anyhow!(e))
}

fn encrypt_body(body: &DataBody,
    state: &StatelessTransportState
) -> anyhow::Result<Vec<u8>> {
    let mut buffer = [0u8; 65536];
    let len = state.write_message(0, &bincode::serialize(body)?, &mut buffer)?;
    Ok(buffer[..len].to_vec())
}


pub(super) async fn data_udp_executor(
    stop_sender: Sender<RuntimeError>,
    mut stop: Receiver<RuntimeError>,
    mut queue: mpsc::Receiver<server::packet::DataPacket>,
    tun_sender: mpsc::Sender<Vec<u8>>,
    state: Arc<StatelessTransportState>,
) {
    loop {
        tokio::select! {
            _ = stop.recv() => break,
            data = queue.recv() => match data { // todo: may exec in another thread from pool
                Some(data) => match decrypt_body(&data, &state) {
                    Ok(data_body) => match data_body {
                        server::packet::DataBody::KeepAlive(ref body) => {
                            info!("keepalive rtt: {} ms; owd: {} ms", body.rtt(), body.owd());
                            continue;
                        },
                        server::packet::DataBody::Disconnect(ref code) => {
                            stop_sender.send(RuntimeError::Disconnect(
                                format!("server disconnected code {}", code)
                            )).unwrap();
                            continue;
                        },
                        server::packet::DataBody::Payload(payload) => {
                            tun_sender.send(payload).await.unwrap()
                        }
                    },
                    Err(e) => {
                        warn!("received damaged package: {}", e);
                        continue;
                    }
                },
                None => return
            }
        }
    }
}

pub(super) async fn data_tun_executor(
    stop_sender: Sender<RuntimeError>,
    mut stop: Receiver<RuntimeError>,
    mut queue: mpsc::Receiver<Vec<u8>>,
    udp_sender: mpsc::Sender<Packet>,
    state: Arc<StatelessTransportState>,
    sid: SessionId
) {
    loop {
        tokio::select! {
            _ = stop.recv() => break,
            body = queue.recv() => match body { // todo: may exec in another thread from pool??
               Some(packet) => match encrypt_body(&DataBody::Payload(packet), &state) {
                    Ok(enc_body) => {
                        udp_sender.send(Packet::Data(DataPacket{ sid, enc_body })).await.unwrap(); // todo remove await
                    },
                    Err(e) => {
                        stop_sender.send(RuntimeError::Unexpected(
                            format!("failed to encrypt data: {}", e)
                        )).unwrap();
                    }
                },
                None => return
            }
        }
    }
}

pub(super) async fn keepalive_sender(
    stop_sender: Sender<RuntimeError>,
    mut stop: Receiver<RuntimeError>,
    udp_sender: mpsc::Sender<Packet>,
    duration: Duration,
    state: Arc<StatelessTransportState>,
    sid: SessionId
) {
    let mut timer = tokio::time::interval(duration);
    loop {
        tokio::select! {
            _ = stop.recv() => break,
            _ = timer.tick() => match encrypt_body(&DataBody::KeepAlive(KeepAliveBody::new()), &state) {
                Ok(enc_body) => {
                    udp_sender.send(Packet::Data(DataPacket{ sid, enc_body })).await.unwrap();  // todo: if channel is full then we can ignore sending
                },
                Err(e) => {
                    stop_sender.send(RuntimeError::Unexpected(
                        format!("failed to encrypt data: {}", e)
                    )).unwrap();
                }
            }
        }
    }
}
