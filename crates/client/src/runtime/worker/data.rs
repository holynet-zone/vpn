use crate::runtime::error::RuntimeError;
use shared::protocol::{DataClientBody, DataServerBody, EncryptedData, Packet};
use shared::keepalive::{format_duration_millis, micros_since_start};
use shared::session::SessionId;
use snow::StatelessTransportState;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast::{Receiver, Sender};
use tokio::sync::mpsc;
use tracing::{info, warn};


fn decrypt_body(
    encrypted: &EncryptedData,
    state: &StatelessTransportState
) -> anyhow::Result<DataServerBody> {
    let mut buffer = [0u8; 65536];
    state.read_message(0, encrypted, &mut buffer)?;
    bincode::deserialize(&buffer).map_err(|e| anyhow::anyhow!(e))
}

fn encrypt_body(body: &DataClientBody,
    state: &StatelessTransportState
) -> anyhow::Result<EncryptedData> {
    let mut buffer = [0u8; 65536];
    let len = state.write_message(0, &bincode::serialize(body)?, &mut buffer)?;
    Ok(buffer[..len].to_vec())
}


pub(super) async fn data_udp_executor(
    stop_sender: Sender<RuntimeError>,
    mut stop: Receiver<RuntimeError>,
    mut queue: mpsc::Receiver<EncryptedData>,
    tun_sender: mpsc::Sender<Vec<u8>>,
    state: Arc<StatelessTransportState>,
) {
    loop {
        tokio::select! {
            _ = stop.recv() => break,
            data = queue.recv() => match data { // todo: may exec in another thread from pool
                Some(data) => match decrypt_body(&data, &state) {
                    Ok(data_body) => match data_body {
                        DataServerBody::KeepAlive(time) => {
                            info!("keepalive rtt: {}", format_duration_millis(
                                time,
                                micros_since_start()
                            ));
                            continue;
                        },
                        DataServerBody::Disconnect(ref code) => {
                            stop_sender.send(RuntimeError::Disconnect(
                                format!("server disconnected code {}", code)
                            )).unwrap();
                            continue;
                        },
                        DataServerBody::Payload(payload) => {
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
               Some(packet) => match encrypt_body(&DataClientBody::Payload(packet), &state) {
                    Ok(encrypted) => {
                        udp_sender.send(Packet::DataClient{ sid, encrypted }).await.unwrap(); // todo remove await
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
            _ = timer.tick() => match encrypt_body(&DataClientBody::KeepAlive(micros_since_start()), &state) {
                Ok(encrypted) => {
                    udp_sender.send(Packet::DataClient{ sid, encrypted }).await.unwrap();  // todo: if channel is full then we can ignore sending
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
