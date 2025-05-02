use std::sync::Arc;
use tokio::sync::broadcast::{Receiver, Sender};
use tokio::sync::mpsc;
use tracing::{error, warn};
use shared::protocol::{EncryptedData, Packet};
use crate::runtime::error::RuntimeError;
use crate::runtime::transport::{TransportReceiver, TransportSender};

pub async fn transport_sender(
    stop_sender: Sender<RuntimeError>,
    mut stop: Receiver<RuntimeError>,
    transport: Arc<dyn TransportSender>,
    mut queue: mpsc::Receiver<Packet>
) {
    loop {
        tokio::select! {
            _ = stop.recv() => break,
            result = queue.recv() => match result {
                Some(packet) => {
                    if let Err(err) = transport.send(&packet.to_bytes()).await {
                        stop_sender.send(RuntimeError::IO(format!("failed to send udp: {}", err))).unwrap();
                    }
                },
                None => break
            }
        }
    }
}

pub async fn transport_listener(
    stop_sender: Sender<RuntimeError>,
    mut stop: Receiver<RuntimeError>,
    transport: Arc<dyn TransportReceiver>,
    data_receiver: mpsc::Sender<EncryptedData>
) {
    let mut udp_buffer = [0u8; 65536];
    loop {
        tokio::select! {
            _ = stop.recv() => break,
            result = transport.recv(&mut udp_buffer) => match result {
                Ok(n) => {
                    if n == 0 {
                        warn!("received UDP packet with 0 bytes, dropping it");
                        continue;
                    }
                    if n > 65536 {
                        warn!("received UDP packet larger than 65536 bytes, dropping it");
                        continue;
                    }
                    match Packet::try_from(&udp_buffer[..n]) {
                        Ok(packet) => match packet {
                            Packet::DataServer(data) => {
                                if let Err(err) = data_receiver.send(data).await {
                                    error!("failed to send data to data_receiver: {}", err);
                                }
                            },
                            Packet::HandshakeResponder(_) => {
                                warn!("received handshake packet, but expected data packet");
                                continue;
                            },
                            _ => {
                                warn!("received unexpected packet type");
                                continue;
                            }
                        },
                        Err(err) => {
                            warn!("failed to parse UDP packet: {}", err);
                            continue;
                        }
                    }
                }
                Err(err) => {
                    stop_sender.send(RuntimeError::IO(format!("failed to receive udp: {}", err))).unwrap();
                }
            }
        }
    }
}