use std::sync::Arc;
use tokio::sync::broadcast::{Receiver, Sender};
use tokio::sync::mpsc;
use tracing::{debug, error, warn};
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
                Some(packet) => match transport.send(&packet.to_bytes()).await {
                    Ok(n) => debug!("sent transport packet with {} bytes", n),
                    Err(err) => {
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
    let mut transport_buffer = [0u8; 65536];
    loop {
        tokio::select! {
            _ = stop.recv() => break,
            result = transport.recv(&mut transport_buffer) => match result {
                Ok(n) => {
                    debug!("received transport packet with {} bytes", n);
                    if n == 0 {
                        warn!("received transport packet with 0 bytes, dropping it");
                        continue;
                    }
                    if n > 65536 {
                        warn!("received transport packet larger than 65536 bytes, dropping it");
                        continue;
                    }
                    match Packet::try_from(&transport_buffer[..n]) {
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
                            warn!("failed to parse transport packet: {}", err);
                            continue;
                        }
                    }
                }
                Err(err) => {
                    stop_sender.send(RuntimeError::IO(format!("failed to receive transport: {}", err))).unwrap();
                }
            }
        }
    }
}