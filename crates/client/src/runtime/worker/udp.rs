use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::UdpSocket;
use tokio::sync::broadcast::{Receiver, Sender};
use tokio::sync::mpsc;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tracing::{error, warn};
use shared::protocol::{EncryptedData, Packet};
use crate::runtime::error::RuntimeError;


pub async fn udp_sender(
    stop_sender: Sender<RuntimeError>,
    mut stop: Receiver<RuntimeError>,
    socket: Arc<UdpSocket>,
    mut queue: UnboundedReceiver<Packet>
) {
    loop {
        tokio::select! {
            _ = stop.recv() => break,
            result = queue.recv() => match result {
                Some(packet) => {
                    if let Err(err) = socket.send(&packet.to_bytes()).await {
                        stop_sender.send(RuntimeError::IO(format!("failed to send udp: {}", err))).unwrap();
                    }
                },
                None => break
            }
        }
    }
}


pub async fn udp_listener(
    stop_sender: Sender<RuntimeError>,
    mut stop: Receiver<RuntimeError>,
    socket: Arc<UdpSocket>,
    queues: Vec<UnboundedSender<EncryptedData>>
) {
    let queues_len = queues.len();
    let mut index = 0;
    let mut udp_buffer = [0u8; 65536];

    loop {
        tokio::select! {
            _ = stop.recv() => break,
            result = socket.recv(&mut udp_buffer) => match result {
                Ok(n) => {
                    if n == 0 {
                        warn!("received UDP packet with 0 bytes, dropping it");
                        continue;
                    }
                    if n > udp_buffer.len() {
                        warn!("received UDP packet larger than buffer, dropping it");
                        continue;
                    }

                    match Packet::try_from(&udp_buffer[..n]) {
                        Ok(packet) => match packet {
                            Packet::DataServer(data) => {
                                let tx = unsafe{queues.get_unchecked(index)};
                                index = (index + 1) % queues_len;
                                if let Err(err) = tx.send(data) {
                                    error!("failed to send data to data_receiver[{}]: {}", index, err);
                                }
                            },
                            Packet::HandshakeResponder(_) => {
                                warn!("received handshake packet, but expected data packet");
                            },
                            _ => {
                                warn!("received unexpected packet type");
                            }
                        },
                        Err(err) => {
                            warn!("failed to parse UDP packet: {}", err);
                        }
                    }
                }
                Err(err) => {
                    let _ = stop_sender.send(RuntimeError::IO(format!("failed to receive udp: {}", err)));
                }
            }
        }
    }
}