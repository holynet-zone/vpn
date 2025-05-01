use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::broadcast::Receiver;
use tokio::sync::mpsc;
use tracing::{error, warn};
use shared::protocol::{EncryptedData, EncryptedHandshake, Packet};
use shared::session::SessionId;
use crate::runtime::error::RuntimeError;

pub async fn udp_sender(
    mut stop: Receiver<RuntimeError>,
    socket: Arc<UdpSocket>,
    mut out_udp_rx: mpsc::Receiver<(Packet, SocketAddr)>
) {
    loop {
        tokio::select! {
            _ = stop.recv() => break,
            result = out_udp_rx.recv() => match result {
                Some((data, client_addr)) => {
                    if let Err(e) = socket.send_to(&data.to_bytes(), &client_addr).await {
                        warn!("failed to send data to {}: {}", client_addr, e);
                    }
                },
                None => break
            }
        }
    }
}

pub async fn udp_listener(
    mut stop: Receiver<RuntimeError>,
    socket: Arc<UdpSocket>,
    handshake_tx: mpsc::Sender<(EncryptedHandshake, SocketAddr)>,
    data_tx: mpsc::Sender<(SessionId, EncryptedData, SocketAddr)>
) {
    let mut udp_buffer = [0u8; 65536];
    loop {
        tokio::select! {
            _ = stop.recv() => break,
            result = socket.recv_from(&mut udp_buffer) => {
                match result {
                    Ok((n, client_addr)) => {
                        if n == 0 {
                            warn!("received UDP packet from {} with 0 bytes, dropping it", client_addr);
                            continue;
                        }
                        if n > 65536 {
                            warn!("received UDP packet from {} larger than 65536 bytes, dropping it", client_addr);
                            continue;
                        }
                        match Packet::try_from(&udp_buffer[..n]) {
                            Ok(packet) => match packet {
                                Packet::HandshakeInitial(handshake) => {
                                    if let Err(e) = handshake_tx.send((handshake, client_addr)).await {
                                        error!("failed to send handshake to executor: {}", e);
                                    }
                                },
                                Packet::DataClient{ sid, encrypted } => {
                                    if let Err(e) = data_tx.send((sid, encrypted, client_addr)).await {
                                        error!("failed to send data to executor: {}", e);
                                    }
                                },
                                _ => {
                                    warn!("received unexpected packet from {}, length {}", client_addr, n);
                                    continue;
                                }
                            },
                            Err(e) => {
                                warn!("failed to parse UDP packet from {}: {}", client_addr, e);
                                continue;
                            }
                        }
                    }
                    Err(e) => warn!("failed to receive udp: {}", e)
                }
            }
        }
    }
}

