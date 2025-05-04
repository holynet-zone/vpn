use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::broadcast::Receiver;
use tokio::sync::mpsc;
use tracing::{debug, error, warn};
use shared::protocol::{EncryptedData, EncryptedHandshake, Packet};
use shared::session::SessionId;
use crate::runtime::error::RuntimeError;
use crate::runtime::transport::{TransportReceiver, TransportSender};

pub async fn transport_sender(
    mut stop: Receiver<RuntimeError>,
    transport: Arc<dyn TransportSender>,
    mut out_transport_rx: mpsc::Receiver<(Packet, SocketAddr)>
) {
    loop {
        tokio::select! {
            _ = stop.recv() => break,
            result = out_transport_rx.recv() => match result {
                Some((data, client_addr)) => {
                    match transport.send_to(&data.to_bytes(), &client_addr).await {
                        Ok(len) => {
                            debug!("sent packet to {}: len: {}", client_addr, len);

                        },
                        Err(e) => {
                            error!("failed to send data to {}: {}", client_addr, e);
                            continue;
                        }
                    }
                },
                None => break
            }
        }
    }
}

pub async fn transport_listener(
    mut stop: Receiver<RuntimeError>,
    transport: Arc<dyn TransportReceiver>,
    handshake_tx: mpsc::Sender<(EncryptedHandshake, SocketAddr)>,
    data_tx: mpsc::Sender<(SessionId, EncryptedData, SocketAddr)>
) {
    let mut buffer = [0u8; 65536];
    loop {
        tokio::select! {
            _ = stop.recv() => break,
            result = transport.recv_from(&mut buffer) => {
                match result {
                    Ok((n, client_addr)) => {
                        debug!("received transport packet from {}: len: {}", client_addr, n);
                        if n == 0 {
                            warn!("received transport packet from {} with 0 bytes, dropping it", client_addr);
                            continue;
                        }
                        if n > 65536 {
                            warn!("received transport packet from {} larger than 65536 bytes, dropping it", client_addr);
                            continue;
                        }
                        match Packet::try_from(&buffer[..n]) {
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
                                warn!("failed to parse transport packet from {}: {}", client_addr, e);
                                continue;
                            }
                        }
                    }
                    Err(e) => warn!("failed to receive transport: {}", e)
                }
            }
        }
    }
}

