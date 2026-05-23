use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::sync::watch;
use tracing::{debug, error, warn};

use crate::gateway::transport::{TransportReceiver, TransportSender};
use crate::protocol::{EncryptedData, EncryptedHandshake, Packet, SessionId};

pub async fn transport_sender(
    mut stop: watch::Receiver<bool>,
    transport: Arc<dyn TransportSender>,
    mut out_transport_rx: mpsc::Receiver<(Packet, SocketAddr)>,
) {
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            result = out_transport_rx.recv() => match result {
                Some((packet, client_addr)) => {
                    match transport.send_to(&packet.to_bytes(), &client_addr).await {
                        Ok(len) => debug!("sent {} bytes to {}", len, client_addr),
                        Err(e) => error!("failed to send to {}: {}", client_addr, e),
                    }
                }
                None => break,
            }
        }
    }
}

pub async fn transport_listener(
    mut stop: watch::Receiver<bool>,
    transport: Arc<dyn TransportReceiver>,
    handshake_tx: mpsc::Sender<(EncryptedHandshake, SocketAddr)>,
    data_tx: mpsc::Sender<(SessionId, EncryptedData, SocketAddr)>,
) {
    let mut buffer = [0u8; 65536];
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            result = transport.recv_from(&mut buffer) => match result {
                Ok((n, client_addr)) => {
                    debug!("received {} bytes from {}", n, client_addr);
                    if n == 0 {
                        warn!("empty packet from {}, dropping", client_addr);
                        continue;
                    }
                    if n >= buffer.len() {
                        warn!("oversized packet from {} ({} bytes), dropping", client_addr, n);
                        continue;
                    }
                    match Packet::try_from(&buffer[..n]) {
                        Ok(packet) => match packet {
                            Packet::HandshakeInitial(handshake) => {
                                if let Err(e) = handshake_tx.send((handshake, client_addr)).await {
                                    error!("failed to forward handshake: {}", e);
                                }
                            }
                            Packet::DataClient { sid, encrypted } => {
                                if let Err(e) = data_tx.send((sid, encrypted, client_addr)).await {
                                    error!("failed to forward data: {}", e);
                                }
                            }
                            _ => warn!("unexpected packet type from {}", client_addr),
                        },
                        Err(e) => warn!("failed to parse packet from {}: {}", client_addr, e),
                    }
                }
                Err(e) => warn!("transport recv error: {}", e),
            }
        }
    }
}
