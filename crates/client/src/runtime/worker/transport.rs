use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch::Sender;
use tokio::sync::mpsc;
use tracing::{debug, error, warn};
use shared::protocol::{EncryptedData, Packet};
use crate::runtime::state::RuntimeState;
use crate::runtime::transport::{TransportReceiver, TransportSender};

pub async fn transport_sender(
    state_tx: Sender<RuntimeState>,
    transport: Arc<dyn TransportSender>,
    mut queue: mpsc::Receiver<Packet>
) {
    let mut state_wait_timer = tokio::time::interval(Duration::from_secs(1));

    let mut state_rx = state_tx.subscribe();
    let mut is_connected = false;
    
    loop {
        match state_rx.has_changed() {
            Ok(has_changed) => if has_changed {
                state_rx.mark_unchanged();
                match state_rx.borrow().deref() {
                    RuntimeState::Error(_) => break,
                    RuntimeState::Connecting => {
                        is_connected = false;
                    },
                    RuntimeState::Connected(_) => {
                        is_connected = true;
                    }
                }
            },
            Err(err) => {
                warn!("state channel broken: {}", err);
                break;
            }
        }

        if !is_connected {
            state_wait_timer.tick().await;
            continue;
        }
        
        
        tokio::select! {
            _ = state_rx.changed() => {
                state_rx.mark_changed();
                continue
            },
            result = queue.recv() => match result {
                Some(packet) => match transport.send(&packet.to_bytes()).await {
                    Ok(n) => debug!("sent transport packet with {} bytes", n),
                    Err(_) => {
                        state_tx.send(RuntimeState::Connecting).unwrap(); // todo log
                    }
                },
                None => break
            }
        }
    }
}

pub async fn transport_listener(
    state_tx: Sender<RuntimeState>,
    transport: Arc<dyn TransportReceiver>,
    data_receiver: mpsc::Sender<EncryptedData>
) {
    let mut state_wait_timer = tokio::time::interval(Duration::from_secs(1));

    let mut state_rx = state_tx.subscribe();
    let mut is_connected = false;
    let mut transport_buffer = [0u8; 65536];
    loop {
        match state_rx.has_changed() {
            Ok(has_changed) => if has_changed {
                state_rx.mark_unchanged();
                match state_rx.borrow().deref() {
                    RuntimeState::Error(_) => break,
                    RuntimeState::Connecting => {
                        is_connected = false;
                    },
                    RuntimeState::Connected(_) => {
                        is_connected = true;
                    }
                }
            },
            Err(err) => {
                warn!("state channel broken: {}", err);
                break;
            }
        }

        if !is_connected {
            state_wait_timer.tick().await;
            continue;
        }
        debug!("transport listener ok");
        
        tokio::select! {
            _ = state_rx.changed() => {
                state_rx.mark_changed();
                continue
            },
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
                Err(_) => state_tx.send(RuntimeState::Connecting).unwrap() // todo log
            }
        }
    }
}