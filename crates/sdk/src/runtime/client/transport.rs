use std::{
    ops::Deref,
    sync::Arc,
};

use tokio::{
    time::interval,
    sync::{
        watch::Sender,
        mpsc
    }
};
use tracing::{debug, error, warn};
use crate::{
    gateway::transport::{TransportReceiver, TransportSender},
    protocol::{Packet, EncryptedData},
    runtime::{
        state::RuntimeState,
        client::{AWAIT_STATE_DELAY, MAX_PACKET_SIZE}
    }
};

pub async fn transport_sender(
    state: Sender<RuntimeState>,
    transport: Arc<dyn TransportSender>,
    mut queue: mpsc::Receiver<Packet>
) {
    let mut state_wait_timer = interval(AWAIT_STATE_DELAY);

    let mut state_rx = state.subscribe();
    let mut is_connected = false;
    
    loop {
        // If not yet connected, pause until state changes rather than spin.
        if !is_connected {
            match state_rx.has_changed() {
                Ok(false) => { state_wait_timer.tick().await; continue; }
                Err(_) => break, // watch sender dropped — runtime is shutting down
                Ok(true) => {}
            }
        }

        tokio::select! {
            _ = state_rx.changed() => match state_rx.borrow().deref() {
                RuntimeState::Error(_) => break,
                RuntimeState::Listening | RuntimeState::Connected(_) => {
                    is_connected = true;
                }
                RuntimeState::Connecting => {
                    is_connected = false;
                }
            },
            result = queue.recv() => match result {
                Some(packet) => match transport.send(&packet.to_bytes()).await {
                    Ok(n) => debug!("sent transport packet with {} bytes", n),
                    Err(e) => {
                        warn!("transport send error, signalling reconnect: {}", e);
                        if state.send(RuntimeState::Connecting).is_err() { break; }
                    }
                },
                None => break
            }
        }
    }
}

pub async fn transport_receiver(
    state: Sender<RuntimeState>,
    transport: Arc<dyn TransportReceiver>,
    data_receiver: mpsc::Sender<EncryptedData>
) {
    let mut state_wait_timer = interval(AWAIT_STATE_DELAY);

    let mut state_rx = state.subscribe();
    let mut is_connected = false;
    let mut transport_buffer = [0u8; MAX_PACKET_SIZE];
    loop {
        // If not yet connected, pause until state changes rather than spin.
        if !is_connected {
            match state_rx.has_changed() {
                Ok(false) => { state_wait_timer.tick().await; continue; }
                Err(_) => break, // watch sender dropped — runtime is shutting down
                Ok(true) => {}
            }
        }

        tokio::select! {
            _ = state_rx.changed() => match state_rx.borrow().deref() {
                RuntimeState::Error(_) => break,
                RuntimeState::Listening | RuntimeState::Connected(_) => {
                    is_connected = true;
                },
                RuntimeState::Connecting => {
                    is_connected = false;
                }
            },
            result = transport.recv(&mut transport_buffer) => match result {
                Ok(n) => {
                    debug!("received transport packet with {} bytes", n);
                    if n == 0 {
                        warn!("received transport packet with 0 bytes, dropping it");
                        continue;
                    }
                    if n >= transport_buffer.len() {
                        warn!("received transport packet >= {} bytes, possible truncation", transport_buffer.len());
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
                Err(e) => {
                    warn!("transport recv error, signalling reconnect: {}", e);
                    if state.send(RuntimeState::Connecting).is_err() { break; }
                }
            }
        }
    }
}
