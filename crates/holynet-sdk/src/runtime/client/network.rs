use std::{
    ops::Deref,
    sync::Arc,
};
use tokio::sync::{
    watch::Sender,
    mpsc
};
use tracing::{error, warn};
use crate::{
    gateway::network::Network,
    error::RuntimeError,
    runtime::{
        state::RuntimeState,
        client::{AWAIT_STATE_DELAY, MAX_PACKET_SIZE}
    }
};

pub async fn network_sender(
    state_tx: Sender<RuntimeState>,
    network: Arc<dyn Network>,
    mut queue: mpsc::Receiver<Vec<u8>>
) {
    let mut state_rx = state_tx.subscribe();
    loop {
        tokio::select! {
            _ = state_rx.changed() => {
                match state_rx.borrow().deref() {
                    RuntimeState::Error(_) => break,
                    _ => continue
                }
            },
            result = queue.recv() => match result {
                Some(packet) => {
                    if let Err(err) = network.send(&packet).await {
                        state_tx.send(RuntimeState::Error(
                            RuntimeError::IO(format!("failed to send network: {}", err))
                        )).unwrap();
                    }
                },
                None => break
            }
        }
    }
}

pub async fn network_receiver(
    state_tx: Sender<RuntimeState>,
    network: Arc<dyn Network>,
    queue: mpsc::Sender<Vec<u8>>
) {
    let mut state_wait_timer = tokio::time::interval(AWAIT_STATE_DELAY);

    let mut state_rx = state_tx.subscribe();
    let mut is_connected = false;

    let mut buffer = [0u8; MAX_PACKET_SIZE];
    loop {
        if !is_connected && !state_rx.has_changed().unwrap() {
            state_wait_timer.tick().await;
            continue;
        }
        
        tokio::select! {
            _ = state_rx.changed() => {
                match state_rx.borrow().deref() {
                    RuntimeState::Error(_) => break,
                    RuntimeState::Connecting => {
                        is_connected = false;
                    },
                    RuntimeState::Connected(_) => {
                        is_connected = true;
                    }
                _ => {}
                }
            },
            result = network.recv(&mut buffer) => match result {
                Ok(n) => {
                    if n == 0 {
                        warn!("received network packet with 0 bytes, dropping it");
                        continue;
                    }
                    if n > MAX_PACKET_SIZE {
                        warn!("received network packet larger than 65536 bytes, dropping it (check your mtu)");
                        continue;
                    }
                    if let Err(err) = queue.send(buffer[..n].to_vec()).await {
                        error!("failed to send data to data_receiver: {}", err);
                    }
                }
                Err(err) => {
                    state_tx.send(RuntimeState::Error(
                        RuntimeError::IO(format!("failed to receive network: {}",err))
                    )).unwrap();
                }
            }
        }
    }
}
