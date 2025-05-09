use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch::Sender;
use tokio::sync::mpsc;
use tracing::{error, warn};
use tun_rs::AsyncDevice;
use crate::runtime::error::RuntimeError;
use crate::runtime::state::RuntimeState;

pub async fn tun_sender(
    state_tx: Sender<RuntimeState>,
    tun: Arc<AsyncDevice>,
    mut queue: mpsc::Receiver<Vec<u8>>
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
                Some(packet) => {
                    if let Err(err) = tun.send(&packet).await {
                        state_tx.send(RuntimeState::Error(
                            RuntimeError::IO(format!("failed to send tun: {}", err))
                        )).unwrap();
                    }
                },
                None => break
            }
        }
    }
}

pub async fn tun_listener(
    state_tx: Sender<RuntimeState>,
    tun: Arc<AsyncDevice>,
    queue: mpsc::Sender<Vec<u8>>
) {
    let mut state_wait_timer = tokio::time::interval(Duration::from_secs(1));

    let mut state_rx = state_tx.subscribe();
    let mut is_connected = false;
    let mut buffer = [0u8; 65536];
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
            result = tun.recv(&mut buffer) => match result {
                Ok(n) => {
                    if n == 0 {
                        warn!("received tun packet with 0 bytes, dropping it");
                        continue;
                    }
                    if n > 65536 {
                        warn!("received tun packet larger than 65536 bytes, dropping it (check ur mtu)");
                        continue;
                    }
                    if let Err(err) = queue.send(buffer[..n].to_vec()).await {
                        error!("failed to send data to data_receiver: {}", err);
                    }
                }
                Err(err) => {
                    state_tx.send(RuntimeState::Error(
                        RuntimeError::IO(format!("failed to receive tun: {}",err))
                    )).unwrap();
                }
            }
        }
    }
}

