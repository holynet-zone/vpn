use std::sync::Arc;
use tokio::sync::broadcast::{Receiver, Sender};
use tokio::sync::mpsc;
use tracing::{error, warn};
use tun_rs::AsyncDevice;
use crate::runtime::error::RuntimeError;

pub async fn tun_sender(
    stop_sender: Sender<RuntimeError>,
    mut stop: Receiver<RuntimeError>,
    tun: Arc<AsyncDevice>,
    mut queue: mpsc::Receiver<Vec<u8>>
) {
    loop {
        tokio::select! {
            _ = stop.recv() => break,
            result = queue.recv() => match result {
                Some(packet) => {
                    if let Err(err) = tun.send(&packet).await {
                        stop_sender.send(RuntimeError::IO(format!("failed to send tun: {}", err))).unwrap();
                    }
                },
                None => break
            }
        }
    }
}

pub async fn tun_listener(
    stop_sender: Sender<RuntimeError>,
    mut stop: Receiver<RuntimeError>,
    tun: Arc<AsyncDevice>,
    queue: mpsc::Sender<Vec<u8>>
) {
    let mut buffer = [0u8; 65536];
    loop {
        tokio::select! {
            _ = stop.recv() => break,
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
                    stop_sender.send(RuntimeError::IO(format!("failed to receive tun: {}",err))).unwrap();
                }
            }
        }
    }
}

