use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
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


static NEXT_TUN_INDEX: AtomicUsize = AtomicUsize::new(0);

pub async fn tun_listener(
    stop_sender: Sender<RuntimeError>,
    mut stop: Receiver<RuntimeError>,
    tun: Arc<AsyncDevice>,
    queues: Vec<mpsc::Sender<Vec<u8>>>
) {
    let queues_len = queues.len();
    let mut index = 0;
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
                    if n > buffer.len() {
                        warn!("received tun packet larger than buffer, dropping it (check your MTU)");
                        continue;
                    }

                    let tx = unsafe{queues.get_unchecked(index % queues_len)};
                    index += 1;
                    if let Err(err) = tx.send(buffer[..n].to_vec()).await {
                        error!("failed to send data to tun queue[{}]: {}", index, err);
                    }
                }
                Err(err) => {
                    let _ = stop_sender.send(RuntimeError::IO(format!("failed to receive tun: {}", err)));
                }
            }
        }
    }
}