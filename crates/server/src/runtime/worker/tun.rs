use std::sync::Arc;
use tokio::sync::broadcast::Receiver;
use tokio::sync::mpsc;
use tracing::{error, warn};
use tun_rs::AsyncDevice;
use crate::runtime::error::RuntimeError;
use crate::runtime::network::parse_source;
use crate::runtime::session::HolyIp;

pub async fn tun_sender(
    mut stop: Receiver<RuntimeError>,
    tun: Arc<AsyncDevice>,
    mut out_tun_rx: mpsc::Receiver<Vec<u8>>
) {
    loop {
        tokio::select! {
            _ = stop.recv() => break,
            result = out_tun_rx.recv() => match result {
                Some(data) => {
                    if let Err(e) = tun.send(&data).await {
                        error!("failed to send data to tun: {}", e);
                        // todo add stop signal
                    }
                },
                None => break
            }
        }
    }
}

pub async fn tun_listener(
    mut stop: Receiver<RuntimeError>,
    tun: Arc<AsyncDevice>,
    data_tun_tx: mpsc::Sender<(Vec<u8>, HolyIp)>
) {
    let mut buffer = [0u8; 65536];
    loop {
        tokio::select! {
            _ = stop.recv() => break,
            result = tun.recv(&mut buffer) => match result {
                Ok(len) => match parse_source(&buffer[..len]) {
                    Ok(ip) => {
                        if let Err(e) = data_tun_tx.send((buffer[..len].to_vec(), ip)).await {
                            error!("failed to send data to tun executor: {}", e);
                        }
                    },
                    Err(e) => {
                        warn!("failed to parse tun packet: {}", e);
                        continue;
                    }
                },
                Err(e) => {
                    error!("failed to receive tun packet: {}", e); // todo add stop signal
                    continue;
                }
            }
        }
    }
}