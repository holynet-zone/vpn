use std::time::Duration;
use tokio::sync::{broadcast, mpsc};
use tracing::error;
use crate::client;
use crate::client::error::RuntimeError;

pub(super) async fn keepalive_sender(
    mut stop: broadcast::Receiver<RuntimeError>,
    sender: mpsc::Sender<client::packet::DataBody>,
    duration: Duration
) {
    let mut timer = tokio::time::interval(duration);
    loop {
        tokio::select! {
            _ = stop.recv() => break,
            _ = timer.tick() => {
                let body = client::packet::DataBody::KeepAlive(client::packet::KeepAliveBody::new());
                if let Err(e) = sender.send(body).await {
                    error!("failed to send keepalive packet: {}", e); // todo: if channel is full then we can ignore sending
                }
            }
        }
    }
}
