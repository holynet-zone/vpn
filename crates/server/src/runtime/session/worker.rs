use crate::runtime::{
    error::RuntimeError,
    session::Sessions
};
use std::time::Duration;
use tokio::sync::broadcast::Sender;

pub async fn run(
    stop_tx: Sender<RuntimeError>,
    sessions: Sessions,
    timeout: Duration,
    cleanup_interval: Duration,
) {
    let mut stop = stop_tx.subscribe();
    let mut timer = tokio::time::interval(cleanup_interval);
    loop {
        tokio::select! {
            _ = stop.recv() => break,
            _ = timer.tick() => sessions.cleanup_sessions(timeout).await
        }
    }
}
