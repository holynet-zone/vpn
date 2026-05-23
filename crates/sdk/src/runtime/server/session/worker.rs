use super::Sessions;
use std::time::Duration;
use tokio::sync::watch;

pub async fn run(
    mut stop: watch::Receiver<bool>,
    sessions: Sessions,
    timeout: Duration,
    cleanup_interval: Duration,
) {
    let mut timer = tokio::time::interval(cleanup_interval);
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            _ = timer.tick() => sessions.cleanup_sessions(timeout),
        }
    }
}
