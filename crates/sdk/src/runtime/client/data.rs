use std::ops::Deref;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::sync::watch::Sender;
use tracing::{info, warn};

use crate::protocol::{DataClientBody, DataServerBody, EncryptedData, Packet, SessionId};
use crate::runtime::crypto::{noise_decrypt, noise_encrypt};
use crate::runtime::error::RuntimeError;
use crate::runtime::state::RuntimeState;
use crate::time::{format_duration_millis, micros_since_start};

pub(super) async fn data_udp_executor(
    state_tx: Sender<RuntimeState>,
    mut queue: mpsc::Receiver<EncryptedData>,
    tun_sender: mpsc::Sender<Vec<u8>>,
) {
    let mut state_rx = state_tx.subscribe();
    let mut state = None;

    loop {
        tokio::select! {
            _ = state_rx.changed() => {
                match state_rx.borrow().deref() {
                    RuntimeState::Error(_) => break,
                    RuntimeState::Connecting => continue,
                    RuntimeState::Connected((_, transport_state)) => {
                        state = Some(transport_state.clone());
                    }
                    _ => {}
                }
            },
            data = queue.recv() => match data {
                Some(data) => {
                    let Some(ref s) = state else {
                        warn!("received data before connected state, dropping");
                        continue;
                    };
                    match noise_decrypt::<DataServerBody>(&data, s) {
                        Ok(data_body) => match data_body {
                            DataServerBody::KeepAlive(time) => {
                                info!("keepalive rtt: {}", format_duration_millis(
                                    time,
                                    micros_since_start()
                                ));
                            }
                            DataServerBody::Disconnect(ref code) => {
                                warn!("got server disconnect code {}", code);
                                if let Err(e) = state_tx.send(RuntimeState::Connecting) {
                                    warn!("state channel closed: {}", e);
                                    break;
                                }
                            }
                            DataServerBody::Packet(payload) => {
                                if let Err(e) = tun_sender.send(payload).await {
                                    warn!("tun channel closed: {}", e);
                                    break;
                                }
                            }
                        },
                        Err(e) => {
                            warn!("received damaged package: {}", e);
                        }
                    }
                }
                None => return,
            }
        }
    }
}

pub(super) async fn data_tun_executor(
    state_tx: Sender<RuntimeState>,
    mut queue: mpsc::Receiver<Vec<u8>>,
    udp_sender: mpsc::Sender<Packet>,
) {
    let mut state_rx = state_tx.subscribe();
    let mut sid = SessionId::default();
    let mut state = None;

    loop {
        tokio::select! {
            _ = state_rx.changed() => {
                match state_rx.borrow().deref() {
                    RuntimeState::Error(_) => break,
                    RuntimeState::Connecting => {}
                    RuntimeState::Connected((payload, transport_state)) => {
                        sid = payload.sid;
                        state = Some(transport_state.clone());
                    }
                    _ => {}
                }
            },
            body = queue.recv() => match body {
                Some(packet) => {
                    let Some(ref s) = state else {
                        warn!("received tun packet before connected state, dropping");
                        continue;
                    };
                    match noise_encrypt(&DataClientBody::Packet(packet), s) {
                        Ok(encrypted) => {
                            if let Err(e) = udp_sender.send(Packet::DataClient { sid, encrypted }).await {
                                warn!("transport channel closed: {}", e);
                                break;
                            }
                        }
                        Err(e) => {
                            if let Err(send_err) = state_tx.send(RuntimeState::Error(
                                RuntimeError::Unexpected(format!("failed to encrypt data: {}", e))
                            )) {
                                warn!("state channel closed: {}", send_err);
                                break;
                            }
                        }
                    }
                }
                None => return,
            }
        }
    }
}

pub(super) async fn keepalive_sender(
    state_tx: Sender<RuntimeState>,
    udp_sender: mpsc::Sender<Packet>,
    duration: Duration,
) {
    let mut keepalive_timer = tokio::time::interval(duration);
    let mut state_wait_timer = tokio::time::interval(Duration::from_secs(1));

    let mut state_rx = state_tx.subscribe();
    let mut sid = SessionId::default();
    let mut state = None;
    let mut is_connected = false;

    loop {
        match state_rx.has_changed() {
            Ok(has_changed) => {
                if has_changed {
                    state_rx.mark_unchanged();
                    match state_rx.borrow().deref() {
                        RuntimeState::Error(_) => break,
                        RuntimeState::Connecting => {
                            is_connected = false;
                        }
                        RuntimeState::Connected((payload, transport_state)) => {
                            sid = payload.sid;
                            state = Some(transport_state.clone());
                            is_connected = true;
                        }
                        _ => {}
                    }
                }
            }
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
            }
            _ = keepalive_timer.tick() => {
                let Some(ref s) = state else { continue; };
                match noise_encrypt(&DataClientBody::KeepAlive(micros_since_start()), s) {
                    Ok(encrypted) => {
                        if let Err(e) = udp_sender.send(Packet::DataClient { sid, encrypted }).await {
                            warn!("transport channel closed: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        if let Err(send_err) = state_tx.send(RuntimeState::Error(
                            RuntimeError::Unexpected(format!("failed to encrypt keepalive: {}", e))
                        )) {
                            warn!("state channel closed: {}", send_err);
                            break;
                        }
                    }
                }
            }
        }
    }
}
