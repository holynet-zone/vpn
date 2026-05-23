use std::ops::Deref;
use std::time::Duration;

use snow::StatelessTransportState;
use tokio::sync::mpsc;
use tokio::sync::watch::Sender;
use tracing::{info, warn};

use crate::protocol::{DataClientBody, DataServerBody, EncryptedData, Packet, SessionId};
use crate::runtime::error::RuntimeError;
use crate::runtime::state::RuntimeState;
use crate::time::{format_duration_millis, micros_since_start};

fn decrypt_body(
    encrypted: &EncryptedData,
    state: &StatelessTransportState,
) -> anyhow::Result<DataServerBody> {
    let mut buffer = [0u8; 65536];
    state.read_message(0, encrypted, &mut buffer)?;
    match bincode::serde::decode_from_slice(&buffer, bincode::config::standard()) {
        Ok((obj, _)) => Ok(obj),
        Err(err) => Err(anyhow::anyhow!(err)),
    }
}

fn encrypt_body(
    body: &DataClientBody,
    state: &StatelessTransportState,
) -> anyhow::Result<EncryptedData> {
    let mut temp_buffer = [0u8; 65536];
    let encoded_len = bincode::serde::encode_into_slice(
        body,
        &mut temp_buffer,
        bincode::config::standard(),
    )?;

    let mut encrypted_buffer = [0u8; 65536];
    let encrypted_len =
        state.write_message(0, &temp_buffer[..encoded_len], &mut encrypted_buffer)?;

    Ok(encrypted_buffer[..encrypted_len].to_vec().into())
}

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
                Some(data) => match decrypt_body(&data, state.as_deref().unwrap()) {
                    Ok(data_body) => match data_body {
                        DataServerBody::KeepAlive(time) => {
                            info!("keepalive rtt: {}", format_duration_millis(
                                time,
                                micros_since_start()
                            ));
                        }
                        DataServerBody::Disconnect(ref code) => {
                            warn!("got server disconnect code {}", code);
                            state_tx.send(RuntimeState::Connecting).unwrap();
                        }
                        DataServerBody::Packet(payload) => {
                            tun_sender.send(payload.0).await.unwrap();
                        }
                    },
                    Err(e) => {
                        warn!("received damaged package: {}", e);
                    }
                },
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
                Some(packet) => match encrypt_body(
                    &DataClientBody::Packet(packet.into()),
                    state.as_deref().unwrap()
                ) {
                    Ok(encrypted) => {
                        udp_sender.send(Packet::DataClient { sid, encrypted }).await.unwrap();
                    }
                    Err(e) => {
                        state_tx.send(RuntimeState::Error(RuntimeError::Unexpected(
                            format!("failed to encrypt data: {}", e)
                        ))).expect("broken runtime state pipe in data_tun_executor");
                    }
                },
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
                match encrypt_body(
                    &DataClientBody::KeepAlive(micros_since_start()),
                    state.as_deref().unwrap()
                ) {
                    Ok(encrypted) => {
                        udp_sender.send(Packet::DataClient { sid, encrypted }).await.unwrap();
                    }
                    Err(e) => {
                        state_tx.send(RuntimeState::Error(RuntimeError::Unexpected(
                            format!("failed to encrypt keepalive: {}", e)
                        ))).unwrap();
                    }
                }
            }
        }
    }
}
