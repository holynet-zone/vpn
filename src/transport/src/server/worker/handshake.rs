use std::net::SocketAddr;
use std::sync::Arc;
use dashmap::DashMap;
use snow::{Builder, HandshakeState};
use tokio::sync::broadcast::Receiver;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use crate::{client, server};
use crate::keys::handshake::{PublicKey, SecretKey};
use crate::server::error::RuntimeError;
use crate::server::packet::Handshake;
use crate::server::session::Sessions;
use crate::session::Alg;
use crate::handshake::{
    NOISE_IK_PSK2_25519_AESGCM_BLAKE2S,
    NOISE_IK_PSK2_25519_CHACHAPOLY_BLAKE2S,
    params_from_alg
};

fn decode_handshake_params(
    handshake: &client::packet::Handshake, 
    sk: &SecretKey
) -> anyhow::Result<(PublicKey, Alg)> {
    let mut client_pk = [0u8; 32];
    let mut buffer = [0u8; 65536];

    let mut responder = Builder::new(NOISE_IK_PSK2_25519_AESGCM_BLAKE2S.clone())
        .local_private_key(sk.as_slice())
        .build_responder()?;

    responder.read_message(&handshake.body, &mut buffer)?;
    if let Some(client_pk) = responder.get_remote_static().map(|pk| {
        client_pk.copy_from_slice(pk);
        PublicKey::from(client_pk)
    }) {
        return Ok((client_pk, Alg::Aes256))
    }

    responder = Builder::new(NOISE_IK_PSK2_25519_CHACHAPOLY_BLAKE2S.clone())
        .local_private_key(sk.as_slice())
        .build_responder()?;

    responder.read_message(&handshake.body, &mut buffer)?;
    if let Some(client_pk) = responder.get_remote_static().map(|pk| {
        client_pk.copy_from_slice(pk);
        PublicKey::from(client_pk)
    }) {
        return Ok((client_pk, Alg::ChaCha20Poly1305))
    }

    Err(anyhow::anyhow!("key or params is invalid"))
}

fn complete(
    handshake: &client::packet::Handshake,
    sk: &SecretKey,
    psk: &SecretKey,
    client_pk: &PublicKey,
    alg: Alg,
    sessions: Sessions
) -> anyhow::Result<(server::packet::HandshakeBody, HandshakeState)> {
    let mut responder = Builder::new(match alg {
        Alg::ChaCha20Poly1305 => NOISE_IK_PSK2_25519_CHACHAPOLY_BLAKE2S.clone(),
        Alg::Aes256 => NOISE_IK_PSK2_25519_AESGCM_BLAKE2S.clone()
    })
        .local_private_key(sk.as_slice())
        .remote_public_key(client_pk.as_slice())
        .psk(2, psk.as_slice())
        .build_responder()?;


    let mut buffer = [0u8; 65536];
    let len = responder.read_message(&handshake.body, &mut buffer)?;
    let body = bincode::deserialize(&buffer[..len])?;
    let (body, sid) = match sessions.add(addr, alg, None).await {
        Some(sid) => {
            info!("[{}] session created with sid: {}", addr, sid);
            (server::packet::HandshakeBody::Connected {
                sid: sid.clone(),
                payload: vec![]
            }, Some(sid))
        },
        None => {
            warn!("[{}] failed to create session: overload", addr);
            (server::packet::HandshakeBody::Disconnected(
                HandshakeError::ServerOverloaded
            ), None)
        }
    };
    
}

async fn handshake_executor(
    mut stop: Receiver<RuntimeError>,
    mut queue: mpsc::Receiver<(client::packet::Handshake, SocketAddr)>,
    udp_tx: mpsc::Sender<(server::packet::Packet, SocketAddr)>,
    known_clients: Arc<DashMap<PublicKey, SecretKey>>,
    sessions: Sessions,
    sk: SecretKey
) {
    loop {
        tokio::select! {
            _ = stop.recv() => break,
            data = queue.recv() => match data {
                Some((handshake, addr)) => match decode_handshake_params(&handshake, &sk) {
                    Ok((client_pk, alg)) => match known_clients.get(&client_pk) {
                        Some(psk) => match handshake.try_decode(&sk, &psk, &client_pk, &alg) {
                            Ok((_, state)) => {
                                let (body, sid) = match sessions.add(addr, alg, None).await {
                                    Some(sid) => {
                                        info!("[{}] session created with sid: {}", addr, sid);
                                        (server::packet::HandshakeBody::Connected {
                                            sid: sid.clone(),
                                            payload: vec![]
                                        }, Some(sid))
                                    },
                                    None => {
                                        warn!("[{}] failed to create session: overload", addr);
                                        (server::packet::HandshakeBody::Disconnected(
                                            HandshakeError::ServerOverloaded
                                        ), None)
                                    }
                                };
                                match server::packet::Handshake::complete(&body, state) {
                                    Ok((handshake, state)) => {
                                        if let Some(sid) = sid {
                                            sessions.set_transport_state(&sid, state);
                                        }
                                        if let Err(e) = udp_tx.send((server::packet::Packet::Handshake(handshake), addr)).await {
                                            error!("failed to send server handshake packet to udp queue: {}", e);
                                        }
                                    },
                                    Err(e) => {
                                        warn!("[{}] failed to encode handshake (last receive): {}", addr, e);
                                    }
                                }
                            },
                            Err(e) => {
                                warn!("[{}] failed to decode handshake (step 2): {}", addr, e);
                                continue;
                            }
                        },
                        None => {
                            warn!("[{}] received handshake from unknown client: {}", addr, client_pk);
                            continue;
                        }
                    },
                    Err(e) => {
                        warn!("[{}] failed to decode handshake (step 1): {}", addr, e);
                        continue;
                    }
                },
                None => {
                    error!("handshake_executor channel is closed");
                    break
                }
            }
        }
    }
}