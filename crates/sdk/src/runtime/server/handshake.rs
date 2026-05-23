use std::net::SocketAddr;
use std::sync::Arc;

use dashmap::DashMap;
use snow::Builder;
use tokio::sync::mpsc;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::crypto::{PublicKey, SecretKey};
use crate::protocol::{
    Alg, EncryptedHandshake, HandshakeError, HandshakeResponderBody, HandshakeResponderPayload,
    Packet,
};
use crate::protocol::handshake::{
    params_from_alg, NOISE_IK_PSK2_25519_AESGCM_BLAKE2S, NOISE_IK_PSK2_25519_CHACHAPOLY_BLAKE2S,
};
use crate::runtime::cred::ServerCredential;
use super::session::Sessions;

fn decode_handshake_params(
    handshake: &EncryptedHandshake,
    sk: &SecretKey,
) -> anyhow::Result<(PublicKey, Alg)> {
    let mut buffer = [0u8; 65536];

    let mut responder = Builder::new(NOISE_IK_PSK2_25519_AESGCM_BLAKE2S.clone())
        .local_private_key(sk.as_slice())?
        .build_responder()?;

    let alg = match responder.read_message(handshake, &mut buffer) {
        Ok(_) => Alg::Aes256,
        Err(snow::Error::Decrypt) => {
            responder = Builder::new(NOISE_IK_PSK2_25519_CHACHAPOLY_BLAKE2S.clone())
                .local_private_key(sk.as_slice())?
                .build_responder()?;
            responder.read_message(handshake, &mut buffer)?;
            Alg::ChaCha20Poly1305
        }
        Err(err) => return Err(anyhow::Error::from(err)),
    };

    match responder.get_remote_static().map(|bytes: &[u8]| PublicKey::try_from(bytes)) {
        Some(Ok(key)) => Ok((key, alg)),
        Some(Err(e)) => Err(anyhow::anyhow!("invalid remote static key: {}", e)),
        None => Err(anyhow::anyhow!("invalid handshake: missing remote static")),
    }
}

async fn complete(
    handshake: &[u8],
    cred: &ServerCredential,
    alg: Alg,
    addr: &SocketAddr,
    sessions: &Sessions,
) -> anyhow::Result<EncryptedHandshake> {
    let mut responder = Builder::new(params_from_alg(&alg).clone())
        .local_private_key(cred.sk.as_slice())?
        .remote_public_key(cred.peer_pk.as_slice())?
        .psk(2, cred.psk.as_bytes())?
        .build_responder()?;

    let mut buffer = [0u8; 65536];
    let _len = responder.read_message(handshake, &mut buffer)?;

    let (body, keys) = match sessions.next_session_id() {
        Some(sid) => match sessions.next_holy_ip() {
            Some(ipaddr) => {
                info!("[{}] session created with sid: {}", addr, sid);
                (
                    HandshakeResponderBody::Complete(HandshakeResponderPayload { sid, ipaddr }),
                    Some((sid, ipaddr)),
                )
            }
            None => {
                warn!("[{}] failed to create session: no holy ip available", addr);
                sessions.release_session_id(&sid);
                (
                    HandshakeResponderBody::Disconnect(HandshakeError::ServerOverloaded),
                    None,
                )
            }
        },
        None => {
            warn!("[{}] failed to create session: no session id available", addr);
            (
                HandshakeResponderBody::Disconnect(HandshakeError::ServerOverloaded),
                None,
            )
        }
    };

    let len = responder.write_message(
        &bincode::serde::encode_to_vec(&body, bincode::config::standard())?,
        &mut buffer,
    )?;

    if let Some((sid, holy_ip)) = keys {
        sessions.add(sid, holy_ip, *addr, alg, responder.into_stateless_transport_mode()?);
    }

    Ok(buffer[..len].to_vec().into())
}

pub(super) async fn handshake_executor(
    mut stop: watch::Receiver<bool>,
    mut queue: mpsc::Receiver<(EncryptedHandshake, SocketAddr)>,
    transport_tx: mpsc::Sender<(Packet, SocketAddr)>,
    known_clients: Arc<DashMap<PublicKey, SecretKey>>,
    sessions: Sessions,
    sk: SecretKey,
) {
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            data = queue.recv() => match data {
                Some((handshake, addr)) => match decode_handshake_params(&handshake, &sk) {
                    Ok((peer_pk, alg)) => match known_clients.get(&peer_pk) {
                        Some(psk) => {
                            let cred = ServerCredential {
                                sk: sk.clone(),
                                psk: psk.clone(),
                                peer_pk,
                            };
                            match complete(&handshake, &cred, alg, &addr, &sessions).await {
                                Ok(response) => {
                                    match transport_tx.send((Packet::HandshakeResponder(response), addr)).await {
                                        Ok(_) => info!("[{}] handshake complete", addr),
                                        Err(e) => warn!("[{}] failed to send handshake response: {}", addr, e),
                                    }
                                }
                                Err(err) => warn!("[{}] failed to complete handshake: {}", addr, err),
                            }
                        }
                        None => {
                            warn!("[{}] received handshake from unknown client: {}", addr, peer_pk);
                        }
                    },
                    Err(e) => warn!("[{}] failed to decode handshake params: {}", addr, e),
                },
                None => {
                    debug!("handshake_executor channel closed");
                    break;
                }
            }
        }
    }
}
