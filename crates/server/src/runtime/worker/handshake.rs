use std::net::SocketAddr;
use std::sync::Arc;
use dashmap::DashMap;
use snow::{Builder};
use tokio::sync::broadcast::Receiver;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use shared::credential::Credential;
use shared::keys::handshake::{PublicKey, SecretKey};

use super::Sessions;
use shared::handshake::{
    NOISE_IK_PSK2_25519_AESGCM_BLAKE2S,
    NOISE_IK_PSK2_25519_CHACHAPOLY_BLAKE2S,
    params_from_alg
};
use shared::protocol::{EncryptedHandshake, HandshakeError, HandshakeResponderBody, HandshakeResponderPayload, Packet};
use shared::session::Alg;
use crate::runtime::error::RuntimeError;


fn decode_handshake_params(
    handshake: &EncryptedHandshake, 
    sk: &SecretKey
) -> anyhow::Result<(PublicKey, Alg)> {
    let mut buffer = [0u8; 65536];

    let mut responder = Builder::new(NOISE_IK_PSK2_25519_AESGCM_BLAKE2S.clone())
        .local_private_key(sk.as_slice())
        .build_responder()?;

    let alg = match responder.read_message(handshake, &mut buffer) {
        Err(err) => match err {
            snow::Error::Decrypt => {
                responder = Builder::new(NOISE_IK_PSK2_25519_CHACHAPOLY_BLAKE2S.clone())
                    .local_private_key(sk.as_slice())
                    .build_responder()?;
                responder.read_message(handshake, &mut buffer)?;
                Alg::ChaCha20Poly1305
            },
            _ => return Err(anyhow::Error::from(err))
        },
        Ok(_) => Alg::Aes256
    };

    match responder.get_remote_static().map(PublicKey::try_from) {
        Some(key) => Ok((
            key.expect("when decoding handshake params, pk should be valid 32 bytes"), 
            alg
        )),
        None =>  Err(anyhow::anyhow!("invalid handshake"))
    }
}

async fn complete(
    handshake: &[u8],
    cred: &Credential,
    alg: Alg,
    addr: &SocketAddr,
    sessions: &Sessions
) -> anyhow::Result<EncryptedHandshake> {
    let mut responder = Builder::new(params_from_alg(&alg).clone())
        .local_private_key(cred.sk.as_slice())
        .remote_public_key(cred.peer_pk.as_slice())
        .psk(2, cred.psk.as_slice())
        .build_responder()?;
    
    let mut buffer = [0u8; 65536];
    let _len = responder.read_message(handshake, &mut buffer)?; // todo we now dont need msg from client
    let (body, keys) = match sessions.next_session_id().await {
        Some(sid) => match sessions.next_holy_ip().await {
            Some(ipaddr) => {
                info!("[{}] session created with sid: {}", addr, sid);
                (
                    HandshakeResponderBody::Complete(HandshakeResponderPayload { sid, ipaddr }), 
                    Some((sid, ipaddr))
                )
            },
            None => {
                warn!("[{}] failed to create session: ran out of holy ip", addr);
                sessions.release_session_id(&sid).await;
                (HandshakeResponderBody::Disconnect(HandshakeError::ServerOverloaded), None)
            }
        },
        None => {
            warn!("[{}] failed to create session: ran out of sid", addr);
            (HandshakeResponderBody::Disconnect(HandshakeError::ServerOverloaded), None)
        }
    };
    let len = responder.write_message(
        &bincode::serde::encode_to_vec(
            &body,
            bincode::config::standard()
        )?, // todo: may we can use buffer here?
        &mut buffer
    )?;
    if let Some((sid, holy_ip)) = keys {
        sessions.add(sid, holy_ip,  *addr, alg, responder.into_stateless_transport_mode()?);
    }
    Ok(buffer[..len].to_vec().into())
}

pub(super) async fn handshake_executor(
    mut stop: Receiver<RuntimeError>,
    mut queue: mpsc::Receiver<(EncryptedHandshake, SocketAddr)>,
    udp_tx: mpsc::Sender<(Packet, SocketAddr)>,
    known_clients: Arc<DashMap<PublicKey, SecretKey>>,
    sessions: Sessions,
    sk: SecretKey
) {
    loop {
        tokio::select! {
            _ = stop.recv() => break,
            data = queue.recv() => match data {
                Some((handshake, addr)) => match decode_handshake_params(&handshake, &sk) {
                    Ok((peer_pk, alg)) => match known_clients.get(&peer_pk) {
                        Some(psk) => match complete(
                            &handshake, 
                            &Credential { peer_pk, psk: psk.clone(), sk: sk.clone() }, 
                            alg, 
                            &addr, 
                            &sessions
                        ).await {
                            Ok(handshake) => match udp_tx.send((Packet::HandshakeResponder(handshake), addr)).await {
                                Ok(_) => info!("[{}] handshake complete", addr),
                                Err(e) => warn!("[{}] failed to send handshake: {}", addr, e)
                            },
                            Err(err) => {
                                warn!("[{}] failed to complete handshake: {}", addr, err);
                            }
                        }
                        None => {
                            warn!("[{}] received handshake from unknown storage: {}", addr, peer_pk);
                            continue;
                        }
                    },
                    Err(e) => {
                        warn!("[{}] failed to decode handshake params: {}", addr, e);
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
