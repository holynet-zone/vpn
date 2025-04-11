use std::net::SocketAddr;
use std::sync::Arc;
use dashmap::DashMap;
use snow::{Builder};
use tokio::sync::broadcast::Receiver;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use shared::client;
use shared::credential::Credential;
use shared::keys::handshake::{PublicKey, SecretKey};

use super::Sessions;
use shared::handshake::{
    NOISE_IK_PSK2_25519_AESGCM_BLAKE2S,
    NOISE_IK_PSK2_25519_CHACHAPOLY_BLAKE2S,
    params_from_alg
};
use shared::server::packet::{Handshake, HandshakeBody, HandshakePayload, HandshakeError, Packet};
use shared::session::Alg;
use crate::runtime::error::RuntimeError;


fn decode_handshake_params(
    handshake: &client::packet::Handshake, 
    sk: &SecretKey
) -> anyhow::Result<(PublicKey, Alg)> {
    let mut buffer = [0u8; 65536];

    let mut responder = Builder::new(NOISE_IK_PSK2_25519_AESGCM_BLAKE2S.clone())
        .local_private_key(sk.as_slice())
        .build_responder()?;

    let alg = match responder.read_message(&handshake.body, &mut buffer) {
        Err(err) => match err {
            snow::Error::Decrypt => {
                responder = Builder::new(NOISE_IK_PSK2_25519_CHACHAPOLY_BLAKE2S.clone())
                    .local_private_key(sk.as_slice())
                    .build_responder()?;
                responder.read_message(&handshake.body, &mut buffer)?;
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
    handshake: &client::packet::Handshake,
    cred: &Credential,
    alg: Alg,
    addr: &SocketAddr,
    sessions: &Sessions
) -> anyhow::Result<Handshake> {
    let mut responder = Builder::new(params_from_alg(&alg).clone())
        .local_private_key(cred.sk.as_slice())
        .remote_public_key(cred.peer_pk.as_slice())
        .psk(2, cred.psk.as_slice())
        .build_responder()?;
    
    let mut buffer = [0u8; 65536];
    let _len = responder.read_message(&handshake.body, &mut buffer)?; // todo we now dont need msg from client
    let (body, sid) = match sessions.add(addr.clone(), alg, None).await {
        Some((sid, holy_ip)) => {
            info!("[{}] session created with sid: {}", addr, sid);
            let handshake_payload = HandshakePayload {
                sid,
                ipaddr: holy_ip
            };
            (HandshakeBody::Connected(handshake_payload), Some(sid))
        },
        None => {
            warn!("[{}] failed to create session: overload", addr);
            (HandshakeBody::Disconnected(HandshakeError::ServerOverloaded), None)
        }
    };
    let len = responder.write_message(&bincode::serialize(&body)?, &mut buffer)?;
    if let Some(sid) = sid {
        sessions.set_transport_state(&sid, responder.into_stateless_transport_mode()?);
    }
    Ok(Handshake {
        body: buffer[..len].to_vec() // FIXME: remove copy
    })
    
    
}

pub(super) async fn handshake_executor(
    mut stop: Receiver<RuntimeError>,
    mut queue: mpsc::Receiver<(client::packet::Handshake, SocketAddr)>,
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
                            Ok(handshake) => match udp_tx.send((Packet::Handshake(handshake), addr)).await {
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
