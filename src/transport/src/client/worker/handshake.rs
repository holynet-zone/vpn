use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use lazy_static::lazy_static;
use snow::{Builder, HandshakeState, StatelessTransportState};
use snow::params::NoiseParams;
use tokio::net::UdpSocket;
use tracing::warn;
use super::super::{
    error::RuntimeError
};
use crate::{
    session::{Alg, SessionId},
    client, 
    server
};
use crate::credential::Credential;
use crate::server::packet::HandshakeBody;

lazy_static! {
    static ref NOISE_IK_PSK2_25519_CHACHAPOLY_BLAKE2S: NoiseParams = NoiseParams::from_str("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s").unwrap();
    static ref NOISE_IK_PSK2_25519_AESGCM_BLAKE2S: NoiseParams = NoiseParams::from_str("Noise_IKpsk2_25519_AESGCM_BLAKE2s").unwrap();
}


fn initial(
    payload: &[u8], 
    alg: Alg, 
    cred: &Credential
) -> Result<(client::packet::Handshake, HandshakeState), RuntimeError> {
    let mut initiator = Builder::new(match alg {
        Alg::ChaCha20Poly1305 => NOISE_IK_PSK2_25519_CHACHAPOLY_BLAKE2S.clone(),
        Alg::Aes256 => NOISE_IK_PSK2_25519_AESGCM_BLAKE2S.clone()
    })
        .local_private_key(cred.sk.as_slice())
        .remote_public_key(cred.peer_pk.as_slice())
        .psk(2, cred.psk.as_slice())
        .build_initiator()?;

    let mut buffer = [0u8; 65536];
    let len = initiator.write_message(payload, &mut buffer)?;
    Ok((
        client::packet::Handshake {
            body: buffer[..len].to_vec()
        },
        initiator
    ))
}

fn complete(
    handshake: &server::packet::Handshake, 
    mut initiator: HandshakeState
) -> Result<(HandshakeBody, StatelessTransportState), RuntimeError> {
    let mut buffer = [0u8; 65536];
    let len = initiator.read_message(&handshake.body, &mut buffer)?;
    Ok((
        bincode::deserialize(&buffer[..len])?,
        initiator.into_stateless_transport_mode()?
    ))
}

pub(super) async fn handshake_step(
    socket: Arc<UdpSocket>,
    cred: Credential,
    alg: Alg,
    timeout: Duration,
    payload: Vec<u8>,
    handler: Option<Arc<dyn Fn(SessionId, Vec<u8>) -> Pin<Box<dyn Future<Output = Result<(), RuntimeError>> + Send>> + Send + Sync>>
) -> Result<(SessionId, StatelessTransportState), RuntimeError> {
    // [step 1] Client initial
    let (handshake, handshake_state) = initial(
        &payload,
        alg,
        &cred
    )?;
    
    socket.send(&client::packet::Packet::Handshake(handshake).to_bytes()).await?;

    // [step 2] Server complete
    let mut buffer = [0u8; 65536];
    let resp = tokio::select! {
        _ = tokio::time::sleep(timeout) => Err(RuntimeError::Handshake(
            format!("server timeout ({:?})", timeout)
        )),
        handshake = async { loop {
            let size = socket.recv(&mut buffer).await?;
            match server::packet::Packet::try_from(&buffer[..size]) {
                Ok(server::packet::Packet::Handshake(handshake)) => break Ok(handshake),
                Err(e) => {
                    warn!("failed to parse handshake packet: {}", e);
                    continue;
                },
                _ => {
                    warn!("trash handshake packet");
                    continue;
                }
            }
        }} => handshake,
    }?;

    // [step 3] Client complete
    let (body, transport_state) = complete(&resp, handshake_state)?;
    match body {
        HandshakeBody::Connected { sid, payload } => {
            match handler {
                Some(handler) => handler(sid, payload).await?,
                None => {}
            }
            Ok((sid, transport_state))
        },
        HandshakeBody::Disconnected(err) => match err {
            server::packet::HandshakeError::MaxConnectedDevices(max) => {
                Err(RuntimeError::Handshake(format!("max connected devices: {}", max)))
            },
            server::packet::HandshakeError::ServerOverloaded => {
                Err(RuntimeError::Handshake("server overloaded".into()))
            },
            server::packet::HandshakeError::Unexpected(err) => {
                Err(RuntimeError::Handshake(format!("unexpected server error: {}", err)))
            }
        }
    }
}
