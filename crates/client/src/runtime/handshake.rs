use std::sync::Arc;
use std::time::Duration;
use snow::{Builder, HandshakeState, StatelessTransportState};
use tokio::select;
use tracing::warn;
use shared::connection_config::CredentialsConfig;
use shared::handshake::{
    NOISE_IK_PSK2_25519_CHACHAPOLY_BLAKE2S,
    NOISE_IK_PSK2_25519_AESGCM_BLAKE2S
};
use shared::protocol::{
    EncryptedHandshake,
    HandshakeError,
    HandshakeResponderBody,
    HandshakeResponderPayload,
    Packet
};
use shared::session::Alg;
use super::{
    error::RuntimeError,
    transport::Transport
};


fn initial(
    alg: Alg,
    cred: &CredentialsConfig
) -> Result<(EncryptedHandshake, HandshakeState), RuntimeError> {
    let mut initiator = Builder::new(match alg {
        Alg::ChaCha20Poly1305 => NOISE_IK_PSK2_25519_CHACHAPOLY_BLAKE2S.clone(),
        Alg::Aes256 => NOISE_IK_PSK2_25519_AESGCM_BLAKE2S.clone()
    })
        .local_private_key(cred.private_key.as_slice())
        .remote_public_key(cred.server_public_key.as_slice())
        .psk(2, cred.pre_shared_key.as_slice())
        .build_initiator()?;

    let mut buffer = [0u8; 65536];
    let len = initiator.write_message(&[], &mut buffer)?;
    Ok((buffer[..len].to_vec().into(), initiator))
}

fn complete(
    handshake: &EncryptedHandshake,
    mut initiator: HandshakeState
) -> Result<(HandshakeResponderBody, StatelessTransportState), RuntimeError> {
    let mut buffer = [0u8; 65536];
    let len = initiator.read_message(handshake, &mut buffer)?;
    match bincode::serde::decode_from_slice(&buffer[..len], bincode::config::standard()) {
        Ok((body, _)) => Ok((body, initiator.into_stateless_transport_mode()?)),
        Err(err) => Err(RuntimeError::Handshake(
            format!("decode handshake complete packet: {}", err)
        ))
    }
}

pub async fn handshake_step(
    transport: Arc<dyn Transport>,
    cred: CredentialsConfig,
    alg: Alg,
    timeout: Duration
) -> Result<(HandshakeResponderPayload, StatelessTransportState), RuntimeError> {
    // [step 1] Client initial
    let (handshake, handshake_state) = initial(
        alg,
        &cred
    )?;

    transport.send(&Packet::HandshakeInitial(handshake).to_bytes()).await?;

    // [step 2] Server complete
    let mut buffer = [0u8; 65536];
    let resp = select! {
        _ = tokio::time::sleep(timeout) => Err(RuntimeError::Handshake(
            format!("server timeout ({:?})", timeout)
        )),
        handshake = async { loop {
            let size = transport.recv(&mut buffer).await.map_err(
                |err| RuntimeError::IO(format!("receive handshake: {}", err))
            )?;
            match Packet::try_from(&buffer[..size]) {
                Ok(Packet::HandshakeResponder(handshake)) => break Ok(handshake),
                Err(err) => {
                    warn!("parse handshake packet: {}", err);
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
        HandshakeResponderBody::Complete(payload) => Ok((payload, transport_state)),
        HandshakeResponderBody::Disconnect(err) => match err {
            HandshakeError::MaxConnectedDevices(max) => {
                Err(RuntimeError::Handshake(format!("max connected devices: {}", max)))
            },
            HandshakeError::ServerOverloaded => {
                Err(RuntimeError::Handshake("server overloaded".into()))
            },
            HandshakeError::Unexpected(err) => {
                Err(RuntimeError::Handshake(format!("unexpected server error: {}", err)))
            }
        }
    }
}