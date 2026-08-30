use snow::{Builder, HandshakeState, StatelessTransportState};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::select;
use tracing::warn;

use crate::gateway::transport::ClientTransport;
use crate::protocol::handshake::{alg_hint_byte, params_from_alg};
use crate::protocol::{
    Alg, DataClientBody, EncryptedHandshake, HandshakeError, HandshakeResponderBody,
    HandshakeResponderPayload, Packet, PacketRef, SessionId,
};
use crate::runtime::cred::Cred;
use crate::runtime::crypto::{
    DataServerActionRef, encode_data_client_frame, noise_decrypt_data_server_into, noise_encrypt,
};
use crate::runtime::error::RuntimeError;
use crate::runtime::state::ClientSession;

fn initial(alg: &Alg, cred: &Cred) -> Result<(EncryptedHandshake, HandshakeState), RuntimeError> {
    let mut initiator = Builder::new(params_from_alg(alg).clone())
        .local_private_key(cred.sk.as_slice())?
        .remote_public_key(cred.spk.as_slice())?
        .psk(2, cred.psk.as_bytes())?
        .build_initiator()?;

    let mut buffer = [0u8; 65536];
    let len = initiator.write_message(&cred.enrollment.to_bytes(), &mut buffer)?;
    // Prepend a 1-byte algorithm hint so the server can select the correct
    // Noise params on first read without a decrypt-then-retry heuristic.
    let mut msg = Vec::with_capacity(1 + len);
    msg.push(alg_hint_byte(alg));
    msg.extend_from_slice(&buffer[..len]);
    Ok((msg.into(), initiator))
}

fn complete(
    handshake: &EncryptedHandshake,
    mut initiator: HandshakeState,
) -> Result<(HandshakeResponderBody, StatelessTransportState), RuntimeError> {
    let mut buffer = [0u8; 65536];
    let len = initiator.read_message(handshake, &mut buffer)?;
    match bincode::serde::decode_from_slice(&buffer[..len], bincode::config::standard()) {
        Ok((body, _)) => Ok((body, initiator.into_stateless_transport_mode()?)),
        Err(err) => Err(RuntimeError::Handshake(format!(
            "decode handshake complete packet: {}",
            err
        ))),
    }
}

pub async fn handshake_step<T: ClientTransport>(
    transport: Arc<T>,
    cred: &Cred,
    alg: &Alg,
    timeout: Duration,
) -> Result<(HandshakeResponderPayload, StatelessTransportState), RuntimeError> {
    let (handshake, handshake_state) = initial(alg, cred)?;
    transport
        .send(&Packet::HandshakeInitial(handshake).to_bytes())
        .await?;

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
                }
                _ => {
                    warn!("unexpected packet during handshake");
                    continue;
                }
            }
        }} => handshake,
    }?;

    let (body, transport_state) = complete(&resp, handshake_state)?;
    match body {
        HandshakeResponderBody::Complete(payload) => Ok((payload, transport_state)),
        HandshakeResponderBody::Disconnect(err) => match err {
            HandshakeError::MaxConnectedDevices(max) => Err(RuntimeError::Handshake(format!(
                "max connected devices: {}",
                max
            ))),
            HandshakeError::ServerOverloaded => {
                Err(RuntimeError::Handshake("server overloaded".into()))
            }
            HandshakeError::Unexpected(err) => Err(RuntimeError::Handshake(format!(
                "unexpected server error: {}",
                err
            ))),
        },
    }
}

pub async fn lease_step<T: ClientTransport>(
    transport: Arc<T>,
    session: &ClientSession,
    sid: SessionId,
    timeout: Duration,
) -> Result<IpAddr, RuntimeError> {
    let nonce = session.send_nonce.fetch_add(1, Ordering::Relaxed);
    let encrypted = noise_encrypt(&DataClientBody::LeaseRequest, &session.noise, nonce)
        .map_err(|e| RuntimeError::Handshake(format!("lease encrypt: {}", e)))?;
    let mut out = [0u8; 128];
    let n = encode_data_client_frame(sid, nonce, &encrypted, &mut out);
    transport.send(&out[..n]).await?;

    let mut buffer = [0u8; 65536];
    let mut plain = [0u8; 65536];
    select! {
        _ = tokio::time::sleep(timeout) => Err(RuntimeError::Handshake(
            format!("lease timeout ({:?})", timeout)
        )),
        res = async { loop {
            let size = transport.recv(&mut buffer).await.map_err(
                |err| RuntimeError::IO(format!("receive lease: {}", err))
            )?;
            match PacketRef::from_bytes(&buffer[..size]) {
                Some(PacketRef::DataServer { nonce, ciphertext }) => {
                    match noise_decrypt_data_server_into(ciphertext, &session.noise, &mut plain, nonce) {
                        Ok(DataServerActionRef::LeaseGrant(ip)) => break Ok(ip),
                        Ok(DataServerActionRef::Disconnect(code)) => break Err(
                            RuntimeError::Handshake(format!("lease refused (code {})", code))
                        ),
                        Ok(_) => continue,
                        Err(e) => { warn!("decrypt lease response: {}", e); continue; }
                    }
                }
                _ => continue,
            }
        }} => res,
    }
}
