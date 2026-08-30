use std::net::SocketAddr;
use std::sync::Arc;

use dashmap::DashMap;
use snow::Builder;
use tokio::sync::mpsc;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use super::session::Sessions;
use crate::crypto::{PublicKey, SecretKey};
use crate::gateway::transport::Transport;
use crate::identity::{AccountPublicKey, Enrollment};
use crate::protocol::handshake::{alg_from_hint_byte, params_from_alg};
use crate::protocol::{
    Alg, EncryptedHandshake, HandshakeError, HandshakeResponderBody, HandshakeResponderPayload,
    Packet,
};
use crate::runtime::cred::ServerCredential;

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Reads the first handshake message to recover the device static key, the
/// negotiated algorithm, and the encrypted metadata payload (the device
/// enrollment). The psk is not mixed into the first IKpsk2 message, so this
/// read succeeds without knowing the account's psk.
fn decode_handshake_params(
    handshake: &EncryptedHandshake,
    sk: &SecretKey,
) -> anyhow::Result<(PublicKey, Alg, Enrollment)> {
    let (hint, noise_msg) = handshake
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("empty handshake"))?;
    let alg = alg_from_hint_byte(*hint)
        .ok_or_else(|| anyhow::anyhow!("unknown algorithm hint byte: 0x{:02x}", hint))?;

    let mut buffer = [0u8; 65536];
    let mut responder = Builder::new(params_from_alg(&alg).clone())
        .local_private_key(sk.as_slice())?
        .build_responder()?;
    let len = responder.read_message(noise_msg, &mut buffer)?;
    let enrollment = Enrollment::from_bytes(&buffer[..len])?;

    match responder
        .get_remote_static()
        .map(|bytes: &[u8]| PublicKey::try_from(bytes))
    {
        Some(Ok(key)) => Ok((key, alg, enrollment)),
        Some(Err(e)) => Err(anyhow::anyhow!("invalid remote static key: {}", e)),
        None => Err(anyhow::anyhow!("invalid handshake: missing remote static")),
    }
}

/// Validate a device enrollment against the connecting static key and the
/// account registry. Returns the account the device belongs to.
fn authorize(
    enrollment: &Enrollment,
    device_pk: &PublicKey,
    known_accounts: &DashMap<AccountPublicKey, SecretKey>,
) -> anyhow::Result<SecretKey> {
    if &enrollment.device != device_pk {
        anyhow::bail!("enrollment device key does not match handshake static key");
    }
    enrollment.verify()?;
    if enrollment.is_expired(now_unix()) {
        anyhow::bail!("enrollment expired");
    }
    known_accounts
        .get(&enrollment.account)
        .map(|psk| psk.clone())
        .ok_or_else(|| anyhow::anyhow!("unknown account {}", enrollment.account))
}

/// `noise_msg` must be the handshake payload with the leading algorithm-hint
/// byte already stripped (i.e. `&handshake[1..]`).
async fn complete(
    noise_msg: &[u8],
    cred: &ServerCredential,
    alg: Alg,
    addr: &SocketAddr,
    sessions: &Sessions,
    account: AccountPublicKey,
    device_index: u32,
) -> anyhow::Result<EncryptedHandshake> {
    let mut responder = Builder::new(params_from_alg(&alg).clone())
        .local_private_key(cred.sk.as_slice())?
        .remote_public_key(cred.peer_pk.as_slice())?
        .psk(2, cred.psk.as_bytes())?
        .build_responder()?;

    let mut buffer = [0u8; 65536];
    let _len = responder.read_message(noise_msg, &mut buffer)?;

    let (body, new_sid) = match sessions.next_session_id() {
        Some(sid) => {
            info!("[{}] session created with sid: {}", addr, sid);
            (
                HandshakeResponderBody::Complete(HandshakeResponderPayload { sid }),
                Some(sid),
            )
        }
        None => {
            warn!(
                "[{}] failed to create session: no session id available",
                addr
            );
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

    if let Some(sid) = new_sid {
        sessions.add(
            sid,
            *addr,
            alg,
            responder.into_stateless_transport_mode()?,
            cred.peer_pk.clone(),
            account,
            device_index,
        );
    }

    Ok(buffer[..len].to_vec().into())
}

pub(super) async fn handshake_executor<T: Transport>(
    mut stop: watch::Receiver<bool>,
    mut queue: mpsc::Receiver<(EncryptedHandshake, SocketAddr)>,
    transport: Arc<T>,
    known_accounts: Arc<DashMap<AccountPublicKey, SecretKey>>,
    sessions: Sessions,
    sk: SecretKey,
) {
    // Encode buffer for handshake responses (handshakes are rare, but we still
    // avoid per-call allocation by reusing this buffer across iterations).
    let mut encode_buf = [0u8; 4096];

    loop {
        tokio::select! {
            _ = stop.changed() => break,
            data = queue.recv() => match data {
                Some((handshake, addr)) => match decode_handshake_params(&handshake, &sk) {
                    Ok((peer_pk, alg, enrollment)) => match authorize(&enrollment, &peer_pk, &known_accounts) {
                        Ok(psk) => {
                            let account = enrollment.account.clone();
                            let device_index = enrollment.device_index;
                            let cred = ServerCredential {
                                sk: sk.clone(),
                                psk,
                                peer_pk,
                            };
                            match complete(&handshake[1..], &cred, alg, &addr, &sessions, account, device_index).await {
                                Ok(response) => {
                                    let pkt = Packet::HandshakeResponder(response);
                                    match bincode::encode_into_slice(
                                        &pkt,
                                        &mut encode_buf,
                                        bincode::config::standard(),
                                    ) {
                                        Ok(n) => match transport.send_to(&encode_buf[..n], &addr).await {
                                            Ok(_) => info!("[{}] handshake complete", addr),
                                            Err(e) => warn!("[{}] failed to send handshake response: {}", addr, e),
                                        },
                                        Err(e) => warn!("[{}] failed to encode handshake response: {}", addr, e),
                                    }
                                }
                                Err(err) => warn!("[{}] failed to complete handshake: {}", addr, err),
                            }
                        }
                        Err(e) => {
                            warn!("[{}] rejected handshake: {}", addr, e);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SecretKey;
    use crate::identity::AccountKey;

    fn device_pair() -> (SecretKey, PublicKey) {
        let sk = SecretKey::generate_x25519();
        let pk = PublicKey::from_secret(&sk);
        (sk, pk)
    }

    fn registry(account: &AccountKey, psk: SecretKey) -> DashMap<AccountPublicKey, SecretKey> {
        let map = DashMap::new();
        map.insert(account.public(), psk);
        map
    }

    #[test]
    fn authorize_accepts_valid_enrollment() {
        let account = AccountKey::generate();
        let (_dsk, dpk) = device_pair();
        let psk = SecretKey::generate_x25519();
        let cert = account.issue(&dpk, 0, 0, 0);
        let map = registry(&account, psk.clone());
        let got = authorize(&cert, &dpk, &map).expect("valid enrollment authorized");
        assert_eq!(got.as_bytes(), psk.as_bytes());
    }

    #[test]
    fn authorize_rejects_device_mismatch() {
        let account = AccountKey::generate();
        let (_dsk, dpk) = device_pair();
        let (_osk, other) = device_pair();
        let cert = account.issue(&dpk, 0, 0, 0);
        let map = registry(&account, SecretKey::generate_x25519());
        assert!(authorize(&cert, &other, &map).is_err());
    }

    #[test]
    fn authorize_rejects_unknown_account() {
        let account = AccountKey::generate();
        let (_dsk, dpk) = device_pair();
        let cert = account.issue(&dpk, 0, 0, 0);
        let empty = DashMap::new();
        assert!(authorize(&cert, &dpk, &empty).is_err());
    }

    #[test]
    fn authorize_rejects_tampered_enrollment() {
        let account = AccountKey::generate();
        let (_dsk, dpk) = device_pair();
        let mut cert = account.issue(&dpk, 0, 0, 0);
        cert.device_index = 9;
        let map = registry(&account, SecretKey::generate_x25519());
        assert!(authorize(&cert, &dpk, &map).is_err());
    }

    #[test]
    fn authorize_rejects_expired_enrollment() {
        let account = AccountKey::generate();
        let (_dsk, dpk) = device_pair();
        let cert = account.issue(&dpk, 0, 0, 1);
        let map = registry(&account, SecretKey::generate_x25519());
        assert!(authorize(&cert, &dpk, &map).is_err());
    }
}
