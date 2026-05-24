use super::Alg;
use super::session::SessionId;
use serde::{Deserialize, Serialize};
use snow::params::NoiseParams;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::LazyLock;

/// Single-byte algorithm hint prepended to every `HandshakeInitial` payload.
///
/// Lets the server select the correct Noise params on the first read without
/// a decrypt-then-retry heuristic.
pub fn alg_hint_byte(alg: &Alg) -> u8 {
    match alg {
        Alg::Aes256 => 0x01,
        Alg::ChaCha20Poly1305 => 0x02,
    }
}

pub fn alg_from_hint_byte(b: u8) -> Option<Alg> {
    match b {
        0x01 => Some(Alg::Aes256),
        0x02 => Some(Alg::ChaCha20Poly1305),
        _ => None,
    }
}

pub static NOISE_IK_PSK2_25519_CHACHAPOLY_BLAKE2S: LazyLock<NoiseParams> =
    LazyLock::new(|| NoiseParams::from_str("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s").unwrap());

pub static NOISE_IK_PSK2_25519_AESGCM_BLAKE2S: LazyLock<NoiseParams> =
    LazyLock::new(|| NoiseParams::from_str("Noise_IKpsk2_25519_AESGCM_BLAKE2s").unwrap());

pub fn params_from_alg(alg: &Alg) -> &'static NoiseParams {
    match alg {
        Alg::ChaCha20Poly1305 => &NOISE_IK_PSK2_25519_CHACHAPOLY_BLAKE2S,
        Alg::Aes256 => &NOISE_IK_PSK2_25519_AESGCM_BLAKE2S,
    }
}

#[derive(Serialize, Deserialize)]
pub enum HandshakeResponderBody {
    Complete(HandshakeResponderPayload),
    Disconnect(HandshakeError),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HandshakeResponderPayload {
    pub sid: SessionId,
    pub ipaddr: IpAddr,
}

#[derive(Serialize, Deserialize)]
pub enum HandshakeError {
    /// Server limit on connected devices per credential
    MaxConnectedDevices(u32),
    /// No available IP addresses or session identifiers
    ServerOverloaded,
    /// Malformed request
    Unexpected(String),
}
