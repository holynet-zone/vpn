use super::Alg;
use super::session::SessionId;
use serde::{Deserialize, Serialize};
use snow::params::NoiseParams;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::LazyLock;

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
