use std::str::FromStr;
use lazy_static::lazy_static;
use snow::params::NoiseParams;
use crate::session::Alg;

lazy_static! {
    pub static ref NOISE_IK_PSK2_25519_CHACHAPOLY_BLAKE2S: NoiseParams = NoiseParams::from_str("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s").unwrap();
    pub static ref NOISE_IK_PSK2_25519_AESGCM_BLAKE2S: NoiseParams = NoiseParams::from_str("Noise_IKpsk2_25519_AESGCM_BLAKE2s").unwrap();
}

pub fn params_from_alg(alg: &Alg) -> &'static NoiseParams {
    match alg {
        Alg::ChaCha20Poly1305 => &NOISE_IK_PSK2_25519_CHACHAPOLY_BLAKE2S,
        Alg::Aes256 => &NOISE_IK_PSK2_25519_AESGCM_BLAKE2S
    }
}