use serde::{Deserialize, Serialize};

pub type SessionId = u32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Alg {
    Aes256,
    ChaCha20Poly1305,
}

impl Default for Alg {
    fn default() -> Self {
        #[cfg(target_arch = "x86_64")]
        if is_x86_feature_detected!("aes") {
            return Alg::Aes256;
        }
        Alg::ChaCha20Poly1305
    }
}
