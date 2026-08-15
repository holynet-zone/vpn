use serde::{Deserialize, Serialize};

pub type SessionId = u32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Alg {
    Aes256,
    ChaCha20Poly1305,
}

impl Default for Alg {
    fn default() -> Self {
        // Prefer AES-256 when the CPU has a hardware AES implementation
        // (AES-NI on x86, ARMv8 crypto extensions on aarch64); otherwise
        // ChaCha20-Poly1305 is faster in software.
        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
        if is_x86_feature_detected!("aes") {
            return Alg::Aes256;
        }
        #[cfg(target_arch = "aarch64")]
        if std::arch::is_aarch64_feature_detected!("aes") {
            return Alg::Aes256;
        }
        Alg::ChaCha20Poly1305
    }
}
