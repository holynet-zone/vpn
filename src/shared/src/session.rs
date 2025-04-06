use serde::{Deserialize, Serialize};

pub type SessionId = u32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Alg {
    Aes256,
    ChaCha20Poly1305
}
