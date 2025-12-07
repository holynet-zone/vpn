use serde::{Deserialize, Serialize};

pub type SessionId = u32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Alg {
    Aes256,
    ChaCha20Poly1305
}


impl Default for Alg {
    fn default() -> Self {
        todo!("need default for system support!!!")
    }
    
}