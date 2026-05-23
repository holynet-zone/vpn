use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Serialize, Deserialize)]
pub struct SecretKey([u8; 32]);

impl SecretKey {
    pub fn generate_x25519() -> Self {
        use rand_core::OsRng;
        use x25519_dalek::StaticSecret;
        let secret = StaticSecret::random_from_rng(OsRng);
        Self(secret.to_bytes())
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", STANDARD_NO_PAD.encode(&self.0))
    }
}

impl From<[u8; 32]> for SecretKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl TryFrom<&[u8]> for SecretKey {
    type Error = &'static str;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        bytes.try_into()
            .map(Self)
            .map_err(|_| "secret key must be exactly 32 bytes")
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    pub fn from_secret(secret: &SecretKey) -> Self {
        use x25519_dalek::{PublicKey as DalekPK, StaticSecret};
        let sk = StaticSecret::from(secret.0);
        let pk = DalekPK::from(&sk);
        Self(pk.to_bytes())
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", STANDARD_NO_PAD.encode(&self.0))
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = &'static str;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        bytes.try_into()
            .map(Self)
            .map_err(|_| "public key must be exactly 32 bytes")
    }
}
