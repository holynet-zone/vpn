use rand_core::OsRng;
use super::Key;


pub type SecretKey = Key<32>;
pub type PublicKey = Key<32>;

impl PublicKey {
    pub fn derive_from(secret: SecretKey) -> Self {
        Self::from(x25519_dalek::PublicKey::from(
            &x25519_dalek::StaticSecret::from(Into::<[u8; 32]>::into(secret))
        ).to_bytes())
    }
}

impl SecretKey {
    pub fn generate_x25519() -> Self { x25519_dalek::StaticSecret::random_from_rng(OsRng).into() }
}

impl Into<x25519_dalek::PublicKey> for PublicKey {
    fn into(self) -> x25519_dalek::PublicKey {
        x25519_dalek::PublicKey::from(self.0)
    }
}

impl Into<x25519_dalek::StaticSecret> for SecretKey {
    fn into(self) -> x25519_dalek::StaticSecret {
        x25519_dalek::StaticSecret::from(self.0)
    }
}

impl From<x25519_dalek::PublicKey> for PublicKey {
    fn from(key: x25519_dalek::PublicKey) -> Self {
        Self::from(key.to_bytes())
    }
}

impl From<x25519_dalek::StaticSecret> for SecretKey {
    fn from(key: x25519_dalek::StaticSecret) -> Self {
        Self::from(key.to_bytes())
    }
}
