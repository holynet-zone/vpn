use crate::crypto::{PublicKey, SecretKey};

pub struct Cred {
    pub sk: SecretKey,
    pub psk: SecretKey,
    /// Server public key
    pub spk: PublicKey,
}

pub struct ServerCredential {
    pub sk: SecretKey,
    pub psk: SecretKey,
    /// Client's public key
    pub peer_pk: PublicKey,
}
