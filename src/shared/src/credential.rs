use crate::keys::handshake::{PublicKey, SecretKey};

#[derive(Clone)]
pub struct Credential {
    pub sk: SecretKey,
    pub psk: SecretKey,
    pub peer_pk: PublicKey
}