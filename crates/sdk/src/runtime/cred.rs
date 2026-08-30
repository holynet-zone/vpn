use crate::crypto::{PublicKey, SecretKey};
use crate::identity::Enrollment;

pub struct Cred {
    pub sk: SecretKey,
    pub psk: SecretKey,
    /// Server public key
    pub spk: PublicKey,
    /// Account-signed device enrollment, sent inside the encrypted handshake
    /// metadata so the node can attribute the device without pre-provisioning
    /// its static key.
    pub enrollment: Enrollment,
}

pub struct ServerCredential {
    pub sk: SecretKey,
    pub psk: SecretKey,
    /// Client's public key
    pub peer_pk: PublicKey,
}
