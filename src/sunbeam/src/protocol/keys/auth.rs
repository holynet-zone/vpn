use crate::protocol::enc::kdf;
use super::Key;

const AUTH_KEY_SIZE: usize = 32;

pub type AuthKey = Key<AUTH_KEY_SIZE>;

impl AuthKey {
    pub fn derive_from(password: &[u8], salt: &[u8]) -> Self {
        let key = env!("DERIVATION_KEY").as_bytes().to_vec();
        Self(kdf::derive_key(salt, password, &key))
    }
}
