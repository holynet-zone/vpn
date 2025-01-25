use serde::{Deserialize, Serialize};
use clap::ValueEnum;
use strum_macros::EnumIter;
pub use strum::IntoEnumIterator;


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, EnumIter)]
pub enum EncAlg {
    Aes256,
    ChaCha20Poly1305
}


/// The HKDF algorithm is used to generate a fixed key.
///
/// Why is this necessary? A user password is not always as secure 
/// as we would like: it can have a variable length or consist 
/// of simple combinations ("1234")
pub mod kdf {
    use hkdf::Hkdf;
    use sha2::Sha256;
    
    pub fn derive_key(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; 32] {
        let mut okm = [0u8; 32];
        let hkdf = Hkdf::<Sha256>::new(Some(salt), ikm);
        hkdf.expand(info, &mut okm).unwrap();
        okm
    }
    
    pub fn derive_random_key(salt: &[u8], len: usize, info: &[u8]) -> Vec<u8> {
        const MAX_OKM_LENGTH: usize = 255 * 32;
        if len > MAX_OKM_LENGTH {
            panic!("Requested key length {} exceeds maximum allowed length {}", len, MAX_OKM_LENGTH);
        }
        let ikm = rand::random::<[u8; 32]>();
        let hkdf = Hkdf::<Sha256>::new(Some(salt), &ikm);
        let mut okm = vec![0u8; len];
        hkdf.expand(info, &mut okm).expect("HKDF expansion failed");
        okm
    }
    
}


pub mod aes256 {
    use aes_gcm::{
        aead::{Aead, AeadCore, KeyInit, OsRng},
        Aes256Gcm, Key, Nonce
    };

    pub fn encrypt(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
        let key = Key::<Aes256Gcm>::from_slice(key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let cipher = Aes256Gcm::new(key);

        let ciphered_data = cipher.encrypt(&nonce, data).unwrap();
        let mut result = Vec::with_capacity(12 + ciphered_data.len());
        result.extend_from_slice(nonce.as_ref());
        result.extend_from_slice(&ciphered_data);
        result
    }

    pub fn decrypt(data: &[u8], key: &[u8; 32]) -> Option<Vec<u8>> {
        if data.len() < 12 {
            return None;
        }
        let key = Key::<Aes256Gcm>::from_slice(key);
        let (nonce_arr, ciphered_data) = data.split_at(12);
        let nonce = Nonce::from_slice(nonce_arr);
        let cipher = Aes256Gcm::new(key);
        cipher.decrypt(nonce, ciphered_data).ok()
    }
}


pub mod chacha20_poly1305 {
    use chacha20poly1305::{
        aead::{Aead, AeadCore, KeyInit, OsRng},
        ChaCha20Poly1305, Key, Nonce
    };

    pub fn encrypt(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
        let key = Key::from_slice(key);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let cipher = ChaCha20Poly1305::new(key);

        let ciphered_data = cipher.encrypt(&nonce, data).unwrap();
        let mut result = Vec::with_capacity(12 + ciphered_data.len());
        result.extend_from_slice(nonce.as_ref());
        result.extend_from_slice(&ciphered_data);
        result
    }

    pub fn decrypt(data: &[u8], key: &[u8; 32]) -> Option<Vec<u8>> {
        let key = Key::from_slice(key);
        if data.len() < 12 {
            return None;
        }
        let (nonce_arr, ciphered_data) = data.split_at(12);
        let nonce = Nonce::from_slice(nonce_arr);
        let cipher = ChaCha20Poly1305::new(key);
        cipher.decrypt(nonce, ciphered_data).ok()
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    
    
    fn make_derive_key_256(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
        let info = "tag".as_bytes();
        kdf::derive_key(&salt, &ikm, &info)
    }
    
    #[test]
    fn test_kdf_256_len() {
        let salt = rand::random::<[u8; 128]>();
        let ikm = rand::random::<[u8; 255]>();
        let key = make_derive_key_256(&salt, &ikm);
        assert_eq!(key.len(), 32);
    }
    
    #[test]
    fn test_kdf_256_determinism() {
        let salt = rand::random::<[u8; 128]>();
        let ikm = rand::random::<[u8; 255]>();
        let key1 = make_derive_key_256(&salt, &ikm);
        let key2 = make_derive_key_256(&salt, &ikm);
        assert_eq!(key1, key2);
    }
    
    #[test]
    fn test_aes256() {
        let key = make_derive_key_256(&[0; 128], &[0; 255]);
        let data = rand::random::<[u8; 1500]>().to_vec();
        let encrypted = aes256::encrypt(&data, &key);
        let decrypted = aes256::decrypt(&encrypted, &key).unwrap();
        assert_eq!(data, decrypted);
    }
    
    #[test]
    fn test_chacha20_poly1305() {
        let key = make_derive_key_256(&[0; 128], &[0; 255]);
        let data = rand::random::<[u8; 1500]>().to_vec();
        let encrypted = chacha20_poly1305::encrypt(&data, &key);
        let decrypted = chacha20_poly1305::decrypt(&encrypted, &key).unwrap();
        assert_eq!(data, decrypted);
    }
}