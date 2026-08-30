use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::fmt;

use crate::crypto::PublicKey;

pub const ENROLLMENT_LEN: usize = 32 + 32 + 4 + 4 + 8 + 64;
const SIGNED_LEN: usize = 32 + 32 + 4 + 4 + 8;

#[derive(Clone)]
pub struct AccountKey(SigningKey);

impl AccountKey {
    pub fn generate() -> Self {
        use rand_core::OsRng;
        Self(SigningKey::generate(&mut OsRng))
    }

    pub fn public(&self) -> AccountPublicKey {
        AccountPublicKey(self.0.verifying_key().to_bytes())
    }

    pub fn issue(
        &self,
        device: &PublicKey,
        device_index: u32,
        capabilities: u32,
        expiry: u64,
    ) -> Enrollment {
        let mut cert = Enrollment {
            account: self.public(),
            device: device.clone(),
            device_index,
            capabilities,
            expiry,
            signature: [0u8; 64],
        };
        let signed = cert.signed_bytes();
        cert.signature = self.0.sign(&signed).to_bytes();
        cert
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl From<[u8; 32]> for AccountKey {
    fn from(seed: [u8; 32]) -> Self {
        Self(SigningKey::from_bytes(&seed))
    }
}

impl fmt::Display for AccountKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", STANDARD_NO_PAD.encode(self.0.to_bytes()))
    }
}

impl Serialize for AccountKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let bytes = self.0.to_bytes();
        if s.is_human_readable() {
            s.serialize_str(&STANDARD_NO_PAD.encode(bytes))
        } else {
            s.serialize_bytes(&bytes)
        }
    }
}

impl<'de> Deserialize<'de> for AccountKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bytes = deserialize_32(d, "a 32-byte account signing key")?;
        Ok(Self(SigningKey::from_bytes(&bytes)))
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct AccountPublicKey([u8; 32]);

impl AccountPublicKey {
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn verifying_key(&self) -> Option<VerifyingKey> {
        VerifyingKey::from_bytes(&self.0).ok()
    }
}

impl fmt::Display for AccountPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", STANDARD_NO_PAD.encode(self.0))
    }
}

impl TryFrom<&[u8]> for AccountPublicKey {
    type Error = &'static str;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        bytes
            .try_into()
            .map(Self)
            .map_err(|_| "account public key must be exactly 32 bytes")
    }
}

impl TryFrom<&str> for AccountPublicKey {
    type Error = String;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let bytes = STANDARD_NO_PAD.decode(s).map_err(|e| e.to_string())?;
        Self::try_from(bytes.as_slice()).map_err(|e| e.to_string())
    }
}

impl Serialize for AccountPublicKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&STANDARD_NO_PAD.encode(self.0))
        } else {
            s.serialize_bytes(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for AccountPublicKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        deserialize_32(d, "a 32-byte account public key").map(Self)
    }
}

fn deserialize_32<'de, D: Deserializer<'de>>(
    d: D,
    expecting: &'static str,
) -> Result<[u8; 32], D::Error> {
    struct Visitor(&'static str);
    impl<'de> de::Visitor<'de> for Visitor {
        type Value = [u8; 32];
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str(self.0)
        }
        fn visit_str<E: de::Error>(self, v: &str) -> Result<[u8; 32], E> {
            let bytes = STANDARD_NO_PAD.decode(v).map_err(de::Error::custom)?;
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| de::Error::invalid_length(bytes.len(), &self))
        }
        fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<[u8; 32], E> {
            v.try_into()
                .map_err(|_| de::Error::invalid_length(v.len(), &self))
        }
        fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<[u8; 32], A::Error> {
            let mut buf = [0u8; 32];
            for b in buf.iter_mut() {
                *b = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
            }
            Ok(buf)
        }
    }
    if d.is_human_readable() {
        d.deserialize_str(Visitor(expecting))
    } else {
        d.deserialize_bytes(Visitor(expecting))
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Enrollment {
    pub account: AccountPublicKey,
    pub device: PublicKey,
    pub device_index: u32,
    pub capabilities: u32,
    pub expiry: u64,
    pub signature: [u8; 64],
}

#[derive(Debug, PartialEq, Eq)]
pub enum EnrollmentError {
    BadSignature,
    Malformed,
    Expired,
    DeviceMismatch,
}

impl fmt::Display for EnrollmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EnrollmentError::BadSignature => f.write_str("enrollment signature invalid"),
            EnrollmentError::Malformed => f.write_str("enrollment malformed"),
            EnrollmentError::Expired => f.write_str("enrollment expired"),
            EnrollmentError::DeviceMismatch => {
                f.write_str("enrollment device key does not match handshake static key")
            }
        }
    }
}

impl std::error::Error for EnrollmentError {}

impl Enrollment {
    fn signed_bytes(&self) -> [u8; SIGNED_LEN] {
        let mut out = [0u8; SIGNED_LEN];
        out[0..32].copy_from_slice(&self.account.0);
        out[32..64].copy_from_slice(self.device.as_bytes());
        out[64..68].copy_from_slice(&self.device_index.to_le_bytes());
        out[68..72].copy_from_slice(&self.capabilities.to_le_bytes());
        out[72..80].copy_from_slice(&self.expiry.to_le_bytes());
        out
    }

    pub fn to_bytes(&self) -> [u8; ENROLLMENT_LEN] {
        let mut out = [0u8; ENROLLMENT_LEN];
        out[..SIGNED_LEN].copy_from_slice(&self.signed_bytes());
        out[SIGNED_LEN..].copy_from_slice(&self.signature);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EnrollmentError> {
        if bytes.len() != ENROLLMENT_LEN {
            return Err(EnrollmentError::Malformed);
        }
        let account = AccountPublicKey(bytes[0..32].try_into().unwrap());
        let device = PublicKey::try_from(&bytes[32..64]).map_err(|_| EnrollmentError::Malformed)?;
        let device_index = u32::from_le_bytes(bytes[64..68].try_into().unwrap());
        let capabilities = u32::from_le_bytes(bytes[68..72].try_into().unwrap());
        let expiry = u64::from_le_bytes(bytes[72..80].try_into().unwrap());
        let signature = bytes[SIGNED_LEN..].try_into().unwrap();
        Ok(Self {
            account,
            device,
            device_index,
            capabilities,
            expiry,
            signature,
        })
    }

    pub fn verify(&self) -> Result<(), EnrollmentError> {
        let vk = self
            .account
            .verifying_key()
            .ok_or(EnrollmentError::Malformed)?;
        let sig = ed25519_dalek::Signature::from_bytes(&self.signature);
        vk.verify(&self.signed_bytes(), &sig)
            .map_err(|_| EnrollmentError::BadSignature)
    }

    pub fn is_expired(&self, now_unix: u64) -> bool {
        self.expiry != 0 && now_unix >= self.expiry
    }
}

impl Serialize for Enrollment {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let bytes = self.to_bytes();
        if s.is_human_readable() {
            s.serialize_str(&STANDARD_NO_PAD.encode(bytes))
        } else {
            s.serialize_bytes(&bytes)
        }
    }
}

impl<'de> Deserialize<'de> for Enrollment {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = Enrollment;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a 144-byte device enrollment")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Enrollment, E> {
                let bytes = STANDARD_NO_PAD.decode(v).map_err(de::Error::custom)?;
                Enrollment::from_bytes(&bytes).map_err(de::Error::custom)
            }
            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Enrollment, E> {
                Enrollment::from_bytes(v).map_err(de::Error::custom)
            }
            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Enrollment, A::Error> {
                let mut buf = Vec::with_capacity(ENROLLMENT_LEN);
                while let Some(b) = seq.next_element::<u8>()? {
                    buf.push(b);
                }
                Enrollment::from_bytes(&buf).map_err(de::Error::custom)
            }
        }
        if d.is_human_readable() {
            d.deserialize_str(Visitor)
        } else {
            d.deserialize_bytes(Visitor)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SecretKey;

    fn device() -> PublicKey {
        PublicKey::from_secret(&SecretKey::generate_x25519())
    }

    #[test]
    fn issue_verify_roundtrip() {
        let account = AccountKey::generate();
        let dev = device();
        let cert = account.issue(&dev, 3, 0, 0);
        assert_eq!(cert.account, account.public());
        assert_eq!(cert.device, dev);
        assert_eq!(cert.device_index, 3);
        assert!(cert.verify().is_ok());
    }

    #[test]
    fn wire_roundtrip() {
        let account = AccountKey::generate();
        let cert = account.issue(&device(), 7, 1, 42);
        let bytes = cert.to_bytes();
        assert_eq!(bytes.len(), ENROLLMENT_LEN);
        let back = Enrollment::from_bytes(&bytes).unwrap();
        assert_eq!(back, cert);
        assert!(back.verify().is_ok());
    }

    #[test]
    fn tampered_index_fails_verify() {
        let account = AccountKey::generate();
        let mut cert = account.issue(&device(), 1, 0, 0);
        cert.device_index = 2;
        assert_eq!(cert.verify(), Err(EnrollmentError::BadSignature));
    }

    #[test]
    fn foreign_signer_fails_verify() {
        let issuer = AccountKey::generate();
        let attacker = AccountKey::generate();
        let dev = device();
        let mut cert = issuer.issue(&dev, 0, 0, 0);
        cert.account = attacker.public();
        assert_eq!(cert.verify(), Err(EnrollmentError::BadSignature));
    }

    #[test]
    fn expiry_semantics() {
        let account = AccountKey::generate();
        let never = account.issue(&device(), 0, 0, 0);
        assert!(!never.is_expired(u64::MAX));
        let dated = account.issue(&device(), 0, 0, 100);
        assert!(!dated.is_expired(99));
        assert!(dated.is_expired(100));
    }

    #[test]
    fn serde_bincode_roundtrip() {
        let account = AccountKey::generate();
        let cert = account.issue(&device(), 5, 0, 0);
        let bytes = bincode::serde::encode_to_vec(&cert, bincode::config::standard()).unwrap();
        let (back, _): (Enrollment, _) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(back, cert);
        assert!(back.verify().is_ok());
    }

    #[test]
    fn malformed_length_rejected() {
        assert_eq!(
            Enrollment::from_bytes(&[0u8; 10]),
            Err(EnrollmentError::Malformed)
        );
    }
}
