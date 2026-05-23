use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

#[derive(Clone)]
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

impl TryFrom<&str> for SecretKey {
    type Error = String;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let bytes = STANDARD_NO_PAD.decode(s).map_err(|e| e.to_string())?;
        Self::try_from(bytes.as_slice()).map_err(|e| e.to_string())
    }
}

impl Serialize for SecretKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&STANDARD_NO_PAD.encode(&self.0))
        } else {
            s.serialize_bytes(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for SecretKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = SecretKey;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a 32-byte secret key as base64 string or bytes")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<SecretKey, E> {
                let bytes = STANDARD_NO_PAD.decode(v).map_err(de::Error::custom)?;
                bytes.as_slice().try_into().map(SecretKey).map_err(|_| de::Error::invalid_length(bytes.len(), &self))
            }
            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<SecretKey, E> {
                v.try_into().map(SecretKey).map_err(|_| de::Error::invalid_length(v.len(), &self))
            }
            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<SecretKey, A::Error> {
                let mut buf = [0u8; 32];
                for b in buf.iter_mut() {
                    *b = seq.next_element()?.ok_or_else(|| de::Error::invalid_length(0, &self))?;
                }
                Ok(SecretKey(buf))
            }
        }
        if d.is_human_readable() {
            d.deserialize_str(Visitor)
        } else {
            d.deserialize_bytes(Visitor)
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
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

impl TryFrom<&str> for PublicKey {
    type Error = String;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let bytes = STANDARD_NO_PAD.decode(s).map_err(|e| e.to_string())?;
        Self::try_from(bytes.as_slice()).map_err(|e| e.to_string())
    }
}

impl Serialize for PublicKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&STANDARD_NO_PAD.encode(&self.0))
        } else {
            s.serialize_bytes(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = PublicKey;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a 32-byte public key as base64 string or bytes")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<PublicKey, E> {
                let bytes = STANDARD_NO_PAD.decode(v).map_err(de::Error::custom)?;
                bytes.as_slice().try_into().map(PublicKey).map_err(|_| de::Error::invalid_length(bytes.len(), &self))
            }
            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<PublicKey, E> {
                v.try_into().map(PublicKey).map_err(|_| de::Error::invalid_length(v.len(), &self))
            }
            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<PublicKey, A::Error> {
                let mut buf = [0u8; 32];
                for b in buf.iter_mut() {
                    *b = seq.next_element()?.ok_or_else(|| de::Error::invalid_length(0, &self))?;
                }
                Ok(PublicKey(buf))
            }
        }
        if d.is_human_readable() {
            d.deserialize_str(Visitor)
        } else {
            d.deserialize_bytes(Visitor)
        }
    }
}
