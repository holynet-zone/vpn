use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use rand_core::{OsRng, RngCore};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::fmt::{Display, Formatter};
use std::ops::Deref;

pub mod handshake;

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Key<const SIZE: usize>(pub [u8; SIZE]);

impl<const SIZE: usize> Key<SIZE> {
    pub const SIZE: usize = SIZE;

    pub fn generate() -> Self {
        let mut key = [0u8; SIZE];
        OsRng.fill_bytes(&mut key);
        Self(key)
    }
    
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{:02x}", b)).collect()
    }
    
    pub fn from_hex(hex: &str) -> Result<Self, anyhow::Error> {
        if hex.len() != SIZE * 2 {
            return Err(anyhow::anyhow!("invalid key size, expected {} but actual {}", SIZE * 2, hex.len()));
        }
        let mut key = [0u8; SIZE];
        for (i, byte) in hex.as_bytes().chunks(2).enumerate() {
            key[i] = u8::from_str_radix(std::str::from_utf8(byte)?, 16)?;
        }
        Ok(Self(key))
    }
}

impl<const SIZE: usize> Deref for Key<SIZE> {
    type Target = [u8; SIZE];

    fn deref(&self) -> &Self::Target { &self.0 }
}

impl<const SIZE: usize> TryFrom<&[u8]> for Key<SIZE> {
    type Error = anyhow::Error;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        if slice.len() != SIZE {
            return Err(anyhow::anyhow!("invalid key size, expected {}", SIZE));
        }
        let mut key = [0u8; SIZE];
        key.copy_from_slice(slice);
        Ok(Self(key))
    }
}

impl<const SIZE: usize> TryFrom<&str> for Key<SIZE> {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let bytes = STANDARD_NO_PAD.decode(value)?;
        Self::try_from(bytes.as_slice())
    }
}

impl<const SIZE: usize> Into<[u8; SIZE]> for Key<SIZE> {
    fn into(self) -> [u8; SIZE] {
        self.0
    }
}

impl<const SIZE: usize> From<[u8; SIZE]> for Key<SIZE> {
    fn from(key: [u8; SIZE]) -> Self {
        Self(key)
    }
}

impl<const SIZE: usize> Display for Key<SIZE> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:?}", &self.0)
    }
}

impl<const SIZE: usize> Serialize for Key<SIZE> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            let s = STANDARD_NO_PAD.encode(&self.0);
            serializer.serialize_str(&s)
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}

impl<'de, const SIZE: usize> Deserialize<'de> for Key<SIZE> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            STANDARD_NO_PAD.decode(&s).map_err(de::Error::custom)?
        } else {
            Vec::<u8>::deserialize(deserializer)?
        };

        if bytes.len() != SIZE {
            return Err(de::Error::custom(format!("key must be {} bytes", SIZE)));
        }

        let mut key = [0u8; SIZE];
        key.copy_from_slice(&bytes); // todo: use array, not vec
        Ok(Self(key)) 
    }
}
