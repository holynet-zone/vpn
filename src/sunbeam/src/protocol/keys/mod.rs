use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use rand_core::{OsRng, RngCore};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::fmt::{Display, Formatter};
use std::ops::Deref;

pub mod session;
pub mod auth;

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Key<const SIZE: usize>(pub [u8; SIZE]);

impl<const SIZE: usize> Key<SIZE> {
    pub const SIZE: usize = SIZE;

    pub fn generate() -> Self {
        let mut key = [0u8; SIZE];
        OsRng.fill_bytes(&mut key);
        Self(key)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl<const SIZE: usize> Deref for Key<SIZE> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl<const SIZE: usize> TryFrom<&[u8]> for Key<SIZE> {
    type Error = String;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        if slice.len() != SIZE {
            return Err(format!("invalid key size, expected {}", SIZE));
        }
        let mut key = [0u8; SIZE];
        key.copy_from_slice(slice);
        Ok(Self(key))
    }
}

impl<const SIZE: usize> TryFrom<&str> for Key<SIZE> {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let bytes = STANDARD_NO_PAD.decode(value).map_err(|error| error.to_string())?;
        Self::try_from(bytes.as_slice())
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
            return Err(de::Error::custom(format!("Key must be {} bytes", SIZE)));
        }

        let mut key = [0u8; SIZE];
        key.copy_from_slice(&bytes);
        Ok(Self(key))
    }
}
