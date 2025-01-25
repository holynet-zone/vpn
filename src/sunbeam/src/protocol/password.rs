use std::fmt;
use std::fmt::{Display, Formatter};
use std::ops::Deref;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, Serializer};


#[derive(Clone)]
pub struct Password(pub Vec<u8>);

impl Password {
    pub fn len(&self) -> usize {
        self.0.len()
    }
    
    pub fn generate() -> Self {
        let mut password = [0u8; 128];
        OsRng.fill_bytes(&mut password);
        Self(Vec::from(password))
    }
    
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for Password {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl From<&[u8]> for Password {
    fn from(value: &[u8]) -> Self {
        let mut password = Vec::new();
        password.extend_from_slice(value);
        Self(password)
    }
}

impl From<Vec<u8>> for Password {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl From<String> for Password {
    fn from(value: String) -> Self {
        let mut password = Vec::new();
        password.extend_from_slice(value.as_bytes());
        Self(password)
    }
}

impl From<&str> for Password {
    fn from(s: &str) -> Self {
        let mut password = Vec::new();
        password.extend_from_slice(s.as_bytes());
        Self(password)
    }
}

impl Display for Password {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let s = String::from_utf8_lossy(&self.0);
        write!(f, "{}", s.trim_end_matches('\0'))
    }
}

impl Serialize for Password {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            let s = String::from_utf8_lossy(&self.0);
            serializer.serialize_str(&s)
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for Password {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            s.as_bytes().to_vec()
        } else {
            Vec::deserialize(deserializer)?
        };
        
        let mut password = Vec::new();
        password.extend_from_slice(&bytes);
        Ok(Self(password))
    }
}
