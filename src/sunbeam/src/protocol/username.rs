use std::fmt;
use std::fmt::{Display, Formatter};
use std::ops::Deref;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

const USERNAME_SIZE: usize = 128;

#[derive(Clone)]
pub struct Username(pub [u8; USERNAME_SIZE]);

impl Username {
    pub const SIZE: usize = USERNAME_SIZE;
    
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for Username {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl TryFrom<&[u8]> for Username {
    type Error = String;
    
    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        if slice.len() != Self::SIZE {
            return Err("invalid username size".to_string());
        }
        let mut username = [0u8; Self::SIZE];
        username.copy_from_slice(slice);
        Ok(Self(username))
    }
}

impl TryFrom<String> for Username {
    type Error = String;
    
    fn try_from(s: String) -> Result<Self, Self::Error> {
        if s.len() > Self::SIZE {
            return Err("username too long".to_string());
        }
        let mut username = [0u8; Self::SIZE];
        username[..s.len()].copy_from_slice(s.as_bytes());
        Ok(Self(username))
    }
}

impl Display for Username {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let s = String::from_utf8_lossy(&self.0);
        write!(f, "{}", s.trim_end_matches('\0'))
    }
}

impl Serialize for Username {
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

impl<'de> Deserialize<'de> for Username {
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
        
        if bytes.len() > Self::SIZE {
            return Err(serde::de::Error::custom("username too long"));
        }
        
        let mut username = [0u8; Self::SIZE];
        username[..bytes.len()].copy_from_slice(&bytes);
        Ok(Self(username))
    }
}