use std::fmt;
use std::fmt::{Display, Formatter};
use std::ops::Deref;
use std::str::FromStr;
use serde::{Deserialize, Deserializer, Serialize, Serializer};


#[derive(Clone)]
pub struct Username(pub Vec<u8>);

impl Username {
    pub const SIZE: usize = 128;
    
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
        Ok(Self(slice.to_vec()))
    }
}

impl TryFrom<String> for Username {
    type Error = String;    // todo: anyhow
    
    fn try_from(s: String) -> Result<Self, Self::Error> {
        let bytes = s.as_bytes();
        if bytes.len() > Self::SIZE {
            return Err(format!("username too long, max {} chars", Self::SIZE));
        }
        Ok(Self(bytes.to_vec()))
    }
}

impl FromStr for Username {
    type Err = anyhow::Error;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = s.as_bytes();
        if bytes.len() > Self::SIZE {
            return Err(anyhow::Error::msg(format!("username too long, max {} chars", Self::SIZE)));
        }
        Ok(Self(bytes.to_vec()))

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
            serializer.serialize_str(&String::from_utf8_lossy(&self.0))
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
            String::deserialize(deserializer)?.as_bytes().to_vec()
        } else {
            Vec::deserialize(deserializer)?
        };
        
        if bytes.len() > Self::SIZE {
            return Err(serde::de::Error::custom(format!("username too long, max {} chars", Self::SIZE)));
        }
        
        Ok(Self(bytes))
    }
}