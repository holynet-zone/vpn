use bincode::{serialize, deserialize};
use serde::{Serialize, Deserialize};

pub trait ToBytes {
    fn to_bytes(&self) -> Result<Vec<u8>, String>;
}

pub trait FromBytes: Sized {
    fn from_bytes(data: &[u8]) -> anyhow::Result<Self>;
}

impl<T> ToBytes for T
where
    T: Serialize,
{
    fn to_bytes(&self) -> Result<Vec<u8>, String> {
        serialize(self).map_err(|e| e.to_string())
    }
}

impl<T> FromBytes for T
where
    T: for<'de> Deserialize<'de>,
{
    fn from_bytes(data: &[u8]) -> anyhow::Result<Self> {
        deserialize(data).map_err(|e| anyhow::anyhow!(e))
    }
}
