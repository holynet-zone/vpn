mod handshake;
mod data;

use serde::{Deserialize, Serialize};
pub use data::{
    DataServerBody,
    DataClientBody,
};
pub use handshake::{
    HandshakeResponderBody,
    HandshakeResponderPayload,
    HandshakeError
};
use crate::session::SessionId;

pub type EncryptedHandshake = Vec<u8>;
pub type EncryptedData = Vec<u8>;

#[derive(Serialize, Deserialize)]
pub enum Packet {
    HandshakeInitial(EncryptedHandshake),
    HandshakeResponder(EncryptedHandshake),
    DataClient {
        sid: SessionId,
        encrypted: EncryptedData
    },
    DataServer(EncryptedData)
}


impl TryFrom<&[u8]> for Packet {
    type Error = anyhow::Error;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        Ok(bincode::deserialize(data)?)
    }
}

impl Packet {
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }
}
