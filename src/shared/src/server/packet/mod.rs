mod keepalive;
mod data;
mod handshake;

use serde::{Deserialize, Serialize};
pub use self::{
    handshake::{
        Handshake,
        HandshakeBody,
        HandshakeError,
        HandshakePayload
    },
    data::{
        DataPacket,
        DataBody
    },
    keepalive::KeepAliveBody
};


#[derive(Serialize, Deserialize)]
pub enum Packet {
    Handshake(Handshake),
    Data(DataPacket)
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
