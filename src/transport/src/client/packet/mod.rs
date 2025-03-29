mod keepalive;
mod data;
mod handshake;

pub use self::{
    data::{
        DataPacket,
        DataBody
    },
    handshake::Handshake
};


use bincode;
use serde::{Deserialize, Serialize};

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
