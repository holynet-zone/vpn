mod handshake;
mod data;

use bincode::{Decode, Encode};
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
use crate::types::VecU16;

pub type EncryptedHandshake = VecU16<u8>;
pub type EncryptedData = VecU16<u8>;

#[derive(Decode, Encode)]
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
        match bincode::decode_from_slice(
            data,
            bincode::config::standard()
        ) {
            Ok((obj, _)) => Ok(obj),
            Err(err) => Err(anyhow::anyhow!(err))
        }
    }
}

impl Packet {
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::encode_to_vec(
            self,
            bincode::config::standard()
        ).expect("unexpected error encoding packet")
    }
}
