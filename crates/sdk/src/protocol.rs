pub mod handshake;
mod data;
mod primitives;
mod session;

use bincode::{Decode, Encode};
pub use data::{DataClientBody, DataServerBody};
pub use handshake::{HandshakeError, HandshakeResponderBody, HandshakeResponderPayload};
use primitives::VecU16;
pub use session::{Alg, SessionId};

pub type EncryptedHandshake = VecU16<u8>;
pub type EncryptedData = VecU16<u8>;

#[derive(Decode, Encode)]
pub enum Packet {
    HandshakeInitial(EncryptedHandshake),
    HandshakeResponder(EncryptedHandshake),
    DataClient {
        sid: SessionId,
        encrypted: EncryptedData,
    },
    DataServer(EncryptedData),
}

impl TryFrom<&[u8]> for Packet {
    type Error = &'static str;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        match bincode::decode_from_slice(data, bincode::config::standard()) {
            Ok((obj, _)) => Ok(obj),
            Err(_) => Err("error decoding packet"),
        }
    }
}

impl Packet {
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::encode_to_vec(self, bincode::config::standard())
            .expect("unexpected error encoding packet")
    }
}
