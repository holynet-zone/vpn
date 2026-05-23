pub mod handshake;
mod data;
mod primitives;
mod session;

use bincode::{Decode, Encode};
use bytes::Bytes;
pub use data::{DataClientBody, DataServerBody};
pub use handshake::{HandshakeError, HandshakeResponderBody, HandshakeResponderPayload};
use primitives::VecU16;
pub use session::{Alg, SessionId};

pub type EncryptedHandshake = VecU16<u8>;

/// Zero-copy encrypted payload for the data path.
///
/// Backed by `bytes::Bytes` (Arc-counted) so that passing through channels
/// is a cheap pointer move. Created from a thread-local cipher buffer via
/// `Bytes::from_owner` in `noise_encrypt` — no heap allocation on the hot path
/// once each thread's buffer pool is warmed up.
///
/// Wire format (bincode): `u16` little-endian length followed by raw bytes —
/// identical to the previous `VecU16<u8>` representation.
#[derive(Clone, Debug)]
pub struct EncryptedData(pub(crate) Bytes);

impl std::ops::Deref for EncryptedData {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Bytes> for EncryptedData {
    fn from(b: Bytes) -> Self {
        EncryptedData(b)
    }
}

/// Encode as `u16` length + raw bytes (same wire layout as `VecU16<u8>`).
impl bincode::Encode for EncryptedData {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        use bincode::enc::write::Writer;
        let len = self.0.len();
        if len > u16::MAX as usize {
            return Err(bincode::error::EncodeError::Other(
                "EncryptedData exceeds 65535 bytes",
            ));
        }
        (len as u16).encode(encoder)?;
        encoder.writer().write(&self.0)
    }
}

/// Decode from `u16` length + raw bytes. Allocates on the receive path
/// (unavoidable — data arrives from the wire into a fresh buffer).
impl<Context> bincode::Decode<Context> for EncryptedData {
    fn decode<D: bincode::de::Decoder<Context = Context>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        use bincode::de::read::Reader;
        let len = u16::decode(decoder)? as usize;
        let mut buf = vec![0u8; len];
        decoder.reader().read(&mut buf)?;
        Ok(EncryptedData(Bytes::from(buf)))
    }
}

impl<'de, Context> bincode::BorrowDecode<'de, Context> for EncryptedData {
    fn borrow_decode<D>(decoder: &mut D) -> Result<Self, bincode::error::DecodeError>
    where
        D: bincode::de::Decoder<Context = Context> + bincode::de::BorrowDecoder<'de>,
    {
        <EncryptedData as bincode::Decode<Context>>::decode(decoder)
    }
}

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
