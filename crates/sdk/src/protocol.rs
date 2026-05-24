mod data;
pub mod handshake;
mod primitives;
mod session;
pub(crate) mod varint;

use bincode::{Decode, Encode};
use bytes::Bytes;
pub use data::{DataClientBody, DataServerBody};
pub(crate) use data::{DataClientBodyRef, DataServerBodyRef};
pub use handshake::{HandshakeError, HandshakeResponderBody, HandshakeResponderPayload};
use primitives::VecU16;
pub use session::{Alg, SessionId};
use varint::{read_u16, read_u32, read_u64};

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
        nonce: u64,
        encrypted: EncryptedData,
    },
    DataServer {
        nonce: u64,
        encrypted: EncryptedData,
    },
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

// Zero-copy packet view

/// Zero-copy view into a raw UDP receive buffer.
///
/// Parses the bincode-encoded `Packet` without heap allocation by borrowing
/// byte slices directly from the input. Used on the hot receive path so the
/// ciphertext never needs to leave the stack buffer.
///
/// Wire format mirrors the bincode `Decode` impl for `Packet`:
///   variant (varint u32) | fields...
/// where `EncryptedData` fields are: varint-u16 length | raw bytes.
pub(crate) enum PacketRef<'a> {
    HandshakeInitial(&'a [u8]),
    HandshakeResponder(&'a [u8]),
    DataClient {
        sid: SessionId,
        nonce: u64,
        ciphertext: &'a [u8],
    },
    DataServer {
        nonce: u64,
        ciphertext: &'a [u8],
    },
}

impl<'a> PacketRef<'a> {
    /// Parse a `PacketRef` from `buf` without allocating.
    /// Returns `None` on truncation or unknown variant.
    pub(crate) fn from_bytes(buf: &'a [u8]) -> Option<Self> {
        let (variant, buf) = read_u32(buf)?;
        match variant {
            0 => {
                // HandshakeInitial(VecU16<u8>) — encoded as varint-u16 len + bytes
                let (len, buf) = read_u16(buf)?;
                let data = buf.get(..len as usize)?;
                Some(PacketRef::HandshakeInitial(data))
            }
            1 => {
                // HandshakeResponder(VecU16<u8>)
                let (len, buf) = read_u16(buf)?;
                let data = buf.get(..len as usize)?;
                Some(PacketRef::HandshakeResponder(data))
            }
            2 => {
                // DataClient { sid: SessionId(u32), nonce: u64, encrypted: EncryptedData }
                let (sid, buf) = read_u32(buf)?;
                let (nonce, buf) = read_u64(buf)?;
                let (enc_len, buf) = read_u16(buf)?;
                let ciphertext = buf.get(..enc_len as usize)?;
                Some(PacketRef::DataClient {
                    sid,
                    nonce,
                    ciphertext,
                })
            }
            3 => {
                // DataServer { nonce: u64, encrypted: EncryptedData }
                let (nonce, buf) = read_u64(buf)?;
                let (enc_len, buf) = read_u16(buf)?;
                let ciphertext = buf.get(..enc_len as usize)?;
                Some(PacketRef::DataServer { nonce, ciphertext })
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    fn make_encrypted(data: Vec<u8>) -> EncryptedData {
        EncryptedData(Bytes::from(data))
    }

    #[test]
    fn test_encrypted_data_bincode_roundtrip() {
        let original = make_encrypted(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let encoded = bincode::encode_to_vec(&original, bincode::config::standard()).unwrap();
        let (decoded, _): (EncryptedData, _) =
            bincode::decode_from_slice(&encoded, bincode::config::standard()).unwrap();
        assert_eq!(&*decoded, &*original);
    }

    #[test]
    fn test_encrypted_data_empty_roundtrip() {
        let original = make_encrypted(vec![]);
        let encoded = bincode::encode_to_vec(&original, bincode::config::standard()).unwrap();
        let (decoded, _): (EncryptedData, _) =
            bincode::decode_from_slice(&encoded, bincode::config::standard()).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_packet_data_client_roundtrip() {
        let encrypted = make_encrypted(vec![1, 2, 3]);
        let packet = Packet::DataClient {
            sid: 0xDEAD_BEEF,
            nonce: 0xCAFE_1234_5678_9ABCu64,
            encrypted,
        };
        let bytes = packet.to_bytes();
        let decoded = Packet::try_from(bytes.as_slice()).unwrap();
        match decoded {
            Packet::DataClient {
                sid,
                nonce,
                encrypted,
            } => {
                assert_eq!(sid, 0xDEAD_BEEF);
                assert_eq!(nonce, 0xCAFE_1234_5678_9ABCu64);
                assert_eq!(&*encrypted, &[1u8, 2, 3]);
            }
            _ => panic!("wrong packet variant"),
        }
    }

    #[test]
    fn test_packet_data_server_roundtrip() {
        let encrypted = make_encrypted(vec![0xFF, 0x00, 0xAB]);
        let packet = Packet::DataServer {
            nonce: 42,
            encrypted,
        };
        let bytes = packet.to_bytes();
        let decoded = Packet::try_from(bytes.as_slice()).unwrap();
        match decoded {
            Packet::DataServer { nonce, encrypted } => {
                assert_eq!(nonce, 42);
                assert_eq!(&*encrypted, &[0xFF, 0x00, 0xAB]);
            }
            _ => panic!("wrong packet variant"),
        }
    }

    #[test]
    fn test_packet_corrupt_bytes_returns_err() {
        assert!(Packet::try_from(&[0xFF, 0xFF, 0xFF, 0xFF][..]).is_err());
    }

    #[test]
    fn test_encrypted_data_clone_shares_data() {
        let original = make_encrypted(vec![1, 2, 3]);
        let cloned = original.clone();
        assert_eq!(&*original, &*cloned);
        // Bytes clone is zero-copy — both point to the same allocation
        assert!(std::ptr::eq(original.0.as_ptr(), cloned.0.as_ptr()));
    }

    // PacketRef tests

    /// Build a Packet, encode it, parse via PacketRef, verify ciphertext matches.
    #[test]
    fn test_packet_ref_data_client() {
        let cipher = vec![0xAAu8; 32];
        let enc = make_encrypted(cipher.clone());
        let pkt = Packet::DataClient {
            sid: 42,
            nonce: 999,
            encrypted: enc,
        };
        let raw = pkt.to_bytes();

        match PacketRef::from_bytes(&raw).unwrap() {
            PacketRef::DataClient {
                sid,
                nonce,
                ciphertext,
            } => {
                assert_eq!(sid, 42);
                assert_eq!(nonce, 999);
                assert_eq!(ciphertext, &cipher[..]);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_packet_ref_data_server() {
        let cipher = vec![0xBBu8; 48];
        let enc = make_encrypted(cipher.clone());
        let pkt = Packet::DataServer {
            nonce: 12345,
            encrypted: enc,
        };
        let raw = pkt.to_bytes();

        match PacketRef::from_bytes(&raw).unwrap() {
            PacketRef::DataServer { nonce, ciphertext } => {
                assert_eq!(nonce, 12345);
                assert_eq!(ciphertext, &cipher[..]);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_packet_ref_large_ciphertext() {
        let cipher = vec![0xCCu8; 1416]; // typical MTU-sized encrypted packet
        let enc = make_encrypted(cipher.clone());
        let pkt = Packet::DataClient {
            sid: 0xDEAD_BEEF,
            nonce: u64::MAX,
            encrypted: enc,
        };
        let raw = pkt.to_bytes();

        match PacketRef::from_bytes(&raw).unwrap() {
            PacketRef::DataClient {
                sid,
                nonce,
                ciphertext,
            } => {
                assert_eq!(sid, 0xDEAD_BEEF);
                assert_eq!(nonce, u64::MAX);
                assert_eq!(ciphertext, &cipher[..]);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_packet_ref_truncated_returns_none() {
        let cipher = vec![0xAAu8; 32];
        let enc = make_encrypted(cipher);
        let pkt = Packet::DataClient {
            sid: 1,
            nonce: 0,
            encrypted: enc,
        };
        let raw = pkt.to_bytes();
        // truncate
        assert!(PacketRef::from_bytes(&raw[..3]).is_none());
    }
}
