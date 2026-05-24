//! Shared noise encrypt/decrypt helpers with zero-allocation hot path.
//!
//! Each worker thread owns two 65 KB buffers stored in thread-local storage:
//!
//! - `PLAIN_BUF` — fixed stack-like BSS buffer for bincode plaintext encoding
//!   and Noise decryption output. Zero heap cost.
//!
//! - `CIPHER_POOL` — a small pool of `Arc<[u8]>` cipher buffers (typically just
//!   one entry in steady state). After Noise encryption the result is wrapped in
//!   a `bytes::Bytes` via `Bytes::from_owner`, which shares the Arc with the pool
//!   entry. The pool slot is reused on the next call once the previous `Bytes`
//!   has been dropped (Arc strong_count drops back to 1). This eliminates the
//!   `malloc` that the old `cipher[..n].to_vec()` incurred on every packet.
//!
//! Contract: these functions must not be called re-entrantly on the same thread
//! (e.g., from within a bincode Serialize impl that itself calls noise_encrypt).
//! This is guaranteed by the current call sites which are plain sync functions
//! invoked from async executors without interior recursion.

use std::cell::RefCell;
use std::sync::Arc;

use bytes::Bytes;
use snow::StatelessTransportState;

use crate::protocol::{DataClientBodyRef, DataServerBodyRef, EncryptedData};
use crate::runtime::buf_pool::BufPool;

thread_local! {
    /// Intermediate plaintext buffer: used for bincode encode (encrypt) or
    /// noise decode output (decrypt). Stored in thread-local BSS — zero cost.
    static PLAIN_BUF: RefCell<[u8; 65536]> = const { RefCell::new([0u8; 65536]) };

    /// Pool of Arc-wrapped 65 KB cipher buffers.
    ///
    /// Each slot is reused when its `Arc::strong_count` drops to 1, meaning
    /// no live `Bytes` object is still referencing it. In steady state only
    /// one buffer exists per thread. A new buffer is allocated only when the
    /// previous encrypted packet hasn't been consumed yet.
    static CIPHER_POOL: RefCell<Vec<Arc<[u8]>>> = const { RefCell::new(Vec::new()) };
}

/// Encrypt `body` via bincode/serde then Noise `StatelessTransportState`.
///
/// `nonce` must be a unique, monotonically increasing counter per session.
/// The caller is responsible for fetching it via `session.send_nonce.fetch_add(1, Relaxed)`.
///
/// Allocations (after warm-up): **zero** — cipher buffer is reused from the
/// thread-local pool.
#[inline]
pub(crate) fn noise_encrypt<T: serde::Serialize>(
    body: &T,
    state: &StatelessTransportState,
    nonce: u64,
) -> anyhow::Result<EncryptedData> {
    PLAIN_BUF.with_borrow_mut(|plain| {
        let encoded_len =
            bincode::serde::encode_into_slice(body, plain, bincode::config::standard())
                .map_err(|e| anyhow::anyhow!("bincode encode: {e}"))?;

        CIPHER_POOL.with_borrow_mut(|pool| {
            let slot = match pool.iter_mut().position(|a| Arc::strong_count(a) == 1) {
                Some(idx) => &mut pool[idx],
                None => {
                    pool.push(vec![0u8; 65536].into());
                    pool.last_mut().unwrap()
                }
            };

            // SAFETY: strong_count == 1 guarantees unique ownership on this thread.
            let buf = Arc::get_mut(slot).expect("Arc::get_mut failed despite strong_count == 1");

            let encrypted_len = state.write_message(nonce, &plain[..encoded_len], buf)?;

            let bytes_arc: Arc<[u8]> = slot.clone();
            let bytes = Bytes::from_owner(bytes_arc).slice(..encrypted_len);

            Ok(EncryptedData::from(bytes))
        })
    })
}

// --- Zero-copy IP-packet encode path ---

#[inline]
fn usize_varint_len(v: usize) -> usize {
    match v {
        0..=250 => 1,
        251..=65535 => 3,
        65536..=4294967295 => 5,
        _ => 9,
    }
}

/// Returns the size of the Noise ciphertext for an IP packet of `payload_len` bytes.
///
/// Plain frame: `varint_u32(0)` (1 B) + `varint_usize(payload_len)` + `payload_len`
/// Cipher = plain + 16 (AEAD tag).
#[inline]
fn ip_packet_cipher_len(payload_len: usize) -> usize {
    let plain = 1 + usize_varint_len(payload_len) + payload_len;
    plain + 16
}

/// Write a `DataClientBody::Packet` / `DataServerBody::Packet` plaintext frame
/// (variant 0 + varint length + raw bytes) into `plain_buf`. Returns bytes written.
///
/// Caller must ensure `1 + usize_varint_len(payload.len()) + payload.len() <= plain_buf.len()`.
#[inline]
fn write_ip_packet_plain(plain_buf: &mut [u8], payload: &[u8]) -> usize {
    use crate::protocol::varint::{write_u32, write_usize};
    let mut pos = write_u32(plain_buf, 0); // enum variant 0 = Packet
    pos += write_usize(&mut plain_buf[pos..], payload.len());
    plain_buf[pos..pos + payload.len()].copy_from_slice(payload);
    pos + payload.len()
}

/// Write the outer `Packet::DataServer { nonce, encrypted }` header into `buf`.
/// Returns the number of header bytes written.
#[inline]
fn write_data_server_frame(buf: &mut [u8], nonce: u64, cipher_len: usize) -> usize {
    use crate::protocol::varint::{write_u16, write_u32, write_u64};
    let mut pos = write_u32(buf, 3); // Packet::DataServer = variant 3
    pos += write_u64(&mut buf[pos..], nonce);
    pos += write_u16(&mut buf[pos..], cipher_len as u16);
    pos
}

/// Write the outer `Packet::DataClient { sid, nonce, encrypted }` header into `buf`.
/// Returns the number of header bytes written.
#[inline]
fn write_data_client_frame(buf: &mut [u8], sid: u32, nonce: u64, cipher_len: usize) -> usize {
    use crate::protocol::varint::{write_u16, write_u32, write_u64};
    let mut pos = write_u32(buf, 2); // Packet::DataClient = variant 2
    pos += write_u32(&mut buf[pos..], sid);
    pos += write_u64(&mut buf[pos..], nonce);
    pos += write_u16(&mut buf[pos..], cipher_len as u16);
    pos
}

/// Encode a raw IP packet as a complete `Packet::DataServer` wire frame into `out`.
///
/// Layout: `[header | noise_ciphertext]`
/// - header: variant(1B) + nonce(1–9B) + cipher_len(1–3B)
/// - noise_ciphertext: plain_frame + 16-byte AEAD tag, written directly by Noise
///
/// Hot path: **two memcpy** only — payload→PLAIN_BUF, then AEAD-encrypt→out.
/// No heap allocation, no CIPHER_POOL.
///
/// Returns the total number of bytes written to `out`.
pub(crate) fn encode_data_server_packet(
    payload: &[u8],
    state: &StatelessTransportState,
    nonce: u64,
    out: &mut [u8],
) -> anyhow::Result<usize> {
    let cipher_len = ip_packet_cipher_len(payload.len());
    let plain_len = cipher_len - 16;
    if plain_len > 65536 {
        anyhow::bail!("IP packet too large: {} payload bytes", payload.len());
    }
    let header_len = write_data_server_frame(out, nonce, cipher_len);
    PLAIN_BUF.with_borrow_mut(|plain| {
        let n = write_ip_packet_plain(plain, payload);
        debug_assert_eq!(n, plain_len);
        let written = state
            .write_message(nonce, &plain[..n], &mut out[header_len..])
            .map_err(|e| anyhow::anyhow!("noise write_message: {e}"))?;
        debug_assert_eq!(written, cipher_len);
        Ok(header_len + written)
    })
}

/// Encode a raw IP packet as a complete `Packet::DataClient` wire frame into `out`.
///
/// Same layout as `encode_data_server_packet` but with a session ID prefix.
/// Returns the total number of bytes written to `out`.
pub(crate) fn encode_data_client_packet(
    payload: &[u8],
    sid: u32,
    state: &StatelessTransportState,
    nonce: u64,
    out: &mut [u8],
) -> anyhow::Result<usize> {
    let cipher_len = ip_packet_cipher_len(payload.len());
    let plain_len = cipher_len - 16;
    if plain_len > 65536 {
        anyhow::bail!("IP packet too large: {} payload bytes", payload.len());
    }
    let header_len = write_data_client_frame(out, sid, nonce, cipher_len);
    PLAIN_BUF.with_borrow_mut(|plain| {
        let n = write_ip_packet_plain(plain, payload);
        debug_assert_eq!(n, plain_len);
        let written = state
            .write_message(nonce, &plain[..n], &mut out[header_len..])
            .map_err(|e| anyhow::anyhow!("noise write_message: {e}"))?;
        debug_assert_eq!(written, cipher_len);
        Ok(header_len + written)
    })
}

/// Result of decrypting a DataClientBody (server receives this from clients).
pub(crate) enum DataClientAction {
    /// IP packet to forward to TUN. `Bytes` is backed by the caller's BufPool.
    Forward(Bytes),
    /// Keepalive timestamp (microseconds since client process start).
    KeepAlive(u128),
}

/// Result of decrypting a DataServerBody (client receives this from server).
pub(crate) enum DataServerAction {
    /// IP packet to forward to network/TUN.
    Forward(Bytes),
    /// Keepalive echo timestamp.
    KeepAlive(u128),
    /// Server-initiated disconnect code.
    Disconnect(u8),
}

/// Decrypt a DataClientBody from raw ciphertext without any heap allocation.
///
/// `nonce` is taken from the packet header; the replay window check must be
/// performed by the caller before calling this function.
#[inline]
pub(crate) fn noise_decrypt_data_client(
    ciphertext: &[u8],
    state: &StatelessTransportState,
    pool: &mut BufPool,
    nonce: u64,
) -> anyhow::Result<DataClientAction> {
    PLAIN_BUF.with_borrow_mut(|plain| {
        let len = state.read_message(nonce, ciphertext, plain)?;
        let body = DataClientBodyRef::from_plain_buf(&plain[..len])
            .ok_or_else(|| anyhow::anyhow!("malformed DataClientBody"))?;
        Ok(match body {
            DataClientBodyRef::Packet(data) => DataClientAction::Forward(pool.copy_to_bytes(data)),
            DataClientBodyRef::KeepAlive(ts) => DataClientAction::KeepAlive(ts),
        })
    })
}

/// Decrypt a DataServerBody from raw ciphertext without any heap allocation.
///
/// `nonce` is taken from the packet header; the replay window check must be
/// performed by the caller before calling this function.
#[inline]
pub(crate) fn noise_decrypt_data_server(
    ciphertext: &[u8],
    state: &StatelessTransportState,
    pool: &mut BufPool,
    nonce: u64,
) -> anyhow::Result<DataServerAction> {
    PLAIN_BUF.with_borrow_mut(|plain| {
        let len = state.read_message(nonce, ciphertext, plain)?;
        let body = DataServerBodyRef::from_plain_buf(&plain[..len])
            .ok_or_else(|| anyhow::anyhow!("malformed DataServerBody"))?;
        Ok(match body {
            DataServerBodyRef::Packet(data) => DataServerAction::Forward(pool.copy_to_bytes(data)),
            DataServerBodyRef::KeepAlive(ts) => DataServerAction::KeepAlive(ts),
            DataServerBodyRef::Disconnect(code) => DataServerAction::Disconnect(code),
        })
    })
}

#[cfg(test)]
pub(crate) fn make_noise_pair_for_test() -> (StatelessTransportState, StatelessTransportState) {
    use crate::crypto::{PublicKey, SecretKey};
    use crate::protocol::handshake::NOISE_IK_PSK2_25519_CHACHAPOLY_BLAKE2S;
    use snow::Builder;

    let server_sk = SecretKey::generate_x25519();
    let server_pk = PublicKey::from_secret(&server_sk);
    let client_sk = SecretKey::generate_x25519();
    let client_pk = PublicKey::from_secret(&client_sk);
    let psk = [0u8; 32];
    let params = NOISE_IK_PSK2_25519_CHACHAPOLY_BLAKE2S.clone();

    let mut init = Builder::new(params.clone())
        .local_private_key(client_sk.as_slice())
        .unwrap()
        .remote_public_key(server_pk.as_slice())
        .unwrap()
        .psk(2, &psk)
        .unwrap()
        .build_initiator()
        .unwrap();
    let mut resp = Builder::new(params)
        .local_private_key(server_sk.as_slice())
        .unwrap()
        .remote_public_key(client_pk.as_slice())
        .unwrap()
        .psk(2, &psk)
        .unwrap()
        .build_responder()
        .unwrap();

    let mut buf = [0u8; 65536];
    let n = init.write_message(&[], &mut buf).unwrap();
    resp.read_message(&buf[..n], &mut [0u8; 65536]).unwrap();
    let n = resp.write_message(&[], &mut buf).unwrap();
    init.read_message(&buf[..n], &mut [0u8; 65536]).unwrap();

    (
        init.into_stateless_transport_mode().unwrap(),
        resp.into_stateless_transport_mode().unwrap(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{DataClientBody, DataServerBody};

    /// Test-only generic decrypt helper (uses bincode/serde path).
    fn noise_decrypt<T: serde::de::DeserializeOwned>(
        encrypted: &EncryptedData,
        state: &StatelessTransportState,
        nonce: u64,
    ) -> anyhow::Result<T> {
        PLAIN_BUF.with_borrow_mut(|buf| {
            let len = state.read_message(nonce, encrypted, buf)?;
            bincode::serde::decode_from_slice(&buf[..len], bincode::config::standard())
                .map(|(obj, _)| obj)
                .map_err(|e| anyhow::anyhow!("bincode decode: {e}"))
        })
    }

    #[test]
    fn test_roundtrip_data_packet() {
        let (tx, rx) = make_noise_pair_for_test();
        let body = DataClientBody::Packet(vec![1, 2, 3, 4, 5].into());
        let enc = noise_encrypt(&body, &tx, 0).unwrap();
        let dec: DataClientBody = noise_decrypt(&enc, &rx, 0).unwrap();
        match dec {
            DataClientBody::Packet(data) => assert_eq!(&data[..], [1, 2, 3, 4, 5]),
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn test_roundtrip_keepalive() {
        let (tx, rx) = make_noise_pair_for_test();
        let body = DataServerBody::KeepAlive(0xDEAD_CAFE_1234_5678u128);
        let enc = noise_encrypt(&body, &tx, 0).unwrap();
        let dec: DataServerBody = noise_decrypt(&enc, &rx, 0).unwrap();
        match dec {
            DataServerBody::KeepAlive(ts) => assert_eq!(ts, 0xDEAD_CAFE_1234_5678u128),
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn test_roundtrip_empty_payload() {
        let (tx, rx) = make_noise_pair_for_test();
        let body = DataClientBody::Packet(Bytes::new());
        let enc = noise_encrypt(&body, &tx, 0).unwrap();
        let dec: DataClientBody = noise_decrypt(&enc, &rx, 0).unwrap();
        match dec {
            DataClientBody::Packet(data) => assert!(data.is_empty()),
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn test_decrypt_with_wrong_key_fails() {
        let (tx, _) = make_noise_pair_for_test();
        let (_, rx_wrong) = make_noise_pair_for_test(); // independent key pair
        let body = DataClientBody::KeepAlive(42);
        let enc = noise_encrypt(&body, &tx, 0).unwrap();
        assert!(noise_decrypt::<DataClientBody>(&enc, &rx_wrong, 0).is_err());
    }

    #[test]
    fn test_different_nonces_roundtrip() {
        let (tx, rx) = make_noise_pair_for_test();
        for nonce in [0u64, 1, 42, u32::MAX as u64, u64::MAX / 2] {
            let body = DataClientBody::KeepAlive(nonce as u128);
            let enc = noise_encrypt(&body, &tx, nonce).unwrap();
            let dec: DataClientBody = noise_decrypt(&enc, &rx, nonce).unwrap();
            match dec {
                DataClientBody::KeepAlive(ts) => assert_eq!(ts, nonce as u128),
                _ => panic!("unexpected variant"),
            }
        }
    }

    #[test]
    fn test_wrong_nonce_decrypt_fails() {
        let (tx, rx) = make_noise_pair_for_test();
        let body = DataClientBody::KeepAlive(99);
        let enc = noise_encrypt(&body, &tx, 5).unwrap();
        // Decrypting with a different nonce must fail (AEAD tag mismatch).
        assert!(noise_decrypt::<DataClientBody>(&enc, &rx, 6).is_err());
    }

    // --- encode_data_server/client_packet tests ---

    /// encode_data_server_packet produces wire bytes that PacketRef parses correctly
    /// and that noise_decrypt_data_server recovers the original payload from.
    #[test]
    fn test_encode_data_server_packet_roundtrip() {
        use crate::protocol::PacketRef;
        use crate::runtime::buf_pool::BufPool;
        use crate::runtime::crypto::{
            DataServerAction, encode_data_server_packet, noise_decrypt_data_server,
        };

        let (tx, rx) = make_noise_pair_for_test();
        let payload = vec![0xABu8; 1400];
        let mut out = vec![0u8; 65600];
        let nonce = 7u64;

        let n = encode_data_server_packet(&payload, &tx, nonce, &mut out).unwrap();
        let frame = &out[..n];

        // Parse header
        match PacketRef::from_bytes(frame).unwrap() {
            PacketRef::DataServer {
                nonce: pkt_nonce,
                ciphertext,
            } => {
                assert_eq!(pkt_nonce, nonce);
                // Decrypt
                let mut pool = BufPool::new(65536);
                match noise_decrypt_data_server(ciphertext, &rx, &mut pool, nonce).unwrap() {
                    DataServerAction::Forward(data) => assert_eq!(&data[..], &payload[..]),
                    _ => panic!("expected Forward"),
                }
            }
            _ => panic!("expected DataServer"),
        }
    }

    /// encode_data_client_packet round-trip via PacketRef + noise_decrypt_data_client.
    #[test]
    fn test_encode_data_client_packet_roundtrip() {
        use crate::protocol::PacketRef;
        use crate::runtime::buf_pool::BufPool;
        use crate::runtime::crypto::{
            DataClientAction, encode_data_client_packet, noise_decrypt_data_client,
        };

        let (tx, rx) = make_noise_pair_for_test();
        let payload = vec![0xDEu8; 512];
        let sid: u32 = 0xDEAD_BEEF;
        let mut out = vec![0u8; 65600];
        let nonce = 42u64;

        let n = encode_data_client_packet(&payload, sid, &tx, nonce, &mut out).unwrap();
        let frame = &out[..n];

        match PacketRef::from_bytes(frame).unwrap() {
            PacketRef::DataClient {
                sid: pkt_sid,
                nonce: pkt_nonce,
                ciphertext,
            } => {
                assert_eq!(pkt_sid, sid);
                assert_eq!(pkt_nonce, nonce);
                let mut pool = BufPool::new(65536);
                match noise_decrypt_data_client(ciphertext, &rx, &mut pool, nonce).unwrap() {
                    DataClientAction::Forward(data) => assert_eq!(&data[..], &payload[..]),
                    _ => panic!("expected Forward"),
                }
            }
            _ => panic!("expected DataClient"),
        }
    }

    /// Verify that encode_data_server_packet produces identical bytes to the old
    /// noise_encrypt + bincode::encode_into_slice path.
    #[test]
    fn test_encode_server_matches_old_path() {
        use crate::protocol::{DataServerBody, Packet};
        use bytes::Bytes;

        let (tx, _rx) = make_noise_pair_for_test();
        let payload = vec![0x55u8; 64];
        let nonce = 3u64;

        // Old path
        let body = DataServerBody::Packet(Bytes::from(payload.clone()));
        let encrypted = noise_encrypt(&body, &tx, nonce).unwrap();
        let old_frame = Packet::DataServer { nonce, encrypted }.to_bytes();

        // New path
        let mut out = vec![0u8; 65600];
        let n = encode_data_server_packet(&payload, &tx, nonce, &mut out).unwrap();
        let new_frame = &out[..n];

        assert_eq!(old_frame, new_frame);
    }

    /// Same for DataClient.
    #[test]
    fn test_encode_client_matches_old_path() {
        use crate::protocol::{DataClientBody, Packet};
        use bytes::Bytes;

        let (tx, _rx) = make_noise_pair_for_test();
        let payload = vec![0xAAu8; 128];
        let sid: u32 = 42;
        let nonce = 11u64;

        // Old path
        let body = DataClientBody::Packet(Bytes::from(payload.clone()));
        let encrypted = noise_encrypt(&body, &tx, nonce).unwrap();
        let old_frame = Packet::DataClient {
            sid,
            nonce,
            encrypted,
        }
        .to_bytes();

        // New path
        let mut out = vec![0u8; 65600];
        let n = encode_data_client_packet(&payload, sid, &tx, nonce, &mut out).unwrap();
        let new_frame = &out[..n];

        assert_eq!(old_frame, new_frame);
    }

    /// Encrypt multiple packets without dropping previous results — the pool
    /// must allocate separate buffers and each must decrypt independently.
    #[test]
    fn test_pool_grows_under_concurrent_in_flight() {
        let (tx, rx) = make_noise_pair_for_test();

        let enc1 = noise_encrypt(&DataClientBody::Packet(vec![1u8; 64].into()), &tx, 0).unwrap();
        let enc2 = noise_encrypt(&DataClientBody::Packet(vec![2u8; 64].into()), &tx, 1).unwrap();
        let enc3 = noise_encrypt(&DataClientBody::Packet(vec![3u8; 64].into()), &tx, 2).unwrap();

        let dec = |enc: &EncryptedData, expected: u8, nonce: u64| {
            let body: DataClientBody = noise_decrypt(enc, &rx, nonce).unwrap();
            match body {
                DataClientBody::Packet(d) => assert_eq!(&d[..], vec![expected; 64]),
                _ => panic!("unexpected variant"),
            }
        };
        dec(&enc1, 1, 0);
        dec(&enc2, 2, 1);
        dec(&enc3, 3, 2);
    }

    #[test]
    fn test_pool_reuse_after_drop() {
        let (tx, rx) = make_noise_pair_for_test();
        for (nonce, byte) in (0u8..=16).enumerate() {
            let body = DataClientBody::Packet(vec![byte; 128].into());
            let enc = noise_encrypt(&body, &tx, nonce as u64).unwrap();
            let dec: DataClientBody = noise_decrypt(&enc, &rx, nonce as u64).unwrap();
            match dec {
                DataClientBody::Packet(data) => assert_eq!(&data[..], vec![byte; 128]),
                _ => panic!("unexpected variant"),
            }
        }
    }
}
