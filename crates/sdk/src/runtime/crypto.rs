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

/// Returns the plaintext frame length for an IP packet of `payload_len` bytes.
///
/// Plain frame: `varint_u32(0)` (1 B) + `varint_usize(payload_len)` + `payload_len`.
#[inline]
fn ip_packet_plain_len(payload_len: usize) -> usize {
    1 + usize_varint_len(payload_len) + payload_len
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

// --- Fixed-size data-frame headers (network byte order) ---
//
// Unlike the handshake frames, data frames carry **no length field**: the
// ciphertext runs to the end of the UDP datagram (WireGuard-style). Fixed
// header size is what makes a batch of equal-size plaintext packets produce
// equal-size datagrams, which is the precondition for coalescing them into one
// `sendmsg` with UDP GSO (`UDP_SEGMENT`).

/// `DataServer` wire type byte.
pub(crate) const TYPE_DATA_SERVER: u8 = 3;
/// `DataClient` wire type byte.
pub(crate) const TYPE_DATA_CLIENT: u8 = 2;
/// `DataServer` header length: `type(1) + nonce(8)`.
pub(crate) const DATA_SERVER_HDR_LEN: usize = 1 + 8;
/// `DataClient` header length: `type(1) + sid(4) + nonce(8)`.
pub(crate) const DATA_CLIENT_HDR_LEN: usize = 1 + 4 + 8;

/// Write the fixed `DataServer` header (`type | nonce`) into `buf`.
#[inline]
fn write_data_server_header(buf: &mut [u8], nonce: u64) -> usize {
    buf[0] = TYPE_DATA_SERVER;
    buf[1..9].copy_from_slice(&nonce.to_be_bytes());
    DATA_SERVER_HDR_LEN
}

/// Write the fixed `DataClient` header (`type | sid | nonce`) into `buf`.
#[inline]
fn write_data_client_header(buf: &mut [u8], sid: u32, nonce: u64) -> usize {
    buf[0] = TYPE_DATA_CLIENT;
    buf[1..5].copy_from_slice(&sid.to_be_bytes());
    buf[5..13].copy_from_slice(&nonce.to_be_bytes());
    DATA_CLIENT_HDR_LEN
}

/// Assemble a complete `DataServer` frame from an already-encrypted body
/// (keepalive path). Returns the total frame length.
pub(crate) fn encode_data_server_frame(nonce: u64, cipher: &[u8], out: &mut [u8]) -> usize {
    let h = write_data_server_header(out, nonce);
    out[h..h + cipher.len()].copy_from_slice(cipher);
    h + cipher.len()
}

/// Assemble a complete `DataClient` frame from an already-encrypted body
/// (keepalive path). Returns the total frame length.
pub(crate) fn encode_data_client_frame(
    sid: u32,
    nonce: u64,
    cipher: &[u8],
    out: &mut [u8],
) -> usize {
    let h = write_data_client_header(out, sid, nonce);
    out[h..h + cipher.len()].copy_from_slice(cipher);
    h + cipher.len()
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
    let plain_len = ip_packet_plain_len(payload.len());
    if plain_len > 65536 {
        anyhow::bail!("IP packet too large: {} payload bytes", payload.len());
    }
    let header_len = write_data_server_header(out, nonce);
    PLAIN_BUF.with_borrow_mut(|plain| {
        let n = write_ip_packet_plain(plain, payload);
        debug_assert_eq!(n, plain_len);
        let written = state
            .write_message(nonce, &plain[..n], &mut out[header_len..])
            .map_err(|e| anyhow::anyhow!("noise write_message: {e}"))?;
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
    let plain_len = ip_packet_plain_len(payload.len());
    if plain_len > 65536 {
        anyhow::bail!("IP packet too large: {} payload bytes", payload.len());
    }
    let header_len = write_data_client_header(out, sid, nonce);
    PLAIN_BUF.with_borrow_mut(|plain| {
        let n = write_ip_packet_plain(plain, payload);
        debug_assert_eq!(n, plain_len);
        let written = state
            .write_message(nonce, &plain[..n], &mut out[header_len..])
            .map_err(|e| anyhow::anyhow!("noise write_message: {e}"))?;
        Ok(header_len + written)
    })
}

/// Result of decrypting a DataClientBody (server receives this from clients).
///
/// `Forward` borrows the caller's plaintext buffer directly — no copy, no
/// allocation. The borrow lives as long as the `plain` buffer passed to the
/// decrypt function.
pub(crate) enum DataClientActionRef<'p> {
    /// IP packet to forward to TUN, borrowed from the caller's plaintext buffer.
    Forward(&'p [u8]),
    /// Keepalive timestamp (microseconds since client process start).
    KeepAlive(u128),
}

/// Result of decrypting a DataServerBody (client receives this from server).
///
/// `Forward` borrows the caller's plaintext buffer directly — see
/// [`DataClientActionRef`].
pub(crate) enum DataServerActionRef<'p> {
    /// IP packet to forward to network/TUN, borrowed from the plaintext buffer.
    Forward(&'p [u8]),
    /// Keepalive echo timestamp.
    KeepAlive(u128),
    /// Server-initiated disconnect code.
    Disconnect(u8),
}

/// Decrypt a DataClientBody from raw ciphertext directly into `plain`.
///
/// The decrypted IP packet is returned as a `&[u8]` slice borrowing `plain`,
/// so it can be handed straight to `network.send()` with **zero copies and
/// zero allocations** — no intermediate `Bytes`/`BufPool` hop.
///
/// `plain` must be large enough to hold the decrypted plaintext
/// (`ciphertext.len() - 16` bytes); a 64 KiB task-owned buffer always suffices.
///
/// `nonce` is taken from the packet header; the replay window check must be
/// performed by the caller before calling this function.
#[inline]
pub(crate) fn noise_decrypt_data_client_into<'p>(
    ciphertext: &[u8],
    state: &StatelessTransportState,
    plain: &'p mut [u8],
    nonce: u64,
) -> anyhow::Result<DataClientActionRef<'p>> {
    let len = state.read_message(nonce, ciphertext, plain)?;
    let body = DataClientBodyRef::from_plain_buf(&plain[..len])
        .ok_or_else(|| anyhow::anyhow!("malformed DataClientBody"))?;
    Ok(match body {
        DataClientBodyRef::Packet(data) => DataClientActionRef::Forward(data),
        DataClientBodyRef::KeepAlive(ts) => DataClientActionRef::KeepAlive(ts),
    })
}

/// Decrypt a DataServerBody from raw ciphertext directly into `plain`.
///
/// See [`noise_decrypt_data_client_into`] — same zero-copy, zero-allocation
/// contract; the returned `Forward` slice borrows `plain`.
#[inline]
pub(crate) fn noise_decrypt_data_server_into<'p>(
    ciphertext: &[u8],
    state: &StatelessTransportState,
    plain: &'p mut [u8],
    nonce: u64,
) -> anyhow::Result<DataServerActionRef<'p>> {
    let len = state.read_message(nonce, ciphertext, plain)?;
    let body = DataServerBodyRef::from_plain_buf(&plain[..len])
        .ok_or_else(|| anyhow::anyhow!("malformed DataServerBody"))?;
    Ok(match body {
        DataServerBodyRef::Packet(data) => DataServerActionRef::Forward(data),
        DataServerBodyRef::KeepAlive(ts) => DataServerActionRef::KeepAlive(ts),
        DataServerBodyRef::Disconnect(code) => DataServerActionRef::Disconnect(code),
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
    /// and that noise_decrypt_data_server_into recovers the original payload from.
    #[test]
    fn test_encode_data_server_packet_roundtrip() {
        use crate::protocol::PacketRef;
        use crate::runtime::crypto::{
            DataServerActionRef, encode_data_server_packet, noise_decrypt_data_server_into,
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
                let mut plain = [0u8; 65536];
                match noise_decrypt_data_server_into(ciphertext, &rx, &mut plain, nonce).unwrap() {
                    DataServerActionRef::Forward(data) => assert_eq!(data, &payload[..]),
                    _ => panic!("expected Forward"),
                }
            }
            _ => panic!("expected DataServer"),
        }
    }

    /// encode_data_client_packet round-trip via PacketRef + noise_decrypt_data_client_into.
    #[test]
    fn test_encode_data_client_packet_roundtrip() {
        use crate::protocol::PacketRef;
        use crate::runtime::crypto::{
            DataClientActionRef, encode_data_client_packet, noise_decrypt_data_client_into,
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
                let mut plain = [0u8; 65536];
                match noise_decrypt_data_client_into(ciphertext, &rx, &mut plain, nonce).unwrap() {
                    DataClientActionRef::Forward(data) => assert_eq!(data, &payload[..]),
                    _ => panic!("expected Forward"),
                }
            }
            _ => panic!("expected DataClient"),
        }
    }

    /// Verify the fixed-size DataServer header layout (`type=3 | nonce BE`).
    #[test]
    fn test_data_server_fixed_header() {
        let (tx, _rx) = make_noise_pair_for_test();
        let payload = vec![0x55u8; 64];
        let nonce = 0x0102_0304_0506_0708u64;

        let mut out = vec![0u8; 65600];
        let n = encode_data_server_packet(&payload, &tx, nonce, &mut out).unwrap();
        assert_eq!(out[0], TYPE_DATA_SERVER);
        assert_eq!(&out[1..9], &nonce.to_be_bytes());
        // Ciphertext runs from the fixed header to the end — no length field.
        assert_eq!(
            n - DATA_SERVER_HDR_LEN,
            ip_packet_plain_len(payload.len()) + 16
        );
    }

    /// Verify the fixed-size DataClient header layout (`type=2 | sid BE | nonce BE`).
    #[test]
    fn test_data_client_fixed_header() {
        let (tx, _rx) = make_noise_pair_for_test();
        let payload = vec![0xAAu8; 128];
        let sid: u32 = 0xDEAD_BEEF;
        let nonce = 0x1122_3344_5566_7788u64;

        let mut out = vec![0u8; 65600];
        let n = encode_data_client_packet(&payload, sid, &tx, nonce, &mut out).unwrap();
        assert_eq!(out[0], TYPE_DATA_CLIENT);
        assert_eq!(&out[1..5], &sid.to_be_bytes());
        assert_eq!(&out[5..13], &nonce.to_be_bytes());
        assert_eq!(
            n - DATA_CLIENT_HDR_LEN,
            ip_packet_plain_len(payload.len()) + 16
        );
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
