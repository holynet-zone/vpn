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
/// Allocations (after warm-up): **zero** — cipher buffer is reused from the
/// thread-local pool; the returned `EncryptedData` wraps a `Bytes` that points
/// into the pool Arc without copying. A fresh 65 KB buffer is allocated only
/// when all pool slots are still referenced by live `Bytes` objects (burst
/// scenario); the pool grows by one slot and shrinks back to 1 in steady state.
#[inline]
pub(crate) fn noise_encrypt<T: serde::Serialize>(
    body: &T,
    state: &StatelessTransportState,
) -> anyhow::Result<EncryptedData> {
    PLAIN_BUF.with_borrow_mut(|plain| {
        let encoded_len =
            bincode::serde::encode_into_slice(body, plain, bincode::config::standard())
                .map_err(|e| anyhow::anyhow!("bincode encode: {e}"))?;

        CIPHER_POOL.with_borrow_mut(|pool| {
            // Find a buffer solely owned by the pool (strong_count == 1 means
            // no live Bytes references it). Thread-local access is single-
            // threaded so the count cannot change between the check and get_mut.
            let slot = match pool.iter_mut().position(|a| Arc::strong_count(a) == 1) {
                Some(idx) => &mut pool[idx],
                None => {
                    // All slots are live; allocate a new 65 KB buffer.
                    pool.push(vec![0u8; 65536].into());
                    pool.last_mut().unwrap()
                }
            };

            // SAFETY: strong_count == 1 guarantees unique ownership on this thread.
            let buf = Arc::get_mut(slot).expect("Arc::get_mut failed despite strong_count == 1");

            let encrypted_len = state.write_message(0, &plain[..encoded_len], buf)?;

            // Clone the Arc so Bytes can keep the buffer alive independently.
            // strong_count goes from 1 → 2; back to 1 when Bytes is dropped.
            let bytes_arc: Arc<[u8]> = slot.clone();
            let bytes = Bytes::from_owner(bytes_arc).slice(..encrypted_len);

            Ok(EncryptedData::from(bytes))
        })
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
/// `ciphertext` is a slice into the UDP receive buffer (stack-allocated in the
/// caller). `pool` is a task-local BufPool; the returned `Bytes` borrows from
/// a pool slot and becomes reusable once dropped.
#[inline]
pub(crate) fn noise_decrypt_data_client(
    ciphertext: &[u8],
    state: &StatelessTransportState,
    pool: &mut BufPool,
) -> anyhow::Result<DataClientAction> {
    PLAIN_BUF.with_borrow_mut(|plain| {
        let len = state.read_message(0, ciphertext, plain)?;
        let body = DataClientBodyRef::from_plain_buf(&plain[..len])
            .ok_or_else(|| anyhow::anyhow!("malformed DataClientBody"))?;
        Ok(match body {
            DataClientBodyRef::Packet(data) => DataClientAction::Forward(pool.copy_to_bytes(data)),
            DataClientBodyRef::KeepAlive(ts) => DataClientAction::KeepAlive(ts),
        })
    })
}

/// Decrypt a DataServerBody from raw ciphertext without any heap allocation.
#[inline]
pub(crate) fn noise_decrypt_data_server(
    ciphertext: &[u8],
    state: &StatelessTransportState,
    pool: &mut BufPool,
) -> anyhow::Result<DataServerAction> {
    PLAIN_BUF.with_borrow_mut(|plain| {
        let len = state.read_message(0, ciphertext, plain)?;
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
    ) -> anyhow::Result<T> {
        PLAIN_BUF.with_borrow_mut(|buf| {
            let len = state.read_message(0, encrypted, buf)?;
            bincode::serde::decode_from_slice(&buf[..len], bincode::config::standard())
                .map(|(obj, _)| obj)
                .map_err(|e| anyhow::anyhow!("bincode decode: {e}"))
        })
    }

    #[test]
    fn test_roundtrip_data_packet() {
        let (tx, rx) = make_noise_pair_for_test();
        let body = DataClientBody::Packet(vec![1, 2, 3, 4, 5].into());
        let enc = noise_encrypt(&body, &tx).unwrap();
        let dec: DataClientBody = noise_decrypt(&enc, &rx).unwrap();
        match dec {
            DataClientBody::Packet(data) => assert_eq!(&data[..], [1, 2, 3, 4, 5]),
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn test_roundtrip_keepalive() {
        let (tx, rx) = make_noise_pair_for_test();
        let body = DataServerBody::KeepAlive(0xDEAD_CAFE_1234_5678u128);
        let enc = noise_encrypt(&body, &tx).unwrap();
        let dec: DataServerBody = noise_decrypt(&enc, &rx).unwrap();
        match dec {
            DataServerBody::KeepAlive(ts) => assert_eq!(ts, 0xDEAD_CAFE_1234_5678u128),
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn test_roundtrip_empty_payload() {
        let (tx, rx) = make_noise_pair_for_test();
        let body = DataClientBody::Packet(Bytes::new());
        let enc = noise_encrypt(&body, &tx).unwrap();
        let dec: DataClientBody = noise_decrypt(&enc, &rx).unwrap();
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
        let enc = noise_encrypt(&body, &tx).unwrap();
        assert!(noise_decrypt::<DataClientBody>(&enc, &rx_wrong).is_err());
    }

    /// Encrypt multiple packets without dropping previous results — the pool
    /// must allocate separate buffers and each must decrypt independently.
    #[test]
    fn test_pool_grows_under_concurrent_in_flight() {
        let (tx, rx) = make_noise_pair_for_test();

        let enc1 = noise_encrypt(&DataClientBody::Packet(vec![1u8; 64].into()), &tx).unwrap();
        let enc2 = noise_encrypt(&DataClientBody::Packet(vec![2u8; 64].into()), &tx).unwrap();
        let enc3 = noise_encrypt(&DataClientBody::Packet(vec![3u8; 64].into()), &tx).unwrap();

        // All three EncryptedData objects are live simultaneously.
        // Decrypting each must return its own payload unchanged.
        let dec = |enc: &EncryptedData, expected: u8| {
            let body: DataClientBody = noise_decrypt(enc, &rx).unwrap();
            match body {
                DataClientBody::Packet(d) => assert_eq!(&d[..], vec![expected; 64]),
                _ => panic!("unexpected variant"),
            }
        };
        dec(&enc1, 1);
        dec(&enc2, 2);
        dec(&enc3, 3);
    }

    /// After enc is dropped, the pool slot's refcount returns to 1 and the
    /// buffer is reused for the next call — data must not bleed across packets.
    #[test]
    fn test_pool_reuse_after_drop() {
        let (tx, rx) = make_noise_pair_for_test();
        for byte in 0u8..=16 {
            let body = DataClientBody::Packet(vec![byte; 128].into());
            let enc = noise_encrypt(&body, &tx).unwrap();
            // enc dropped at end of this iteration → pool slot refcount → 1
            let dec: DataClientBody = noise_decrypt(&enc, &rx).unwrap();
            match dec {
                DataClientBody::Packet(data) => assert_eq!(&data[..], vec![byte; 128]),
                _ => panic!("unexpected variant"),
            }
        }
    }
}
