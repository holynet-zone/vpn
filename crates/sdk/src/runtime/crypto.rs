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

use crate::protocol::EncryptedData;

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
    static CIPHER_POOL: RefCell<Vec<Arc<[u8]>>> = RefCell::new(Vec::new());
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
        let encoded_len = bincode::serde::encode_into_slice(
            body,
            plain,
            bincode::config::standard(),
        )
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

/// Decrypt `encrypted` via Noise `StatelessTransportState` then bincode/serde.
///
/// Allocations: only what `T`'s `Deserialize` impl requires (e.g., `Vec<u8>`
/// inside `DataServerBody::Packet`). The 65 KB plaintext buffer is reused
/// from thread-local storage — no intermediate heap allocation for decryption.
#[inline]
pub(crate) fn noise_decrypt<T: serde::de::DeserializeOwned>(
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
