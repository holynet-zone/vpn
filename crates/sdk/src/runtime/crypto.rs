//! Shared noise encrypt/decrypt helpers with zero-allocation hot path.
//!
//! Each worker thread owns two 65 KB buffers stored in thread-local storage
//! (BSS segment — no heap allocation, no initialization overhead at runtime).
//! The buffers are reused across every call on the same thread.
//!
//! Contract: these functions must not be called re-entrantly on the same thread
//! (e.g., from within a bincode Serialize impl that itself calls noise_encrypt).
//! This is guaranteed by the current call sites which are plain sync functions
//! invoked from async executors without interior recursion.

use std::cell::RefCell;

use snow::StatelessTransportState;

use crate::protocol::EncryptedData;

thread_local! {
    /// Intermediate plaintext buffer: used for bincode encode (encrypt) or
    /// noise decode output (decrypt). Stored in thread-local BSS — zero cost.
    static PLAIN_BUF: RefCell<[u8; 65536]> = const { RefCell::new([0u8; 65536]) };

    /// Intermediate ciphertext buffer: used for noise encode output.
    static CIPHER_BUF: RefCell<[u8; 65536]> = const { RefCell::new([0u8; 65536]) };
}

/// Encrypt `body` via bincode/serde then Noise `StatelessTransportState`.
///
/// Allocations: one `Vec<u8>` for the returned `EncryptedData` (unavoidable —
/// the caller needs ownership). The two 65 KB intermediate buffers are reused
/// from thread-local storage.
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

        CIPHER_BUF.with_borrow_mut(|cipher| {
            let encrypted_len =
                state.write_message(0, &plain[..encoded_len], cipher)?;
            // One allocation per packet: copy encrypted bytes to owned Vec.
            Ok(cipher[..encrypted_len].to_vec().into())
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
