//! Task-local buffer pool for zero-allocation TUN packet transfer.
//!
//! [`BufPool`] follows the same Arc-reuse pattern as [`CIPHER_POOL`] in
//! `crypto.rs`, but lives as an ordinary local variable inside an async task
//! rather than in thread-local storage.  This is intentional: tokio tasks can
//! be moved between OS threads at `.await` points, so thread-local state is
//! not safe for async use.
//!
//! ## How it works
//!
//! Each call to [`BufPool::copy_to_bytes`] looks for a pool slot whose
//! `Arc::strong_count` is 1 (meaning no live [`Bytes`] object still
//! references it).  If found, the slot is written in-place and wrapped in a
//! new [`Bytes`] view (via `Bytes::from_owner`).  If all slots are still
//! referenced, a new 65 KB buffer is allocated and appended.
//!
//! When the receiver drops the [`Bytes`] the strong count returns to 1 and
//! the slot is reused on the next call — zero allocations in steady state.
//!
//! [`CIPHER_POOL`]: super::crypto

use std::sync::Arc;

use bytes::Bytes;

/// Task-local reusable buffer pool.
///
/// Create one instance per async task that reads raw bytes from a TUN or
/// network device and forwards them through a channel as [`Bytes`].
pub(crate) struct BufPool {
    slots: Vec<Arc<[u8]>>,
    buf_size: usize,
}

impl BufPool {
    pub fn new(buf_size: usize) -> Self {
        Self {
            slots: Vec::new(),
            buf_size,
        }
    }

    /// Copy `data` into a pooled buffer and return a [`Bytes`] slice.
    ///
    /// The underlying buffer is reused once all [`Bytes`] views of it are
    /// dropped.  In steady state (one packet in flight at a time) this
    /// performs zero heap allocations.
    pub fn copy_to_bytes(&mut self, data: &[u8]) -> Bytes {
        // Find a slot that is solely owned by the pool (no live Bytes view).
        // strong_count == 1 ↔ only the pool Vec holds a reference.
        let slot = match self.slots.iter_mut().position(|a| Arc::strong_count(a) == 1) {
            Some(idx) => &mut self.slots[idx],
            None => {
                // All slots are referenced by live Bytes objects; grow the pool.
                self.slots.push(vec![0u8; self.buf_size].into());
                self.slots.last_mut().unwrap()
            }
        };

        // SAFETY: strong_count == 1 and this task is the only writer.
        let buf = Arc::get_mut(slot).expect("Arc::get_mut failed despite strong_count == 1");
        buf[..data.len()].copy_from_slice(data);

        // Clone the Arc so Bytes keeps the buffer alive independently.
        // strong_count: 1 → 2; returns to 1 when Bytes is dropped by receiver.
        Bytes::from_owner(slot.clone()).slice(..data.len())
    }
}
