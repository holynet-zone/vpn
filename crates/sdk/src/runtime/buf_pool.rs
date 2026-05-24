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
//! referenced, a new buffer is allocated and appended.
//!
//! When the receiver drops the [`Bytes`] the strong count returns to 1 and
//! the slot is reused on the next call — zero allocations in steady state.
//!
//! ## Slot sizing
//!
//! `buf_size` should be set to the expected maximum decrypted packet size,
//! typically `MTU_BUF`.  Packets larger than `buf_size` are handled with a
//! one-off `Bytes::copy_from_slice` allocation (rare under normal MTU).
//!
//! [`CIPHER_POOL`]: super::crypto

#[cfg(test)]
/// Test default: standard Ethernet MTU (1500 B) + 32 bytes slack.
const MTU_BUF: usize = 1500 + 32;

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
    ///
    /// If `data.len() > buf_size` (packet larger than the MTU hint), falls
    /// back to a one-off `Bytes::copy_from_slice` allocation rather than
    /// panicking.
    pub fn copy_to_bytes(&mut self, data: &[u8]) -> Bytes {
        if data.len() > self.buf_size {
            // Oversized packet — above MTU hint. One-off allocation; does not
            // pollute the pool with an oversized slot that wastes memory on
            // every subsequent reuse.
            return Bytes::copy_from_slice(data);
        }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reuse_after_drop() {
        let mut pool = BufPool::new(MTU_BUF);
        let data = vec![0xABu8; 64];

        let b1 = pool.copy_to_bytes(&data);
        assert_eq!(&b1[..], &data[..]);
        drop(b1);

        // slot must be reused — pool should still have exactly 1 slot
        let b2 = pool.copy_to_bytes(&data);
        assert_eq!(&b2[..], &data[..]);
        assert_eq!(pool.slots.len(), 1);
    }

    #[test]
    fn test_grows_when_all_referenced() {
        let mut pool = BufPool::new(MTU_BUF);
        let data = vec![0x55u8; 32];

        let b1 = pool.copy_to_bytes(&data);
        let b2 = pool.copy_to_bytes(&data); // b1 still alive → new slot
        assert_eq!(pool.slots.len(), 2);
        drop(b1);
        drop(b2);
    }

    #[test]
    fn test_oversized_fallback_no_panic() {
        let mut pool = BufPool::new(MTU_BUF);
        // A packet larger than MTU_BUF must not panic and must return correct data.
        let big = vec![0xFFu8; MTU_BUF + 1];
        let b = pool.copy_to_bytes(&big);
        assert_eq!(&b[..], &big[..]);
        // Pool slots must remain untouched by the oversized fallback.
        assert_eq!(pool.slots.len(), 0);
    }

    #[test]
    fn test_mtu_buf_sized_packet_uses_pool() {
        let mut pool = BufPool::new(MTU_BUF);
        // Exactly MTU_BUF bytes must go through the pool, not the fallback.
        let exact = vec![0x77u8; MTU_BUF];
        let b = pool.copy_to_bytes(&exact);
        assert_eq!(&b[..], &exact[..]);
        assert_eq!(pool.slots.len(), 1);
    }
}
