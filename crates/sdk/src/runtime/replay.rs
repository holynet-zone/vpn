/// Anti-replay sliding window (WireGuard-style, 2048-bit).
///
/// The window tracks the last WINDOW_SIZE nonces seen for a session.
/// Call `check_and_update` under the session's Mutex before decryption.
/// If it returns `false`, drop the packet immediately without decrypting.
///
/// Unlike WireGuard, we do NOT undo the update if decryption subsequently
/// fails — an attacker can advance the window only if they know the session
/// key (to construct a well-formed ciphertext that passes the nonce pre-check).
/// The minor DoS risk this creates is acceptable given that a key-knowing
/// attacker can flood the session anyway.
use std::fmt;

const WINDOW_SIZE: u64 = 2048;
const BITMAP_WORDS: usize = (WINDOW_SIZE as usize) / 64;

pub(crate) struct ReplayWindow {
    /// Highest nonce accepted so far.
    last: u64,
    /// Circular bitmap: bit at index `n % WINDOW_SIZE` is set when nonce `n` was accepted.
    bitmap: [u64; BITMAP_WORDS],
    /// Whether any packet has been accepted yet (handles nonce=0 correctly).
    initialized: bool,
}

impl fmt::Debug for ReplayWindow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReplayWindow")
            .field("last", &self.last)
            .field("initialized", &self.initialized)
            .finish()
    }
}

impl ReplayWindow {
    pub(crate) fn new() -> Self {
        Self {
            last: 0,
            bitmap: [0; BITMAP_WORDS],
            initialized: false,
        }
    }

    /// Returns `true` if `nonce` is valid and not a replay; marks it as seen.
    /// Returns `false` if the nonce is too old or was already seen.
    pub(crate) fn check_and_update(&mut self, nonce: u64) -> bool {
        if !self.initialized {
            // Very first packet — any nonce is valid.
            self.initialized = true;
            self.last = nonce;
            set_bit(&mut self.bitmap, nonce);
            return true;
        }

        if nonce > self.last {
            let diff = nonce - self.last;
            if diff >= WINDOW_SIZE {
                // New nonce is far ahead: entire window is stale, reset it.
                self.bitmap.fill(0);
            } else {
                // Advance: clear the positions entering the window from the front.
                let start = ((self.last.wrapping_add(1)) % WINDOW_SIZE) as usize;
                let end = (nonce % WINDOW_SIZE) as usize;
                if start <= end {
                    clear_bitmap_range(&mut self.bitmap, start, end);
                } else {
                    clear_bitmap_range(&mut self.bitmap, start, WINDOW_SIZE as usize - 1);
                    clear_bitmap_range(&mut self.bitmap, 0, end);
                }
            }
            self.last = nonce;
        } else {
            let diff = self.last - nonce;
            if diff >= WINDOW_SIZE {
                return false; // Too old to be in the window.
            }
        }

        // Check and set the bit for this nonce.
        let idx = (nonce % WINDOW_SIZE) as usize;
        let word = idx / 64;
        let bit = idx % 64;
        let mask = 1u64 << bit;
        if self.bitmap[word] & mask != 0 {
            return false; // Already seen (replay).
        }
        self.bitmap[word] |= mask;
        true
    }
}

#[inline]
fn set_bit(bitmap: &mut [u64; BITMAP_WORDS], nonce: u64) {
    let idx = (nonce % WINDOW_SIZE) as usize;
    bitmap[idx / 64] |= 1u64 << (idx % 64);
}

/// Clear all bits in `bitmap[start..=end]` (both inclusive, no wrap).
#[inline]
fn clear_bitmap_range(bitmap: &mut [u64; BITMAP_WORDS], start: usize, end: usize) {
    debug_assert!(start <= end);
    debug_assert!(end < WINDOW_SIZE as usize);

    let start_w = start / 64;
    let end_w = end / 64;

    if start_w == end_w {
        // Entire range within one 64-bit word.
        bitmap[start_w] &= !(high_bits_from(start % 64) & low_bits_to(end % 64));
    } else {
        // Clear high bits of the first word, full middle words, low bits of the last word.
        bitmap[start_w] &= !high_bits_from(start % 64);
        bitmap[(start_w + 1)..end_w].fill(0);
        bitmap[end_w] &= !low_bits_to(end % 64);
    }
}

/// Mask with bits `[from_bit, 63]` set.
#[inline]
fn high_bits_from(from_bit: usize) -> u64 {
    !0u64 << from_bit
}

/// Mask with bits `[0, to_bit]` set.
#[inline]
fn low_bits_to(to_bit: usize) -> u64 {
    if to_bit >= 63 {
        !0u64
    } else {
        (1u64 << (to_bit + 1)) - 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_packet_nonce_zero() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_update(0));
    }

    #[test]
    fn replay_nonce_zero_rejected() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_update(0));
        assert!(!w.check_and_update(0));
    }

    #[test]
    fn sequential_nonces_accepted() {
        let mut w = ReplayWindow::new();
        for n in 0u64..256 {
            assert!(w.check_and_update(n), "nonce {n} rejected");
        }
    }

    #[test]
    fn replay_rejected() {
        let mut w = ReplayWindow::new();
        for n in 0u64..10 {
            w.check_and_update(n);
        }
        for n in 0u64..10 {
            assert!(!w.check_and_update(n), "replay nonce {n} accepted");
        }
    }

    #[test]
    fn too_old_rejected() {
        let mut w = ReplayWindow::new();
        w.check_and_update(WINDOW_SIZE + 10);
        // Nonces 0..=10 are now outside the window.
        assert!(!w.check_and_update(0));
        assert!(!w.check_and_update(10));
    }

    #[test]
    fn out_of_order_within_window_accepted() {
        let mut w = ReplayWindow::new();
        w.check_and_update(100);
        assert!(w.check_and_update(50)); // within window, not seen
        assert!(!w.check_and_update(50)); // now it's a replay
    }

    #[test]
    fn large_jump_clears_window() {
        let mut w = ReplayWindow::new();
        for n in 0u64..100 {
            w.check_and_update(n);
        }
        // Jump far ahead.
        assert!(w.check_and_update(WINDOW_SIZE + 100));
        // Old nonces are gone from the window.
        assert!(!w.check_and_update(0)); // too old
    }

    #[test]
    fn window_boundary_exact() {
        let mut w = ReplayWindow::new();
        w.check_and_update(WINDOW_SIZE - 1);
        // Nonce 0 is at the exact window boundary (last - 0 = WINDOW_SIZE - 1 < WINDOW_SIZE) — valid.
        assert!(w.check_and_update(0));
        // Move one step further: nonce 0 is now just outside (last - 0 = WINDOW_SIZE).
        let mut w2 = ReplayWindow::new();
        w2.check_and_update(WINDOW_SIZE);
        assert!(!w2.check_and_update(0)); // exactly at the edge, rejected
    }

    #[test]
    fn advance_by_one_each_step() {
        let mut w = ReplayWindow::new();
        for n in 0u64..WINDOW_SIZE * 2 {
            assert!(w.check_and_update(n), "nonce {n} rejected");
        }
    }

    #[test]
    fn high_nonce_first() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_update(u64::MAX / 2));
        assert!(!w.check_and_update(u64::MAX / 2)); // replay
        assert!(w.check_and_update(u64::MAX / 2 + 1)); // next in sequence
    }
}
