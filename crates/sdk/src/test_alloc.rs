//! Test-only allocation counter.
//!
//! A global allocator (active only under `cfg(test)`) that delegates to the
//! system allocator and bumps a **thread-local** counter on every alloc/realloc.
//! Thread-local isolation means a zero-alloc assertion on one test thread is not
//! disturbed by other tests running in parallel. Used to prove the steady-state
//! packet hot path performs no heap allocation after warm-up.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    static ALLOCS: Cell<u64> = const { Cell::new(0) };
}

pub struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // `try_with` never panics during TLS teardown; a `Cell<u64>` needs no
        // allocation to initialise, so counting here cannot recurse.
        let _ = ALLOCS.try_with(|c| c.set(c.get() + 1));
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let _ = ALLOCS.try_with(|c| c.set(c.get() + 1));
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

/// Allocations counted on the current thread since the last [`reset`].
pub fn count() -> u64 {
    ALLOCS.with(|c| c.get())
}

/// Reset the current thread's allocation counter to zero.
pub fn reset() {
    ALLOCS.with(|c| c.set(0));
}
