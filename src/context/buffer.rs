//! [`ReadBuffer`]: the reusable, lazily-allocated read buffer shared by [`Chksumer`](crate::Chksumer) and
//! [`AsyncChksumer`](crate::AsyncChksumer).

use std::num::NonZeroUsize;

/// Reusable scratch buffer for draining a reader. Empty until the first [`get_or_alloc`](Self::get_or_alloc) call
/// materializes it at the configured capacity; reused across all reads after that. Keeps a context used only for
/// in-memory hashing (`chksum`/`update`) free of the read-buffer allocation entirely, since such a context never
/// calls `get_or_alloc`.
#[derive(Debug)]
pub(crate) struct ReadBuffer {
    /// Configured capacity; the buffer itself is materialized lazily at this size (see `buffer`).
    capacity: NonZeroUsize,
    // Zero-filled because safe Rust has no way to expose an uninitialized `[u8]` of this length as a readable
    // `&mut [u8]`; materialized once, on first use, and reused across all reads after that.
    buffer: Box<[u8]>,
}

impl ReadBuffer {
    /// Creates an empty buffer configured to materialize at `capacity` on first [`get_or_alloc`](Self::get_or_alloc)
    /// call.
    pub(crate) fn new(capacity: NonZeroUsize) -> Self {
        Self {
            capacity,
            buffer: Box::new([]),
        }
    }

    /// Returns the configured capacity, unaffected by whether the buffer has materialized yet.
    pub(crate) fn capacity(&self) -> NonZeroUsize {
        self.capacity
    }

    /// Returns the scratch buffer, materializing it at the configured capacity on first call.
    pub(crate) fn get_or_alloc(&mut self) -> &mut [u8] {
        if self.buffer.is_empty() {
            self.buffer = vec![0u8; self.capacity.get()].into_boxed_slice();
        }
        &mut self.buffer
    }
}
