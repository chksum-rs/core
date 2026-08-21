//! [`Chksumer`]/[`ChksumerBuilder`]: the synchronous, stateful checksum context. The `tokio` sibling module (behind
//! the `async-runtime-tokio` feature) mirrors this for async I/O.

use std::fs::Metadata;
use std::io::{self, Read, Write};
use std::num::NonZeroUsize;

use crate::DEFAULT_BUFFER_CAPACITY;
use crate::context::buffer::ReadBuffer;
use crate::context::descent::{DepthTicket, Descent};
use crate::diagnostic::Diagnostic;
use crate::hashable::Hash;
use crate::policy::Policy;

/// Builder for [`Chksumer`].
#[derive(Debug)]
pub struct ChksumerBuilder<H>
where
    H: Hash,
{
    capacity: NonZeroUsize,
    hash: H,
    policy: Policy,
}

impl<H> ChksumerBuilder<H>
where
    H: Hash,
{
    policy_setters!();

    fn new() -> Self {
        Self {
            capacity: DEFAULT_BUFFER_CAPACITY,
            hash: H::default(),
            policy: Policy::default(),
        }
    }

    /// Override the read-buffer capacity.
    #[must_use = "this method consumes and returns the builder; assign the result or it is dropped"]
    pub fn capacity(mut self, capacity: NonZeroUsize) -> Self {
        self.capacity = capacity;
        self
    }

    /// Consumes the builder and constructs the configured [`Chksumer`].
    #[must_use]
    pub fn build(self) -> Chksumer<H> {
        let Self { capacity, hash, policy } = self;
        Chksumer {
            hash,
            buffer: ReadBuffer::new(capacity),
            policy,
            descent: Descent::default(),
        }
    }
}

impl<H> Default for ChksumerBuilder<H>
where
    H: Hash,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<H> From<H> for ChksumerBuilder<H>
where
    H: Hash,
{
    /// Seeds the builder with an existing hash so the built [`Chksumer`] preserves its state.
    fn from(hash: H) -> Self {
        Self { hash, ..Self::new() }
    }
}

/// Stateful checksum context. Owns hash state and buffer.
///
/// Construct via [`Chksumer::new`], [`Chksumer::with_capacity`], or [`Chksumer::builder`]. Feed data via
/// [`update`](Chksumer::update), [`update_from`](Chksumer::update_from),
/// [`update_from_reader`](Chksumer::update_from_reader), or the [`io::Write`] impl.
#[derive(Debug)]
pub struct Chksumer<H>
where
    H: Hash,
{
    pub(crate) hash: H,
    /// Read-buffer capacity/scratch: see [`ReadBuffer`].
    buffer: ReadBuffer,
    /// Directory-traversal policy configured via the builder: see [`Policy`].
    policy: Policy,
    /// Directory-recursion depth/visited-set bookkeeping: see [`Descent`].
    descent: Descent,
}

impl<H> Chksumer<H>
where
    H: Hash,
{
    common_methods!();

    /// Creates a new [`Chksumer`] with the default buffer capacity.
    #[must_use]
    pub fn new() -> Self {
        Self::builder().build()
    }

    /// Creates a new [`Chksumer`] with a custom buffer capacity.
    #[must_use]
    pub fn with_capacity(capacity: NonZeroUsize) -> Self {
        Self::builder().capacity(capacity).build()
    }

    /// Returns a builder for [`Chksumer`].
    #[must_use]
    pub fn builder() -> ChksumerBuilder<H> {
        ChksumerBuilder::new()
    }

    /// Folds any [`Chksumable`](crate::Chksumable) source (file, path, dir, etc.) into the hash.
    ///
    /// This is the sole entry point that *resets* traversal bookkeeping (recursion depth and the symlinked-directory
    /// visited set) before folding in `data`, uniformly for every kind of top-level source (`Path`, `DirEntry`,
    /// `ReadDir`, or any external `Chksumable`). Nested descent (a directory entry recursing into a subdirectory)
    /// always calls the source's
    /// [`Chksumable::chksum_into`](crate::chksumable::blocking::Chksumable::chksum_into) directly instead, never
    /// re-entering here, so descent must not trigger a reset. A fresh top-level traversal typically starts from a
    /// newly built `Chksumer` (whose bookkeeping is already zeroed) or from `update_from` on a reused one; calling
    /// [`Chksumable::chksum_into`](crate::chksumable::blocking::Chksumable::chksum_into) directly on a reused
    /// `Chksumer` — bypassing `update_from` — skips this reset and inherits whatever depth/visited state that
    /// `Chksumer` was left in. Without `update_from`'s reset, a `Chksumer` reused across two separate top-level calls
    /// through it could carry a stale visited entry from the first call into the second, silently causing a
    /// legitimately distinct symlinked directory to be skipped. The recursion depth is reset alongside the visited set
    /// for the same reason: a `Chksumer` reused after an earlier call returned early (error, or a caller-driven early
    /// stop) must not start the next fresh call from an already-consumed depth budget.
    ///
    /// On error, the hash may already reflect a partially-processed source (e.g. a directory entry framed under
    /// [`NameMode::FileName`](crate::policy::NameMode::FileName) whose contents failed to read); call
    /// [`reset`](Self::reset) before reusing `self` for
    /// anything else.
    ///
    /// # Errors
    ///
    /// Propagates any error produced by the source's
    /// [`Chksumable::chksum_into`](crate::chksumable::blocking::Chksumable::chksum_into), such as
    /// [`Error::Io`](crate::Error::Io) for read failures, [`Error::IsTerminal`](crate::Error::IsTerminal) for
    /// terminal input,
    /// [`Error::NotARegularFile`](crate::Error::NotARegularFile) for irregular paths,
    /// [`Error::TraversalTooDeep`](crate::Error::TraversalTooDeep) for directory nesting beyond the configured maximum,
    /// or [`Error::DirectoryTooLarge`](crate::Error::DirectoryTooLarge) for a directory with more entries than the
    /// configured maximum. The depth/entry limits are configurable via [`ChksumerBuilder::max_directory_depth`] /
    /// [`ChksumerBuilder::max_directory_entries`], and the symlinked-directory dedup via
    /// [`ChksumerBuilder::follow_symlink_revisits`].
    #[inline]
    pub fn update_from<T>(&mut self, mut data: T) -> crate::Result<&mut Self>
    where
        T: crate::chksumable::blocking::Chksumable,
    {
        self.descent.reset();
        data.chksum_into(self)?;
        Ok(self)
    }

    /// Drains a raw `reader` to EOF through the configured buffer, hashing as it goes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`](crate::Error::Io) if reading from `reader` fails.
    pub fn update_from_reader<R>(&mut self, reader: &mut R) -> crate::Result<u64>
    where
        R: Read,
    {
        let buf = self.buffer.get_or_alloc();
        let mut total = 0;
        loop {
            let n = match reader.read(buf) {
                Ok(0) => break,
                Ok(n) => n,
                // A signal interrupting the read is not a real failure; retry, as `io::copy` and `Read::read_to_end`
                // do.
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                    self.policy.notify(|| Diagnostic::ReadInterrupted);
                    continue;
                },
                Err(e) => return Err(e.into()),
            };
            self.hash.update(&buf[..n]);
            total += n as u64;
        }
        Ok(total)
    }

    /// Returns the directory-traversal policy configured via the builder.
    pub(crate) fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Admits one more level of directory recursion (S1) against the configured
    /// [`max_directory_depth`](ChksumerBuilder::max_directory_depth), returning a ticket to return via
    /// [`leave_directory`](Self::leave_directory).
    ///
    /// # Errors
    ///
    /// Returns [`Error::TraversalTooDeep`](crate::Error::TraversalTooDeep) if nesting would exceed the configured
    /// maximum.
    pub(crate) fn enter_directory(&mut self) -> crate::Result<DepthTicket> {
        self.descent.enter(self.policy.max_directory_depth)
    }

    /// Returns one level of directory recursion admitted by the matching [`enter_directory`](Self::enter_directory).
    pub(crate) fn leave_directory(&mut self, ticket: DepthTicket) {
        self.descent.leave(ticket);
    }

    /// Records a symlinked directory's identity for cycle/fan-out protection (S3). Returns `true` if the caller should
    /// descend into it — the first encounter this traversal, an identity unknowable on this platform, or the
    /// `follow_symlink_revisits` opt-out is set — and `false` if it was already visited and must be skipped.
    pub(crate) fn visit_symlinked_dir(&mut self, metadata: &Metadata) -> bool {
        self.descent
            .visit_symlinked_dir(self.policy.follow_symlink_revisits, metadata)
    }
}

impl<H> Default for Chksumer<H>
where
    H: Hash,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<H> From<H> for Chksumer<H>
where
    H: Hash,
{
    /// Wraps an existing hash in a context with the default buffer capacity, preserving its state.
    fn from(hash: H) -> Self {
        ChksumerBuilder::from(hash).build()
    }
}

/// Lets a [`Chksumer`] act as an [`io::Write`] sink, so data can be streamed in with [`io::copy`] or `write!`. Each
/// write feeds the hash directly; `flush` is a no-op and writes never fail.
impl<H> Write for Chksumer<H>
where
    H: Hash,
{
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.hash.update(buf);
        Ok(buf.len())
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::diagnostic::Diagnostic;
    use crate::test_util::Collect;

    #[test]
    fn bytes_hashable() {
        let data = b"hello";
        let mut ctx = Chksumer::<Collect>::new();
        ctx.update(data.as_slice());
        assert_eq!(ctx.digest().0, data.to_vec());
    }

    #[test]
    fn update_from_reader_notifies_on_interrupted_retry() {
        /// Reader that fails once with `Interrupted` before yielding its data.
        struct FlakyReader {
            data: &'static [u8],
            interrupted: bool,
        }

        impl Read for FlakyReader {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if !self.interrupted {
                    self.interrupted = true;
                    return Err(io::Error::from(io::ErrorKind::Interrupted));
                }
                let n = std::cmp::min(buf.len(), self.data.len());
                buf[..n].copy_from_slice(&self.data[..n]);
                self.data = &self.data[n..];
                Ok(n)
            }
        }

        let diagnostics: Arc<Mutex<Vec<Diagnostic>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&diagnostics);
        let mut ctx = Chksumer::<Collect>::builder()
            .on_diagnostic(move |d| sink.lock().expect("lock diagnostics").push(d.clone()))
            .build();
        let mut reader = FlakyReader {
            data: b"hello",
            interrupted: false,
        };
        ctx.update_from_reader(&mut reader).expect("read through interruption");

        assert_eq!(ctx.digest().0, b"hello".to_vec());
        let seen = diagnostics.lock().expect("lock diagnostics");
        assert_eq!(seen.len(), 1, "expected one ReadInterrupted diagnostic: {seen:?}");
        assert!(
            matches!(seen[0], Diagnostic::ReadInterrupted),
            "unexpected diagnostic: {seen:?}"
        );
    }

    // --- lazy read buffer: capacity() reports the configured capacity even before any reader has been drained, and
    //     the buffer materializes correctly (and only) on first `update_from_reader` use ---

    #[test]
    fn capacity_reflects_configured_value_before_any_reader_use() {
        let capacity = NonZeroUsize::new(123).expect("non-zero");
        let ctx = Chksumer::<Collect>::with_capacity(capacity);
        assert_eq!(
            ctx.capacity(),
            capacity,
            "capacity() must report the configured capacity even though no reader has been drained yet"
        );
    }

    #[test]
    fn update_from_reader_materializes_and_reuses_the_buffer_correctly() {
        let mut ctx = Chksumer::<Collect>::with_capacity(NonZeroUsize::new(4).expect("non-zero"));
        // First call materializes the buffer at the configured capacity; content larger than that capacity must still
        // be drained correctly across multiple internal reads.
        let mut first = b"hello world".as_slice();
        ctx.update_from_reader(&mut first)
            .expect("first read materializes the buffer");
        // Second call reuses the already-materialized buffer.
        let mut second = b"!".as_slice();
        ctx.update_from_reader(&mut second)
            .expect("second read reuses the buffer");
        assert_eq!(ctx.digest().0, b"hello world!".to_vec());
        assert_eq!(
            ctx.capacity().get(),
            4,
            "capacity() must be unaffected by buffer materialization"
        );
    }
}
