//! [`AsyncChksumer`]/[`AsyncChksumerBuilder`]: the async mirror of the blocking `Chksumer`/`ChksumerBuilder` in
//! `crate::context::blocking`.

use std::fs::Metadata;
use std::io;
use std::num::NonZeroUsize;

use ::tokio::io::{AsyncRead, AsyncReadExt as _};

use crate::DEFAULT_BUFFER_CAPACITY;
use crate::context::buffer::ReadBuffer;
use crate::context::descent::{DepthTicket, Descent};
use crate::diagnostic::Diagnostic;
use crate::hashable::Hash;
use crate::policy::Policy;

/// Builder for [`AsyncChksumer`].
#[derive(Debug)]
pub struct AsyncChksumerBuilder<H>
where
    H: Hash,
{
    capacity: NonZeroUsize,
    hash: H,
    policy: Policy,
}

impl<H> AsyncChksumerBuilder<H>
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

    /// Consumes the builder and constructs the configured [`AsyncChksumer`].
    #[must_use]
    pub fn build(self) -> AsyncChksumer<H> {
        let Self { capacity, hash, policy } = self;
        AsyncChksumer {
            hash,
            buffer: ReadBuffer::new(capacity),
            policy,
            descent: Descent::default(),
        }
    }
}

impl<H> Default for AsyncChksumerBuilder<H>
where
    H: Hash,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<H> From<H> for AsyncChksumerBuilder<H>
where
    H: Hash,
{
    /// Seeds the builder with an existing hash so the built [`AsyncChksumer`] preserves its state.
    fn from(hash: H) -> Self {
        Self { hash, ..Self::new() }
    }
}

/// Stateful async checksum context. Owns hash state and buffer.
///
/// Construct via [`AsyncChksumer::new`], [`AsyncChksumer::with_capacity`], or [`AsyncChksumer::builder`]. Feed data via
/// [`update_from`](AsyncChksumer::update_from) or [`update_from_reader`](AsyncChksumer::update_from_reader).
#[derive(Debug)]
pub struct AsyncChksumer<H>
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

impl<H> AsyncChksumer<H>
where
    H: Hash,
{
    common_methods!();

    /// Creates a new [`AsyncChksumer`] with the default buffer capacity.
    #[must_use]
    pub fn new() -> Self {
        Self::builder().build()
    }

    /// Creates a new [`AsyncChksumer`] with a custom buffer capacity.
    #[must_use]
    pub fn with_capacity(capacity: NonZeroUsize) -> Self {
        Self::builder().capacity(capacity).build()
    }

    /// Returns a builder for [`AsyncChksumer`].
    #[must_use]
    pub fn builder() -> AsyncChksumerBuilder<H> {
        AsyncChksumerBuilder::new()
    }

    /// Folds any [`AsyncChksumable`](crate::AsyncChksumable) source (file, path, dir, etc.) into the hash.
    ///
    /// This is the sole entry point that *resets* traversal bookkeeping (recursion depth and the symlinked-directory
    /// visited set) before folding in `data`, uniformly for every kind of top-level source (`Path`, `DirEntry`,
    /// `ReadDir`, or any external `AsyncChksumable`). Nested descent (a directory entry recursing into a
    /// subdirectory) always calls the source's
    /// [`AsyncChksumable::chksum_into`](crate::chksumable::tokio::AsyncChksumable::chksum_into) directly instead,
    /// never re-entering here, so descent must not trigger a reset. A fresh top-level traversal typically starts
    /// from a newly built `AsyncChksumer` (whose bookkeeping is already zeroed) or from `update_from` on a reused
    /// one; calling
    /// [`AsyncChksumable::chksum_into`](crate::chksumable::tokio::AsyncChksumable::chksum_into) directly on a reused
    /// `AsyncChksumer` — bypassing `update_from` — skips this reset and inherits whatever depth/visited state that
    /// `AsyncChksumer` was left in. Without `update_from`'s reset, an `AsyncChksumer` reused across two separate
    /// top-level calls through it could carry a stale visited entry from the first call into the second, silently
    /// causing a legitimately distinct symlinked directory to be skipped. The recursion depth is reset alongside the
    /// visited set for the same reason: a cancelled `update_from` future (dropped mid-poll, e.g. by a `select!` or
    /// timeout) can leave `depth` incremented from a partial descent, and the next fresh call on the reused
    /// `AsyncChksumer` must still start from a full depth budget rather than an already-exhausted one.
    ///
    /// On error, the hash may already reflect a partially-processed source (e.g. a directory entry framed under
    /// [`NameMode::FileName`](crate::policy::NameMode::FileName) whose contents failed to read); call
    /// [`reset`](Self::reset) before reusing `self` for
    /// anything else.
    ///
    /// # Errors
    ///
    /// Propagates any error produced by the source's
    /// [`AsyncChksumable::chksum_into`](crate::chksumable::tokio::AsyncChksumable::chksum_into), such as
    /// [`Error::Io`](crate::Error::Io) for read failures, [`Error::IsTerminal`](crate::Error::IsTerminal) for terminal
    /// input, [`Error::NotARegularFile`](crate::Error::NotARegularFile) for irregular paths,
    /// [`Error::TraversalTooDeep`](crate::Error::TraversalTooDeep) for directory nesting beyond the configured maximum,
    /// or [`Error::DirectoryTooLarge`](crate::Error::DirectoryTooLarge) for a directory with more entries than the
    /// configured maximum. The depth/entry limits are configurable via [`AsyncChksumerBuilder::max_directory_depth`] /
    /// [`AsyncChksumerBuilder::max_directory_entries`], and the symlinked-directory dedup via
    /// [`AsyncChksumerBuilder::follow_symlink_revisits`].
    #[inline]
    pub async fn update_from<T>(&mut self, mut data: T) -> crate::Result<&mut Self>
    where
        T: crate::chksumable::tokio::AsyncChksumable,
        H: Send,
    {
        self.descent.reset();
        data.chksum_into(self).await?;
        Ok(self)
    }

    /// Drains a raw async `reader` to EOF through the configured buffer, hashing as it goes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`](crate::Error::Io) if reading from `reader` fails.
    pub async fn update_from_reader<R>(&mut self, reader: &mut R) -> crate::Result<u64>
    where
        R: AsyncRead + Unpin + Send,
    {
        let buf = self.buffer.get_or_alloc();
        let mut total = 0;
        loop {
            let n = match reader.read(buf).await {
                Ok(0) => break,
                Ok(n) => n,
                // A signal interrupting the read is not a real failure; retry.
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
    /// [`max_directory_depth`](AsyncChksumerBuilder::max_directory_depth), returning a ticket to return via
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

impl<H> Default for AsyncChksumer<H>
where
    H: Hash,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<H> From<H> for AsyncChksumer<H>
where
    H: Hash,
{
    /// Wraps an existing hash in a context with the default buffer capacity, preserving its state.
    fn from(hash: H) -> Self {
        AsyncChksumerBuilder::from(hash).build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::Collect;

    #[test]
    fn async_bytes_hashable() {
        let data = b"hello";
        let mut ctx = AsyncChksumer::<Collect>::new();
        ctx.update(data.as_slice());
        assert_eq!(ctx.digest().0, data.to_vec());
    }
}
