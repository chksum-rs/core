//! [`Chksumable`]: the source-side trait that folds a value into a [`Chksumer`](crate::Chksumer) context, and its
//! blanket impl over [`Hashable`]. Dispatch logic for `std` I/O and filesystem sources is added alongside this trait
//! in the `tokio` mirror (behind the `async-runtime-tokio` feature).

use crate::context::blocking::Chksumer;
use crate::error::Result;
use crate::hashable::{Hash, Hashable};

/// A source that can be folded into a checksum context.
///
/// Implemented for bytes-like values (via the blanket impl over [`Hashable`]) and for I/O sources such as
/// [`File`](std::fs::File), [`Path`](std::path::Path), and directories. External types implement
/// [`chksum_into`](Chksumable::chksum_into) by feeding the context through [`Chksumer::update_from_reader`],
/// [`Chksumer::update`], or the [`io::Write`](std::io::Write) impl.
///
/// A `&str`/[`String`] argument dispatches through the [`Hashable`] blanket impl and hashes the *string's own
/// bytes*, not a file at that path — pass a [`Path`](std::path::Path) to hash the filesystem target instead; see the
/// crate repository's `docs/GOTCHAS.md` for this and other surprising-but-compiling call shapes. A
/// [`File`](std::fs::File) is hashed from its *current* cursor position, and reading through a shared `&File` still
/// advances the caller's handle to EOF, since the offset lives in the kernel, not in the borrow; a
/// [`ReadDir`](std::fs::ReadDir) is hashed from wherever its iterator was left, so entries already consumed via
/// `next()` are silently excluded. See `docs/GOTCHAS.md` for worked examples of both.
pub trait Chksumable {
    /// Calculates the checksum of the object.
    ///
    /// # Errors
    ///
    /// Propagates any error from [`chksum_into`](Chksumable::chksum_into), such as [`Error::Io`](crate::Error::Io),
    /// [`Error::IsTerminal`](crate::Error::IsTerminal), [`Error::NotARegularFile`](crate::Error::NotARegularFile),
    /// [`Error::TraversalTooDeep`](crate::Error::TraversalTooDeep), or
    /// [`Error::DirectoryTooLarge`](crate::Error::DirectoryTooLarge).
    fn chksum<H>(&mut self) -> Result<H::Digest>
    where
        H: Hash,
    {
        let mut ctx = Chksumer::<H>::new();
        self.chksum_into(&mut ctx)?;
        Ok(ctx.digest())
    }

    /// Updates the checksum context with data from the object.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`](crate::Error) if the source cannot be read — for I/O sources,
    /// [`Error::Io`](crate::Error::Io) on read failure, [`Error::IsTerminal`](crate::Error::IsTerminal) for terminal
    /// input, [`Error::NotARegularFile`](crate::Error::NotARegularFile) for irregular paths,
    /// [`Error::TraversalTooDeep`](crate::Error::TraversalTooDeep) for directory nesting beyond the configured maximum,
    /// or [`Error::DirectoryTooLarge`](crate::Error::DirectoryTooLarge) for a directory with more entries than the
    /// configured maximum.
    fn chksum_into<H>(&mut self, ctx: &mut Chksumer<H>) -> Result<()>
    where
        H: Hash;
}

impl<T> Chksumable for T
where
    T: Hashable,
{
    #[inline]
    fn chksum_into<H>(&mut self, ctx: &mut Chksumer<H>) -> Result<()>
    where
        H: Hash,
    {
        // `self.hash_into(..)` autorefs to the `&mut T` blanket impl and bypasses `T`'s override; UFCS picks `Self = T`.
        Hashable::hash_into(self, &mut ctx.hash);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::io::Read;

    use super::Chksumable;
    use crate::chksum;
    use crate::context::blocking::Chksumer;
    use crate::error::Result;
    use crate::hashable::{Hash, Hashable};
    use crate::test_util::Collect;

    /// External type that is Chksumable but NOT Hashable.
    struct ExternalReader {
        data: &'static [u8],
    }

    impl ExternalReader {
        fn new(data: &'static [u8]) -> Self {
            ExternalReader { data }
        }
    }

    impl Read for ExternalReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = std::cmp::min(buf.len(), self.data.len());
            buf[..n].copy_from_slice(&self.data[..n]);
            self.data = &self.data[n..];
            Ok(n)
        }
    }

    impl Chksumable for ExternalReader {
        fn chksum_into<H>(&mut self, ctx: &mut Chksumer<H>) -> Result<()>
        where
            H: Hash,
        {
            ctx.update_from_reader(self)?;
            Ok(())
        }
    }

    /// Bytes-like type overriding [`Hashable::hash_into`] to prove the blanket [`Chksumable`] impl dispatches
    /// through it rather than hardcoding `ctx.hash.update(self)`.
    struct DoublingBytes(&'static [u8]);

    impl AsRef<[u8]> for DoublingBytes {
        fn as_ref(&self) -> &[u8] {
            self.0
        }
    }

    impl Hashable for DoublingBytes {
        fn hash_into<H>(&self, hash: &mut H)
        where
            H: Hash,
        {
            // Deliberately deviates from the default (single `hash.update(self)`) so a test relying on the default
            // would fail: this override feeds the bytes twice.
            hash.update(self.0);
            hash.update(self.0);
        }
    }

    #[test]
    fn chksum_dispatches_through_overridden_hash_into() {
        let value = DoublingBytes(b"ab");
        let digest = crate::chksum::<Collect>(value).expect("hash via chksum()");
        assert_eq!(
            digest.0,
            b"abab".to_vec(),
            "overridden hash_into must be honored by chksum()"
        );
    }

    #[test]
    fn external_chksumable_sync() {
        let data = b"external type data";
        let reader = ExternalReader::new(data);
        let digest = chksum::<Collect>(reader).expect("hash external type");
        assert_eq!(digest.0, data.to_vec());
    }
}
