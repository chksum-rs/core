//! [`AsyncChksumable`]: the async mirror of [`Chksumable`](crate::chksumable::blocking::Chksumable), and its blanket
//! impl over [`Hashable`]. Dispatch logic for async I/O and filesystem sources is added alongside this trait.

use async_trait::async_trait;

use crate::context::tokio::AsyncChksumer;
use crate::error::Result;
use crate::hashable::{Hash, Hashable};

/// An async source that can be folded into a checksum context.
///
/// Implemented for bytes-like values (via the blanket impl over [`Hashable`]) and for async I/O sources. External
/// types implement [`chksum_into`](AsyncChksumable::chksum_into) by feeding the context through
/// [`AsyncChksumer::update_from_reader`].
// `async_trait` boxes each method's returned future, which clippy misreads as a redundant `#[must_use]` on top of an
// already-must-use type; the future is not actually double-wrapped, so this is a macro-expansion false positive.
#[allow(clippy::double_must_use)]
#[async_trait]
pub trait AsyncChksumable: Send {
    /// Calculates the checksum of the object.
    ///
    /// # Errors
    ///
    /// Propagates any error from [`chksum_into`](AsyncChksumable::chksum_into), such as
    /// [`Error::Io`](crate::Error::Io), [`Error::IsTerminal`](crate::Error::IsTerminal),
    /// [`Error::NotARegularFile`](crate::Error::NotARegularFile),
    /// [`Error::TraversalTooDeep`](crate::Error::TraversalTooDeep), or
    /// [`Error::DirectoryTooLarge`](crate::Error::DirectoryTooLarge).
    async fn chksum<H>(&mut self) -> Result<H::Digest>
    where
        H: Hash + Send,
        Self: Sized,
    {
        let mut ctx = AsyncChksumer::<H>::new();
        self.chksum_into(&mut ctx).await?;
        Ok(ctx.digest())
    }

    /// Updates the async checksum context with data from the object.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`](crate::Error) if the source cannot be read — for I/O sources,
    /// [`Error::Io`](crate::Error::Io) on read failure, [`Error::IsTerminal`](crate::Error::IsTerminal) for terminal
    /// input, [`Error::NotARegularFile`](crate::Error::NotARegularFile) for irregular paths,
    /// [`Error::TraversalTooDeep`](crate::Error::TraversalTooDeep) for directory nesting beyond the configured maximum,
    /// or [`Error::DirectoryTooLarge`](crate::Error::DirectoryTooLarge) for a directory with more entries than the
    /// configured maximum.
    async fn chksum_into<H>(&mut self, ctx: &mut AsyncChksumer<H>) -> Result<()>
    where
        H: Hash + Send;
}

#[async_trait]
impl<T> AsyncChksumable for T
where
    T: Hashable + Send,
{
    async fn chksum_into<H>(&mut self, ctx: &mut AsyncChksumer<H>) -> Result<()>
    where
        H: Hash + Send,
    {
        // `self.hash_into(..)` autorefs to the `&mut T` blanket impl and bypasses `T`'s override; UFCS picks `Self = T`.
        Hashable::hash_into(self, &mut ctx.hash);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;

    use super::AsyncChksumable;
    use crate::context::tokio::AsyncChksumer;
    use crate::error::Result;
    use crate::hashable::{Hash, Hashable};
    use crate::test_util::Collect;

    /// Bytes-like type overriding [`Hashable::hash_into`] to prove the blanket [`AsyncChksumable`] impl dispatches
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

    #[tokio::test]
    async fn async_chksum_dispatches_through_overridden_hash_into() {
        let value = DoublingBytes(b"cd");
        let digest = crate::async_chksum::<Collect>(value)
            .await
            .expect("hash via async_chksum()");
        assert_eq!(
            digest.0,
            b"cdcd".to_vec(),
            "overridden hash_into must be honored by async_chksum()"
        );
    }

    /// External async type that is AsyncChksumable but NOT Hashable.
    struct AsyncExternalReader {
        data: &'static [u8],
    }

    #[async_trait]
    impl AsyncChksumable for AsyncExternalReader {
        async fn chksum_into<H>(&mut self, ctx: &mut AsyncChksumer<H>) -> Result<()>
        where
            H: Hash + Send,
        {
            ctx.update_from_reader(&mut self.data).await?;
            Ok(())
        }
    }

    #[tokio::test]
    async fn external_chksumable_async() {
        let data = b"external async type data";
        let reader = AsyncExternalReader { data };
        let digest = crate::async_chksum::<Collect>(reader)
            .await
            .expect("hash external type async");
        assert_eq!(digest.0, data.to_vec());
    }

    // --- parity: AsyncChksumable::chksum mirrors Chksumable::chksum ---

    #[tokio::test]
    async fn chksum_method_dispatches_through_overridden_hash_into() {
        let mut value = DoublingBytes(b"ef");
        let digest = value.chksum::<Collect>().await.expect("hash via chksum() method");
        assert_eq!(
            digest.0,
            b"efef".to_vec(),
            "overridden hash_into must be honored by AsyncChksumable::chksum()"
        );
    }
}
