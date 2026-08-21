//! Core traits and functions for straightforward hash computation of bytes, files, directories and more.
//!
//! # Setup
//!
//! To use this crate, add the following entry to your `Cargo.toml` file in the `dependencies` section:
//!
//! ```toml
//! [dependencies]
//! chksum-core = "0.1.0"
//! ```
//!
//! Alternatively, you can use the [`cargo add`](https://doc.rust-lang.org/cargo/commands/cargo-add.html) subcommand:
//!
//! ```sh
//! cargo add chksum-core
//! ```
//!
//! # Features
//!
//! ## Asynchronous Runtime
//!
//! * `async-runtime-tokio`: Enables async interface for Tokio runtime.
//!
//! By default, none of these features is enabled.
//!
//! # Example Crates
//!
//! For implementation-specific examples, refer to the source code of the following crates:
//!
//! * [`chksum-md5`](https://docs.rs/chksum-md5/)
//! * [`chksum-sha1`](https://docs.rs/chksum-sha1/)
//! * [`chksum-sha2`](https://docs.rs/chksum-sha2/)
//!     * [`chksum-sha2-224`](https://docs.rs/chksum-sha2-224/)
//!     * [`chksum-sha2-256`](https://docs.rs/chksum-sha2-256/)
//!     * [`chksum-sha2-384`](https://docs.rs/chksum-sha2-384/)
//!     * [`chksum-sha2-512`](https://docs.rs/chksum-sha2-512/)
//!
//! # License
//!
//! This crate is licensed under the MIT License.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]

mod chksumable;
mod context;
mod diagnostic;
mod error;
mod hashable;
mod policy;
mod traversal;
mod visited;

use std::num::NonZeroUsize;

#[doc(no_inline)]
pub use chksum_hash_core as hash;

#[cfg(feature = "async-runtime-tokio")]
pub use crate::chksumable::AsyncChksumable;
pub use crate::chksumable::Chksumable;
#[cfg(feature = "async-runtime-tokio")]
pub use crate::context::{AsyncChksumer, AsyncChksumerBuilder};
pub use crate::context::{Chksumer, ChksumerBuilder};
pub use crate::diagnostic::Diagnostic;
pub use crate::error::{Error, Result};
pub use crate::hashable::{Digest, Hash, Hashable};
pub use crate::policy::{DEFAULT_MAX_DIRECTORY_DEPTH, DEFAULT_MAX_DIRECTORY_ENTRIES, IrregularFile, NameMode};

#[cfg(target_os = "espidf")]
const DEFAULT_BUFFER_CAPACITY_BYTES: usize = 512;
#[cfg(not(target_os = "espidf"))]
const DEFAULT_BUFFER_CAPACITY_BYTES: usize = 64 * 1024;

/// Default I/O buffer capacity (64 KiB on most platforms, 512 B on espidf).
///
/// Read overhead flattens out around 64 KiB, the same capacity hashing tools like `b3sum` default to; larger buffers
/// buy little and cost memory per context. See also [`DEFAULT_MAX_DIRECTORY_DEPTH`] and
/// [`DEFAULT_MAX_DIRECTORY_ENTRIES`], the directory-traversal counterparts to this buffer default.
pub const DEFAULT_BUFFER_CAPACITY: NonZeroUsize = match NonZeroUsize::new(DEFAULT_BUFFER_CAPACITY_BYTES) {
    Some(n) => n,
    None => panic!("DEFAULT_BUFFER_CAPACITY must be non-zero"),
};

/// Creates a default hash.
#[must_use]
pub fn default<H>() -> H
where
    H: Hash,
{
    H::default()
}

/// Computes the hash of in-memory bytes-like input.
#[must_use]
pub fn hash<H>(data: impl Hashable) -> H::Digest
where
    H: Hash,
{
    data.hash::<H>()
}

/// Returns a builder for a [`Chksumer`].
#[must_use]
pub fn builder<H>() -> ChksumerBuilder<H>
where
    H: Hash,
{
    Chksumer::<H>::builder()
}

/// Computes the checksum of a [`Chksumable`] source such as a file, path, or directory.
///
/// This always uses a default-configured [`Chksumer`]; for non-default policies (e.g. [`NameMode`],
/// [`IrregularFile`], directory limits, or diagnostic hooks), use [`chksum_with`] instead.
///
/// A `&str`/[`String`] path argument compiles but hashes the *string's own bytes*, not a file at that path — that
/// call goes through [`Hashable`] instead of the filesystem [`Chksumable`] impls; pass a
/// [`Path`](std::path::Path)/[`PathBuf`](std::path::PathBuf) to hash the filesystem target. See `docs/GOTCHAS.md` in
/// the crate repository for this and other surprising-but-compiling call shapes.
///
/// # Errors
///
/// Returns an [`Error`] if the source cannot be read; see [`Chksumable::chksum_into`] for the specific variants.
pub fn chksum<H>(mut data: impl Chksumable) -> Result<H::Digest>
where
    H: Hash,
{
    data.chksum::<H>()
}

/// Computes the checksum of a [`Chksumable`] source using a [`Chksumer`] configured via `configure`.
///
/// This is the way to run a one-shot checksum with non-default policies (e.g. [`NameMode`], [`IrregularFile`],
/// directory limits, buffer capacity, or diagnostic hooks), in contrast to [`chksum`], which always uses a
/// default-configured context.
///
/// # Errors
///
/// Returns an [`Error`] if the source cannot be read; see [`Chksumer::update_from`] for the specific variants.
pub fn chksum_with<H>(
    data: impl Chksumable,
    configure: impl FnOnce(ChksumerBuilder<H>) -> ChksumerBuilder<H>,
) -> Result<H::Digest>
where
    H: Hash,
{
    let mut ctx = configure(Chksumer::builder()).build();
    ctx.update_from(data)?;
    Ok(ctx.digest())
}

/// Returns a builder for an [`AsyncChksumer`].
#[cfg(feature = "async-runtime-tokio")]
#[must_use]
pub fn async_builder<H>() -> AsyncChksumerBuilder<H>
where
    H: Hash,
{
    AsyncChksumer::<H>::builder()
}

/// Asynchronously computes the checksum of an [`AsyncChksumable`] source.
///
/// This always uses a default-configured [`AsyncChksumer`]; for non-default policies (e.g. [`NameMode`],
/// [`IrregularFile`], directory limits, or diagnostic hooks), use [`async_chksum_with`] instead.
///
/// # Errors
///
/// Returns an [`Error`] if the source cannot be read; see [`AsyncChksumable::chksum_into`] for the specific variants.
#[cfg(feature = "async-runtime-tokio")]
pub async fn async_chksum<H>(mut data: impl AsyncChksumable) -> Result<H::Digest>
where
    H: Hash + Send,
{
    let mut ctx = AsyncChksumer::<H>::new();
    data.chksum_into(&mut ctx).await?;
    Ok(ctx.digest())
}

/// Asynchronously computes the checksum of an [`AsyncChksumable`] source using an [`AsyncChksumer`] configured via
/// `configure`.
///
/// This is the way to run a one-shot asynchronous checksum with non-default policies (e.g. [`NameMode`],
/// [`IrregularFile`], directory limits, buffer capacity, or diagnostic hooks), in contrast to [`async_chksum`], which
/// always uses a default-configured context.
///
/// # Errors
///
/// Returns an [`Error`] if the source cannot be read; see [`AsyncChksumer::update_from`] for the specific variants.
#[cfg(feature = "async-runtime-tokio")]
pub async fn async_chksum_with<H>(
    data: impl AsyncChksumable,
    configure: impl FnOnce(AsyncChksumerBuilder<H>) -> AsyncChksumerBuilder<H>,
) -> Result<H::Digest>
where
    H: Hash + Send,
{
    let mut ctx = configure(AsyncChksumer::builder()).build();
    ctx.update_from(data).await?;
    Ok(ctx.digest())
}

#[cfg(test)]
mod test_util {
    use std::fmt;

    use crate::hashable::{Digest, Hash, Hashable};

    /// Test hash that collects all bytes for equality checking.
    #[derive(Debug, Default, Clone, PartialEq)]
    pub(crate) struct Collect(pub(crate) Vec<u8>);

    impl Hashable for Collect {}

    impl Hash for Collect {
        type Digest = CollectDigest;

        fn update<T>(&mut self, data: T)
        where
            T: AsRef<[u8]>,
        {
            let Self(vec) = self;
            vec.extend_from_slice(data.as_ref());
        }

        fn reset(&mut self) {
            let Self(vec) = self;
            vec.clear();
        }

        fn digest(&self) -> Self::Digest {
            let Self(vec) = self;
            CollectDigest(vec.clone())
        }
    }

    impl AsRef<[u8]> for Collect {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub(crate) struct CollectDigest(pub(crate) Vec<u8>);

    impl fmt::Display for CollectDigest {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let Self(vec) = self;
            write!(f, "{vec:?}")
        }
    }

    impl Digest for CollectDigest {}
}

#[cfg(test)]
mod tests {
    use crate::builder;
    use crate::test_util::Collect;

    #[test]
    fn builder_produces_working_chksumer() {
        let mut ctx = builder::<Collect>().build();
        ctx.update(b"hello".as_slice());
        assert_eq!(ctx.digest().0, b"hello".to_vec());
    }

    #[cfg(feature = "async-runtime-tokio")]
    #[tokio::test]
    async fn async_builder_produces_working_async_chksumer() {
        let mut ctx = crate::async_builder::<Collect>().build();
        ctx.update(b"hello".as_slice());
        assert_eq!(ctx.digest().0, b"hello".to_vec());
    }
}
