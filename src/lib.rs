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
//! # Usage
//!
//! Hashing a directory has two modes: hash file contents only, or also commit entry names and directory structure.
//! Both modes, ready to paste (substitute `H` with a concrete hash type from one of the family crates listed under
//! [Example Crates](#example-crates)):
//!
//! ```rust
//! use std::path::Path;
//!
//! use chksum_core::{Chksumer, Hash, NameMode, Result, chksum};
//!
//! // Default (`NameMode::Off`): raw file contents only, concatenated in name-sorted order.
//! fn contents_digest<H: Hash>(dir: &Path) -> Result<H::Digest> {
//!     chksum::<H>(dir)
//! }
//!
//! // `NameMode::FileName`: commit entry names and directory structure (git-tree style).
//! fn tree_digest<H: Hash>(dir: &Path) -> Result<H::Digest> {
//!     let mut chksumer = Chksumer::<H>::builder()
//!         .name_mode(NameMode::FileName)
//!         .build();
//!     chksumer.update_from(dir)?;
//!     Ok(chksumer.digest())
//! }
//! # fn main() {}
//! ```
//!
//! [`chksum`] takes a [`Chksumable`] source. A `&str`/[`String`] argument looks like a path but is not one: it
//! dispatches through [`Hashable`] and hashes the string's own bytes, not the file at that path — pass a
//! [`Path`](std::path::Path) instead. See `docs/GOTCHAS.md` in the crate repository for this and other
//! surprising-but-compiling call shapes.
//!
//! # Features
//!
//! ## Asynchronous Runtime
//!
//! * `async-runtime-tokio`: Enables async interface for Tokio runtime.
//!
//! ## Hardening
//!
//! * `nonblocking-open`: On Unix, opens directory-entry files — and a regular file (or symlink-to-file) passed
//!   directly as the top-level source — with `O_NONBLOCK` so a race-swapped FIFO or slow device between
//!   classification and open cannot hang traversal. Without it (the default, or off Unix) a race-swapped FIFO can
//!   block until a writer appears.
//!
//! By default, none of these features is enabled.
//!
//! # Supported Platforms
//!
//! Only Linux, macOS, and Windows are tested. Other targets may work but are unverified.
//!
//! # Symlinks
//!
//! Directory traversal follows symbolic links: linked files are hashed and linked directories are traversed. On Unix,
//! traversal records each *directory's* filesystem identity (dev+ino) when entered through a symlink; a symlink whose
//! target was already visited this traversal is skipped once and surfaced as
//! [`Diagnostic::SkippedRevisitedDirectory`], bounding symlink cycles and repeated-directory-target fan-out. This dedup
//! is scoped to directory targets, not file targets: a symlink to a regular file is read in full every time it is
//! encountered, so many symlinks pointing at the same large file are not deduplicated and each one re-hashes it —
//! bounded by the depth/entry limits below, not eliminated. Windows currently has no such identity-based dedup for
//! directories either: its equivalent (`MetadataExt::volume_serial_number`/`file_index`) is gated behind the unstable
//! `windows_by_handle` std feature ([rust-lang/rust#63010](https://github.com/rust-lang/rust/issues/63010)), and this
//! crate is `#![forbid(unsafe_code)]`, so it relies on the maximum-depth limit below as its only backstop against
//! symlink cycles/fan-out, pending that std feature's stabilization. On any platform without a stable directory
//! identity, the maximum-depth limit below is likewise the backstop. Set
//! `follow_symlink_revisits(true)` on the builder to disable the dedup and restore full re-traversal (and the exact
//! pre-dedup digest) for trees with duplicate symlink targets. A symlink pointing back at an ancestor — including the
//! top-level root itself — is bounded and terminates correctly via this dedup, but costs one additional full traversal
//! pass of that subtree before the revisit is caught, because the top-level directory's own identity is not
//! pre-registered; this is an accepted, documented cost, not a defect.
//!
//! The ancestor-cycle case is not the only source of this bounded amplification: only a directory *entered through a
//! symlink* is ever registered in the visited set, so a directory reached by its own plain (non-symlink) path is never
//! recorded there. A directory that is both a plain descendant of the root and, separately, the target of one or more
//! symlinks elsewhere in the tree is therefore walked in full via its plain path, then walked in full once more by the
//! first symlink that reaches it (which registers its identity so any later symlinks to the same target are skipped) —
//! one extra full pass of that subtree, not one per symlink. Nesting such plain-path/symlink pairs at successive levels
//! compounds this by at most one extra pass per level of directory nesting, so the total amplification stays bounded by
//! `max_directory_depth`, never unbounded — fan-out is bounded here, not absent.
//!
//! Traversal aborts with [`Error::TraversalTooDeep`] when nesting exceeds the configured maximum depth (default 64,
//! `max_directory_depth` on the builder), or [`Error::DirectoryTooLarge`] when one directory holds more entries than
//! the configured maximum it will buffer (default 10,000,000, `max_directory_entries`). The default depth is sized to
//! stay safely below a native stack overflow on both the synchronous and the asynchronous path (see
//! [`ChksumerBuilder::max_directory_depth`](crate::ChksumerBuilder::max_directory_depth)); raising it is a
//! caller-opted-in risk unless the calling thread's stack is sized accordingly.
//!
//! A chain of forward symlinks (`a` → `b` → `c` → …, each one further into the tree, as opposed to a cycle) is
//! resolved by a single `stat`-family call per symlink encountered, so it is bounded by the operating system's own
//! per-lookup symlink-resolution limit (`ELOOP`, surfaced by Rust as `io::ErrorKind::FilesystemLoop` — unstable as of
//! this crate's MSRV, so not itself part of this crate's API — roughly 40 on Linux) well before `max_directory_depth`
//! is reached — raising `max_directory_depth` gives no
//! additional protection against this specific pattern. Traversal still fails safely: an `ELOOP` is surfaced as
//! [`Error::Io`], not a hang or a crash.
//!
//! A symlink's target is classified (regular file, directory, or neither) and then reopened by path; traversal is not
//! race-safe against a filesystem that mutates concurrently with the scan — a target swapped between the two steps is
//! read (or opened) as whatever it has become, not as what was classified. This matters only against a local attacker
//! able to modify the tree mid-scan.
//!
//! # Directory digests
//!
//! By default a directory is hashed as the raw contents of its regular files, concatenated in name-sorted order, with
//! **no** entry names, lengths, structure, or separators. This is fast and stable, but distinct trees can collide:
//! re-splitting the same bytes across differently named files, renaming files, adding an empty file or directory, and a
//! flat file versus a directory split all produce the same digest.
//!
//! Set a [`NameMode`] on a [`Chksumer`] (through its builder) to commit names and structure: [`NameMode::FileName`]
//! hashes bare names with directory nesting (git-tree style), so renames, reordering, re-splitting, and flattening or
//! nesting alter the digest while it stays reproducible across machines of the same platform family. Because only Unix
//! currently has a stable directory-identity source (see the Symlinks section above), a tree containing duplicate
//! symlink targets can hash differently on a platform without that dedup (currently non-Unix, including Windows) than
//! on Unix, even though both hash the same tree under the same [`NameMode`]. The default, [`NameMode::Off`], preserves
//! the historical behavior. Because symlinks are followed transparently, under [`NameMode::FileName`] a symlinked
//! entry and a real entry sharing the same bare name and resolved kind produce the same frame — `FileName` commits
//! names and structure, not whether an entry is itself a symlink.
//!
//! Under `FileName`, each entry's name is length-prefixed, while each regular file's content length is committed as a
//! suffix (the actual number of bytes read and hashed). This is an intentional encoding-style asymmetry, noted for
//! completeness — not a name-vs-content parity requirement. Each record is anchored at its start by a fixed tag and
//! length-prefixed name; whether the trailing content-length placement could ever be exploited to construct a collision
//! has not been formally analyzed or tested, so the asymmetry is noted as an unverified stylistic choice, not a proven
//! weakness. A directory revisited through a symlink is committed as an empty framed directory (its name plus an
//! immediate close, no children), so its structural presence is preserved even though its contents are not re-walked.
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

// `doc_auto_cfg` was removed from nightly (probed 2026-08: rustc 1.99.0-nightly rejects it with E0557); on current
// nightly `feature(doc_cfg)` alone already auto-generates the per-feature badges (verified empirically 2026-08 on
// this crate). Do not "restore" `doc_auto_cfg`.
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
    use std::ops::Deref;
    use std::path::{Path, PathBuf};
    use std::{fmt, fs};

    use crate::hashable::{Digest, Hash, Hashable};

    /// Writes `contents` to `path`, creating parent directories as needed. Shared by the `blocking`/`tokio` test
    /// modules so both dispatch paths' directory-traversal tests build fixtures the same way.
    pub(crate) fn write_file(path: &Path, contents: &[u8]) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent dirs");
        }
        fs::write(path, contents).expect("write test file");
    }

    /// RAII scratch directory under `env::temp_dir()`, unique per test name and process (via `std::process::id()`),
    /// so concurrent test processes cannot collide over the same path. Removed recursively on drop, including when a
    /// test panics, so fixtures no longer leak or need a manual pre/post `remove_dir_all`.
    pub(crate) struct TempTree(PathBuf);

    impl TempTree {
        pub(crate) fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!("chksum_test_{name}_{}", std::process::id()));
            // A prior test run killed (e.g. SIGKILL) before its `Drop` ran can leave a stale directory behind; a
            // reused pid would then let its leftovers leak into this run's fixtures and assertions.
            let _ = fs::remove_dir_all(&path);
            Self(path)
        }

        /// Borrows the scratch directory as a `Path`. An inherent method (rather than relying on `Deref` resolution)
        /// works around a nightly toolchain quirk where `.as_path()` reached through `Deref` spuriously requires the
        /// unstable `str_as_str` feature.
        pub(crate) fn as_path(&self) -> &Path {
            &self.0
        }
    }

    impl Deref for TempTree {
        type Target = Path;

        fn deref(&self) -> &Path {
            &self.0
        }
    }

    impl AsRef<Path> for TempTree {
        fn as_ref(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

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
    use crate::policy::NameMode;
    use crate::test_util::{Collect, TempTree, write_file};
    use crate::{Chksumer, builder, chksum_with};

    #[test]
    fn builder_produces_working_chksumer() {
        let mut ctx = builder::<Collect>().build();
        ctx.update(b"hello".as_slice());
        assert_eq!(ctx.digest().0, b"hello".to_vec());
    }

    #[test]
    fn chksum_with_matches_hand_built_chksumer() {
        let base = TempTree::new("chksum_with_name_mode");
        write_file(&base.join("a"), b"foo");
        write_file(&base.join("b"), b"bar");

        let via_helper = chksum_with::<Collect>(base.as_path(), |builder| builder.name_mode(NameMode::FileName))
            .expect("chksum_with should succeed");

        let mut ctx = Chksumer::<Collect>::builder().name_mode(NameMode::FileName).build();
        ctx.update_from(base.as_path())
            .expect("hand-built chksumer should succeed");
        let expected = ctx.digest();

        assert_eq!(via_helper, expected);
    }

    #[cfg(feature = "async-runtime-tokio")]
    #[tokio::test]
    async fn async_builder_produces_working_async_chksumer() {
        let mut ctx = crate::async_builder::<Collect>().build();
        ctx.update(b"hello".as_slice());
        assert_eq!(ctx.digest().0, b"hello".to_vec());
    }

    #[cfg(feature = "async-runtime-tokio")]
    #[tokio::test]
    async fn async_chksum_with_matches_hand_built_async_chksumer() {
        let base = TempTree::new("async_chksum_with_name_mode");
        write_file(&base.join("a"), b"foo");
        write_file(&base.join("b"), b"bar");

        let via_helper =
            crate::async_chksum_with::<Collect>(base.as_path(), |builder| builder.name_mode(NameMode::FileName))
                .await
                .expect("async_chksum_with should succeed");

        let mut ctx = crate::AsyncChksumer::<Collect>::builder()
            .name_mode(NameMode::FileName)
            .build();
        ctx.update_from(base.as_path())
            .await
            .expect("hand-built async chksumer should succeed");
        let expected = ctx.digest();

        assert_eq!(via_helper, expected);
    }
}
