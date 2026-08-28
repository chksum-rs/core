use std::io;
#[cfg(any(unix, windows))]
use std::io::IsTerminal;
#[cfg(unix)]
use std::os::fd::AsFd;
#[cfg(windows)]
use std::os::windows::io::AsHandle;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
#[cfg(all(unix, feature = "nonblocking-open"))]
use tokio::fs::OpenOptions;
use tokio::fs::{DirEntry, File, ReadDir, metadata, read_dir, symlink_metadata};

use crate::context::tokio::AsyncChksumer;
use crate::diagnostic::Diagnostic;
use crate::error::{Result, terminal_err, too_many_entries_err};
use crate::hashable::{Hash, Hashable};
use crate::policy::{NameMode, SkipKind};
use crate::traversal::{EntryAction, SymlinkTarget, Tag, classify_entry, classify_symlink_target, frame_named};

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

/// Reports whether an async I/O source is attached to an interactive terminal.
///
/// This mirrors the synchronous `File`/`StdinLock` guards in [`crate::chksumable::blocking`], which call
/// [`std::io::IsTerminal::is_terminal`] directly. Tokio's `File`/`Stdin` do not implement `IsTerminal` themselves — it
/// is blocked on a tokio MSRV bump (see [tokio-rs/tokio#6407](https://github.com/tokio-rs/tokio/issues/6407); the
/// proposed [tokio-rs/tokio#7114](https://github.com/tokio-rs/tokio/pull/7114) adds inherent `is_terminal` methods but
/// is still unreleased). Until that lands we go through the borrowed file descriptor the type already exposes via
/// [`AsFd`], whose `BorrowedFd` *does* implement `IsTerminal`. The `AsFd`/`AsHandle` impls have been available since
/// tokio 1.27, well below this crate's declared `tokio` floor.
#[cfg(unix)]
fn is_terminal(io: impl AsFd) -> bool {
    io.as_fd().is_terminal()
}

/// Windows counterpart of the Unix [`is_terminal`]: the borrowed [`AsHandle`]'s `BorrowedHandle` implements
/// [`std::io::IsTerminal`], so terminal detection goes through it.
#[cfg(windows)]
fn is_terminal(io: impl AsHandle) -> bool {
    io.as_handle().is_terminal()
}

/// Fallback for targets that expose neither a borrowed file descriptor nor a handle: assume the source is not a
/// terminal so hashing still proceeds, matching the crate's "just read it" default for sources it cannot classify. On
/// these targets an actually interactive source is misclassified rather than rejected with
/// [`crate::error::Error::IsTerminal`], so a caller feeding one in blocks on the source's own read call until it
/// produces EOF instead of getting a prompt error up front. No CI target currently exercises this branch, so a
/// regression here (or in the platforms it silently covers) would not be caught by this crate's test suite.
#[cfg(not(any(unix, windows)))]
fn is_terminal<T>(_io: T) -> bool {
    false
}

/// Async counterpart of the blocking `open_nonblocking`, used both for directory entries and for a regular
/// file/symlink-to-file passed directly as the top-level source. With the `nonblocking-open` feature on a Unix
/// target, opens `path` read-only with `O_NONBLOCK` so a race-swapped FIFO/slow device fails or returns immediately
/// instead of blocking the traversal; `O_NONBLOCK` is a no-op for genuine regular files. Without the feature (or off
/// Unix) this is a plain `File::open` and does NOT guard the FIFO/slow-device hang.
#[cfg(all(unix, feature = "nonblocking-open"))]
async fn open_nonblocking(path: impl AsRef<Path>) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .await
}

#[cfg(not(all(unix, feature = "nonblocking-open")))]
async fn open_nonblocking(path: impl AsRef<Path>) -> io::Result<File> {
    File::open(path).await
}

macro_rules! impl_async_chksumable {
    ($($t:ty),+ => $i:tt) => {
        $(
            #[async_trait]
            impl AsyncChksumable for $t $i
        )*
    };
}

impl_async_chksumable!(Path, &Path, &mut Path => {
    async fn chksum_into<H>(&mut self, ctx: &mut AsyncChksumer<H>) -> Result<()>
    where
        H: Hash + Send,
    {
        // Mirrors the synchronous `Path` impl: a top-level symlink must go through the same policy-aware
        // classification as a symlinked `DirEntry`, instead of a bare `metadata` call that propagates a dangling
        // target as a raw `Error::Io`. `symlink_metadata` is captured once and reused for the non-symlink branch
        // below (`lstat` == `stat` when the path is not itself a symlink), so a non-symlink path costs exactly one
        // syscall; only the symlink branch needs the extra `classify_symlink_target(metadata(&path))` call to
        // resolve the target.
        let meta = symlink_metadata(&self).await?;
        if meta.is_symlink() {
            return match classify_symlink_target(metadata(&self).await)? {
                SymlinkTarget::Directory(_) => read_dir(self).await?.chksum_into(ctx).await,
                SymlinkTarget::File => open_nonblocking(self).await?.chksum_into(ctx).await,
                SymlinkTarget::Irregular => ctx.policy().skip_or_err(SkipKind::Irregular, || self.to_path_buf()),
                SymlinkTarget::Unresolvable => {
                    ctx.policy().skip_or_err(SkipKind::UnresolvableSymlink, || self.to_path_buf())
                },
            };
        }
        if meta.is_dir() {
            read_dir(self).await?.chksum_into(ctx).await
        } else if meta.is_file() {
            open_nonblocking(self).await?.chksum_into(ctx).await
        } else {
            ctx.policy().skip_or_err(SkipKind::Irregular, || self.to_path_buf())
        }
    }
});

impl_async_chksumable!(PathBuf, &PathBuf, &mut PathBuf => {
    async fn chksum_into<H>(&mut self, ctx: &mut AsyncChksumer<H>) -> Result<()>
    where
        H: Hash + Send,
    {
        self.as_path().chksum_into(ctx).await
    }
});

// No `&File` counterpart, unlike the synchronous `Chksumable` impl for `File`, `&File`, `&mut File`:
// `tokio::fs::File`'s `AsyncRead` requires `&mut self`, with no shared-reference impl to dispatch through, so a caller
// holding only `&File` cannot fold it in asynchronously.
impl_async_chksumable!(File, &mut File => {
    async fn chksum_into<H>(&mut self, ctx: &mut AsyncChksumer<H>) -> Result<()>
    where
        H: Hash + Send,
    {
        if is_terminal(&self) {
            return Err(terminal_err());
        }
        ctx.update_from_reader(self).await?;
        Ok(())
    }
});

impl_async_chksumable!(DirEntry, &DirEntry, &mut DirEntry => {
    async fn chksum_into<H>(&mut self, ctx: &mut AsyncChksumer<H>) -> Result<()>
    where
        H: Hash + Send,
    {
        // Mirrors the synchronous `DirEntry` impl: a top-level `DirEntry` must hash identically to its own `path()`
        // passed directly (no name framing, no visited-set registration for a symlinked-directory target — both
        // apply only to nested descent via `chksum_dir_entry`, reached through `ReadDir`).
        self.path().chksum_into(ctx).await
    }
});

/// Folds a single directory entry into `ctx`. `path` is the entry's path, already computed by the caller (`ReadDir`)
/// while sorting, so it is resolved exactly once per entry. Mirrors the synchronous `chksum_dir_entry`.
async fn chksum_dir_entry<H>(entry: &DirEntry, path: &Path, ctx: &mut AsyncChksumer<H>) -> Result<()>
where
    H: Hash + Send,
{
    let file_type = entry.file_type().await?;
    let symlink_target = if file_type.is_symlink() {
        Some(classify_symlink_target(metadata(path).await)?)
    } else {
        None
    };
    let action = classify_entry(file_type, symlink_target, |meta| ctx.visit_symlinked_dir(meta));

    match (action, ctx.policy().name_mode) {
        (EntryAction::Irregular, _) => ctx.policy().skip_or_err(SkipKind::Irregular, || path.to_path_buf()),
        (EntryAction::UnresolvableSymlink, _) => {
            ctx.policy()
                .skip_or_err(SkipKind::UnresolvableSymlink, || path.to_path_buf())
        },
        (EntryAction::Dir, NameMode::Off) => read_dir(path).await?.chksum_into(ctx).await,
        (EntryAction::File, NameMode::Off) => {
            let mut file = open_nonblocking(path).await?;
            ctx.update_from_reader(&mut file).await.map(|_| ())
        },
        (EntryAction::SkippedRevisitedDirectory, NameMode::Off) => {
            ctx.policy().notify(|| {
                Diagnostic::SkippedRevisitedDirectory {
                    path: path.to_path_buf(),
                }
            });
            Ok(())
        },
        (EntryAction::Dir, NameMode::FileName) => {
            let name = path.file_name().expect("directory entry path always has a file name");
            let mut dir = read_dir(path).await?;
            frame_named(&mut ctx.hash, Tag::Dir, name.as_encoded_bytes());
            dir.chksum_into(ctx).await?;
            ctx.hash.update([Tag::DirClose as u8]);
            Ok(())
        },
        (EntryAction::File, NameMode::FileName) => {
            let name = path.file_name().expect("directory entry path always has a file name");
            let mut file = open_nonblocking(path).await?;
            frame_named(&mut ctx.hash, Tag::File, name.as_encoded_bytes());
            let content_len = ctx.update_from_reader(&mut file).await?;
            ctx.hash.update(content_len.to_be_bytes());
            Ok(())
        },
        // FLAG C: FileName still commits the revisited directory's structural presence — frame its name and an
        // immediate close, no children — so it never vanishes from the digest (hashes identically to an empty
        // directory of that name).
        (EntryAction::SkippedRevisitedDirectory, NameMode::FileName) => {
            let name = path.file_name().expect("directory entry path always has a file name");
            ctx.policy().notify(|| {
                Diagnostic::SkippedRevisitedDirectory {
                    path: path.to_path_buf(),
                }
            });
            frame_named(&mut ctx.hash, Tag::Dir, name.as_encoded_bytes());
            ctx.hash.update([Tag::DirClose as u8]);
            Ok(())
        },
    }
}

impl_async_chksumable!(ReadDir, &mut ReadDir => {
    async fn chksum_into<H>(&mut self, ctx: &mut AsyncChksumer<H>) -> Result<()>
    where
        H: Hash + Send,
    {
        // S3: the visited-set for a fresh top-level traversal is cleared once, in `AsyncChksumer::update_from` (the
        // sole entry point for a fresh traversal) — not here, since this impl also runs for nested descent into
        // subdirectories, which must NOT clear it.
        // S1: refuse to descend past the configured limit (guards the boxed future chain here / the native stack in
        // the synchronous mirror).
        let ticket = ctx.enter_directory()?;
        let mut entries: Vec<(PathBuf, DirEntry)> = Vec::with_capacity(ctx.policy().dir_entries_capacity_hint);
        loop {
            // Mirrors the synchronous impl's precedence: the entries already buffered reaching the configured cap is
            // checked before a raw io error from reading one entry past it is allowed to surface (a directory that
            // is simply exhausted, `Ok(None)`, is not affected — it must still succeed at exactly the cap).
            let next = self.next_entry().await;
            if entries.len() >= ctx.policy().max_directory_entries.get() && !matches!(next, Ok(None)) {
                return Err(too_many_entries_err(ctx.policy().max_directory_entries.get()));
            }
            match next? {
                Some(entry) => entries.push((entry.path(), entry)),
                None => break,
            }
        }
        // Sort by full path: equivalent to sorting by bare name here (all entries share the parent prefix), and
        // `sort_unstable` is fine since names are unique per directory.
        entries.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));
        for (path, entry) in entries {
            chksum_dir_entry(&entry, &path, ctx).await?;
        }
        // The `?` early-returns above intentionally leave the ticket unreturned to `leave_directory`, stranding
        // depth until the reuse contract's `reset()` runs.
        ctx.leave_directory(ticket);
        Ok(())
    }
});

// No `&Stdin` counterpart, unlike the synchronous `Chksumable` impl for `Stdin`, `&Stdin`, `&mut Stdin` — same reason
// as `File` above: `tokio::io::Stdin`'s `AsyncRead` requires `&mut self`.
impl_async_chksumable!(tokio::io::Stdin, &mut tokio::io::Stdin => {
    async fn chksum_into<H>(&mut self, ctx: &mut AsyncChksumer<H>) -> Result<()>
    where
        H: Hash + Send,
    {
        if is_terminal(&self) {
            return Err(terminal_err());
        }
        ctx.update_from_reader(self).await?;
        Ok(())
    }
});

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;
    use std::num::NonZeroUsize;
    #[cfg(unix)]
    use std::os::unix::fs::symlink;
    #[cfg(unix)]
    use std::os::unix::net::UnixListener;
    use std::path::Path;
    #[cfg(unix)]
    use std::sync::{Arc, Mutex};

    use super::AsyncChksumable;
    use crate::context::tokio::AsyncChksumer;
    #[cfg(unix)]
    use crate::diagnostic::Diagnostic;
    use crate::hashable::Hash;
    #[cfg(unix)]
    use crate::policy::IrregularFile;
    use crate::policy::NameMode;
    use crate::test_util::{Collect, TempTree, write_file};
    use crate::{Error, Result, async_chksum};

    /// Bytes-like type overriding [`Hashable::hash_into`](crate::hashable::Hashable::hash_into) to prove the blanket
    /// [`AsyncChksumable`] impl dispatches through it rather than hardcoding `ctx.hash.update(self)`.
    struct DoublingBytes(&'static [u8]);

    impl AsRef<[u8]> for DoublingBytes {
        fn as_ref(&self) -> &[u8] {
            self.0
        }
    }

    impl crate::hashable::Hashable for DoublingBytes {
        fn hash_into<H>(&self, hash: &mut H)
        where
            H: crate::hashable::Hash,
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

    #[async_trait::async_trait]
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

    /// Hashes `path` asynchronously with the given [`NameMode`] and returns the collected bytes.
    async fn dir_digest(path: &Path, name_mode: NameMode) -> Vec<u8> {
        let mut ctx = AsyncChksumer::<Collect>::builder().name_mode(name_mode).build();
        ctx.update_from(path).await.expect("hash path");
        ctx.digest().0
    }

    #[tokio::test]
    async fn async_file_non_empty() {
        let base = TempTree::new("async_file_non_empty");
        fs::create_dir_all(&base).expect("create base dir");
        let path = base.join("file.bin");

        let data = b"async test file content";
        std::fs::File::create(&path)
            .and_then(|mut f| f.write_all(data))
            .expect("create test file");

        let digest = async_chksum::<Collect>(&path).await.expect("hash file async");
        assert_eq!(digest.0, data.to_vec(), "async file hash should match content");
    }

    // --- D4: file-content framing bytes (current suffix encoding, unchanged) ---

    #[tokio::test]
    async fn file_name_frames_content_length_as_suffix() {
        let base = TempTree::new("async_content_suffix");
        let one = base.join("one");
        write_file(&one.join("x"), b"hi");

        let mut expected = Vec::new();
        expected.push(0x01u8); // Tag::File
        expected.extend_from_slice(&1u64.to_be_bytes()); // name length prefix
        expected.push(b'x');
        expected.extend_from_slice(b"hi");
        expected.extend_from_slice(&2u64.to_be_bytes()); // content length suffix

        assert_eq!(dir_digest(&one, NameMode::FileName).await, expected);
    }

    // --- NEW: empty-directory FileName framing (async) ---

    #[tokio::test]
    async fn name_mode_captures_empty_directories() {
        let base = TempTree::new("async_emptydir");
        let with = base.join("with");
        let without = base.join("without");
        write_file(&with.join("a.txt"), b"x");
        fs::create_dir_all(with.join("empty")).expect("create empty dir");
        write_file(&without.join("a.txt"), b"x");

        // `Off` ignores empty directories entirely -> collision.
        assert_eq!(
            dir_digest(&with, NameMode::Off).await,
            dir_digest(&without, NameMode::Off).await
        );
        // `FileName` records every directory entry -> the empty dir is committed.
        assert_ne!(
            dir_digest(&with, NameMode::FileName).await,
            dir_digest(&without, NameMode::FileName).await
        );
    }

    // --- F2/F3: top-level dangling/irregular symlink honors IrregularFile policy (async) ---

    #[cfg(unix)]
    #[tokio::test]
    async fn top_level_dangling_symlink_errors_and_skip_yields_empty() {
        let base = TempTree::new("async_toplevel_dangling_symlink");
        fs::create_dir_all(&base).expect("create base dir");
        let link_path = base.join("dangling");
        symlink(base.join("missing"), &link_path).expect("create dangling symlink");

        let error = async_chksum::<Collect>(link_path.as_path())
            .await
            .expect_err("dangling symlink should abort by default");
        assert!(
            matches!(&error, Error::NotARegularFile { path } if path == &link_path),
            "unexpected error: {error:?}"
        );

        let mut ctx = AsyncChksumer::<Collect>::builder()
            .irregular_file(IrregularFile::Skip)
            .build();
        ctx.update_from(link_path.as_path())
            .await
            .expect("skip top-level dangling symlink");
        assert_eq!(ctx.digest().0, Vec::<u8>::new(), "skip digest should be empty");
    }

    // --- D5: top-level irregular file (async) ---

    #[cfg(unix)]
    #[tokio::test]
    async fn top_level_irregular_file_errors_and_skip_yields_empty() {
        let base = TempTree::new("async_toplevel_irregular");
        fs::create_dir_all(&base).expect("create base dir");
        let socket_path = base.join("socket");
        let _socket = UnixListener::bind(&socket_path).expect("bind unix socket");

        let error = async_chksum::<Collect>(socket_path.as_path())
            .await
            .expect_err("socket should error by default");
        assert!(
            matches!(&error, Error::NotARegularFile { path } if path == &socket_path),
            "unexpected error: {error:?}"
        );

        let mut ctx = AsyncChksumer::<Collect>::builder()
            .irregular_file(IrregularFile::Skip)
            .build();
        ctx.update_from(socket_path.as_path())
            .await
            .expect("skip top-level socket");
        assert_eq!(ctx.digest().0, Vec::<u8>::new(), "skip digest should be empty");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn top_level_symlink_to_socket_errors_and_skip_yields_empty() {
        let base = TempTree::new("async_toplevel_symlink_socket");
        fs::create_dir_all(&base).expect("create base dir");
        let socket_path = base.join("socket");
        let _socket = UnixListener::bind(&socket_path).expect("bind unix socket");
        let link_path = base.join("link_to_socket");
        symlink(&socket_path, &link_path).expect("create symlink to socket");

        let error = async_chksum::<Collect>(link_path.as_path())
            .await
            .expect_err("symlink to socket should abort by default");
        assert!(
            matches!(&error, Error::NotARegularFile { path } if path == &link_path),
            "unexpected error: {error:?}"
        );

        let mut ctx = AsyncChksumer::<Collect>::builder()
            .irregular_file(IrregularFile::Skip)
            .build();
        ctx.update_from(link_path.as_path())
            .await
            .expect("skip top-level symlink to socket");
        assert_eq!(ctx.digest().0, Vec::<u8>::new(), "skip digest should be empty");
    }

    // --- S3: symlink cycle terminates (async) ---

    #[cfg(unix)]
    #[tokio::test]
    async fn async_symlink_cycle_terminates() {
        let base = TempTree::new("async_symlink_cycle");
        let root = base.join("root");
        write_file(&root.join("sub").join("a.txt"), b"alpha");
        symlink(&root, root.join("sub").join("loop")).expect("create symlink cycle");

        let diagnostics: Arc<Mutex<Vec<Diagnostic>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&diagnostics);
        let mut ctx = AsyncChksumer::<Collect>::builder()
            .on_diagnostic(move |d| sink.lock().expect("lock diagnostics").push(d.clone()))
            .build();
        ctx.update_from(root.as_path())
            .await
            .expect("cycle should terminate, not hang or overflow");

        let seen = diagnostics.lock().expect("lock diagnostics");
        assert!(
            seen.iter()
                .any(|d| matches!(d, Diagnostic::SkippedRevisitedDirectory { .. })),
            "expected at least one SkippedRevisitedDirectory diagnostic: {seen:?}"
        );

        drop(seen);
    }

    // --- D1: symlink to a non-regular target inside a traversed directory (async) ---

    #[cfg(unix)]
    #[tokio::test]
    async fn async_symlink_to_socket_reports_skipped_irregular_not_unresolvable() {
        let base = TempTree::new("async_symlink_socket");
        let root = base.join("root");
        write_file(&root.join("a.txt"), b"alpha");
        let socket_path = base.join("socket_target");
        let _socket = UnixListener::bind(&socket_path).expect("bind unix socket");
        symlink(&socket_path, root.join("link_to_socket")).expect("create symlink to socket");

        let error = async_chksum::<Collect>(root.as_path())
            .await
            .expect_err("default policy should abort");
        assert!(
            matches!(&error, Error::NotARegularFile { path } if path.ends_with("link_to_socket")),
            "unexpected error: {error:?}"
        );

        let diagnostics: Arc<Mutex<Vec<Diagnostic>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&diagnostics);
        let mut ctx = AsyncChksumer::<Collect>::builder()
            .irregular_file(IrregularFile::Skip)
            .on_diagnostic(move |d| sink.lock().expect("lock diagnostics").push(d.clone()))
            .build();
        ctx.update_from(root.as_path()).await.expect("skip symlink to socket");

        let seen = diagnostics.lock().expect("lock diagnostics");
        assert!(
            seen.iter()
                .any(|d| matches!(d, Diagnostic::SkippedIrregular { path } if path.ends_with("link_to_socket"))),
            "missing SkippedIrregular diagnostic: {seen:?}"
        );
        assert!(
            !seen
                .iter()
                .any(|d| matches!(d, Diagnostic::SkippedUnresolvableSymlink { .. })),
            "symlink to socket should not be reported as unresolvable: {seen:?}"
        );

        drop(seen);
    }

    // --- NEW: follow_symlink_revisits parity (async) ---

    #[cfg(unix)]
    #[tokio::test]
    async fn async_follow_symlink_revisits_toggle_changes_digest() {
        let base = TempTree::new("async_follow_revisits");
        let root = base.join("root");
        write_file(&root.join("d").join("f"), b"x");
        symlink(root.join("d"), root.join("a")).expect("create symlink a");
        symlink(root.join("d"), root.join("b")).expect("create symlink b");

        let default_digest = {
            let mut ctx = AsyncChksumer::<Collect>::builder().name_mode(NameMode::Off).build();
            ctx.update_from(root.as_path()).await.expect("hash with default dedup");
            ctx.digest().0
        };
        let follow_digest = {
            let mut ctx = AsyncChksumer::<Collect>::builder()
                .name_mode(NameMode::Off)
                .follow_symlink_revisits(true)
                .build();
            ctx.update_from(root.as_path()).await.expect("hash with follow enabled");
            ctx.digest().0
        };

        assert_ne!(
            default_digest, follow_digest,
            "digests should differ when revisits are followed"
        );
        assert!(
            follow_digest.len() > default_digest.len(),
            "follow(true) should walk more content than the deduped default: default={default_digest:?} \
             follow={follow_digest:?}"
        );
    }

    // --- NEW: FLAG C name preservation on revisit (async) ---

    #[cfg(unix)]
    #[tokio::test]
    async fn async_revisited_directory_preserves_name_framing() {
        let base = TempTree::new("async_revisit_framing");
        let root = base.join("root");
        write_file(&root.join("d").join("f"), b"x");
        symlink(root.join("d"), root.join("a")).expect("create symlink a");
        symlink(root.join("d"), root.join("b")).expect("create symlink b");

        let digest = dir_digest(&root, NameMode::FileName).await;

        // `b` (sorted after `a`, and a revisit of the same target already visited via `a`) must be framed as an empty
        // directory named "b": Tag::Dir, name length 1, b'b', Tag::DirClose.
        let expected_b_frame: Vec<u8> = {
            let mut v = Vec::new();
            v.push(0x02u8); // Tag::Dir
            v.extend_from_slice(&1u64.to_be_bytes());
            v.push(b'b');
            v.push(0x03u8); // Tag::DirClose
            v
        };
        assert!(
            digest
                .windows(expected_b_frame.len())
                .any(|w| w == expected_b_frame.as_slice()),
            "expected empty-directory framing for revisited `b` not found in digest: {digest:?}"
        );
    }

    // --- S1: async depth limit ---

    #[test]
    fn async_depth_limit_errors() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .build()
                    .expect("build current-thread runtime");
                rt.block_on(async {
                    let base = TempTree::new("async_depth");
                    let mut path = base.to_path_buf();
                    for _ in 0..=crate::policy::DEFAULT_MAX_DIRECTORY_DEPTH.get() {
                        path.push("d");
                    }
                    fs::create_dir_all(&path).expect("create deep dir chain");
                    let error = async_chksum::<Collect>(base.as_path())
                        .await
                        .expect_err("deep tree should abort");
                    assert!(
                        matches!(&error, Error::TraversalTooDeep { .. }),
                        "unexpected error: {error:?}"
                    );
                });
            })
            .expect("spawn deep-traversal thread")
            .join()
            .expect("join deep-traversal thread");
    }

    // --- F4: the default depth limit must also be safe on a small (2 MiB) stack on the ASYNC path. Heap-boxing a
    // future's state (via `async_trait`) does not make polling a chain of nested futures free of native-stack use —
    // each level's `poll` call still recurses on the native stack, just with a smaller per-level cost than the
    // synchronous path. ---

    #[test]
    fn async_depth_limit_default_errors_too_deep_on_default_sized_stack() {
        std::thread::Builder::new()
            .stack_size(2 * 1024 * 1024)
            .spawn(|| {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .build()
                    .expect("build current-thread runtime");
                rt.block_on(async {
                    let base = TempTree::new("async_depth_limit_default_small_stack");
                    let mut path = base.to_path_buf();
                    for _ in 0..=crate::policy::DEFAULT_MAX_DIRECTORY_DEPTH.get() {
                        path.push("d");
                    }
                    fs::create_dir_all(&path).expect("create deep dir chain");

                    let error = async_chksum::<Collect>(base.as_path())
                        .await
                        .expect_err("should exceed default depth limit");
                    assert!(
                        matches!(&error, Error::TraversalTooDeep { .. }),
                        "expected a clean TraversalTooDeep on a 2 MiB stack, not a crash or other error: {error:?}"
                    );
                });
            })
            .expect("spawn thread")
            .join()
            .expect("join thread");
    }

    // --- update_from resets depth alongside the visited set (async mirror) ---

    #[tokio::test]
    async fn update_from_resets_depth_after_prior_error() {
        let base = TempTree::new("async_depth_reset_after_error");
        let deep_root = base.join("deep");
        write_file(&deep_root.join("a").join("b").join("c.txt"), b"too deep");
        let shallow_root = base.join("shallow");
        write_file(&shallow_root.join("f.txt"), b"shallow");

        let mut ctx = AsyncChksumer::<Collect>::builder()
            .max_directory_depth(NonZeroUsize::new(2).expect("non-zero"))
            .build();
        let error = ctx
            .update_from(deep_root.as_path())
            .await
            .expect_err("tree exceeds the configured depth limit");
        assert!(
            matches!(error, Error::TraversalTooDeep { limit } if limit == 2),
            "unexpected error: {error:?}"
        );

        ctx.update_from(shallow_root.as_path())
            .await
            .expect("a fresh top-level call must start with a full depth budget, not a stranded one");
        assert_eq!(ctx.digest().0, b"shallow".to_vec());
    }

    // --- NEW: max_directory_depth override (async mirror) ---

    #[tokio::test]
    async fn depth_limit_override_errors_at_configured_limit() {
        let base = TempTree::new("async_depth_limit_override");
        let mut deepest = base.to_path_buf();
        for _ in 0..6 {
            deepest = deepest.join("d");
        }
        fs::create_dir_all(&deepest).expect("create tree");

        let mut ctx = AsyncChksumer::<Collect>::builder()
            .max_directory_depth(NonZeroUsize::new(4).expect("non-zero"))
            .build();
        let error = ctx
            .update_from(base.as_path())
            .await
            .expect_err("should exceed configured depth limit");
        assert!(
            matches!(error, Error::TraversalTooDeep { limit } if limit == 4),
            "unexpected error: {error:?}"
        );
    }

    // --- NEW: max_directory_entries boundary (async mirror; also pins the error-precedence alignment with blocking) ---

    #[tokio::test]
    async fn max_directory_entries_boundary() {
        let base = TempTree::new("async_max_entries_boundary");
        for i in 0..3 {
            write_file(&base.join(format!("f{i}")), b"x");
        }

        let mut ctx = AsyncChksumer::<Collect>::builder()
            .max_directory_entries(NonZeroUsize::new(3).expect("non-zero"))
            .build();
        ctx.update_from(base.as_path())
            .await
            .expect("a directory with exactly the configured cap of entries must not error");

        let mut ctx = AsyncChksumer::<Collect>::builder()
            .max_directory_entries(NonZeroUsize::new(2).expect("non-zero"))
            .build();
        let error = ctx
            .update_from(base.as_path())
            .await
            .expect_err("a directory exceeding the configured cap must abort");
        assert!(
            matches!(error, Error::DirectoryTooLarge { limit } if limit == 2),
            "unexpected error: {error:?}"
        );
    }

    // --- F6: the visited-set must not leak across two top-level DirEntry sources sharing one reused AsyncChksumer ---

    #[cfg(unix)]
    #[tokio::test]
    async fn visited_set_does_not_leak_across_reused_chksumer_top_level_calls() {
        let base = TempTree::new("async_visited_leak_direntry_reuse");
        write_file(&base.join("shared").join("f"), b"x");
        let root1 = base.join("root1");
        fs::create_dir_all(&root1).expect("create root1");
        symlink(base.join("shared"), root1.join("link")).expect("create nested symlink to shared dir");
        let root2 = base.join("root2");
        fs::create_dir_all(&root2).expect("create root2");
        symlink(base.join("shared"), root2.join("link2")).expect("create second symlink to shared dir");

        // `AsyncChksumable` is implemented for `tokio::fs::DirEntry`, not `std::fs::DirEntry`, so entries are read
        // through tokio's async fs.
        let entry_root1 = {
            let mut rd = tokio::fs::read_dir(&base).await.expect("async read base");
            loop {
                let entry = rd.next_entry().await.expect("read entry").expect("find root1 entry");
                if entry.file_name() == "root1" {
                    break entry;
                }
            }
        };
        let entry_link2 = tokio::fs::read_dir(&root2)
            .await
            .expect("async read root2")
            .next_entry()
            .await
            .expect("read entry")
            .expect("root2 has an entry");

        let mut ctx = AsyncChksumer::<Collect>::new();
        ctx.update_from(entry_root1)
            .await
            .expect("first top-level DirEntry traversal (root1, containing a nested symlink to shared)");
        assert_eq!(
            ctx.digest().0,
            b"x".to_vec(),
            "sanity: first traversal hashed shared's content once"
        );

        ctx.update_from(entry_link2)
            .await
            .expect("second top-level DirEntry traversal (link2, itself a symlink to shared)");

        assert_eq!(
            ctx.digest().0,
            b"xx".to_vec(),
            "second top-level traversal must not be skipped due to a stale visited entry from the first"
        );
    }

    // --- F8: async top-level regular file open goes through the same nonblocking-open hardening as a directory
    //     entry (async mirror; direct test of the async `open_nonblocking` helper) ---

    #[cfg(all(unix, feature = "nonblocking-open"))]
    #[tokio::test]
    async fn open_nonblocking_does_not_hang_on_a_fifo() {
        let base = TempTree::new("async_toplevel_nonblocking_open");
        fs::create_dir_all(&base).expect("create base dir");
        let fifo_path = base.join("fifo");
        // The crate is `#![forbid(unsafe_code)]`, so the FIFO is created by shelling out to the `mkfifo` binary
        // (present on Linux/macOS) rather than calling `libc::mkfifo` directly.
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo_path)
            .status()
            .expect("run mkfifo");
        assert!(status.success(), "mkfifo command failed: {status:?}");

        // Mirrors the synchronous pin: calls the async `open_nonblocking` helper directly, proving it opens a FIFO
        // with no writer immediately (no hang) and that the subsequent read sees EOF, producing an empty digest.
        let mut file = super::open_nonblocking(&fifo_path)
            .await
            .expect("open must not hang; O_NONBLOCK returns immediately");
        let mut ctx = AsyncChksumer::<Collect>::new();
        ctx.update_from_reader(&mut file)
            .await
            .expect("read must not hang; FIFO with no writer is EOF");
        assert_eq!(
            ctx.digest().0,
            Vec::<u8>::new(),
            "no writer ever connected, so content is empty"
        );
    }
}
