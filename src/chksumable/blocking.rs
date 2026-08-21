//! [`Chksumable`] impls for standard, blocking I/O and filesystem sources: bytes-like values, [`File`], and directory
//! traversal (`Path`/`DirEntry`/`ReadDir`), including the [`NameMode`]/[`IrregularFile`] dispatch logic. The `tokio`
//! module (behind the `async-runtime-tokio` feature) mirrors this for async I/O.

// Internal shorthand used in comments throughout this module, its `tokio` mirror, and
// `context.rs`/`traversal.rs`/`visited.rs` — tags a comment to the specific safety/correctness/perf property or
// pinned regression it backs, without restating it in full at every site:
//   S1/S2  - the max_directory_depth/max_directory_entries safety limits.
//   S3     - the symlinked-directory visited-set dedup (cycle/fan-out protection).
//   P2/P3  - hot-path perf choices (buffering, allocation reuse).
//   D<n>   - a documented behavior decision pinned by a test, not a safety/perf concern.
//   F<n>   - a bug fix pinned by a regression test.
//   FLAG C - the FileName framing decision to still emit an empty-directory frame for a skipped revisit.
// Not part of the public API; never appears in public rustdoc.
#[cfg(all(unix, feature = "nonblocking-open"))]
use std::fs::OpenOptions;
use std::fs::{DirEntry, File, ReadDir, read_dir};
use std::io::{self, IsTerminal, Stdin, StdinLock};
#[cfg(all(unix, feature = "nonblocking-open"))]
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use crate::context::blocking::Chksumer;
use crate::diagnostic::Diagnostic;
use crate::error::{Result, terminal_err, too_many_entries_err};
use crate::hashable::{Hash, Hashable};
use crate::policy::{NameMode, SkipKind};
use crate::traversal::{EntryAction, SymlinkTarget, Tag, classify_entry, classify_symlink_target, frame_named};

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

macro_rules! impl_chksumable {
    ($($t:ty),+ => $i:tt) => {
        $(
            impl Chksumable for $t $i
        )*
    };
}

/// Opens `path` read-only for hashing: a directory entry, or a regular file/symlink-to-file passed directly as the
/// top-level source.
///
/// With the `nonblocking-open` feature on a Unix target, the file is opened with `O_NONBLOCK` so that if the path —
/// verified a regular file at classification — was race-swapped for a FIFO or slow character device before this open,
/// the call returns immediately instead of blocking the whole traversal until a writer appears. `O_NONBLOCK` is a no-op
/// for genuine regular files.
///
/// Without the feature (or off Unix) this is a plain [`File::open`]: the TOCTOU / FIFO-hang risk is NOT guarded and a
/// race-swapped FIFO can block the traversal until the pipe is opened for writing. Enable `nonblocking-open` on Unix to
/// harden traversal against this race.
#[cfg(all(unix, feature = "nonblocking-open"))]
fn open_nonblocking(path: impl AsRef<Path>) -> io::Result<File> {
    OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK).open(path)
}

/// See the `nonblocking-open`-gated variant above. Without that feature (or off Unix) this is a plain read-only
/// [`File::open`] and does NOT guard against a race-swapped FIFO/slow device hanging the traversal.
#[cfg(not(all(unix, feature = "nonblocking-open")))]
fn open_nonblocking(path: impl AsRef<Path>) -> io::Result<File> {
    File::open(path)
}

impl_chksumable!(Path, &Path, &mut Path => {
    fn chksum_into<H>(&mut self, ctx: &mut Chksumer<H>) -> Result<()>
    where
        H: Hash,
    {
        // A symlink at the top level must go through the same policy-aware classification as a symlinked `DirEntry`
        // (`classify_symlink_target`): a bare `self.metadata()?` follows the symlink and, for a dangling target,
        // propagates a raw `Error::Io` before the `IrregularFile` policy ever gets a say. `symlink_metadata` is
        // captured once and reused for the non-symlink branch below (`lstat` == `stat` when the path is not itself a
        // symlink), so a non-symlink path costs exactly one syscall; only the symlink branch needs the extra
        // `classify_symlink_target(self.metadata())` call to resolve the target.
        let metadata = self.symlink_metadata()?;
        if metadata.is_symlink() {
            return match classify_symlink_target(self.metadata())? {
                SymlinkTarget::Directory(_) => Chksumable::chksum_into(&mut read_dir(self)?, ctx),
                SymlinkTarget::File => Chksumable::chksum_into(&mut open_nonblocking(self)?, ctx),
                SymlinkTarget::Irregular => ctx.policy().skip_or_err(SkipKind::Irregular, || self.to_path_buf()),
                SymlinkTarget::Unresolvable => {
                    ctx.policy().skip_or_err(SkipKind::UnresolvableSymlink, || self.to_path_buf())
                },
            };
        }
        if metadata.is_dir() {
            Chksumable::chksum_into(&mut read_dir(self)?, ctx)
        } else if metadata.is_file() {
            Chksumable::chksum_into(&mut open_nonblocking(self)?, ctx)
        } else {
            ctx.policy().skip_or_err(SkipKind::Irregular, || self.to_path_buf())
        }
    }
});

impl_chksumable!(PathBuf, &PathBuf, &mut PathBuf => {
    fn chksum_into<H>(&mut self, ctx: &mut Chksumer<H>) -> Result<()>
    where
        H: Hash,
    {
        Chksumable::chksum_into(&mut self.as_path(), ctx)
    }
});

impl_chksumable!(File, &File, &mut File => {
    fn chksum_into<H>(&mut self, ctx: &mut Chksumer<H>) -> Result<()>
    where
        H: Hash,
    {
        if self.is_terminal() {
            Err(terminal_err())
        } else {
            ctx.update_from_reader(self).map(|_| ())
        }
    }
});

impl_chksumable!(DirEntry, &DirEntry, &mut DirEntry => {
    fn chksum_into<H>(&mut self, ctx: &mut Chksumer<H>) -> Result<()>
    where
        H: Hash,
    {
        // A top-level `DirEntry` must hash identically to its own `path()` passed directly: it is the traversal
        // root, not a child of some other directory, so it gets no name framing under `NameMode::FileName` and no
        // visited-set registration for a symlinked-directory target (both of those apply only to nested descent via
        // `chksum_dir_entry`, reached through `ReadDir`). Delegating to `Path`'s impl gives both for free at the cost
        // of repeating the `file_type`/`stat` this entry's caller may already have done.
        Chksumable::chksum_into(&mut self.path(), ctx)
    }
});

/// Folds a single directory entry into `ctx`. `path` is the entry's path, already computed by the caller (`ReadDir`)
/// while sorting, so it is resolved exactly once per entry.
fn chksum_dir_entry<H>(entry: &DirEntry, path: &Path, ctx: &mut Chksumer<H>) -> Result<()>
where
    H: Hash,
{
    // The entry kind is already known here (from `d_type` on most filesystems), so verified files and directories are
    // opened directly: dispatching through the `Path` impl would repeat the `stat`, and a verified regular file cannot
    // be a terminal, so the `File` impl's guard (an `ioctl` per file) is skipped too. Symlinks are resolved and
    // classified via `classify_symlink_target`, then `classify_entry` decides the action once (dir/file/irregular/
    // unresolvable/already-visited), so `NameMode::Off` and `NameMode::FileName` act on the same classification
    // instead of each re-deriving it.
    let file_type = entry.file_type()?;
    let symlink_target = if file_type.is_symlink() {
        Some(classify_symlink_target(path.metadata())?)
    } else {
        None
    };
    let action = classify_entry(file_type, symlink_target, |metadata| ctx.visit_symlinked_dir(metadata));

    match (action, ctx.policy().name_mode) {
        (EntryAction::Irregular, _) => ctx.policy().skip_or_err(SkipKind::Irregular, || path.to_path_buf()),
        (EntryAction::UnresolvableSymlink, _) => {
            ctx.policy()
                .skip_or_err(SkipKind::UnresolvableSymlink, || path.to_path_buf())
        },
        (EntryAction::Dir, NameMode::Off) => Chksumable::chksum_into(&mut read_dir(path)?, ctx),
        (EntryAction::File, NameMode::Off) => {
            let mut file = open_nonblocking(path)?;
            ctx.update_from_reader(&mut file).map(|_| ())
        },
        // Off has no framing to preserve, so a revisited directory is a pure no-op (FLAG C, framing the empty
        // directory, applies only to FileName below).
        (EntryAction::SkippedRevisitedDirectory, NameMode::Off) => {
            ctx.policy().notify(|| {
                Diagnostic::SkippedRevisitedDirectory {
                    path: path.to_path_buf(),
                }
            });
            Ok(())
        },
        // git-tree style: bare name, directories bracket their children. The frame is written only after the entry is
        // confirmed openable, so a failed open/read_dir leaves `ctx`'s hash state untouched for this entry instead of a
        // half-written, unclosed frame. File content is length-committed as a SUFFIX (the actual byte count streamed
        // through the hasher) — the current, unchanged encoding (D4).
        (EntryAction::Dir, NameMode::FileName) => {
            let name = path.file_name().expect("directory entry path always has a file name");
            let mut dir = read_dir(path)?;
            frame_named(&mut ctx.hash, Tag::Dir, name.as_encoded_bytes());
            Chksumable::chksum_into(&mut dir, ctx)?;
            ctx.hash.update([Tag::DirClose as u8]);
            Ok(())
        },
        (EntryAction::File, NameMode::FileName) => {
            let name = path.file_name().expect("directory entry path always has a file name");
            let mut file = open_nonblocking(path)?;
            frame_named(&mut ctx.hash, Tag::File, name.as_encoded_bytes());
            let content_len = ctx.update_from_reader(&mut file)?;
            ctx.hash.update(content_len.to_be_bytes());
            Ok(())
        },
        // FLAG C: FileName commits structure, so a skipped revisited directory must still appear in the digest — frame
        // its name and an immediate close, with no children walked — rather than vanishing. It therefore hashes
        // identically to an empty directory of the same name.
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

impl_chksumable!(ReadDir, &mut ReadDir => {
    fn chksum_into<H>(&mut self, ctx: &mut Chksumer<H>) -> Result<()>
    where
        H: Hash,
    {
        // S3: the visited-set for a fresh top-level traversal is cleared once, in `Chksumer::update_from` (the sole
        // entry point for a fresh traversal) — not here, since this impl also runs for nested descent into
        // subdirectories, which must NOT clear it. (A symlink back to an ancestor, including the top-level root, is
        // bounded and terminates via this dedup, at the documented cost of one extra traversal pass of that subtree
        // before the revisit is caught — see the crate-level Symlinks docs.)
        // S1: refuse to descend past the configured limit (guards the native stack here / the boxed future chain in the
        // async mirror).
        let ticket = ctx.enter_directory()?;
        // P2/P3: collect (path, entry) once so the sort key and the framed name share a single `path()` allocation
        // per entry, instead of a separate `file_name()` alloc for sorting plus repeated `path()` calls in dispatch.
        // `ReadDir` gives no count hint, so seed the configured modest capacity.
        let mut entries: Vec<(PathBuf, DirEntry)> = Vec::with_capacity(ctx.policy().dir_entries_capacity_hint);
        for entry in self.by_ref() {
            // S2: cap per-directory buffering; error on the entry that would exceed the maximum.
            if entries.len() >= ctx.policy().max_directory_entries.get() {
                return Err(too_many_entries_err(ctx.policy().max_directory_entries.get()));
            }
            let entry = entry?;
            entries.push((entry.path(), entry));
        }
        // Sort by full path: all entries share the parent prefix, so this is equivalent to sorting by bare name here
        // (locale-independent, aligned with the hashed identifier), and `sort_unstable` is fine since names are unique
        // per directory.
        entries.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));
        for (path, entry) in entries {
            chksum_dir_entry(&entry, &path, ctx)?;
        }
        // The `?` early-returns above intentionally leave the ticket unreturned to `leave_directory`, stranding depth
        // until the reuse contract's `reset()` runs.
        ctx.leave_directory(ticket);
        Ok(())
    }
});

impl_chksumable!(Stdin, &Stdin, &mut Stdin => {
    fn chksum_into<H>(&mut self, ctx: &mut Chksumer<H>) -> Result<()>
    where
        H: Hash,
    {
        Chksumable::chksum_into(&mut self.lock(), ctx)
    }
});

impl_chksumable!(StdinLock<'_>, &mut StdinLock<'_> => {
    fn chksum_into<H>(&mut self, ctx: &mut Chksumer<H>) -> Result<()>
    where
        H: Hash,
    {
        if self.is_terminal() {
            Err(terminal_err())
        } else {
            ctx.update_from_reader(self).map(|_| ())
        }
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
    #[cfg(unix)]
    use std::sync::{Arc, Mutex};

    use super::*;
    #[cfg(feature = "async-runtime-tokio")]
    use crate::context::tokio::AsyncChksumer;
    #[cfg(unix)]
    use crate::diagnostic::Diagnostic;
    use crate::policy::IrregularFile;
    use crate::test_util::{Collect, TempTree, write_file};
    use crate::{Error, chksum};

    /// External type that is Chksumable but NOT Hashable.
    struct ExternalReader {
        data: &'static [u8],
    }

    impl ExternalReader {
        fn new(data: &'static [u8]) -> Self {
            ExternalReader { data }
        }
    }

    impl std::io::Read for ExternalReader {
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

    #[test]
    fn file_non_empty() {
        let base = TempTree::new("file_non_empty");
        fs::create_dir_all(&base).expect("create base dir");
        let path = base.join("file.bin");

        let data = b"test file content with some bytes";
        File::create(&path)
            .and_then(|mut f| f.write_all(data))
            .expect("create test file");

        let digest = chksum::<Collect>(&path).expect("hash file");
        assert_eq!(digest.0, data.to_vec(), "file hash should match content");
    }

    // --- NameMode: directory naming/structure framing ---

    /// Hashes `path` with the given [`NameMode`] and returns the collected bytes.
    fn dir_digest(path: &Path, name_mode: NameMode) -> Vec<u8> {
        let mut ctx = Chksumer::<Collect>::builder().name_mode(name_mode).build();
        ctx.update_from(path).expect("hash path");
        ctx.digest().0
    }

    #[test]
    fn name_mode_distinguishes_resplit_content() {
        let base = TempTree::new("resplit");
        let a = base.join("a");
        let b = base.join("b");
        // Same total bytes, split differently across the same file names.
        write_file(&a.join("1"), b"foo");
        write_file(&a.join("2"), b"bar");
        write_file(&b.join("1"), b"foobar");
        write_file(&b.join("2"), b"");

        // `Off` concatenates content only -> the two trees collide (documented hazard).
        assert_eq!(dir_digest(&a, NameMode::Off), dir_digest(&b, NameMode::Off));
        // `FileName` commits per-file content lengths -> distinct digests.
        assert_ne!(dir_digest(&a, NameMode::FileName), dir_digest(&b, NameMode::FileName));
    }

    #[test]
    fn name_mode_distinguishes_flat_file_from_dir_split() {
        let base = TempTree::new("flatvsdir");
        let flat = base.join("flat.bin");
        let dir = base.join("dir");
        write_file(&flat, b"helloworld");
        write_file(&dir.join("1"), b"hello");
        write_file(&dir.join("2"), b"world");

        // `Off`: a flat file and a directory whose contents concatenate to the same bytes collide.
        assert_eq!(dir_digest(&flat, NameMode::Off), dir_digest(&dir, NameMode::Off));
        // `FileName`: the directory's entries are framed, the lone file is not -> distinct.
        assert_ne!(
            dir_digest(&flat, NameMode::FileName),
            dir_digest(&dir, NameMode::FileName)
        );
    }

    #[test]
    fn name_mode_does_not_frame_a_top_level_file() {
        // Framing is emitted only along the directory-entry path, so hashing a lone file is identical in every mode
        // (and equal to its raw content).
        let base = TempTree::new("lonefile");
        let file = base.join("x.bin");
        write_file(&file, b"top level content");

        let off = dir_digest(&file, NameMode::Off);
        assert_eq!(off, b"top level content".to_vec());
        assert_eq!(off, dir_digest(&file, NameMode::FileName));
    }

    #[test]
    fn name_mode_captures_empty_directories() {
        let base = TempTree::new("emptydir");
        let with = base.join("with");
        let without = base.join("without");
        write_file(&with.join("a.txt"), b"x");
        fs::create_dir_all(with.join("empty")).expect("create empty dir");
        write_file(&without.join("a.txt"), b"x");

        // `Off` ignores empty directories entirely -> collision.
        assert_eq!(dir_digest(&with, NameMode::Off), dir_digest(&without, NameMode::Off));
        // `FileName` records every directory entry -> the empty dir is committed.
        assert_ne!(
            dir_digest(&with, NameMode::FileName),
            dir_digest(&without, NameMode::FileName)
        );
    }

    // --- IrregularFile: non-regular directory entries ---

    #[cfg(unix)]
    #[test]
    fn irregular_file_error_aborts_and_skip_ignores() {
        let base = TempTree::new("irregular");
        let root = base.join("root");
        let expected = base.join("expected");
        write_file(&root.join("a.txt"), b"alpha");
        write_file(&expected.join("a.txt"), b"alpha");
        let _socket = UnixListener::bind(root.join("socket")).expect("bind unix socket");

        for name_mode in [NameMode::Off, NameMode::FileName] {
            // The default policy aborts with `NotARegularFile` naming the offending entry.
            let mut ctx = Chksumer::<Collect>::builder().name_mode(name_mode).build();
            let error = ctx
                .update_from(root.as_path())
                .expect_err("socket should abort traversal");
            assert!(
                matches!(&error, Error::NotARegularFile { path } if path.ends_with("socket")),
                "unexpected error for {name_mode:?}: {error:?}"
            );

            // `Skip` hashes the rest of the tree as if the socket were absent.
            let mut ctx = Chksumer::<Collect>::builder()
                .name_mode(name_mode)
                .irregular_file(IrregularFile::Skip)
                .build();
            ctx.update_from(root.as_path()).expect("skip socket");
            assert_eq!(
                ctx.digest().0,
                dir_digest(&expected, name_mode),
                "skip digest mismatch for {name_mode:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn irregular_file_dangling_symlink_error_aborts_and_skip_ignores() {
        let base = TempTree::new("dangling_symlink");
        let root = base.join("root");
        let expected = base.join("expected");
        write_file(&root.join("a.txt"), b"alpha");
        write_file(&expected.join("a.txt"), b"alpha");
        std::os::unix::fs::symlink(base.join("missing"), root.join("dangling")).expect("create dangling symlink");

        for name_mode in [NameMode::Off, NameMode::FileName] {
            // A target that cannot even be resolved (dangling symlink) is not a regular file or directory either, so
            // the default policy aborts with `NotARegularFile`, not a raw `Io` error from the failed `metadata` lookup.
            let mut ctx = Chksumer::<Collect>::builder().name_mode(name_mode).build();
            let error = ctx
                .update_from(root.as_path())
                .expect_err("dangling symlink should abort traversal");
            assert!(
                matches!(&error, Error::NotARegularFile { path } if path.ends_with("dangling")),
                "unexpected error for {name_mode:?}: {error:?}"
            );

            // `Skip` hashes the rest of the tree as if the dangling symlink were absent.
            let mut ctx = Chksumer::<Collect>::builder()
                .name_mode(name_mode)
                .irregular_file(IrregularFile::Skip)
                .build();
            ctx.update_from(root.as_path()).expect("skip dangling symlink");
            assert_eq!(
                ctx.digest().0,
                dir_digest(&expected, name_mode),
                "skip digest mismatch for {name_mode:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn irregular_file_skip_notifies_diagnostic_hook() {
        let base = TempTree::new("diagnostic_hook");
        let root = base.join("root");
        let expected = base.join("expected");
        write_file(&root.join("a.txt"), b"alpha");
        write_file(&expected.join("a.txt"), b"alpha");
        let _socket = UnixListener::bind(root.join("socket")).expect("bind unix socket");
        std::os::unix::fs::symlink(base.join("missing"), root.join("dangling")).expect("create dangling symlink");

        for name_mode in [NameMode::Off, NameMode::FileName] {
            let diagnostics: Arc<Mutex<Vec<Diagnostic>>> = Arc::new(Mutex::new(Vec::new()));
            let sink = Arc::clone(&diagnostics);
            let mut ctx = Chksumer::<Collect>::builder()
                .name_mode(name_mode)
                .irregular_file(IrregularFile::Skip)
                .on_diagnostic(move |d| sink.lock().expect("lock diagnostics").push(d.clone()))
                .build();
            ctx.update_from(root.as_path()).expect("skip irregular entries");

            // The hook is purely observational: it must not change the digest.
            assert_eq!(
                ctx.digest().0,
                dir_digest(&expected, name_mode),
                "hook must not change the skip digest for {name_mode:?}"
            );

            let seen = diagnostics.lock().expect("lock diagnostics");
            assert_eq!(seen.len(), 2, "expected two diagnostics for {name_mode:?}: {seen:?}");
            assert!(
                seen.iter()
                    .any(|d| matches!(d, Diagnostic::SkippedIrregular { path } if path.ends_with("socket"))),
                "missing SkippedIrregular diagnostic for {name_mode:?}: {seen:?}"
            );
            assert!(
                seen.iter().any(
                    |d| matches!(d, Diagnostic::SkippedUnresolvableSymlink { path } if path.ends_with("dangling"))
                ),
                "missing SkippedUnresolvableSymlink diagnostic for {name_mode:?}: {seen:?}"
            );
        }
    }

    #[cfg(all(unix, feature = "async-runtime-tokio"))]
    #[tokio::test]
    async fn irregular_file_dangling_symlink_sync_matches_async() {
        let base = TempTree::new("dangling_symlink_async");
        let root = base.join("root");
        write_file(&root.join("a.txt"), b"alpha");
        std::os::unix::fs::symlink(base.join("missing"), root.join("dangling")).expect("create dangling symlink");

        for name_mode in [NameMode::Off, NameMode::FileName] {
            let mut ctx = AsyncChksumer::<Collect>::builder().name_mode(name_mode).build();
            let error = ctx
                .update_from(root.as_path())
                .await
                .expect_err("dangling symlink should abort traversal");
            assert!(
                matches!(&error, Error::NotARegularFile { path } if path.ends_with("dangling")),
                "unexpected error for {name_mode:?}: {error:?}"
            );

            let mut sync_ctx = Chksumer::<Collect>::builder()
                .name_mode(name_mode)
                .irregular_file(IrregularFile::Skip)
                .build();
            sync_ctx
                .update_from(root.as_path())
                .expect("sync skip dangling symlink");
            let mut ctx = AsyncChksumer::<Collect>::builder()
                .name_mode(name_mode)
                .irregular_file(IrregularFile::Skip)
                .build();
            ctx.update_from(root.as_path())
                .await
                .expect("async skip dangling symlink");
            assert_eq!(
                sync_ctx.digest().0,
                ctx.digest().0,
                "sync/async digest mismatch for {name_mode:?}"
            );
        }
    }

    #[cfg(all(unix, feature = "async-runtime-tokio"))]
    #[tokio::test]
    async fn irregular_file_sync_matches_async() {
        let base = TempTree::new("irregular_async");
        let root = base.join("root");
        write_file(&root.join("a.txt"), b"alpha");
        let _socket = UnixListener::bind(root.join("socket")).expect("bind unix socket");

        for name_mode in [NameMode::Off, NameMode::FileName] {
            // The default policy aborts, matching the synchronous path.
            let mut ctx = AsyncChksumer::<Collect>::builder().name_mode(name_mode).build();
            let error = ctx
                .update_from(root.as_path())
                .await
                .expect_err("socket should abort traversal");
            assert!(
                matches!(&error, Error::NotARegularFile { path } if path.ends_with("socket")),
                "unexpected error for {name_mode:?}: {error:?}"
            );

            // `Skip` produces the same digest as the synchronous traversal.
            let mut sync_ctx = Chksumer::<Collect>::builder()
                .name_mode(name_mode)
                .irregular_file(IrregularFile::Skip)
                .build();
            sync_ctx.update_from(root.as_path()).expect("sync skip socket");
            let mut ctx = AsyncChksumer::<Collect>::builder()
                .name_mode(name_mode)
                .irregular_file(IrregularFile::Skip)
                .build();
            ctx.update_from(root.as_path()).await.expect("async skip socket");
            assert_eq!(
                sync_ctx.digest().0,
                ctx.digest().0,
                "sync/async digest mismatch for {name_mode:?}"
            );
        }
    }

    #[cfg(feature = "async-runtime-tokio")]
    #[tokio::test]
    async fn name_mode_sync_matches_async() {
        let base = TempTree::new("syncasync");
        let root = base.join("root");
        write_file(&root.join("a.txt"), b"alpha");
        write_file(&root.join("sub").join("b.txt"), b"bravo");
        write_file(&root.join("sub").join("deep").join("c.txt"), b"charlie");

        for name_mode in [NameMode::Off, NameMode::FileName] {
            let sync = dir_digest(&root, name_mode);
            let mut ctx = AsyncChksumer::<Collect>::builder().name_mode(name_mode).build();
            ctx.update_from(root.as_path()).await.expect("async hash path");
            assert_eq!(sync, ctx.digest().0, "sync/async digest mismatch for {name_mode:?}");
        }
    }

    // --- D4: file-content framing bytes (current suffix encoding, unchanged) ---

    #[test]
    fn file_name_frames_content_length_as_suffix() {
        let base = TempTree::new("content_suffix");
        let one = base.join("one");
        write_file(&one.join("x"), b"hi");

        let mut expected = Vec::new();
        expected.push(0x01u8); // Tag::File
        expected.extend_from_slice(&1u64.to_be_bytes()); // name length prefix
        expected.push(b'x');
        expected.extend_from_slice(b"hi");
        expected.extend_from_slice(&2u64.to_be_bytes()); // content length suffix

        assert_eq!(dir_digest(&one, NameMode::FileName), expected);
    }

    // --- D5: top-level irregular file ---

    #[cfg(unix)]
    #[test]
    fn top_level_irregular_file_errors_and_skip_yields_empty() {
        let base = TempTree::new("toplevel_irregular");
        fs::create_dir_all(&base).expect("create base dir");
        let socket_path = base.join("socket");
        let _socket = UnixListener::bind(&socket_path).expect("bind unix socket");

        let error = chksum::<Collect>(&socket_path).expect_err("socket should error by default");
        assert!(
            matches!(&error, Error::NotARegularFile { path } if path == &socket_path),
            "unexpected error: {error:?}"
        );

        let mut ctx = Chksumer::<Collect>::builder()
            .irregular_file(IrregularFile::Skip)
            .build();
        ctx.update_from(socket_path.as_path()).expect("skip top-level socket");
        assert_eq!(ctx.digest().0, Vec::<u8>::new(), "skip digest should be empty");
    }

    // --- F2/F3: top-level dangling/irregular symlink honors IrregularFile policy ---

    #[cfg(unix)]
    #[test]
    fn top_level_dangling_symlink_errors_and_skip_yields_empty() {
        let base = TempTree::new("toplevel_dangling_symlink");
        fs::create_dir_all(&base).expect("create base dir");
        let link_path = base.join("dangling");
        symlink(base.join("missing"), &link_path).expect("create dangling symlink");

        // Previously this propagated a raw `Error::Io` from the bare `metadata()` call instead of the same
        // `NotARegularFile` a dangling symlink nested inside a directory already reported.
        let error = chksum::<Collect>(&link_path).expect_err("dangling symlink should abort by default");
        assert!(
            matches!(&error, Error::NotARegularFile { path } if path == &link_path),
            "unexpected error: {error:?}"
        );

        let mut ctx = Chksumer::<Collect>::builder()
            .irregular_file(IrregularFile::Skip)
            .build();
        ctx.update_from(link_path.as_path())
            .expect("skip top-level dangling symlink");
        assert_eq!(ctx.digest().0, Vec::<u8>::new(), "skip digest should be empty");
    }

    #[cfg(unix)]
    #[test]
    fn top_level_symlink_to_socket_errors_and_skip_yields_empty() {
        let base = TempTree::new("toplevel_symlink_socket");
        fs::create_dir_all(&base).expect("create base dir");
        let socket_path = base.join("socket");
        let _socket = UnixListener::bind(&socket_path).expect("bind unix socket");
        let link_path = base.join("link_to_socket");
        symlink(&socket_path, &link_path).expect("create symlink to socket");

        let error = chksum::<Collect>(&link_path).expect_err("symlink to socket should abort by default");
        assert!(
            matches!(&error, Error::NotARegularFile { path } if path == &link_path),
            "unexpected error: {error:?}"
        );

        let mut ctx = Chksumer::<Collect>::builder()
            .irregular_file(IrregularFile::Skip)
            .build();
        ctx.update_from(link_path.as_path())
            .expect("skip top-level symlink to socket");
        assert_eq!(ctx.digest().0, Vec::<u8>::new(), "skip digest should be empty");
    }

    #[cfg(unix)]
    #[test]
    fn top_level_symlink_to_dir_or_file_still_works() {
        let base = TempTree::new("toplevel_symlink_ok_targets");
        let target_dir = base.join("target_dir");
        write_file(&target_dir.join("a.txt"), b"alpha");
        let target_file = base.join("target_file");
        write_file(&target_file, b"beta");
        let link_to_dir = base.join("link_to_dir");
        let link_to_file = base.join("link_to_file");
        symlink(&target_dir, &link_to_dir).expect("create symlink to dir");
        symlink(&target_file, &link_to_file).expect("create symlink to file");

        assert_eq!(
            chksum::<Collect>(link_to_dir.as_path()).expect("hash symlink to dir").0,
            chksum::<Collect>(target_dir.as_path()).expect("hash dir directly").0,
        );
        assert_eq!(
            chksum::<Collect>(link_to_file.as_path())
                .expect("hash symlink to file")
                .0,
            b"beta".to_vec(),
        );
    }

    // --- F8: a top-level regular file open goes through the same nonblocking-open hardening as a directory entry ---

    #[cfg(all(unix, feature = "nonblocking-open"))]
    #[test]
    fn top_level_open_uses_o_nonblock_and_does_not_hang_on_a_fifo() {
        let base = TempTree::new("toplevel_nonblocking_open");
        fs::create_dir_all(&base).expect("create base dir");
        let fifo_path = base.join("fifo");
        // The crate is `#![forbid(unsafe_code)]`, so the FIFO is created by shelling out to the `mkfifo` binary
        // (present on Linux/macOS) rather than calling `libc::mkfifo` directly.
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo_path)
            .status()
            .expect("run mkfifo");
        assert!(status.success(), "mkfifo command failed: {status:?}");

        // A genuine top-level TOCTOU race (a path classified as a regular file, then swapped for a FIFO before the
        // open call) is inherently timing-dependent and not reproducible deterministically here. Instead, this pins
        // the mechanism directly: before this fix, the top-level `Path` impl's regular-file branch called a bare
        // `File::open` regardless of the `nonblocking-open` feature, so opening a FIFO with no writer through it
        // would block indefinitely. `open_nonblocking` is the exact helper the fixed top-level impl now routes
        // through (the same one a directory entry already used) -- calling it directly here proves it opens a FIFO
        // with no writer immediately (no hang) and that the subsequent read sees EOF, producing an empty digest.
        let mut file = open_nonblocking(&fifo_path).expect("open must not hang; O_NONBLOCK returns immediately");
        let mut ctx = Chksumer::<Collect>::new();
        ctx.update_from_reader(&mut file)
            .expect("read must not hang; FIFO with no writer is EOF");
        assert_eq!(
            ctx.digest().0,
            Vec::<u8>::new(),
            "no writer ever connected, so content is empty"
        );
    }

    // --- D1: symlink to a non-regular target inside a traversed directory ---

    #[cfg(unix)]
    #[test]
    fn symlink_to_socket_reports_skipped_irregular_not_unresolvable() {
        let base = TempTree::new("symlink_socket");
        let root = base.join("root");
        write_file(&root.join("a.txt"), b"alpha");
        let socket_path = base.join("socket_target");
        let _socket = UnixListener::bind(&socket_path).expect("bind unix socket");
        symlink(&socket_path, root.join("link_to_socket")).expect("create symlink to socket");

        let error = chksum::<Collect>(root.as_path()).expect_err("default policy should abort");
        assert!(
            matches!(&error, Error::NotARegularFile { path } if path.ends_with("link_to_socket")),
            "unexpected error: {error:?}"
        );

        let diagnostics: Arc<Mutex<Vec<Diagnostic>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&diagnostics);
        let mut ctx = Chksumer::<Collect>::builder()
            .irregular_file(IrregularFile::Skip)
            .on_diagnostic(move |d| sink.lock().expect("lock diagnostics").push(d.clone()))
            .build();
        ctx.update_from(root.as_path()).expect("skip symlink to socket");

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

    // --- S3: symlink cycle terminates ---

    #[cfg(unix)]
    #[test]
    fn symlink_cycle_terminates() {
        let base = TempTree::new("symlink_cycle");
        let root = base.join("root");
        write_file(&root.join("sub").join("a.txt"), b"alpha");
        symlink(&root, root.join("sub").join("loop")).expect("create symlink cycle");

        let diagnostics: Arc<Mutex<Vec<Diagnostic>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&diagnostics);
        let mut ctx = Chksumer::<Collect>::builder()
            .on_diagnostic(move |d| sink.lock().expect("lock diagnostics").push(d.clone()))
            .build();
        ctx.update_from(root.as_path())
            .expect("cycle should terminate, not hang or overflow");

        let seen = diagnostics.lock().expect("lock diagnostics");
        assert!(
            seen.iter()
                .any(|d| matches!(d, Diagnostic::SkippedRevisitedDirectory { .. })),
            "expected at least one SkippedRevisitedDirectory diagnostic: {seen:?}"
        );

        drop(seen);
    }

    // --- F5: a long chain of forward symlinks hits the OS's own ELOOP limit, not max_directory_depth ---

    #[cfg(unix)]
    #[test]
    fn forward_symlink_chain_hits_eloop_not_depth_limit() {
        let base = TempTree::new("symlink_chain_eloop");
        fs::create_dir_all(&base).expect("create base dir");
        write_file(&base.join("target"), b"end");

        // A chain long enough to exceed the OS's own symlink-resolution limit (ELOOP, ~40 on Linux), but far short of
        // even the crate's own default max_directory_depth.
        let mut previous = base.join("target");
        for i in 0..60 {
            let link = base.join(format!("link{i}"));
            symlink(&previous, &link).expect("create chain link");
            previous = link;
        }

        // The chain is resolved from a plain file at the top level (not a directory), so this exercises the
        // top-level Path dispatch's symlink handling. `io::ErrorKind::FilesystemLoop` is unstable
        // (rust-lang/rust#86442), so it cannot be matched directly on this crate's stable MSRV; check the raw ELOOP
        // errno on Linux instead, and settle for the weaker (but still meaningful) "not TraversalTooDeep, not a
        // hang/crash" check elsewhere.
        let error = chksum::<Collect>(previous.as_path()).expect_err("chain should fail via ELOOP, not hang or crash");
        assert!(
            matches!(&error, Error::Io(_)),
            "expected a clean Io error (ELOOP), not a TraversalTooDeep or other error: {error:?}"
        );
        #[cfg(target_os = "linux")]
        if let Error::Io(e) = &error {
            assert_eq!(e.raw_os_error(), Some(40), "expected ELOOP (errno 40) on Linux: {e:?}");
        }
    }

    // --- S1: depth limit ---

    #[test]
    fn depth_limit_default_errors_too_deep() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let base = TempTree::new("depth_limit_default");
                let mut deepest = base.to_path_buf();
                for _ in 0..=crate::policy::DEFAULT_MAX_DIRECTORY_DEPTH.get() {
                    deepest = deepest.join("d");
                }
                fs::create_dir_all(&deepest).expect("create deep tree");

                let error = chksum::<Collect>(base.as_path()).expect_err("should exceed default depth limit");
                assert!(
                    matches!(error, Error::TraversalTooDeep { .. }),
                    "unexpected error: {error:?}"
                );
            })
            .expect("spawn thread")
            .join()
            .expect("join thread");
    }

    // --- F4: default depth limit is safe on a small (2 MiB) default-sized thread stack ---

    #[test]
    fn depth_limit_default_errors_too_deep_on_default_sized_stack() {
        // 2 MiB matches std::thread::spawn's / tokio::task::spawn_blocking's default worker stack size -- the
        // realistic worst case the default `max_directory_depth` must stay safely below.
        std::thread::Builder::new()
            .stack_size(2 * 1024 * 1024)
            .spawn(|| {
                let base = TempTree::new("depth_limit_default_small_stack");
                let mut deepest = base.to_path_buf();
                for _ in 0..=crate::policy::DEFAULT_MAX_DIRECTORY_DEPTH.get() {
                    deepest = deepest.join("d");
                }
                fs::create_dir_all(&deepest).expect("create deep tree");

                let error = chksum::<Collect>(base.as_path()).expect_err("should exceed default depth limit");
                assert!(
                    matches!(error, Error::TraversalTooDeep { .. }),
                    "unexpected error: {error:?}"
                );
            })
            .expect("spawn thread")
            .join()
            .expect("thread overflowed its stack instead of returning Error::TraversalTooDeep");
    }

    // --- NEW: max_directory_depth override ---

    #[test]
    fn depth_limit_override_errors_at_configured_limit() {
        let base = TempTree::new("depth_limit_override");
        let mut deepest = base.to_path_buf();
        for _ in 0..6 {
            deepest = deepest.join("d");
        }
        fs::create_dir_all(&deepest).expect("create tree");

        let mut ctx = Chksumer::<Collect>::builder()
            .max_directory_depth(NonZeroUsize::new(4).expect("non-zero"))
            .build();
        let error = ctx
            .update_from(base.as_path())
            .expect_err("should exceed configured depth limit");
        assert!(
            matches!(error, Error::TraversalTooDeep { limit } if limit == 4),
            "unexpected error: {error:?}"
        );
    }

    // --- NEW: follow_symlink_revisits toggle ---

    #[cfg(unix)]
    #[test]
    fn follow_symlink_revisits_toggle_changes_digest() {
        let base = TempTree::new("follow_revisits");
        let root = base.join("root");
        write_file(&root.join("d").join("f"), b"x");
        symlink(root.join("d"), root.join("a")).expect("create symlink a");
        symlink(root.join("d"), root.join("b")).expect("create symlink b");

        let default_digest = {
            let mut ctx = Chksumer::<Collect>::builder().name_mode(NameMode::Off).build();
            ctx.update_from(root.as_path()).expect("hash with default dedup");
            ctx.digest().0
        };
        let follow_digest = {
            let mut ctx = Chksumer::<Collect>::builder()
                .name_mode(NameMode::Off)
                .follow_symlink_revisits(true)
                .build();
            ctx.update_from(root.as_path()).expect("hash with follow enabled");
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

    // --- NEW: FLAG C name preservation on revisit ---

    #[cfg(unix)]
    #[test]
    fn revisited_directory_preserves_name_framing() {
        let base = TempTree::new("revisit_framing");
        let root = base.join("root");
        write_file(&root.join("d").join("f"), b"x");
        symlink(root.join("d"), root.join("a")).expect("create symlink a");
        symlink(root.join("d"), root.join("b")).expect("create symlink b");

        let digest = dir_digest(&root, NameMode::FileName);

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

    // --- top-level DirEntry vs Path digest parity (NameMode::Off and NameMode::FileName) ---

    #[test]
    fn top_level_direntry_matches_path_digest() {
        let base = TempTree::new("direntry_matches_path");
        let target = base.join("target");
        write_file(&target.join("a.txt"), b"alpha");
        write_file(&target.join("sub").join("b.txt"), b"bravo");

        for name_mode in [NameMode::Off, NameMode::FileName] {
            let via_path = dir_digest(&target, name_mode);
            let mut ctx = Chksumer::<Collect>::builder().name_mode(name_mode).build();
            let entry = fs::read_dir(&base)
                .expect("read base")
                .filter_map(|e| e.ok())
                .find(|e| e.file_name() == "target")
                .expect("find target entry");
            ctx.update_from(entry).expect("hash via top-level DirEntry");
            assert_eq!(
                ctx.digest().0,
                via_path,
                "top-level DirEntry must hash identically to the same object passed as a top-level Path for \
                 {name_mode:?}"
            );
        }
    }

    #[cfg(feature = "async-runtime-tokio")]
    #[tokio::test]
    async fn top_level_direntry_matches_path_digest_async() {
        let base = TempTree::new("async_direntry_matches_path");
        let target = base.join("target");
        write_file(&target.join("a.txt"), b"alpha");
        write_file(&target.join("sub").join("b.txt"), b"bravo");

        for name_mode in [NameMode::Off, NameMode::FileName] {
            let mut path_ctx = AsyncChksumer::<Collect>::builder().name_mode(name_mode).build();
            path_ctx
                .update_from(target.as_path())
                .await
                .expect("hash via top-level Path");

            let entry = tokio::fs::read_dir(&base)
                .await
                .expect("async read base")
                .next_entry()
                .await
                .expect("read entry")
                .expect("find target entry");
            let mut entry_ctx = AsyncChksumer::<Collect>::builder().name_mode(name_mode).build();
            entry_ctx.update_from(entry).await.expect("hash via top-level DirEntry");

            assert_eq!(
                path_ctx.digest().0,
                entry_ctx.digest().0,
                "async top-level DirEntry must hash identically to the same object passed as a top-level Path for \
                 {name_mode:?}"
            );
        }
    }

    // --- top-level symlink-to-directory DirEntry must not register itself into the visited set (Path doesn't) ---

    #[cfg(unix)]
    #[test]
    fn top_level_symlink_direntry_visited_registration_matches_path() {
        // Before the fix, a top-level `DirEntry` that is itself a symlink to a directory went through
        // `chksum_dir_entry`'s symlink branch, which registers the target in `ctx.visited` (S3) -- something the
        // top-level `Path` impl deliberately does not do. A *nested* symlink inside that same tree pointing back at
        // the very same target would then be (incorrectly) treated as an already-visited revisit only via the
        // `DirEntry` entry point, diverging from `Path`. Delegating the top-level `DirEntry` impl to `Path` removes
        // this divergence.
        let base = TempTree::new("toplevel_symlink_direntry_visited");
        let shared = base.join("shared");
        write_file(&shared.join("f"), b"x");
        let link = base.join("link_to_shared"); // the top-level source itself is a symlink to `shared`
        symlink(&shared, &link).expect("create symlink to shared");
        // A nested symlink inside `shared`, pointing back at the very same target as the top-level source.
        symlink(&shared, shared.join("nested_link")).expect("create nested symlink back to shared");

        let via_path = {
            let mut ctx = Chksumer::<Collect>::new();
            ctx.update_from(link.as_path()).expect("hash via top-level Path");
            ctx.digest().0
        };
        let entry = fs::read_dir(&base)
            .expect("read base")
            .filter_map(|e| e.ok())
            .find(|e| e.file_name() == "link_to_shared")
            .expect("find link entry");
        let via_direntry = {
            let mut ctx = Chksumer::<Collect>::new();
            ctx.update_from(entry).expect("hash via top-level DirEntry");
            ctx.digest().0
        };

        assert_eq!(
            via_path, via_direntry,
            "top-level DirEntry must not register itself into the visited set, unlike top-level Path"
        );
    }

    // --- update_from resets depth alongside the visited set, so a reused Chksumer after an aborted (too-deep)
    //     traversal starts its next fresh call with a full depth budget instead of a stranded one ---

    #[test]
    fn update_from_resets_depth_after_prior_error() {
        let base = TempTree::new("depth_reset_after_error");
        let deep_root = base.join("deep");
        // depth 0 = deep_root's ReadDir, 1 = a's, 2 = b's (this one hits the limit and aborts without decrementing).
        write_file(&deep_root.join("a").join("b").join("c.txt"), b"too deep");
        let shallow_root = base.join("shallow");
        write_file(&shallow_root.join("f.txt"), b"shallow");

        let mut ctx = Chksumer::<Collect>::builder()
            .max_directory_depth(NonZeroUsize::new(2).expect("non-zero"))
            .build();
        let error = ctx
            .update_from(deep_root.as_path())
            .expect_err("tree exceeds the configured depth limit");
        assert!(
            matches!(error, Error::TraversalTooDeep { limit } if limit == 2),
            "unexpected error: {error:?}"
        );

        // Before the fix, `ctx.depth` was left stranded at the limit (the error path returns before any of the
        // unwound frames' `depth -= 1` runs), so this second, unrelated, shallow top-level call would immediately
        // hit the same depth limit and fail spuriously.
        ctx.update_from(shallow_root.as_path())
            .expect("a fresh top-level call must start with a full depth budget, not a stranded one");
        assert_eq!(ctx.digest().0, b"shallow".to_vec());
    }

    // --- NEW: max_directory_entries boundary (exactly at the cap succeeds, one more errors) ---

    #[test]
    fn max_directory_entries_boundary() {
        let base = TempTree::new("max_entries_boundary");
        for i in 0..3 {
            write_file(&base.join(format!("f{i}")), b"x");
        }

        // Exactly at the configured cap: succeeds.
        let mut ctx = Chksumer::<Collect>::builder()
            .max_directory_entries(NonZeroUsize::new(3).expect("non-zero"))
            .build();
        ctx.update_from(base.as_path())
            .expect("a directory with exactly the configured cap of entries must not error");

        // One more than the cap: aborts with DirectoryTooLarge.
        let mut ctx = Chksumer::<Collect>::builder()
            .max_directory_entries(NonZeroUsize::new(2).expect("non-zero"))
            .build();
        let error = ctx
            .update_from(base.as_path())
            .expect_err("a directory exceeding the configured cap must abort");
        assert!(
            matches!(error, Error::DirectoryTooLarge { limit } if limit == 2),
            "unexpected error: {error:?}"
        );
    }

    // --- F6: the visited-set must not leak across two top-level DirEntry sources sharing one reused Chksumer ---

    #[cfg(unix)]
    #[test]
    fn visited_set_does_not_leak_across_reused_chksumer_top_level_calls() {
        let base = TempTree::new("visited_leak_direntry_reuse");
        // A directory shared as the target of two unrelated symlinks reached from two unrelated top-level sources.
        write_file(&base.join("shared").join("f"), b"x");
        // First top-level source: a *plain* directory (not itself a symlink) containing a nested symlink to
        // `shared`. The nested symlink is visited at depth >= 1, so its identity survives in `ctx.visited` after the
        // call completes (only a depth-0 `ReadDir` call clears the set, and the one depth-0 call here is `root1`'s
        // own -- before the nested symlink is even reached).
        let root1 = base.join("root1");
        fs::create_dir_all(&root1).expect("create root1");
        symlink(base.join("shared"), root1.join("link")).expect("create nested symlink to shared dir");
        // Second top-level source: a symlink *itself* (not nested) pointing at the same `shared` directory.
        let root2 = base.join("root2");
        fs::create_dir_all(&root2).expect("create root2");
        symlink(base.join("shared"), root2.join("link2")).expect("create second symlink to shared dir");

        let entry_root1 = fs::read_dir(&base)
            .expect("read base")
            .filter_map(|e| e.ok())
            .find(|e| e.file_name() == "root1")
            .expect("find root1 entry");
        let entry_link2 = fs::read_dir(&root2)
            .expect("read root2")
            .next()
            .expect("root2 has an entry")
            .expect("read root2 entry");

        let mut ctx = Chksumer::<Collect>::new();
        ctx.update_from(entry_root1)
            .expect("first top-level DirEntry traversal (root1, containing a nested symlink to shared)");
        assert_eq!(
            ctx.digest().0,
            b"x".to_vec(),
            "sanity: first traversal hashed shared's content once"
        );

        // Reusing `ctx` (no `reset()`) for a second, unrelated top-level `DirEntry` source that is itself a symlink
        // resolving to the same `shared` directory must NOT treat it as already visited: this is a fresh top-level
        // traversal, not a nested revisit within the same one.
        ctx.update_from(entry_link2)
            .expect("second top-level DirEntry traversal (link2, itself a symlink to shared)");

        // Content-only (`NameMode::Off`) concatenates hashed bytes across both `update_from` calls, so `shared`'s
        // single file must contribute its content twice -- once per independent top-level traversal -- not once.
        assert_eq!(
            ctx.digest().0,
            b"xx".to_vec(),
            "second top-level traversal must not be skipped due to a stale visited entry from the first"
        );
    }
}
