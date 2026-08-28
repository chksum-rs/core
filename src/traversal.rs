//! Directory-traversal dispatch primitives shared by the blocking and async dispatch modules: the
//! [`NameMode::FileName`](crate::NameMode::FileName) wire format ([`Tag`], [`frame_named`]), symlink-target
//! classification ([`SymlinkTarget`], [`classify_symlink_target`]), and the single-pass directory-entry decision
//! ([`EntryAction`], [`classify_entry`]).

use std::fs::{FileType, Metadata};
use std::io;

use crate::error::{Error, Result};
use crate::hashable::Hash;

/// Domain tag prefixing a framed record, disambiguating it from adjacent names or content in a
/// [`NameMode::FileName`](crate::NameMode::FileName) digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Tag {
    /// Prefixes a framed regular-file record.
    File = 0x01,
    /// Prefixes a framed directory record.
    Dir = 0x02,
    /// Closes a directory's bracketed children.
    DirClose = 0x03,
}

/// Feeds `tag ‖ bytes.len() as u64 big-endian ‖ bytes` to the hash, length-framing `bytes` in network byte order so it
/// cannot be confused with adjacent names or content.
#[inline]
pub(crate) fn frame_named<H>(hash: &mut H, tag: Tag, bytes: &[u8])
where
    H: Hash,
{
    hash.update([tag as u8]);
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

/// Classification of a symlink's resolved target, driving the traversal dispatch.
pub(crate) enum SymlinkTarget {
    /// Target is a directory; carries its (symlink-followed) metadata for identity keying (S3).
    Directory(Metadata),
    /// Target is a regular file.
    File,
    /// Target resolves but is neither a regular file nor a directory (socket/FIFO/device).
    Irregular,
    /// Target could not be resolved (e.g. a dangling symlink: NotFound).
    Unresolvable,
}

/// Classifies the resolved target of a symlink from its symlink-following `metadata()` result. A `NotFound` error is
/// folded into `Unresolvable` (dangling link, handled per policy); any other I/O error is surfaced (not masked) as
/// [`Error::Io`] — including the OS's own `ELOOP` (surfaced by Rust as the unstable `io::ErrorKind::FilesystemLoop`),
/// which is raised when resolving a long chain of forward symlinks, well before the crate's own maximum directory
/// depth would ever apply (see the crate-level Symlinks docs); this is a clean, documented `Error::Io`, not a hang or
/// crash.
pub(crate) fn classify_symlink_target(metadata: io::Result<Metadata>) -> Result<SymlinkTarget> {
    match metadata {
        Ok(m) if m.is_dir() => Ok(SymlinkTarget::Directory(m)),
        Ok(m) if m.is_file() => Ok(SymlinkTarget::File),
        Ok(_) => Ok(SymlinkTarget::Irregular),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(SymlinkTarget::Unresolvable),
        Err(e) => Err(Error::Io(e)),
    }
}

/// Traversal action for a directory entry, decided once from its `file_type` and — for a symlink — its
/// already-classified target, instead of re-classifying separately per [`NameMode`](crate::NameMode) branch.
pub(crate) enum EntryAction {
    /// Descend into it as a directory (a real directory, or a symlink resolving to one, first encounter this
    /// traversal).
    Dir,
    /// Read it as a regular file (a real file, or a symlink resolving to one).
    File,
    /// A symlinked directory whose target was already visited this traversal (S3): no I/O, but under
    /// [`NameMode::FileName`](crate::NameMode::FileName) it must still be framed as an empty directory to preserve
    /// its structural presence.
    SkippedRevisitedDirectory,
    /// Neither a regular file nor a directory (socket, FIFO, device node, or a symlink resolving to one).
    Irregular,
    /// A symlink whose target could not be resolved (e.g. dangling).
    UnresolvableSymlink,
}

/// Classifies a directory entry into the [`EntryAction`] the traversal should take, given its `file_type` and — for a
/// symlink (`file_type.is_symlink()`) — the caller's already-classified `symlink_target`. Also applies the
/// visited-directory dedup (S3) via `visit_symlinked_dir` for a symlinked directory target, so classification and
/// dedup happen exactly once per entry regardless of `NameMode`. No I/O of its own: callers resolve any I/O (symlink
/// metadata) themselves before calling this; the only mutation is the visited-set registration performed through the
/// caller-provided `visit_symlinked_dir` closure.
pub(crate) fn classify_entry(
    file_type: FileType,
    symlink_target: Option<SymlinkTarget>,
    mut visit_symlinked_dir: impl FnMut(&Metadata) -> bool,
) -> EntryAction {
    if file_type.is_dir() {
        EntryAction::Dir
    } else if file_type.is_file() {
        EntryAction::File
    } else if let Some(target) = symlink_target {
        match target {
            SymlinkTarget::Directory(metadata) => {
                if visit_symlinked_dir(&metadata) {
                    EntryAction::Dir
                } else {
                    EntryAction::SkippedRevisitedDirectory
                }
            },
            SymlinkTarget::File => EntryAction::File,
            SymlinkTarget::Irregular => EntryAction::Irregular,
            SymlinkTarget::Unresolvable => EntryAction::UnresolvableSymlink,
        }
    } else {
        EntryAction::Irregular
    }
}
