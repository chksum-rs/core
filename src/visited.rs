//! Cross-platform directory identity, used to recognize a directory already entered through a symlink so that symlink
//! cycles and repeated-target fan-out cannot drive unbounded traversal.

use std::collections::HashSet;
use std::fs::Metadata;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt as _;

/// Filesystem identity of a directory on Unix: (device, inode). Two paths with the same key are the same directory.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct DirKey {
    dev: u64,
    ino: u64,
}

#[cfg(unix)]
impl DirKey {
    /// Derives a directory identity from (symlink-followed) metadata.
    pub(crate) fn from_metadata(metadata: &Metadata) -> Option<Self> {
        Some(Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
        })
    }
}

/// Directory identity on platforms without a stable identity source available through stable std APIs — this includes
/// Windows: its equivalent identity, `MetadataExt::volume_serial_number`/`file_index`, is gated behind the unstable
/// `windows_by_handle` feature ([rust-lang/rust#63010](https://github.com/rust-lang/rust/issues/63010)) and this crate
/// is `#![forbid(unsafe_code)]`, so no raw `Win32` FFI workaround is available either. Traversal relies on the
/// max-depth backstop instead of cycle detection here.
#[cfg(not(unix))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct DirKey;

#[cfg(not(unix))]
impl DirKey {
    /// Always returns `None`: this platform has no stable directory identity available through stable std APIs.
    pub(crate) fn from_metadata(_metadata: &Metadata) -> Option<Self> {
        None
    }
}

/// Records a symlinked directory's identity in `visited` for cycle/fan-out protection (S3). Returns `true` if the
/// caller should descend into it — the first encounter this traversal, an identity unknowable on this platform, or
/// `follow_symlink_revisits` is set — and `false` if it was already visited and must be skipped. Shared by
/// [`Chksumer`](crate::Chksumer) and [`AsyncChksumer`](crate::AsyncChksumer), which are otherwise fully synchronous
/// here (no I/O, just a set lookup).
pub(crate) fn visit_symlinked_dir(
    visited: &mut HashSet<DirKey>,
    follow_symlink_revisits: bool,
    metadata: &Metadata,
) -> bool {
    if follow_symlink_revisits {
        // Opt-out: never dedup, so every symlinked directory is re-walked (restores the exact pre-dedup digest for
        // trees with duplicate symlink targets).
        return true;
    }
    match DirKey::from_metadata(metadata) {
        Some(key) => visited.insert(key),
        None => true,
    }
}
