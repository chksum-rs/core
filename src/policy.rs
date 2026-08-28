//! User-facing directory-traversal policy: [`NameMode`] and [`IrregularFile`], their default limits, and the
//! [`skip_or_err`] dispatch that enacts the [`IrregularFile`] choice.

use std::num::NonZeroUsize;
use std::path::PathBuf;

use crate::diagnostic::{Diagnostic, DiagnosticHook};
use crate::error::{Result, not_regular_file_err};

// Default traversal limits. Each is the starting value of a builder-configurable field on Chksumer/AsyncChksumer; the
// traversal reads the per-context field, never these consts directly.
/// Default maximum directory-recursion depth before traversal aborts with
/// [`Error::TraversalTooDeep`](crate::Error::TraversalTooDeep). A power of two.
/// Overridable per context via
/// [`ChksumerBuilder::max_directory_depth`](crate::ChksumerBuilder::max_directory_depth). Guards native stack (sync) /
/// boxed-future-chain (async) exhaustion on deeply nested or cyclically linked trees.
///
/// Both the synchronous AND the asynchronous traversal recurse on the native call stack, so this value must stay
/// safely below the depth at which that recursion overflows a small stack. The synchronous path recurses directly;
/// the async path recurses through `async_trait`'s heap-boxed futures, but heap-boxing only avoids storing each
/// level's future state inline in its caller — polling a chain of nested boxed futures still drives a chain of
/// nested `poll` calls on the native stack, so async recursion is bounded by the same kind of native-stack limit,
/// just with a smaller per-level cost.
///
/// Measured empirically on an unoptimized (`dev` profile) build, a 2 MiB stack — the default
/// `std::thread::spawn`/`tokio::task::spawn_blocking` worker stack size — overflows between roughly 440 and 460
/// levels of nesting for the synchronous path, but only roughly 150 and 180 levels for the async path (smaller
/// per-level frames, but still real stack consumption per level). 64 keeps a wide margin below the tighter (async)
/// measured threshold — roughly 2-3x — to absorb variance across compilers, optimization levels, and architectures.
/// Raising `max_directory_depth` past a safe bound for the stack size actually in use is a caller-opted-in risk —
/// this crate has no way to inspect the calling thread's stack size and cannot enforce a safe ceiling on a caller's
/// behalf; a caller intentionally raising the limit for deeper legitimate trees should size or reserve its own
/// thread stack accordingly (and, for the async path, should not assume heap-boxed futures make depth free).
pub const DEFAULT_MAX_DIRECTORY_DEPTH: NonZeroUsize = match NonZeroUsize::new(64) {
    Some(n) => n,
    None => panic!("DEFAULT_MAX_DIRECTORY_DEPTH must be non-zero"),
};
/// Default maximum number of entries buffered from one directory before traversal aborts with
/// [`Error::DirectoryTooLarge`](crate::Error::DirectoryTooLarge). Overridable via
/// [`ChksumerBuilder::max_directory_entries`](crate::ChksumerBuilder::max_directory_entries).
pub const DEFAULT_MAX_DIRECTORY_ENTRIES: NonZeroUsize = match NonZeroUsize::new(10_000_000) {
    Some(n) => n,
    None => panic!("DEFAULT_MAX_DIRECTORY_ENTRIES must be non-zero"),
};
/// Default initial capacity for the per-directory entry buffer. `ReadDir` yields no entry-count hint, so this modest
/// fixed size spares the first few reallocations on the common small-directory case without pretending to know the real
/// count. Overridable via
/// [`ChksumerBuilder::dir_entries_capacity_hint`](crate::ChksumerBuilder::dir_entries_capacity_hint).
pub(crate) const DEFAULT_DIR_ENTRIES_CAPACITY_HINT: usize = 32;

/// Selects whether and how directory entry names and structure are folded into a directory digest.
///
/// The default, [`Off`](NameMode::Off), preserves the historical content-only behavior. See the crate-level
/// documentation on directory digests for the collision caveats this controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum NameMode {
    /// Hash only the raw contents of regular files, concatenated in sorted order — no entry names, lengths, structure,
    /// or boundaries are committed.
    ///
    /// This is the default and matches the historical behavior. Because nothing frames the content, **distinct trees
    /// can collide**: re-splitting the same bytes across differently named files, renaming files, and a flat file
    /// versus a directory split all produce the same digest.
    #[default]
    Off,
    /// Commit each entry's bare file name and the directory nesting, git-tree style: every entry is length-framed and
    /// directories bracket their children. Renames, reordering, re-splitting content, and flattening or nesting
    /// subtrees all change the digest. Only bare names are used, so the digest is independent of where the tree lives.
    ///
    /// Each entry's name is length-prefixed, while a regular file's content is also length-committed — as a suffix (the
    /// actual byte count read and hashed), not a prefix. This is an intentional encoding-style asymmetry, noted for
    /// completeness, not a name-vs-content parity requirement: each record is anchored at its start by a fixed tag and
    /// length-prefixed name, but whether the trailing content-length placement could ever be exploited to construct a
    /// collision has not been formally analyzed or tested. A directory revisited through a symlink (see the crate-level
    /// symlink docs) is committed as an empty framed directory — its name plus an immediate close, no children — so its
    /// structural presence is preserved even though its contents are not re-walked.
    FileName,
}

/// Selects what directory traversal does with an entry that is neither a regular file nor a directory — a socket, FIFO,
/// device node, a dangling or otherwise-unresolvable symlink, or a symlink resolving to one of these.
///
/// The default, [`Error`](IrregularFile::Error), aborts the whole computation, matching what happens when such a path
/// is hashed directly (see [`Error::NotARegularFile`](crate::Error::NotARegularFile)). Choose
/// [`Skip`](IrregularFile::Skip) to keep hashing the rest of the tree instead.
///
/// This policy also governs an irregular path passed directly at the top level (e.g. to
/// [`Chksumer::update_from`](crate::Chksumer::update_from)), not only entries nested inside a traversed directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum IrregularFile {
    /// Abort with [`Error::NotARegularFile`](crate::Error::NotARegularFile) naming the offending entry. This is the
    /// default, and matches hashing such a path directly.
    #[default]
    Error,
    /// Silently skip the entry and keep hashing the rest of the directory, so a single irregular entry cannot abort an
    /// otherwise-hashable tree.
    ///
    /// For a symlink, only a resolution failure shaped like [`io::ErrorKind::NotFound`](std::io::ErrorKind::NotFound)
    /// (e.g. a dangling target) counts as unresolvable and is skipped this way; any other resolution error (such as
    /// `ENOTDIR` from a bad path component, or `EACCES` from a permission denial) is a genuine I/O failure and still
    /// surfaces as [`Error::Io`](crate::Error::Io), not skipped.
    Skip,
}

/// Builder-configured directory-traversal policy shared by [`Chksumer`](crate::Chksumer) and
/// [`AsyncChksumer`](crate::AsyncChksumer): the 7 fields a [`ChksumerBuilder`](crate::ChksumerBuilder)/
/// [`AsyncChksumerBuilder`](crate::AsyncChksumerBuilder) setter assigns into, invariant-free like a config record.
/// Frozen once `build()` moves it into the context, whose `policy()` accessor exposes it read-only — "frozen after
/// build()" becomes compiler-enforced rather than a documented convention.
#[derive(Debug)]
pub(crate) struct Policy {
    pub(crate) name_mode: NameMode,
    pub(crate) irregular_file: IrregularFile,
    pub(crate) on_diagnostic: Option<DiagnosticHook>,
    pub(crate) max_directory_depth: NonZeroUsize,
    pub(crate) max_directory_entries: NonZeroUsize,
    pub(crate) follow_symlink_revisits: bool,
    pub(crate) dir_entries_capacity_hint: usize,
}

impl Default for Policy {
    /// Absorbs the builder defaults that used to be duplicated between `ChksumerBuilder::new` and
    /// `AsyncChksumerBuilder::new`.
    fn default() -> Self {
        Self {
            name_mode: NameMode::Off,
            irregular_file: IrregularFile::Error,
            on_diagnostic: None,
            max_directory_depth: DEFAULT_MAX_DIRECTORY_DEPTH,
            max_directory_entries: DEFAULT_MAX_DIRECTORY_ENTRIES,
            follow_symlink_revisits: false,
            dir_entries_capacity_hint: DEFAULT_DIR_ENTRIES_CAPACITY_HINT,
        }
    }
}

impl Policy {
    /// Applies this policy to a directory entry that is not a regular file or directory: skip it (`Ok(())`) per
    /// [`IrregularFile::Skip`] (notifying the diagnostic hook, if any) or abort with
    /// [`Error::NotARegularFile`](crate::Error::NotARegularFile) per [`IrregularFile::Error`]. See the free
    /// [`skip_or_err`] this delegates to for the allocation-avoidance details.
    pub(crate) fn skip_or_err(&self, kind: SkipKind, path: impl FnOnce() -> PathBuf) -> Result<()> {
        skip_or_err(self.irregular_file, self.on_diagnostic.as_ref(), kind, path)
    }

    /// Invokes the registered diagnostic hook, if any, with a lazily-built [`Diagnostic`]; a no-op if no hook was
    /// registered.
    pub(crate) fn notify(&self, diagnostic: impl FnOnce() -> Diagnostic) {
        if let Some(hook) = self.on_diagnostic.as_ref() {
            hook.notify(&diagnostic());
        }
    }
}

/// Which [`Diagnostic`] a skipped entry is reported as, distinguishing an irregular target from an unresolvable
/// symlink without requiring the caller to build the [`Diagnostic`] itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SkipKind {
    /// The target resolves but is neither a regular file nor a directory (socket, FIFO, device node).
    Irregular,
    /// The target could not be resolved or classified (e.g. a dangling symlink).
    UnresolvableSymlink,
}

/// Applies the configured [`IrregularFile`] policy to a directory entry that is not a regular file or directory: skip
/// it (`Ok(())`) or abort with [`Error::NotARegularFile`](crate::Error::NotARegularFile). The path is only materialized
/// when the policy errors or a diagnostic hook is registered — with neither, the skip path stays allocation-free.
#[inline]
pub(crate) fn skip_or_err(
    policy: IrregularFile,
    on_diagnostic: Option<&DiagnosticHook>,
    kind: SkipKind,
    path: impl FnOnce() -> PathBuf,
) -> Result<()> {
    match policy {
        IrregularFile::Skip => {
            if let Some(hook) = on_diagnostic {
                let diagnostic = match kind {
                    SkipKind::Irregular => Diagnostic::SkippedIrregular { path: path() },
                    SkipKind::UnresolvableSymlink => Diagnostic::SkippedUnresolvableSymlink { path: path() },
                };
                hook.notify(&diagnostic);
            }
            Ok(())
        },
        IrregularFile::Error => Err(not_regular_file_err(path())),
    }
}
