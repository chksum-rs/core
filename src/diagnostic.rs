//! Additive observability channel: the [`Diagnostic`] event type and its caller-registered callback carrier.

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

/// Non-error event the crate would otherwise handle silently, offered to a caller-registered diagnostic callback (see
/// `on_diagnostic` on [`Chksumer`](crate::Chksumer)'s and [`AsyncChksumer`](crate::AsyncChksumer)'s builders). Never
/// affects the digest or any `Result` — purely
/// additive observability. Wire in your own logger, e.g. `.on_diagnostic(|d| log::warn!("{d:?}"))` or
/// `.on_diagnostic(|d| tracing::debug!(?d))`.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum Diagnostic {
    /// A directory entry that is neither a regular file nor a directory (socket, FIFO, device node, or a symlink
    /// resolving to one) was skipped per [`IrregularFile::Skip`](crate::IrregularFile::Skip).
    #[non_exhaustive]
    SkippedIrregular {
        /// Path of the skipped entry.
        path: PathBuf,
    },
    /// A symlink's target could not be resolved or classified (e.g. dangling) and the symlink was skipped per
    /// [`IrregularFile::Skip`](crate::IrregularFile::Skip).
    #[non_exhaustive]
    SkippedUnresolvableSymlink {
        /// Path of the skipped symlink.
        path: PathBuf,
    },
    /// A read was interrupted by a signal (`io::ErrorKind::Interrupted`) and is being retried transparently; not an
    /// error.
    ReadInterrupted,
    /// A directory reached again through a symlink during one traversal was skipped, bounding symlink cycles and
    /// repeated-directory-target fan-out (this dedup does not cover symlinks to regular files; see the crate-level
    /// Symlinks docs). Suppressed (never emitted) when `follow_symlink_revisits(true)` is set, since nothing is then
    /// skipped.
    #[non_exhaustive]
    SkippedRevisitedDirectory {
        /// Path of the skipped symlink whose target had already been visited this traversal.
        path: PathBuf,
    },
}

/// Opaque handle for a caller-supplied [`Diagnostic`] callback. Wrapped (rather than a bare `Arc<dyn Fn>` field) so
/// [`Chksumer`](crate::Chksumer)/[`ChksumerBuilder`](crate::ChksumerBuilder) keep their `#[derive(Debug)]` — `dyn Fn`
/// itself isn't `Debug`.
pub(crate) struct DiagnosticHook(Arc<dyn Fn(&Diagnostic) + Send + Sync>);

impl DiagnosticHook {
    pub(crate) fn new(hook: impl Fn(&Diagnostic) + Send + Sync + 'static) -> Self {
        Self(Arc::new(hook))
    }

    pub(crate) fn notify(&self, diagnostic: &Diagnostic) {
        (self.0)(diagnostic);
    }
}

impl fmt::Debug for DiagnosticHook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("DiagnosticHook").finish()
    }
}
