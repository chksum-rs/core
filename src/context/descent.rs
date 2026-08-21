//! [`Descent`]/[`DepthTicket`]: directory-recursion depth tracking and the symlinked-directory visited set, shared
//! by [`Chksumer`](crate::Chksumer) and [`AsyncChksumer`](crate::AsyncChksumer).

use std::collections::HashSet;
use std::fs::Metadata;
use std::num::NonZeroUsize;

use crate::error::{Result, too_deep_err};
use crate::visited::{self, DirKey};

/// Proof that a matching [`Descent::enter`] admitted one more level of directory recursion; consumed by
/// [`Descent::leave`] to return it. The private field is load-bearing: without it, a bare unit struct would let code
/// outside this module fabricate a ticket that was never checked against the depth limit.
pub(crate) struct DepthTicket(());

/// Directory-recursion bookkeeping for one traversal: current depth (S1) and the filesystem identities of
/// directories already entered through a symlink this traversal (S3).
#[derive(Debug, Default)]
pub(crate) struct Descent {
    depth: usize,
    visited: HashSet<DirKey>,
}

impl Descent {
    /// Admits one more level of directory recursion (S1), erroring instead once `depth` would reach `max`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TraversalTooDeep`](crate::Error::TraversalTooDeep) if nesting would exceed `max`.
    pub(crate) fn enter(&mut self, max: NonZeroUsize) -> Result<DepthTicket> {
        if self.depth >= max.get() {
            return Err(too_deep_err(max.get()));
        }
        self.depth += 1;
        Ok(DepthTicket(()))
    }

    /// Returns the level of directory recursion admitted by the matching [`Descent::enter`]. An error path that
    /// drops its ticket instead of calling this deliberately leaves `depth` stranded until [`Descent::reset`] — the
    /// reuse contract requires a `reset()` after an error.
    pub(crate) fn leave(&mut self, _ticket: DepthTicket) {
        self.depth -= 1;
    }

    /// Clears recursion depth and the visited set, for a fresh top-level traversal.
    pub(crate) fn reset(&mut self) {
        self.depth = 0;
        self.visited.clear();
    }

    /// Records a symlinked directory's identity for cycle/fan-out protection (S3). Returns `true` if the caller
    /// should descend into it — the first encounter this traversal, an identity unknowable on this platform, or the
    /// `follow_symlink_revisits` opt-out is set — and `false` if it was already visited and must be skipped.
    /// Delegates to [`visited::visit_symlinked_dir`].
    pub(crate) fn visit_symlinked_dir(&mut self, follow_symlink_revisits: bool, metadata: &Metadata) -> bool {
        visited::visit_symlinked_dir(&mut self.visited, follow_symlink_revisits, metadata)
    }
}
