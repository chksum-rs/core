//! `macro_rules!` bodies shared verbatim between `crate::context::blocking` and `crate::context::tokio`, so the two
//! context/builder pairs are guaranteed to expose byte-identical signatures and docs instead of two hand-maintained
//! copies drifting apart. Not a module in the public API surface; nothing here is `pub`.

/// Generates the seven [`Policy`](crate::policy::Policy)-backed builder setters. Invoked once inside each of
/// `ChksumerBuilder`/`AsyncChksumerBuilder`'s inherent `impl` blocks, both of which have a private `policy: Policy`
/// field to assign into.
macro_rules! policy_setters {
    () => {
        /// Selects how directory entry names and structure are committed to the digest. See
        /// [`NameMode`](crate::policy::NameMode).
        #[must_use = "this method consumes and returns the builder; assign the result or it is dropped"]
        pub fn name_mode(mut self, name_mode: crate::policy::NameMode) -> Self {
            self.policy.name_mode = name_mode;
            self
        }

        /// Selects what traversal does with an entry that is not a regular file or directory. See
        /// [`IrregularFile`](crate::policy::IrregularFile).
        #[must_use = "this method consumes and returns the builder; assign the result or it is dropped"]
        pub fn irregular_file(mut self, irregular_file: crate::policy::IrregularFile) -> Self {
            self.policy.irregular_file = irregular_file;
            self
        }

        /// Overrides the maximum directory-recursion depth. Traversal aborts with
        /// [`Error::TraversalTooDeep`](crate::Error::TraversalTooDeep) once nesting would exceed it. Defaults to
        /// [`DEFAULT_MAX_DIRECTORY_DEPTH`](crate::DEFAULT_MAX_DIRECTORY_DEPTH) (64), sized to stay safely below a
        /// native stack overflow for a 2 MiB thread stack (the default
        /// `std::thread::spawn`/`tokio::task::spawn_blocking` worker stack size) on EITHER path: the synchronous path
        /// recurses directly, and the async path recurses through a chain of nested `poll` calls on heap-boxed
        /// futures, which avoids storing each level's state inline but not the native-stack cost of polling. Raising
        /// this past a safe bound for the stack size actually in use is a caller-opted-in risk: this crate cannot
        /// inspect the calling thread's stack size, so a caller raising the limit for deeper legitimate trees should
        /// size or reserve its own thread stack accordingly on both paths.
        #[must_use = "this method consumes and returns the builder; assign the result or it is dropped"]
        pub fn max_directory_depth(mut self, limit: std::num::NonZeroUsize) -> Self {
            self.policy.max_directory_depth = limit;
            self
        }

        /// Overrides the maximum number of entries buffered from a single directory. Traversal aborts with
        /// [`Error::DirectoryTooLarge`](crate::Error::DirectoryTooLarge) once a directory would exceed it. Defaults
        /// to [`DEFAULT_MAX_DIRECTORY_ENTRIES`](crate::DEFAULT_MAX_DIRECTORY_ENTRIES) (10,000,000).
        #[must_use = "this method consumes and returns the builder; assign the result or it is dropped"]
        pub fn max_directory_entries(mut self, limit: std::num::NonZeroUsize) -> Self {
            self.policy.max_directory_entries = limit;
            self
        }

        /// Selects whether a directory reached again through a symlink during one traversal is re-walked. The
        /// default (`false`) skips it: directories are recorded by filesystem identity so symlink cycles and
        /// repeated-target fan-out cannot drive unbounded traversal. Passing `true` disables that check entirely,
        /// restoring full re-traversal and the exact pre-dedup digest for trees with duplicate symlink targets.
        ///
        /// On a platform without a stable directory-identity source (currently non-Unix, including Windows; see the
        /// crate-level [Symlinks](crate#symlinks) section), directory identity is never available, so this setting
        /// is a no-op there: traversal already re-walks every symlinked directory regardless of this flag, with only
        /// the maximum-depth limit as a backstop.
        #[must_use = "this method consumes and returns the builder; assign the result or it is dropped"]
        pub fn follow_symlink_revisits(mut self, follow: bool) -> Self {
            self.policy.follow_symlink_revisits = follow;
            self
        }

        /// Overrides the initial capacity of the per-directory entry buffer. `ReadDir` yields no entry-count hint, so
        /// this modest fixed size spares the first few reallocations on the common small-directory case. Defaults to
        /// 32.
        #[must_use = "this method consumes and returns the builder; assign the result or it is dropped"]
        pub fn dir_entries_capacity_hint(mut self, hint: usize) -> Self {
            self.policy.dir_entries_capacity_hint = hint;
            self
        }

        /// Registers a callback invoked for [`Diagnostic`] events the crate would otherwise handle silently: an
        /// entry skipped per [`IrregularFile::Skip`](crate::policy::IrregularFile::Skip), a directory skipped
        /// because a symlink revisited an
        /// already-visited target (see [`Diagnostic::SkippedRevisitedDirectory`]), or a read transparently retried
        /// after `io::ErrorKind::Interrupted`. Purely observational: never affects the digest or any `Result`, and
        /// costs nothing unless registered.
        #[must_use = "this method consumes and returns the builder; assign the result or it is dropped"]
        pub fn on_diagnostic(mut self, hook: impl Fn(&crate::diagnostic::Diagnostic) + Send + Sync + 'static) -> Self {
            self.policy.on_diagnostic = Some(crate::diagnostic::DiagnosticHook::new(hook));
            self
        }
    };
}

/// Generates the common methods shared by `Chksumer`/`AsyncChksumer`: [`update`](Chksumer::update),
/// [`capacity`](Chksumer::capacity), [`digest`](Chksumer::digest), [`reset`](Chksumer::reset), and
/// [`into_inner`](Chksumer::into_inner). Invoked once inside each context's inherent `impl<H> ... where H: Hash`
/// block, both of which have `hash: H`, `buffer: ReadBuffer`, and `descent: Descent` fields.
macro_rules! common_methods {
    () => {
        /// Feeds bytes directly to the hash (infallible, no I/O).
        #[inline]
        pub fn update(&mut self, data: impl crate::hashable::Hashable) -> &mut Self {
            data.hash_into(&mut self.hash);
            self
        }

        /// Returns the buffer capacity.
        #[inline]
        #[must_use]
        pub fn capacity(&self) -> std::num::NonZeroUsize {
            self.buffer.capacity()
        }

        /// Finalizes and returns the hash digest.
        #[inline]
        #[must_use]
        pub fn digest(&self) -> H::Digest {
            self.hash.digest()
        }

        /// Resets the hash to its initial state and clears traversal bookkeeping (recursion depth and the
        /// visited-directory set). The buffer is not cleared (it is pure scratch).
        #[inline]
        pub fn reset(&mut self) -> &mut Self {
            self.hash.reset();
            self.descent.reset();
            self
        }

        /// Consumes the context and returns the underlying hash, discarding the buffer.
        #[inline]
        #[must_use]
        pub fn into_inner(self) -> H {
            self.hash
        }
    };
}
