use std::path::PathBuf;
use std::{io, result};

/// The error type for checksum-based operations.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The input is an interactive terminal.
    #[error("cannot process terminal input")]
    IsTerminal,
    /// The path is not a regular file or directory.
    #[error("path is not a regular file or directory: {path}")]
    #[non_exhaustive]
    NotARegularFile {
        /// Path of the entry that is not a regular file or directory.
        path: PathBuf,
    },
    /// The directory tree is nested more deeply than the configured maximum traversal depth.
    #[error("directory nesting exceeds the maximum depth of {limit}")]
    #[non_exhaustive]
    TraversalTooDeep {
        /// The maximum nesting depth that was exceeded, configurable via
        /// [`ChksumerBuilder::max_directory_depth`](crate::ChksumerBuilder::max_directory_depth).
        limit: usize,
    },
    /// A single directory holds more entries than the configured maximum the traversal will buffer.
    #[error("directory entry count exceeds the maximum of {limit}")]
    #[non_exhaustive]
    DirectoryTooLarge {
        /// The maximum entry count that was exceeded, configurable via
        /// [`ChksumerBuilder::max_directory_entries`](crate::ChksumerBuilder::max_directory_entries).
        limit: usize,
    },
    /// An I/O error occurred.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// A specialized [`Result`](std::result::Result) type for checksum-based operations.
///
/// This typedef is generally used to avoid writing out [Error] directly and is otherwise a direct mapping to [Result].
pub type Result<T> = result::Result<T, Error>;

#[cold]
#[inline(never)]
pub(crate) fn terminal_err() -> Error {
    Error::IsTerminal
}

#[cold]
#[inline(never)]
pub(crate) fn not_regular_file_err(path: PathBuf) -> Error {
    Error::NotARegularFile { path }
}

#[cold]
#[inline(never)]
pub(crate) fn too_deep_err(limit: usize) -> Error {
    Error::TraversalTooDeep { limit }
}

#[cold]
#[inline(never)]
pub(crate) fn too_many_entries_err(limit: usize) -> Error {
    Error::DirectoryTooLarge { limit }
}
