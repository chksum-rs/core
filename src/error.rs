use std::{io, result};

/// The error type for checksum-based operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The input is an interactive terminal.
    #[error("cannot process terminal input")]
    IsTerminal,
    /// The I/O error occured.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// A specialized [`Result`](std::result::Result) type for checksum-based operations.
///
/// This typedef is generally used to avoid writing out [Error] directly and is otherwise a direct mapping to [Result].
pub type Result<T> = result::Result<T, Error>;
