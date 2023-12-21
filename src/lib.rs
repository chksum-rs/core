//! Core traits and functions for straightforward hash computation of bytes, files, directories and more.
//!
//! # Setup
//!
//! To use this crate, add the following entry to your `Cargo.toml` file in the `dependencies` section:
//!
//! ```toml
//! [dependencies]
//! chksum-core = "0.0.0"
//! ```
//!
//! Alternatively, you can use the [`cargo add`](https://doc.rust-lang.org/cargo/commands/cargo-add.html) subcommand:
//!
//! ```sh
//! cargo add chksum-core
//! ```     
//!
//! # Example Crates
//!
//! For implementation-specific examples, refer to the source code of the following crates:
//!
//! * [`chksum-md5`](https://docs.rs/chksum-md5/)
//! * [`chksum-sha1`](https://docs.rs/chksum-sha1/)
//! * [`chksum-sha2`](https://docs.rs/chksum-sha2/)
//!     * [`chksum-sha2-224`](https://docs.rs/chksum-sha2-224/)
//!     * [`chksum-sha2-256`](https://docs.rs/chksum-sha2-256/)
//!     * [`chksum-sha2-384`](https://docs.rs/chksum-sha2-384/)
//!     * [`chksum-sha2-512`](https://docs.rs/chksum-sha2-512/)
//!
//! # License
//!
//! This crate is licensed under the MIT License.

mod error;

use std::fmt::{Display, LowerHex, UpperHex};
use std::fs::{read_dir, DirEntry, File, ReadDir};
use std::io::{self, BufRead, BufReader, IsTerminal, Stdin, StdinLock};
use std::path::{Path, PathBuf};

#[doc(no_inline)]
pub use chksum_hash_core as hash;

pub use crate::error::{Error, Result};

/// Creates a default hash.
#[must_use]
pub fn default<H>() -> H
where
    H: Hash,
{
    Default::default()
}

/// Computes the hash of the given input.
pub fn hash<T>(data: impl Hashable) -> T::Digest
where
    T: Hash,
{
    data.hash::<T>()
}

/// Computes the hash of the given input.
pub fn chksum<T>(mut data: impl Chksumable) -> Result<T::Digest>
where
    T: Hash,
{
    data.chksum::<T>()
}

/// A trait for hash digests.
pub trait Digest: Display {
    #[must_use]
    fn as_bytes(&self) -> &[u8]
    where
        Self: AsRef<[u8]>,
    {
        self.as_ref()
    }

    #[must_use]
    fn to_hex_lowercase(&self) -> String
    where
        Self: LowerHex,
    {
        format!("{self:x}")
    }

    #[must_use]
    fn to_hex_uppercase(&self) -> String
    where
        Self: UpperHex,
    {
        format!("{self:X}")
    }
}

/// A trait for hash objects.
pub trait Hash: Default {
    /// The type representing the digest produced by finalizing the hash.
    type Digest: Digest;

    /// Calculates the hash digest of an input data.
    #[must_use]
    fn hash<T>(data: T) -> Self::Digest
    where
        T: AsRef<[u8]>,
    {
        let mut hash = Self::default();
        hash.update(data);
        hash.digest()
    }

    /// Updates the hash state with an input data.
    fn update<T>(&mut self, data: T)
    where
        T: AsRef<[u8]>;

    /// Resets the hash state to its initial state.
    fn reset(&mut self);

    /// Produces the hash digest.
    #[must_use]
    fn digest(&self) -> Self::Digest;
}

/// A trait for simple bytes-like objects.
pub trait Hashable: AsRef<[u8]> {
    fn hash<H>(&self) -> H::Digest
    where
        H: Hash,
    {
        let mut hash = H::default();
        self.hash_with(&mut hash);
        hash.digest()
    }

    fn hash_with<H>(&self, hash: &mut H)
    where
        H: Hash,
    {
        hash.update(self);
    }
}

impl Hashable for &[u8] {}

impl<const LENGTH: usize> Hashable for [u8; LENGTH] {}

impl Hashable for Vec<u8> {}

impl Hashable for &str {}

impl Hashable for String {}

impl<T> Hashable for &T where T: Hashable {}

impl<T> Hashable for &mut T where T: Hashable {}

/// A trait for complex objects which must be processed chunk by chunk.
pub trait Chksumable {
    fn chksum<H>(&mut self) -> Result<H::Digest>
    where
        H: Hash,
    {
        let mut hash = H::default();
        self.chksum_with(&mut hash)?;
        Ok(hash.digest())
    }

    fn chksum_with<H>(&mut self, hash: &mut H) -> Result<()>
    where
        H: Hash;
}

impl<T> Chksumable for T
where
    T: Hashable,
{
    fn chksum_with<H>(&mut self, hash: &mut H) -> Result<()>
    where
        H: Hash,
    {
        self.hash_with(hash);
        Ok(())
    }
}

impl Chksumable for Path {
    fn chksum_with<H>(&mut self, hash: &mut H) -> Result<()>
    where
        H: Hash,
    {
        let metadata = self.metadata()?;
        if metadata.is_dir() {
            read_dir(self)?.chksum_with(hash)
        } else {
            // everything treat as a file when it is not a directory
            File::open(self)?.chksum_with(hash)
        }
    }
}

impl Chksumable for &Path {
    fn chksum_with<H>(&mut self, hash: &mut H) -> Result<()>
    where
        H: Hash,
    {
        let metadata = self.metadata()?;
        if metadata.is_dir() {
            read_dir(self)?.chksum_with(hash)
        } else {
            // everything treat as a file when it is not a directory
            File::open(self)?.chksum_with(hash)
        }
    }
}

impl Chksumable for &mut Path {
    fn chksum_with<H>(&mut self, hash: &mut H) -> Result<()>
    where
        H: Hash,
    {
        let metadata = self.metadata()?;
        if metadata.is_dir() {
            read_dir(self)?.chksum_with(hash)
        } else {
            // everything treat as a file when it is not a directory
            File::open(self)?.chksum_with(hash)
        }
    }
}

impl Chksumable for PathBuf {
    fn chksum_with<H>(&mut self, hash: &mut H) -> Result<()>
    where
        H: Hash,
    {
        self.as_path().chksum_with(hash)
    }
}

impl Chksumable for &PathBuf {
    fn chksum_with<H>(&mut self, hash: &mut H) -> Result<()>
    where
        H: Hash,
    {
        self.as_path().chksum_with(hash)
    }
}

impl Chksumable for &mut PathBuf {
    fn chksum_with<H>(&mut self, hash: &mut H) -> Result<()>
    where
        H: Hash,
    {
        self.as_path().chksum_with(hash)
    }
}

impl Chksumable for File {
    fn chksum_with<H>(&mut self, hash: &mut H) -> Result<()>
    where
        H: Hash,
    {
        if self.is_terminal() {
            return Err(Error::IsTerminal);
        }

        let mut reader = BufReader::new(self);
        loop {
            let buffer = reader.fill_buf()?;
            let length = buffer.len();
            if length == 0 {
                break;
            }
            buffer.hash_with(hash);
            reader.consume(length);
        }
        Ok(())
    }
}

impl Chksumable for &File {
    fn chksum_with<H>(&mut self, hash: &mut H) -> Result<()>
    where
        H: Hash,
    {
        if self.is_terminal() {
            return Err(Error::IsTerminal);
        }

        let mut reader = BufReader::new(self);
        loop {
            let buffer = reader.fill_buf()?;
            let length = buffer.len();
            if length == 0 {
                break;
            }
            buffer.hash_with(hash);
            reader.consume(length);
        }
        Ok(())
    }
}

impl Chksumable for &mut File {
    fn chksum_with<H>(&mut self, hash: &mut H) -> Result<()>
    where
        H: Hash,
    {
        if self.is_terminal() {
            return Err(Error::IsTerminal);
        }

        let mut reader = BufReader::new(self);
        loop {
            let buffer = reader.fill_buf()?;
            let length = buffer.len();
            if length == 0 {
                break;
            }
            buffer.hash_with(hash);
            reader.consume(length);
        }
        Ok(())
    }
}

impl Chksumable for DirEntry {
    fn chksum_with<H>(&mut self, hash: &mut H) -> Result<()>
    where
        H: Hash,
    {
        self.path().chksum_with(hash)
    }
}

impl Chksumable for &DirEntry {
    fn chksum_with<H>(&mut self, hash: &mut H) -> Result<()>
    where
        H: Hash,
    {
        self.path().chksum_with(hash)
    }
}

impl Chksumable for &mut DirEntry {
    fn chksum_with<H>(&mut self, hash: &mut H) -> Result<()>
    where
        H: Hash,
    {
        self.path().chksum_with(hash)
    }
}

impl Chksumable for ReadDir {
    fn chksum_with<H>(&mut self, hash: &mut H) -> Result<()>
    where
        H: Hash,
    {
        let dir_entries: io::Result<Vec<DirEntry>> = self.collect();
        let mut dir_entries = dir_entries?;
        dir_entries.sort_by_key(DirEntry::path);
        dir_entries
            .into_iter()
            .try_for_each(|mut dir_entry| dir_entry.chksum_with(hash))?;
        Ok(())
    }
}

impl Chksumable for &mut ReadDir {
    fn chksum_with<H>(&mut self, hash: &mut H) -> Result<()>
    where
        H: Hash,
    {
        let dir_entries: io::Result<Vec<DirEntry>> = self.collect();
        let mut dir_entries = dir_entries?;
        dir_entries.sort_by_key(DirEntry::path);
        dir_entries
            .into_iter()
            .try_for_each(|mut dir_entry| dir_entry.chksum_with(hash))?;
        Ok(())
    }
}

impl Chksumable for Stdin {
    fn chksum_with<H>(&mut self, hash: &mut H) -> Result<()>
    where
        H: Hash,
    {
        self.lock().chksum_with(hash)
    }
}

impl Chksumable for &Stdin {
    fn chksum_with<H>(&mut self, hash: &mut H) -> Result<()>
    where
        H: Hash,
    {
        self.lock().chksum_with(hash)
    }
}

impl Chksumable for &mut Stdin {
    fn chksum_with<H>(&mut self, hash: &mut H) -> Result<()>
    where
        H: Hash,
    {
        self.lock().chksum_with(hash)
    }
}

impl Chksumable for StdinLock<'_> {
    fn chksum_with<H>(&mut self, hash: &mut H) -> Result<()>
    where
        H: Hash,
    {
        if self.is_terminal() {
            return Err(Error::IsTerminal);
        }

        loop {
            let buffer = self.fill_buf()?;
            let length = buffer.len();
            if length == 0 {
                break;
            }
            buffer.hash_with(hash);
            self.consume(length);
        }
        Ok(())
    }
}

impl Chksumable for &mut StdinLock<'_> {
    fn chksum_with<H>(&mut self, hash: &mut H) -> Result<()>
    where
        H: Hash,
    {
        if self.is_terminal() {
            return Err(Error::IsTerminal);
        }

        loop {
            let buffer = self.fill_buf()?;
            let length = buffer.len();
            if length == 0 {
                break;
            }
            buffer.hash_with(hash);
            self.consume(length);
        }
        Ok(())
    }
}
