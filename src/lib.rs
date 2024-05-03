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
//! # Features
//!
//! ## Asynchronous Runtime
//!
//! * `async-runtime-tokio`: Enables async interface for Tokio runtime.
//!
//! By default, neither of these features is enabled.
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

#![forbid(unsafe_code)]

mod error;
#[cfg(feature = "async-runtime-tokio")]
mod tokio;

use std::fmt::{Display, LowerHex, UpperHex};
use std::fs::{read_dir, DirEntry, File, ReadDir};
use std::io::{self, BufRead, BufReader, IsTerminal, Stdin, StdinLock};
use std::path::{Path, PathBuf};

#[cfg(feature = "async-runtime-tokio")]
use async_trait::async_trait;
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

/// Computes the hash of the given input.
#[cfg(feature = "async-runtime-tokio")]
pub async fn async_chksum<T>(mut data: impl AsyncChksumable) -> Result<T::Digest>
where
    T: Hash + Send,
{
    data.chksum::<T>().await
}

/// A trait for hash digests.
pub trait Digest: Display {
    /// Returns a byte slice of the digest's contents.
    #[must_use]
    fn as_bytes(&self) -> &[u8]
    where
        Self: AsRef<[u8]>,
    {
        self.as_ref()
    }

    /// Returns a string in the lowercase hexadecimal representation.
    #[must_use]
    fn to_hex_lowercase(&self) -> String
    where
        Self: LowerHex,
    {
        format!("{self:x}")
    }

    /// Returns a string in the uppercase hexadecimal representation.
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
    /// Computes the hash digest.
    fn hash<H>(&self) -> H::Digest
    where
        H: Hash,
    {
        let mut hash = H::default();
        self.hash_with(&mut hash);
        hash.digest()
    }

    /// Updates the given hash instance with the bytes from this object.
    fn hash_with<H>(&self, hash: &mut H)
    where
        H: Hash,
    {
        hash.update(self);
    }
}

macro_rules! impl_hashable {
    ([$t:ty; LENGTH], $($rest:tt)+) => {
        impl_hashable!([$t; LENGTH]);
        impl_hashable!($($rest)*);
    };

    ($t:ty, $($rest:tt)+) => {
        impl_hashable!($t);
        impl_hashable!($($rest)*);
    };

    ([$t:ty; LENGTH]) => {
        impl<const LENGTH: usize> Hashable for [$t; LENGTH] {}
    };

    ($t:ty) => {
        impl Hashable for $t {}
    };
}

impl_hashable!(&[u8], [u8; LENGTH], Vec<u8>, &str, String);

impl<T> Hashable for &T where T: Hashable {}

impl<T> Hashable for &mut T where T: Hashable {}

/// A trait for complex objects which must be processed chunk by chunk.
pub trait Chksumable {
    /// Calculates the checksum of the object.
    fn chksum<H>(&mut self) -> Result<H::Digest>
    where
        H: Hash,
    {
        let mut hash = H::default();
        self.chksum_with(&mut hash)?;
        Ok(hash.digest())
    }

    /// Updates the given hash instance with the data from the object.
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

macro_rules! impl_chksumable {
    ($($t:ty),+ => $i:tt) => {
        $(
            impl Chksumable for $t $i
        )*
    };
}

impl_chksumable!(Path, &Path, &mut Path => {
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
});

impl_chksumable!(PathBuf, &PathBuf, &mut PathBuf => {
    fn chksum_with<H>(&mut self, hash: &mut H) -> Result<()>
    where
        H: Hash,
    {
        Chksumable::chksum_with(&mut self.as_path(), hash)
    }
});

impl_chksumable!(File, &File, &mut File => {
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
});

impl_chksumable!(DirEntry, &DirEntry, &mut DirEntry => {
    fn chksum_with<H>(&mut self, hash: &mut H) -> Result<()>
    where
        H: Hash,
    {
        Chksumable::chksum_with(&mut self.path(), hash)
    }
});

impl_chksumable!(ReadDir, &mut ReadDir => {
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
});

impl_chksumable!(Stdin, &Stdin, &mut Stdin => {
    fn chksum_with<H>(&mut self, hash: &mut H) -> Result<()>
    where
        H: Hash,
    {
        self.lock().chksum_with(hash)
    }
});

impl_chksumable!(StdinLock<'_>, &mut StdinLock<'_> => {
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
});

/// A trait for complex objects which must be processed chunk by chunk.
#[cfg(feature = "async-runtime-tokio")]
#[async_trait]
pub trait AsyncChksumable: Send {
    /// Calculates the checksum of the object.
    async fn chksum<H>(&mut self) -> Result<H::Digest>
    where
        H: Hash + Send,
    {
        let mut hash = H::default();
        self.chksum_with(&mut hash).await?;
        Ok(hash.digest())
    }

    /// Updates the given hash instance with the data from the object.
    async fn chksum_with<H>(&mut self, hash: &mut H) -> Result<()>
    where
        H: Hash + Send;
}

#[cfg(feature = "async-runtime-tokio")]
#[async_trait]
impl<T> AsyncChksumable for T
where
    T: Hashable + Send,
{
    async fn chksum_with<H>(&mut self, hash: &mut H) -> Result<()>
    where
        H: Hash + Send,
    {
        self.hash_with(hash);
        Ok(())
    }
}
