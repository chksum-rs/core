//! Base hashing traits: [`Digest`], [`Hash`], and [`Hashable`] for bytes-like input.

use std::fmt::{Display, LowerHex, UpperHex};

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
        self.hash_into(&mut hash);
        hash.digest()
    }

    /// Updates the given hash instance with the bytes from this object.
    fn hash_into<H>(&self, hash: &mut H)
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

    ([$t:ty; LENGTH]) => {
        impl<const LENGTH: usize> Hashable for [$t; LENGTH] {}
    };

    ($t:ty, $($rest:tt)+) => {
        impl_hashable!($t);
        impl_hashable!($($rest)*);
    };

    ($t:ty) => {
        impl Hashable for $t {}
    };
}

impl_hashable!(&[u8], [u8; LENGTH], Vec<u8>, &str, String);

impl<T> Hashable for &T where T: Hashable {}

impl<T> Hashable for &mut T where T: Hashable {}
