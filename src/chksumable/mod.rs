//! [`Chksumable`] and [`AsyncChksumable`]: the source-side traits that fold a file, path, directory, or other input
//! into a [`Chksumer`](crate::Chksumer)/[`AsyncChksumer`](crate::AsyncChksumer) context. The trait definitions live in
//! `crate::chksumable::blocking` (and its async mirror behind the `async-runtime-tokio` feature,
//! `crate::chksumable::tokio`), alongside the dispatch logic for std types.

pub(crate) mod blocking;
#[cfg(feature = "async-runtime-tokio")]
pub(crate) mod tokio;

pub use blocking::Chksumable;
#[cfg(feature = "async-runtime-tokio")]
pub use tokio::AsyncChksumable;
