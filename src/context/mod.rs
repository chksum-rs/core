//! [`Chksumer`]/[`ChksumerBuilder`] and their async mirrors, [`AsyncChksumer`]/[`AsyncChksumerBuilder`]: the stateful
//! checksum context that owns the hash state, the reusable read buffer, and the
//! [`NameMode`](crate::policy::NameMode)/[`IrregularFile`](crate::policy::IrregularFile) traversal policy. The sync
//! context lives in `crate::context::blocking`; its async mirror lives behind the `async-runtime-tokio` feature in
//! `crate::context::tokio`.

#[macro_use]
mod shared;
pub(crate) mod blocking;
mod buffer;
mod descent;
#[cfg(feature = "async-runtime-tokio")]
pub(crate) mod tokio;

pub use blocking::{Chksumer, ChksumerBuilder};
#[cfg(feature = "async-runtime-tokio")]
pub use tokio::{AsyncChksumer, AsyncChksumerBuilder};
