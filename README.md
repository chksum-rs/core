# chksum-core

[![crates.io][cratesio-badge]][cratesio]
[![Build][build-badge]][build]
[![docs.rs][docsrs-badge]][docsrs]
[![MSRV][msrv-badge]][msrv]
[![deps.rs][depsrs-badge]][depsrs]
[![unsafe forbidden][unsafe-forbidden-badge]][unsafe-forbidden]
[![LICENSE][license-badge]][license]

[cratesio-badge]: https://img.shields.io/crates/v/chksum-core?style=flat-square&logo=rust
[cratesio]: https://crates.io/crates/chksum-core
[build-badge]: https://img.shields.io/github/actions/workflow/status/chksum-rs/core/rust.yml?branch=master&style=flat-square&logo=github
[build]: https://github.com/chksum-rs/core/actions/workflows/rust.yml
[docsrs-badge]: https://img.shields.io/docsrs/chksum-core?style=flat-square&logo=docsdotrs
[docsrs]: https://docs.rs/chksum-core/
[msrv-badge]: https://img.shields.io/badge/MSRV-1.95.0-informational?style=flat-square
[msrv]: https://github.com/chksum-rs/core/blob/master/Cargo.toml
[depsrs-badge]: https://deps.rs/crate/chksum-core/0.1.0/status.svg?style=flat-square
[depsrs]: https://deps.rs/crate/chksum-core/0.1.0
[unsafe-forbidden-badge]: https://img.shields.io/badge/unsafe-forbidden-success.svg?style=flat-square
[unsafe-forbidden]: https://github.com/rust-secure-code/safety-dance
[license-badge]: https://img.shields.io/github/license/chksum-rs/core?style=flat-square
[license]: https://github.com/chksum-rs/core/blob/master/LICENSE

Core traits and functions for straightforward hash computation of bytes, files, directories and more.

## Setup

To use this crate, add the following entry to your `Cargo.toml` file in the `dependencies` section:

```toml
[dependencies]
chksum-core = "0.1.0"
```

Alternatively, you can use the [`cargo add`](https://doc.rust-lang.org/cargo/commands/cargo-add.html) subcommand:

```sh
cargo add chksum-core
```

## Usage

Hashing a directory has two modes: hash file contents only, or also commit entry names and directory structure.
Both modes, ready to paste (substitute `H` with a concrete hash type from one of the family crates listed below):

```rust
use std::path::Path;
use chksum_core::{chksum, Chksumer, Hash, NameMode, Result};

// Default (`NameMode::Off`): raw file contents only, concatenated in name-sorted order.
fn contents_digest<H: Hash>(dir: &Path) -> Result<H::Digest> {
    chksum::<H>(dir)
}

// `NameMode::FileName`: commit entry names and directory structure (git-tree style).
fn tree_digest<H: Hash>(dir: &Path) -> Result<H::Digest> {
    let mut chksumer = Chksumer::<H>::builder().name_mode(NameMode::FileName).build();
    chksumer.update_from(dir)?;
    Ok(chksumer.digest())
}
```

Directory-digest semantics, framing, and collision classes: see [Directory digests](docs/DIRECTORY-DIGESTS.md).

## Features

### Asynchronous Runtime

* `async-runtime-tokio`: Enables async interface for Tokio runtime.

### Hardening

* `nonblocking-open`: On Unix, opens files with `O_NONBLOCK` so a race-swapped FIFO or slow device cannot hang
  traversal; off by default. See [Hardening](docs/HARDENING.md).

By default, none of these features is enabled.

## Supported Platforms

Only Linux, macOS, and Windows are tested. Other targets may work but are unverified.

## Behavior

* **Symlinks are followed**: linked files are hashed and linked directories are traversed.
  See [Symlinks](docs/SYMLINKS.md).
* **Cycles and fan-out are bounded, not eliminated**: on Unix, directories entered through a symlink are
  deduplicated by filesystem identity and a revisit is reported as `Diagnostic::SkippedRevisitedDirectory`;
  elsewhere the depth limit is the backstop; opt out with `follow_symlink_revisits(true)`.
  See [Symlinks](docs/SYMLINKS.md).
* **Names and structure are opt-in**: the default `NameMode::Off` hashes file contents only (distinct trees can
  collide); `NameMode::FileName` commits bare names and directory nesting, git-tree style.
  See [Directory digests](docs/DIRECTORY-DIGESTS.md).
* **Irregular files abort by default**: an entry that is neither a regular file nor a directory aborts traversal
  with `Error::NotARegularFile`; `IrregularFile::Skip` skips it and reports it through the `Diagnostic` callback.
  See [Hardening](docs/HARDENING.md).
* **Traversal limits exist**: `Error::TraversalTooDeep` past `max_directory_depth` (default 64) and
  `Error::DirectoryTooLarge` past `max_directory_entries` (default 10,000,000). See [Hardening](docs/HARDENING.md).

## Documentation

* [Symlinks](docs/SYMLINKS.md) — following, cycle/fan-out bounding, platform coverage, and `ELOOP` interaction.
* [Directory digests](docs/DIRECTORY-DIGESTS.md) — digest semantics, `NameMode::FileName` framing, and
  reproducibility.
* [Hardening](docs/HARDENING.md) — `nonblocking-open`, race windows, irregular-file policy, and traversal limits.
* [Gotchas](docs/GOTCHAS.md) — call shapes that compile and run but silently do the wrong thing.

## Example Crates

For implementation-specific examples, refer to the source code of the following crates:

* [`chksum-md5`](https://github.com/chksum-rs/md5)
* [`chksum-sha1`](https://github.com/chksum-rs/sha1)
* [`chksum-sha2`](https://github.com/chksum-rs/sha2)
    * [`chksum-sha2-224`](https://github.com/chksum-rs/sha2-224)
    * [`chksum-sha2-256`](https://github.com/chksum-rs/sha2-256)
    * [`chksum-sha2-384`](https://github.com/chksum-rs/sha2-384)
    * [`chksum-sha2-512`](https://github.com/chksum-rs/sha2-512)

## License

This crate is licensed under the MIT License.
