# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added `Chksumer` and `AsyncChksumer` contexts with a configurable I/O buffer.
- Added the `NameMode` option (`FileName`) on the `Chksumer`/`AsyncChksumer` builders to commit directory entry names and structure; the default `Off` keeps the content-only digest. A directory entry's tag/name frame is written to the hash only after the entry is confirmed openable, so a failed open/read on that entry never leaves the hash in a partially-written state.
- Added the `IrregularFile` option on the `Chksumer`/`AsyncChksumer` builders to choose whether traversal aborts (`Error`, the default) or skips (`Skip`) an entry that is neither a regular file nor a directory.
- Added the `NotARegularFile` error variant for paths that are neither files nor directories.
- Added a `Diagnostic` callback (`on_diagnostic` on the `Chksumer`/`AsyncChksumer` builders) reporting entries skipped per `IrregularFile::Skip` and reads retried after `ErrorKind::Interrupted`, previously silent. Purely observational and dependency-free — wire in your own `log`/`tracing` call from the closure.
- Added `max_directory_depth`, `max_directory_entries`, `follow_symlink_revisits`, and `dir_entries_capacity_hint` builder options on `Chksumer`/`AsyncChksumer` (defaults 64, 10,000,000, dedup-on, and 32 respectively); `max_directory_depth`/`max_directory_entries` take a `NonZeroUsize`, consistent with `capacity`.
- Added the `TraversalTooDeep` and `DirectoryTooLarge` error variants.
- Added the `Diagnostic::SkippedRevisitedDirectory` variant.
- Added `AsyncChksumer::update`, an infallible synchronous method mirroring `Chksumer::update` for feeding in-memory bytes-like data without an `.await`.
- Exported `DEFAULT_MAX_DIRECTORY_DEPTH` and `DEFAULT_MAX_DIRECTORY_ENTRIES` as public consts, so the documented `max_directory_depth`/`max_directory_entries` defaults are programmatically readable.
- Added `DEFAULT_BUFFER_CAPACITY` as a public const documenting the default I/O buffer capacity (64 KiB on most platforms, 512 B on `espidf`).
- Added an `io::Write` impl for `Chksumer` so data can be streamed in via `io::copy` or `write!`, feeding the hash directly; `flush` is a no-op and writes never fail.
- Added crate-root `builder`/`async_builder` and `chksum_with`/`async_chksum_with` helpers: the former delegate to `Chksumer::builder`/`AsyncChksumer::builder`, and the latter run a one-shot checksum through a caller-configured builder, for callers who need non-default policies without hand-building a context.

### Fixed

- Reads interrupted by a signal (`ErrorKind::Interrupted`) are now retried instead of aborting the computation.
- Restored dispatch through `Hashable::hash_into` in the blanket `Chksumable`/`AsyncChksumable` impls, so a type overriding `hash_into` is honored by `chksum`/`async_chksum` instead of being bypassed.
- `Chksumer`/`AsyncChksumer::update_from` now resets the recursion depth alongside the visited-directory set on every fresh top-level call, so a `Chksumer`/`AsyncChksumer` reused after an earlier call returned early (error, or a cancelled `AsyncChksumer::update_from` future) always starts with a full depth budget instead of a stranded one.

### Changed

- Upgraded Rust edition to 2024 and MSRV to 1.95.0.
- Renamed `Hashable::hash_with` to `hash_into`.
- Renamed `Chksumable::chksum_with` to `chksum_into`; it now takes `&mut Chksumer<H>`.
- Renamed `AsyncChksumable::chksum_with` to `chksum_into`; it now takes `&mut AsyncChksumer<H>`.
- Increased the default I/O buffer capacity from 8 KiB to 64 KiB; override it via the builder's `capacity`.
- Deferred `Chksumer`/`AsyncChksumer`'s read buffer allocation to first `update_from_reader` use instead of upfront on construction, so hashing purely in-memory data (`chksum`/`update`) no longer pays for a buffer it never reads into; `capacity()` is unaffected and still reports the configured capacity either way.
- Upgraded `thiserror` to 2.0.
- Marked `Error` and its struct variants, and `Diagnostic`'s struct variants, `#[non_exhaustive]` to allow adding variants/fields without a breaking change.
- Relaxed the `chksum-hash-core` requirement from `0.0.0` to `0.0` to accept future compatible `0.0.x` releases.

## [0.1.0] - 2024-05-03

### Added

- Added async support for Tokio runtime.
- Added `doc_auto_cfg` feature.

### Fixed

- Added missing method comments to improve documentation clarity.

### Changed

- Refactored code to use macros for trait implementations, improving maintainability and reducing duplication.
- Updated year range in `LICENSE`.

## [0.0.0] - 2023-12-21

### Added

- Initial release.

[Unreleased]: https://github.com/chksum-rs/core/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/chksum-rs/core/compare/v0.0.0...v0.1.0
[0.0.0]: https://github.com/chksum-rs/core/releases/tag/v0.0.0
