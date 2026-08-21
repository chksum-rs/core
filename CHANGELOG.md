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
- Added the `nonblocking-open` Cargo feature (Unix `O_NONBLOCK` opens for directory entries and for a regular file/symlink-to-file passed directly as the top-level source; off by default).
- Added `AsyncChksumer::update`, an infallible synchronous method mirroring `Chksumer::update` for feeding in-memory bytes-like data without an `.await`.
- Exported `DEFAULT_MAX_DIRECTORY_DEPTH` and `DEFAULT_MAX_DIRECTORY_ENTRIES` as public consts, so the documented `max_directory_depth`/`max_directory_entries` defaults are programmatically readable.
- Added `DEFAULT_BUFFER_CAPACITY` as a public const documenting the default I/O buffer capacity (64 KiB on most platforms, 512 B on `espidf`).
- Added an `io::Write` impl for `Chksumer` so data can be streamed in via `io::copy` or `write!`, feeding the hash directly; `flush` is a no-op and writes never fail.
- Added crate-root `builder`/`async_builder` and `chksum_with`/`async_chksum_with` helpers: the former delegate to `Chksumer::builder`/`AsyncChksumer::builder`, and the latter run a one-shot checksum through a caller-configured builder, for callers who need non-default policies without hand-building a context.

### Fixed

- Added a terminal guard to the async `File` and `Stdin` sources so they return `IsTerminal` instead of blocking on a TTY, matching the synchronous path (works around [tokio-rs/tokio#6407](https://github.com/tokio-rs/tokio/issues/6407) via `AsFd`/`AsHandle`).
- Reads interrupted by a signal (`ErrorKind::Interrupted`) are now retried instead of aborting the computation.
- Fixed `IrregularFile::Skip` not covering a symlink whose target cannot be resolved (e.g. a dangling symlink), which previously still aborted traversal with a raw `Io` error instead of being skipped.
- Symlink cycles no longer cause unbounded traversal, and repeated-directory-target fan-out is now bounded (not eliminated): directories reached through a symlink are deduplicated by filesystem identity (opt out with `follow_symlink_revisits(true)`). A symlink pointing back at an ancestor (including the root), or a directory reachable both by its own plain path and through one or more symlinks, is bounded and terminates, at the documented cost of at most one extra traversal pass of that subtree per level of directory nesting before the revisit is caught.
- Traversal no longer risks stack overflow on deeply nested trees nor unbounded memory on a single huge directory (configurable `max_directory_depth` / `max_directory_entries` limits). The default `max_directory_depth` (64) is chosen to stay safely below a native stack overflow on a 2 MiB thread stack -- the default `std::thread::spawn`/`tokio::task::spawn_blocking` worker stack size -- on both the synchronous path (which recurses directly) and the asynchronous path (which recurses through a chain of nested `poll` calls on heap-boxed futures: cheaper per level, but not free of native-stack use). Raising the limit is a caller-opted-in risk unless the calling thread's stack is sized accordingly, on both paths.
- With the `nonblocking-open` feature enabled on Unix, a directory entry, or a regular file (or symlink-to-file) passed directly as the top-level source, racing into a FIFO or slow device between classification and open no longer hangs the traversal (without the feature the risk remains, as documented).
- A symlink resolving to an irregular target is now reported as `SkippedIrregular` rather than `SkippedUnresolvableSymlink`, and a genuine I/O error while resolving a symlink target is surfaced instead of masked.
- An irregular path passed directly at the top level now honors the `IrregularFile` policy instead of always erroring, including when that path is itself a symlink to an irregular or dangling target.
- A top-level `DirEntry` now hashes identically to the same object passed as a top-level `Path`: it no longer frames itself with its own name under `NameMode::FileName`, and no longer registers a symlinked-directory target into the visited set, matching `Path`'s top-level behavior in both cases.
- Restored dispatch through `Hashable::hash_into` in the blanket `Chksumable`/`AsyncChksumable` impls, so a type overriding `hash_into` is honored by `chksum`/`async_chksum` instead of being bypassed.
- Aligned the async directory-entry-count check to the same precedence as the synchronous path: the configured `max_directory_entries` cap is checked before propagating a raw I/O error from reading one entry past it, so identical trees produce `DirectoryTooLarge` on both paths.
- `Chksumer`/`AsyncChksumer::update_from` now resets the recursion depth alongside the visited-directory set on every fresh top-level call, so a `Chksumer`/`AsyncChksumer` reused after an earlier call returned early (error, or a cancelled `AsyncChksumer::update_from` future) always starts with a full depth budget instead of a stranded one.

### Changed

- Upgraded Rust edition to 2024 and MSRV to 1.95.0.
- Renamed `Hashable::hash_with` to `hash_into`.
- Renamed `Chksumable::chksum_with` to `chksum_into`; it now takes `&mut Chksumer<H>`.
- Renamed `AsyncChksumable::chksum_with` to `chksum_into`; it now takes `&mut AsyncChksumer<H>`.
- Changed `Path` to return `NotARegularFile` for paths that are neither files nor directories.
- Changed directory traversal to abort with `NotARegularFile` on non-regular entries such as sockets and named pipes by default, instead of attempting to open them as files; opt into skipping them via `IrregularFile::Skip`.
- Changed directory traversal to open verified entries directly, skipping a redundant `stat` and a per-file terminal check.
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
