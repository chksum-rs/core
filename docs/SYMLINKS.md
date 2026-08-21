# Symlinks

This page covers how directory traversal follows symbolic links, how it deduplicates directories reached through a
symlink to bound cycles and fan-out, platform coverage of that dedup, the resulting amplification bounds, and how a
chain of forward symlinks interacts with `ELOOP`. This page documents internal traversal mechanisms. Their details
are not a stability contract unless a sentence explicitly says otherwise. See the [README](../README.md) for the
quick-start overview, [Directory digests](DIRECTORY-DIGESTS.md) for how `NameMode` interacts with symlinks, and
[Hardening](HARDENING.md) for the traversal limits referenced below.

## Following symlinks

Directory traversal follows symbolic links: linked files are hashed and linked directories are traversed. Directories
reached through a symlink are deduplicated per traversal — see the next section for how.

## Directory identity and the visited set

On Unix, traversal records each directory's filesystem identity (dev+ino) when entered through a symlink; a symlink
whose target was already visited this traversal is skipped once and surfaced as
`Diagnostic::SkippedRevisitedDirectory`, bounding symlink cycles and repeated-directory-target fan-out. Set
`follow_symlink_revisits(true)` on the builder to disable the dedup and restore full re-traversal (and the exact
pre-dedup digest) for trees with duplicate symlink targets. A symlink pointing back at an ancestor — including the
top-level root itself — is bounded and terminates correctly via this dedup, but costs one additional full traversal
pass of that subtree before the revisit is caught, because the top-level directory's own identity is not
pre-registered; this is an accepted, documented cost, not a defect. This dedup is scoped to directory targets, not
file targets: a symlink to a regular file is read in full every time it is encountered, so many symlinks pointing at
the same large file are not deduplicated and each one re-hashes it — bounded by the
[depth/entry limits](HARDENING.md#traversal-limits), not eliminated.

## Platform coverage

Windows currently has no such identity-based dedup: its equivalent (`MetadataExt::volume_serial_number`/`file_index`)
is gated behind the unstable `windows_by_handle` std feature
([rust-lang/rust#63010](https://github.com/rust-lang/rust/issues/63010)), and this crate is
`#![forbid(unsafe_code)]`, so it relies on the [maximum-depth limit](HARDENING.md#traversal-limits) as its only
backstop against symlink cycles/fan-out, pending that std feature's stabilization. On any platform without a stable
directory identity, the maximum-depth limit is likewise the backstop.

## Bounded amplification

The ancestor-cycle case is not the only source of this bounded amplification: only a directory *entered through a
symlink* is ever registered in the visited set, so a directory reached by its own plain (non-symlink) path is never
recorded there. A directory that is both a plain descendant of the root and, separately, the target of one or more
symlinks elsewhere in the tree is therefore walked in full via its plain path, then walked in full once more by the
first symlink that reaches it (which registers its identity so any later symlinks to the same target are skipped) —
one extra full pass of that subtree, not one per symlink. Nesting such plain-path/symlink pairs at successive levels
compounds this by at most one extra pass per level of directory nesting, so the total amplification stays bounded by
[`max_directory_depth`](HARDENING.md#traversal-limits), never unbounded — fan-out is bounded here, not absent.

## Forward symlink chains and ELOOP

A chain of forward symlinks (`a` → `b` → `c` → …, each one further into the tree, as opposed to a cycle) is resolved
by a single `stat`-family call per symlink encountered, so it is bounded by the operating system's own per-lookup
symlink-resolution limit (`ELOOP`, surfaced by Rust as `io::ErrorKind::FilesystemLoop` — unstable as of this crate's
MSRV, so not itself part of this crate's API — roughly 40 on Linux) well before `max_directory_depth` is reached —
raising `max_directory_depth` gives no additional protection against this specific pattern. Traversal still fails
safely: an `ELOOP` is surfaced as `Error::Io`, not a hang or a crash.

## Related

* [Directory digests](DIRECTORY-DIGESTS.md) — the cross-platform reproducibility caveat that follows from the
  platform coverage above.
* [Hardening](HARDENING.md) — the traversal limits that back up symlink cycle/fan-out bounding.
