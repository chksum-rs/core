# Hardening

This page covers the `nonblocking-open` feature, the race window between classifying a symlink's target and
reopening it, the default policy for irregular files (and how to opt out of it), and the traversal limits that bound
recursion depth and per-directory entry counts. This page documents internal hardening mechanisms. Their details are
not a stability contract unless a sentence explicitly says otherwise. See the [README](../README.md) for the
quick-start overview, [Symlinks](SYMLINKS.md) for how symlink cycles/fan-out are bounded, and
[Directory digests](DIRECTORY-DIGESTS.md) for how these limits interact with digest computation.

## The `nonblocking-open` feature

On Unix, opens directory-entry files — and a regular file (or symlink-to-file) passed directly as the top-level
source — with `O_NONBLOCK` so a race-swapped FIFO or slow device between classification and open cannot hang
traversal. Without it (the default, or off Unix) a race-swapped FIFO can block until a writer appears.

## Classification and open race window

A symlink's target is classified (regular file, directory, or neither) and then reopened by path; traversal is not
race-safe against a filesystem that mutates concurrently with the scan — a target swapped between the two steps is
read (or opened) as whatever it has become, not as what was classified. This matters only against a local attacker
able to modify the tree mid-scan.

## Irregular files

An entry that is neither a regular file nor a directory (for example a socket, a named pipe, or a symlink whose
target cannot be resolved, such as a dangling symlink) aborts traversal with `Error::NotARegularFile` by default. Set
`IrregularFile::Skip` on the builder to skip such an entry instead; the skip is reported through the `Diagnostic`
callback rather than passing silently.

## Traversal limits

Traversal aborts with `Error::TraversalTooDeep` when nesting exceeds the configured maximum depth (default 64,
`max_directory_depth` on the builder), or `Error::DirectoryTooLarge` when one directory holds more entries than the
configured maximum it will buffer (default 10,000,000, `max_directory_entries`). The default depth is sized to stay
safely below a native stack overflow on both the synchronous path (which recurses directly) and the asynchronous
path (which recurses through a chain of nested `poll` calls on heap-boxed futures — cheaper per level, but not free
of native-stack use); raising it is a caller-opted-in risk unless the calling thread's stack is sized accordingly.

## Related

* [Symlinks](SYMLINKS.md) — a forward symlink chain is bounded by the OS's own `ELOOP` limit, not by these limits.
* [Directory digests](DIRECTORY-DIGESTS.md) — how `NameMode::FileName` frames a directory these limits reject.
