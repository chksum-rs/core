# Gotchas

This page collects call shapes that compile, run, and return a plausible-looking digest while silently doing
something different from what the call site suggests — no panic, no error, no warning. Each entry shows the wrong
call, the right call, and why the two diverge. See the [README](../README.md) for the quick-start overview,
[Symlinks](SYMLINKS.md) for traversal/dedup mechanics, [Directory digests](DIRECTORY-DIGESTS.md) for `NameMode`
framing, and [Hardening](HARDENING.md) for the `IrregularFile` policy and traversal limits referenced below.

In the snippets below `H` stands for any type implementing this crate's `Hash` trait — substitute a concrete hash
from one of the family crates listed in the [README](../README.md).

## A string path argument hashes the string, not the file

```rust
// hashes the 10 UTF-8 bytes "./data.bin", NOT the file's contents
let digest = chksum_core::chksum::<H>("./data.bin")?;
```

```rust
use std::path::Path;
let digest = chksum_core::chksum::<H>(Path::new("./data.bin"))?;
```

The blanket `impl<T: Hashable> Chksumable for T` covers every bytes-like type, and `Hashable` is implemented for
`&str`/`String` plus the `&T`/`&mut T` blankets. A path spelled as a string therefore resolves to the bytes impl,
feeding the string's own UTF-8 bytes into the hash — no filesystem access, no error. Only `Path`/`PathBuf` (and
`File`, `DirEntry`, `ReadDir`) dispatch to the filesystem impls. The same trap fires through
`Chksumer::update_from("./path")`, `chksum_with`, `async_chksum`, and `ctx.update("./path")`.

## Hashing a `File` starts at its current cursor, and `&File` moves the caller's offset

```rust
let mut file = File::open("data.bin")?;
let mut header = [0u8; 5];
file.read_exact(&mut header)?; // peek at a header first
// digest covers only bytes 5..EOF; afterwards `file` is at EOF for the caller too
let digest = chksum_core::chksum::<H>(&file)?;
```

Hash by path instead: it always covers the full content and leaves the caller's handle untouched.

```rust
let digest = chksum_core::chksum::<H>(Path::new("data.bin"))?;
```

If the handle must be reused, rewind it first:

```rust
let mut file = File::open("data.bin")?;
use std::io::{Seek, SeekFrom};
file.seek(SeekFrom::Start(0))?;
let digest = chksum_core::chksum::<H>(&file)?;
```

`impl Chksumable for File`/`&File`/`&mut File` calls `ctx.update_from_reader(self)`, which drains the reader from its
*current* position to EOF — it never seeks to the start. Two silent surprises stack: a partially-read `File` yields
the digest of the remaining tail only, so two equal-looking `chksum(&file)` calls before and after any read produce
different digests; and because `Read for &File` advances the shared kernel offset, even the borrow-looking
`chksum(&file)` leaves the *caller's* handle at EOF afterward.

## A user-opened `File` bypasses the `IrregularFile` policy and the nonblocking-open hardening

```rust
// on an irregular file (device, FIFO) this can hang the whole traversal instead of
// erroring NotARegularFile
let file = File::open("/dev/zero")?;
let digest = chksum_core::chksum::<H>(file)?;
```

```rust
// pass the Path so the source is classified first: irregular targets are rejected (or
// skipped under IrregularFile::Skip), and nonblocking-open hardening applies
let digest = chksum_core::chksum::<H>(Path::new("/dev/zero"))?; // -> Err(NotARegularFile)
```

The `Path` impl classifies the target via metadata before opening: a non-file/non-directory target goes through the
`IrregularFile` policy, and regular files open through the nonblocking-open helper (see [Hardening](HARDENING.md)).
The `File` impl only checks `is_terminal()` and then drains to EOF — no classification, no policy, no hardening,
because by the time a caller holds a `File` the type system can no longer route through the path-based checks. A
character device like `/dev/zero` never reaches EOF, so hashing it directly hashes forever; a FIFO blocks at the
user's own `File::open` before this crate is even involved.

## A partially-consumed `ReadDir` hashes only the remaining entries

```rust
let mut rd = std::fs::read_dir(&dir)?;
let first = rd.next().unwrap()?; // peek at the first entry
// digest silently excludes the peeked entry, yet looks like a valid whole-directory digest
let digest = chksum_core::chksum::<H>(rd)?;
```

```rust
// hash the directory by path (or by a fresh, unconsumed ReadDir)
let digest = chksum_core::chksum::<H>(dir.as_path())?;
```

`ReadDir` is a stateful iterator, and the `Chksumable` impl only ever sees what has not yet been yielded. Any `next()`
a caller performed beforehand permanently removes that entry from the digest, and the call still succeeds with a
digest indistinguishable from a full-directory one.

## `IrregularFile::Skip` on a top-level irregular path returns the digest of zero bytes

```rust
// Skip is chosen so one odd entry inside a tree can't abort the scan, but if `path` ITSELF
// is a socket/FIFO/dangling symlink this returns Ok with the empty-input digest
// (e.g. MD5 d41d8cd98f00b204e9800998ecf8427e) — indistinguishable from a real success
let digest = chksum_core::chksum_with::<H>(path, |b| b.irregular_file(chksum_core::IrregularFile::Skip))?;
```

```rust
// wire on_diagnostic to detect a skipped top-level source, and treat it as distinct from a
// real digest (e.g. don't record it as the object's checksum)
let digest = chksum_core::chksum_with::<H>(path, |b| {
    b.irregular_file(chksum_core::IrregularFile::Skip).on_diagnostic(|d| record_diagnostic(d))
})?;
```

`IrregularFile` also governs a top-level irregular path, not only entries nested inside a directory, and `Skip`
returns `Ok(())` having hashed nothing. A caller who enabled `Skip` to survive one odd entry inside a large tree gets,
for an entirely-irregular root, `Ok` plus the well-known empty-input digest — a value that passes any "is this a
digest" check while attesting to nothing. The `Diagnostic` callback (see [Hardening](HARDENING.md)) is the only
signal it happened.

## `update_from_reader` skips the terminal guard that `update_from(File)` applies

```rust
// looks equivalent to ctx.update_from(file), but performs no IsTerminal check: if `file` is
// /dev/tty (or stdin redirected from a terminal), this blocks reading keystrokes until EOF
// (Ctrl-D) instead of returning Error::IsTerminal
ctx.update_from_reader(&mut file)?;
```

```rust
// route through the Chksumable impl for File: it runs the is_terminal() guard first
ctx.update_from(file)?;
```

The terminal guard lives only in the `Chksumable`/`AsyncChksumable` impls for `File`/`Stdin`, not in the context's
raw-reader method. `update_from_reader` accepts any `Read`/`AsyncRead` and enters the read loop unconditionally, so
choosing it over the adjacent `update_from` — e.g. because the caller already holds `&mut File` — silently drops the
one guard the `File` impl itself carries.

## Reusing a `Chksumer`/`AsyncChksumer` without `reset()` corrupts the next digest

```rust
let mut ctx = Chksumer::<H>::new();
for path in paths {
    ctx.update_from(path)?;
    results.push(ctx.digest()); // item N's "digest" covers items 1..=N concatenated
}
```

```rust
let mut ctx = Chksumer::<H>::new();
for path in paths {
    ctx.reset(); // keeps the allocated buffer, zeroes hash + traversal state
    ctx.update_from(path)?;
    results.push(ctx.digest());
}
```

`update_from` clears traversal bookkeeping (depth, visited set) on every call, but it deliberately never resets the
underlying hash — a context reused in a loop accumulates every source into one running hash instead of one digest
per item. The same applies after a failed `update_from`: an error mid-tree (unreadable file, depth limit, an
irregular entry under the default `Error` policy) leaves every byte hashed before the failure inside the context, so
the *next* item's digest is silently prefixed with the previous failure's partial bytes — reset unconditionally,
success or error alike. It also applies to a cancelled async future: dropping `ctx.update_from(..)` mid-poll (the
normal effect of `tokio::select!`/`timeout`) leaves every chunk already read permanently in the hash with no error at
all, so a retry without `reset()` first double-counts them.

## Calling `chksum_into` directly, instead of `update_from`, inherits stale traversal state

```rust
let mut ctx = Chksumer::<H>::new();
let (mut a, mut b) = (PathBuf::from("./a"), PathBuf::from("./b"));
// chksum_into is public, looks equivalent to update_from, and compiles:
Chksumable::chksum_into(&mut a, &mut ctx)?;
Chksumable::chksum_into(&mut b, &mut ctx)?; // a symlinked dir in `b` sharing a's target is
                                            // silently skipped as an already-visited revisit
```

```rust
let mut ctx = Chksumer::<H>::new();
let (a, b) = (PathBuf::from("./a"), PathBuf::from("./b"));
// update_from is the top-level entry point: it resets depth and the visited set per source
ctx.update_from(&a)?;
ctx.update_from(&b)?;
```

`Chksumable::chksum_into` is public and is exactly what `update_from` calls internally, but only `update_from` clears
the symlinked-directory visited set and depth budget between independent traversals (see
[Symlinks](SYMLINKS.md#directory-identity-and-the-visited-set)). A direct `chksum_into` call on a reused context
inherits whatever traversal state the previous call left behind, silently dropping a distinct symlinked directory
from the second tree's digest if it happens to share a target already visited by the first.

## `NameMode::FileName` never commits the traversal root's own name

```rust
// "FileName commits names" — but NOT the root's: release-v1/ and release-v2/ with
// identical contents produce the SAME digest
let digest = chksum_core::chksum_with::<H>(root, |b| b.name_mode(chksum_core::NameMode::FileName))?;
```

```rust
let mut ctx = chksum_core::builder::<H>().name_mode(chksum_core::NameMode::FileName).build();
if let Some(name) = root.file_name() {
    ctx.update(name.as_encoded_bytes()); // commit the root's identity yourself
}
ctx.update_from(root)?;
let digest = ctx.digest();
```

Name/structure framing is emitted only for entries reached through a parent `ReadDir`; the top-level dispatch writes
no frame for the root itself (see [Directory digests](DIRECTORY-DIGESTS.md)). A caller who chose `FileName`
specifically because renames change the digest finds the one rename it never detects is the root's own.

## A revisited symlinked directory hashes like a genuinely empty directory of the same name

```rust
// Tree A: root/{d/f, a -> d, b -> d}  (b's target already visited via a: framed as an
// empty dir "b")
// Tree B: root/{d/f, a -> d, b/}      (b is a real, empty directory)
let digest = chksum_core::chksum_with::<H>(root, |b| b.name_mode(chksum_core::NameMode::FileName))?;
// Both trees return the SAME digest under NameMode::FileName, despite the mode's
// "structure is committed" promise.
```

```rust
let digest = chksum_core::chksum_with::<H>(root, |b| {
    b.name_mode(chksum_core::NameMode::FileName).follow_symlink_revisits(true) // re-walk revisited targets
})?;
```

A symlinked directory whose target was already visited this traversal is committed as its name plus an immediate
close — the exact frame of an empty directory of the same name (see [Directory digests](DIRECTORY-DIGESTS.md)). Two
structurally different trees can therefore collide under the mode whose selling point is that structure changes the
digest. The dedup this relies on is Unix-only (see the next entry), and `follow_symlink_revisits(true)` restores the
distinguishing, pre-dedup digest at the cost of re-walking.

## The default content-only directory digest is blind to renames, re-splits, and empty entries

```rust
// "Detect any tampering in the release directory" — the default NameMode::Off commits no
// names, lengths, or structure, so this does not do that
let digest = chksum_core::chksum::<H>(dir)?;
```

```rust
let digest = chksum_core::chksum_with::<H>(dir, |b| b.name_mode(chksum_core::NameMode::FileName))?;
```

Under the default `NameMode::Off` a directory is hashed as the raw contents of its regular files, concatenated in
name-sorted order, with no names, lengths, structure, or separators (see
[Directory digests](DIRECTORY-DIGESTS.md)). Renaming files, re-splitting the same bytes across differently named
files, adding an empty file or directory, and a flat file versus a directory split all produce the same digest. A
caller who writes `chksum(dir)` as an integrity check gets a valid-looking digest that detects none of this; only
`NameMode::FileName` commits names and structure.

## `NameMode::FileName` digests can diverge between Unix and non-Unix for the same tree

```rust
// Digest recorded by Linux CI, verified by a Windows client — diverges when the tree
// contains two or more symlinks resolving to the same directory.
let digest = chksum_with::<Sha2_256>(Path::new("tree"), |b| b.name_mode(NameMode::FileName))?;
assert_eq!(digest.to_hex_lowercase(), EXPECTED_FROM_LINUX_CI); // fails on Windows
```

```rust
// disable the Unix-only dedup so every platform walks every symlinked directory in full
let digest = chksum_with::<Sha2_256>(Path::new("tree"), |b| {
    b.name_mode(NameMode::FileName).follow_symlink_revisits(true)
})?;
```

Directory-identity dedup is Unix-only (see [Symlinks](SYMLINKS.md#platform-coverage)); on any other platform the
same duplicate-symlink-target entry is walked in full instead of framed as an empty revisit. `NameMode::FileName` is
marketed as reproducible across machines of the same platform family — the trap is that nothing at the call site
signals a cross-platform digest comparison is comparing two different encodings of the same tree.

## A borrow silently bypasses a custom `Hashable::hash_into` override

```rust
struct Framed(Vec<u8>); // domain-separated framing via an overridden hash_into
impl AsRef<[u8]> for Framed { fn as_ref(&self) -> &[u8] { &self.0 } }
impl Hashable for Framed {
    fn hash_into<H: Hash>(&self, hash: &mut H) {
        hash.update((self.0.len() as u64).to_be_bytes()); // length-prefix framing
        hash.update(&self.0);
    }
}
// looks equivalent to passing by value — the override is silently ignored: this hashes
// only the raw AsRef bytes, no length prefix
let digest = chksum_core::chksum::<H>(&framed)?;
```

```rust
// pass by value so Self = Framed is picked and the override runs
let digest = chksum_core::chksum::<H>(framed)?;
```

`impl<T: Hashable> Hashable for &T` (and the `&mut T` twin) is an *empty* impl, so a reference inherits the trait's
default `hash_into` body — a single raw `hash.update(self)` through `AsRef<[u8]>` — instead of delegating to the
referent's override. Every generic entry point (`chksum`, `hash`, `Chksumer::update`, and their async twins)
therefore honors an overridden `hash_into` when the value is passed by value but silently falls back to raw-bytes
hashing when the equivalent-looking `&value`/`&mut value` is passed instead — same call shape, different digest, no
warning.

## `H::hash(value)` bypasses a custom `Hashable::hash_into` override; `chksum`/`hash` honor it

```rust
// compiles via AsRef<[u8]>, hashes RAW bytes: the Framed override above is silently dropped
let digest = H::hash(&framed);
```

```rust
// pass by value so Self = Framed is picked and the override runs
let digest = chksum_core::hash::<H>(framed);
let digest = chksum_core::chksum::<H>(framed)?;
```

The `Hash` trait's associated `hash` function takes `T: AsRef<[u8]>` and calls `hash.update(data)` directly, so it
can never see a `Hashable` override. The free function `hash` and the blanket `Chksumable` impl both route through
`Hashable::hash_into` instead, which this crate deliberately supports overriding. Since every `Hashable` is also
`AsRef<[u8]>`, both spellings compile identically and silently disagree the moment `hash_into` is customized.

## `reset()` on a seeded `Chksumer`/`AsyncChksumer` discards the seed, not just the input

```rust
let mut seeded = H::default();
seeded.update(b"PREFIX:");
let mut ctx = Chksumer::from(seeded); // docs: "preserving its state"
for item in &items {
    ctx.update(item.as_slice());
    record(ctx.digest());
    ctx.reset(); // resets to H::default()'s initial state, NOT to the seeded state
}
```

```rust
// re-establish the seed each iteration; reset() cannot restore it
for item in &items {
    let mut seeded = H::default();
    seeded.update(b"PREFIX:");
    let mut ctx = Chksumer::from(seeded);
    ctx.update(item.as_slice());
    record(ctx.digest());
}
```

`Chksumer::from(hash)`/`ChksumerBuilder::from(hash)` are documented as "preserving its state", inviting a
seeded-prefix pattern (a domain separator, a protocol version tag, a poor-man's key). But `reset()` calls the
underlying `Hash::reset`, whose contract is "reset to its initial state" — the algorithm's default IV, not the seed
the context was constructed with; the context keeps no separate copy of the seed. So the first item's digest covers
seed+data, and every item after a `reset()` covers data alone: same input shape, different digest, no error. This is
sharper still because `update_from`'s own reuse contract instructs calling `reset()` before reusing a context after
an error — following that documented advice on a seeded context silently strips the seed from every digest after
the first.

## Related

* [README](../README.md) — quick-start overview and feature list.
* [Symlinks](SYMLINKS.md) — traversal, following, and the visited-set dedup several entries above rely on.
* [Directory digests](DIRECTORY-DIGESTS.md) — `NameMode` semantics and the collision classes it accepts or closes.
* [Hardening](HARDENING.md) — `IrregularFile` policy, `nonblocking-open`, and traversal limits.
