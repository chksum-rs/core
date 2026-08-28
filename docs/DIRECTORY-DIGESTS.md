# Directory digests

This page covers the default content-only directory digest and the collision classes it accepts, how
`NameMode::FileName` commits entry names and directory structure instead, the byte-level frame encoding it uses, and
a cross-platform reproducibility caveat. This page documents internal digest-construction mechanisms. Their details
are not a stability contract unless a sentence explicitly says otherwise — the digest *values* themselves are
behavior users depend on and are described as such wherever the text below says so. See the
[README](../README.md) for the quick-start overview and [Symlinks](SYMLINKS.md) for how symlinked directories are
deduplicated during traversal.

## Default: contents only (`NameMode::Off`)

By default a directory is hashed as the raw contents of its regular files, concatenated in name-sorted order, with
**no** entry names, lengths, structure, or separators. This is fast and stable, but distinct trees can collide:
re-splitting the same bytes across differently named files, renaming files, adding an empty file or directory, and a
flat file versus a directory split all produce the same digest.

## Committing names and structure (`NameMode::FileName`)

Set a `NameMode` on a `Chksumer` (through its builder) to commit names and structure: `NameMode::FileName` hashes
bare names with directory nesting (git-tree style), so renames, reordering, re-splitting, and flattening or nesting
alter the digest while it stays reproducible across machines of the same platform family. Because only Unix currently
has a stable directory-identity source (see [Symlinks](SYMLINKS.md)), a tree containing duplicate symlink targets can
hash differently on a platform without that dedup (currently non-Unix, including Windows) than on Unix, even though
both hash the same tree under the same `NameMode`. The default, `NameMode::Off`, preserves the historical behavior.
Because symlinks are followed transparently, under `NameMode::FileName` a symlinked entry and a real entry sharing
the same bare name and resolved kind produce the same frame — `FileName` commits names and structure, not whether an
entry is itself a symlink.

## Example

Both modes, ready to paste (substitute `H` with a concrete hash type from one of the family crates listed in the
[README](../README.md#example-crates)):

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

## Frame encoding

Under `FileName`, each entry's name is length-prefixed, while each regular file's content length is committed as a
suffix (the actual number of bytes read and hashed). This is an intentional encoding-style asymmetry, noted for
completeness — not a name-vs-content parity requirement. Each record is anchored at its start by a fixed tag and
length-prefixed name; whether the trailing content-length placement could ever be exploited to construct a collision
has not been formally analyzed or tested, so the asymmetry is noted as an unverified stylistic choice, not a proven
weakness. A directory revisited through a symlink is committed as an empty framed directory (its name plus an
immediate close, no children), so its structural presence is preserved even though its contents are not re-walked.

## Related

* [Symlinks](SYMLINKS.md) — directory-identity dedup, and why it affects cross-platform reproducibility above.
* [Hardening](HARDENING.md) — traversal limits that bound how large a digest computation can grow.
