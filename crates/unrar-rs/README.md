# unrar-rs

[![crates.io](https://img.shields.io/crates/v/unrar-rs.svg)](https://crates.io/crates/unrar-rs)
[![docs.rs](https://docs.rs/unrar-rs/badge.svg)](https://docs.rs/unrar-rs)

RAR archive reading and extraction in pure Rust. No C bindings, no external
`unrar` binary.

```toml
[dependencies]
unrar-rs = "0.5"
```

This crate reads existing archives. It exposes no writer, builder, or
archive-creation API, for the licensing reason given below.

## Listing

Reading headers decompresses nothing, so listing a large set costs only its
headers.

```rust
use unrar_rs::RarArchive;

let archive = RarArchive::open(std::fs::File::open("release.part01.rar")?)?;
for member in archive.entries() {
    println!("{} ({:?} bytes)", member.name, member.unpacked_size);
}
```

## Extracting

Take an `Entry` for the member you want, then say where its bytes go.
`by_index` and `by_name` decode nothing on their own; the handle they return is
consumed by exactly one of `copy_to`, `unpack_to`, `unpack_in`,
`copy_to_volumes`, `skip`, or reading it as a `Read`.

```rust
use unrar_rs::RarArchive;

let mut archive = RarArchive::open(std::fs::File::open("release.rar")?)?;

for index in 0..archive.len() {
    let mut sink = std::io::sink();
    archive.by_index(index)?.copy_to(&mut sink)?;
}
```

`copy_to` hands each span the decoder produces straight to the writer: nothing
is buffered in memory or spooled to a temporary file on the way. When there is
no writer to give, the entry is itself a `Read`, served from a spool it fills on
the first read.

Verification is on by default, so a member whose CRC32 or BLAKE2sp does not
match is an error rather than a silently wrong result. `set_verify` turns it
off; `set_password` and `set_restore_owners` are the other two settings an
entry extracts under.

To land a member on disk with the metadata the archive carries — times,
permissions, Windows attributes, and symlinks and hardlinks as such — use
`unpack_to`, or `unpack_in` to let the member's own sanitized name choose the
file.

```rust
use unrar_rs::RarArchive;

let mut archive = RarArchive::open(std::fs::File::open("release.rar")?)?;
archive.by_name("movie.mkv")?.unpack_to("movie.mkv".as_ref())?;
```

### Volumes that are not files yet

`by_index_via` reads a member's volumes from a `VolumeProvider` instead of from
the archive's own, which is how a member is extracted while its volumes are
still arriving, or from volumes that never exist as files at all.
`StaticVolumeProvider` wraps a list of paths.

```rust
use unrar_rs::{RarArchive, StaticVolumeProvider};

let path = std::path::PathBuf::from("release.rar");
let mut archive = RarArchive::open(std::fs::File::open(&path)?)?;
let provider = StaticVolumeProvider::from_ordered(vec![path]);

for index in 0..archive.len() {
    let mut sink = std::io::sink();
    archive.by_index_via(index, &provider)?.copy_to(&mut sink)?;
}
```

`copy_to_volumes` takes that further and gives each volume its own writer, so a
member spanning five volumes lands as five pieces attributed to the volumes they
came from. The writer type is yours: it needs neither `Send` nor `'static`, so
writers sharing one sink through a borrow are fine.

### Solid archives

Every call above handles solid and non-solid archives alike. What solidity adds
is an order: a solid archive compresses its members against one shared
dictionary, so they are consumed in ascending index order. Reaching forward
decodes the members in between for you; reaching backwards is refused. `skip`
walks past a member you do not want without producing its bytes, and dropping an
entry unconsumed costs nothing.

If a solid member fails partway — a decode error, or a writer that returns one —
the carried-over dictionary no longer lines up with any member boundary, so the
archive is poisoned: later solid extractions are refused until
`reset_solid_state` clears it and extraction restarts from the first member.

## Capabilities

- RAR5 and RAR4, including legacy RAR 1.5 / 2.0 / 2.9, and SFX archives.
- All five RAR5 header types, vint decoding, header CRC32 validation.
- Store, LZ (methods 1–5), and PPMd variant H decompression, plus the Delta,
  E8, E8E9 and ARM filters.
- AES decryption for file data (`-p`) and encrypted headers (`-hp`), with
  RAR-compatible key derivation.
- Multi-volume topology tracking and cross-volume member layout.
- Metadata-only mode for inspection without extraction.
- Path sanitisation against traversal, and header-declared limits that bound
  allocation.

## Volume numbering

Volumes are addressed in the set's own numbering throughout: a member whose
first segment is in volume 5 requests volume 5. Do not re-key a provider to the
member's first volume.

## Verification

Checks follow what the format provides. A member carries a whole-member CRC32 or
BLAKE2sp. A member split across volumes also carries a packed checksum in every
non-final part, so damage is caught at the part carrying it rather than at the
end of the member. Note that `-htb` archives replace CRC32 with BLAKE2sp rather
than adding it.

## Performance

`2.0×` means `rarpar` finished in half the time:

| CPU | Arch | Instruction set | unrar (binary) | unrar (text) |
|---|---|---|---:|---:|
| AMD EPYC 9R14 (Zen 4) | x86-64 | GFNI + AVX-512 | 2.7× | 1.7× |
| Intel Xeon Platinum 8488C (Sapphire Rapids) | x86-64 | GFNI + AVX-512 | 2.1× | 1.4× |
| Intel Core i5-1240P (Alder Lake) | x86-64 | GFNI + AVX2 | 1.7× | 1.3× |
| Intel Xeon Platinum 8124M (Skylake-SP) | x86-64 | AVX-512 | 1.5× | 1.2× |
| AMD Ryzen 5 3600 (Zen 2) | x86-64 | AVX2 | 1.6× | 1.5× |
| Intel Xeon E5-2666 v3 (Haswell) | x86-64 | AVX2 | 1.5× | 1.2× |
| Intel Atom C3538 (Denverton) | x86-64 | SSSE3 (no AVX) | 1.2× | 1.3× |
| Apple M5 Max | arm64 | NEON | 1.3× | 1.4× |
| Arm Cortex-A72 | arm64 | NEON | 2.3× | 1.6× |
| Arm Neoverse N1 | arm64 | NEON | 3.1× | 1.7× |
| Arm Neoverse V2 | arm64 | NEON | 3.8× | 1.8× |


`binary` is store-mode extraction (uncompressible media payloads, encrypted
variants included); `text` is compressed extraction (LZ and PPMd). Encrypted
extraction is the widest win: 1.2×–13.4× depending on silicon and shape.

Per-case charts for every machine, the full methodology, and the versions
these numbers were measured with:
[**rarpar benchmarks**](https://github.com/scryer-media/rarpar/blob/main/docs/benchmark.md).

## Provenance

This is a Rust port of RARLAB's reference UnRAR implementation, with additional
optimisations: runtime-dispatched SIMD, a streaming extraction path, and
cross-volume layout assembly that the reference implementation does not provide.

The RAR format is documented in RARLAB's
[technical note](https://www.rarlab.com/technote.htm).

Versioned API and behavior notes are in [CHANGELOG.md](https://github.com/scryer-media/rarpar/blob/main/CHANGELOG.md).

## License

GPL-3.0-or-later. The RAR engine was developed using the source code of the
unRAR program; all copyrights to the original unRAR code are owned by
Alexander Roshal, and its license restriction continues to govern the
unRAR-derived code in this crate:

> UnRAR source code may be used in any software to handle RAR archives without
> limitations free of charge, but cannot be used to develop RAR (WinRAR)
> compatible archiver and to re-create RAR compression algorithm, which is
> proprietary. Distribution of modified UnRAR source code in separate form or as
> a part of other software is permitted, provided that full text of this
> paragraph, starting from "UnRAR source code" words, is included in license, or
> in documentation if license is not available, and in source code comments of
> resulting package.

This restriction is why the crate provides no compression or archive-writing
API, and it applies to anything that links this crate. See [LICENSE](https://github.com/scryer-media/rarpar/blob/main/crates/unrar-rs/LICENSE).
