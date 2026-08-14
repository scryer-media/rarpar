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

## Usage

```rust
use unrar_rs::RarArchive;

let archive = RarArchive::open(std::fs::File::open("release.part01.rar")?)?;
for member in &archive.metadata().members {
    println!("{} ({:?} bytes)", member.name, member.unpacked_size);
}
```

Reading headers decompresses nothing, so listing a large set costs only its
headers. Extraction verifies by default:

```rust
use unrar_rs::{ExtractOptions, RarArchive};

let mut archive = RarArchive::open(std::fs::File::open("release.rar")?)?;
let index = archive.find_member("movie.mkv").expect("member present");
archive.extract_member_to_file(
    index,
    &ExtractOptions { verify: true, password: None, restore_owners: false },
    None,
    "movie.mkv".as_ref(),
)?;
```

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

## Extracting from volumes that are not files

`extract_member_streaming` reads through a `VolumeProvider` rather than the
filesystem, so a member can be extracted while its volumes are still arriving,
or from volumes that never exist as files. Volumes are addressed in the set's
own numbering throughout: a member whose first segment is in volume 5 requests
volume 5.

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
| AMD EPYC 9R14 (Zen 4) | x86-64 | GFNI + AVX-512 | 2.0× | 1.5× |
| Intel Xeon Platinum 8488C (Sapphire Rapids) | x86-64 | GFNI + AVX-512 | 1.9× | 1.4× |
| Intel Core i5-1240P (Alder Lake) | x86-64 | GFNI + AVX2 | 1.5× | 1.2× |
| AMD Ryzen 5 3600 (Zen 2) | x86-64 | AVX2 | 1.6× | 1.5× |
| Intel Atom C3538 (Denverton) | x86-64 | SSSE3 (no AVX) | 1.2× | 1.3× |
| Apple M5 Max | arm64 | NEON | 1.4× | 1.5× |
| Arm Cortex-A72 | arm64 | NEON | 2.1× | 1.4× |
| Arm Neoverse N1 | arm64 | NEON | 2.6× | 1.5× |
| Arm Neoverse V2 | arm64 | NEON | 3.1× | 1.6× |

`binary` is store-mode extraction (uncompressible media payloads, encrypted
variants included); `text` is compressed extraction (LZ and PPMd). Encrypted
extraction is the widest win: 2.0×–10.7× depending on silicon.

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

GPL-3.0-or-later, with the additional UnRAR source-code restriction:

> UnRAR source code may be used in any software to handle RAR archives without
> limitations free of charge, but cannot be used to develop RAR (WinRAR)
> compatible archiver and to re-create RAR compression algorithm, which is
> proprietary. Distribution of modified UnRAR source code in separate form or as
> a part of other software is permitted, provided that full text of this
> paragraph, starting from "UnRAR source code" words, is included in license, or
> in documentation if license is not available, and in source code comments of
> resulting package.

This restriction is why the crate provides no compression or archive-writing
API, and it applies to anything that links this crate. See [LICENSE](https://github.com/scryer-media/rarpar/blob/main/crates/weaver-unrar/LICENSE).
