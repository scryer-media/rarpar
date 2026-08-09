# unrar-rs

[![crates.io](https://img.shields.io/crates/v/unrar-rs.svg)](https://crates.io/crates/unrar-rs)
[![docs.rs](https://docs.rs/unrar-rs/badge.svg)](https://docs.rs/unrar-rs)

RAR archive reading and extraction in pure Rust. No C bindings, no external
`unrar` binary.

```toml
[dependencies]
unrar-rs = "0.4"
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

### rarpar 0.3.0 release validation

These deterministic end-to-end runs use the synthetic `rarpar-bench` corpus,
one warmup, seven measured runs, CPU-only release builds, and SHA-256 output
validation. They include CLI discovery and output handling as well as archive
extraction, so they are release-workflow measurements rather than isolated
decoder microbenchmarks.

![RAR workloads on AMD Ryzen 5 3600 with Windows x86-64](https://raw.githubusercontent.com/scryer-media/rarpar/rarpar-v0.3.0/crates/weaver-unrar/docs/rarpar-rar-benchmark-windows-x86_64.svg)

![RAR workloads on Intel Core i5-1240P with Linux x86-64](https://raw.githubusercontent.com/scryer-media/rarpar/rarpar-v0.3.0/crates/weaver-unrar/docs/rarpar-rar-benchmark-linux-x86_64.svg)

![RAR workloads on Apple M5 Max with macOS arm64](https://raw.githubusercontent.com/scryer-media/rarpar/rarpar-v0.3.0/crates/weaver-unrar/docs/rarpar-rar-benchmark-macos-arm64.svg)

### Broader library workloads

Measured against `unrar 7.20` on archives built natively with `rar 7.20` (and
`rar 6.24` for RAR4). Extraction includes full verification, and every output is
byte-compared against the source payload. Warm-cache medians from release builds
with shipped flags. Test machines: Apple M5 Max (macOS), Intel Core Ultra 9 285H
(Ubuntu 24.04, P-core pinned), AMD Ryzen 5 3600 (Windows, Zen 2).

![unrar-rs relative speed against unrar 7.20, by workload and machine](https://raw.githubusercontent.com/scryer-media/rarpar/948edda929dcb4b4d48af91ff58eeefb099afc4d/docs/img/unrar-benchmark.svg)

Absolute times behind the chart:

| Machine | Workload | unrar 7.20 | unrar-rs | |
|---|---|---:|---:|---|
| M5 Max | RAR7 video, 4.9 GB, 4.6 GB dictionary, `-m3` | 8.6 s | **5.8 s** | 1.5× |
| M5 Max | RAR5 encrypted, AES-256 | 0.41 s | **0.25 s** | 1.6× |
| M5 Max | RAR5 solid video, 225 MB | 0.27 s | **0.22 s** | 1.2× |
| M5 Max | Store-mode verify, BLAKE2sp, 4.9 GB | 1.27 s | **0.76 s** | 1.7× |
| M5 Max | RAR4 solid video *(CPU seconds)* | 1.21 s | **0.19 s** | 6× |
| M5 Max | RAR4 PPMd solid text, 200 MB | **44.2 s** | 50.9 s | 0.87× |
| 285H | RAR7 video, 4.9 GB, `-m3` | 17.7 s | **13.5 s** | 1.3× |
| 285H | RAR5 encrypted, AES-256 | 0.83 s | **0.52 s** | 1.6× |
| 285H | RAR5 solid video, 216 MB | 0.78 s | **0.54 s** | 1.4× |
| 285H | RAR5 solid text, 157 MB | **1.52 s** | 2.98 s | 0.5× |
| 285H | RAR4 PPMd solid text, 156 MB | **28.7 s** | 47.5 s | 0.6× |
| Ryzen 5 3600 | RAR7 video, 4.94 GB, `-m3` | 13.5 s | 13.6 s | parity |
| Ryzen 5 3600 | Store-mode verify, BLAKE2sp, 4.94 GB | 3.48 s | **1.80 s** | 1.9× |
| Ryzen 5 3600 | Store-mode extract to disk, 4.94 GB | **3.28 s** | 5.0 s | 0.66× |

Video, encrypted, and store-mode verification win. Compressible text and RAR4
PPMd lose: PPMd keeps bounds checks where the reference uses raw pointers, and
dense text is a tighter per-symbol Huffman loop upstream. Windows store-mode
write-to-disk trails on the write path.

Peak memory is archive-size-independent, roughly 275 MB on a 2.25 GB solid set
(reference unrar MT: ~264 MB). Encrypted extraction costs almost nothing extra
because AES runs through AWS-LC.

## Provenance

This is a Rust port of RARLAB's reference UnRAR implementation, with additional
optimisations: runtime-dispatched SIMD, a streaming extraction path, and
cross-volume layout assembly that the reference implementation does not provide.

The RAR format is documented in RARLAB's
[technical note](https://www.rarlab.com/technote.htm).

Versioned API and behavior notes are in [CHANGELOG.md](CHANGELOG.md).

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
API, and it applies to anything that links this crate. See [LICENSE](LICENSE).
