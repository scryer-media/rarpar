# unrar-rs

[![crates.io](https://img.shields.io/crates/v/unrar-rs.svg)](https://crates.io/crates/unrar-rs)
[![docs.rs](https://docs.rs/unrar-rs/badge.svg)](https://docs.rs/unrar-rs)

Read and extract RAR archives in Rust, with no C bindings and no `unrar`
program needed.

```toml
[dependencies]
unrar-rs = "0.12"
```

It only reads archives. It cannot create them, for the licensing reason
given [below](#license).

## Listing

Listing reads only the headers and decompresses nothing, so it is cheap even
for a large set of volumes.

```rust
use unrar_rs::RarArchive;

let archive = RarArchive::open(std::fs::File::open("release.part01.rar")?)?;
for member in archive.entries() {
    println!("{} ({:?} bytes)", member.name, member.unpacked_size);
}
```

## Extracting

Pick a member with `by_index` or `by_name`, then say where its bytes go:
`copy_to` a writer, `unpack_to` a path, `unpack_in` a directory, `skip` it,
or read it as a `Read`. Picking a member decodes nothing until you do one of
these.

```rust
use unrar_rs::RarArchive;

let mut archive = RarArchive::open(std::fs::File::open("release.rar")?)?;

for index in 0..archive.len() {
    let mut sink = std::io::sink();
    archive.by_index(index)?.copy_to(&mut sink)?;
}
```

`copy_to` passes the bytes straight to your writer as they are decoded,
with no buffering in memory and no temporary file.

`unpack_to` and `unpack_in` write the member to disk with what the archive
records about it: times, permissions, Windows attributes, symlinks and
hardlinks. `unpack_in` uses the member's own name, cleaned so it cannot
escape the directory.

```rust
use unrar_rs::RarArchive;

let mut archive = RarArchive::open(std::fs::File::open("release.rar")?)?;
archive.by_name("movie.mkv")?.unpack_to("movie.mkv".as_ref())?;
```

Every member is checked against its CRC32 or BLAKE2sp, so a damaged member
is an error, not wrong output. `set_verify(false)` turns that off. A member
split across volumes is also checked at each volume, so damage is found
where it is rather than at the end.

For an archive that is still downloading, call
`archive.set_decode_mode(unrar_rs::DecodeMode::Serial)` first. It decodes on
the calling thread, which suits waiting for input. Finished archives keep
the default, `DecodeMode::Auto`.

### Volumes that are not files yet

`by_index_via` reads a member's volumes from a `VolumeProvider` you supply,
so you can extract while volumes are still arriving, or from volumes that are
never files at all. `StaticVolumeProvider` wraps a list of paths.

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

Volumes are numbered as the set numbers them: a member that starts in volume
5 asks the provider for volume 5.

`copy_to_volumes` gives each volume its own writer, so a member spread over
five volumes arrives as five pieces, each tagged with the volume it came
from. The writers need not be `Send` or `'static`.

### Solid archives

Everything above works on solid archives too, with one rule: their members
share one dictionary, so they must be read in order. Asking for a later
member decodes the ones before it for you; going back is refused. `skip`
passes a member without producing its bytes.

If a solid member fails partway, the members after it cannot be decoded
until `reset_solid_state` is called and extraction starts again from the
first member.

## Passwords

Both kinds of RAR encryption work: encrypted file data (`rar -p`) and
encrypted headers (`rar -hp`). Use `set_password`, `open_with_password` when
the headers are encrypted, or `with_password` for a single member.

The `crypto` module is for programs that move encrypted bytes around rather
than extract them: it derives a member's key, checks a password before
decrypting (`Verified`, `Wrong` or `Unverifiable`), and decrypts or
re-encrypts any range.

## Errors

Failures are typed (`RarError`), and the `io::Error` a reader returns carries
the original error, so `io::Error::downcast` gives back the `RarError` or the
`VolumeProviderError` behind it.

## What it reads

- RAR5 and RAR4, including the older RAR 1.5, 2.0 and 2.9 formats, and
  self-extracting archives.
- Stored and compressed members, including PPMd.
- RAR5's filters (delta, x86, ARM) and RAR4's (x86, Itanium, delta, RGB,
  audio).
- Encrypted data and headers.
- Multi-volume sets, with members that span volumes.
- Hostile archives: names that would escape the output directory are
  cleaned, and sizes declared in headers are capped before anything is
  allocated.

## Encryption backend

- `crypto-aws-lc` (default): AWS-LC. It needs a C compiler, and it is what
  the speed figures below were measured with.
- `crypto-rust`: pure Rust. Use it where AWS-LC does not build, such as
  WebAssembly. Decryption is slower; the output is the same.

```toml
unrar-rs = { version = "0.12", default-features = false, features = ["crypto-rust"] }
```

Turning on neither is a compile error. With both on, AWS-LC is used.
`native-crypto` is an old name for `crypto-aws-lc`.

On WebAssembly, `crypto-host` hands decryption, and `crc-host` the CRC-32
checks, to the program that embeds the module. On other targets they do
nothing.

## Speed

How many times faster than RARLAB's `unrar` a member is extracted (2.0× is
half the time):

| CPU | Arch | Instruction set | binary | text |
|---|---|---|---:|---:|
| AMD EPYC 9R14 (Zen 4) | x86-64 | GFNI + AVX-512 | 2.5× | 1.8× |
| Intel Xeon Platinum 8488C (Sapphire Rapids) | x86-64 | GFNI + AVX-512 | 2.0× | 1.5× |
| Intel Core i5-1240P (Alder Lake) | x86-64 | GFNI + AVX2 | 1.6× | 1.4× |
| Intel Xeon Platinum 8124M (Skylake-SP) | x86-64 | AVX-512 | 1.6× | 1.3× |
| AMD Ryzen 5 3600 (Zen 2) † | x86-64 | AVX2 | 1.6× | 1.5× |
| Intel Xeon E5-2666 v3 (Haswell) | x86-64 | AVX2 | 1.6× | 1.3× |
| Intel Atom C3538 (Denverton) | x86-64 | SSSE3 (no AVX) | 1.2× | 1.4× |
| Apple M5 Max † | arm64 | NEON | 1.3× | 1.5× |
| Arm Cortex-A72 | arm64 | NEON | 2.0× | 1.6× |
| Arm Neoverse N1 | arm64 | NEON | 2.9× | 1.7× |
| Arm Neoverse V2 | arm64 | NEON | 3.1× | 1.8× |

† From an older release, awaiting a re-measure.

`binary` is stored, incompressible media, with and without encryption and
BLAKE2sp. `text` is compressed data, LZ and PPMd. Both are measured through the
`rarpar` command.

Every case on every machine, the method and the versions measured are in
[the rarpar benchmarks](https://github.com/scryer-media/rarpar/blob/main/docs/benchmark.md).

## Provenance

This is a Rust port of RARLAB's UnRAR, with additions of its own: SIMD
chosen at run time, streaming extraction, and assembling members across
volumes. PPMd comes from the
[`ppmd-turbo`](https://github.com/scryer-media/ppmd-turbo) crate. The RAR
format is described in RARLAB's
[technical note](https://www.rarlab.com/technote.htm).

Changes by version are in [CHANGELOG.md](https://github.com/scryer-media/rarpar/blob/main/crates/unrar-rs/CHANGELOG.md).

## License

Apache-2.0 plus the unRAR license restriction, from version 0.11.0 onward.
Releases before 0.11.0 stay under GPL-3.0-or-later with the same
restriction. The RAR engine was developed using the source code of the
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
