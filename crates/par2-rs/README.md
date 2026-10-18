# par2-rs

[![crates.io](https://img.shields.io/crates/v/par2-rs.svg)](https://crates.io/crates/par2-rs)
[![docs.rs](https://docs.rs/par2-rs/badge.svg)](https://docs.rs/par2-rs)

Verify and repair files with PAR2 recovery sets, in Rust, with no C bindings
and no `par2` program needed.

```toml
[dependencies]
par2-rs = "0.10"
```

## Usage

```rust
use par2_rs::{DiskFileAccess, Par2FileSet, Repairability, scan_packets_from_path, verify_all};
use std::path::Path;

fn main() -> par2_rs::Result<()> {
    let packets = scan_packets_from_path(Path::new("release.par2"))?
        .into_iter()
        .map(|(packet, _offset)| packet)
        .collect();
    let set = Par2FileSet::from_packets(packets)?;

    let access = DiskFileAccess::new("/downloads/release".into(), &set);
    let result = verify_all(&set, &access);

    println!("{} recovery blocks available", result.recovery_blocks_available);
    match result.repairable {
        Repairability::NotNeeded => println!("everything verified clean"),
        Repairability::Repairable { blocks_needed, .. } => {
            println!("repairable: {blocks_needed} blocks to rebuild")
        }
        Repairability::Insufficient { blocks_needed, .. } => {
            println!("not enough recovery data: {blocks_needed} blocks short")
        }
        other => println!("{other:?}"),
    }
    Ok(())
}
```

`Par2Repairer` does the whole job: scan, verify, work out the repair, rebuild,
and verify again.

`Par2RepairSession` is for files that are still downloading. It remembers
what it has already verified, so each new check only looks at what changed,
and repair starts from what is known. Its input can be files in a
directory, your own `FileAccess`, or a set you have already parsed; repair
always writes real files.

`verify_all` reads through the `FileAccess` trait. `DiskFileAccess` reads
files from disk; your own implementation can verify bytes that are still
arriving over the network, or that never exist as files.

## What it does

- Reads every PAR2 packet type, from any number of `.par2` files, as one set.
- Finds damage block by block, so one bad block does not condemn a whole
  file.
- Identifies files cheaply from their first 16 KiB, and by their full MD5
  when a set has no per-block checksums.
- Finds renamed and moved files by their content.
- Skips malformed or truncated packets instead of failing the whole set.

## MD5 backend

MD5 is the slowest single step in verifying, scanning and creating, so the
default backend is fast assembly:

- `crypto-native` (default): AWS-LC's MD5 assembly, built into this crate, on
  x86-64 and little-endian AArch64; RustCrypto's `md-5` elsewhere. No C
  compiler is needed. The speed figures below use it.
- `crypto-rust`: RustCrypto's `md-5` everywhere. About 25% slower on x86-64;
  the results are the same.

```toml
par2-rs = { version = "0.10", default-features = false, features = ["crypto-rust"] }
```

`crypto-aws-lc` and `native-crypto` are old names for `crypto-native`. On
x86-64 and AArch64, turning on neither backend is a compile error.

## GPU repair

`metal` and `wgpu` repair on the GPU through `reedsolomon-rs`, and fall
back to the CPU when there is no suitable device. On Apple Silicon, `metal`
can also create sets on the GPU, through `CreationBackend`.

## Speed

How many times faster than par2cmdline-turbo a heavy repair runs, measured
through the `rarpar` command (2.0× is half the time):

| CPU | Arch | Instruction set | par2 (heavy) |
|---|---|---|---:|
| AMD EPYC 9R14 (Zen 4) | x86-64 | GFNI + AVX-512 | 3.1× |
| Intel Xeon Platinum 8488C (Sapphire Rapids) | x86-64 | GFNI + AVX-512 | 2.5× |
| Intel Core i5-1240P (Alder Lake) | x86-64 | GFNI + AVX2 | 2.7× |
| Intel Xeon Platinum 8124M (Skylake-SP) | x86-64 | AVX-512 | 2.2× |
| AMD Ryzen 5 3600 (Zen 2) | x86-64 | AVX2 | 1.9× |
| Intel Xeon E5-2666 v3 (Haswell) | x86-64 | AVX2 | 2.2× |
| Intel Atom C3538 (Denverton) | x86-64 | SSSE3 (no AVX) | 1.5× |
| Apple M5 Max † | arm64 | NEON | 7.8× |
| Arm Cortex-A72 | arm64 | NEON | 1.4× |
| Arm Neoverse N1 | arm64 | NEON | 1.8× |
| Arm Neoverse V2 | arm64 | NEON | 1.9× |

† From an older release, awaiting a re-measure.

The Apple row is CPU only, against par2cmdline-turbo's published macOS arm64
binary.

Every case on every machine, the method and the versions measured are in
[the rarpar benchmarks](https://github.com/scryer-media/rarpar/blob/main/docs/benchmark.md).

## Provenance

This is an independent Rust implementation, heavily informed by
[par2cmdline-turbo](https://github.com/animetosho/par2cmdline-turbo), Anime
Tosho's speed-focused fork of
[par2cmdline](https://github.com/Parchive/par2cmdline). Both are
GPL-2.0-or-later, and par2cmdline-turbo is what the speed figures compare
against.

The PAR2 format is specified in the
[Parity Volume Set Specification 2.0](https://parchive.sourceforge.net/docs/specifications/parity-volume-spec/article-spec.html).

Changes by version are in [CHANGELOG.md](https://github.com/scryer-media/rarpar/blob/main/crates/par2-rs/CHANGELOG.md).

## License

Apache-2.0 from version 0.10.11 onward. See
[LICENSE](https://github.com/scryer-media/rarpar/blob/main/crates/par2-rs/LICENSE).
Releases before 0.10.11 stay under GPL-3.0-or-later.

The AArch64 MD5 assembly comes from AWS-LC (originally OpenSSL), also under
Apache-2.0. The repository's tests adapted from par2cmdline stay GPL and are
not part of the published crate.
