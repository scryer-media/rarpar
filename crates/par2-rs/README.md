# par2-rs

[![crates.io](https://img.shields.io/crates/v/par2-rs.svg)](https://crates.io/crates/par2-rs)
[![docs.rs](https://docs.rs/par2-rs/badge.svg)](https://docs.rs/par2-rs)

PAR2 verification and repair in pure Rust. No C bindings, no external `par2`
binary.

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

`Par2Repairer` drives the full sequence: scan, verify, solve, repair, verify
again.

`Par2RepairSession` retains verification evidence while a download is still
arriving, so assessment is incremental and repair uses what is already known.
Its source can be files under a base directory, a `FileAccess` implementation,
or an already-parsed set; repair output is always real files.

## Capabilities

- All PAR2 packet types: Main, File Description, IFSC, Recovery Slice, Creator.
- Packets from any number of `.par2` files aggregate into one set.
- Slice-level verification from IFSC CRC32 + MD5 pairs, so damage is localised
  rather than condemning a whole file.
- 16 KB quick-check for cheap file identification; full-file MD5 for sets with
  no IFSC data.
- Placement-aware repair: renamed and moved files are matched by content.
- Malformed or truncated packets are skipped by scanning forward, rather than
  failing the set.

## Verifying data that is not on disk

`verify_all` reads through the `FileAccess` trait. `DiskFileAccess` is the
ordinary implementation, but supplying your own allows verification against
bytes that are still arriving over a network, or that are assembled from a
source with no file paths at all.

## Crypto backend

MD5 has two interchangeable backends, chosen at compile time.

- `crypto-native` *(default)*: the crate's own assembly on x86-64 and
  little-endian AArch64, AWS-LC's MD5 block functions carried into `asm!`.
  No C toolchain and no crypto library, and it is the configuration the
  performance figures below were measured with. Every other target uses
  RustCrypto `md-5`.
- `crypto-rust`: the portable RustCrypto `md-5` implementation on every
  target. Expect slower hashing on x86-64; the digests are of course
  identical.

The assembly is here because RustCrypto `md-5` dropped its assembly after
0.10.0, and its pure-Rust MD5 is about 25% slower on x86-64, where MD5 is the
serial floor of verify, scan and create. Linking `aws-lc-sys` for one block
function was heavy, and its version-keyed `links` gave consumers a second
AWS-LC build whenever their own `aws-lc-rs` linked another version.

To use RustCrypto everywhere:

```toml
par2-rs = { version = "0.10", default-features = false, features = ["crypto-rust"] }
```

`crypto-aws-lc` and `native-crypto` stay as aliases for `crypto-native`, so
dependency declarations written against the old names keep resolving to the
fast backend. On x86-64 and AArch64, enabling neither backend is a compile
error rather than a silent choice.

## Feature flags

- `metal` / `wgpu`: GPU-accelerated repair through `reedsolomon-rs`, with CPU
  fallback when no suitable device or driver is present. On native Apple
  Silicon, `metal` also enables policy-driven creation through
  `CreationBackend`.

## Performance

`2.0×` means `rarpar` finished in half the time:

| CPU | Arch | Instruction set | par2 (heavy) |
|---|---|---|---:|
| AMD EPYC 9R14 (Zen 4) | x86-64 | GFNI + AVX-512 | 1.8× |
| Intel Xeon Platinum 8488C (Sapphire Rapids) | x86-64 | GFNI + AVX-512 | 1.7× |
| Intel Core i5-1240P (Alder Lake) | x86-64 | GFNI + AVX2 | 1.9× |
| AMD Ryzen 5 3600 (Zen 2) | x86-64 | AVX2 | 1.5× |
| Intel Atom C3538 (Denverton) | x86-64 | SSSE3 (no AVX) | 1.3× |
| Apple M5 Max | arm64 | NEON | 7.1× |
| Arm Cortex-A72 | arm64 | NEON | 1.2× |
| Arm Neoverse N1 | arm64 | NEON | 1.4× |
| Arm Neoverse V2 | arm64 | NEON | 1.5× |

The Apple row is the CPU lane, measured against upstream's published macOS
arm64 reference binary.

Per-case charts for every machine, the full methodology, and the versions
these numbers were measured with:
[**rarpar benchmarks**](https://github.com/scryer-media/rarpar/blob/main/docs/benchmark.md).

## Provenance

This is an independent Rust implementation, heavily informed by
[par2cmdline-turbo](https://github.com/animetosho/par2cmdline-turbo), Anime
Tosho's speed-focused fork of
[par2cmdline](https://github.com/Parchive/par2cmdline). Both are
GPL-2.0-or-later. That work is also the benchmark reference this crate is
measured against.

The PAR2 format itself is specified in the
[Parity Volume Set Specification 2.0](https://parchive.sourceforge.net/docs/specifications/parity-volume-spec/article-spec.html).

Versioned API and migration notes are in [CHANGELOG.md](https://github.com/scryer-media/rarpar/blob/main/crates/par2-rs/CHANGELOG.md).

## License

GPL-3.0-or-later. See [LICENSE](https://github.com/scryer-media/rarpar/blob/main/crates/par2-rs/LICENSE).

[`reedsolomon-rs`]: https://crates.io/crates/reedsolomon-rs
