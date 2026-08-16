# par2-rs

[![crates.io](https://img.shields.io/crates/v/par2-rs.svg)](https://crates.io/crates/par2-rs)
[![docs.rs](https://docs.rs/par2-rs/badge.svg)](https://docs.rs/par2-rs)

PAR2 verification and repair in pure Rust. No C bindings, no external `par2`
binary.

```toml
[dependencies]
par2-rs = "0.4"
```

## Usage

```rust
use par2_rs::{DiskFileAccess, Par2FileSet, scan_packets_from_path, verify_all};

let packets = scan_packets_from_path("release.par2".as_ref())?
    .into_iter()
    .map(|(packet, _offset)| packet)
    .collect();
let set = Par2FileSet::from_packets(packets)?;

let access = DiskFileAccess::new("/downloads/release".into(), &set);
let result = verify_all(&set, &access);
println!("{} blocks missing", result.total_missing_blocks);
```

`Par2Repairer` drives the full sequence: scan, verify, solve, repair, verify
again.

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

## Performance

`2.0×` means `rarpar` finished in half the time:

| CPU | Arch | Instruction set | par2 (heavy) |
|---|---|---|---:|
| AMD EPYC 9R14 (Zen 4) | x86-64 | GFNI + AVX-512 | 2.3× |
| Intel Xeon Platinum 8488C (Sapphire Rapids) | x86-64 | GFNI + AVX-512 | 1.9× |
| Intel Core i5-1240P (Alder Lake) | x86-64 | GFNI + AVX2 | 2.3× |
| Intel Xeon Platinum 8124M (Skylake-SP) | x86-64 | AVX-512 | 1.8× |
| AMD Ryzen 5 3600 (Zen 2) | x86-64 | AVX2 | 1.6× |
| Intel Xeon E5-2666 v3 (Haswell) | x86-64 | AVX2 | 1.9× |
| Intel Atom C3538 (Denverton) | x86-64 | SSSE3 (no AVX) | 1.4× |
| Apple M5 Max | arm64 | NEON | 7.2× |
| Arm Cortex-A72 | arm64 | NEON | 1.2× |
| Arm Neoverse N1 | arm64 | NEON | 1.5× |
| Arm Neoverse V2 | arm64 | NEON | 1.5× |


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

Versioned API and migration notes are in [CHANGELOG.md](https://github.com/scryer-media/rarpar/blob/main/crates/weaver-par2/CHANGELOG.md).

## License

GPL-3.0-or-later. See [LICENSE](https://github.com/scryer-media/rarpar/blob/main/crates/weaver-par2/LICENSE).

[`reedsolomon-rs`]: https://crates.io/crates/reedsolomon-rs
