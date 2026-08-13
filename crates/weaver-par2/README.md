# par2-rs

[![crates.io](https://img.shields.io/crates/v/par2-rs.svg)](https://crates.io/crates/par2-rs)
[![docs.rs](https://docs.rs/par2-rs/badge.svg)](https://docs.rs/par2-rs)

PAR2 verification and repair in pure Rust. No C bindings, no external `par2`
binary.

```toml
[dependencies]
par2-rs = "0.3"
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

### rarpar release validation

These deterministic end-to-end runs use the synthetic `rarpar-bench` corpus,
one warmup, seven measured runs, canonical PAR2 placement, and SHA-256 output
validation. Windows and Linux CLI builds are CPU-only. Apple Silicon is shown
with CPU-only and Metal-capable builds. Normal runtime gating, not a force
override, chooses Metal only for qualifying heavy repairs, while verification
and smaller repairs remain on CPU. These runs include CLI discovery, repair,
and post-repair verification rather than measuring only the repair kernel.

[![PAR2 workloads on AMD Ryzen 5 3600 with Windows x86-64](https://raw.githubusercontent.com/scryer-media/rarpar/main/crates/weaver-par2/docs/rarpar-par2-benchmark-windows-x86_64.svg)](https://raw.githubusercontent.com/scryer-media/rarpar/main/crates/weaver-par2/docs/rarpar-par2-benchmark-windows-x86_64.svg)

[![PAR2 workloads on Intel Core i5-1240P with Linux x86-64](https://raw.githubusercontent.com/scryer-media/rarpar/main/crates/weaver-par2/docs/rarpar-par2-benchmark-linux-x86_64.svg)](https://raw.githubusercontent.com/scryer-media/rarpar/main/crates/weaver-par2/docs/rarpar-par2-benchmark-linux-x86_64.svg)

[![PAR2 workloads on AMD EPYC 9R14 with Linux x86-64 and AVX-512](https://raw.githubusercontent.com/scryer-media/rarpar/main/crates/weaver-par2/docs/rarpar-par2-benchmark-linux-x86_64-avx512.svg)](https://raw.githubusercontent.com/scryer-media/rarpar/main/crates/weaver-par2/docs/rarpar-par2-benchmark-linux-x86_64-avx512.svg)

[![PAR2 CPU workloads on Apple M5 Max with macOS arm64](https://raw.githubusercontent.com/scryer-media/rarpar/main/crates/weaver-par2/docs/rarpar-par2-benchmark-macos-arm64-cpu.svg)](https://raw.githubusercontent.com/scryer-media/rarpar/main/crates/weaver-par2/docs/rarpar-par2-benchmark-macos-arm64-cpu.svg)

[![PAR2 Metal repair workloads on Apple M5 Max with macOS arm64](https://raw.githubusercontent.com/scryer-media/rarpar/main/crates/weaver-par2/docs/rarpar-par2-benchmark-macos-arm64-metal.svg)](https://raw.githubusercontent.com/scryer-media/rarpar/main/crates/weaver-par2/docs/rarpar-par2-benchmark-macos-arm64-metal.svg)

### Broader library workloads

Measured against `par2cmdline-turbo 1.4.0` on the same damaged sets, across an
11-scenario differential suite. Warm-cache medians from release builds with
shipped flags; every repair is byte-compared against pristine output. Test
machines: Apple M5 Max (macOS), Intel Core Ultra 9 285H (Ubuntu 24.04), AMD
Ryzen 5 3600 (Windows, Zen 2 — no GFNI).

**Repair**

| Machine | Workload | turbo | par2-rs | |
|---|---|---:|---:|---|
| M5 Max | 4 GB set, 1 MB slices, 407 missing | 112 s | **28.5 s** | 3.9× |
| M5 Max | 2 GB set, 32,768 slices, 3,000 missing | 457 s | **95 s** | 4.8× |
| 285H | 4 GB set, 1 MB slices, 407 missing | 12.1 s | **8.1 s** | 1.5× |
| 285H | 2 GB set, 32,768 slices, 3,000 missing | **36.6 s** | 51.5 s | 0.7× |
| Ryzen 5 3600 | 4 GB set, 1 MB slices, 407 damaged | 26.3 s | **20.0 s** | 1.3× |
| Ryzen 5 3600 | 2 GB set, 32,768 slices, 3,000 damaged | **62.7 s** | 105.7 s | 0.6× |

**Verification**

| Machine | Workload | turbo | par2-rs | |
|---|---|---:|---:|---|
| M5 Max | Clean 1 GB set | 2.43 s | **0.09 s** | 27× |
| 285H | Clean 1 GB set | 0.66 s | **0.37 s** | 1.8× |
| 285H | Damaged 2 GB set, 3,000 bad blocks | 7.3 s | **5.4 s** | 1.35× |
| Ryzen 5 3600 | Clean 1 GB set | 1.70 s | **0.30 s** | 5.7× |

**GPU repair** (Apple Silicon, `metal` feature)

| Workload | turbo | CPU (NEON) | Metal | |
|---|---:|---:|---:|---|
| 512 MB set, 64 KiB slices, 1,400 missing | 78.1 s | 8.96 s | **4.10 s** | 19× |
| 76 MB set, 400 missing | 3.71 s | 0.62 s | **0.40 s** | 9× |

Verification wins on every machine: candidate windows are CRC-gated, MD5 is
confirmed only when needed, and a single file is scanned in parallel where
turbo's damaged scan is serial.

Repair is shape-dependent. The many-file case wins; the single-file,
many-slice case still trails on x86 and Windows, where turbo's ParPar
auto-selects an XOR-JIT kernel that runs the GF(2¹⁶) multiply on vector-XOR
ports rather than the saturated shuffle ports. An equivalent tier is in
progress.

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
