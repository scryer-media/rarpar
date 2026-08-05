# par2-rs

[![crates.io](https://img.shields.io/crates/v/par2-rs.svg)](https://crates.io/crates/par2-rs)
[![docs.rs](https://docs.rs/par2-rs/badge.svg)](https://docs.rs/par2-rs)

PAR2 verification and repair in pure Rust. No C bindings, no external `par2`
binary.

```toml
[dependencies]
par2-rs = "0.2"
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

Repair is backed by [`reedsolomon-rs`], which selects GF(2¹⁶) SIMD kernels at
runtime from the host CPU's features. Optional `metal` and `wgpu` features add
GPU-accelerated repair, both falling back to CPU when no suitable device is
present.

## Provenance

This is an independent Rust implementation, heavily informed by
[par2cmdline-turbo](https://github.com/animetosho/par2cmdline-turbo), Anime
Tosho's speed-focused fork of
[par2cmdline](https://github.com/Parchive/par2cmdline). Both are
GPL-2.0-or-later. That work is also the benchmark reference this crate is
measured against.

The PAR2 format itself is specified in the
[Parity Volume Set Specification 2.0](https://parchive.sourceforge.net/docs/specifications/parity-volume-spec/article-spec.html).

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).

[`reedsolomon-rs`]: https://crates.io/crates/reedsolomon-rs
