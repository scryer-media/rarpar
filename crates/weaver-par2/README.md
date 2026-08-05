# par2-rs

A pure-Rust PAR2 (Parity Archive Volume Set v2.0) verification and repair
engine. No C bindings, no shelling out to `par2`.

```toml
[dependencies]
par2-rs = "0.2"
```

## What it handles

- **Every PAR2 packet type** — Main, File Description, IFSC, Recovery Slice,
  Creator — with header validation (magic, MD5, length alignment).
- **Multi-file sets**: packets from any number of `.par2` files aggregate into
  one unified set, duplicates and all.
- **Slice-level verification** using the CRC32 + MD5 pairs in IFSC packets, so a
  damaged file is localised to the slices that are actually wrong.
- **Fast identification** via the 16 KB quick-check hash, with full-file MD5
  when a set carries no IFSC data.
- **Placement-aware repair**: files that were renamed or moved are matched by
  content rather than by name, and repair verifies again afterwards.
- **Damaged input**: malformed or truncated packets are skipped by scanning
  forward for the next valid one, rather than failing the set.

## Streaming

Verification and repair run through a `FileAccess` trait rather than assuming
paths on a filesystem. Supply your own implementation and a set can be verified
against bytes that are still arriving, or that never land on disk — which is how
[Weaver](https://github.com/scryer-media/weaver) verifies Usenet downloads
against their PAR2 sets while the download is still in flight.

## Performance

Repair is backed by [`reedsolomon-rs`](https://crates.io/crates/reedsolomon-rs),
which dispatches GF(2¹⁶) arithmetic at runtime across SIMD tiers and, when the
crate's GPU features are enabled and a suitable device is present, Metal or
`wgpu`. Every GPU path falls back to CPU when no device or driver is available,
so a build is never tied to the hardware it was compiled on.

## Related crates

- [`unrar-rs`](https://crates.io/crates/unrar-rs) — RAR reading and extraction,
  the usual consumer of a repaired set.
- [`reedsolomon-rs`](https://crates.io/crates/reedsolomon-rs) — the finite-field
  kernels underneath repair.

## Licence

GPL-3.0-or-later.
