# reedsolomon-rs

High-performance Reed-Solomon finite-field kernels for parity and archive
repair — the GF(2¹⁶) arithmetic that PAR2 repair and RAR recovery records are
built on.

```toml
[dependencies]
reedsolomon-rs = "0.2"
```

This is a **kernel crate**, not a codec: it provides the field arithmetic and
multiply-accumulate primitives, and leaves matrix semantics to its callers. If
you want to verify or repair a PAR2 set, use
[`par2-rs`](https://crates.io/crates/par2-rs), which is built on this.

## What it provides

- `gf` — GF(2¹⁶) arithmetic shared by PAR2 and RAR5.
- `gf_simd` — SIMD multiply-accumulate kernels, selected at **runtime** from the
  CPU's actual features rather than at compile time, so one binary runs the best
  available tier on the machine it lands on.
- RAR-specific coders in separate modules, kept apart deliberately so PAR2
  matrix semantics stay unchanged.

## GPU backends

Optional `metal` and `wgpu` features add GPU-accelerated repair for large
workloads. Both fall back to CPU whenever a suitable device or driver is
unavailable — enabling a feature never makes a build refuse to run.

## Related crates

- [`par2-rs`](https://crates.io/crates/par2-rs) — PAR2 verification and repair.
- [`unrar-rs`](https://crates.io/crates/unrar-rs) — RAR reading and extraction.

## Licence

GPL-3.0-or-later.
