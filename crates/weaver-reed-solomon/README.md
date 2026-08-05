# reedsolomon-rs

[![crates.io](https://img.shields.io/crates/v/reedsolomon-rs.svg)](https://crates.io/crates/reedsolomon-rs)
[![docs.rs](https://docs.rs/reedsolomon-rs/badge.svg)](https://docs.rs/reedsolomon-rs)

GF(2¹⁶) Reed-Solomon kernels for parity and archive repair: the finite-field
arithmetic underneath PAR2 repair and RAR5 recovery records.

```toml
[dependencies]
reedsolomon-rs = "0.2"
```

This is a kernel crate, not a codec. It provides field operations and
multiply-accumulate primitives and leaves matrix semantics to its callers. To
verify or repair a PAR2 set, use [`par2-rs`], which is built on this.

## Usage

```rust
use reedsolomon_rs::gf;

// Addition is XOR, and therefore its own inverse.
assert_eq!(gf::add(gf::add(0x1234, 0x89ab), 0x89ab), 0x1234);

// Every non-zero element has a multiplicative inverse, which is what allows a
// decode matrix to be inverted and missing data recovered.
assert_eq!(gf::mul(0x89ab, gf::inv(0x89ab)), 1);
```

## Contents

- `gf`: scalar GF(2¹⁶) arithmetic shared by PAR2 and RAR5.
- `gf_simd`: multiply-accumulate kernels, `mul_acc_region` for one region and
  `mul_acc_multi_region` for the many-input shape a repair pass generates.
- RAR-specific coders in separate modules, kept apart so PAR2 matrix semantics
  stay unchanged.

Kernel tier is selected at runtime from the host CPU's features rather than at
compile time, so one binary runs the best available path on whatever machine it
lands on.

## GPU backends

Optional `metal` and `wgpu` features add GPU-accelerated repair. Both fall back
to CPU when no suitable device or driver is available, so enabling a feature
never prevents a build from running.

## Provenance

The GF(2¹⁶) approach and much of the kernel design are heavily informed by
[par2cmdline-turbo](https://github.com/animetosho/par2cmdline-turbo) and the
[ParPar](https://github.com/animetosho/parpar) work it draws on, both by Anime
Tosho, and by their ancestor
[par2cmdline](https://github.com/Parchive/par2cmdline). par2cmdline-turbo is
GPL-2.0-or-later.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).

[`par2-rs`]: https://crates.io/crates/par2-rs
