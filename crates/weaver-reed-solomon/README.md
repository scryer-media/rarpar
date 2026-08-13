# reedsolomon-rs

[![crates.io](https://img.shields.io/crates/v/reedsolomon-rs.svg)](https://crates.io/crates/reedsolomon-rs)
[![docs.rs](https://docs.rs/reedsolomon-rs/badge.svg)](https://docs.rs/reedsolomon-rs)

GF(2¹⁶) Reed-Solomon kernels for parity and archive repair: the finite-field
arithmetic underneath PAR2 repair and RAR5 recovery records.

```toml
[dependencies]
reedsolomon-rs = "0.4"
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
- `gf_simd`: multiply-accumulate kernels, including `mul_acc_region` for one
  source and destination, `mul_acc_multi_region` for one source and multiple
  destinations, and `mul_acc_input_batch` for multiple sources and one
  destination.
- RAR-specific coders in separate modules, kept apart so PAR2 matrix semantics
  stay unchanged.

CPU dispatch is target-specific. x86-64 builds detect supported instructions at
runtime and select among the implemented kernels. AArch64 builds use NEON,
while WebAssembly SIMD is selected through compile-time target features.

## GPU backends

Optional `metal` and `wgpu` features expose GPU GF(2¹⁶) session backends; this
crate does not choose a repair workflow. The Metal backend is available only on
Apple Silicon macOS. The `wgpu` backend uses a suitable adapter exposed by
`wgpu`.

Automatic admission rejects workloads below 256 MiB of effective work and may
also reject a session because of configuration, adapter, shape, or allocation
constraints. Higher-level callers such as [`par2-rs`] can use that result to
stay on CPU. The admission threshold is an implementation policy, not a
performance guarantee.

Versioned API and migration notes are in [CHANGELOG.md](https://github.com/scryer-media/rarpar/blob/main/crates/weaver-reed-solomon/CHANGELOG.md).

## License

GPL-3.0-or-later. See [LICENSE](https://github.com/scryer-media/rarpar/blob/main/crates/weaver-reed-solomon/LICENSE).

[`par2-rs`]: https://crates.io/crates/par2-rs
