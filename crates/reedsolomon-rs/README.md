# reedsolomon-rs

[![crates.io](https://img.shields.io/crates/v/reedsolomon-rs.svg)](https://crates.io/crates/reedsolomon-rs)
[![docs.rs](https://docs.rs/reedsolomon-rs/badge.svg)](https://docs.rs/reedsolomon-rs)

GF(2⁸), GF(2¹⁶), and additive Cantor-transform kernels for PAR2, PAR3, and RAR
recovery. Field representations and codec geometry must match the caller's format.

```toml
[dependencies]
reedsolomon-rs = "0.4"
```

This crate provides arithmetic kernels and RAR-specific recovery coders; it
does not scan or repair PAR archive sets. Use [`par2-rs`] or
[`par3-rs`](https://crates.io/crates/par3-rs) for those workflows. Packet layout,
matrix selection, resource budgets, and job policy belong to callers.

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

See [Cantor transform measurements](https://github.com/scryer-media/rarpar/blob/main/crates/reedsolomon-rs/FFT_BENCHMARKS.md) for the reproducible
CPU comparison harness and the limits of the exploratory native results.

- `gf`: scalar GF(2¹⁶) arithmetic shared by PAR2 and RAR5.
- `gf8`: GF(2⁸) arithmetic with reusable multiplication plans and runtime
  NEON, AVX2, or SSSE3 dispatch, with a scalar fallback.
- `fft`: clean-room additive transforms and erasure locator factors over
  GF(2⁸) and GF(2¹⁶) in Cantor representation. Butterfly multiplication uses
  Cantor-derived SIMD maps with an explicit scalar oracle. Codec geometry,
  interleaving, allocation budgets, and worker policy belong to callers.
  `transform_in_pool` distributes butterfly pairs inside an explicitly supplied
  Rayon pool, with cancellation and synchronous execution for small stripes.
- `gf_simd`: multiply-accumulate kernels, including `mul_acc_region` for one
  source and destination, `mul_acc_multi_region` for one source and multiple
  destinations, and `mul_acc_input_batch` for multiple sources and one
  destination. `LinearMap16` also applies caller-defined binary maps using
  NEON/AVX2/SSSE3 shuffles and representation-independent scalar tails.
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

Versioned API and migration notes are in [CHANGELOG.md](https://github.com/scryer-media/rarpar/blob/main/crates/reedsolomon-rs/CHANGELOG.md).

## License

GPL-3.0-or-later. See [LICENSE](https://github.com/scryer-media/rarpar/blob/main/crates/reedsolomon-rs/LICENSE).

[`par2-rs`]: https://crates.io/crates/par2-rs
