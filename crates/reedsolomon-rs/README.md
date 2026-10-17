# reedsolomon-rs

[![crates.io](https://img.shields.io/crates/v/reedsolomon-rs.svg)](https://crates.io/crates/reedsolomon-rs)
[![docs.rs](https://docs.rs/reedsolomon-rs/badge.svg)](https://docs.rs/reedsolomon-rs)

The arithmetic under PAR2, PAR3 and RAR recovery data, fast, in Rust: the
Galois-field math (GF(2⁸) and GF(2¹⁶)) and the transforms that create and
repair recovery blocks.

```toml
[dependencies]
reedsolomon-rs = "0.4"
```

This crate does the math only. To verify or repair files, use
[`par2-rs`] or [`par3-rs`](https://crates.io/crates/par3-rs). Packet formats,
which matrix to use, memory limits and threading decisions are the caller's.

## Usage

```rust
use reedsolomon_rs::gf;

// Addition is XOR, and therefore its own inverse.
assert_eq!(gf::add(gf::add(0x1234, 0x89ab), 0x89ab), 0x1234);

// Every non-zero element has a multiplicative inverse, which is what allows a
// decode matrix to be inverted and missing data recovered.
assert_eq!(gf::mul(0x89ab, gf::inv(0x89ab)), 1);
```

## What is in it

- `gf`: GF(2¹⁶) arithmetic, as PAR2 and RAR5 use it.
- `gf8`: GF(2⁸) arithmetic.
- `gf_simd`: the bulk multiply-and-add loops that do most of the work, for
  one or many inputs and outputs.
- `fft`: the transforms behind PAR3's FFT recovery, over GF(2⁸) and
  GF(2¹⁶). `transform_in_pool` spreads one transform over a Rayon pool you
  supply.
- `matrix` and `vandermonde_solve`: building and solving PAR2's repair
  equations.
- `xor_jit`: generated code for GF(2¹⁶) multiplication on x86-64 CPUs
  without GFNI.
- `rar3` and `rar5`: RAR's own recovery coders, kept separate so the PAR2
  math is untouched.

On x86-64 the fastest kernels the CPU supports (SSSE3, AVX2, AVX-512, GFNI)
are chosen at run time. AArch64 uses NEON. WebAssembly uses SIMD when the
build enables it. Scalar versions are kept as the fallback and as the
reference the SIMD kernels are tested against.

[FFT_BENCHMARKS.md](https://github.com/scryer-media/rarpar/blob/main/crates/reedsolomon-rs/FFT_BENCHMARKS.md)
has the transform measurements and how to repeat them.

## GPU

The `metal` (Apple Silicon macOS only) and `wgpu` features add GPU sessions
for GF(2¹⁶) work. A session can turn a job down (too small, unsupported
shape, no suitable device, not enough memory), and callers such as
[`par2-rs`] then stay on the CPU.

Changes by version are in [CHANGELOG.md](https://github.com/scryer-media/rarpar/blob/main/crates/reedsolomon-rs/CHANGELOG.md).

## License

Apache-2.0 from version 0.4.10 onward. See [LICENSE](https://github.com/scryer-media/rarpar/blob/main/crates/reedsolomon-rs/LICENSE).
Releases before 0.4.10 stay under GPL-3.0-or-later.

Several GF(2^16) kernels (the SSSE3 shuffle multiply-add and its block
prepare and finish steps) are ports of routines from
[ParPar](https://github.com/animetosho/ParPar) by Anime Tosho, which its
author released as public domain or CC0. The comments beside each port name
the routine it follows. The additive transforms in `fft` follow Lin,
Al-Naffouri, Han and Chung (2016), with the four-step factorization of
Samanta, Badakhshan and Gong (2026); the full references are in the
repository's
[ATTRIBUTION.md](https://github.com/scryer-media/rarpar/blob/main/ATTRIBUTION.md).

[`par2-rs`]: https://crates.io/crates/par2-rs
