//! High-performance Reed-Solomon finite-field kernels for parity and archive repair.
//!
//! This is the GF(2¹⁶) arithmetic that PAR2 repair and RAR5 recovery records are
//! built on. It is a **kernel crate, not a codec**: it provides the field
//! operations and multiply-accumulate primitives and leaves matrix semantics to
//! its callers. To verify or repair a PAR2 set, reach for
//! [`par2-rs`](https://crates.io/crates/par2-rs), which is built on this.
//!
//! # The field
//!
//! [`gf`] is scalar GF(2¹⁶): addition is XOR, and the multiplicative structure
//! is what makes erasure coding work.
//!
//! ```
//! use reedsolomon_rs::gf;
//!
//! // Addition is its own inverse, which is why parity can be applied and
//! // removed by the same operation.
//! assert_eq!(gf::add(gf::add(0x1234, 0x89ab), 0x89ab), 0x1234);
//!
//! // Every non-zero element has a multiplicative inverse, which is what lets a
//! // decode matrix be inverted to recover missing data.
//! let x = 0x89abu16;
//! assert_eq!(gf::mul(x, gf::inv(x)), 1);
//! ```
//!
//! # The kernels
//!
//! [`gf_simd`] holds the multiply-accumulate routines that do the actual work —
//! [`mul_acc_region`](gf_simd::mul_acc_region) for one source and destination,
//! [`mul_acc_multi_region`](gf_simd::mul_acc_multi_region) for one source and
//! multiple destinations, and [`mul_acc_input_batch`](gf_simd::mul_acc_input_batch)
//! for multiple sources and one destination.
//!
//! CPU dispatch is target-specific. x86-64 builds detect supported instructions
//! at runtime and select among the implemented kernels. AArch64 builds use NEON,
//! while WebAssembly SIMD is selected through compile-time target features.
//!
//! RAR-specific coders live in their own modules, deliberately kept apart so
//! PAR2 matrix semantics stay unchanged.
//!
//! # Feature flags
//!
//! - `metal`: opt-in native Apple-GPU GF(2¹⁶) sessions on Apple Silicon macOS.
//! - `wgpu`: opt-in GF(2¹⁶) sessions on suitable `wgpu` adapters.
//!
//! Session admission can fail because of workload size, configuration, device,
//! shape, or allocation constraints. Callers decide whether to remain on CPU.
//!
pub mod gf;
pub mod gf_pmul;
pub mod gf_simd;
pub mod matrix;
pub mod matrix_tiled;
#[cfg(all(feature = "metal", target_os = "macos", target_arch = "aarch64"))]
pub mod metal_gf16;
pub mod rar3;
pub mod rar5;
pub mod threading;
#[cfg(feature = "wgpu")]
pub mod wgpu_gf16;
/// JIT-generated bit-plane XOR GF(2^16) multiply for pre-GFNI x86.
#[cfg(target_arch = "x86_64")]
pub mod xor_jit;
