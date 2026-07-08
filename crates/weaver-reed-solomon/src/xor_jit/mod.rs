//! XOR-JIT GF(2^16) multiply tier for pre-GFNI x86 (see `scryer-docs/plans/125`).
//!
//! Runtime-dispatched when AVX2 is present but GFNI is not. Reconstruction
//! multiply is JIT-generated as bit-plane XOR sequences, which run on the four
//! vector-ALU ports instead of the two shuffle ports that bound the shuffle2x
//! tier — matching the method ParPar/par2cmdline-turbo auto-selects on AMD.
//!
//! Build order (each phase validated before the next):
//! 1. [`emit`] — the x86-64 machine-code emitter (byte-exact unit tests).
//! 2. `memory` — W^X executable buffers.
//! 3. `transpose` — the 16-plane bit-transpose prepare/finish.
//! 4. `deps` + `codegen` — factor -> vpxor schedule.

pub mod codegen;
pub mod deps;
pub mod emit;
pub mod memory;
pub mod transpose;
