# Changelog

## 0.4.1

This is a patch release from 0.4.0: kernel selection, code-memory accounting,
and a new kernel, all behind the existing public surface. No public item
changed shape, so it stays inside the 0.4.x compatibility range.

### Runtime Behavior

- GF(2¹⁶) kernel selection for the accumulate path now mirrors the reference
  tool's ladder arm for arm: the GFNI affine kernel when GFNI exists, a new
  512-bit shuffle2x kernel on AVX512BW/VL-without-GFNI silicon (honoring the
  existing `WEAVER_GF16_SHUFFLE2X_AVX512` pin), the AVX2 XOR-JIT behind the
  fast-JIT CPU gate, and the 256-bit shuffle kernel as the remaining AVX2
  fallback. The previous ladder admitted XOR-JIT above the AVX2 line, which
  measured badly on AVX-512-without-GFNI hosts.
- The new 512-bit shuffle2x kernel is the split-layout shuffle widened to
  zmm: two destination blocks per iteration with all 24 table registers
  resident and a pairwise lane-swap fold, single-group by register math (the
  shuffle needs 4 table registers per source where affine needs 2, so the
  GFNI pair shape cannot fit).
- The AVX2 XOR-JIT builds ONE sealed multi-row batch per input batch and
  recycles it across stripes — never a build per output row. The coefficient
  rows depend only on the input batch and the recovery exponents, never the
  stripe, so codegen, mapping, and both W^X transitions happen once where
  they previously happened per row per stripe.

### Fixed

- Packed-arena admission bounds were wrong in both directions and are now
  derived from the emitter itself. The AVX-512 prefix-family layout's
  per-factor slot model structurally undercounted (a real 12-factor arena
  needed 49241 bytes against a 49152-byte grant — failing every real PAR2
  create on AVX-512-without-GFNI hosts); the bound is now exact
  per-instruction encodings times the worst dependency popcount over the
  whole GF(2¹⁶) factor domain, pinned by an exhaustive test. The AVX2 bound
  over-reserved in the other direction (~1 GiB modeled against ~84 MiB
  actual on a maximal multi-row build) and is now capped at the coefficient
  domain, since a build deduplicates bodies by factor and can never retain
  more than 65535.

## 0.4.0

This is a minor release from 0.3.0 with source-compatible additions only; no
existing API changed shape.

### Public API

- Metal GF16 sessions gained explicit planning and admission:
  `metal_gf16_memory_plan`, `MetalGf16MemoryPlan`, `MetalGf16PlanError`,
  `MetalGf16AdmissionError`, `MetalGf16Buffer`, `try_new_explicit`,
  `try_new_with_source_capacity`, and `finish_chunk_into`.
- Packed XOR-JIT batches gained up-front memory estimation:
  `PackedJitBatch::memory_upper_bound` and `PackedMemoryEstimate`, so callers
  can admit JIT arenas against a budget before building.

### Runtime Behavior

- GF16 kernel and dispatch refinements behind the existing public surface;
  benchmark methodology and results are documented in the dependent crates'
  READMEs.

## 0.3.0

This is a minor release from 0.2.3.

### Public API

- Added `xor_jit::packed`, including bounded packed batches, reusable
  workspaces, immutable AVX2 codebooks, explicit execution scratch, and code
  memory accounting.
- Added packed and prefetch-aware builders and runners on `JitWidth` and
  `PackedJitCode`.
- Added `strict_wx_available()` so callers can test whether executable memory
  can complete a writable-to-executable-to-writable round trip.

Existing scalar, matrix, RAR recovery, and `gf_simd` entry points remain
available. Callers using the new packed unsafe APIs must uphold the pointer,
length, alignment, and lifetime contracts documented on `PackedRun` and its
runner methods.

### Runtime Behavior

- XOR-JIT code follows strict W^X: mappings are writable while generated and
  executable only after sealing. Active mappings are returned to writable
  state only after all workers release them.
- Packed AVX2 generation uses bounded fixed slots and runtime CPU dispatch;
  release binaries are not specialized with `target-cpu`.
- The declared minimum supported Rust version is 1.97.1.

