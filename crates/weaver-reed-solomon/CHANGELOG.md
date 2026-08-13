# Changelog

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

