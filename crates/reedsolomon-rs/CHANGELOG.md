# Changelog

## 0.4.3

### Public API

- `avx512bmm_detected` reports the AMD AVX512BMM CPUID feature, and
  `avx512bmm_enabled` reports whether its kernel tier may run. The tier remains
  deliberately disabled until a bit-exact kernel is implemented and validated,
  so dispatch behavior is unchanged on every current CPU.


## 0.4.2

This is a patch release from 0.4.1: wider aarch64 CLMUL passes, a
block-interleaved input-batch layout with one additive entry point, and
instruction diets on existing kernels. No existing public item changed shape
or meaning, so it stays inside the 0.4.x compatibility range.

### Public API

- `mul_acc_input_batch_prepared_interleaved`: the grouped-input multiply-
  accumulate over a **block-interleaved** batch — `lanes` source regions sharing
  one contiguous stream, lane `l`'s block `b` at
  `(b * lanes + l) * INPUT_BATCH_BLOCK_BYTES` — instead of one slice per source.
  A pass over such a group reads one sequential stream plus its destination
  rather than `lanes + 1` regions at a shared offset, so it needs two cache ways
  rather than `lanes + 1` however the regions are strided. Same arithmetic, same
  bytes, same dispatch rule (CLMUL above three live sources, VTBL below it);
  `lanes == 1` is the lane-major layout and behaves exactly like
  `mul_acc_input_batch_prepared`. Targets without a grouped-input vector kernel
  get a portable definition of the layout rather than nothing.
- `INPUT_BATCH_BLOCK_BYTES` and `INPUT_BATCH_INTERLEAVE_LANES`: the layout's
  block granularity (32 bytes, the `vld2q`/`vst2q` strip the grouped-input
  kernels step by) and the interleave width a caller should stage for — the
  sixteen sources the wide aarch64 CLMUL pass folds, and 1 elsewhere, where
  the grouped-input kernels walk one source region at a time and lane-major
  is what they want. Sixteen was measured against eight on the interleaved
  layout once the wide pass existed: +3.9% on the Apple fused flavour and
  +11.8% on the EOR3-merge flavour, because an eight-source pass over a
  sixteen-wide stream reads every other block where the wide pass reads the
  stream densely.

### Runtime Behavior

- The aarch64 CLMUL input-batch kernels fold sixteen sources into one pass
  over the destination where they folded eight. The pass's fixed per-block
  work — the destination `LD2`/`ST2` read-modify-write, the packed Barrett
  reduction, and the fold — is charged once however many sources it carries,
  and sixteen divides it twice as far: (32 + 16×12)/16 ≈ 14.0 vector issue
  slots per source against 138/8 ≈ 17.25. The extra live coefficients spill,
  and a spill reload is a load-pipe uop on a kernel whose vector pipes are the
  binding resource (~98% occupancy on a Neoverse V2 model, load pipes half
  idle). Partial groups keep the eight-source shape, so every width the kernel
  generated before is emitted unchanged.
- The aarch64 CLMUL and VTBL grouped-input kernels now take a source *block
  stride*, so they can consume either staging layout. On the lane-major layout
  the emitted loop is instruction-for-instruction what it was — LLVM folds the
  second induction variable away against the constant stride — and the
  interleaved loop pays 8 instructions per 32-byte block at eight sources
  (one `add`, six `mov`, one `ldr`; the 48 `pmull` are unchanged).
- The aarch64 CLMUL kernels emit `PMULL`/`PMULL2` directly through
  single-instruction inline asm for their high-half products. The intrinsic
  spelling let LLVM see that each broadcast coefficient's high half equals its
  low half and rewrite the multiply as `ext` plus a low `pMULL` — two
  instructions in place of one on three of the six products of every source.
  Instructions per 256 bytes of source at eight live sources: 191 → 166 on the
  plain-NEON flavour, 170 → 153 on the EOR3-merge flavour, 157 → 147 on the
  Apple fused flavour, with every `ext` gone. The reference encoder blocks the
  same rewrite the same way.
- Adjacent groups now fuse into a single twelve-source destination pass on
  AVX512BW/VL-without-GFNI silicon, mirroring the reference's multi-region
  shape (`idealInputMultiple` 3 for `SHUFFLE_AVX512`, 6 for
  `SHUFFLE2X_AVX512`) at twelve regions. `vpshufb` looks up per 128-bit lane,
  so one table register can serve *two* sources rather than holding one
  source's table twice — four registers per source pair, twelve sources in
  the same 24 zmm the single-group kernel spends on six. The per-source
  `vinserti64x4` that built a zmm from two 32-byte staging blocks is gone
  with it: 62 vector ALU ops (31 port-5-only) per twelve source-block
  operations become 58 (26), and each destination block is read and written
  once per twelve sources instead of once per six. Same arithmetic, same
  bytes; `WEAVER_GF16_SHUFFLE2X_PAIR=0` pins the previous single-group loop
  shape for A/B.
- `WEAVER_GF16_CLMUL_APPLE_FUSION=0` selects the non-Apple EOR3-merge SHA3
  flavour on Apple silicon, which also has FEAT_SHA3, so the flavour a
  Neoverse part runs can be disassembled and A/B'd there. Off Apple there is
  only one SHA3 flavour and the check folds away; the environment is never
  read.

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
