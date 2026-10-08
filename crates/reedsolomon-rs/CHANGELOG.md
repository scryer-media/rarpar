# Changelog

## 0.4.10 (2026-10-08)

- Relicensed from GPL-3.0-or-later to Apache-2.0. Releases up to 0.4.9 stay
  under GPL-3.0-or-later. No code changed. The README now credits the
  GF(2^16) kernels ported from ParPar, which is public domain or CC0.

## 0.4.9

- `rar3::Rar3RsCoder::decode_matrix(total, erasures)` returns the RAR3
  decoder for one erasure set as a dense GF(2^8) matrix, one row per erasure
  and one column per block position. It is built by running `decode` on each
  unit vector, so it is the scalar decoder's own map, bit for bit, and it
  refuses exactly the shapes `decode` refuses.
- `decode_apply::apply_decode_matrix_gf8` applies such a matrix to whole
  regions: one rayon task per output row and stripe (16 to 256 KiB), each
  folding groups of sources through `gf8::mul_acc_input_batch`. Zero
  coefficients are skipped. The output does not depend on the stripe size,
  thread count or kernel tier.
- `decode_apply::apply_decode_matrix_gf16` is the same driver over GF(2^16),
  folding groups through `gf_simd::mul_acc_input_batch_prepared` with every
  coefficient prepared once per matrix rather than once per stripe.
- `rar5::Rar5RsCoder::apply_units` rebuilds every missing row from all the
  logical units of a chunk at once through `apply_decode_matrix_gf16`, and
  `Rar5RsCoder::matrix` exposes the inverted decode rows. The result is the
  one a full `update_outputs` pass leaves.
- `Rar3RsCoder::decode` rebuilds its cached erasure locator when the block
  length changes, not only when the erasure set does; a coder reused across
  blocks of different lengths with the same erasures no longer corrects the
  wrong positions. `decode_matrix` derives its matrix from fresh locator
  state rather than from whatever block the coder decoded last.

## 0.4.8

- SVE2 tiers on aarch64. On a host that reports SVE2, these NEON kernels hand
  over to vector-length-agnostic SVE2 loops: GF(2^8) `mul_acc_region`,
  `MulPlan::accumulate` and `gf8::mul_acc_input_batch` (eight sources per
  pass, table pairs held in registers); GF(2^16) `mul_acc_region`; the
  `LinearMap8` multiply-accumulate, fused butterfly and radix-4 on rows of
  at least 1 KiB; and the lane-major `mul_acc_input_batch` and
  `mul_acc_input_batch_prepared` through a nibble table kernel, for up to
  three sources or when `WEAVER_GF16_CLMUL_BATCH=0` turns the carry-less
  batch off. Above three sources the NEON carry-less
  batch stays, because it measured ahead of both SVE2 forms on Graviton 4.
  `LinearMap16`, the `LinearMap8` map-in-place kernel, rows under 1 KiB,
  the interleaved grouped-input layout and `mul_acc_multi_region` stay on
  NEON, where the SVE2 forms measured level or behind. Each loop is
  predicated with `whilelo`, so there is no scalar tail, and the same code
  runs at any vector length. `gf_simd::uses_sve2` reports the tier,
  `LinearKernel` still reports `Neon`, and `WEAVER_SVE2=0` pins NEON. Output
  is bit-identical.
- The SVE2 kernels are inline `asm!` confined to one private module, because
  the SVE intrinsics are unstable on Rust 1.97 (`stdarch_aarch64_sve`). Each
  kernel is a whole loop in one `asm!` block, so no scalable register crosses
  a Rust boundary. The GF(2^8) maps use `tbl` nibble lookups, not `pmul`.
  A constant multiply by polynomial products costs about twice the
  instructions of two lookups, and the FFT maps are arbitrary linear maps
  rather than field products.
- `gf_simd::LinearMap8` is an 8-bit linear map beside `LinearMap16`: two
  nibble tables built from the caller's basis images, run through the existing
  `gf8` NEON, AVX2, SSSE3 and scalar kernels. `TransformField` gains
  `scale_u8_with_backend`, `transform_u8_with_backend`, `transform_u8_in_pool`
  and `derivative_u8`, so a GF(2^8) FFT codec works on byte rows instead of
  zero-extended `u16` rows. The 16-bit methods are unchanged.
- Fused butterfly and radix-4 kernels for every tier on both lanes: each
  butterfly loads and stores its row pair once, and two levels of the transform
  run per sweep when the vector maps run. Output is bit-identical to the
  radix-2 sequence; the scalar oracle still runs radix-2.
- `transform_known_zero_with_backend`, `transform_u8_known_zero_with_backend`,
  `transform_known_zero_in_pool` and `transform_u8_known_zero_in_pool` take one
  flag per row that the caller knows to be zero (padding past the inputs,
  erased rows before an inverse transform) and skip or reduce the butterflies
  those rows feed. Flags come from the layout; rows are never scanned.
- Scaling runs in place on every tier, with no bounce buffer, and
  `TransformField::scale_le_bytes_with_backend` unpacks little-endian byte
  pairs into scaled `u16` rows in one pass. The range check for `u16`
  rows on GF(2^8) is a vectorised fold; GF(2^16) and byte rows make no check
  pass. A radix-2 scale step with a known-zero left row is one accumulate,
  copy or product instead of a butterfly. `derivative_in_pool` and
  `derivative_u8_in_pool` store each row once and split columns across the
  pool; the sequential derivative also stores each row once.
- On x86_64 hosts with GFNI and AVX2, the AVX2 tier of `LinearMap8` and
  `LinearMap16` (multiply-accumulate, map, fused butterfly and radix-4) runs
  as `vgf2p8affineqb` affine transforms. Each byte map is one 8x8 bit matrix
  built from the images of the eight unit bits, so an 8-bit map is one
  instruction per 32 bytes instead of two shuffles and the nibble masking, and
  a 16-bit map is four instead of eight shuffles. `LinearKernel` still reports
  `Avx2`; the new `gf_simd::linear_uses_gfni` says whether the affine form is
  in use, and `WEAVER_LINEAR_GFNI=0` pins the shuffle form. Output is
  bit-identical.
- The formal derivative's column XOR runs as one AVX2 pass on x86_64: every
  source folds into a register pair per 64 bytes and the row stores once, on
  the sequential and pooled paths. aarch64 is unchanged.
- Benches: `kernel_ceiling` reports single-thread GiB/s for the GF(2^8) and
  GF(2^16) multiply-accumulate kernels, the fused batch kernels and memory
  baselines; `fft_transform` gains the u8-vs-u16, pooled and known-zero groups
  and prints which linear kernel runs.
- The GF(2^16) GFNI batch kernels accumulate in byte planes: the destination
  strip is split into its low and high bytes once, every source's four
  affine products land in the planes, and the planes merge once before the
  store, instead of splitting and merging around every source. On AVX-512
  hosts with VBMI the planes come from `vpermt2b` over 128-byte strips and
  the matrices broadcast from memory; `WEAVER_GF16_GFNI_VBMI=0` pins the
  previous interleaved kernel. The AVX2 kernels do the same with shuffles and
  unpacks. Output is bit-identical. Sixteen-source batch ceiling at 64 KiB:
  Zen 4 41.8 → 50.1 GiB/s, Sapphire Rapids 36.7 → 48.7 GiB/s, Alder Lake
  (AVX2) 30.0 → 31.2 GiB/s.
- `gf_simd::input_batch_width` reports how many sources the grouped
  multiply-accumulate folds per destination pass on this host, or 1 where the
  single-source kernel is faster than the grouped one (AVX-512 without GFNI,
  AVX2 without GFNI), so a caller can fold source by source there.
- The planar AVX-512 kernel prefetches each source four strips ahead of its
  loads: one load instruction streaming eight sources defeats an IP-stride
  prefetcher, and the loads outrun the L1 fill at 64 KiB blocks on Sapphire
  Rapids. `WEAVER_GF16_VBMI_PF=0` pins the plain loop. Create encode at one
  worker, 1 GiB, 100 rows: Sapphire Rapids 2.48 → 2.21 s at 1 MiB blocks and
  2.62 → 2.25 s at 64 KiB; Zen 4, whose hardware prefetcher keeps up, 2.09 →
  2.12 s and 2.04 → 2.10 s.
- `gf8::mul_acc_input_batch` is the grouped GF(2^8) multiply-accumulate:
  the destination strip stays in registers while eight sources stream past
  it, so it is read and written once per group instead of once per source.
  GFNI AVX-512 and AVX2 kernels apply one `vgf2p8affineqb` per vector per
  source; the AVX2 and NEON kernels apply the split-nibble map; every other
  tier folds source by source through `MulPlan::accumulate`, which
  `gf8::input_batch_width` reports as width 1 (`WEAVER_GF8_BATCH=0` pins
  that answer everywhere). `MulPlan::accumulate` itself
  now takes the GFNI form on x86_64 hosts that have it, 512-bit where
  AVX512BW/VL are present; `WEAVER_GF8_GFNI=0` pins the nibble shuffles for
  both. The 512-bit grouped kernel prefetches each source two strips ahead
  (`WEAVER_GF8_PF=0` pins the plain loop): create encode at one worker,
  1 GiB, 100 rows, 8 MiB blocks, Sapphire Rapids 2.07 → 1.87 s and Zen 4
  2.10 → 2.03 s on top of the grouping. Output is bit-identical.
- Transforms and derivatives run a bank in column tiles, in place. On a
  target that tiles (`fft::COLUMN_TILES`: every target but Apple silicon),
  a bank of three levels or more beyond `fft::TRANSFORM_TILE_BYTES`
  (512 KiB) runs a pass at a time, each pass a tile at a time: a group of
  rows at a window of columns, which takes every sweep of the pass while
  it stays in the cache. One pass over every row when the domain is short
  enough for a window of 2 KiB rows, otherwise two split at the middle
  level, the low levels over blocks of consecutive rows and the high levels
  over rows a block apart. With a pool the workers take the tiles of a
  pass; without one the calling thread runs them, so a lone worker tiles
  too. A tiled transform takes no scratch: it keeps the butterflies of
  every sweep, prepared once for all the tiles, which `walk_units_bytes`
  reports, and `walks` says whether a transform tiles at all. A tiled
  derivative differentiates each tile into scratch as large as the tile,
  at most half of `TRANSFORM_TILE_BYTES` a worker and the bank across all
  of them. Rows flagged zero before a pass are not visited. Apple silicon
  streams the whole-row sweeps about as fast as the tiles run, on one
  worker and on a pool, so there every transform and derivative sweeps
  whole rows as before, a level at a time across a pool's workers, and
  takes no scratch. Output is bit-identical.
- `fft::RowBank` holds equally wide rows of 8- or 16-bit symbols in one
  zeroed, page-aligned allocation, and hands out one slice per row:
  `zeroed`, `rows_mut`, `row` and `allocation_bytes`, which a caller can
  charge before it allocates. A row a whole multiple of 512 bytes wide is
  followed by one cache line of padding (`RowBank::ROW_PAD` at most), so
  rows a power of two apart, which a tile holds, do not all start in the
  same cache set. On Linux x86_64 a bank of 2 MiB or more is mapped on its
  own and asks for transparent huge pages, so the rows of a tile, each a
  page of its own at base pages, share a few translations: without that,
  the tiled erasure decode below ran 6–16% slower than the slab walk it
  replaces. The row-slice methods take a bank's rows as well as `Vec`s:
  `transform_rows` and `transform_u8_rows` (with `zero` flags, a pool or
  none), `transform_rows_adding` and `transform_u8_rows_adding`, which add
  each tile of the result into a second bank as the last pass leaves it,
  so an encoder's running sum costs no pass of its own, and
  `differentiate_rows` and `differentiate_u8_rows`; `derivative_at` and
  `derivative_u8_at` take any row slices too.
- Against the slab walk that gathered rows into per-worker scratch, which
  this release carried until the tiles replaced it, on Sapphire Rapids
  (GF(2^16), 1.5 GiB of 32 KiB blocks, 4916 recovery blocks, 2000 lost):
  create 4.09 → 3.27 s and CPU 3.25 → 2.43 s at one worker, 2.87 → 2.42 s
  and CPU 4.46 → 3.88 s at eight; the repair's decode 6.37 → 6.05 s at one
  worker and 4.06 → 3.56 s at eight. GF(2^8), 512 MiB of 4 MiB blocks,
  eight lost: decode 0.86 → 0.69 s and 0.74 → 0.68 s, CPU 1.26 → 1.09 s and
  2.31 → 1.88 s. The AVX2 and GFNI tier the same host takes without
  AVX-512 moves the same way. On an M-series, which does not tile, the same
  creates and repairs stay within 3% of the slab-walk build's wall and CPU
  at 1, 8 and 18 workers.
- x86_64 hosts with AVX512BW but no GFNI (Skylake-SP and its server
  successors before Ice Lake) run the GF(2^8) one-source and grouped
  multiply-accumulate kernels as `vpshufb` nibble shuffles on 512-bit
  vectors; only whole 64-byte strips take the 512-bit form and the tail
  runs the existing kernels. `gf8::kernel_name` reports the tier in use, and
  `WEAVER_GF8_AVX512=0` pins the 256-bit kernels the way `WEAVER_GF8_GFNI=0`
  pins the shuffles. Output is bit-identical. 1 GiB, 100 rows, GF(2^8)
  Cauchy, Skylake-SP: create 8.24 → 6.21 s at one worker and 4.70 → 3.75 s
  at four (CPU -26% and -32%), repair 4.72 → 3.77 s and 3.15 → 2.78 s;
  one-source ceiling at 4 KiB 27.2 → 46.8 GiB/s. GFNI hosts are unchanged.
- `MulPlan::cached` returns a plan for any factor from a table built at
  compile time (`MulPlan::new` and `gf8::mul` are now `const fn`), so a
  caller that folds short rows no longer rebuilds the nibble tables and
  affine matrix per call: build-plus-accumulate at 4 KiB rises 7% on Zen 4
  and 9% on Skylake-SP with the AVX2 GFNI and nibble kernels; at 64 KiB
  and above it is neutral. `gf8::mul_acc_region` takes the cached plan.
- In `MulPlan::accumulate`, factor 0 is a no-op and factor 1 a vector XOR on
  every tier instead of a full table multiply, and the grouped kernel drops
  zero-factor sources before it forms its groups.
- `LinearMap8` runs its nibble-shuffle maps (multiply-accumulate, map, fused
  butterfly and radix-4) on 512-bit vectors on AVX512BW hosts without GFNI;
  `gf_simd::linear_uses_avx512` says whether it does and
  `WEAVER_LINEAR_AVX512=0` pins the 256-bit kernels. On Skylake-SP the u8
  lane transform of 256 rows of 4 KiB runs 386 → 280 µs, and a 1 GiB GF(2^8)
  FFT create takes about 1% less wall and 1-3% less CPU. The GFNI affine
  maps stay at 256 bits: a 512-bit form measured a wash on Zen 4 and 2-4%
  slower end to end on Sapphire Rapids, where the 512-bit units clock lower.
  Output is bit-identical.
- `kernel_ceiling` names the GF(2^8) kernel and linear forms in use and
  gains rows for `MulPlan::new` plus accumulate (the gap to the cached row
  is the table build) and for `LinearMap8::accumulate`.
- Pooled transforms and derivatives walk the bank in slabs. When a bank of
  three levels or more outgrows `fft::TRANSFORM_SCRATCH_BYTES` (512 KiB)
  and every pass of the walk has at least one slab per thread, each worker
  gathers the rows of a slab into its own contiguous scratch, runs every
  sweep of a pass over that slab and scatters the result back, in one pass
  when a window of the scratch holds 2 KiB rows and otherwise in two passes
  split at the middle level — the low levels over blocks of consecutive
  rows, the high levels over rows a block apart — so each sweep reads its
  rows from cache instead of streaming the whole bank per level. A slab's
  window is no wider than the rows split across the workers, so their
  slabs together never hold more than the bank, rounded up to whole
  64-symbol runs. Rows flagged zero before a
  pass are not gathered and rows still zero after it are not put back. A
  walked transform keeps the butterflies of every sweep while it runs,
  prepared once for all the slabs: `walk_units_bytes` says how much that
  is and `walks` whether a transform walks at all; a bank the pool would
  not walk is still swept a level at a time across the workers, which on
  the Alder Lake cores beats transforming banks of a mebibyte side by side
  on sibling threads. The derivative gathers a window of every row the
  same way and differentiates bit-major into a second copy, so each worker
  takes at most the scratch and all of them together at most twice the
  bank. The sequential
  `transform` and `derivative` sweep whole rows as before: alone, the
  kernels are bound by their own work and the copies would be pure cost.
  `fft::POOL_GATHERS` is false on Apple silicon, whose memory system
  streams the whole-row sweeps faster than the copies cost (walk 1.5 times
  and derivative twice as long as the row-parallel sweeps on an M-series),
  so there the pooled paths stay as they were and take no scratch. Output
  is bit-identical. Decode of 2048 data rows of 1 MiB over GF(2^16), 50
  lost, eight workers on four Alder Lake P-cores: 1.67 → 1.34 s, CPU
  11.3 → 8.3 s; one worker unchanged.
- `TransformField::derivative_at` and `derivative_u8_at` run an erasure
  decode's inverse transform, formal derivative and forward transform as
  one step and return only the rows the caller asks for. With the levels
  split at the middle, the steps regroup into three tiled passes over the
  bank: blocks of consecutive rows (the low half of the inverse, and for a
  block holding a requested row the whole low-level term), classes of rows
  a block apart (the high halves of both transforms around the high-level
  derivative), then only the blocks holding a requested row (the last low
  half, added into the output). The derivative never leaves the tile's
  scratch, so the bank is read and written once per pass instead of once
  per transform pass plus once per set bit of a row index; every butterfly
  takes the factor and order the separate steps take, and the rows returned
  are bit-identical to theirs. `derivative_at_bytes` is what it keeps
  beside the rows: its prepared sweeps, flags, each worker's tile scratch
  and row list, and the call's and the pool's bookkeeping, measured at
  no more than that on every engaged shape. `fft::derivative_at_walks` says
  whether a bank is large enough for the fused passes (from 16 rows of 1-
  or 2-byte symbols, beyond `TRANSFORM_TILE_BYTES`); both return nothing
  for any other symbol size and saturate rather than overflow. The
  non-exhaustive `DerivativeWork` counts the transforms and butterflies it
  performed: the inverse once, the forward once per class and twice per
  block holding a requested row, so where most blocks hold one it runs
  more butterflies than the two whole transforms. Smaller domains run the
  separate steps. `COLUMN_TILES` is the default for whether a caller takes
  the fused passes at all, on one worker as on a pool.
- `TransformField::le_image` and `le_image_mut` view a `u16` row as its
  bytes on a little-endian target, where a symbol's little-endian pair is
  its own representation, so a caller can read the on-disk layout into and
  write it from the row itself; `None` elsewhere.
- A wasm simd128 tier for `LinearMap8` and `LinearMap16`: multiply-accumulate,
  map, fused butterfly and fused radix-4 run as `i8x16.swizzle` nibble
  lookups, with byte planes split by two shuffles on the 16-bit lane. It is
  compiled only into a `+simd128` build (wasm has no runtime detection), and
  a `+relaxed-simd` build takes `i8x16.relaxed_swizzle` in the same kernels.
  `LinearKernel` still reports `Scalar` on wasm; the new
  `gf_simd::linear_uses_wasm_simd128` says whether the tier is in use. Output
  is bit-identical to the scalar oracle.
- The GF(2^16) wasm kernel covers all sixteen symbols of each 32-byte step
  instead of eight, and the GF(2^8) wasm kernels load, map and store two
  vectors per step. The 16-bit radix-4 keeps one block per step, where two
  were slower. The grouped GF(2^8) batch stays source by source on wasm: a
  grouped wasm kernel tied at 64 KiB and lost a third at 1 MiB and above.
  Single-thread GiB/s at 64 KiB under wasmtime on an Apple M5 Max (the only
  wasm host measured), previous simd128 build → this one: `gf16
  mul_acc_region` 11.1 → 19.4, `gf8 mul_acc_region` 31.7 → 40.9,
  `LinearMap8` accumulate 1.6 → 41.7, `LinearMap16` accumulate 0.8 → 19.3,
  8-bit map 1.9 → 46.3, 16-bit map 0.8 → 22.7, 8-bit butterfly 3.6 → 37.8,
  8-bit radix-4 1.2 → 34.5, 16-bit butterfly 1.7 → 32.5, 16-bit radix-4
  1.3 → 18.0.
- `kernel_ceiling` builds and runs on wasm32-wasip1 and gains rows for the
  linear-map accumulate, map, butterfly and radix-4 kernels on both lanes.

## 0.4.7

- `gf8::MulPlan` has a wasm tier. The GF(2^8) multiply-accumulate carried NEON,
  AVX2 and SSSE3 kernels and fell to the scalar loop on wasm, which is the
  kernel PAR3's Cauchy codec dispatches every region multiply through. The new
  tier takes the same split-nibble shape as the NEON one: the two precomputed
  16-byte product tables are the swizzle operands, so one `i8x16.swizzle` per
  nibble replaces sixteen table indexings. wasm has no runtime feature
  detection, so the tier is chosen at compile time from the artifact's
  `target_feature` set — `+relaxed-simd` takes `i8x16.relaxed_swizzle`, which
  is the same permutation without the lane clamp the plain form must emit on
  x86 hosts, plain `+simd128` takes `i8x16.swizzle`, and a wasm build with
  neither keeps the scalar path it always had. The scalar tail is unchanged and
  no native target is touched: the `__text` of a native build is byte-identical
  either way, on aarch64 and on x86-64.

  Under wasmtime 47 on aarch64, against the same build with the tier removed,
  a PAR3 create of a GF(2^8) set over a 16 MiB source is 3.96x faster and the
  repair that rebuilds twenty of its blocks is 4.72x; end to end the wasm
  harness's whole run is 2.79x. A set in GF(2^16), which does not reach this
  kernel, is unchanged.

## 0.4.6

- Add `gf16_dft`: PAR2 recovery and syndrome rows computed as an
  output-pruned multiplicative DFT over GF(2^16) instead of the dense
  slices x recovery-blocks product. PAR2's per-slice constants are powers of a
  primitive element, so the weighted sum is a 65535-point cyclic transform;
  65535 = 3 * 5 * 17 * 257 factors it the Good-Thomas way into short stages
  with no twiddle factors. The schedule prunes to the exponents a caller
  actually asked for and streams the length-257 dimension, so per-worker
  scratch follows the transform's row count and the stripe length, never the
  slice count or the slice size. At PAR2's ceiling (32768 slices, 6553
  recovery blocks) it performs 2,539,264 region folds where the dense product
  performs 214,728,704, measured at 96x less wall time on aarch64; it falls
  back to the dense fold count for very small output counts and never exceeds
  it. `DftPlan` is `Send + Sync` and allocation-free per stripe.
- Add `vandermonde_solve`: a closed-form PAR2 erasure solve for consecutive
  recovery exponents. `ConsecutiveSolvePlan` reconstructs the missing slices
  from the syndrome rows with a Forney-style locator and a two-stage fold —
  a correlation against the locator coefficients, then an evaluation at each
  missing input's constant — so no `m x m` matrix is built, stored, or
  inverted. The solve is stripe-wise and in place, allocates nothing, and
  overwrites the caller's syndrome rows with the answers. Non-consecutive
  exponent selections are rejected so callers fall back to `matrix`, which is
  unchanged.
- `vandermonde_solve` carries two transformed forms of the same arithmetic,
  selected by row count and pinnable through `SolveStrategy`. Stage 1 becomes
  blocked cyclic correlations of length 255 evaluated by a twiddle-free
  Good-Thomas 3x5x17 transform, with the padded inputs and unread outputs of
  its radix-17 passes pruned. Stage 2 splits the evaluation across the two
  coprime factors of the group order, `65535 = 255 * 257`, so the constants
  sharing a residue share one set of 257 partial rows. Both are bit-exact
  against the written-out form and against `matrix`; at 8192 rows and a 64 KiB
  stripe the transformed solve is 17x cheaper than applying an explicit
  inverse, before that inverse is even built.

## 0.4.5

- Add reusable GF(2^8) region arithmetic and clean-room Cantor-field FFT
  primitives for the PAR3 engine, with runtime SIMD dispatch and scalar
  fallbacks. PAR3 packet layouts and recovery geometry remain in `par3-rs`.
- Add FFT transform benchmarks and native parity coverage. Existing PAR2 and
  RAR arithmetic APIs remain compatible; GPU features remain opt-in.

## 0.4.4

A patch release from 0.4.3: one additive constant and a cheaper RAR3 decoder.
No existing public item changed shape or meaning.

### Public API

- `Rar3RsCoder::MAX_BLOCK_LEN`: the longest block `decode` accepts, data plus
  parity symbols together (255, the GF(2^8) field size less one). A RAR3
  recovery set has one symbol per volume, so this is also the largest set of
  data plus recovery volumes a caller can hand the coder.

### Performance

- `Rar3RsCoder::decode` no longer zeroes a 512-entry syndrome buffer and a
  1024-entry error-evaluator buffer on every call, nor allocates either. The
  scratch lives in the coder, only the `par_size` entries in use are cleared,
  and the polynomial multiply clears only the prefix it writes. unrar's own
  `RSCoder::Decode` has always worked this way; the per-call clearing was an
  artifact of the port. RAR3 recovery calls `decode` once per byte column, so
  on a `.rev` restore of a 33 MiB set the decode CPU time drops by roughly an
  order of magnitude.

### Fixed

- A reused `Rar3RsCoder` handed a different erasure set than its first
  `decode` saw now rebuilds its cached locator polynomial instead of
  correcting the previous call's positions. The cache exists because RAR3
  recovery decodes every column of a set with the same erasures; the check is
  a slice comparison per call.

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
