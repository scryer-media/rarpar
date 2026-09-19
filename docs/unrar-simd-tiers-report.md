# unrar-rs SIMD tiers: measured results

This is the record of a benchmark-gated SIMD arc in `unrar-rs`. A kernel was
kept only when a differential test proved it bit-identical to the scalar path,
a criterion microbench showed it faster where its ISA engages, and the
end-to-end `archive_hotspots` benches moved by at least 5% on a host where the
tier engages with no more than a 1% regression anywhere. Everything else is
recorded here with its numbers and dropped. Most of this arc is drops, and the
drops are the useful part: they say where the extraction path's time actually
goes, which is not where instruction-level width helps.

## Hosts

| Host | CPU | ISA ceiling | Role |
| --- | --- | --- | --- |
| Mac (local) | Apple silicon, aarch64 | NEON (no SVE) | profiling, differential tests, noisy |
| codex-x86 | Arrow Lake-H, x86-64 | AVX2 / x86-64-v3, no AVX-512 | all decisive A/B, quiet (load ~1.3) |
| SYLIX (Windows) | — | — | unused this arc |
| AWS fleet | — | — | not launched; see "AWS" below |

Measurement protocol for every A/B in this document: one binary, both arms
selected by a cached environment toggle sitting in exactly the position the
shipped runtime-detection bool sits in, so no build-to-build codegen or layout
difference can leak into the delta; interleaved rounds (base, candidate, base,
candidate, …); medians of at least five rounds; `taskset -c 0-5` on codex-x86.
Single post-build runs were never trusted, and the Mac was treated as
indicative only — a concurrent agent session kept its load average above 6 for
the whole arc, and its run-to-run spread on the PPMd benches reached ±100%.

## Step 0: baselines and profile

Baseline medians, n = 10.

| Bench | Mac | codex-x86 |
| --- | --- | --- |
| rar_solid_lz_chunked_extract | 68.9 ms | 176.3 ms |
| weaver_solid_chunked_shape | 69.8 ms | 180.1 ms |
| rar5_solid_extract_all_members | 76.2 ms | 201.5 ms |
| rar4_solid_extract_all_members | 200.9 ms | 408.9 ms |
| rar4_ppmd_restart | 214.6 ms | 392.0 ms |
| rar4_ppmd_solid_multi_member | 298.9 ms | 502.6 ms |
| rar4_ppmd_order16_32m | 6.675 s | 11.306 s |
| rar5_solid_reopen_later_member | 64.9 ms | — |
| rar_filter_e8e9 | 132.8 µs | 138.9 µs |
| rar_crc_fast_baseline | 84.8 µs | 393.7 µs |

Function shares (samply, Mac; `perf` could not be used on codex-x86 because
`kernel.perf_event_paranoid` is 4 there and changing a kernel setting was out
of scope):

- **RAR5 solid LZ** — `decode_block_symbols_counted` 22.3% of all samples,
  which is 80.6% of on-CPU time (about 70% of samples are worker threads
  waiting); `_platform_memmove` 7.2% of on-CPU; `HuffmanTable::build` 2.5%.
  The window-copy path `apply_decoded_items_parallel` is 0.29% inclusive.
- **RAR4 PPMd order-16** — `decode_char` 73.87%, `create_successors` 7.92%,
  `update_model` 6.18%, `alloc_units_rare` 5.35%, `do_update_model_core` 4.82%.
- **RAR5 encrypted store** — `KdfCache::derive_material_rar5` 76.5%, AWS-LC
  AES-CBC 4.2%. BLAKE2sp does not appear above the noise floor in any profile.

PPMd state-count histogram at the symbol-search call site (ns = states in the
context):

| Workload | find calls | ns ≥ 33 | mean states/call |
| --- | --- | --- | --- |
| rar4_ppmd_order16_32m | 32.66 M | 92.1% | 62.3 |
| rar4_ppmd_order16_32m (escape path) | — | 91.4% | 56.0 |
| rar4_ppmd_restart | 22.32 M | 76.4% | 138.6 |
| rar4_ppmd_solid_multi_member | — | 35.3% (ns ≥ 8) | 8.34 |

Decrypt call sizes: mean **145,606 bytes per call**, 87.5% of calls at or above
64 KiB. AWS-LC's eight-block interleaved AES-CBC is therefore never starved by
the reader, and the conditional reader-buffering work in the brief was not
needed.

## Items

### Step 1 — blake2sp_simd prerequisites (not gated, KEPT)

Two defects in the in-crate NEON BLAKE2sp:

1. `Neon::load` used `vld1q_u32`, which stdarch lowers to an LLVM load
   carrying `align 4`, while the seam always hands it a byte-aligned
   `&[u8; 16]` — undefined behaviour, even though the hardware instruction is
   alignment-agnostic. Replaced with `vld1q_u8` plus a free reinterpret.
2. `Blake2spState::update_with` appended input to the buffer and then drained,
   costing two extra passes over every streamed byte. Rewritten to the
   drain-first two-phase shape the leaf-group path already used.

Measured on the Mac (interleaved, n = 5, noisy host, indicative only):
`blake2sp_streaming_4mib_chunks` 38.380 ms → 37.579 ms in the quiet rounds
(≈ −2.1%); the noisy rounds are unusable and are not counted. This is a
correctness fix (1) plus a shape fix (2), not a gated kernel, and is kept on
that basis.

### (a) PPMd symbol search, NEON 16-wide — DROPPED

Implemented (`vqtbl3q_u8` gather of the six-byte states' symbol field, one
`vceqq_u8`, lane index from `vshrn_n_u16(cmp, 4)`), differentially tested over
ns = 1..=24 plus 31/32/33, 47/48/49, 63/64/65 against the scalar scan, and
dropped on measurement.

### (b) PPMd symbol search, AVX2 16-wide — DROPPED

Implemented as the two-lane `vinserti128` twin of the shipped SSSE3 kernel and
differentially tested the same way.

A/B on codex-x86, n = 6, AVX2 tier off vs on:

| Bench | SSSE3 only | + AVX2 | delta |
| --- | --- | --- | --- |
| rar4_ppmd_restart | 388.355 ms | 388.405 ms | +0.01% |
| rar4_ppmd_solid_multi_member | 493.960 ms | 493.350 ms | −0.12% |

Nothing. So the question became how much the *whole* family is worth, which is
the number that settles (a), (b), (c) and the AVX-512 PPMd tier at once.

**Ceiling: scalar vs. every PPMd batch kernel** (codex-x86, interleaved,
`UNRAR_RS_PPMD_SCALAR`):

| Bench | n | scalar | all SIMD | delta |
| --- | --- | --- | --- | --- |
| rar4_ppmd_restart | 5 | 400.850 ms | 394.880 ms | −1.49% |
| rar4_ppmd_solid_multi_member | 5 | 490.940 ms | 499.280 ms | **+1.70%** (SIMD slower) |
| rar4_ppmd_order16_32m | 5 | 9.8288 s | 9.8277 s | +0.01% |

`rar4_ppmd_order16_32m`, the most PPMd-dominated workload in the corpus
(`decode_char` 73.9% of its profile), per-round medians:

| Round | scalar | all SIMD |
| --- | --- | --- |
| 1 | 9.8288 s | 9.8277 s |
| 2 | 9.9577 s | 10.075 s |
| 3 | 9.6613 s | 9.9540 s |
| 4 | 9.6625 s | 9.7575 s |
| 5 | 9.8368 s | 9.6646 s |
| median | 9.8288 s | 9.8277 s |

Removing every vector kernel from the PPMd symbol search moves the heaviest
PPMd workload by less than its round-to-round spread. The cause is structural
and worth stating plainly: **PPMd keeps each context's state array sorted by
frequency**, so the scalar scan almost always terminates within the first few
states. The ns histogram above is an upper bound on how far a scan *could* go,
not how far it does; a 16-wide gather spends its width on states the scalar
walk never reaches. No batch width can fix that, which is why the AVX-512
VBMI/VBMI2 variant was declined below rather than rented.

All code for (a) and (b) was removed. The differential test's widened state
counts were kept: they exercise the shipped SSSE3 kernel's boundaries, which
were previously only covered up to 24.

### (c) PPMd escape-path collection — DROPPED

Same call site, same sorted-array argument, and it shares the ±1.5% envelope
measured above; the escape path's own histogram (91.4% at ns ≥ 33, 56 states
per call) is the same upper-bound artefact. Declined on the (a)/(b) ceiling
without writing a second kernel family.

### (d) LZ pattern copy / 64-byte copy_chunked — DROPPED

`apply_decoded_items_parallel` is **0.29% inclusive** in the RAR5 solid
profile. Even an infinitely fast window copy cannot reach the 5% end-to-end
gate; the ceiling is under 1%. The counter instrumentation written for this
item was removed unmeasured, because the profile already bounds it below the
gate.

This also declines the AVX-512 VBMI/BW third tier for the same path: a tier on
a 0.29% path cannot clear a 5% gate, and renting a c7i to confirm arithmetic
would be spending for a foregone conclusion.

### (e) x86-64-v3 multiversioning of the LZ symbol decoder and PPMd decode loop

`decode_block_symbols_fast` is 80.6% of on-CPU time in the RAR5 solid
workload — the one genuinely hot function in the corpus — and its inner work
is bit-field extraction from a bit reader, exactly what `shrx`/`bzhi`/`lzcnt`
are for. The candidate compiles the existing body twice: once at the crate's
shipped baseline and once inside
`#[target_feature(enable = "avx2,bmi1,bmi2,lzcnt,popcnt")]`, dispatched on a
cached detection bool. No algorithm changes, so the differential question is
trivially satisfied: it is the same source.

The codegen was verified rather than assumed: the built bench binary contains
52 `shrx`/`bzhi` instructions, which the baseline build cannot emit, so the
second clone really is a different loop.

**LZ symbol decoder, codex-x86, n = 6** (base = tier off):

| Bench | tier off | tier on | delta |
| --- | --- | --- | --- |
| rar_solid_lz_chunked_extract | 161.460 ms | 155.250 ms | **−3.85%** |
| weaver_solid_chunked_shape | 161.110 ms | 156.730 ms | −2.72% |
| rar_non_solid_lz_chunked_extract | 0.733 ms | 0.725 ms | −1.16% |
| rar5_solid_extract_all_members | 187.210 ms | 186.190 ms | −0.54% |

**PPMd decode loop, codex-x86, n = 5** (same tier, dispatched on the model):

| Bench | tier off | tier on | delta |
| --- | --- | --- | --- |
| rar4_ppmd_restart | 371.56 ms | 371.67 ms | +0.03% |
| rar4_ppmd_solid_multi_member | 494.62 ms | 510.47 ms | **+3.20% (slower)** |

**Verdict: DROPPED, both halves.** The PPMd half fails outright: a 3.2%
regression on a workload where the tier engages is three times the gate's 1%
regression budget, and the plausible cause is that a `target_feature` clone of
a function this large changes inlining and register allocation in ways that
have nothing to do with the new instructions.

The LZ half is the one item in this arc that came close and the one worth
arguing about. It is faster on every bench measured, by 3.85% on the workload
whose profile is 80.6% this function, and it regresses nothing. It is still
below the 5% end-to-end bar the brief set, and the brief set that bar
deliberately, so it is dropped and the number is recorded here rather than
quietly reinterpreted. If the bar is meant to be "faster everywhere, no
regressions", this item passes and the diff is three thin wrappers around an
unchanged body; that is the operator's call, not mine.

### (f) ARM executable filter — NOT MEASURED

No ARM-executable fixture exists in the pinned corpus, and the corpus is
generated only by the pinned toolchain pipeline
(`xtask test-corpus generate`, Docker images, RARLAB `rar`), which is not
available on this host — neither `rar` nor `unrar` is installed, and inventing
a fixture outside that pipeline would violate the corpus ledger. Unmeasured,
no code written.

### (g) Delta filter — NOT MEASURED

Same fixture problem. The `data.to_vec()` removal is a real allocation on the
delta path, but with no delta fixture there is no end-to-end number to gate it
with, and `rar_filter_e8e9` (the only filter bench in the corpus) is 133 µs
against 69 ms of extraction, i.e. 0.2% of the workload it belongs to. Left
alone.

### (h) wasm ports under wasmtime — NOT MEASURED

Gated behind (a)–(e); with every x86/NEON kernel in that set dropped there was
nothing to port.

### BLAKE2sp SVE2 (c8g) and AVX-512VL (c7i/c7a) — DECLINED ON CEILING

BLAKE2sp does not appear above the noise floor in any profile taken this arc.
The corpus has no large plain stored member: the biggest stored fixtures are
the 180 KiB `generated_matrix_rar5_store_plain` parts, and the one stored
workload with size, `rar5_encrypted_store_chunked_multivolume`, is 76.5% PBKDF2
and 4.2% AES. The hashing-heavy fixture the amendment's gate asks for does not
exist in the pinned corpus and cannot be generated here (see (f)).

**Ceiling: all BLAKE2sp work removed** (codex-x86, n = 5, base = hashing
skipped entirely, candidate = hashing as shipped). This is the absolute upper
bound on what *any* BLAKE2sp kernel — SVE2, AVX-512VL or otherwise — could
return end-to-end, since an infinitely fast hash is exactly the base arm:

| Bench | no hashing | hashing on | cost of all hashing |
| --- | --- | --- | --- |
| rar5_solid_extract_all_members | 198.53 ms | 205.85 ms | +3.69% (noisy: intra-arm spread 192–214 ms) |
| rar5_encrypted_store_chunked_multivolume | 3.2025 ms | 3.1995 ms | −0.09% |
| weaver_streaming_chunked_shape | 2.1496 ms | 2.1414 ms | −0.38% |

Deleting BLAKE2sp altogether buys at most about 3.7% on one bench, inside that
bench's own noise, and nothing anywhere else. A tier that made hashing 20%
faster would therefore move the best case by under 0.8%, against a 5% gate.
That is a measured decline, not an ISA-availability decline.

The microbench harness for these tiers was still built and kept
(`blake2sp_streaming_4mib_chunks`, `blake2sp_streaming_64kib_chunks`,
`blake2sp_oneshot_64mib` in `archive_hotspots`), so a future arc with a
hashing-heavy fixture can pick this up with the measurement surface already in
place.

## AWS

**Instances launched: none. Instance-hours used: 0.**

The amendment was explicit that a kernel must not be dropped for want of local
ISA, and none was. Each AWS candidate was declined on a *measured ceiling*
taken on hardware that was already available, which is the gate's own rule
("a microbench win with no end-to-end movement is a DROP"):

- AVX-512 VBMI/VBMI2 PPMd symbol search and escape path: the entire PPMd
  vector family is worth ±1.5% end-to-end on codex-x86, and ≈0% on the most
  PPMd-dominated workload. A wider gather cannot beat a scan that stops in the
  first few states.
- AVX-512 VBMI/BW LZ pattern copy: the path is 0.29% inclusive.
- SVE2 / AVX-512VL BLAKE2sp: no fixture in the pinned corpus makes BLAKE2sp
  more than a rounding error end-to-end, so no c8g/c7i/c7a round could produce
  a number that clears the gate.

Renting hardware to confirm a ceiling that local hardware already bounds below
the gate would have cost money to learn nothing. If a hashing-heavy fixture
lands in the corpus, the BLAKE2sp tiers become measurable and worth a c7i and
c8g round; the other three stay declined on structure, not on ISA.

## Summary

**Kept:** the two step-1 BLAKE2sp prerequisites (a `vld1q_u32` alignment UB
fix, and the drain-first `update_with` shape), three BLAKE2sp microbenches, and
a wider differential test for the shipped SSSE3 PPMd kernel. Version bumped to
0.10.8 with a changelog entry.

**Dropped, with numbers:** PPMd symbol search NEON 16-wide and AVX2 16-wide
(the whole PPMd vector family is worth ±1.5% end-to-end, ≈0% on the most
PPMd-heavy workload, because the state array is frequency-sorted and the scalar
scan stops early); the PPMd escape path (same call site, same ceiling); the LZ
pattern copy and its AVX-512 variant (0.29% of the profile); x86-64-v3
multiversioning of the PPMd decode loop (+3.2% regression); x86-64-v3
multiversioning of the LZ symbol decoder (−3.85%, below the 5% bar — the near
miss); AVX-512 VBMI/VBMI2 PPMd tiers (declined on the PPMd ceiling); SVE2 and
AVX-512VL BLAKE2sp (declined on a ceiling of ≤3.7% for removing hashing
entirely).

**Not measured:** ARM and delta filter items, and the wasm ports — no fixture
exists in the pinned corpus and none can be generated on this host.

**AWS:** no instances launched, 0 instance-hours, every candidate declined on a
locally measured ceiling rather than on missing ISA.

The one-line version: outside `decode_block_symbols_fast`, this crate's
extraction time is not spent anywhere a wider vector can reach, and inside it
the win available from instruction selection alone is about 4%.

## Delivery note

The work sits on `feature/unrar-simd-tiers` in `.worktrees/unrar-simd`, staged
but **uncommitted**: the SSH signing agent (1Password) failed every commit
attempt with `1Password: failed to fill whole buffer`, and an unsigned commit
is not an option. Nothing was reset, stashed or reverted; the tree is the
finished state and needs only `git commit` once signing works again. The
prepared commit message and the raw interleaved A/B logs for every table above
were kept alongside the session scratchpad.
