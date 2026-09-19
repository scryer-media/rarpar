# PAR3 on wasm: a GF(2⁸) SIMD kernel and SIMD BLAKE3

Two changes were proposed for the PAR3 path on wasm, each gated on measurement:
a wasm SIMD tier for the GF(2⁸) multiply-accumulate, and forwarding blake3's
`wasm32_simd` feature so a `+simd128` build hashes with blake3's SIMD kernels.

**Both are kept.** The GF(2⁸) tier makes a PAR3 create 3.96x faster and a
repair 4.72x under wasmtime; forwarding the blake3 feature makes a verify 1.84x
faster. The gate asked for 2%. Neither touches native code generation, which is
shown below by byte comparison rather than by timing.

## Hosts and tools

| | |
| --- | --- |
| wasm and native aarch64 | Apple M5 Max, macOS 26.0 (Darwin 25.6.0), 18 cores |
| native x86-64 | `codex-x86`, 12th Gen Intel Core i5-1240P, 16 threads, Ubuntu |
| runtime | wasmtime 47.0.3 — the version `ci.yml` pins as `WASMTIME_VERSION` |
| toolchain | rustc 1.97.1, the `rust-toolchain.toml` pin, on both hosts |
| target | `wasm32-wasip1`, release profile (`lto = "fat"`, one codegen unit) |
| corpus | the published PAR3 fixture corpus, `xtask test-corpus hydrate --profile par3` |

wasmtime is not installed on `codex-x86`, so every wasm number here is from the
Mac. What that leaves unmeasured is stated at the end.

## What is measured

`crates/par3-rs/examples/wasm_par3_check.rs` is new: an end-to-end pass over the
corpus that verifies each set healthy, damages whole blocks of its largest input
against a pristine copy held outside the scanned directory, verifies the damage,
repairs, and asserts the repaired file is byte-identical to the copy. It then
creates a fresh set over the 16 MiB `large_stream` input at a block size chosen
to keep the set in GF(2⁸) — 103 input blocks, 21 recovery — damages twenty of
its blocks and rebuilds them from the carriers it just wrote. A last phase
fingerprints the same 16 MiB on its own, which is what turns "the hashing share
of a verify" into a number.

Every phase prints its wall time, and every lane-invariant line carries a
BLAKE3 fingerprint rather than a verdict. The repo already had this shape for
PAR2 and UnRAR; `.github/scripts/wasm-harness-check.sh` gained a `par3` arm and
`ci.yml` a `wasm-par3-harness` job, which runs the harness natively and then on
three wasm lanes and requires each lane's canonical report to be byte-identical
to the native run in the same job.

### Builds compared

wasm dispatch is compile-time, so the two arms of each comparison are two
artifacts, not two code paths in one:

| lane | RUSTFLAGS | feature | what it has |
| --- | --- | --- | --- |
| `portable` | — | — | scalar GF(2⁸), scalar GF(2¹⁶), portable BLAKE3 |
| `simd128-nogf8` | `+simd128` | `wasm-simd` | the shipped build with the new GF(2⁸) tier removed |
| `simd128-nob3` | `+simd128` | — | the shipped build without blake3's feature forwarded |
| `simd128` | `+simd128` | `wasm-simd` | **the shipped configuration** |
| `relaxed-simd` | `+relaxed-simd` | `wasm-simd` | as above, with `i8x16.relaxed_swizzle` |

`simd128-nogf8` is built from the pre-change `gf8.rs`; `simd128-nob3` needs the
compile-time assertion removed as well, because that assertion is exactly what
stops such a build existing. Both were built from temporary edits that were
restored and verified identical afterwards.

The artifacts differ as expected. Counting opcodes with `wasm-tools print`:
`portable` has no `i8x16.swizzle` at all, `simd128-nogf8` has the eight of the
existing GF(2¹⁶) kernel, `simd128` has ten — the same eight plus this change's
two — and `relaxed-simd` has ten `i8x16.relaxed_swizzle` and no plain ones.

### Protocol

Whole processes, alternated round-robin, with the within-round order reversed on
alternate rounds so no build always occupies the same position. Medians of
n = 11 for the wasm lanes, n = 20 (aarch64) and n = 15 (x86-64) for native.
Times are milliseconds. The first protocol pass used a fixed within-round order
and produced the same conclusions with visibly fatter tails; the numbers below
are from the alternating pass.

## Correctness

Bit-exactness was established at two levels, and nothing below is a timing
argument.

**Kernel.** `gf8.rs` gained a differential test that runs every dispatched tier
against `MulPlan::scalar` for all 256 coefficients, at four source alignments,
over twenty-one lengths chosen around 16, 32 and 64 so every tail the kernels
can produce is covered. Comparing the two tiers directly — rather than both
against `mul` — is what makes the swizzle's lane bookkeeping load-bearing: an
index outside 0..=15 clears its lane and a misplaced lane moves a product, and
either changes a byte. It passes natively (aarch64) and under wasmtime on all
three wasm lanes, alongside the pre-existing all-coefficients test.

**End to end.** The harness's canonical report — 40 asserted rows, including a
fingerprint for every repaired file, every created carrier and the rebuilt
source — is byte-identical across native aarch64, `wasip1-portable`,
`wasip1-simd128` and `wasip1-relaxed-simd`.

## Item 1 — the GF(2⁸) wasm kernel

`simd128` against `simd128-nogf8`. Both have the GF(2¹⁶) wasm kernel and SIMD
BLAKE3; the only difference is this change.

| phase | `simd128-nogf8` | `simd128` | speedup |
| --- | ---: | ---: | ---: |
| whole run | 594.96 | 212.97 | **2.79x** |
| create (GF(2⁸), 103 blocks, 21 recovery) | 258.21 | 65.23 | **3.96x** |
| rebuild (20 blocks solved) | 237.73 | 50.34 | **4.72x** |
| repair `large_stream` (GF(2¹⁶)) | 44.38 | 44.66 | 0.99x |
| verify `large_stream` | 8.10 | 8.24 | 0.98x |
| fingerprint 16 MiB | 7.23 | 7.26 | 1.00x |

The bottom three rows are the control: they never reach GF(2⁸), and they do not
move. Whole runs, sorted:

```
simd128-nogf8  579.1 580.9 587.3 591.6 594.9 595.0 597.2 597.4 606.0 640.5 646.1
simd128        209.2 210.6 212.0 212.1 212.9 213.0 216.7 221.2 224.7 228.7 236.4
```

The distributions do not overlap.

**Verdict: KEEP.** Bit-exact against scalar; 2.79x end to end under wasmtime
with simd128, against a gate of ≥ 2%; no native target regresses (below).

### relaxed-simd

`relaxed-simd` against `simd128`, whole run 213.83 against 212.97 — 0.996x, a
wash, and each phase is within ±0.7%. That is the expected result on this host:
wasmtime lowers `i8x16.swizzle` on aarch64 straight to `TBL`, which has the
out-of-range-yields-zero behaviour already, so there is no clamp to drop. The
lane is kept because the flavour costs one macro arm, is covered by the same
differential test and the same CI diff, and is where an x86 host's saving would
appear — see the unmeasured note below.

## Item 2 — blake3's `wasm32_simd` on wasm

`simd128` against `simd128-nob3`. Both have both GF kernels; the only difference
is whether blake3's feature is forwarded.

| phase | `simd128-nob3` | `simd128` | speedup |
| --- | ---: | ---: | ---: |
| whole run | 316.34 | 212.97 | **1.49x** |
| fingerprint 16 MiB | 14.21 | 7.26 | **1.96x** |
| verify `large_stream` (16 MiB) | 15.17 | 8.24 | **1.84x** |
| repair `large_stream` | 73.23 | 44.66 | 1.64x |
| rebuild | 75.97 | 50.34 | 1.51x |
| create | 81.48 | 65.23 | 1.25x |

### The hashing share of a verify

Asked for explicitly. The verify of the 16 MiB `large_stream` set reads every
block, takes its CRC-64 and fingerprints it; the harness's last phase
fingerprints the same bytes alone, so the ratio is the share directly:

| build | fingerprint | verify | hashing share |
| --- | ---: | ---: | ---: |
| `simd128-nob3` (portable BLAKE3) | 14.21 | 15.17 | **93.7 %** |
| `simd128` (SIMD BLAKE3) | 7.26 | 8.24 | **88.0 %** |
| `portable` (everything scalar) | 14.08 | 14.93 | 94.3 % |
| native aarch64 (NEON BLAKE3) | 7.31 | 9.78 | 74.8 % |

A PAR3 verify is, to within a tenth, a BLAKE3 benchmark. Which is also the
honest framing of this item: the kernel doing the work is upstream's, not this
repository's, and the change is one Cargo feature plus the gate that keeps it
attached. The number is why it is worth having attached.

**Verdict: KEEP.** 1.84x on a verify and 1.49x end to end under wasmtime with
simd128, against a gate of ≥ 2%. Kept on the measurement, not on the "it is
upstream's kernel" basis.

### Why it is a feature and not unconditional

A wasm build without simd128 is a supported target — `ci.yml`'s `par3-tests`
lane checks exactly that build, and the harness runs a `wasip1-portable` lane.
Cargo cannot key a feature on a `target_feature`, so the feature is the only
seam available.

The blake3 documentation implies `wasm32_simd` will not compile without
`-C target-feature=+simd128`. On blake3 1.8.7 that is **not true**: the build
succeeds. It is still wrong to enable unconditionally, for a different reason —
the resulting module carries v128 instructions (`wasm-tools print` finds 1290
`v128.load` and 1364 `v128.store` in exactly that build), so a target that
promised its runtime no SIMD would ship a module requiring it.

So the feature stays opt-in, and the pairing is enforced instead:

* `crates/par3-rs/src/lib.rs` carries a `const` assertion, compiled only for
  `wasm32` with `simd128`, on blake3's own `platform::MAX_SIMD_DEGREE` — four
  with the SIMD kernels, one without. A `+simd128` build that did not forward
  the feature fails with a message naming it. This checks the outcome, not the
  spelling of a feature name.
* The harness re-asserts it at run time, so the artifact that actually ran is
  covered and not merely the compilation. This is not theoretical: the
  `simd128-nob3` artifact above is 56 KB rather than 1.2 MB when the assertion
  is left in, because the constant folds and LTO deletes the program behind it.
* `wasm-harness-check.sh` asserts the tier each lane reports from outside the
  artifact, against the lane header the artifact declares — a `+simd128` lane
  must report degree > 1 and the portable lane must report 1.

Rayon is untouched: `available_parallelism` fails under wasip1, `WorkerPool`
therefore returns no pool, and every stage runs serially. Nothing was changed
there and nothing needed to be.

## Gate (c) — native non-regression

The wasm kernel is behind `#[cfg(target_arch = "wasm32", …)]`, so it should not
reach a native compilation at all. That is checkable directly, and the check is
stronger than any timing:

| host | before | after | `.text` |
| --- | ---: | ---: | --- |
| aarch64 (M5 Max) | 530 960 B | 530 960 B | **byte-identical** |
| x86-64 (i5-1240P) | 778 824 B | 778 824 B | **byte-identical** |

`before` is the native harness built with the pre-change `gf8.rs`, `after` with
the new one; the `__text`/`.text` sections were extracted with `otool -s` and
`objcopy --only-section` respectively and compared byte for byte. The whole
binaries differ only in panic-location metadata, whose line numbers moved.

The timing A/B was run anyway, as asked:

| host | n | before | after | delta |
| --- | ---: | ---: | ---: | ---: |
| x86-64 `codex-x86` | 15 | 155.15 | 154.57 | **−0.38 %** |
| aarch64 Mac | 20 | 198.39 | 192.71 | **−2.86 %** |

The x86 figure is inside the ±1% the gate names. The Mac figure is not, in the
direction of being faster, and it is not trustworthy either way: three
independent blocks on that host gave −1.12 % (n = 9, fixed order), +1.35 %
(n = 15, fixed order) and −2.86 % (n = 20, alternating), a 4-point spread
between blocks measuring two binaries whose machine code is identical. The
laptop's thermal drift is larger than the effect the gate asks about. The
byte comparison is what settles this row; the timings are reported because they
were asked for, and they contain no signal.

**Verdict: no native regression.** Proven by construction, consistent with the
x86-64 timings, and not contradicted by the aarch64 ones.

## wasm against native, for context

The shipped wasm build against the native aarch64 build of the same harness:

| phase | native aarch64 | wasm `simd128` | wasm / native |
| --- | ---: | ---: | ---: |
| whole run | 192.71 | 212.97 | 1.11x |
| create | 57.59 | 65.23 | 1.13x |
| rebuild | 43.56 | 50.34 | 1.16x |
| repair `large_stream` | 39.98 | 44.66 | 1.12x |
| fingerprint 16 MiB | 7.31 | 7.26 | 0.99x |

PAR3 under wasmtime now runs within about 15 % of native on this host, and
fingerprints at native speed. Before these two changes the same comparison was
3.4x (whole run) and 1.9x (fingerprint).

## Unmeasured, and why

* **relaxed-simd on an x86 host.** The clamp `i8x16.swizzle` must emit on x86
  is the only thing `i8x16_relaxed_swizzle` removes, so the flavour's benefit
  can only appear there. wasmtime is not installed on `codex-x86` and installing
  it was out of scope for this pass. The lane is correct and byte-exact on both
  hosts' terms; only its x86 speedup is unknown.
* **A wasm runtime other than wasmtime.** Every wasm number is wasmtime 47.0.3,
  matching the CI pin. Browser engines lower swizzles differently.
* **Threads.** `wasm32-wasip1-threads` modules do not instantiate on wasmtime 47
  — the runtime removed wasi-threads outright — which is the same reason the
  PAR2 harness dropped its threads lanes in August. Nothing here is threaded on
  wasm regardless.
* **GF(2⁸) above 128 input blocks.** The reference's field choice moves to
  GF(2¹⁶) there, so a larger GF(2⁸) workload than the created set cannot be
  built from this corpus without leaving what the reference implementation
  writes.

## Version impact

| crate | version | why |
| --- | --- | --- |
| `reedsolomon-rs` | 0.4.6 → **0.4.7** | the GF(2⁸) wasm tier |
| `par3-rs` | 0.4.2 → **0.4.3** | the `wasm-simd` feature, the assertion, the harness; requires `reedsolomon-rs` 0.4.7 |
| `xtask` | 0.4.6 → **0.4.7** | carried by the workspace version; unpublished |
| `par2-rs` | unchanged | keeps its `reedsolomon-rs` 0.4.6 requirement; nothing it calls moved |
| `unrar-rs` | unchanged | — |
| `rarpar` | unchanged | no CLI behaviour changes; its caret requirement on `par3-rs` 0.4.2 already accepts 0.4.3 |
