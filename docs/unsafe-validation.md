# Native and unsafe-code validation

The memory-safety lanes in `.github/workflows/ci.yml` (`unsafe-valgrind`,
`unsafe-sanitizer`, `unsafe-miri-plan`/`unsafe-miri`, joined by
`unsafe-complete`) cover the unsafe-bearing code of the four library crates:
`reedsolomon-rs`, `unrar-rs`, `par2-rs` and `par3-rs`. The `rarpar` CLI holds
unsafe code of its own but is not in these lanes (see
[Not instrumented](#not-instrumented)); `xtask`'s only unsafe code is
`std::env::set_var`/`remove_var` in its tests.

Every lane selects library unit tests by module with a nextest `-E` filter,
so that each job runs the tests that reach the unsafe code rather than the
whole suite under an instrument that makes it 10–50× slower. A crate's step
runs only when the `changes` job marks that crate affected. New unsafe code
must extend the filters here and in `ci.yml` (and, for Miri, the policy in
`.github/scripts/miri-matrix.py`) rather than widen a lane to the whole
crate.

## Where the unsafe code is

| Crate | Unsafe-bearing code |
| --- | --- |
| `reedsolomon-rs` | GF(2^8)/GF(2^16) SIMD kernels (`gf_simd`, `gf8`, `gf_pmul`, `sve2`: SSSE3/AVX2/AVX-512/GFNI, NEON, SVE2); the FFT's shared row banks and raw row views (`fft`); the tiled inversion's byte views (`matrix_tiled`); the x86-64 XOR JIT (`xor_jit`: W^X mappings and an `asm!` trampoline); the Metal and wgpu backends (opt-in features) |
| `unrar-rs` | The LZ window and bit readers' unaligned loads and stores (`decompress::lz::window`, `block_reader`); the parallel RAR5 decoder's fast symbol path (`decompress::lz::parallel`); BLAKE2sp, AES and CRC SIMD (`crypto::`, `crc_simd`); the AWS-LC backend's FFI; member metadata FFI (`archive::member`: umask, owners, extended attributes, Windows security); `mktime` in `rar4` |
| `par2-rs` | The repair controller's interleaved output pointers and packed checksums (`repair`); MD5 and CRC SIMD (`md5_simd`, `crc_simd`); the single-stream and paired MD5 assembly (`md5_asm`, `md5_pair_asm`, reached through `checksum`); checksum tests' guard-page mmap/mprotect wrapper; the repair transform and matrix byte views; `openat`/`unlinkat` (`disk`); create's aligned encode buffers and JIT calls (`create::encode`); output-file FFI (`create::output`); the repairer's `MappedFile` mmap wrapper (`repairer`); `posix_fadvise` on Linux for sources of 64 MiB or more (`file_cache`) |
| `par3-rs` | Only OS FFI: `statfs`/`GetVolumePathNameW` (`mount`), `fclonefileat`/`FICLONE`/`copy_file_range` (`repair_tree_clone`), Windows file identity (`repair_tree_windows`). Its threading (hash, FFT, repair and creation pools) has no unsafe code but is where a race would come from |

## Lanes per crate

| Lane | `reedsolomon-rs` | `unrar-rs` | `par2-rs` | `par3-rs` |
| --- | --- | --- | --- | --- |
| `unsafe-valgrind` (Memcheck, Linux x86-64 and ARM64, default features) | `gf_simd`, `gf8`, `gf_pmul`, `fft`, `matrix_tiled`, `sve2`, `decode_apply`, `threading`, `xor_jit` | `decompress::`, `crypto::`, `crc_simd`, `hash_pipeline`, `archive::member`, `rar4` (AWS-LC) | `repair`, `md5_simd`, `crc_simd`, `repair_transform`, `matrix`, `disk`, `checksum`, `create::encode`, `create::output`, the `repairer` tests that map a file or copy from a 64 MiB source, the latter reaching `file_cache`'s `posix_fadvise`; the strict single-read dispatch, verdict-differential and one-read tests in `verify` (assembly MD5) | `mount`, `repair_tree`, `session_repair`, `hash`, `fft`, `runtime`, `gf` |
| `unsafe-sanitizer` AddressSanitizer (Linux x86-64 and ARM64, `-Zbuild-std`) | as Memcheck | as Memcheck, RustCrypto | as Memcheck, RustCrypto | as Memcheck |
| `unsafe-sanitizer` ThreadSanitizer (same) | — | `decompress::lz::parallel`, `decompress::lz::tests`, `hash_pipeline`, `recovery`, RustCrypto | — | `hash`, `fft`, `runtime`, `session_repair`, `session`, `evidence`, `creation` |
| `unsafe-miri` (one job per discovered test, `-Zmiri-strict-provenance`) | `fft::tests`: the row-bank, known-zero-step and transform round-trip tests | `decompress::lz::window::tests`, `decompress::lz::block_reader::tests` except the exhaustive `copy_matrix_matches_reference_*` sweeps, RustCrypto | — | — |
| guard pages | — | — | `checksum::tests::paired_assembly_stops_at_guard_page` (Unix, native backend, also selected by Memcheck) | — |

The sanitizer lanes run on nightly `nightly-2026-09-01` with an instrumented
standard library. They use the RustCrypto backend for `unrar-rs` and
`par2-rs`, so that the AES, BLAKE2sp and MD5 under the code being tested are
Rust the sanitizer instruments; Memcheck uses the default backends (AWS-LC
in `unrar-rs`, the `md5_asm` assembly in `par2-rs`), because assembly is what
Memcheck can see and the sanitizers cannot. Memcheck builds the tests with the
`memcheck` profile: optimised, with debug assertions and overflow checks kept.

The selected strict single-read tests cover both a permitted two-chain join
and a one-worker execution context, so adaptive scheduling cannot leave the
paired assembly untested. The dispatch counter assertion is native-only;
RustCrypto sanitizer runs still exercise both execution contexts for verdicts
and byte counts.

The ARM64 Memcheck runner uses `--fair-sched=yes`. Valgrind's default
non-fair guest-thread scheduler can starve the helper that cancels a CPU-bound
scan: two existing mid-scan cancellation tests completed the entire scan under
the default scheduler on A72. Both passed natively and under fair scheduling,
with unchanged assertions, polling, inputs and cancellation timing. This is a
runner setting, not a longer test deadline or a memory-error suppression. The
original failures are retained with the performance validation evidence.

Miri discovery runs `cargo miri nextest list` with the same filters the matrix
script enforces, requires named tests to stay selected, and fails if a filter
picks up a test outside the allowed modules. Miri's runtime feature detection
reports only the target's baseline features, so under Miri the portable
fallbacks run: Miri checks the pointer arithmetic, aliasing and
initialization of the scalar paths and the shared row banks, not the
dispatched SIMD kernels.

## Fail-closed MD5 assembly controls

The existing Linux x86-64 and AArch64 Memcheck jobs first run a short native
checksum/strict-verification pass from the same optimized test build. This
exposes host BMI1 before Valgrind can mask CPU features. There is no extra
matrix job. `.github/scripts/ci/par2-md5-coverage.py` checks nextest's actual
inventory: every required test must exist, be non-ignored, and match the same
filter the instrumented pass uses. A missing cfg-gated assembly test fails
the job instead of silently reducing its coverage. Runner architecture is
checked against the matrix, and negative checker self-tests run in both jobs.

| Evidence | Durable gate |
| --- | --- |
| Native default on both architectures | Native streaming test asserts the selected backend is assembly and a nonempty assembly execution counter increased; logs identify AArch64 baseline, x86 baseline or BMI1 |
| Arbitrary-state differential | 20,480 state/length/alignment cases (16,384 nonempty assembly calls) compare against independent scalar MD5 and the Rust paired oracle, including all 64-by-64 input alignments |
| x86 baseline and BMI1 | Baseline is called directly even on BMI1 hosts. BMI1 must execute when runtime detection advertises it; it must remain unused otherwise. Both paths have counter assertions |
| Bounds | Guard pages precede/follow readable pages; 384 paired cases vary boundaries, alignments and block lengths. Another 192 exact-sized heap cases give Memcheck byte-exact upper redzones for unaligned streams. Both compare scalar results and assert baseline/runtime execution |
| Actual Memcheck | `PAR2_CI_MD5_RUN=memcheck` makes the native streaming test require the Memcheck preload in its own Linux mappings. The preceding native pass requires its absence. These are test-only controls, with no production behavior switch |
| Both features | Existing crypto-backend job requires the native and independent Rust differential tests, then runs them. The streaming assertion continues to require native selection |
| Opt-in Rust-only | Existing crypto-backend job requires the Rust-only fallback test and absence of all native MD5 test cases. A dev LLVM IR audit requires RustCrypto evidence and rejects both handwritten MD5 module names |
| ASan wrapper/fallback on x86 and ARM | Existing Rust-only sanitizer builds must list the fallback, verdict-differential and read-count tests, with native MD5/dispatch test cases absent, before the unchanged sanitizer pass runs |

The native and Memcheck steps print successful test output, including selected
backend and execution counters. They share the same profile/build artifacts;
only the short uninstrumented checksum pass is additional execution. Existing
ARM suppression and sanitizer settings are unchanged.

Miri does **not** execute these MD5 assembly paths and no MD5 Miri coverage is
claimed. Its existing FFT/window/bit-reader gates cover their selected Rust
invariants. Rust-only MD5 wrappers/fallback receive native differential and
ASan coverage instead. ASan cannot see handwritten assembly; native guard
pages and Linux Memcheck provide that memory-bounds evidence. The IR audit
excludes handwritten **MD5** assembly, not all SIMD, unsafe code or FFI in
the crate/dependency graph.

Darwin and Windows retain their native platform unit tests. Unix guard pages
also run on Darwin; this focused inventory/IR audit and native instrumentation
are enforced on Linux. Windows guard pages and Windows native memory
instrumentation are unsupported here. A BMI1-less runner proves baseline
and records that BMI1 was unavailable; no additional hardware is provisioned.

## Scoped out, and why

- **Guard pages beyond paired MD5.** Paired MD5 receives caller-owned
  buffers, so a direct mmap test guards both sides of each input across
  complete-block lengths and all byte alignments. Its alignment, arbitrary-state and dispatch tests also live in
  `checksum`, already included in the native Memcheck selector above. The
  LZ window, FFT row banks and repair output area allocate internally through
  `alloc_zeroed` or `Vec`; guarding them would need a global guard allocator.
  These other allocations have no guard-page tests.
- **Miri for `par2-rs`.** The repair controller rebuilds output pointers from
  `usize` (`interleaved_output_ptr` in `src/repair.rs`, `base as *mut u8`),
  which `-Zmiri-strict-provenance` rejects by design. Its tests stay under
  Memcheck and AddressSanitizer until the controller carries a pointer
  rather than an address.
- **Miri for `par3-rs`.** Its only unsafe code is OS FFI that Miri cannot
  execute; Memcheck and the sanitizers cover it.
- **Miri for the rest of `reedsolomon-rs`.** Most of its FFT tests run their
  passes on rayon, and crossbeam-epoch (under rayon) casts integers to
  pointers, which `-Zmiri-strict-provenance` rejects; the tiled inversion
  (`matrix_tiled.rs`, `*(submat_ptr as *const u16)`) does the same in its
  own code; and on ARM64 hosts some tests reach NEON intrinsics Miri cannot
  execute. Miri runs the three FFT tests that avoid all three; the rest stay
  under Memcheck and AddressSanitizer.
- **Miri beyond the window, bit readers and those FFT tests.** The SIMD
  kernels are not run by Miri (see above); the parallel decoder, the hash
  pipeline and the repair pools are too slow interpreted to fit a job. So are
  the window's three exhaustive `copy_matrix_matches_reference_*` sweeps:
  each ran past three minutes interpreted, where the rest of the window and
  bit-reader tests finish in under ninety seconds. They stay under Memcheck
  and AddressSanitizer; Miri runs the targeted copy, wrap and peek cases.
- **Where the Miri selection was measured.** The timings and results above
  are from Miri on an aarch64-apple-darwin host; the x86-64 Linux selection
  was not run locally (its C build dependencies need a Linux cross
  compiler), so the first CI run is its first run.
- **ThreadSanitizer for `reedsolomon-rs` and `par2-rs`.** Their threading is
  rayon over disjoint slices; the shared-row FFT pool in `reedsolomon-rs` is
  reached through `par3-rs`'s TSan selection (`fft`).

## Not instrumented

What no lane above runs, so that a pass is not read as more than it is:

- The sanitizers cannot instrument assembly or C: AWS-LC, `par2-rs`'s
  `md5_asm`, and `asm!` in the XOR-JIT trampoline. AWS-LC and `md5_asm` are
  under Memcheck only. JIT-generated code runs
  under Memcheck (anonymous mappings are re-translated) but no sanitizer.
- Memcheck's CPUID hides AVX-512, so the AVX-512 and GFNI-with-AVX-512 tiers
  run under no instrument; the x86 lanes exercise AVX2 and below. SVE2 runs
  only where the ARM64 runner has it.
- The Metal and wgpu GF(2^16) backends (opt-in features) and the Windows FFI
  (`repair_tree_windows`, Windows branches of `archive::member` and
  `create::output`) are Linux-invisible; the lanes are Linux only. So is the
  WASI-only `pread`/`pwrite` FFI in `repairer` (`read_file_at`,
  `write_file_at` under `cfg(target_os = "wasi")`).
- The `rarpar` CLI's own unsafe code (`libc` FFI in `compat_7z`,
  `compat_par3`, `discovery`, `error` and `par3`: terminal state,
  directory-relative `openat`/`renameat`/`unlinkat` and friends, time
  conversion, `posix_fadvise`) is outside these lanes, which instrument the
  library crates only.
- Integration tests (`tests/`) and the fixture corpora are not under any
  instrument; only library unit tests are selected. The fuzz targets run
  under AddressSanitizer in ClusterFuzzLite (`cflite-pr.yml`,
  `cflite-batch.yml`) for `unrar-rs`, `par2-rs` and `par3-rs`.

`unsafe-complete` fails if any Valgrind, sanitizer, discovery or Miri job is
failed, cancelled or skipped while crates are affected; the Miri shards alone
may be skipped, and only when discovery found no Miri-covered crate
affected. `ci-complete` needs it, so a memory-safety failure fails the
required check. No retry or interpreter check is disabled, and no sanitizer
suppression is used. Memcheck carries one suppression, on ARM64 only:
`.github/valgrind/aarch64-memcheck.supp`, loaded by the ARM64
`unsafe-valgrind` runner (the reedsolomon-rs and par3-rs lanes hit it), holds
one `Memcheck:Cond` entry for `reedsolomon_rs::fft::add_tile`. ARM64 Memcheck
reports a conditional jump on uninitialised values there, reached from
`transform_tiles_alone`/`transform_sum` in
`fft::tests::tiled_transforms_match_whole_row_sweeps` (reedsolomon-rs) and
`fft::lane_tests::the_four_step_gate_does_not_change_a_byte` and
`fft::lane_tests::the_byte_lane_matches_the_word_lane_bit_for_bit` (par3-rs).
It is judged a false positive: everything `add_tile` reads is initialised
(`after` is cloned from a collected vector; the tile views and `sum` are rows
of `RowBank::zeroed` or collected `Vec`s, with no `set_len` or `MaybeUninit`
in either crate's FFT), and the same tests pass under x86-64 Memcheck and
under AddressSanitizer on both architectures. Remove it when a newer Valgrind
passes those tests without it.
