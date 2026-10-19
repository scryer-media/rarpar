# PAR2 and RAR5 performance validation, 2026-10-18

The current candidate implements paired MD5, discovery reuse/deferred reads,
and RAR5 recovery-buffer right-sizing. It preserves the original production
compute preferences and 12-source repair batches. **F1's A72 CPU acceptance
criterion remains unresolved.** Current Spot measurements are separate from
the earlier A72 prototype; no Mac timing is acceptance evidence.

Current PR versions: par2-rs 0.10.11 → 0.10.12, unrar-rs 0.12.0 → 0.13.0,
and rarpar 0.9.1 → 0.9.2. The measured candidate used unrar-rs 0.12.1 before
the operator added the KDF/key-hygiene API change in `a3b6df5`. That code and
the recovery fix now share prospective 0.13.0; dependency floors, lockfile,
README examples and changelogs agree. No new performance measurement is
claimed for the combined KDF change.

## Source findings and implemented behavior

The requested baseline is `22d19cd70edb23ad60c17c10046161f620db4b61`.
The archive was made from `e954b913be454ffa4da3010879ce0749249a81c6`;
both have tree `301d37839ebb51bb9ec41b42ff8f036b081fbd4b`.
Its SHA-256 is `ab41bf03196854dcb5bfa475e552b40ba97498a85d184e09e9bcbd2a56b4e46c`.
The measured integrated source patch SHA-256 is
`a70168de5959251750e342f7de8e406b986c322ad736c34c25b82f8b981732fd`.
The first signed commit, `054d1877`, keeps these measured Rust sources.
Later review fixes change the CLI's stream/deferred-discovery paths and
tracing output destination, plus integration regressions. The hashing,
repair controller and RAR5 kernels remain the measured bytes. No new
performance measurement is claimed for those review fixes; each host
retains a source-file hash inventory.

The supplied sizing diagnosis has two material errors:

- A packed 64 KiB slice includes a checksum stride, giving 65,568 bytes.
  Four workers with the 32 KiB preference produce four tiles: three of
  16,416 bytes and a final 16,320 bytes. Each worker covers all outputs;
  this is not two 32 KiB tiles split by output range. A 16 KiB preference
  produces the same layout. An 8 KiB preference produces seven 8,224-byte
  tiles and a final 8,000-byte tile. Plain stride-two data similarly gives
  four approximately 16 KiB tiles.
- The pinned reference's CLMUL NEON and SHA3 contracts have input multiple
  eight. Its nominal twelve inputs round to **sixteen**. NEON shuffle uses
  multiple two and groups twelve. Rarpar groups twelve, so its dense repair
  batch uses 8+4; its 16-source kernel is unreachable from that default
  repair batch, though other kernel callers can use it.

The nominal address spans for twelve sources plus one output are therefore
208.4 versus 104.4 KiB, not 416 versus 104 KiB. An eight-source pass spans
144.3 versus 72.3 KiB; the reference's sixteen-source 8 KiB group spans
136.5 KiB. These are address spans, not measured cache residency.

The reference source is par2cmdline-turbo
`3e60f6fcfed52bf257e79c46deae616cb6135d59`, including its ParPar headers.
Its CLMUL preference is 8 KiB and NEON shuffle preference is 16 KiB.
The proposed production preference change was rolled back: the A72 results
below did not establish the proposed cache cause or close the CPU gap.
Diagnostic-only tile/batch controls remain behind `PAR2_BENCH_DIAGNOSTICS=1`.

Strict verification uses ParPar's interleaved scalar MD5 instruction streams
on x86-64 and AArch64. Runtime BMI1 detection selects that x86 variant;
the baseline x86 variant is also tested directly. AArch64 needs baseline
integer instructions. SIMD x2 variants and CPU-name heuristics were not ported.
Rust supplies iteration, registers and feed-forward. The existing AWS-LC
single-stream assembly remains for single chains, incompatible buffered
positions and tails. The 16 KiB prefix, full identity, IFSC padding and
single-read behavior have differential and read-count coverage.

A permitted two-chain Rayon join is preserved when spare workers exist.
Paired assembly is used when those chains would otherwise execute serially.
A red/green execution-counter regression distinguishes these paths without
asserting timing. Rust-only builds exclude both handwritten MD5 assembly
modules and retain their safe MD5 fallback. Other SIMD, FFI, mmap and JIT
unsafe code remains in the crate and dependencies; this is not an
unsafe-free build.

The port uses the public-domain/CC0 `md5x2-x86-asm.h` and
`md5x2-arm-asm.h`, with no GPL wrapper copied. Original source links and
existing license notices are retained. These terms are compatible with the
library's Apache-2.0 terms and impose no commit-attribution trailer.
See [the pinned instruction sources](https://github.com/animetosho/par2cmdline-turbo/tree/3e60f6fcfed52bf257e79c46deae616cb6135d59/parpar/hasher)
and [ParPar's license](https://github.com/animetosho/ParPar#license).

Discovery reuses the unfinished, budgeted seed scan, preserving orphan IFSC
packets across volumes in either order. A failed scanner cannot be reused.
The normal path parses the seed once. The rare deferred recovery fallback
can reparse the combined set. Sibling discovery starts with `name.*.par2`,
and defers unrelated headers and protected-name/length matches. Missing
metadata or incomplete verification triggers the exhaustive fallback;
fully verified canonical data can be skipped safely. Regressions cover a
removed seed, split metadata and obfuscated recovery at a protected name
and exact length.

RAR5 recovery clamps capacity to useful volume bytes with even GF16 padding.
The spare input set is allocated only when another chunk exists. Large
restores retain the existing two-input-set budget and overlapping reads.
Short even/odd tails, actual multi-chunk read-ahead and output bytes are tested.
The THP-off default is unchanged.

During PR review, `par verify --name` was found to omit deferred volumes
before choosing its file. It now expands those volumes before reading stdin:
the pipe cannot be reread if hidden metadata changes its checksums. This
stream-only path opens deferred candidates eagerly, preserving descriptions,
IFSC checksums and recovery-block counts. Disk verification retains its lazy
fallback. A real pipe regression covers missing FileDesc, missing IFSC and
complete metadata with obfuscated recovery blocks, and checks clean and damaged
verdicts. The original implementation fails the regression. Tracing now writes
to stderr, keeping warnings out of JSON stdout without suppressing them.
The narrow paired-MD5 exception in AGENTS.md records the operator's explicit
F2 instruction; source origins, notices and single-stream fallback remain.

## Native Spot method and scope

| Host | Actual CPU / caches | Target | Instance |
|---|---|---|---|
| C7a | EPYC 9R14, four physical cores; 32 KiB L1D and 1 MiB L2 per core, 16 MiB L3 | x86_64-unknown-linux-musl | `i-08e37c8d92b700874` |
| C6g | Neoverse-N1 r3p1, four cores; 64 KiB L1D and 1 MiB L2 per core, 32 MiB L3; PMULL, no SHA3 | aarch64-unknown-linux-musl | `i-0bce259217f9fba25` |

Both native Linux hosts used Rust 1.97.1 / LLVM 22.1.6, the musl target,
`--locked --offline`, release fat LTO and one codegen unit, debug information,
no stripping, and `RUSTFLAGS=-Cforce-frame-pointers=yes`.
`CARGO_BUILD_JOBS=4`; C was built with `-DMI_DEFAULT_ALLOW_THP=0`, plus
`-march=x86-64 -mtune=generic` on x86. Baseline and candidate used the same
compiler, flags, locked third-party dependency resolutions and default
features; only the documented workspace package versions differ. Binary hashes and
compiler/tool logs are retained. Production builds did not enable the
benchmark cfg; a separate diagnostic build did.

Each role used a fresh copy of identical inputs and wrote outputs on the
same root gp3/ext4 filesystem. No disk/tmpfs comparison, cache drop, kernel
THP change or security change was made. Default affinity exposed CPUs 0–3;
`RAYON_NUM_THREADS=4`, except the explicit one-worker controls.
Native ELF architecture and hashes were checked before measurements.

The heavy archive is 80,704,030 bytes, SHA-256
`b80bcf6ad34c9b1e9c836cb82da674e7d87209c65427e57685bcbe611c774e3c`.
Damage matches the harness: 64 KiB blocks, stride
`ceil(file_bytes/65536)/(damage+1)` rounded down, then 1,024 bytes of
`0xa5` written at each chosen block plus offset 100, followed by `fsync`.
Every repaired archive was SHA-256 checked outside the measured interval.
The four-file case protects four 16 MiB files with the pinned turbo 1.4.0.

RAR cases reuse the existing fleet corpus, including v5/v7 writers, one/two
missing volumes, recovery plus extraction, complete extraction and RAR3
control. The large case uses a deterministic 64 MiB + 4,097-byte payload,
RARLAB 7.23 store mode, nine 8 MiB volumes and two recovery volumes. The
writer archive's pinned BLAKE3 is
`edc2f6074771680eed9317fc8288c027c6b0a550201ac1889e3ea8a478d66784`.
Its exact generated bytes were copied from x86 to ARM and verified there.
Both missing-volume counts span three unchanged recovery compute chunks.
All source, restored-volume and extraction hashes are checked.

The native C launcher measures `CLOCK_MONOTONIC` around fork/exec plus a
blocking `wait4`, and records child user/system CPU, RSS and fault counts.
Python's timeout polling does not supply the measured wall time. Role order
is randomized in paired rounds; staging, output checks and warmups are
outside accepted samples. RAR runs use `MIMALLOC_ALLOW_THP=0` and observe
`THP_enabled=0` in the child. Some short samples also observe the initial
process-enabled state before `main` disables THP; raw state sets are retained.

All bulk debug-binary exports finish before accepted timing windows. The
initial x86 campaign overlapped exports and is retained separately. Its
final repeat completed production/control rows, then the reference refused
an existing four-file parity target. Those 180 valid rows were preserved;
only the remaining cases resumed in a fresh fixture directory. No failed
observation or assertion was removed. ARM uses an export barrier from the
start. Small metric checkpoints continue during runs.

Captured heavy-250 plans distinguish slice bytes from compute tiles:

| Host | Rarpar backend / compute tile / chunks / source batch | Turbo tile / block grouping |
|---|---|---|
| C7a | Folded / 8,224 bytes / eight / twelve | 4,224 bytes / twelve |
| N1 | NeonPacked / 16,416 bytes (last 16,320) / four / twelve | 8,224 bytes / sixteen |

Both Rarpar plans request four workers. All four assignments cover all 250
outputs and partition the byte ranges. Complete assignments, baseline debug
plans and reference verbose output are retained with the raw logs.

## Current PAR2 medians

Times are wall / total child CPU milliseconds. Heavy cases have seven
measured rounds after one warmup; clean four-worker has fifteen, clean
one-worker and four-file have eleven. Ranges and all raw rows are retained.

| Host / workload | n | Baseline wall / CPU | Candidate wall / CPU | Turbo wall / CPU |
|---|---:|---:|---:|---:|
| C7a / Zen 4 clean, 4 threads | 15 | 240.01 / 192.84 | 248.50 / 192.39 | 161.53 / 161.43 |
| C7a / Zen 4 clean, 1 thread | 11 | 261.61 / 184.51 | 242.19 / 171.59 | 161.81 / 161.72 |
| C7a / Zen 4 four files, 4 threads | 11 | 36.26 / 125.83 | 32.94 / 113.10 | 51.90 / 99.36 |
| C7a / Zen 4 heavy-28, 4 threads | 7 | 143.55 / 212.70 | 142.00 / 208.79 | 469.44 / 520.63 |
| C7a / Zen 4 heavy-250, 4 threads | 7 | 266.89 / 483.56 | 266.76 / 471.56 | 763.58 / 971.92 |
| C6g / N1 clean, 4 threads | 15 | 333.04 / 350.84 | 345.26 / 351.00 | 274.36 / 274.22 |
| C6g / N1 clean, 1 thread | 11 | 429.83 / 342.06 | 377.13 / 285.70 | 274.32 / 274.22 |
| C6g / N1 four files, 4 threads | 11 | 64.12 / 232.85 | 52.21 / 185.23 | 91.21 / 176.98 |
| C6g / N1 heavy-28, 4 threads | 7 | 362.19 / 737.27 | 362.93 / 737.01 | 788.07 / 1,073.24 |
| C6g / N1 heavy-250, 4 threads | 7 | 1,158.52 / 3,610.52 | 1,160.04 / 3,607.86 | 1,773.79 / 4,008.57 |

Single-worker and file-parallel verification show the targeted paired-hashing benefit. Four-worker single-file clean verification has essentially unchanged CPU, but wall medians are 3.5% higher on C7a and 3.7% higher on N1; ranges overlap broadly, and no speedup is claimed for this case. Heavy-28 and heavy-250 remain close to baseline. The small uninstrumented C7a heavy-250 CPU decrease is not accompanied by a comparable perf-counter decrease, so no compute-kernel speedup is claimed. Both Spot hosts beat turbo on heavy repair in these runs, while single-file clean verification still uses more CPU than turbo. These are combined-candidate observations, not isolated causal estimates for every component.

Diagnostic controls force the old path with `RARPAR_BENCH_STITCHED=0`, the
paired path with `=1`, or leave adaptive dispatch unset. These variables
exist only in the diagnostic build. Its logs show the actual join and
stitched choices. Production tile and source-batch preferences are unchanged.

## Current RAR5 medians

Times are wall / total child CPU milliseconds; RSS is peak MiB.
Small cases have fifteen measured rounds after two warmups; large cases
have seven. Baseline/candidate storage, affinity and flags are identical.

| Host / case | Baseline wall / CPU | Candidate wall / CPU | RSS MiB baseline → candidate |
|---|---:|---:|---:|
| C7a / Zen 4 RAR5 v7 restore 1 missing | 42.55 / 45.95 | 10.23 / 12.80 | 61.70 → 15.85 |
| C7a / Zen 4 RAR5 v7 restore 2 missing | 45.32 / 51.73 | 11.64 / 16.35 | 62.20 → 16.85 |
| C7a / Zen 4 RAR5 v5 restore 1 missing | 42.46 / 46.05 | 10.09 / 12.80 | 61.70 → 15.76 |
| C7a / Zen 4 RAR5 v7 recovery + extract 1 missing | 69.19 / 100.21 | 35.28 / 65.95 | 73.57 → 27.64 |
| C7a / Zen 4 RAR5 v7 recovery + extract 2 missing | 68.42 / 100.16 | 36.72 / 69.04 | 63.57 → 28.14 |
| C7a / Zen 4 RAR5 v5 recovery + extract 1 missing | 69.84 / 103.09 | 35.34 / 66.60 | 73.57 → 27.51 |
| C7a / Zen 4 RAR5 v7 complete extract | 26.08 / 58.91 | 27.44 / 57.84 | 17.57 → 17.64 |
| C7a / Zen 4 RAR3 control extract | 16.04 / 15.96 | 15.62 / 15.54 | 9.70 → 9.52 |
| C7a / Zen 4 RAR5 large restore 1 missing | 60.41 / 86.04 | 61.19 / 85.41 | 69.95 → 69.98 |
| C7a / Zen 4 RAR5 large restore 2 missing | 64.05 / 103.47 | 64.84 / 103.52 | 69.95 → 70.01 |
| C7a / Zen 4 RAR5 large recovery + extract 1 missing | 74.31 / 106.91 | 72.67 / 105.66 | 76.82 → 71.01 |
| C7a / Zen 4 RAR5 large recovery + extract 2 missing | 76.97 / 125.86 | 73.88 / 120.70 | 76.82 → 70.89 |
| C6g / N1 RAR5 v7 restore 1 missing | 30.62 / 34.84 | 8.95 / 13.07 | 61.13 → 15.07 |
| C6g / N1 RAR5 v7 restore 2 missing | 31.88 / 38.24 | 10.49 / 16.14 | 61.76 → 16.20 |
| C6g / N1 RAR5 v5 restore 1 missing | 30.80 / 35.17 | 9.05 / 13.17 | 61.13 → 15.07 |
| C6g / N1 RAR5 v7 recovery + extract 1 missing | 62.43 / 104.59 | 41.52 / 85.79 | 62.63 → 26.45 |
| C6g / N1 RAR5 v7 recovery + extract 2 missing | 67.60 / 107.80 | 46.74 / 88.95 | 62.88 → 27.95 |
| C6g / N1 RAR5 v5 recovery + extract 1 missing | 62.67 / 104.65 | 43.73 / 86.03 | 62.63 → 26.95 |
| C6g / N1 RAR5 v7 complete extract | 35.57 / 77.83 | 38.88 / 77.26 | 17.01 → 17.07 |
| C6g / N1 RAR3 control extract | 24.19 / 24.12 | 24.25 / 24.17 | 8.76 → 8.95 |
| C6g / N1 RAR5 large restore 1 missing | 44.66 / 71.01 | 45.03 / 71.32 | 69.38 → 69.32 |
| C6g / N1 RAR5 large restore 2 missing | 48.90 / 89.42 | 48.85 / 88.99 | 69.38 → 69.32 |
| C6g / N1 RAR5 large recovery + extract 1 missing | 63.65 / 109.08 | 63.94 / 107.88 | 73.88 → 70.32 |
| C6g / N1 RAR5 large recovery + extract 2 missing | 68.07 / 128.16 | 68.45 / 128.03 | 70.01 → 70.20 |

The earlier supplied ADL default-affinity recovery-plus-extraction result
had higher CPU (102.74 → 124.58 ms) despite lower wall time. That result is
retained in the recovery bundle. Four-CPU ADL and these four-core Spot
results do not justify a universal full-job CPU-saving claim. Prior SYLIX
native CLI checks passed, but Windows security denied the separate
allocation-count diagnostic before execution. It was not retried or bypassed.

## Counters and profiles

The heavy-250 counter pass has five repetitions for each production role
and turbo. It is separate from normal timings. Cycles profiles use 199 Hz,
frame-pointer call graphs and retained unstripped binaries.

| Host / event | Baseline median | Candidate median | Turbo median |
|---|---:|---:|---:|
| C7a / Zen 4 task-clock ms | 533.517 | 535.065 | 1,091.182 |
| C7a / Zen 4 cycles billion | 1.683 | 1.684 | 3.479 |
| C7a / Zen 4 instructions billion | 2.901 | 2.901 | 7.414 |
| C7a / Zen 4 L1-dcache-load-misses million | 0.000 (non-informative zero) | 0.000 (non-informative zero) | 0.000 (non-informative zero) |
| C6g / N1 task-clock ms | 3,953.872 | 3,952.706 | 4,480.794 |
| C6g / N1 cycles billion | 8.978 | 8.984 | 9.619 |
| C6g / N1 instructions billion | 14.890 | 14.927 | 18.672 |
| C6g / N1 l1d_cache_refill million | 462.202 | 464.038 | 55.061 |
| C6g / N1 l2d_cache_refill million | 16.247 | 15.631 | 16.250 |
| C6g / N1 ll_cache_miss_rd million | 0.000 (non-informative zero) | 0.000 (non-informative zero) | 0.000 (non-informative zero) |

C7a / Zen 4: unsupported counters: LLC-load-misses. Accepted but zero in all workload samples: L1-dcache-load-misses. Zero-valued cache events are non-informative; they do not establish absence of misses.

C7a / Zen 4 candidate profile: # Total Lost Samples: 0, # Samples: 200  of event 'cycles'. Largest resolved self symbol: `reedsolomon_rs::gf_simd::mul_acc_folded_pair_gfni_avx512`, 49.86%. Sampling percentages are descriptive; small profiles and incomplete deep unwinds limit attribution.

C7a / Zen 4 minimum reported counter running percentage: 100.0%.

C6g / N1: unsupported counters: none among requested probes. Accepted but zero in all workload samples: ll_cache_miss_rd. Zero-valued cache events are non-informative; they do not establish absence of misses.

C6g / N1 candidate profile: # Total Lost Samples: 0, # Samples: 837  of event 'cycles'. Largest resolved self symbol: `reedsolomon_rs::gf_simd::mul_acc_input_batch_clmul_prepared`, 87.14%. Sampling percentages are descriptive; small profiles and incomplete deep unwinds limit attribution.

C6g / N1 minimum reported counter running percentage: 39.0%.

N1 hardware events were multiplexed: the lowest running fraction was 39–42% for the last-level/L2 events and about 59–63% for cycles/instructions/L1. The table retains perf-scaled estimates; do not infer precise refill changes or a cache cause from this pass. The uninstrumented CPU/wall samples remain the primary performance comparisons. Task-clock CSV values are raw nanoseconds, converted to milliseconds in this table.

## Earlier Cortex-A72 evidence and remaining F1 gap

The previous approved a1.xlarge was an actual Cortex-A72 (part `0xd08`),
with 32 KiB L1D per core, shared 2 MiB L2 and no L3. It was terminated and
its storage/network cleanup verified before the Spot phase. These results
apply to the archived **8 KiB / always-paired** candidate, not the current
join-preserving candidate:

| Workload | Baseline wall / CPU ms | Archived candidate | Turbo |
|---|---:|---:|---:|
| Clean | 465.77 / 493.58 | 566.42 / 457.25 | 465.77 / 426.55 |
| Heavy-28 | 769.13 / 1,853.14 | 768.36 / 1,772.46 | 1,270.52 / 1,899.43 |
| Heavy-250 | 3,227.55 / 11,175.63 | 3,126.30 / 10,608.74 | 3,128.32 / 7,856.57 |

That Python harness used timeout polling with sleeps up to 50 ms, producing
coarse wall buckets. Scheduling can add further delay, so this is not a
hard 50 ms error bound. The near-identical baseline/turbo clean medians are
a polling result, not a copied number. Independent application phase logs
confirm a real always-paired clean regression: verification median
327.846 ms baseline versus 455.807 ms paired; the stitching-disabled control
was 308.305 ms. This motivated preserving the available parallel chains.

A72 diagnostic 8/16/32 KiB heavy-250 CPU medians were
10,397 / 10,607 / 10,603 ms, and heavy-28 were 1,746 / 1,795 / 1,791 ms.
The 16-source control regressed. One/two workers and the disabled-CLMUL-batch
control were also recorded. Five-repeat perf data, plan lines and a profile
are retained outside the repository. `ll_cache_miss_rd` was unsupported.
The archived candidate spent 91.24% of sampled self time in the prepared
CLMUL input-batch kernel, with no lost samples; some deep unwinds were
unresolved. The same-binary 8/32 comparison lowered cycles slightly without
lower L1/L2 refill counts. Thus the proposed shared-L2 explanation remains
a hypothesis. Archived heavy-250 CPU was still about 35% above turbo, and
the wall difference against turbo was below the timer's resolution.

**The current candidate has not been measured on A72.** N1 is different
microarchitecture/cache coverage, not an A72 replacement. No unmeasured
A72 improvement or completed F1 CPU criterion is claimed.

## Correctness, package and API gates

The full local run used complete existing fixtures. An initial broad attempt
exposed missing fixtures and inherited `RUST_LOG=info`; missing fixtures were
copied from the existing checkout and diagnostic environment variables were
removed, then the full suite passed. No assertion or selector was weakened.

Local commands were dispatched with `rtk proxy` and `CARGO_BUILD_JOBS=4`,
using the external build target directory.

```text
cargo fmt --all --check
cargo clippy --workspace --all-targets --features unrar-rs/unstable-internals --locked --offline -- -D warnings
cargo nextest run --workspace --features unrar-rs/unstable-internals --locked --offline --no-fail-fast --test-threads 4
cargo nextest run -p par2-rs --features slow-tests --locked --offline --no-fail-fast --test-threads 4
cargo test --doc --workspace --features unrar-rs/unstable-internals --locked --offline
cargo nextest run -p par2-rs --no-default-features --features crypto-rust --locked --offline --no-fail-fast --test-threads 4
cargo run --locked --offline -p xtask -- docs --check
cargo metadata --locked --offline --no-deps --format-version 1
cargo package --locked --offline -p par2-rs --allow-dirty
cargo package --locked --offline -p unrar-rs --allow-dirty
cargo semver-checks -p par2-rs --baseline-version 0.10.11 --default-features
cargo semver-checks -p unrar-rs --baseline-version 0.12.0 --default-features
```

Results: formatting/lint/docs/metadata/package pass; 3,201 workspace nextest
passes (24 skipped), 725 PAR2 slow passes (three skipped), 675 Rust-only
passes (three skipped), 25 doctest passes. Each library passed 196 applicable
semver checks (58 skipped). Formatting and semver-checks do not accept
`--locked`; formatting does not resolve dependencies.

Native build/test commands, with each host's matching target substituted:

```text
cargo build --locked --offline --release --target x86_64-unknown-linux-musl -p rarpar
cargo build --locked --offline --release --target aarch64-unknown-linux-musl -p rarpar
cargo test --locked --offline --target TARGET -p par2-rs --lib -- --test-threads=4
cargo test --locked --offline --target TARGET -p unrar-rs --lib recovery:: -- --test-threads=4
cargo test --locked --offline --target TARGET -p par2-rs --no-default-features --features crypto-rust --lib -- --test-threads=4
cargo test --locked --offline --profile memcheck --target GNU_TARGET -p par2-rs --lib --no-run --message-format=json
```

| Native lane | C7a | N1 |
|---|---:|---:|
| PAR2 native | 622 passed, 2 ignored | 608 passed, 2 ignored |
| RAR5 recovery | 53 passed | 53 passed |
| PAR2 Rust-only | 615 passed, 2 ignored | 601 passed, 2 ignored |
| GNU Memcheck selector | 197 passed, no ignored tests | 183 passed, no ignored tests |

The GNU test binary runs the exact native unsafe selector from CI, with
`valgrind --quiet --fair-sched=yes --error-exitcode=1 --leak-check=full
--errors-for-leak-kinds=definite,indirect`, one libtest thread and two test
processes. ARM retains the existing FFT suppression file. No new suppression
was added. Fair scheduling prevents Valgrind starving the existing 5 ms
cancellation watchdog; assertions and timing thresholds are unchanged.
Scalar-state, independent streaming, guard-page, selected-backend execution,
strict verdict/read-count and actual dispatch regressions are included.

No current GPU performance, full Windows PAR2 suite or new ASan result is
claimed. Both musl release builds retain the pre-existing `libc::time_t`
deprecation warning; host Clippy with warnings denied passed.

## PR review follow-up validation, 2026-10-19

The real-pipe regression failed on `054d1877` (exit 100, missing requested
name). After eager stream metadata expansion it exposed warnings on JSON
stdout; directing tracing to stderr fixed that without relaxing the test.
All 16 stream CLI tests then passed, including clean/damaged checks for
FileDesc, IFSC and obfuscated recovery counts. The full local workspace
passed again with 3,202 tests and 24 skips; 25 doctests passed. Formatting,
warnings-denied Clippy, locked docs and locked metadata also passed.
Library implementations, dependency versions and resolutions did not change.
The exact commands use the same external target directory and four jobs:

```text
cargo fmt --all --check
cargo nextest run --locked --offline -p rarpar --test stream_cli --no-fail-fast --test-threads 4
cargo clippy --workspace --all-targets --features unrar-rs/unstable-internals --locked --offline -- -D warnings
cargo nextest run --workspace --features unrar-rs/unstable-internals --locked --offline --no-fail-fast --test-threads 4
cargo test --doc --workspace --features unrar-rs/unstable-internals --locked --offline --no-fail-fast
cargo run --locked --offline -p xtask -- docs --check
cargo metadata --locked --offline --no-deps --format-version 1
```

## Deferred-discovery review regressions, 2026-10-19

The review of `c7400e9` found two further CLI issues. Real-pipe tests
reproduced ENOENT for an absent `-C` directory and EACCES when opening a
protected file whose length cannot form a PAR2 volume. Deferred expansion
now returns immediately for no candidates and canonicalizes the primary
only as an optional optimization for verified canonical data. Missing
working directories remain valid in Smart and Canonical placement, with
and without deferred metadata.

Exhaustive discovery and deferred expansion share the recorded-name/length
guard; a matching protected file shorter than a header or not divisible by
four is skipped unread. All files shorter than a header are also rejected
before opening. Other names and mismatched lengths remain eligible, including
valid obfuscated volumes; no general nonmultiple-of-four filter was added
for unknown files that might contain packets plus trailing bytes.

The regressions cover unreadable 32/65-byte protected files and an unreadable
unrelated sub-header sibling. All 18 stream tests pass, along with 3,204 full
workspace tests (24 skipped), 25 doctests, formatting, warnings-denied Clippy,
locked docs and locked metadata. The commands are the same as the preceding
review-follow-up run. Library MD5 backend selection, parallel scheduling and
all dependency/version records are unchanged. These CLI changes have no new
performance measurements.

## Durable MD5 safety CI audit, 2026-10-19

Completed c7400e9 workflow logs confirm the paired-state, runtime-dispatch,
guard-page and strict single-read tests passed in the existing native
Memcheck jobs (197 x86 tests, 183 AArch64 tests). The new controls retain
those jobs and add no runner or matrix job. The audit found that broad
selectors alone could hide cfg-gated omissions, Valgrind could mask host
BMI1, the original guard case was narrow, and Rust-only exclusion lacked
an explicit build-artifact assertion.

The existing native jobs now require the actual selected nextest inventory
and execute a short uninstrumented checksum pass before reusing the same
build under Memcheck. Nonempty execution counters prove native assembly,
forced x86 baseline and runtime BMI1 where advertised. Test-only mapping
checks distinguish the uninstrumented pass from actual Memcheck execution.
The inventory checker fails for absent, ignored, filtered or wrongly compiled
backend tests; five negative/self tests cover those failure modes.

Bounds coverage includes 384 two-sided guard cases and 192 exact-sized heap
cases for unaligned Memcheck redzones. Arbitrary-state coverage contains
20,480 length/alignment/state cases, including 16,384 nonempty calls. Native
and both-feature tests still require the assembly default. Rust-only jobs
require the portable fallback and absence of native MD5 tests; a real LLVM
IR audit rejects both handwritten MD5 modules. Existing x86/ARM ASan jobs
require portable verdict/read-count coverage with native tests excluded.
See [the coverage mapping](unsafe-validation.md#fail-closed-md5-assembly-controls).
Miri is not assembly coverage, and no MD5 Miri claim is made. Linux provides
native instrumentation; Darwin/Windows retain functional platform tests,
with Unix guard pages on Darwin and no Windows instrumentation claim.

On the combined tree including the operator's a3b6df5 commit, local validation
passed 3,207 workspace tests (24 skipped), 25 doctests, warnings-denied Clippy,
all-feature checks, formatting, locked docs/metadata and both package checks.
The selected native/both/Rust-only MD5 passes ran 20/21/12 tests. Native and
both modes require 12/13 named tests respectively, including strict dispatch;
Rust-only requires four portable tests and excludes native dispatch. The
Rust-only IR audit passed. Workflow actionlint also passed. The operator's
Rust-only crypto and encrypted integration lanes passed 60 and 19 tests;
the combined-crypto lane passed 66.

Par2-rs semver checks passed 196 applicable checks (58 skipped). For unrar-rs,
a forced-minor compatibility probe identified only the deliberate Copy
removal (195 pass, one incompatible API finding, 58 skip). Checking the
actual 0.12 → 0.13 version step correctly classifies it as breaking and
accepts it; 254 API checks are skipped at that permitted boundary. This is
not a claim that the new API is backward compatible. Formatting and
semver-checks do not support `--locked`; other Cargo gates used it.

The operator's added cache tests also produced six CodeQL hard-coded-value
alerts against fixed test passwords/salts. The flagged lines are inside
`#[cfg(test)] mod tests` and exercise cache identity and Debug redaction,
not production credentials. They were not dismissed, suppressed, hidden by
query configuration, or changed to evade analysis. Their resolution remains
separate from the native safety controls. No additional AWS resource or
security-setting change was used.

## Resource cleanup, evidence and publication

| Lease | Launch UTC | Local / guest deadlines UTC | Verified final resources |
|---|---|---|---|
| `i-08e37c8d92b700874` | 18:08:50 | 19:38:50 / 19:49:07 | terminated; roots `vol-03eb85f7ec9abe8ef` deleted; ENIs `eni-056a5c634acf7e332` deleted; no snapshots or active SSM sessions |
| `i-0bce259217f9fba25` | 18:53:58 | 20:23:58 / 20:34:19 | terminated; roots `vol-050feb81d862c628b` deleted; ENIs `eni-03c0fb54e4b036580` deleted; no snapshots or active SSM sessions |

One-time Spot requests used the verified existing subnet, security group,
SSM profile and Spot role. No inbound rule, credentials, role, EIP, snapshot,
S3 object, persistent service or on-demand replacement was created. Each
root and interface used DeleteOnTermination, with independent local
90-minute and guest 100-minute termination guards. Completed logs/metrics
were checkpointed locally and all three debug binaries exported and hashed
before accepted timings. Spot notices were checked every five seconds;
notices are best effort, and the last uncompleted trial can be lost on an
abrupt interruption. No interruption occurred in the observed runs.

The approved combined Spot cap was US$5, including storage, transfer and mandatory network charges. Observed pre-launch quotes were $0.0799/hour for C7a and $0.0744/hour for C6g; bids were capped at verified on-demand rates $0.20528 and $0.136. Using the full launch-to-cleanup interval, those bid ceilings, 32 GiB gp3 roots, public IPv4, and a conservative four-GB transfer allowance at $0.15/GB gives an upper estimate of **US$0.88**, not a settled invoice. No task-owned resources remain accruing charges. The earlier separately approved A72 run was estimated below $0.23.

C7a / Zen 4: 207710708 bytes, SHA-256 `23860d592d9515d978e20cea6491601ecd9ea073d0e96a7c7301d8f957af3784`.

C6g / N1: 1185601 bytes, SHA-256 `9b28621415ad2debd6c31846bd5af2a3b2c83e860de01736f83a9c8d82366927`.

The ARM final archive contains new raw metrics/logs/profiles only. Its debug binaries were exported and independently hashed before timing, and its fixture bytes already exist in the shared input and x86 archive; these large files were not redundantly exported at the end. Exact inputs, binaries, helper revisions, source hashes, raw perf files, all samples and cleanup receipts are retained in the task artifacts outside this repository.

Local Podman inspection was denied by automatic approval review after a
socket permission failure and was not retried. Prepared source/dependency
bundles were built on the approved Spot hosts instead. All raw data remains
outside the repository, including earlier unfavorable measurements and
recoverable harness failures.

Residual c5 verification CPU remains a follow-up in the PR body. No c5
profiling, GitHub issue or auto-merge was performed. The change remains on
one branch. Signing initially failed with `1Password: failed to fill whole
buffer`; the operator reported signing available on 2026-10-19 and authorized
the signed-commit and PR flow. No unsigned bypass is permitted.

## Version reconciliation and intentional additions, 2026-10-19

Initial publication preflight found main at `e954b913`, published par2-rs
0.10.11, unrar-rs 0.12.0 and rarpar 0.9.1. The initial performance branch
proposed unrar-rs 0.12.1 separately from PR #121's 0.13.0 API change.

The operator then intentionally added signed commit `a3b6df5` to this PR:
64 cached RAR5 derivations, redacted key debugging, and non-Copy key material
that zeroizes on drop. The combined branch therefore uses unrar-rs 0.13.0,
with recovery-buffer and API-change entries under one heading and rarpar's
requirement at 0.13.0. The CI additions were reconciled by fast-forwarding
to the operator's commit, preserving all six of its changed files. No user
code was reset, removed or rewritten. No third-party dependency changed.

This branch no longer proposes a 0.12.1 release. PR #121 remains separate
and was not modified or merged by this work. Its overlapping KDF/version
changes require reconciliation before both PRs can land; the second PR must
preserve already-landed code and changelog entries. Reuse appropriate
unpublished 0.13.0 / CLI 0.9.2 versions, or use the next patch if published
before additional behavior lands. No release is performed here.
