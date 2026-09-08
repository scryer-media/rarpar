# Native PAR3 performance

## x86-64 results, 2026-09-08

Host: Intel Core i5-1240P, native Linux x86-64, 62 GiB RAM, AVX2 and GFNI;
Rust 1.98.1 / LLVM 22.1.8, GCC 15.2.0. The existing `powersave` governor was
left unchanged. Library code is revision `f5fd7c1`; the benchmark harness is
recorded in `048ca20`. No engine implementation changes were made for this run.

All **534 measured invocations passed** across 54 trials. This includes
reference verification of newly created sets and SHA-256 confirmation of both
engines' repaired files. All 54 batches of 100 cached reassessments performed
zero source reads. The small-file trials staged exactly the 64 damaged files.

The ratios below are reference wall time divided by engine wall time; above
1.0 means higher engine throughput. Each workload contributes equally to its
codec's geometric mean, calculated from three-run median process times.

| Codec / worker ceiling | Create | Verify | Repair |
| --- | ---: | ---: | ---: |
| Cauchy / 1 | 3.43× | 3.27× | 5.07× |
| Cauchy / 4 | 3.44× | 3.42× | 5.66× |
| FFT / 1 | 1.25× | 2.48× | 1.72× |
| FFT / 4 | 1.37× | 2.49× | 1.88× |

These measured x86-64 aggregates exceed the reference for both codecs. They
do **not** complete performance acceptance: the ARM64 run below exposes an FFT
creation shortfall, this is the first native x86-64 baseline, and there are
individual shortfalls worth tuning. No historical x86-64 regression percentage is inferred
from the earlier emulated reference or contended ARM64 runs.

One-worker median times, in milliseconds (engine / reference):

| Workload | Create | Verify | Repair |
| --- | ---: | ---: | ---: |
| Cauchy GF8 | 65.8 / 267.0 | 15.8 / 60.6 | 57.9 / 328.6 |
| Cauchy GF16 | 79.0 / 395.7 | 21.1 / 42.9 | 101.7 / 380.4 |
| FFT GF8 | 83.5 / 104.9 | 17.5 / 63.2 | 326.0 / 408.5 |
| FFT GF16 | 56.1 / 92.3 | 23.6 / 45.7 | 212.2 / 324.9 |
| Uneven FFT | 82.8 / 80.5 | 23.3 / 44.6 | 303.3 / 272.5 |
| Heavy Cauchy | 2014.6 / 10411.3 | 72.1 / 199.3 | 1395.4 / 11625.1 |
| Heavy FFT | 318.4 / 381.5 | 69.0 / 196.5 | 897.2 / 4498.2 |
| Large blocks | 53.2 / 154.6 | 18.6 / 394.9 | 54.3 / 693.8 |
| Small files | 13.7 / 21.2 | 14.8 / 12.1 | 16.0 / 23.6 |

All raw timings, including four-worker results, are in the evidence archive.
Four workers reduced heavy Cauchy repair to 665.8 ms and heavy FFT repair to
793.3 ms. Worker count is a ceiling, not a guarantee of parallel execution.

### Shortfalls and stage attribution

- **Small-file verification:** one-worker engine time was 14.8 ms versus
  12.1 ms. Its median ingestion stage alone took 9.2 ms; assessment took
  2.7 ms. A separate syscall-count probe recorded 4,445 `openat`, 5,222 `statx`,
  and 4,184 `lseek` calls for the engine versus 298 `openat` calls for the
  reference. The current disk provider opens positioned reads individually;
  a bounded carrier-reader cache is a concrete tuning candidate. Traced times
  were excluded from the benchmark aggregates.
- **Uneven FFT repair:** one-worker time was 303.3 ms versus 272.5 ms. Nested
  decoder timing accounted for 268.1 ms of the engine's 279.5 ms repair stage
  across three cohorts. The decoder still uses scalar per-symbol locator
  multiplication around the dispatched transforms; this is a candidate for
  further profiling, not a proven exclusive cause. Four-worker process times
  were approximately equal: 268.8 ms versus 273.7 ms. A hardware-counter probe
  was refused by the host's existing `perf_event_paranoid=4`; no host policy
  was changed.

Scan-only medians range from 1–8 ms on the ordinary cases and about 26–28 ms
on heavy cases. CRC64 placement traversed a 32 MiB input in about 171–176 ms,
and a 128 MiB input in about 700–714 ms. Those are separate engine stages,
without a matched reference CLI measurement.

### Memory observations

All engine reservation peaks stayed within their configured ceilings, and the
maximum observed engine handle count was two. Reservations are conservative
and can exceed physically resident allocations.

- With an **8 MiB** setting and 4 MiB blocks, peak reservation was 4.18 MiB;
  engine repair RSS was at most 3.55 MiB, versus 23.67 MiB for the reference.
- With **64 MiB** configured for heavy Cauchy, repair RSS peaked at 28.32 MiB
  versus 54.11 MiB. Heavy FFT peaked at 65.55 MiB versus 77.38 MiB: allocator
  and runtime overhead explain why RSS is not the engine reservation limit.
- Across the complete matrix, peak engine repair RSS was 67.98 MiB, versus
  118.22 MiB for the reference. These are different workloads' maxima.

### Evidence

[`benchmarks/native-x86-20260908.tar.gz`](benchmarks/native-x86-20260908.tar.gz)
contains the final 534 JSONL records, per-process logs and RSS measurements,
input digests, compiler/CPU provenance, final binary hashes, syscall probes,
and Criterion raw samples. It contains no protected inputs or PAR3 packets.
Archive SHA-256:
`f782e3b965acb3228e9448f5bb079e79b6797c8c299d185da37daf3707fe0bee`.
The earlier pilot runs are excluded: the first timing wrapper had polling
granularity, and the initial driver included 100 reassessments in its process
timing. Both were corrected before the final run; no pilot timing enters the
tables above.

The companion [Cantor transform measurements](../reedsolomon-rs/FFT_BENCHMARKS.md)
record the arithmetic-only comparison. Automatic x86 dispatch was 6.35–10.17×
faster than scalar in those four shapes. That speedup is not an end-to-end
throughput ratio.

## ARM64 results, 2026-09-08

Host: Apple M5 Max, 18 logical CPUs, 128 GiB RAM, macOS 26.6.2;
Rust 1.97.1 / LLVM 22.1.6, Homebrew Clang 22.1.8 and libomp 22.1.7.
Library code is unchanged from the x86-64 run; the Mac runner is `10b1640`.
Rust uses `-C target-cpu=native`; the reference uses `-mcpu=native -fopenmp`.
There is no emulation, CPU affinity, or frequency control. Existing services
remained running; measured one-minute host load ranged from 3.92 to 8.71.
No build or other task-owned benchmark ran concurrently with the final matrix.

All **534 final invocations passed** across the same nine workloads, two worker
ceilings, and three repetitions. Every Rust-created set verified with the
reference; both engines' repaired files matched saved SHA-256 input digests.
All 54 batches of 100 unchanged reassessments had zero source bytes and read
calls. Each small-file trial staged exactly the 64 damaged files.

### Reference-build qualification

The pinned reference does not provide a macOS build. Its benchmark-only scratch
adaptation enables the existing POSIX platform layer, adjusts headers and
timestamp access, and replaces x86-only compiler flags. Leopard's existing ARM
path uses the added, pinned SSE2NEON header. Because the archive also lacks the
BLAKE3 NEON source, its existing SSE2 hashing source is compiled through that
same header and exposed to the ARM dispatcher with a symbol alias. Single-block
compression retains the reference's portable ARM path. No algorithm bodies or
Rust dependencies changed.

These results compare against that **adapted reference**, not an official
macOS binary or an upstream dedicated-NEON BLAKE3 build. The exact patch, header
revision and hash, compiler flags, binary hashes, and build recipe are archived.
A prior complete portable-hashing reference run and all pilots are excluded
from the reported ratios. Both-way verification and repair checks were repeated
after enabling SIMD hashing.

### Throughput

Reference wall time divided by engine wall time, using the same geometric-mean
method as the x86-64 report:

| Codec / worker ceiling | Create | Verify | Repair |
| --- | ---: | ---: | ---: |
| Cauchy / 1 | 1.64× | 2.25× | 2.67× |
| Cauchy / 4 | 1.64× | 2.25× | 2.76× |
| FFT / 1 | **0.80×** | 1.98× | 1.44× |
| FFT / 4 | **0.85×** | 1.97× | 1.61× |

**Performance acceptance remains open:** aggregate FFT creation throughput is
15–20% below this adapted reference. Cauchy exceeds it in all three aggregates;
FFT verification and repair also exceed it. This is the first matched native
ARM64 baseline, not evidence of a historical implementation regression.

One-worker median milliseconds (engine / adapted reference):

| Workload | Create | Verify | Repair |
| --- | ---: | ---: | ---: |
| Cauchy GF8 | 108.3 / 216.4 | 22.4 / 72.9 | 92.9 / 272.5 |
| Cauchy GF16 | 140.4 / 264.5 | 35.8 / 57.9 | 114.5 / 269.7 |
| FFT GF8 | 138.8 / 90.3 | 25.9 / 80.1 | 244.5 / 284.4 |
| FFT GF16 | 122.8 / 93.1 | 40.2 / 61.3 | 176.3 / 239.5 |
| Uneven FFT | 136.5 / 86.8 | 38.9 / 57.7 | 231.8 / 210.4 |
| Heavy Cauchy | 2005.0 / 7024.1 | 117.3 / 258.0 | 1595.4 / 7657.7 |
| Heavy FFT | 432.1 / 565.3 | 115.7 / 252.4 | 932.6 / 2770.9 |
| Large blocks | 102.3 / 157.6 | 30.8 / 416.4 | 87.9 / 653.1 |
| Small files | 69.3 / 39.9 | 43.1 / 15.9 | 62.5 / 34.4 |

Four-worker heavy Cauchy repair took 755.7 ms; heavy FFT took 820.2 ms.
All four-worker medians and raw repetitions are in `summary.json` and JSONL.

### Shortfalls and stage attribution

- **FFT creation:** on the ordinary GF8, GF16, and uneven workloads, planning
  consumed about 39–40 ms before execution. Nested encoding took 30.9, 16.2,
  and 33.3 ms respectively, compared with complete process times of 138.8,
  122.8, and 136.5 ms. Source reads, verification, scratch/output handling,
  and other work therefore account for much of the elapsed time. These stage
  timings identify where to profile; they do not isolate filesystem overhead
  as the exclusive cause. Nested times must not be added to enclosing times.
- **Small files:** ingestion consumed 32.8 ms of the 43.1 ms verification
  process; assessment took 4.4 ms. Creation and repair also lagged the
  reference. This agrees with the x86 syscall probe's carrier-open concern,
  but no macOS syscall attribution was collected in this run.
- **Uneven FFT repair:** one-worker time was 231.8 ms versus 210.4 ms.
  Decoder work consumed 160.2 ms of the 193.2 ms repair stage. Four-worker
  process times were close, at 204.2 versus 207.3 ms.

Separate scan-only medians were about 8–15 ms for ordinary single-file cases,
39–40 ms for small files, and 53–54 ms for heavy cases. CRC64 placement traversed
32 MiB in about 213–238 ms and 128 MiB in 921–955 ms. Primitive FFT NEON dispatch
was 5.59–10.81× scalar in the separately recorded
[transform benchmark](../reedsolomon-rs/FFT_BENCHMARKS.md); that is not the engine
throughput ratio.

### Memory and storage

All reservation peaks stayed within their configured ceilings; observed engine
handle peaks never exceeded two. Native `/usr/bin/time -l -p` reports peak RSS
in bytes, which the runner converts to KiB. RSS includes runtime and allocator
overhead and is distinct from the engine's reservation limit.

- **8 MiB budget, 4 MiB blocks:** peak reservation 4.18 MiB; maximum repair RSS
  2.67 MiB for the engine and 20.78 MiB for the reference.
- **64 MiB heavy cases:** maximum Cauchy repair RSS 28.08 MiB versus 83.67 MiB;
  FFT 67.81 MiB versus 99.20 MiB.
- Maximum repair RSS across the matrix: 67.81 MiB for the engine, 111.89 MiB
  for the reference, from different workloads. The engine did not use less
  RSS in every case: ordinary Cauchy GF16 was 5.53 versus 3.56 MiB.

Mac inputs, scratch, and outputs use APFS under `/tmp`, with normal caching and
no cache flush. The x86 run used tmpfs, different hardware and a different Rust
version. Do not interpret absolute cross-host timing differences as CPU-only
or code regressions. Each host's paired ratio is the comparison reported here.

### Evidence and reproduction

[`benchmarks/native-arm64-20260908.tar.gz`](benchmarks/native-arm64-20260908.tar.gz)
contains the final JSONL records, process logs and RSS, input digests, summary
and analysis script, host/build provenance, the reference adaptation recipe and
patch, and fresh Criterion samples. Protected inputs, PAR3 carriers, downloaded
dependency source, pilots, and portable-only reference timings are excluded.
Archive SHA-256:
`5084cf94eddc8b7219ee7625c9b900517a9b85735b0f9df5df622196a36df822`.

Build the native Rust example as in the Linux recipe below. Extract the evidence
archive and follow `REFERENCE-BUILD.md` in a separate pinned-reference checkout;
then run:

```sh
python3 crates/par3-rs/benches/run_native.py \
  --engine /path/to/native-build/release/examples/engine_perf \
  --reference /path/to/adapted-reference/build/par3cmd/par3 \
  --output /path/to/new-mac-results --workers 1,4 --repetitions 3
```

Omit `--cpus` on macOS. Omitting `--reference` gives Rust-only measurements,
which do not supply independent interoperability or reference-throughput
evidence. The native runner supports both forms and refuses existing output
directories. The engine source and crate dependencies are unchanged by these
measurements.

## Method for the x86-64 run

The native Linux measurements use the retained engine through
`examples/engine_perf.rs`, orchestrated by `benches/run_native.py`. The driver
reports planning, creation, scanning, assessment, placement, and repair
separately, with nested encoder/decoder timings, source I/O counters, allocation
reservations, and handle peaks. A separate invocation measures 100 unchanged
reassessments and asserts zero source reads.

The reference is official `par3cmdline` commit
`2971702e501f1350b1c7b9d11369af9157d6ed56`. No reference implementation code was
copied into the harness or engine. Workloads use deterministic SHAKE256 input
files; damage flips bytes in those inputs. Recovery packets are generated by
the respective implementations and are never patched or synthesized by the
runner.

Creation compares the same inputs, block size, recovery count, codec, cohort
count, and recovery capacity. Verification and repair compare both engines
against the same reference-created carriers. The reference verifies every
Rust-created set. Both repairs must match saved SHA-256 digests; the small-file
case additionally asserts that clean files are not staged.

Each operation runs in a fresh process. Both implementations receive the same
memory setting and CPU affinity: logical CPU 0 for one worker, or 0/2/4/6 for
four workers, each on a separate P-core. Rust uses explicit worker limits;
OpenMP is enabled for the reference with `OMP_NUM_THREADS` and
`OMP_THREAD_LIMIT` set to the same ceiling, and dynamic teams disabled. Some
stages remain serial in either implementation. Builds are native release
builds, with Rust `-C target-cpu=native` and C/C++ `-march=native -fopenmp`.

GNU time records each child process's peak RSS. The configured memory ceilings
have different accounting semantics in the implementations and are not RSS
caps; measured RSS is reported separately. Host-owned fixture generation is
outside the timed child and outside its RSS measurement. Rust stages output
files separately; reference repair uses its normal installation behavior.

Inputs, scratch, and output are on Linux tmpfs. These are warm-memory native
workloads, not storage-device throughput tests. No cache flushes, governor
changes, service stops, or CPU isolation changes are made. Existing services
remain running. The runner alternates engine/reference order across three
repetitions; tables use medians. These short runs establish an initial native
comparison, not a confidence bound on small differences.

## Workloads

Each case runs with both one and four workers:

- **Cauchy GF8:** 32 MiB, 128 × 256 KiB blocks, 16 recovery blocks, 8 damaged.
- **Cauchy GF16:** 32 MiB, 512 × 64 KiB blocks, 32 recovery blocks, 16 damaged.
- **FFT GF8:** 32 MiB, 128 × 256 KiB blocks, capacity/recovery 32, 16 damaged.
- **FFT GF16:** 32 MiB, 512 × 64 KiB blocks, capacity/recovery 64, 32 damaged.
- **Uneven FFT:** 515 × 64 KiB blocks, three cohorts, 63 recovery packets,
  capacity 32 per cohort, 30 damaged blocks.
- **Heavy Cauchy/FFT:** 128 MiB, 512 × 256 KiB blocks, 256 recovery blocks,
  192 damaged blocks, 64 MiB memory setting.
- **Large blocks:** 32 MiB, eight 4 MiB blocks, four Cauchy recovery blocks,
  two damaged blocks, 8 MiB memory setting.
- **Small files:** 256 × 4 KiB files packed into sixteen 64 KiB blocks,
  eight Cauchy recovery blocks, four damaged packed blocks affecting 64 files.

Other cases use a 256 MiB memory setting. Placement searches for the last full
extent in the generated file and confirms it with BLAKE3, traversing the file
with CRC64. It is timed separately and has no reference CLI equivalent in this
report. Scan-only timings likewise are engine measurements; reference process
verification and repair include their own scanning.

## Reproduction

Use an otherwise quiet native Linux host and an explicitly selected new output
directory. Preserve the resulting `results.jsonl`, per-command logs, resource
measurements, and input digests.

```sh
RUSTFLAGS='-C target-cpu=native' \
  cargo build --locked --release -p par3-rs --example engine_perf

cmake -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_FLAGS='-march=native -fopenmp' \
  -DCMAKE_CXX_FLAGS='-march=native -fopenmp' \
  -DCMAKE_EXE_LINKER_FLAGS=-fopenmp \
  -S /path/to/pinned-reference/src -B /path/to/reference-build
cmake --build /path/to/reference-build -j4

python3 crates/par3-rs/benches/run_native.py \
  --engine target/release/examples/engine_perf \
  --reference /path/to/reference-build/par3cmd/par3 \
  --output /path/to/new-results \
  --workers 1,4 --cpus 0,2,4,6 --repetitions 3
```

Adjust the CPU list to physical-core topology on another host. The runner
refuses an existing results directory. Timeouts terminate only the new process
group created for that benchmark command. The driver is a developer benchmark
tool, not a supported PAR3 CLI.
