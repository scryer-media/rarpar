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
do **not** complete performance acceptance: matched ARM64 measurements remain
outstanding, this is the first native x86-64 baseline, and there are individual
shortfalls worth tuning. No historical x86-64 regression percentage is inferred
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

## Method

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
