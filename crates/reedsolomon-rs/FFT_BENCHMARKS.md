# Cantor transform measurements

The `fft_transform` benchmark compares one-worker scalar log-table butterflies
with automatic CPU dispatch on identical caller-owned symbol stripes. Each
iteration performs a forward and inverse transform and restores the original
symbols. Setup and field tables are outside the measured loop. Both executions
include geometry validation; automatic execution includes per-group shuffle-map
construction. No PAR3 scanning, I/O, encoding layout, or decoder locator work is
measured here.

Run on an otherwise idle native host:

```sh
rtk proxy cargo bench --locked -p reedsolomon-rs --bench fft_transform -- \
  --sample-size 20 --warm-up-time 1 --measurement-time 3
```

Criterion writes raw samples and estimates under `target/criterion`. Throughput
counts both visits to the symbol buffers (two transforms, two bytes per symbol),
not protected-file bytes. The GF8 representation also occupies `u16` symbols in
these primitives. The largest input stripe is 8 MiB; the scalar and automatic
runs each retain one additional original copy for the post-measurement check.

## Exploratory ARM64 run, 2026-09-07

Host: Apple M5 Max, native macOS ARM64, Rust 1.97.1
(`8bab26f4f 2026-07-14`), Cargo bench release profile, one execution worker.
Automatic dispatch selected NEON. No CPU-affinity or frequency controls were
applied. Mean times from the 20-sample run:

| Field and symbol shape | Scalar pair | Automatic pair |
| --- | ---: | ---: |
| GF8, 128 × 64 | 90.336 µs | 22.546 µs |
| GF8, 128 × 4096 | 7.2047 ms | 1.1717 ms |
| GF16, 1024 × 64 | 1.4106 ms | 261.65 µs |
| GF16, 1024 × 4096 | 148.19 ms | 26.033 ms |

These results are **not performance acceptance**. In an earlier 10-sample run,
the largest automatic case measured 7.5170 ms; the later run had a 21.740–32.626 ms
confidence interval. Both scalar and automatic times deteriorated. Inspection
found concurrent local compiler and test processes consuming several cores.
Contention is a plausible contributor, but was not isolated experimentally.
Do not interpret Criterion's cross-run regression report as an isolated code
regression or use these measurements to claim a stable speedup.

Raw local run logs were `/tmp/par3-fft-simd-bench.log` and
`/tmp/par3-fft-simd-bench-confirm.log`. Their temporary location is not durable
evidence; the values and limitations above preserve the observation. Repeat on
idle ARM64 hosts before accepting ARM64 tuning decisions. The native x86-64
run below supplies automatic-dispatch evidence on AVX2 hardware. End-to-end PAR3 acceptance separately
requires matched official-reference workloads, worker limits, and memory
measurements for each codec and stage.

## Native x86-64 run, 2026-09-08

Intel Core i5-1240P on native Linux, Rust 1.98.1, release build with
`-C target-cpu=native`. One worker pinned to P-core logical CPU 0; existing
services and the `powersave` governor were left running unchanged. The command
above used 20 samples, one second of warmup, and three seconds of measurement
per shape/backend. Every forward/inverse round trip restored the original rows.

Criterion arithmetic-mean estimates (not its fitted slope):

| Field and symbol shape | Scalar pair | Automatic pair | Speedup |
| --- | ---: | ---: | ---: |
| GF8, 128 × 64 | 102.217 µs | 16.091 µs | 6.35× |
| GF8, 128 × 4096 | 6.0077 ms | 0.63769 ms | 9.42× |
| GF16, 1024 × 64 | 1.13315 ms | 0.15355 ms | 7.38× |
| GF16, 1024 × 4096 | 75.4635 ms | 7.42368 ms | 10.17× |

Raw Criterion samples, estimates, console output, and host provenance are
preserved in `crates/par3-rs/benchmarks/native-x86-20260908.tar.gz` at the
repository root. These are primitive transform measurements; see the
[PAR3 native report](../par3-rs/PERFORMANCE.md) for the separate matched
reference workloads, memory observations, and remaining acceptance limits.

## Native ARM64 rerun, 2026-09-08

The later PAR3 tuning pass additionally uses
`TransformField::scale_with_backend` for decoder locator factors. It uses the
same dispatched linear-map kernels with fixed stack scratch, a scalar fallback,
and cancellation checks at most 256 symbols apart. Its effect is measured in
the [tuned engine report](../par3-rs/PERFORMANCE.md), separately from the
transform-pair measurements below; no new primitive speedup is inferred here.

Apple M5 Max, 128 GiB RAM, macOS 26.6.2, Rust 1.97.1 / LLVM 22.1.6;
release build with `-C target-cpu=native`. One worker, automatic NEON dispatch,
no affinity or frequency controls. Existing services remained running. Builds
finished before measurement, and no other benchmark was run concurrently.
This run used Criterion's defaults: 100 samples, three seconds of warmup and
five seconds of target measurement time. The slowest scalar case extended its
collection interval to collect the requested samples.

Arithmetic-mean estimates from fresh Criterion output:

| Field and symbol shape | Scalar pair | Automatic pair | Speedup |
| --- | ---: | ---: | ---: |
| GF8, 128 × 64 | 70.198 µs | 12.565 µs | 5.59× |
| GF8, 128 × 4096 | 4.39770 ms | 0.59243 ms | 7.42× |
| GF16, 1024 × 64 | 790.232 µs | 111.935 µs | 7.06× |
| GF16, 1024 × 4096 | 46.8388 ms | 4.33420 ms | 10.81× |

Every round trip restored its original symbols. These measurements supersede
the contended exploratory ARM64 observations for tuning comparisons, but the
different load, compiler flags, and sample settings prevent attributing their
difference to a code change. Raw samples and the console log are preserved in
`crates/par3-rs/benchmarks/native-arm64-20260908.tar.gz`. End-to-end engine
measurements and reference-build qualifications are in the
[PAR3 native report](../par3-rs/PERFORMANCE.md).
