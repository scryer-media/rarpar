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
idle ARM64 and x86-64 hosts before accepting tuning decisions. AVX2/SSSE3 paths
also require native execution evidence. End-to-end PAR3 acceptance separately
requires matched official-reference workloads, worker limits, and memory
measurements for each codec and stage.
