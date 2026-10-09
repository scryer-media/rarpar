# Native PAR3 performance

## FFT decode and transform experiments, 2026-10

Seven experimental FFT-codec lanes were measured against the 0.5.0 default
on three AWS hosts. Two shipped in 0.5.1; the others were dropped, and their
code is gone. This section is their record.

### What shipped

- **Capacity decode with a pipelined fill** (`decode-capacity`,
  `decode-pipeline`) is the only FFT decoder. It keeps two banks of
  `capacity` rows instead of a full-domain work area, and with workers on a
  direct lane over a domain wider than twice the capacity it adds a third
  bank so the next fill overlaps the current transform. If the budget refuses
  the third bank, it runs on two. Repair output is byte-identical.
- **The four-step transform** (`fft-four-step`, leaf 2^6) runs only where it
  measured faster. A codec takes it when the CPU reports `AuthenticAMD` and
  the linear-map kernel resolves to AVX2. On top of that CPU gate, each
  transform of `n` points over rows of `row_bytes` takes it when
  `n > 1` and either:
  - it runs in the worker pool and `n > 64`, or
  - it runs on the calling thread and `row_bytes >= 16 KiB`.

  The first rule excludes the 128 × 64 KiB-class encode at 4 or more
  workers. The second excludes the one-worker 30000 × 1 KiB decode. Output
  is the same with four-step on or off.
- **Dropped:** `fft-hash-feed`, `cauchy-shared`, `encode-pruned` and
  `fft-recursive`, along with the four-step leaf and split knobs and the
  `RARPAR_PAR3_EXPERIMENTS` environment read.

### Method

- **Hosts:** c7a.2xlarge (AMD EPYC 9R14, Zen 4), c7i.2xlarge (Intel Xeon
  Platinum 8488C, Sapphire Rapids) and c8g.2xlarge (AWS Graviton4), each with
  8 vCPUs. The 30000 × 1 KiB decode was rerun at n = 8 on c7a and c8g.
- **Builds:** the baseline is the unmodified 0.5.0 engine. Every other arm
  is one experimental build with the lanes selected per process by
  environment, so `control` (the experimental build with nothing selected)
  measures build-to-build noise.
- **Runs:** each arm runs in a fresh process. Arms rotate order on every
  repeat, after one discarded warm-up. Workers are 1, 4 and 8, and n = 3
  unless a table says otherwise. Every created set is compared with the
  baseline's carrier SHA-256s and every repair with the input's SHA-256.
  There were no mismatches.
- **Whole operations** go through the `engine_perf` example with a 512 MiB
  budget:

  | workload | codec | inputs × block | recovery | losses |
  |---|---|---|---:|---:|
  | cauchy-S | Cauchy | 1024 × 1 KiB | 16 | 4 |
  | cauchy-M | Cauchy | 512 × 8 KiB | 16 | 4 |
  | cauchy-L | Cauchy | 256 × 64 KiB | 16 | 4 |
  | fft-S | FFT | 30000 × 1 KiB | 256 | 10 |
  | fft-L | FFT | 4096 × 16 KiB | 192 | 4 |
  | fft-1.5G | FFT | 49152 × 32 KiB | 4916 | 2000 |

  fft-1.5G ran with a 2 GiB budget and a 256 MiB retained-source cap, so
  sources are re-read. The cold row drops the page cache before each run.
- **Codec-only rows** time the encoder or decoder alone through an A/B
  example over generated rows.

### Scale

Every figure is **default ÷ experiment** on median wall time, so a figure
above 1 means the experiment was faster. Memory figures are default ÷
experiment on the engine's charged peak, so a figure above 1 means the
experiment used less. A dash means that arm was not run at that worker count.

Two rows carry noise that the control arm exposes, so read them with care:
- On c7a, fft-1.5G create at w1: every arm reads 1.5–1.8, control included,
  because the baseline's w1 runs were slow.
- On c7a, the codec-only 128 × 64 KiB encode at w4: the control spread is
  0.77–1.27, and arms that cannot touch encode read about 0.6.

On c7i and c8g, the four-step loss on that encode is clear (0.64).

### Per-host results

#### c7a: AMD EPYC 9R14 (Zen 4), AVX2 kernels with GFNI

Whole operations through `engine_perf`, each cell w1 / w4 / w8. The last column is the pipeline decode with four-step, the closest measured arm to what landed.

| workload | capacity | pipeline | four-step | hash-feed | cauchy-shared | encode-pruned | recursive | pipeline + four-step |
|---|---|---|---|---|---|---|---|---|
| cauchy-L create | 1.00 / 1.00 / 1.01 | 1.01 / 1.00 / 1.02 | 1.01 / 0.99 / 1.01 | 1.00 / 0.99 / 1.00 | 0.03 / 0.10 / 0.10 | 1.01 / 1.00 / – | 1.01 / 0.99 / – | 1.00 / 1.00 / 1.01 |
| cauchy-L repair | 1.00 / 0.99 / 1.00 | 1.04 / 1.00 / 1.00 | 1.03 / 0.99 / 1.00 | 1.01 / 0.99 / 1.00 | 1.01 / 1.00 / 1.00 | 1.01 / 1.01 / – | 0.99 / 1.00 / – | 1.00 / 1.00 / 1.01 |
| cauchy-M create | 1.00 / 1.01 / 1.03 | 1.01 / 1.02 / 1.05 | 1.01 / 1.01 / 1.04 | 1.01 / 1.01 / 1.03 | 0.01 / 0.02 / 0.02 | 0.98 / 1.00 / – | 0.99 / 1.01 / – | 1.01 / 1.02 / 1.01 |
| cauchy-M repair | 1.02 / 1.01 / 1.00 | 1.01 / 1.02 / 1.00 | 1.01 / 1.00 / 1.00 | 1.03 / 1.02 / 1.02 | 1.01 / 1.01 / 1.01 | 1.02 / 1.02 / – | 1.01 / 1.00 / – | 1.02 / 1.03 / 1.01 |
| cauchy-S create | 1.02 / 1.01 / 0.97 | 1.02 / 1.00 / 0.96 | 1.02 / 1.02 / 0.97 | 1.02 / 1.01 / 0.98 | 0.01 / 0.01 / 0.01 | 1.00 / 1.01 / – | 1.02 / 1.02 / – | 1.00 / 1.01 / 0.95 |
| cauchy-S repair | 1.03 / 1.00 / 1.00 | 1.03 / 1.00 / 0.99 | 1.02 / 1.00 / 1.01 | 1.04 / 0.98 / 0.99 | 1.01 / 0.98 / 1.00 | 1.04 / 0.95 / – | 1.03 / 1.01 / – | 1.05 / 1.02 / 1.00 |
| fft-L create | 0.99 / 1.01 / 1.01 | 1.00 / 1.01 / 1.01 | 1.01 / 1.09 / 1.11 | 1.07 / 1.07 / 1.09 | 0.99 / 1.00 / 1.02 | 0.99 / 1.00 / – | 1.01 / 1.00 / – | 1.00 / 1.08 / 1.11 |
| fft-L repair | 1.70 / 1.31 / 1.21 | 1.72 / 1.49 / 1.39 | 0.99 / 1.00 / 1.00 | 1.00 / 1.00 / 0.99 | 0.99 / 1.00 / 1.00 | 1.00 / 1.00 / – | 1.00 / 1.00 / – | 1.77 / 1.62 / 1.46 |
| fft-S create | 1.03 / 1.00 / 1.01 | 1.05 / 1.00 / 1.01 | 1.06 / 1.00 / 1.20 | 1.10 / 1.00 / 1.19 | 1.03 / 1.00 / 1.00 | 0.94 / 1.00 / – | 1.10 / 1.00 / – | 0.96 / 1.00 / 0.89 |
| fft-S repair | 1.28 / 1.16 / 1.11 | 1.29 / 1.24 / 1.19 | 1.01 / 1.01 / 0.99 | 1.00 / 1.00 / 0.99 | 1.00 / 1.01 / 0.98 | 1.00 / 1.02 / – | 0.99 / 1.03 / – | 1.25 / 1.24 / 1.19 |
| fft-1.5G create | – | – | 1.76 / 1.01 / 0.98 | 1.54 / 0.92 / 1.01 | – | 1.75 / 1.00 / 1.00 | – | – |
| fft-1.5G repair | 1.91 / 1.58 / 1.36 | 1.92 / 1.66 / 1.41 | – | – | – | – | – | 1.99 / 1.68 / 1.33 |
| fft-1.5G create (cold cache, w8) | – | – | 1.02 | 1.02 | – | – | – | – |

Codec only (`fft_ab`), each cell w1 / w4 / w8. A case is the operation, input blocks × block size, the cohort capacity, the recovery rows encoded or the losses decoded, and the first recovery index.

| case | capacity | pipeline | encode-pruned | recursive | four-step | capacity + four-step | pipeline + four-step |
|---|---|---|---|---|---|---|---|
| decode 128×64K, 2^5, 4 losses, first 0 | 2.50 / 1.55 / 1.42 | 2.51 / 1.57 / 1.46 | 0.98 / 1.01 / 0.96 | 0.98 / 0.97 / 1.07 | 0.98 / 0.97 / 0.95 | 2.57 / 1.43 / 1.36 | 2.61 / 1.56 / 1.38 |
| decode 30000×1K, 2^11, 10 losses, first 23 | 1.90 / 1.45 / 1.42 | 1.85 / 1.48 / 1.63 | 1.01 / 0.99 / 1.00 | 1.01 / 1.01 / 0.98 | 1.00 / 1.00 / 1.01 | 1.42 / 2.35 / 2.47 | 1.43 / 2.66 / 2.87 |
| decode 4096×16K, 2^8, 128 losses, first 0 | 2.84 / 1.86 / 1.60 | 2.85 / 2.25 / 2.00 | 0.99 / 1.00 / 1.01 | 0.98 / 1.00 / 1.00 | 0.98 / 1.00 / 1.00 | 3.17 / 3.56 / 2.87 | 3.16 / 4.54 / 3.58 |
| decode 4096×16K, 2^8, 4 losses, first 5 | 3.24 / 2.24 / 1.91 | 3.36 / 2.88 / 2.61 | 1.00 / 0.99 / 1.01 | 0.99 / 0.99 / 1.00 | 1.00 / 1.00 / 0.95 | 3.59 / 3.69 / 3.28 | 3.67 / 5.00 / 4.29 |
| encode 128×64K, 2^5, 16 rows, first 0 | 1.01 / 0.98 / 1.05 | 1.02 / 0.64 / 1.03 | 1.01 / 0.65 / 1.00 | 1.06 / 0.62 / 1.05 | 1.04 / 0.56 / 0.97 | 1.04 / 0.90 / 0.91 | 1.05 / 0.58 / 0.92 |
| encode 4096×16K, 2^8, 128 rows, first 0 | 1.01 / 0.96 / 1.03 | 1.00 / 0.99 / 1.15 | 1.02 / 1.00 / 1.08 | 1.01 / 0.98 / 1.02 | 1.03 / 1.63 / 1.69 | 1.00 / 1.51 / 1.69 | 0.99 / 1.50 / 1.70 |
| encode 4096×16K, 2^8, 32 rows, first 64 | 0.99 / 0.99 / 0.96 | 0.95 / 1.01 / 1.00 | 1.02 / 1.00 / 0.98 | 0.96 / 0.99 / 1.00 | 1.05 / 1.51 / 1.60 | 1.03 / 1.54 / 1.74 | 1.06 / 1.57 / 1.57 |

Four-step leaf and split variants, codec only, w1 / w4 / w8 (alone, over the old decode). Leaf 6 is what landed.

| case | leaf 2 | leaf 4 | leaf 6 | leaf 8 | leaf 6, split 2 | leaf 6, split 4 |
|---|---|---|---|---|---|---|
| decode 128×64K, 2^5, 4 losses, first 0 | 0.98 / 0.96 / 0.99 | 0.98 / 1.21 / 0.96 | 0.98 / 0.97 / 0.95 | 0.99 / 0.98 / 1.19 | 0.98 / 1.17 / 0.97 | 0.98 / 1.21 / 1.06 |
| decode 30000×1K, 2^11, 10 losses, first 23 | 0.99 / 1.01 / 1.00 | 1.00 / 0.99 / 1.00 | 1.00 / 1.00 / 1.01 | 1.00 / 1.00 / 1.00 | 1.00 / 1.00 / 1.00 | 1.00 / 0.99 / 1.00 |
| decode 4096×16K, 2^8, 128 losses, first 0 | 0.99 / 1.01 / 1.00 | 1.00 / 1.00 / 1.00 | 0.98 / 1.00 / 1.00 | 0.99 / 1.00 / 0.99 | 0.99 / 1.00 / 1.01 | 0.97 / 1.00 / 1.00 |
| decode 4096×16K, 2^8, 4 losses, first 5 | 0.99 / 1.00 / 1.01 | 0.98 / 1.00 / 1.01 | 1.00 / 1.00 / 0.95 | 1.00 / 1.00 / 1.00 | 1.00 / 0.99 / 1.01 | 0.99 / 1.00 / 1.00 |
| encode 128×64K, 2^5, 16 rows, first 0 | 1.08 / 0.62 / 1.04 | 1.07 / 1.01 / 1.01 | 1.04 / 0.56 / 0.97 | 1.04 / 0.55 / 0.99 | 1.05 / 0.59 / 0.89 | 1.06 / 0.89 / 0.91 |
| encode 4096×16K, 2^8, 128 rows, first 0 | 0.99 / 1.47 / 1.63 | 1.03 / 1.50 / 1.67 | 1.03 / 1.63 / 1.69 | 1.09 / 0.95 / 0.97 | 1.04 / 1.40 / 1.48 | 1.06 / 1.50 / 1.71 |
| encode 4096×16K, 2^8, 32 rows, first 64 | 0.97 / 1.49 / 1.57 | 1.03 / 1.57 / 1.58 | 1.05 / 1.51 / 1.60 | 1.09 / 0.95 / 0.92 | 1.01 / 1.41 / 1.38 | 1.00 / 1.58 / 1.60 |

The one-worker small-block decode, 30000×1K, 2^11, 10 losses, first 23 rerun at n = 8, w1 / w4:

| arm | w1 / w4 |
|---|---|
| decode-capacity | 1.90 / 1.44 |
| decode-pipeline | 1.89 / 1.51 |
| fft-four-step[leaf6] | 1.00 / 1.01 |
| decode-capacity+fft-four-step[leaf6] | 1.44 / 2.46 |
| decode-pipeline+fft-four-step[leaf6] | 1.46 / 2.59 |
| decode-capacity+fft-four-step[leaf4] | 1.07 / 2.04 |
| decode-pipeline+fft-four-step[leaf4] | 1.08 / 2.14 |

#### c7i: Intel Xeon Platinum 8488C (Sapphire Rapids), AVX2 kernels with GFNI

Whole operations through `engine_perf`, each cell w1 / w4 / w8. The last column is the pipeline decode with four-step, the closest measured arm to what landed.

| workload | capacity | pipeline | four-step | hash-feed | cauchy-shared | encode-pruned | recursive | pipeline + four-step |
|---|---|---|---|---|---|---|---|---|
| cauchy-L create | 1.01 / 1.04 / 1.00 | 1.02 / 1.02 / 1.01 | 1.00 / 1.02 / 1.01 | 1.03 / 1.04 / 0.98 | 0.03 / 0.09 / 0.06 | 1.01 / 1.04 / – | 1.00 / 1.01 / – | 1.01 / 1.02 / 1.01 |
| cauchy-L repair | 1.00 / 0.96 / 0.94 | 1.02 / 0.98 / 0.95 | 1.03 / 1.02 / 1.00 | 1.02 / 0.95 / 0.97 | 0.98 / 1.00 / 0.92 | 0.98 / 0.96 / – | 1.00 / 1.02 / – | 0.99 / 0.98 / 0.97 |
| cauchy-M create | 1.00 / 1.03 / 1.03 | 1.01 / 1.01 / 1.02 | 1.03 / 1.03 / 1.05 | 1.02 / 1.08 / 1.03 | 0.01 / 0.02 / 0.02 | 1.01 / 1.04 / – | 1.03 / 1.03 / – | 1.04 / 1.04 / 0.99 |
| cauchy-M repair | 1.06 / 0.98 / 1.02 | 1.00 / 1.05 / 1.03 | 1.02 / 1.02 / 0.99 | 1.04 / 1.03 / 1.00 | 1.01 / 1.03 / 1.00 | 1.06 / 1.04 / – | 0.99 / 1.05 / – | 0.97 / 1.04 / 0.98 |
| cauchy-S create | 0.96 / 1.01 / 1.00 | 1.01 / 1.00 / 0.95 | 0.98 / 1.00 / 0.97 | 1.02 / 0.99 / 0.96 | 0.01 / 0.01 / 0.01 | 0.98 / 1.00 / – | 1.00 / 1.00 / – | 1.03 / 1.00 / 0.97 |
| cauchy-S repair | 0.99 / 1.03 / 0.95 | 1.12 / 1.05 / 1.07 | 1.10 / 1.03 / 0.92 | 1.09 / 1.02 / 1.04 | 1.06 / 1.02 / 1.02 | 1.09 / 1.03 / – | 1.08 / 1.00 / – | 1.05 / 1.05 / 1.03 |
| fft-L create | 0.98 / 1.01 / 1.02 | 0.99 / 0.97 / 1.01 | 0.97 / 0.99 / 0.99 | 1.06 / 1.03 / 1.03 | 1.02 / 0.96 / 0.99 | 0.99 / 0.97 / – | 0.98 / 0.99 / – | 0.97 / 0.98 / 1.00 |
| fft-L repair | 1.69 / 1.28 / 1.22 | 1.70 / 1.45 / 1.34 | 1.00 / 0.99 / 0.99 | 1.01 / 0.98 / 0.99 | 1.00 / 1.00 / 0.99 | 0.99 / 1.02 / – | 0.99 / 1.01 / – | 1.70 / 1.45 / 1.37 |
| fft-S create | 1.00 / 1.00 / 1.00 | 1.00 / 1.00 / 1.00 | 1.00 / 1.00 / 1.15 | 0.99 / 1.00 / 1.00 | 1.00 / 1.00 / 1.01 | 1.00 / 1.00 / – | 1.00 / 1.00 / – | 1.08 / 1.00 / 1.00 |
| fft-S repair | 1.37 / 1.16 / 1.15 | 1.37 / 1.26 / 1.25 | 1.00 / 1.01 / 1.00 | 1.00 / 1.00 / 1.00 | 1.00 / 1.00 / 1.00 | 1.02 / 0.99 / – | 1.00 / 1.00 / – | 1.31 / 1.28 / 1.25 |
| fft-1.5G create | – | – | 0.95 / 0.97 / 0.86 | 1.02 / 0.83 / 1.01 | – | 0.72 / 1.00 / 0.98 | – | – |
| fft-1.5G repair | 1.89 / 1.67 / 1.46 | 1.84 / 1.74 / 1.42 | – | – | – | – | – | 1.79 / 1.71 / 1.46 |
| fft-1.5G create (cold cache, w8) | – | – | 1.00 | 1.00 | – | – | – | – |

Codec only (`fft_ab`), each cell w1 / w4 / w8. A case is the operation, input blocks × block size, the cohort capacity, the recovery rows encoded or the losses decoded, and the first recovery index.

| case | capacity | pipeline | encode-pruned | recursive | four-step | capacity + four-step | pipeline + four-step |
|---|---|---|---|---|---|---|---|
| decode 128×64K, 2^5, 4 losses, first 0 | 2.08 / 1.03 / 0.91 | 2.16 / 1.10 / 1.01 | 1.01 / 1.18 / 0.91 | 0.99 / 1.00 / 0.90 | 1.04 / 1.00 / 0.82 | 2.06 / 0.68 / 0.58 | 2.08 / 0.81 / 0.69 |
| decode 30000×1K, 2^11, 10 losses, first 23 | 1.71 / 1.12 / 1.10 | 1.75 / 1.21 / 1.30 | 1.01 / 0.99 / 1.02 | 0.99 / 1.00 / 1.00 | 1.00 / 1.00 / 1.01 | 1.38 / 1.37 / 1.35 | 1.39 / 1.48 / 1.53 |
| decode 4096×16K, 2^8, 128 losses, first 0 | 2.68 / 1.58 / 1.49 | 2.69 / 1.92 / 1.78 | 1.00 / 1.02 / 1.02 | 1.00 / 1.02 / 1.02 | 1.00 / 1.02 / 1.02 | 2.62 / 1.68 / 1.56 | 2.62 / 1.92 / 1.74 |
| decode 4096×16K, 2^8, 4 losses, first 5 | 2.92 / 1.92 / 1.76 | 2.92 / 2.63 / 2.35 | 0.99 / 1.00 / 0.99 | 0.99 / 1.01 / 0.98 | 0.99 / 0.97 / 0.99 | 2.94 / 1.92 / 1.80 | 2.92 / 2.36 / 1.91 |
| encode 128×64K, 2^5, 16 rows, first 0 | 0.99 / 1.03 / 0.94 | 0.97 / 1.03 / 0.87 | 0.97 / 0.99 / 0.96 | 0.97 / 1.07 / 1.00 | 0.99 / 0.64 / 0.71 | 1.05 / 0.66 / 0.67 | 0.97 / 0.65 / 0.73 |
| encode 4096×16K, 2^8, 128 rows, first 0 | 1.02 / 1.00 / 1.00 | 0.99 / 1.00 / 1.00 | 1.02 / 0.97 / 1.03 | 0.99 / 1.01 / 1.03 | 0.96 / 0.95 / 0.91 | 0.97 / 0.93 / 0.96 | 0.96 / 0.93 / 0.93 |
| encode 4096×16K, 2^8, 32 rows, first 64 | 1.00 / 0.95 / 0.96 | 1.01 / 0.98 / 0.99 | 1.03 / 0.98 / 0.94 | 1.00 / 0.95 / 0.97 | 0.96 / 0.92 / 0.90 | 0.94 / 0.90 / 0.91 | 0.95 / 0.91 / 0.92 |

Four-step leaf and split variants, codec only, w1 / w4 / w8 (alone, over the old decode). Leaf 6 is what landed.

| case | leaf 2 | leaf 4 | leaf 6 | leaf 8 | leaf 6, split 2 | leaf 6, split 4 |
|---|---|---|---|---|---|---|
| decode 128×64K, 2^5, 4 losses, first 0 | 1.01 / 1.04 / 0.91 | 0.99 / 0.91 / 0.79 | 1.04 / 1.00 / 0.82 | 1.02 / 0.95 / 0.87 | 1.01 / 1.03 / 0.89 | 1.00 / 1.05 / 0.99 |
| decode 30000×1K, 2^11, 10 losses, first 23 | 0.98 / 1.01 / 1.01 | 0.98 / 1.01 / 1.02 | 1.00 / 1.00 / 1.01 | 0.99 / 0.99 / 1.04 | 1.04 / 1.00 / 1.05 | 1.00 / 1.02 / 1.02 |
| decode 4096×16K, 2^8, 128 losses, first 0 | 1.00 / 1.04 / 1.03 | 1.00 / 1.01 / 1.02 | 1.00 / 1.02 / 1.02 | 1.02 / 1.01 / 1.02 | 1.02 / 1.00 / 1.02 | 1.01 / 1.02 / 1.02 |
| decode 4096×16K, 2^8, 4 losses, first 5 | 1.00 / 1.00 / 0.98 | 0.98 / 1.02 / 1.00 | 0.99 / 0.97 / 0.99 | 1.00 / 1.02 / 1.00 | 1.00 / 1.02 / 0.99 | 1.00 / 1.02 / 0.98 |
| encode 128×64K, 2^5, 16 rows, first 0 | 0.92 / 0.85 / 0.84 | 0.98 / 0.89 / 0.85 | 0.99 / 0.64 / 0.71 | 0.95 / 0.67 / 0.69 | 1.00 / 0.65 / 0.68 | 0.97 / 0.68 / 0.72 |
| encode 4096×16K, 2^8, 128 rows, first 0 | 0.94 / 0.91 / 0.89 | 0.97 / 0.91 / 0.93 | 0.96 / 0.95 / 0.91 | 0.95 / 0.76 / 0.68 | 0.94 / 0.88 / 0.83 | 0.98 / 0.98 / 0.94 |
| encode 4096×16K, 2^8, 32 rows, first 64 | 0.92 / 0.90 / 0.89 | 0.97 / 0.87 / 0.90 | 0.96 / 0.92 / 0.90 | 0.95 / 0.74 / 0.65 | 0.94 / 0.91 / 0.81 | 0.94 / 0.93 / 0.93 |

The one-worker small-block decode, 30000×1K, 2^11, 10 losses, first 23 rerun at n = 8, w1 / w4:

| arm | w1 / w4 |
|---|---|
| decode-capacity | 1.71 / 1.13 |
| decode-pipeline | 1.71 / 1.23 |
| fft-four-step[leaf6] | 1.01 / 1.02 |
| decode-capacity+fft-four-step[leaf6] | 1.37 / 1.33 |
| decode-pipeline+fft-four-step[leaf6] | 1.37 / 1.52 |
| decode-capacity+fft-four-step[leaf4] | 1.06 / 1.17 |
| decode-pipeline+fft-four-step[leaf4] | 1.06 / 1.36 |

#### c8g: AWS Graviton4 (Neoverse V2), NEON kernels

Whole operations through `engine_perf`, each cell w1 / w4 / w8. The last column is the pipeline decode with four-step, the closest measured arm to what landed.

| workload | capacity | pipeline | four-step | hash-feed | cauchy-shared | encode-pruned | recursive | pipeline + four-step |
|---|---|---|---|---|---|---|---|---|
| cauchy-L create | 1.00 / 0.99 / 1.00 | 1.00 / 1.00 / 0.98 | 0.99 / 1.00 / 0.99 | 0.99 / 1.01 / 0.99 | 0.04 / 0.09 / 0.08 | 0.98 / 0.99 / – | 0.96 / 0.99 / – | 1.00 / 1.00 / 1.00 |
| cauchy-L repair | 1.00 / 1.06 / 1.03 | 0.99 / 1.05 / 1.03 | 1.00 / 1.03 / 1.00 | 0.97 / 1.11 / 1.02 | 1.00 / 1.05 / 1.03 | 0.98 / 1.10 / – | 0.99 / 1.09 / – | 1.00 / 1.05 / 1.01 |
| cauchy-M create | 0.99 / 1.01 / 0.99 | 0.97 / 1.00 / 1.00 | 1.01 / 1.00 / 0.99 | 0.99 / 1.01 / 1.00 | 0.01 / 0.02 / 0.02 | 1.01 / 1.00 / – | 1.00 / 1.00 / – | 0.98 / 1.01 / 0.99 |
| cauchy-M repair | 0.98 / 1.00 / 1.01 | 1.00 / 1.01 / 1.00 | 1.01 / 1.01 / 1.01 | 1.00 / 1.01 / 1.01 | 0.98 / 1.01 / 1.01 | 0.99 / 1.02 / – | 1.00 / 1.01 / – | 1.00 / 1.00 / 1.00 |
| cauchy-S create | 0.99 / 1.00 / 1.01 | 1.00 / 1.01 / 1.00 | 1.01 / 1.00 / 1.00 | 1.00 / 1.00 / 1.01 | 0.01 / 0.01 / 0.01 | 1.00 / 1.01 / – | 0.99 / 1.01 / – | 1.00 / 1.00 / 0.98 |
| cauchy-S repair | 1.01 / 1.00 / 1.00 | 1.01 / 1.03 / 1.00 | 1.02 / 1.02 / 1.00 | 1.02 / 1.01 / 0.98 | 1.03 / 1.03 / 1.00 | 1.03 / 1.02 / – | 1.04 / 1.02 / – | 1.03 / 1.00 / 1.00 |
| fft-L create | 0.99 / 1.00 / 0.99 | 1.00 / 1.00 / 0.99 | 1.02 / 1.00 / 1.01 | 1.01 / 0.87 / 1.02 | 1.00 / 1.00 / 1.01 | 1.00 / 1.00 / – | 1.00 / 1.02 / – | 1.01 / 1.00 / 1.01 |
| fft-L repair | 1.67 / 1.45 / 1.38 | 1.67 / 1.51 / 1.44 | 1.00 / 0.96 / 0.97 | 1.01 / 0.99 / 0.97 | 0.97 / 0.99 / 0.98 | 0.98 / 1.01 / – | 0.96 / 0.99 / – | 1.67 / 1.53 / 1.41 |
| fft-S create | 0.96 / 1.00 / 1.00 | 0.94 / 1.00 / 1.00 | 0.95 / 1.00 / 1.00 | 0.92 / 1.00 / 1.01 | 0.94 / 1.00 / 1.00 | 0.95 / 1.01 / – | 0.98 / 1.01 / – | 0.96 / 1.00 / 1.00 |
| fft-S repair | 1.29 / 1.12 / 1.12 | 1.30 / 1.21 / 1.19 | 0.99 / 0.99 / 1.00 | 0.99 / 0.97 / 1.01 | 1.00 / 0.99 / 1.01 | 1.00 / 0.99 / – | 1.00 / 0.98 / – | 1.27 / 1.21 / 1.19 |
| fft-1.5G create | – | – | 1.01 / 0.99 / 0.99 | 1.00 / 0.73 / 0.97 | – | 1.01 / 1.00 / 1.00 | – | – |
| fft-1.5G repair | 1.83 / 1.47 / 1.34 | 1.83 / 1.50 / 1.33 | – | – | – | – | – | 1.84 / 1.48 / 1.35 |
| fft-1.5G create (cold cache, w8) | – | – | 0.98 | 0.97 | – | – | – | – |

Codec only (`fft_ab`), each cell w1 / w4 / w8. A case is the operation, input blocks × block size, the cohort capacity, the recovery rows encoded or the losses decoded, and the first recovery index.

| case | capacity | pipeline | encode-pruned | recursive | four-step | capacity + four-step | pipeline + four-step |
|---|---|---|---|---|---|---|---|
| decode 128×64K, 2^5, 4 losses, first 0 | 2.15 / 2.45 / 1.99 | 2.34 / 2.21 / 1.79 | 0.98 / 1.05 / 0.98 | 1.00 / 0.97 / 1.00 | 0.99 / 1.02 / 1.00 | 2.47 / 1.37 / 1.15 | 2.43 / 1.33 / 1.20 |
| decode 30000×1K, 2^11, 10 losses, first 23 | 1.48 / 1.55 / 1.52 | 1.50 / 1.65 / 1.69 | 1.02 / 0.98 / 1.00 | 1.02 / 0.94 / 0.98 | 1.00 / 0.99 / 0.96 | 1.41 / 1.83 / 2.03 | 1.42 / 2.01 / 2.18 |
| decode 4096×16K, 2^8, 128 losses, first 0 | 2.71 / 3.23 / 2.48 | 2.74 / 3.43 / 2.65 | 1.00 / 1.02 / 1.03 | 1.00 / 1.01 / 1.01 | 1.00 / 1.03 / 1.03 | 2.84 / 3.23 / 3.16 | 2.90 / 3.49 / 3.20 |
| decode 4096×16K, 2^8, 4 losses, first 5 | 3.13 / 3.64 / 2.73 | 3.07 / 3.96 / 3.35 | 0.99 / 1.01 / 0.96 | 1.00 / 0.97 / 0.94 | 0.98 / 1.02 / 0.99 | 3.34 / 3.65 / 3.59 | 3.41 / 3.94 / 3.84 |
| encode 128×64K, 2^5, 16 rows, first 0 | 1.00 / 0.99 / 1.02 | 1.03 / 0.99 / 0.94 | 1.04 / 1.00 / 0.98 | 1.03 / 0.99 / 0.97 | 1.06 / 0.64 / 0.65 | 1.06 / 0.62 / 0.67 | 1.06 / 0.64 / 0.67 |
| encode 4096×16K, 2^8, 128 rows, first 0 | 1.05 / 1.05 / 0.88 | 1.05 / 1.05 / 0.91 | 1.08 / 1.00 / 0.99 | 1.01 / 1.03 / 0.95 | 1.10 / 1.00 / 1.03 | 1.13 / 0.96 / 1.02 | 1.15 / 0.98 / 0.96 |
| encode 4096×16K, 2^8, 32 rows, first 64 | 0.97 / 1.09 / 0.94 | 1.01 / 1.09 / 0.94 | 1.05 / 1.14 / 1.00 | 1.01 / 1.02 / 1.02 | 1.08 / 1.09 / 1.06 | 1.08 / 1.07 / 1.05 | 1.09 / 1.09 / 1.05 |

Four-step leaf and split variants, codec only, w1 / w4 / w8 (alone, over the old decode). Leaf 6 is what landed.

| case | leaf 2 | leaf 4 | leaf 6 | leaf 8 | leaf 6, split 2 | leaf 6, split 4 |
|---|---|---|---|---|---|---|
| decode 128×64K, 2^5, 4 losses, first 0 | 0.97 / 1.03 / 0.92 | 0.95 / 1.02 / 0.95 | 0.99 / 1.02 / 1.00 | 1.00 / 1.01 / 0.98 | 1.00 / 1.04 / 1.05 | 1.01 / 1.04 / 0.95 |
| decode 30000×1K, 2^11, 10 losses, first 23 | 0.99 / 0.97 / 0.97 | 1.00 / 0.98 / 0.98 | 1.00 / 0.99 / 0.96 | 1.00 / 0.98 / 1.00 | 0.99 / 1.00 / 1.01 | 1.01 / 0.97 / 0.95 |
| decode 4096×16K, 2^8, 128 losses, first 0 | 1.00 / 1.05 / 1.02 | 0.99 / 1.01 / 1.01 | 1.00 / 1.03 / 1.03 | 1.00 / 1.03 / 0.92 | 1.00 / 1.01 / 1.04 | 1.01 / 1.02 / 0.96 |
| decode 4096×16K, 2^8, 4 losses, first 5 | 1.00 / 1.01 / 0.92 | 0.99 / 1.01 / 0.96 | 0.98 / 1.02 / 0.99 | 0.98 / 1.01 / 0.96 | 0.99 / 0.99 / 1.03 | 0.99 / 1.00 / 1.03 |
| encode 128×64K, 2^5, 16 rows, first 0 | 1.03 / 0.85 / 0.91 | 1.04 / 0.86 / 0.84 | 1.06 / 0.64 / 0.65 | 1.04 / 0.65 / 0.69 | 1.03 / 0.67 / 0.69 | 1.06 / 0.63 / 0.69 |
| encode 4096×16K, 2^8, 128 rows, first 0 | 1.13 / 1.02 / 1.01 | 1.09 / 0.98 / 1.03 | 1.10 / 1.00 / 1.03 | 1.14 / 0.45 / 0.38 | 1.15 / 0.95 / 0.90 | 1.10 / 0.99 / 1.00 |
| encode 4096×16K, 2^8, 32 rows, first 64 | 1.06 / 1.09 / 1.03 | 1.09 / 1.03 / 1.07 | 1.08 / 1.09 / 1.06 | 1.09 / 0.45 / 0.39 | 1.07 / 1.04 / 0.92 | 1.05 / 1.08 / 1.01 |

The one-worker small-block decode, 30000×1K, 2^11, 10 losses, first 23 rerun at n = 8, w1 / w4:

| arm | w1 / w4 |
|---|---|
| decode-capacity | 1.55 / 1.54 |
| decode-pipeline | 1.55 / 1.67 |
| fft-four-step[leaf6] | 1.00 / 0.99 |
| decode-capacity+fft-four-step[leaf6] | 1.44 / 1.87 |
| decode-pipeline+fft-four-step[leaf6] | 1.44 / 1.82 |
| decode-capacity+fft-four-step[leaf4] | 1.25 / 1.69 |
| decode-pipeline+fft-four-step[leaf4] | 1.25 / 1.72 |

#### Charged peak memory

The engine's charged peak (`reserved_peak`) at w8 in MB: the default, the capacity decode, the pipeline decode, and default ÷ pipeline. The charge is deterministic, so the c7a rows stand for all three hosts: c7i matches c7a to the decimal, and c8g's default is up to 6% lower on the 1 KiB-block rows, with the same arms. Every other lane matched the default within 1%, except `cauchy-shared`.

| host | workload | default | capacity | pipeline | default ÷ pipeline |
|---|---|---:|---:|---:|---:|
| c7a | cauchy-L repair | 4.9 | 4.9 | 4.9 | 1.00 |
| c7a | cauchy-M repair | 2.6 | 2.6 | 2.6 | 1.00 |
| c7a | cauchy-S repair | 2.3 | 2.3 | 2.3 | 1.00 |
| c7a | fft-L repair | 137.9 | 11.8 | 15.8 | 8.71 |
| c7a | fft-S repair | 56.3 | 6.7 | 6.4 | 8.76 |
| c7a | fft-1.5G repair | 1899.9 | 527.3 | 783.9 | 2.42 |
| c7a | decode 128×64K, 2^5, 4 losses, first 0 | 20.9 | 6.6 | 8.6 | 2.43 |
| c7a | decode 30000×1K, 2^11, 10 losses, first 23 | 54.7 | 9.1 | 11.3 | 4.84 |
| c7a | decode 4096×16K, 2^8, 128 losses, first 0 | 139.5 | 11.4 | 15.4 | 9.04 |
| c7a | decode 4096×16K, 2^8, 4 losses, first 5 | 137.5 | 11.4 | 15.4 | 8.91 |

`cauchy-shared` on Cauchy create at w8, MB default / arm, the same on every host:

| host | workload | default / cauchy-shared | default ÷ arm |
|---|---|---|---:|
| c7a | cauchy-L create | 21.6 / 23.6 | 0.92 |
| c7a | cauchy-M create | 6.3 / 7.3 | 0.86 |
| c7a | cauchy-S create | 2.9 / 3.4 | 0.85 |

`fft-hash-feed` source reads at w8 in MB, the same on every host:

| host | workload | default | hash-feed |
|---|---|---:|---:|
| c7a | fft-L create | 128.0 | 64.0 |
| c7a | fft-S create | 29.3 | 29.3 |
| c7a | fft-1.5G create | 3072.0 | 1536.0 |

### Defects found and their disposition

1. **The hash feed left most workers idle.** `fft-hash-feed` gave the hash
   feed one thread out of `workers - hash_workers`. At w4 it measured
   0.73–1.07 on fft-L and fft-1.5G create, and about 1.0 at w1 and w8.
   Dropped with the lane.
2. **No check of the layout against the plan** before the hash feed used
   planned parity. Unreachable: the feed and its planned-recovery path are
   deleted.
3. **Four-step had no ISA or geometry gate.** Its sign changed with host and
   shape:
   - it won on c7a;
   - it lost on c7i encode and on c7i's small-block decode together with
     the capacity decode;
   - it lost on the 128 × 64 KiB encode at w4 and w8 on c7i and c8g;
   - it lost on the one-worker 30000 × 1 KiB decode against the capacity
     decode alone, on every host;
   - leaf 8 lost on c8g (0.38–0.45 on encode).

   Fixed by the CPU gate and the per-transform rule above.
4. **`cauchy-shared` was 25–100 times slower** on every Cauchy create, and
   its charged peak was higher (0.85–0.92 on the memory scale). Dropped.
5. **`encode-pruned` and `fft-recursive` had no measurable effect** anywhere.
   Dropped.
6. **Halving source reads bought no time.** The hash feed halved reads on
   fft-L and fft-1.5G and left fft-S unchanged, but saved no time, cached or
   cold, on these hosts. Dropped with the lane.
7. **The library read an environment variable on every codec
   construction,** and an invalid value failed every operation. Fixed: the
   variable and the module that read it are deleted.
8. **The grid's data generator overflowed on CPython before 3.12** at 1.5
   GiB. This was in the measurement tooling, not in this crate, and was
   worked around with chunked generation (the same byte stream).

### Not yet measured, and what is uncertain

- **Four-step at 2 workers, and on serial rows of 2 to 8 KiB.** Neither was
  a grid row. The gate applies the pooled rule at two workers and the 16 KiB
  serial threshold to those rows without a measurement behind either.
- **AMD hosts with AVX-512 GF kernels (Zen 5).** The gate requires the AVX2
  kernel, so four-step stays off there until it is measured.
- **The 128 × 64 KiB encode at 4 or more workers.** On c7a this row is noisy:
  the control spread is 0.77 to 1.27, and arms that cannot touch encode read
  about 0.6. On c7i and c8g, four-step loses on it with no such noise (0.64
  at w4). That loss is why the pooled rule excludes transforms of 64 points or
  fewer.
- **Thread counts in the PAR2 against PAR3 rows.** `rarpar par` has no
  thread flag, so every arm runs at its default thread count and the arms are
  not thread-matched.

### PAR2 against PAR3

This comparison has not been run yet; the fleet benchmark will run it once
this release is published.

The `rarpar-bench` harness has a `par3 versus` profile for it. Every arm
uses the same generated inputs, block size, recovery count and damage. The
arms are:
- PAR2 through `rarpar par`;
- par2cmdline-turbo, where the host has it;
- PAR3 Cauchy through `rarpar par3`;
- PAR3 FFT through `rarpar par3`.

Each arm creates its own set and repairs it over the same damaged copy of
the inputs. Every repair is checked against the inputs' SHA-256. The scale is
**par2 ÷ par3** median wall time, so a figure above 1 means the PAR3 arm was
faster. Peak RSS is reported raw for every arm.

The rows are:
- every arm at one recovery count on the Cauchy-class sets A (1 GiB, 1 MiB
  blocks) and B (10 × 30 MiB, 1 MiB blocks), at 10% recovery;
- FFT-only rows against both PAR2 arms on set A at 64 KiB blocks, at 10% and
  30% recovery.

### Open

1. Measure four-step at 2 workers and on serial rows of 2 to 8 KiB, and move
   the pooled and serial thresholds if the result says so.
2. Measure four-step on Zen 5 with the AVX-512 GF kernels; the gate keeps it
   off there until then.
3. Rerun the 128 × 64 KiB encode at 4 and 8 workers on c7a with more repeats,
   to confirm the loss seen on c7i and c8g, or show the exclusion is wider
   than it needs to be there.
4. Give `rarpar par` a thread flag, or record each arm's thread count, so the
   PAR2 against PAR3 rows can be thread-matched.

## Tuned verification and repair, 2026-09-08

The Weaver-facing tuning pass closes the measured small-file verification and
uneven-cohort FFT repair shortfalls on both native hosts. Weaver consumes
verification and repair; creation is reported separately below. This is engine
evidence, not a measurement of a Weaver application integration.

The changes reuse a budgeted carrier read-ahead stripe across packet boundaries
and dispatch FFT locator scaling through the existing SIMD linear-map kernels.
Source-generation checks, packet authentication, cancellation, and repair output
synchronization remain enabled. Default stripe size remains 64 KiB. Creation
also combines file/chunk hashing in one planning pass and buffers carrier writes.

Both final matrices passed **534 invocations each**, with the same nine cases,
one/four-worker limits, three repetitions, and reference builds described in
the earlier baseline sections. Reference verification of created carriers and
SHA-256 checks of both engines' repairs passed. All 108 batches of 100 unchanged
reassessments read zero source bytes; small-file repairs staged only the 64
damaged files. Memory reservations stayed within every configured limit and
observed handle peaks remained two.

Reference time divided by engine time, geometric means of workload medians:

| Host / codec / workers | Verify | Repair |
| --- | ---: | ---: |
| x86-64 / Cauchy / 1 | 3.56× | 5.49× |
| x86-64 / Cauchy / 4 | 3.46× | 6.00× |
| x86-64 / FFT / 1 | 2.59× | 1.98× |
| x86-64 / FFT / 4 | 2.57× | 2.20× |
| ARM64 / Cauchy / 1 | 3.04× | 2.94× |
| ARM64 / Cauchy / 4 | 2.84× | 2.83× |
| ARM64 / FFT / 1 | 2.09× | 1.64× |
| ARM64 / FFT / 4 | 2.09× | 1.87× |

One-worker improvements versus each host's earlier baseline:

- **Mac small files:** verification 43.1 → 13.4 ms; repair 62.5 → 30.4 ms;
  scan-only 39.6 → 8.6 ms. Current adapted-reference verification/repair:
  15.7 / 33.2 ms.
- **x86 small files:** verification 14.8 → 8.7 ms; repair 16.0 → 11.7 ms.
  Current reference: 11.0 / 23.2 ms.
- **Mac uneven FFT repair:** 231.8 → 201.7 ms, versus 215.8 ms for the
  adapted reference. Four-worker repair: 170.6 versus 212.6 ms.
- **x86 uneven FFT repair:** 303.3 → 241.4 ms, versus 267.2 ms for the
  reference. Four-worker repair: 221.4 versus 269.5 ms.

Peak repair RSS was 67.88 MiB on ARM64 and 68.05 MiB on x86-64. The 8 MiB
large-block case reserved at most 4.18 MiB, with repair RSS at most 2.66 and
3.55 MiB respectively. RSS includes allocator/runtime overhead outside engine
reservation accounting; it is not an allocation-budget assertion.

### Regression investigation

Comparisons with the historical runs flagged several Mac Cauchy timings above
5%, and x86 four-worker Cauchy GF8 verification at +6.9% (about 1 ms). The
reference also slowed on several Mac cases, but that alone does not explain
the engine changes. The exact earlier implementation was rebuilt with each
host's same native Rust toolchain for interleaved old/new comparisons.

On Mac, seven paired repetitions covered scan, verification, placement, and
repair for both worker limits on Cauchy GF8/GF16, heavy Cauchy, and large-block
cases: **448 successful invocations**, with repaired-output hash checks. None
of the 32 median comparisons regressed above 5%; the largest increase was 3.65%.
The x86 verification check used fifteen paired repetitions; the difference was
1.65%. A separate seven-pair Mac Cauchy GF16 creation check, with reference
verification of each set, measured a 10.45% improvement. These checks do not
reproduce a >5% implementation regression. All
original final-matrix samples remain in the report; A/B samples do not replace
them or enter reference-throughput aggregates. Mac load ranged 3.92–7.57 and
x86 load 0.27–1.43 in the final matrices. No task-owned build overlapped either
host's measurements, and existing services were not stopped.

### Creation is a separate result

With unchanged file-synchronization defaults, Cauchy creation reached 3.83/3.86×
reference throughput on x86 and 1.89/1.87× on Mac (one/four workers). FFT
creation reached 1.33/1.43× on x86 and **0.89/0.95× on Mac**. The all-operation
performance gate therefore remains open for default ARM64 FFT creation; it
does not block the measured verification/repair use case.

File-sync diagnostics attributed 36–46 ms to storage barriers in the ordinary
one-worker Mac FFT creation cases. A separate native sample spent 20 of 40
samples in `fcntl`; this is corroborating attribution, not a statistical
profile. Rust's Apple `sync_all` requests `F_FULLFSYNC`; the pinned reference
has no explicit matching barrier. The approved `CreationDurability::Buffered`
policy is opt-in through `execute_with_durability`: it flushes application
buffers and authenticates output while omitting durable storage barriers.
Default creation and all repair synchronization remain unchanged. See the
[Rust filesystem implementation](https://raw.githubusercontent.com/rust-lang/rust/1.97.0/library/std/src/sys/fs/unix.rs)
for the platform barrier semantics.

A separate buffered-creation matrix passed all **240 invocations** across the
four FFT cases, both worker limits, and three repetitions. Its FFT creation
geometric means were **1.32× / 1.38×** the adapted reference. Every creation
record reports `Buffered` and zero synchronization calls. This result is
explicitly opt-in and is excluded from the durable-default aggregates above;
it neither changes nor measures a different repair policy.

### Validation and evidence

Workspace formatting, all-target/all-feature Clippy, **2,546 Nextest tests**,
and **24 doctests** passed after these code changes. Twelve existing opt-in
tests and one host-hook doctest remain skipped. All four PAR2 real-world
consumer regressions passed within the workspace sweep. Targeted tests check
one-pass planning, scanner read counts and stale generations, scalar/SIMD
scaling equivalence and cancellation, and byte-identical creation policies.

The scanner slice is signed commit `276c7c1`; the complete measured runtime is
reproduced by applying the archived `tuning.patch` to `10b1640`. Binary and
source hashes are included. The earlier baseline sections below are retained
as historical measurements, including their then-open tuning gaps.

[`benchmarks/native-tuning-20260908.tar.gz`](benchmarks/native-tuning-20260908.tar.gz)
contains both tuned matrices, baseline comparisons, A/B checks, the separate
buffered-creation run, source patch, binary hashes, scripts, and validation logs.
It excludes generated inputs, carriers, outputs, and downloaded dependencies.
Archive SHA-256:
`8aebf8c7a470cd1ae19ed627c8d218fa3005a35ec05ace19acbe1644e5d62f0c`.

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
