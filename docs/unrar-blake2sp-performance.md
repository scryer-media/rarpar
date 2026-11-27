# BLAKE2sp verification performance

RAR5 archives can select BLAKE2sp for member verification. On a 64 MiB stored member, the new kernels reduced extraction time by 28% on Intel Sapphire Rapids, 22% on AMD Zen 4 and 14% in local WebAssembly engines. Graviton4 gained 5% when pinned to one CPU. Its default four-vCPU extraction retained the existing two-worker NEON implementation and had essentially identical timing.

## Standalone hashing

Median elapsed milliseconds per 64 MiB hash, from baseline to candidate. Process CPU and peak resident memory refer to the 64 KiB update workload. CPU reductions are medians of paired changes. The Wasm guest timers exclude engine startup.

| Hardware and engine | One shot (ms) | 64 KiB updates (ms) | Process CPU reduction | Peak RSS (MiB) |
|---|---:|---:|---:|---:|
| Xeon Platinum 8488C | 28.95 → 19.88 | 30.22 → 20.07 | 32.3% | 66.02 → 66.10 |
| EPYC 9R14 | 22.62 → 16.66 | 22.86 → 16.73 | 25.0% | 65.96 → 65.98 |
| Graviton4 | 38.99 → 36.65 | 39.02 → 36.72 | 5.7% | 65.60 → 65.57 |
| M5 Max, Wasmtime 47 | 43.39 → 36.85 | 43.49 → 35.99 | 16.3% | 72.06 → 72.06 |
| M5 Max, Node 26 | 44.50 → 37.35 | 43.22 → 36.15 | 13.4% | 114.77 → 113.52 |

The two WebAssembly CPU percentages above use the ratio of process medians. With 4 MiB updates, native hash times fell from 29.35 to 19.89 ms on Intel, 22.65 to 16.66 ms on AMD and 39.00 to 36.67 ms on Graviton4.

## Verified extraction

The time per member is the median of each process's timed extraction average. CPU reductions use paired total process CPU time, including worker threads. Peak RSS columns give the median of each arm.

| Hardware and engine | Time per member (ms) | Paired elapsed reduction | Process CPU reduction | Peak RSS (MiB) |
|---|---:|---:|---:|---:|
| Xeon Platinum 8488C | 30.96 → 22.34 | 28.0% | 21.1% | 15.94 → 16.85 |
| EPYC 9R14 | 24.64 → 19.26 | 21.6% | 17.0% | 16.02 → 15.92 |
| Graviton4, one vCPU allowed | 46.19 → 43.87 | 5.0% | 5.0% | 12.92 → 12.92 |
| Graviton4, all four vCPUs | 30.14 → 30.15 | −0.06% | −0.07% | 15.13 → 15.19 |
| M5 Max, Wasmtime 47 | 51.20 → 43.78 | 14.5% | 14.4% | 13.59 → 13.65 |
| M5 Max, Node 26 | 50.90 → 43.93 | 13.7% | 12.3% | 59.05 → 58.05 |

Intel extraction's seven primary pairs showed a median peak RSS increase of 816 KiB. Independent five-pair measurements with GNU time gave a 116 KiB increase. A separate allocation trace observed an extra live 1 MiB buffer in one run and equal peaks in other runs with increased RSS. The cause of the RSS variation remains unresolved. The x86 hasher state occupied 1,328 bytes in both builds.

## Kernel selection

- **x86-64.** Runtime detection selects an eight-leaf, 256-bit kernel when AVX2, AVX-512F and AVX-512VL are available. It transposes message words in registers and carries the chaining state across batches. Release disassembly showed native vector rotates and zero ZMM register references in both compression functions. The timings measure the combined kernel and streaming changes. Tests exercised the existing upstream, SSE2, SSSE3 and portable paths.
- **AArch64.** With SVE2, whole-tree bulk hashing uses fused XOR and rotate for 7 and 12 bits. Dispatch occurs after the buffered tail has been drained and enough data remains for direct compression. Dispatching every update made one-byte fragments 47% slower. Moving dispatch into the bulk path reduced that difference to +0.12% on Graviton4. Fusing all four rotations increased hash time by 3.6% and verified extraction time by 10.8%. Applying selective fusion to the four-leaf workers also slowed extraction by 1.7%. Those workers retain NEON.
- **Apple silicon.** Exact-source NEON fallback hash times stayed within 0.7% of baseline on the M5 Max. Interleaving the two four-leaf groups by round or mixing operation changed timings by less than 1%. Processing 8, 32 or 128 superblocks per group before switching groups increased one-shot time by 3.9–5.4%. These scheduling experiments were discarded.
- **WebAssembly.** The simd128 kernel uses byte shuffles for the 8- and 16-bit rotations. Interleaving gave small one-shot gains and mixed streaming results, so the existing schedule was retained. Wasm extraction already uses inline hashing.

## Measurement

The control was `63d5819`. Both arms used Rust 1.97.1, the workspace release profile with fat LTO and one codegen unit, and the same dependency lockfile. Native tests used `c7i.xlarge` (Xeon Platinum 8488C), `c7a.xlarge` (EPYC 9R14) and `c8g.xlarge` (Graviton4, Neoverse V2). WebAssembly ran locally on an M5 Max in Wasmtime 47 and Node 26 with WASI Preview 1.

The hash workloads used the public one-shot and streaming interfaces with 64 MiB inputs. Native paired runs alternated execution order and pinned standalone hash comparisons to one CPU. WebAssembly runs varied execution order and verified the digest in both engines. The repository's existing `archive_hotspots` Criterion benchmark also exposes the one-shot, 4 MiB and 64 KiB update shapes.

For extraction, RARLAB RAR 7.23 packed a 64 MiB zero-filled member using `-m0 -htb -qo-`. Its BLAKE2sp digest was `a92b6715ea4ee95235c090b6a61dd92c9dd77e4d494a06a8ce26493ea16ac430`. Every iteration reopened the archive, copied the member through `RarArchive::by_index(0)?.copy_to(...)`, and checked that the writer received 67,108,864 bytes. The archive was warm in the filesystem cache. Each extraction process performed one warmup and ten timed verifications on x86 and WebAssembly, or eight on Graviton4. The extraction comparisons used seven pairs on Intel and Graviton4, nine on AMD and eight per WebAssembly engine. Process CPU includes all threads. Peak RSS covers the whole process. This fixture isolates a hash-heavy stored member. It provides no estimate of how many Usenet posts select BLAKE2sp.

The existing benchmark can be run with `cargo bench --locked -p unrar-rs --features unstable-internals --bench archive_hotspots -- blake2sp_`. The hash oracle on AArch64 and wasm32 with simd128 is the `blake2sp_wasm_check` example. It checks 1,094 one-shot and 240 randomly split streaming cases against `blake2s_simd`.
