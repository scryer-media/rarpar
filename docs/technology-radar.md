# Technology radar

Engine-side kernel and platform work for the PAR2, PAR3 and RAR crates. Weaver keeps the yEnc, CRC and server-side radar in its own repository.

Rules that govern every row: one binary with runtime dispatch; a kernel tier is never dropped because no local host has its instruction set; a tier is kept when it materially moves wall clock or CPU time where it engages without adding significant risk or code, and regresses nothing else by more than 1%; there is no minimum percentage; disk work (fsyncs, opens, read and write calls) is a regression axis on its own.

Status: **Landed** ships; **Building** has an owner now; **Exploring** is a measured spike before a decision; **Watch** waits on hardware or evidence; **Dropped** was measured and abandoned, kept on the radar so the attempt is not repeated.

| Item | Serves | Status | Needs |
|---|---|---|---|
| GFNI affine tiers on AVX2 for GF(2^8), GF(2^16) and the FFT linear maps | PAR2, PAR3 | Landed | |
| Native 8-bit FFT lane, fused butterflies and radix-4, zero truncation, in-place scaling | PAR3 FFT | Landed | |
| FFT repair through capacity-sized windows (Algorithm 5 of Chen, Lin, Tang, Han and others, 2026): two banks of `capacity` rows plus a third that overlaps the next fill when workers can use it; pass-count admission, proof frontiers before decode; 1.2–1.9x faster repair on c7a, c7i and c8g, and a 4096 × 16 KiB repair's charged peak down from 137.9 MB to 15.8 MB | PAR3 repair | Landed | |
| Four-step FFT transform (leaf 2^6), gated to AMD CPUs with the AVX2 linear kernels, on pooled transforms over more than 64 points and serial ones over rows of at least 16 KiB | PAR3 FFT on AMD | Landed | Zen 5 with AVX-512 kernels, two workers and 2–8 KiB serial rows are unmeasured, so gated off |
| Grouped multi-source Cauchy kernels, resident recovery rows, clone-based staging, no read-back, spool never fsynced | PAR3 create and repair | Landed | |
| Reference comparison fleet and PAR3 bench suite (`rarpar-bench par3`) | measurement | Landed | live Windows and SSM runs |
| GF(2^8) AVX-512 tiers (GFNI on zmm, VBMI nibble form), cached multiply plans, factor 0 and 1 short-circuits | PAR2, PAR3 | Building | Zen 4 and Sapphire Rapids via the fleet |
| SVE2 tiers for GF(2^8), the FFT linear maps and the fused Cauchy kernels | PAR2, PAR3 on Graviton 4 | Building | c8g via the fleet |
| wasm simd128 tiers for the FFT linear maps and grouped GF(2^8); GF(2^16) wasm widened to all lanes | PAR3, PAR2 on wasm | Building | wasmtime benches |
| Column-tiled FFT execution, budget-sized FFT stripes, contiguous aligned banks | PAR3 FFT | Building | |
| Planning hashes fused with the encode read; redundant zero-fills and coverage scans removed; repair validation fused into the codec read | PAR3 disk work | Building | |
| par3cmdline-compatible command line (`v`, `l`, `r`, `vs`, `rs` when run as `par3`) | rarpar CLI | Landed | |
| PAR3 inside RAR5 archives and volume sets (experimental `par3 inside`): one `PAR3` service record before the end header, its header sealed under `-hp`; rarpar orchestrates unrar-rs service-record hooks and the container-blind par3-rs embedded sets; round trips and extraction checked with unrar-rs, other RAR readers not yet re-checked with this record; earlier layouts measured 1 GiB inserts in 0.7 to 1.5 s at 2 to 15% and repairs in 1.6 to 2.6 s | PAR3, rarpar CLI, unrar-rs | Building | layout agreed with the PAR3 maintainers |
| Frobenius additive FFT: evaluations at conjugate points follow from one another under the Frobenius map, so one point per orbit is transformed (Li, Chen, Kuo, Cheng, Yang 2018) | PAR3 FFT | Exploring | the published saving is for polynomials whose coefficients lie in a subfield, and block data fills the whole field, so the spike first has to show that any of it carries over; on create the byte-exact par3cmdline differential is the gate |
| Recursive stage order for the additive FFT (Samanta, Badakhshan, Gong 2026) and the `encode-pruned`, `fft-hash-feed` and `cauchy-shared` lanes | PAR3 FFT and Cauchy | Dropped | measured on c7a, c7i and c8g: the recursive order and `encode-pruned` about 1.0x everywhere; `fft-hash-feed` halved source reads but saved no time and was 0.73–0.92x at 4 workers on the 1.5 GiB create; `cauchy-shared` 10–100x slower on Cauchy create with a higher charged peak; see `crates/par3-rs/PERFORMANCE.md` |
| SME2 GF(2) outer-product GEMM (`BMOPA`) for Cauchy and Vandermonde encode and solve | PAR2, PAR3 | Watch | spike measured: slower than NEON at the 12–16 source groups the engines issue and at 8–18 workers (SME unit shared per cluster); wins 2–3x only at 64 or more sources per product; kept as an opt-in `kernel_ceiling` lane |
| Wide-K engine restructure: stage 64 or more source stripes per matrix product instead of 16 | PAR2, PAR3 Cauchy, matrix-unit ISAs | Dropped | breakpoint spike measured on Apple silicon at 8 workers: repair of 1–10 lost blocks never crosses on realistic sets (N 256–51,200 blocks, 64 KiB stripe: SME2 saves 8–14 ms of compute per pass against at least 130 ms of streamed read, and holding K stripes resident forfeits NEON's read-ahead overlap, a net loss cold); PAR2 shows no crossover up to N=32,000 for 1–4 lost blocks or 5–10% recovery; full-recovery create is 1.2–1.5x on the kernel but per-pass plan rebuilds erase it and cached plans cost 32·R·N bytes (1.6 GB at N=32,000); the apparent 1.9x on one lost block was the PAR3 repair nest running row-parallel on one thread, fixed by a column split instead (see PAR3 repair row); revisit only if large-set create with page-cached sources and a 256 KiB or larger stripe becomes a hot path |
| PAR3 repair nest column split when fewer blocks are lost than there are workers | PAR3 | Dropped | measured on Sapphire Rapids and Apple silicon against the merged column-tiled FFT: at 8 workers it was 1.06–1.11x slower on wall and 1.26–1.64x on CPU for 1–4 lost blocks at a 64 KiB stripe, flat at 10 lost, and 1.02–1.16x CPU with +16 MiB at a 1 MiB stripe; repair is bounded by disk reads the existing nest already overlaps, so the idle threads the wide-K spike saw were waiting on I/O, not on the kernel; the patch is kept in the campaign handoff folder |
| GF(2^16) folded tier for AVX2 hosts without GFNI (Zen 2, pre-Ice-Lake) | PAR2 repair | Watch | measured gap on Zen 2 is 2.4x wall against par2cmdline-turbo |
| SME streaming-width multi-buffer hashing (MD5, BLAKE3) | PAR2 verify, PAR3 planning | Watch | unproven; mode-switch cost |
| AVX512BMM GF(2^16) tier (Zen 6 `VBMACXOR16x16x16`) | PAR2, PAR3 | Watch | no Zen 6 instances on EC2 yet |
| AVX10.2 and APX | every x86 kernel | Watch | Diamond Rapids and Nova Lake; EVEX kernels carry over, APX helps register-bound grouped kernels |
| AVX-512 FFT linear map tier | PAR3 FFT | Watch | depends on the GF(2^8) AVX-512 result |

The PAR3 FFT lane shipped today is the additive transform of Lin, Al-Naffouri, Han and Chung (2016) with the capacity-window erasure decoder of Chen, Lin, Tang, Han and others (2026). The other rows come from later work:

- Baseline: S.-J. Lin, T. Y. Al-Naffouri, Y. S. Han, W.-H. Chung, "Novel Polynomial Basis With Fast Fourier Transform and Its Application to Reed-Solomon Erasure Codes", IEEE Trans. Inf. Theory 62(11), 2016, [doi:10.1109/TIT.2016.2608892](https://doi.org/10.1109/TIT.2016.2608892).
- C. Chen, S.-J. Lin, Z. Li, S. Cai, Y. S. Han, B. Bai, "Reduced-Complexity Erasure Decoding of Low-Rate Reed-Solomon Codes Based on LCH-FFT", IEEE ISIT 2023, pp. 1015-1019; extended by C. Chen, S.-J. Lin, N. Tang, Y. S. Han, S. Cai, L. Yu, Z. Li, B. Bai, B. Bai, "Two Fast Erasure Decoding Algorithms for Reed-Solomon Codes Based on LCH-FFT", IEEE Trans. Inf. Theory, 2026 (authors' version).
- W.-D. Li, M.-S. Chen, P.-C. Kuo, C.-M. Cheng, B.-Y. Yang, "Frobenius Additive Fast Fourier Transform", ISSAC 2018, [arXiv:1802.03932](https://arxiv.org/abs/1802.03932).
- S. Samanta, M. Badakhshan, G. Gong, "On the Additive FFT Techniques over Binary Extension Fields", 2026, [arXiv:2608.20855](https://arxiv.org/abs/2608.20855).

Error-correcting decoders (the Welch-Berlekamp line, Tang and Han 2022) are not on the radar: PAR3 repair knows which blocks are lost from their checksums, so it only ever decodes erasures.

What each shipped paper contributed, and where it is used, is recorded in
[ATTRIBUTION.md](../ATTRIBUTION.md).
