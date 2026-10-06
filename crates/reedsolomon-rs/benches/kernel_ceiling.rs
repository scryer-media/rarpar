//! Single-thread throughput ceilings of the region kernels.
//!
//! Each kernel is timed on one thread over buffer sizes from L1-resident to
//! far beyond the last-level cache, next to a plain XOR and a
//! `copy_from_slice` of the same size as memory-bandwidth baselines. The
//! numbers are an upper bound on what any pipeline built from these kernels
//! can do per core; they say nothing about end-to-end PAR2/PAR3 parity.
//!
//! Reported throughput is *region bytes per second*: for a kernel that folds
//! `k` sources into one destination, or one source into `k` destinations,
//! that is `k * len` per call, the bytes of product terms it accumulates. For
//! the copy and XOR baselines it is `len`.
//!
//! This is not a criterion bench: the output is one table meant to be read
//! side by side. Every cell is the best of several timed repetitions, each
//! long enough to dwarf timer resolution.
//!
//! The `fft` rows time the FFT linear maps on their own: `accumulate` with
//! each backend, the in-place map through a stripe scale, and the fused
//! butterfly and radix-4 kernels through a forward transform of two and of
//! four rows (one sweep each) that together hold the cell's bytes. With the
//! `Scalar` backend a transform takes the log-table oracle instead.
//!
//! Run: `cargo bench -p reedsolomon-rs --bench kernel_ceiling`
//! Knob: `RS_CEILING_MS` (per-repetition floor in milliseconds, default: 60).
//!
//! The bench also builds for `wasm32-wasip1`, where a portable build and a
//! `-C target-feature=+simd128` build of the same source are the scalar and
//! SIMD sides of each row (wasm selects its tier at compile time):
//!
//! ```text
//! RUSTFLAGS="-C target-feature=+simd128" cargo bench --locked --no-run \
//!     -p reedsolomon-rs --bench kernel_ceiling --target wasm32-wasip1
//! wasmtime run -W simd=y --env RS_CEILING_MS=60 kernel_ceiling-<hash>.wasm
//! ```
//!
//! SME2 lane (aarch64 with SME2, opt-in): `RS_CEILING_SME2=1` adds the
//! `BMOPA` GF(2) matrix-product kernels of `support/sme2_gemm.rs` against the
//! NEON grouped kernels at Reed-Solomon product shapes, in wall and CPU time.
//! `RS_CEILING_SME2_THREADS` (default `1`, e.g. `1,8,18`) sets the worker
//! counts; `RS_CEILING_SME2_STRIPE` (KiB, default 64) the stripe.

#[cfg(target_arch = "aarch64")]
#[path = "support/sme2_gemm.rs"]
mod sme2_gemm;

fn main() {
    imp::main();
    #[cfg(target_arch = "aarch64")]
    if std::env::var_os("RS_CEILING_SME2").is_some_and(|v| v == "1") {
        sme2_lane::main();
    }
}

mod imp {
    use std::hint::black_box;
    use std::time::{Duration, Instant};

    use reedsolomon_rs::fft::TransformField;
    use reedsolomon_rs::gf_simd::{
        self, FactorDst, FactorSrc, LinearBackend, PreparedFactorSrc, mul_acc_input_batch,
        mul_acc_input_batch_prepared, mul_acc_multi_region, prepare_input_factor,
    };
    use reedsolomon_rs::gf_simd::{LinearMap8, LinearMap16};
    use reedsolomon_rs::gf8;

    const SIZES: [usize; 4] = [4 << 10, 64 << 10, 1 << 20, 16 << 20];
    /// Timed repetitions per cell; the fastest is reported.
    const REPETITIONS: usize = 5;
    /// Sources (or destinations) in the wide fused shapes. Above three, the
    /// aarch64 grouped-input dispatch switches from table shuffles to CLMUL.
    const WIDE: usize = 16;
    /// The widest grouped-input shape that stays on the aarch64 shuffle path.
    const NARROW: usize = 3;

    fn fill(seed: u64, len: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; len];
        let mut state = seed | 1;
        for word in bytes.chunks_mut(8) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            word.copy_from_slice(&state.to_le_bytes()[..word.len()]);
        }
        bytes
    }

    /// Nonzero, non-identity GF(2^16) factors, so no call takes the XOR path.
    fn factor16(at: usize) -> u16 {
        0x1234u16.wrapping_add(0x0f1d * at as u16) | 2
    }

    /// Best region-bytes-per-second over the repetitions of `call`, which
    /// processes `bytes` per invocation.
    fn measure(bytes: usize, floor: Duration, mut call: impl FnMut()) -> f64 {
        call();
        // Size a repetition from one timed batch so tiny buffers are not
        // dominated by `Instant` reads.
        let mut calls = 1usize;
        loop {
            let start = Instant::now();
            for _ in 0..calls {
                call();
            }
            if start.elapsed() >= floor / 4 || calls >= 1 << 24 {
                break;
            }
            calls *= 2;
        }
        let mut best = Duration::MAX;
        for _ in 0..REPETITIONS {
            let start = Instant::now();
            for _ in 0..calls {
                call();
            }
            best = best.min(start.elapsed());
        }
        (bytes * calls) as f64 / best.as_secs_f64() / (1u64 << 30) as f64
    }

    fn backend() -> String {
        let mut notes = vec![
            format!("arch {}", std::env::consts::ARCH),
            format!("fft linear kernel {:?}", LinearBackend::Auto.kernel()),
        ];
        #[cfg(target_arch = "aarch64")]
        {
            for (name, present) in [
                ("neon", std::arch::is_aarch64_feature_detected!("neon")),
                ("pmull", std::arch::is_aarch64_feature_detected!("aes")),
                ("sha3", std::arch::is_aarch64_feature_detected!("sha3")),
            ] {
                notes.push(format!("{name} {present}"));
            }
            // The CLMUL grouped-input gate is crate-private; its only input
            // besides the batch width is this override.
            notes.push(format!(
                "WEAVER_GF16_CLMUL_BATCH {}",
                std::env::var("WEAVER_GF16_CLMUL_BATCH").unwrap_or_else(|_| "unset".into())
            ));
        }
        #[cfg(target_arch = "x86_64")]
        {
            for (name, present) in [
                ("ssse3", is_x86_feature_detected!("ssse3")),
                ("avx2", is_x86_feature_detected!("avx2")),
                ("avx512bw", is_x86_feature_detected!("avx512bw")),
                ("avx512vl", is_x86_feature_detected!("avx512vl")),
                ("gfni", is_x86_feature_detected!("gfni")),
            ] {
                notes.push(format!("{name} {present}"));
            }
        }
        #[cfg(target_family = "wasm")]
        notes.push(format!(
            "simd128 {}, relaxed-simd {}, fft linear wasm simd128 {}",
            cfg!(target_feature = "simd128"),
            cfg!(target_feature = "relaxed-simd"),
            gf_simd::linear_uses_wasm_simd128()
        ));
        notes.push(format!("folded gfni {}", gf_simd::folded_uses_gfni()));
        notes.join(", ")
    }

    pub fn main() {
        let floor = Duration::from_millis(
            std::env::var("RS_CEILING_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),
        );
        println!("kernel_ceiling: single-thread region throughput, GiB/s (best of {REPETITIONS})");
        println!("{}\n", backend());

        let names = [
            "copy_from_slice".to_owned(),
            "xor".to_owned(),
            "gf8::mul_acc_region".to_owned(),
            "gf8::MulPlan::accumulate".to_owned(),
            format!("gf8 mul_acc_input_batch x{WIDE}"),
            "gf16 mul_acc_region".to_owned(),
            format!("gf16 mul_acc_input_batch x{NARROW}"),
            format!("gf16 mul_acc_input_batch x{WIDE}"),
            format!("gf16 mul_acc_input_batch_prepared x{WIDE}"),
            format!("gf16 mul_acc_multi_region 1->{WIDE}"),
            "fft LinearMap8::accumulate Scalar".to_owned(),
            "fft LinearMap8::accumulate Auto".to_owned(),
            "fft LinearMap16::accumulate Scalar".to_owned(),
            "fft LinearMap16::accumulate Auto".to_owned(),
            "fft gf8 map (scale_u8) Auto".to_owned(),
            "fft gf16 map (scale) Auto".to_owned(),
            "fft gf8 butterfly (2-row transform) Auto".to_owned(),
            "fft gf8 radix-4 (4-row transform) Auto".to_owned(),
            "fft gf16 butterfly (2-row transform) Auto".to_owned(),
            "fft gf16 radix-4 (4-row transform) Auto".to_owned(),
        ];
        let field8 = TransformField::new(8).expect("8-bit field");
        let field16 = TransformField::new(16).expect("16-bit field");
        // Images of the input bits under a nonzero, non-identity factor.
        let basis8: [u8; 8] = std::array::from_fn(|bit| field8.mul(1 << bit, 0x53) as u8);
        let basis16: [u16; 16] = std::array::from_fn(|bit| field16.mul(1 << bit, 0x1234));
        let never = || false;
        let mut table = vec![[0f64; SIZES.len()]; names.len()];

        for (column, &len) in SIZES.iter().enumerate() {
            let sources: Vec<Vec<u8>> = (0..WIDE).map(|at| fill(at as u64 + 1, len)).collect();
            let mut outputs: Vec<Vec<u8>> = (0..WIDE).map(|_| vec![0u8; len]).collect();
            let src = &sources[0];
            let mut row = 0;
            let mut cell = |value: f64| {
                table[row][column] = value;
                row += 1;
            };

            let dst = &mut outputs[0];
            cell(measure(len, floor, || {
                dst.copy_from_slice(black_box(src));
                black_box(&mut *dst);
            }));
            cell(measure(len, floor, || {
                for (to, from) in dst.iter_mut().zip(black_box(src)) {
                    *to ^= from;
                }
                black_box(&mut *dst);
            }));
            cell(measure(len, floor, || {
                gf8::mul_acc_region(0x8e, black_box(src), dst);
                black_box(&mut *dst);
            }));
            let plan = gf8::MulPlan::new(0x8e);
            cell(measure(len, floor, || {
                plan.accumulate(black_box(src), dst);
                black_box(&mut *dst);
            }));
            let plans: Vec<gf8::MulPlan> = (0..WIDE)
                .map(|at| gf8::MulPlan::new((at as u8).wrapping_mul(29).wrapping_add(3)))
                .collect();
            let batch8: Vec<gf8::PlanSrc<'_>> = plans
                .iter()
                .zip(&sources)
                .map(|(plan, src)| gf8::PlanSrc { plan, src })
                .collect();
            cell(measure(WIDE * len, floor, || {
                gf8::mul_acc_input_batch(dst, black_box(&batch8));
                black_box(&mut *dst);
            }));
            cell(measure(len, floor, || {
                gf_simd::mul_acc_region(factor16(0), black_box(src), dst);
                black_box(&mut *dst);
            }));

            for width in [NARROW, WIDE] {
                let batch: Vec<FactorSrc<'_>> = sources[..width]
                    .iter()
                    .enumerate()
                    .map(|(at, src)| FactorSrc {
                        factor: factor16(at),
                        src,
                    })
                    .collect();
                cell(measure(width * len, floor, || {
                    mul_acc_input_batch(dst, black_box(&batch));
                    black_box(&mut *dst);
                }));
            }

            let prepared: Vec<_> = (0..WIDE)
                .map(|at| prepare_input_factor(factor16(at)))
                .collect();
            let batch: Vec<PreparedFactorSrc<'_>> = sources
                .iter()
                .zip(&prepared)
                .map(|(src, prepared)| PreparedFactorSrc { prepared, src })
                .collect();
            cell(measure(WIDE * len, floor, || {
                mul_acc_input_batch_prepared(dst, black_box(&batch));
                black_box(&mut *dst);
            }));

            cell(measure(WIDE * len, floor, || {
                let mut fan: Vec<FactorDst<'_>> = outputs
                    .iter_mut()
                    .enumerate()
                    .map(|(at, dst)| FactorDst {
                        factor: factor16(at),
                        dst,
                    })
                    .collect();
                mul_acc_multi_region(&mut fan, black_box(src));
                black_box(&mut fan);
            }));

            let dst = &mut outputs[0];
            for backend in [LinearBackend::Scalar, LinearBackend::Auto] {
                let map = LinearMap8::new(basis8, backend);
                cell(measure(len, floor, || {
                    map.accumulate(black_box(src), dst);
                    black_box(&mut *dst);
                }));
            }
            let words: Vec<u16> = src
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect();
            let mut word_dst = vec![0u16; words.len()];
            for backend in [LinearBackend::Scalar, LinearBackend::Auto] {
                let map = LinearMap16::new(basis16, backend);
                cell(measure(len, floor, || {
                    map.accumulate(black_box(&words), &mut word_dst);
                    black_box(&mut word_dst);
                }));
            }
            let mut bytes = src.clone();
            cell(measure(len, floor, || {
                field8
                    .scale_u8_with_backend(&mut bytes, 0x53, LinearBackend::Auto, &never)
                    .unwrap();
                black_box(&mut bytes);
            }));
            let mut symbols = words.clone();
            cell(measure(len, floor, || {
                field16
                    .scale_with_backend(&mut symbols, 0x1234, LinearBackend::Auto, &never)
                    .unwrap();
                black_box(&mut symbols);
            }));
            // A forward transform of `count` rows is one sweep: a butterfly
            // for two rows, a radix-4 for four. The origin is a multiple of
            // both counts that gives every map a factor other than 0 and 1.
            for count in [2usize, 4] {
                let mut rows: Vec<Vec<u8>> =
                    src.chunks_exact(len / count).map(<[u8]>::to_vec).collect();
                cell(measure(len, floor, || {
                    field8
                        .transform_u8_with_backend(
                            &mut rows,
                            52,
                            false,
                            LinearBackend::Auto,
                            &never,
                        )
                        .unwrap();
                    black_box(&mut rows);
                }));
            }
            for count in [2usize, 4] {
                let mut rows: Vec<Vec<u16>> = words
                    .chunks_exact(words.len() / count)
                    .map(<[u16]>::to_vec)
                    .collect();
                cell(measure(len, floor, || {
                    field16
                        .transform_with_backend(&mut rows, 52, false, LinearBackend::Auto, &never)
                        .unwrap();
                    black_box(&mut rows);
                }));
            }
        }

        let width = names.iter().map(String::len).max().unwrap_or(0);
        print!("{:width$}", "kernel");
        for len in SIZES {
            let label = if len >= 1 << 20 {
                format!("{} MiB", len >> 20)
            } else {
                format!("{} KiB", len >> 10)
            };
            print!(" {label:>9}");
        }
        println!();
        for (name, row) in names.iter().zip(&table) {
            print!("{name:width$}");
            for value in row {
                print!(" {value:>9.2}");
            }
            println!();
        }
    }
}

/// The SME2 lane: one table of NEON grouped kernels against the `BMOPA`
/// matrix product per shape and worker count.
#[cfg(target_arch = "aarch64")]
mod sme2_lane {
    use std::time::Instant;

    use rayon::prelude::*;
    use reedsolomon_rs::{gf_simd, gf8};

    use crate::sme2_gemm::{self, CHUNK, Plan};

    /// Process CPU time in seconds.
    fn cpu_seconds() -> f64 {
        #[repr(C)]
        struct Timespec {
            sec: i64,
            nsec: i64,
        }
        unsafe extern "C" {
            fn clock_gettime(clock: std::ffi::c_int, out: *mut Timespec) -> std::ffi::c_int;
        }
        #[cfg(target_os = "macos")]
        const CLOCK_PROCESS_CPUTIME_ID: std::ffi::c_int = 12;
        #[cfg(not(target_os = "macos"))]
        const CLOCK_PROCESS_CPUTIME_ID: std::ffi::c_int = 2;
        let mut now = Timespec { sec: 0, nsec: 0 };
        // SAFETY: a valid clock id and out-pointer.
        unsafe { clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &mut now) };
        now.sec as f64 + now.nsec as f64 * 1e-9
    }

    fn fill(seed: u64, len: usize) -> Vec<u8> {
        let mut state = seed | 1;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect()
    }

    /// Best (wall, cpu) seconds per call over three rounds of ~`budget`.
    fn timed(budget: f64, mut call: impl FnMut()) -> (f64, f64) {
        call();
        let mut best = (f64::MAX, 0.0);
        for _ in 0..3 {
            let (cpu, start) = (cpu_seconds(), Instant::now());
            let mut calls = 0u32;
            while calls == 0 || start.elapsed().as_secs_f64() < budget / 3.0 {
                call();
                calls += 1;
            }
            let wall = start.elapsed().as_secs_f64() / f64::from(calls);
            if wall < best.0 {
                best = (wall, (cpu_seconds() - cpu) / f64::from(calls));
            }
        }
        best
    }

    /// `parts` ranges of whole chunks covering `[0, symbols)`.
    fn ranges(symbols: usize, parts: usize) -> Vec<(usize, usize)> {
        let chunks = symbols / CHUNK;
        let per = chunks.div_ceil(parts).max(1);
        (0..chunks)
            .step_by(per)
            .map(|c| (c * CHUNK, ((c + per).min(chunks) - c) * CHUNK))
            .collect()
    }

    struct Rows(Vec<*mut u8>);
    // SAFETY: tasks write disjoint column ranges of the rows.
    unsafe impl Sync for Rows {}

    impl Rows {
        /// The rows, viewed by one task that only touches its own columns.
        #[allow(clippy::mut_from_ref)]
        fn view(&self, len: usize) -> Vec<&mut [u8]> {
            // SAFETY: each pointer is a live row of `len` bytes; concurrent
            // tasks touch disjoint columns.
            self.0
                .iter()
                .map(|&p| unsafe { std::slice::from_raw_parts_mut(p, len) })
                .collect()
        }
    }

    fn row(shape: &str, workers: usize, bytes: usize, neon: (f64, f64), sme: (f64, f64)) {
        let gib = |wall: f64| bytes as f64 / wall / f64::from(1u32 << 30);
        println!(
            "{shape:<16} {workers:>2} | {:>7.2} {:>9.1} {:>9.1} | {:>7.2} {:>9.1} {:>9.1} | {:>5.2} {:>5.2}",
            gib(neon.0),
            neon.0 * 1e6,
            neon.1 * 1e6,
            gib(sme.0),
            sme.0 * 1e6,
            sme.1 * 1e6,
            neon.0 / sme.0,
            neon.1 / sme.1
        );
    }

    fn gf8_shape(sources: usize, rows: usize, len: usize, workers: &[usize], budget: f64) {
        let srcs: Vec<Vec<u8>> = (0..sources).map(|s| fill(s as u64 + 1, len)).collect();
        let coef: Vec<Vec<u8>> = (0..rows)
            .map(|r| (0..sources).map(|s| ((r * 31 + s * 7) as u8) | 2).collect())
            .collect();
        let plans: Vec<Vec<gf8::MulPlan>> = coef
            .iter()
            .map(|row| row.iter().map(|&c| gf8::MulPlan::new(c)).collect())
            .collect();
        let plan = Plan::gf8(&coef);
        let mut out: Vec<Vec<u8>> = (0..rows).map(|_| vec![0u8; len]).collect();
        let dsts = Rows(out.iter_mut().map(|d| d.as_mut_ptr()).collect());
        let views: Vec<&[u8]> = srcs.iter().map(Vec::as_slice).collect();
        for &threads in workers {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap();
            let parts = ranges(len, threads);
            let neon = timed(budget, || {
                pool.install(|| {
                    parts.par_iter().for_each(|&(at, n)| {
                        for (r, dst) in dsts.view(len).into_iter().enumerate() {
                            let inputs: Vec<gf8::PlanSrc<'_>> = (0..sources)
                                .map(|s| gf8::PlanSrc {
                                    plan: &plans[r][s],
                                    src: &views[s][at..at + n],
                                })
                                .collect();
                            for group in inputs.chunks(16) {
                                gf8::mul_acc_input_batch(&mut dst[at..at + n], group);
                            }
                        }
                    });
                });
            });
            let sme = timed(budget, || {
                pool.install(|| {
                    parts
                        .par_iter()
                        .for_each_init(Vec::new, |scratch, &(at, n)| {
                            plan.apply(&views, &mut dsts.view(len), at, n, scratch);
                        });
                });
            });
            row(
                &format!("gf8 S{sources} R{rows}"),
                threads,
                sources * len,
                neon,
                sme,
            );
        }
    }

    fn gf16_shape(sources: usize, rows: usize, len: usize, workers: &[usize], budget: f64) {
        let srcs: Vec<Vec<u8>> = (0..sources).map(|s| fill(s as u64 + 1, len)).collect();
        let coef: Vec<Vec<u16>> = (0..rows)
            .map(|r| {
                (0..sources)
                    .map(|s| ((r * 0x0f1d + s * 0x1234) as u16) | 2)
                    .collect()
            })
            .collect();
        let prepared: Vec<Vec<gf_simd::PreparedInputFactor>> = coef
            .iter()
            .map(|row| {
                row.iter()
                    .map(|&c| gf_simd::prepare_input_factor(c))
                    .collect()
            })
            .collect();
        let plan = Plan::gf16(&coef);
        let mut out: Vec<Vec<u8>> = (0..rows).map(|_| vec![0u8; len]).collect();
        let dsts = Rows(out.iter_mut().map(|d| d.as_mut_ptr()).collect());
        let views: Vec<&[u8]> = srcs.iter().map(Vec::as_slice).collect();
        for &threads in workers {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap();
            let parts = ranges(len / 2, threads);
            let neon = timed(budget, || {
                pool.install(|| {
                    parts.par_iter().for_each(|&(at, n)| {
                        let (at, n) = (2 * at, 2 * n);
                        for (r, dst) in dsts.view(len).into_iter().enumerate() {
                            let inputs: Vec<gf_simd::PreparedFactorSrc<'_>> = (0..sources)
                                .map(|s| gf_simd::PreparedFactorSrc {
                                    prepared: &prepared[r][s],
                                    src: &views[s][at..at + n],
                                })
                                .collect();
                            // PAR2's input grouping.
                            for group in inputs.chunks(12) {
                                gf_simd::mul_acc_input_batch_prepared(&mut dst[at..at + n], group);
                            }
                        }
                    });
                });
            });
            let sme = timed(budget, || {
                pool.install(|| {
                    parts
                        .par_iter()
                        .for_each_init(Vec::new, |scratch, &(at, n)| {
                            plan.apply(&views, &mut dsts.view(len), at, n, scratch);
                        });
                });
            });
            row(
                &format!("gf16 S{sources} R{rows}"),
                threads,
                sources * len,
                neon,
                sme,
            );
        }
    }

    /// The kernels agree with the scalar oracle on this host before anything
    /// is timed.
    fn check() {
        let len = 3 * CHUNK * 2;
        let srcs: Vec<Vec<u8>> = (0..17).map(|s| fill(s as u64 + 99, len)).collect();
        let views: Vec<&[u8]> = srcs.iter().map(Vec::as_slice).collect();
        let coef: Vec<Vec<u8>> = (0..33)
            .map(|r| (0..17).map(|s| (r * 13 + s * 5) as u8).collect())
            .collect();
        let mut want: Vec<Vec<u8>> = (0..33).map(|r| fill(r as u64 + 7, len)).collect();
        let mut got = want.clone();
        sme2_gemm::oracle8(&coef, &views, &mut want);
        let mut rows: Vec<&mut [u8]> = got.iter_mut().map(Vec::as_mut_slice).collect();
        Plan::gf8(&coef).apply(&views, &mut rows, 0, len, &mut Vec::new());
        assert_eq!(got, want, "gf8 SME2 kernel disagrees with the oracle");
        let coef: Vec<Vec<u16>> = (0..5)
            .map(|r| (0..17).map(|s| (r * 0x3001 + s * 0x0107) as u16).collect())
            .collect();
        let mut want: Vec<Vec<u8>> = (0..5).map(|r| fill(r as u64 + 11, len)).collect();
        let mut got = want.clone();
        sme2_gemm::oracle16(&coef, &views, &mut want);
        let mut rows: Vec<&mut [u8]> = got.iter_mut().map(Vec::as_mut_slice).collect();
        Plan::gf16(&coef).apply(&views, &mut rows, 0, len / 2, &mut Vec::new());
        assert_eq!(got, want, "gf16 SME2 kernel disagrees with the oracle");
    }

    pub fn main() {
        if !sme2_gemm::sme2_available() {
            println!("\nSME2 lane: this host has no SME2");
            return;
        }
        check();
        let n = 2_000_000;
        let start = Instant::now();
        // SAFETY: SME2 is present.
        unsafe { sme2_gemm::mode_switch(n) };
        let switch = start.elapsed().as_secs_f64() / n as f64;
        let start = Instant::now();
        // SAFETY: SME2 is present.
        unsafe { sme2_gemm::bmopa_loop(n) };
        let bmopa = (8 * n) as f64 / start.elapsed().as_secs_f64();
        println!(
            "\nSME2 lane: SMSTART+SMSTOP {:.1} ns, BMOPA {:.2} G/s on one thread (4 tiles)",
            switch * 1e9,
            bmopa / 1e9
        );
        let workers: Vec<usize> = std::env::var("RS_CEILING_SME2_THREADS")
            .unwrap_or_else(|_| "1".into())
            .split(',')
            .filter_map(|v| v.trim().parse().ok())
            .collect();
        let stripe = std::env::var("RS_CEILING_SME2_STRIPE")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(64)
            << 10;
        let budget = 0.4;
        println!(
            "stripe {} KiB; GiB/s of source consumed, wall and CPU in us per product",
            stripe >> 10
        );
        println!(
            "{:<16} {:>2} | {:>7} {:>9} {:>9} | {:>7} {:>9} {:>9} | {:>5} {:>5}",
            "shape", "T", "NEON", "wall", "cpu", "SME2", "wall", "cpu", "wall×", "cpu×"
        );
        for (sources, rows) in [
            (16, 1),
            (16, 8),
            (16, 32),
            (16, 103),
            (64, 8),
            (64, 32),
            (64, 103),
        ] {
            gf8_shape(sources, rows, stripe, &workers, budget);
        }
        for (sources, rows) in [
            (12, 10),
            (12, 100),
            (16, 10),
            (16, 100),
            (100, 10),
            (100, 100),
            (500, 100),
            (2000, 100),
        ] {
            gf16_shape(sources, rows, stripe, &workers, budget);
        }
    }
}
