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
//! Run: `cargo bench -p reedsolomon-rs --bench kernel_ceiling`
//! Knob: `RS_CEILING_MS` (per-repetition floor in milliseconds, default: 60).

#[cfg(not(target_family = "wasm"))]
fn main() {
    imp::main();
}

#[cfg(target_family = "wasm")]
fn main() {}

#[cfg(not(target_family = "wasm"))]
mod imp {
    use std::hint::black_box;
    use std::time::{Duration, Instant};

    use reedsolomon_rs::gf_simd::{
        self, FactorDst, FactorSrc, LinearBackend, PreparedFactorSrc, mul_acc_input_batch,
        mul_acc_input_batch_prepared, mul_acc_multi_region, prepare_input_factor,
    };
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
                ("sve2", std::arch::is_aarch64_feature_detected!("sve2")),
            ] {
                notes.push(format!("{name} {present}"));
            }
            // `WEAVER_SVE2=0` pins NEON on an SVE2 host.
            notes.push(format!(
                "sve2 kernels {}",
                reedsolomon_rs::gf_simd::uses_sve2()
            ));
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
        ];
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
