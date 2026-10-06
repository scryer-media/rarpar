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

fn main() {
    imp::main();
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
