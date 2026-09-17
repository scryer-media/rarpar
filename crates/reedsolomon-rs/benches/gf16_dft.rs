//! Dense PAR2 recovery folds vs the output-pruned GF(2^16) DFT.
//!
//! Both arms compute the same rows — `R_e = sum_i D_i * 2^(L_i*e)` for a
//! contiguous exponent range — through the same [`mul_acc_input_batch`] kernel,
//! so the only difference measured is the *schedule*: how many region folds the
//! arm performs and in what batch shapes.
//!
//! This is not a criterion bench. A single ceiling-shape iteration moves
//! hundreds of gigabytes and runs for seconds, which criterion's ten-sample
//! floor cannot express, and the dense arm at the ceiling would run for a
//! quarter of an hour. Instead each arm is timed directly, and the dense arm is
//! *extrapolated* from a measured fold rate at the same slice count whenever a
//! direct run would be absurd — marked `~` in the table. Dense is a perfectly
//! uniform loop, so its per-fold cost does not depend on the output count;
//! shapes where both a direct and an extrapolated number are cheap enough to
//! take agree to a few percent.
//!
//! Parallelism is across stripes, one rayon worker per stripe, which is how a
//! caller would drive this: each worker owns its slices, its output rows and
//! its scratch, and the arms share nothing.
//!
//! Reported throughput is *slice bytes consumed per second* — `n * stripe` per
//! transformed stripe — which is the rate a PAR2 create pass would see.
//!
//! One asymmetry worth naming: the transform performs some folds whose
//! coefficient is 1 (every zero output coordinate), and the kernels take a
//! plain-XOR path for those. Dense factors are almost never 1. That advantage
//! is real rather than an artifact — it is part of what the factorisation buys.
//!
//! Run: `cargo bench -p reedsolomon-rs --bench gf16_dft`
//! Knobs: `RS_DFT_THREADS` (default: 6), `RS_DFT_STRIPE` (default: 65536).

#[cfg(not(target_family = "wasm"))]
fn main() {
    imp::main();
}

#[cfg(target_family = "wasm")]
fn main() {}

#[cfg(not(target_family = "wasm"))]
mod imp {
    use std::time::{Duration, Instant};

    use rayon::prelude::*;
    use reedsolomon_rs::gf;
    use reedsolomon_rs::gf_simd::{FactorSrc, mul_acc_input_batch};
    use reedsolomon_rs::gf16_dft::{DftPlan, DftScratch, MAX_BUCKET_BATCH};

    /// Sources folded into one destination per dense kernel call.
    const DENSE_BATCH: usize = 16;
    /// Above this, a direct dense run is replaced by an extrapolation.
    const DENSE_FOLD_CAP: u64 = 5_000_000;

    fn env_usize(name: &str, fallback: usize) -> usize {
        std::env::var(name)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(fallback)
    }

    /// The PAR2 input-slice exponents: positive integers coprime to 65535.
    fn par2_slots(count: usize) -> Vec<u16> {
        let mut slots = Vec::with_capacity(count);
        let mut exponent = 1u32;
        while slots.len() < count {
            if !(exponent.is_multiple_of(3)
                || exponent.is_multiple_of(5)
                || exponent.is_multiple_of(17)
                || exponent.is_multiple_of(257))
            {
                slots.push(exponent as u16);
            }
            exponent += 1;
        }
        slots
    }

    /// One worker's stripe: every slice flat, plus its own output rows.
    struct Lane {
        sources: Vec<u8>,
        outputs: Vec<u8>,
    }

    impl Lane {
        fn new(seed: u64, sources: usize, outputs: usize, stripe: usize) -> Self {
            let mut bytes = vec![0u8; sources * stripe];
            // Cheap, non-constant fill: the kernels are data-oblivious, and a
            // xorshift over gigabytes would dominate the setup.
            let mut state = seed | 1;
            for word in bytes.chunks_mut(8) {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                word.copy_from_slice(&state.to_le_bytes()[..word.len()]);
            }
            Self {
                sources: bytes,
                outputs: vec![0u8; outputs * stripe],
            }
        }
    }

    /// The dense definition, driven through the same kernel as the transform.
    fn dense_stripe(slots: &[u16], first: u32, lane: &mut Lane, stripe: usize) {
        let sources: Vec<&[u8]> = lane.sources.chunks(stripe).collect();
        for (at, dst) in lane.outputs.chunks_mut(stripe).enumerate() {
            let exponent = first + at as u32;
            dst.fill(0);
            let mut batch: [FactorSrc<'_>; DENSE_BATCH] = std::array::from_fn(|_| FactorSrc {
                factor: 0,
                src: &[],
            });
            for chunk in (0..sources.len()).step_by(DENSE_BATCH) {
                let upto = (chunk + DENSE_BATCH).min(sources.len());
                for (slot, source) in (chunk..upto).enumerate() {
                    batch[slot] = FactorSrc {
                        factor: gf::pow_from_log(slots[source], exponent),
                        src: sources[source],
                    };
                }
                mul_acc_input_batch(dst, &batch[..upto - chunk]);
            }
        }
    }

    /// Wall time for one parallel pass, one stripe per lane.
    fn time_transform(plan: &DftPlan, lanes: &mut [Lane], stripe: usize) -> Duration {
        let started = Instant::now();
        lanes.par_iter_mut().for_each(|lane| {
            let views: Vec<&[u8]> = lane.sources.chunks(stripe).collect();
            let mut scratch = DftScratch::new(plan, stripe);
            plan.transform_stripe(&views, &mut lane.outputs, &mut scratch, &|| false)
                .unwrap();
        });
        started.elapsed()
    }

    fn time_dense(slots: &[u16], first: u32, lanes: &mut [Lane], stripe: usize) -> Duration {
        let started = Instant::now();
        lanes
            .par_iter_mut()
            .for_each(|lane| dense_stripe(slots, first, lane, stripe));
        started.elapsed()
    }

    /// Slice bytes consumed per second across every lane.
    fn gbps(sources: usize, stripe: usize, lanes: usize, elapsed: Duration) -> f64 {
        (sources as f64 * stripe as f64 * lanes as f64) / elapsed.as_secs_f64() / 1e9
    }

    pub fn main() {
        let stripe = env_usize("RS_DFT_STRIPE", 64 * 1024);
        let threads = env_usize("RS_DFT_THREADS", 6).max(1);
        assert!(stripe.is_multiple_of(2), "stripe must be even");

        println!("gf16_dft: dense folds vs output-pruned DFT");
        println!("stripe {stripe} B, {threads} lanes (one stripe each), aarch64/NEON\n");

        let shapes = [
            (2000usize, 200u32),
            (14000, 256),
            (14000, 2098),
            (14000, 4096),
            (32768, 6553),
        ];

        println!(
            "{:>6} {:>6} {:>13} {:>13} {:>7} {:>10} {:>10} {:>7} {:>9} {:>8}",
            "n",
            "r",
            "dense folds",
            "dft folds",
            "fold x",
            "dense GB/s",
            "dft GB/s",
            "time x",
            "scratch",
            "plan"
        );

        for (sources, outputs) in shapes {
            let slots = par2_slots(sources);
            let plan = DftPlan::build(&slots, 0..outputs).unwrap();
            let mut lanes: Vec<Lane> = (0..threads)
                .map(|at| Lane::new(at as u64 + 1, sources, outputs as usize, stripe))
                .collect();

            // Warm the pages and the kernel dispatch caches once.
            time_transform(&plan, &mut lanes, stripe);
            let dft = time_transform(&plan, &mut lanes, stripe);

            let dense_folds = plan.dense_region_folds();
            let (dense, estimated) = if dense_folds <= DENSE_FOLD_CAP {
                (time_dense(&slots, 0, &mut lanes, stripe), false)
            } else {
                // Calibrate the dense fold rate at the same slice count with an
                // output count that keeps the run short, then scale.
                let probe = (DENSE_FOLD_CAP / sources as u64).max(1) as u32;
                let mut probe_lanes: Vec<Lane> = (0..threads)
                    .map(|at| Lane::new(at as u64 + 1, sources, probe as usize, stripe))
                    .collect();
                time_dense(&slots, 0, &mut probe_lanes, stripe);
                let measured = time_dense(&slots, 0, &mut probe_lanes, stripe);
                let per_fold = measured.as_secs_f64() / (sources as f64 * probe as f64);
                (Duration::from_secs_f64(per_fold * dense_folds as f64), true)
            };

            println!(
                "{:>6} {:>6} {:>13} {:>13} {:>6.1}x {:>9.2}{} {:>10.2} {:>6.1}x {:>8.1}M {:>7.2}M",
                sources,
                outputs,
                dense_folds,
                plan.region_folds(),
                dense_folds as f64 / plan.region_folds() as f64,
                gbps(sources, stripe, threads, dense),
                if estimated { "~" } else { " " },
                gbps(sources, stripe, threads, dft),
                dense.as_secs_f64() / dft.as_secs_f64(),
                plan.scratch_bytes(stripe) as f64 / 1e6,
                plan.plan_bytes() as f64 / 1e6,
            );
        }

        bucket_batch_sweep(stripe, threads);
        fold_crossover();
    }

    /// What holding more 257-buckets in flight buys, and what it costs.
    fn bucket_batch_sweep(stripe: usize, threads: usize) {
        let (sources, outputs) = (14000usize, 2098u32);
        println!("\nbucket batch sweep (n={sources}, r={outputs})");
        println!("{:>6} {:>10} {:>9}", "batch", "dft GB/s", "scratch");
        let slots = par2_slots(sources);
        let mut lanes: Vec<Lane> = (0..threads)
            .map(|at| Lane::new(at as u64 + 1, sources, outputs as usize, stripe))
            .collect();
        for batch in 1..=MAX_BUCKET_BATCH {
            let plan = DftPlan::build_tuned(&slots, 0..outputs, batch).unwrap();
            time_transform(&plan, &mut lanes, stripe);
            let elapsed = time_transform(&plan, &mut lanes, stripe);
            println!(
                "{:>6} {:>10.2} {:>8.1}M",
                batch,
                gbps(sources, stripe, threads, elapsed),
                plan.scratch_bytes(stripe) as f64 / 1e6
            );
        }
    }

    /// The exact fold-count crossover: the first output count at which the
    /// schedule performs fewer folds than the dense product. Planning is cheap,
    /// so this is a scan rather than a measurement.
    fn fold_crossover() {
        println!("\nfold-count crossover (first r where the transform folds less)");
        println!("{:>7} {:>10} {:>12}", "n", "r*", "ratio at r*");
        for sources in [100usize, 500, 2000, 8000, 14000, 32768] {
            let slots = par2_slots(sources);
            let mut found = None;
            for outputs in 1u32..=512 {
                let plan = DftPlan::build(&slots, 0..outputs).unwrap();
                if plan.region_folds() < plan.dense_region_folds() {
                    found = Some((outputs, plan.dense_region_folds(), plan.region_folds()));
                    break;
                }
            }
            match found {
                Some((outputs, dense, dft)) => println!(
                    "{sources:>7} {outputs:>10} {:>11.2}x",
                    dense as f64 / dft as f64
                ),
                None => println!("{sources:>7} {:>10} {:>12}", ">512", "-"),
            }
        }
    }
}
