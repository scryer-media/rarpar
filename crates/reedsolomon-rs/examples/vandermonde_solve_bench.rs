//! Where the closed-form consecutive-exponent solve overtakes the explicit
//! inverse, and where its two transforms overtake the written-out form.
//!
//! Four solves of the same system, at one stripe width, timed separately from
//! their setup:
//!
//! - `inverse`: what a caller does today — `matrix::build_repair_matrix` for
//!   the coefficients (a Gauss-Jordan inverse, `O(m^3)` scalar work) and one
//!   `m x m` block product to apply them.
//! - `direct`: `vandermonde_solve` with both stages written out.
//! - `grouped`: stage 2 through the `255 x 257` split.
//! - `transformed`: stage 1 through blocked length-255 convolutions as well.
//!
//! The solve columns are what matters: setup is per repair, the solve is per
//! stripe of every slice. One timed run each — every configuration here moves
//! hundreds of gigabytes, which is its own averaging.
//!
//! Run with `cargo run --release --example vandermonde_solve_bench`, optionally
//! with a row count list: `... --example vandermonde_solve_bench -- 256 512`.

use reedsolomon_rs::gf;
use reedsolomon_rs::gf_simd::{self, FactorSrc};
use reedsolomon_rs::matrix;
use reedsolomon_rs::vandermonde_solve::{ConsecutiveSolvePlan, SolveStrategy};
use std::time::{Duration, Instant};

/// One stripe of every row, the width a repair would hand the solve.
const STRIPE: usize = 64 * 1024;

/// Live source streams per destination pass in the reference product, matching
/// what the solve's own folds use.
const BATCH: usize = 8;

/// Above this the reference's `O(m^3)` inverse takes longer than every other
/// measurement in the sweep put together, so only its block product is timed.
const INVERSION_LIMIT: usize = 1024;

/// xorshift64*: the data only has to be incompressible and reproducible.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
}

fn random_bytes(len: usize, rng: &mut Rng) -> Vec<u8> {
    let mut out = vec![0u8; len];
    for word in out.chunks_exact_mut(8) {
        word.copy_from_slice(&rng.next().to_le_bytes());
    }
    out
}

fn timed<T>(work: impl FnOnce() -> T) -> (T, Duration) {
    let start = Instant::now();
    let value = work();
    (value, start.elapsed())
}

/// `dst ^= sum_i coeffs[i] * sources[i]`, the same batched shape the solve
/// folds with, so the reference product is not handicapped by its loop.
fn fold(dst: &mut [u8], sources: &[&[u8]], coeffs: &[u16]) {
    let mut first = 0usize;
    while first < sources.len() {
        let width = BATCH.min(sources.len() - first);
        let batch: [FactorSrc<'_>; BATCH] = std::array::from_fn(|lane| FactorSrc {
            factor: if lane < width {
                coeffs[first + lane]
            } else {
                0
            },
            src: sources[first + lane.min(width - 1)],
        });
        gf_simd::mul_acc_input_batch(dst, &batch[..width]);
        first += width;
    }
}

/// The reference solve: every output row folds every source row once.
fn dense_product(out: &mut [u8], sources: &[u8], coefficients: &[u16], rows: usize) {
    let mut refs: Vec<&[u8]> = Vec::with_capacity(rows);
    for row in 0..rows {
        refs.push(&sources[row * STRIPE..(row + 1) * STRIPE]);
    }
    for (row, dst) in out.chunks_exact_mut(STRIPE).enumerate() {
        dst.fill(0);
        fold(dst, &refs, &coefficients[row * rows..(row + 1) * rows]);
    }
}

fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1e3
}

fn main() {
    let requested: Vec<usize> = std::env::args()
        .skip(1)
        .filter_map(|argument| argument.parse().ok())
        .collect();
    let rows_list = if requested.is_empty() {
        vec![256usize, 512, 1024, 2048, 4096, 8192]
    } else {
        requested
    };

    println!(
        "stripe {} KiB, one run per cell, times in ms",
        STRIPE / 1024
    );
    println!(
        "{:>6}  {:>10} {:>9} {:>9} {:>11}  {:>11} {:>10} {:>10} {:>11}  {:>9}",
        "m",
        "inv setup",
        "dir setup",
        "grp setup",
        "trans setup",
        "inv solve",
        "direct",
        "grouped",
        "transformed",
        "scratch"
    );

    let mut rng = Rng(0x0123_4567_89ab_cdef);
    for rows in rows_list {
        let constants = gf::input_slice_constants(rows);
        let logs: Vec<u16> = constants.iter().map(|&c| gf::log(c)).collect();

        // Setup, per repair. The reference builds and inverts an m x m matrix;
        // the plans build O(m) tables out of O(m^2) scalar multiplies.
        let inverse_setup = (rows <= INVERSION_LIMIT).then(|| {
            let missing: Vec<usize> = (0..rows).collect();
            let exponents: Vec<u32> = (0..rows as u32).collect();
            timed(|| matrix::build_repair_matrix(&[], &missing, &exponents, &constants).unwrap()).1
        });
        let (direct, direct_setup) = timed(|| {
            ConsecutiveSolvePlan::build_with_strategy(&logs, 0, SolveStrategy::Direct).unwrap()
        });
        let (grouped, grouped_setup) = timed(|| {
            ConsecutiveSolvePlan::build_with_strategy(&logs, 0, SolveStrategy::GroupedEvaluation)
                .unwrap()
        });
        let (transformed, transformed_setup) = timed(|| {
            ConsecutiveSolvePlan::build_with_strategy(&logs, 0, SolveStrategy::Transformed).unwrap()
        });

        // The reference product's cost does not depend on which coefficients it
        // applies, only on how many, so a random dense matrix times it exactly.
        let coefficients: Vec<u16> = (0..rows * rows).map(|_| (rng.next() as u16) | 1).collect();
        let sources = random_bytes(rows * STRIPE, &mut rng);
        let mut out = vec![0u8; rows * STRIPE];
        let inverse_solve = timed(|| dense_product(&mut out, &sources, &coefficients, rows)).1;
        drop(coefficients);
        drop(out);

        let mut scratch = vec![0u8; transformed.scratch_bytes(STRIPE)];
        let mut rows_buffer = vec![0u8; rows * STRIPE];
        let mut solve = |plan: &ConsecutiveSolvePlan| {
            rows_buffer.copy_from_slice(&sources);
            timed(|| {
                plan.solve_stripe(&mut rows_buffer, STRIPE, &mut scratch, &|| false)
                    .unwrap()
            })
            .1
        };
        let direct_solve = solve(&direct);
        let grouped_solve = solve(&grouped);
        let transformed_solve = solve(&transformed);

        println!(
            "{rows:>6}  {:>10} {:>9.1} {:>9.1} {:>11.1}  {:>11.1} {:>10.1} {:>10.1} {:>11.1}  {:>8} M",
            inverse_setup.map_or("-".to_string(), |d| format!("{:.1}", millis(d))),
            millis(direct_setup),
            millis(grouped_setup),
            millis(transformed_setup),
            millis(inverse_solve),
            millis(direct_solve),
            millis(grouped_solve),
            millis(transformed_solve),
            transformed.scratch_bytes(STRIPE) >> 20,
        );
    }
}
