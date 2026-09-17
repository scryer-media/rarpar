//! Differential coverage for the closed-form consecutive-exponent solve.
//!
//! Every case builds a real PAR2-shaped system — random input slices, densely
//! encoded recovery slices, a random erasure pattern — and checks the solve
//! against two independent references: the original bytes, and the coefficient
//! matrix `matrix::build_repair_matrix` produces from the same selection. The
//! second reference is what keeps the closed form honest against the
//! Gauss-Jordan path callers fall back to.

use reedsolomon_rs::gf;
use reedsolomon_rs::gf_simd;
use reedsolomon_rs::matrix;
use reedsolomon_rs::vandermonde_solve::{ConsecutiveSolvePlan, SolveError, SolveStrategy};

/// xorshift64*, so a failing case is reproducible from its seed alone.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next_u64() % bound as u64) as usize
    }
}

/// One erasure scenario: `missing` unknowns out of `missing + spare` inputs,
/// recovery exponents `first_exponent ..`, slices of `stripe_len` bytes.
struct Scenario {
    constants: Vec<u16>,
    missing: Vec<usize>,
    available: Vec<usize>,
    exponents: Vec<u32>,
    originals: Vec<Vec<u8>>,
    recovery: Vec<Vec<u8>>,
    stripe_len: usize,
}

impl Scenario {
    fn build(
        missing: usize,
        spare: usize,
        first_exponent: u32,
        stripe_len: usize,
        seed: u64,
    ) -> Self {
        assert!(stripe_len.is_multiple_of(2));
        let mut rng = Rng(seed);
        let total = missing + spare;
        let constants = gf::input_slice_constants(total);

        let originals: Vec<Vec<u8>> = (0..total)
            .map(|_| {
                let mut slice = vec![0u8; stripe_len];
                for word in slice.chunks_exact_mut(2) {
                    word.copy_from_slice(&(rng.next_u64() as u16).to_le_bytes());
                }
                slice
            })
            .collect();

        let exponents: Vec<u32> = (0..missing as u32).map(|r| first_exponent + r).collect();
        let recovery: Vec<Vec<u8>> = exponents
            .iter()
            .map(|&exponent| {
                let mut block = vec![0u8; stripe_len];
                for (input, slice) in originals.iter().enumerate() {
                    gf_simd::mul_acc_region(gf::pow(constants[input], exponent), slice, &mut block);
                }
                block
            })
            .collect();

        // Pick the erasure pattern by partial Fisher-Yates over the input list.
        let mut order: Vec<usize> = (0..total).collect();
        for at in 0..missing {
            let pick = at + rng.below(total - at);
            order.swap(at, pick);
        }
        let mut missing_indices = order[..missing].to_vec();
        missing_indices.sort_unstable();
        let mut available: Vec<usize> = (0..total)
            .filter(|i| missing_indices.binary_search(i).is_err())
            .collect();
        available.sort_unstable();

        Self {
            constants,
            missing: missing_indices,
            available,
            exponents,
            originals,
            recovery,
            stripe_len,
        }
    }

    /// Recovery rows with every surviving input's contribution removed: the
    /// syndromes the solve consumes.
    fn syndromes(&self) -> Vec<u8> {
        let mut rows = vec![0u8; self.exponents.len() * self.stripe_len];
        for (r, row) in rows.chunks_exact_mut(self.stripe_len).enumerate() {
            row.copy_from_slice(&self.recovery[r]);
            for &input in &self.available {
                gf_simd::mul_acc_region(
                    gf::pow(self.constants[input], self.exponents[r]),
                    &self.originals[input],
                    row,
                );
            }
        }
        rows
    }

    /// The discrete logs of the missing inputs' constants, in the row order the
    /// solve reports its answers in.
    fn missing_logs(&self) -> Vec<u16> {
        self.missing
            .iter()
            .map(|&i| gf::log(self.constants[i]))
            .collect()
    }

    /// Reconstruct through `matrix::build_repair_matrix`: the Gauss-Jordan
    /// reference the closed form has to agree with bit for bit.
    fn matrix_reference(&self) -> Vec<Vec<u8>> {
        let coefficients = matrix::build_repair_matrix(
            &self.available,
            &self.missing,
            &self.exponents,
            &self.constants,
        )
        .expect("consecutive exponents are never singular here");
        let mut sources: Vec<&[u8]> = self
            .available
            .iter()
            .map(|&i| self.originals[i].as_slice())
            .collect();
        for block in &self.recovery {
            sources.push(block.as_slice());
        }
        (0..self.missing.len())
            .map(|row| {
                let mut out = vec![0u8; self.stripe_len];
                for (column, source) in sources.iter().enumerate() {
                    gf_simd::mul_acc_region(coefficients.get(row, column), source, &mut out);
                }
                out
            })
            .collect()
    }
}

/// Solve one scenario with one strategy and check it against both references.
fn check(scenario: &Scenario, strategy: SolveStrategy, against_matrix: bool) {
    let logs = scenario.missing_logs();
    let plan = ConsecutiveSolvePlan::build_with_strategy(&logs, scenario.exponents[0], strategy)
        .expect("distinct PAR2 constants");
    assert_eq!(plan.rows(), scenario.missing.len());

    let mut rows = scenario.syndromes();
    let mut scratch = vec![0xa5u8; plan.scratch_bytes(scenario.stripe_len)];
    plan.solve_stripe(&mut rows, scenario.stripe_len, &mut scratch, &|| false)
        .expect("a well-formed solve");

    let reference = against_matrix.then(|| scenario.matrix_reference());
    for (row, solved) in rows.chunks_exact(scenario.stripe_len).enumerate() {
        let input = scenario.missing[row];
        assert_eq!(
            solved,
            scenario.originals[input].as_slice(),
            "{strategy:?}: input {input} (row {row}) not recovered"
        );
        if let Some(reference) = &reference {
            assert_eq!(
                solved, reference[row],
                "{strategy:?}: input {input} differs from the Gauss-Jordan result"
            );
        }
    }
}

/// Run one shape through every pinned form of the two stages.
fn every_strategy(missing: usize, first_exponent: u32, stripe_len: usize, against_matrix: bool) {
    let seed = 0x5eed_0000 ^ (missing as u64) << 8 ^ first_exponent as u64;
    let scenario = Scenario::build(missing, 5, first_exponent, stripe_len, seed);
    for strategy in [
        SolveStrategy::Direct,
        SolveStrategy::GroupedEvaluation,
        SolveStrategy::Transformed,
    ] {
        check(&scenario, strategy, against_matrix);
    }
}

#[test]
fn matches_gauss_jordan_across_row_counts_and_first_exponents() {
    // 127/128/129 and 255/256/257 straddle the batch width and the two coprime
    // factors of the group order, where the grouped evaluation's bucket count
    // meets the row count.
    for missing in [1usize, 2, 3, 127, 128, 129, 255, 256, 257] {
        for first_exponent in [0u32, 1, 5000] {
            every_strategy(missing, first_exponent, 64, true);
        }
    }
}

#[test]
fn handles_odd_stripe_tails() {
    // 2 bytes is one word; 66 and 126 leave tails the SIMD kernels finish with
    // their scalar epilogue.
    for stripe_len in [2usize, 66, 126, 1022] {
        every_strategy(37, 3, stripe_len, true);
    }
}

#[test]
fn solves_a_slice_one_stripe_at_a_time() {
    // The whole point of the stripe-wise shape: a long slice is solved in
    // pieces with one plan and one scratch buffer, and the pieces agree with a
    // single-shot solve of the same data.
    let missing = 40usize;
    let stripe_len = 128usize;
    let stripes = 5usize;
    let scenario = Scenario::build(missing, 3, 11, stripe_len * stripes, 0x1234_5678);
    let logs = scenario.missing_logs();
    let plan = ConsecutiveSolvePlan::build(&logs, scenario.exponents[0]).unwrap();

    let wide = scenario.syndromes();
    let mut scratch = vec![0u8; plan.scratch_bytes(stripe_len)];
    for stripe in 0..stripes {
        // Gather this stripe of every syndrome row into a compact buffer, the
        // way a caller reading slices in windows would.
        let mut rows = vec![0u8; missing * stripe_len];
        for row in 0..missing {
            let at = row * stripe_len * stripes + stripe * stripe_len;
            rows[row * stripe_len..(row + 1) * stripe_len]
                .copy_from_slice(&wide[at..at + stripe_len]);
        }
        plan.solve_stripe(&mut rows, stripe_len, &mut scratch, &|| false)
            .unwrap();
        for row in 0..missing {
            let original = &scenario.originals[scenario.missing[row]];
            assert_eq!(
                &rows[row * stripe_len..(row + 1) * stripe_len],
                &original[stripe * stripe_len..(stripe + 1) * stripe_len],
                "stripe {stripe} of row {row}"
            );
        }
    }
}

#[test]
fn auto_and_pinned_strategies_agree() {
    // `Auto` is only a policy switch: whichever form it picks must produce the
    // same bytes as both pinned forms.
    let scenario = Scenario::build(300, 4, 9, 64, 0xfeed_face);
    let logs = scenario.missing_logs();
    let mut results = Vec::new();
    for strategy in [
        SolveStrategy::Auto,
        SolveStrategy::Direct,
        SolveStrategy::GroupedEvaluation,
        SolveStrategy::Transformed,
    ] {
        let plan = ConsecutiveSolvePlan::build_with_strategy(&logs, 9, strategy).unwrap();
        let mut rows = scenario.syndromes();
        let mut scratch = vec![0u8; plan.scratch_bytes(scenario.stripe_len)];
        plan.solve_stripe(&mut rows, scenario.stripe_len, &mut scratch, &|| false)
            .unwrap();
        results.push(rows);
    }
    assert_eq!(results[0], results[1]);
    assert_eq!(results[0], results[2]);
}

#[test]
fn non_consecutive_selections_are_rejected() {
    let scenario = Scenario::build(6, 4, 2, 32, 0x0bad_0bad);
    let logs = scenario.missing_logs();
    let mut exponents = scenario.exponents.clone();
    exponents[3] += 7;
    assert_eq!(
        ConsecutiveSolvePlan::build_for_exponents(&logs, &exponents).unwrap_err(),
        SolveError::NonConsecutive
    );
    assert!(ConsecutiveSolvePlan::build_for_exponents(&logs, &scenario.exponents).is_ok());
}

/// The large shapes. `m = 1000` alone costs a 1000x1000 Gauss-Jordan inverse in
/// the reference, which is minutes of debug-build scalar work, so both the
/// large row counts and the matrix cross-check live behind `--ignored`.
#[test]
#[ignore = "slow: large row counts and an O(m^3) reference inverse"]
fn matches_gauss_jordan_at_large_row_counts() {
    for missing in [255usize, 256, 257, 1000] {
        for first_exponent in [0u32, 5000] {
            every_strategy(missing, first_exponent, 64, true);
        }
    }
}
