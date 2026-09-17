//! Closed-form GF(2^16) erasure solve for consecutive PAR2 recovery exponents.
//!
//! A PAR2 repair is a linear system. With `m` input slices missing, the caller
//! holds `m` recovery slices; subtracting the contribution of every surviving
//! input from each of them leaves a *syndrome* row per recovery slice, and the
//! remaining system is square. The usual way to finish is to build the `m x m`
//! Vandermonde submatrix, invert it by Gauss-Jordan, and multiply the syndromes
//! through the inverse: `O(m^3)` scalar work to build the coefficients and
//! `O(m^2)` block folds to apply them ([`crate::matrix`] does exactly that).
//!
//! When the recovery exponents are *consecutive* the inverse has a closed form
//! and the cubic elimination disappears. This module implements it. The block
//! work stays `O(m^2)` folds in the baseline form — the same order the explicit
//! inverse needs to be applied — but nothing here ever builds or stores an
//! `m x m` matrix, and the scalar setup drops to `O(m^2)` table lookups.
//!
//! # The system
//!
//! Missing input `c` carries the PAR2 constant `g_c = 2^(k_c)`, all distinct.
//! For consecutive exponents `e0 .. e0 + m - 1` the syndromes are
//!
//! ```text
//! S_r = sum over c of  x_c * g_c^(e0 + r),        r = 0 .. m-1
//! ```
//!
//! where `x_c` is the missing slice we want. Computing `S` is the caller's job;
//! this module consumes it. Folding the leading power into the unknown,
//! `y_c = g_c^(e0) * x_c`, turns the system into a plain power sum
//! `S_r = sum_c y_c * g_c^r`.
//!
//! # The closed form
//!
//! Let `P(z) = product over c of (z + g_c) = sum_j p[j] z^j` (degree `m`,
//! monic), and `Q_c(z) = P(z) / (z + g_c)`. `Q_c` vanishes at every other
//! constant, so weighting the syndromes by its coefficients isolates one
//! unknown:
//!
//! ```text
//! sum_r Q_c[r] * S_r = y_c * Q_c(g_c) = y_c * P'(g_c)
//! ```
//!
//! — the erasure-value step of Forney's algorithm, with `P` in the role of the
//! erasure locator. In characteristic 2 the formal derivative keeps only the
//! odd-degree terms, `P'(z) = sum over odd j of p[j] z^(j-1)`, and it is never
//! zero at a root of `P` because the constants are distinct.
//!
//! Synthetic division gives `Q_c` without dividing anything:
//! `Q_c[r] = sum over j >= r of p[j+1] * g_c^(j-r)`. Substituting `t = j - r`
//! and exchanging the two sums separates the syndromes from the constants:
//!
//! ```text
//! T_t = sum_r S_r * p[r + t + 1]                       (stage 1)
//! x_c = g_c^(-e0) / P'(g_c) * sum_t T_t * g_c^t        (stage 2)
//! ```
//!
//! `p[j] = 0` for `j > m`, so stage 1 is triangular: row `t` folds `m - t`
//! syndromes. Stage 1 is a correlation of the block sequence `S` with the
//! scalar sequence `p`; stage 2 evaluates the block polynomial `T` at each
//! constant. Neither stage needs the inverse matrix, and both are ordinary
//! multiply-accumulate passes over a stripe, so they run on the crate's SIMD
//! region kernels.
//!
//! # Fast stage 2
//!
//! Stage 2 evaluates `m` points of an `m`-term polynomial: `m^2` folds written
//! out. Because every constant is a power of two, the exponent arithmetic
//! happens in `Z/65535`, and `65535 = 255 * 257` with the two factors coprime.
//! Pick `alpha = 2^257` (order 255) and `beta = 2^255` (order 257); then
//!
//! ```text
//! g_c^t = 2^(k_c * t) = alpha^u * beta^v,
//!     u = 128 * (k_c mod 255) * (t mod 255)  mod 255,
//!     v = 128 * (k_c mod 257) * (t mod 257)  mod 257
//! ```
//!
//! (128 is the inverse of 257 modulo 255 and of 255 modulo 257 alike). The
//! `alpha` half depends on `k_c` only through `k_c mod 255`, so all unknowns
//! sharing that residue share one intermediate: fold each `T_t` once into
//! bucket `t mod 257`, and the 257 buckets that come out serve every unknown in
//! the group with a single 257-source fold each. A PAR2 constant's exponent is
//! coprime to 65535, so at most `phi(255) = 128` distinct residues exist and the
//! whole stage costs `(groups + 257) * m` folds instead of `m^2`. It wins once
//! `m` is comfortably past 257 and loses below that, which is what
//! [`SolveStrategy::Auto`] arbitrates.
//!
//! # Shape
//!
//! The solve is stripe-wise and in place: the caller holds one `m x stripe`
//! syndrome buffer whose rows are overwritten with the answers, plus a scratch
//! buffer sized by [`ConsecutiveSolvePlan::scratch_bytes`]. Nothing is
//! allocated inside [`ConsecutiveSolvePlan::solve_stripe`], and the working set
//! never scales with the full slice length.
//!
//! Non-consecutive exponent selections are out of scope: build rejects them so
//! the caller can fall back to [`crate::matrix`].

use crate::gf;
use crate::gf_simd::{self, FactorSrc};

/// Order of the GF(2^16) multiplicative group, `65535 = 3 * 5 * 17 * 257`.
const ORDER: u32 = 65535;

/// The small coprime factor of [`ORDER`]: `255 = 3 * 5 * 17`.
const SMALL: u32 = 255;

/// The large coprime factor of [`ORDER`].
const LARGE: u32 = 257;

/// Inverse of 257 modulo 255, and of 255 modulo 257: both are 128.
///
/// `257 = 2 (mod 255)` and `2 * 128 = 256 = 1 (mod 255)`; `255 = -2 (mod 257)`
/// and `-2 * 128 = -256 = 1 (mod 257)`.
const CRT_INVERSE: u32 = 128;

/// Live source streams per destination pass. The grouped-input kernels read
/// their destination once per batch and stream the sources past it, so a batch
/// wants to be as wide as the line-fill buffers of the smallest supported core
/// allow — the same bound `gf_simd`'s own source blocking uses.
const BATCH_SOURCES: usize = 8;

/// Row count at or above which [`SolveStrategy::Auto`] selects the grouped
/// stage-2 evaluation. Below it the 257 buckets cost more than they save.
///
/// Measured on this crate's `vandermonde_solve` bench; the two forms cross
/// between 512 and 1024 rows on Apple Silicon and the shape of the estimate
/// (`groups + 257` folds per row against `m`) puts the crossover in the same
/// place on any host, because both forms are bound by passes over memory.
const FAST_MIN_ROWS: usize = 768;

/// A solve plan rejected its inputs, its buffers, or observed cancellation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SolveError {
    /// The recovery exponents are not `e0, e0+1, ... e0+m-1`. Only consecutive
    /// selections have the closed form; solve these with [`crate::matrix`].
    NonConsecutive,
    /// Two missing inputs share a constant, an exponent is out of range, or the
    /// set is larger than the field can index.
    Constants,
    /// Row count, stripe length, or scratch size disagrees with the plan.
    Geometry,
    /// Cooperative cancellation was requested.
    Cancelled,
}

impl std::fmt::Display for SolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NonConsecutive => "recovery exponents are not consecutive",
            Self::Constants => "invalid or repeated missing-input constants",
            Self::Geometry => "invalid solve geometry",
            Self::Cancelled => "solve cancelled",
        })
    }
}
impl std::error::Error for SolveError {}

/// Which stage-2 evaluation a plan carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SolveStrategy {
    /// Evaluate the block polynomial at each constant directly: `m^2` folds,
    /// no extra scratch beyond the stage-1 rows.
    Baseline,
    /// Group the constants by their exponent residue modulo 255 and share 257
    /// bucket rows per group. Cheaper for large `m`, 257 extra scratch rows.
    Grouped,
    /// [`Self::Grouped`] from [`FAST_MIN_ROWS`] rows up, [`Self::Baseline`]
    /// below it.
    Auto,
}

/// One residue class of `128 * k_c mod 255`, and the unknowns that share it.
#[derive(Debug)]
struct EvalGroup {
    /// `128 * (k_c mod 255) mod 255`, shared by every member.
    small: u32,
    /// `(row, 128 * (k_c mod 257) mod 257)` for each unknown in the class.
    members: Vec<(u32, u32)>,
}

/// Tables for the grouped stage-2 evaluation.
#[derive(Debug)]
struct GroupedEval {
    /// `alpha^i` for `i` in `0..255`, `alpha = 2^257` of order 255.
    alpha: Vec<u16>,
    /// `beta^j` for `j` in `0..257`, `beta = 2^255` of order 257.
    beta: Vec<u16>,
    /// The residue classes, in no particular order.
    groups: Vec<EvalGroup>,
}

/// A prepared solve for one set of missing inputs and one consecutive exponent
/// run. Build it once per repair; reuse it for every stripe.
#[derive(Debug)]
pub struct ConsecutiveSolvePlan {
    /// Number of unknowns, and of syndrome rows.
    rows: usize,
    /// Coefficients of `P(z) = product (z + g_c)`, `p[0 ..= rows]`, monic.
    locator: Vec<u16>,
    /// `g_c^(-e0) / P'(g_c)`, one per unknown: the whole scalar tail of the
    /// Forney value, folded into stage 2's factors.
    scale: Vec<u16>,
    /// `g_c` per unknown, for the baseline stage-2 power ladder.
    constants: Vec<u16>,
    /// Present when the plan evaluates stage 2 by residue groups.
    grouped: Option<GroupedEval>,
}

impl ConsecutiveSolvePlan {
    /// Prepare a solve for the inputs whose PAR2 constants are `2^(k_c)`, given
    /// the first of `missing_logs.len()` consecutive recovery exponents.
    ///
    /// `missing_logs` holds the `k_c` — the exponents of the constants, not the
    /// constants themselves, because that is what a PAR2 caller already has
    /// from its constant assignment. They must be distinct and below 65535.
    /// Stage-2 evaluation is chosen by [`SolveStrategy::Auto`].
    pub fn build(missing_logs: &[u16], first_exponent: u32) -> Result<Self, SolveError> {
        Self::build_with_strategy(missing_logs, first_exponent, SolveStrategy::Auto)
    }

    /// [`Self::build`] with the stage-2 evaluation pinned. Benchmarks and
    /// differential tests pin it; production callers want `Auto`.
    pub fn build_with_strategy(
        missing_logs: &[u16],
        first_exponent: u32,
        strategy: SolveStrategy,
    ) -> Result<Self, SolveError> {
        let rows = missing_logs.len();
        if rows > ORDER as usize {
            return Err(SolveError::Constants);
        }

        // Distinctness is what makes P squarefree, and a squarefree P is what
        // makes P'(g_c) nonzero. Check it against a bitmap of the exponents
        // rather than pairwise: the sets reach tens of thousands of rows.
        let mut seen = vec![false; ORDER as usize];
        let mut constants = Vec::with_capacity(rows);
        for &log in missing_logs {
            let log = log as u32;
            if log >= ORDER {
                return Err(SolveError::Constants);
            }
            if std::mem::replace(&mut seen[log as usize], true) {
                return Err(SolveError::Constants);
            }
            constants.push(gf::pow_from_log(1, log));
        }
        drop(seen);

        let locator = locator_polynomial(&constants);
        let mut scale = Vec::with_capacity(rows);
        for &g in &constants {
            let derivative = evaluate_derivative(&locator, g);
            debug_assert_ne!(derivative, 0, "distinct roots keep P' nonzero");
            // g^(-e0) / P'(g): one inverse each, both operands nonzero.
            scale.push(gf::mul(
                gf::inv(derivative),
                gf::inv(gf::pow(g, first_exponent)),
            ));
        }

        let grouped = match strategy {
            SolveStrategy::Baseline => None,
            SolveStrategy::Grouped => Some(GroupedEval::build(missing_logs)),
            SolveStrategy::Auto if rows >= FAST_MIN_ROWS => Some(GroupedEval::build(missing_logs)),
            SolveStrategy::Auto => None,
        };

        Ok(Self {
            rows,
            locator,
            scale,
            constants,
            grouped,
        })
    }

    /// [`Self::build`] for callers holding an explicit exponent list.
    ///
    /// Returns [`SolveError::NonConsecutive`] unless the list is
    /// `e0, e0+1, ..., e0+m-1`, which is the signal to fall back to the
    /// Gauss-Jordan path in [`crate::matrix`].
    pub fn build_for_exponents(
        missing_logs: &[u16],
        exponents: &[u32],
    ) -> Result<Self, SolveError> {
        if exponents.len() != missing_logs.len() {
            return Err(SolveError::Geometry);
        }
        let Some(&first) = exponents.first() else {
            return Self::build(missing_logs, 0);
        };
        for (step, &exponent) in exponents.iter().enumerate() {
            if exponent != first + step as u32 {
                return Err(SolveError::NonConsecutive);
            }
        }
        Self::build(missing_logs, first)
    }

    /// Number of unknowns the plan solves, which is also the syndrome row count.
    pub fn rows(&self) -> usize {
        self.rows
    }

    /// Whether stage 2 runs the grouped evaluation.
    pub fn uses_grouped_evaluation(&self) -> bool {
        self.grouped.is_some()
    }

    /// Scratch bytes [`Self::solve_stripe`] needs for a stripe of `stripe_len`
    /// bytes. Linear in the row count, never in the slice length.
    pub fn scratch_bytes(&self, stripe_len: usize) -> usize {
        let bucket_rows = if self.grouped.is_some() {
            LARGE as usize
        } else {
            0
        };
        (self.rows + bucket_rows) * stripe_len
    }

    /// Solve one stripe in place.
    ///
    /// `rows` holds the `m` syndrome rows back to back, each `stripe_len`
    /// bytes of little-endian `u16` words: row `r` is
    /// `S_r = recovery block (e0 + r) with every surviving input removed`. On
    /// return row `c` holds the recovered input slice `x_c`, in the order the
    /// constants were handed to [`Self::build`]. `scratch` must be at least
    /// [`Self::scratch_bytes`] long; its contents on entry are ignored and on
    /// return are unspecified.
    ///
    /// `cancelled` is polled once per output row of each stage. A cancelled
    /// solve leaves both buffers in an unspecified state.
    pub fn solve_stripe(
        &self,
        rows: &mut [u8],
        stripe_len: usize,
        scratch: &mut [u8],
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), SolveError> {
        if !stripe_len.is_multiple_of(2) {
            return Err(SolveError::Geometry);
        }
        if rows.len() != self.rows * stripe_len || scratch.len() < self.scratch_bytes(stripe_len) {
            return Err(SolveError::Geometry);
        }
        if self.rows == 0 || stripe_len == 0 {
            return Ok(());
        }

        let (correlation, buckets) = scratch.split_at_mut(self.rows * stripe_len);
        self.correlate(rows, stripe_len, correlation, cancelled)?;
        match &self.grouped {
            Some(grouped) => {
                self.evaluate_grouped(grouped, rows, stripe_len, correlation, buckets, cancelled)
            }
            None => self.evaluate_direct(rows, stripe_len, correlation, cancelled),
        }
    }

    /// Stage 1: `T_t = sum_r S_r * p[r + t + 1]`.
    ///
    /// Row `t`'s factors are the contiguous window `p[t+1 ..= m]`, so the fold
    /// reads the locator straight out of the plan with no per-row scalar setup.
    /// The window shortens by one per row — that is the triangularity of the
    /// synthetic division showing through.
    fn correlate(
        &self,
        syndromes: &[u8],
        stripe_len: usize,
        out: &mut [u8],
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), SolveError> {
        for (t, dst) in out.chunks_exact_mut(stripe_len).enumerate() {
            if cancelled() {
                return Err(SolveError::Cancelled);
            }
            dst.fill(0);
            let live = self.rows - t;
            let factors = &self.locator[t + 1..=self.rows];
            let mut first = 0usize;
            while first < live {
                let width = BATCH_SOURCES.min(live - first);
                let batch: [FactorSrc<'_>; BATCH_SOURCES] = std::array::from_fn(|lane| {
                    let source = first + lane.min(width - 1);
                    FactorSrc {
                        // Lanes past the batch width repeat the last source
                        // with a zero factor; the kernels skip those without
                        // touching the stream.
                        factor: if lane < width { factors[source] } else { 0 },
                        src: stripe(syndromes, source, stripe_len),
                    }
                });
                gf_simd::mul_acc_input_batch(dst, &batch[..width]);
                first += width;
            }
        }
        Ok(())
    }

    /// Stage 2, direct: `x_c = scale_c * sum_t T_t * g_c^t`, one power ladder
    /// per unknown. The per-unknown scale rides on the `t = 0` factor and
    /// travels through the ladder with it, so no separate scaling pass is
    /// needed.
    fn evaluate_direct(
        &self,
        rows: &mut [u8],
        stripe_len: usize,
        correlation: &[u8],
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), SolveError> {
        for (c, dst) in rows.chunks_exact_mut(stripe_len).enumerate() {
            if cancelled() {
                return Err(SolveError::Cancelled);
            }
            dst.fill(0);
            let g = self.constants[c];
            let mut ladder = self.scale[c];
            let mut first = 0usize;
            while first < self.rows {
                let width = BATCH_SOURCES.min(self.rows - first);
                let mut factors = [0u16; BATCH_SOURCES];
                for factor in factors.iter_mut().take(width) {
                    *factor = ladder;
                    ladder = gf::mul(ladder, g);
                }
                let batch: [FactorSrc<'_>; BATCH_SOURCES] = std::array::from_fn(|lane| {
                    let source = first + lane.min(width - 1);
                    FactorSrc {
                        factor: if lane < width { factors[lane] } else { 0 },
                        src: stripe(correlation, source, stripe_len),
                    }
                });
                gf_simd::mul_acc_input_batch(dst, &batch[..width]);
                first += width;
            }
        }
        Ok(())
    }

    /// Stage 2, grouped: split `g_c^t` across the two coprime factors of 65535,
    /// share the 255-side work across every unknown with the same exponent
    /// residue, and finish each unknown with one 257-source fold.
    fn evaluate_grouped(
        &self,
        grouped: &GroupedEval,
        rows: &mut [u8],
        stripe_len: usize,
        correlation: &[u8],
        buckets: &mut [u8],
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), SolveError> {
        for group in &grouped.groups {
            // Bucket j gathers every T_t with t = j (mod 257), each weighted by
            // the 255-side factor this group shares.
            for (j, dst) in buckets
                .chunks_exact_mut(stripe_len)
                .take(LARGE as usize)
                .enumerate()
            {
                if cancelled() {
                    return Err(SolveError::Cancelled);
                }
                dst.fill(0);
                let mut source = j;
                while source < self.rows {
                    let mut factors = [0u16; BATCH_SOURCES];
                    let mut width = 0usize;
                    let mut scan = source;
                    while width < BATCH_SOURCES && scan < self.rows {
                        let small = (group.small * (scan as u32 % SMALL)) % SMALL;
                        factors[width] = grouped.alpha[small as usize];
                        width += 1;
                        scan += LARGE as usize;
                    }
                    let batch: [FactorSrc<'_>; BATCH_SOURCES] = std::array::from_fn(|lane| {
                        let at = source + lane.min(width - 1) * LARGE as usize;
                        FactorSrc {
                            factor: if lane < width { factors[lane] } else { 0 },
                            src: stripe(correlation, at, stripe_len),
                        }
                    });
                    gf_simd::mul_acc_input_batch(dst, &batch[..width]);
                    source = scan;
                }
            }

            for &(row, large) in &group.members {
                if cancelled() {
                    return Err(SolveError::Cancelled);
                }
                let row = row as usize;
                let scale = self.scale[row];
                let dst = &mut rows[row * stripe_len..(row + 1) * stripe_len];
                dst.fill(0);
                let mut first = 0usize;
                while first < LARGE as usize {
                    let width = BATCH_SOURCES.min(LARGE as usize - first);
                    let mut factors = [0u16; BATCH_SOURCES];
                    for (lane, factor) in factors.iter_mut().take(width).enumerate() {
                        let j = (first + lane) as u32;
                        *factor = gf::mul(scale, grouped.beta[((large * j) % LARGE) as usize]);
                    }
                    let batch: [FactorSrc<'_>; BATCH_SOURCES] = std::array::from_fn(|lane| {
                        let source = first + lane.min(width - 1);
                        FactorSrc {
                            factor: if lane < width { factors[lane] } else { 0 },
                            src: stripe(buckets, source, stripe_len),
                        }
                    });
                    gf_simd::mul_acc_input_batch(dst, &batch[..width]);
                    first += width;
                }
            }
        }
        Ok(())
    }
}

impl GroupedEval {
    /// Sort the unknowns into residue classes and build the two power tables.
    fn build(missing_logs: &[u16]) -> Self {
        let alpha_base = gf::pow(2, LARGE);
        let beta_base = gf::pow(2, SMALL);
        let alpha: Vec<u16> = (0..SMALL).map(|i| gf::pow(alpha_base, i)).collect();
        let beta: Vec<u16> = (0..LARGE).map(|j| gf::pow(beta_base, j)).collect();

        // Residue classes are dense and small (255 of them at most), so a flat
        // index beats sorting or hashing the row list.
        let mut slot = vec![usize::MAX; SMALL as usize];
        let mut groups: Vec<EvalGroup> = Vec::new();
        for (row, &log) in missing_logs.iter().enumerate() {
            let log = log as u32;
            let small = (CRT_INVERSE * (log % SMALL)) % SMALL;
            let large = (CRT_INVERSE * (log % LARGE)) % LARGE;
            let at = &mut slot[small as usize];
            if *at == usize::MAX {
                *at = groups.len();
                groups.push(EvalGroup {
                    small,
                    members: Vec::new(),
                });
            }
            groups[*at].members.push((row as u32, large));
        }

        Self {
            alpha,
            beta,
            groups,
        }
    }
}

/// Row `index` of a stripe-major buffer.
#[inline]
fn stripe(buffer: &[u8], index: usize, stripe_len: usize) -> &[u8] {
    &buffer[index * stripe_len..(index + 1) * stripe_len]
}

/// `P(z) = product over c of (z + g_c)`, returned as `p[0 ..= roots.len()]`.
///
/// Built by multiplying in one root at a time, highest coefficient first so the
/// shifted copy is read before it is overwritten. `O(m^2)` field multiplies,
/// which is the whole scalar cost of the locator.
fn locator_polynomial(roots: &[u16]) -> Vec<u16> {
    let mut p = vec![0u16; roots.len() + 1];
    p[0] = 1;
    for (degree, &root) in roots.iter().enumerate() {
        for j in (0..=degree + 1).rev() {
            let shifted = if j > 0 { p[j - 1] } else { 0 };
            p[j] = shifted ^ gf::mul(root, p[j]);
        }
    }
    p
}

/// `P'(at)`, the formal derivative of the locator evaluated at one root.
///
/// In characteristic 2 every even-degree term differentiates away and each odd
/// term loses its coefficient's multiplier, leaving
/// `P'(z) = p[1] + p[3] z^2 + p[5] z^4 + ...` — a polynomial in `z^2`, so one
/// Horner pass over the odd coefficients in `z^2` evaluates it.
fn evaluate_derivative(locator: &[u16], at: u16) -> u16 {
    let square = gf::mul(at, at);
    let mut acc = 0u16;
    let mut index = locator.len() - 1;
    // Walk the odd indices downward. `locator.len() - 1` is the degree, so the
    // highest odd index is it or one below.
    if index % 2 == 0 {
        index = index.wrapping_sub(1);
    }
    while index != usize::MAX {
        acc = gf::mul(acc, square) ^ locator[index];
        index = index.wrapping_sub(2);
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Syndromes for a hand-built system, so the unit tests do not depend on
    /// the differential harness in `tests/`.
    fn syndromes(values: &[u16], logs: &[u16], first_exponent: u32, rows: usize) -> Vec<u8> {
        let mut out = vec![0u8; rows * 2];
        for (r, word) in out.chunks_exact_mut(2).enumerate() {
            let mut acc = 0u16;
            for (&x, &log) in values.iter().zip(logs) {
                acc ^= gf::mul(x, gf::pow_from_log(log, first_exponent + r as u32));
            }
            word.copy_from_slice(&acc.to_le_bytes());
        }
        out
    }

    fn solve(
        logs: &[u16],
        values: &[u16],
        first_exponent: u32,
        strategy: SolveStrategy,
    ) -> Vec<u16> {
        let plan =
            ConsecutiveSolvePlan::build_with_strategy(logs, first_exponent, strategy).unwrap();
        let mut rows = syndromes(values, logs, first_exponent, logs.len());
        let mut scratch = vec![0u8; plan.scratch_bytes(2)];
        plan.solve_stripe(&mut rows, 2, &mut scratch, &|| false)
            .unwrap();
        rows.chunks_exact(2)
            .map(|w| u16::from_le_bytes([w[0], w[1]]))
            .collect()
    }

    #[test]
    fn locator_is_monic_with_the_expected_roots() {
        let roots = [2u16, 4, 16, 0x89ab];
        let p = locator_polynomial(&roots);
        assert_eq!(p.len(), roots.len() + 1);
        assert_eq!(p[roots.len()], 1);
        for root in roots {
            let mut acc = 0u16;
            for &coefficient in p.iter().rev() {
                acc = gf::mul(acc, root) ^ coefficient;
            }
            assert_eq!(acc, 0, "P({root:#x}) should vanish");
        }
    }

    #[test]
    fn derivative_matches_the_product_of_root_differences() {
        let roots = [2u16, 4, 16, 32, 0x1234];
        let p = locator_polynomial(&roots);
        for (i, &root) in roots.iter().enumerate() {
            let mut expected = 1u16;
            for (j, &other) in roots.iter().enumerate() {
                if i != j {
                    expected = gf::mul(expected, root ^ other);
                }
            }
            assert_eq!(evaluate_derivative(&p, root), expected);
        }
    }

    #[test]
    fn solves_small_systems_both_ways() {
        let logs: Vec<u16> = (1..=6u16).collect();
        let values: Vec<u16> = vec![0x0001, 0xbeef, 0x1234, 0xffff, 0x0002, 0x8000];
        for first_exponent in [0u32, 1, 5000] {
            for strategy in [SolveStrategy::Baseline, SolveStrategy::Grouped] {
                assert_eq!(
                    solve(&logs, &values, first_exponent, strategy),
                    values,
                    "{strategy:?} at e0={first_exponent}"
                );
            }
        }
    }

    #[test]
    fn solves_a_single_unknown() {
        assert_eq!(
            solve(&[7], &[0xabcd], 12, SolveStrategy::Baseline),
            [0xabcd]
        );
        assert_eq!(solve(&[7], &[0xabcd], 12, SolveStrategy::Grouped), [0xabcd]);
    }

    #[test]
    fn rejects_repeated_and_out_of_range_constants() {
        assert_eq!(
            ConsecutiveSolvePlan::build(&[3, 3], 0).unwrap_err(),
            SolveError::Constants
        );
        assert_eq!(
            ConsecutiveSolvePlan::build(&[0xffff], 0).unwrap_err(),
            SolveError::Constants
        );
    }

    #[test]
    fn rejects_non_consecutive_exponents() {
        assert_eq!(
            ConsecutiveSolvePlan::build_for_exponents(&[1, 2, 4], &[0, 1, 3]).unwrap_err(),
            SolveError::NonConsecutive
        );
        assert!(ConsecutiveSolvePlan::build_for_exponents(&[1, 2, 4], &[7, 8, 9]).is_ok());
        assert_eq!(
            ConsecutiveSolvePlan::build_for_exponents(&[1, 2], &[7]).unwrap_err(),
            SolveError::Geometry
        );
    }

    #[test]
    fn rejects_mismatched_buffers() {
        let plan = ConsecutiveSolvePlan::build(&[1, 2], 0).unwrap();
        let mut scratch = vec![0u8; plan.scratch_bytes(4)];
        assert_eq!(
            plan.solve_stripe(&mut [0u8; 7], 4, &mut scratch, &|| false)
                .unwrap_err(),
            SolveError::Geometry
        );
        assert_eq!(
            plan.solve_stripe(&mut [0u8; 6], 3, &mut scratch, &|| false)
                .unwrap_err(),
            SolveError::Geometry
        );
        assert_eq!(
            plan.solve_stripe(&mut [0u8; 8], 4, &mut [], &|| false)
                .unwrap_err(),
            SolveError::Geometry
        );
    }

    #[test]
    fn reports_cancellation() {
        let plan = ConsecutiveSolvePlan::build(&[1, 2], 0).unwrap();
        let mut scratch = vec![0u8; plan.scratch_bytes(4)];
        assert_eq!(
            plan.solve_stripe(&mut [0u8; 8], 4, &mut scratch, &|| true)
                .unwrap_err(),
            SolveError::Cancelled
        );
    }

    #[test]
    fn auto_picks_the_grouped_evaluation_only_for_large_sets() {
        let few: Vec<u16> = (1..=8u16).collect();
        assert!(
            !ConsecutiveSolvePlan::build(&few, 0)
                .unwrap()
                .uses_grouped_evaluation()
        );
        let many: Vec<u16> = (1..=FAST_MIN_ROWS as u16).collect();
        assert!(
            ConsecutiveSolvePlan::build(&many, 0)
                .unwrap()
                .uses_grouped_evaluation()
        );
    }
}
