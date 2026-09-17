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
//! syndromes. Written out, stage 1 is a Hankel product of the block sequence
//! `S` with the scalar sequence `p` and stage 2 evaluates the block polynomial
//! `T` at each constant — both `O(m^2)` block folds, both *structured*, and
//! both ordinary multiply-accumulate passes over a stripe that run on the
//! crate's SIMD region kernels.
//!
//! # Stage 1 as a blocked convolution
//!
//! A Hankel product is a correlation, and a correlation is a convolution with
//! one side reversed. Cut both index ranges into segments of [`BLOCK`] = 128:
//! with `r = j*128 + r'` and `t = i*128 + t'`, the coefficient `p[r + t + 1]`
//! depends on the segments only through `i + j`, so each segment pair is one
//! convolution of a 128-tap block sequence with the reversed locator window
//! `R_s[w] = p[s*128 + 255 - w]`, read out at `v = 254 - t'`. Those indices
//! never wrap modulo 255, so a *cyclic* convolution of length
//! [`CONV`] = `2*128 - 1` carries it exactly — and 255 divides 65535, so
//! GF(2^16) has a root of unity of exactly that order and the cyclic
//! convolution is a length-255 transform, a pointwise product, and an inverse.
//!
//! Each input segment is transformed once, the spectra are accumulated into one
//! output spectrum at a time (triangularly: the locator runs out of windows
//! past `s = ceil(m/128)`), and each output segment is transformed back once.
//! The quadratic term survives only in the spectral accumulate, at
//! `255 / (2 * 128^2)` per `m^2` — 128 times under the direct form's
//! coefficient.
//!
//! The length-255 transform itself factors. `255 = 3 * 5 * 17` with pairwise
//! coprime radices, so the Good-Thomas (prime-factor) map re-indexes it as
//! three independent short transforms with **no twiddle factors** between them:
//! writing both indices through the CRT idempotents 85, 51 and 120 of `Z/255`
//! makes the cross terms vanish, because each idempotent is one modulo its own
//! radix and zero modulo the other two. Ordering the radices puts the prunable
//! work where it is cheapest: radix 17 runs *first* going forward, so the 127
//! zero rows padding a 128-row segment out to 255 are never folded, and *last*
//! coming back, so the 127 outputs the Hankel product does not read are never
//! computed.
//!
//! # Stage 2 as a two-level evaluation
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
//! [`SolveStrategy::Auto`] arbitrates — for both stages, each against its own
//! row-count threshold.
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

/// Segment length of the blocked stage-1 convolution.
///
/// Paired with [`CONV`] = `2 * BLOCK - 1`: the linear convolution of two
/// length-`BLOCK` sequences is exactly that long, so a cyclic convolution of
/// that length carries it with nothing wrapping. 128 is the largest such
/// pairing whose length divides 65535 — 255 does, 511 and 1023 do not — and the
/// quadratic spectral-accumulate term wants `BLOCK` as large as the field
/// allows.
const BLOCK: usize = 128;

/// Length of the stage-1 cyclic convolution, `2 * BLOCK - 1 == 255`.
const CONV: usize = 2 * BLOCK - 1;

/// The pairwise coprime radices [`CONV`] factors into.
const RADICES: [usize; 3] = [3, 5, 17];

/// Most rows of one segment that can share a `(n mod 3, n mod 5)` class: a
/// class is one residue modulo 15, so `ceil(128 / 15) = 9`.
const RADIX17_GROUP: usize = BLOCK.div_ceil(15);

/// The re-indexing weight for one radix of [`CONV`]: the element of `Z/255`
/// that is one modulo that radix and zero modulo the other two.
///
/// Sending both the input and the output index of the transform through these
/// weights is what makes the prime-factor split twiddle-free — every cross
/// term picks up a factor that is zero modulo 255.
fn radix_weight(radix: usize) -> usize {
    let cofactor = CONV / radix;
    // The cofactor is invertible modulo its own radix, and 255 is small enough
    // that searching for the multiplier beats writing out an extended GCD.
    let multiplier = (1..radix)
        .find(|step| cofactor * step % radix == 1)
        .expect("each radix is coprime to its cofactor");
    cofactor * multiplier
}

/// Live source streams per destination pass. The grouped-input kernels read
/// their destination once per batch and stream the sources past it, so a batch
/// wants to be as wide as the line-fill buffers of the smallest supported core
/// allow — the same bound `gf_simd`'s own source blocking uses.
const BATCH_SOURCES: usize = 8;

/// Row count at or above which [`SolveStrategy::Auto`] moves stage 2 to the
/// grouped evaluation, and stage 1 to the transformed correlation. Below it
/// the 257 bucket rows and the fixed per-segment transform cost more than the
/// `m^2` and `m^2 / 2` folds they replace.
///
/// One threshold serves both because the measurement never favoured splitting
/// them: at every row count where either transform paid for itself, both did.
/// Solve times in milliseconds for one 64 KiB stripe on an Apple M-series core,
/// from this crate's `vandermonde_solve_bench` example — `inverse` is the
/// explicit inverse's `m x m` block product, the others are this module's three
/// forms:
///
/// ```text
///     m    inverse    direct   grouped   transformed
///   256      118.5     173.3     296.4         277.8
///   512      468.8     694.4     651.7         498.5
///  1024     1887.2    2925.6    1666.6         907.4
///  2048     7799.4   11816.3    5403.1        1802.7
///  4096    32746.2   61083.2   18723.5        4741.6
///  8192   137721.7  188012.8   67527.4        7880.3
/// ```
///
/// Both stages are bound by passes over memory rather than by multiplies, so
/// the crossover sits in much the same place on any host: the transformed form
/// is already the cheapest of the three at 512 rows, and by 8192 it is 8.6x
/// the grouped form and 17.5x the inverse's block product — which the inverse
/// has to spend an `O(m^3)` Gauss-Jordan on before it can run at all.
const GROUPED_MIN_ROWS: usize = 512;

/// Row count at or above which [`SolveStrategy::Auto`] moves stage 1 to the
/// transformed correlation. Equal to [`GROUPED_MIN_ROWS`]: see the table
/// there.
const TRANSFORM_MIN_ROWS: usize = GROUPED_MIN_ROWS;

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

/// Which form each of the two stages takes. The variants are a ladder: each
/// adds one transform to the one before it, and all of them produce identical
/// bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SolveStrategy {
    /// Both stages written out: `1.5 * m^2` folds, scratch for `m` rows only.
    Direct,
    /// Direct stage 1; stage 2 groups the constants by their exponent residue
    /// modulo 255 and shares 257 bucket rows per group. 257 extra scratch rows.
    GroupedEvaluation,
    /// Stage 1 as blocked length-255 convolutions as well. Adds the input
    /// spectra, which are the largest arena the solve holds.
    Transformed,
    /// Per-stage thresholds: [`GROUPED_MIN_ROWS`] for stage 2,
    /// [`TRANSFORM_MIN_ROWS`] for stage 1.
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

/// Tables for the blocked stage-1 correlation.
#[derive(Debug)]
struct ConvolutionPlan {
    /// `ceil(m / BLOCK)`: segments of the index range, and of the locator.
    segments: usize,
    /// Spectrum of each reversed locator window, `[segment * CONV + point]`.
    /// Window `s` is empty for `s >= segments`, which is the triangularity the
    /// spectral accumulate exploits.
    kernel: Vec<u16>,
    /// Forward radix-3, radix-5 and radix-17 matrices, row-major by output.
    forward: [Vec<u16>; 3],
    /// The same three transforms with the root exponent negated. The missing
    /// `1/255` scale is one in characteristic two, so nothing else changes.
    inverse: [Vec<u16>; 3],
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
    /// `g_c` per unknown, for the direct stage-2 power ladder.
    constants: Vec<u16>,
    /// Present when stage 1 runs as blocked convolutions.
    convolution: Option<ConvolutionPlan>,
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

        let (blocked, grouped) = match strategy {
            SolveStrategy::Direct => (false, false),
            SolveStrategy::GroupedEvaluation => (false, true),
            SolveStrategy::Transformed => (true, true),
            SolveStrategy::Auto => (rows >= TRANSFORM_MIN_ROWS, rows >= GROUPED_MIN_ROWS),
        };

        Ok(Self {
            convolution: blocked.then(|| ConvolutionPlan::build(&locator, rows)),
            grouped: grouped.then(|| GroupedEval::build(missing_logs)),
            rows,
            locator,
            scale,
            constants,
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

    /// Whether stage 1 runs as blocked convolutions.
    pub fn uses_blocked_correlation(&self) -> bool {
        self.convolution.is_some()
    }

    /// Whether stage 2 runs the grouped evaluation.
    pub fn uses_grouped_evaluation(&self) -> bool {
        self.grouped.is_some()
    }

    /// Scratch rows of one stripe each, in the order [`Self::solve_stripe`]
    /// slices them: the correlation output, then stage 1's arenas, then stage
    /// 2's buckets.
    fn scratch_rows(&self) -> usize {
        // Stage 1 holds one spectrum per input segment, one resident output
        // spectrum, and the two arenas the three-radix network bounces through.
        let stage1 = self
            .convolution
            .as_ref()
            .map_or(0, |plan| (plan.segments + 3) * CONV);
        let buckets = if self.grouped.is_some() {
            LARGE as usize
        } else {
            0
        };
        self.rows + stage1 + buckets
    }

    /// Scratch bytes [`Self::solve_stripe`] needs for a stripe of `stripe_len`
    /// bytes. Linear in the row count, never in the slice length.
    pub fn scratch_bytes(&self, stripe_len: usize) -> usize {
        self.scratch_rows() * stripe_len
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

        let (correlation, rest) = scratch.split_at_mut(self.rows * stripe_len);
        let buckets = match &self.convolution {
            Some(plan) => {
                let (arenas, rest) = rest.split_at_mut((plan.segments + 3) * CONV * stripe_len);
                plan.correlate(self.rows, rows, stripe_len, correlation, arenas, cancelled)?;
                rest
            }
            None => {
                self.correlate(rows, stripe_len, correlation, cancelled)?;
                rest
            }
        };
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

impl ConvolutionPlan {
    /// Spectra of the reversed locator windows, plus the six radix matrices.
    fn build(locator: &[u16], rows: usize) -> Self {
        let segments = rows.div_ceil(BLOCK);
        // omega = 2^257 has order 65535 / 257 = 255 = CONV.
        let root: Vec<u16> = (0..CONV as u32).map(|i| gf::pow(2, LARGE * i)).collect();

        // R_s[w] = p[s * BLOCK + 2 * BLOCK - 1 - w]: the locator window of
        // segment pair sum `s`, reversed so the correlation reads the
        // convolution at v = 2 * BLOCK - 2 - t.
        let mut kernel = vec![0u16; segments * CONV];
        for (s, spectrum) in kernel.chunks_exact_mut(CONV).enumerate() {
            for w in 0..CONV {
                let at = s * BLOCK + 2 * BLOCK - 1 - w;
                let coefficient = if at < locator.len() { locator[at] } else { 0 };
                if coefficient == 0 {
                    continue;
                }
                for (point, slot) in spectrum.iter_mut().enumerate() {
                    *slot ^= gf::mul(coefficient, root[point * w % CONV]);
                }
            }
        }

        let matrices =
            |inverse: bool| std::array::from_fn(|axis| radix_matrix(&root, RADICES[axis], inverse));
        Self {
            segments,
            kernel,
            forward: matrices(false),
            inverse: matrices(true),
        }
    }

    /// Stage 1 as `segments` forward transforms, a triangular accumulate in the
    /// spectral domain, and `segments` inverse transforms.
    fn correlate(
        &self,
        rows: usize,
        syndromes: &[u8],
        stripe_len: usize,
        out: &mut [u8],
        arenas: &mut [u8],
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), SolveError> {
        let (spectra, rest) = arenas.split_at_mut(self.segments * CONV * stripe_len);
        let (accumulator, rest) = rest.split_at_mut(CONV * stripe_len);
        let (first_arena, second_arena) = rest.split_at_mut(CONV * stripe_len);

        for segment in 0..self.segments {
            if cancelled() {
                return Err(SolveError::Cancelled);
            }
            let start = segment * BLOCK;
            let live = BLOCK.min(rows - start);
            radix17_forward(
                syndromes,
                start,
                live,
                stripe_len,
                first_arena,
                &self.forward[2],
            );
            radix5(first_arena, second_arena, stripe_len, &self.forward[1]);
            radix3_to_natural(
                second_arena,
                &mut spectra[segment * CONV * stripe_len..(segment + 1) * CONV * stripe_len],
                stripe_len,
                &self.forward[0],
            );
        }

        for segment in 0..self.segments {
            if cancelled() {
                return Err(SolveError::Cancelled);
            }
            // The locator runs out of windows past `segments`, so an output
            // segment pairs only with the input segments before its complement.
            let pairs = self.segments - segment;
            for (point, dst) in accumulator
                .chunks_exact_mut(stripe_len)
                .take(CONV)
                .enumerate()
            {
                dst.fill(0);
                let mut first = 0usize;
                while first < pairs {
                    let width = BATCH_SOURCES.min(pairs - first);
                    let mut factors = [0u16; BATCH_SOURCES];
                    let mut sources = [EMPTY; BATCH_SOURCES];
                    for (lane, factor) in factors.iter_mut().take(width).enumerate() {
                        let input = first + lane;
                        *factor = self.kernel[(segment + input) * CONV + point];
                        sources[lane] = stripe(spectra, input * CONV + point, stripe_len);
                    }
                    fold(dst, &sources[..width], &factors[..width]);
                    first += width;
                }
            }

            radix3_from_natural(accumulator, first_arena, stripe_len, &self.inverse[0]);
            radix5(first_arena, second_arena, stripe_len, &self.inverse[1]);
            let start = segment * BLOCK;
            let live = BLOCK.min(rows - start);
            radix17_inverse(
                second_arena,
                &mut out[start * stripe_len..(start + live) * stripe_len],
                stripe_len,
                &self.inverse[2],
            );
        }
        Ok(())
    }
}

/// Re-indexed coordinates `(n mod 3, n mod 5, n mod 17)`, laid out so the
/// radix-17 axis is contiguous: the arenas the three stages bounce through are
/// indexed this way.
#[inline]
fn split_index(three: usize, five: usize, seventeen: usize) -> usize {
    (three * 5 + five) * 17 + seventeen
}

/// The natural index in `0..255` those coordinates stand for, reassembled
/// through the radix weights.
#[inline]
fn natural_index(three: usize, five: usize, seventeen: usize) -> usize {
    (radix_weight(3) * three + radix_weight(5) * five + radix_weight(17) * seventeen) % CONV
}

/// One radix's dense transform matrix, row-major by output then input.
///
/// The radix weight is what makes `omega^(weight * k * n)` depend on nothing
/// but this axis. The inverse negates the exponent; its missing `1/radix`
/// scale is one in characteristic two because every radix here is odd.
fn radix_matrix(root: &[u16], radix: usize, inverse: bool) -> Vec<u16> {
    let weight = radix_weight(radix);
    let mut out = vec![0u16; radix * radix];
    for k in 0..radix {
        for n in 0..radix {
            let mut exponent = weight * k * n % CONV;
            if inverse && exponent != 0 {
                exponent = CONV - exponent;
            }
            out[k * radix + n] = root[exponent];
        }
    }
    out
}

/// The forward transform's radix-17 stage, pruned at the source.
///
/// Only the segment's `live <= 128` rows exist; the rows that pad the segment
/// out to 255 are zero and are never folded. A `(n mod 3, n mod 5)` class is
/// one residue modulo 15, so each of the fifteen classes holds at most
/// [`RADIX17_GROUP`] rows and each of a class's seventeen outputs folds only
/// those.
fn radix17_forward(
    syndromes: &[u8],
    first_row: usize,
    live: usize,
    stripe_len: usize,
    dst: &mut [u8],
    matrix: &[u16],
) {
    debug_assert!(live <= BLOCK, "one segment at a time");
    let mut sources = [EMPTY; RADIX17_GROUP];
    let mut residues = [0usize; RADIX17_GROUP];
    for three in 0..3 {
        for five in 0..5 {
            let mut count = 0usize;
            for row in 0..live {
                if row % 3 == three && row % 5 == five {
                    sources[count] = stripe(syndromes, first_row + row, stripe_len);
                    residues[count] = row % 17;
                    count += 1;
                }
            }
            for k in 0..17 {
                let mut factors = [0u16; RADIX17_GROUP];
                for (factor, &residue) in factors.iter_mut().zip(&residues[..count]) {
                    *factor = matrix[k * 17 + residue];
                }
                let out = stripe_mut(dst, split_index(three, five, k), stripe_len);
                out.fill(0);
                fold(out, &sources[..count], &factors[..count]);
            }
        }
    }
}

/// The radix-5 stage, both arenas in re-indexed coordinate order. Forward and
/// inverse differ only in the matrix handed in.
fn radix5(src: &[u8], dst: &mut [u8], stripe_len: usize, matrix: &[u16]) {
    for three in 0..3 {
        for seventeen in 0..17 {
            let mut sources = [EMPTY; 5];
            for (five, source) in sources.iter_mut().enumerate() {
                *source = stripe(src, split_index(three, five, seventeen), stripe_len);
            }
            for k in 0..5 {
                let out = stripe_mut(dst, split_index(three, k, seventeen), stripe_len);
                out.fill(0);
                fold(out, &sources, &matrix[k * 5..k * 5 + 5]);
            }
        }
    }
}

/// The forward transform's last stage: radix 3, writing natural spectral order
/// so the spectral accumulate reads one point's spectrum contiguously.
fn radix3_to_natural(src: &[u8], dst: &mut [u8], stripe_len: usize, matrix: &[u16]) {
    for five in 0..5 {
        for seventeen in 0..17 {
            let mut sources = [EMPTY; 3];
            for (three, source) in sources.iter_mut().enumerate() {
                *source = stripe(src, split_index(three, five, seventeen), stripe_len);
            }
            for k in 0..3 {
                let out = stripe_mut(dst, natural_index(k, five, seventeen), stripe_len);
                out.fill(0);
                fold(out, &sources, &matrix[k * 3..k * 3 + 3]);
            }
        }
    }
}

/// The inverse transform's first stage: natural spectral order back into
/// re-indexed coordinates.
fn radix3_from_natural(src: &[u8], dst: &mut [u8], stripe_len: usize, matrix: &[u16]) {
    for five in 0..5 {
        for seventeen in 0..17 {
            let mut sources = [EMPTY; 3];
            for (three, source) in sources.iter_mut().enumerate() {
                *source = stripe(src, natural_index(three, five, seventeen), stripe_len);
            }
            for k in 0..3 {
                let out = stripe_mut(dst, split_index(k, five, seventeen), stripe_len);
                out.fill(0);
                fold(out, &sources, &matrix[k * 3..k * 3 + 3]);
            }
        }
    }
}

/// The inverse transform's radix-17 stage, pruned at the destination.
///
/// The correlation reads the convolution at `v = 2 * BLOCK - 2 - t` for this
/// output segment's `live <= 128` rows, so the other outputs are never
/// computed.
fn radix17_inverse(src: &[u8], dst: &mut [u8], stripe_len: usize, matrix: &[u16]) {
    for (t, out) in dst.chunks_exact_mut(stripe_len).enumerate() {
        let natural = CONV - 1 - t;
        let (three, five, seventeen) = (natural % 3, natural % 5, natural % 17);
        let mut sources = [EMPTY; 17];
        for (n, source) in sources.iter_mut().enumerate() {
            *source = stripe(src, split_index(three, five, n), stripe_len);
        }
        out.fill(0);
        fold(out, &sources, &matrix[seventeen * 17..seventeen * 17 + 17]);
    }
}

/// Row `index` of a stripe-major buffer.
#[inline]
fn stripe(buffer: &[u8], index: usize, stripe_len: usize) -> &[u8] {
    &buffer[index * stripe_len..(index + 1) * stripe_len]
}

/// Row `index` of a stripe-major buffer, for writing.
#[inline]
fn stripe_mut(buffer: &mut [u8], index: usize, stripe_len: usize) -> &mut [u8] {
    &mut buffer[index * stripe_len..(index + 1) * stripe_len]
}

/// The empty slice a fixed-size source array starts life filled with.
const EMPTY: &[u8] = &[];

/// `dst ^= sum_i coeffs[i] * sources[i]`, in batches of [`BATCH_SOURCES`].
///
/// Lanes past a batch's width repeat its last source with a zero factor; the
/// grouped-input kernels skip those without touching the stream.
fn fold(dst: &mut [u8], sources: &[&[u8]], coeffs: &[u16]) {
    debug_assert_eq!(sources.len(), coeffs.len());
    let mut first = 0usize;
    while first < sources.len() {
        let width = BATCH_SOURCES.min(sources.len() - first);
        let batch: [FactorSrc<'_>; BATCH_SOURCES] = std::array::from_fn(|lane| FactorSrc {
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

    /// Every pinned form, so a unit test never silently covers just one.
    const EVERY_STRATEGY: [SolveStrategy; 3] = [
        SolveStrategy::Direct,
        SolveStrategy::GroupedEvaluation,
        SolveStrategy::Transformed,
    ];

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
    fn solves_small_systems_every_way() {
        let logs: Vec<u16> = (1..=6u16).collect();
        let values: Vec<u16> = vec![0x0001, 0xbeef, 0x1234, 0xffff, 0x0002, 0x8000];
        for first_exponent in [0u32, 1, 5000] {
            for strategy in EVERY_STRATEGY {
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
        for strategy in EVERY_STRATEGY {
            assert_eq!(
                solve(&[7], &[0xabcd], 12, strategy),
                [0xabcd],
                "{strategy:?}"
            );
        }
    }

    #[test]
    fn coordinate_split_is_a_bijection() {
        // The whole transform rests on this: the radix weights reassemble every
        // natural index exactly once, and each coordinate is that index's own
        // residue.
        let mut seen = vec![false; CONV];
        for three in 0..3 {
            for five in 0..5 {
                for seventeen in 0..17 {
                    let natural = natural_index(three, five, seventeen);
                    assert_eq!(
                        (natural % 3, natural % 5, natural % 17),
                        (three, five, seventeen)
                    );
                    assert!(!std::mem::replace(&mut seen[natural], true));
                    assert!(split_index(three, five, seventeen) < CONV);
                }
            }
        }
    }

    #[test]
    fn radix_matrices_invert_each_other() {
        let root: Vec<u16> = (0..CONV as u32).map(|i| gf::pow(2, LARGE * i)).collect();
        assert_eq!(gf::pow(root[1], CONV as u32), 1, "omega has order 255");
        for radix in RADICES {
            let forward = radix_matrix(&root, radix, false);
            let inverse = radix_matrix(&root, radix, true);
            for i in 0..radix {
                for j in 0..radix {
                    let mut acc = 0u16;
                    for k in 0..radix {
                        acc ^= gf::mul(inverse[i * radix + k], forward[k * radix + j]);
                    }
                    // The missing 1/radix is one in characteristic two only for
                    // an odd radix, which 3, 5 and 17 all are.
                    assert_eq!(acc, u16::from(i == j), "radix {radix} at ({i},{j})");
                }
            }
        }
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
        for strategy in EVERY_STRATEGY {
            let plan = ConsecutiveSolvePlan::build_with_strategy(&[1, 2], 0, strategy).unwrap();
            let mut scratch = vec![0u8; plan.scratch_bytes(4)];
            assert_eq!(
                plan.solve_stripe(&mut [0u8; 8], 4, &mut scratch, &|| true)
                    .unwrap_err(),
                SolveError::Cancelled,
                "{strategy:?}"
            );
        }
    }

    #[test]
    fn auto_picks_each_transform_only_for_large_sets() {
        let few: Vec<u16> = (1..=8u16).collect();
        let plan = ConsecutiveSolvePlan::build(&few, 0).unwrap();
        assert!(!plan.uses_grouped_evaluation());
        assert!(!plan.uses_blocked_correlation());

        let below: Vec<u16> = (1..GROUPED_MIN_ROWS.max(TRANSFORM_MIN_ROWS) as u16).collect();
        let plan = ConsecutiveSolvePlan::build(&below, 0).unwrap();
        assert_eq!(
            plan.uses_grouped_evaluation(),
            below.len() >= GROUPED_MIN_ROWS
        );
        assert_eq!(
            plan.uses_blocked_correlation(),
            below.len() >= TRANSFORM_MIN_ROWS
        );

        let many: Vec<u16> = (1..=GROUPED_MIN_ROWS.max(TRANSFORM_MIN_ROWS) as u16).collect();
        let plan = ConsecutiveSolvePlan::build(&many, 0).unwrap();
        assert!(plan.uses_blocked_correlation());
        assert!(plan.uses_grouped_evaluation());
    }
}
