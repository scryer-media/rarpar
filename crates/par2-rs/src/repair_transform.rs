//! The transform arm of PAR2 repair: syndromes by DFT, solve by the m×m inverse.
//!
//! # Why
//!
//! The dense repair executor folds every available source into every missing
//! output: `m * n_available` region folds, plus `m * m` for the recovery
//! columns. At a large set that product is the whole runtime — 4096 missing
//! slices against 14000 available ones is 57 million folds per stripe of the
//! slice.
//!
//! The same answer can be reached in two cheaper steps.
//!
//! **Syndromes.** For a selected recovery exponent `e`,
//!
//! ```text
//! S_e = R_e ^ sum over present i of D_i * c_i^e
//! ```
//!
//! and that sum is exactly one output row of the multiplicative GF(2^16) DFT
//! over the present slices' PAR2 constants. [`DftPlan`] computes a contiguous
//! range of such rows in `region_folds()` folds instead of `m * n_available`,
//! which at the shape above is a ~35x reduction. `S_e` is then the recovery
//! row `R_e` with the present contributions removed, i.e. the parity of the
//! *missing* slices alone.
//!
//! **Solve.** Those syndromes are `A * X`, where `A[r][c] = c_missing_c ^ e_r`
//! is the m×m Vandermonde block over the missing slots and `X` the missing
//! slices. [`crate::matrix`] already inverts `A` while planning the repair —
//! `RepairPlan::decode_matrix` *is* `A^-1` — so the solve is `m * m` folds of
//! that inverse against the syndrome rows.
//!
//! Total: `region_folds + m^2` against `m * (n_available + m)`. GF(2^16)
//! addition is XOR and multiplication is exact, so re-associating the sum this
//! way is bit-identical to the dense product, not merely equivalent. The dense
//! path computes `A^-1 * (pre * present + I * R)`; this computes
//! `A^-1 * (R + pre * present)`. Same terms, same field, different order.
//!
//! (The transform itself is a Good–Thomas factorisation of the length-65535
//! cyclic DFT; its derivation, cost model and pruning live in
//! [`reedsolomon_rs::gf16_dft`]. The idea of running PAR2 repair through a
//! syndrome transform rather than a dense matrix product is not new — other
//! Reed-Solomon implementations do it — but the schedule, the memory contract
//! and the divergence probe here are this crate's own.)
//!
//! # What it costs in memory, and why that decides everything
//!
//! The dense executor streams one source at a time: two transfer buffers and a
//! staging area, independent of `n_available`. The transform cannot. A DFT row
//! is a sum over *every* present slice, so the same byte range of every present
//! slice has to be resident at once.
//!
//! So the arm works in **bands**. A band is a byte range of each slice; one
//! pass stages that range of every present slice, produces every missing
//! slice's bytes for that range, writes them, and moves on. Within a band the
//! work splits into **stripes**, which are what the transform and the solve
//! actually consume and what the rayon workers take one at a time. A band is
//! always a whole number of stripes, and both are 64-byte aligned.
//!
//! Every arena is summed before a byte is allocated, and the whole sum is
//! charged against the caller's existing [`crate::repair::RepairOptions`]
//! `memory_limit`:
//!
//! ```text
//! (n_present + m + 2) * band                     staging, output rows, probe
//! + workers * (range_len * stripe + dft scratch) per-worker syndrome rows
//! + one spare dft scratch                        the short tail stripe
//! + plan tables
//! ```
//!
//! If the limit cannot buy a band of at least [`MIN_BAND`] bytes, or the slice
//! would need more than [`MAX_PASSES`] bands, the arm declines and the dense
//! executor runs unchanged. The decode matrix is *not* charged here: it is
//! built by `plan_repair` under the separate matrix-workspace budget
//! (`MATRIX_WORKSPACE_BUDGET_FLOOR`), exactly as it is for the dense path, and
//! charging it twice would only make the arm decline where the dense path
//! happily proceeds.
//!
//! # Safety
//!
//! Per band, one syndrome row is also computed the dense way over the staged
//! bytes and compared with the transform's, and the solved rows are re-encoded
//! at that exponent and compared with the same syndrome, so neither half of the
//! arm is trusted on its own word. A mismatch abandons the arm and
//! the caller reruns the whole repair on the dense path. Nothing is written
//! until the probe for that band has passed, and the dense rerun recomputes
//! and rewrites every missing byte from sources the arm never touches, so a
//! band already written is simply overwritten.

use std::collections::HashMap;
use std::fs::File;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use rayon::prelude::*;
use reedsolomon_rs::fft::TransformError;
use reedsolomon_rs::gf16_dft::{DftPlan, DftScratch};
use reedsolomon_rs::vandermonde_solve::{ConsecutiveSolvePlan, SolveError};
use tracing::{debug, info, warn};

use crate::error::{Par2Error, Result};
use crate::gf;
use crate::gf_simd::FactorSrc;
use crate::matrix;
use crate::par2_set::Par2FileSet;
use crate::repair::{
    RepairOptions, RepairPlan, StreamSourceReader, build_write_targets, check_cancel,
    read_stream_source_chunk,
};
use crate::types::{ProgressPhase, ProgressStage, ProgressUpdate};
use crate::verify::FileAccess;

/// Smallest band the arm will accept. Below this the strided read of every
/// present slice degenerates into one syscall per few kilobytes per slice.
///
/// 2 KiB rather than a rounder 4 KiB because the staging arena is
/// `n_present * band`: on a 16k-block set (16320 present slices, 64 KiB
/// slices) the default 64 MiB limit buys a band of 3840 bytes, and a 4 KiB
/// floor would have refused every repair on that set at the default limit. At
/// 2 KiB the same set repairs in 1.8 s (m=512), 3.0 s (m=2048) and 5.9 s
/// (m=4096) against the dense path's 2.2 s, 7.9 s and 20.3 s, with a peak RSS
/// of 95, 190 and 246 MB against dense's 86, 149 and 264 MB.
pub(crate) const MIN_BAND: usize = 2 * 1024;

/// Most bands the arm will split a slice into. A pass re-walks every present
/// file's descriptor set; past a couple of hundred that bookkeeping, not the
/// arithmetic, sets the runtime.
pub(crate) const MAX_PASSES: usize = 256;

/// Missing slices below which the arm never engages, whatever the fold ratio.
///
/// Two reasons, both measured. The transform's cost is dominated by its
/// length-257 accumulation, `live_buckets * m` folds, and `live_buckets`
/// saturates at 257 as soon as the set is large; at small `m` that fixed cost
/// is most of the work and the ratio against `m * n` is near 1. And the arm's
/// setup — plan build, arena allocation, per-band probe — is charged whole
/// against a repair whose dense form may take milliseconds. Everyday repairs
/// of a handful of blocks must not notice this module exists, and with this
/// floor they never reach it: the gate is three integer comparisons.
pub(crate) const MIN_MISSING: usize = 256;

/// The transform must beat the dense fold count by this factor to engage.
///
/// A fold is not a constant-cost unit across the two arms: the dense executor
/// folds long contiguous source rows with prepared factors and a tuned
/// controller, while the transform's folds are short stripe passes over
/// scratch rows, several of them dependent. Requiring a 2x paper margin is the
/// cheapest way to keep the arm out of the region where its better fold count
/// does not survive contact with the memory system.
const FOLD_MARGIN: u64 = 2;

/// Hard cap on how far the covering exponent range may exceed `m`.
///
/// The selected exponents are normally the smallest available and therefore
/// contiguous; a deleted middle recovery volume opens a gap. Rows inside the
/// range but outside the selection are computed and discarded, and they also
/// occupy per-worker syndrome memory, so a badly scattered selection is capped
/// here as well as by the fold gate.
const MAX_RANGE_MULTIPLE: usize = 4;

/// Rows at or above which the closed-form consecutive solve beats the m×m
/// product enough to be worth its scratch.
///
/// Measured in `reedsolomon-rs`: the crossover against the explicit inverse is
/// around 600 rows (2.1x at 1024, 17x at 8192), and its setup is ~500x cheaper
/// than the Gauss-Jordan at 1024. Below this the product wins and needs no
/// scratch at all.
const CONSECUTIVE_SOLVE_MIN_ROWS: usize = 512;

/// Stripe length the arm aims for before memory forces it smaller.
const STRIPE_TARGET: usize = 16 * 1024;

/// Smallest stripe the arm will shrink to. The DFT only needs an even length;
/// this is where the per-stripe bookkeeping stops being worth it.
const STRIPE_FLOOR: usize = 256;

/// Alignment of bands and stripes.
const ALIGN: usize = 64;

/// Sources folded into one syndrome-combining destination per kernel call.
const SOLVE_BATCH: usize = 16;

/// In-process override of the arm, for tests and A/B runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransformArm {
    /// Never take the transform arm.
    Off,
    /// Take it wherever it is admissible, ignoring the win gate.
    On,
}

thread_local! {
    static ARM_OVERRIDE: std::cell::Cell<Option<TransformArm>> =
        const { std::cell::Cell::new(None) };
}

/// Force the repair transform arm on or off for repairs started on this thread.
///
/// `None` restores the automatic gate. This is an in-process, thread-local
/// switch: it takes precedence over `RARPAR_PAR2_TRANSFORM`, and it is read
/// once, on the thread that calls `execute_repair_with_options`.
pub fn set_transform_arm_override(value: Option<TransformArm>) {
    ARM_OVERRIDE.with(|cell| cell.set(value));
}

thread_local! {
    static ARM_STATS: std::cell::Cell<TransformArmStats> =
        const {
            std::cell::Cell::new(TransformArmStats {
                executed: 0,
                diverged: 0,
                consecutive_solves: 0,
            })
        };
}

/// What the transform arm did on this thread, since the process started.
///
/// Repairs are driven from the thread that calls
/// [`crate::repair::execute_repair_with_options`], so these counters are that
/// thread's own and never race. Exposed so a caller (or a test) can tell a
/// transform-arm repair from a dense one without parsing logs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TransformArmStats {
    /// Repairs completed on the transform arm.
    pub executed: u64,
    /// Repairs the arm abandoned after its probe diverged.
    pub diverged: u64,
    /// Repairs the arm chose the closed-form consecutive solve for, rather
    /// than the explicit inverse. Counted when the solver is picked, so it
    /// covers diverged runs too.
    pub consecutive_solves: u64,
}

/// This thread's [`TransformArmStats`].
pub fn transform_arm_stats() -> TransformArmStats {
    ARM_STATS.with(|cell| cell.get())
}

fn record_consecutive_solve() {
    ARM_STATS.with(|cell| {
        let mut stats = cell.get();
        stats.consecutive_solves += 1;
        cell.set(stats);
    });
}

fn record_executed() {
    ARM_STATS.with(|cell| {
        let mut stats = cell.get();
        stats.executed += 1;
        cell.set(stats);
    });
}

fn record_diverged() {
    ARM_STATS.with(|cell| {
        let mut stats = cell.get();
        stats.diverged += 1;
        cell.set(stats);
    });
}

// Corrupt the arm's own syndrome probe so the divergence path can be tested.
#[cfg(test)]
thread_local! {
    static PROBE_FAULT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Make the next band's probe disagree with the transform, once.
#[cfg(test)]
fn take_probe_fault() -> bool {
    PROBE_FAULT.with(|cell| cell.replace(false))
}

#[cfg(test)]
thread_local! {
    static SOLVE_FAULT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Corrupt the next band's solved output, once.
#[cfg(test)]
fn take_solve_fault() -> bool {
    SOLVE_FAULT.with(|cell| cell.replace(false))
}

/// The current thread's transform-arm override, if any.
pub fn transform_arm_override() -> Option<TransformArm> {
    ARM_OVERRIDE.with(|cell| cell.get())
}

fn arm_setting() -> Option<TransformArm> {
    if let Some(value) = transform_arm_override() {
        return Some(value);
    }
    match std::env::var("RARPAR_PAR2_TRANSFORM").ok().as_deref() {
        Some("0") => Some(TransformArm::Off),
        Some("1") => Some(TransformArm::On),
        _ => None,
    }
}

/// Whether this build can engage a GPU repair arm at all.
///
/// The transform arm is a CPU alternative and is only offered where the CPU
/// dense path would have run. Ranking it against a live GPU session would mean
/// re-deciding GPU policy, so it declines outright in any build that carries a
/// GPU backend. Default builds (and every shipped `rarpar` artifact) carry
/// none, so the arm is live there.
const GPU_ARM_POSSIBLE: bool = cfg!(any(
    all(
        feature = "metal",
        target_os = "macos",
        target_arch = "aarch64"
    ),
    feature = "wgpu"
));

/// What `try_execute` did.
#[derive(Debug)]
pub(crate) enum TransformOutcome {
    /// The repair is complete; every missing slice has been written.
    Executed,
    /// The arm did not run. Nothing was written; run the dense path.
    Declined(&'static str),
    /// The arm ran, diverged from its own probe and stopped. Bands already
    /// written are stale but harmless — rerun the dense path over the whole
    /// plan, which rewrites them from untouched sources.
    Diverged,
}

/// The stripe-granular half of the repair: syndrome rows in, missing rows out.
///
/// This is the seam a Forney-style O(m)-folds solver drops into. An
/// implementation sees one stripe of every syndrome row and must fill one
/// stripe of every missing row, in `missing_global_indices` order; it may
/// assume every region has the same, even length and that the destinations are
/// pairwise disjoint and uninitialised.
pub(crate) trait StripeSolver: Send + Sync {
    /// Working bytes one worker needs at this stripe length.
    fn scratch_bytes(&self, stripe_len: usize) -> usize;

    /// Turn one stripe of syndromes into one stripe of every missing slice.
    ///
    /// `syndromes` is the transform's whole output buffer for the stripe —
    /// `range_len` rows of `stripe_len` bytes — and `row_offsets[r]` is where
    /// the `r`-th selected recovery exponent's row sits in it. The buffer may
    /// be overwritten. `outputs[c]` receives missing slice `c`, in
    /// `missing_global_indices` order.
    fn solve_stripe(
        &self,
        syndromes: &mut [u8],
        row_offsets: &[usize],
        stripe_len: usize,
        scratch: &mut [u8],
        outputs: &mut [&mut [u8]],
        cancelled: &dyn Fn() -> bool,
    ) -> Result<()>;
}

/// Apply `A^-1` as an explicit m×m stripe-wise product.
///
/// `m^2` folds, no scratch, and no requirement on the exponents at all. This
/// is the arm's fallback solver and the oracle its faster sibling is checked
/// against.
struct DenseInverseSolver<'a> {
    /// `A^-1`, `m` rows by `m` columns — `RepairPlan::decode_matrix`.
    inverse: &'a matrix::Matrix,
}

impl StripeSolver for DenseInverseSolver<'_> {
    fn scratch_bytes(&self, _stripe_len: usize) -> usize {
        0
    }

    fn solve_stripe(
        &self,
        syndromes: &mut [u8],
        row_offsets: &[usize],
        stripe_len: usize,
        _scratch: &mut [u8],
        outputs: &mut [&mut [u8]],
        cancelled: &dyn Fn() -> bool,
    ) -> Result<()> {
        debug_assert_eq!(outputs.len(), self.inverse.rows);
        debug_assert_eq!(row_offsets.len(), self.inverse.cols);
        let syndromes: &[u8] = syndromes;
        let mut batch: Vec<FactorSrc<'_>> = Vec::with_capacity(SOLVE_BATCH);
        for (row, out) in outputs.iter_mut().enumerate() {
            if row.is_multiple_of(64) && cancelled() {
                return Err(Par2Error::Cancelled);
            }
            out.fill(0);
            let factors = self.inverse.row(row);
            batch.clear();
            for (column, &factor) in factors.iter().enumerate() {
                if factor == 0 {
                    continue;
                }
                batch.push(FactorSrc {
                    factor,
                    src: &syndromes[row_offsets[column] * stripe_len..][..stripe_len],
                });
                if batch.len() == SOLVE_BATCH {
                    crate::gf_simd::mul_acc_input_batch(out, &batch);
                    batch.clear();
                }
            }
            if !batch.is_empty() {
                crate::gf_simd::mul_acc_input_batch(out, &batch);
                batch.clear();
            }
        }
        Ok(())
    }
}

/// The closed-form solve for a consecutive exponent run.
///
/// [`ConsecutiveSolvePlan`] replaces the m×m product with a locator
/// correlation and a Forney evaluation — `O(m)` folds per unknown instead of
/// `m`, and a setup that costs a fraction of the Gauss-Jordan the inverse
/// needs. It only exists for `e0, e0+1, ...`, and it buys that speed with a
/// large per-stripe scratch, so both the exponent shape and the memory
/// contract have to admit it before the arm picks it up.
struct ConsecutiveSolver {
    plan: ConsecutiveSolvePlan,
}

impl StripeSolver for ConsecutiveSolver {
    fn scratch_bytes(&self, stripe_len: usize) -> usize {
        self.plan.scratch_bytes(stripe_len)
    }

    fn solve_stripe(
        &self,
        syndromes: &mut [u8],
        row_offsets: &[usize],
        stripe_len: usize,
        scratch: &mut [u8],
        outputs: &mut [&mut [u8]],
        cancelled: &dyn Fn() -> bool,
    ) -> Result<()> {
        let rows = self.plan.rows();
        debug_assert_eq!(outputs.len(), rows);
        // A consecutive selection lands on the first `rows` rows of the
        // transform's range in order, which is exactly the contiguous buffer
        // the solve wants; the arm only builds this solver in that case.
        debug_assert!(row_offsets.iter().copied().eq(0..rows));
        self.plan
            .solve_stripe(
                &mut syndromes[..rows * stripe_len],
                stripe_len,
                scratch,
                cancelled,
            )
            .map_err(|error| match error {
                SolveError::Cancelled => Par2Error::Cancelled,
                other => Par2Error::ReedSolomonError {
                    reason: format!("repair transform solve failed: {other}"),
                },
            })?;
        let solved: &[u8] = syndromes;
        for (row, out) in outputs.iter_mut().enumerate() {
            out.copy_from_slice(&solved[row * stripe_len..][..stripe_len]);
        }
        Ok(())
    }
}

/// The band/stripe geometry and the arenas it implies.
#[derive(Debug, Clone, Copy)]
pub(crate) struct BandGeometry {
    pub(crate) band: usize,
    pub(crate) stripe: usize,
    pub(crate) passes: usize,
    pub(crate) workers: usize,
    pub(crate) arena_bytes: usize,
}

/// Solve the memory contract: the most workers, at the largest stripe and the
/// largest band, that fit `budget` once every arena is summed.
///
/// Returns `None` when no admissible geometry exists — the caller then either
/// tries a solver with a smaller scratch or takes the dense path. `range_len`
/// is the covering exponent range, `rows` the missing count, `present` the
/// available source count.
#[allow(clippy::too_many_arguments)]
pub(crate) fn plan_geometry(
    slice_size: usize,
    present: usize,
    rows: usize,
    range_len: usize,
    max_workers: usize,
    plan_bytes: usize,
    per_worker_bytes: &dyn Fn(usize) -> usize,
    budget: usize,
) -> Option<BandGeometry> {
    let free = budget.checked_sub(plan_bytes)?;
    // Per band, every present slice, every output row, and the two probe rows
    // hold one band's bytes.
    let per_band_byte = present.checked_add(rows)?.checked_add(2)?;

    let mut workers = max_workers.max(1);
    loop {
        let mut stripe = STRIPE_TARGET.min(slice_size.next_multiple_of(ALIGN));
        stripe = (stripe / ALIGN).max(1) * ALIGN;
        loop {
            // One spare per-worker arena covers the single short tail stripe a
            // slice length that is not a multiple of the stripe leaves behind.
            let per_worker = range_len
                .checked_mul(stripe)
                .and_then(|syndrome| syndrome.checked_add(per_worker_bytes(stripe)));
            if let Some(per_worker) = per_worker
                && let Some(worker_total) = per_worker
                    .checked_mul(workers)
                    .and_then(|total| total.checked_add(per_worker))
                && let Some(band_budget) = free.checked_sub(worker_total)
            {
                let band = ((band_budget / per_band_byte) / stripe) * stripe;
                let band = band.min(slice_size.next_multiple_of(stripe));
                if band >= stripe && band >= MIN_BAND.min(slice_size) {
                    let passes = slice_size.div_ceil(band);
                    if passes <= MAX_PASSES {
                        return Some(BandGeometry {
                            band,
                            stripe,
                            passes,
                            workers,
                            arena_bytes: plan_bytes + worker_total + band * per_band_byte,
                        });
                    }
                }
            }
            if stripe <= STRIPE_FLOOR {
                break;
            }
            stripe = (stripe / 2).next_multiple_of(ALIGN).max(STRIPE_FLOOR);
        }
        if workers == 1 {
            return None;
        }
        workers = (workers / 2).max(1);
    }
}

/// Pick the solver and the geometry together: the two are one decision,
/// because a solver's per-stripe scratch is part of the memory contract.
///
/// The closed-form solve is tried first when the exponents are consecutive and
/// the row count is past its crossover against the m×m product; if its scratch
/// cannot be afforded, the explicit inverse — which needs none — is tried at
/// the same budget before the arm gives up.
fn choose_solver<'a>(
    plan: &'a RepairPlan,
    dft: &DftPlan,
    range_len: usize,
    budget: usize,
    workers: usize,
) -> Option<(Box<dyn StripeSolver + 'a>, BandGeometry, &'static str)> {
    let rows = plan.missing_slices.len();
    let present = plan.available_input_global_indices.len();
    let slice_size = plan.slice_size as usize;
    let geometry_for = |solver: &dyn StripeSolver| {
        plan_geometry(
            slice_size,
            present,
            rows,
            range_len,
            workers,
            dft.plan_bytes(),
            // A worker holds the transform's scratch and the solver's at once.
            &|stripe| {
                dft.scratch_bytes(stripe)
                    .saturating_add(solver.scratch_bytes(stripe))
            },
            budget,
        )
    };

    if rows >= CONSECUTIVE_SOLVE_MIN_ROWS && range_len == rows {
        let missing_logs: Vec<u16> = plan
            .missing_global_indices
            .iter()
            .map(|&global| gf::log(plan.constants[global]))
            .collect();
        match ConsecutiveSolvePlan::build_for_exponents(&missing_logs, &plan.recovery_exponents) {
            Ok(consecutive) => {
                let solver = ConsecutiveSolver { plan: consecutive };
                if let Some(geometry) = geometry_for(&solver) {
                    record_consecutive_solve();
                    return Some((Box::new(solver), geometry, "consecutive"));
                }
                debug!(
                    budget,
                    "the consecutive solve does not fit the memory limit; trying the inverse"
                );
            }
            Err(SolveError::NonConsecutive) => {}
            Err(error) => {
                debug!(%error, "the consecutive solve refused the selection");
            }
        }
    }

    let solver = DenseInverseSolver {
        inverse: &plan.decode_matrix,
    };
    let geometry = geometry_for(&solver)?;
    Some((Box::new(solver), geometry, "inverse"))
}

/// Try to run the repair on the transform arm.
///
/// `Ok(TransformOutcome::Declined)` and `Ok(TransformOutcome::Diverged)` both
/// mean the caller must run the dense path; `Declined` additionally guarantees
/// nothing was written. Errors (cancellation, I/O, write failures) are the
/// caller's to propagate — they are not arm-specific and the dense path would
/// hit them too.
pub(crate) fn try_execute(
    plan: &RepairPlan,
    par2_set: &Par2FileSet,
    file_access: &mut dyn FileAccess,
    options: &RepairOptions,
    budget: usize,
) -> Result<TransformOutcome> {
    let setting = arm_setting();
    if setting == Some(TransformArm::Off) {
        return Ok(TransformOutcome::Declined("forced off"));
    }
    if GPU_ARM_POSSIBLE {
        return Ok(TransformOutcome::Declined("GPU arm is compiled in"));
    }

    let rows = plan.missing_slices.len();
    let present = plan.available_input_global_indices.len();
    let slice_size = plan.slice_size as usize;
    if setting != Some(TransformArm::On) && rows < MIN_MISSING {
        return Ok(TransformOutcome::Declined("below the missing-slice floor"));
    }
    if rows == 0 || present == 0 || slice_size == 0 {
        return Ok(TransformOutcome::Declined("degenerate shape"));
    }
    if plan.decode_matrix.rows != rows || plan.decode_matrix.cols != rows {
        return Ok(TransformOutcome::Declined("decode matrix is not m x m"));
    }

    let Some(&lowest) = plan.recovery_exponents.iter().min() else {
        return Ok(TransformOutcome::Declined("no recovery exponents"));
    };
    let highest = *plan
        .recovery_exponents
        .iter()
        .max()
        .expect("a non-empty selection has a maximum");
    let Some(range_len) = (highest as usize)
        .checked_sub(lowest as usize)
        .map(|d| d + 1)
    else {
        return Ok(TransformOutcome::Declined("exponent range underflow"));
    };
    if highest >= 65535 {
        return Ok(TransformOutcome::Declined("exponent outside the transform"));
    }
    if range_len > rows.saturating_mul(MAX_RANGE_MULTIPLE) {
        return Ok(TransformOutcome::Declined(
            "exponent selection too scattered",
        ));
    }

    let slots: Vec<u16> = plan
        .available_input_global_indices
        .iter()
        .map(|&global| gf::log(plan.constants[global]))
        .collect();
    let dft = match DftPlan::build(&slots, lowest..highest + 1) {
        Ok(dft) => dft,
        Err(error) => {
            debug!(%error, "repair transform plan refused the shape");
            return Ok(TransformOutcome::Declined("transform plan refused"));
        }
    };

    let transform_folds = dft
        .region_folds()
        .saturating_add((rows as u64).saturating_mul(rows as u64));
    let dense_folds = (rows as u64).saturating_mul((present + rows) as u64);
    if setting != Some(TransformArm::On)
        && transform_folds.saturating_mul(FOLD_MARGIN) > dense_folds
    {
        debug!(
            transform_folds,
            dense_folds, "repair transform arm does not beat the dense path by enough"
        );
        return Ok(TransformOutcome::Declined("fold margin not met"));
    }

    let workers = rayon::current_num_threads().max(1);
    let Some((solver, geometry, solver_name)) =
        choose_solver(plan, &dft, range_len, budget, workers)
    else {
        info!(
            budget,
            present,
            rows,
            "repair transform arm does not fit the memory limit; taking the dense path"
        );
        return Ok(TransformOutcome::Declined("memory limit too small"));
    };

    info!(
        missing_slices = rows,
        present_slices = present,
        solver = solver_name,
        band_bytes = geometry.band,
        stripe_bytes = geometry.stripe,
        passes = geometry.passes,
        workers = geometry.workers,
        arena_bytes = geometry.arena_bytes,
        transform_folds,
        dense_folds,
        exponent_range = range_len,
        "repairing with the transform arm"
    );

    run(
        plan,
        par2_set,
        file_access,
        options,
        &dft,
        solver.as_ref(),
        geometry,
        lowest,
    )
}

/// One worker's private buffers. Sized once from the geometry; the short tail
/// stripe is the only case that reallocates, and only its DFT scratch.
struct Worker {
    syndromes: Vec<u8>,
    scratch: DftScratch,
    solve_scratch: Vec<u8>,
}

#[allow(clippy::too_many_arguments)]
fn run(
    plan: &RepairPlan,
    par2_set: &Par2FileSet,
    file_access: &mut dyn FileAccess,
    options: &RepairOptions,
    dft: &DftPlan,
    solver: &dyn StripeSolver,
    geometry: BandGeometry,
    first_exponent: u32,
) -> Result<TransformOutcome> {
    let rows = plan.missing_slices.len();
    let present = plan.available_input_global_indices.len();
    let slice_size = plan.slice_size as usize;
    let range_len = dft.output_count();
    let band = geometry.band;
    let stripe = geometry.stripe;

    let write_targets = build_write_targets(plan, par2_set)?;
    let mut recovery_files: HashMap<PathBuf, File> = HashMap::new();
    let mut source_reader: Option<StreamSourceReader> = None;

    // Row `r` of `syndrome_row` is the position of recovery exponent `r` inside
    // the transform's contiguous output range.
    let syndrome_row: Vec<usize> = plan
        .recovery_exponents
        .iter()
        .map(|&exponent| (exponent - first_exponent) as usize)
        .collect();

    let mut staging = vec![0u8; present.checked_mul(band).expect("band arena fits")];
    let mut output = vec![0u8; rows.checked_mul(band).expect("band arena fits")];
    let mut probe_seen = vec![0u8; band];
    let mut probe_expect = vec![0u8; band];

    let total_bytes = slice_size as u64;
    let mut band_index = 0usize;
    let mut band_start = 0usize;
    while band_start < slice_size {
        check_cancel(options)?;
        let band_len = band.min(slice_size - band_start);

        for source in 0..present {
            if source % 64 == 0 {
                check_cancel(options)?;
            }
            read_stream_source_chunk(
                plan,
                par2_set,
                file_access,
                &mut recovery_files,
                &mut source_reader,
                present,
                source,
                band_start,
                &mut staging[source * band..source * band + band_len],
            )?;
        }
        for row in 0..rows {
            if row % 64 == 0 {
                check_cancel(options)?;
            }
            read_stream_source_chunk(
                plan,
                par2_set,
                file_access,
                &mut recovery_files,
                &mut source_reader,
                present,
                present + row,
                band_start,
                &mut output[row * band..row * band + band_len],
            )?;
        }

        // The probe exponent rotates so a systematic error in one row cannot
        // hide behind a band boundary.
        let probe = band_index % rows;
        probe_expect[..band_len].copy_from_slice(&output[probe * band..probe * band + band_len]);

        transform_band(
            dft,
            solver,
            options,
            &staging,
            &mut output,
            &mut probe_seen[..band_len],
            &syndrome_row,
            TransformBand {
                present,
                rows,
                range_len,
                band,
                band_len,
                stripe,
                workers: geometry.workers,
                probe,
            },
        )?;

        #[cfg(test)]
        if take_probe_fault() {
            probe_seen[0] ^= 0xFF;
        }

        let factors: Vec<u16> = plan
            .available_input_global_indices
            .iter()
            .map(|&global| gf::pow(plan.constants[global], plan.recovery_exponents[probe]))
            .collect();
        dense_row(
            &staging,
            band,
            band_len,
            &factors,
            &mut probe_expect[..band_len],
        );
        if probe_expect[..band_len] != probe_seen[..band_len] {
            warn!(
                band = band_index,
                probe_exponent = plan.recovery_exponents[probe],
                "repair transform arm diverged from its dense probe; falling back"
            );
            record_diverged();
            return Ok(TransformOutcome::Diverged);
        }

        // The probe above vouches for the transform only. The solve gets its
        // own: re-encoding the repaired rows at the probe exponent must give
        // the dense syndrome back, so XORing that re-encoding over a row equal
        // to it has to leave zeros. `m` folds per band, and no solver shares
        // any of it.
        #[cfg(test)]
        if take_solve_fault() {
            output[0] ^= 0xFF;
        }
        let factors: Vec<u16> = plan
            .missing_global_indices
            .iter()
            .map(|&global| gf::pow(plan.constants[global], plan.recovery_exponents[probe]))
            .collect();
        dense_row(&output, band, band_len, &factors, &mut probe_seen[..band_len]);
        if probe_seen[..band_len].iter().any(|&byte| byte != 0) {
            warn!(
                band = band_index,
                probe_exponent = plan.recovery_exponents[probe],
                "repair transform arm's solve does not re-encode to its syndrome; falling back"
            );
            record_diverged();
            return Ok(TransformOutcome::Diverged);
        }

        check_cancel(options)?;
        for (row, target) in write_targets.iter().enumerate() {
            let write_offset = target.offset + band_start as u64;
            let remaining = target.file_end.saturating_sub(write_offset);
            let write_len = remaining.min(band_len as u64) as usize;
            if write_len == 0 {
                continue;
            }
            file_access
                .write_file_range(
                    &target.file_id,
                    write_offset,
                    &output[row * band..row * band + write_len],
                )
                .map_err(|error| Par2Error::RepairWriteFailed {
                    filename: target.filename.clone(),
                    offset: write_offset,
                    source: error,
                })?;
        }

        band_start += band_len;
        band_index += 1;
        if let Some(ref progress) = options.progress {
            progress(ProgressUpdate {
                stage: ProgressStage::Repairing,
                current: band_index.min(u32::MAX as usize) as u32,
                total: geometry.passes.min(u32::MAX as usize) as u32,
                bytes_processed: band_start as u64,
                total_bytes: Some(total_bytes),
                phase: ProgressPhase::Whole,
            });
        }
    }

    info!(missing_slices = rows, "transform-arm repair complete");
    record_executed();
    Ok(TransformOutcome::Executed)
}

/// Shape of one band, passed whole so the stripe loop keeps one argument list.
#[derive(Clone, Copy)]
struct TransformBand {
    present: usize,
    rows: usize,
    range_len: usize,
    band: usize,
    band_len: usize,
    stripe: usize,
    workers: usize,
    probe: usize,
}

/// Transform and solve one staged band, in place over `output`.
///
/// `output` arrives holding each selected recovery block's bytes for the band
/// and leaves holding each missing slice's repaired bytes. `probe_seen`
/// receives the transform's own syndrome row for the probe exponent.
#[allow(clippy::too_many_arguments)]
fn transform_band(
    dft: &DftPlan,
    solver: &dyn StripeSolver,
    options: &RepairOptions,
    staging: &[u8],
    output: &mut [u8],
    probe_seen: &mut [u8],
    syndrome_row: &[usize],
    shape: TransformBand,
) -> Result<()> {
    let stripes = shape.band_len.div_ceil(shape.stripe);
    let output_base = output.as_mut_ptr() as usize;
    let probe_base = probe_seen.as_mut_ptr() as usize;
    let next = AtomicUsize::new(0);
    let failure: std::sync::Mutex<Option<Par2Error>> = std::sync::Mutex::new(None);
    let cancelled = || {
        options
            .cancel
            .as_ref()
            .is_some_and(|token| token.is_cancelled())
    };

    rayon::scope(|scope| {
        for _ in 0..shape.workers {
            let next = &next;
            let failure = &failure;
            let cancelled = &cancelled;
            scope.spawn(move |_| {
                let mut worker = Worker {
                    syndromes: vec![0u8; shape.range_len * shape.stripe],
                    scratch: DftScratch::new(dft, shape.stripe),
                    solve_scratch: vec![0u8; solver.scratch_bytes(shape.stripe)],
                };
                let mut sources: Vec<&[u8]> = Vec::with_capacity(shape.present);
                loop {
                    let stripe_index = next.fetch_add(1, Ordering::Relaxed);
                    if stripe_index >= stripes {
                        return;
                    }
                    if failure.lock().expect("stripe failure lock").is_some() {
                        return;
                    }
                    let offset = stripe_index * shape.stripe;
                    let len = shape.stripe.min(shape.band_len - offset);
                    if worker.scratch.stripe_len() != len {
                        worker.scratch = DftScratch::new(dft, len);
                        worker.solve_scratch = vec![0u8; solver.scratch_bytes(len)];
                    }

                    let syndromes = &mut worker.syndromes[..shape.range_len * len];
                    syndromes.fill(0);
                    // SAFETY: stripes are disjoint byte ranges of every row, and
                    // exactly one worker owns `stripe_index` at a time.
                    for (row, &position) in syndrome_row.iter().enumerate() {
                        let src = unsafe {
                            std::slice::from_raw_parts(
                                (output_base as *const u8).add(row * shape.band + offset),
                                len,
                            )
                        };
                        syndromes[position * len..position * len + len].copy_from_slice(src);
                    }

                    sources.clear();
                    for source in 0..shape.present {
                        sources.push(&staging[source * shape.band + offset..][..len]);
                    }
                    if let Err(error) =
                        dft.transform_stripe(&sources, syndromes, &mut worker.scratch, cancelled)
                    {
                        let mapped = match error {
                            TransformError::Cancelled => Par2Error::Cancelled,
                            other => Par2Error::ReedSolomonError {
                                reason: format!("repair transform stripe failed: {other}"),
                            },
                        };
                        *failure.lock().expect("stripe failure lock") = Some(mapped);
                        return;
                    }

                    let probe_position = syndrome_row[shape.probe];
                    // SAFETY: one worker owns this stripe of the probe row.
                    let probe_dst = unsafe {
                        std::slice::from_raw_parts_mut((probe_base as *mut u8).add(offset), len)
                    };
                    probe_dst.copy_from_slice(
                        &syndromes[probe_position * len..probe_position * len + len],
                    );

                    let mut output_refs: Vec<&mut [u8]> = Vec::with_capacity(shape.rows);
                    for row in 0..shape.rows {
                        // SAFETY: as above — disjoint stripe of a distinct row.
                        output_refs.push(unsafe {
                            std::slice::from_raw_parts_mut(
                                (output_base as *mut u8).add(row * shape.band + offset),
                                len,
                            )
                        });
                    }
                    if let Err(error) = solver.solve_stripe(
                        syndromes,
                        syndrome_row,
                        len,
                        &mut worker.solve_scratch,
                        &mut output_refs,
                        cancelled,
                    ) {
                        *failure.lock().expect("stripe failure lock") = Some(error);
                        return;
                    }
                }
            });
        }
    });

    match failure.into_inner().expect("stripe failure lock") {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// XOR one dense syndrome row over the staged band into `dst`.
///
/// `dst` arrives holding `R_e` and leaves holding `S_e`. This is the probe's
/// oracle: the same sum the transform computes, with the shared code path
/// being only the multiply-accumulate kernel.
fn dense_row(staging: &[u8], band: usize, band_len: usize, factors: &[u16], dst: &mut [u8]) {
    debug_assert_eq!(dst.len(), band_len);
    let chunk = ALIGN * 64;
    dst.par_chunks_mut(chunk).enumerate().for_each(|(at, out)| {
        let offset = at * chunk;
        let mut batch: Vec<FactorSrc<'_>> = Vec::with_capacity(SOLVE_BATCH);
        for (source, &factor) in factors.iter().enumerate() {
            if factor == 0 {
                continue;
            }
            batch.push(FactorSrc {
                factor,
                src: &staging[source * band + offset..][..out.len()],
            });
            if batch.len() == SOLVE_BATCH {
                crate::gf_simd::mul_acc_input_batch(out, &batch);
                batch.clear();
            }
        }
        if !batch.is_empty() {
            crate::gf_simd::mul_acc_input_batch(out, &batch);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geometry_declines_a_budget_that_cannot_buy_a_band() {
        let geometry = plan_geometry(
            262_144,
            14_000,
            4_096,
            4_096,
            8,
            1 << 20,
            &|stripe| 1275 * stripe,
            8 * 1024 * 1024,
        );
        assert!(geometry.is_none(), "{geometry:?}");
    }

    #[test]
    fn geometry_stays_inside_the_budget_it_is_given() {
        for budget in [
            64 * 1024 * 1024,
            256 * 1024 * 1024,
            1024 * 1024 * 1024,
            4096 * 1024 * 1024,
        ] {
            let Some(geometry) = plan_geometry(
                262_144,
                14_000,
                2_048,
                2_048,
                10,
                512 * 1024,
                &|stripe| 1275 * stripe,
                budget,
            ) else {
                continue;
            };
            assert!(geometry.arena_bytes <= budget, "{geometry:?} for {budget}");
            assert!(
                geometry.band.is_multiple_of(geometry.stripe),
                "{geometry:?}"
            );
            assert!(geometry.band.is_multiple_of(ALIGN), "{geometry:?}");
            assert!(geometry.stripe.is_multiple_of(ALIGN), "{geometry:?}");
            assert!(geometry.band >= MIN_BAND, "{geometry:?}");
            assert!(geometry.passes <= MAX_PASSES, "{geometry:?}");
        }
    }

    #[test]
    fn geometry_declines_when_the_band_would_need_too_many_passes() {
        // A slice far larger than the budget can band: the pass cap, not the
        // band floor, is what refuses it.
        let geometry = plan_geometry(
            64 * 1024 * 1024,
            14_000,
            2_048,
            2_048,
            10,
            512 * 1024,
            &|stripe| 1275 * stripe,
            64 * 1024 * 1024,
        );
        assert!(geometry.is_none(), "{geometry:?}");
    }

    /// Damage `slices` of a single-file set, repair it with the arm in the
    /// given state, and return the restored bytes.
    fn repair_once(
        arm: Option<TransformArm>,
        file_data: &[u8],
        slice_size: u64,
        recovery: usize,
        damaged: &[usize],
        fault: bool,
    ) -> (Vec<u8>, TransformArmStats) {
        let (set, file_id) =
            crate::repair::tests::setup_repairable_set(file_data, slice_size, recovery);
        let mut broken = file_data.to_vec();
        for &slice in damaged {
            let start = slice * slice_size as usize;
            let end = (start + slice_size as usize).min(broken.len());
            broken[start..end].fill(0xA5);
        }
        let mut access = crate::verify::MemoryFileAccess::new();
        access.add_file(file_id, broken);

        let verification = crate::verify::verify_all(&set, &access);
        let plan = crate::repair::plan_repair(&set, &verification).expect("plan");

        set_transform_arm_override(arm);
        #[cfg(test)]
        PROBE_FAULT.with(|cell| cell.set(fault));
        let before = transform_arm_stats();
        crate::repair::execute_repair(&plan, &set, &mut access).expect("repair");
        let after = transform_arm_stats();
        set_transform_arm_override(None);
        PROBE_FAULT.with(|cell| cell.set(false));

        let restored = crate::verify::FileAccess::read_file(&access, &file_id).expect("read back");
        (
            restored,
            TransformArmStats {
                executed: after.executed - before.executed,
                diverged: after.diverged - before.diverged,
                consecutive_solves: after.consecutive_solves - before.consecutive_solves,
            },
        )
    }

    fn noise(len: usize, seed: u64) -> Vec<u8> {
        let mut state = seed | 1;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 25) as u8
            })
            .collect()
    }

    #[test]
    fn the_arm_is_bit_identical_to_the_dense_path() {
        // Slice sizes that are and are not multiples of 64, a partial last
        // slice, and a spread of damage patterns.
        for (slice_size, slices, damaged) in [
            (64u64, 16usize, vec![0usize, 3, 9]),
            (68, 12, vec![1, 2, 3, 4]),
            (256, 9, vec![0, 8]),
            (4, 20, vec![5, 6, 7]),
        ] {
            let full = slice_size as usize * slices;
            // A short final slice: the file stops before its last slice ends.
            let data = noise(full - slice_size as usize / 2, 0x51 + slice_size);
            let recovery = damaged.len() + 2;
            let (dense, dense_stats) = repair_once(
                Some(TransformArm::Off),
                &data,
                slice_size,
                recovery,
                &damaged,
                false,
            );
            let (transform, transform_stats) = repair_once(
                Some(TransformArm::On),
                &data,
                slice_size,
                recovery,
                &damaged,
                false,
            );
            assert_eq!(dense_stats.executed, 0, "slice_size={slice_size}");
            assert_eq!(transform_stats.executed, 1, "slice_size={slice_size}");
            assert_eq!(dense, data, "dense: slice_size={slice_size}");
            assert_eq!(transform, data, "transform: slice_size={slice_size}");
        }
    }

    #[test]
    fn a_non_contiguous_exponent_selection_still_matches() {
        // Delete a middle recovery volume: the selection keeps its count but
        // its covering range is now wider than the selection itself.
        let slice_size = 64u64;
        let data = noise(64 * 20, 0xBEEF);
        let damaged = [2usize, 5, 11];
        let (set, file_id) = crate::repair::tests::setup_repairable_set(&data, slice_size, 8);
        let mut set = set;
        set.recovery_slices.remove(&1);
        set.recovery_slices.remove(&2);

        let mut restored = Vec::new();
        for arm in [TransformArm::Off, TransformArm::On] {
            let mut broken = data.clone();
            for &slice in &damaged {
                broken[slice * 64..slice * 64 + 64].fill(0x5A);
            }
            let mut access = crate::verify::MemoryFileAccess::new();
            access.add_file(file_id, broken);
            let verification = crate::verify::verify_all(&set, &access);
            let plan = crate::repair::plan_repair(&set, &verification).expect("plan");
            assert!(
                plan.recovery_exponents.iter().max().unwrap()
                    - plan.recovery_exponents.iter().min().unwrap()
                    > 2,
                "the gap must survive selection: {:?}",
                plan.recovery_exponents
            );
            set_transform_arm_override(Some(arm));
            let before = transform_arm_stats();
            crate::repair::execute_repair(&plan, &set, &mut access).expect("repair");
            let after = transform_arm_stats();
            set_transform_arm_override(None);
            assert_eq!(
                after.executed - before.executed,
                u64::from(arm == TransformArm::On),
                "{arm:?}"
            );
            restored.push(crate::verify::FileAccess::read_file(&access, &file_id).unwrap());
        }
        assert_eq!(restored[0], data);
        assert_eq!(restored[1], data);
    }

    #[test]
    fn a_probe_mismatch_abandons_the_arm_and_the_dense_path_finishes_the_repair() {
        let slice_size = 64u64;
        let data = noise(64 * 16, 0xC0FFEE);
        let damaged = [1usize, 4, 7];
        let (restored, stats) =
            repair_once(Some(TransformArm::On), &data, slice_size, 6, &damaged, true);
        assert_eq!(stats.diverged, 1, "the injected fault must be caught");
        assert_eq!(
            stats.executed, 0,
            "a diverged arm must not claim the repair"
        );
        assert_eq!(
            restored, data,
            "the dense rerun must still restore the file"
        );
    }

    #[test]
    fn a_wrong_solve_abandons_the_arm_and_the_dense_path_finishes_the_repair() {
        // The syndrome probe cannot see a solver that turns right syndromes
        // into wrong slices; the re-encode check has to.
        let slice_size = 64u64;
        let data = noise(64 * 16, 0xBADC0DE);
        let damaged = [0usize, 5, 11];
        SOLVE_FAULT.with(|cell| cell.set(true));
        let (restored, stats) =
            repair_once(Some(TransformArm::On), &data, slice_size, 6, &damaged, false);
        SOLVE_FAULT.with(|cell| cell.set(false));
        assert_eq!(stats.diverged, 1, "the corrupted solve must be caught");
        assert_eq!(stats.executed, 0);
        assert_eq!(restored, data);
    }

    #[test]
    fn a_cancelled_token_stops_the_arm_mid_band() {
        // `transform_band` is the arm's inner loop: a token cancelled while a
        // band is in flight must surface as `Cancelled`, not as a wrong answer.
        let slots: Vec<u16> = (1..=32u16).map(gf::log).collect();
        let dft = DftPlan::build(&slots, 0..4).expect("plan");
        let solver = DenseInverseSolver {
            inverse: &matrix::Matrix::identity(4),
        };
        let cancel = crate::types::CancellationToken::new();
        cancel.cancel();
        let options = RepairOptions {
            cancel: Some(cancel),
            progress: None,
            memory_limit: None,
        };
        let staging = vec![0u8; slots.len() * 128];
        let mut output = vec![0u8; 4 * 128];
        let mut probe = vec![0u8; 128];
        let error = transform_band(
            &dft,
            &solver,
            &options,
            &staging,
            &mut output,
            &mut probe,
            &[0, 1, 2, 3],
            TransformBand {
                present: slots.len(),
                rows: 4,
                range_len: 4,
                band: 128,
                band_len: 128,
                stripe: 128,
                workers: 2,
                probe: 0,
            },
        )
        .expect_err("a cancelled token must stop the band");
        assert!(matches!(error, Par2Error::Cancelled), "{error:?}");
    }

    #[test]
    fn a_tiny_memory_limit_still_repairs_bit_identically() {
        // Force many passes: the band shrinks to the floor and the slice is
        // walked in pieces.
        let slice_size = 4096u64;
        let data = noise(4096 * 12, 0x1234);
        let damaged = [0usize, 5, 9];
        let (set, file_id) = crate::repair::tests::setup_repairable_set(&data, slice_size, 6);

        let mut restored = Vec::new();
        for (arm, limit) in [
            (TransformArm::Off, None),
            (TransformArm::On, Some(1024 * 1024)),
        ] {
            let mut broken = data.clone();
            for &slice in &damaged {
                broken[slice * 4096..slice * 4096 + 4096].fill(0x11);
            }
            let mut access = crate::verify::MemoryFileAccess::new();
            access.add_file(file_id, broken);
            let verification = crate::verify::verify_all(&set, &access);
            let plan = crate::repair::plan_repair(&set, &verification).expect("plan");
            set_transform_arm_override(Some(arm));
            let before = transform_arm_stats();
            crate::repair::execute_repair_with_options(
                &plan,
                &set,
                &mut access,
                &RepairOptions {
                    cancel: None,
                    progress: None,
                    memory_limit: limit,
                },
            )
            .expect("repair");
            let after = transform_arm_stats();
            set_transform_arm_override(None);
            assert_eq!(
                after.executed - before.executed,
                u64::from(arm == TransformArm::On)
            );
            restored.push(crate::verify::FileAccess::read_file(&access, &file_id).unwrap());
        }
        assert_eq!(restored[0], data);
        assert_eq!(restored[1], data);
    }

    #[test]
    fn a_limit_too_small_for_a_band_falls_back_to_the_dense_path() {
        let slice_size = 4096u64;
        let data = noise(4096 * 12, 0x99);
        let (set, file_id) = crate::repair::tests::setup_repairable_set(&data, slice_size, 6);
        let mut broken = data.clone();
        broken[..4096].fill(0x22);
        let mut access = crate::verify::MemoryFileAccess::new();
        access.add_file(file_id, broken);
        let verification = crate::verify::verify_all(&set, &access);
        let plan = crate::repair::plan_repair(&set, &verification).expect("plan");

        set_transform_arm_override(Some(TransformArm::On));
        let before = transform_arm_stats();
        crate::repair::execute_repair_with_options(
            &plan,
            &set,
            &mut access,
            &RepairOptions {
                cancel: None,
                progress: None,
                memory_limit: Some(16 * 1024),
            },
        )
        .expect("repair");
        let after = transform_arm_stats();
        set_transform_arm_override(None);
        assert_eq!(
            after.executed, before.executed,
            "the arm must have declined"
        );
        assert_eq!(
            crate::verify::FileAccess::read_file(&access, &file_id).unwrap(),
            data
        );
    }

    #[test]
    fn the_arm_override_is_thread_local() {
        set_transform_arm_override(Some(TransformArm::Off));
        assert_eq!(transform_arm_override(), Some(TransformArm::Off));
        let seen = std::thread::spawn(transform_arm_override).join().unwrap();
        assert_eq!(seen, None);
        set_transform_arm_override(None);
        assert_eq!(transform_arm_override(), None);
    }
}
