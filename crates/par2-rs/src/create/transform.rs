//! The transform arm of PAR2 creation.
//!
//! The dense forward encoder computes every recovery row as an explicit
//! weighted sum of every source slice: `n * r` region folds per stripe. The
//! same rows are output `e` of a length-65535 multiplicative DFT over
//! GF(2^16), and [`DftPlan`] evaluates a contiguous window of those outputs in
//! roughly `n + 256 * r` folds instead. This module is the creation-side
//! caller of that plan: it decides whether the transform wins, sizes its
//! arenas against the caller's existing memory limit, drives the passes, and
//! checks every pass against the dense definition before the bytes are kept.
//!
//! # Why the shape is different from the dense arm's
//!
//! The dense encoder streams: it holds one stripe of the recovery output and
//! pushes small batches of source slices past it, so its resident source
//! memory is a dozen slices whatever `n` is. The transform cannot stream that
//! way. Its whole economy comes from folding *all* `n` sources into the
//! transform's 255 intermediate rows at once — split the source set into
//! batches of twelve and each batch's plan costs its own `12 * r`
//! accumulation, which is the dense cost again. So the transform needs the
//! same byte range of every source slice resident simultaneously, and that
//! range — the *band* — is what the memory budget buys.
//!
//! One pass therefore holds:
//!
//! ```text
//! sources    n * band
//! outputs    r * band
//! scratch    workers * plan.scratch_bytes(stripe)
//! probe      workers * stripe        (the safety row, below)
//! views      workers * n * 16        (one slice descriptor per source)
//! plan       plan.plan_bytes()
//! ```
//!
//! and [`admit`] picks the largest `band` that keeps the sum inside the budget
//! it is handed — which is never more than the dense arm's own admitted peak
//! at the same limit, so the transform arm cannot make a create resident in
//! more memory than it already was.
//!
//! # Band, stripe and pass
//!
//! A *pass* covers one band of every slice. Inside the band the work splits
//! into *stripes*: a stripe is the slice-range one [`DftPlan::transform_stripe`]
//! call sees, and stripes are independent, so they are the parallel axis. The
//! output arena is stripe-major (`chunk c, row o` at `(c * r + o) * stripe`)
//! precisely so that one worker's destination is the contiguous, row-major
//! buffer the plan wants; nothing is transposed afterwards.
//!
//! Stripes are deliberately small (8 KiB, 4 KiB when memory is tight, and 2 KiB
//! only when nothing wider fits at all). The
//! plan's working set is `rows * stripe`, and the fold count does not depend on
//! the stripe at all, so a small stripe keeps the intermediate rows in cache
//! and buys more stripes per band — which is the parallel width.
//!
//! # Source reads and hashing
//!
//! Slice order is file order, so a pass is one forward, strided sweep per file
//! rather than a random walk. What it is not is *sequential*: the bytes of one
//! slice arrive `passes` times, split. The whole-file MD5 and the 16 KiB digest
//! are single serial messages over a file's bytes in file order, so they cannot
//! be driven from a multi-pass feed — exactly the rule the dense arm already
//! follows when its own stripe count exceeds one. A single-pass transform *is*
//! in file order and fuses the digests as before; a multi-pass one leaves them
//! to the separate hashing read `write_outputs` already performs for every
//! multi-stripe create. No per-slice digest state is carried across passes.
//!
//! # The safety row
//!
//! The transform and the dense definition are the same sum, but the transform
//! is a different program, and a wrong recovery volume is not detectable by
//! anything downstream of creation. Every stripe therefore also computes one
//! recovery row the dense way — `n` folds, `1/r` of the dense arm's total work
//! — and compares; which row rotates from band to band. A mismatch abandons the arm for the whole create
//! and the caller recreates every volume from the dense path.

use std::sync::atomic::{AtomicBool, Ordering};

use reedsolomon_rs::gf;
use reedsolomon_rs::gf_simd::{FactorSrc, mul_acc_input_batch};
use reedsolomon_rs::gf16_dft::{DftPlan, DftScratch};

use crate::error::{Par2Error, Result};
use crate::types::{CancellationToken, RecoveryExponent};

use super::encode::{
    AlignedBuffer, ForwardEncoderOptions, ForwardRecoverySink, ForwardSourceObserver,
    ForwardSourceProvider, configured_create_threads,
};

/// Smallest band the arm will run. Below this the per-pass read of every slice
/// degenerates into a seek per kilobyte or so and the pass count explodes; the
/// create takes the dense path instead.
///
/// The band a budget buys is `budget / (sources + outputs)`, and the budget is
/// the dense arm's own reservation, which for a narrow slice or a modest
/// recovery count is little more than `outputs * slice`. Two shapes measured
/// on an x86-64 performance core (GFNI, page-cached inputs, 1 thread) sit
/// below a 4 KiB floor by that arithmetic: 10 x 100 MiB at 32,008-byte slices
/// with 3,277 recovery blocks buys a ~2.9 KiB band, and 32,768 slices of 5,552
/// bytes with 32,768 recovery blocks buys ~3.0 KiB. At a 4 KiB floor both took
/// the dense arm (61.8 s and 115.4 s, medians of three); at 2 KiB they run the
/// transform in 16 and 3 passes and take 4.9 s and 4.4 s, at a lower peak RSS
/// than the dense arm (85 MiB against 119 MiB, 147 MiB against 209 MiB).
const MIN_BAND_BYTES: usize = 2 * 1024;

/// Largest number of passes the arm will run. Each pass re-opens the strided
/// read of the whole payload, so the bound is what keeps a tiny budget from
/// turning a create into hundreds of sweeps.
const MAX_PASSES: usize = 256;

/// How many times fewer region folds the transform must perform before the
/// automatic policy prefers it.
///
/// The transform's fold is the same `dst ^= c * src` region fold the dense arm
/// performs, but the arm around it is not free: it reads every source slice
/// once per pass instead of once per create, and it spends `n` folds per stripe
/// on the safety row. Measured fold ratios (dense folds over plan folds) on the
/// 4 GiB / 768000 fixture, n = 5600: 0.97 at r = 32, 3.33 at r = 280 (`-r 5`),
/// 7.65 at r = 840 (`-r 15`), 11.33 at r = 1678 (`-r 30`). The three ratios at
/// or above 3.3 all beat the dense arm on wall time by 1.4x to 2.6x; the r = 32
/// shape, where the plan performs MORE folds than the dense arm, must not be
/// taken. Two is the smallest integer margin that keeps the whole measured
/// losing region out while admitting every measured winner.
const FOLD_MARGIN: u64 = 2;

/// Source slices below which the automatic policy never takes the transform.
///
/// The schedule's fixed cost is the 257-dimension accumulation, `256 * r`
/// folds, against the dense `n * r`: the transform cannot win until `n` is
/// comfortably past 256. Measured, a 512-source set never reaches the fold
/// margin above at any recovery amount tried — its ratio tops out at 1.47 at
/// r = 1678 — so the margin would reject these shapes anyway. This is the
/// cheap test that avoids building a plan for them at all.
const MIN_SOURCE_SLICES: usize = 512;

/// Stripe lengths tried, widest first. See the module docs for why these are
/// small; 4 KiB is the floor of the ordinary search because the plan's rows
/// must still be worth a kernel call.
const STRIPE_CANDIDATES: [usize; 3] = [16 * 1024, 8 * 1024, 4 * 1024];

/// The stripe tried only when no [`STRIPE_CANDIDATES`] entry fits the budget.
///
/// The accumulation stage makes `256 * outputs / batch` kernel calls per
/// stripe whatever its length, so a shorter stripe only adds calls. Measured on
/// an x86-64 performance core (GFNI, 1 thread) at 32,760 sources and 32,768
/// recovery blocks, a 2 KiB stripe costs the same as a 4 KiB one (21.7 s
/// against 21.8 s) and a 1 KiB stripe costs 1.6x (34.0 s). In the ordinary
/// search a 2 KiB stripe would still win shapes the wider stripes already
/// admit — it buys more stripes per band, which [`better`] prefers — and on
/// 4,096 recovery blocks of 44,436 bytes at 8 threads that traded 12% of wall
/// time for 70% more CPU. It is therefore a fallback that opens shapes the
/// arm could not run at all, never a competitor for the ones it could.
const NARROW_STRIPE: usize = 2 * 1024;

/// Bucket batches tried, widest first. A wider batch divides the accumulation
/// stage's destination traffic and multiplies the plan's scratch; when memory
/// is the binding constraint a narrower batch buys band.
const BATCH_CANDIDATES: [usize; 3] = [4, 2, 1];

/// Bytes charged for one source's slice descriptor in a worker's view table.
const VIEW_BYTES: usize = std::mem::size_of::<&[u8]>();

/// Bytes charged per source for the per-pass bookkeeping the producer keeps
/// (the unpadded length of each slice's band, and the first row's factor).
const PER_SOURCE_BOOKKEEPING_BYTES: usize = std::mem::size_of::<usize>() + 2;

/// Consecutive slices handed to the fused source hasher in one run.
const OBSERVE_RUN: usize = 16;

/// Stack given to each stripe worker, and charged for it.
///
/// The workers hold a slice-descriptor table on the heap and a few fixed arrays
/// on the stack; nothing here recurses. Rust's default two megabytes per thread
/// would be the arm's largest uncounted allocation at a wide worker count —
/// measured, it was the whole of a 3% overshoot against the dense arm's peak —
/// so the arm asks for a stack it can account for instead of the default one it
/// cannot.
const WORKER_STACK_BYTES: usize = 512 * 1024;

/// Share of the budget held back for what an arena plan cannot name: the
/// allocator's own rounding on a handful of multi-hundred-megabyte blocks, the
/// aligned buffers' 64-byte cells, thread guard pages and thread-local storage.
///
/// Measured against the dense arm's peak on the 4 GiB / 768000 fixture, the
/// unnamed remainder after the worker stacks are charged runs to 2.5% of the
/// budget at the tightest shape tried (a 256 MiB limit at 30% recovery, where
/// the arm's arenas are nearly the whole budget); a 1/32 reserve covers that
/// with room, and costs the band about one part in thirty.
const BUDGET_SLACK_SHIFT: u32 = 5;

/// Whether a create may use the transform arm.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum TransformPolicy {
    /// Take the transform when it is admissible and expected to win.
    #[default]
    Auto,
    /// Never take it; the dense arm is the whole story.
    Never,
    /// Take it whenever it is admissible, whatever the shape suggests. For
    /// tests and benchmarking only — it never bypasses the memory admission.
    Force,
}

/// `RARPAR_PAR2_TRANSFORM`: `0` forces the dense arm, `1` forces the transform
/// wherever it is admissible, anything else (including unset) is [`Auto`].
///
/// Process-stable by construction, like every other creation knob here, so the
/// pass count a create plans and the arm it runs cannot disagree.
///
/// [`Auto`]: TransformPolicy::Auto
pub(crate) fn policy_from_env() -> TransformPolicy {
    #[cfg(test)]
    if let Some(forced) = test_policy::current() {
        return forced;
    }
    static CONFIGURED: std::sync::OnceLock<TransformPolicy> = std::sync::OnceLock::new();
    *CONFIGURED.get_or_init(|| match std::env::var("RARPAR_PAR2_TRANSFORM") {
        Ok(value) => match value.trim() {
            "0" => TransformPolicy::Never,
            "1" => TransformPolicy::Force,
            _ => TransformPolicy::Auto,
        },
        Err(_) => TransformPolicy::Auto,
    })
}

/// The in-process policy override the crate's own tests use instead of the
/// environment variable.
///
/// Thread-local, and a create resolves the policy on the thread that called it,
/// so two tests running side by side can pin opposite policies without either
/// seeing the other's — which a process-global switch could not promise.
#[cfg(test)]
pub(crate) mod test_policy {
    use super::TransformPolicy;
    use std::cell::Cell;

    thread_local! {
        static FORCED: Cell<Option<TransformPolicy>> = const { Cell::new(None) };
    }

    /// Pin `policy` for the duration of `body`, restoring whatever was pinned
    /// before — including across a panic, so one failing test cannot leak its
    /// policy into the next one on the same thread.
    pub(crate) fn with<T>(policy: TransformPolicy, body: impl FnOnce() -> T) -> T {
        struct Restore(Option<TransformPolicy>);
        impl Drop for Restore {
            fn drop(&mut self) {
                FORCED.with(|forced| forced.set(self.0));
            }
        }
        let _restore = Restore(FORCED.with(|forced| forced.replace(Some(policy))));
        body()
    }

    pub(crate) fn current() -> Option<TransformPolicy> {
        FORCED.with(Cell::get)
    }
}

/// Test-only instrumentation: how many transform passes this thread has run,
/// and a switch that makes the safety row fail on purpose.
///
/// Both are thread-local and both are read on the thread that called `create`,
/// so tests running side by side cannot see each other's.
#[cfg(test)]
pub(crate) mod test_probe {
    use std::cell::Cell;

    thread_local! {
        static PASSES: Cell<usize> = const { Cell::new(0) };
        static FAULT: Cell<bool> = const { Cell::new(false) };
        static SHARED_BANDS: Cell<usize> = const { Cell::new(0) };
        static FORCE_SHARED: Cell<bool> = const { Cell::new(false) };
        static BUDGET: Cell<Option<usize>> = const { Cell::new(None) };
    }

    /// Run `body` with the transform arm's budget pinned to `bytes` instead of
    /// the dense reservation, which differs by architecture.
    pub(crate) fn with_budget<T>(bytes: usize, body: impl FnOnce() -> T) -> T {
        struct Restore(Option<usize>);
        impl Drop for Restore {
            fn drop(&mut self) {
                BUDGET.with(|budget| budget.set(self.0));
            }
        }
        let _restore = Restore(BUDGET.with(|budget| budget.replace(Some(bytes))));
        body()
    }

    pub(crate) fn budget_override() -> Option<usize> {
        BUDGET.with(Cell::get)
    }

    /// Run `body` with every band on the shared-stripe runner, whatever the
    /// host's worker count, and hand back how many bands took it.
    pub(crate) fn with_shared_bands<T>(body: impl FnOnce() -> T) -> (T, usize) {
        struct Restore(bool);
        impl Drop for Restore {
            fn drop(&mut self) {
                FORCE_SHARED.with(|force| force.set(self.0));
            }
        }
        let _restore = Restore(FORCE_SHARED.with(|force| force.replace(true)));
        SHARED_BANDS.with(|bands| bands.set(0));
        let produced = body();
        (produced, SHARED_BANDS.with(Cell::get))
    }

    pub(crate) fn shared_forced() -> bool {
        FORCE_SHARED.with(Cell::get)
    }

    pub(crate) fn record_shared_band() {
        SHARED_BANDS.with(|bands| bands.set(bands.get() + 1));
    }

    /// Run `body` with the pass counter reset, and hand back what it produced
    /// alongside the number of transform passes it ran.
    pub(crate) fn counted<T>(body: impl FnOnce() -> T) -> (T, usize) {
        PASSES.with(|passes| passes.set(0));
        let produced = body();
        (produced, PASSES.with(Cell::get))
    }

    /// Run `body` with the first transform band's safety row forced to fail.
    pub(crate) fn with_fault<T>(body: impl FnOnce() -> T) -> T {
        struct Restore(bool);
        impl Drop for Restore {
            fn drop(&mut self) {
                FAULT.with(|fault| fault.set(self.0));
            }
        }
        let _restore = Restore(FAULT.with(|fault| fault.replace(true)));
        body()
    }

    pub(crate) fn record_pass() {
        PASSES.with(|passes| passes.set(passes.get() + 1));
    }

    pub(crate) fn fault_armed() -> bool {
        FAULT.with(Cell::get)
    }
}

/// The resolved geometry of one transform create.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TransformShape {
    /// Bytes of every source slice resident per pass.
    pub(crate) band: usize,
    /// Bytes one [`DftPlan::transform_stripe`] call covers.
    pub(crate) stripe: usize,
    /// Stripes in a full band.
    pub(crate) chunks: usize,
    /// Passes over the slice.
    pub(crate) passes: usize,
    /// Concurrent stripe workers.
    pub(crate) workers: usize,
    /// Bytes every arena of this arm occupies together.
    pub(crate) total_bytes: usize,
}

/// An admitted transform arm: the schedule and the geometry it runs at.
pub(crate) struct TransformArm {
    plan: DftPlan,
    shape: TransformShape,
}

impl TransformArm {
    pub(crate) fn shape(&self) -> TransformShape {
        self.shape
    }
}

/// What one encode attempt produced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EncodeAttempt {
    /// Every recovery byte was written.
    Complete,
    /// The transform's safety row disagreed with the dense definition. Nothing
    /// downstream may keep the volumes; the caller recreates them densely.
    TransformProbeMismatch,
}

/// Decide whether this create takes the transform arm, and at what geometry.
///
/// `budget` is the total bytes every arena of the arm may occupy together. The
/// caller passes the smaller of its own memory limit and the dense arm's
/// admitted peak, which is what makes the transform's residency a bound on the
/// dense arm's rather than an addition to it.
pub(crate) fn admit(
    slice_size: usize,
    source_count: usize,
    exponents: &[RecoveryExponent],
    budget: usize,
    policy: TransformPolicy,
) -> Option<TransformArm> {
    if policy == TransformPolicy::Never || source_count == 0 || exponents.is_empty() {
        return None;
    }
    if policy == TransformPolicy::Auto && source_count < MIN_SOURCE_SLICES {
        return None;
    }
    // The arm's bands run on spawned workers. A target that cannot spawn
    // (plain single-threaded wasm) keeps the serial dense encoder, forced or
    // not.
    if !reedsolomon_rs::threading::parallel_enabled() {
        return None;
    }
    let outputs = contiguous_range(exponents)?;
    if slice_size == 0 || !slice_size.is_multiple_of(2) {
        return None;
    }

    let slots: Vec<u16> = gf::input_slice_constants(source_count)
        .into_iter()
        .map(gf::log)
        .collect();

    let workers = configured_create_threads().max(1);
    let mut best: Option<(usize, TransformShape)> = None;
    // Every worker count from the configured one down to 1, halving: the
    // widest that fits is not always the best (see [`better`]).
    let search_widths = |plan: &DftPlan,
                         bucket_batch: usize,
                         stripe: usize,
                         best: &mut Option<(usize, TransformShape)>| {
        let mut width = workers;
        loop {
            if let Some(shape) = fit(
                plan,
                slice_size,
                source_count,
                exponents.len(),
                budget,
                stripe,
                width,
            ) && best.is_none_or(|(_, incumbent)| better(shape, incumbent))
            {
                *best = Some((bucket_batch, shape));
            }
            if width == 1 {
                break;
            }
            width /= 2;
        }
    };
    for &bucket_batch in &BATCH_CANDIDATES {
        let Ok(plan) = DftPlan::build_tuned(&slots, outputs.clone(), bucket_batch) else {
            return None;
        };
        if policy == TransformPolicy::Auto
            && plan.region_folds().saturating_mul(FOLD_MARGIN) > plan.dense_region_folds()
        {
            return None;
        }
        for &stripe in &STRIPE_CANDIDATES {
            search_widths(&plan, bucket_batch, stripe, &mut best);
        }
    }
    if best.is_none() {
        for &bucket_batch in &BATCH_CANDIDATES {
            let Ok(plan) = DftPlan::build_tuned(&slots, outputs.clone(), bucket_batch) else {
                return None;
            };
            search_widths(&plan, bucket_batch, NARROW_STRIPE, &mut best);
        }
    }
    let (bucket_batch, shape) = best?;
    // Plans are index tables only — `O(sources + outputs)` — so rebuilding the
    // winner once is cheaper than keeping every candidate's alive through the
    // search.
    let plan = DftPlan::build_tuned(&slots, outputs, bucket_batch).ok()?;
    Some(TransformArm { plan, shape })
}

/// Order two admissible geometries.
///
/// A single pass comes first and beats everything, because it is not an
/// arithmetic property at all: a one-pass arm delivers the payload in file
/// order, so the create fuses the source digests into it and never reads the
/// payload a second time. Nothing else on this list is worth a whole extra
/// sweep of the inputs.
///
/// Past that, the pass count itself is nearly free — the bytes read are the
/// payload however many passes they arrive in — so the next key is the parallel
/// width, which is what the arithmetic's wall clock follows, and then the band,
/// which is how long each file's strided run is.
fn better(candidate: TransformShape, incumbent: TransformShape) -> bool {
    let key = |shape: TransformShape| {
        (
            shape.passes == 1,
            shape.workers.min(shape.chunks),
            shape.band,
            shape.stripe,
        )
    };
    key(candidate) > key(incumbent)
}

/// The largest band this (plan, stripe, worker count) can afford, or `None`
/// when the budget cannot buy an admissible one.
fn fit(
    plan: &DftPlan,
    slice_size: usize,
    source_count: usize,
    output_count: usize,
    budget: usize,
    stripe: usize,
    workers: usize,
) -> Option<TransformShape> {
    let per_worker = plan
        .scratch_bytes(stripe)
        .checked_add(stripe)?
        .checked_add(source_count.checked_mul(VIEW_BYTES)?)?
        .checked_add(WORKER_STACK_BYTES)?;
    let fixed = workers
        .checked_mul(per_worker)?
        .checked_add(plan.plan_bytes())?
        .checked_add(source_count.checked_mul(PER_SOURCE_BOOKKEEPING_BYTES)?)?;
    let available = budget
        .checked_sub(budget >> BUDGET_SLACK_SHIFT)?
        .checked_sub(fixed)?;
    let per_band_byte = source_count.checked_add(output_count)?;

    let span = slice_size.div_ceil(stripe).checked_mul(stripe)?;
    let mut band = available / per_band_byte;
    band -= band % stripe;
    band = band.min(span);
    if band < stripe || band < MIN_BAND_BYTES {
        return None;
    }
    let passes = slice_size.div_ceil(band);
    if passes > MAX_PASSES {
        return None;
    }
    Some(TransformShape {
        band,
        stripe,
        chunks: band / stripe,
        passes,
        workers,
        total_bytes: fixed + band * per_band_byte,
    })
}

/// The exponent window `exponents` covers, when it is one contiguous ascending
/// run the plan can be built for.
fn contiguous_range(exponents: &[RecoveryExponent]) -> Option<std::ops::Range<u32>> {
    let first = *exponents.first()?;
    let end = first.checked_add(u32::try_from(exponents.len()).ok()?)?;
    if end > 65_535 {
        return None;
    }
    exponents
        .iter()
        .enumerate()
        .all(|(at, &exponent)| exponent == first + at as u32)
        .then_some(first..end)
}

/// Run one create through the transform arm.
///
/// `observer` may only be supplied for a single-pass arm; see the module docs.
#[allow(clippy::too_many_arguments)]
pub(crate) fn encode<P: ForwardSourceProvider + ?Sized, S: ForwardRecoverySink>(
    arm: &TransformArm,
    slice_size: usize,
    exponents: &[RecoveryExponent],
    provider: &mut P,
    options: &ForwardEncoderOptions,
    sink: &mut S,
    mut observer: Option<&mut dyn ForwardSourceObserver>,
) -> Result<EncodeAttempt> {
    let shape = arm.shape;
    let source_count = provider.source_count();
    let output_count = exponents.len();
    if observer.is_some() && shape.passes != 1 {
        return Err(resource_limit(
            "fused source hashing needs a single-pass transform",
        ));
    }

    let mut sources = AlignedBuffer::new(
        source_count
            .checked_mul(shape.band)
            .ok_or_else(|| resource_limit("transform source arena overflows"))?,
    );
    let mut outputs = AlignedBuffer::new(
        shape
            .chunks
            .checked_mul(output_count)
            .and_then(|rows| rows.checked_mul(shape.stripe))
            .ok_or_else(|| resource_limit("transform output arena overflows"))?,
    );
    let mut scratches: Vec<DftScratch> = (0..shape.workers)
        .map(|_| DftScratch::new(&arm.plan, shape.stripe))
        .collect();
    let mut probes: Vec<Vec<u8>> = (0..shape.workers)
        .map(|_| vec![0u8; shape.stripe])
        .collect();
    let mut band_lens = vec![0usize; source_count];

    // The safety row rotates through the recovery rows band by band, so a
    // fault confined to some rows cannot sit behind one that is always right
    // (the first row of a set starting at exponent 0 is a plain XOR). Its
    // factors are retaken per band from these logs: `n` table lookups.
    let source_logs: Vec<u16> = gf::input_slice_constants(source_count)
        .into_iter()
        .map(gf::log)
        .collect();
    let mut probe_factors: Vec<u16> = vec![0; source_count];

    let total_bytes = (output_count as u64).saturating_mul(slice_size as u64);
    let passes_u32 = u32::try_from(shape.passes)
        .map_err(|_| resource_limit("transform pass count exceeds progress range"))?;

    let mut band_offset = 0usize;
    let mut pass = 0usize;
    while band_offset < slice_size {
        check_cancel(options)?;
        let band_len = (slice_size - band_offset).min(shape.band);
        let live_chunks = band_len.div_ceil(shape.stripe);

        fill_band(
            provider,
            sources.as_bytes_mut(),
            &mut band_lens,
            shape.band,
            band_offset,
            band_len,
        )?;
        if let Some(observer) = observer.as_mut() {
            observe_band(&mut **observer, sources.as_bytes(), &band_lens, shape.band)?;
        }

        let probe_row = pass % output_count;
        for (factor, &log) in probe_factors.iter_mut().zip(&source_logs) {
            *factor = gf::pow_from_log(log, exponents[probe_row]);
        }

        #[cfg(test)]
        test_probe::record_pass();
        // Fewer stripes than workers: the workers share each stripe instead of
        // leaving all but `live_chunks` of them idle (see `run_band_shared`).
        let shared = live_chunks < shape.workers;
        #[cfg(test)]
        let shared = shared || test_probe::shared_forced();
        #[cfg(test)]
        if shared {
            test_probe::record_shared_band();
        }
        let runner = if shared { run_band_shared } else { run_band };
        let mismatch = runner(
            &arm.plan,
            sources.as_bytes(),
            outputs.as_bytes_mut(),
            &mut scratches,
            &mut probes,
            &probe_factors,
            probe_row,
            source_count,
            output_count,
            shape,
            live_chunks,
            options.cancel.as_ref(),
            #[cfg(test)]
            test_probe::fault_armed(),
        )?;
        if mismatch {
            return Ok(EncodeAttempt::TransformProbeMismatch);
        }

        emit_band(
            sink,
            outputs.as_bytes(),
            exponents,
            shape.stripe,
            live_chunks,
            band_offset,
            slice_size,
        )?;

        pass += 1;
        report_progress(
            options,
            u32::try_from(pass - 1).unwrap_or(u32::MAX),
            passes_u32,
            (pass as u64)
                .saturating_mul(output_count as u64)
                .saturating_mul(shape.band as u64)
                .min(total_bytes),
            total_bytes,
        );
        band_offset += band_len;
    }

    check_cancel(options)?;
    Ok(EncodeAttempt::Complete)
}

/// Read `[offset, offset + band_len)` of every slice into the source arena,
/// zeroing each slice's padding out to the full band so every stripe view is a
/// whole, defined region.
fn fill_band<P: ForwardSourceProvider + ?Sized>(
    provider: &mut P,
    arena: &mut [u8],
    band_lens: &mut [usize],
    band: usize,
    offset: usize,
    band_len: usize,
) -> Result<()> {
    for (source_index, slot) in arena.chunks_mut(band).enumerate() {
        let read = provider.read_source_chunk(source_index, offset, &mut slot[..band_len])?;
        slot[read..].fill(0);
        band_lens[source_index] = read;
    }
    Ok(())
}

/// Hand a single-pass band's real source bytes to the fused hasher, in source
/// order, in runs the multi-buffer digest kernel can lane.
fn observe_band(
    observer: &mut dyn ForwardSourceObserver,
    arena: &[u8],
    band_lens: &[usize],
    band: usize,
) -> Result<()> {
    let run_len = crate::md5_simd::max_lanes().clamp(1, OBSERVE_RUN);
    let mut index = 0usize;
    while index < band_lens.len() {
        let run = run_len.min(band_lens.len() - index);
        let mut views: [&[u8]; OBSERVE_RUN] = [&[][..]; OBSERVE_RUN];
        for (slot, view) in views[..run].iter_mut().enumerate() {
            let start = (index + slot) * band;
            *view = &arena[start..start + band_lens[index + slot]];
        }
        observer.observe_slices(index, &views[..run])?;
        index += run;
    }
    Ok(())
}

/// Transform every live stripe of one band, checking each against the dense
/// definition. Returns `true` when the safety row disagreed anywhere.
#[allow(clippy::too_many_arguments)]
fn run_band(
    plan: &DftPlan,
    sources: &[u8],
    outputs: &mut [u8],
    scratches: &mut [DftScratch],
    probes: &mut [Vec<u8>],
    probe_factors: &[u16],
    probe_row: usize,
    source_count: usize,
    output_count: usize,
    shape: TransformShape,
    live_chunks: usize,
    cancel: Option<&CancellationToken>,
    #[cfg(test)] inject_fault: bool,
) -> Result<bool> {
    let chunk_bytes = output_count * shape.stripe;
    // Deal the stripes round-robin so every worker owns a disjoint, statically
    // known set of destinations: no shared mutable state, and no unsafe split.
    let mut lanes: Vec<Vec<(usize, &mut [u8])>> = (0..shape.workers).map(|_| Vec::new()).collect();
    for (chunk_index, chunk) in outputs[..live_chunks * chunk_bytes]
        .chunks_mut(chunk_bytes)
        .enumerate()
    {
        lanes[chunk_index % shape.workers].push((chunk_index, chunk));
    }

    let stopped = AtomicBool::new(false);
    let mismatched = AtomicBool::new(false);
    let stopped = &stopped;
    let mismatched = &mismatched;
    // Polled inside a stripe's transform as well as between stripes: at a
    // large shape one stripe is most of a band's work.
    let cancelled = move || {
        stopped.load(Ordering::Relaxed) || cancel.is_some_and(CancellationToken::is_cancelled)
    };

    let mut results: Vec<Result<()>> = Vec::with_capacity(shape.workers);
    let mut spawn_failure: Option<Par2Error> = None;
    std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(shape.workers);
        for ((lane, scratch), probe) in lanes
            .into_iter()
            .zip(scratches.iter_mut())
            .zip(probes.iter_mut())
        {
            let cancelled = &cancelled;
            let worker = std::thread::Builder::new()
                .name("par2-transform".to_string())
                .stack_size(WORKER_STACK_BYTES);
            let spawned = worker.spawn_scoped(scope, move || {
                let mut views: Vec<&[u8]> = Vec::with_capacity(source_count);
                for (chunk_index, chunk) in lane {
                    if stopped.load(Ordering::Relaxed)
                        || cancel.is_some_and(CancellationToken::is_cancelled)
                    {
                        stopped.store(true, Ordering::Relaxed);
                        return Ok(());
                    }
                    let start = chunk_index * shape.stripe;
                    views.clear();
                    views.extend(
                        sources
                            .chunks(shape.band)
                            .map(|slot| &slot[start..start + shape.stripe]),
                    );
                    chunk.fill(0);
                    if let Err(error) = plan.transform_stripe(&views, chunk, scratch, cancelled) {
                        // A cancellation this worker observed because another
                        // one already stopped is that worker's news, not an
                        // error of its own.
                        if stopped.load(Ordering::Relaxed) {
                            return Ok(());
                        }
                        stopped.store(true, Ordering::Relaxed);
                        return Err(transform_error(error));
                    }
                    dense_probe_row(probe, &views, probe_factors);
                    #[cfg(test)]
                    if inject_fault {
                        probe[0] ^= 0xff;
                    }
                    if probe[..] != chunk[probe_row * shape.stripe..][..shape.stripe] {
                        mismatched.store(true, Ordering::Relaxed);
                        stopped.store(true, Ordering::Relaxed);
                        return Ok(());
                    }
                }
                Ok(())
            });
            match spawned {
                Ok(handle) => handles.push(handle),
                Err(error) => {
                    // Whatever has already started must stop; this band's work
                    // cannot be completed without every lane.
                    stopped.store(true, Ordering::Relaxed);
                    spawn_failure = Some(Par2Error::Io(error));
                }
            }
        }
        results.extend(handles.into_iter().map(|handle| {
            handle
                .join()
                .unwrap_or_else(|payload| std::panic::resume_unwind(payload))
        }));
    });

    if let Some(error) = spawn_failure {
        return Err(error);
    }
    if mismatched.load(Ordering::Relaxed) {
        // The safety row is the first thing the caller must hear about: the
        // other workers stopped because of it, not on their own account.
        return Ok(true);
    }
    for result in results {
        result?;
    }
    if cancel.is_some_and(CancellationToken::is_cancelled) {
        return Err(Par2Error::Cancelled);
    }
    Ok(false)
}

/// Result slots one shared stripe can fold per round; the largest bucket batch
/// [`admit`] tries.
const SHARED_MAX_SLOTS: usize = 4;

/// Transform every live stripe of one band with all workers sharing each
/// stripe, checking each against the dense definition. Returns `true` when the
/// safety row disagreed anywhere.
///
/// [`run_band`] gives each worker whole stripes, so a band of fewer stripes
/// than workers — a narrow slice, or a budget that buys a stripe or two per
/// pass — leaves workers idle: at 32,768 slices of 5,552 bytes the band is one
/// 2 KiB stripe and seven of eight workers would wait. Here the workers share
/// each stripe, in rounds of one scratch's `bucket_batch` result slots. The
/// first worker fills the slots ([`DftPlan::transform_bucket`]); once they are
/// full (a barrier) every worker folds them into its own disjoint range of
/// output rows; a second barrier frees the slots for the next round. The safety row is split the
/// same way, by source, into each worker's probe buffer, and summed by the
/// worker that owns the row.
///
/// Memory stays what [`run_band`] touches for the same band, by construction:
/// the first scratch's result slots and stage, the probes, and one
/// slice-descriptor table per live stripe; the workers allocate nothing. That
/// is why one worker runs every sub-transform. A second needs a stage of its
/// own, which `run_band` never touches for a one-stripe band, and on an x86
/// host with 4 SMT performance cores (8 threads) four slot workers bought only 4-8%
/// more wall time than one at 32,768 slices of 5,552 or 16,384 of 11,104
/// bytes, for 1-3 MiB more peak RSS: the fold into the output rows is the cost
/// that needs sharing, and every worker shares it. Every worker
/// walks the same fixed sequence of barriers whatever happens — a
/// cancellation, an error or a caught panic only makes the remaining phases
/// no-ops — so no worker can be left waiting on one that stopped.
#[allow(clippy::too_many_arguments)]
fn run_band_shared(
    plan: &DftPlan,
    sources: &[u8],
    outputs: &mut [u8],
    scratches: &mut [DftScratch],
    probes: &mut [Vec<u8>],
    probe_factors: &[u16],
    probe_row: usize,
    source_count: usize,
    output_count: usize,
    shape: TransformShape,
    live_chunks: usize,
    cancel: Option<&CancellationToken>,
    #[cfg(test)] inject_fault: bool,
) -> Result<bool> {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::{Mutex, PoisonError, RwLock};

    let stripe = shape.stripe;
    let chunk_bytes = output_count * stripe;
    let batch = plan.bucket_batch();
    let buckets = plan.bucket_count();
    let workers = shape.workers.min(probes.len());
    if workers == 0 || batch > SHARED_MAX_SLOTS || live_chunks == 0 {
        return Err(resource_limit(
            "shared transform band has no usable geometry",
        ));
    }
    let Some(first) = scratches.first_mut() else {
        return Err(resource_limit("shared transform band has no scratch"));
    };
    let (slot_parts, stage) = plan.scratch_parts(first).map_err(transform_error)?;
    let slots: Vec<RwLock<&mut [u8]>> = slot_parts.map(RwLock::new).collect();
    let mut stage = Some(stage);

    let row_bounds: Vec<usize> = (0..=workers).map(|w| w * output_count / workers).collect();
    let source_bounds: Vec<usize> = (0..=workers).map(|w| w * source_count / workers).collect();
    let owner = (0..workers)
        .find(|&w| probe_row < row_bounds[w + 1])
        .unwrap_or(workers - 1);

    // Each live stripe's slice descriptors, shared read-only by every worker.
    let views: Vec<Vec<&[u8]>> = (0..live_chunks)
        .map(|chunk_index| {
            let start = chunk_index * stripe;
            sources
                .chunks(shape.band)
                .map(|slot| &slot[start..start + stripe])
                .collect()
        })
        .collect();

    // Each worker's rows of every live stripe, as disjoint mutable slices.
    let mut lanes: Vec<Vec<&mut [u8]>> = (0..workers)
        .map(|_| Vec::with_capacity(live_chunks))
        .collect();
    for chunk in outputs[..live_chunks * chunk_bytes].chunks_mut(chunk_bytes) {
        let mut rest = chunk;
        for (worker, lane) in lanes.iter_mut().enumerate() {
            let rows = row_bounds[worker + 1] - row_bounds[worker];
            let (head, tail) = rest.split_at_mut(rows * stripe);
            lane.push(head);
            rest = tail;
        }
    }

    let probes: Vec<RwLock<&mut Vec<u8>>> = probes[..workers].iter_mut().map(RwLock::new).collect();
    let barrier = Rendezvous::new(workers);
    let stopped = AtomicBool::new(false);
    let mismatched = AtomicBool::new(false);
    let failure: Mutex<Option<Par2Error>> = Mutex::new(None);
    let panicked: Mutex<Option<Box<dyn std::any::Any + Send>>> = Mutex::new(None);
    let mut spawn_failure: Option<Par2Error> = None;

    let (slots, probes, views, barrier, stopped, mismatched, failure, panicked) = (
        &slots,
        &probes,
        &views,
        &barrier,
        &stopped,
        &mismatched,
        &failure,
        &panicked,
    );
    // Run one phase's work unless the band has already stopped, turning an
    // error or a panic into "stopped" so the barrier sequence carries on.
    let phase = move |work: &mut dyn FnMut() -> Result<()>| {
        if stopped.load(Ordering::Relaxed) {
            return;
        }
        if cancel.is_some_and(CancellationToken::is_cancelled) {
            stopped.store(true, Ordering::Relaxed);
            return;
        }
        match catch_unwind(AssertUnwindSafe(work)) {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                stopped.store(true, Ordering::Relaxed);
                failure
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .get_or_insert(error);
            }
            Err(payload) => {
                stopped.store(true, Ordering::Relaxed);
                panicked
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .get_or_insert(payload);
            }
        }
    };

    std::thread::scope(|scope| {
        let mut spawned_workers = 0;
        for (worker, lane) in lanes.into_iter().enumerate() {
            let phase = &phase;
            let row_bounds = &row_bounds;
            let source_bounds = &source_bounds;
            let mut stage = stage.take();
            let builder = std::thread::Builder::new()
                .name("par2-transform".to_string())
                .stack_size(WORKER_STACK_BYTES);
            let spawned = builder.spawn_scoped(scope, move || {
                let rows = row_bounds[worker]..row_bounds[worker + 1];
                let mine = source_bounds[worker]..source_bounds[worker + 1];
                for (views, out) in views.iter().zip(lane) {
                    out.fill(0);
                    for round in 0..buckets.div_ceil(batch) {
                        let first = round * batch;
                        let live = batch.min(buckets - first);
                        if let Some(stage) = stage.as_deref_mut() {
                            phase(&mut || {
                                for (slot, lock) in slots[..live].iter().enumerate() {
                                    let mut result =
                                        lock.write().unwrap_or_else(PoisonError::into_inner);
                                    plan.transform_bucket(first + slot, views, &mut result, stage)
                                        .map_err(transform_error)?;
                                }
                                Ok(())
                            });
                        }
                        barrier.wait();
                        phase(&mut || {
                            let guards: [Option<_>; SHARED_MAX_SLOTS] =
                                std::array::from_fn(|slot| {
                                    (slot < live).then(|| {
                                        slots[slot].read().unwrap_or_else(PoisonError::into_inner)
                                    })
                                });
                            let finished: [(usize, &[u8]); SHARED_MAX_SLOTS] =
                                std::array::from_fn(|slot| {
                                    (
                                        first + slot,
                                        guards[slot].as_deref().map_or(&[][..], |r| &r[..]),
                                    )
                                });
                            plan.accumulate_buckets(&finished[..live], rows.clone(), out)
                                .map_err(transform_error)
                        });
                        barrier.wait();
                    }
                    // The safety row, split by source across the workers.
                    phase(&mut || {
                        let mut probe = probes[worker]
                            .write()
                            .unwrap_or_else(PoisonError::into_inner);
                        dense_probe_row(
                            &mut probe[..],
                            &views[mine.clone()],
                            &probe_factors[mine.clone()],
                        );
                        Ok(())
                    });
                    barrier.wait();
                    if worker == owner {
                        phase(&mut || {
                            let mut sum = probes[worker]
                                .write()
                                .unwrap_or_else(PoisonError::into_inner);
                            for (other, lock) in probes.iter().enumerate() {
                                if other == worker {
                                    continue;
                                }
                                let part = lock.read().unwrap_or_else(PoisonError::into_inner);
                                for (byte, &add) in sum.iter_mut().zip(part.iter()) {
                                    *byte ^= add;
                                }
                            }
                            #[cfg(test)]
                            if inject_fault {
                                sum[0] ^= 0xff;
                            }
                            let at = (probe_row - rows.start) * stripe;
                            if sum[..] != out[at..at + stripe] {
                                mismatched.store(true, Ordering::Relaxed);
                                stopped.store(true, Ordering::Relaxed);
                            }
                            Ok(())
                        });
                    }
                    // The probes are rewritten for the next stripe.
                    barrier.wait();
                }
            });
            match spawned {
                Ok(_) => spawned_workers += 1,
                Err(error) => {
                    // The workers already running would wait at the first
                    // barrier for this one forever: stop the band and take the
                    // missing workers out of the barrier's count.
                    stopped.store(true, Ordering::Relaxed);
                    spawn_failure = Some(Par2Error::Io(error));
                    break;
                }
            }
        }
        for _ in spawned_workers..workers {
            barrier.leave();
        }
    });
    if let Some(payload) = panicked
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take()
    {
        std::panic::resume_unwind(payload);
    }
    if let Some(error) = spawn_failure {
        return Err(error);
    }
    if mismatched.load(Ordering::Relaxed) {
        return Ok(true);
    }
    if let Some(error) = failure
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take()
    {
        return Err(error);
    }
    if cancel.is_some_and(CancellationToken::is_cancelled) {
        return Err(Par2Error::Cancelled);
    }
    Ok(false)
}

/// A reusable barrier whose party count can shrink: [`std::sync::Barrier`]
/// cannot release workers that are waiting for a thread that never started.
struct Rendezvous {
    state: std::sync::Mutex<RendezvousState>,
    turned: std::sync::Condvar,
}

struct RendezvousState {
    parties: usize,
    arrived: usize,
    generation: u64,
}

impl Rendezvous {
    fn new(parties: usize) -> Self {
        Self {
            state: std::sync::Mutex::new(RendezvousState {
                parties,
                arrived: 0,
                generation: 0,
            }),
            turned: std::sync::Condvar::new(),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, RendezvousState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Release everyone waiting when the last expected party has arrived.
    fn turn_if_full(&self, state: &mut RendezvousState) -> bool {
        if state.arrived >= state.parties {
            state.arrived = 0;
            state.generation = state.generation.wrapping_add(1);
            self.turned.notify_all();
            return true;
        }
        false
    }

    fn wait(&self) {
        let mut state = self.lock();
        state.arrived += 1;
        if self.turn_if_full(&mut state) {
            return;
        }
        let generation = state.generation;
        while state.generation == generation {
            state = self
                .turned
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }

    /// Remove one party for good, releasing the current round if it was the
    /// only one missing.
    fn leave(&self) {
        let mut state = self.lock();
        state.parties = state.parties.saturating_sub(1);
        if state.arrived > 0 {
            self.turn_if_full(&mut state);
        }
    }
}

/// One recovery row, straight from the PAR2 definition: `n` region folds over
/// the same staged stripe the transform just consumed.
fn dense_probe_row(probe: &mut [u8], views: &[&[u8]], factors: &[u16]) {
    probe.fill(0);
    let mut batch: [FactorSrc<'_>; OBSERVE_RUN] = std::array::from_fn(|_| FactorSrc {
        factor: 0,
        src: &[],
    });
    for run in (0..views.len()).step_by(OBSERVE_RUN) {
        let upto = (run + OBSERVE_RUN).min(views.len());
        for (at, source) in (run..upto).enumerate() {
            batch[at] = FactorSrc {
                factor: factors[source],
                src: views[source],
            };
        }
        mul_acc_input_batch(probe, &batch[..upto - run]);
    }
}

/// Hand one finished band to the sink, one row at a time in ascending offset
/// order — which is the order the recovery writer's per-slot append demands.
fn emit_band<S: ForwardRecoverySink>(
    sink: &mut S,
    outputs: &[u8],
    exponents: &[RecoveryExponent],
    stripe: usize,
    live_chunks: usize,
    band_offset: usize,
    slice_size: usize,
) -> Result<()> {
    let output_count = exponents.len();
    sink.write_recovery_band(output_count, live_chunks, &|output_index, chunk_index| {
        let offset = band_offset + chunk_index * stripe;
        let len = stripe.min(slice_size - offset);
        let start = (chunk_index * output_count + output_index) * stripe;
        (
            exponents[output_index],
            offset as u64,
            &outputs[start..start + len],
        )
    })
}

fn transform_error(error: reedsolomon_rs::fft::TransformError) -> Par2Error {
    match error {
        reedsolomon_rs::fft::TransformError::Cancelled => Par2Error::Cancelled,
        other => resource_limit(format!("transform stripe rejected: {other:?}")),
    }
}

fn check_cancel(options: &ForwardEncoderOptions) -> Result<()> {
    if options
        .cancel
        .as_ref()
        .is_some_and(CancellationToken::is_cancelled)
    {
        Err(Par2Error::Cancelled)
    } else {
        Ok(())
    }
}

fn report_progress(
    options: &ForwardEncoderOptions,
    current: u32,
    total: u32,
    bytes_processed: u64,
    total_bytes: u64,
) {
    if let Some(progress) = &options.progress {
        progress(crate::types::ProgressUpdate {
            stage: crate::types::ProgressStage::Creating,
            current,
            total,
            bytes_processed,
            total_bytes: Some(total_bytes),
            phase: crate::types::ProgressPhase::RecoveryEncode,
        });
    }
}

fn resource_limit(reason: impl Into<String>) -> Par2Error {
    Par2Error::ResourceLimitExceeded {
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    use crate::create::{BlockSizing, Par2Creator, Par2CreatorOptions, RecoveryAmount};

    /// Deterministic pseudo-random payload; no dev-dependency needed.
    fn noise(seed: u64, len: usize) -> Vec<u8> {
        let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect()
    }

    /// One creation shape, described once and created twice.
    struct Shape {
        /// Source file lengths, in bytes.
        lengths: Vec<usize>,
        slice_size: u64,
        recovery: u32,
        first_exponent: u32,
        memory_limit: Option<usize>,
    }

    fn write_sources(directory: &Path, lengths: &[usize]) -> Vec<PathBuf> {
        std::fs::create_dir_all(directory).unwrap();
        lengths
            .iter()
            .enumerate()
            .map(|(at, &length)| {
                let path = directory.join(format!("source-{at}.bin"));
                std::fs::write(&path, noise(0x5EED + at as u64, length)).unwrap();
                path
            })
            .collect()
    }

    /// Create one set under a pinned policy, and hand back every output file's
    /// bytes keyed by name, plus the number of transform passes it ran.
    fn create(
        shape: &Shape,
        inputs: &[PathBuf],
        base: &Path,
        output_directory: &Path,
        policy: TransformPolicy,
    ) -> (BTreeMap<String, Vec<u8>>, usize) {
        std::fs::create_dir_all(output_directory).unwrap();
        let mut options = Par2CreatorOptions::new(Some(base.to_path_buf()), inputs.to_vec());
        options.output = Some(output_directory.join("set.par2"));
        options.block_sizing = BlockSizing::Bytes(shape.slice_size);
        options.recovery_amount = RecoveryAmount::Count(shape.recovery);
        options.first_exponent = shape.first_exponent;
        options.memory_limit = shape.memory_limit;

        let (outcome, passes) = test_probe::counted(|| {
            test_policy::with(policy, || {
                let creator = Par2Creator::new(options.clone());
                let plan = creator.plan().unwrap();
                creator.create(&plan)
            })
        });
        outcome.unwrap();

        let mut produced = BTreeMap::new();
        for entry in std::fs::read_dir(output_directory).unwrap() {
            let entry = entry.unwrap();
            produced.insert(
                entry.file_name().to_string_lossy().into_owned(),
                std::fs::read(entry.path()).unwrap(),
            );
        }
        (produced, passes)
    }

    /// Create `shape` twice — dense, then transform — and assert the two sets
    /// are byte-identical. Returns the transform pass count so the caller can
    /// pin whether the arm was actually taken.
    fn compare_arms(shape: &Shape, label: &str) -> usize {
        let root = tempfile::tempdir().unwrap();
        let sources = root.path().join("sources");
        let inputs = write_sources(&sources, &shape.lengths);

        let (dense, dense_passes) = create(
            shape,
            &inputs,
            &sources,
            &root.path().join("dense"),
            TransformPolicy::Never,
        );
        assert_eq!(
            dense_passes, 0,
            "{label}: the kill switch still transformed"
        );
        let (transformed, passes) = create(
            shape,
            &inputs,
            &sources,
            &root.path().join("transform"),
            TransformPolicy::Force,
        );

        assert_eq!(
            dense.keys().collect::<Vec<_>>(),
            transformed.keys().collect::<Vec<_>>(),
            "{label}: the two arms produced different output files"
        );
        for (name, expected) in &dense {
            assert_eq!(
                transformed[name].len(),
                expected.len(),
                "{label}: {name} differs in length"
            );
            assert!(
                &transformed[name] == expected,
                "{label}: {name} differs in content"
            );
        }
        passes
    }

    #[test]
    fn a_multi_file_set_with_short_tails_is_byte_identical() {
        let passes = compare_arms(
            &Shape {
                lengths: vec![4 * 32_768 + 137, 60 * 32_768, 70 * 32_768 + 1],
                slice_size: 32_768,
                recovery: 32,
                first_exponent: 0,
                memory_limit: None,
            },
            "multi-file short tails",
        );
        assert!(passes > 0, "the transform arm never ran");
    }

    #[test]
    fn an_unaligned_slice_size_and_a_nonzero_first_exponent_are_byte_identical() {
        // 32772 is a multiple of 4 (PAR2's rule) and of neither 64 nor the
        // stripe, so every band's tail lands mid-stripe.
        let passes = compare_arms(
            &Shape {
                lengths: vec![30 * 32_772, 30 * 32_772 + 5],
                slice_size: 32_772,
                recovery: 24,
                first_exponent: 8,
                memory_limit: None,
            },
            "unaligned slice, first exponent 8",
        );
        assert!(passes > 0, "the transform arm never ran");
    }

    #[test]
    fn a_tight_memory_limit_runs_many_passes_and_is_byte_identical() {
        let shape = Shape {
            lengths: vec![50 * 65_536, 50 * 65_536 + 9],
            slice_size: 65_536,
            recovery: 48,
            first_exponent: 0,
            memory_limit: Some(6 * 1024 * 1024),
        };
        let passes = compare_arms(&shape, "tight limit");
        assert!(passes > 1, "expected a multi-pass arm, ran {passes}");
    }

    #[test]
    fn a_two_kilobyte_band_is_byte_identical() {
        // The narrowest band the arm admits: four passes over an 8 KiB slice,
        // one 2 KiB stripe each.
        let shape = Shape {
            lengths: vec![300 * 8_192, 300 * 8_192 + 77],
            slice_size: 8_192,
            recovery: 256,
            first_exponent: 3,
            memory_limit: Some(4 * 1024 * 1024),
        };
        // The budget is pinned: the dense reservation it otherwise follows
        // depends on the architecture's dense kernel.
        let passes =
            test_probe::with_budget(4 * 1024 * 1024, || compare_arms(&shape, "2 KiB band"));
        assert_eq!(passes, 4, "expected four 2 KiB passes, ran {passes}");
    }

    #[test]
    fn a_limit_too_small_for_a_band_falls_back_to_dense() {
        let shape = Shape {
            lengths: vec![40 * 65_536, 40 * 65_536 + 3],
            slice_size: 65_536,
            recovery: 16,
            first_exponent: 0,
            memory_limit: Some(768 * 1024),
        };
        let passes = compare_arms(&shape, "limit below one band");
        assert_eq!(passes, 0, "the arm should not have been admissible");
    }

    #[test]
    fn a_single_pass_arm_fuses_the_source_digests_and_is_byte_identical() {
        // Few slices and many recovery blocks is the shape whose band covers
        // the whole slice: the feed is then in file order and the create drives
        // the fused hasher from it, so the FileDesc and IFSC packets in these
        // bytes are the ones the transform arm produced.
        let passes = compare_arms(
            &Shape {
                lengths: vec![8 * 32_768, 4 * 32_768 + 11],
                slice_size: 32_768,
                recovery: 128,
                first_exponent: 0,
                memory_limit: None,
            },
            "single pass, fused hashing",
        );
        assert_eq!(passes, 1, "expected a single-pass arm, ran {passes}");
    }

    /// `PAR2_TURBO_BINARY` names the reference implementation, exactly as the
    /// integration suite's interoperability cases do. Absent, this skips.
    #[test]
    fn the_reference_implementation_verifies_a_transform_created_set() {
        let Some(binary) = std::env::var_os("PAR2_TURBO_BINARY").map(PathBuf::from) else {
            eprintln!("PAR2_TURBO_BINARY is unset; skipping the interoperability check");
            return;
        };
        let shape = Shape {
            lengths: vec![4 * 32_768 + 137, 60 * 32_768, 70 * 32_768 + 1],
            slice_size: 32_768,
            recovery: 32,
            first_exponent: 0,
            memory_limit: None,
        };
        let root = tempfile::tempdir().unwrap();
        let sources = root.path().join("sources");
        let inputs = write_sources(&sources, &shape.lengths);
        // The reference resolves source names relative to the set, so the
        // outputs go beside the files they protect.
        let (_, passes) = create(&shape, &inputs, &sources, &sources, TransformPolicy::Force);
        assert!(passes > 0, "the transform arm never ran");

        let output = std::process::Command::new(&binary)
            .current_dir(&sources)
            .args(["v", "set.par2"])
            .output()
            .unwrap_or_else(|error| panic!("run {}: {error}", binary.display()));
        assert!(
            output.status.success(),
            "reference verification failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn a_safety_row_mismatch_recreates_every_volume_densely() {
        let shape = Shape {
            lengths: vec![4 * 32_768 + 137, 60 * 32_768],
            slice_size: 32_768,
            recovery: 32,
            first_exponent: 0,
            memory_limit: None,
        };
        let root = tempfile::tempdir().unwrap();
        let sources = root.path().join("sources");
        let inputs = write_sources(&sources, &shape.lengths);

        let (dense, _) = create(
            &shape,
            &inputs,
            &sources,
            &root.path().join("dense"),
            TransformPolicy::Never,
        );
        let (recovered, passes) = test_probe::with_fault(|| {
            create(
                &shape,
                &inputs,
                &sources,
                &root.path().join("faulted"),
                TransformPolicy::Force,
            )
        });
        assert_eq!(passes, 1, "the arm should abandon at its first band");
        assert_eq!(
            dense.keys().collect::<Vec<_>>(),
            recovered.keys().collect::<Vec<_>>()
        );
        for (name, expected) in &dense {
            assert!(
                &recovered[name] == expected,
                "{name} differs after the dense recreation"
            );
        }
    }

    #[test]
    fn bands_shared_by_every_worker_are_byte_identical() {
        // Several stripes per band and several passes, every band forced onto
        // the shared-stripe runner, plus the one-stripe 2 KiB band that takes
        // it on its own wherever more than one worker is configured.
        for (label, shape) in [
            (
                "shared, several stripes",
                Shape {
                    lengths: vec![40 * 65_536 + 5, 23 * 65_536],
                    slice_size: 65_536,
                    recovery: 300,
                    first_exponent: 1,
                    memory_limit: None,
                },
            ),
            (
                "shared, 2 KiB band",
                Shape {
                    lengths: vec![300 * 8_192, 300 * 8_192 + 77],
                    slice_size: 8_192,
                    recovery: 256,
                    first_exponent: 3,
                    memory_limit: Some(4 * 1024 * 1024),
                },
            ),
        ] {
            // Pinned budgets: several stripes and several workers per band
            // wherever more than one thread is configured, and the one-stripe
            // 2 KiB band.
            let budget = if shape.slice_size == 65_536 { 16 } else { 4 } * 1024 * 1024;
            let (passes, shared) = test_probe::with_shared_bands(|| {
                test_probe::with_budget(budget, || compare_arms(&shape, label))
            });
            assert!(passes > 1, "{label}: expected several passes, ran {passes}");
            assert_eq!(shared, passes, "{label}: a band skipped the shared runner");
        }
    }

    #[test]
    fn a_shared_band_safety_row_mismatch_recreates_every_volume_densely() {
        let shape = Shape {
            lengths: vec![4 * 32_768 + 137, 60 * 32_768],
            slice_size: 32_768,
            recovery: 32,
            first_exponent: 0,
            memory_limit: None,
        };
        let root = tempfile::tempdir().unwrap();
        let sources = root.path().join("sources");
        let inputs = write_sources(&sources, &shape.lengths);

        let (dense, _) = create(
            &shape,
            &inputs,
            &sources,
            &root.path().join("dense"),
            TransformPolicy::Never,
        );
        let ((recovered, passes), shared) = test_probe::with_shared_bands(|| {
            test_probe::with_fault(|| {
                create(
                    &shape,
                    &inputs,
                    &sources,
                    &root.path().join("faulted"),
                    TransformPolicy::Force,
                )
            })
        });
        assert_eq!(passes, 1, "the arm should abandon at its first band");
        assert_eq!(shared, 1, "the band should have run shared");
        assert_eq!(
            dense.keys().collect::<Vec<_>>(),
            recovered.keys().collect::<Vec<_>>()
        );
        for (name, expected) in &dense {
            assert!(
                &recovered[name] == expected,
                "{name} differs after the dense recreation"
            );
        }
    }

    #[test]
    fn a_rendezvous_releases_waiters_when_a_party_leaves() {
        let rendezvous = Rendezvous::new(3);
        std::thread::scope(|scope| {
            for _ in 0..2 {
                scope.spawn(|| {
                    for _ in 0..4 {
                        rendezvous.wait();
                    }
                });
            }
            // The third party never arrives; leaving lets the other two finish
            // all four rounds between themselves.
            rendezvous.leave();
        });
    }

    fn exponents(first: u32, count: usize) -> Vec<RecoveryExponent> {
        (0..count as u32).map(|at| first + at).collect()
    }

    #[test]
    fn a_contiguous_window_is_recognised_and_a_gap_is_not() {
        assert_eq!(contiguous_range(&exponents(7, 4)), Some(7..11));
        assert_eq!(contiguous_range(&[1, 2, 4]), None);
        assert_eq!(contiguous_range(&[65_534, 65_535]), None);
    }

    #[test]
    fn the_automatic_policy_refuses_shapes_the_transform_cannot_win() {
        // Too few sources for the 257-dimension's fixed cost to pay off.
        assert!(
            admit(
                65_536,
                64,
                &exponents(0, 64),
                1 << 30,
                TransformPolicy::Auto
            )
            .is_none()
        );
        // Enough sources, but one output prunes the schedule back to the dense
        // fold count.
        assert!(
            admit(
                65_536,
                4000,
                &exponents(0, 1),
                1 << 30,
                TransformPolicy::Auto
            )
            .is_none()
        );
    }

    #[test]
    fn the_kill_switch_policy_refuses_every_shape() {
        assert!(
            admit(
                65_536,
                4000,
                &exponents(0, 256),
                1 << 30,
                TransformPolicy::Never
            )
            .is_none()
        );
    }

    #[test]
    fn an_admitted_shape_fits_the_budget_it_was_given() {
        let budget = 256 * 1024 * 1024;
        let arm = admit(
            768_000,
            4000,
            &exponents(0, 256),
            budget,
            TransformPolicy::Auto,
        )
        .expect("this shape is exactly what the arm is for");
        let shape = arm.shape();
        assert!(shape.total_bytes <= budget, "{shape:?}");
        assert!(shape.band.is_multiple_of(shape.stripe), "{shape:?}");
        assert!(shape.band >= MIN_BAND_BYTES, "{shape:?}");
        assert!(shape.passes <= MAX_PASSES, "{shape:?}");
        assert_eq!(shape.chunks, shape.band / shape.stripe);
    }

    #[test]
    fn a_budget_too_small_for_one_band_is_refused() {
        // 4000 sources cannot hold even a 2 KiB band in 8 MiB.
        assert!(
            admit(
                768_000,
                4000,
                &exponents(0, 256),
                8 * 1024 * 1024,
                TransformPolicy::Force
            )
            .is_none()
        );
    }
}
