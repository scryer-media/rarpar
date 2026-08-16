//! Forward PAR2 recovery-data encoding.
//!
//! The encoder keeps the recovery output in output-major order while it walks
//! each input slice in bounded, stride-aligned stripes.  Input batches rotate
//! through two staging areas, so the arithmetic path can accumulate a complete
//! output stripe without requiring a source-sized working allocation.
//!
//! Accumulation and output finishing split the recovery outputs into
//! contiguous bands, one rayon task per band.  Bands write disjoint
//! output-major regions and never share mutable state, so the produced
//! recovery bytes are identical at every band count.

use std::mem::size_of;

use crate::error::{Par2Error, Result};
use crate::gf;
use crate::types::{
    CancellationToken, MAX_TOTAL_INPUT_SLICES, ProgressCallback, ProgressPhase, ProgressStage,
    ProgressUpdate, RecoveryExponent,
};
use reedsolomon_rs::gf_simd::{self, PreparedFactorSrc};

use super::plan::default_memory_limit;

/// Sources per input batch for the families whose kernels take one slice per
/// source in fixed-size groups on x86 (the folded pair kernels take two groups
/// of six; the packed XOR-JIT is built for twelve regions).
const DEFAULT_INPUT_GROUPING: usize = 12;
/// Sources per input batch for the aarch64 CLMUL family. Its kernel folds
/// eight sources into the destination per pass, so twelve inputs cost a full
/// pass plus a half-empty one whose per-block reduction and destination
/// traffic are amortized over only four sources; sixteen is two full passes.
/// This is the reference's own batching rule (`inputBatchSize = 12 +
/// idealInputMultiple/2`, rounded down to a multiple of `idealInputMultiple`,
/// which is 8 for CLMUL_NEON/SHA3) — a fact about the kernel's group shape,
/// not about any core.
#[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
const CLMUL_INPUT_GROUPING: usize = 16;
/// Upper bound on any family's input grouping: sizes the fixed per-row arrays
/// (coefficient rows, prepared-source descriptors) that must not touch the
/// heap per output row.
const MAX_INPUT_GROUPING: usize = 16;
const _: () = assert!(DEFAULT_INPUT_GROUPING <= MAX_INPUT_GROUPING);
const _: () = assert!(CLMUL_INPUT_GROUPING <= MAX_INPUT_GROUPING);
/// Staging areas in the per-stripe hand-off ring.
///
/// The ring is general in the code below — the producer fills area
/// `batch_index % STAGING_AREA_COUNT` and may run `STAGING_AREA_COUNT - 1`
/// batches ahead of the slowest band — but two is what [`BufferPlan`] admits
/// and therefore what [`Par2MemoryPlan`](super::plan::Par2MemoryPlan)
/// describes, so the constant and the accounting move together. Two is also
/// the reference's own depth. One area would serialize the fill behind the
/// arithmetic, which is the whole point of the pipeline.
const STAGING_AREA_COUNT: usize = 2;
const TRANSFER_BUFFER_COUNT: usize = 2;
const _: () = assert!(STAGING_AREA_COUNT >= 2);

/// Folded coefficient groups covered by one output row, bounding the stack
/// reference tables in `accumulate_band`. The folded family's
/// [`KernelContract`] always uses [`DEFAULT_INPUT_GROUPING`], so this is the
/// exact group count, not a worst case; the arm still checks before slicing.
#[cfg(target_arch = "x86_64")]
const MAX_FOLDED_GROUPS: usize = DEFAULT_INPUT_GROUPING / gf_simd::FOLDED_GROUP;

/// Worker bands used by forward accumulation. `WEAVER_PAR2_CREATE_THREADS=N`
/// pins the band count (1 = the sequential pre-banding behavior) so the two
/// shapes can be A/B'd without a rebuild (same escape-hatch pattern as
/// `WEAVER_GF16_FOLDED_AVX512`); unset or `0` follows the host CPU count.
///
/// The resolved value is process-stable by construction: it must not read
/// `rayon::current_num_threads()`, whose answer is pool-relative and would
/// make the plan's memory accounting differ between a caller's rayon worker
/// and the main thread (breaking `Par2CreatePlan` equality), and whose first
/// call would eagerly spawn the global pool from plan-only paths. Bands
/// therefore follow `available_parallelism`.
///
/// Forward accumulation now runs one scoped OS thread per band (see
/// [`encode_stripe_banded`] for why a work-stealing pool cannot host a
/// blocking producer/consumer ring), so this is literally the worker count of
/// a create pass rather than only a partitioning width — a deliberately huge
/// `WEAVER_PAR2_CREATE_THREADS` now costs that many threads per stripe.
/// Source hashing and staged-volume validation still run on rayon.
pub(crate) fn configured_create_threads() -> usize {
    static CONFIGURED: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *CONFIGURED.get_or_init(|| {
        // Single-threaded wasm (`wasm32-wasip1`) has no worker pool at all;
        // keep rayon machinery untouched there, exactly as before. On
        // `wasm32-wasip1-threads` the probe reports `true` and the normal
        // resolution below applies — including `WEAVER_PAR2_CREATE_THREADS`,
        // which is how an embedder states the host width, because
        // `available_parallelism()` answers `Ok(1)` under wasi (the guest
        // cannot see the host's core count) and would otherwise pin the
        // banding to 1 on a perfectly capable threaded runtime.
        if !reedsolomon_rs::threading::parallel_enabled() {
            return 1;
        }
        std::env::var("WEAVER_PAR2_CREATE_THREADS")
            .ok()
            .and_then(|value| value.trim().parse::<usize>().ok())
            .filter(|&threads| threads != 0)
            .unwrap_or_else(|| {
                std::thread::available_parallelism()
                    .map(std::num::NonZeroUsize::get)
                    .unwrap_or(1)
            })
    })
}

/// Input grouping for the slice-per-source families that have no structural
/// group size (`Portable`, `Simd`): the CLMUL grouping on aarch64, the default
/// elsewhere. `WEAVER_PAR2_CREATE_GROUPING=N` (1..=16) pins it so the two
/// batch shapes can be A/B'd from one binary (same escape-hatch pattern as
/// `WEAVER_PAR2_CREATE_THREADS`); unset, `0`, or out of range means the
/// family default. Process-stable by construction: the staging plan and the
/// batch loop must agree.
fn configured_input_grouping() -> usize {
    static CONFIGURED: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *CONFIGURED.get_or_init(|| {
        #[cfg(target_arch = "aarch64")]
        let family_default = CLMUL_INPUT_GROUPING;
        #[cfg(not(target_arch = "aarch64"))]
        let family_default = DEFAULT_INPUT_GROUPING;
        std::env::var("WEAVER_PAR2_CREATE_GROUPING")
            .ok()
            .and_then(|value| value.trim().parse::<usize>().ok())
            .filter(|&grouping| (1..=MAX_INPUT_GROUPING).contains(&grouping))
            .unwrap_or(family_default)
    })
}

/// Band shape for one encoding pass: `(band_size, band_count)` with
/// `band_count = ceil(output_count / band_size)` exactly, so chunked splits,
/// workspace counts, and memory admission all agree. Never zero-sized.
fn create_band_shape(output_count: usize) -> (usize, usize) {
    let outputs = output_count.max(1);
    let target = configured_create_threads().clamp(1, outputs);
    let band_size = outputs.div_ceil(target);
    (band_size, outputs.div_ceil(band_size))
}

/// Forward working-set quantities used by both planning and encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ForwardMemoryEstimate {
    pub(crate) factor_workspace_bytes: usize,
    pub(crate) jit_workspace_bytes: usize,
    pub(crate) stripe_buffer_bytes: usize,
    pub(crate) processing_peak_bytes: usize,
}

/// Arithmetic path requested for forward encoding.
///
/// `Auto` follows the creation-specific runtime ladder (the oracle's:
/// affine/shuffle families only).  The other variants are
/// useful for deterministic validation and controlled
/// benchmarking; an explicitly requested unavailable tier returns an error.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ForwardKernel {
    /// Select the best supported path for the current process.
    #[default]
    Auto,
    /// Word-wise portable arithmetic.  This is the final non-SIMD fallback.
    Portable,
    /// Direct grouped GF(2^16) SIMD dispatch.
    Simd,
    /// AVX2 split-layout folded dispatch (GFNI, 512/256-bit shuffle2x).
    #[cfg(target_arch = "x86_64")]
    Folded,
    /// Packed AVX2 XOR-JIT dispatch (fast-JIT CPUs without GFNI).
    #[cfg(target_arch = "x86_64")]
    XorJitAvx2,
}

/// Options controlling one forward encoding pass.
pub struct ForwardEncoderOptions {
    /// Maximum bytes retained by the stripe controller and active arithmetic
    /// tier.  The default follows the creator's system-memory policy.
    pub memory_limit: Option<usize>,
    /// Cooperative cancellation shared with the caller.
    pub cancel: Option<CancellationToken>,
    /// Optional progress callback.  Updates use the existing long-running
    /// operation progress shape and report the number of completed stripes.
    pub progress: Option<ProgressCallback>,
    /// Arithmetic path to use.
    pub kernel: ForwardKernel,
}

impl Default for ForwardEncoderOptions {
    fn default() -> Self {
        Self {
            memory_limit: None,
            cancel: None,
            progress: None,
            kernel: ForwardKernel::Auto,
        }
    }
}

/// One complete recovery block produced by [`ForwardEncoder::encode`].
#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForwardRecoveryBlock {
    /// The PAR2 recovery exponent assigned to this block.
    pub exponent: RecoveryExponent,
    /// The recovery payload, exactly `slice_size` bytes long.
    pub data: Vec<u8>,
}

/// Ordered destination for streamed recovery stripes.
///
/// Calls occur in increasing stripe offset and increasing output index order.
/// A writer can therefore place each chunk directly into its recovery packet
/// without retaining all recovery blocks in memory.
pub trait ForwardRecoverySink {
    /// Store one output stripe.
    fn write_recovery_chunk(
        &mut self,
        output_index: usize,
        exponent: RecoveryExponent,
        offset: u64,
        data: &[u8],
    ) -> Result<()>;
}

/// Source-slice access used by the forward stripe controller.
pub(crate) trait ForwardSourceProvider {
    /// Number of logical source slices in encoder order.
    fn source_count(&self) -> usize;

    /// Length of one source slice before zero padding.
    fn source_slice_len(&self, source_index: usize) -> Result<usize>;

    /// Read a slice range into the supplied staging buffer.
    fn read_source_chunk(
        &mut self,
        source_index: usize,
        offset: usize,
        destination: &mut [u8],
    ) -> Result<usize>;
}

#[cfg(test)]
struct InMemorySourceProvider<'a> {
    sources: &'a [&'a [u8]],
}

#[cfg(test)]
impl ForwardSourceProvider for InMemorySourceProvider<'_> {
    fn source_count(&self) -> usize {
        self.sources.len()
    }

    fn source_slice_len(&self, source_index: usize) -> Result<usize> {
        self.sources
            .get(source_index)
            .map(|source| source.len())
            .ok_or_else(|| invalid_input("source slice index is out of range"))
    }

    fn read_source_chunk(
        &mut self,
        source_index: usize,
        offset: usize,
        destination: &mut [u8],
    ) -> Result<usize> {
        let source = self
            .sources
            .get(source_index)
            .ok_or_else(|| invalid_input("source slice index is out of range"))?;
        let start = offset.min(source.len());
        let take = destination.len().min(source.len().saturating_sub(start));
        destination[..take].copy_from_slice(&source[start..start + take]);
        Ok(take)
    }
}

/// Forward PAR2 recovery encoder.
#[derive(Clone, Debug)]
pub struct ForwardEncoder {
    slice_size: usize,
    recovery_exponents: Vec<RecoveryExponent>,
}

impl ForwardEncoder {
    /// Construct an encoder for one PAR2 slice size and ordered exponents.
    pub fn new(slice_size: usize, recovery_exponents: Vec<RecoveryExponent>) -> Result<Self> {
        if slice_size == 0 || !slice_size.is_multiple_of(4) {
            return Err(invalid_input(format!(
                "slice size must be a nonzero multiple of 4, got {slice_size}"
            )));
        }
        if recovery_exponents.len() > u32::MAX as usize {
            return Err(resource_limit("recovery output count exceeds u32"));
        }
        Ok(Self {
            slice_size,
            recovery_exponents,
        })
    }

    /// The configured slice size.
    #[cfg(test)]
    pub fn slice_size(&self) -> usize {
        self.slice_size
    }

    /// Return the CPU paths available in this process.
    #[cfg(test)]
    pub fn available_kernels() -> Vec<ForwardKernel> {
        let kernels = vec![ForwardKernel::Portable, ForwardKernel::Simd];
        #[cfg(target_arch = "x86_64")]
        {
            let mut kernels = kernels;
            let capabilities = runtime_kernel_capabilities();
            if capabilities.folded {
                kernels.push(ForwardKernel::Folded);
            }
            if capabilities.avx2_jit {
                kernels.push(ForwardKernel::XorJitAvx2);
            }
            kernels
        }
        #[cfg(not(target_arch = "x86_64"))]
        kernels
    }

    /// Resolve the automatic runtime choice without starting an encoding pass.
    #[cfg(test)]
    pub fn selected_kernel(&self, requested: ForwardKernel) -> Result<ForwardKernel> {
        resolve_kernel_with_capabilities(requested, runtime_kernel_capabilities())
            .map(public_kernel)
    }

    /// Encode all recovery blocks into memory.
    #[cfg(test)]
    pub fn encode(
        &self,
        sources: &[&[u8]],
        options: &ForwardEncoderOptions,
    ) -> Result<Vec<ForwardRecoveryBlock>> {
        let mut sink = VecRecoverySink::new(&self.recovery_exponents, self.slice_size);
        let mut provider = InMemorySourceProvider { sources };
        self.encode_to(&mut provider, options, &mut sink)?;
        Ok(sink.blocks)
    }

    /// Encode in-memory source slices through an ordered, bounded sink.
    #[cfg(test)]
    pub fn encode_slices_to<S: ForwardRecoverySink>(
        &self,
        sources: &[&[u8]],
        options: &ForwardEncoderOptions,
        sink: &mut S,
    ) -> Result<()> {
        let mut provider = InMemorySourceProvider { sources };
        self.encode_to(&mut provider, options, sink)
    }

    /// Encode provider-backed source slices through an ordered, bounded sink.
    pub fn encode_to<P: ForwardSourceProvider + ?Sized, S: ForwardRecoverySink>(
        &self,
        provider: &mut P,
        options: &ForwardEncoderOptions,
        sink: &mut S,
    ) -> Result<()> {
        validate_provider(provider, self.slice_size)?;
        check_cancel(options)?;

        if self.recovery_exponents.is_empty() {
            return Ok(());
        }

        let memory_limit = options.memory_limit.unwrap_or_else(default_memory_limit);
        let (kernel, buffers) = select_kernel_for_memory(
            self.slice_size,
            self.recovery_exponents.len(),
            provider.source_count(),
            memory_limit,
            options.kernel,
        )?;
        let contract = KernelContract::for_kernel(kernel);

        let factors = FactorSource::new(provider.source_count());

        // Held behind `Arc` so one filled area can be handed to every band
        // worker for the duration of a batch and reclaimed for refilling by
        // `Arc::get_mut` once they have all let go — the hand-off is the
        // ownership, with no aliasing of a mutable buffer anywhere.
        let mut staging: Vec<std::sync::Arc<AlignedBuffer>> = (0..STAGING_AREA_COUNT)
            .map(|_| std::sync::Arc::new(AlignedBuffer::new(buffers.staging_bytes)))
            .collect();
        let mut transfers: Vec<AlignedBuffer> = (0..TRANSFER_BUFFER_COUNT)
            .map(|_| AlignedBuffer::new(buffers.aligned_chunk_len))
            .collect();
        let mut output = AlignedBuffer::new(buffers.output_bytes);

        let (band_size, band_count) = create_band_shape(self.recovery_exponents.len());
        #[cfg(not(target_arch = "x86_64"))]
        let _ = band_count;
        #[cfg(target_arch = "x86_64")]
        let mut jit_workspaces: Vec<reedsolomon_rs::xor_jit::packed::PackedJitWorkspace> =
            (0..band_count).map(|_| Default::default()).collect();
        #[cfg(target_arch = "x86_64")]
        let jit_code_budget = buffers.jit_build_limit_bytes;

        let stripe_count = self.slice_size.div_ceil(buffers.chunk_len);
        let stripe_count_u32 = u32::try_from(stripe_count)
            .map_err(|_| resource_limit("stripe count exceeds progress range"))?;
        let total_bytes = (self.recovery_exponents.len() as u64)
            .checked_mul(self.slice_size as u64)
            .ok_or_else(|| resource_limit("progress byte count overflow"))?;

        // One dispatch per stripe. The band workers are started once for the
        // stripe and walk every input batch themselves; this thread is the
        // producer, filling the staging ring ahead of them. The ring is what
        // bounds the hand-off: the producer may run `STAGING_AREA_COUNT - 1`
        // batches ahead of the slowest band and no further, which is the same
        // two-stage overlap the previous per-batch `rayon::in_place_scope`
        // gave, minus one scope entry and one band fan-out per input batch
        // (342 of each per stripe on the 4096-source create shape).
        //
        // `banded` is false exactly when banding is off (single-threaded wasm
        // and the `WEAVER_PAR2_CREATE_THREADS=1` escape hatch); the sequential
        // arm performs the identical operation order on one thread, so the
        // produced bytes cannot differ between the arms.
        let batch_starts: Vec<usize> = (0..provider.source_count())
            .step_by(contract.input_grouping)
            .collect();
        let banded = band_size < self.recovery_exponents.len();

        let mut stripe_offset = 0usize;
        let mut stripe_index = 0usize;
        while stripe_offset < self.slice_size {
            check_cancel(options)?;
            let actual_len = (self.slice_size - stripe_offset).min(buffers.chunk_len);
            let aligned_len = round_up(actual_len, contract.stride)?;
            if banded {
                encode_stripe_banded(
                    kernel,
                    provider,
                    options,
                    contract,
                    &factors,
                    &self.recovery_exponents,
                    &mut staging,
                    &mut transfers[0],
                    &mut output.as_bytes_mut()[..buffers.output_bytes],
                    &batch_starts,
                    StripeGeometry {
                        stripe_offset,
                        actual_len,
                        aligned_len,
                        output_stride: buffers.row_stride,
                    },
                    band_size,
                    #[cfg(target_arch = "x86_64")]
                    &mut jit_workspaces,
                    #[cfg(target_arch = "x86_64")]
                    jit_code_budget,
                )?;
            } else {
                output.as_bytes_mut()[..buffers.output_bytes].fill(0);
                if let Some(&first_start) = batch_starts.first() {
                    fill_staging(
                        kernel,
                        std::sync::Arc::get_mut(&mut staging[0])
                            .ok_or_else(|| resource_limit("staging area is still in use"))?,
                        &mut transfers[0],
                        provider,
                        first_start,
                        stripe_offset,
                        actual_len,
                        aligned_len,
                        contract,
                    )?;
                }
                for (batch_index, &source_start) in batch_starts.iter().enumerate() {
                    check_cancel(options)?;
                    let live_inputs = provider
                        .source_count()
                        .saturating_sub(source_start)
                        .min(contract.input_grouping);
                    let next_start = batch_starts.get(batch_index + 1).copied();
                    let current_area = batch_index % STAGING_AREA_COUNT;
                    let next_area = (batch_index + 1) % STAGING_AREA_COUNT;
                    accumulate_batch(
                        kernel,
                        &mut output.as_bytes_mut()[..buffers.output_bytes],
                        &staging[current_area],
                        &factors,
                        &self.recovery_exponents,
                        source_start,
                        live_inputs,
                        aligned_len,
                        buffers.row_stride,
                        contract,
                        band_size,
                        #[cfg(target_arch = "x86_64")]
                        &mut jit_workspaces,
                        #[cfg(target_arch = "x86_64")]
                        jit_code_budget,
                    )?;
                    if let Some(next_start) = next_start {
                        fill_staging(
                            kernel,
                            std::sync::Arc::get_mut(&mut staging[next_area])
                                .ok_or_else(|| resource_limit("staging area is still in use"))?,
                            &mut transfers[(batch_index + 1) % TRANSFER_BUFFER_COUNT],
                            provider,
                            next_start,
                            stripe_offset,
                            actual_len,
                            aligned_len,
                            contract,
                        )?;
                    }
                }

                finish_output(
                    kernel,
                    &mut output.as_bytes_mut()[..buffers.output_bytes],
                    buffers.row_stride,
                    aligned_len,
                    self.recovery_exponents.len(),
                )?;
            }

            for (output_index, &exponent) in self.recovery_exponents.iter().enumerate() {
                let start = output_index
                    .checked_mul(buffers.row_stride)
                    .ok_or_else(|| resource_limit("output stripe offset overflow"))?;
                let end = start
                    .checked_add(actual_len)
                    .ok_or_else(|| resource_limit("output stripe end overflow"))?;
                sink.write_recovery_chunk(
                    output_index,
                    exponent,
                    stripe_offset as u64,
                    &output.as_bytes()[start..end],
                )?;
            }

            stripe_index += 1;
            let completed_stripe = u32::try_from(stripe_index - 1)
                .map_err(|_| resource_limit("completed stripe exceeds progress range"))?;
            report_progress(
                options,
                completed_stripe,
                stripe_count_u32,
                (stripe_index as u64)
                    .saturating_mul(self.recovery_exponents.len() as u64)
                    .saturating_mul(buffers.chunk_len as u64)
                    .min(total_bytes),
                total_bytes,
            );
            stripe_offset = stripe_offset
                .checked_add(actual_len)
                .ok_or_else(|| resource_limit("stripe offset overflow"))?;
        }

        check_cancel(options)
    }
}

/// The per-stripe quantities every band worker and the producer share.
#[derive(Clone, Copy)]
struct StripeGeometry {
    stripe_offset: usize,
    actual_len: usize,
    aligned_len: usize,
    output_stride: usize,
}

/// One filled staging area handed from the producer to the band workers.
///
/// The `Arc` is the hand-off: the producer cannot refill an area until every
/// band has dropped its clone, which is exactly the condition
/// [`StripeFeed`] tracks, and `Arc::get_mut` then proves it rather than
/// trusting it.
#[derive(Clone)]
struct BatchTicket {
    staging: std::sync::Arc<AlignedBuffer>,
    source_start: usize,
    live_inputs: usize,
}

struct FeedState {
    tickets: [Option<BatchTicket>; STAGING_AREA_COUNT],
    /// Batches published so far; a band may consume batch `index` once
    /// `published > index`.
    published: usize,
    /// Batches every band has finished; the producer may refill the area of
    /// batch `index` once `completed + STAGING_AREA_COUNT > index`.
    completed: usize,
    /// Bands that have finished the batch currently resident in each area.
    /// Unambiguous because a band can never be more than one batch ahead of
    /// the slowest: reaching batch `b + 2` needs `published > b + 2`, which
    /// needs `completed > b`, which needs every band to have finished `b`.
    done: [usize; STAGING_AREA_COUNT],
    /// Set by whichever side failed first (producer error, cancellation, or a
    /// band's error) so the other side stops waiting instead of deadlocking.
    failed: bool,
}

/// The bounded producer/consumer hand-off for one stripe.
struct StripeFeed {
    state: std::sync::Mutex<FeedState>,
    ready: std::sync::Condvar,
    free: std::sync::Condvar,
    band_count: usize,
}

impl StripeFeed {
    fn new(band_count: usize) -> Self {
        Self {
            state: std::sync::Mutex::new(FeedState {
                tickets: std::array::from_fn(|_| None),
                published: 0,
                completed: 0,
                done: [0; STAGING_AREA_COUNT],
                failed: false,
            }),
            ready: std::sync::Condvar::new(),
            free: std::sync::Condvar::new(),
            band_count,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, FeedState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Producer: block until the area for `batch_index` may be refilled, and
    /// release the producer-side ticket clone that pins it. `false` means the
    /// pass has already failed and the producer must stop.
    fn wait_for_area(&self, batch_index: usize) -> bool {
        let mut state = self.lock();
        while !state.failed && state.completed + STAGING_AREA_COUNT <= batch_index {
            state = self
                .free
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        if state.failed {
            return false;
        }
        state.tickets[batch_index % STAGING_AREA_COUNT] = None;
        true
    }

    /// Producer: hand a filled area to the bands.
    fn publish(&self, batch_index: usize, ticket: BatchTicket) {
        let mut state = self.lock();
        state.tickets[batch_index % STAGING_AREA_COUNT] = Some(ticket);
        state.published = batch_index + 1;
        drop(state);
        self.ready.notify_all();
    }

    /// Band: block until batch `batch_index` is available. `None` means the
    /// pass failed elsewhere and this band must stop.
    fn acquire(&self, batch_index: usize) -> Option<BatchTicket> {
        let mut state = self.lock();
        while !state.failed && state.published <= batch_index {
            state = self
                .ready
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        if state.failed {
            return None;
        }
        state.tickets[batch_index % STAGING_AREA_COUNT].clone()
    }

    /// Band: record that this band is done with `batch_index`. Must be called
    /// only after the band's own ticket clone has been dropped.
    fn release(&self, batch_index: usize) {
        let mut state = self.lock();
        let area = batch_index % STAGING_AREA_COUNT;
        state.done[area] += 1;
        if state.done[area] == self.band_count {
            state.done[area] = 0;
            state.completed = batch_index + 1;
            drop(state);
            self.free.notify_all();
        }
    }

    /// Stop both sides. Idempotent, and safe to call from either side.
    fn fail(&self) {
        let mut state = self.lock();
        state.failed = true;
        // Dropping the parked tickets here would race a band that still holds
        // its clone; the areas are reclaimed when the whole feed is dropped.
        drop(state);
        self.ready.notify_all();
        self.free.notify_all();
    }
}

/// Accumulate one stripe with the band workers dispatched once, fed by this
/// thread through [`StripeFeed`].
///
/// The workers are plain scoped OS threads rather than rayon tasks on purpose:
/// a band that waits for the producer, and a producer that waits for the
/// slowest band, are blocking waits, and blocking waits inside a work-stealing
/// pool deadlock as soon as the pool is narrower than the band count (a queued
/// band would never run, so the ring would never drain). The band count is the
/// process-stable [`configured_create_threads`] value the memory plan is
/// already built on, so this creates exactly the workers the plan admits.
#[allow(clippy::too_many_arguments)]
fn encode_stripe_banded<P: ForwardSourceProvider + ?Sized>(
    kernel: ResolvedKernel,
    provider: &mut P,
    options: &ForwardEncoderOptions,
    contract: KernelContract,
    factors: &FactorSource,
    exponents: &[RecoveryExponent],
    staging: &mut [std::sync::Arc<AlignedBuffer>],
    transfer: &mut AlignedBuffer,
    output: &mut [u8],
    batch_starts: &[usize],
    geometry: StripeGeometry,
    band_size: usize,
    #[cfg(target_arch = "x86_64")]
    jit_workspaces: &mut [reedsolomon_rs::xor_jit::packed::PackedJitWorkspace],
    #[cfg(target_arch = "x86_64")] jit_code_budget: usize,
) -> Result<()> {
    debug_assert_eq!(output.len(), exponents.len() * geometry.output_stride);
    let band_bytes = checked_mul(
        band_size,
        geometry.output_stride,
        "band byte range overflow",
    )?;
    let band_count = exponents.len().div_ceil(band_size);
    #[cfg(target_arch = "x86_64")]
    debug_assert_eq!(jit_workspaces.len(), band_count);
    let batch_count = batch_starts.len();
    let feed = StripeFeed::new(band_count);
    let feed = &feed;
    let source_count = provider.source_count();

    let mut band_results: Vec<Result<()>> = Vec::with_capacity(band_count);
    let produced = std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(band_count);
        let bands = output
            .chunks_mut(band_bytes)
            .zip(exponents.chunks(band_size));
        #[cfg(target_arch = "x86_64")]
        let bands = bands.zip(jit_workspaces.iter_mut());
        for band in bands {
            #[cfg(target_arch = "x86_64")]
            let ((band_output, band_exponents), jit_workspace) = band;
            #[cfg(not(target_arch = "x86_64"))]
            let (band_output, band_exponents) = band;
            handles.push(scope.spawn(move || {
                accumulate_band_stream(
                    feed,
                    kernel,
                    band_output,
                    band_exponents,
                    factors,
                    contract,
                    geometry,
                    batch_count,
                    #[cfg(target_arch = "x86_64")]
                    jit_workspace,
                    #[cfg(target_arch = "x86_64")]
                    jit_code_budget,
                )
            }));
        }

        let produced = produce_stripe(
            kernel,
            provider,
            options,
            contract,
            staging,
            transfer,
            batch_starts,
            geometry,
            source_count,
            feed,
        );
        if produced.is_err() {
            feed.fail();
        }
        band_results.extend(handles.into_iter().map(|handle| {
            handle.join().unwrap_or_else(|payload| {
                // `panic = "abort"` in release makes this unreachable
                // there; under a unwinding test profile the band's panic
                // must surface as a panic, not as a silent short pass.
                std::panic::resume_unwind(payload)
            })
        }));
        produced
    });

    produced?;
    for result in band_results {
        result?;
    }
    Ok(())
}

/// The producer half of [`encode_stripe_banded`]: fill one staging area per
/// input batch, in increasing source order, and hand it to the bands.
#[allow(clippy::too_many_arguments)]
fn produce_stripe<P: ForwardSourceProvider + ?Sized>(
    kernel: ResolvedKernel,
    provider: &mut P,
    options: &ForwardEncoderOptions,
    contract: KernelContract,
    staging: &mut [std::sync::Arc<AlignedBuffer>],
    transfer: &mut AlignedBuffer,
    batch_starts: &[usize],
    geometry: StripeGeometry,
    source_count: usize,
    feed: &StripeFeed,
) -> Result<()> {
    for (batch_index, &source_start) in batch_starts.iter().enumerate() {
        check_cancel(options)?;
        if !feed.wait_for_area(batch_index) {
            // A band already failed; its error is the one that surfaces.
            return Ok(());
        }
        let area = batch_index % STAGING_AREA_COUNT;
        let buffer = std::sync::Arc::get_mut(&mut staging[area])
            .ok_or_else(|| resource_limit("staging area is still in use"))?;
        fill_staging(
            kernel,
            buffer,
            transfer,
            provider,
            source_start,
            geometry.stripe_offset,
            geometry.actual_len,
            geometry.aligned_len,
            contract,
        )?;
        let live_inputs = source_count
            .saturating_sub(source_start)
            .min(contract.input_grouping);
        feed.publish(
            batch_index,
            BatchTicket {
                staging: std::sync::Arc::clone(&staging[area]),
                source_start,
                live_inputs,
            },
        );
    }
    Ok(())
}

/// One band worker: zero its own output rows, accumulate every input batch of
/// the stripe from the feed, then finish its rows.
#[allow(clippy::too_many_arguments)]
fn accumulate_band_stream(
    feed: &StripeFeed,
    kernel: ResolvedKernel,
    band_output: &mut [u8],
    band_exponents: &[RecoveryExponent],
    factors: &FactorSource,
    contract: KernelContract,
    geometry: StripeGeometry,
    batch_count: usize,
    #[cfg(target_arch = "x86_64")]
    jit_workspace: &mut reedsolomon_rs::xor_jit::packed::PackedJitWorkspace,
    #[cfg(target_arch = "x86_64")] jit_code_budget: usize,
) -> Result<()> {
    // Each band zeroes exactly its own rows, and the bands partition the
    // output buffer, so the union is the whole-buffer clear the per-batch
    // shape did on the calling thread.
    band_output.fill(0);
    for batch_index in 0..batch_count {
        let Some(ticket) = feed.acquire(batch_index) else {
            return Ok(());
        };
        let accumulated = accumulate_band(
            kernel,
            band_output,
            &ticket.staging,
            factors,
            band_exponents,
            ticket.source_start,
            ticket.live_inputs,
            geometry.aligned_len,
            geometry.output_stride,
            contract,
            #[cfg(target_arch = "x86_64")]
            jit_workspace,
            #[cfg(target_arch = "x86_64")]
            jit_code_budget,
        );
        // Released before the completion is recorded: the producer treats the
        // recorded completion as proof that no band still holds the area.
        drop(ticket);
        if let Err(error) = accumulated {
            feed.fail();
            return Err(error);
        }
        feed.release(batch_index);
    }
    finish_band_rows(
        kernel,
        band_output,
        geometry.output_stride,
        geometry.aligned_len,
        band_exponents.len(),
    )
    .inspect_err(|_| feed.fail())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResolvedKernel {
    Portable,
    Simd,
    #[cfg(target_arch = "x86_64")]
    Folded,
    #[cfg(target_arch = "x86_64")]
    XorJitAvx2,
}

#[cfg(test)]
fn public_kernel(kernel: ResolvedKernel) -> ForwardKernel {
    match kernel {
        ResolvedKernel::Portable => ForwardKernel::Portable,
        ResolvedKernel::Simd => ForwardKernel::Simd,
        #[cfg(target_arch = "x86_64")]
        ResolvedKernel::Folded => ForwardKernel::Folded,
        #[cfg(target_arch = "x86_64")]
        ResolvedKernel::XorJitAvx2 => ForwardKernel::XorJitAvx2,
    }
}

fn resolve_kernel_with_capabilities(
    requested: ForwardKernel,
    capabilities: KernelCapabilities,
) -> Result<ResolvedKernel> {
    #[cfg(not(target_arch = "x86_64"))]
    let _ = capabilities;

    match requested {
        ForwardKernel::Portable => Ok(ResolvedKernel::Portable),
        ForwardKernel::Simd => Ok(ResolvedKernel::Simd),
        #[cfg(target_arch = "x86_64")]
        ForwardKernel::Folded => {
            if capabilities.folded {
                return Ok(ResolvedKernel::Folded);
            }
            Err(unavailable_kernel("folded AVX2"))
        }
        #[cfg(target_arch = "x86_64")]
        ForwardKernel::XorJitAvx2 => {
            if capabilities.avx2_jit {
                return Ok(ResolvedKernel::XorJitAvx2);
            }
            Err(unavailable_kernel("packed AVX2 XOR-JIT"))
        }
        ForwardKernel::Auto => {
            // The oracle's ladder, arm for arm (`default_method`,
            // gf16mul.cpp:1550-1572): affine when GFNI exists, 512-bit
            // shuffle when AVX512BW/VL exists, and only then — at the AVX2
            // line — the XOR-JIT behind the fast-JIT CPU gate, with the
            // 256-bit shuffle as the remaining AVX2 fallback. The AVX-512
            // JIT is gone entirely (c5-measured; git history preserves it).
            #[cfg(target_arch = "x86_64")]
            {
                if capabilities.folded && (capabilities.folded_wide || !capabilities.avx2_jit) {
                    return Ok(ResolvedKernel::Folded);
                }
                if capabilities.avx2_jit {
                    return Ok(ResolvedKernel::XorJitAvx2);
                }
            }
            Ok(ResolvedKernel::Simd)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct KernelCapabilities {
    /// Split-layout folded family available (AVX2 present).
    folded: bool,
    /// The folded family's non-GFNI arm runs the 512-bit shuffle kernel.
    folded_wide: bool,
    /// Packed AVX2 XOR-JIT usable: fast-JIT CPU, no GFNI, strict W^X, not
    /// binary-translated (`JitWidth::detect`).
    avx2_jit: bool,
}

fn runtime_kernel_capabilities() -> KernelCapabilities {
    #[cfg(target_arch = "x86_64")]
    {
        KernelCapabilities {
            folded: gf_simd::altmap_supported(),
            folded_wide: gf_simd::folded_wide_shuffle_available(),
            avx2_jit: reedsolomon_rs::xor_jit::JitWidth::detect().is_some(),
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    KernelCapabilities {
        folded: false,
        folded_wide: false,
        avx2_jit: false,
    }
}

/// Bytes of one input region that a band's output rows consume together.
///
/// The stripe length handed to [`accumulate_band`] comes from [`BufferPlan`],
/// which takes the largest chunk the memory budget allows — so without an inner
/// tile every output row of the band re-streams the whole
/// `input_grouping * aligned_len` staging area from memory, and the reuse
/// distance is a memory-budget number rather than a cache-sized one. Tiling the
/// byte dimension *inside* the in-memory stripe fixes that reuse distance
/// without touching the stripe: sources are still read once per stripe and the
/// coefficient state is still built once per (batch, band).
///
/// The constants are per kernel FAMILY, mirroring the reference's per-method
/// ideal chunk size (4 KiB where the multiply is a GFNI affine transform,
/// 8 KiB where it is a table/shuffle or CLMUL body): a family is a
/// kernel-availability fact, exactly like the tier ladder itself. They are
/// deliberately not per-microarchitecture and carry no topology probe.
/// Only the folded family selects this tile, and that family is x86-only.
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
const AFFINE_TILE_BYTES: usize = 4 * 1024;
const TABLE_TILE_BYTES: usize = 8 * 1024;
/// Sentinel for a family that consumes the whole stripe in one call. Only the
/// packed XOR-JIT family selects it, and that family is x86-only.
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
const UNTILED: usize = usize::MAX;

/// A/B override for the per-family tile, in bytes; `0` selects the untiled
/// shape. Same escape-hatch pattern as `WEAVER_PAR2_CREATE_THREADS`: it exists
/// so the tiled and untiled shapes can be compared, and the ladder's constants
/// re-derived on new hardware, without a rebuild. Nothing in the plan depends
/// on it — the tile lives strictly inside one already-planned stripe, so every
/// `Par2MemoryPlan` and `ForwardMemoryEstimate` number is identical at every
/// setting, as are the produced recovery bytes.
///
/// Process-stable by construction, for the same reason the band count is: two
/// reads inside one pass must not disagree.
fn configured_tile_bytes() -> Option<usize> {
    static CONFIGURED: std::sync::OnceLock<Option<usize>> = std::sync::OnceLock::new();
    *CONFIGURED.get_or_init(|| {
        std::env::var("WEAVER_PAR2_CREATE_TILE")
            .ok()
            .and_then(|value| value.trim().parse::<usize>().ok())
            .map(|bytes| if bytes == 0 { UNTILED } else { bytes })
    })
}

/// Resolve one family's tile: the A/B override when set, otherwise the
/// family's constant, rounded up to a whole number of kernel strides.
fn family_tile_bytes(default_bytes: usize, stride: usize) -> usize {
    let requested = configured_tile_bytes().unwrap_or(default_bytes);
    if requested == UNTILED || stride == 0 {
        return requested;
    }
    requested
        .max(stride)
        .div_ceil(stride)
        .saturating_mul(stride)
}

/// Largest skew inserted between consecutive staging lanes and between
/// consecutive output rows, in bytes.
///
/// A stripe of `aligned_len` bytes per lane used to place input lane `l` at
/// `l * aligned_len` and output row `r` at `r * aligned_len`. For the
/// power-of-two stripes real jobs run (64 KiB slices), every lane and the row a
/// kernel pass reads at one offset then map to the *same* L1D set: the CLMUL
/// arm's 8-source pass plus its destination is 9 lines competing for a 4-way
/// (Neoverse N1/V2) or 2-way (Cortex-A72) set, and every block refills. The
/// fleet's own counters showed it — 35 L1D refills per thousand instructions
/// against the reference's 1.6–2.5 on the same create at near-equal
/// instruction counts (fullround-20260815T215405Z, v2/n1) — and a code-free
/// A/B reproduced the mechanism on x86 (Alder Lake `simd` arm: 8.47% → 4.45%
/// L1D misses, cycles −4.2%, when the slice moved from 65,536 to 66,560 bytes
/// and nothing else changed). The split-layout folded family interleaves six
/// lanes per stream and was flat in the same A/B, which is the control.
///
/// The skew makes the lane and row stride land at `1 KiB (mod 4 KiB)`. Every
/// stride that is a multiple of 4 KiB puts consecutive lanes in the same set
/// group of every common L1D (4 KiB, 8 KiB and 16 KiB way sizes), and a
/// 2 KiB residue only halves that; a 1 KiB residue gives four lane groups on a
/// 4 KiB way size and, because 5 is coprime to 16, twelve distinct 16-set
/// windows on a 16 KiB way size — with room for the prefetch window in both.
/// The same x86 A/B measured all four residues: 0 → 8.47% misses, 2 KiB →
/// 6.85%, 1 KiB → 4.4% (twice, from either side). The skew is capped at 1/8 of
/// the stripe so short stripes never pay more than 12.5% extra memory, and a
/// stripe whose stride already has the residue pays none. This is a fixed rule
/// of the stripe length — no cache probe, no topology input — and it changes
/// no arithmetic: only where bytes sit.
const SKEW_PERIOD_BYTES: usize = 4096;
const SKEW_TARGET_RESIDUE_BYTES: usize = 1024;

/// Bytes of skew between consecutive lanes/rows of a stripe of `aligned_len`
/// bytes: the smallest amount that moves the stride to
/// [`SKEW_TARGET_RESIDUE_BYTES`] modulo [`SKEW_PERIOD_BYTES`], capped at
/// `aligned_len / 8` and rounded down to whole 64-byte lines so every lane and
/// row start keeps the alignment the stripe itself has.
fn stripe_skew_bytes(aligned_len: usize) -> usize {
    let residue = aligned_len % SKEW_PERIOD_BYTES;
    let wanted = (SKEW_TARGET_RESIDUE_BYTES + SKEW_PERIOD_BYTES - residue) % SKEW_PERIOD_BYTES;
    let cap = aligned_len / 8;
    wanted.min(cap) / 64 * 64
}

/// Distance between consecutive staging lanes for one stripe: skewed for the
/// families whose kernels take one slice per source, and exactly `aligned_len`
/// for the packed XOR-JIT family, whose `PackedRun` addresses source region
/// `r` at `src + r * len` by contract.
fn lane_stride(contract: KernelContract, aligned_len: usize) -> usize {
    if contract.skewed_lanes {
        aligned_len + stripe_skew_bytes(aligned_len)
    } else {
        aligned_len
    }
}

/// Output rows whose coefficient state is built in one step.
///
/// The tile loop runs *inside* this, which is what keeps a row's coefficients
/// built once per (input batch, row) rather than once per tile: tiling must
/// not turn into a coefficient rebuild multiplier. Holding whole bands instead
/// would make the workspace scale with the recovery-row count, so this is a
/// compile-time constant — the per-band temporaries then stay a fixed size,
/// scaling with neither recovery rows nor threads, which is what
/// [`factor_workspace_bytes`] promises.
const COEFF_ROWS: usize = 16;

/// Byte ranges of one stripe in `tile_bytes` steps, last range short.
///
/// `aligned_len` is a multiple of the kernel stride and every tile constant is
/// a multiple of every stride in the ladder, so every emitted range is
/// stride-aligned — which is what lets the split-layout and word-wise kernels
/// be invoked per tile at all.
fn stripe_tiles(aligned_len: usize, tile_bytes: usize) -> impl Iterator<Item = (usize, usize)> {
    let tile = tile_bytes.min(aligned_len).max(1);
    (0..aligned_len)
        .step_by(tile)
        .map(move |start| (start, tile.min(aligned_len - start)))
}

#[derive(Clone, Copy)]
struct KernelContract {
    stride: usize,
    input_grouping: usize,
    tile_bytes: usize,
    /// Whether staging lanes sit `lane_stride` apart (skewed) rather than
    /// exactly `aligned_len` apart. See [`SKEW_PERIOD_BYTES`].
    skewed_lanes: bool,
}

impl KernelContract {
    fn for_kernel(kernel: ResolvedKernel) -> Self {
        match kernel {
            ResolvedKernel::Portable | ResolvedKernel::Simd => Self {
                stride: 2,
                input_grouping: configured_input_grouping(),
                tile_bytes: family_tile_bytes(TABLE_TILE_BYTES, 2),
                skewed_lanes: true,
            },
            #[cfg(target_arch = "x86_64")]
            ResolvedKernel::Folded => Self {
                stride: gf_simd::SPLIT_BLOCK_BYTES,
                input_grouping: DEFAULT_INPUT_GROUPING,
                // The folded arm dispatches to the affine kernel exactly when
                // GFNI is usable and to the shuffle tables otherwise; that is
                // the same availability answer the arm itself branches on, so
                // the tile follows the kernel that will actually run.
                tile_bytes: family_tile_bytes(
                    if gf_simd::folded_uses_gfni() {
                        AFFINE_TILE_BYTES
                    } else {
                        TABLE_TILE_BYTES
                    },
                    gf_simd::SPLIT_BLOCK_BYTES,
                ),
                // Six lanes share one interleaved stream here, so the skew
                // separates the two group streams; harmless, and it keeps one
                // layout rule for every slice-per-source family.
                skewed_lanes: true,
            },
            #[cfg(target_arch = "x86_64")]
            ResolvedKernel::XorJitAvx2 => Self {
                stride: reedsolomon_rs::xor_jit::JitWidth::Avx2.block_bytes(),
                input_grouping: DEFAULT_INPUT_GROUPING,
                // Untiled by family contract: `PackedRun` addresses source
                // region `r` at `src + r * len`, so a sub-range of the stripe
                // is not expressible without re-laying-out staging.
                tile_bytes: UNTILED,
                // The same contract fixes the lane stride at `len`; the skew
                // for this family needs a `PackedRun` source stride first.
                skewed_lanes: false,
            },
        }
    }
}

fn factor_workspace_bytes(kernel: ResolvedKernel, source_count: usize) -> Result<usize> {
    let constants = checked_mul(
        source_count,
        size_of::<u16>(),
        "factor constant allocation overflow",
    )?;
    // The per-row arrays are sized for the widest grouping; the per-chunk
    // vectors below follow the family's actual grouping.
    let grouping = KernelContract::for_kernel(kernel).input_grouping;
    let row = checked_mul(
        MAX_INPUT_GROUPING,
        size_of::<u16>(),
        "factor row allocation overflow",
    )?;
    let active = match kernel {
        ResolvedKernel::Portable => row,
        ResolvedKernel::Simd => checked_add(
            row,
            checked_add(
                checked_mul(
                    // One row chunk's prepared factors, not one row's: the tile
                    // loop runs inside a chunk of `COEFF_ROWS` rows so no row's
                    // coefficients are rebuilt per tile. A compile-time count,
                    // so this still scales with neither rows nor threads.
                    checked_mul(COEFF_ROWS, grouping, "prepared factor allocation overflow")?,
                    size_of::<gf_simd::PreparedInputFactor>(),
                    "prepared factor allocation overflow",
                )?,
                checked_mul(
                    MAX_INPUT_GROUPING,
                    size_of::<PreparedFactorSrc>(),
                    "prepared source allocation overflow",
                )?,
                "prepared factor allocation overflow",
            )?,
            "prepared factor allocation overflow",
        )?,
        #[cfg(target_arch = "x86_64")]
        ResolvedKernel::Folded => {
            let groups = DEFAULT_INPUT_GROUPING / gf_simd::FOLDED_GROUP;
            // One row chunk's tables, not one row's; see the SIMD arm above.
            let chunk_lanes = checked_mul(
                COEFF_ROWS,
                DEFAULT_INPUT_GROUPING,
                "folded table allocation overflow",
            )?;
            let affine_tables = checked_mul(
                chunk_lanes,
                size_of::<gf_simd::AffineMulMatrices>(),
                "folded affine table allocation overflow",
            )?;
            let shuffle_tables = checked_mul(
                chunk_lanes,
                size_of::<gf_simd::Shuffle2xTables>(),
                "folded shuffle table allocation overflow",
            )?;
            let staging_views = checked_mul(
                groups,
                size_of::<&[u8]>(),
                "folded staging view allocation overflow",
            )?;
            let affine_sets = checked_mul(
                groups,
                size_of::<[&gf_simd::AffineMulMatrices; gf_simd::FOLDED_GROUP]>(),
                "folded affine set allocation overflow",
            )?;
            let shuffle_sets = checked_mul(
                groups,
                size_of::<[&gf_simd::Shuffle2xTables; gf_simd::FOLDED_GROUP]>(),
                "folded shuffle set allocation overflow",
            )?;
            checked_add(
                row,
                [
                    affine_tables,
                    shuffle_tables,
                    staging_views,
                    affine_sets,
                    shuffle_sets,
                ]
                .into_iter()
                .try_fold(0usize, |total, bytes| {
                    checked_add(total, bytes, "folded factor allocation overflow")
                })?,
                "folded factor allocation overflow",
            )?
        }
        #[cfg(target_arch = "x86_64")]
        ResolvedKernel::XorJitAvx2 => row,
    };
    // This counts ONE band's coefficient storage. The other bands' copies are
    // deliberately excluded: this value feeds
    // Par2MemoryPlan.factor_workspace_bytes, which must not scale with
    // recovery-row or band count, and every term above is a compile-time
    // quantity for exactly that reason.
    checked_add(constants, active, "factor workspace allocation overflow")
}

/// Reserved bytes for the banded JIT workspaces, and the per-build arena
/// limit handed to them. Each band holds ONE active multi-row batch at a
/// time (all of the band's rows for the current input batch) and recycles it
/// before the next batch, so the reservation is one band-sized arena per
/// band and never scales with the input-batch count.
fn jit_workspace_bytes(kernel: ResolvedKernel, output_count: usize) -> Result<(usize, usize)> {
    #[cfg(target_arch = "x86_64")]
    if matches!(kernel, ResolvedKernel::XorJitAvx2) {
        let (band_size, band_count) = create_band_shape(output_count.max(1));
        let estimate = reedsolomon_rs::xor_jit::packed::PackedJitBatch::memory_upper_bound(
            reedsolomon_rs::xor_jit::JitWidth::Avx2,
            band_size.max(1),
            DEFAULT_INPUT_GROUPING,
        )
        .ok_or_else(|| resource_limit("packed JIT workspace size overflows"))?;
        let reserved = estimate
            .peak_bytes
            .checked_mul(band_count)
            .ok_or_else(|| resource_limit("banded JIT workspace accounting overflows"))?;
        return Ok((reserved, estimate.executable_arena_bytes));
    }
    let _ = (kernel, output_count);
    Ok((0, 0))
}

/// Optional cache-oriented cap on one stripe's working set, in MiB, from
/// `WEAVER_PAR2_CREATE_STRIPE_MIB`. Unset or `0` keeps the shipped behavior:
/// [`BufferPlan`] takes the largest chunk the caller's memory budget allows.
///
/// Why the hatch exists, and why it is not the default. The recovery-output
/// stripe (`output_count * aligned_chunk_len`) is read and written once per
/// *input batch*, so a stripe larger than the last-level cache makes every
/// batch re-stream all of it from memory; capping the stripe is what decouples
/// the chunk from `physical_memory / 8`. Measured both ways, same corpus
/// (128 MiB over 2048 input slices, 410 recovery slices, 64 KiB slice),
/// shipped default vs this cap at 8 MiB:
///
/// - 12th-gen mobile x86 (12 MB L3, GFNI-folded path): 3.96 -> 3.31 CPU-s and
///   0.52 -> 0.42 s wall. The cache effect is real and large.
/// - Apple-silicon aarch64 (18 threads, NEON/CLMUL path): 3.03 -> 4.19 CPU-s.
///   The chunk size itself costs nothing there — with banding off
///   (`WEAVER_PAR2_CREATE_THREADS=1`) the two budgets are indistinguishable
///   (2.12 vs 2.14 user-s, 0.05 vs 0.06 sys-s). The whole regression is the
///   per-`(stripe, batch)` rayon dispatch, which the smaller chunk multiplies
///   by the stripe count.
///
/// So the win is gated behind an implementation artifact, not a hardware
/// property: while the parallel dispatch happens once per (stripe, batch)
/// rather than once per stripe, shrinking the stripe trades memory traffic for
/// thread wakeups, and which side wins is a property of the host's cache and
/// its thread-park cost. Making a smaller stripe unconditionally right needs
/// the staging area to hold the stripe for *all* sources so each band can walk
/// the batches itself; that is a separate change, and this hatch is here so
/// the cap can be re-measured on any host without a rebuild until then.
///
/// Process-stable, and read through the same function by both the encoder and
/// [`estimate_forward_memory`], so a plan and the pass it admits always agree.
/// Parse a `WEAVER_PAR2_CREATE_KERNEL` value. Split out from the env reader
/// so the mapping is unit-testable without process-global state.
fn parse_kernel_override(value: &str) -> Result<ForwardKernel> {
    match value.trim().to_ascii_lowercase().as_str() {
        "auto" => Ok(ForwardKernel::Auto),
        "portable" => Ok(ForwardKernel::Portable),
        "simd" => Ok(ForwardKernel::Simd),
        #[cfg(target_arch = "x86_64")]
        "folded" => Ok(ForwardKernel::Folded),
        #[cfg(target_arch = "x86_64")]
        "xor-jit-avx2" => Ok(ForwardKernel::XorJitAvx2),
        other => Err(invalid_input(format!(
            "WEAVER_PAR2_CREATE_KERNEL={other:?} names no kernel on this \
             architecture; use auto, portable, simd, folded or xor-jit-avx2"
        ))),
    }
}

/// Optional create-kernel override from `WEAVER_PAR2_CREATE_KERNEL`, so a
/// tier A/B never needs a rebuild (there is no CLI flag for the kernel).
///
/// The override replaces the caller's requested kernel *before* capability
/// resolution, so forcing a kernel this host cannot run fails the pass loudly
/// through `unavailable_kernel` instead of silently measuring another tier,
/// and an unrecognized value is an error for the same reason. Process-stable,
/// and applied inside `select_kernel_for_memory`, which both the encoder and
/// `estimate_forward_memory` funnel through, so a plan and the pass it admits
/// always agree.
fn configured_kernel_override() -> Result<Option<ForwardKernel>> {
    static CONFIGURED: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    CONFIGURED
        .get_or_init(|| std::env::var("WEAVER_PAR2_CREATE_KERNEL").ok())
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(parse_kernel_override)
        .transpose()
}

fn configured_stripe_cap_bytes() -> Option<usize> {
    static CONFIGURED: std::sync::OnceLock<Option<usize>> = std::sync::OnceLock::new();
    *CONFIGURED.get_or_init(|| {
        std::env::var("WEAVER_PAR2_CREATE_STRIPE_MIB")
            .ok()
            .and_then(|value| value.trim().parse::<usize>().ok())
            .filter(|&mib| mib != 0)
            .and_then(|mib| mib.checked_mul(1024 * 1024))
    })
}

struct BufferPlan {
    chunk_len: usize,
    aligned_chunk_len: usize,
    /// Distance between consecutive output rows in the output buffer:
    /// `aligned_chunk_len` plus the stripe skew (see [`SKEW_PERIOD_BYTES`]).
    /// Every row still holds exactly `aligned_chunk_len` payload bytes.
    row_stride: usize,
    staging_bytes: usize,
    output_bytes: usize,
    data_bytes: usize,
    memory_bytes: usize,
    // Read only by the x86 accumulate path; other arches plan it but never
    // consume it.
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    jit_build_limit_bytes: usize,
}

impl BufferPlan {
    fn new_with_reserved(
        slice_size: usize,
        output_count: usize,
        contract: KernelContract,
        memory_limit: usize,
        factor_workspace_bytes: usize,
        jit_workspace_bytes: usize,
        jit_build_limit_bytes: usize,
    ) -> Result<Self> {
        if memory_limit == 0 {
            return Err(resource_limit("forward memory limit is zero"));
        }
        let reserved_bytes = checked_add(
            factor_workspace_bytes,
            jit_workspace_bytes,
            "forward persistent memory accounting overflow",
        )?;
        let stripe_memory_limit = memory_limit.checked_sub(reserved_bytes).ok_or_else(|| {
            resource_limit(format!(
                "forward persistent allocations need {reserved_bytes} bytes, limit is {memory_limit}"
            ))
        })?;
        // Unset by default, in which case this is exactly `stripe_memory_limit`
        // and nothing below changes; see `configured_stripe_cap_bytes`. A
        // tighter caller budget always still wins, and the cap is never allowed
        // to reject a shape the caller's budget admits: the loop below falls
        // back to `stripe_memory_limit` once the chunk cannot shrink further.
        let chosen_stripe_limit = match configured_stripe_cap_bytes() {
            Some(cap) => stripe_memory_limit.min(cap),
            None => stripe_memory_limit,
        };
        let mut chunk_len = if slice_size >= contract.stride {
            slice_size - slice_size % contract.stride
        } else {
            slice_size
        };
        chunk_len = chunk_len.max(2);

        loop {
            let aligned_chunk_len = round_up(chunk_len.min(slice_size), contract.stride)?;
            // Staging is sized for the skewed lane stride whatever the family:
            // the packed XOR-JIT family lays its lanes exactly `aligned_len`
            // apart and simply leaves the tail unused, which keeps one plan
            // shape per stripe length instead of one per family.
            let skew = stripe_skew_bytes(aligned_chunk_len);
            let lane_alloc = checked_add(aligned_chunk_len, skew, "staging lane overflow")?;
            let row_stride = lane_alloc;
            let staging_bytes = checked_mul(
                contract.input_grouping,
                lane_alloc,
                "staging allocation overflow",
            )?;
            let output_bytes = checked_mul(output_count, row_stride, "output allocation overflow")?;
            let aligned_allocation_bytes = checked_mul(
                aligned_chunk_len.div_ceil(64),
                64,
                "aligned buffer allocation overflow",
            )?;
            let skewed_allocation_bytes = checked_add(
                aligned_allocation_bytes,
                skew,
                "aligned buffer allocation overflow",
            )?;
            let data_bytes = checked_add(
                checked_mul(
                    STAGING_AREA_COUNT,
                    checked_mul(
                        contract.input_grouping,
                        skewed_allocation_bytes,
                        "staging allocation overflow",
                    )?,
                    "staging allocation overflow",
                )?,
                checked_add(
                    checked_mul(
                        output_count,
                        skewed_allocation_bytes,
                        "output allocation overflow",
                    )?,
                    checked_mul(
                        TRANSFER_BUFFER_COUNT,
                        aligned_allocation_bytes,
                        "transfer allocation overflow",
                    )?,
                    "forward buffer allocation overflow",
                )?,
                "forward buffer allocation overflow",
            )?;
            if data_bytes <= chosen_stripe_limit
                || (chunk_len <= 2 && data_bytes <= stripe_memory_limit)
            {
                return Ok(Self {
                    chunk_len: chunk_len.min(slice_size),
                    aligned_chunk_len,
                    row_stride,
                    staging_bytes,
                    output_bytes,
                    data_bytes,
                    memory_bytes: reserved_bytes + data_bytes,
                    jit_build_limit_bytes,
                });
            }
            if chunk_len <= 2 {
                return Err(resource_limit(format!(
                    "forward persistent allocations and stripe buffers need {} bytes, limit is {memory_limit}",
                    reserved_bytes + data_bytes
                )));
            }
            if slice_size < contract.stride {
                chunk_len = 2;
                continue;
            }
            let bytes_per_aligned_byte = data_bytes / aligned_chunk_len;
            let max_aligned_len =
                (chosen_stripe_limit / bytes_per_aligned_byte) / contract.stride * contract.stride;
            let smaller_chunk_len = chunk_len.saturating_sub(contract.stride).max(2);
            chunk_len = max_aligned_len.max(2).min(smaller_chunk_len);
        }
    }
}

fn select_kernel_for_memory(
    slice_size: usize,
    output_count: usize,
    source_count: usize,
    memory_limit: usize,
    requested: ForwardKernel,
) -> Result<(ResolvedKernel, BufferPlan)> {
    select_kernel_for_memory_with_capabilities(
        slice_size,
        output_count,
        source_count,
        memory_limit,
        requested,
        runtime_kernel_capabilities(),
    )
}

fn select_kernel_for_memory_with_capabilities(
    slice_size: usize,
    output_count: usize,
    source_count: usize,
    memory_limit: usize,
    requested: ForwardKernel,
    capabilities: KernelCapabilities,
) -> Result<(ResolvedKernel, BufferPlan)> {
    let requested = match configured_kernel_override()? {
        Some(forced) => forced,
        None => requested,
    };
    let candidates = match requested {
        ForwardKernel::Auto => auto_kernel_candidates(capabilities),
        requested => vec![resolve_kernel_with_capabilities(requested, capabilities)?],
    };
    let mut last_error = None;
    for kernel in candidates {
        let contract = KernelContract::for_kernel(kernel);
        let factor_bytes = factor_workspace_bytes(kernel, source_count)?;
        // One active multi-row batch per band, recycled between input batches:
        // admission reserves one band-sized arena per band, and the build
        // limit is the largest band's arena bound.
        let (jit_bytes, jit_arena_bytes) = jit_workspace_bytes(kernel, output_count)?;
        match BufferPlan::new_with_reserved(
            slice_size,
            output_count,
            contract,
            memory_limit,
            factor_bytes,
            jit_bytes,
            jit_arena_bytes,
        ) {
            Ok(buffers) => return Ok((kernel, buffers)),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| resource_limit("no forward arithmetic kernel is available")))
}

fn auto_kernel_candidates(capabilities: KernelCapabilities) -> Vec<ResolvedKernel> {
    let mut kernels = Vec::with_capacity(4);
    let preferred = resolve_kernel_with_capabilities(ForwardKernel::Auto, capabilities)
        .expect("automatic forward kernel selection cannot fail");
    kernels.push(preferred);
    #[cfg(target_arch = "x86_64")]
    {
        if capabilities.avx2_jit && preferred != ResolvedKernel::XorJitAvx2 {
            kernels.push(ResolvedKernel::XorJitAvx2);
        }
        if capabilities.folded && preferred != ResolvedKernel::Folded {
            kernels.push(ResolvedKernel::Folded);
        }
    }
    let simd = resolve_kernel_with_capabilities(ForwardKernel::Simd, capabilities)
        .expect("direct grouped SIMD selection cannot fail");
    if preferred != simd {
        kernels.push(simd);
    }
    let portable = resolve_kernel_with_capabilities(ForwardKernel::Portable, capabilities)
        .expect("portable selection cannot fail");
    if preferred != portable {
        kernels.push(portable);
    }
    kernels
}

struct FactorSource {
    /// PAR2 input-slice constants, one per source block. Every entry is an
    /// antilog value and therefore nonzero, which is what lets
    /// [`RowFactors::fill_row`] use the log form of `gf::pow` unconditionally.
    constants: Vec<u16>,
}

impl FactorSource {
    fn new(source_count: usize) -> Self {
        Self {
            constants: gf::input_slice_constants(source_count),
        }
    }

    /// Bind one input group's constants for a whole band of output rows.
    ///
    /// The discrete logs are the only part of `base^exponent` that depends on
    /// the source rather than the output row, so taking them once per (band,
    /// input group) removes `live_inputs` lookups into the 128 KiB log table
    /// from every output row — table traffic that also evicts the streaming
    /// kernel's working set.
    fn row_factors(&self, source_start: usize, live_inputs: usize) -> RowFactors {
        let mut logs = [0u16; MAX_INPUT_GROUPING];
        for (lane, log) in logs[..live_inputs].iter_mut().enumerate() {
            let constant = self.constants[source_start + lane];
            debug_assert_ne!(constant, 0, "input slice constants are never zero");
            *log = gf::log(constant);
        }
        RowFactors { logs, live_inputs }
    }
}

/// One input group's per-source discrete logs, reused across a band's rows.
struct RowFactors {
    logs: [u16; MAX_INPUT_GROUPING],
    live_inputs: usize,
}

impl RowFactors {
    fn fill_row(&self, exponent: RecoveryExponent, row: &mut [u16; MAX_INPUT_GROUPING]) {
        row.fill(0);
        for (factor, &log) in row[..self.live_inputs]
            .iter_mut()
            .zip(self.logs[..self.live_inputs].iter())
        {
            *factor = gf::pow_from_log(log, exponent);
        }
    }
}

pub(crate) fn estimate_forward_memory(
    slice_size: u64,
    source_count: usize,
    output_count: usize,
    memory_limit: usize,
    requested_kernel: ForwardKernel,
) -> Result<ForwardMemoryEstimate> {
    if output_count == 0 {
        return Ok(ForwardMemoryEstimate {
            factor_workspace_bytes: 0,
            jit_workspace_bytes: 0,
            stripe_buffer_bytes: 0,
            processing_peak_bytes: 0,
        });
    }
    let slice_size = usize::try_from(slice_size)
        .map_err(|_| resource_limit("slice size exceeds addressable memory"))?;
    let (kernel, buffers) = select_kernel_for_memory(
        slice_size,
        output_count,
        source_count,
        memory_limit,
        requested_kernel,
    )?;
    let factor_workspace_bytes = factor_workspace_bytes(kernel, source_count)?;
    let (jit_workspace_bytes, _) = jit_workspace_bytes(kernel, output_count)?;
    Ok(ForwardMemoryEstimate {
        factor_workspace_bytes,
        jit_workspace_bytes,
        stripe_buffer_bytes: buffers.data_bytes,
        processing_peak_bytes: buffers.memory_bytes,
    })
}

#[repr(align(64))]
#[derive(Clone, Copy)]
struct AlignedCell(pub [u8; 64]);

impl AlignedCell {
    fn as_ptr(&self) -> *const u8 {
        self.0.as_ptr()
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.0.as_mut_ptr()
    }
}

struct AlignedBuffer {
    cells: Vec<AlignedCell>,
    len: usize,
}

impl AlignedBuffer {
    fn new(len: usize) -> Self {
        Self {
            cells: vec![AlignedCell([0; 64]); len.div_ceil(64)],
            len,
        }
    }

    fn as_bytes(&self) -> &[u8] {
        let ptr = self
            .cells
            .first()
            .map_or_else(|| self.cells.as_ptr().cast::<u8>(), AlignedCell::as_ptr);
        unsafe { std::slice::from_raw_parts(ptr, self.len) }
    }

    fn as_bytes_mut(&mut self) -> &mut [u8] {
        let ptr = if self.cells.is_empty() {
            self.cells.as_mut_ptr().cast::<u8>()
        } else {
            self.cells[0].as_mut_ptr()
        };
        unsafe { std::slice::from_raw_parts_mut(ptr, self.len) }
    }
}

#[allow(clippy::too_many_arguments)]
fn fill_staging<P: ForwardSourceProvider + ?Sized>(
    kernel: ResolvedKernel,
    staging: &mut AlignedBuffer,
    transfer: &mut AlignedBuffer,
    provider: &mut P,
    source_start: usize,
    stripe_offset: usize,
    actual_len: usize,
    aligned_len: usize,
    contract: KernelContract,
) -> Result<()> {
    let staging_bytes = staging.as_bytes_mut();
    staging_bytes.fill(0);
    let transfer_bytes = transfer.as_bytes_mut();
    if transfer_bytes.len() < aligned_len {
        return Err(resource_limit(
            "transfer buffer is shorter than aligned stripe",
        ));
    }
    let lane_stride = lane_stride(contract, aligned_len);

    for lane in 0..contract.input_grouping {
        transfer_bytes[..aligned_len].fill(0);
        let source_index = source_start + lane;
        if source_index < provider.source_count() {
            provider.read_source_chunk(
                source_index,
                stripe_offset,
                &mut transfer_bytes[..actual_len],
            )?;
        }

        match kernel {
            ResolvedKernel::Portable | ResolvedKernel::Simd => {
                let start = lane
                    .checked_mul(lane_stride)
                    .ok_or_else(|| resource_limit("staging lane offset overflow"))?;
                staging_bytes[start..start + aligned_len]
                    .copy_from_slice(&transfer_bytes[..aligned_len]);
            }
            #[cfg(target_arch = "x86_64")]
            ResolvedKernel::Folded => {
                let group = lane / gf_simd::FOLDED_GROUP;
                let group_lane = lane % gf_simd::FOLDED_GROUP;
                let group_start = group
                    .checked_mul(gf_simd::FOLDED_GROUP)
                    .and_then(|value| value.checked_mul(lane_stride))
                    .ok_or_else(|| resource_limit("folded staging offset overflow"))?;
                gf_simd::split_encode_scatter(
                    &transfer_bytes[..aligned_len],
                    &mut staging_bytes
                        [group_start..group_start + aligned_len * gf_simd::FOLDED_GROUP],
                    group_lane,
                );
            }
            #[cfg(target_arch = "x86_64")]
            ResolvedKernel::XorJitAvx2 => {
                let width = reedsolomon_rs::xor_jit::JitWidth::Avx2;
                let block = width.block_bytes();
                debug_assert_eq!(aligned_len % block, 0);
                // `PackedRun` reads region `r` at `src + r * len`.
                debug_assert_eq!(lane_stride, aligned_len);
                let lane_start = lane
                    .checked_mul(lane_stride)
                    .ok_or_else(|| resource_limit("packed staging offset overflow"))?;
                for offset in (0..aligned_len).step_by(block) {
                    unsafe {
                        width.prepare_block(
                            &transfer_bytes[offset..offset + block],
                            &mut staging_bytes[lane_start + offset..lane_start + offset + block],
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn accumulate_batch(
    kernel: ResolvedKernel,
    output: &mut [u8],
    staging: &AlignedBuffer,
    factors: &FactorSource,
    exponents: &[RecoveryExponent],
    source_start: usize,
    live_inputs: usize,
    aligned_len: usize,
    output_stride: usize,
    contract: KernelContract,
    band_size: usize,
    #[cfg(target_arch = "x86_64")]
    jit_workspaces: &mut [reedsolomon_rs::xor_jit::packed::PackedJitWorkspace],
    #[cfg(target_arch = "x86_64")] jit_code_budget: usize,
) -> Result<()> {
    let output_count = exponents.len();
    // The chunked splits below are exact only over a whole-output slice, and
    // the workspace zip silently truncates if the caller's band shape ever
    // disagrees with the workspace count.
    debug_assert_eq!(output.len(), output_count * output_stride);
    #[cfg(target_arch = "x86_64")]
    debug_assert_eq!(
        jit_workspaces.len(),
        output_count.max(1).div_ceil(band_size)
    );
    if band_size >= output_count || output_count <= 1 {
        return accumulate_band(
            kernel,
            output,
            staging,
            factors,
            exponents,
            source_start,
            live_inputs,
            aligned_len,
            output_stride,
            contract,
            #[cfg(target_arch = "x86_64")]
            &mut jit_workspaces[0],
            #[cfg(target_arch = "x86_64")]
            jit_code_budget,
        );
    }

    // Contiguous exponent bands map to contiguous output-major byte ranges,
    // so the chunked splits below hand each call a disjoint destination. The
    // split is walked in order here; the parallel pass drives the same
    // per-band function from [`encode_stripe_banded`], which is why the two
    // cannot produce different bytes.
    let band_bytes = checked_mul(band_size, output_stride, "band byte range overflow")?;
    let bands = output
        .chunks_mut(band_bytes)
        .zip(exponents.chunks(band_size));
    #[cfg(target_arch = "x86_64")]
    let bands = bands.zip(jit_workspaces.iter_mut());
    for band in bands {
        #[cfg(target_arch = "x86_64")]
        let ((band_output, band_exponents), jit_workspace) = band;
        #[cfg(not(target_arch = "x86_64"))]
        let (band_output, band_exponents) = band;
        accumulate_band(
            kernel,
            band_output,
            staging,
            factors,
            band_exponents,
            source_start,
            live_inputs,
            aligned_len,
            output_stride,
            contract,
            #[cfg(target_arch = "x86_64")]
            jit_workspace,
            #[cfg(target_arch = "x86_64")]
            jit_code_budget,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn accumulate_band(
    kernel: ResolvedKernel,
    output: &mut [u8],
    staging: &AlignedBuffer,
    factors: &FactorSource,
    exponents: &[RecoveryExponent],
    source_start: usize,
    live_inputs: usize,
    aligned_len: usize,
    output_stride: usize,
    contract: KernelContract,
    #[cfg(target_arch = "x86_64")]
    jit_workspace: &mut reedsolomon_rs::xor_jit::packed::PackedJitWorkspace,
    #[cfg(target_arch = "x86_64")] jit_code_budget: usize,
) -> Result<()> {
    let staging_bytes = staging.as_bytes();
    // An empty batch has no coefficients to build and no sources to read; the
    // per-arm row assembly below indexes lane 0 unconditionally.
    if live_inputs == 0 {
        return Ok(());
    }
    let lane_stride = lane_stride(contract, aligned_len);
    let mut row = [0u16; MAX_INPUT_GROUPING];
    match kernel {
        ResolvedKernel::Portable => {
            let row_factors = factors.row_factors(source_start, live_inputs);
            let mut rows = [[0u16; MAX_INPUT_GROUPING]; COEFF_ROWS];
            for (chunk_index, chunk) in exponents.chunks(COEFF_ROWS).enumerate() {
                for (slot, &exponent) in rows.iter_mut().zip(chunk) {
                    row_factors.fill_row(exponent, slot);
                }
                let first_output = chunk_index * COEFF_ROWS;
                for (tile_start, tile_len) in stripe_tiles(aligned_len, contract.tile_bytes) {
                    for (offset, row) in rows[..chunk.len()].iter().enumerate() {
                        let dst_start = (first_output + offset) * output_stride + tile_start;
                        scalar_accumulate(
                            &mut output[dst_start..dst_start + tile_len],
                            &staging_bytes[tile_start..],
                            lane_stride,
                            row,
                            live_inputs,
                            tile_len,
                        );
                    }
                }
            }
        }
        ResolvedKernel::Simd => {
            // One allocation for the whole band: the factors differ per row but
            // the capacity does not, so each row chunk rebuilds contents.
            let mut prepared: Vec<gf_simd::PreparedInputFactor> =
                Vec::with_capacity(COEFF_ROWS * live_inputs);
            let row_factors = factors.row_factors(source_start, live_inputs);
            for (chunk_index, chunk) in exponents.chunks(COEFF_ROWS).enumerate() {
                prepared.clear();
                for &exponent in chunk {
                    row_factors.fill_row(exponent, &mut row);
                    prepared.extend(
                        row[..live_inputs]
                            .iter()
                            .map(|&factor| gf_simd::prepare_input_factor(factor)),
                    );
                }
                let first_output = chunk_index * COEFF_ROWS;
                for (tile_start, tile_len) in stripe_tiles(aligned_len, contract.tile_bytes) {
                    for offset in 0..chunk.len() {
                        let dst_start = (first_output + offset) * output_stride + tile_start;
                        let row_base = offset * live_inputs;
                        // Stack-resident: `live_inputs <=
                        // MAX_INPUT_GROUPING`, so the descriptor list never
                        // needs the heap. Building it per row used to cost one
                        // allocate/free pair per (output row, input group) —
                        // 3.3M of them on the 4096×819 create shape.
                        let inputs: [PreparedFactorSrc<'_>; MAX_INPUT_GROUPING] =
                            std::array::from_fn(|lane| {
                                let clamped = lane.min(live_inputs - 1);
                                let source_start_bytes = clamped * lane_stride + tile_start;
                                PreparedFactorSrc {
                                    prepared: &prepared[row_base + clamped],
                                    src: &staging_bytes
                                        [source_start_bytes..source_start_bytes + tile_len],
                                }
                            });
                        gf_simd::mul_acc_input_batch_prepared(
                            &mut output[dst_start..dst_start + tile_len],
                            &inputs[..live_inputs],
                        );
                    }
                }
            }
        }
        #[cfg(target_arch = "x86_64")]
        ResolvedKernel::Folded => {
            debug_assert_eq!(contract.input_grouping, DEFAULT_INPUT_GROUPING);
            let groups = contract.input_grouping / gf_simd::FOLDED_GROUP;
            if groups > MAX_FOLDED_GROUPS {
                return Err(invalid_input(
                    "folded input grouping exceeds the reserved group count",
                ));
            }
            let mut affine = Vec::with_capacity(COEFF_ROWS * live_inputs);
            let mut shuffle2x = Vec::with_capacity(COEFF_ROWS * live_inputs);
            // Hoisted: a process-wide capability answer, not a per-row one.
            let uses_gfni = gf_simd::folded_uses_gfni();
            let row_factors = factors.row_factors(source_start, live_inputs);
            // Rebuilt per tile, not per (tile, output row): the views only
            // depend on where the tile starts.
            let mut staging_views: Vec<&[u8]> = Vec::with_capacity(groups);
            for (chunk_index, chunk) in exponents.chunks(COEFF_ROWS).enumerate() {
                affine.clear();
                shuffle2x.clear();
                for &exponent in chunk {
                    row_factors.fill_row(exponent, &mut row);
                    if uses_gfni {
                        affine.extend(
                            row[..live_inputs]
                                .iter()
                                .map(|&factor| gf_simd::precompute_affine_matrices(factor)),
                        );
                    } else {
                        shuffle2x.extend(
                            row[..live_inputs]
                                .iter()
                                .map(|&factor| gf_simd::precompute_shuffle2x_tables(factor)),
                        );
                    }
                }
                let first_output = chunk_index * COEFF_ROWS;
                for (tile_start, tile_len) in stripe_tiles(aligned_len, contract.tile_bytes) {
                    staging_views.clear();
                    staging_views.extend((0..groups).map(|group| {
                        // Within a group the six lanes are interleaved by
                        // `SPLIT_BLOCK_BYTES` blocks, so the tile that starts at
                        // logical byte `tile_start` of every lane starts at
                        // `tile_start * FOLDED_GROUP` of the interleaved stream.
                        let start = group * gf_simd::FOLDED_GROUP * lane_stride
                            + tile_start * gf_simd::FOLDED_GROUP;
                        &staging_bytes[start..start + gf_simd::FOLDED_GROUP * tile_len]
                    }));
                    for offset in 0..chunk.len() {
                        let dst_start = (first_output + offset) * output_stride + tile_start;
                        let row_base = offset * live_inputs;
                        if uses_gfni {
                            // Stack-resident for the same reason as the SIMD
                            // arm's descriptor list: `groups` is bounded by the
                            // compile-time input grouping, so the reference
                            // table costs no allocator traffic per output row.
                            let matrix_sets: [[&gf_simd::AffineMulMatrices; gf_simd::FOLDED_GROUP];
                                MAX_FOLDED_GROUPS] = std::array::from_fn(|group| {
                                std::array::from_fn(|lane| {
                                    let source_index = group * gf_simd::FOLDED_GROUP + lane;
                                    affine
                                        .get(row_base + source_index)
                                        .filter(|_| source_index < live_inputs)
                                        .unwrap_or(&gf_simd::ZERO_AFFINE)
                                })
                            });
                            gf_simd::mul_acc_folded_batch(
                                &mut output[dst_start..dst_start + tile_len],
                                &staging_views,
                                &matrix_sets[..groups],
                            );
                        } else {
                            let table_sets: [[&gf_simd::Shuffle2xTables; gf_simd::FOLDED_GROUP];
                                MAX_FOLDED_GROUPS] = std::array::from_fn(|group| {
                                std::array::from_fn(|lane| {
                                    let source_index = group * gf_simd::FOLDED_GROUP + lane;
                                    shuffle2x
                                        .get(row_base + source_index)
                                        .filter(|_| source_index < live_inputs)
                                        .unwrap_or(&gf_simd::ZERO_SHUFFLE2X)
                                })
                            });
                            gf_simd::mul_acc_shuffle2x_batch(
                                &mut output[dst_start..dst_start + tile_len],
                                &staging_views,
                                &table_sets[..groups],
                            );
                        }
                    }
                }
            }
        }
        #[cfg(target_arch = "x86_64")]
        ResolvedKernel::XorJitAvx2 => {
            // Admission covers the workspace arena and stripe buffers before
            // any sink mutation. A later W^X/code-generation or execution
            // error is terminal for this pass; it is not a post-admission
            // tier downgrade.
            //
            // One sealed multi-row batch per input batch — every row of this
            // band in a single build, recycled before the next batch — never
            // a build per output row (per-row churn measured at 60% of create
            // on c5 pass 2) and never a pass-retained store (measured
            // self-rejecting at real job shapes on c5 pass 3).
            //
            // No tile loop: `PackedRun` addresses source region `r` at
            // `src + r * len`, so the family consumes the whole stripe per
            // call by contract.
            debug_assert_eq!(contract.tile_bytes, UNTILED);
            debug_assert_eq!(lane_stride, aligned_len);
            debug_assert_eq!(contract.input_grouping, DEFAULT_INPUT_GROUPING);
            let width = reedsolomon_rs::xor_jit::JitWidth::Avx2;
            let row_factors = factors.row_factors(source_start, live_inputs);
            let rows: Vec<[u16; DEFAULT_INPUT_GROUPING]> = exponents
                .iter()
                .map(|&exponent| {
                    // Full-width row: zero tail factors keep their source
                    // positions for the packed group shape. The family's
                    // grouping is the packed width, so the wide row's tail
                    // beyond it is always zero.
                    let mut wide = [0u16; MAX_INPUT_GROUPING];
                    row_factors.fill_row(exponent, &mut wide);
                    let mut row = [0u16; DEFAULT_INPUT_GROUPING];
                    row.copy_from_slice(&wide[..DEFAULT_INPUT_GROUPING]);
                    row
                })
                .collect();
            let row_refs: Vec<&[u16]> = rows.iter().map(|row| &row[..]).collect();
            let batch = jit_workspace
                .build(width, &row_refs, jit_code_budget.max(1))
                .map_err(|error| jit_build_error(error.to_string()))?;
            for output_index in 0..exponents.len() {
                let dst_start = output_index * output_stride;
                let code = batch
                    .row(output_index)
                    .ok_or_else(|| invalid_input("packed XOR-JIT output row missing"))?;
                unsafe {
                    width
                        .try_run_packed(
                            code,
                            &mut reedsolomon_rs::xor_jit::packed::PackedScratch::default(),
                            reedsolomon_rs::xor_jit::packed::PackedRun {
                                packed_regions: contract.input_grouping,
                                live_regions: live_inputs,
                                dst: output[dst_start..dst_start + aligned_len].as_mut_ptr(),
                                src: staging_bytes.as_ptr(),
                                len: aligned_len,
                                prefetch_in: Some(staging_bytes.as_ptr()),
                                prefetch_out: None,
                            },
                        )
                        .map_err(|error| jit_build_error(error.to_string()))?;
                }
            }
            jit_workspace
                .recycle(batch)
                .map_err(|error| jit_build_error(error.to_string()))?;
        }
    }
    Ok(())
}

/// Word-wise accumulate of one tile.
///
/// `staging` starts at the tile's first byte of lane 0 and `staging_stride` is
/// the distance between lanes in the whole stripe, which is the stripe length
/// rather than the tile length whenever the stripe is tiled.
fn scalar_accumulate(
    dst: &mut [u8],
    staging: &[u8],
    staging_stride: usize,
    row: &[u16],
    live_inputs: usize,
    len: usize,
) {
    for word in 0..len / 2 {
        let mut value = u16::from_le_bytes([dst[word * 2], dst[word * 2 + 1]]);
        for (lane, &factor) in row.iter().take(live_inputs).enumerate() {
            let source_offset = lane * staging_stride + word * 2;
            let source = u16::from_le_bytes([staging[source_offset], staging[source_offset + 1]]);
            value ^= gf::mul(source, factor);
        }
        dst[word * 2..word * 2 + 2].copy_from_slice(&value.to_le_bytes());
    }
}

fn finish_output(
    kernel: ResolvedKernel,
    output: &mut [u8],
    output_stride: usize,
    aligned_len: usize,
    output_count: usize,
) -> Result<()> {
    debug_assert_eq!(output.len(), output_count * output_stride);
    finish_band_rows(kernel, output, output_stride, aligned_len, output_count)
}

/// Finish one contiguous run of output rows.
///
/// Row-local by construction on every family that needs it, which is what
/// lets each band worker finish its own rows at the end of a stripe instead of
/// a second banded pass over the whole output.
fn finish_band_rows(
    kernel: ResolvedKernel,
    output: &mut [u8],
    output_stride: usize,
    aligned_len: usize,
    output_count: usize,
) -> Result<()> {
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (kernel, output, output_stride, aligned_len, output_count);
    }

    #[cfg(target_arch = "x86_64")]
    {
        if matches!(kernel, ResolvedKernel::Portable | ResolvedKernel::Simd) {
            return Ok(());
        }
        return finish_band(kernel, output, output_stride, aligned_len, output_count);
    }
    #[allow(unreachable_code)]
    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn finish_band(
    kernel: ResolvedKernel,
    output: &mut [u8],
    output_stride: usize,
    aligned_len: usize,
    output_count: usize,
) -> Result<()> {
    for output_index in 0..output_count {
        let start = output_index
            .checked_mul(output_stride)
            .ok_or_else(|| resource_limit("output finish offset overflow"))?;
        let end = start
            .checked_add(aligned_len)
            .ok_or_else(|| resource_limit("output finish end overflow"))?;
        let dst = &mut output[start..end];

        match kernel {
            ResolvedKernel::Portable | ResolvedKernel::Simd => {}
            ResolvedKernel::Folded => {
                gf_simd::altmap_decode(dst);
            }
            ResolvedKernel::XorJitAvx2 => {
                let width = reedsolomon_rs::xor_jit::JitWidth::Avx2;
                let block = width.block_bytes();
                for offset in (0..aligned_len).step_by(block) {
                    unsafe { width.finish_block(&mut dst[offset..offset + block]) };
                }
            }
        }
    }
    Ok(())
}

fn validate_provider<P: ForwardSourceProvider + ?Sized>(
    provider: &P,
    slice_size: usize,
) -> Result<()> {
    let source_count = provider.source_count();
    if source_count > MAX_TOTAL_INPUT_SLICES {
        return Err(resource_limit(format!(
            "input slice count {} exceeds {MAX_TOTAL_INPUT_SLICES}",
            source_count
        )));
    }
    for source_index in 0..source_count {
        if provider.source_slice_len(source_index)? > slice_size {
            return Err(invalid_input(
                "an input slice is longer than the configured slice size",
            ));
        }
    }
    Ok(())
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
        progress(ProgressUpdate {
            stage: ProgressStage::Creating,
            current,
            total,
            bytes_processed,
            total_bytes: Some(total_bytes),
            phase: ProgressPhase::RecoveryEncode,
        });
    }
}

#[cfg(test)]
struct VecRecoverySink {
    blocks: Vec<ForwardRecoveryBlock>,
    slice_size: usize,
}

#[cfg(test)]
impl VecRecoverySink {
    fn new(exponents: &[RecoveryExponent], slice_size: usize) -> Self {
        Self {
            blocks: exponents
                .iter()
                .map(|&exponent| ForwardRecoveryBlock {
                    exponent,
                    data: vec![0; slice_size],
                })
                .collect(),
            slice_size,
        }
    }
}

#[cfg(test)]
impl ForwardRecoverySink for VecRecoverySink {
    fn write_recovery_chunk(
        &mut self,
        output_index: usize,
        exponent: RecoveryExponent,
        offset: u64,
        data: &[u8],
    ) -> Result<()> {
        let block = self
            .blocks
            .get_mut(output_index)
            .ok_or_else(|| invalid_input("recovery output index is out of order"))?;
        if block.exponent != exponent {
            return Err(invalid_input("recovery exponent changed during encoding"));
        }
        let start =
            usize::try_from(offset).map_err(|_| resource_limit("stripe offset overflow"))?;
        let end = start
            .checked_add(data.len())
            .ok_or_else(|| resource_limit("recovery chunk end overflow"))?;
        if end > self.slice_size {
            return Err(invalid_input(
                "recovery chunk exceeds the configured slice size",
            ));
        }
        block.data[start..end].copy_from_slice(data);
        Ok(())
    }
}

fn round_up(value: usize, alignment: usize) -> Result<usize> {
    if alignment == 0 {
        return Err(invalid_input("zero alignment"));
    }
    value
        .checked_add(alignment - 1)
        .map(|value| value / alignment * alignment)
        .ok_or_else(|| resource_limit("aligned length overflow"))
}

fn checked_mul(left: usize, right: usize, reason: &'static str) -> Result<usize> {
    left.checked_mul(right)
        .ok_or_else(|| resource_limit(reason))
}

fn checked_add(left: usize, right: usize, reason: &'static str) -> Result<usize> {
    left.checked_add(right)
        .ok_or_else(|| resource_limit(reason))
}

fn invalid_input(reason: impl Into<String>) -> Par2Error {
    Par2Error::ReedSolomonError {
        reason: reason.into(),
    }
}

fn resource_limit(reason: impl Into<String>) -> Par2Error {
    Par2Error::ResourceLimitExceeded {
        reason: reason.into(),
    }
}

#[cfg(target_arch = "x86_64")]
fn unavailable_kernel(name: &'static str) -> Par2Error {
    Par2Error::ReedSolomonError {
        reason: format!("forward arithmetic kernel unavailable: {name}"),
    }
}

#[cfg(target_arch = "x86_64")]
fn jit_build_error(reason: String) -> Par2Error {
    Par2Error::ReedSolomonError {
        reason: format!("forward packed arithmetic dispatch failed: {reason}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_sources() -> Vec<Vec<u8>> {
        (0..19usize)
            .map(|source| {
                (0..(73 + source * 11).min(256))
                    .map(|index| (index.wrapping_mul(17) ^ (source * 29)) as u8)
                    .collect()
            })
            .collect()
    }

    fn encode_with_kernel(
        sources: &[Vec<u8>],
        kernel: ForwardKernel,
    ) -> Result<Vec<ForwardRecoveryBlock>> {
        let refs = sources.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let encoder = ForwardEncoder::new(256, vec![0, 1, 2, 7, 31])?;
        encoder.encode(
            &refs,
            &ForwardEncoderOptions {
                memory_limit: Some(4 * 1024 * 1024),
                kernel,
                ..ForwardEncoderOptions::default()
            },
        )
    }

    #[test]
    fn portable_output_matches_every_available_cpu_path() {
        let sources = test_sources();
        let portable = encode_with_kernel(&sources, ForwardKernel::Portable).unwrap();
        for kernel in ForwardEncoder::available_kernels() {
            let actual = encode_with_kernel(&sources, kernel).unwrap();
            assert_eq!(actual, portable, "kernel {kernel:?} differs from portable");
        }
    }

    #[test]
    fn automatic_selection_matches_its_explicit_kernel() {
        let sources = test_sources();
        let auto = encode_with_kernel(&sources, ForwardKernel::Auto).unwrap();
        let encoder = ForwardEncoder::new(256, vec![0, 1, 2, 7, 31]).unwrap();
        let selected = encoder.selected_kernel(ForwardKernel::Auto).unwrap();
        let explicit = encode_with_kernel(&sources, selected).unwrap();
        assert_eq!(auto, explicit, "automatic kernel {selected:?} differs");
    }

    /// The env override's value mapping, tested without process-global state.
    #[test]
    fn kernel_override_values_parse_and_reject() {
        assert!(matches!(
            parse_kernel_override("auto"),
            Ok(ForwardKernel::Auto)
        ));
        assert!(matches!(
            parse_kernel_override(" Portable "),
            Ok(ForwardKernel::Portable)
        ));
        assert!(matches!(
            parse_kernel_override("SIMD"),
            Ok(ForwardKernel::Simd)
        ));
        #[cfg(target_arch = "x86_64")]
        {
            assert!(matches!(
                parse_kernel_override("folded"),
                Ok(ForwardKernel::Folded)
            ));
            assert!(matches!(
                parse_kernel_override("xor-jit-avx2"),
                Ok(ForwardKernel::XorJitAvx2)
            ));
            // The AVX-512 JIT is removed; its old name must fail loudly, not
            // silently select something else.
            assert!(parse_kernel_override("xor-jit-avx512").is_err());
        }
        assert!(parse_kernel_override("fast").is_err());
        assert!(parse_kernel_override("").is_err());
    }

    /// The stripe hand-off must give every band every batch, in order, and
    /// must not let the producer refill an area a band is still reading.
    ///
    /// The marker byte is the witness: the producer stamps the batch index
    /// into the area it just filled, and every band asserts the stamp it sees
    /// is the batch it asked for. A ring that reclaimed an area early would
    /// overwrite a live area with the *next* batch's stamp, which is exactly
    /// the failure this catches; `Arc::get_mut` on the producer side is the
    /// same reclaim proof the encoder relies on.
    #[test]
    fn the_stripe_feed_reclaims_an_area_only_after_every_band_is_done() {
        const BATCHES: usize = 37;
        for band_count in [1usize, 2, 5] {
            let feed = StripeFeed::new(band_count);
            let feed = &feed;
            let mut areas: Vec<std::sync::Arc<AlignedBuffer>> = (0..STAGING_AREA_COUNT)
                .map(|_| std::sync::Arc::new(AlignedBuffer::new(64)))
                .collect();
            std::thread::scope(|scope| {
                for _ in 0..band_count {
                    scope.spawn(move || {
                        for batch in 0..BATCHES {
                            let ticket = feed.acquire(batch).expect("no failure is injected");
                            assert_eq!(ticket.source_start, batch * 7, "batch order");
                            assert_eq!(
                                ticket.staging.as_bytes()[0],
                                (batch % 251) as u8,
                                "area was refilled while a band still held it"
                            );
                            drop(ticket);
                            feed.release(batch);
                        }
                    });
                }
                for batch in 0..BATCHES {
                    assert!(feed.wait_for_area(batch));
                    let area = batch % STAGING_AREA_COUNT;
                    let buffer = std::sync::Arc::get_mut(&mut areas[area])
                        .expect("every band released the area before it was reclaimed");
                    buffer.as_bytes_mut()[0] = (batch % 251) as u8;
                    feed.publish(
                        batch,
                        BatchTicket {
                            staging: std::sync::Arc::clone(&areas[area]),
                            source_start: batch * 7,
                            live_inputs: 1,
                        },
                    );
                }
            });
        }
    }

    /// A failed pass must release both sides of the hand-off. Without the
    /// flag, `acquire` waits for a publish that will never come and
    /// `wait_for_area` waits for a completion that will never come.
    #[test]
    fn a_failed_pass_releases_both_sides_of_the_feed() {
        let feed = StripeFeed::new(2);
        feed.fail();
        assert!(feed.acquire(0).is_none(), "a band must stop on failure");
        assert!(
            !feed.wait_for_area(STAGING_AREA_COUNT),
            "the producer must stop on failure"
        );
    }

    /// The banded accumulate/finish split must be byte-identical to the
    /// sequential pass for every runtime kernel, including an uneven trailing
    /// band (seven outputs over three bands).
    #[test]
    fn banded_accumulation_matches_sequential() {
        let sources = test_sources();
        let refs = sources.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let exponents: Vec<RecoveryExponent> = vec![0, 1, 2, 7, 31, 64, 100];
        for requested in ForwardEncoder::available_kernels() {
            let resolved =
                resolve_kernel_with_capabilities(requested, runtime_kernel_capabilities())
                    .expect("advertised kernels resolve");
            let contract = KernelContract::for_kernel(resolved);
            let aligned_len = round_up(256, contract.stride).unwrap();

            let mut passes = Vec::new();
            // band_size = 7 covers the sequential path; 3 exercises uneven
            // banding (bands of 3, 3, 1 outputs).
            for band_size in [7usize, 3] {
                let mut provider = InMemorySourceProvider { sources: &refs };
                let mut staging = AlignedBuffer::new(
                    contract.input_grouping * lane_stride(contract, aligned_len),
                );
                let mut transfer = AlignedBuffer::new(aligned_len);
                fill_staging(
                    resolved,
                    &mut staging,
                    &mut transfer,
                    &mut provider,
                    0,
                    0,
                    256,
                    aligned_len,
                    contract,
                )
                .unwrap();
                let factors = FactorSource::new(refs.len());
                let mut output = AlignedBuffer::new(exponents.len() * aligned_len);
                #[cfg(target_arch = "x86_64")]
                let mut jit_workspaces: Vec<
                    reedsolomon_rs::xor_jit::packed::PackedJitWorkspace,
                > = (0..exponents.len().div_ceil(band_size))
                    .map(|_| Default::default())
                    .collect();
                accumulate_batch(
                    resolved,
                    output.as_bytes_mut(),
                    &staging,
                    &factors,
                    &exponents,
                    0,
                    contract.input_grouping.min(refs.len()),
                    aligned_len,
                    aligned_len,
                    contract,
                    band_size,
                    #[cfg(target_arch = "x86_64")]
                    &mut jit_workspaces,
                    #[cfg(target_arch = "x86_64")]
                    usize::MAX,
                )
                .unwrap();
                finish_output(
                    resolved,
                    output.as_bytes_mut(),
                    aligned_len,
                    aligned_len,
                    exponents.len(),
                )
                .unwrap();
                passes.push(output.as_bytes().to_vec());
            }
            assert_eq!(
                passes[0], passes[1],
                "kernel {requested:?} banded output differs from sequential"
            );
        }
    }

    /// Every emitted tile is stride-aligned and the ranges tile the stripe
    /// exactly once, including a stripe that is not a whole number of tiles.
    #[test]
    fn stripe_tiles_cover_the_stripe_exactly() {
        for (aligned_len, tile) in [
            (4096usize, 4096usize),
            (4096, 8192),
            (4096, UNTILED),
            (10 * 1024, 4096),
            (32, 4096),
            (0, 4096),
        ] {
            let ranges: Vec<(usize, usize)> = stripe_tiles(aligned_len, tile).collect();
            let mut next = 0usize;
            for (start, len) in &ranges {
                assert_eq!(*start, next, "tiles are contiguous");
                assert!(*len > 0 && *len <= tile.min(aligned_len).max(1));
                next += len;
            }
            assert_eq!(next, aligned_len, "tiles cover the stripe");
            if aligned_len > 0 {
                // Only the final tile may be short.
                for (_, len) in &ranges[..ranges.len() - 1] {
                    assert_eq!(*len, tile.min(aligned_len));
                }
            }
        }
    }

    /// Tiling one in-memory stripe is a pure loop transformation: for every
    /// runtime kernel whose family is tiled, the accumulated bytes must not
    /// depend on the tile size, including tiles that do not divide the stripe.
    #[test]
    fn stripe_tiling_matches_untiled_accumulation() {
        const SLICE: usize = 40 * 1024;
        let sources: Vec<Vec<u8>> = (0..14usize)
            .map(|source| {
                (0..SLICE)
                    .map(|index| (index.wrapping_mul(31) ^ (source * 131)) as u8)
                    .collect()
            })
            .collect();
        let refs = sources.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let exponents: Vec<RecoveryExponent> = vec![0, 1, 2, 7, 31];
        for requested in ForwardEncoder::available_kernels() {
            let resolved =
                resolve_kernel_with_capabilities(requested, runtime_kernel_capabilities())
                    .expect("advertised kernels resolve");
            let base = KernelContract::for_kernel(resolved);
            if base.tile_bytes == UNTILED {
                continue;
            }
            let aligned_len = round_up(SLICE, base.stride).unwrap();
            let mut passes = Vec::new();
            for tile_bytes in [UNTILED, 8192, 4096, 96, base.stride] {
                let contract = KernelContract { tile_bytes, ..base };
                let mut provider = InMemorySourceProvider { sources: &refs };
                let mut staging = AlignedBuffer::new(
                    contract.input_grouping * lane_stride(contract, aligned_len),
                );
                let mut transfer = AlignedBuffer::new(aligned_len);
                fill_staging(
                    resolved,
                    &mut staging,
                    &mut transfer,
                    &mut provider,
                    0,
                    0,
                    SLICE,
                    aligned_len,
                    contract,
                )
                .unwrap();
                let factors = FactorSource::new(refs.len());
                let mut output = AlignedBuffer::new(exponents.len() * aligned_len);
                #[cfg(target_arch = "x86_64")]
                let mut jit_workspaces: Vec<
                    reedsolomon_rs::xor_jit::packed::PackedJitWorkspace,
                > = vec![Default::default()];
                accumulate_batch(
                    resolved,
                    output.as_bytes_mut(),
                    &staging,
                    &factors,
                    &exponents,
                    0,
                    contract.input_grouping.min(refs.len()),
                    aligned_len,
                    aligned_len,
                    contract,
                    exponents.len(),
                    #[cfg(target_arch = "x86_64")]
                    &mut jit_workspaces,
                    #[cfg(target_arch = "x86_64")]
                    usize::MAX,
                )
                .unwrap();
                finish_output(
                    resolved,
                    output.as_bytes_mut(),
                    aligned_len,
                    aligned_len,
                    exponents.len(),
                )
                .unwrap();
                passes.push(output.as_bytes().to_vec());
            }
            for (index, pass) in passes.iter().enumerate().skip(1) {
                assert_eq!(
                    *pass, passes[0],
                    "kernel {requested:?} tiling pass {index} differs from the untiled pass"
                );
            }
        }
    }

    /// The order in which the encode feed asks for source bytes, which is what
    /// decides whether a hash can be driven from inside it.
    ///
    /// Within one stripe the feed walks sources in increasing index, and each
    /// source's bytes arrive in increasing offset across stripes — so a
    /// PER-SLICE digest can be carried across stripes and fused into the feed.
    /// A PER-FILE digest cannot unless the pass is single-stripe: with more
    /// than one stripe the order is stripe-major (every source's first chunk,
    /// then every source's second chunk), never file order. This test pins that
    /// distinction, because "hash from the encode feed" is only correct for the
    /// file MD5 while `chunk_len == slice_size`.
    #[test]
    fn the_feed_is_stripe_major_once_a_slice_needs_more_than_one_stripe() {
        struct Recorder<'a> {
            sources: &'a [&'a [u8]],
            reads: Vec<(usize, usize)>,
        }
        impl ForwardSourceProvider for Recorder<'_> {
            fn source_count(&self) -> usize {
                self.sources.len()
            }
            fn source_slice_len(&self, source_index: usize) -> Result<usize> {
                Ok(self.sources[source_index].len())
            }
            fn read_source_chunk(
                &mut self,
                source_index: usize,
                offset: usize,
                destination: &mut [u8],
            ) -> Result<usize> {
                if source_index < self.sources.len() {
                    self.reads.push((source_index, offset));
                }
                let source = self.sources[source_index];
                let start = offset.min(source.len());
                let take = destination.len().min(source.len() - start);
                destination[..take].copy_from_slice(&source[start..start + take]);
                Ok(take)
            }
        }

        const SLICE: usize = 4096;
        let sources: Vec<Vec<u8>> = (0..3usize).map(|s| vec![s as u8 + 1; SLICE]).collect();
        let refs = sources.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let encoder = ForwardEncoder::new(SLICE, vec![0, 1]).unwrap();

        // A budget that admits the whole slice: one stripe, so every source is
        // delivered start to end before the next one begins — file order.
        let mut single = Recorder {
            sources: &refs,
            reads: Vec::new(),
        };
        let mut sink = VecRecoverySink::new(&[0, 1], SLICE);
        encoder
            .encode_to(
                &mut single,
                &ForwardEncoderOptions {
                    memory_limit: Some(4 * 1024 * 1024),
                    ..ForwardEncoderOptions::default()
                },
                &mut sink,
            )
            .unwrap();
        assert_eq!(
            single.reads,
            vec![(0, 0), (1, 0), (2, 0)],
            "a single-stripe feed must deliver each source once, whole"
        );

        // A budget that forces the slice into several stripes: the same source
        // is now revisited at a later offset only after every other source has
        // been served at the earlier one.
        let mut split = Recorder {
            sources: &refs,
            reads: Vec::new(),
        };
        let mut sink = VecRecoverySink::new(&[0, 1], SLICE);
        encoder
            .encode_to(
                &mut split,
                &ForwardEncoderOptions {
                    memory_limit: Some(32 * 1024),
                    ..ForwardEncoderOptions::default()
                },
                &mut sink,
            )
            .unwrap();
        let offsets: Vec<usize> = split.reads.iter().map(|&(_, offset)| offset).collect();
        assert!(
            offsets.iter().any(|&offset| offset > 0),
            "the tight budget must split the slice into stripes"
        );
        assert!(
            split
                .reads
                .windows(2)
                .any(|pair| pair[0].0 > pair[1].0 && pair[1].1 > pair[0].1),
            "a multi-stripe feed is stripe-major: {:?}",
            split.reads
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn advertised_kernels_use_the_production_capability_resolver() {
        let capabilities = runtime_kernel_capabilities();
        let advertised = ForwardEncoder::available_kernels();
        assert_eq!(
            advertised.contains(&ForwardKernel::Folded),
            capabilities.folded
        );
        let encoder = ForwardEncoder::new(256, vec![0]).unwrap();
        for kernel in advertised {
            assert!(
                encoder.selected_kernel(kernel).is_ok(),
                "advertised kernel {kernel:?} cannot be selected"
            );
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn automatic_admission_keeps_the_full_kernel_ladder_ordered() {
        let folded_only = KernelCapabilities {
            folded: true,
            folded_wide: false,
            avx2_jit: false,
        };
        assert_eq!(
            auto_kernel_candidates(folded_only),
            vec![
                ResolvedKernel::Folded,
                ResolvedKernel::Simd,
                ResolvedKernel::Portable,
            ]
        );

        let direct_simd_only = KernelCapabilities {
            folded: false,
            folded_wide: false,
            avx2_jit: false,
        };
        assert_eq!(
            auto_kernel_candidates(direct_simd_only),
            vec![ResolvedKernel::Simd, ResolvedKernel::Portable]
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn production_admission_can_fall_back_from_folded_to_simd() {
        let capabilities = KernelCapabilities {
            folded: true,
            folded_wide: false,
            avx2_jit: false,
        };
        let raw = resolve_kernel_with_capabilities(ForwardKernel::Auto, capabilities).unwrap();
        assert_eq!(raw, ResolvedKernel::Folded);

        let slice_size = 60;
        let source_count = 19;
        let first_exponent = 0_u32;
        let recovery_count = u32::from(u16::MAX);
        assert!(first_exponent + recovery_count < u32::from(u16::MAX) + 1);
        let output_count = recovery_count as usize;
        let minimum_memory_limit = |requested| {
            let (_, full_plan) = select_kernel_for_memory_with_capabilities(
                slice_size,
                output_count,
                source_count,
                usize::MAX,
                requested,
                capabilities,
            )
            .unwrap();
            let mut lower = 0;
            let mut upper = full_plan.memory_bytes;
            while lower < upper {
                let middle = lower + (upper - lower) / 2;
                if select_kernel_for_memory_with_capabilities(
                    slice_size,
                    output_count,
                    source_count,
                    middle,
                    requested,
                    capabilities,
                )
                .is_ok()
                {
                    upper = middle;
                } else {
                    lower = middle + 1;
                }
            }
            assert!(
                select_kernel_for_memory_with_capabilities(
                    slice_size,
                    output_count,
                    source_count,
                    lower,
                    requested,
                    capabilities,
                )
                .is_ok()
            );
            if lower > 0 {
                assert!(
                    select_kernel_for_memory_with_capabilities(
                        slice_size,
                        output_count,
                        source_count,
                        lower - 1,
                        requested,
                        capabilities,
                    )
                    .is_err()
                );
            }
            lower
        };
        let folded_minimum = minimum_memory_limit(ForwardKernel::Folded);
        let simd_minimum = minimum_memory_limit(ForwardKernel::Simd);
        assert!(
            folded_minimum > simd_minimum,
            "folded minimum {folded_minimum} is not above simd minimum {simd_minimum}"
        );
        let memory_limit = simd_minimum;
        assert!(
            select_kernel_for_memory_with_capabilities(
                slice_size,
                output_count,
                source_count,
                memory_limit,
                ForwardKernel::Folded,
                capabilities,
            )
            .is_err()
        );
        let (admitted, _) = select_kernel_for_memory_with_capabilities(
            slice_size,
            output_count,
            source_count,
            memory_limit,
            ForwardKernel::Auto,
            capabilities,
        )
        .unwrap();
        assert_eq!(admitted, ResolvedKernel::Simd);
    }

    #[test]
    fn final_stripe_is_not_padded_in_sink() {
        struct Sink {
            chunks: Vec<(usize, RecoveryExponent, u64, Vec<u8>)>,
        }
        impl ForwardRecoverySink for Sink {
            fn write_recovery_chunk(
                &mut self,
                output_index: usize,
                exponent: RecoveryExponent,
                offset: u64,
                data: &[u8],
            ) -> Result<()> {
                self.chunks
                    .push((output_index, exponent, offset, data.to_vec()));
                Ok(())
            }
        }

        let sources = test_sources();
        let refs = sources.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let encoder =
            ForwardEncoder::new(260, vec![4, 9]).expect("slice size is a valid PAR2 size");
        let mut sink = Sink { chunks: Vec::new() };
        encoder
            .encode_slices_to(
                &refs,
                &ForwardEncoderOptions {
                    memory_limit: Some(8_800),
                    kernel: ForwardKernel::Portable,
                    ..ForwardEncoderOptions::default()
                },
                &mut sink,
            )
            .unwrap();
        assert!(sink.chunks.iter().all(|(_, _, _, data)| data.len() <= 260));
        // The stripe length is whatever the 8,800-byte budget admits for the
        // family's staging shape (256 with twelve lanes, 188 with sixteen);
        // what must hold regardless is that the final stripe carries exactly
        // the slice remainder and nothing after it.
        let stripe = sink.chunks[0].3.len();
        assert!(
            (2..260).contains(&stripe),
            "the memory limit must force a multi-stripe plan, got stripe {stripe}"
        );
        let stripes = 260usize.div_ceil(stripe);
        assert_eq!(sink.chunks.len(), 2 * stripes);
        let last = sink.chunks.last().unwrap();
        assert_eq!(last.2 as usize, (stripes - 1) * stripe);
        assert_eq!(last.3.len(), 260 - (stripes - 1) * stripe);
    }

    #[test]
    fn tight_memory_preserves_recovery_bytes_for_every_available_kernel() {
        let slice_size = 1028usize;
        let source_count = 19;
        let output_count = 3;
        let sources = (0..source_count)
            .map(|source| {
                (0..slice_size)
                    .map(|index| (index.wrapping_mul(17) ^ (source * 29)) as u8)
                    .collect()
            })
            .collect::<Vec<Vec<u8>>>();
        let refs = sources.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let exponents = vec![4, 9, 17];
        assert_eq!(refs.len(), source_count);
        assert_eq!(exponents.len(), output_count);
        let encoder = ForwardEncoder::new(slice_size, exponents).unwrap();
        let (_, reference_plan) = select_kernel_for_memory(
            slice_size,
            output_count,
            source_count,
            usize::MAX,
            ForwardKernel::Portable,
        )
        .unwrap();
        assert_eq!(reference_plan.chunk_len, slice_size);
        let reference = encoder
            .encode(
                &refs,
                &ForwardEncoderOptions {
                    memory_limit: Some(reference_plan.memory_bytes),
                    kernel: ForwardKernel::Portable,
                    ..ForwardEncoderOptions::default()
                },
            )
            .unwrap();

        for kernel in ForwardEncoder::available_kernels() {
            let (_, full_plan) = select_kernel_for_memory(
                slice_size,
                output_count,
                source_count,
                usize::MAX,
                kernel,
            )
            .unwrap();
            let (tight_limit, tight_plan) = if full_plan.chunk_len < slice_size {
                (full_plan.memory_bytes, full_plan)
            } else {
                let mut memory_limit = full_plan.memory_bytes;
                loop {
                    memory_limit = memory_limit
                        .checked_sub(1)
                        .expect("a full-stripe plan has a smaller admitted plan");
                    match select_kernel_for_memory(
                        slice_size,
                        output_count,
                        source_count,
                        memory_limit,
                        kernel,
                    ) {
                        Ok((_, plan))
                            if plan.chunk_len < slice_size
                                && !slice_size.is_multiple_of(plan.chunk_len) =>
                        {
                            break (memory_limit, plan);
                        }
                        Ok(_) | Err(_) => {}
                    }
                }
            };
            assert!(
                tight_plan.chunk_len < slice_size,
                "kernel {kernel:?} retained a full-size stripe"
            );
            let stripe_count = slice_size.div_ceil(tight_plan.chunk_len);
            assert!(stripe_count > 1, "kernel {kernel:?} used one stripe");
            let final_len = slice_size % tight_plan.chunk_len;
            assert!(
                final_len > 0 && final_len < tight_plan.chunk_len,
                "kernel {kernel:?} did not produce a short final stripe"
            );

            let actual = encoder
                .encode(
                    &refs,
                    &ForwardEncoderOptions {
                        memory_limit: Some(tight_limit),
                        kernel,
                        ..ForwardEncoderOptions::default()
                    },
                )
                .unwrap();
            assert_eq!(actual, reference, "kernel {kernel:?} differs from portable");
        }
    }

    #[test]
    fn every_available_kernel_streams_contiguous_unpadded_chunks() {
        struct Sink {
            chunks: Vec<(usize, RecoveryExponent, u64, Vec<u8>)>,
        }
        impl ForwardRecoverySink for Sink {
            fn write_recovery_chunk(
                &mut self,
                output_index: usize,
                exponent: RecoveryExponent,
                offset: u64,
                data: &[u8],
            ) -> Result<()> {
                self.chunks
                    .push((output_index, exponent, offset, data.to_vec()));
                Ok(())
            }
        }

        let sources = test_sources();
        let refs = sources.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let exponents = vec![4, 9];
        let encoder = ForwardEncoder::new(260, exponents.clone()).unwrap();
        let options = |kernel| ForwardEncoderOptions {
            memory_limit: Some(1024 * 1024),
            kernel,
            ..ForwardEncoderOptions::default()
        };
        let reference = encoder
            .encode(&refs, &options(ForwardKernel::Portable))
            .unwrap();

        for kernel in ForwardEncoder::available_kernels() {
            let actual = encoder.encode(&refs, &options(kernel)).unwrap();
            assert_eq!(actual, reference, "kernel {kernel:?} differs from portable");

            let mut sink = Sink { chunks: Vec::new() };
            encoder
                .encode_slices_to(&refs, &options(kernel), &mut sink)
                .unwrap();
            let mut next_offset = vec![0u64; exponents.len()];
            for (position, (output_index, exponent, offset, data)) in sink.chunks.iter().enumerate()
            {
                assert_eq!(*output_index, position % exponents.len());
                assert_eq!(*exponent, exponents[*output_index]);
                assert_eq!(*offset, next_offset[*output_index]);
                assert!(*offset + data.len() as u64 <= encoder.slice_size() as u64);
                next_offset[*output_index] += data.len() as u64;
            }
            assert!(next_offset.iter().all(|&offset| offset == 260));
        }
    }

    #[test]
    fn insufficient_memory_rejects_without_zero_length_stripes() {
        let result = BufferPlan::new_with_reserved(
            260,
            1,
            KernelContract {
                stride: 32,
                input_grouping: DEFAULT_INPUT_GROUPING,
                tile_bytes: TABLE_TILE_BYTES,
                skewed_lanes: true,
            },
            1,
            0,
            0,
            0,
        );
        assert!(matches!(
            result,
            Err(Par2Error::ResourceLimitExceeded { .. })
        ));
    }

    #[test]
    fn factor_workspace_does_not_scale_with_recovery_rows() {
        let one = estimate_forward_memory(
            4,
            MAX_TOTAL_INPUT_SLICES,
            1,
            3 * 1024 * 1024,
            ForwardKernel::Portable,
        )
        .unwrap();
        let many = estimate_forward_memory(
            4,
            MAX_TOTAL_INPUT_SLICES,
            MAX_TOTAL_INPUT_SLICES,
            3 * 1024 * 1024,
            ForwardKernel::Portable,
        )
        .unwrap();
        assert_eq!(one.factor_workspace_bytes, many.factor_workspace_bytes);
        assert!(one.factor_workspace_bytes < 128 * 1024);
        assert!(many.processing_peak_bytes <= 3 * 1024 * 1024);
    }

    #[test]
    fn low_memory_rejects_before_large_output_allocation() {
        let result = estimate_forward_memory(
            4096,
            MAX_TOTAL_INPUT_SLICES,
            MAX_TOTAL_INPUT_SLICES,
            64 * 1024,
            ForwardKernel::Portable,
        );
        assert!(matches!(
            result,
            Err(Par2Error::ResourceLimitExceeded { .. })
        ));
    }

    #[test]
    fn staging_zero_pads_an_odd_final_byte_as_a_low_byte_word() {
        let source = [0x11, 0x22, 0x33];
        let refs = [source.as_slice()];
        let mut provider = InMemorySourceProvider { sources: &refs };
        let mut staging = AlignedBuffer::new(DEFAULT_INPUT_GROUPING * 4);
        let mut transfer = AlignedBuffer::new(4);
        fill_staging(
            ResolvedKernel::Portable,
            &mut staging,
            &mut transfer,
            &mut provider,
            0,
            0,
            3,
            4,
            KernelContract {
                stride: 2,
                input_grouping: DEFAULT_INPUT_GROUPING,
                tile_bytes: TABLE_TILE_BYTES,
                skewed_lanes: true,
            },
        )
        .unwrap();
        assert_eq!(&staging.as_bytes()[..4], &[0x11, 0x22, 0x33, 0]);
    }

    #[test]
    fn cancellation_is_observed_before_allocation() {
        let sources = test_sources();
        let refs = sources.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let token = CancellationToken::new();
        token.cancel();
        let encoder = ForwardEncoder::new(256, vec![0]).unwrap();
        let error = encoder
            .encode(
                &refs,
                &ForwardEncoderOptions {
                    cancel: Some(token),
                    ..ForwardEncoderOptions::default()
                },
            )
            .unwrap_err();
        assert!(matches!(error, Par2Error::Cancelled));
    }

    #[test]
    fn payload_matches_vandermonde_definition() {
        let sources = test_sources();
        let refs = sources.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let exponents = [0, 31];
        let encoder = ForwardEncoder::new(256, exponents.to_vec()).unwrap();
        let actual = encoder
            .encode(
                &refs,
                &ForwardEncoderOptions {
                    kernel: ForwardKernel::Portable,
                    ..ForwardEncoderOptions::default()
                },
            )
            .unwrap();
        let constants = gf::input_slice_constants(refs.len());

        for (output, &exponent) in exponents.iter().enumerate() {
            let mut expected = vec![0u8; 256];
            for (source_index, source) in refs.iter().enumerate() {
                let factor = gf::pow(constants[source_index], exponent);
                for word in 0..128 {
                    let offset = word * 2;
                    let source_word = if offset < source.len() {
                        u16::from_le_bytes([
                            source[offset],
                            source.get(offset + 1).map_or(0, |byte| *byte),
                        ])
                    } else {
                        0
                    };
                    let output_word = u16::from_le_bytes([expected[offset], expected[offset + 1]])
                        ^ gf::mul(source_word, factor);
                    expected[offset..offset + 2].copy_from_slice(&output_word.to_le_bytes());
                }
            }
            assert_eq!(actual[output].data, expected);
        }
    }

    /// The stripe skew is a fixed rule of the stripe length: it moves the
    /// stride to 1 KiB modulo 4 KiB, capped at 1/8 of the stripe, and is zero
    /// when the stripe already sits at that residue.
    #[test]
    fn stripe_skew_follows_the_stripe_length() {
        assert_eq!(stripe_skew_bytes(2), 0);
        assert_eq!(stripe_skew_bytes(256), 0);
        assert_eq!(stripe_skew_bytes(1023), 0);
        assert_eq!(stripe_skew_bytes(1024), 0, "already 1 KiB mod 4 KiB");
        assert_eq!(stripe_skew_bytes(2048), 256, "wants 3 KiB, capped at 1/8");
        assert_eq!(stripe_skew_bytes(4096), 512, "wants 1 KiB, capped at 1/8");
        assert_eq!(stripe_skew_bytes(40_960), 1024);
        assert_eq!(stripe_skew_bytes(65_536), 1024);
        assert_eq!(stripe_skew_bytes(66_560), 0, "already 1 KiB mod 4 KiB");
        assert_eq!(
            stripe_skew_bytes(67_584),
            3072,
            "2 KiB residue moves to 1 KiB"
        );
        assert_eq!(stripe_skew_bytes(1 << 20), 1024);
        // Uncapped cases land exactly on the target residue.
        for aligned_len in [8192usize, 40_960, 65_536, 67_584, 1 << 20] {
            let stride = aligned_len + stripe_skew_bytes(aligned_len);
            assert_eq!(stride % 4096, 1024, "stride residue for {aligned_len}");
        }
        // The plan carries the skew into both strides at the shape the
        // benchmark corpus uses (64 KiB slices, 12-lane staging).
        let contract = KernelContract {
            stride: 2,
            input_grouping: DEFAULT_INPUT_GROUPING,
            tile_bytes: TABLE_TILE_BYTES,
            skewed_lanes: true,
        };
        let plan =
            BufferPlan::new_with_reserved(65_536, 820, contract, usize::MAX, 0, 0, 0).unwrap();
        assert_eq!(plan.aligned_chunk_len, 65_536);
        assert_eq!(plan.row_stride, 65_536 + 1024);
        assert_eq!(plan.staging_bytes, DEFAULT_INPUT_GROUPING * (65_536 + 1024));
        assert_eq!(plan.output_bytes, 820 * (65_536 + 1024));
        assert_eq!(lane_stride(contract, 65_536), 65_536 + 1024);
        assert_eq!(
            lane_stride(
                KernelContract {
                    skewed_lanes: false,
                    ..contract
                },
                65_536
            ),
            65_536
        );
    }

    /// The slice-per-source families batch by kernel shape: sixteen on the
    /// aarch64 CLMUL family (two full eight-source passes), twelve elsewhere;
    /// the folded and packed XOR-JIT families are structurally twelve.
    #[test]
    fn input_grouping_follows_the_kernel_family() {
        let simd = KernelContract::for_kernel(ResolvedKernel::Simd);
        let portable = KernelContract::for_kernel(ResolvedKernel::Portable);
        assert_eq!(simd.input_grouping, portable.input_grouping);
        assert!((1..=MAX_INPUT_GROUPING).contains(&simd.input_grouping));
        if std::env::var_os("WEAVER_PAR2_CREATE_GROUPING").is_none() {
            #[cfg(target_arch = "aarch64")]
            assert_eq!(simd.input_grouping, CLMUL_INPUT_GROUPING);
            #[cfg(not(target_arch = "aarch64"))]
            assert_eq!(simd.input_grouping, DEFAULT_INPUT_GROUPING);
        }
        #[cfg(target_arch = "x86_64")]
        for kernel in ForwardEncoder::available_kernels() {
            let resolved =
                resolve_kernel_with_capabilities(kernel, runtime_kernel_capabilities()).unwrap();
            if matches!(
                resolved,
                ResolvedKernel::Folded | ResolvedKernel::XorJitAvx2
            ) {
                assert_eq!(
                    KernelContract::for_kernel(resolved).input_grouping,
                    DEFAULT_INPUT_GROUPING
                );
            }
        }
    }

    /// With the skew live (a 4 KiB stripe skews lanes and rows by 512 bytes),
    /// every runtime kernel must still produce exactly the Vandermonde
    /// definition — the layout moves bytes, never arithmetic. Sources are
    /// deliberately of unequal lengths so lane tails and the zero padding sit
    /// in the skewed positions too.
    #[test]
    fn skewed_stripe_layout_matches_vandermonde_definition_on_every_kernel() {
        const SLICE: usize = 4096;
        assert_eq!(stripe_skew_bytes(SLICE), 512, "the skew must be live here");
        let sources: Vec<Vec<u8>> = (0..27usize)
            .map(|source| {
                (0..(SLICE - source * 97))
                    .map(|index| (index.wrapping_mul(31) ^ (source * 53) ^ (index >> 7)) as u8)
                    .collect()
            })
            .collect();
        let refs = sources.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let exponents: [RecoveryExponent; 4] = [0, 1, 31, 100];
        let constants = gf::input_slice_constants(refs.len());
        let mut expected = Vec::new();
        for &exponent in &exponents {
            let mut block = vec![0u8; SLICE];
            for (source_index, source) in refs.iter().enumerate() {
                let factor = gf::pow(constants[source_index], exponent);
                for word in 0..SLICE / 2 {
                    let offset = word * 2;
                    let source_word = if offset < source.len() {
                        u16::from_le_bytes([
                            source[offset],
                            source.get(offset + 1).map_or(0, |byte| *byte),
                        ])
                    } else {
                        0
                    };
                    let output_word = u16::from_le_bytes([block[offset], block[offset + 1]])
                        ^ gf::mul(source_word, factor);
                    block[offset..offset + 2].copy_from_slice(&output_word.to_le_bytes());
                }
            }
            expected.push(block);
        }
        for kernel in ForwardEncoder::available_kernels() {
            let encoder = ForwardEncoder::new(SLICE, exponents.to_vec()).unwrap();
            let actual = encoder
                .encode(
                    &refs,
                    &ForwardEncoderOptions {
                        kernel,
                        ..ForwardEncoderOptions::default()
                    },
                )
                .unwrap();
            for (output, block) in expected.iter().enumerate() {
                assert_eq!(
                    &actual[output].data, block,
                    "kernel {kernel:?} output {output} diverged from the definition"
                );
            }
        }
    }

    #[test]
    fn zero_input_produces_zero_recovery_blocks() {
        let encoder = ForwardEncoder::new(256, vec![0, 5]).unwrap();
        let blocks = encoder
            .encode(&[], &ForwardEncoderOptions::default())
            .unwrap();
        assert_eq!(blocks.len(), 2);
        assert!(
            blocks
                .iter()
                .all(|block| block.data.iter().all(|&byte| byte == 0))
        );
    }
}
