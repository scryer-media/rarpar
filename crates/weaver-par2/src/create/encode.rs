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

use rayon::prelude::*;

use crate::error::{Par2Error, Result};
use crate::gf;
use crate::types::{
    CancellationToken, MAX_TOTAL_INPUT_SLICES, ProgressCallback, ProgressStage, ProgressUpdate,
    RecoveryExponent,
};
use reedsolomon_rs::gf_simd::{self, PreparedFactorSrc};

use super::plan::default_memory_limit;

const DEFAULT_INPUT_GROUPING: usize = 12;
const STAGING_AREA_COUNT: usize = 2;
const TRANSFER_BUFFER_COUNT: usize = 2;
// The stripe pipeline's split_at_mut parity selection and the per-stripe
// prefill of staging[0] are written for exactly two areas; a wider pipeline
// would silently accumulate from the wrong area.
const _: () = assert!(STAGING_AREA_COUNT == 2);

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
/// therefore follow `available_parallelism`; execution still lands on
/// whatever rayon pool is current, which is correct at any width.
pub(crate) fn configured_create_threads() -> usize {
    static CONFIGURED: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *CONFIGURED.get_or_init(|| {
        // wasm never has a worker pool; keep rayon machinery untouched there
        // (same convention as the matrix/repairer guards).
        if cfg!(target_family = "wasm") {
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
/// `Auto` follows the creation-specific runtime ladder, which may prioritize
/// AVX-512 and does not follow the repair controller.  The other variants are
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
    /// AVX2 split-layout folded dispatch (GFNI or shuffle2x).
    #[cfg(target_arch = "x86_64")]
    Folded,
    /// Packed AVX2 XOR-JIT dispatch.
    #[cfg(target_arch = "x86_64")]
    XorJitAvx2,
    /// Packed AVX-512 XOR-JIT dispatch.
    #[cfg(target_arch = "x86_64")]
    XorJitAvx512,
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
            if capabilities.avx512_jit {
                kernels.push(ForwardKernel::XorJitAvx512);
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

        let mut staging = [
            AlignedBuffer::new(buffers.staging_bytes),
            AlignedBuffer::new(buffers.staging_bytes),
        ];
        let mut transfers = [
            AlignedBuffer::new(buffers.aligned_chunk_len),
            AlignedBuffer::new(buffers.aligned_chunk_len),
        ];
        let mut output = AlignedBuffer::new(buffers.output_bytes);

        let (band_size, band_count) = create_band_shape(self.recovery_exponents.len());
        #[cfg(not(target_arch = "x86_64"))]
        let _ = band_count;
        #[cfg(target_arch = "x86_64")]
        let mut jit_workspaces: Vec<reedsolomon_rs::xor_jit::packed::PackedJitWorkspace> =
            (0..band_count).map(|_| Default::default()).collect();

        let stripe_count = self.slice_size.div_ceil(buffers.chunk_len);
        let stripe_count_u32 = u32::try_from(stripe_count)
            .map_err(|_| resource_limit("stripe count exceeds progress range"))?;
        let total_bytes = (self.recovery_exponents.len() as u64)
            .checked_mul(self.slice_size as u64)
            .ok_or_else(|| resource_limit("progress byte count overflow"))?;
        let jit_code_budget = buffers.jit_build_limit_bytes;

        // The two staging areas run as a two-stage pipeline: while the
        // rayon bands accumulate batch N from one area, this thread fills
        // batch N+1 into the other, hiding source reads and split-layout
        // conversion behind the GF16 math. `overlap` is false exactly when
        // banding is off (wasm and the WEAVER_PAR2_CREATE_THREADS=1 escape
        // hatch), and the sequential arm performs the identical operation
        // order without rayon, so the produced bytes cannot differ between
        // the arms.
        let batch_starts: Vec<usize> = (0..provider.source_count())
            .step_by(contract.input_grouping)
            .collect();
        let overlap = band_size < self.recovery_exponents.len();

        let mut stripe_offset = 0usize;
        let mut stripe_index = 0usize;
        while stripe_offset < self.slice_size {
            check_cancel(options)?;
            let actual_len = (self.slice_size - stripe_offset).min(buffers.chunk_len);
            let aligned_len = round_up(actual_len, contract.stride)?;
            output.as_bytes_mut()[..buffers.output_bytes].fill(0);
            if let Some(&first_start) = batch_starts.first() {
                fill_staging(
                    kernel,
                    &mut staging[0],
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
                let (left, right) = staging.split_at_mut(1);
                let (current_staging, next_staging) = if batch_index % STAGING_AREA_COUNT == 0 {
                    (&left[0], &mut right[0])
                } else {
                    (&right[0], &mut left[0])
                };
                let output_bytes = &mut output.as_bytes_mut()[..buffers.output_bytes];
                let mut accumulate_result: Result<()> = Ok(());
                let mut fill_result: Result<()> = Ok(());
                if overlap {
                    let accumulate_slot = &mut accumulate_result;
                    #[cfg(target_arch = "x86_64")]
                    let jit_workspaces = &mut jit_workspaces;
                    let exponents = &self.recovery_exponents;
                    let factors = &factors;
                    rayon::in_place_scope(|scope| {
                        scope.spawn(move |_| {
                            *accumulate_slot = accumulate_batch(
                                kernel,
                                output_bytes,
                                current_staging,
                                factors,
                                exponents,
                                source_start,
                                live_inputs,
                                aligned_len,
                                buffers.aligned_chunk_len,
                                contract,
                                band_size,
                                #[cfg(target_arch = "x86_64")]
                                jit_workspaces,
                                jit_code_budget,
                            );
                        });
                        if let Some(next_start) = next_start {
                            fill_result = fill_staging(
                                kernel,
                                next_staging,
                                &mut transfers[(batch_index + 1) % TRANSFER_BUFFER_COUNT],
                                provider,
                                next_start,
                                stripe_offset,
                                actual_len,
                                aligned_len,
                                contract,
                            );
                        }
                    });
                } else {
                    accumulate_result = accumulate_batch(
                        kernel,
                        output_bytes,
                        current_staging,
                        &factors,
                        &self.recovery_exponents,
                        source_start,
                        live_inputs,
                        aligned_len,
                        buffers.aligned_chunk_len,
                        contract,
                        band_size,
                        #[cfg(target_arch = "x86_64")]
                        &mut jit_workspaces,
                        jit_code_budget,
                    );
                    if let Some(next_start) = next_start {
                        fill_result = fill_staging(
                            kernel,
                            next_staging,
                            &mut transfers[(batch_index + 1) % TRANSFER_BUFFER_COUNT],
                            provider,
                            next_start,
                            stripe_offset,
                            actual_len,
                            aligned_len,
                            contract,
                        );
                    }
                }
                accumulate_result?;
                fill_result?;
            }

            finish_output(
                kernel,
                &mut output.as_bytes_mut()[..buffers.output_bytes],
                buffers.aligned_chunk_len,
                aligned_len,
                self.recovery_exponents.len(),
                band_size,
            )?;

            for (output_index, &exponent) in self.recovery_exponents.iter().enumerate() {
                let start = output_index
                    .checked_mul(buffers.aligned_chunk_len)
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResolvedKernel {
    Portable,
    Simd,
    #[cfg(target_arch = "x86_64")]
    Folded,
    #[cfg(target_arch = "x86_64")]
    XorJit(reedsolomon_rs::xor_jit::JitWidth),
}

#[cfg(test)]
fn public_kernel(kernel: ResolvedKernel) -> ForwardKernel {
    match kernel {
        ResolvedKernel::Portable => ForwardKernel::Portable,
        ResolvedKernel::Simd => ForwardKernel::Simd,
        #[cfg(target_arch = "x86_64")]
        ResolvedKernel::Folded => ForwardKernel::Folded,
        #[cfg(target_arch = "x86_64")]
        ResolvedKernel::XorJit(reedsolomon_rs::xor_jit::JitWidth::Avx2) => {
            ForwardKernel::XorJitAvx2
        }
        #[cfg(target_arch = "x86_64")]
        ResolvedKernel::XorJit(reedsolomon_rs::xor_jit::JitWidth::Avx512) => {
            ForwardKernel::XorJitAvx512
        }
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
        ForwardKernel::Auto => {
            #[cfg(target_arch = "x86_64")]
            if let Some(width) = select_jit_width(capabilities) {
                return Ok(ResolvedKernel::XorJit(width));
            }
            #[cfg(target_arch = "x86_64")]
            if capabilities.folded {
                return Ok(ResolvedKernel::Folded);
            }
            Ok(ResolvedKernel::Simd)
        }
        #[cfg(target_arch = "x86_64")]
        ForwardKernel::XorJitAvx2 => {
            if capabilities.avx2_jit {
                Ok(ResolvedKernel::XorJit(
                    reedsolomon_rs::xor_jit::JitWidth::Avx2,
                ))
            } else {
                Err(unavailable_kernel("packed AVX2 XOR-JIT"))
            }
        }
        #[cfg(target_arch = "x86_64")]
        ForwardKernel::XorJitAvx512 => {
            if capabilities.avx512_jit {
                Ok(ResolvedKernel::XorJit(
                    reedsolomon_rs::xor_jit::JitWidth::Avx512,
                ))
            } else {
                Err(unavailable_kernel("packed AVX-512 XOR-JIT"))
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct KernelCapabilities {
    avx512_jit: bool,
    avx2_jit: bool,
    folded: bool,
}

fn runtime_kernel_capabilities() -> KernelCapabilities {
    #[cfg(target_arch = "x86_64")]
    {
        KernelCapabilities {
            avx512_jit: reedsolomon_rs::xor_jit::supported_512(),
            avx2_jit: reedsolomon_rs::xor_jit::JitWidth::detect().is_some(),
            folded: gf_simd::altmap_supported(),
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    KernelCapabilities {
        avx512_jit: false,
        avx2_jit: false,
        folded: false,
    }
}

#[cfg(target_arch = "x86_64")]
fn select_jit_width(capabilities: KernelCapabilities) -> Option<reedsolomon_rs::xor_jit::JitWidth> {
    if capabilities.avx512_jit {
        Some(reedsolomon_rs::xor_jit::JitWidth::Avx512)
    } else if capabilities.avx2_jit {
        Some(reedsolomon_rs::xor_jit::JitWidth::Avx2)
    } else {
        None
    }
}

#[derive(Clone, Copy)]
struct KernelContract {
    stride: usize,
    input_grouping: usize,
}

impl KernelContract {
    fn for_kernel(kernel: ResolvedKernel) -> Self {
        match kernel {
            ResolvedKernel::Portable | ResolvedKernel::Simd => Self {
                stride: 2,
                input_grouping: DEFAULT_INPUT_GROUPING,
            },
            #[cfg(target_arch = "x86_64")]
            ResolvedKernel::Folded => Self {
                stride: gf_simd::SPLIT_BLOCK_BYTES,
                input_grouping: DEFAULT_INPUT_GROUPING,
            },
            #[cfg(target_arch = "x86_64")]
            ResolvedKernel::XorJit(width) => Self {
                stride: width.block_bytes(),
                input_grouping: DEFAULT_INPUT_GROUPING,
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
    let row = checked_mul(
        DEFAULT_INPUT_GROUPING,
        size_of::<u16>(),
        "factor row allocation overflow",
    )?;
    let active = match kernel {
        ResolvedKernel::Portable => row,
        ResolvedKernel::Simd => checked_add(
            row,
            checked_add(
                checked_mul(
                    DEFAULT_INPUT_GROUPING,
                    size_of::<gf_simd::PreparedInputFactor>(),
                    "prepared factor allocation overflow",
                )?,
                checked_mul(
                    DEFAULT_INPUT_GROUPING,
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
            let affine_tables = checked_mul(
                DEFAULT_INPUT_GROUPING,
                size_of::<gf_simd::AffineMulMatrices>(),
                "folded affine table allocation overflow",
            )?;
            let shuffle_tables = checked_mul(
                DEFAULT_INPUT_GROUPING,
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
        ResolvedKernel::XorJit(_) => row,
    };
    // Per-band kernel temporaries (~2 KiB each) are deliberately excluded:
    // this value feeds Par2MemoryPlan.factor_workspace_bytes, which must not
    // scale with recovery-row or band count.
    checked_add(constants, active, "factor workspace allocation overflow")
}

fn jit_workspace_bytes(kernel: ResolvedKernel) -> Result<(usize, usize)> {
    #[cfg(target_arch = "x86_64")]
    if let ResolvedKernel::XorJit(width) = kernel {
        let estimate = reedsolomon_rs::xor_jit::packed::PackedJitBatch::memory_upper_bound(
            width,
            1,
            DEFAULT_INPUT_GROUPING,
        )
        .ok_or_else(|| resource_limit("packed JIT workspace size overflows"))?;
        return Ok((estimate.peak_bytes, estimate.executable_arena_bytes));
    }
    let _ = kernel;
    Ok((0, 0))
}

struct BufferPlan {
    chunk_len: usize,
    aligned_chunk_len: usize,
    staging_bytes: usize,
    output_bytes: usize,
    data_bytes: usize,
    memory_bytes: usize,
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
        let mut chunk_len = if slice_size >= contract.stride {
            slice_size - slice_size % contract.stride
        } else {
            slice_size
        };
        chunk_len = chunk_len.max(2);

        loop {
            let aligned_chunk_len = round_up(chunk_len.min(slice_size), contract.stride)?;
            let staging_bytes = checked_mul(
                contract.input_grouping,
                aligned_chunk_len,
                "staging allocation overflow",
            )?;
            let output_bytes = checked_mul(
                output_count,
                aligned_chunk_len,
                "output allocation overflow",
            )?;
            let aligned_allocation_bytes = checked_mul(
                aligned_chunk_len.div_ceil(64),
                64,
                "aligned buffer allocation overflow",
            )?;
            let data_bytes = checked_add(
                checked_mul(
                    STAGING_AREA_COUNT,
                    checked_mul(
                        contract.input_grouping,
                        aligned_allocation_bytes,
                        "staging allocation overflow",
                    )?,
                    "staging allocation overflow",
                )?,
                checked_add(
                    checked_mul(
                        output_count,
                        aligned_allocation_bytes,
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
            if data_bytes <= stripe_memory_limit {
                return Ok(Self {
                    chunk_len: chunk_len.min(slice_size),
                    aligned_chunk_len,
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
                (stripe_memory_limit / bytes_per_aligned_byte) / contract.stride * contract.stride;
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
    let candidates = match requested {
        ForwardKernel::Auto => auto_kernel_candidates(capabilities),
        requested => vec![resolve_kernel_with_capabilities(requested, capabilities)?],
    };
    let (_, bands) = create_band_shape(output_count);
    let mut last_error = None;
    for kernel in candidates {
        let contract = KernelContract::for_kernel(kernel);
        let factor_bytes = factor_workspace_bytes(kernel, source_count)?;
        let (jit_bytes_per_band, jit_arena_bytes) = jit_workspace_bytes(kernel)?;
        // Each accumulation band owns a JIT workspace, so admission reserves
        // all of them; the build limit stays per-workspace.
        let jit_bytes = checked_mul(
            jit_bytes_per_band,
            bands,
            "banded JIT workspace accounting overflow",
        )?;
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
        for width in [
            reedsolomon_rs::xor_jit::JitWidth::Avx512,
            reedsolomon_rs::xor_jit::JitWidth::Avx2,
        ] {
            let available = match width {
                reedsolomon_rs::xor_jit::JitWidth::Avx512 => capabilities.avx512_jit,
                reedsolomon_rs::xor_jit::JitWidth::Avx2 => capabilities.avx2_jit,
            };
            let candidate = ResolvedKernel::XorJit(width);
            if available && candidate != preferred {
                kernels.push(candidate);
            }
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
    constants: Vec<u16>,
}

impl FactorSource {
    fn new(source_count: usize) -> Self {
        Self {
            constants: gf::input_slice_constants(source_count),
        }
    }

    fn fill_row(
        &self,
        exponent: RecoveryExponent,
        source_start: usize,
        live_inputs: usize,
        row: &mut [u16; DEFAULT_INPUT_GROUPING],
    ) {
        row.fill(0);
        for (lane, factor) in row[..live_inputs].iter_mut().enumerate() {
            *factor = gf::pow(self.constants[source_start + lane], exponent);
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
    let (_, bands) = create_band_shape(output_count);
    let factor_workspace_bytes = factor_workspace_bytes(kernel, source_count)?;
    let (jit_bytes_per_band, _) = jit_workspace_bytes(kernel)?;
    let jit_workspace_bytes = checked_mul(
        jit_bytes_per_band,
        bands,
        "banded JIT workspace accounting overflow",
    )?;
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
                    .checked_mul(aligned_len)
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
                    .and_then(|value| value.checked_mul(aligned_len))
                    .ok_or_else(|| resource_limit("folded staging offset overflow"))?;
                gf_simd::split_encode_scatter(
                    &transfer_bytes[..aligned_len],
                    &mut staging_bytes
                        [group_start..group_start + aligned_len * gf_simd::FOLDED_GROUP],
                    group_lane,
                );
            }
            #[cfg(target_arch = "x86_64")]
            ResolvedKernel::XorJit(width) => {
                let block = width.block_bytes();
                debug_assert_eq!(aligned_len % block, 0);
                let lane_start = lane
                    .checked_mul(aligned_len)
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
    jit_code_budget: usize,
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
            jit_code_budget,
        );
    }

    // Contiguous exponent bands map to contiguous output-major byte ranges,
    // so the chunked splits below hand each task a disjoint destination.
    let band_bytes = checked_mul(band_size, output_stride, "band byte range overflow")?;

    #[cfg(target_arch = "x86_64")]
    {
        output
            .par_chunks_mut(band_bytes)
            .zip(exponents.par_chunks(band_size))
            .zip(jit_workspaces.par_iter_mut())
            .try_for_each(|((band_output, band_exponents), jit_workspace)| {
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
                    jit_workspace,
                    jit_code_budget,
                )
            })
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        output
            .par_chunks_mut(band_bytes)
            .zip(exponents.par_chunks(band_size))
            .try_for_each(|(band_output, band_exponents)| {
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
                    jit_code_budget,
                )
            })
    }
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
    jit_code_budget: usize,
) -> Result<()> {
    let staging_bytes = staging.as_bytes();
    #[cfg(not(target_arch = "x86_64"))]
    let _ = contract;
    #[cfg(not(target_arch = "x86_64"))]
    let _ = jit_code_budget;
    let mut row = [0u16; DEFAULT_INPUT_GROUPING];
    match kernel {
        ResolvedKernel::Portable => {
            for (output_index, &exponent) in exponents.iter().enumerate() {
                factors.fill_row(exponent, source_start, live_inputs, &mut row);
                let dst_start = output_index * output_stride;
                scalar_accumulate(
                    &mut output[dst_start..dst_start + aligned_len],
                    staging_bytes,
                    &row,
                    live_inputs,
                    aligned_len,
                );
            }
        }
        ResolvedKernel::Simd => {
            for (output_index, &exponent) in exponents.iter().enumerate() {
                factors.fill_row(exponent, source_start, live_inputs, &mut row);
                let prepared = row[..live_inputs]
                    .iter()
                    .map(|&factor| gf_simd::prepare_input_factor(factor))
                    .collect::<Vec<_>>();
                let dst_start = output_index * output_stride;
                let mut inputs = Vec::with_capacity(live_inputs);
                for (lane, prepared_factor) in prepared.iter().enumerate() {
                    let source_start_bytes = lane * aligned_len;
                    inputs.push(PreparedFactorSrc {
                        prepared: prepared_factor,
                        src: &staging_bytes[source_start_bytes..source_start_bytes + aligned_len],
                    });
                }
                gf_simd::mul_acc_input_batch_prepared(
                    &mut output[dst_start..dst_start + aligned_len],
                    &inputs,
                );
            }
        }
        #[cfg(target_arch = "x86_64")]
        ResolvedKernel::Folded => {
            let groups = contract.input_grouping / gf_simd::FOLDED_GROUP;
            let staging_views = (0..groups)
                .map(|group| {
                    let start = group * gf_simd::FOLDED_GROUP * aligned_len;
                    &staging_bytes[start..start + gf_simd::FOLDED_GROUP * aligned_len]
                })
                .collect::<Vec<_>>();
            let mut affine = Vec::with_capacity(live_inputs);
            let mut shuffle2x = Vec::with_capacity(live_inputs);
            for (output_index, &exponent) in exponents.iter().enumerate() {
                factors.fill_row(exponent, source_start, live_inputs, &mut row);
                let dst_start = output_index * output_stride;
                if gf_simd::folded_uses_gfni() {
                    affine.clear();
                    affine.extend(
                        row[..live_inputs]
                            .iter()
                            .map(|&factor| gf_simd::precompute_affine_matrices(factor)),
                    );
                    let matrix_sets = (0..groups)
                        .map(|group| {
                            std::array::from_fn(|lane| {
                                let source_index = group * gf_simd::FOLDED_GROUP + lane;
                                affine.get(source_index).unwrap_or(&gf_simd::ZERO_AFFINE)
                            })
                        })
                        .collect::<Vec<_>>();
                    gf_simd::mul_acc_folded_batch(
                        &mut output[dst_start..dst_start + aligned_len],
                        &staging_views,
                        &matrix_sets,
                    );
                } else {
                    shuffle2x.clear();
                    shuffle2x.extend(
                        row[..live_inputs]
                            .iter()
                            .map(|&factor| gf_simd::precompute_shuffle2x_tables(factor)),
                    );
                    let table_sets = (0..groups)
                        .map(|group| {
                            std::array::from_fn(|lane| {
                                let source_index = group * gf_simd::FOLDED_GROUP + lane;
                                shuffle2x
                                    .get(source_index)
                                    .unwrap_or(&gf_simd::ZERO_SHUFFLE2X)
                            })
                        })
                        .collect::<Vec<_>>();
                    gf_simd::mul_acc_shuffle2x_batch(
                        &mut output[dst_start..dst_start + aligned_len],
                        &staging_views,
                        &table_sets,
                    );
                }
            }
        }
        #[cfg(target_arch = "x86_64")]
        ResolvedKernel::XorJit(width) => {
            // Admission covers the persistent arena and stripe buffers before
            // any sink mutation. A later W^X/code-generation or execution
            // error is terminal for this pass; it is not a post-admission
            // tier downgrade.
            for (output_index, &exponent) in exponents.iter().enumerate() {
                factors.fill_row(exponent, source_start, live_inputs, &mut row);
                let row_refs = [&row[..]];
                let batch = jit_workspace
                    .build(width, &row_refs, jit_code_budget.max(1))
                    .map_err(|error| jit_build_error(error.to_string()))?;
                let dst_start = output_index * output_stride;
                let code = batch
                    .row(0)
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
                jit_workspace
                    .recycle(batch)
                    .map_err(|error| jit_build_error(error.to_string()))?;
            }
        }
    }
    Ok(())
}

fn scalar_accumulate(dst: &mut [u8], staging: &[u8], row: &[u16], live_inputs: usize, len: usize) {
    for word in 0..len / 2 {
        let mut value = u16::from_le_bytes([dst[word * 2], dst[word * 2 + 1]]);
        for (lane, &factor) in row.iter().take(live_inputs).enumerate() {
            let source_offset = lane * len + word * 2;
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
    band_size: usize,
) -> Result<()> {
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (
            kernel,
            output,
            output_stride,
            aligned_len,
            output_count,
            band_size,
        );
    }

    #[cfg(target_arch = "x86_64")]
    {
        // Whole-number-of-outputs chunking below relies on an exact slice.
        debug_assert_eq!(output.len(), output_count * output_stride);
        if matches!(kernel, ResolvedKernel::Portable | ResolvedKernel::Simd) {
            return Ok(());
        }
        if band_size >= output_count || output_count <= 1 {
            return finish_band(kernel, output, output_stride, aligned_len, output_count);
        }
        let band_bytes = checked_mul(band_size, output_stride, "band byte range overflow")?;
        return output
            .par_chunks_mut(band_bytes)
            .try_for_each(|band_output| {
                // The output buffer is exactly output_count * output_stride
                // bytes, so every chunk holds a whole number of outputs.
                let band_outputs = band_output.len() / output_stride;
                finish_band(
                    kernel,
                    band_output,
                    output_stride,
                    aligned_len,
                    band_outputs,
                )
            });
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
            ResolvedKernel::XorJit(width) => {
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
            let (_, jit_build_limit) = jit_workspace_bytes(resolved).unwrap();

            let mut passes = Vec::new();
            // band_size = 7 covers the sequential path; 3 exercises uneven
            // banding (bands of 3, 3, 1 outputs).
            for band_size in [7usize, 3] {
                let band_count = exponents.len().div_ceil(band_size);
                let mut provider = InMemorySourceProvider { sources: &refs };
                let mut staging = AlignedBuffer::new(contract.input_grouping * aligned_len);
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
                > = (0..band_count).map(|_| Default::default()).collect();
                #[cfg(not(target_arch = "x86_64"))]
                let _ = band_count;
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
                    jit_build_limit.max(1),
                )
                .unwrap();
                finish_output(
                    resolved,
                    output.as_bytes_mut(),
                    aligned_len,
                    aligned_len,
                    exponents.len(),
                    band_size,
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

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn capability_selection_prefers_avx512_before_avx2() {
        assert_eq!(
            select_jit_width(KernelCapabilities {
                avx512_jit: true,
                avx2_jit: true,
                folded: true,
            }),
            Some(reedsolomon_rs::xor_jit::JitWidth::Avx512)
        );
        assert_eq!(
            select_jit_width(KernelCapabilities {
                avx512_jit: false,
                avx2_jit: true,
                folded: true,
            }),
            Some(reedsolomon_rs::xor_jit::JitWidth::Avx2)
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
        assert_eq!(
            advertised.contains(&ForwardKernel::XorJitAvx2),
            capabilities.avx2_jit
        );
        assert_eq!(
            advertised.contains(&ForwardKernel::XorJitAvx512),
            capabilities.avx512_jit
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
        let all_capabilities = KernelCapabilities {
            avx512_jit: true,
            avx2_jit: true,
            folded: true,
        };
        assert_eq!(
            auto_kernel_candidates(all_capabilities),
            vec![
                ResolvedKernel::XorJit(reedsolomon_rs::xor_jit::JitWidth::Avx512),
                ResolvedKernel::XorJit(reedsolomon_rs::xor_jit::JitWidth::Avx2),
                ResolvedKernel::Folded,
                ResolvedKernel::Simd,
                ResolvedKernel::Portable,
            ]
        );

        let folded_only = KernelCapabilities {
            avx512_jit: false,
            avx2_jit: false,
            folded: true,
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
            avx512_jit: false,
            avx2_jit: false,
            folded: false,
        };
        assert_eq!(
            auto_kernel_candidates(direct_simd_only),
            vec![ResolvedKernel::Simd, ResolvedKernel::Portable]
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn production_admission_can_fall_back_from_supported_avx512_to_avx2() {
        let capabilities = KernelCapabilities {
            avx512_jit: true,
            avx2_jit: true,
            folded: true,
        };
        let raw = resolve_kernel_with_capabilities(ForwardKernel::Auto, capabilities).unwrap();
        assert_eq!(
            raw,
            ResolvedKernel::XorJit(reedsolomon_rs::xor_jit::JitWidth::Avx512)
        );

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
        let avx512_minimum = minimum_memory_limit(ForwardKernel::XorJitAvx512);
        let avx2_minimum = minimum_memory_limit(ForwardKernel::XorJitAvx2);
        assert!(
            avx512_minimum > avx2_minimum,
            "AVX-512 minimum {avx512_minimum} is not above AVX2 minimum {avx2_minimum}"
        );
        let memory_limit = avx2_minimum;
        assert!(
            select_kernel_for_memory_with_capabilities(
                slice_size,
                output_count,
                source_count,
                memory_limit,
                ForwardKernel::XorJitAvx512,
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
        assert_eq!(
            admitted,
            ResolvedKernel::XorJit(reedsolomon_rs::xor_jit::JitWidth::Avx2)
        );
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
        assert_eq!(sink.chunks.last().unwrap().2, 256);
        assert_eq!(sink.chunks.last().unwrap().3.len(), 4);
        assert_eq!(sink.chunks.len(), 4);
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
