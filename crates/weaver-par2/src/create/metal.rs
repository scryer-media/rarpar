use crate::error::{Par2Error, Result};
#[cfg(all(feature = "metal", target_os = "macos", target_arch = "aarch64"))]
use crate::gf;
#[cfg(all(feature = "metal", target_os = "macos", target_arch = "aarch64"))]
use crate::types::{
    CancellationToken, MAX_TOTAL_INPUT_SLICES, ProgressCallback, ProgressPhase, ProgressStage,
    ProgressUpdate, RecoveryExponent,
};

use super::encode::ForwardMemoryEstimate;
#[cfg(all(feature = "metal", target_os = "macos", target_arch = "aarch64"))]
use super::encode::{ForwardRecoverySink, ForwardSourceProvider};
use super::options::CreationBackend;
#[cfg(all(feature = "metal", target_os = "macos", target_arch = "aarch64"))]
use super::plan::default_memory_limit;

#[cfg(all(feature = "metal", target_os = "macos", target_arch = "aarch64"))]
use reedsolomon_rs::metal_gf16::{
    MAX_SOURCES as METAL_MAX_SOURCES, MetalGf16PlanError, MetalGf16Session, metal_gf16_memory_plan,
};

#[cfg(all(feature = "metal", target_os = "macos", target_arch = "aarch64"))]
const MAX_OUTPUT_TILE: usize = 16;

pub(crate) enum SelectedBackend {
    Cpu,
    #[cfg(all(feature = "metal", target_os = "macos", target_arch = "aarch64"))]
    Metal(Box<MetalCreationState>),
}

pub(crate) fn selected_policy(selected: &SelectedBackend) -> CreationBackend {
    match selected {
        SelectedBackend::Cpu => CreationBackend::Cpu,
        #[cfg(all(feature = "metal", target_os = "macos", target_arch = "aarch64"))]
        SelectedBackend::Metal(_) => CreationBackend::Metal,
    }
}

/// Auto reserves Metal admission for at least 16 GiB of
/// `slice_size * source_count * output_count` work so smaller products avoid
/// the fixed setup cost of the native Metal path.
pub(crate) const METAL_AUTO_MIN_WORK_BYTES: u128 = 16 * 1024 * 1024 * 1024;

/// Return whether the saturating creation-work product reaches the Auto threshold.
pub(crate) fn auto_metal_work_admitted(
    slice_size: usize,
    source_count: usize,
    output_count: usize,
) -> bool {
    (slice_size as u128)
        .saturating_mul(source_count as u128)
        .saturating_mul(output_count as u128)
        >= METAL_AUTO_MIN_WORK_BYTES
}

pub(crate) fn estimate_processing_memory(
    requested: CreationBackend,
    slice_size: usize,
    source_count: usize,
    output_count: usize,
    memory_limit: usize,
    cpu_memory: ForwardMemoryEstimate,
) -> Result<ForwardMemoryEstimate> {
    match requested {
        CreationBackend::Cpu => Ok(cpu_memory),
        CreationBackend::Auto => {
            if !auto_metal_work_admitted(slice_size, source_count, output_count) {
                return Ok(cpu_memory);
            }
            #[cfg(all(feature = "metal", target_os = "macos", target_arch = "aarch64"))]
            {
                Ok(
                    estimate_metal_memory(slice_size, source_count, output_count, memory_limit)
                        .map_or(cpu_memory, |metal| max_processing_memory(cpu_memory, metal)),
                )
            }
            #[cfg(not(all(feature = "metal", target_os = "macos", target_arch = "aarch64")))]
            {
                let _ = (slice_size, source_count, output_count, memory_limit);
                Ok(cpu_memory)
            }
        }
        CreationBackend::Metal => {
            #[cfg(all(feature = "metal", target_os = "macos", target_arch = "aarch64"))]
            {
                estimate_metal_memory(slice_size, source_count, output_count, memory_limit)
                    .map_err(|reason| Par2Error::MetalUnavailable { reason })
            }
            #[cfg(not(all(feature = "metal", target_os = "macos", target_arch = "aarch64")))]
            {
                let _ = (slice_size, source_count, output_count, memory_limit);
                Ok(cpu_memory)
            }
        }
    }
}

pub(crate) fn select_backend(
    requested: CreationBackend,
    slice_size: usize,
    source_count: usize,
    output_count: usize,
    memory_limit: Option<usize>,
) -> Result<SelectedBackend> {
    if output_count == 0 {
        return Ok(SelectedBackend::Cpu);
    }

    match requested {
        CreationBackend::Cpu => Ok(SelectedBackend::Cpu),
        CreationBackend::Auto => {
            if !auto_metal_work_admitted(slice_size, source_count, output_count) {
                return Ok(SelectedBackend::Cpu);
            }
            #[cfg(all(feature = "metal", target_os = "macos", target_arch = "aarch64"))]
            {
                match MetalCreationState::prepare(
                    slice_size,
                    source_count,
                    output_count,
                    memory_limit,
                ) {
                    Ok(state) => Ok(SelectedBackend::Metal(Box::new(state))),
                    Err(_) => Ok(SelectedBackend::Cpu),
                }
            }
            #[cfg(not(all(feature = "metal", target_os = "macos", target_arch = "aarch64")))]
            {
                let _ = (slice_size, source_count, memory_limit);
                Ok(SelectedBackend::Cpu)
            }
        }
        CreationBackend::Metal => {
            #[cfg(all(feature = "metal", target_os = "macos", target_arch = "aarch64"))]
            {
                MetalCreationState::prepare(slice_size, source_count, output_count, memory_limit)
                    .map(|state| SelectedBackend::Metal(Box::new(state)))
                    .map_err(|reason| Par2Error::MetalUnavailable { reason })
            }
            #[cfg(not(all(feature = "metal", target_os = "macos", target_arch = "aarch64")))]
            {
                let _ = (slice_size, source_count, memory_limit);
                Err(Par2Error::MetalUnavailable {
                    reason: "this target was built without a native Metal creation backend"
                        .to_string(),
                })
            }
        }
    }
}

#[cfg(all(feature = "metal", target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct MetalCreationState {
    session: MetalGf16Session,
    constants: Vec<u16>,
    source_buffer: Vec<u8>,
    output_buffer: Vec<u8>,
    source_capacity: usize,
    output_tile_capacity: usize,
    dispatch_chunk_len: usize,
}

#[cfg(all(feature = "metal", target_os = "macos", target_arch = "aarch64"))]
impl MetalCreationState {
    fn prepare(
        slice_size: usize,
        source_count: usize,
        output_count: usize,
        memory_limit: Option<usize>,
    ) -> std::result::Result<Self, String> {
        let memory_limit = memory_limit.unwrap_or_else(default_memory_limit);
        let shape = choose_shape(slice_size, source_count, output_count, memory_limit)?;
        let session = MetalGf16Session::try_new_explicit(
            shape.output_tile_capacity,
            shape.source_capacity,
            shape.dispatch_chunk_len,
        )
        .map_err(|error| format!("Metal session admission failed: {error:?}"))?;

        let source_buffer = allocate_bytes(shape.source_bytes, "Metal source host buffer")?;
        let output_buffer = allocate_bytes(shape.output_bytes, "Metal output host buffer")?;
        let constants = gf::input_slice_constants(source_count);

        Ok(Self {
            session,
            constants,
            source_buffer,
            output_buffer,
            source_capacity: shape.source_capacity,
            output_tile_capacity: shape.output_tile_capacity,
            dispatch_chunk_len: shape.dispatch_chunk_len,
        })
    }

    pub(crate) fn encode<P: ForwardSourceProvider + ?Sized, S: ForwardRecoverySink>(
        &mut self,
        provider: &mut P,
        exponents: &[RecoveryExponent],
        slice_size: usize,
        cancellation: &CancellationToken,
        progress: Option<ProgressCallback>,
        sink: &mut S,
    ) -> Result<()> {
        validate_provider(provider, slice_size)?;
        if slice_size != self.dispatch_chunk_len && slice_size < self.dispatch_chunk_len {
            return Err(Par2Error::MetalExecutionFailed {
                reason: "Metal stripe shape exceeds the configured slice".to_string(),
            });
        }
        let stripe_count = slice_size.div_ceil(self.dispatch_chunk_len);
        let stripe_count =
            u32::try_from(stripe_count).map_err(|_| Par2Error::ResourceLimitExceeded {
                reason: "Metal stripe count exceeds progress range".to_string(),
            })?;
        let total_bytes = (exponents.len() as u64)
            .checked_mul(slice_size as u64)
            .ok_or_else(|| Par2Error::ResourceLimitExceeded {
                reason: "Metal progress byte count overflows".to_string(),
            })?;
        let mut stripe_offset = 0usize;
        let mut stripe_index = 0usize;

        while stripe_offset < slice_size {
            check_cancel(cancellation)?;
            let live_len = (slice_size - stripe_offset).min(self.dispatch_chunk_len);
            let dispatch_len = round_up_even(live_len)?;
            if dispatch_len > self.dispatch_chunk_len {
                return Err(Par2Error::MetalExecutionFailed {
                    reason: "Metal dispatch padding exceeds its admitted region".to_string(),
                });
            }
            for tile_start in (0..exponents.len()).step_by(self.output_tile_capacity) {
                check_cancel(cancellation)?;
                let tile_end = (tile_start + self.output_tile_capacity).min(exponents.len());
                let tile_len = tile_end - tile_start;
                self.session
                    .begin_chunk(dispatch_len)
                    .map_err(metal_runtime_error)?;

                for source_start in (0..provider.source_count()).step_by(self.source_capacity) {
                    check_cancel(cancellation)?;
                    let live_inputs = provider
                        .source_count()
                        .saturating_sub(source_start)
                        .min(self.source_capacity);
                    for lane in 0..live_inputs {
                        let start = lane.checked_mul(self.dispatch_chunk_len).ok_or_else(|| {
                            Par2Error::ResourceLimitExceeded {
                                reason: "Metal source buffer offset overflows".to_string(),
                            }
                        })?;
                        let end = start.checked_add(dispatch_len).ok_or_else(|| {
                            Par2Error::ResourceLimitExceeded {
                                reason: "Metal source buffer range overflows".to_string(),
                            }
                        })?;
                        let source = &mut self.source_buffer[start..end];
                        source.fill(0);
                        provider.read_source_chunk(
                            source_start + lane,
                            stripe_offset,
                            &mut source[..live_len],
                        )?;
                    }
                    let mut source_refs = [&[][..]; METAL_MAX_SOURCES];
                    for (lane, source_ref) in source_refs.iter_mut().enumerate().take(live_inputs) {
                        let start = lane.checked_mul(self.dispatch_chunk_len).ok_or_else(|| {
                            Par2Error::ResourceLimitExceeded {
                                reason: "Metal source buffer offset overflows".to_string(),
                            }
                        })?;
                        let end = start.checked_add(dispatch_len).ok_or_else(|| {
                            Par2Error::ResourceLimitExceeded {
                                reason: "Metal source buffer range overflows".to_string(),
                            }
                        })?;
                        *source_ref = &self.source_buffer[start..end];
                    }
                    let constants = &self.constants;
                    let tile_exponents = &exponents[tile_start..tile_end];
                    self.session
                        .accumulate(&source_refs[..live_inputs], |output, source| {
                            if output < tile_len {
                                gf::pow(constants[source_start + source], tile_exponents[output])
                            } else {
                                0
                            }
                        })
                        .map_err(metal_runtime_error)?;
                }

                check_cancel(cancellation)?;
                self.session
                    .finish_chunk_into(&mut self.output_buffer, self.dispatch_chunk_len, live_len)
                    .map_err(metal_runtime_error)?;
                for output in 0..tile_len {
                    let offset = output.checked_mul(self.dispatch_chunk_len).ok_or_else(|| {
                        Par2Error::ResourceLimitExceeded {
                            reason: "Metal output offset overflows".to_string(),
                        }
                    })?;
                    sink.write_recovery_chunk(
                        tile_start + output,
                        exponents[tile_start + output],
                        stripe_offset as u64,
                        &self.output_buffer[offset..offset + live_len],
                    )?;
                }
            }

            stripe_index += 1;
            let current =
                u32::try_from(stripe_index - 1).map_err(|_| Par2Error::ResourceLimitExceeded {
                    reason: "Metal progress stripe index overflows".to_string(),
                })?;
            if let Some(progress) = &progress {
                progress(ProgressUpdate {
                    stage: ProgressStage::Creating,
                    current,
                    total: stripe_count,
                    bytes_processed: (stripe_index as u64)
                        .saturating_mul(exponents.len() as u64)
                        .saturating_mul(self.dispatch_chunk_len as u64)
                        .min(total_bytes),
                    total_bytes: Some(total_bytes),
                    phase: ProgressPhase::RecoveryEncode,
                });
            }
            stripe_offset = stripe_offset.checked_add(live_len).ok_or_else(|| {
                Par2Error::ResourceLimitExceeded {
                    reason: "Metal stripe offset overflows".to_string(),
                }
            })?;
        }

        check_cancel(cancellation)
    }
}

#[cfg(all(feature = "metal", target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MetalShape {
    output_tile_capacity: usize,
    source_capacity: usize,
    dispatch_chunk_len: usize,
    source_bytes: usize,
    output_bytes: usize,
    factor_workspace_bytes: usize,
    stripe_buffer_bytes: usize,
    combined_bytes: usize,
}

#[cfg(all(feature = "metal", target_os = "macos", target_arch = "aarch64"))]
fn estimate_metal_memory(
    slice_size: usize,
    source_count: usize,
    output_count: usize,
    memory_limit: usize,
) -> std::result::Result<ForwardMemoryEstimate, String> {
    if output_count == 0 {
        return Ok(ForwardMemoryEstimate {
            factor_workspace_bytes: 0,
            stripe_buffer_bytes: 0,
            processing_peak_bytes: 0,
        });
    }
    let shape = choose_shape(slice_size, source_count, output_count, memory_limit)?;
    Ok(ForwardMemoryEstimate {
        factor_workspace_bytes: shape.factor_workspace_bytes,
        stripe_buffer_bytes: shape.stripe_buffer_bytes,
        processing_peak_bytes: shape.combined_bytes,
    })
}

#[cfg(all(feature = "metal", target_os = "macos", target_arch = "aarch64"))]
fn max_processing_memory(
    cpu_memory: ForwardMemoryEstimate,
    metal_memory: ForwardMemoryEstimate,
) -> ForwardMemoryEstimate {
    if metal_memory.processing_peak_bytes > cpu_memory.processing_peak_bytes {
        metal_memory
    } else {
        cpu_memory
    }
}

#[cfg(all(feature = "metal", target_os = "macos", target_arch = "aarch64"))]
fn choose_shape(
    slice_size: usize,
    source_count: usize,
    output_count: usize,
    memory_limit: usize,
) -> std::result::Result<MetalShape, String> {
    if slice_size == 0 || !slice_size.is_multiple_of(2) {
        return Err("the Metal creation slice shape is invalid".to_string());
    }
    if source_count == 0 || output_count == 0 {
        return Err("the Metal creation workload is empty".to_string());
    }
    if source_count > MAX_TOTAL_INPUT_SLICES {
        return Err(format!(
            "input slice count {source_count} exceeds {MAX_TOTAL_INPUT_SLICES}"
        ));
    }
    let source_capacity = source_count.min(METAL_MAX_SOURCES);
    let mut tile = output_count.min(MAX_OUTPUT_TILE);
    while tile > 0 {
        let mut low_words = 1usize;
        let mut high_words = slice_size / 2;
        let mut best = None;
        while low_words <= high_words {
            let words = low_words + (high_words - low_words) / 2;
            let dispatch = words
                .checked_mul(2)
                .ok_or_else(|| "Metal dispatch length overflows".to_string())?;
            match checked_shape(tile, source_count, source_capacity, dispatch, memory_limit)? {
                Some(shape) => {
                    best = Some(shape);
                    low_words = words + 1;
                }
                None => {
                    high_words = words - 1;
                }
            }
        }
        if let Some(shape) = best {
            return Ok(shape);
        }
        if tile == 1 {
            break;
        }
        tile = tile.div_ceil(2);
    }
    Err(format!(
        "Metal processing buffers exceed the configured memory limit of {memory_limit} bytes"
    ))
}

#[cfg(all(feature = "metal", target_os = "macos", target_arch = "aarch64"))]
fn checked_shape(
    output_tile_capacity: usize,
    source_count: usize,
    source_capacity: usize,
    dispatch_chunk_len: usize,
    memory_limit: usize,
) -> std::result::Result<Option<MetalShape>, String> {
    let device_plan =
        match metal_gf16_memory_plan(output_tile_capacity, source_capacity, dispatch_chunk_len) {
            Ok(plan) => plan,
            Err(MetalGf16PlanError::ShaderIndexLimit | MetalGf16PlanError::ArithmeticOverflow) => {
                return Ok(None);
            }
            Err(error) => return Err(format!("Metal shape admission failed: {error:?}")),
        };
    let Some(source_bytes) = source_capacity.checked_mul(dispatch_chunk_len) else {
        return Ok(None);
    };
    let Some(output_bytes) = output_tile_capacity.checked_mul(dispatch_chunk_len) else {
        return Ok(None);
    };
    let Some(source_constants_bytes) = source_count.checked_mul(std::mem::size_of::<u16>()) else {
        return Ok(None);
    };
    let Some(factor_workspace_bytes) = source_constants_bytes
        .checked_add(device_plan.factor_slots_bytes)
        .and_then(|total| total.checked_add(device_plan.table_bytes))
        .and_then(|total| total.checked_add(device_plan.table_tracking_bytes))
    else {
        return Ok(None);
    };
    let Some(stripe_buffer_bytes) = device_plan
        .source_slots_bytes
        .checked_add(device_plan.destination_bytes)
        .and_then(|total| total.checked_add(source_bytes))
        .and_then(|total| total.checked_add(output_bytes))
    else {
        return Ok(None);
    };
    let Some(combined_bytes) = factor_workspace_bytes.checked_add(stripe_buffer_bytes) else {
        return Ok(None);
    };
    let Some(expected_combined_bytes) = device_plan
        .total_bytes
        .checked_add(source_bytes)
        .and_then(|total| total.checked_add(output_bytes))
        .and_then(|total| total.checked_add(source_constants_bytes))
    else {
        return Ok(None);
    };
    if combined_bytes != expected_combined_bytes {
        return Err("Metal processing memory accounting mismatch".to_string());
    }
    if combined_bytes > memory_limit {
        return Ok(None);
    }
    Ok(Some(MetalShape {
        output_tile_capacity,
        source_capacity,
        dispatch_chunk_len,
        source_bytes,
        output_bytes,
        factor_workspace_bytes,
        stripe_buffer_bytes,
        combined_bytes,
    }))
}

#[cfg(all(feature = "metal", target_os = "macos", target_arch = "aarch64"))]
fn allocate_bytes(length: usize, label: &str) -> std::result::Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| format!("{label} allocation failed for {length} bytes"))?;
    bytes.resize(length, 0);
    Ok(bytes)
}

#[cfg(all(feature = "metal", target_os = "macos", target_arch = "aarch64"))]
fn validate_provider<P: ForwardSourceProvider + ?Sized>(
    provider: &P,
    slice_size: usize,
) -> Result<()> {
    let source_count = provider.source_count();
    if source_count > MAX_TOTAL_INPUT_SLICES {
        return Err(Par2Error::ResourceLimitExceeded {
            reason: format!("input slice count {source_count} exceeds {MAX_TOTAL_INPUT_SLICES}"),
        });
    }
    for source in 0..source_count {
        if provider.source_slice_len(source)? > slice_size {
            return Err(Par2Error::InvalidCreationOptions {
                reason: "an input slice is longer than the configured slice size".to_string(),
            });
        }
    }
    Ok(())
}

#[cfg(all(feature = "metal", target_os = "macos", target_arch = "aarch64"))]
fn check_cancel(cancellation: &CancellationToken) -> Result<()> {
    if cancellation.is_cancelled() {
        Err(Par2Error::Cancelled)
    } else {
        Ok(())
    }
}

#[cfg(all(feature = "metal", target_os = "macos", target_arch = "aarch64"))]
fn round_up_even(length: usize) -> Result<usize> {
    if length.is_multiple_of(2) {
        Ok(length)
    } else {
        length
            .checked_add(1)
            .ok_or_else(|| Par2Error::ResourceLimitExceeded {
                reason: "Metal dispatch length overflows".to_string(),
            })
    }
}

#[cfg(all(feature = "metal", target_os = "macos", target_arch = "aarch64"))]
fn metal_runtime_error(reason: &'static str) -> Par2Error {
    Par2Error::MetalExecutionFailed {
        reason: reason.to_string(),
    }
}

#[cfg(test)]
mod auto_tests {
    use super::*;

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn creation_work_boundary_is_admitted() {
        let slice_size = 256 * 1024;
        let source_count = 1024;
        let output_count = 64;
        assert!(auto_metal_work_admitted(
            slice_size,
            source_count,
            output_count
        ));
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn creation_work_below_boundary_is_not_admitted() {
        assert!(!auto_metal_work_admitted(256 * 1024, 1024, 63));
        assert!(!auto_metal_work_admitted(0, usize::MAX, usize::MAX));
    }

    #[test]
    fn creation_work_that_overflows_usize_is_admitted() {
        assert!(auto_metal_work_admitted(usize::MAX, 5, 1));
    }

    #[test]
    fn auto_selection_stays_cpu_below_work_boundary_without_hardware() {
        let selected = select_backend(CreationBackend::Auto, 1, 1, 1, None).unwrap();
        assert!(matches!(selected, SelectedBackend::Cpu));
    }

    #[test]
    fn auto_planning_uses_cpu_memory_below_work_boundary() {
        let cpu_memory = ForwardMemoryEstimate {
            factor_workspace_bytes: 11,
            stripe_buffer_bytes: 33,
            processing_peak_bytes: 44,
        };
        let planned =
            estimate_processing_memory(CreationBackend::Auto, 1, 1, 1, usize::MAX, cpu_memory)
                .unwrap();
        assert_eq!(planned, cpu_memory);
    }
}

#[cfg(all(test, feature = "metal", target_os = "macos", target_arch = "aarch64"))]
mod tests {
    use super::*;

    #[test]
    fn shape_admission_rejects_a_limit_below_resident_tables() {
        let error = choose_shape(4_096, 67, 17, 1024 * 1024).unwrap_err();
        assert!(error.contains("memory limit"));
    }

    #[test]
    fn shape_admission_bounds_tiles_and_dispatch_regions() {
        let shape = choose_shape(5_000, 67, 37, 16 * 1024 * 1024).unwrap();
        assert!(shape.output_tile_capacity <= MAX_OUTPUT_TILE);
        assert!(shape.dispatch_chunk_len <= 5_000);
        assert!(shape.dispatch_chunk_len.is_multiple_of(2));
    }

    #[test]
    fn shape_admission_bisects_to_the_largest_fitting_even_dispatch() {
        let slice_size = 5_000;
        let memory_limit = 8 * 1024 * 1024 + 512 * 1024;
        let shape = choose_shape(slice_size, 67, 17, memory_limit).unwrap();
        assert_eq!(shape.output_tile_capacity, MAX_OUTPUT_TILE);
        assert!(
            checked_shape(
                shape.output_tile_capacity,
                67,
                shape.source_capacity,
                shape.dispatch_chunk_len,
                memory_limit,
            )
            .unwrap()
            .is_some()
        );
        let next_dispatch = shape.dispatch_chunk_len + 2;
        assert!(next_dispatch <= slice_size);
        assert!(
            checked_shape(
                shape.output_tile_capacity,
                67,
                shape.source_capacity,
                next_dispatch,
                memory_limit,
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn tight_memory_shape_has_multiple_stripes_and_a_short_final_stripe() {
        let slice_size = 5_000;
        let shape = choose_shape(slice_size, 67, 17, 8 * 1024 * 1024 + 512 * 1024).unwrap();
        let stripe_count = slice_size.div_ceil(shape.dispatch_chunk_len);
        let final_stripe_len = slice_size % shape.dispatch_chunk_len;
        assert!(stripe_count > 1);
        assert!(final_stripe_len > 0);
        assert!(final_stripe_len < shape.dispatch_chunk_len);
    }

    #[test]
    fn memory_estimate_matches_the_admitted_combined_shape() {
        let shape = choose_shape(5_000, 67, 37, 16 * 1024 * 1024).unwrap();
        let estimate = estimate_metal_memory(5_000, 67, 37, 16 * 1024 * 1024).unwrap();
        let device_plan = metal_gf16_memory_plan(
            shape.output_tile_capacity,
            shape.source_capacity,
            shape.dispatch_chunk_len,
        )
        .unwrap();
        assert_eq!(estimate.processing_peak_bytes, shape.combined_bytes);
        assert_eq!(
            estimate.factor_workspace_bytes + estimate.stripe_buffer_bytes,
            estimate.processing_peak_bytes
        );
        assert_eq!(
            estimate.factor_workspace_bytes,
            67 * std::mem::size_of::<u16>()
                + device_plan.factor_slots_bytes
                + device_plan.table_bytes
                + device_plan.table_tracking_bytes
        );
        assert_eq!(
            estimate.stripe_buffer_bytes,
            device_plan.source_slots_bytes
                + device_plan.destination_bytes
                + shape.source_bytes
                + shape.output_bytes
        );
        assert_eq!(
            shape.source_bytes,
            shape.source_capacity * shape.dispatch_chunk_len
        );
        assert_eq!(
            shape.output_bytes,
            shape.output_tile_capacity * shape.dispatch_chunk_len
        );
    }
}
