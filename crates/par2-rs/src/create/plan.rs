use std::fs;
use std::mem::size_of;
use std::path::{Path, PathBuf};

use crate::checksum::md5;
use crate::error::{Par2Error, Result};
use crate::types::{FileId, RecoveryExponent, RecoverySetId, SliceChecksum};

use super::encode::{ForwardKernel, estimate_forward_memory};
use super::metal::estimate_processing_memory;
use super::options::{BlockSizing, CreationBackend, Par2CreatorOptions, RecoveryAmount};
use super::output::{
    TargetSnapshot, capture_target_snapshot, estimate_critical_packet_bytes,
    estimate_packet_build_workspace_bytes, estimate_transaction_workspace_bytes,
    estimate_validation_workspace_bytes,
};
use super::source::{CreationSource, InputLength, collect_input_lengths, collect_sources};
use super::volume::{RecoveryVolumePlan, allocate_volumes};

const AUTO_SOURCE_SLICE_TARGET: u64 = 2_000;
const MAX_RECOVERY_EXPONENT: u32 = 65_535;
const MEMORY_FLOOR_BYTES: usize = 256 * 1024 * 1024;
const MEMORY_32_BIT_CAP_BYTES: usize = 1024 * 1024 * 1024;
pub(crate) fn default_memory_limit() -> usize {
    memory_limit_for(physical_memory_bytes(), usize::BITS)
}

fn memory_limit_for(physical_memory: Option<u64>, address_bits: u32) -> usize {
    let mut limit = physical_memory
        .and_then(|bytes| usize::try_from(bytes / 8).ok())
        .unwrap_or(MEMORY_FLOOR_BYTES)
        .max(MEMORY_FLOOR_BYTES);
    if address_bits < 64 {
        limit = limit.min(MEMORY_32_BIT_CAP_BYTES);
    }
    limit
}

pub(crate) fn controller_overhead_blocks(source_blocks: u32) -> usize {
    2 + 24usize.min(source_blocks as usize + 1)
}

#[cfg(unix)]
fn physical_memory_bytes() -> Option<u64> {
    let pages = unsafe { libc::sysconf(libc::_SC_PHYS_PAGES) };
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if pages <= 0 || page_size <= 0 {
        return None;
    }
    (pages as u64).checked_mul(page_size as u64)
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct WindowsMemoryStatusEx {
    length: u32,
    memory_load: u32,
    total_phys: u64,
    available_phys: u64,
    total_page_file: u64,
    available_page_file: u64,
    total_virtual: u64,
    available_virtual: u64,
    available_extended_virtual: u64,
}

#[cfg(target_os = "windows")]
unsafe extern "system" {
    fn GlobalMemoryStatusEx(status: *mut WindowsMemoryStatusEx) -> i32;
}

#[cfg(target_os = "windows")]
fn physical_memory_bytes() -> Option<u64> {
    let mut status = WindowsMemoryStatusEx {
        length: std::mem::size_of::<WindowsMemoryStatusEx>() as u32,
        memory_load: 0,
        total_phys: 0,
        available_phys: 0,
        total_page_file: 0,
        available_page_file: 0,
        total_virtual: 0,
        available_virtual: 0,
        available_extended_virtual: 0,
    };
    // SAFETY: the Windows API writes exactly the documented structure into a
    // valid, size-initialized mutable buffer, and does not retain the pointer.
    let success = unsafe { GlobalMemoryStatusEx(&mut status) } != 0;
    success.then_some(status.total_phys)
}

#[cfg(not(any(unix, target_os = "windows")))]
fn physical_memory_bytes() -> Option<u64> {
    None
}

/// The memory quantities used by one creation pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Par2MemoryPlan {
    /// Retained source descriptions, hashes, names, and per-slice checksums.
    /// This does not include source file contents.
    pub source_metadata_bytes: usize,
    /// Temporary hashing buffers and source-index collections.
    pub source_hash_workspace_bytes: usize,
    /// Critical packet bytes retained while staged outputs are assembled.
    pub critical_packet_bytes: usize,
    /// Temporary Main packet file-ID body retained while critical packets are built.
    pub main_file_id_workspace_bytes: usize,
    /// Largest temporary padded FileDesc or IFSC body, including its Vec controller.
    /// Main packet body workspace is accounted separately above.
    pub packet_build_workspace_bytes: usize,
    /// Transaction and provider bookkeeping retained beside critical packets.
    pub transaction_workspace_bytes: usize,
    /// Scanner, parsed-packet, and file-backed recovery-hash workspace used
    /// while one staged volume is validated.
    pub validation_workspace_bytes: usize,
    /// Processing-buffer budget passed to the forward encoder.
    pub processing_buffer_limit_bytes: usize,
    /// Conservative peak working-set bound for the forward processing buffers.
    pub processing_peak_bytes: usize,
    /// Conservative peak bound for the complete creation operation.
    pub total_creation_peak_bytes: usize,
    /// Source constants and one active kernel's factor preparation storage.
    /// Each accumulation band holds its own ~2 KiB of transient kernel
    /// temporaries; those are deliberately excluded so this value never
    /// scales with recovery-row or thread count.
    pub factor_workspace_bytes: usize,
    /// Peak executable-code and JIT build bookkeeping storage.
    pub jit_workspace_bytes: usize,
    /// Stripe staging, transfer, and recovery-output buffers.
    pub stripe_buffer_bytes: usize,
    /// Controller buffer units used by the creation memory calculation.
    pub controller_overhead_blocks: usize,
}

/// Fully validated creation inputs and deterministic output allocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Par2CreatePlan {
    /// Canonical base directory used for source resolution and packet names.
    pub base_path: PathBuf,
    /// Canonical output stem without the final par2 suffix.
    pub output_stem: PathBuf,
    /// Main critical-packet output path.
    pub main_path: PathBuf,
    /// Recovery volume allocations, in increasing exponent order.
    pub volumes: Vec<RecoveryVolumePlan>,
    /// Recovery volume sizing policy used for the allocation.
    pub volume_scheme: super::options::VolumeScheme,
    /// Recovery volume paths, matching the volume allocations.
    pub volume_paths: Vec<PathBuf>,
    /// All output paths, with the main file first.
    pub output_paths: Vec<PathBuf>,
    /// Target states authorized by the validated planning pass.
    pub(crate) target_snapshots: Vec<TargetSnapshot>,
    /// Sources sorted by PAR2 file identifier, which is also encoder input order.
    pub sources: Vec<CreationSource>,
    /// Source slice size in bytes.
    pub slice_size: u64,
    /// Total number of source slices across all files.
    pub source_slice_count: u32,
    /// Number of recovery slices.
    pub recovery_count: u32,
    /// Exponent assigned to the first recovery slice.
    pub first_exponent: RecoveryExponent,
    /// Recovery exponents in output order.
    pub recovery_exponents: Vec<RecoveryExponent>,
    /// Recovery-set identifier from the Main packet body.
    pub recovery_set_id: RecoverySetId,
    /// Forward arithmetic path selected when this plan was built.
    pub forward_kernel: ForwardKernel,
    /// Creation backend policy requested for this plan.
    pub backend: CreationBackend,
    /// Memory accounting for this plan.
    pub memory: Par2MemoryPlan,
    /// Whether the caller requested a write-free operation.
    pub dry_run: bool,
    /// Inputs excluded from the set because they are zero-length, in input
    /// order, as the caller spelled them.
    ///
    /// A PAR2 set cannot describe an empty file (the format protects slices
    /// and an empty file has none), so these inputs are not in `sources`, get
    /// no packets, and are invisible to verify and repair. The reference
    /// encoder makes the same exclusion and reports it unconditionally
    /// ("Skipping 0 byte file"); callers that surface plans to a human should
    /// do the same with this list, because a set that silently protects fewer
    /// files than were listed reads as protection it does not provide.
    pub skipped_empty: Vec<PathBuf>,
}

impl Par2CreatePlan {
    /// Return the number of critical source files in the set.
    pub fn file_count(&self) -> usize {
        self.sources.len()
    }

    /// Return the number of recovery volume files.
    pub fn volume_count(&self) -> usize {
        self.volumes.len()
    }

    pub(crate) fn validate_integrity(&self) -> Result<()> {
        if self.sources.is_empty()
            || self.output_paths.len() != self.volume_paths.len() + 1
            || self.output_paths.first() != Some(&self.main_path)
            || self.volumes.len() != self.volume_paths.len()
            || self.target_snapshots.len() != self.output_paths.len()
            || self.recovery_exponents.len() != self.recovery_count as usize
        {
            return Err(Par2Error::InvalidCreationOptions {
                reason: "creation plan structure is inconsistent".to_string(),
            });
        }
        if self.slice_size == 0 || !self.slice_size.is_multiple_of(4) {
            return Err(Par2Error::InvalidCreationOptions {
                reason: "creation plan has an invalid slice size".to_string(),
            });
        }
        if self.first_exponent > 32_768 {
            return Err(Par2Error::InvalidCreationOptions {
                reason: "creation plan first exponent is out of range".to_string(),
            });
        }
        let expected_end = self
            .first_exponent
            .checked_add(self.recovery_count)
            .filter(|end| *end < 65_536)
            .ok_or_else(|| Par2Error::InvalidCreationOptions {
                reason: "creation plan recovery exponent range is out of range".to_string(),
            })?;
        if self
            .sources
            .windows(2)
            .any(|pair| pair[0].file_id >= pair[1].file_id)
        {
            return Err(Par2Error::InvalidCreationOptions {
                reason: "creation plan sources are not strictly sorted".to_string(),
            });
        }
        let source_slice_count = self.sources.iter().try_fold(0u32, |total, source| {
            total.checked_add(source.slice_count()).ok_or_else(|| {
                Par2Error::InvalidCreationOptions {
                    reason: "creation plan source slice count overflows".to_string(),
                }
            })
        })?;
        if source_slice_count != self.source_slice_count {
            return Err(Par2Error::InvalidCreationOptions {
                reason: "creation plan source slice count differs from sources".to_string(),
            });
        }
        let cpu_memory = estimate_forward_memory(
            self.slice_size,
            self.source_slice_count as usize,
            self.recovery_count as usize,
            self.memory.processing_buffer_limit_bytes,
            self.forward_kernel,
        )?;
        let forward_memory = estimate_processing_memory(
            self.backend,
            usize::try_from(self.slice_size).map_err(|_| Par2Error::ResourceLimitExceeded {
                reason: "slice size exceeds addressable memory".to_string(),
            })?,
            self.source_slice_count as usize,
            self.recovery_count as usize,
            self.memory.processing_buffer_limit_bytes,
            cpu_memory,
        )?;
        let expected_memory = memory_plan_for(
            &self.sources,
            self.sources.len(),
            self.source_slice_count,
            self.slice_size,
            MemoryPlanPaths {
                base_path: &self.base_path,
                output_stem: &self.output_stem,
                main_path: &self.main_path,
                output_paths: &self.output_paths,
            },
            &self.volumes,
            self.memory.processing_buffer_limit_bytes,
            forward_memory,
        )?;
        if self.memory != expected_memory {
            return Err(Par2Error::InvalidCreationOptions {
                reason: "creation plan memory estimate differs from sources".to_string(),
            });
        }
        let output_parent =
            self.main_path
                .parent()
                .ok_or_else(|| Par2Error::InvalidCreationOptions {
                    reason: "creation plan main path has no parent".to_string(),
                })?;
        if self.output_stem.parent() != Some(output_parent)
            || self.output_stem.file_name().is_none()
            || self.main_path.file_stem() != self.output_stem.file_name()
            || self
                .main_path
                .extension()
                .and_then(|extension| extension.to_str())
                .is_none_or(|extension| !extension.eq_ignore_ascii_case("par2"))
            || self
                .volume_paths
                .iter()
                .zip(&self.volumes)
                .any(|(path, volume)| path != &output_parent.join(&volume.filename))
        {
            return Err(Par2Error::InvalidCreationOptions {
                reason: "creation plan output paths do not match the naming contract".to_string(),
            });
        }
        let mut main_body = Vec::with_capacity(12 + self.sources.len() * 16);
        main_body.extend_from_slice(&self.slice_size.to_le_bytes());
        main_body.extend_from_slice(&(self.sources.len() as u32).to_le_bytes());
        for source in &self.sources {
            main_body.extend_from_slice(source.file_id.as_bytes());
        }
        if RecoverySetId::from_bytes(md5(&main_body)) != self.recovery_set_id {
            return Err(Par2Error::InvalidCreationOptions {
                reason: "creation plan recovery-set identifier differs from Main packet"
                    .to_string(),
            });
        }
        let mut exponent = self.first_exponent;
        for (index, volume) in self.volumes.iter().enumerate() {
            if self.output_paths[index + 1] != self.volume_paths[index]
                || volume.first_exponent != exponent
                || volume.recovery_count == 0
            {
                return Err(Par2Error::InvalidCreationOptions {
                    reason: "creation plan volume allocation is inconsistent".to_string(),
                });
            }
            exponent = exponent.checked_add(volume.recovery_count).ok_or_else(|| {
                Par2Error::InvalidCreationOptions {
                    reason: "creation plan recovery exponent range overflows".to_string(),
                }
            })?;
        }
        if exponent != expected_end {
            return Err(Par2Error::InvalidCreationOptions {
                reason: "creation plan recovery allocation does not sum to recovery count"
                    .to_string(),
            });
        }
        for (offset, exponent) in self.recovery_exponents.iter().enumerate() {
            let expected = self.first_exponent.checked_add(offset as u32);
            if expected != Some(*exponent) {
                return Err(Par2Error::InvalidCreationOptions {
                    reason: "creation plan recovery exponents are not contiguous".to_string(),
                });
            }
        }
        Ok(())
    }
}

struct MemoryPlanPaths<'a> {
    base_path: &'a Path,
    output_stem: &'a Path,
    main_path: &'a Path,
    output_paths: &'a [PathBuf],
}

#[allow(clippy::too_many_arguments)]
fn memory_plan_for(
    sources: &[CreationSource],
    input_count: usize,
    source_slice_count: u32,
    block_size: u64,
    paths: MemoryPlanPaths<'_>,
    volumes: &[RecoveryVolumePlan],
    processing_buffer_limit_bytes: usize,
    forward_memory: super::encode::ForwardMemoryEstimate,
) -> Result<Par2MemoryPlan> {
    if processing_buffer_limit_bytes == 0 {
        return Err(Par2Error::ResourceLimitExceeded {
            reason: "memory limit must be greater than zero".to_string(),
        });
    }
    let source_metadata_bytes = estimate_source_metadata_bytes(sources, input_count)?;
    let source_hash_workspace_bytes = estimate_source_hash_workspace(input_count, block_size)?;
    let critical_packet_bytes = estimate_critical_packet_bytes(sources)?;
    let main_file_id_workspace_bytes = estimate_main_file_id_workspace_bytes(sources)?;
    let packet_build_workspace_bytes = estimate_packet_build_workspace_bytes(sources)?;
    let transaction_workspace_bytes = estimate_transaction_workspace_bytes(
        paths.base_path,
        paths.output_stem,
        paths.main_path,
        paths.output_paths,
        volumes,
        sources,
        volumes
            .iter()
            .try_fold(0u32, |total, volume| {
                total.checked_add(volume.recovery_count)
            })
            .ok_or_else(|| Par2Error::ResourceLimitExceeded {
                reason: "recovery volume count estimate overflows".to_string(),
            })?,
    )?;
    let validation_workspace_bytes = estimate_validation_workspace_bytes(
        sources,
        paths.output_paths,
        volumes,
        critical_packet_bytes,
    )?;
    let plan_phase = checked_memory_add(
        source_metadata_bytes,
        source_hash_workspace_bytes,
        "source creation estimate overflows",
    )?;
    let create_phase = [
        source_hash_workspace_bytes,
        checked_memory_mul(
            source_metadata_bytes,
            2,
            "source creation estimate overflows",
        )?,
        critical_packet_bytes,
        main_file_id_workspace_bytes,
        packet_build_workspace_bytes,
        transaction_workspace_bytes,
        forward_memory.processing_peak_bytes,
    ]
    .into_iter()
    .try_fold(0usize, |total, bytes| {
        checked_memory_add(total, bytes, "creation peak estimate overflows")
    })?;
    let validation_phase = [
        checked_memory_mul(
            source_metadata_bytes,
            2,
            "validation source metadata estimate overflows",
        )?,
        critical_packet_bytes,
        main_file_id_workspace_bytes,
        packet_build_workspace_bytes,
        transaction_workspace_bytes,
        validation_workspace_bytes,
    ]
    .into_iter()
    .try_fold(0usize, |total, bytes| {
        checked_memory_add(total, bytes, "validation peak estimate overflows")
    })?;

    Ok(Par2MemoryPlan {
        source_metadata_bytes,
        source_hash_workspace_bytes,
        critical_packet_bytes,
        main_file_id_workspace_bytes,
        packet_build_workspace_bytes,
        transaction_workspace_bytes,
        validation_workspace_bytes,
        processing_buffer_limit_bytes,
        processing_peak_bytes: forward_memory.processing_peak_bytes,
        total_creation_peak_bytes: plan_phase.max(create_phase).max(validation_phase),
        factor_workspace_bytes: forward_memory.factor_workspace_bytes,
        jit_workspace_bytes: forward_memory.jit_workspace_bytes,
        stripe_buffer_bytes: forward_memory.stripe_buffer_bytes,
        controller_overhead_blocks: controller_overhead_blocks(source_slice_count),
    })
}

fn estimate_source_metadata_bytes(sources: &[CreationSource], capacity: usize) -> Result<usize> {
    let mut total = checked_memory_mul(
        capacity,
        size_of::<CreationSource>(),
        "source metadata estimate overflows",
    )?;
    for source in sources {
        total = checked_memory_add(
            total,
            source
                .path
                .as_os_str()
                .len()
                .checked_add(64)
                .ok_or_else(|| Par2Error::ResourceLimitExceeded {
                    reason: "source path estimate overflows".to_string(),
                })?,
            "source path estimate overflows",
        )?;
        total = checked_memory_add(
            total,
            source.par2_name.len().checked_add(64).ok_or_else(|| {
                Par2Error::ResourceLimitExceeded {
                    reason: "source name estimate overflows".to_string(),
                }
            })?,
            "source name estimate overflows",
        )?;
        total = checked_memory_add(
            total,
            checked_memory_mul(
                source.slice_checksums.len(),
                size_of::<SliceChecksum>(),
                "source checksum estimate overflows",
            )?,
            "source metadata estimate overflows",
        )?;
    }
    Ok(total)
}

fn estimate_source_hash_workspace(input_count: usize, block_size: u64) -> Result<usize> {
    const READ_BUFFER_BYTES: usize = 256 * 1024;
    const HASH_SET_ENTRY_RESERVE_BYTES: usize = 128;
    let input_lengths = checked_memory_mul(
        input_count,
        size_of::<InputLength>(),
        "source length estimate overflows",
    )?;
    let hash_sets = checked_memory_mul(
        checked_memory_mul(
            input_count,
            HASH_SET_ENTRY_RESERVE_BYTES,
            "source index estimate overflows",
        )?,
        2,
        "source index estimate overflows",
    )?;
    // Source hashing runs one file per rayon task, each with its own read
    // buffer; the gate mirrors the parallel scan's split in source.rs and
    // the +1 covers the calling thread. Process-stable thread count only.
    let threads = super::encode::configured_create_threads();
    let concurrent_reads = if threads == 1 || input_count <= 1 {
        1
    } else {
        input_count.min(threads.saturating_add(1))
    };
    // A task either stages a batch of slices for the multi-buffer slice-hash
    // kernel or streams one slice through a single read buffer, whichever
    // `create_md5_batch_lanes` selected for this block size. Mirrors the split
    // in `source.rs` exactly; the two must move together or the plan's
    // self-consistency check in `Par2CreatePlan` fails.
    // `READ_BUFFER_BYTES` stays a floor rather than the exact figure: the
    // streaming arm allocates only `min(READ_BUFFER_BYTES, block_size)`, so
    // this estimate has always been an upper bound for small blocks, and
    // tightening it here would move a reported number for no benefit.
    let block_size_usize = usize::try_from(block_size).unwrap_or(usize::MAX);
    let lanes = super::source::create_md5_batch_lanes(block_size_usize);
    let per_task_bytes = if lanes >= 2 {
        checked_memory_mul(
            lanes,
            block_size_usize,
            "source hash batch estimate overflows",
        )?
        .max(READ_BUFFER_BYTES)
    } else {
        READ_BUFFER_BYTES
    };
    let read_buffers = checked_memory_mul(
        per_task_bytes,
        concurrent_reads,
        "concurrent source read buffer estimate overflows",
    )?;
    [read_buffers, input_lengths, hash_sets]
        .into_iter()
        .try_fold(0usize, |total, bytes| {
            checked_memory_add(total, bytes, "source hashing estimate overflows")
        })
}

fn estimate_main_file_id_workspace_bytes(sources: &[CreationSource]) -> Result<usize> {
    checked_memory_add(
        size_of::<Vec<u8>>(),
        checked_memory_add(
            12,
            checked_memory_mul(
                sources.len(),
                size_of::<FileId>(),
                "Main packet file-ID estimate overflows",
            )?,
            "Main packet file-ID estimate overflows",
        )?,
        "Main packet file-ID estimate overflows",
    )
}

fn checked_memory_add(left: usize, right: usize, reason: &'static str) -> Result<usize> {
    left.checked_add(right)
        .ok_or_else(|| Par2Error::ResourceLimitExceeded {
            reason: reason.to_string(),
        })
}

fn checked_memory_mul(left: usize, right: usize, reason: &'static str) -> Result<usize> {
    left.checked_mul(right)
        .ok_or_else(|| Par2Error::ResourceLimitExceeded {
            reason: reason.to_string(),
        })
}

/// Build a creation plan, optionally reusing the creator's source-scan memo.
///
/// `Par2Creator` passes the same memo to `plan()` and to `create()`, so the
/// canonical rebuild inside `create()` re-validates every input by `stat` but
/// reads and hashes only what actually changed since planning. `None` is the
/// unmemoized behavior: every input is read and hashed.
pub(crate) fn build_plan_with_cache(
    options: &Par2CreatorOptions,
    cache: Option<&super::source::SourceScanCache>,
) -> Result<Par2CreatePlan> {
    if options.cancellation.is_cancelled() {
        return Err(Par2Error::Cancelled);
    }
    let output = options
        .output
        .as_ref()
        .ok_or_else(|| Par2Error::InvalidCreationOptions {
            reason: "an output path or stem is required".to_string(),
        })?;
    let (output_parent, output_stem, main_path, stem_name) = normalize_output(output)?;
    let base_path = match &options.base_path {
        Some(path) => canonical_source_directory(path)?,
        None => output_parent.clone(),
    };
    let input_lengths = collect_input_lengths(&base_path, &options.inputs, &options.cancellation)?;
    let total_bytes = input_lengths.iter().try_fold(0u64, |total, input| {
        total
            .checked_add(input.length)
            .ok_or_else(|| Par2Error::ResourceLimitExceeded {
                reason: "source byte count overflows".to_string(),
            })
    })?;
    let block_size = choose_block_size(&input_lengths, options.block_sizing)?;
    let collected = collect_sources(
        &base_path,
        &options.inputs,
        block_size,
        &options.cancellation,
        options.progress.as_ref(),
        total_bytes,
        cache,
    )?;
    let skipped_empty = collected.skipped_empty;
    let mut sources = collected.sources;
    sources.sort_by_key(|source| source.file_id);
    if options.cancellation.is_cancelled() {
        return Err(Par2Error::Cancelled);
    }

    let source_slice_count = sources.iter().try_fold(0u32, |total, source| {
        total
            .checked_add(source.slice_count())
            .ok_or_else(|| Par2Error::ResourceLimitExceeded {
                reason: "source slice count overflows u32".to_string(),
            })
    })?;
    let recovery_count = choose_recovery_count(
        source_slice_count,
        options.recovery_amount,
        options.first_exponent,
    )?;
    validate_exponent_range(options.first_exponent, recovery_count)?;

    let forward_memory_limit = options.memory_limit.unwrap_or_else(default_memory_limit);
    if forward_memory_limit == 0 {
        return Err(Par2Error::ResourceLimitExceeded {
            reason: "memory limit must be greater than zero".to_string(),
        });
    }
    let cpu_memory = estimate_forward_memory(
        block_size,
        source_slice_count as usize,
        recovery_count as usize,
        forward_memory_limit,
        options.forward_kernel,
    )?;
    let forward_memory = estimate_processing_memory(
        options.backend,
        usize::try_from(block_size).map_err(|_| Par2Error::ResourceLimitExceeded {
            reason: "slice size exceeds addressable memory".to_string(),
        })?,
        source_slice_count as usize,
        recovery_count as usize,
        forward_memory_limit,
        cpu_memory,
    )?;
    let volumes = allocate_volumes(
        options.first_exponent,
        recovery_count,
        options.volume_count,
        options.volume_scheme,
        &stem_name,
        sources
            .iter()
            .map(|source| source.file_length)
            .max()
            .unwrap_or(0),
        block_size,
    )?;
    let volume_paths = volumes
        .iter()
        .map(|volume| output_parent.join(&volume.filename))
        .collect::<Vec<_>>();
    let mut output_paths = Vec::with_capacity(volume_paths.len() + 1);
    output_paths.push(main_path.clone());
    output_paths.extend(volume_paths.iter().cloned());
    let target_snapshots = validate_output_targets(&output_paths, &sources, options.overwrite)?;

    let mut main_body = Vec::with_capacity(12 + sources.len() * 16);
    main_body.extend_from_slice(&block_size.to_le_bytes());
    main_body.extend_from_slice(&(sources.len() as u32).to_le_bytes());
    for source in &sources {
        main_body.extend_from_slice(source.file_id.as_bytes());
    }
    let recovery_set_id = RecoverySetId::from_bytes(md5(&main_body));
    let recovery_exponents = (0..recovery_count)
        .map(|offset| options.first_exponent + offset)
        .collect();
    let memory = memory_plan_for(
        &sources,
        input_lengths.len(),
        source_slice_count,
        block_size,
        MemoryPlanPaths {
            base_path: &base_path,
            output_stem: &output_stem,
            main_path: &main_path,
            output_paths: &output_paths,
        },
        &volumes,
        forward_memory_limit,
        forward_memory,
    )?;

    Ok(Par2CreatePlan {
        base_path,
        output_stem,
        main_path,
        volumes,
        volume_scheme: options.volume_scheme,
        volume_paths,
        output_paths,
        target_snapshots,
        sources,
        slice_size: block_size,
        source_slice_count,
        recovery_count,
        first_exponent: options.first_exponent,
        recovery_exponents,
        recovery_set_id,
        forward_kernel: options.forward_kernel,
        backend: options.backend,
        memory,
        dry_run: options.dry_run,
        skipped_empty,
    })
}

fn canonical_directory(path: &Path, label: &str) -> Result<PathBuf> {
    let canonical = fs::canonicalize(path).map_err(|error| Par2Error::UnsafeCreationOutput {
        path: path.display().to_string(),
        reason: format!("{label} cannot be resolved: {error}"),
    })?;
    if !fs::metadata(&canonical).map_err(Par2Error::Io)?.is_dir() {
        return Err(Par2Error::UnsafeCreationOutput {
            path: path.display().to_string(),
            reason: format!("{label} is not a directory"),
        });
    }
    Ok(canonical)
}

fn canonical_source_directory(path: &Path) -> Result<PathBuf> {
    let canonical = fs::canonicalize(path).map_err(|error| Par2Error::UnsafeCreationSource {
        path: path.display().to_string(),
        reason: format!("base path cannot be resolved: {error}"),
    })?;
    if !fs::metadata(&canonical).map_err(Par2Error::Io)?.is_dir() {
        return Err(Par2Error::UnsafeCreationSource {
            path: path.display().to_string(),
            reason: "base path is not a directory".to_string(),
        });
    }
    Ok(canonical)
}

fn normalize_output(output: &Path) -> Result<(PathBuf, PathBuf, PathBuf, String)> {
    let file_name = output
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| Par2Error::UnsafeCreationOutput {
            path: output.display().to_string(),
            reason: "output must have a valid UTF-8 filename".to_string(),
        })?;
    if file_name.is_empty() || file_name == "." || file_name == ".." || file_name.contains('\0') {
        return Err(Par2Error::UnsafeCreationOutput {
            path: output.display().to_string(),
            reason: "output filename is empty or unsafe".to_string(),
        });
    }
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = canonical_directory(parent, "output directory")?;
    let (stem_name, main_name) = match file_name.rsplit_once('.') {
        Some((stem, extension)) if extension.eq_ignore_ascii_case("par2") => {
            if stem.is_empty() {
                return Err(Par2Error::UnsafeCreationOutput {
                    path: output.display().to_string(),
                    reason: "output stem is empty".to_string(),
                });
            }
            (stem.to_string(), file_name.to_string())
        }
        _ => (file_name.to_string(), format!("{file_name}.par2")),
    };
    let stem_path = parent.join(&stem_name);
    let main_path = parent.join(main_name);
    Ok((parent, stem_path, main_path, stem_name))
}

pub(crate) fn validate_output_targets(
    output_paths: &[PathBuf],
    sources: &[CreationSource],
    overwrite: bool,
) -> Result<Vec<TargetSnapshot>> {
    let mut snapshots = Vec::with_capacity(output_paths.len());
    for (index, target) in output_paths.iter().enumerate() {
        if output_paths[..index].iter().any(|other| other == target) {
            return Err(Par2Error::UnsafeCreationOutput {
                path: target.display().to_string(),
                reason: "output paths are not unique".to_string(),
            });
        }
        if sources.iter().any(|source| source.path == *target) {
            return Err(Par2Error::UnsafeCreationOutput {
                path: target.display().to_string(),
                reason: "output would replace an explicit source file".to_string(),
            });
        }
        let snapshot = capture_target_snapshot(target).map_err(Par2Error::Io)?;
        match snapshot {
            TargetSnapshot::Directory => {
                return Err(Par2Error::UnsafeCreationOutput {
                    path: target.display().to_string(),
                    reason: "output path is a directory".to_string(),
                });
            }
            TargetSnapshot::Symlink => {
                return Err(Par2Error::UnsafeCreationOutput {
                    path: target.display().to_string(),
                    reason: "output path is a symlink".to_string(),
                });
            }
            TargetSnapshot::Special => {
                return Err(Par2Error::UnsafeCreationOutput {
                    path: target.display().to_string(),
                    reason: "output path is not a regular file".to_string(),
                });
            }
            TargetSnapshot::File(_) if !overwrite => {
                return Err(Par2Error::CreationOutputExists {
                    path: target.display().to_string(),
                });
            }
            TargetSnapshot::Absent | TargetSnapshot::File(_) => {}
        }
        snapshots.push(snapshot);
    }
    Ok(snapshots)
}

fn choose_block_size(lengths: &[InputLength], sizing: BlockSizing) -> Result<u64> {
    match sizing {
        BlockSizing::Bytes(bytes) => validate_block_size(bytes),
        BlockSizing::Count(count) => {
            if count == 0 {
                return Err(Par2Error::InvalidCreationOptions {
                    reason: "block count must be greater than zero".to_string(),
                });
            }
            if (count as usize) < lengths.len() {
                return Err(Par2Error::InvalidCreationOptions {
                    reason: format!(
                        "block count {count} is smaller than the source file count {}",
                        lengths.len()
                    ),
                });
            }
            if count as usize == lengths.len() {
                return largest_rounded_block_size(lengths);
            }
            smallest_block_for_count(lengths, count as u64)
        }
        BlockSizing::Auto => automatic_block_size(lengths),
    }
}

fn automatic_block_size(lengths: &[InputLength]) -> Result<u64> {
    let total_bytes = lengths.iter().try_fold(0u64, |total, input| {
        total
            .checked_add(input.length)
            .ok_or_else(|| Par2Error::ResourceLimitExceeded {
                reason: "source byte count overflows".to_string(),
            })
    })?;
    let target = total_bytes
        .checked_add(AUTO_SOURCE_SLICE_TARGET - 1)
        .ok_or_else(|| Par2Error::ResourceLimitExceeded {
            reason: "automatic block-size rounding overflows".to_string(),
        })?
        / AUTO_SOURCE_SLICE_TARGET;
    let minimum =
        total_bytes
            .checked_add(32_768 - 1)
            .ok_or_else(|| Par2Error::ResourceLimitExceeded {
                reason: "automatic block-size limit rounding overflows".to_string(),
            })?
            / 32_768;
    round_block_size(target.max(minimum).max(4))
}

fn largest_rounded_block_size(lengths: &[InputLength]) -> Result<u64> {
    let largest = lengths.iter().map(|input| input.length).max().unwrap_or(0);
    round_block_size(largest.max(4))
}

fn round_block_size(bytes: u64) -> Result<u64> {
    bytes
        .checked_add(3)
        .map(|value| value / 4 * 4)
        .ok_or_else(|| Par2Error::ResourceLimitExceeded {
            reason: "block size rounding overflows".to_string(),
        })
}

fn validate_block_size(block_size: u64) -> Result<u64> {
    if block_size == 0 || !block_size.is_multiple_of(4) {
        return Err(Par2Error::InvalidCreationOptions {
            reason: format!("block size {block_size} is not a positive multiple of four"),
        });
    }
    Ok(block_size)
}

fn smallest_block_for_count(lengths: &[InputLength], target: u64) -> Result<u64> {
    let maximum = lengths.iter().try_fold(4u64, |maximum, input| {
        let rounded =
            input
                .length
                .checked_add(3)
                .ok_or_else(|| Par2Error::ResourceLimitExceeded {
                    reason: "source length rounding overflows".to_string(),
                })?
                / 4
                * 4;
        Ok::<u64, Par2Error>(maximum.max(rounded))
    })?;
    let mut low = 4u64;
    let mut high = maximum;
    while low < high {
        let low_units = low / 4;
        let high_units = high / 4;
        let mid = (low_units + (high_units - low_units) / 2) * 4;
        if count_for_block(lengths, mid)? <= target {
            high = mid;
        } else {
            low = mid + 4;
        }
    }
    Ok(low)
}

fn count_for_block(lengths: &[InputLength], block_size: u64) -> Result<u64> {
    lengths.iter().try_fold(0u64, |total, input| {
        let count = if input.length == 0 {
            0
        } else {
            (input.length - 1) / block_size + 1
        };
        total
            .checked_add(count)
            .ok_or_else(|| Par2Error::ResourceLimitExceeded {
                reason: "source slice count overflows".to_string(),
            })
    })
}

fn choose_recovery_count(
    source_slice_count: u32,
    amount: RecoveryAmount,
    first_exponent: RecoveryExponent,
) -> Result<u32> {
    match amount {
        RecoveryAmount::Count(count) => {
            if count > 32_768 {
                return Err(Par2Error::InvalidCreationOptions {
                    reason: "explicit recovery count cannot exceed 32768".to_string(),
                });
            }
            Ok(count)
        }
        RecoveryAmount::Percent(percent) => {
            let scaled = (source_slice_count as u64)
                .checked_mul(percent as u64)
                .and_then(|value| value.checked_add(50))
                .ok_or_else(|| Par2Error::ResourceLimitExceeded {
                    reason: "percentage recovery count overflows".to_string(),
                })?;
            let mut count = scaled / 100;
            if percent > 0 && count == 0 {
                count = 1;
            }
            let count = u32::try_from(count).map_err(|_| Par2Error::InvalidCreationOptions {
                reason: "percentage recovery count exceeds the exponent range".to_string(),
            })?;
            validate_exponent_range(first_exponent, count)?;
            Ok(count)
        }
    }
}

fn validate_exponent_range(first_exponent: RecoveryExponent, count: u32) -> Result<()> {
    if first_exponent > 32_768 {
        return Err(Par2Error::InvalidCreationOptions {
            reason: "first recovery exponent cannot exceed 32768".to_string(),
        });
    }
    let end =
        first_exponent
            .checked_add(count)
            .ok_or_else(|| Par2Error::InvalidCreationOptions {
                reason: "recovery exponent range overflows".to_string(),
            })?;
    if end > MAX_RECOVERY_EXPONENT {
        return Err(Par2Error::InvalidCreationOptions {
            reason: "first recovery exponent plus count must be less than 65536".to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_default_policy_has_floor_and_32_bit_cap() {
        assert_eq!(memory_limit_for(None, 64), MEMORY_FLOOR_BYTES,);
        assert_eq!(
            memory_limit_for(Some((MEMORY_FLOOR_BYTES as u64) * 16), 64),
            MEMORY_FLOOR_BYTES * 2,
        );
        assert_eq!(
            memory_limit_for(Some(u64::MAX), 32),
            MEMORY_32_BIT_CAP_BYTES,
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_global_memory_status_reports_physical_memory() {
        assert!(physical_memory_bytes().is_some_and(|bytes| bytes > 0));
    }
}
