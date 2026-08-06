//! PAR2 repair orchestration using Reed-Solomon decoding over GF(2^16).
//!
//! This module implements the full repair pipeline:
//! 1. Analyze verification results to identify missing/damaged slices
//! 2. Build a repair plan (decode matrix from Gaussian elimination)
//! 3. Execute repair by reading recovery data, XOR-ing out known contributions,
//!    and multiplying by the decode matrix to reconstruct missing slices
//! 4. Write repaired data back to files

use rayon::prelude::*;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::mem::MaybeUninit;
use std::path::{Path, PathBuf};
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::AtomicU32;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

use crate::cpu_repair_controller::{
    ControllerAddResult, ControllerAddStatus, ControllerExecutionEvent, ControllerExecutionTrace,
    ControllerFailurePhase, ControllerLayout, ControllerLifecycle, CpuControllerPlan,
    CpuMethodContract, CpuPrefetch, InputBatch,
};
use crate::error::{Par2Error, Result};
use crate::gf;
use crate::matrix;
use crate::par2_set::Par2FileSet;
use crate::types::{
    CancellationToken, FileId, MAX_SLICES_PER_FILE, MAX_TOTAL_INPUT_SLICES, ProgressCallback,
    ProgressStage, ProgressUpdate,
};
use crate::verify::{FileAccess, FileRangeReader, Repairability, VerificationResult};

pub(crate) const DEFAULT_REPAIR_MEMORY_LIMIT: usize = 64 * 1024 * 1024;
/// The decode matrix is a transient planning workspace whose size is set by
/// the damage (missing^2 + missing*total words), not by streaming buffer
/// tuning. Give it its own budget floor so tight slice-buffer limits do not
/// refuse legitimately repairable sets; an explicitly larger `memory_limit`
/// raises it further. Bounded in practice by the 32768-slice spec cap.
const MATRIX_WORKSPACE_BUDGET_FLOOR: usize = 1024 * 1024 * 1024;
const XOR_OUT_PAR_CHUNK: usize = 16;
const CPU_CONTROLLER_BUDGET_INPUTS: usize = 12;

/// A plan for repairing missing/damaged slices.
#[derive(Debug, Clone)]
pub struct RepairPlan {
    /// The missing input slices as (FileId, slice_index) pairs.
    pub missing_slices: Vec<(FileId, u32)>,
    /// Global indices of missing slices in the concatenated input slice ordering.
    pub missing_global_indices: Vec<usize>,
    /// Global indices of source slices that are already available and will be read as inputs.
    pub available_input_global_indices: Vec<usize>,
    /// Which recovery block exponents to use (one per missing slice).
    pub recovery_exponents: Vec<u32>,
    /// The inverted decode matrix rows (each row has `missing_slices.len()` entries).
    pub decode_matrix: matrix::Matrix,
    /// Full repair coefficients with columns ordered as
    /// `available_input_global_indices` followed by `recovery_exponents`.
    pub input_factors: matrix::Matrix,
    /// The PAR2 slice size in bytes.
    pub slice_size: u64,
    /// Constants for all input slices (needed for XOR-out step).
    pub constants: Vec<u16>,
    /// Total number of input slices across all files.
    pub total_input_slices: usize,
    /// Mapping from global slice index to (FileId, local_slice_index).
    pub global_to_file: Vec<(FileId, u32)>,
}

/// Plan a repair operation based on verification results.
///
/// Examines the verification result to find missing/damaged slices, selects
/// recovery blocks to use, and builds the decode matrix via Gaussian elimination.
pub fn plan_repair(
    par2_set: &Par2FileSet,
    verification: &VerificationResult,
) -> Result<RepairPlan> {
    plan_repair_with_memory_limit(par2_set, verification, Some(DEFAULT_REPAIR_MEMORY_LIMIT))
}

/// Plan a repair operation using an explicit repair workspace memory limit.
pub fn plan_repair_with_memory_limit(
    par2_set: &Par2FileSet,
    verification: &VerificationResult,
    memory_limit: Option<usize>,
) -> Result<RepairPlan> {
    // Check repairability.
    match &verification.repairable {
        Repairability::NotNeeded => {
            return Err(Par2Error::ReedSolomonError {
                reason: "no repair needed".to_string(),
            });
        }
        Repairability::Insufficient {
            blocks_needed,
            blocks_available,
            deficit,
        } => {
            return Err(Par2Error::InsufficientRecoveryData {
                needed: *blocks_needed,
                available: *blocks_available,
                deficit: *deficit,
            });
        }
        Repairability::ResourceLimited { reason } => {
            return Err(Par2Error::ResourceLimitExceeded {
                reason: format!("PAR2 verification is resource-limited: {reason}"),
            });
        }
        Repairability::Repairable { .. } => {}
    }

    // Build the global slice index mapping.
    // Global ordering: files in order of recovery_file_ids, slices in order within each file.
    let mut global_to_file: Vec<(FileId, u32)> = Vec::new();
    for file_id in &par2_set.recovery_file_ids {
        if let Some(desc) = par2_set.file_description(file_id) {
            let slice_count =
                usize::try_from(par2_set.slice_count_for_file(desc.length)).map_err(|_| {
                    Par2Error::ResourceLimitExceeded {
                        reason: format!(
                            "file {} has more than {MAX_SLICES_PER_FILE} addressable PAR2 slices",
                            desc.filename
                        ),
                    }
                })?;
            if slice_count > MAX_SLICES_PER_FILE {
                return Err(Par2Error::ResourceLimitExceeded {
                    reason: format!(
                        "file {} has {slice_count} PAR2 slices; max is {MAX_SLICES_PER_FILE}",
                        desc.filename
                    ),
                });
            }
            for s in 0..slice_count {
                global_to_file.push((*file_id, s as u32));
            }
        }
    }
    let total_input_slices = global_to_file.len();
    if total_input_slices > MAX_TOTAL_INPUT_SLICES {
        return Err(Par2Error::ResourceLimitExceeded {
            reason: format!(
                "recovery set has {total_input_slices} input slices; PAR2 supports at most {MAX_TOTAL_INPUT_SLICES}"
            ),
        });
    }

    // Identify missing slices (global indices).
    let mut missing_slices: Vec<(FileId, u32)> = Vec::new();
    let mut missing_global_indices: Vec<usize> = Vec::new();

    let mut global_idx = 0usize;
    for file_id in &par2_set.recovery_file_ids {
        let desc = match par2_set.file_description(file_id) {
            Some(d) => d,
            None => continue,
        };
        let slice_count =
            usize::try_from(par2_set.slice_count_for_file(desc.length)).map_err(|_| {
                Par2Error::ResourceLimitExceeded {
                    reason: format!(
                        "file {} has more than {MAX_SLICES_PER_FILE} addressable PAR2 slices",
                        desc.filename
                    ),
                }
            })?;
        if slice_count > MAX_SLICES_PER_FILE {
            return Err(Par2Error::ResourceLimitExceeded {
                reason: format!(
                    "file {} has {slice_count} PAR2 slices; max is {MAX_SLICES_PER_FILE}",
                    desc.filename
                ),
            });
        }

        // Find this file's verification result.
        let file_verif = verification.files.iter().find(|fv| fv.file_id == *file_id);

        for s in 0..slice_count {
            let is_valid = file_verif
                .map(|fv| fv.valid_slices.get(s).copied().unwrap_or(false))
                .unwrap_or(false);

            if !is_valid {
                missing_slices.push((*file_id, s as u32));
                missing_global_indices.push(global_idx + s);
            }
        }
        global_idx += slice_count;
    }

    let missing_count = missing_slices.len();
    debug!("repair: {missing_count} missing slices identified");

    // Select recovery exponents. Try the first N available; if the decode
    // matrix is singular (bad recovery block), skip that exponent and retry
    // with the next available one.
    let mut all_exponents: Vec<u32> = par2_set.recovery_slices.keys().copied().collect();
    all_exponents.sort_unstable();

    if all_exponents.len() < missing_count {
        return Err(Par2Error::InsufficientRecoveryData {
            needed: missing_count as u32,
            available: all_exponents.len() as u32,
            deficit: (missing_count - all_exponents.len()) as u32,
        });
    }
    if let Some(reason) =
        repair_matrix_limit_reason(total_input_slices, missing_count, memory_limit)
    {
        return Err(Par2Error::ResourceLimitExceeded { reason });
    }

    // Compute constants for all input slices.
    let constants = gf::input_slice_constants(total_input_slices);
    let missing_set: HashSet<usize> = missing_global_indices.iter().copied().collect();
    let available_input_global_indices: Vec<usize> = (0..total_input_slices)
        .filter(|global_idx| !missing_set.contains(global_idx))
        .collect();

    // Try building the decode matrix, skipping corrupt or singular recovery
    // blocks. Payload validation is lazy: only selected blocks are hashed,
    // each at most once, so undamaged repairs never pay for unused volumes.
    let mut skip_set: HashSet<usize> = HashSet::new();
    let mut validated_exponents: HashMap<u32, bool> = HashMap::new();
    let (recovery_exponents, input_factors, decode) = loop {
        let selected_indices: Vec<usize> = all_exponents
            .iter()
            .enumerate()
            .filter(|(i, _)| !skip_set.contains(i))
            .map(|(i, _)| i)
            .take(missing_count)
            .collect();
        let selected: Vec<u32> = selected_indices
            .iter()
            .map(|&idx| all_exponents[idx])
            .collect();

        if selected.len() < missing_count {
            return Err(Par2Error::InsufficientRecoveryData {
                needed: missing_count as u32,
                available: selected.len() as u32,
                deficit: (missing_count - selected.len()) as u32,
            });
        }

        let mut corrupt_selection = None;
        for (position, &exponent) in selected.iter().enumerate() {
            let valid = *validated_exponents.entry(exponent).or_insert_with(|| {
                let slice = &par2_set.recovery_slices[&exponent];
                match slice
                    .data
                    .validate_packet_hash(par2_set.recovery_set_id.as_bytes(), exponent)
                {
                    Ok(valid) => {
                        if !valid {
                            warn!(
                                "recovery block exponent {exponent} failed packet hash validation, skipping"
                            );
                        }
                        valid
                    }
                    Err(error) => {
                        warn!("recovery block exponent {exponent} is unreadable ({error}), skipping");
                        false
                    }
                }
            });
            if !valid {
                corrupt_selection = Some(selected_indices[position]);
                break;
            }
        }
        if let Some(skip_idx) = corrupt_selection {
            skip_set.insert(skip_idx);
            continue;
        }

        match matrix::build_repair_matrix_with_bad_row(
            &available_input_global_indices,
            &missing_global_indices,
            &selected,
            &constants,
        ) {
            Ok((input_factors, decode)) => break (selected, input_factors, decode),
            Err(matrix_error) => {
                let mut skip_idx = matrix_error
                    .bad_row
                    .and_then(|row| selected_indices.get(row).copied());
                if skip_idx.is_none() {
                    for candidate_idx in &selected_indices {
                        let trial: Vec<u32> = all_exponents
                            .iter()
                            .enumerate()
                            .filter(|(idx, _)| !skip_set.contains(idx) && idx != candidate_idx)
                            .map(|(_, &exponent)| exponent)
                            .take(missing_count)
                            .collect();
                        if trial.len() < missing_count {
                            continue;
                        }
                        if matrix::build_repair_matrix_with_bad_row(
                            &available_input_global_indices,
                            &missing_global_indices,
                            &trial,
                            &constants,
                        )
                        .is_ok()
                        {
                            skip_idx = Some(*candidate_idx);
                            break;
                        }
                    }
                }
                let skip_idx = skip_idx.unwrap_or_else(|| {
                    *selected_indices
                        .last()
                        .expect("singular repair selection must contain at least one row")
                });
                warn!(
                    "recovery exponent {} produced singular matrix, skipping",
                    all_exponents[skip_idx]
                );
                skip_set.insert(skip_idx);
            }
        }
    };

    info!(
        "repair plan: {} missing slices, {} recovery blocks selected",
        missing_count,
        recovery_exponents.len()
    );

    Ok(RepairPlan {
        missing_slices,
        missing_global_indices,
        available_input_global_indices,
        recovery_exponents,
        decode_matrix: decode,
        input_factors,
        slice_size: par2_set.slice_size,
        constants,
        total_input_slices,
        global_to_file,
    })
}

pub(crate) fn repair_matrix_resource_limit_reason(
    par2_set: &Par2FileSet,
    verification: &VerificationResult,
    memory_limit: Option<usize>,
) -> Result<Option<String>> {
    if !matches!(verification.repairable, Repairability::Repairable { .. }) {
        return Ok(None);
    }

    let total_input_slices = total_input_slices_for_set(par2_set)?;
    let missing_count = verification.total_missing_blocks as usize;
    Ok(repair_matrix_limit_reason(
        total_input_slices,
        missing_count,
        memory_limit,
    ))
}

/// Options controlling repair execution.
pub struct RepairOptions {
    /// If set, repair will check this token and stop early if cancelled.
    pub cancel: Option<CancellationToken>,
    /// If set, called with progress updates during repair.
    pub progress: Option<ProgressCallback>,
    /// Maximum transient repair workspace size in bytes.
    ///
    /// The CPU repair controller sizes its streamed chunks from this budget.
    /// Caller-provided solvers supplied through [`execute_repair_with_solver`]
    /// retain their explicit in-memory contract.
    ///
    /// If `None`, the crate default bounded repair budget is used.
    pub memory_limit: Option<usize>,
}

impl Default for RepairOptions {
    fn default() -> Self {
        Self {
            cancel: None,
            progress: None,
            memory_limit: Some(DEFAULT_REPAIR_MEMORY_LIMIT),
        }
    }
}

#[derive(Clone, Copy)]
struct FactorIndex {
    factor: u16,
    input_idx: u16,
}

#[derive(Clone, Debug)]
struct RepairWriteTarget {
    file_id: FileId,
    filename: String,
    offset: u64,
    file_end: u64,
}

fn check_cancel(options: &RepairOptions) -> Result<()> {
    if let Some(ref cancel) = options.cancel
        && cancel.is_cancelled()
    {
        return Err(Par2Error::Cancelled);
    }
    Ok(())
}

fn recv_with_cancel<T>(
    receiver: &std::sync::mpsc::Receiver<T>,
    cancel: Option<&CancellationToken>,
    reason: &'static str,
) -> Result<T> {
    loop {
        match receiver.recv_timeout(Duration::from_millis(20)) {
            Ok(value) => return Ok(value),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if cancel.is_some_and(|token| token.is_cancelled()) {
                    return Err(Par2Error::Cancelled);
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                return Err(Par2Error::ReedSolomonError {
                    reason: reason.to_string(),
                });
            }
        }
    }
}

fn estimated_repair_matrix_bytes(total_inputs: usize, missing_rows: usize) -> usize {
    let working_words = missing_rows
        .saturating_mul(missing_rows)
        .saturating_add(missing_rows.saturating_mul(total_inputs));
    working_words.saturating_mul(std::mem::size_of::<u16>())
}

fn repair_memory_limit_bytes(memory_limit: Option<usize>) -> usize {
    memory_limit.unwrap_or(DEFAULT_REPAIR_MEMORY_LIMIT)
}

fn repair_matrix_limit_reason(
    total_input_slices: usize,
    missing_count: usize,
    memory_limit: Option<usize>,
) -> Option<String> {
    if total_input_slices > MAX_TOTAL_INPUT_SLICES {
        return Some(format!(
            "recovery set has {total_input_slices} input slices; PAR2 supports at most {MAX_TOTAL_INPUT_SLICES}"
        ));
    }
    let estimated = estimated_repair_matrix_bytes(total_input_slices, missing_count);
    let limit = repair_memory_limit_bytes(memory_limit).max(MATRIX_WORKSPACE_BUDGET_FLOOR);
    (estimated > limit).then(|| {
        format!(
            "repair matrix for {missing_count} missing slices would require {estimated} bytes, exceeding the {limit} byte matrix workspace budget"
        )
    })
}

fn total_input_slices_for_set(par2_set: &Par2FileSet) -> Result<usize> {
    let mut total = 0usize;
    for file_id in &par2_set.recovery_file_ids {
        let Some(desc) = par2_set.file_description(file_id) else {
            continue;
        };
        let slice_count =
            usize::try_from(par2_set.slice_count_for_file(desc.length)).map_err(|_| {
                Par2Error::ResourceLimitExceeded {
                    reason: format!(
                        "file {} has more than {MAX_SLICES_PER_FILE} addressable PAR2 slices",
                        desc.filename
                    ),
                }
            })?;
        if slice_count > MAX_SLICES_PER_FILE {
            return Err(Par2Error::ResourceLimitExceeded {
                reason: format!(
                    "file {} has {slice_count} PAR2 slices; max is {MAX_SLICES_PER_FILE}",
                    desc.filename
                ),
            });
        }
        total = total.saturating_add(slice_count);
    }
    Ok(total)
}

fn cpu_controller_plan(
    current_slice_size: usize,
    output_count: usize,
    worker_count: usize,
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))] method: CpuMethodContract,
    allocated_staging_width: usize,
) -> CpuControllerPlan {
    CpuControllerPlan::new_with_input_grouping_and_staging_width(
        current_slice_size,
        output_count,
        worker_count,
        method,
        method.input_grouping(),
        allocated_staging_width,
    )
}

fn controller_execution_parameters(
    plan: &RepairPlan,
    options: &RepairOptions,
    method: CpuMethodContract,
    allocated_staging_width: usize,
    persistent_bytes: usize,
    workers: usize,
) -> Result<(usize, usize, CpuControllerPlan)> {
    let word_count = (plan.slice_size as usize / 2).max(1);
    let limit = options.memory_limit.unwrap_or(DEFAULT_REPAIR_MEMORY_LIMIT);
    let controller_budget = limit.checked_sub(persistent_bytes).ok_or_else(|| {
        Par2Error::ResourceLimitExceeded {
            reason: format!(
                "persistent CPU repair state needs {persistent_bytes} bytes, exceeding the {limit} byte memory limit"
            ),
        }
    })?;
    let mut chunk_words = word_count;
    loop {
        let controller = cpu_controller_plan(
            chunk_words.saturating_mul(2),
            plan.missing_slices.len(),
            workers,
            method,
            allocated_staging_width,
        );
        if controller.buffer_accounting().total_bytes <= controller_budget {
            return Ok((chunk_words, limit, controller));
        }
        if chunk_words == 1 {
            return Err(Par2Error::ResourceLimitExceeded {
                reason: format!(
                    "CPU repair controller needs at least {} bytes, leaving {} bytes after persistent state",
                    controller.buffer_accounting().total_bytes,
                    controller_budget
                ),
            });
        }
        chunk_words = chunk_words.div_ceil(2);
    }
}

fn build_write_targets(
    plan: &RepairPlan,
    par2_set: &Par2FileSet,
) -> Result<Vec<RepairWriteTarget>> {
    plan.missing_slices
        .iter()
        .map(|(file_id, local_slice)| {
            let desc =
                par2_set
                    .file_description(file_id)
                    .ok_or_else(|| Par2Error::ReedSolomonError {
                        reason: format!("file description not found for {file_id}"),
                    })?;
            Ok(RepairWriteTarget {
                file_id: *file_id,
                filename: desc.filename.clone(),
                offset: *local_slice as u64 * plan.slice_size,
                file_end: desc.length,
            })
        })
        .collect()
}

fn grouped_input_factors(coefficients: &matrix::Matrix) -> Vec<Vec<FactorIndex>> {
    (0..coefficients.rows)
        .map(|row_idx| {
            coefficients
                .row(row_idx)
                .iter()
                .enumerate()
                .filter_map(|(input_idx, &factor)| {
                    if factor == 0 {
                        None
                    } else {
                        Some(FactorIndex {
                            factor,
                            input_idx: input_idx as u16,
                        })
                    }
                })
                .collect()
        })
        .collect()
}

// Cache-tile preferences are scheduling capabilities, not correctness limits.
const PLAIN_IDEAL_CHUNK_BYTES: usize = 32 * 1024;
const FOLDED_IDEAL_CHUNK_BYTES: usize = 8 * 1024;
#[cfg(target_arch = "x86_64")]
const XORJIT_AVX2_IDEAL_CHUNK_BYTES: usize = 128 * 1024;
#[cfg(target_arch = "x86_64")]
const XORJIT_AVX512_IDEAL_CHUNK_BYTES: usize = 48 * 1024;

/// 64-byte-aligned backing for the folded staging streams so every 32-byte
/// block sits cache-line aligned.
#[repr(C, align(64))]
#[derive(Clone, Copy)]
struct StagingCell([u8; 64]);

fn staging_cells_for(bytes: usize) -> Vec<StagingCell> {
    vec![StagingCell([0u8; 64]); bytes.div_ceil(64)]
}

fn staging_bytes(cells: &[StagingCell]) -> &[u8] {
    // Safe: StagingCell is a plain 64-byte array with alignment 64; viewing
    // the contiguous cell storage as bytes narrows alignment only.
    unsafe { std::slice::from_raw_parts(cells.as_ptr() as *const u8, cells.len() * 64) }
}

fn staging_bytes_mut(cells: &mut [StagingCell]) -> &mut [u8] {
    unsafe { std::slice::from_raw_parts_mut(cells.as_mut_ptr() as *mut u8, cells.len() * 64) }
}

/// Persistent chunk-major controller output area.
///
/// Within each compute chunk, all output regions are contiguous, keeping the
/// active input/output working set local to the worker before the transfer
/// thread gathers one output for writing.
struct AlignedOutputArea {
    cells: Vec<StagingCell>,
}

impl AlignedOutputArea {
    fn new(output_count: usize, byte_len: usize) -> Self {
        Self {
            cells: staging_cells_for(output_count.saturating_mul(byte_len)),
        }
    }

    fn base(&mut self) -> usize {
        self.cells.as_mut_ptr() as *mut u8 as usize
    }
}

/// Lazily prepared multiply tables, one slot per distinct GF(2^16) factor.
/// Entries are boxed so references handed to worker threads stay valid; the
/// memo is fully populated before any parallel compute runs.
struct MemoEntry {
    prepared: crate::gf_simd::PreparedInputFactor,
    /// Affine matrix forms for the GFNI folded split-layout kernel; only built
    /// when that path is active.
    affine: Option<crate::gf_simd::AffineMulMatrices>,
    /// Shuffle2x table forms for the non-GFNI AVX2 folded kernel; only built
    /// when that path (AVX2 without GFNI) is active.
    shuffle2x: Option<crate::gf_simd::Shuffle2xTables>,
}

struct PreparedFactorMemo {
    slots: Vec<Option<Box<MemoEntry>>>,
}

impl PreparedFactorMemo {
    fn from_matrix(matrix: &matrix::Matrix, with_folded: bool) -> Self {
        let mut slots: Vec<Option<Box<MemoEntry>>> = (0..1usize << 16).map(|_| None).collect();
        // The folded split layout is shared; the GFNI affine kernel and the
        // non-GFNI shuffle2x kernel consume it with different coefficient
        // forms, so build whichever the active kernel needs.
        let uses_gfni = with_folded && crate::gf_simd::folded_uses_gfni();
        let uses_shuffle2x = with_folded && !uses_gfni;
        // Factor 0 backs the padding lanes of partially filled groups.
        let ensure = |factor: u16, slots: &mut Vec<Option<Box<MemoEntry>>>| {
            let slot = &mut slots[factor as usize];
            if slot.is_none() {
                *slot = Some(Box::new(MemoEntry {
                    prepared: crate::gf_simd::prepare_input_factor(factor),
                    affine: uses_gfni.then(|| crate::gf_simd::precompute_affine_matrices(factor)),
                    shuffle2x: uses_shuffle2x
                        .then(|| crate::gf_simd::precompute_shuffle2x_tables(factor)),
                }));
            }
        };
        ensure(0, &mut slots);
        for output_idx in 0..matrix.rows {
            for source_idx in 0..matrix.cols {
                ensure(matrix.get(output_idx, source_idx), &mut slots);
            }
        }
        Self { slots }
    }

    #[inline]
    fn get(&self, factor: u16) -> &crate::gf_simd::PreparedInputFactor {
        &self.slots[factor as usize]
            .as_deref()
            .expect("factor prepared during memo construction")
            .prepared
    }

    #[inline]
    fn get_affine(&self, factor: u16) -> &crate::gf_simd::AffineMulMatrices {
        self.slots[factor as usize]
            .as_deref()
            .expect("factor prepared during memo construction")
            .affine
            .as_ref()
            .expect("affine matrices built for the folded path")
    }

    #[inline]
    fn get_shuffle2x(&self, factor: u16) -> &crate::gf_simd::Shuffle2xTables {
        self.slots[factor as usize]
            .as_deref()
            .expect("factor prepared during memo construction")
            .shuffle2x
            .as_ref()
            .expect("shuffle2x tables built for the folded path")
    }
}

/// XOR-JIT tier (x86_64, AVX2- or AVX512-without-GFNI): packed dispatch for
/// every controller batch/output row. The normal bounded mode rotates two
/// strict-W^X arenas. AVX2 may instead retain one immutable repair codebook
/// when it fits without reducing the controller's data chunk.
#[cfg(target_arch = "x86_64")]
enum JitDispatchStorage {
    RepairCodebook(Arc<reedsolomon_rs::xor_jit::packed::Avx2Codebook>),
    ActiveArenas { arena_limit: usize },
}

#[cfg(target_arch = "x86_64")]
struct JitMemo {
    width: reedsolomon_rs::xor_jit::JitWidth,
    input_grouping: usize,
    output_count: usize,
    storage: JitDispatchStorage,
    reserved_bytes: usize,
}

#[cfg(target_arch = "x86_64")]
impl JitMemo {
    fn new(
        width: reedsolomon_rs::xor_jit::JitWidth,
        method: CpuMethodContract,
        output_count: usize,
        repair_factors: &[u16],
        codebook_limit: usize,
        available_bytes: usize,
    ) -> std::result::Result<Self, reedsolomon_rs::xor_jit::packed::PackedBuildError> {
        if !method.strict_wx_available {
            return Err(
                reedsolomon_rs::xor_jit::packed::PackedBuildError::InvalidInput(
                    "XOR-JIT method contract lacks strict W^X capability",
                ),
            );
        }
        let input_grouping = method.input_grouping();
        let codebook = matches!(width, reedsolomon_rs::xor_jit::JitWidth::Avx2)
            .then(|| {
                reedsolomon_rs::xor_jit::packed::Avx2Codebook::build(repair_factors, codebook_limit)
            })
            .transpose();
        let (storage, reserved_bytes) = match codebook {
            Ok(Some(codebook)) => {
                let retained_bytes = codebook.retained_bytes();
                (JitDispatchStorage::RepairCodebook(codebook), retained_bytes)
            }
            Ok(None) | Err(reedsolomon_rs::xor_jit::packed::PackedBuildError::Resource { .. }) => {
                // Each controller staging area owns one immutable active
                // arena and returns it to RW only after all workers finish.
                let arena_limit =
                    reedsolomon_rs::xor_jit::packed::PackedJitBatch::active_arena_upper_bound(
                        width,
                        output_count,
                        input_grouping,
                    )
                    .ok_or(
                        reedsolomon_rs::xor_jit::packed::PackedBuildError::Resource {
                            requested_bytes: usize::MAX,
                            limit_bytes: available_bytes,
                        },
                    )?;
                let reserved_bytes = arena_limit.checked_mul(2).ok_or(
                    reedsolomon_rs::xor_jit::packed::PackedBuildError::Resource {
                        requested_bytes: usize::MAX,
                        limit_bytes: available_bytes,
                    },
                )?;
                if reserved_bytes > available_bytes {
                    return Err(
                        reedsolomon_rs::xor_jit::packed::PackedBuildError::Resource {
                            requested_bytes: reserved_bytes,
                            limit_bytes: available_bytes,
                        },
                    );
                }
                (
                    JitDispatchStorage::ActiveArenas { arena_limit },
                    reserved_bytes,
                )
            }
            Err(error) => return Err(error),
        };

        Ok(Self {
            width,
            input_grouping,
            output_count,
            storage,
            reserved_bytes,
        })
    }

    #[inline]
    fn get<'a>(
        &self,
        batch: &'a reedsolomon_rs::xor_jit::packed::PackedJitBatch,
        output: usize,
    ) -> &'a reedsolomon_rs::xor_jit::packed::PackedJitCode {
        batch
            .row(output)
            .expect("packed JIT row exists for every controller output")
    }

    fn build_active_batch(
        &self,
        set: &StreamBatchSet,
        workspace: &mut reedsolomon_rs::xor_jit::packed::PackedJitWorkspace,
    ) -> std::result::Result<
        reedsolomon_rs::xor_jit::packed::PackedJitBatch,
        reedsolomon_rs::xor_jit::packed::PackedBuildError,
    > {
        if set.input_grouping != self.input_grouping
            || set.coefficients.len() != self.output_count.saturating_mul(self.input_grouping)
        {
            return Err(
                reedsolomon_rs::xor_jit::packed::PackedBuildError::InvalidInput(
                    "controller coefficient batch shape does not match the JIT memo",
                ),
            );
        }
        let rows = set
            .coefficients
            .chunks_exact(self.input_grouping)
            .collect::<Vec<_>>();
        match &self.storage {
            JitDispatchStorage::RepairCodebook(codebook) => codebook.build_batch(&rows),
            JitDispatchStorage::ActiveArenas { arena_limit } => {
                workspace.build(self.width, &rows, *arena_limit)
            }
        }
    }

    #[inline]
    fn reserved_bytes(&self) -> usize {
        self.reserved_bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CpuKernelKind {
    Plain,
    Folded,
    #[cfg(target_arch = "x86_64")]
    XorJit(reedsolomon_rs::xor_jit::JitWidth),
}

impl CpuKernelKind {
    /// Complete method contract. Controller policy reads this value; the enum
    /// itself is only the arithmetic dispatch selector.
    fn method(self) -> CpuMethodContract {
        match self {
            Self::Plain => CpuMethodContract {
                stride: 2,
                alignment: 64,
                ideal_input_multiple: 1,
                staging_multiple: 1,
                ideal_chunk_size: PLAIN_IDEAL_CHUNK_BYTES,
                checksum_width: 2,
                prefetch: CpuPrefetch {
                    inputs_per_invoke: 0,
                    input_distance_shift: 0,
                    output: false,
                },
                strict_wx_available: false,
            },
            Self::Folded => CpuMethodContract {
                stride: crate::gf_simd::SPLIT_BLOCK_BYTES,
                alignment: 64,
                ideal_input_multiple: crate::gf_simd::FOLDED_GROUP,
                staging_multiple: crate::gf_simd::FOLDED_GROUP,
                ideal_chunk_size: FOLDED_IDEAL_CHUNK_BYTES,
                checksum_width: crate::gf_simd::SPLIT_BLOCK_BYTES,
                prefetch: CpuPrefetch {
                    inputs_per_invoke: 0,
                    input_distance_shift: 0,
                    output: false,
                },
                strict_wx_available: false,
            },
            #[cfg(target_arch = "x86_64")]
            Self::XorJit(width) => CpuMethodContract {
                stride: width.block_bytes(),
                alignment: match width {
                    reedsolomon_rs::xor_jit::JitWidth::Avx2 => 32,
                    reedsolomon_rs::xor_jit::JitWidth::Avx512 => 64,
                },
                ideal_input_multiple: match width {
                    reedsolomon_rs::xor_jit::JitWidth::Avx2 => 1,
                    reedsolomon_rs::xor_jit::JitWidth::Avx512 => 6,
                },
                staging_multiple: 1,
                ideal_chunk_size: match width {
                    reedsolomon_rs::xor_jit::JitWidth::Avx2 => XORJIT_AVX2_IDEAL_CHUNK_BYTES,
                    reedsolomon_rs::xor_jit::JitWidth::Avx512 => XORJIT_AVX512_IDEAL_CHUNK_BYTES,
                },
                checksum_width: width.block_bytes() / 16,
                prefetch: CpuPrefetch {
                    inputs_per_invoke: 1,
                    input_distance_shift: 1,
                    output: true,
                },
                strict_wx_available: reedsolomon_rs::xor_jit::strict_wx_available(),
            },
        }
    }
}

/// One double-buffered set of streamed source chunks. Which sources feed
/// which outputs is read directly from the decode matrix inside the compute
/// tasks — no gather lists are materialized.
struct StreamBatchSet {
    /// Per-source chunk buffers (generic kernel path).
    bufs: Vec<Vec<u8>>,
    /// XOR-JIT packed inputs in one persistent, aligned, chunk-major area.
    /// Each compute chunk contains contiguous source regions.
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    packed: Vec<StagingCell>,
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    packed_stride: usize,
    /// Folded path: per group of FOLDED_GROUP sources, their split-layout
    /// blocks interleaved at 32-byte granularity into one 64-byte-aligned
    /// stream.
    staging: Vec<Vec<StagingCell>>,
    /// Coefficients for this staged group, output-major with a fixed
    /// `input_grouping` stride. Unused lanes in a short final group are zero.
    coefficients: Vec<u16>,
    input_grouping: usize,
    start: usize,
    len: usize,
}

impl StreamBatchSet {
    fn new(
        max_byte_len: usize,
        input_grouping: usize,
        allocated_staging_width: usize,
        output_count: usize,
        folded: bool,
        xorjit: bool,
        gpu_staging: bool,
    ) -> Self {
        let groups = allocated_staging_width / crate::gf_simd::FOLDED_GROUP;
        let bufs = if gpu_staging || (!xorjit && !folded) {
            vec![vec![0u8; max_byte_len]; allocated_staging_width]
        } else {
            Vec::new()
        };
        let packed = if xorjit {
            staging_cells_for(allocated_staging_width.saturating_mul(max_byte_len))
        } else {
            Vec::new()
        };
        let staging = if folded {
            (0..groups)
                .map(|_| staging_cells_for(max_byte_len * crate::gf_simd::FOLDED_GROUP))
                .collect()
        } else {
            Vec::new()
        };
        Self {
            bufs,
            packed,
            packed_stride: max_byte_len,
            staging,
            coefficients: vec![0; output_count.saturating_mul(input_grouping)],
            input_grouping,
            start: 0,
            len: 0,
        }
    }

    #[inline]
    fn coefficient(&self, output: usize, lane: usize) -> u16 {
        self.coefficients[output * self.input_grouping + lane]
    }
}

/// Read one streamed source chunk (a present input slice range or a recovery
/// block range) into `dst`, zero-padding any short tail.
struct StreamSourceReader {
    file_id: FileId,
    reader: Box<dyn FileRangeReader>,
}

#[allow(clippy::too_many_arguments)]
fn read_stream_source_chunk(
    plan: &RepairPlan,
    par2_set: &Par2FileSet,
    file_access: &mut dyn FileAccess,
    recovery_files: &mut HashMap<PathBuf, File>,
    source_reader: &mut Option<StreamSourceReader>,
    available_inputs: usize,
    source_idx: usize,
    byte_start: usize,
    dst: &mut [u8],
) -> Result<()> {
    if source_idx < available_inputs {
        let global_idx = plan.available_input_global_indices[source_idx];
        let (file_id, local_slice) = plan.global_to_file[global_idx];
        let offset = local_slice as u64 * plan.slice_size + byte_start as u64;
        let file_length = par2_set
            .file_description(&file_id)
            .ok_or_else(|| Par2Error::ReedSolomonError {
                reason: format!("file description not found for {file_id}"),
            })?
            .length;
        let expected_len = file_length.saturating_sub(offset).min(dst.len() as u64) as usize;
        if source_reader
            .as_ref()
            .is_none_or(|open| open.file_id != file_id)
        {
            *source_reader = file_access
                .open_range_reader(&file_id)
                .map_err(Par2Error::Io)?
                .map(|reader| StreamSourceReader { file_id, reader });
        }
        if let Some(open) = source_reader.as_mut() {
            open.reader
                .seek(SeekFrom::Start(offset))
                .and_then(|_| open.reader.read_exact(&mut dst[..expected_len]))
                .map_err(Par2Error::Io)?;
        } else {
            let mut read_len = 0usize;
            while read_len < expected_len {
                let read = file_access
                    .read_file_range_into(
                        &file_id,
                        offset + read_len as u64,
                        &mut dst[read_len..expected_len],
                    )
                    .map_err(Par2Error::Io)?;
                if read == 0 {
                    return Err(Par2Error::Io(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        format!("source slice {file_id}:{local_slice} ended during repair"),
                    )));
                }
                read_len += read;
            }
        }
        dst[expected_len..].fill(0);
    } else {
        *source_reader = None;
        let exp = plan.recovery_exponents[source_idx - available_inputs];
        let rs = par2_set
            .recovery_slices
            .get(&exp)
            .ok_or_else(|| Par2Error::ReedSolomonError {
                reason: format!("recovery block with exponent {exp} not found"),
            })?;
        fill_recovery_chunk(&rs.data, byte_start, dst, recovery_files).map_err(Par2Error::Io)?;
    }
    Ok(())
}

fn prepare_stream_source(
    set: &mut StreamBatchSet,
    lane: usize,
    source: &[u8],
    aligned_len: usize,
    #[cfg(target_arch = "x86_64")] chunk_len: usize,
    #[cfg(not(target_arch = "x86_64"))] _chunk_len: usize,
    kernel: CpuKernelKind,
) {
    match kernel {
        #[cfg(target_arch = "x86_64")]
        CpuKernelKind::XorJit(width) => {
            let block = width.block_bytes();
            debug_assert_eq!(aligned_len % block, 0);
            debug_assert_eq!(chunk_len % block, 0);
            let num_chunks = aligned_len.div_ceil(chunk_len);
            let packed = staging_bytes_mut(&mut set.packed);
            for chunk in 0..num_chunks {
                let source_start = chunk * chunk_len;
                let source_len = (aligned_len - source_start).min(chunk_len);
                let lane_start = chunk
                    .saturating_mul(set.input_grouping)
                    .saturating_mul(chunk_len)
                    .saturating_add(lane.saturating_mul(source_len));
                packed[lane_start..lane_start + source_len].fill(0);
                for offset in (0..source_len).step_by(block) {
                    // SAFETY: XOR-JIT selection proves the required CPU
                    // features; source and destination are disjoint, aligned
                    // controller regions exactly one JIT block wide.
                    unsafe {
                        width.prepare_block(
                            &source[source_start + offset..source_start + offset + block],
                            &mut packed[lane_start + offset..lane_start + offset + block],
                        );
                    }
                }
            }
        }
        CpuKernelKind::Folded => {
            let group = lane / crate::gf_simd::FOLDED_GROUP;
            let group_lane = lane % crate::gf_simd::FOLDED_GROUP;
            crate::gf_simd::split_encode_scatter(
                &source[..aligned_len],
                staging_bytes_mut(&mut set.staging[group]),
                group_lane,
            );
        }
        CpuKernelKind::Plain => {}
    }
    if !set.bufs.is_empty() {
        set.bufs[lane][..aligned_len].copy_from_slice(&source[..aligned_len]);
    }
}

#[inline]
fn gf16_mul2(value: u16) -> u16 {
    (value << 1) ^ if value & 0x8000 != 0 { 0x100b } else { 0 }
}

fn update_packed_checksum(checksum: &mut [u8], block: &[u8]) {
    debug_assert_eq!(checksum.len() % 2, 0);
    debug_assert_eq!(block.len() % checksum.len(), 0);
    let width = checksum.len();
    for lane in (0..width).step_by(2) {
        let mut folded = 0u16;
        for region in block.chunks_exact(width) {
            folded ^= u16::from_le_bytes([region[lane], region[lane + 1]]);
        }
        let previous = u16::from_le_bytes([checksum[lane], checksum[lane + 1]]);
        checksum[lane..lane + 2].copy_from_slice(&(gf16_mul2(previous) ^ folded).to_le_bytes());
    }
}

fn write_packed_checksum(
    buffer: &mut [u8],
    data_len: usize,
    block_len: usize,
    checksum_width: usize,
) {
    debug_assert_eq!(data_len % block_len, 0);
    debug_assert!(checksum_width <= block_len);
    debug_assert_eq!(block_len % checksum_width, 0);
    let (data, checksum_block) = buffer.split_at_mut(data_len);
    let checksum_block = &mut checksum_block[..block_len];
    checksum_block.fill(0);
    for block in data.chunks_exact(block_len) {
        update_packed_checksum(&mut checksum_block[..checksum_width], block);
    }
}

fn packed_checksum_matches(
    buffer: &[u8],
    data_len: usize,
    block_len: usize,
    checksum_width: usize,
) -> bool {
    debug_assert_eq!(data_len % block_len, 0);
    debug_assert!(checksum_width <= 64);
    debug_assert!(checksum_width <= block_len);
    let (data, checksum_block) = buffer.split_at(data_len);
    let checksum_block = &checksum_block[..block_len];
    let mut expected = [0u8; 64];
    for block in data.chunks_exact(block_len) {
        update_packed_checksum(&mut expected[..checksum_width], block);
    }
    checksum_block[..checksum_width] == expected[..checksum_width]
        && checksum_block[checksum_width..]
            .iter()
            .all(|byte| *byte == 0)
}

struct PrepareBatch {
    set: StreamBatchSet,
    aligned_len: usize,
    chunk_len: usize,
    layout: Option<Arc<ControllerLayout>>,
}

struct PreparedControllerBatch {
    set: StreamBatchSet,
}

struct SubmittedControllerBatch<'a> {
    batch: crate::cpu_repair_controller::InputBatch,
    ticket: CpuComputeTicket<'a>,
}

#[derive(Clone, Copy)]
enum OutputTransferSource {
    Contiguous(usize),
    ChunkInterleaved {
        base: usize,
        output: usize,
        output_count: usize,
        chunk_len: usize,
    },
}

enum OutputTransferLayout<'a> {
    Contiguous(&'a [usize]),
    ChunkInterleaved {
        base: usize,
        output_count: usize,
        chunk_len: usize,
    },
}

impl OutputTransferLayout<'_> {
    fn len(&self) -> usize {
        match self {
            Self::Contiguous(outputs) => outputs.len(),
            Self::ChunkInterleaved { output_count, .. } => *output_count,
        }
    }

    fn source(&self, output: usize) -> OutputTransferSource {
        match self {
            Self::Contiguous(outputs) => OutputTransferSource::Contiguous(outputs[output]),
            Self::ChunkInterleaved {
                base,
                output_count,
                chunk_len,
            } => OutputTransferSource::ChunkInterleaved {
                base: *base,
                output,
                output_count: *output_count,
                chunk_len: *chunk_len,
            },
        }
    }
}

enum PreparationMessage {
    Begin(PrepareBatch),
    Input {
        lane: usize,
        coefficients: Vec<u16>,
        buffer: TransferBuffer,
        submitted: Option<crate::cpu_repair_controller::InputBatch>,
    },
    Flush {
        batch: crate::cpu_repair_controller::InputBatch,
    },
    #[cfg(target_arch = "x86_64")]
    RecycleJit {
        staging_area: usize,
        batch: reedsolomon_rs::xor_jit::packed::PackedJitBatch,
    },
    FinishOutput {
        index: usize,
        source: OutputTransferSource,
        aligned_len: usize,
        buffer: TransferBuffer,
    },
}

/// One of two controller-owned transfer buffers. The slot identity survives
/// preparation and output finishing so a completion cannot duplicate or
/// replace a checked-out buffer.
struct TransferBuffer {
    slot: usize,
    bytes: Vec<u8>,
}

struct FinishedOutput {
    index: usize,
    buffer: TransferBuffer,
    checksum_valid: bool,
    elapsed: Duration,
}

struct CpuInputPreparer<'a> {
    command_tx: std::sync::mpsc::SyncSender<PreparationMessage>,
    complete_rx: std::sync::mpsc::Receiver<TransferBuffer>,
    prepared_rx: std::sync::mpsc::Receiver<PreparedControllerBatch>,
    submitted_rx:
        std::sync::mpsc::Receiver<std::result::Result<SubmittedControllerBatch<'a>, String>>,
    finished_rx: std::sync::mpsc::Receiver<FinishedOutput>,
    transfer_buffers: [Option<TransferBuffer>; 2],
    transfer_buffer_len: usize,
}

impl CpuInputPreparer<'_> {
    fn take_transfer_buffer(
        &mut self,
        cancel: Option<&CancellationToken>,
    ) -> Result<TransferBuffer> {
        if let Some(buffer) = self.transfer_buffers.iter_mut().find_map(Option::take) {
            return Ok(buffer);
        }

        let buffer = recv_with_cancel(
            &self.complete_rx,
            cancel,
            "CPU repair preparation worker stopped unexpectedly",
        )?;
        self.validate_transfer_buffer(&buffer)?;
        Ok(buffer)
    }

    fn return_transfer_buffer(&mut self, buffer: TransferBuffer) -> Result<()> {
        self.validate_transfer_buffer(&buffer)?;
        let slot = buffer.slot;
        let Some(destination) = self.transfer_buffers.get_mut(slot) else {
            return Err(Par2Error::ReedSolomonError {
                reason: format!("CPU repair transfer buffer returned unknown slot {slot}"),
            });
        };
        if destination.is_some() {
            return Err(Par2Error::ReedSolomonError {
                reason: format!("CPU repair transfer buffer slot {slot} was returned twice"),
            });
        }
        *destination = Some(buffer);
        Ok(())
    }

    fn restore_transfer_buffers(&mut self, cancel: Option<&CancellationToken>) -> Result<()> {
        while self.transfer_buffers.iter().any(Option::is_none) {
            let buffer = recv_with_cancel(
                &self.complete_rx,
                cancel,
                "CPU repair preparation worker stopped unexpectedly",
            )?;
            self.return_transfer_buffer(buffer)?;
        }
        Ok(())
    }

    fn validate_transfer_buffer(&self, buffer: &TransferBuffer) -> Result<()> {
        if buffer.slot >= self.transfer_buffers.len() {
            return Err(Par2Error::ReedSolomonError {
                reason: format!(
                    "CPU repair transfer buffer returned unknown slot {}",
                    buffer.slot
                ),
            });
        }
        if buffer.bytes.len() != self.transfer_buffer_len {
            return Err(Par2Error::ReedSolomonError {
                reason: format!(
                    "CPU repair transfer buffer slot {} has {} bytes; expected {}",
                    buffer.slot,
                    buffer.bytes.len(),
                    self.transfer_buffer_len
                ),
            });
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn run_preparation_worker<'a>(
    command_rx: std::sync::mpsc::Receiver<PreparationMessage>,
    complete_tx: std::sync::mpsc::SyncSender<TransferBuffer>,
    prepared_tx: std::sync::mpsc::SyncSender<PreparedControllerBatch>,
    submitted_tx: std::sync::mpsc::SyncSender<
        std::result::Result<SubmittedControllerBatch<'a>, String>,
    >,
    finished_tx: std::sync::mpsc::SyncSender<FinishedOutput>,
    kernel: CpuKernelKind,
    method: CpuMethodContract,
    output_base: usize,
    output_count: usize,
    memo: &'a PreparedFactorMemo,
    #[cfg(target_arch = "x86_64")] jit_memo: Option<&'a JitMemo>,
    timings: &'a CpuControllerTimings,
    mut compute_submitter: CpuComputeSubmitter<'a>,
    trace: ControllerExecutionTrace,
) {
    let mut active: Option<PrepareBatch> = None;
    #[cfg(target_arch = "x86_64")]
    let mut jit_workspaces = [
        reedsolomon_rs::xor_jit::packed::PackedJitWorkspace::default(),
        reedsolomon_rs::xor_jit::packed::PackedJitWorkspace::default(),
    ];
    while let Ok(message) = command_rx.recv() {
        match message {
            PreparationMessage::Begin(batch) => {
                debug_assert!(active.is_none());
                active = Some(batch);
            }
            PreparationMessage::Input {
                lane,
                coefficients,
                mut buffer,
                submitted,
            } => {
                let Some(batch) = active.as_mut() else {
                    trace.record(ControllerExecutionEvent::Failed {
                        phase: ControllerFailurePhase::Prepare,
                    });
                    break;
                };
                if coefficients.len() != batch.set.coefficients.len() / batch.set.input_grouping {
                    trace.record(ControllerExecutionEvent::Failed {
                        phase: ControllerFailurePhase::Prepare,
                    });
                    break;
                }
                for (output, coefficient) in coefficients.into_iter().enumerate() {
                    batch.set.coefficients[output * batch.set.input_grouping + lane] = coefficient;
                }
                let checksum_block_len = method.stride;
                write_packed_checksum(
                    &mut buffer.bytes[..batch.aligned_len],
                    batch.aligned_len - checksum_block_len,
                    checksum_block_len,
                    method.checksum_width,
                );
                prepare_stream_source(
                    &mut batch.set,
                    lane,
                    &buffer.bytes,
                    batch.aligned_len,
                    batch.chunk_len,
                    kernel,
                );
                let mut stop_after_buffer = false;
                if let Some(submitted) = submitted {
                    let mut batch = active.take().expect("active preparation batch");
                    if submitted.input_len != lane + 1
                        || submitted.staging_area >= 2
                        || submitted.input_start != batch.set.start
                    {
                        trace.record(ControllerExecutionEvent::Failed {
                            phase: ControllerFailurePhase::Prepare,
                        });
                        break;
                    }
                    batch.set.len = submitted.input_len;
                    let submitted_info = submitted;
                    if batch.layout.is_some() {
                        let submitted = submit_prepared_controller_batch(
                            submitted,
                            batch,
                            output_base,
                            output_count,
                            memo,
                            #[cfg(target_arch = "x86_64")]
                            jit_memo,
                            #[cfg(target_arch = "x86_64")]
                            &mut jit_workspaces,
                            method,
                            timings,
                            &trace,
                            &mut compute_submitter,
                        );
                        stop_after_buffer = submitted.is_err();
                        if submitted_tx.send(submitted).is_err() {
                            trace.record(ControllerExecutionEvent::Failed {
                                phase: ControllerFailurePhase::Prepare,
                            });
                            break;
                        }
                    } else if prepared_tx
                        .send(PreparedControllerBatch { set: batch.set })
                        .is_err()
                    {
                        trace.record(ControllerExecutionEvent::Failed {
                            phase: ControllerFailurePhase::Prepare,
                        });
                        break;
                    }
                    if !stop_after_buffer {
                        trace.record(ControllerExecutionEvent::PreparationCompleted {
                            staging_area: submitted_info.staging_area,
                            input_len: submitted_info.input_len,
                        });
                    }
                }
                // Launch the completed group before resolving the input future;
                // compute is already queued when this buffer is returned.
                if complete_tx.send(buffer).is_err() {
                    trace.record(ControllerExecutionEvent::Failed {
                        phase: ControllerFailurePhase::Prepare,
                    });
                    break;
                }
                if stop_after_buffer {
                    break;
                }
            }
            PreparationMessage::Flush { batch: submitted } => {
                let Some(mut batch) = active.take() else {
                    trace.record(ControllerExecutionEvent::Failed {
                        phase: ControllerFailurePhase::Prepare,
                    });
                    break;
                };
                if submitted.input_len == 0
                    || submitted.input_len > batch.set.input_grouping
                    || submitted.staging_area >= 2
                    || submitted.input_start != batch.set.start
                {
                    trace.record(ControllerExecutionEvent::Failed {
                        phase: ControllerFailurePhase::Prepare,
                    });
                    break;
                }
                batch.set.len = submitted.input_len;
                let submitted_info = submitted;
                let submitted = submit_prepared_controller_batch(
                    submitted,
                    batch,
                    output_base,
                    output_count,
                    memo,
                    #[cfg(target_arch = "x86_64")]
                    jit_memo,
                    #[cfg(target_arch = "x86_64")]
                    &mut jit_workspaces,
                    method,
                    timings,
                    &trace,
                    &mut compute_submitter,
                );
                let submit_failed = submitted.is_err();
                if submitted_tx.send(submitted).is_err() {
                    trace.record(ControllerExecutionEvent::Failed {
                        phase: ControllerFailurePhase::Prepare,
                    });
                    break;
                }
                if submit_failed {
                    break;
                }
                trace.record(ControllerExecutionEvent::PreparationCompleted {
                    staging_area: submitted_info.staging_area,
                    input_len: submitted_info.input_len,
                });
            }
            #[cfg(target_arch = "x86_64")]
            PreparationMessage::RecycleJit {
                staging_area,
                batch,
            } => {
                if staging_area >= jit_workspaces.len()
                    || jit_workspaces[staging_area].recycle(batch).is_err()
                {
                    trace.record(ControllerExecutionEvent::Failed {
                        phase: ControllerFailurePhase::Compute,
                    });
                    break;
                }
            }
            PreparationMessage::FinishOutput {
                index,
                source,
                aligned_len,
                mut buffer,
            } => {
                let started = Instant::now();
                debug_assert!(active.is_none());
                let validate_checksum =
                    matches!(&source, OutputTransferSource::ChunkInterleaved { .. });
                // SAFETY: output storage stays fixed until every queued finish
                // operation has completed and the transfer worker is joined.
                match source {
                    OutputTransferSource::Contiguous(source) => {
                        let source =
                            unsafe { std::slice::from_raw_parts(source as *const u8, aligned_len) };
                        buffer.bytes[..aligned_len].copy_from_slice(source);
                    }
                    OutputTransferSource::ChunkInterleaved {
                        base,
                        output,
                        output_count,
                        chunk_len,
                    } => {
                        let source = unsafe {
                            std::slice::from_raw_parts(
                                base as *const u8,
                                aligned_len.saturating_mul(output_count),
                            )
                        };
                        for chunk_start in (0..aligned_len).step_by(chunk_len) {
                            let len = (aligned_len - chunk_start).min(chunk_len);
                            let source_start = chunk_start * output_count + output * len;
                            buffer.bytes[chunk_start..chunk_start + len]
                                .copy_from_slice(&source[source_start..source_start + len]);
                        }
                    }
                }
                match kernel {
                    #[cfg(target_arch = "x86_64")]
                    CpuKernelKind::XorJit(width) => {
                        let block = width.block_bytes();
                        for start in (0..aligned_len).step_by(block) {
                            unsafe {
                                width.finish_block(&mut buffer.bytes[start..start + block]);
                            }
                        }
                    }
                    CpuKernelKind::Folded => {
                        crate::gf_simd::altmap_decode(&mut buffer.bytes[..aligned_len]);
                    }
                    CpuKernelKind::Plain => {}
                }
                let checksum_block_len = method.stride;
                let checksum_valid = !validate_checksum
                    || packed_checksum_matches(
                        &buffer.bytes[..aligned_len],
                        aligned_len - checksum_block_len,
                        checksum_block_len,
                        method.checksum_width,
                    );
                if finished_tx
                    .send(FinishedOutput {
                        index,
                        buffer,
                        checksum_valid,
                        elapsed: started.elapsed(),
                    })
                    .is_err()
                {
                    trace.record(ControllerExecutionEvent::Failed {
                        phase: ControllerFailurePhase::OutputTransfer,
                    });
                    break;
                }
            }
        }
    }
}

fn queue_output_finish(
    preparer: &mut CpuInputPreparer,
    index: usize,
    source: OutputTransferSource,
    aligned_len: usize,
    buffer: TransferBuffer,
    trace: &ControllerExecutionTrace,
) -> Result<()> {
    preparer
        .command_tx
        .send(PreparationMessage::FinishOutput {
            index,
            source,
            aligned_len,
            buffer,
        })
        .map_err(|_| {
            trace.record(ControllerExecutionEvent::Failed {
                phase: ControllerFailurePhase::OutputTransfer,
            });
            Par2Error::ReedSolomonError {
                reason: "CPU repair transfer worker stopped unexpectedly".to_string(),
            }
        })
}

#[allow(clippy::too_many_arguments)]
fn finish_and_write_stream_outputs(
    preparer: &mut CpuInputPreparer,
    outputs: OutputTransferLayout<'_>,
    aligned_len: usize,
    byte_start: usize,
    byte_len: usize,
    write_targets: &[RepairWriteTarget],
    file_access: &mut dyn FileAccess,
    options: &RepairOptions,
    #[cfg_attr(not(target_arch = "x86_64"), allow(unused_variables))]
    timings: &CpuControllerTimings,
    trace: &ControllerExecutionTrace,
) -> Result<()> {
    debug_assert_eq!(outputs.len(), write_targets.len());
    let initially_queued = outputs.len().min(2);
    for index in 0..initially_queued {
        let buffer = preparer.take_transfer_buffer(options.cancel.as_ref())?;
        queue_output_finish(
            preparer,
            index,
            outputs.source(index),
            aligned_len,
            buffer,
            trace,
        )?;
        trace.record(ControllerExecutionEvent::OutputTransferQueued { output: index });
    }

    let mut next_to_queue = initially_queued;
    for expected in 0..outputs.len() {
        let FinishedOutput {
            index,
            buffer,
            checksum_valid,
            elapsed,
        } = recv_with_cancel(
            &preparer.finished_rx,
            options.cancel.as_ref(),
            "CPU repair transfer worker stopped unexpectedly",
        )
        .inspect_err(|_| {
            trace.record(ControllerExecutionEvent::Failed {
                phase: ControllerFailurePhase::OutputTransfer,
            });
        })?;
        if index != expected {
            return Err(Par2Error::ReedSolomonError {
                reason: "CPU repair output transfer arrived out of order".to_string(),
            });
        }
        CpuControllerTimings::record(&timings.finish_ns, elapsed);
        check_cancel(options)?;
        if !checksum_valid {
            trace.record(ControllerExecutionEvent::Failed {
                phase: ControllerFailurePhase::OutputTransfer,
            });
            preparer.return_transfer_buffer(buffer)?;
            return Err(Par2Error::ReedSolomonError {
                reason: format!("CPU repair output {index} failed its packed checksum"),
            });
        }

        let target = &write_targets[index];
        let write_offset = target.offset + byte_start as u64;
        let remaining = target.file_end.saturating_sub(write_offset);
        let write_len = remaining.min(byte_len as u64) as usize;
        let write_started = Instant::now();
        if write_len != 0
            && let Err(error) = file_access.write_file_range(
                &target.file_id,
                write_offset,
                &buffer.bytes[..write_len],
            )
        {
            trace.record(ControllerExecutionEvent::Failed {
                phase: ControllerFailurePhase::Write,
            });
            return Err(Par2Error::RepairWriteFailed {
                filename: target.filename.clone(),
                offset: write_offset,
                source: error,
            });
        }
        CpuControllerTimings::record(&timings.write_ns, write_started.elapsed());
        trace.record(ControllerExecutionEvent::OutputWritten { output: index });

        if next_to_queue < outputs.len() {
            queue_output_finish(
                preparer,
                next_to_queue,
                outputs.source(next_to_queue),
                aligned_len,
                buffer,
                trace,
            )?;
            trace.record(ControllerExecutionEvent::OutputTransferQueued {
                output: next_to_queue,
            });
            next_to_queue += 1;
        } else {
            preparer.return_transfer_buffer(buffer)?;
        }
    }
    Ok(())
}

/// Read one complete GPU input group through the transfer worker. The CPU
/// controller uses the live per-source dispatcher below instead.
#[allow(clippy::too_many_arguments)]
fn fill_gpu_stream_batch(
    preparer: &mut CpuInputPreparer,
    mut set: StreamBatchSet,
    plan: &RepairPlan,
    par2_set: &Par2FileSet,
    file_access: &mut dyn FileAccess,
    recovery_files: &mut HashMap<PathBuf, File>,
    source_reader: &mut Option<StreamSourceReader>,
    available_inputs: usize,
    batch_start: usize,
    batch_len: usize,
    byte_start: usize,
    byte_len: usize,
    aligned_len: usize,
    chunk_len: usize,
    chunk_count: usize,
    options: &RepairOptions,
    timings: &CpuControllerTimings,
) -> Result<StreamBatchSet> {
    set.start = batch_start;
    set.len = batch_len;
    set.packed_stride = chunk_len;
    debug_assert_eq!(chunk_count, aligned_len.div_ceil(chunk_len));
    set.coefficients.fill(0);

    let started = Instant::now();
    preparer
        .command_tx
        .send(PreparationMessage::Begin(PrepareBatch {
            set,
            aligned_len,
            chunk_len,
            layout: None,
        }))
        .map_err(|_| Par2Error::ReedSolomonError {
            reason: "CPU repair preparation worker stopped unexpectedly".to_string(),
        })?;
    for lane in 0..batch_len {
        check_cancel(options)?;
        let mut buffer = preparer.take_transfer_buffer(options.cancel.as_ref())?;
        read_stream_source_chunk(
            plan,
            par2_set,
            file_access,
            recovery_files,
            source_reader,
            available_inputs,
            batch_start + lane,
            byte_start,
            &mut buffer.bytes[..byte_len],
        )?;
        buffer.bytes[byte_len..aligned_len].fill(0);
        let coefficients = (0..plan.input_factors.rows)
            .map(|output| plan.input_factors.get(output, batch_start + lane))
            .collect();
        preparer
            .command_tx
            .send(PreparationMessage::Input {
                lane,
                coefficients,
                buffer,
                submitted: (lane + 1 == batch_len).then_some(
                    crate::cpu_repair_controller::InputBatch {
                        staging_area: 0,
                        input_start: batch_start,
                        input_len: batch_len,
                        add: false,
                        reason: crate::cpu_repair_controller::BatchSubmitReason::GroupFull,
                    },
                ),
            })
            .map_err(|_| Par2Error::ReedSolomonError {
                reason: "CPU repair preparation worker stopped unexpectedly".to_string(),
            })?;
    }
    preparer.restore_transfer_buffers(options.cancel.as_ref())?;
    let result = recv_with_cancel(
        &preparer.prepared_rx,
        options.cancel.as_ref(),
        "CPU repair preparation worker stopped unexpectedly",
    );
    CpuControllerTimings::record(&timings.read_prepare_ns, started.elapsed());
    result.map(|prepared| prepared.set)
}

/// Start one controller staging area. Inputs are admitted individually by
/// [`queue_live_stream_input`] rather than filling a group before the
/// lifecycle sees it.
fn begin_live_stream_batch(
    preparer: &CpuInputPreparer,
    mut set: StreamBatchSet,
    input_start: usize,
    aligned_len: usize,
    chunk_len: usize,
    layout: Arc<ControllerLayout>,
    trace: &ControllerExecutionTrace,
) -> Result<()> {
    set.start = input_start;
    set.len = 0;
    set.packed_stride = chunk_len;
    set.coefficients.fill(0);
    preparer
        .command_tx
        .send(PreparationMessage::Begin(PrepareBatch {
            set,
            aligned_len,
            chunk_len,
            layout: Some(layout),
        }))
        .map_err(|_| {
            trace.record(ControllerExecutionEvent::Failed {
                phase: ControllerFailurePhase::Prepare,
            });
            Par2Error::ReedSolomonError {
                reason: "CPU repair preparation worker stopped unexpectedly".to_string(),
            }
        })
}

/// Fill one transfer buffer before waiting for the destination staging area.
/// This keeps disk work overlapped with the older active batch.
#[allow(clippy::too_many_arguments)]
fn read_live_stream_input(
    preparer: &mut CpuInputPreparer,
    plan: &RepairPlan,
    par2_set: &Par2FileSet,
    file_access: &mut dyn FileAccess,
    recovery_files: &mut HashMap<PathBuf, File>,
    source_reader: &mut Option<StreamSourceReader>,
    available_inputs: usize,
    source_index: usize,
    mut buffer: TransferBuffer,
    staging_area: usize,
    byte_start: usize,
    byte_len: usize,
    aligned_len: usize,
    options: &RepairOptions,
    trace: &ControllerExecutionTrace,
) -> Result<TransferBuffer> {
    check_cancel(options)?;
    if let Err(error) = read_stream_source_chunk(
        plan,
        par2_set,
        file_access,
        recovery_files,
        source_reader,
        available_inputs,
        source_index,
        byte_start,
        &mut buffer.bytes[..byte_len],
    ) {
        trace.record(ControllerExecutionEvent::Failed {
            phase: ControllerFailurePhase::Read,
        });
        preparer.return_transfer_buffer(buffer)?;
        return Err(error);
    }
    buffer.bytes[byte_len..aligned_len].fill(0);
    trace.record(ControllerExecutionEvent::SourceRead {
        source_index,
        staging_area,
    });
    Ok(buffer)
}

/// Admit and dispatch a source whose transfer-buffer read has already
/// completed. The caller has cleared any controller backpressure first.
fn queue_live_stream_input(
    preparer: &mut CpuInputPreparer,
    lifecycle: &mut ControllerLifecycle,
    plan: &RepairPlan,
    source_index: usize,
    buffer: TransferBuffer,
    trace: &ControllerExecutionTrace,
) -> Result<(usize, Option<InputBatch>)> {
    let expected_area = lifecycle.current_staging_area;
    let ControllerAddResult::Accepted {
        staging_area,
        slot,
        submitted,
    } = lifecycle.add_input(false)
    else {
        preparer.return_transfer_buffer(buffer)?;
        return Err(Par2Error::ReedSolomonError {
            reason: "CPU repair controller accepted a source while its staging area was full"
                .to_string(),
        });
    };
    if staging_area != expected_area {
        preparer.return_transfer_buffer(buffer)?;
        return Err(Par2Error::ReedSolomonError {
            reason: format!(
                "CPU repair controller changed staging area while admitting source {source_index}"
            ),
        });
    }
    let coefficients = (0..plan.input_factors.rows)
        .map(|output| plan.input_factors.get(output, source_index))
        .collect();
    preparer
        .command_tx
        .send(PreparationMessage::Input {
            lane: slot,
            coefficients,
            buffer,
            submitted,
        })
        .map_err(|_| {
            trace.record(ControllerExecutionEvent::Failed {
                phase: ControllerFailurePhase::Prepare,
            });
            Par2Error::ReedSolomonError {
                reason: "CPU repair preparation worker stopped unexpectedly".to_string(),
            }
        })?;
    trace.record(ControllerExecutionEvent::InputQueued {
        source_index,
        staging_area,
        slot,
    });
    Ok((staging_area, submitted))
}

fn flush_live_stream_batch(
    preparer: &CpuInputPreparer,
    batch: InputBatch,
    trace: &ControllerExecutionTrace,
) -> Result<()> {
    preparer
        .command_tx
        .send(PreparationMessage::Flush { batch })
        .map_err(|_| {
            trace.record(ControllerExecutionEvent::Failed {
                phase: ControllerFailurePhase::Prepare,
            });
            Par2Error::ReedSolomonError {
                reason: "CPU repair preparation worker stopped unexpectedly".to_string(),
            }
        })
}

enum FoldedBatchCoefficients<'a> {
    None,
    Gfni(Vec<[&'a crate::gf_simd::AffineMulMatrices; crate::gf_simd::FOLDED_GROUP]>),
    Shuffle2x(Vec<[&'a crate::gf_simd::Shuffle2xTables; crate::gf_simd::FOLDED_GROUP]>),
}

impl<'a> FoldedBatchCoefficients<'a> {
    fn prepare(set: &StreamBatchSet, memo: &'a PreparedFactorMemo, output_count: usize) -> Self {
        if set.staging.is_empty() {
            return Self::None;
        }
        let groups = set.len.div_ceil(crate::gf_simd::FOLDED_GROUP);
        if crate::gf_simd::folded_uses_gfni() {
            let mut matrices = Vec::with_capacity(output_count * groups);
            for output in 0..output_count {
                for group in 0..groups {
                    matrices.push(std::array::from_fn(|lane| {
                        let input = group * crate::gf_simd::FOLDED_GROUP + lane;
                        memo.get_affine(if input < set.len {
                            set.coefficient(output, input)
                        } else {
                            0
                        })
                    }));
                }
            }
            Self::Gfni(matrices)
        } else {
            let mut tables = Vec::with_capacity(output_count * groups);
            for output in 0..output_count {
                for group in 0..groups {
                    tables.push(std::array::from_fn(|lane| {
                        let input = group * crate::gf_simd::FOLDED_GROUP + lane;
                        memo.get_shuffle2x(if input < set.len {
                            set.coefficient(output, input)
                        } else {
                            0
                        })
                    }));
                }
            }
            Self::Shuffle2x(tables)
        }
    }
}

struct CpuComputeContext<'a> {
    output_base: usize,
    output_count: usize,
    set: StreamBatchSet,
    memo: &'a PreparedFactorMemo,
    #[cfg(target_arch = "x86_64")]
    jit_memo: Option<&'a JitMemo>,
    #[cfg(target_arch = "x86_64")]
    jit_batch: Option<reedsolomon_rs::xor_jit::packed::PackedJitBatch>,
    layout: Arc<ControllerLayout>,
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    method: CpuMethodContract,
    trace: ControllerExecutionTrace,
    folded_coefficients: FoldedBatchCoefficients<'a>,
    add: bool,
}

#[inline]
unsafe fn interleaved_output_ptr(
    base: usize,
    output_count: usize,
    output: usize,
    chunk_start: usize,
    chunk_len: usize,
) -> *mut u8 {
    unsafe { (base as *mut u8).add(chunk_start * output_count + output * chunk_len) }
}

#[derive(Clone, Copy)]
struct CpuPlainSource {
    factor: u16,
    src: *const u8,
    len: usize,
}

#[derive(Clone, Copy)]
struct CpuFoldedStaging {
    src: *const u8,
    len: usize,
}

#[derive(Default)]
struct CpuWorkerScratch {
    active_inputs: Vec<usize>,
    plain_sources: Vec<CpuPlainSource>,
    folded_stagings: Vec<CpuFoldedStaging>,
    #[cfg(target_arch = "x86_64")]
    packed_scratch: reedsolomon_rs::xor_jit::packed::PackedScratch,
}

#[inline]
fn xor_into(dst: &mut [u8], source: &[u8]) {
    for (out, input) in dst.iter_mut().zip(source.iter().copied()) {
        *out ^= input;
    }
}

#[inline]
fn xor_folded_group_into(dst: &mut [u8], staging: &[u8], active_lanes: usize) {
    debug_assert_eq!(staging.len(), dst.len() * crate::gf_simd::FOLDED_GROUP);
    debug_assert!(active_lanes <= crate::gf_simd::FOLDED_GROUP);
    for (block, dst_block) in dst
        .chunks_exact_mut(crate::gf_simd::SPLIT_BLOCK_BYTES)
        .enumerate()
    {
        let staging_block =
            block * crate::gf_simd::FOLDED_GROUP * crate::gf_simd::SPLIT_BLOCK_BYTES;
        for lane in 0..active_lanes {
            let start = staging_block + lane * crate::gf_simd::SPLIT_BLOCK_BYTES;
            xor_into(
                dst_block,
                &staging[start..start + crate::gf_simd::SPLIT_BLOCK_BYTES],
            );
        }
    }
}

fn run_cpu_worker(
    worker: usize,
    context: &CpuComputeContext<'_>,
    scratch: &mut CpuWorkerScratch,
) -> std::result::Result<(), String> {
    scratch.plain_sources.clear();
    scratch.folded_stagings.clear();
    #[cfg(target_arch = "x86_64")]
    if let Some(jit_memo) = context.jit_memo {
        let width = jit_memo.width;
        let jit_batch = context
            .jit_batch
            .as_ref()
            .expect("XOR-JIT compute context owns an active coefficient batch");
        let packed = staging_bytes(&context.set.packed).as_ptr();
        debug_assert_eq!(context.layout.aligned_len % width.block_bytes(), 0);
        debug_assert_eq!(context.layout.chunk_len, context.set.packed_stride);
        let packed_regions = context.set.input_grouping;
        let packed_chunk_bytes = packed_regions * context.set.packed_stride;
        for work in context
            .layout
            .assignments
            .iter()
            .filter(|work| work.worker == worker)
        {
            let work_end = work.byte_start + work.byte_len;
            let mut byte_start = work.byte_start;
            while byte_start < work_end {
                let chunk_index = byte_start / context.layout.chunk_len;
                let chunk_len = (work_end - byte_start).min(context.layout.chunk_len);
                let packed_chunk = unsafe { packed.add(chunk_index * packed_chunk_bytes) };
                let local_output_count = work.output_len;
                let prefetch = context.method.prefetch;
                let ideal_input_multiple = context.method.ideal_input_multiple.max(1);
                let pf_factor = prefetch.input_distance_shift;
                let mut inputs_prefetched_per_invoke = (context.set.len / ideal_input_multiple)
                    .saturating_mul(prefetch.inputs_per_invoke);
                let mut input_prefetch_out_offset = local_output_count.saturating_sub(1);
                if inputs_prefetched_per_invoke > 0
                    && inputs_prefetched_per_invoke > (1usize << pf_factor)
                {
                    inputs_prefetched_per_invoke -= 1usize << pf_factor;
                    inputs_prefetched_per_invoke <<= 3 - pf_factor;
                    let input_prefetch_passes =
                        (context.set.len << 3).div_ceil(inputs_prefetched_per_invoke);
                    input_prefetch_out_offset =
                        local_output_count.saturating_sub(input_prefetch_passes);
                }
                // Prefetch input only between rounds owned by this worker
                // request, never across an assignment boundary.
                let next_packed_chunk = (byte_start + chunk_len < work_end)
                    .then(|| unsafe { packed.add((chunk_index + 1) * packed_chunk_bytes) });
                for (local_output, output) in
                    (work.output_start..work.output_start + work.output_len).enumerate()
                {
                    let dst = unsafe {
                        interleaved_output_ptr(
                            context.output_base,
                            context.output_count,
                            output,
                            byte_start,
                            chunk_len,
                        )
                    };
                    if !context.add {
                        unsafe { std::slice::from_raw_parts_mut(dst, chunk_len) }.fill(0);
                    }
                    let prefetch_in = if local_output >= input_prefetch_out_offset {
                        next_packed_chunk.map(|next| unsafe {
                            next.add(
                                (inputs_prefetched_per_invoke
                                    .saturating_mul(local_output - input_prefetch_out_offset)
                                    .saturating_mul(chunk_len))
                                    >> 3,
                            )
                        })
                    } else {
                        None
                    };
                    let prefetch_out = (prefetch.output && local_output + 1 < work.output_len)
                        .then(|| unsafe { dst.add(chunk_len) as *const u8 });
                    unsafe {
                        jit_memo
                            .get(jit_batch, output)
                            .try_run_with_scratch(
                            &mut scratch.packed_scratch,
                            reedsolomon_rs::xor_jit::packed::PackedRun {
                                packed_regions,
                                live_regions: context.set.len,
                                dst,
                                src: packed_chunk,
                                len: chunk_len,
                                prefetch_in,
                                prefetch_out,
                            },
                        )
                        .map_err(|error| {
                            format!(
                                "XOR-JIT packed dispatch failed in worker {worker}, output {output}: {error}"
                            )
                        })?;
                    }
                }
                byte_start += chunk_len;
            }
        }
        return Ok(());
    }

    if !matches!(&context.folded_coefficients, FoldedBatchCoefficients::None) {
        let groups = context.set.len.div_ceil(crate::gf_simd::FOLDED_GROUP);
        for work in context
            .layout
            .assignments
            .iter()
            .filter(|work| work.worker == worker)
        {
            let work_end = work.byte_start + work.byte_len;
            let mut byte_start = work.byte_start;
            while byte_start < work_end {
                let chunk_len = (work_end - byte_start).min(context.layout.chunk_len);
                let byte_end = byte_start + chunk_len;
                scratch.folded_stagings.clear();
                for group in 0..groups {
                    let staging = &staging_bytes(&context.set.staging[group])[byte_start
                        * crate::gf_simd::FOLDED_GROUP
                        ..byte_end * crate::gf_simd::FOLDED_GROUP];
                    scratch.folded_stagings.push(CpuFoldedStaging {
                        src: staging.as_ptr(),
                        len: staging.len(),
                    });
                }
                debug_assert!(groups <= 2);
                let mut staging_views: [&[u8]; 2] = [&[]; 2];
                for (group, source) in scratch.folded_stagings.iter().enumerate() {
                    staging_views[group] =
                        unsafe { std::slice::from_raw_parts(source.src, source.len) };
                }
                for output in work.output_start..work.output_start + work.output_len {
                    let dst = unsafe {
                        std::slice::from_raw_parts_mut(
                            interleaved_output_ptr(
                                context.output_base,
                                context.output_count,
                                output,
                                byte_start,
                                chunk_len,
                            ),
                            chunk_len,
                        )
                    };
                    if !context.add {
                        dst.fill(0);
                    }
                    if (0..context.set.len).all(|input| context.set.coefficient(output, input) == 1)
                    {
                        for (group, source) in scratch.folded_stagings.iter().enumerate() {
                            let staging =
                                unsafe { std::slice::from_raw_parts(source.src, source.len) };
                            let active_lanes = context
                                .set
                                .len
                                .saturating_sub(group * crate::gf_simd::FOLDED_GROUP)
                                .min(crate::gf_simd::FOLDED_GROUP);
                            xor_folded_group_into(dst, staging, active_lanes);
                        }
                    } else {
                        match &context.folded_coefficients {
                            FoldedBatchCoefficients::Gfni(matrices) => {
                                let matrix_start = output * groups;
                                crate::gf_simd::mul_acc_folded_batch(
                                    dst,
                                    &staging_views[..groups],
                                    &matrices[matrix_start..matrix_start + groups],
                                );
                            }
                            FoldedBatchCoefficients::Shuffle2x(tables) => {
                                let table_start = output * groups;
                                crate::gf_simd::mul_acc_shuffle2x_batch(
                                    dst,
                                    &staging_views[..groups],
                                    &tables[table_start..table_start + groups],
                                );
                            }
                            FoldedBatchCoefficients::None => unreachable!(),
                        }
                    }
                }
                byte_start = byte_end;
            }
        }
        scratch.folded_stagings.clear();
        return Ok(());
    }

    for work in context
        .layout
        .assignments
        .iter()
        .filter(|work| work.worker == worker)
    {
        let work_end = work.byte_start + work.byte_len;
        let mut byte_start = work.byte_start;
        while byte_start < work_end {
            let chunk_len = (work_end - byte_start).min(context.layout.chunk_len);
            let byte_end = byte_start + chunk_len;
            for output in work.output_start..work.output_start + work.output_len {
                scratch.plain_sources.clear();
                scratch.active_inputs.clear();
                scratch.active_inputs.extend(
                    (0..context.set.len)
                        .filter(|input| context.set.coefficient(output, *input) != 0),
                );
                for &input in &scratch.active_inputs {
                    let factor = context.set.coefficient(output, input);
                    let source = &context.set.bufs[input][byte_start..byte_end];
                    scratch.plain_sources.push(CpuPlainSource {
                        factor,
                        src: source.as_ptr(),
                        len: source.len(),
                    });
                }
                let dst = unsafe {
                    std::slice::from_raw_parts_mut(
                        interleaved_output_ptr(
                            context.output_base,
                            context.output_count,
                            output,
                            byte_start,
                            chunk_len,
                        ),
                        chunk_len,
                    )
                };
                if !context.add {
                    dst.fill(0);
                }
                if !scratch.plain_sources.is_empty() {
                    let all_one = scratch
                        .active_inputs
                        .iter()
                        .all(|&input| context.set.coefficient(output, input) == 1);
                    if all_one {
                        for source in &scratch.plain_sources {
                            let source =
                                unsafe { std::slice::from_raw_parts(source.src, source.len) };
                            xor_into(dst, source);
                        }
                    } else {
                        debug_assert!(scratch.plain_sources.len() <= CPU_CONTROLLER_BUDGET_INPUTS);
                        let mut prepared: [MaybeUninit<crate::gf_simd::PreparedFactorSrc<'_>>;
                            CPU_CONTROLLER_BUDGET_INPUTS] =
                            std::array::from_fn(|_| MaybeUninit::uninit());
                        for (index, source) in scratch.plain_sources.iter().enumerate() {
                            let source_bytes =
                                unsafe { std::slice::from_raw_parts(source.src, source.len) };
                            prepared[index].write(crate::gf_simd::PreparedFactorSrc {
                                prepared: context.memo.get(source.factor),
                                src: source_bytes,
                            });
                        }
                        // SAFETY: every prefix element is initialized above, and
                        // the view lives only for this backend call.
                        let prepared = unsafe {
                            std::slice::from_raw_parts(
                                prepared
                                    .as_ptr()
                                    .cast::<crate::gf_simd::PreparedFactorSrc<'_>>(),
                                scratch.plain_sources.len(),
                            )
                        };
                        crate::gf_simd::mul_acc_input_batch_prepared(dst, prepared);
                    }
                }
            }
            byte_start = byte_end;
        }
    }
    scratch.plain_sources.clear();
    Ok(())
}

struct CpuComputeJob<'a> {
    id: u64,
    context: Arc<CpuComputeContext<'a>>,
}

struct CpuComputeCompletion {
    id: u64,
    worker: usize,
    elapsed: Duration,
    failure: Option<String>,
}

struct CpuComputeTicket<'a> {
    id: u64,
    expected: usize,
    submission_failure: Option<String>,
    context: Arc<CpuComputeContext<'a>>,
}

struct CpuComputeSubmitter<'a> {
    senders: Vec<std::sync::mpsc::SyncSender<CpuComputeJob<'a>>>,
    next_id: u64,
}

struct CpuComputePool<'a> {
    completion_rx: std::sync::mpsc::Receiver<CpuComputeCompletion>,
    deferred: HashMap<u64, Vec<CpuComputeCompletion>>,
    _lifetime: std::marker::PhantomData<&'a ()>,
}

impl<'a> CpuComputeSubmitter<'a> {
    fn submit(&mut self, context: CpuComputeContext<'a>) -> CpuComputeTicket<'a> {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let context = Arc::new(context);
        let active_workers = context
            .layout
            .assignments
            .iter()
            .map(|work| work.worker)
            .max()
            .map_or(0, |worker| worker + 1);
        let mut expected = 0usize;
        let mut submission_failure = None;
        for sender in self.senders.iter().take(active_workers) {
            if sender
                .send(CpuComputeJob {
                    id,
                    context: Arc::clone(&context),
                })
                .is_err()
            {
                submission_failure =
                    Some("CPU repair compute worker stopped unexpectedly".to_string());
                break;
            }
            expected += 1;
        }
        CpuComputeTicket {
            id,
            expected,
            submission_failure,
            context,
        }
    }
}

impl<'a> CpuComputePool<'a> {
    fn wait(
        &mut self,
        ticket: CpuComputeTicket<'a>,
        cancel: Option<&CancellationToken>,
        timings: &CpuControllerTimings,
    ) -> Result<CpuComputeContext<'a>> {
        let CpuComputeTicket {
            id,
            expected,
            submission_failure,
            context,
        } = ticket;
        let mut max_elapsed = Duration::ZERO;
        let mut failure = submission_failure;
        let mut cancelled = cancel.is_some_and(|token| token.is_cancelled());
        let mut completions = self.deferred.remove(&id).unwrap_or_default();
        while completions.len() < expected {
            let completion = loop {
                match self.completion_rx.recv_timeout(Duration::from_millis(20)) {
                    Ok(completion) => break completion,
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        cancelled |= cancel.is_some_and(|token| token.is_cancelled());
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        return Err(Par2Error::ReedSolomonError {
                            reason: "CPU repair compute workers stopped unexpectedly".to_string(),
                        });
                    }
                }
            };
            if completion.id == id {
                completions.push(completion);
            } else {
                self.deferred
                    .entry(completion.id)
                    .or_default()
                    .push(completion);
            }
        }
        for completion in completions {
            cancelled |= cancel.is_some_and(|token| token.is_cancelled());
            max_elapsed = max_elapsed.max(completion.elapsed);
            if let Some(reason) = completion.failure {
                failure.get_or_insert_with(|| {
                    format!("CPU repair worker {} failed: {reason}", completion.worker)
                });
            }
        }
        CpuControllerTimings::record(&timings.compute_ns, max_elapsed);
        if cancelled {
            Err(Par2Error::Cancelled)
        } else if let Some(reason) = failure {
            Err(Par2Error::ReedSolomonError { reason })
        } else {
            Arc::try_unwrap(context).map_err(|_| Par2Error::ReedSolomonError {
                reason: "CPU repair batch remained active after worker completion".to_string(),
            })
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn submit_prepared_controller_batch<'a>(
    batch: InputBatch,
    prepared: PrepareBatch,
    output_base: usize,
    output_count: usize,
    memo: &'a PreparedFactorMemo,
    #[cfg(target_arch = "x86_64")] jit_memo: Option<&'a JitMemo>,
    #[cfg(target_arch = "x86_64")] jit_workspaces: &mut [reedsolomon_rs::xor_jit::packed::PackedJitWorkspace;
             2],
    method: CpuMethodContract,
    #[cfg_attr(not(target_arch = "x86_64"), allow(unused_variables))]
    timings: &CpuControllerTimings,
    trace: &ControllerExecutionTrace,
    compute_submitter: &mut CpuComputeSubmitter<'a>,
) -> std::result::Result<SubmittedControllerBatch<'a>, String> {
    let staging_area = batch.staging_area;
    let layout = prepared
        .layout
        .ok_or_else(|| "CPU repair batch is missing its controller layout".to_string())?;
    let folded_coefficients = FoldedBatchCoefficients::prepare(&prepared.set, memo, output_count);
    #[cfg(target_arch = "x86_64")]
    let jit_batch = if let Some(jit_memo) = jit_memo {
        let started = Instant::now();
        let built = jit_memo.build_active_batch(&prepared.set, &mut jit_workspaces[staging_area]);
        CpuControllerTimings::record(&timings.jit_prepare_ns, started.elapsed());
        Some(built.map_err(|error| {
            trace.record(ControllerExecutionEvent::Failed {
                phase: ControllerFailurePhase::Compute,
            });
            format!("XOR-JIT packed batch generation failed: {error}")
        })?)
    } else {
        None
    };
    let compute_context = CpuComputeContext {
        output_base,
        output_count,
        set: prepared.set,
        memo,
        #[cfg(target_arch = "x86_64")]
        jit_memo,
        #[cfg(target_arch = "x86_64")]
        jit_batch,
        layout,
        method,
        trace: trace.clone(),
        folded_coefficients,
        add: batch.add,
    };
    let ticket = compute_submitter.submit(compute_context);
    trace.record(ControllerExecutionEvent::ComputeSubmitted {
        staging_area,
        add: batch.add,
    });
    Ok(SubmittedControllerBatch { batch, ticket })
}

#[derive(Clone, Copy)]
enum SubmittedReceiveMode {
    ReadyOnly,
    Wait,
}

fn receive_submitted_controller_batch<'a>(
    mode: SubmittedReceiveMode,
    preparer: &CpuInputPreparer<'a>,
    options: &RepairOptions,
    pending_prepared: &mut [Option<InputBatch>; 2],
    preparing: &mut [bool; 2],
    trace: &ControllerExecutionTrace,
    active: &mut [Option<CpuComputeTicket<'a>>; 2],
) -> Result<bool> {
    let submitted = match mode {
        SubmittedReceiveMode::ReadyOnly => match preparer.submitted_rx.try_recv() {
            Ok(submitted) => submitted,
            Err(std::sync::mpsc::TryRecvError::Empty) => return Ok(false),
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                trace.record(ControllerExecutionEvent::Failed {
                    phase: ControllerFailurePhase::Prepare,
                });
                return Err(Par2Error::ReedSolomonError {
                    reason: "CPU repair preparation worker stopped unexpectedly".to_string(),
                });
            }
        },
        SubmittedReceiveMode::Wait => recv_with_cancel(
            &preparer.submitted_rx,
            options.cancel.as_ref(),
            "CPU repair preparation worker stopped unexpectedly",
        )
        .inspect_err(|_| {
            trace.record(ControllerExecutionEvent::Failed {
                phase: ControllerFailurePhase::Prepare,
            });
        })?,
    }
    .map_err(|reason| Par2Error::ReedSolomonError { reason })?;

    let staging_area = submitted.batch.staging_area;
    let expected = pending_prepared
        .get_mut(staging_area)
        .and_then(Option::take)
        .ok_or_else(|| Par2Error::ReedSolomonError {
            reason: format!(
                "CPU repair preparation completed unsubmitted staging area {staging_area}"
            ),
        })?;
    if submitted.batch != expected || !preparing[staging_area] {
        return Err(Par2Error::ReedSolomonError {
            reason: format!(
                "CPU repair preparation completed an unexpected batch for staging area {staging_area}"
            ),
        });
    }
    if active[staging_area].is_some() {
        return Err(Par2Error::ReedSolomonError {
            reason: format!("CPU repair controller submitted occupied staging area {staging_area}"),
        });
    }
    preparing[staging_area] = false;
    active[staging_area] = Some(submitted.ticket);
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
fn complete_active_controller_batch<'a>(
    staging_area: usize,
    _preparer: &CpuInputPreparer<'a>,
    compute_pool: &mut CpuComputePool<'a>,
    active: &mut [Option<CpuComputeTicket<'a>>; 2],
    batch_sets: &mut [Option<StreamBatchSet>; 2],
    lifecycle: &mut ControllerLifecycle,
    options: &RepairOptions,
    timings: &CpuControllerTimings,
    trace: &ControllerExecutionTrace,
) -> Result<()> {
    #[allow(unused_mut)]
    let mut finished = compute_pool.wait(
        active[staging_area]
            .take()
            .expect("active controller staging area has a ticket"),
        options.cancel.as_ref(),
        timings,
    )?;
    #[cfg(target_arch = "x86_64")]
    if let Some(jit_batch) = finished.jit_batch.take() {
        if jit_batch.requires_workspace_recycle() {
            _preparer
                .command_tx
                .send(PreparationMessage::RecycleJit {
                    staging_area,
                    batch: jit_batch,
                })
                .map_err(|_| Par2Error::ReedSolomonError {
                    reason: "CPU repair preparation worker stopped before recycling XOR-JIT state"
                        .to_string(),
                })?;
        }
    }
    batch_sets[staging_area] = Some(finished.set);
    lifecycle.complete_batch(staging_area);
    trace.record(ControllerExecutionEvent::ComputeCompleted { staging_area });
    Ok(())
}

fn run_compute_worker<'a>(
    worker: usize,
    receiver: std::sync::mpsc::Receiver<CpuComputeJob<'a>>,
    completion_tx: std::sync::mpsc::SyncSender<CpuComputeCompletion>,
) {
    let mut scratch = CpuWorkerScratch::default();
    while let Ok(job) = receiver.recv() {
        let CpuComputeJob { id, context } = job;
        let started = Instant::now();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_cpu_worker(worker, &context, &mut scratch)
        }));
        let failure = match result {
            Ok(Ok(())) => None,
            Ok(Err(reason)) => Some(reason),
            Err(_) => Some("kernel panicked".to_string()),
        };
        if failure.is_some() {
            context.trace.record(ControllerExecutionEvent::Failed {
                phase: ControllerFailurePhase::Compute,
            });
        }
        scratch.plain_sources.clear();
        scratch.folded_stagings.clear();
        // The completion means this worker has released every reference to
        // the staging area, so the controller may safely reuse it.
        drop(context);
        if completion_tx
            .send(CpuComputeCompletion {
                id,
                worker,
                elapsed: started.elapsed(),
                failure: failure.clone(),
            })
            .is_err()
        {
            break;
        }
        if failure.is_some() {
            break;
        }
    }
}

fn xor_out_known_data(
    recovery_buffers: &mut [Vec<u8>],
    recovery_factors: &[u16],
    data: &[u8],
    chunk_words: usize,
) {
    assert_eq!(
        recovery_buffers.len(),
        recovery_factors.len(),
        "recovery factor count must match recovery buffer count"
    );
    assert!(
        data.len().is_multiple_of(2),
        "PAR2 slice_size must be a multiple of 2"
    );

    let word_count = data.len() / 2;
    let chunk_words = chunk_words.max(1).min(word_count.max(1));
    let word_chunks: Vec<usize> = (0..word_count.max(1)).step_by(chunk_words).collect();
    let recovery_ptrs: Vec<usize> = recovery_buffers
        .iter_mut()
        .map(|recovery| recovery.as_mut_ptr() as usize)
        .collect();

    word_chunks.par_iter().for_each(|&chunk_start| {
        let chunk_end = (chunk_start + chunk_words).min(word_count);
        let byte_start = chunk_start * 2;
        let byte_len = (chunk_end - chunk_start) * 2;
        let src = &data[byte_start..byte_start + byte_len];

        for factor_start in (0..recovery_factors.len()).step_by(XOR_OUT_PAR_CHUNK) {
            let factor_end = (factor_start + XOR_OUT_PAR_CHUNK).min(recovery_factors.len());
            let mut pairs: Vec<crate::gf_simd::FactorDst<'_>> =
                Vec::with_capacity(factor_end - factor_start);

            for idx in factor_start..factor_end {
                let factor = recovery_factors[idx];
                if factor == 0 {
                    continue;
                }

                let dst = unsafe {
                    let ptr = recovery_ptrs[idx] as *mut u8;
                    std::slice::from_raw_parts_mut(ptr.add(byte_start), byte_len)
                };
                pairs.push(crate::gf_simd::FactorDst { factor, dst });
            }

            if !pairs.is_empty() {
                crate::gf_simd::mul_acc_multi_region(&mut pairs, src);
            }
        }
    });
}

fn read_exact_at_cached(
    files: &mut HashMap<PathBuf, File>,
    path: &Path,
    offset: u64,
    dst: &mut [u8],
) -> io::Result<()> {
    let file = if let Some(file) = files.get_mut(path) {
        file
    } else {
        files.insert(path.to_path_buf(), File::open(path)?);
        files.get_mut(path).expect("cached file should exist")
    };
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(dst)
}

fn fill_recovery_chunk(
    data: &crate::packet::RecoverySliceData,
    start: usize,
    dst: &mut [u8],
    file_cache: &mut HashMap<PathBuf, File>,
) -> io::Result<()> {
    dst.fill(0);

    if let Some(bytes) = data.as_bytes() {
        if start >= bytes.len() {
            return Ok(());
        }
        let end = (start + dst.len()).min(bytes.len());
        let copy_len = end - start;
        dst[..copy_len].copy_from_slice(&bytes[start..end]);
        return Ok(());
    }

    let Some((path, base_offset, len)) = data.file_span() else {
        return Ok(());
    };
    if start >= len {
        return Ok(());
    }

    let read_len = dst.len().min(len - start);
    read_exact_at_cached(
        file_cache,
        path,
        base_offset + start as u64,
        &mut dst[..read_len],
    )
}

/// Execute a repair plan, reading recovery data and writing repaired slices.
///
/// The algorithm:
/// 1. For each recovery block, read its data
/// 2. XOR out contributions from all *known* input slices
/// 3. Multiply the adjusted recovery data by the decode matrix to get missing slices
/// 4. Write repaired slices back to files
pub fn execute_repair(
    plan: &RepairPlan,
    par2_set: &Par2FileSet,
    file_access: &mut dyn FileAccess,
) -> Result<()> {
    execute_repair_with_options(plan, par2_set, file_access, &RepairOptions::default())
}

/// Load recovery block data into buffers, one per selected recovery exponent.
/// Each buffer is resized to `plan.slice_size`.
pub fn prepare_recovery_buffers(
    plan: &RepairPlan,
    par2_set: &Par2FileSet,
    options: &RepairOptions,
) -> Result<Vec<Vec<u8>>> {
    let n = plan.missing_slices.len();
    let slice_size = plan.slice_size as usize;

    let mut recovery_data: Vec<Vec<u8>> = Vec::with_capacity(n);
    for (i, &exp) in plan.recovery_exponents.iter().enumerate() {
        if let Some(ref cancel) = options.cancel
            && cancel.is_cancelled()
        {
            return Err(Par2Error::Cancelled);
        }
        let rs = par2_set
            .recovery_slices
            .get(&exp)
            .ok_or_else(|| Par2Error::ReedSolomonError {
                reason: format!("recovery block with exponent {exp} not found"),
            })?;
        let mut data = rs.data.to_vec().map_err(Par2Error::Io)?;
        data.resize(slice_size, 0);
        recovery_data.push(data);

        if let Some(ref progress) = options.progress {
            progress(ProgressUpdate {
                stage: ProgressStage::ReadingRecovery,
                current: i as u32 + 1,
                total: n as u32,
                bytes_processed: (i + 1) as u64 * slice_size as u64,
                total_bytes: None,
            });
        }
    }

    Ok(recovery_data)
}

/// XOR-out a single known-good input slice's contribution from all recovery buffers.
///
/// `global_idx` is the slice's position in the global input ordering.
/// `input_data` is the slice data (will be zero-padded to `plan.slice_size` if shorter).
pub fn xor_out_slice(
    recovery_buffers: &mut [Vec<u8>],
    plan: &RepairPlan,
    global_idx: usize,
    input_data: &[u8],
) {
    let slice_size = plan.slice_size as usize;
    assert!(
        slice_size.is_multiple_of(2),
        "PAR2 slice_size must be a multiple of 2"
    );

    // Pad input data to slice_size if needed.
    let padded;
    let data = if input_data.len() < slice_size {
        padded = {
            let mut v = input_data.to_vec();
            v.resize(slice_size, 0);
            v
        };
        &padded[..]
    } else {
        &input_data[..slice_size]
    };

    let recovery_factors: Vec<u16> = plan
        .recovery_exponents
        .iter()
        .map(|&exp| gf::pow(plan.constants[global_idx], exp))
        .collect();

    xor_out_known_data(
        recovery_buffers,
        &recovery_factors,
        &data[..slice_size],
        slice_size / 2,
    );
}

/// This legacy whole-buffer entry point is retained as an API symbol, but
/// native repair is exclusively driven by the streamed CPU controller.
pub fn reconstruct_and_write(
    _plan: &RepairPlan,
    _par2_set: &Par2FileSet,
    _recovery_buffers: Vec<Vec<u8>>,
    _file_access: &mut dyn FileAccess,
    _chunk_words: usize,
    _options: &RepairOptions,
) -> Result<()> {
    Err(Par2Error::ReedSolomonError {
        reason:
            "legacy in-memory PAR2 reconstruction is quarantined; use execute_repair_with_options"
                .to_string(),
    })
}

// Kept only for differential experimentation in unit builds. Production
// targets compile one authoritative CPU repair controller.
#[cfg(test)]
#[allow(dead_code)]
fn legacy_reconstruct_and_write(
    plan: &RepairPlan,
    par2_set: &Par2FileSet,
    recovery_buffers: Vec<Vec<u8>>,
    file_access: &mut dyn FileAccess,
    chunk_words: usize,
    options: &RepairOptions,
) -> Result<()> {
    let n = plan.missing_slices.len();
    if n == 0 {
        return Ok(());
    }

    let slice_size = plan.slice_size as usize;
    assert!(
        slice_size.is_multiple_of(2),
        "PAR2 slice_size must be a multiple of 2"
    );
    let word_count = slice_size / 2;

    // Step 2: Multiply adjusted recovery data by decode matrix.
    info!("reconstructing {} missing slices", n);

    #[cfg(target_arch = "x86_64")]
    if is_x86_feature_detected!("gfni") && is_x86_feature_detected!("avx2") {
        return reconstruct_and_write_grouped_inputs(
            plan,
            par2_set,
            recovery_buffers,
            file_access,
            chunk_words,
            options,
        );
    }

    let mut repaired_slices: Vec<Vec<u8>> = vec![vec![0u8; slice_size]; n];

    let total_chunks_usize = word_count.div_ceil(chunk_words);
    let total_chunks = total_chunks_usize.min(u32::MAX as usize) as u32;
    let repair_total_bytes = (word_count as u64).saturating_mul(2);
    let write_total_bytes = (n as u64).saturating_mul(slice_size as u64);
    let operation_total_bytes = repair_total_bytes.saturating_add(write_total_bytes);

    check_cancel(options)?;

    let completed_chunks = AtomicU32::new(0);
    let repaired_ptrs: Vec<usize> = repaired_slices
        .iter_mut()
        .map(|slice| slice.as_mut_ptr() as usize)
        .collect();

    (0..total_chunks_usize)
        .into_par_iter()
        .try_for_each(|chunk_idx| -> Result<()> {
            check_cancel(options)?;

            let chunk_start = chunk_idx * chunk_words;
            let chunk_end = (chunk_start + chunk_words).min(word_count);
            let chunk_len = chunk_end - chunk_start;
            let byte_start = chunk_start * 2;
            let byte_len = chunk_len * 2;

            // Transposed loop: iterate recovery buffers in the outer loop so each
            // buffer is loaded into cache once and reused for all N output slices.
            // Uses multi-region kernel to read src once per SIMD chunk across all
            // destinations. GF addition is commutative — accumulation order doesn't
            // matter.
            for (r, recovery) in recovery_buffers.iter().enumerate() {
                let src = &recovery[byte_start..byte_start + byte_len];
                let mut pairs: Vec<crate::gf_simd::FactorDst<'_>> = (0..n)
                    .filter_map(|j| {
                        let factor = plan.decode_matrix.get(j, r);
                        if factor != 0 {
                            // Safe because each chunk task writes a disjoint byte
                            // range within every repaired slice, and the slices
                            // themselves live in distinct Vec allocations.
                            let dst = unsafe {
                                let ptr = repaired_ptrs[j] as *mut u8;
                                std::slice::from_raw_parts_mut(ptr.add(byte_start), byte_len)
                            };
                            Some(crate::gf_simd::FactorDst { factor, dst })
                        } else {
                            None
                        }
                    })
                    .collect();
                if !pairs.is_empty() {
                    crate::gf_simd::mul_acc_multi_region(&mut pairs, src);
                }
            }

            if let Some(ref progress) = options.progress {
                let current = completed_chunks.fetch_add(1, Ordering::Relaxed) + 1;
                progress(ProgressUpdate {
                    stage: ProgressStage::Repairing,
                    current,
                    total: total_chunks,
                    bytes_processed: (current as u64)
                        .saturating_mul(chunk_words as u64)
                        .saturating_mul(2)
                        .min(repair_total_bytes),
                    total_bytes: Some(operation_total_bytes),
                });
            }

            Ok(())
        })?;

    check_cancel(options)?;

    // Step 3: Write repaired slices back to files.
    info!("writing repaired slices to files");
    let write_targets = build_write_targets(plan, par2_set)?;

    for (j, target) in write_targets.iter().enumerate() {
        check_cancel(options)?;

        let slice_end = target.offset + plan.slice_size;
        let write_len = if slice_end > target.file_end {
            (target.file_end - target.offset) as usize
        } else {
            slice_size
        };

        file_access
            .write_file_range(
                &target.file_id,
                target.offset,
                &repaired_slices[j][..write_len],
            )
            .map_err(|e| Par2Error::RepairWriteFailed {
                filename: target.filename.clone(),
                offset: target.offset,
                source: e,
            })?;

        debug!(
            "repaired slice {} of file {} ({write_len} bytes at offset {})",
            plan.missing_slices[j].1, target.filename, target.offset
        );

        if let Some(ref progress) = options.progress {
            progress(ProgressUpdate {
                stage: ProgressStage::WritingRepaired,
                current: j as u32 + 1,
                total: n as u32,
                bytes_processed: repair_total_bytes
                    .saturating_add((j + 1) as u64 * slice_size as u64),
                total_bytes: Some(operation_total_bytes),
            });
        }
    }

    info!("repair complete: {} slices restored", n);
    Ok(())
}

#[cfg(all(test, target_arch = "x86_64"))]
#[allow(dead_code)]
fn reconstruct_and_write_grouped_inputs(
    plan: &RepairPlan,
    par2_set: &Par2FileSet,
    recovery_buffers: Vec<Vec<u8>>,
    file_access: &mut dyn FileAccess,
    chunk_words: usize,
    options: &RepairOptions,
) -> Result<()> {
    let n = plan.missing_slices.len();
    if n == 0 {
        return Ok(());
    }

    let slice_size = plan.slice_size as usize;
    assert!(
        slice_size.is_multiple_of(2),
        "PAR2 slice_size must be a multiple of 2"
    );
    let word_count = slice_size / 2;
    let total_chunks_usize = word_count.div_ceil(chunk_words);
    let output_inputs = grouped_input_factors(&plan.decode_matrix);
    // Deduplicate prepared multiply tables per distinct factor value; see the
    // in-memory repair path for rationale.
    let mut factor_slots: HashMap<u16, usize> = HashMap::new();
    let mut prepared_factors: Vec<crate::gf_simd::PreparedInputFactor> = Vec::new();
    let prepared_output_inputs: Vec<Vec<(u16, usize)>> = output_inputs
        .iter()
        .map(|inputs| {
            inputs
                .iter()
                .map(|factor_input| {
                    let slot = *factor_slots.entry(factor_input.factor).or_insert_with(|| {
                        prepared_factors
                            .push(crate::gf_simd::prepare_input_factor(factor_input.factor));
                        prepared_factors.len() - 1
                    });
                    (factor_input.input_idx, slot)
                })
                .collect()
        })
        .collect();

    let mut repaired_slices: Vec<Vec<u8>> = vec![vec![0u8; slice_size]; n];
    let completed_outputs = AtomicU32::new(0);
    let repair_total_bytes = (n as u64).saturating_mul(slice_size as u64);
    let write_total_bytes = (n as u64).saturating_mul(slice_size as u64);
    let operation_total_bytes = repair_total_bytes.saturating_add(write_total_bytes);

    repaired_slices.par_iter_mut().enumerate().try_for_each(
        |(output_idx, repaired)| -> Result<()> {
            check_cancel(options)?;

            let decode_inputs = &prepared_output_inputs[output_idx];
            let mut chunk_inputs = Vec::with_capacity(decode_inputs.len());

            for chunk_idx in 0..total_chunks_usize {
                let chunk_start = chunk_idx * chunk_words;
                let chunk_end = (chunk_start + chunk_words).min(word_count);
                let byte_start = chunk_start * 2;
                let byte_len = (chunk_end - chunk_start) * 2;

                chunk_inputs.clear();
                for (input_idx, factor_slot) in decode_inputs {
                    chunk_inputs.push(crate::gf_simd::PreparedFactorSrc {
                        prepared: &prepared_factors[*factor_slot],
                        src: &recovery_buffers[*input_idx as usize]
                            [byte_start..byte_start + byte_len],
                    });
                }

                crate::gf_simd::mul_acc_input_batch_prepared(
                    &mut repaired[byte_start..byte_start + byte_len],
                    &chunk_inputs,
                );
            }

            if let Some(ref progress) = options.progress {
                let current = completed_outputs.fetch_add(1, Ordering::Relaxed) + 1;
                progress(ProgressUpdate {
                    stage: ProgressStage::Repairing,
                    current,
                    total: n as u32,
                    bytes_processed: current as u64 * slice_size as u64,
                    total_bytes: Some(operation_total_bytes),
                });
            }

            Ok(())
        },
    )?;

    check_cancel(options)?;

    info!("writing repaired slices to files");
    let write_targets = build_write_targets(plan, par2_set)?;

    for (j, target) in write_targets.iter().enumerate() {
        check_cancel(options)?;

        let slice_end = target.offset + plan.slice_size;
        let write_len = if slice_end > target.file_end {
            (target.file_end - target.offset) as usize
        } else {
            slice_size
        };

        file_access
            .write_file_range(
                &target.file_id,
                target.offset,
                &repaired_slices[j][..write_len],
            )
            .map_err(|e| Par2Error::RepairWriteFailed {
                filename: target.filename.clone(),
                offset: target.offset,
                source: e,
            })?;

        if let Some(ref progress) = options.progress {
            progress(ProgressUpdate {
                stage: ProgressStage::WritingRepaired,
                current: j as u32 + 1,
                total: n as u32,
                bytes_processed: repair_total_bytes
                    .saturating_add((j + 1) as u64 * slice_size as u64),
                total_bytes: Some(operation_total_bytes),
            });
        }
    }

    info!("repair complete: {} slices restored", n);
    Ok(())
}

/// One engaged GPU session. Metal (native, unified memory) has precedence on
/// Apple Silicon; the wgpu backend (Vulkan/DX12/Metal) covers the remaining
/// platforms. Both expose the identical begin/accumulate/finish protocol.
#[cfg(any(
    all(feature = "metal", target_os = "macos", target_arch = "aarch64"),
    feature = "wgpu"
))]
enum GpuSession {
    #[cfg(all(feature = "metal", target_os = "macos", target_arch = "aarch64"))]
    Metal(reedsolomon_rs::metal_gf16::MetalGf16Session),
    #[cfg(feature = "wgpu")]
    Wgpu(reedsolomon_rs::wgpu_gf16::WgpuGf16Session),
}

#[cfg(any(
    all(feature = "metal", target_os = "macos", target_arch = "aarch64"),
    feature = "wgpu"
))]
impl GpuSession {
    fn try_new(outputs: usize, max_byte_len: usize, effective_bytes: u64) -> Option<Self> {
        #[cfg(all(feature = "metal", target_os = "macos", target_arch = "aarch64"))]
        if let Some(session) = reedsolomon_rs::metal_gf16::MetalGf16Session::try_new(
            outputs,
            max_byte_len,
            effective_bytes,
        ) {
            return Some(GpuSession::Metal(session));
        }
        #[cfg(feature = "wgpu")]
        if let Some(session) = reedsolomon_rs::wgpu_gf16::WgpuGf16Session::try_new(
            outputs,
            max_byte_len,
            effective_bytes,
        ) {
            return Some(GpuSession::Wgpu(session));
        }
        None
    }

    fn begin_chunk(&mut self, byte_len: usize) -> std::result::Result<(), &'static str> {
        match self {
            #[cfg(all(feature = "metal", target_os = "macos", target_arch = "aarch64"))]
            GpuSession::Metal(s) => s.begin_chunk(byte_len),
            #[cfg(feature = "wgpu")]
            GpuSession::Wgpu(s) => s.begin_chunk(byte_len),
        }
    }

    fn accumulate(
        &mut self,
        srcs: &[&[u8]],
        factor: impl Fn(usize, usize) -> u16,
    ) -> std::result::Result<(), &'static str> {
        match self {
            #[cfg(all(feature = "metal", target_os = "macos", target_arch = "aarch64"))]
            GpuSession::Metal(s) => s.accumulate(srcs, factor),
            #[cfg(feature = "wgpu")]
            GpuSession::Wgpu(s) => s.accumulate(srcs, factor),
        }
    }

    fn finish_chunk(&mut self, rows: &mut [Vec<u8>]) -> std::result::Result<(), &'static str> {
        match self {
            #[cfg(all(feature = "metal", target_os = "macos", target_arch = "aarch64"))]
            GpuSession::Metal(s) => s.finish_chunk(rows),
            #[cfg(feature = "wgpu")]
            GpuSession::Wgpu(s) => s.finish_chunk(rows),
        }
    }

    fn device_name(&self) -> String {
        match self {
            #[cfg(all(feature = "metal", target_os = "macos", target_arch = "aarch64"))]
            GpuSession::Metal(s) => s.device_name(),
            #[cfg(feature = "wgpu")]
            GpuSession::Wgpu(s) => s.device_name(),
        }
    }

    fn backend_name(&self) -> &'static str {
        match self {
            #[cfg(all(feature = "metal", target_os = "macos", target_arch = "aarch64"))]
            GpuSession::Metal(_) => "metal",
            #[cfg(feature = "wgpu")]
            GpuSession::Wgpu(_) => "wgpu",
        }
    }
}

/// Optional GPU arm of the streaming compute. All platform gating lives
/// here: without a GPU feature every method is a no-op and the CPU path
/// runs unchanged; otherwise a session engages only when a device is
/// present and the repair is large enough to amortize dispatch (see
/// `reedsolomon_rs::{metal_gf16, wgpu_gf16}`). Any GPU error
/// permanently disables the arm and the caller redoes the affected chunk
/// on the CPU.
struct GpuComputeArm {
    #[cfg(any(
        all(feature = "metal", target_os = "macos", target_arch = "aarch64"),
        feature = "wgpu"
    ))]
    session: Option<GpuSession>,
}

impl GpuComputeArm {
    fn is_engaged(&self) -> bool {
        #[cfg(any(
            all(feature = "metal", target_os = "macos", target_arch = "aarch64"),
            feature = "wgpu"
        ))]
        return self.session.is_some();

        #[cfg(not(any(
            all(feature = "metal", target_os = "macos", target_arch = "aarch64"),
            feature = "wgpu"
        )))]
        false
    }

    fn disable(&mut self) {
        #[cfg(any(
            all(feature = "metal", target_os = "macos", target_arch = "aarch64"),
            feature = "wgpu"
        ))]
        {
            self.session = None;
        }
    }

    #[cfg(any(
        all(feature = "metal", target_os = "macos", target_arch = "aarch64"),
        feature = "wgpu"
    ))]
    fn engage(enabled: bool, outputs: usize, max_byte_len: usize, effective_bytes: u64) -> Self {
        // The GPU arm consumes the plain staging shape. GPU policy is separate
        // from CPU method selection: an available XOR-JIT method remains the
        // CPU fallback if this arm declines or fails.
        let session = enabled
            .then(|| GpuSession::try_new(outputs, max_byte_len, effective_bytes))
            .flatten();
        if let Some(session) = &session {
            info!(
                backend = session.backend_name(),
                device = %session.device_name(),
                outputs,
                "gpu gf16 tier engaged for streaming repair"
            );
        }
        // A headless box whose only Vulkan ICD is llvmpipe has an adapter and
        // still gets the CPU tier; say so rather than leaving the operator to
        // wonder. Cheap: this never probes an adapter that was not probed.
        #[cfg(feature = "wgpu")]
        if session.is_none() && reedsolomon_rs::wgpu_gf16::auto_refused_cpu_adapter() {
            debug!("wgpu adapter is a cpu rasterizer; keeping the cpu gf16 tier");
        }
        Self { session }
    }

    #[cfg(not(any(
        all(feature = "metal", target_os = "macos", target_arch = "aarch64"),
        feature = "wgpu"
    )))]
    fn engage(
        _enabled: bool,
        _outputs: usize,
        _max_byte_len: usize,
        _effective_bytes: u64,
    ) -> Self {
        Self {}
    }

    /// True when the GPU owns this chunk's accumulation.
    fn begin_chunk(&mut self, _byte_len: usize) -> bool {
        #[cfg(any(
            all(feature = "metal", target_os = "macos", target_arch = "aarch64"),
            feature = "wgpu"
        ))]
        {
            if let Some(session) = self.session.as_mut() {
                match session.begin_chunk(_byte_len) {
                    Ok(()) => return true,
                    Err(reason) => {
                        warn!(reason, "gpu gf16 begin_chunk failed; using CPU path");
                        self.session = None;
                    }
                }
            }
        }
        false
    }

    /// Queue one source batch. `Err` means the GPU arm died mid-chunk and
    /// the caller must redo the chunk on the CPU.
    fn accumulate(
        &mut self,
        _set: &StreamBatchSet,
        _plan: &RepairPlan,
        _byte_len: usize,
    ) -> std::result::Result<(), ()> {
        #[cfg(any(
            all(feature = "metal", target_os = "macos", target_arch = "aarch64"),
            feature = "wgpu"
        ))]
        {
            let Some(session) = self.session.as_mut() else {
                return Err(());
            };
            let srcs: Vec<&[u8]> = _set.bufs[.._set.len]
                .iter()
                .map(|buf| &buf[.._byte_len])
                .collect();
            let matrix = &_plan.input_factors;
            let start = _set.start;
            if let Err(reason) = session.accumulate(&srcs, |j, s| matrix.get(j, start + s)) {
                warn!(reason, "gpu gf16 accumulate failed; redoing chunk on CPU");
                self.session = None;
                return Err(());
            }
            return Ok(());
        }
        #[allow(unreachable_code)]
        Err(())
    }

    /// Drain the chunk's dispatches into the output rows.
    fn finish_chunk(
        &mut self,
        _rows: &mut [Vec<u8>],
        _byte_len: usize,
    ) -> std::result::Result<(), ()> {
        #[cfg(any(
            all(feature = "metal", target_os = "macos", target_arch = "aarch64"),
            feature = "wgpu"
        ))]
        {
            let Some(session) = self.session.as_mut() else {
                return Err(());
            };
            if let Err(reason) = session.finish_chunk(_rows) {
                warn!(reason, "gpu gf16 finish_chunk failed; redoing chunk on CPU");
                self.session = None;
                return Err(());
            }
            return Ok(());
        }
        #[allow(unreachable_code)]
        Err(())
    }
}

#[derive(Default)]
struct CpuControllerTimings {
    read_prepare_ns: AtomicU64,
    jit_prepare_ns: AtomicU64,
    compute_ns: AtomicU64,
    finish_ns: AtomicU64,
    write_ns: AtomicU64,
}

impl CpuControllerTimings {
    fn record(counter: &AtomicU64, elapsed: Duration) {
        let nanos = elapsed.as_nanos().min(u64::MAX as u128) as u64;
        counter.fetch_add(nanos, Ordering::Relaxed);
    }

    fn micros(counter: &AtomicU64) -> u64 {
        counter.load(Ordering::Relaxed) / 1_000
    }

    fn duration_micros(elapsed: Duration) -> u64 {
        elapsed.as_micros().min(u64::MAX as u128) as u64
    }
}

fn execute_repair_streaming(
    plan: &RepairPlan,
    par2_set: &Par2FileSet,
    file_access: &mut dyn FileAccess,
    options: &RepairOptions,
    budget: usize,
) -> Result<()> {
    execute_repair_streaming_with_trace(
        plan,
        par2_set,
        file_access,
        options,
        budget,
        ControllerExecutionTrace::default(),
    )
}

fn execute_repair_streaming_with_trace(
    plan: &RepairPlan,
    par2_set: &Par2FileSet,
    file_access: &mut dyn FileAccess,
    options: &RepairOptions,
    budget: usize,
    trace: ControllerExecutionTrace,
) -> Result<()> {
    check_cancel(options)?;
    let controller_started = Instant::now();
    let n = plan.missing_slices.len();
    if n == 0 {
        return Ok(());
    }

    let slice_size = plan.slice_size as usize;
    assert!(
        slice_size.is_multiple_of(2),
        "PAR2 slice_size must be a multiple of 2"
    );
    let word_count = slice_size / 2;
    let operation_total_bytes = (word_count as u64).saturating_mul(2);
    let write_targets = build_write_targets(plan, par2_set)?;
    let mut recovery_files: HashMap<PathBuf, File> = HashMap::new();
    let available_inputs = plan.available_input_global_indices.len();
    let total_sources = available_inputs + plan.recovery_exponents.len();
    // The folded path keeps every buffer in split byte-plane layout end to
    // end: sources are encoded and group-interleaved as they are read,
    // accumulation runs plane-wise with register-resident folded matrices,
    // and outputs decode once per chunk before writing.
    // Select the CPU method from capability alone. Slice size and GPU policy
    // influence controller allocation and whether the separate GPU arm runs;
    // neither may silently replace a supported CPU method.
    let effective_bytes = (n as u64)
        .saturating_mul(total_sources as u64)
        .saturating_mul(plan.slice_size);
    // WEAVER_GF16_WGPU=1 forces the wgpu GPU arm: the x86 CPU fast tiers are
    // disabled for the run so the batch sets take the plain shape the GPU arm
    // consumes (`bufs`), with the universal CPU tier as the fallback.
    #[cfg(feature = "wgpu")]
    let gpu_forced = reedsolomon_rs::wgpu_gf16::force_requested();
    #[cfg(not(feature = "wgpu"))]
    let gpu_forced = false;
    // A discrete GPU claims accumulation from the x86 fast tiers on its own
    // (see `discrete_auto_candidate` for the measurements and why integrated
    // GPUs don't). The probe runs only where its answer can change the shape —
    // a host that would otherwise take an AVX2 fast tier — so aarch64/macOS
    // never initialize the wgpu stack here and keep their Metal precedence.
    //
    // Decision table (adapter class × gate, when an x86 fast tier exists):
    //   WEAVER_GF16_WGPU=1                → GPU owns accumulation (any adapter)
    //   auto + DiscreteGpu + ≥ size gate  → GPU owns accumulation
    //   auto + Integrated/Virtual/Cpu/…   → fast tier keeps it
    //   WEAVER_GF16_WGPU=0                → fast tier keeps it
    // With no fast tier, `engage` below keeps its own (CPU-rasterizer-only)
    // refusal, unchanged.
    #[cfg(feature = "wgpu")]
    let gpu_discrete_auto = !gpu_forced
        && crate::gf_simd::altmap_supported()
        && reedsolomon_rs::wgpu_gf16::discrete_auto_candidate(effective_bytes);
    #[cfg(not(feature = "wgpu"))]
    let gpu_discrete_auto = false;
    let gpu_preferred = gpu_forced || gpu_discrete_auto;
    // Select AVX2 XOR-JIT only on tuned CPU families; other machines retain
    // the folded controller. A W^X/JIT construction failure is a controller
    // error, never a hidden downgrade to a different arithmetic method.
    #[cfg(target_arch = "x86_64")]
    let jit_width = reedsolomon_rs::xor_jit::JitWidth::detect();
    let workers = rayon::current_num_threads().max(1);
    // Shape the JIT controller from its selected method contract. The cached
    // strict-W^X capability was established by the Reed-Solomon supported()
    // gate; sealing each active batch remains fallible.
    #[cfg(target_arch = "x86_64")]
    let jit_setup_started = Instant::now();
    #[cfg(target_arch = "x86_64")]
    let jit_memo = jit_width.map(|width| {
        let jit_kernel = CpuKernelKind::XorJit(width);
        let jit_method = jit_kernel.method();
        let jit_staging_width = jit_method.staging_width();
        let minimum_controller = cpu_controller_plan(
            2,
            n,
            workers,
            jit_method,
            jit_staging_width,
        );
        let minimum_controller_bytes = minimum_controller.buffer_accounting().total_bytes;
        let available_jit_bytes = budget.checked_sub(minimum_controller_bytes).ok_or_else(|| {
            Par2Error::ResourceLimitExceeded {
                reason: format!(
                    "XOR-JIT controller base needs {minimum_controller_bytes} bytes, exceeding the {budget} byte memory limit"
                ),
            }
        })?;
        let full_controller_bytes = cpu_controller_plan(
            slice_size,
            n,
            workers,
            jit_method,
            jit_staging_width,
        )
        .buffer_accounting()
        .total_bytes;
        let codebook_limit = budget.saturating_sub(full_controller_bytes);
        JitMemo::new(
            width,
            jit_method,
            n,
            &plan.input_factors.data,
            codebook_limit,
            available_jit_bytes,
        )
        .map_err(|error| {
            Par2Error::ReedSolomonError {
                reason: format!("XOR-JIT controller capacity setup failed: {error}"),
            }
        })
    }).transpose()?;
    #[cfg(target_arch = "x86_64")]
    let jit_setup = jit_setup_started.elapsed();
    #[cfg(not(target_arch = "x86_64"))]
    let jit_setup = Duration::ZERO;
    #[cfg(target_arch = "x86_64")]
    let use_xorjit = jit_memo.is_some();
    #[cfg(not(target_arch = "x86_64"))]
    let use_xorjit = false;
    let use_folded = crate::gf_simd::altmap_supported() && !use_xorjit;
    let cpu_kernel = if use_folded {
        CpuKernelKind::Folded
    } else {
        CpuKernelKind::Plain
    };
    #[cfg(target_arch = "x86_64")]
    let cpu_kernel = jit_memo
        .as_ref()
        .map_or(cpu_kernel, |memo| CpuKernelKind::XorJit(memo.width));
    let method = cpu_kernel.method();
    let input_grouping = method.input_grouping();
    #[cfg(target_arch = "x86_64")]
    let persistent_jit_bytes = jit_memo.as_ref().map_or(0, JitMemo::reserved_bytes);
    #[cfg(not(target_arch = "x86_64"))]
    let persistent_jit_bytes = 0;
    let staging_width = method.staging_width();
    let (mut chunk_words, selected_budget, mut max_controller) = controller_execution_parameters(
        plan,
        options,
        method,
        staging_width,
        persistent_jit_bytes,
        workers,
    )?;
    debug_assert_eq!(selected_budget, budget);
    let max_byte_len = chunk_words * 2;
    // A GPU session owns output rows and consumes ordinary source rows. When
    // the selected CPU method uses packed or folded rows, reserve a second
    // pair of staging areas so a failed GPU chunk can fall back to that same
    // CPU method without rereading sources or escaping the repair limit.
    let mut gpu = GpuComputeArm::engage(
        gpu_preferred || (!use_folded && !use_xorjit),
        n,
        max_byte_len,
        effective_bytes,
    );
    let mut gpu_staging = gpu.is_engaged();
    if gpu_staging {
        let extra_gpu_output_bytes = n
            .checked_mul(max_controller.layout().aligned_len)
            .ok_or_else(|| Par2Error::ResourceLimitExceeded {
                reason: "GPU output allocation overflowed".to_string(),
            })?;
        let extra_gpu_staging_bytes = if use_folded || use_xorjit {
            max_controller
                .buffer_accounting()
                .staging_area_bytes
                .checked_mul(2)
                .ok_or_else(|| Par2Error::ResourceLimitExceeded {
                    reason: "GPU fallback staging allocation overflowed".to_string(),
                })?
        } else {
            0
        };
        let gpu_state_bytes = extra_gpu_output_bytes
            .checked_add(extra_gpu_staging_bytes)
            .ok_or_else(|| Par2Error::ResourceLimitExceeded {
                reason: "GPU state accounting overflowed".to_string(),
            })?;
        let persistent_with_gpu_state = persistent_jit_bytes
            .checked_add(gpu_state_bytes)
            .ok_or_else(|| Par2Error::ResourceLimitExceeded {
                reason: "GPU state accounting overflowed".to_string(),
            })?;
        match controller_execution_parameters(
            plan,
            options,
            method,
            staging_width,
            persistent_with_gpu_state,
            workers,
        ) {
            Ok((words, _, controller)) => {
                chunk_words = words;
                max_controller = controller;
            }
            Err(error) => {
                warn!(reason = %error, "GPU state exceeds the repair memory limit; keeping the CPU controller");
                gpu.disable();
                gpu_staging = false;
            }
        }
    }
    let total_chunks_usize = word_count.div_ceil(chunk_words);
    let total_chunks = total_chunks_usize.min(u32::MAX as usize) as u32;
    debug_assert_eq!(max_controller.input_grouping(), input_grouping);
    #[cfg(any(
        all(feature = "metal", target_os = "macos", target_arch = "aarch64"),
        feature = "wgpu"
    ))]
    let max_aligned_len = max_controller.layout().aligned_len;
    let physical_row_len = max_controller.buffer_accounting().physical_row_len;
    let factor_setup_started = Instant::now();
    let memo = PreparedFactorMemo::from_matrix(&plan.input_factors, use_folded);
    let factor_setup = factor_setup_started.elapsed();
    let buffer_setup_started = Instant::now();
    let mut batch_sets = [
        Some(StreamBatchSet::new(
            physical_row_len,
            input_grouping,
            staging_width,
            n,
            use_folded,
            use_xorjit,
            gpu_staging,
        )),
        Some(StreamBatchSet::new(
            physical_row_len,
            input_grouping,
            staging_width,
            n,
            use_folded,
            use_xorjit,
            gpu_staging,
        )),
    ];
    let mut cpu_output_area = AlignedOutputArea::new(n, physical_row_len);
    let output_base = cpu_output_area.base();
    #[cfg(any(
        all(feature = "metal", target_os = "macos", target_arch = "aarch64"),
        feature = "wgpu"
    ))]
    let mut gpu_chunk_output: Vec<Vec<u8>> = vec![vec![0u8; max_aligned_len]; n];
    #[cfg(not(any(
        all(feature = "metal", target_os = "macos", target_arch = "aarch64"),
        feature = "wgpu"
    )))]
    let mut gpu_chunk_output: Vec<Vec<u8>> = Vec::new();
    let gpu_output_ptrs: Vec<usize> = gpu_chunk_output
        .iter_mut()
        .map(|output| output.as_mut_ptr() as usize)
        .collect();
    let buffer_setup = buffer_setup_started.elapsed();
    let timings = CpuControllerTimings::default();

    info!(
        missing_slices = n,
        chunk_bytes = chunk_words * 2,
        budget_bytes = budget,
        source_batch = input_grouping,
        workers,
        backend = ?cpu_kernel,
        "repairing with CPU-controller streamed path"
    );

    let repair_result = std::thread::scope(|scope| -> Result<()> {
        let (command_tx, command_rx) = std::sync::mpsc::sync_channel(2);
        let (complete_tx, complete_rx) = std::sync::mpsc::sync_channel(2);
        let (prepared_tx, prepared_rx) = std::sync::mpsc::sync_channel(1);
        let (submitted_tx, submitted_rx) = std::sync::mpsc::sync_channel(1);
        let (finished_tx, finished_rx) = std::sync::mpsc::sync_channel(2);
        let (compute_completion_tx, compute_completion_rx) =
            std::sync::mpsc::sync_channel(workers.saturating_mul(2).max(1));
        let mut compute_senders = Vec::with_capacity(workers);
        let mut compute_workers = Vec::with_capacity(workers);
        for worker_index in 0..workers {
            let (sender, receiver) = std::sync::mpsc::sync_channel(1);
            let completion_tx = compute_completion_tx.clone();
            compute_senders.push(sender);
            compute_workers.push(scope.spawn(move || {
                run_compute_worker(worker_index, receiver, completion_tx);
            }));
        }
        drop(compute_completion_tx);
        let compute_submitter = CpuComputeSubmitter {
            senders: compute_senders,
            next_id: 0,
        };
        let mut compute_pool = CpuComputePool {
            completion_rx: compute_completion_rx,
            deferred: HashMap::new(),
            _lifetime: std::marker::PhantomData,
        };
        let preparation_trace = trace.clone();
        let preparation_memo = &memo;
        let preparation_timings = &timings;
        #[cfg(target_arch = "x86_64")]
        let preparation_jit_memo = jit_memo.as_ref();
        let preparation_worker = scope.spawn(move || {
            let panic_trace = preparation_trace.clone();
            if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run_preparation_worker(
                    command_rx,
                    complete_tx,
                    prepared_tx,
                    submitted_tx,
                    finished_tx,
                    cpu_kernel,
                    method,
                    output_base,
                    n,
                    preparation_memo,
                    #[cfg(target_arch = "x86_64")]
                    preparation_jit_memo,
                    preparation_timings,
                    compute_submitter,
                    preparation_trace,
                );
            }))
            .is_err()
            {
                panic_trace.record(ControllerExecutionEvent::Failed {
                    phase: ControllerFailurePhase::Prepare,
                });
                true
            } else {
                false
            }
        });
        let mut preparer = CpuInputPreparer {
            command_tx,
            complete_rx,
            prepared_rx,
            submitted_rx,
            finished_rx,
            transfer_buffers: std::array::from_fn(|slot| {
                Some(TransferBuffer {
                    slot,
                    bytes: vec![0u8; physical_row_len],
                })
            }),
            transfer_buffer_len: physical_row_len,
        };

        let repair_result = (|| -> Result<()> {
            let mut chunk_idx = 0usize;
            let mut source_reader = None;
            while chunk_idx < total_chunks_usize {
                check_cancel(options)?;

                let chunk_start = chunk_idx * chunk_words;
                let chunk_end = (chunk_start + chunk_words).min(word_count);
                let chunk_len = chunk_end - chunk_start;
                let byte_start = chunk_start * 2;
                let byte_len = chunk_len * 2;
                let controller = cpu_controller_plan(byte_len, n, workers, method, staging_width);
                let controller_layout = Arc::new(controller.layout().clone());
                debug!(
                    chunk = chunk_idx,
                    aligned_bytes = controller.layout().aligned_len,
                    compute_chunk_bytes = controller.layout().chunk_len,
                    compute_chunks = controller.layout().num_chunks,
                    assignments = controller.layout().assignments.len(),
                    input_grouping = controller.input_grouping(),
                    "CPU repair controller plan"
                );
                let gpu_chunk = gpu.begin_chunk(byte_len);
                let mut gpu_failed = false;
                if gpu_chunk {
                    // GPU dispatch remains on its existing two-set pipeline.
                    // A GPU failure redoes this whole outer chunk on the CPU.
                    let mut current_area = 0usize;
                    let first_len = total_sources.min(controller.input_grouping());
                    let mut current = fill_gpu_stream_batch(
                        &mut preparer,
                        batch_sets[current_area]
                            .take()
                            .expect("controller staging area available"),
                        plan,
                        par2_set,
                        file_access,
                        &mut recovery_files,
                        &mut source_reader,
                        available_inputs,
                        0,
                        first_len,
                        byte_start,
                        byte_len,
                        controller.layout().aligned_len,
                        controller.layout().chunk_len,
                        controller.layout().num_chunks,
                        options,
                        &timings,
                    )?;
                    let mut spare = batch_sets[1 - current_area].take();
                    let mut batch_start = 0usize;
                    while batch_start < total_sources {
                        check_cancel(options)?;
                        if gpu.accumulate(&current, plan, byte_len).is_err() {
                            gpu_failed = true;
                            break;
                        }
                        batch_start += current.len;
                        if batch_start < total_sources {
                            let next_len =
                                (total_sources - batch_start).min(controller.input_grouping());
                            let next = fill_gpu_stream_batch(
                                &mut preparer,
                                spare.take().expect("controller staging area available"),
                                plan,
                                par2_set,
                                file_access,
                                &mut recovery_files,
                                &mut source_reader,
                                available_inputs,
                                batch_start,
                                next_len,
                                byte_start,
                                byte_len,
                                controller.layout().aligned_len,
                                controller.layout().chunk_len,
                                controller.layout().num_chunks,
                                options,
                                &timings,
                            )?;
                            spare = Some(current);
                            current = next;
                            current_area = 1 - current_area;
                        }
                    }
                    batch_sets[current_area] = Some(current);
                    batch_sets[1 - current_area] = spare;
                } else {
                    // A transfer buffer is filled while the older staging area
                    // is still active; controller backpressure gates admission,
                    // not disk I/O.
                    let mut lifecycle = ControllerLifecycle::new(controller.input_grouping())
                        .with_execution_trace(trace.clone());
                    let mut active: [Option<CpuComputeTicket<'_>>; 2] = [None, None];
                    let mut batch_order = VecDeque::<usize>::with_capacity(2);
                    let mut preparing = [false; 2];
                    let mut pending_prepared: [Option<InputBatch>; 2] = [None, None];

                    let mut input_start = 0usize;
                    while input_start < total_sources {
                        check_cancel(options)?;
                        while receive_submitted_controller_batch(
                            SubmittedReceiveMode::ReadyOnly,
                            &preparer,
                            options,
                            &mut pending_prepared,
                            &mut preparing,
                            &trace,
                            &mut active,
                        )? {}

                        let read_area = lifecycle.current_staging_area;
                        let buffer = preparer.take_transfer_buffer(options.cancel.as_ref())?;
                        // The preparation worker dispatches compute before it
                        // releases the transfer buffer. Accept that ticket before
                        // touching controller backpressure for the newly read input.
                        while receive_submitted_controller_batch(
                            SubmittedReceiveMode::ReadyOnly,
                            &preparer,
                            options,
                            &mut pending_prepared,
                            &mut preparing,
                            &trace,
                            &mut active,
                        )? {}
                        let buffer = read_live_stream_input(
                            &mut preparer,
                            plan,
                            par2_set,
                            file_access,
                            &mut recovery_files,
                            &mut source_reader,
                            available_inputs,
                            input_start,
                            buffer,
                            read_area,
                            byte_start,
                            byte_len,
                            controller.layout().aligned_len,
                            options,
                            &trace,
                        )?;

                        if lifecycle.can_add() == ControllerAddStatus::Full {
                            lifecycle.observe_backpressure();
                            lifecycle.wait_for_add();
                            let expected_area = lifecycle.current_staging_area;
                            let completed_area = batch_order.front().copied().ok_or_else(|| {
                                Par2Error::ReedSolomonError {
                                    reason: "CPU repair controller reached backpressure without a submitted batch"
                                        .to_string(),
                                }
                            })?;
                            if completed_area != expected_area {
                                return Err(Par2Error::ReedSolomonError {
                                    reason: format!(
                                        "CPU repair staging order mismatch: expected area {expected_area}, completed area {completed_area}"
                                    ),
                                });
                            }
                            while active[completed_area].is_none() {
                                receive_submitted_controller_batch(
                                    SubmittedReceiveMode::Wait,
                                    &preparer,
                                    options,
                                    &mut pending_prepared,
                                    &mut preparing,
                                    &trace,
                                    &mut active,
                                )?;
                            }
                            batch_order.pop_front();
                            complete_active_controller_batch(
                                completed_area,
                                &preparer,
                                &mut compute_pool,
                                &mut active,
                                &mut batch_sets,
                                &mut lifecycle,
                                options,
                                &timings,
                                &trace,
                            )?;
                        }

                        let staging_area = lifecycle.current_staging_area;
                        debug_assert_eq!(staging_area, read_area);
                        if !preparing[staging_area] {
                            begin_live_stream_batch(
                                &preparer,
                                batch_sets[staging_area]
                                    .take()
                                    .expect("controller staging area available"),
                                input_start,
                                controller.layout().aligned_len,
                                controller.layout().chunk_len,
                                Arc::clone(&controller_layout),
                                &trace,
                            )?;
                            preparing[staging_area] = true;
                        }
                        let (accepted_area, submitted) = queue_live_stream_input(
                            &mut preparer,
                            &mut lifecycle,
                            plan,
                            input_start,
                            buffer,
                            &trace,
                        )?;
                        debug_assert_eq!(accepted_area, staging_area);
                        input_start += 1;
                        if let Some(batch) = submitted {
                            if batch.staging_area != staging_area
                                || pending_prepared[staging_area].replace(batch).is_some()
                            {
                                return Err(Par2Error::ReedSolomonError {
                                    reason: format!(
                                        "CPU repair controller resubmitted staging area {staging_area} before completion"
                                    ),
                                });
                            }
                            batch_order.push_back(staging_area);
                        }
                    }

                    if let Some(batch) = lifecycle.end_input() {
                        let staging_area = batch.staging_area;
                        flush_live_stream_batch(&preparer, batch, &trace)?;
                        if pending_prepared[staging_area].replace(batch).is_some() {
                            return Err(Par2Error::ReedSolomonError {
                                reason: format!(
                                    "CPU repair controller flushed occupied staging area {staging_area}"
                                ),
                            });
                        }
                        batch_order.push_back(staging_area);
                    }

                    while let Some(staging_area) = batch_order.pop_front() {
                        while active[staging_area].is_none() {
                            receive_submitted_controller_batch(
                                SubmittedReceiveMode::Wait,
                                &preparer,
                                options,
                                &mut pending_prepared,
                                &mut preparing,
                                &trace,
                                &mut active,
                            )?;
                        }
                        complete_active_controller_batch(
                            staging_area,
                            &preparer,
                            &mut compute_pool,
                            &mut active,
                            &mut batch_sets,
                            &mut lifecycle,
                            options,
                            &timings,
                            &trace,
                        )?;
                    }
                    debug_assert!(preparing.iter().all(|active| !active));
                    debug_assert!(pending_prepared.iter().all(Option::is_none));
                    lifecycle.processing_finished();
                }
                if gpu_chunk
                    && !gpu_failed
                    && gpu.finish_chunk(&mut gpu_chunk_output, byte_len).is_err()
                {
                    gpu_failed = true;
                }
                if gpu_failed {
                    // The arm is disabled; redo this chunk from batch zero on the
                    // CPU path.
                    continue;
                }

                finish_and_write_stream_outputs(
                    &mut preparer,
                    if gpu_chunk {
                        OutputTransferLayout::Contiguous(gpu_output_ptrs.as_slice())
                    } else {
                        OutputTransferLayout::ChunkInterleaved {
                            base: output_base,
                            output_count: n,
                            chunk_len: controller.layout().chunk_len,
                        }
                    },
                    controller.layout().aligned_len,
                    byte_start,
                    byte_len,
                    &write_targets,
                    file_access,
                    options,
                    &timings,
                    &trace,
                )?;

                if let Some(ref progress) = options.progress {
                    progress(ProgressUpdate {
                        stage: ProgressStage::Repairing,
                        current: chunk_idx as u32 + 1,
                        total: total_chunks,
                        bytes_processed: ((chunk_idx + 1) as u64)
                            .saturating_mul(chunk_words as u64)
                            .saturating_mul(2)
                            .min(operation_total_bytes),
                        total_bytes: Some(operation_total_bytes),
                    });
                }
                chunk_idx += 1;
            }
            Ok(())
        })();
        drop(compute_pool);
        drop(preparer);
        let mut compute_panicked = false;
        for worker in compute_workers {
            compute_panicked |= worker.join().is_err();
        }
        if compute_panicked && repair_result.is_ok() {
            return Err(Par2Error::ReedSolomonError {
                reason: "CPU repair compute worker panicked".to_string(),
            });
        }
        if preparation_worker.join().unwrap_or(true) && repair_result.is_ok() {
            return Err(Par2Error::ReedSolomonError {
                reason: "CPU repair preparation worker panicked".to_string(),
            });
        }
        repair_result
    });
    repair_result?;

    info!(
        missing_slices = n,
        total_us = CpuControllerTimings::duration_micros(controller_started.elapsed()),
        jit_setup_us = CpuControllerTimings::duration_micros(jit_setup),
        jit_prepare_work_us = CpuControllerTimings::micros(&timings.jit_prepare_ns),
        factor_setup_us = CpuControllerTimings::duration_micros(factor_setup),
        buffer_setup_us = CpuControllerTimings::duration_micros(buffer_setup),
        read_prepare_work_us = CpuControllerTimings::micros(&timings.read_prepare_ns),
        compute_work_us = CpuControllerTimings::micros(&timings.compute_ns),
        finish_us = CpuControllerTimings::micros(&timings.finish_ns),
        write_us = CpuControllerTimings::micros(&timings.write_ns),
        "streaming repair complete"
    );
    Ok(())
}

// ── Host-agnostic repair-solver seam (RFC 123 WP2.5) ───────────────────────
//
// The Reed-Solomon reconstruct (`out[j] = XOR over sources s of
// gf::mul(coeff[j][s], src[s])`) is the one step that cannot run under
// single-threaded `wasm32-wasip1`: weaver parallelises it with rayon, which
// cannot spawn a pool there, and the decode-matrix build wants a large native
// stack. This seam lets a host inject a non-rayon solver (e.g. one that
// marshals the solve to native host threads) WITHOUT par2-rs depending on
// any host ABI. `RepairProblem` is a plain description of the solve — the same
// fields the frozen "PAR2 v2" host descriptor carries — so a wasm consumer can
// marshal it, while the native default keeps the current rayon behaviour.

/// A host-agnostic description of a Reed-Solomon repair reconstruct.
///
/// Sources are ordered available inputs first (in `available_indices` order),
/// then the selected recovery blocks (in `recovery_exponents` order) — the same
/// column ordering as [`RepairPlan::input_factors`]. Each source and output
/// region is `word_count * 2` bytes; output regions are pairwise disjoint. A
/// solver reconstructs every `outputs[j]` in place, in `missing_indices` order.
///
/// This carries no pre-built matrix and no weaver-specific types: it is exactly
/// the data a host needs to (re)build the repair coefficient matrix (via
/// [`reedsolomon_rs::matrix::build_repair_matrix`]) and run the GF matmul.
pub struct RepairProblem<'a> {
    /// Total input slices in the recovery set (indexes `constants`).
    pub total_inputs: usize,
    /// `u16` words per slice; each region is `word_count * 2` bytes.
    pub word_count: usize,
    /// Global indices of the missing slices (one per output row).
    pub missing_indices: &'a [usize],
    /// Global indices of the available input slices (source columns first).
    pub available_indices: &'a [usize],
    /// Recovery-block exponents used, one per missing slice (source columns last).
    pub recovery_exponents: &'a [u32],
    /// PAR2 input-slice constants for every input slice in the recovery set.
    pub constants: &'a [u16],
    /// Source byte-regions: available inputs then recovery blocks.
    pub sources: &'a [&'a [u8]],
    /// Output byte-regions for the reconstructed missing slices (disjoint).
    pub outputs: &'a mut [&'a mut [u8]],
}

impl RepairProblem<'_> {
    /// Bytes per source/output region (`word_count * 2`).
    #[inline]
    pub fn slice_bytes(&self) -> usize {
        self.word_count * 2
    }
}

/// Failure returned by a [`RepairSolver`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SolverError {
    /// The selected recovery exponents form a singular (non-invertible) matrix.
    Singular {
        /// Index into `recovery_exponents` of the unusable row, when known.
        bad_row: Option<usize>,
    },
    /// The problem's dimensions were inconsistent with the solver.
    Dimensions(String),
    /// The solve was cancelled cooperatively.
    Cancelled,
    /// An opaque host-side failure (e.g. a wasm host-fn error code).
    Host(String),
}

impl std::fmt::Display for SolverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SolverError::Singular { bad_row: Some(row) } => {
                write!(f, "repair matrix is singular (recovery row {row})")
            }
            SolverError::Singular { bad_row: None } => write!(f, "repair matrix is singular"),
            SolverError::Dimensions(reason) => write!(f, "repair problem dimensions: {reason}"),
            SolverError::Cancelled => write!(f, "repair reconstruct cancelled"),
            SolverError::Host(reason) => write!(f, "repair solver host failure: {reason}"),
        }
    }
}

impl std::error::Error for SolverError {}

impl From<SolverError> for Par2Error {
    fn from(error: SolverError) -> Self {
        match error {
            SolverError::Cancelled => Par2Error::Cancelled,
            other => Par2Error::ReedSolomonError {
                reason: other.to_string(),
            },
        }
    }
}

/// The injectable reconstruct step of a PAR2 repair.
///
/// par2-rs calls this once per repair, at whole-reconstruct granularity;
/// the hot per-element GF loop lives entirely inside an implementation, so the
/// native default ([`NativeRepairSolver`]) is monomorphised with no dynamic
/// dispatch on that loop. A host (e.g. a wasm plugin) implements this to run
/// the solve off the rayon path — for example by marshaling `problem` to a
/// native host-thread solver — without par2-rs knowing any host ABI.
pub trait RepairSolver {
    /// Reconstruct every `problem.outputs[j]` in place from `problem.sources`.
    fn reconstruct(&self, problem: &mut RepairProblem<'_>) -> std::result::Result<(), SolverError>;
}

/// The native default solver: weaver's rayon GF(2^16) matmul over the plan's
/// pre-built `input_factors`. Byte-identical to the pre-seam in-memory
/// reconstruct, and the path exercised by the crate's own repair tests.
pub struct NativeRepairSolver<'a> {
    input_factors: &'a matrix::Matrix,
    chunk_words: usize,
    cancel: Option<CancellationToken>,
}

impl<'a> NativeRepairSolver<'a> {
    /// Build a solver over the plan's repair coefficient matrix. `chunk_words`
    /// is the per-output word tiling used by the rayon kernel.
    pub fn new(input_factors: &'a matrix::Matrix, chunk_words: usize) -> Self {
        Self {
            input_factors,
            chunk_words,
            cancel: None,
        }
    }

    /// Attach a cancellation token, checked once per output row.
    pub fn with_cancellation(mut self, cancel: Option<CancellationToken>) -> Self {
        self.cancel = cancel;
        self
    }
}

impl RepairSolver for NativeRepairSolver<'_> {
    fn reconstruct(&self, problem: &mut RepairProblem<'_>) -> std::result::Result<(), SolverError> {
        let n = problem.outputs.len();
        if n == 0 {
            return Ok(());
        }
        if self.input_factors.rows != n {
            return Err(SolverError::Dimensions(format!(
                "input_factors has {} rows but {n} outputs",
                self.input_factors.rows
            )));
        }
        if self.input_factors.cols != problem.sources.len() {
            return Err(SolverError::Dimensions(format!(
                "input_factors has {} cols but {} sources",
                self.input_factors.cols,
                problem.sources.len()
            )));
        }

        let word_count = problem.word_count;
        let chunk_words = self.chunk_words.max(1);
        let total_chunks_usize = word_count.div_ceil(chunk_words);

        // Deduplicate prepared multiply tables per distinct factor value; a
        // dense decode matrix repeats factors across (output, input) pairs, and
        // preparing one table per pair would multiply memory by outputs*inputs.
        let output_inputs = grouped_input_factors(self.input_factors);
        let mut factor_slots: HashMap<u16, usize> = HashMap::new();
        let mut prepared_factors: Vec<crate::gf_simd::PreparedInputFactor> = Vec::new();
        let prepared_output_inputs: Vec<Vec<(u16, usize)>> = output_inputs
            .iter()
            .map(|inputs| {
                inputs
                    .iter()
                    .map(|factor_input| {
                        let slot = *factor_slots.entry(factor_input.factor).or_insert_with(|| {
                            prepared_factors
                                .push(crate::gf_simd::prepare_input_factor(factor_input.factor));
                            prepared_factors.len() - 1
                        });
                        (factor_input.input_idx, slot)
                    })
                    .collect()
            })
            .collect();

        let sources = problem.sources;
        let prepared_factors = &prepared_factors;
        let prepared_output_inputs = &prepared_output_inputs;
        let cancel = self.cancel.as_ref();
        let outputs = &mut *problem.outputs;

        outputs.par_iter_mut().enumerate().try_for_each(
            |(output_idx, out)| -> std::result::Result<(), SolverError> {
                if let Some(cancel) = cancel
                    && cancel.is_cancelled()
                {
                    return Err(SolverError::Cancelled);
                }
                let out: &mut [u8] = out;
                let decode_inputs = &prepared_output_inputs[output_idx];
                let mut chunk_inputs = Vec::with_capacity(decode_inputs.len());

                for chunk_idx in 0..total_chunks_usize {
                    let chunk_start = chunk_idx * chunk_words;
                    let chunk_end = (chunk_start + chunk_words).min(word_count);
                    let byte_start = chunk_start * 2;
                    let byte_len = (chunk_end - chunk_start) * 2;

                    chunk_inputs.clear();
                    for (input_idx, factor_slot) in decode_inputs {
                        chunk_inputs.push(crate::gf_simd::PreparedFactorSrc {
                            prepared: &prepared_factors[*factor_slot],
                            src: &sources[*input_idx as usize][byte_start..byte_start + byte_len],
                        });
                    }

                    crate::gf_simd::mul_acc_input_batch_prepared(
                        &mut out[byte_start..byte_start + byte_len],
                        &chunk_inputs,
                    );
                }

                Ok(())
            },
        )
    }
}

/// The wasm-only whole-buffer solver seam. Native targets compile and execute
/// only the streamed controller.
#[cfg(target_arch = "wasm32")]
fn run_in_memory_repair<S: RepairSolver + ?Sized>(
    plan: &RepairPlan,
    par2_set: &Par2FileSet,
    file_access: &mut dyn FileAccess,
    options: &RepairOptions,
    solver: &S,
) -> Result<()> {
    let n = plan.missing_slices.len();
    if n == 0 {
        return Ok(());
    }

    let slice_size = plan.slice_size as usize;
    assert!(
        slice_size.is_multiple_of(2),
        "PAR2 slice_size must be a multiple of 2"
    );
    let word_count = slice_size / 2;
    let available_inputs = plan.available_input_global_indices.len();
    let total_inputs = available_inputs + plan.recovery_exponents.len();
    let total_inputs_u32 = total_inputs.min(u32::MAX as usize) as u32;
    let read_total_bytes = (total_inputs as u64).saturating_mul(slice_size as u64);
    let repair_total_bytes = (n as u64).saturating_mul(slice_size as u64);
    let write_total_bytes = (n as u64).saturating_mul(slice_size as u64);
    let operation_total_bytes = read_total_bytes
        .saturating_add(repair_total_bytes)
        .saturating_add(write_total_bytes);
    let mut input_buffers: Vec<Vec<u8>> = vec![vec![0u8; slice_size]; total_inputs];
    let mut repaired_slices: Vec<Vec<u8>> = vec![vec![0u8; slice_size]; n];

    for (input_idx, &global_idx) in plan.available_input_global_indices.iter().enumerate() {
        if input_idx % 64 == 0 {
            check_cancel(options)?;
        }

        let (file_id, local_slice) = plan.global_to_file[global_idx];
        let offset = local_slice as u64 * plan.slice_size;
        let read_len = file_access
            .read_file_range_into(&file_id, offset, &mut input_buffers[input_idx])
            .map_err(Par2Error::Io)?;
        input_buffers[input_idx][read_len..].fill(0);

        if let Some(ref progress) = options.progress {
            progress(ProgressUpdate {
                stage: ProgressStage::Repairing,
                current: input_idx as u32 + 1,
                total: total_inputs_u32,
                bytes_processed: (input_idx + 1) as u64 * slice_size as u64,
                total_bytes: Some(operation_total_bytes),
            });
        }
    }

    for (recovery_idx, &exp) in plan.recovery_exponents.iter().enumerate() {
        check_cancel(options)?;
        let rs = par2_set
            .recovery_slices
            .get(&exp)
            .ok_or_else(|| Par2Error::ReedSolomonError {
                reason: format!("recovery block with exponent {exp} not found"),
            })?;
        let recovery_data = rs.data.to_vec().map_err(Par2Error::Io)?;
        let copy_len = recovery_data.len().min(slice_size);
        input_buffers[available_inputs + recovery_idx][..copy_len]
            .copy_from_slice(&recovery_data[..copy_len]);
        input_buffers[available_inputs + recovery_idx][copy_len..].fill(0);

        if let Some(ref progress) = options.progress {
            let current = available_inputs + recovery_idx + 1;
            progress(ProgressUpdate {
                stage: ProgressStage::Repairing,
                current: current.min(u32::MAX as usize) as u32,
                total: total_inputs_u32,
                bytes_processed: current as u64 * slice_size as u64,
                total_bytes: Some(operation_total_bytes),
            });
        }
    }

    check_cancel(options)?;

    // Reconstruct through the solver seam. The borrows of `input_buffers` and
    // `repaired_slices` are scoped so the slices are free to write afterwards.
    {
        let source_refs: Vec<&[u8]> = input_buffers.iter().map(|b| b.as_slice()).collect();
        let mut output_refs: Vec<&mut [u8]> = repaired_slices
            .iter_mut()
            .map(|b| b.as_mut_slice())
            .collect();
        let mut problem = RepairProblem {
            total_inputs: plan.total_input_slices,
            word_count,
            missing_indices: &plan.missing_global_indices,
            available_indices: &plan.available_input_global_indices,
            recovery_exponents: &plan.recovery_exponents,
            constants: &plan.constants,
            sources: &source_refs,
            outputs: &mut output_refs,
        };
        solver.reconstruct(&mut problem)?;
    }

    if let Some(ref progress) = options.progress {
        progress(ProgressUpdate {
            stage: ProgressStage::Repairing,
            current: n as u32,
            total: n as u32,
            bytes_processed: read_total_bytes.saturating_add(repair_total_bytes),
            total_bytes: Some(operation_total_bytes),
        });
    }

    check_cancel(options)?;
    info!("writing repaired slices to files");
    let write_targets = build_write_targets(plan, par2_set)?;
    for (j, target) in write_targets.iter().enumerate() {
        check_cancel(options)?;

        let slice_end = target.offset + plan.slice_size;
        let write_len = if slice_end > target.file_end {
            (target.file_end - target.offset) as usize
        } else {
            slice_size
        };

        file_access
            .write_file_range(
                &target.file_id,
                target.offset,
                &repaired_slices[j][..write_len],
            )
            .map_err(|e| Par2Error::RepairWriteFailed {
                filename: target.filename.clone(),
                offset: target.offset,
                source: e,
            })?;

        if let Some(ref progress) = options.progress {
            progress(ProgressUpdate {
                stage: ProgressStage::WritingRepaired,
                current: j as u32 + 1,
                total: n as u32,
                bytes_processed: read_total_bytes
                    .saturating_add(repair_total_bytes)
                    .saturating_add((j + 1) as u64 * slice_size as u64),
                total_bytes: Some(operation_total_bytes),
            });
        }
    }

    info!("repair complete: {} slices restored", n);
    Ok(())
}

/// Execute a repair plan through a caller-provided [`RepairSolver`].
///
/// WebAssembly hosts may use this adapter to provide their own reconstruction
/// runtime. Native repair is exclusively driven by the streamed controller.
pub fn execute_repair_with_solver<S: RepairSolver + ?Sized>(
    plan: &RepairPlan,
    par2_set: &Par2FileSet,
    file_access: &mut dyn FileAccess,
    options: &RepairOptions,
    solver: &S,
) -> Result<()> {
    let n = plan.missing_slices.len();
    if n == 0 {
        return Ok(());
    }
    #[cfg(target_arch = "wasm32")]
    return run_in_memory_repair(plan, par2_set, file_access, options, solver);

    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (par2_set, file_access, options, solver);
        Err(Par2Error::ReedSolomonError {
            reason: "caller-provided in-memory PAR2 solvers are only supported on wasm32; native repair uses the streamed controller"
                .to_string(),
        })
    }
}

/// Execute a repair plan with cancellation, progress, and memory budget support.
pub fn execute_repair_with_options(
    plan: &RepairPlan,
    par2_set: &Par2FileSet,
    file_access: &mut dyn FileAccess,
    options: &RepairOptions,
) -> Result<()> {
    let n = plan.missing_slices.len();
    if n == 0 {
        return Ok(());
    }

    let slice_size = plan.slice_size as usize;
    assert!(
        slice_size.is_multiple_of(2),
        "PAR2 slice_size must be a multiple of 2"
    );

    let budget = options.memory_limit.unwrap_or(DEFAULT_REPAIR_MEMORY_LIMIT);
    execute_repair_streaming(plan, par2_set, file_access, options, budget)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checksum::{self, SliceChecksumState};
    use crate::packet::header;
    use crate::par2_set::{Par2FileSet, RecoverySlice};
    use crate::types::SliceChecksum;
    use crate::verify::{self, FileStatus, FileVerification, MemoryFileAccess};
    use bytes::Bytes;
    use md5::{Digest, Md5};
    use tempfile::tempdir;

    struct FailingReadAccess {
        inner: MemoryFileAccess,
        fail_after: usize,
        reads: std::sync::atomic::AtomicUsize,
    }

    impl FileAccess for FailingReadAccess {
        fn read_file_range(
            &self,
            file_id: &FileId,
            offset: u64,
            len: u64,
        ) -> std::io::Result<Vec<u8>> {
            self.inner.read_file_range(file_id, offset, len)
        }

        fn read_file_range_into(
            &self,
            file_id: &FileId,
            offset: u64,
            dst: &mut [u8],
        ) -> std::io::Result<usize> {
            let read = self
                .reads
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if read >= self.fail_after {
                return Err(std::io::Error::other("injected controller read failure"));
            }
            self.inner.read_file_range_into(file_id, offset, dst)
        }

        fn file_exists(&self, file_id: &FileId) -> bool {
            self.inner.file_exists(file_id)
        }

        fn file_length(&self, file_id: &FileId) -> Option<u64> {
            self.inner.file_length(file_id)
        }

        fn read_file(&self, file_id: &FileId) -> std::io::Result<Vec<u8>> {
            self.inner.read_file(file_id)
        }

        fn write_file_range(
            &mut self,
            file_id: &FileId,
            offset: u64,
            data: &[u8],
        ) -> std::io::Result<()> {
            self.inner.write_file_range(file_id, offset, data)
        }
    }

    struct CountingRangeAccess {
        inner: MemoryFileAccess,
        range_opens: std::sync::atomic::AtomicUsize,
        fallback_reads: std::sync::atomic::AtomicUsize,
    }

    impl FileAccess for CountingRangeAccess {
        fn read_file_range(
            &self,
            file_id: &FileId,
            offset: u64,
            len: u64,
        ) -> std::io::Result<Vec<u8>> {
            self.inner.read_file_range(file_id, offset, len)
        }

        fn read_file_range_into(
            &self,
            file_id: &FileId,
            offset: u64,
            dst: &mut [u8],
        ) -> std::io::Result<usize> {
            self.fallback_reads
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.inner.read_file_range_into(file_id, offset, dst)
        }

        fn open_range_reader(
            &self,
            file_id: &FileId,
        ) -> std::io::Result<Option<Box<dyn FileRangeReader>>> {
            self.range_opens
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(Some(Box::new(std::io::Cursor::new(
                self.inner.read_file(file_id)?,
            ))))
        }

        fn file_exists(&self, file_id: &FileId) -> bool {
            self.inner.file_exists(file_id)
        }

        fn file_length(&self, file_id: &FileId) -> Option<u64> {
            self.inner.file_length(file_id)
        }

        fn read_file(&self, file_id: &FileId) -> std::io::Result<Vec<u8>> {
            self.inner.read_file(file_id)
        }

        fn write_file_range(
            &mut self,
            file_id: &FileId,
            offset: u64,
            data: &[u8],
        ) -> std::io::Result<()> {
            self.inner.write_file_range(file_id, offset, data)
        }
    }

    struct FailingWriteAccess {
        inner: MemoryFileAccess,
    }

    impl FileAccess for FailingWriteAccess {
        fn read_file_range(
            &self,
            file_id: &FileId,
            offset: u64,
            len: u64,
        ) -> std::io::Result<Vec<u8>> {
            self.inner.read_file_range(file_id, offset, len)
        }

        fn read_file_range_into(
            &self,
            file_id: &FileId,
            offset: u64,
            dst: &mut [u8],
        ) -> std::io::Result<usize> {
            self.inner.read_file_range_into(file_id, offset, dst)
        }

        fn file_exists(&self, file_id: &FileId) -> bool {
            self.inner.file_exists(file_id)
        }

        fn file_length(&self, file_id: &FileId) -> Option<u64> {
            self.inner.file_length(file_id)
        }

        fn read_file(&self, file_id: &FileId) -> std::io::Result<Vec<u8>> {
            self.inner.read_file(file_id)
        }

        fn write_file_range(
            &mut self,
            _file_id: &FileId,
            _offset: u64,
            _data: &[u8],
        ) -> std::io::Result<()> {
            Err(std::io::Error::other("injected controller write failure"))
        }
    }

    /// Helper to build a complete valid packet (header + body).
    fn make_full_packet(packet_type: &[u8; 16], body: &[u8], recovery_set_id: [u8; 16]) -> Vec<u8> {
        let length = (header::HEADER_SIZE + body.len()) as u64;
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&recovery_set_id);
        hash_input.extend_from_slice(packet_type);
        hash_input.extend_from_slice(body);
        let packet_hash: [u8; 16] = Md5::digest(&hash_input).into();

        let mut data = Vec::new();
        data.extend_from_slice(header::MAGIC);
        data.extend_from_slice(&length.to_le_bytes());
        data.extend_from_slice(&packet_hash);
        data.extend_from_slice(&recovery_set_id);
        data.extend_from_slice(packet_type);
        data.extend_from_slice(body);
        data
    }

    /// Create a PAR2 file set with known data and recovery blocks.
    ///
    /// Returns (par2_set, original_file_data, file_id).
    fn setup_repairable_set(
        file_data: &[u8],
        slice_size: u64,
        num_recovery: usize,
    ) -> (Par2FileSet, FileId) {
        let file_length = file_data.len() as u64;
        let hash_full = checksum::md5(file_data);
        let hash_16k_data = &file_data[..file_data.len().min(16384)];
        let hash_16k = checksum::md5(hash_16k_data);

        let filename = b"testfile.dat";
        let mut id_input = Vec::new();
        id_input.extend_from_slice(&hash_16k);
        id_input.extend_from_slice(&file_length.to_le_bytes());
        id_input.extend_from_slice(filename);
        let file_id_bytes: [u8; 16] = Md5::digest(&id_input).into();
        let file_id = FileId::from_bytes(file_id_bytes);

        let num_slices = if file_length == 0 {
            0
        } else {
            file_length.div_ceil(slice_size) as usize
        };

        let mut checksums = Vec::new();
        for i in 0..num_slices {
            let offset = i as u64 * slice_size;
            let end = ((offset + slice_size) as usize).min(file_data.len());
            let slice_data = &file_data[offset as usize..end];
            let mut state = SliceChecksumState::new();
            state.update(slice_data);
            let pad_to = if (slice_data.len() as u64) < slice_size {
                Some(slice_size)
            } else {
                None
            };
            let (crc, md5) = state.finalize(pad_to);
            checksums.push(SliceChecksum { crc32: crc, md5 });
        }

        // Build packets
        let mut main_body = Vec::new();
        main_body.extend_from_slice(&slice_size.to_le_bytes());
        main_body.extend_from_slice(&1u32.to_le_bytes());
        main_body.extend_from_slice(&file_id_bytes);
        let rsid: [u8; 16] = Md5::digest(&main_body).into();

        let mut fd_body = Vec::new();
        fd_body.extend_from_slice(&file_id_bytes);
        fd_body.extend_from_slice(&hash_full);
        fd_body.extend_from_slice(&hash_16k);
        fd_body.extend_from_slice(&file_length.to_le_bytes());
        fd_body.extend_from_slice(filename);
        while fd_body.len() % 4 != 0 {
            fd_body.push(0);
        }

        let mut ifsc_body = Vec::new();
        ifsc_body.extend_from_slice(&file_id_bytes);
        for cs in &checksums {
            ifsc_body.extend_from_slice(&cs.md5);
            ifsc_body.extend_from_slice(&cs.crc32.to_le_bytes());
        }

        let mut stream = Vec::new();
        stream.extend_from_slice(&make_full_packet(header::TYPE_MAIN, &main_body, rsid));
        stream.extend_from_slice(&make_full_packet(header::TYPE_FILE_DESC, &fd_body, rsid));
        stream.extend_from_slice(&make_full_packet(header::TYPE_IFSC, &ifsc_body, rsid));

        let mut set = Par2FileSet::from_files(&[&stream]).unwrap();

        // Generate recovery blocks using the PAR2 encoding formula.
        let constants = gf::input_slice_constants(num_slices);
        let ss = slice_size as usize;
        let word_count = ss / 2;

        // Pad file data to full slices.
        let mut padded = file_data.to_vec();
        padded.resize(num_slices * ss, 0);

        for r in 0..num_recovery {
            let exp = r as u32;
            let mut recovery = vec![0u8; ss];

            for (i, &constant) in constants.iter().enumerate() {
                let factor = gf::pow(constant, exp);
                for w in 0..word_count {
                    let input_word =
                        u16::from_le_bytes([padded[i * ss + w * 2], padded[i * ss + w * 2 + 1]]);
                    let contribution = gf::mul(input_word, factor);
                    let rec_word = u16::from_le_bytes([recovery[w * 2], recovery[w * 2 + 1]]);
                    let new_val = gf::add(rec_word, contribution);
                    let bytes = new_val.to_le_bytes();
                    recovery[w * 2] = bytes[0];
                    recovery[w * 2 + 1] = bytes[1];
                }
            }

            set.recovery_slices.insert(
                exp,
                RecoverySlice {
                    exponent: exp,
                    data: Bytes::from(recovery).into(),
                },
            );
        }

        (set, file_id)
    }

    fn spill_recovery_slices_to_disk(set: &mut Par2FileSet) -> tempfile::TempDir {
        let dir = tempdir().unwrap();
        for (exp, slice) in &mut set.recovery_slices {
            let path = dir.path().join(format!("recovery_{exp}.bin"));
            let bytes = slice.data.to_vec().unwrap();
            std::fs::write(&path, &bytes).unwrap();
            slice.data = crate::packet::RecoverySliceData::file_backed(path, 0, bytes.len());
        }
        dir
    }

    /// Like [`spill_recovery_slices_to_disk`], but records the PAR2 packet
    /// hash the streaming scanner would have captured, enabling lazy payload
    /// validation.
    fn spill_recovery_slices_to_disk_with_hashes(set: &mut Par2FileSet) -> tempfile::TempDir {
        let dir = tempdir().unwrap();
        let rsid = *set.recovery_set_id.as_bytes();
        for (exp, slice) in &mut set.recovery_slices {
            let path = dir.path().join(format!("recovery_{exp}.bin"));
            let bytes = slice.data.to_vec().unwrap();
            std::fs::write(&path, &bytes).unwrap();

            let mut hash_input = Vec::new();
            hash_input.extend_from_slice(&rsid);
            hash_input.extend_from_slice(header::TYPE_RECOVERY);
            hash_input.extend_from_slice(&exp.to_le_bytes());
            hash_input.extend_from_slice(&bytes);
            let packet_hash: [u8; 16] = Md5::digest(&hash_input).into();

            slice.data = crate::packet::RecoverySliceData::file_backed_with_hash(
                path,
                0,
                bytes.len(),
                packet_hash,
            );
        }
        dir
    }

    #[test]
    fn plan_repair_skips_recovery_blocks_with_corrupt_payloads() {
        let slice_size = 64u64;
        let file_data: Vec<u8> = (0..256u32).map(|i| ((i * 11 + 3) % 256) as u8).collect();
        let (mut par2_set, file_id) = setup_repairable_set(&file_data, slice_size, 4);
        let spill_dir = spill_recovery_slices_to_disk_with_hashes(&mut par2_set);

        // Corrupt the payloads of the two lowest exponents on disk. Selection
        // prefers low exponents, so the plan must detect the damage and fall
        // back to the clean blocks.
        for exp in [0u32, 1] {
            let path = spill_dir.path().join(format!("recovery_{exp}.bin"));
            let mut bytes = std::fs::read(&path).unwrap();
            bytes[7] ^= 0xFF;
            std::fs::write(&path, &bytes).unwrap();
        }

        let mut damaged = file_data.clone();
        damaged[..64].fill(0);
        damaged[128..192].fill(0);

        let mut access = MemoryFileAccess::new();
        access.add_file(file_id, damaged);

        let result = verify::verify_all(&par2_set, &access);
        assert_eq!(result.total_missing_blocks, 2);

        let plan = plan_repair(&par2_set, &result).unwrap();
        assert!(!plan.recovery_exponents.contains(&0));
        assert!(!plan.recovery_exponents.contains(&1));

        execute_repair(&plan, &par2_set, &mut access).unwrap();
        let repaired = access.read_file(&file_id).unwrap();
        assert_eq!(repaired, file_data);
    }

    #[test]
    fn plan_repair_fails_when_all_recovery_payloads_are_corrupt() {
        let slice_size = 64u64;
        let file_data: Vec<u8> = (0..256u32).map(|i| ((i * 5 + 1) % 256) as u8).collect();
        let (mut par2_set, file_id) = setup_repairable_set(&file_data, slice_size, 2);
        let spill_dir = spill_recovery_slices_to_disk_with_hashes(&mut par2_set);

        for exp in [0u32, 1] {
            let path = spill_dir.path().join(format!("recovery_{exp}.bin"));
            let mut bytes = std::fs::read(&path).unwrap();
            bytes[0] ^= 0x01;
            std::fs::write(&path, &bytes).unwrap();
        }

        let mut damaged = file_data.clone();
        damaged[..64].fill(0);

        let mut access = MemoryFileAccess::new();
        access.add_file(file_id, damaged);

        let result = verify::verify_all(&par2_set, &access);
        let err = plan_repair(&par2_set, &result).unwrap_err();
        assert!(matches!(err, Par2Error::InsufficientRecoveryData { .. }));
    }

    #[test]
    fn end_to_end_repair_single_damaged_slice() {
        // Create a file with 4 slices of 64 bytes each (256 bytes total).
        let slice_size = 64u64;
        let file_data: Vec<u8> = (0..256u32).map(|i| (i % 256) as u8).collect();
        let (par2_set, file_id) = setup_repairable_set(&file_data, slice_size, 2);

        // Set up access with damaged data (corrupt slice 2).
        let mut damaged = file_data.clone();
        for item in damaged.iter_mut().take(192).skip(128) {
            *item ^= 0xFF;
        }

        let mut access = MemoryFileAccess::new();
        access.add_file(file_id, damaged);

        // Verify.
        let result = verify::verify_all(&par2_set, &access);
        assert_eq!(result.total_missing_blocks, 1);
        assert!(matches!(
            result.repairable,
            Repairability::Repairable { .. }
        ));

        // Plan repair.
        let plan = plan_repair(&par2_set, &result).unwrap();
        assert_eq!(plan.missing_slices.len(), 1);
        assert_eq!(plan.missing_slices[0], (file_id, 2));

        // Execute repair.
        execute_repair(&plan, &par2_set, &mut access).unwrap();

        // Verify the repaired data matches original.
        let repaired = access.read_file(&file_id).unwrap();
        assert_eq!(repaired, file_data, "repaired data should match original");
    }

    #[test]
    fn end_to_end_repair_multiple_damaged_slices() {
        let slice_size = 32u64;
        let file_data: Vec<u8> = (0..128u32).map(|i| ((i * 7 + 13) % 256) as u8).collect();
        let (par2_set, file_id) = setup_repairable_set(&file_data, slice_size, 3);

        // Damage slices 0 and 3 (out of 4 total).
        let mut damaged = file_data.clone();
        for item in damaged.iter_mut().take(32) {
            *item = 0;
        }
        for item in damaged.iter_mut().take(128).skip(96) {
            *item = 0;
        }

        let mut access = MemoryFileAccess::new();
        access.add_file(file_id, damaged);

        let result = verify::verify_all(&par2_set, &access);
        assert_eq!(result.total_missing_blocks, 2);

        let plan = plan_repair(&par2_set, &result).unwrap();
        assert_eq!(plan.missing_slices.len(), 2);

        execute_repair(&plan, &par2_set, &mut access).unwrap();

        let repaired = access.read_file(&file_id).unwrap();
        assert_eq!(repaired, file_data);
    }

    #[test]
    fn end_to_end_repair_missing_file() {
        // Test repairing a completely missing file.
        let slice_size = 64u64;
        let file_data: Vec<u8> = (0..128u32).map(|i| (i % 256) as u8).collect();
        let (par2_set, file_id) = setup_repairable_set(&file_data, slice_size, 4);

        // File is completely missing -- create with zeros so write_file_range works.
        let mut access = MemoryFileAccess::new();
        access.add_file(file_id, vec![0u8; 128]);

        let result = verify::verify_all(&par2_set, &access);
        assert_eq!(result.total_missing_blocks, 2); // 2 slices, both damaged

        let plan = plan_repair(&par2_set, &result).unwrap();
        assert_eq!(plan.missing_slices.len(), 2);

        execute_repair(&plan, &par2_set, &mut access).unwrap();

        let repaired = access.read_file(&file_id).unwrap();
        assert_eq!(repaired, file_data);
    }

    #[test]
    fn plan_repair_not_needed() {
        let slice_size = 64u64;
        let file_data = vec![0xABu8; 128];
        let (par2_set, file_id) = setup_repairable_set(&file_data, slice_size, 2);

        let mut access = MemoryFileAccess::new();
        access.add_file(file_id, file_data);

        let result = verify::verify_all(&par2_set, &access);
        let err = plan_repair(&par2_set, &result).unwrap_err();
        assert!(matches!(err, Par2Error::ReedSolomonError { .. }));
    }

    #[test]
    fn plan_repair_insufficient() {
        let slice_size = 64u64;
        let file_data: Vec<u8> = (0..256u32).map(|i| (i % 256) as u8).collect();
        let (par2_set, file_id) = setup_repairable_set(&file_data, slice_size, 1);

        // Damage 2 slices but only 1 recovery block.
        let mut damaged = file_data.clone();
        for item in damaged.iter_mut().take(64) {
            *item = 0;
        }
        for item in damaged.iter_mut().take(128).skip(64) {
            *item = 0;
        }

        let mut access = MemoryFileAccess::new();
        access.add_file(file_id, damaged);

        let result = verify::verify_all(&par2_set, &access);
        let err = plan_repair(&par2_set, &result).unwrap_err();
        assert!(matches!(err, Par2Error::InsufficientRecoveryData { .. }));
    }

    #[test]
    fn plan_repair_rejects_resource_limited_verification() {
        let slice_size = 64u64;
        let file_data = vec![0xABu8; 128];
        let (par2_set, file_id) = setup_repairable_set(&file_data, slice_size, 2);
        let result = VerificationResult {
            files: vec![FileVerification {
                file_id,
                filename: "testfile.dat".to_string(),
                status: FileStatus::Damaged(0),
                valid_slices: Vec::new(),
                missing_slice_count: 0,
            }],
            recovery_blocks_available: 2,
            total_missing_blocks: 0,
            repairable: Repairability::ResourceLimited {
                reason: "file testfile.dat exceeds verifier slice limits".to_string(),
            },
        };

        let err = plan_repair(&par2_set, &result).unwrap_err();
        assert!(matches!(err, Par2Error::ResourceLimitExceeded { .. }));
    }

    #[test]
    fn matrix_memory_budget_has_floor_but_still_caps() {
        // A tiny slice-buffer limit no longer starves the transient decode
        // matrix: planning small repairs succeeds even at absurd limits.
        assert!(repair_matrix_limit_reason(4, 2, Some(8)).is_none());

        // A matrix that exceeds even the budget floor is still refused...
        let missing = 20_000usize;
        let reason = repair_matrix_limit_reason(32_768, missing, Some(8)).unwrap();
        assert!(reason.contains("matrix workspace budget"));

        // ...unless the caller raises the limit explicitly.
        assert!(repair_matrix_limit_reason(32_768, missing, Some(8 << 30)).is_none());

        // Sets beyond the PAR2 total-slice cap are reported as such.
        let reason = repair_matrix_limit_reason(40_000, 1, None).unwrap();
        assert!(reason.contains("at most"));
    }

    #[test]
    fn plan_repair_succeeds_with_tiny_configured_memory_limit() {
        let slice_size = 64u64;
        let file_data: Vec<u8> = (0..256u32).map(|i| (i % 256) as u8).collect();
        let (par2_set, file_id) = setup_repairable_set(&file_data, slice_size, 3);

        let mut damaged = file_data.clone();
        damaged[..64].fill(0);
        damaged[64..128].fill(0);

        let mut access = MemoryFileAccess::new();
        access.add_file(file_id, damaged);

        let result = verify::verify_all(&par2_set, &access);
        assert_eq!(result.total_missing_blocks, 2);

        let plan = plan_repair_with_memory_limit(&par2_set, &result, Some(8)).unwrap();
        assert_eq!(plan.missing_slices.len(), 2);
    }

    #[test]
    fn plan_repair_rejects_sets_over_total_slice_limit() {
        let slice_size = 4u64;
        let slices_per_file = 20_000u64;
        let mut files = HashMap::new();
        let mut recovery_file_ids = Vec::new();
        let mut verifications = Vec::new();
        for index in 0..2u8 {
            let file_id = FileId::from_bytes([index + 1; 16]);
            recovery_file_ids.push(file_id);
            files.insert(
                file_id,
                crate::par2_set::FileDescription {
                    file_id,
                    hash_full: [0; 16],
                    hash_16k: [0; 16],
                    length: slice_size * slices_per_file,
                    par2_name: format!("big{index}.dat"),
                    filename: format!("big{index}.dat"),
                },
            );
            let mut valid_slices = vec![true; slices_per_file as usize];
            if index == 0 {
                valid_slices[0] = false;
            }
            verifications.push(FileVerification {
                file_id,
                filename: format!("big{index}.dat"),
                status: if index == 0 {
                    FileStatus::Damaged(1)
                } else {
                    FileStatus::Complete
                },
                missing_slice_count: u32::from(index == 0),
                valid_slices,
            });
        }

        let mut recovery_slices = std::collections::BTreeMap::new();
        recovery_slices.insert(
            0,
            RecoverySlice {
                exponent: 0,
                data: Bytes::from(vec![0u8; slice_size as usize]).into(),
            },
        );
        let par2_set = Par2FileSet {
            recovery_set_id: crate::types::RecoverySetId::from_bytes([9; 16]),
            slice_size,
            recovery_file_ids,
            non_recovery_file_ids: Vec::new(),
            files,
            slice_checksums: HashMap::new(),
            recovery_slices,
            creator: None,
        };
        let result = VerificationResult {
            files: verifications,
            recovery_blocks_available: 1,
            total_missing_blocks: 1,
            repairable: Repairability::Repairable {
                blocks_needed: 1,
                blocks_available: 1,
            },
        };

        let err = plan_repair(&par2_set, &result).unwrap_err();
        assert!(matches!(err, Par2Error::ResourceLimitExceeded { .. }));
    }

    #[test]
    fn repair_with_partial_last_slice() {
        // File size not a multiple of slice_size.
        let slice_size = 64u64;
        // 100 bytes = 2 slices (64 + 36), last slice padded to 64 for RS.
        let file_data: Vec<u8> = (0..100u32).map(|i| ((i * 3 + 5) % 256) as u8).collect();
        let (par2_set, file_id) = setup_repairable_set(&file_data, slice_size, 2);

        // Damage the last slice.
        let mut damaged = file_data.clone();
        for item in damaged.iter_mut().take(100).skip(64) {
            *item = 0;
        }

        let mut access = MemoryFileAccess::new();
        access.add_file(file_id, damaged);

        let result = verify::verify_all(&par2_set, &access);
        assert_eq!(result.total_missing_blocks, 1);

        let plan = plan_repair(&par2_set, &result).unwrap();
        execute_repair(&plan, &par2_set, &mut access).unwrap();

        let repaired = access.read_file(&file_id).unwrap();
        assert_eq!(repaired, file_data);
    }

    #[test]
    fn repair_with_tiny_memory_limit_still_succeeds() {
        let slice_size = 128u64;
        let file_data: Vec<u8> = (0..384u32).map(|i| ((i * 9 + 17) % 256) as u8).collect();
        let (par2_set, file_id) = setup_repairable_set(&file_data, slice_size, 3);

        let mut damaged = file_data.clone();
        for item in damaged.iter_mut().take(128) {
            *item = 0;
        }
        for item in damaged.iter_mut().take(384).skip(256) {
            *item = 0;
        }

        let mut access = MemoryFileAccess::new();
        access.add_file(file_id, damaged);

        let result = verify::verify_all(&par2_set, &access);
        let plan = plan_repair(&par2_set, &result).unwrap();

        execute_repair_with_options(
            &plan,
            &par2_set,
            &mut access,
            &RepairOptions {
                memory_limit: Some(constrained_memory_limit_for_test(&plan)),
                ..RepairOptions::default()
            },
        )
        .unwrap();

        let repaired = access.read_file(&file_id).unwrap();
        assert_eq!(repaired, file_data);
    }

    #[test]
    fn streaming_controller_rotates_two_full_groups_and_flushes_partial_group() {
        let slice_size = 64u64;
        let file_data: Vec<u8> = (0..25 * slice_size as u32)
            .map(|i| ((i * 29 + 7) % 251) as u8)
            .collect();
        let (par2_set, file_id) = setup_repairable_set(&file_data, slice_size, 4);

        let mut damaged = file_data.clone();
        for slice in [0usize, 12, 24] {
            let start = slice * slice_size as usize;
            damaged[start..start + slice_size as usize].fill(0);
        }
        let mut access = MemoryFileAccess::new();
        access.add_file(file_id, damaged);

        let verification = verify::verify_all(&par2_set, &access);
        let plan = plan_repair(&par2_set, &verification).unwrap();
        assert_eq!(plan.input_factors.cols, 25);
        let trace = ControllerExecutionTrace::capture();
        execute_repair_streaming_with_trace(
            &plan,
            &par2_set,
            &mut access,
            &RepairOptions {
                memory_limit: Some(constrained_memory_limit_for_test(&plan)),
                ..RepairOptions::default()
            },
            constrained_memory_limit_for_test(&plan),
            trace.clone(),
        )
        .unwrap();

        assert_eq!(access.read_file(&file_id).unwrap(), file_data);
        let events = trace.events();
        let reads = events
            .iter()
            .filter(|event| matches!(event, ControllerExecutionEvent::SourceRead { .. }))
            .count();
        let queued = events
            .iter()
            .filter(|event| matches!(event, ControllerExecutionEvent::InputQueued { .. }))
            .count();
        let prepared = events
            .iter()
            .filter(|event| matches!(event, ControllerExecutionEvent::PreparationCompleted { .. }))
            .count();
        let submitted = events
            .iter()
            .filter(|event| matches!(event, ControllerExecutionEvent::ComputeSubmitted { .. }))
            .count();
        let completed = events
            .iter()
            .filter(|event| matches!(event, ControllerExecutionEvent::ComputeCompleted { .. }))
            .count();
        let lifecycle_submitted = events
            .iter()
            .filter(|event| matches!(event, ControllerExecutionEvent::BatchSubmitted { .. }))
            .count();
        let rotations = events
            .iter()
            .filter(|event| matches!(event, ControllerExecutionEvent::StagingRotated { .. }))
            .count();
        assert!(reads > 12);
        assert_eq!(reads, queued);
        assert!(prepared > 2);
        assert_eq!(prepared, submitted);
        assert_eq!(submitted, completed);
        assert_eq!(lifecycle_submitted, submitted);
        assert_eq!(rotations, lifecycle_submitted);
        assert!(
            events
                .iter()
                .all(|event| !matches!(event, ControllerExecutionEvent::Failed { .. }))
        );
        for staging_area in 0..2 {
            let prepared = events
                .iter()
                .position(|event| matches!(event, ControllerExecutionEvent::PreparationCompleted { staging_area: area, .. } if *area == staging_area));
            let submitted = events
                .iter()
                .position(|event| matches!(event, ControllerExecutionEvent::ComputeSubmitted { staging_area: area, .. } if *area == staging_area));
            if let (Some(prepared), Some(submitted)) = (prepared, submitted) {
                assert!(submitted < prepared);
            }
        }
        let first_wait = events
            .iter()
            .position(|event| matches!(event, ControllerExecutionEvent::WaitForAdd { .. }))
            .expect("two active staging areas trigger waitForAdd");
        assert!(
            events[..first_wait]
                .iter()
                .filter(|event| matches!(event, ControllerExecutionEvent::BatchSubmitted { .. }))
                .count()
                >= 2,
            "the live controller must not wait after submitting only one staging area"
        );
        assert!(events[..first_wait].iter().any(|event| matches!(
            event,
            ControllerExecutionEvent::SourceRead {
                source_index: 24,
                staging_area: 0,
            }
        )));
        let input_ended = events
            .iter()
            .position(|event| matches!(event, ControllerExecutionEvent::InputEnded { .. }))
            .expect("input lifecycle ended");
        let processing_finished = events
            .iter()
            .position(|event| matches!(event, ControllerExecutionEvent::ProcessingFinished))
            .expect("processing lifecycle finished");
        assert!(input_ended < processing_finished);
    }

    #[test]
    fn streaming_controller_read_failure_does_not_accept_partial_batch() {
        let slice_size = 64u64;
        let file_data: Vec<u8> = (0..25 * slice_size as u32)
            .map(|i| ((i * 17 + 5) % 251) as u8)
            .collect();
        let (par2_set, file_id) = setup_repairable_set(&file_data, slice_size, 4);
        let mut damaged = file_data.clone();
        for slice in [0usize, 12, 24] {
            let start = slice * slice_size as usize;
            damaged[start..start + slice_size as usize].fill(0);
        }

        let mut verification_access = MemoryFileAccess::new();
        verification_access.add_file(file_id, damaged.clone());
        let verification = verify::verify_all(&par2_set, &verification_access);
        let plan = plan_repair(&par2_set, &verification).unwrap();

        let mut inner = MemoryFileAccess::new();
        inner.add_file(file_id, damaged.clone());
        let mut access = FailingReadAccess {
            inner,
            fail_after: 1,
            reads: std::sync::atomic::AtomicUsize::new(0),
        };
        let trace = ControllerExecutionTrace::capture();
        let error = execute_repair_streaming_with_trace(
            &plan,
            &par2_set,
            &mut access,
            &RepairOptions {
                memory_limit: Some(constrained_memory_limit_for_test(&plan)),
                ..RepairOptions::default()
            },
            constrained_memory_limit_for_test(&plan),
            trace.clone(),
        )
        .unwrap_err();

        assert!(matches!(error, Par2Error::Io(_)));
        assert_eq!(access.read_file(&file_id).unwrap(), damaged);
        assert!(trace.events().iter().any(|event| matches!(
            event,
            ControllerExecutionEvent::Failed {
                phase: ControllerFailurePhase::Read
            }
        )));
    }

    #[test]
    fn streaming_controller_honors_cancellation_before_mutation() {
        let slice_size = 64u64;
        let file_data: Vec<u8> = (0..13 * slice_size as u32)
            .map(|i| ((i * 13 + 11) % 251) as u8)
            .collect();
        let (par2_set, file_id) = setup_repairable_set(&file_data, slice_size, 2);
        let mut damaged = file_data.clone();
        damaged[..slice_size as usize].fill(0);

        let mut access = MemoryFileAccess::new();
        access.add_file(file_id, damaged.clone());
        let verification = verify::verify_all(&par2_set, &access);
        let plan = plan_repair(&par2_set, &verification).unwrap();
        let cancel = CancellationToken::new();
        cancel.cancel();
        let error = execute_repair_with_options(
            &plan,
            &par2_set,
            &mut access,
            &RepairOptions {
                memory_limit: Some(256),
                cancel: Some(cancel),
                ..RepairOptions::default()
            },
        )
        .unwrap_err();

        assert!(matches!(error, Par2Error::Cancelled));
        assert_eq!(access.read_file(&file_id).unwrap(), damaged);
    }

    #[test]
    fn streaming_controller_reuses_seekable_source_reader() {
        let slice_size = 64u64;
        let file_data: Vec<u8> = (0..25 * slice_size as u32)
            .map(|i| ((i * 7 + 19) % 251) as u8)
            .collect();
        let (par2_set, file_id) = setup_repairable_set(&file_data, slice_size, 4);
        let mut damaged = file_data.clone();
        for slice in [0usize, 12, 24] {
            let start = slice * slice_size as usize;
            damaged[start..start + slice_size as usize].fill(0);
        }

        let mut verification_access = MemoryFileAccess::new();
        verification_access.add_file(file_id, damaged.clone());
        let verification = verify::verify_all(&par2_set, &verification_access);
        let plan = plan_repair(&par2_set, &verification).unwrap();

        let mut inner = MemoryFileAccess::new();
        inner.add_file(file_id, damaged);
        let mut access = CountingRangeAccess {
            inner,
            range_opens: std::sync::atomic::AtomicUsize::new(0),
            fallback_reads: std::sync::atomic::AtomicUsize::new(0),
        };
        execute_repair_with_options(
            &plan,
            &par2_set,
            &mut access,
            &RepairOptions {
                memory_limit: Some(constrained_memory_limit_for_test(&plan)),
                ..RepairOptions::default()
            },
        )
        .unwrap();

        assert!(
            access
                .range_opens
                .load(std::sync::atomic::Ordering::Relaxed)
                > 0
        );
        assert_eq!(
            access
                .fallback_reads
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert_eq!(access.read_file(&file_id).unwrap(), file_data);
    }

    #[test]
    fn streaming_controller_output_failure_is_not_accepted() {
        let slice_size = 64u64;
        let file_data: Vec<u8> = (0..13 * slice_size as u32)
            .map(|i| ((i * 31 + 3) % 251) as u8)
            .collect();
        let (par2_set, file_id) = setup_repairable_set(&file_data, slice_size, 2);
        let mut damaged = file_data.clone();
        damaged[..slice_size as usize].fill(0);

        let mut verification_access = MemoryFileAccess::new();
        verification_access.add_file(file_id, damaged.clone());
        let verification = verify::verify_all(&par2_set, &verification_access);
        let plan = plan_repair(&par2_set, &verification).unwrap();

        let mut inner = MemoryFileAccess::new();
        inner.add_file(file_id, damaged.clone());
        let mut access = FailingWriteAccess { inner };
        let trace = ControllerExecutionTrace::capture();
        let error = execute_repair_streaming_with_trace(
            &plan,
            &par2_set,
            &mut access,
            &RepairOptions {
                memory_limit: Some(constrained_memory_limit_for_test(&plan)),
                ..RepairOptions::default()
            },
            constrained_memory_limit_for_test(&plan),
            trace.clone(),
        )
        .unwrap_err();

        assert!(matches!(error, Par2Error::RepairWriteFailed { .. }));
        assert_eq!(access.read_file(&file_id).unwrap(), damaged);
        assert!(trace.events().iter().any(|event| matches!(
            event,
            ControllerExecutionEvent::Failed {
                phase: ControllerFailurePhase::Write
            }
        )));
    }

    #[test]
    fn compute_worker_failure_is_reported_before_output_transfer() {
        let factors = matrix::Matrix::identity(1);
        let memo = PreparedFactorMemo::from_matrix(&factors, false);
        let mut set = StreamBatchSet::new(2, 1, 1, 1, false, false, false);
        set.len = 1;
        set.coefficients[0] = 1;
        let layout = ControllerLayout {
            aligned_len: 4,
            chunk_len: 4,
            num_chunks: 1,
            assignments: vec![crate::cpu_repair_controller::WorkAssignment {
                worker: 0,
                byte_start: 0,
                byte_len: 4,
                output_start: 0,
                output_len: 1,
            }],
            worker_count: 1,
            stride: 2,
        };
        let mut output = vec![0x5au8; 4];
        let trace = ControllerExecutionTrace::capture();
        let context = Arc::new(CpuComputeContext {
            output_base: output.as_mut_ptr() as usize,
            output_count: 1,
            set,
            memo: &memo,
            #[cfg(target_arch = "x86_64")]
            jit_memo: None,
            #[cfg(target_arch = "x86_64")]
            jit_batch: None,
            layout: Arc::new(layout),
            method: CpuKernelKind::Plain.method(),
            trace: trace.clone(),
            folded_coefficients: FoldedBatchCoefficients::None,
            add: false,
        });

        std::thread::scope(|scope| {
            let (job_tx, job_rx) = std::sync::mpsc::sync_channel(1);
            let (completion_tx, completion_rx) = std::sync::mpsc::sync_channel(1);
            let worker = scope.spawn(move || run_compute_worker(0, job_rx, completion_tx));
            job_tx
                .send(CpuComputeJob {
                    id: 7,
                    context: Arc::clone(&context),
                })
                .unwrap();
            drop(job_tx);
            let completion = completion_rx.recv().unwrap();
            assert_eq!(completion.id, 7);
            assert!(completion.failure.is_some());
            worker.join().unwrap();
        });
        assert_eq!(output, vec![0x5a; 4]);
        assert!(trace.events().iter().any(|event| matches!(
            event,
            ControllerExecutionEvent::Failed {
                phase: ControllerFailurePhase::Compute
            }
        )));
    }

    #[test]
    fn folded_coefficient_one_add_preserves_split_blocks() {
        let mut destination = vec![0x11; crate::gf_simd::SPLIT_BLOCK_BYTES * 2];
        let mut staging = vec![0u8; destination.len() * crate::gf_simd::FOLDED_GROUP];
        for (index, byte) in staging.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let expected = destination
            .iter()
            .enumerate()
            .map(|(index, byte)| {
                (0..crate::gf_simd::FOLDED_GROUP).fold(*byte, |value, lane| {
                    value
                        ^ staging[index / crate::gf_simd::SPLIT_BLOCK_BYTES
                            * crate::gf_simd::FOLDED_GROUP
                            * crate::gf_simd::SPLIT_BLOCK_BYTES
                            + (index % crate::gf_simd::SPLIT_BLOCK_BYTES)
                            + lane * crate::gf_simd::SPLIT_BLOCK_BYTES]
                })
            })
            .collect::<Vec<_>>();
        xor_folded_group_into(&mut destination, &staging, crate::gf_simd::FOLDED_GROUP);
        assert_eq!(destination, expected);
    }

    #[test]
    fn compute_wait_drains_workers_before_returning_cancelled() {
        let (completion_tx, completion_rx) = std::sync::mpsc::sync_channel(2);
        for worker in 0..2 {
            completion_tx
                .send(CpuComputeCompletion {
                    id: 17,
                    worker,
                    elapsed: Duration::ZERO,
                    failure: None,
                })
                .unwrap();
        }
        let cancel = CancellationToken::new();
        cancel.cancel();
        let factors = matrix::Matrix::identity(1);
        let memo = PreparedFactorMemo::from_matrix(&factors, false);
        let context = Arc::new(CpuComputeContext {
            output_base: std::ptr::NonNull::<u8>::dangling().as_ptr() as usize,
            output_count: 0,
            set: StreamBatchSet::new(2, 1, 1, 1, false, false, false),
            memo: &memo,
            #[cfg(target_arch = "x86_64")]
            jit_memo: None,
            #[cfg(target_arch = "x86_64")]
            jit_batch: None,
            layout: Arc::new(ControllerLayout {
                aligned_len: 2,
                chunk_len: 2,
                num_chunks: 1,
                assignments: Vec::new(),
                worker_count: 1,
                stride: 2,
            }),
            method: CpuKernelKind::Plain.method(),
            trace: ControllerExecutionTrace::default(),
            folded_coefficients: FoldedBatchCoefficients::None,
            add: false,
        });
        let mut pool = CpuComputePool {
            completion_rx,
            deferred: HashMap::new(),
            _lifetime: std::marker::PhantomData,
        };
        let error = match pool.wait(
            CpuComputeTicket {
                id: 17,
                expected: 2,
                submission_failure: None,
                context,
            },
            Some(&cancel),
            &CpuControllerTimings::default(),
        ) {
            Ok(_) => panic!("cancelled compute wait unexpectedly succeeded"),
            Err(error) => error,
        };
        assert!(matches!(error, Par2Error::Cancelled));
    }

    #[test]
    fn preparation_failure_closes_batch_without_output() {
        let set = StreamBatchSet::new(64, 12, 12, 1, false, false, false);
        let trace = ControllerExecutionTrace::capture();
        let worker_trace = trace.clone();
        let factors = matrix::Matrix::identity(1);
        let memo = PreparedFactorMemo::from_matrix(&factors, false);
        let timings = CpuControllerTimings::default();
        std::thread::scope(|scope| {
            let (command_tx, command_rx) = std::sync::mpsc::sync_channel(2);
            let (complete_tx, complete_rx) = std::sync::mpsc::sync_channel(2);
            let (prepared_tx, prepared_rx) = std::sync::mpsc::sync_channel(1);
            let (submitted_tx, submitted_rx) = std::sync::mpsc::sync_channel(1);
            let (finished_tx, _finished_rx) = std::sync::mpsc::sync_channel(1);
            let compute_submitter = CpuComputeSubmitter {
                senders: Vec::new(),
                next_id: 0,
            };
            let worker_memo = &memo;
            let worker_timings = &timings;
            let worker = scope.spawn(move || {
                run_preparation_worker(
                    command_rx,
                    complete_tx,
                    prepared_tx,
                    submitted_tx,
                    finished_tx,
                    CpuKernelKind::Plain,
                    CpuKernelKind::Plain.method(),
                    std::ptr::NonNull::<u8>::dangling().as_ptr() as usize,
                    1,
                    worker_memo,
                    #[cfg(target_arch = "x86_64")]
                    None,
                    worker_timings,
                    compute_submitter,
                    worker_trace,
                );
            });
            command_tx
                .send(PreparationMessage::Begin(PrepareBatch {
                    set,
                    aligned_len: 64,
                    chunk_len: 64,
                    layout: None,
                }))
                .unwrap();
            command_tx
                .send(PreparationMessage::Input {
                    lane: 0,
                    coefficients: Vec::new(),
                    buffer: TransferBuffer {
                        slot: 0,
                        bytes: vec![0u8; 64],
                    },
                    submitted: Some(InputBatch {
                        staging_area: 0,
                        input_start: 0,
                        input_len: 1,
                        add: false,
                        reason: crate::cpu_repair_controller::BatchSubmitReason::GroupFull,
                    }),
                })
                .unwrap();
            drop(command_tx);
            assert!(worker.join().is_ok());
            assert!(complete_rx.recv().is_err());
            assert!(prepared_rx.recv().is_err());
            assert!(submitted_rx.recv().is_err());
        });
        assert!(trace.events().iter().any(|event| matches!(
            event,
            ControllerExecutionEvent::Failed {
                phase: ControllerFailurePhase::Prepare
            }
        )));
    }

    #[test]
    fn controller_transfer_buffers_are_a_fixed_two_slot_protocol() {
        let (command_tx, _command_rx) = std::sync::mpsc::sync_channel(1);
        let (complete_tx, complete_rx) = std::sync::mpsc::sync_channel(2);
        let (_prepared_tx, prepared_rx) = std::sync::mpsc::sync_channel(1);
        let (_submitted_tx, submitted_rx) = std::sync::mpsc::sync_channel(1);
        let (_finished_tx, finished_rx) = std::sync::mpsc::sync_channel(1);
        let mut preparer = CpuInputPreparer {
            command_tx,
            complete_rx,
            prepared_rx,
            submitted_rx,
            finished_rx,
            transfer_buffers: std::array::from_fn(|_| None),
            transfer_buffer_len: 8,
        };

        complete_tx
            .send(TransferBuffer {
                slot: 0,
                bytes: vec![0; 8],
            })
            .unwrap();
        complete_tx
            .send(TransferBuffer {
                slot: 1,
                bytes: vec![0; 8],
            })
            .unwrap();
        preparer.restore_transfer_buffers(None).unwrap();

        let first = preparer.take_transfer_buffer(None).unwrap();
        let second = preparer.take_transfer_buffer(None).unwrap();
        assert_eq!((first.slot, second.slot), (0, 1));
        assert!(preparer.transfer_buffers.iter().all(Option::is_none));

        preparer.return_transfer_buffer(first).unwrap();
        let duplicate = TransferBuffer {
            slot: 0,
            bytes: vec![0; 8],
        };
        assert!(preparer.return_transfer_buffer(duplicate).is_err());
        assert!(
            preparer
                .return_transfer_buffer(TransferBuffer {
                    slot: 2,
                    bytes: vec![0; 8],
                })
                .is_err()
        );
        assert!(
            preparer
                .return_transfer_buffer(TransferBuffer {
                    slot: 1,
                    bytes: vec![0; 7],
                })
                .is_err()
        );

        preparer.return_transfer_buffer(second).unwrap();
        assert!(preparer.transfer_buffers.iter().all(Option::is_some));
    }

    #[test]
    fn controller_output_area_is_aligned_and_stable() {
        let mut area = AlignedOutputArea::new(3, 65_537);
        let first = area.base();
        let second = area.base();
        assert_eq!(first, second);
        assert_eq!(first % 64, 0);
        assert!(area.cells.len() * std::mem::size_of::<StagingCell>() >= 3 * 65_537);
    }

    #[test]
    fn packed_checksum_is_linear_and_rejects_mutation() {
        const DATA_LEN: usize = 96;
        const BLOCK_LEN: usize = 32;
        let mut left = vec![0u8; DATA_LEN + BLOCK_LEN];
        let mut right = vec![0u8; DATA_LEN + BLOCK_LEN];
        for (index, byte) in left[..DATA_LEN].iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(17).wrapping_add(3);
        }
        for (index, byte) in right[..DATA_LEN].iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(29).wrapping_add(11);
        }
        write_packed_checksum(&mut left, DATA_LEN, BLOCK_LEN, BLOCK_LEN);
        write_packed_checksum(&mut right, DATA_LEN, BLOCK_LEN, BLOCK_LEN);

        let mut combined: Vec<u8> = left
            .iter()
            .zip(&right)
            .map(|(left, right)| left ^ right)
            .collect();
        assert!(packed_checksum_matches(
            &combined,
            BLOCK_LEN * 3,
            BLOCK_LEN,
            BLOCK_LEN
        ));

        combined[41] ^= 0x80;
        assert!(!packed_checksum_matches(
            &combined,
            BLOCK_LEN * 3,
            BLOCK_LEN,
            BLOCK_LEN
        ));
    }

    #[test]
    fn repair_with_file_backed_recovery_streaming_succeeds() {
        let slice_size = 128u64;
        let file_data: Vec<u8> = (0..384u32).map(|i| ((i * 9 + 17) % 256) as u8).collect();
        let (mut par2_set, file_id) = setup_repairable_set(&file_data, slice_size, 3);
        let _spill_dir = spill_recovery_slices_to_disk(&mut par2_set);

        let mut damaged = file_data.clone();
        for item in damaged.iter_mut().take(128) {
            *item = 0;
        }
        for item in damaged.iter_mut().take(384).skip(256) {
            *item = 0;
        }

        let mut access = MemoryFileAccess::new();
        access.add_file(file_id, damaged);

        let result = verify::verify_all(&par2_set, &access);
        let plan = plan_repair(&par2_set, &result).unwrap();

        execute_repair_with_options(
            &plan,
            &par2_set,
            &mut access,
            &RepairOptions {
                memory_limit: Some(constrained_memory_limit_for_test(&plan)),
                ..RepairOptions::default()
            },
        )
        .unwrap();

        let repaired = access.read_file(&file_id).unwrap();
        assert_eq!(repaired, file_data);
    }

    fn synthetic_plan(missing_slices: usize, slice_size: u64) -> RepairPlan {
        RepairPlan {
            missing_slices: (0..missing_slices)
                .map(|i| (FileId::from_bytes([i as u8; 16]), i as u32))
                .collect(),
            missing_global_indices: (0..missing_slices).collect(),
            available_input_global_indices: Vec::new(),
            recovery_exponents: (0..missing_slices as u32).collect(),
            decode_matrix: matrix::Matrix {
                rows: missing_slices,
                cols: missing_slices,
                data: vec![1; missing_slices.saturating_mul(missing_slices)],
            },
            input_factors: matrix::Matrix {
                rows: missing_slices,
                cols: missing_slices,
                data: vec![1; missing_slices.saturating_mul(missing_slices)],
            },
            slice_size,
            constants: vec![1; missing_slices],
            total_input_slices: missing_slices,
            global_to_file: (0..missing_slices)
                .map(|i| (FileId::from_bytes([i as u8; 16]), i as u32))
                .collect(),
        }
    }

    fn minimum_controller_bytes_for_test(plan: &RepairPlan, kernel: CpuKernelKind) -> usize {
        let method = kernel.method();
        cpu_controller_plan(
            2,
            plan.missing_slices.len(),
            rayon::current_num_threads().max(1),
            method,
            method.staging_width(),
        )
        .buffer_accounting()
        .total_bytes
    }

    fn constrained_memory_limit_for_test(plan: &RepairPlan) -> usize {
        let required = minimum_controller_bytes_for_test(plan, CpuKernelKind::Plain).max(
            minimum_controller_bytes_for_test(plan, CpuKernelKind::Folded),
        );
        #[cfg(target_arch = "x86_64")]
        let mut required = required;
        #[cfg(target_arch = "x86_64")]
        if let Some(width) = reedsolomon_rs::xor_jit::JitWidth::detect() {
            let kernel = CpuKernelKind::XorJit(width);
            let controller_bytes = minimum_controller_bytes_for_test(plan, kernel);
            let memo = JitMemo::new(
                width,
                kernel.method(),
                plan.missing_slices.len(),
                &plan.input_factors.data,
                0,
                usize::MAX,
            )
            .expect("detected XOR-JIT method has bounded controller accounting");
            required = required.max(controller_bytes.saturating_add(memo.reserved_bytes()));
        }
        required
    }

    #[test]
    fn controller_budget_below_physical_minimum_is_rejected_without_mutation() {
        let plan = synthetic_plan(1, 64);
        let kernel = CpuKernelKind::Plain;
        let method = kernel.method();
        let minimum = minimum_controller_bytes_for_test(&plan, kernel);
        assert!(minimum > 0);
        let error = controller_execution_parameters(
            &plan,
            &RepairOptions {
                memory_limit: Some(minimum - 1),
                ..RepairOptions::default()
            },
            method,
            method.staging_width(),
            0,
            rayon::current_num_threads().max(1),
        )
        .unwrap_err();
        assert!(matches!(error, Par2Error::ResourceLimitExceeded { .. }));
    }

    #[test]
    fn controller_parameters_shrink_chunks_to_a_tight_budget() {
        let plan = synthetic_plan(450, 1024 * 1024);
        let kernel = CpuKernelKind::Plain;
        let method = kernel.method();
        let (chunk_words, budget, _) = controller_execution_parameters(
            &plan,
            &RepairOptions {
                memory_limit: Some(50 * 1024 * 1024),
                ..RepairOptions::default()
            },
            method,
            method.staging_width(),
            0,
            4,
        )
        .unwrap();
        assert_eq!(budget, 50 * 1024 * 1024);
        assert!(chunk_words < plan.slice_size as usize / 2);
    }

    #[test]
    fn cpu_controller_keeps_kernel_grouping_for_small_source_sets() {
        let method = CpuKernelKind::Plain.method();
        let expected_grouping = method.input_grouping();
        for sources in [1, 2, 3, 4, 5, 23, 24] {
            let controller = cpu_controller_plan(4096, 2, 4, method, expected_grouping);
            assert_eq!(controller.input_grouping(), expected_grouping);
            assert_eq!(
                crate::cpu_repair_controller::ControllerLifecycle::simulate(
                    sources,
                    controller.input_grouping(),
                )
                .batches
                .iter()
                .map(|batch| batch.input_len)
                .sum::<usize>(),
                sources
            );
            let set = StreamBatchSet::new(
                controller.layout().aligned_len,
                controller.input_grouping(),
                controller.input_grouping(),
                2,
                false,
                false,
                false,
            );
            assert_eq!(set.bufs.len(), expected_grouping);
        }
    }

    #[test]
    fn gpu_staging_keeps_plain_sources_for_packed_cpu_fallback() {
        let set = StreamBatchSet::new(256, 6, 6, 2, false, true, true);
        assert_eq!(set.bufs.len(), 6);
        assert!(!set.packed.is_empty());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn avx2_jit_memo_accounts_two_active_batch_arenas() {
        let method = CpuMethodContract {
            stride: 32,
            alignment: 64,
            ideal_input_multiple: 1,
            staging_multiple: 1,
            ideal_chunk_size: XORJIT_AVX2_IDEAL_CHUNK_BYTES,
            checksum_width: 2,
            prefetch: CpuPrefetch {
                inputs_per_invoke: 1,
                input_distance_shift: 1,
                output: true,
            },
            strict_wx_available: true,
        };
        let area = reedsolomon_rs::xor_jit::packed::PackedJitBatch::active_arena_upper_bound(
            reedsolomon_rs::xor_jit::JitWidth::Avx2,
            1,
            method.input_grouping(),
        )
        .unwrap();
        let required = area * 2;
        let memo = JitMemo::new(
            reedsolomon_rs::xor_jit::JitWidth::Avx2,
            method,
            1,
            &[1],
            0,
            required,
        )
        .unwrap();
        assert_eq!(memo.reserved_bytes(), required);
        assert!(
            JitMemo::new(
                reedsolomon_rs::xor_jit::JitWidth::Avx2,
                method,
                1,
                &[1],
                0,
                required - 1,
            )
            .is_err()
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn avx2_jit_memo_uses_codebook_only_with_full_chunk_headroom() {
        let method = CpuKernelKind::XorJit(reedsolomon_rs::xor_jit::JitWidth::Avx2).method();
        let factors = [1u16, 2, 3, 2, 1];
        let measured =
            reedsolomon_rs::xor_jit::packed::Avx2Codebook::build(&factors, usize::MAX).unwrap();
        let codebook_limit = measured.build_peak_bytes();
        let retained_bytes = measured.retained_bytes();
        drop(measured);

        let memo = JitMemo::new(
            reedsolomon_rs::xor_jit::JitWidth::Avx2,
            method,
            1,
            &factors,
            codebook_limit,
            usize::MAX,
        )
        .unwrap();
        assert!(matches!(
            &memo.storage,
            JitDispatchStorage::RepairCodebook(_)
        ));
        assert_eq!(memo.reserved_bytes(), retained_bytes);
    }

    #[test]
    fn controller_parameters_use_a_full_slice_when_budget_allows() {
        let plan = synthetic_plan(8, 64 * 1024);
        let kernel = CpuKernelKind::Plain;
        let method = kernel.method();
        let (chunk_words, budget, _) = controller_execution_parameters(
            &plan,
            &RepairOptions {
                memory_limit: Some(16 * 1024 * 1024),
                ..RepairOptions::default()
            },
            method,
            method.staging_width(),
            0,
            4,
        )
        .unwrap();
        assert_eq!(budget, 16 * 1024 * 1024);
        assert_eq!(chunk_words, plan.slice_size as usize / 2);
    }

    // ── Repair-solver seam (RFC 123 WP2.5) ─────────────────────────────────

    /// Assemble the in-memory sources for a plan (available inputs then recovery
    /// blocks) exactly as `run_in_memory_repair` does, drawing the available
    /// slices from the known-good padded original.
    fn seam_sources(
        plan: &RepairPlan,
        par2_set: &Par2FileSet,
        padded_original: &[u8],
        slice_size: usize,
    ) -> Vec<Vec<u8>> {
        let mut sources = Vec::new();
        for &global_idx in &plan.available_input_global_indices {
            let (_file_id, local) = plan.global_to_file[global_idx];
            let start = local as usize * slice_size;
            sources.push(padded_original[start..start + slice_size].to_vec());
        }
        for &exp in &plan.recovery_exponents {
            let mut data = par2_set.recovery_slices[&exp].data.to_vec().unwrap();
            data.resize(slice_size, 0);
            sources.push(data);
        }
        sources
    }

    /// Naive per-word serial GF(2^16) reconstruction used as an independent
    /// reference for every parallel controller path.
    fn serial_reconstruct(
        input_factors: &matrix::Matrix,
        sources: &[Vec<u8>],
        word_count: usize,
    ) -> Vec<Vec<u8>> {
        (0..input_factors.rows)
            .map(|j| {
                let mut out = vec![0u8; word_count * 2];
                for (s, src) in sources.iter().enumerate() {
                    let factor = input_factors.get(j, s);
                    if factor == 0 {
                        continue;
                    }
                    for w in 0..word_count {
                        let sv = u16::from_le_bytes([src[w * 2], src[w * 2 + 1]]);
                        let cur = u16::from_le_bytes([out[w * 2], out[w * 2 + 1]]);
                        let nv = gf::add(cur, gf::mul(factor, sv));
                        let b = nv.to_le_bytes();
                        out[w * 2] = b[0];
                        out[w * 2 + 1] = b[1];
                    }
                }
                out
            })
            .collect()
    }

    /// The seam's native default reconstruct must equal both an independent
    /// serial GF reference and the original bytes — the same property the PoC's
    /// `host_side_reconstruct_recovers_original` checks, but through the real
    /// `NativeRepairSolver` over a `RepairProblem`.
    #[test]
    fn seam_native_solver_matches_serial_reference_and_original() {
        let slice_size = 128u64;
        let ss = slice_size as usize;
        let file_data: Vec<u8> = (0..512u32).map(|i| ((i * 7 + 3) % 256) as u8).collect();
        let (par2_set, file_id) = setup_repairable_set(&file_data, slice_size, 4);

        // Damage slices 1 and 3 (of 4).
        let mut damaged = file_data.clone();
        damaged[128..256].fill(0);
        damaged[384..512].fill(0);
        let mut access = MemoryFileAccess::new();
        access.add_file(file_id, damaged);

        let result = verify::verify_all(&par2_set, &access);
        let plan = plan_repair(&par2_set, &result).unwrap();
        let n = plan.missing_slices.len();
        assert_eq!(n, 2);

        let word_count = ss / 2;
        let num_slices = file_data.len() / ss;
        let mut padded = file_data.clone();
        padded.resize(num_slices * ss, 0);
        let sources = seam_sources(&plan, &par2_set, &padded, ss);
        let expected = serial_reconstruct(&plan.input_factors, &sources, word_count);

        let source_refs: Vec<&[u8]> = sources.iter().map(|s| s.as_slice()).collect();
        let mut outputs: Vec<Vec<u8>> = vec![vec![0u8; ss]; n];
        {
            let mut out_refs: Vec<&mut [u8]> =
                outputs.iter_mut().map(|o| o.as_mut_slice()).collect();
            let mut problem = RepairProblem {
                total_inputs: plan.total_input_slices,
                word_count,
                missing_indices: &plan.missing_global_indices,
                available_indices: &plan.available_input_global_indices,
                recovery_exponents: &plan.recovery_exponents,
                constants: &plan.constants,
                sources: &source_refs,
                outputs: &mut out_refs,
            };
            NativeRepairSolver::new(&plan.input_factors, word_count)
                .reconstruct(&mut problem)
                .unwrap();
        }

        assert_eq!(
            outputs, expected,
            "seam reconstruct must match the serial GF reference byte-for-byte"
        );
        for (j, &(_, local)) in plan.missing_slices.iter().enumerate() {
            let start = local as usize * ss;
            assert_eq!(
                outputs[j],
                &padded[start..start + ss],
                "missing slice {local} not recovered"
            );
        }
    }

    /// A stand-in for Agent P's wasm solver: it ignores the plan's pre-built
    /// matrix and instead rebuilds the coefficient matrix from the `RepairProblem`
    /// raw spec using ONLY the `reedsolomon-rs` host API, then reconstructs
    /// via `mul_acc_region`. Proves the injection path recovers the original.
    struct HostStyleSolver;

    impl RepairSolver for HostStyleSolver {
        fn reconstruct(
            &self,
            problem: &mut RepairProblem<'_>,
        ) -> std::result::Result<(), SolverError> {
            let coeffs = reedsolomon_rs::matrix::build_repair_matrix(
                problem.available_indices,
                problem.missing_indices,
                problem.recovery_exponents,
                problem.constants,
            )
            .map_err(|e| SolverError::Singular { bad_row: e.bad_row })?;
            let sources = problem.sources;
            for (j, out) in problem.outputs.iter_mut().enumerate() {
                let out: &mut [u8] = out;
                out.fill(0);
                for (s, src) in sources.iter().enumerate() {
                    reedsolomon_rs::gf_simd::mul_acc_region(coeffs.get(j, s), src, out);
                }
            }
            Ok(())
        }
    }

    /// Native builds reject the quarantined in-memory solver seam before it
    /// can mutate repaired output.
    #[test]
    fn execute_repair_with_solver_is_quarantined_on_native_targets() {
        let slice_size = 128u64;
        let file_data: Vec<u8> = (0..640u32).map(|i| ((i * 11 + 5) % 256) as u8).collect();
        let (par2_set, file_id) = setup_repairable_set(&file_data, slice_size, 3);

        // Damage slices 0 and 2 (of 5).
        let mut damaged = file_data.clone();
        damaged[..128].fill(0);
        damaged[256..384].fill(0);
        let mut access = MemoryFileAccess::new();
        access.add_file(file_id, damaged);

        let result = verify::verify_all(&par2_set, &access);
        assert_eq!(result.total_missing_blocks, 2);
        let plan = plan_repair(&par2_set, &result).unwrap();

        let error = execute_repair_with_solver(
            &plan,
            &par2_set,
            &mut access,
            &RepairOptions::default(),
            &HostStyleSolver,
        )
        .unwrap_err();

        assert!(matches!(error, Par2Error::ReedSolomonError { .. }));
        assert_ne!(access.read_file(&file_id).unwrap(), file_data);
    }

    /// The host-side repair matrix (`reedsolomon-rs`) must be byte-identical
    /// to the coefficient matrix par2-rs builds natively, so a host solve
    /// equals a native weaver repair.
    #[test]
    fn reedsolomon_rs_repair_matrix_matches_par2_rs() {
        let total = 20usize;
        let constants = gf::input_slice_constants(total);
        let missing = vec![3usize, 7, 11, 15];
        let exps: Vec<u32> = vec![0, 1, 2, 3];
        let avail: Vec<usize> = (0..total).filter(|i| !missing.contains(i)).collect();

        let (weaver_repair, _decode) =
            matrix::build_repair_matrix_with_bad_row(&avail, &missing, &exps, &constants).unwrap();
        let host = reedsolomon_rs::matrix::build_repair_matrix(&avail, &missing, &exps, &constants)
            .unwrap();

        assert_eq!(weaver_repair.rows, host.rows);
        assert_eq!(weaver_repair.cols, host.cols);
        assert_eq!(
            weaver_repair.data, host.data,
            "host repair matrix must be byte-identical to par2-rs's"
        );
    }
}
