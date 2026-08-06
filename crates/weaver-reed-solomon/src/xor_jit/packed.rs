//! Packed reconstruction dispatch for the XOR-JIT tiers.
//!
//! The public shape follows Turbo's `mul_add_multi_packed` and
//! `mul_add_multi_packpf` contracts. AVX2 deliberately uses the oracle's
//! ordered single-input fallback. AVX512 uses immutable multi-source bodies,
//! up to six source regions at a time, matching `XOR512_MULTI_REGIONS`.

#![allow(unsafe_op_in_unsafe_fn)]

use super::{
    JitWidth, codegen512, deps,
    memory::{JitCode, WORKER_JIT_BYTES, WorkerJitBuffer},
    turbo_avx2,
};
use memmap2::{Mmap, MmapMut};
use std::{fmt, io, sync::Arc};

const AVX2_PREFETCH_OUTPUT_SOURCES: usize = 2;
const CODE_ALIGNMENT: usize = 64;
// Turbo's mutable XOR-JIT scratch reserves 1280 bytes for one generated body.
// The worker-owned 4 KiB page reserves this bounded body without retaining a
// coefficient-domain code arena.
const AVX2_MAX_BODY_BYTES: usize = turbo_avx2::MAX_BODY_BYTES;
/// Persistent memory reserved by each AVX2 controller worker: one strict-W^X
/// code page plus the bounded generated-body buffer.
pub const AVX2_WORKER_SCRATCH_BYTES: usize = WORKER_JIT_BYTES + AVX2_MAX_BODY_BYTES;
const AVX512_MAX_BODY_BYTES: usize = 4096;

struct Avx2Body {
    source: usize,
    factor: u16,
}

struct Avx512Group {
    start: usize,
    codes: Vec<JitCode>,
}

#[derive(Clone, Copy)]
struct Avx2BodyPlan {
    source: usize,
    factor: u16,
}

struct Avx512GroupPlan {
    start: usize,
    codes: Vec<usize>,
}

struct PackedRowPlan {
    factors: Vec<u16>,
    avx2: Vec<Avx2BodyPlan>,
    avx512: Vec<Avx512GroupPlan>,
}

struct PackedBatchPlan {
    generated: Vec<u8>,
    offsets: Vec<usize>,
    rows: Vec<PackedRowPlan>,
    size: PackedCodeSize,
}

/// Size accounting for a packed-code dispatch.
///
/// AVX2 bodies are generated into worker-owned 4 KiB scratch pages, so they
/// have no retained coefficient-domain code bytes. AVX512 still reports its
/// immutable active-group arena until it receives the same worker-scratch
/// implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackedCodeSize {
    pub generated_bytes: usize,
    pub arena_bytes: usize,
}

/// Failure while planning or finalizing a packed batch.
#[derive(Debug)]
pub enum PackedBuildError {
    InvalidInput(&'static str),
    Resource {
        requested_bytes: usize,
        limit_bytes: usize,
    },
    Io(io::Error),
}

impl fmt::Display for PackedBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(message) => formatter.write_str(message),
            Self::Resource {
                requested_bytes,
                limit_bytes,
            } => write!(
                formatter,
                "packed XOR-JIT arena needs {requested_bytes} bytes, limit is {limit_bytes}"
            ),
            Self::Io(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for PackedBuildError {}

impl From<io::Error> for PackedBuildError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Failure while generating or running one worker-local AVX2 body.
///
/// Unlike planning errors, this can happen after a repair controller has
/// accepted an active input group. Callers must treat it as a failed compute
/// operation and discard staged output; it is never converted to scalar work
/// inside the packed dispatcher.
#[derive(Debug)]
pub enum PackedExecutionError {
    ScratchAllocation,
    Generator(turbo_avx2::TurboAvx2EmitError),
    WxTransition(io::Error),
}

impl fmt::Display for PackedExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ScratchAllocation => {
                formatter.write_str("unable to reserve worker JIT body scratch")
            }
            Self::Generator(error) => error.fmt(formatter),
            Self::WxTransition(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for PackedExecutionError {}

struct GeneratedBodies {
    bytes: Vec<u8>,
    offsets: Vec<usize>,
    size: PackedCodeSize,
    limit_bytes: usize,
}

impl GeneratedBodies {
    fn new(limit_bytes: usize) -> Self {
        Self {
            bytes: Vec::new(),
            offsets: Vec::new(),
            size: PackedCodeSize {
                generated_bytes: 0,
                arena_bytes: 0,
            },
            limit_bytes,
        }
    }

    fn push(&mut self, code: Vec<u8>) -> Result<usize, PackedBuildError> {
        self.push_bytes(&code)
    }

    fn push_bytes(&mut self, code: &[u8]) -> Result<usize, PackedBuildError> {
        let original_len = self.bytes.len();
        let aligned = original_len
            .checked_add(CODE_ALIGNMENT - 1)
            .map(|value| value & !(CODE_ALIGNMENT - 1))
            .ok_or(PackedBuildError::Resource {
                requested_bytes: usize::MAX,
                limit_bytes: self.limit_bytes,
            })?;
        self.bytes.resize(aligned, 0);
        self.bytes.extend_from_slice(code);
        self.accept_appended(original_len, aligned, code.len())
    }

    fn accept_appended(
        &mut self,
        original_len: usize,
        offset: usize,
        code_len: usize,
    ) -> Result<usize, PackedBuildError> {
        let arena_bytes = self.bytes.len();
        if arena_bytes > self.limit_bytes {
            self.bytes.truncate(original_len);
            return Err(PackedBuildError::Resource {
                requested_bytes: arena_bytes,
                limit_bytes: self.limit_bytes,
            });
        }
        let generated_bytes =
            self.size
                .generated_bytes
                .checked_add(code_len)
                .ok_or(PackedBuildError::Resource {
                    requested_bytes: usize::MAX,
                    limit_bytes: self.limit_bytes,
                })?;

        let index = self.offsets.len();
        self.offsets.push(offset);
        self.size = PackedCodeSize {
            generated_bytes,
            arena_bytes,
        };
        Ok(index)
    }
}

/// Worker-owned scratch for packed dispatch.
///
/// The AVX2 code page belongs here rather than to a coefficient batch: one
/// worker serially emits, seals, executes, and recycles its tiny body scratch.
/// Keeping the source-pointer array alongside it also avoids allocating on
/// every AVX512 multi-source invocation.
#[derive(Default)]
pub struct PackedScratch {
    sources: Vec<*const u8>,
    avx2_code: WorkerJitBuffer,
    avx2_body: Vec<u8>,
}

// SAFETY: the pointers are non-owning call-local addresses. The scratch is
// worker-owned and is never shared while a packed body is executing.
unsafe impl Send for PackedScratch {}

impl PackedScratch {
    pub fn new() -> Self {
        Self::default()
    }

    unsafe fn try_run_avx2(
        &mut self,
        factor: u16,
        src: *const u8,
        dst: *mut u8,
        len: usize,
        prefetch: Option<*const u8>,
    ) -> Result<(), PackedExecutionError> {
        let (body, code) = (&mut self.avx2_body, &mut self.avx2_code);
        body.clear();
        if body.capacity() < AVX2_MAX_BODY_BYTES {
            body.try_reserve_exact(AVX2_MAX_BODY_BYTES - body.capacity())
                .map_err(|_| PackedExecutionError::ScratchAllocation)?;
        }
        turbo_avx2::append_muladd_body(body, factor, prefetch.is_some())
            .map_err(PackedExecutionError::Generator)?;
        match prefetch {
            Some(prefetch) => code.run_muladd_prefetch(body, src, dst, len, prefetch),
            None => code.run_muladd(body, src, dst, len),
        }
        .map_err(PackedExecutionError::WxTransition)
    }
}

/// Pointer and shape contract for one packed multiply-add invocation.
#[derive(Clone, Copy, Debug)]
pub struct PackedRun {
    /// Number of contiguous source regions allocated in `src`.
    pub packed_regions: usize,
    /// Number of leading source regions participating in this invocation.
    pub live_regions: usize,
    /// Writable destination region.
    pub dst: *mut u8,
    /// First contiguous packed source region.
    pub src: *const u8,
    /// Bytes in each source region and in the destination region.
    pub len: usize,
    /// Optional input-side prefetch stream base.
    pub prefetch_in: Option<*const u8>,
    /// Optional output-side prefetch stream base.
    pub prefetch_out: Option<*const u8>,
}

/// Immutable packed dispatch state for one coefficient row.
pub struct PackedJitCode {
    width: JitWidth,
    factors: Vec<u16>,
    avx2: Vec<Avx2Body>,
    avx512: Vec<Avx512Group>,
}

/// Immutable dispatch plans for one active input group.
///
/// AVX2 retains coefficient dependencies only; its worker-local W^X page is
/// generated per invocation. AVX512 prefix bodies remain row-specific and
/// share an active-group RX arena.
pub struct PackedJitBatch {
    rows: Vec<PackedJitCode>,
    size: PackedCodeSize,
    arena: Option<Arc<Mmap>>,
    lease: Option<Arc<WorkspaceLease>>,
}

/// Identity token proving that an active batch still occupies its controller
/// staging area. It is intentionally private: only its originating workspace
/// may recycle the batch.
struct WorkspaceLease;

/// Reusable writable side of one controller area's strict-W^X code arena.
/// A workspace is empty while its corresponding sealed batch is executing.
#[derive(Default)]
pub struct PackedJitWorkspace {
    writable: Option<MmapMut>,
    active: Option<Arc<WorkspaceLease>>,
}

impl PackedJitBatch {
    /// Estimate retained code state without allocating executable memory.
    /// AVX2 has no coefficient-domain arena: each worker emits its current
    /// body into one bounded scratch page immediately before execution.
    pub fn estimate(width: JitWidth, rows: &[&[u16]]) -> Result<PackedCodeSize, PackedBuildError> {
        Ok(build_batch_plan(width, rows, usize::MAX)?.size)
    }

    /// Conservative retained-code bound for one active input group.
    ///
    /// AVX2 uses a single 4 KiB page per worker regardless of output count or
    /// coefficient count. Controller owners retain their existing two-area
    /// backpressure; the worker-local pages themselves are acquired lazily.
    pub fn active_arena_upper_bound(
        width: JitWidth,
        row_count: usize,
        factors_per_row: usize,
    ) -> Option<usize> {
        match width {
            JitWidth::Avx2 => Some(WORKER_JIT_BYTES),
            JitWidth::Avx512 => row_count
                .checked_mul(factors_per_row)?
                .checked_mul(AVX512_MAX_BODY_BYTES),
        }
    }

    /// Build one immutable coefficient plan for an active input group.
    ///
    /// AVX2 retains no executable bodies here. Workers generate and execute
    /// their current body through [`PackedScratch`]. AVX512 retains its
    /// existing active-group RX arena.
    pub fn new(width: JitWidth, rows: &[&[u16]]) -> Result<Self, PackedBuildError> {
        Self::new_with_limit(width, rows, usize::MAX)
    }

    /// Build an active-group plan, refusing it when its retained code state
    /// exceeds `limit_bytes`.
    pub fn new_with_limit(
        width: JitWidth,
        rows: &[&[u16]],
        limit_bytes: usize,
    ) -> Result<Self, PackedBuildError> {
        let plan = build_batch_plan(width, rows, limit_bytes)?;
        Self::from_plan(width, plan, None, None)
    }

    fn from_plan(
        width: JitWidth,
        plan: PackedBatchPlan,
        reusable: Option<MmapMut>,
        lease: Option<Arc<WorkspaceLease>>,
    ) -> Result<Self, PackedBuildError> {
        let PackedBatchPlan {
            generated,
            offsets,
            rows: plans,
            size,
        } = plan;
        let (finalized, arena) = if generated.is_empty() {
            (Vec::new(), None)
        } else {
            JitCode::new_arena_reusing(&generated, &offsets, reusable)?
        };
        let rows = plans
            .into_iter()
            .map(|plan| PackedJitCode {
                width,
                factors: plan.factors,
                avx2: plan
                    .avx2
                    .into_iter()
                    .map(|body| Avx2Body {
                        source: body.source,
                        factor: body.factor,
                    })
                    .collect(),
                avx512: plan
                    .avx512
                    .into_iter()
                    .map(|group| Avx512Group {
                        start: group.start,
                        codes: group
                            .codes
                            .into_iter()
                            .map(|index| finalized[index].clone())
                            .collect(),
                    })
                    .collect(),
            })
            .collect();
        Ok(Self {
            rows,
            size,
            arena,
            lease,
        })
    }

    fn into_workspace_parts(self) -> io::Result<(Option<MmapMut>, Option<Arc<WorkspaceLease>>)> {
        let Self {
            rows,
            size: _,
            arena,
            lease,
        } = self;
        drop(rows);
        Ok((
            arena.map(JitCode::recover_batch_mapping).transpose()?,
            lease,
        ))
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    pub fn row(&self, index: usize) -> Option<&PackedJitCode> {
        self.rows.get(index)
    }

    pub fn code_size(&self) -> PackedCodeSize {
        self.size
    }
}

impl PackedJitWorkspace {
    /// Reserve this controller area for one active coefficient plan.
    ///
    /// A second build is rejected until the completed batch is recycled. The
    /// plan is kept alive while workers read it; AVX2 machine code remains
    /// exclusively worker-owned through [`PackedScratch`].
    pub fn build(
        &mut self,
        width: JitWidth,
        rows: &[&[u16]],
        limit_bytes: usize,
    ) -> Result<PackedJitBatch, PackedBuildError> {
        if self.active.is_some() {
            return Err(PackedBuildError::InvalidInput(
                "packed JIT workspace still has an active batch",
            ));
        }
        // Plan before taking the retained AVX512 mapping so shape/resource
        // failures leave this staging area immediately reusable.
        let plan = build_batch_plan(width, rows, limit_bytes)?;
        let lease = Arc::new(WorkspaceLease);
        let batch =
            PackedJitBatch::from_plan(width, plan, self.writable.take(), Some(Arc::clone(&lease)))?;
        self.active = Some(lease);
        Ok(batch)
    }

    /// Release a completed active group. For AVX512 this restores the shared
    /// mapping to RW; AVX2 has no batch-owned executable mapping to recover.
    pub fn recycle(&mut self, batch: PackedJitBatch) -> io::Result<()> {
        let Some(expected) = self.active.as_ref() else {
            return Err(io::Error::other("packed JIT workspace has no active batch"));
        };
        let owned = batch
            .lease
            .as_ref()
            .is_some_and(|lease| Arc::ptr_eq(lease, expected));
        if !owned {
            return Err(io::Error::other(
                "packed JIT batch belongs to a different workspace",
            ));
        }
        let (writable, _) = batch.into_workspace_parts()?;
        self.writable = writable;
        self.active = None;
        Ok(())
    }
}

fn build_batch_plan(
    width: JitWidth,
    rows: &[&[u16]],
    limit_bytes: usize,
) -> Result<PackedBatchPlan, PackedBuildError> {
    let first = rows.first().ok_or(PackedBuildError::InvalidInput(
        "packed batch needs at least one row",
    ))?;
    if first.is_empty() {
        return Err(PackedBuildError::InvalidInput(
            "packed XOR-JIT dispatch needs at least one factor",
        ));
    }
    if rows.iter().any(|row| row.len() != first.len()) {
        return Err(PackedBuildError::InvalidInput(
            "packed batch rows must have equal factor counts",
        ));
    }

    if width == JitWidth::Avx2 && limit_bytes < WORKER_JIT_BYTES {
        return Err(PackedBuildError::Resource {
            requested_bytes: WORKER_JIT_BYTES,
            limit_bytes,
        });
    }

    let mut generated = GeneratedBodies::new(limit_bytes);
    let mut plans = Vec::with_capacity(rows.len());
    for &factors in rows {
        let mut plan = PackedRowPlan {
            factors: factors.to_vec(),
            avx2: Vec::new(),
            avx512: Vec::new(),
        };
        match width {
            JitWidth::Avx2 => {
                for (source, &factor) in factors.iter().enumerate() {
                    if factor == 0 {
                        continue;
                    }
                    plan.avx2.push(Avx2BodyPlan { source, factor });
                }
            }
            JitWidth::Avx512 => {
                for (group_index, chunk) in
                    factors.chunks(codegen512::MAX_PACKED_REGIONS).enumerate()
                {
                    let start = group_index * codegen512::MAX_PACKED_REGIONS;
                    let mut codes = Vec::with_capacity(chunk.len());
                    for count in 1..=chunk.len() {
                        let dependency_rows = chunk[..count]
                            .iter()
                            .copied()
                            .map(deps::compute_deps)
                            .collect::<Vec<_>>();
                        codes.push(
                            generated.push(codegen512::generate_muladd_multi(&dependency_rows))?,
                        );
                    }
                    plan.avx512.push(Avx512GroupPlan { start, codes });
                }
            }
        }
        plans.push(plan);
    }
    let size = match width {
        JitWidth::Avx2 => PackedCodeSize {
            generated_bytes: 0,
            arena_bytes: WORKER_JIT_BYTES,
        },
        JitWidth::Avx512 => generated.size,
    };
    Ok(PackedBatchPlan {
        generated: generated.bytes,
        offsets: generated.offsets,
        rows: plans,
        size,
    })
}

impl PackedJitCode {
    /// Build the packed bodies in finalized RX mappings. Zero factors retain
    /// their source positions for AVX512 group shape but do not allocate an
    /// AVX2 body.
    pub fn new(width: JitWidth, factors: &[u16]) -> io::Result<Self> {
        if factors.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "packed XOR-JIT dispatch needs at least one factor",
            ));
        }

        let mut packed = Self {
            width,
            factors: factors.to_vec(),
            avx2: Vec::new(),
            avx512: Vec::new(),
        };
        let mut generated = Vec::new();
        let mut avx2_bodies = Vec::new();
        let mut avx512_shapes = Vec::new();
        match width {
            JitWidth::Avx2 => {
                for (source, &factor) in factors.iter().enumerate() {
                    if factor == 0 {
                        continue;
                    }
                    avx2_bodies.push((source, factor));
                }
            }
            JitWidth::Avx512 => {
                for (group_index, chunk) in
                    factors.chunks(codegen512::MAX_PACKED_REGIONS).enumerate()
                {
                    let start = group_index * codegen512::MAX_PACKED_REGIONS;
                    let mut shape = Vec::with_capacity(chunk.len());
                    for count in 1..=chunk.len() {
                        let dependency_rows = chunk[..count]
                            .iter()
                            .copied()
                            .map(deps::compute_deps)
                            .collect::<Vec<_>>();
                        generated.push(codegen512::generate_muladd_multi(&dependency_rows));
                        shape.push(count);
                    }
                    avx512_shapes.push((start, shape));
                }
            }
        }
        let mut finalized = JitCode::new_batch(&generated)?.into_iter();
        match width {
            JitWidth::Avx2 => {
                for (source, factor) in avx2_bodies {
                    packed.avx2.push(Avx2Body { source, factor });
                }
            }
            JitWidth::Avx512 => {
                for (start, shape) in avx512_shapes {
                    let codes = shape
                        .into_iter()
                        .map(|_| finalized.next().expect("packed AVX512 body"))
                        .collect();
                    packed.avx512.push(Avx512Group { start, codes });
                }
            }
        }
        debug_assert!(finalized.next().is_none());
        Ok(packed)
    }

    /// Number of coefficient/source slots represented by this dispatch.
    pub fn regions(&self) -> usize {
        self.factors.len()
    }

    pub(crate) fn width(&self) -> JitWidth {
        self.width
    }

    /// Run packed multiply-add. `run.packed_regions` must equal this
    /// dispatch's allocated input-pack width; `run.live_regions` may be
    /// shorter for Turbo's final input group.
    ///
    /// # Safety
    /// The selected CPU JIT width must be available. `run.src` must be readable
    /// for `run.packed_regions * run.len` bytes and `run.dst` writable for
    /// `run.len` bytes for the duration of the call. Those ranges must not
    /// overlap. `run.len` must be a multiple of 512 for AVX2 or 1024 for
    /// AVX512. Optional prefetch bases must support every address produced by
    /// the documented packed prefetch progression.
    pub unsafe fn run(&self, run: PackedRun) -> Result<(), PackedExecutionError> {
        let mut scratch = PackedScratch::default();
        self.try_run_with_scratch(&mut scratch, run)
    }

    /// Fallible packed dispatch for repair controllers that own staged output.
    ///
    /// A generation or W^X transition error can occur after an earlier source
    /// has contributed to `run.dst`; callers must discard that staged output
    /// and propagate the error instead of retrying this call in place.
    ///
    /// # Safety
    /// The caller must satisfy all requirements of [`Self::run`]. `scratch`
    /// must be exclusively owned by the calling worker until execution
    /// returns.
    pub unsafe fn try_run_with_scratch(
        &self,
        scratch: &mut PackedScratch,
        run: PackedRun,
    ) -> Result<(), PackedExecutionError> {
        self.try_run_with_scratch_inner(scratch, run)
    }

    /// Packed dispatch using caller-owned worker scratch.
    ///
    /// # Safety
    /// The caller must satisfy all requirements of [`Self::run`]. `scratch`
    /// must be exclusively owned by the calling worker until execution
    /// returns.
    pub unsafe fn run_with_scratch(
        &self,
        scratch: &mut PackedScratch,
        run: PackedRun,
    ) -> Result<(), PackedExecutionError> {
        self.try_run_with_scratch(scratch, run)
    }

    unsafe fn try_run_with_scratch_inner(
        &self,
        scratch: &mut PackedScratch,
        run: PackedRun,
    ) -> Result<(), PackedExecutionError> {
        assert_eq!(run.packed_regions, self.factors.len());
        assert!(run.live_regions <= run.packed_regions);
        assert!(run.len != 0 && run.len.is_multiple_of(self.width.block_bytes()));
        if run.live_regions == 0 {
            return Ok(());
        }
        if self.factors[..run.live_regions]
            .iter()
            .all(|&factor| factor == 0)
        {
            return Ok(());
        }
        if self.factors[..run.live_regions]
            .iter()
            .all(|&factor| factor == 1)
        {
            add_packed(run);
            return Ok(());
        }

        match self.width {
            JitWidth::Avx2 => {
                for body in &self.avx2 {
                    if body.source >= run.live_regions {
                        break;
                    }
                    let source = run.src.add(body.source * run.len);
                    let prefetch = prefetch_for_source(
                        body.source,
                        run.len,
                        run.prefetch_in,
                        run.prefetch_out,
                    );
                    scratch.try_run_avx2(body.factor, source, run.dst, run.len, prefetch)?;
                }
            }
            JitWidth::Avx512 => {
                for group in &self.avx512 {
                    if group.start >= run.live_regions {
                        break;
                    }
                    let count = (run.live_regions - group.start).min(group.codes.len());
                    scratch.sources.clear();
                    scratch.sources.extend(
                        (0..count).map(|offset| run.src.add((group.start + offset) * run.len)),
                    );
                    group.codes[count - 1].run_muladd_multi_512(&scratch.sources, run.dst, run.len);
                }
            }
        }
        Ok(())
    }
}

/// XOR the live packed planar regions into the destination. This is the
/// multiply-by-one shortcut corresponding to Turbo's `add_multi_packpf`.
/// Prefetch arguments are hints only; no correctness depends on them.
///
/// # Safety
/// `run.live_regions` must not exceed `run.packed_regions`. `run.src` must be
/// readable for `run.packed_regions * run.len` bytes and `run.dst` writable
/// for `run.len` bytes for the duration of the call; those ranges must not
/// overlap. Optional prefetch bases must support every address produced by the
/// packed prefetch progression.
pub unsafe fn add_packed(run: PackedRun) {
    assert!(run.live_regions <= run.packed_regions);
    for region in 0..run.live_regions {
        let source = run.src.add(region * run.len);
        let prefetch = prefetch_for_source(region, run.len, run.prefetch_in, run.prefetch_out);
        for offset in (0..run.len).step_by(64) {
            if let Some(prefetch) = prefetch {
                prefetch_bytes(prefetch.add(offset));
            }
            let count = (run.len - offset).min(64);
            for byte in 0..count {
                let dst_byte = run.dst.add(offset + byte);
                *dst_byte ^= *source.add(offset + byte);
            }
        }
    }
}

#[inline]
fn prefetch_for_source(
    source: usize,
    len: usize,
    prefetch_in: Option<*const u8>,
    prefetch_out: Option<*const u8>,
) -> Option<*const u8> {
    let half_len = len / 2;
    if source < AVX2_PREFETCH_OUTPUT_SOURCES {
        prefetch_out.map(|pointer| pointer.wrapping_add(source * half_len))
    } else {
        prefetch_in
            .map(|pointer| pointer.wrapping_add((source - AVX2_PREFETCH_OUTPUT_SOURCES) * half_len))
    }
}

#[inline]
unsafe fn prefetch_bytes(pointer: *const u8) {
    #[cfg(target_arch = "x86_64")]
    {
        core::arch::x86_64::_mm_prefetch(pointer.cast::<i8>(), 2);
    }
    #[cfg(target_arch = "x86")]
    {
        core::arch::x86::_mm_prefetch(pointer.cast::<i8>(), 2);
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        let _ = pointer;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn avx512_groups_cover_all_prefix_shapes() {
        let dispatch = PackedJitCode::new(JitWidth::Avx512, &[1, 2, 3, 4, 5, 6]).unwrap();
        assert_eq!(dispatch.avx512[0].codes.len(), 6);
        assert_eq!(dispatch.regions(), 6);
    }

    #[test]
    fn avx2_zero_factors_preserve_source_positions() {
        let dispatch = PackedJitCode::new(JitWidth::Avx2, &[0, 2, 0, 3]).unwrap();
        assert_eq!(dispatch.avx2[0].source, 1);
        assert_eq!(dispatch.avx2[1].source, 3);
    }

    #[test]
    fn add_packed_xors_each_live_region() {
        let mut dst = [0x11u8; 130];
        let mut src = [0x22u8; 260];
        src[130..].fill(0x44);
        unsafe {
            add_packed(PackedRun {
                packed_regions: 2,
                live_regions: 2,
                dst: dst.as_mut_ptr(),
                src: src.as_ptr(),
                len: dst.len(),
                prefetch_in: None,
                prefetch_out: None,
            });
        }
        assert!(dst.iter().all(|&byte| byte == 0x77));
    }

    #[test]
    fn prefetch_offsets_keep_zero_factor_slots() {
        let output = [0u8; 512];
        let input = [0u8; 512];
        let len = 128;
        let output_base = output.as_ptr() as usize;
        let input_base = input.as_ptr() as usize;
        let factors = [0u16, 1, 0, 2];
        let slots = factors
            .iter()
            .enumerate()
            .map(|(slot, _)| {
                prefetch_for_source(slot, len, Some(input.as_ptr()), Some(output.as_ptr())).unwrap()
                    as usize
            })
            .collect::<Vec<_>>();
        // The zero coefficients at slots 0 and 2 are still source positions;
        // the prefetch stream selection must not compact them away.
        assert_eq!(
            slots,
            [
                output_base,
                output_base + len / 2,
                input_base,
                input_base + len / 2,
            ]
        );
    }

    #[test]
    fn packed_avx2_uses_bounded_worker_scratch() {
        let row = [0xA53Cu16];
        let size = PackedJitBatch::estimate(JitWidth::Avx2, &[&row]).unwrap();
        assert_eq!(size.generated_bytes, 0);
        assert_eq!(size.arena_bytes, WORKER_JIT_BYTES);

        let batch = PackedJitBatch::new(JitWidth::Avx2, &[&row]).unwrap();
        assert!(batch.arena.is_none());
    }

    #[test]
    fn packed_batch_retains_avx2_dependencies_without_a_code_arena() {
        let first = [1u16, 2, 0];
        let second = [2u16, 1, 0];
        let one = PackedJitBatch::estimate(JitWidth::Avx2, &[&first]).unwrap();
        let two = PackedJitBatch::estimate(JitWidth::Avx2, &[&first, &second]).unwrap();
        assert_eq!(one, two);

        let batch = PackedJitBatch::new(JitWidth::Avx2, &[&first, &second]).unwrap();
        assert!(batch.arena.is_none());
        assert_eq!(batch.rows[0].avx2.len(), 2);
        assert_eq!(batch.rows[1].avx2.len(), 2);
    }

    #[test]
    fn packed_batch_shares_avx512_arena_for_row_specific_bodies() {
        let first = [1u16, 2, 3];
        let second = [4u16, 5, 6];
        let batch = PackedJitBatch::new(JitWidth::Avx512, &[&first, &second]).unwrap();
        assert!(super::super::memory::shares_mapping(
            &batch.rows[0].avx512[0].codes[0],
            &batch.rows[1].avx512[0].codes[0],
        ));
    }

    #[test]
    fn packed_batch_limit_is_checked_before_mapping() {
        let row = [1u16, 2, 3];
        let size = PackedJitBatch::estimate(JitWidth::Avx2, &[&row]).unwrap();
        let error =
            match PackedJitBatch::new_with_limit(JitWidth::Avx2, &[&row], size.arena_bytes - 1) {
                Err(error) => error,
                Ok(_) => panic!("resource limit must reject the packed arena"),
            };
        assert!(matches!(
            error,
            PackedBuildError::Resource {
                requested_bytes,
                limit_bytes
            } if requested_bytes == size.arena_bytes && limit_bytes + 1 == requested_bytes
        ));
    }

    #[test]
    fn active_avx2_bound_covers_generated_factor_domain() {
        for factor in 1..=u16::MAX {
            let mut normal = Vec::new();
            let mut prefetch = Vec::new();
            turbo_avx2::append_muladd_body(&mut normal, factor, false).unwrap();
            turbo_avx2::append_muladd_body(&mut prefetch, factor, true).unwrap();
            assert!(
                normal.len() <= AVX2_MAX_BODY_BYTES,
                "normal factor {factor:#06x} generated {} bytes",
                normal.len()
            );
            assert!(
                prefetch.len() <= AVX2_MAX_BODY_BYTES,
                "prefetch factor {factor:#06x} generated {} bytes",
                prefetch.len()
            );
        }
    }

    #[test]
    fn turbo_writer_materializes_distinct_normal_and_prefetch_bodies() {
        let mut normal = Vec::new();
        let mut prefetch = Vec::new();
        turbo_avx2::append_muladd_body(&mut normal, 0xA53C, false).unwrap();
        turbo_avx2::append_muladd_body(&mut prefetch, 0xA53C, true).unwrap();

        assert_ne!(normal, prefetch);
        assert!(normal.len() < prefetch.len());
        assert_eq!(normal.last(), Some(&0xc3));
        assert_eq!(prefetch.last(), Some(&0xc3));
        assert!(
            !normal
                .windows(5)
                .any(|window| window == [0x48, 0x85, 0xf6, 0x0f, 0x84])
        );
        assert!(
            !prefetch
                .windows(5)
                .any(|window| window == [0x48, 0x85, 0xf6, 0x0f, 0x84])
        );
    }

    #[test]
    fn avx2_generation_failure_is_explicit_and_does_not_mutate_output() {
        let factor = 0x1234u16;
        let dispatch = PackedJitCode::new(JitWidth::Avx2, &[factor]).unwrap();
        let source = vec![0x5au8; 512];
        let mut output = vec![0xa5u8; 512];
        let before = output.clone();
        let mut scratch = PackedScratch {
            sources: Vec::new(),
            avx2_code: WorkerJitBuffer::new(1),
            avx2_body: Vec::new(),
        };

        let error = unsafe {
            dispatch
                .try_run_with_scratch(
                    &mut scratch,
                    PackedRun {
                        packed_regions: 1,
                        live_regions: 1,
                        dst: output.as_mut_ptr(),
                        src: source.as_ptr(),
                        len: output.len(),
                        prefetch_in: None,
                        prefetch_out: None,
                    },
                )
                .unwrap_err()
        };
        assert!(matches!(error, PackedExecutionError::WxTransition(_)));
        assert_eq!(output, before);
    }

    #[test]
    fn workspace_enforces_active_group_backpressure() {
        let row = [1u16, 2, 3];
        let limit = PackedJitBatch::active_arena_upper_bound(JitWidth::Avx2, 1, row.len()).unwrap();
        let mut workspace = PackedJitWorkspace::default();
        let first = workspace.build(JitWidth::Avx2, &[&row], limit).unwrap();
        let blocked = match workspace.build(JitWidth::Avx2, &[&row], limit) {
            Err(error) => error,
            Ok(_) => panic!("workspace must hold one active input group"),
        };
        assert!(matches!(blocked, PackedBuildError::InvalidInput(_)));
        workspace.recycle(first).unwrap();

        let second = workspace.build(JitWidth::Avx2, &[&row], limit).unwrap();
        workspace.recycle(second).unwrap();
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn worker_scratch_executes_and_reuses_wx_page_for_prefetch_modes() {
        if !std::arch::is_x86_feature_detected!("avx2") {
            return;
        }

        let factor = 0x1234u16;
        let batch = PackedJitBatch::new(JitWidth::Avx2, &[&[factor]]).unwrap();
        let dispatch = batch.row(0).unwrap();
        let source = (0..512).map(|index| index as u8).collect::<Vec<_>>();
        let mut output = vec![0x5au8; 512];
        let mut expected = output.clone();
        deps::muladd_planar_sized(&deps::compute_deps(factor), &source, &mut expected, 512, 32);

        let mut scratch = PackedScratch::new();
        unsafe {
            dispatch
                .run_with_scratch(
                    &mut scratch,
                    PackedRun {
                        packed_regions: 1,
                        live_regions: 1,
                        dst: output.as_mut_ptr(),
                        src: source.as_ptr(),
                        len: output.len(),
                        prefetch_in: None,
                        prefetch_out: None,
                    },
                )
                .unwrap();
        }
        assert_eq!(output, expected);
        let mapping = scratch.avx2_code.mapping_address().unwrap();
        assert!(scratch.avx2_code.is_writable());

        let mut prefetched = vec![0x5au8; 512];
        let mut expected_prefetched = prefetched.clone();
        deps::muladd_planar_sized(
            &deps::compute_deps(factor),
            &source,
            &mut expected_prefetched,
            512,
            32,
        );
        let prefetch = vec![0u8; 1024];
        unsafe {
            dispatch
                .run_with_scratch(
                    &mut scratch,
                    PackedRun {
                        packed_regions: 1,
                        live_regions: 1,
                        dst: prefetched.as_mut_ptr(),
                        src: source.as_ptr(),
                        len: prefetched.len(),
                        prefetch_in: None,
                        prefetch_out: Some(prefetch.as_ptr()),
                    },
                )
                .unwrap();
        }
        assert_eq!(prefetched, expected_prefetched);
        assert_eq!(scratch.avx2_code.mapping_address(), Some(mapping));
        assert!(scratch.avx2_code.is_writable());
    }

    #[test]
    fn generated_body_limit_rejects_before_retaining_candidate() {
        let mut generated = GeneratedBodies::new(80);
        assert_eq!(generated.push(vec![0u8; 32]).unwrap(), 0);
        let accepted_size = generated.size;

        let error = generated.push(vec![0u8; 32]).unwrap_err();
        assert!(matches!(
            error,
            PackedBuildError::Resource {
                requested_bytes: 96,
                limit_bytes: 80,
            }
        ));
        assert_eq!(generated.offsets.len(), 1);
        assert_eq!(generated.bytes.len(), accepted_size.arena_bytes);
        assert_eq!(generated.size, accepted_size);
    }
}
