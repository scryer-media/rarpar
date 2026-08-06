//! Packed reconstruction dispatch for the XOR-JIT tiers.
//!
//! The public shape follows Turbo's `mul_add_multi_packed` and
//! `mul_add_multi_packpf` contracts. AVX2 deliberately uses the oracle's
//! ordered single-input fallback. AVX512 uses immutable multi-source bodies,
//! up to six source regions at a time, matching `XOR512_MULTI_REGIONS`.

#![allow(unsafe_op_in_unsafe_fn)]

use super::{JitWidth, codegen, codegen512, deps, memory::JitCode};
use std::{collections::HashMap, fmt, io};

const AVX2_PREFETCH_OUTPUT_SOURCES: usize = 2;
const CODE_ALIGNMENT: usize = 64;

struct Avx2Body {
    source: usize,
    code: JitCode,
    prefetch_code: JitCode,
}

struct Avx512Group {
    start: usize,
    codes: Vec<JitCode>,
}

#[derive(Clone, Copy)]
struct Avx2BodyPlan {
    source: usize,
    normal: usize,
    prefetch: usize,
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
    generated: Vec<Vec<u8>>,
    rows: Vec<PackedRowPlan>,
    size: PackedCodeSize,
}

/// Size accounting for the generated packed-code arena.
///
/// `generated_bytes` counts unique body bytes before alignment. `arena_bytes`
/// includes the cache-line padding used by the finalized RX mapping.
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

struct GeneratedBodies {
    codes: Vec<Vec<u8>>,
    size: PackedCodeSize,
    limit_bytes: usize,
}

impl GeneratedBodies {
    fn new(limit_bytes: usize) -> Self {
        Self {
            codes: Vec::new(),
            size: PackedCodeSize {
                generated_bytes: 0,
                arena_bytes: 0,
            },
            limit_bytes,
        }
    }

    /// Account for the alignment-inclusive arena size before retaining `code`.
    /// At the limit boundary the caller holds only this one temporary body in
    /// addition to previously accepted, bounded bodies.
    fn push(&mut self, code: Vec<u8>) -> Result<usize, PackedBuildError> {
        let generated_bytes = self.size.generated_bytes.checked_add(code.len()).ok_or(
            PackedBuildError::Resource {
                requested_bytes: usize::MAX,
                limit_bytes: self.limit_bytes,
            },
        )?;
        let arena_bytes = self
            .size
            .arena_bytes
            .checked_add(CODE_ALIGNMENT - 1)
            .map(|value| value & !(CODE_ALIGNMENT - 1))
            .and_then(|value| value.checked_add(code.len()))
            .ok_or(PackedBuildError::Resource {
                requested_bytes: usize::MAX,
                limit_bytes: self.limit_bytes,
            })?;
        if arena_bytes > self.limit_bytes {
            return Err(PackedBuildError::Resource {
                requested_bytes: arena_bytes,
                limit_bytes: self.limit_bytes,
            });
        }

        let index = self.codes.len();
        self.codes.push(code);
        self.size = PackedCodeSize {
            generated_bytes,
            arena_bytes,
        };
        Ok(index)
    }
}

/// Worker-owned scratch for packed dispatch. Keeping the source-pointer array
/// here avoids allocating on every AVX512 multi-source invocation.
#[derive(Default)]
pub struct PackedScratch {
    sources: Vec<*const u8>,
}

// SAFETY: the pointers are non-owning call-local addresses. The scratch is
// worker-owned and is never shared while a packed body is executing.
unsafe impl Send for PackedScratch {}

impl PackedScratch {
    pub fn new() -> Self {
        Self::default()
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

/// One finalized RX arena containing packed dispatch for every output row in
/// an input batch. AVX2 factor bodies are deduplicated by coefficient; AVX512
/// prefix bodies remain row-specific but share the same arena.
pub struct PackedJitBatch {
    rows: Vec<PackedJitCode>,
    size: PackedCodeSize,
}

impl PackedJitBatch {
    /// Estimate the unique generated bodies without allocating executable
    /// memory. The owner of `JitMemo` should use this before shaping repair
    /// buffers, then call [`Self::new_with_limit`] with the same rows.
    pub fn estimate(width: JitWidth, rows: &[&[u16]]) -> Result<PackedCodeSize, PackedBuildError> {
        Ok(build_batch_plan(width, rows, usize::MAX)?.size)
    }

    /// Build one shared executable arena for all coefficient rows.
    ///
    /// Integration contract: retain this batch for the input group and use
    /// [`Self::row`] for each output. Do not call [`PackedJitCode::new`] once
    /// per output. A resource error should select folded fallback before
    /// repair data buffers are shaped.
    pub fn new(width: JitWidth, rows: &[&[u16]]) -> Result<Self, PackedBuildError> {
        Self::new_with_limit(width, rows, usize::MAX)
    }

    /// Build a shared arena, refusing it when its alignment-inclusive size
    /// exceeds `limit_bytes`.
    pub fn new_with_limit(
        width: JitWidth,
        rows: &[&[u16]],
        limit_bytes: usize,
    ) -> Result<Self, PackedBuildError> {
        let PackedBatchPlan {
            generated,
            rows: plans,
            size,
        } = build_batch_plan(width, rows, limit_bytes)?;
        let finalized = JitCode::new_batch(&generated)?;
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
                        code: finalized[body.normal].clone(),
                        prefetch_code: finalized[body.prefetch].clone(),
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
        Ok(Self { rows, size })
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

    let mut generated = GeneratedBodies::new(limit_bytes);
    let mut avx2_bodies = HashMap::<u16, (usize, usize)>::new();
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
                    let (normal, prefetch) = if let Some(&slots) = avx2_bodies.get(&factor) {
                        slots
                    } else {
                        let factor_deps = deps::compute_deps(factor);
                        let normal = generated.push(codegen::generate_muladd(&factor_deps))?;
                        let prefetch = generated
                            .push(codegen::generate_muladd_with_prefetch(&factor_deps, true))?;
                        avx2_bodies.insert(factor, (normal, prefetch));
                        (normal, prefetch)
                    };
                    plan.avx2.push(Avx2BodyPlan {
                        source,
                        normal,
                        prefetch,
                    });
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
    let size = generated.size;
    Ok(PackedBatchPlan {
        generated: generated.codes,
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
        let mut avx2_sources = Vec::new();
        let mut avx512_shapes = Vec::new();
        match width {
            JitWidth::Avx2 => {
                for (source, &factor) in factors.iter().enumerate() {
                    if factor == 0 {
                        continue;
                    }
                    let factor_deps = deps::compute_deps(factor);
                    generated.push(codegen::generate_muladd(&factor_deps));
                    generated.push(codegen::generate_muladd_with_prefetch(&factor_deps, true));
                    avx2_sources.push(source);
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
                for source in avx2_sources {
                    packed.avx2.push(Avx2Body {
                        source,
                        code: finalized.next().expect("packed AVX2 body"),
                        prefetch_code: finalized.next().expect("packed AVX2 prefetch body"),
                    });
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
    pub unsafe fn run(&self, run: PackedRun) {
        let mut scratch = PackedScratch::default();
        self.run_with_scratch(&mut scratch, run);
    }

    /// Run packed multiply-add using caller-owned worker scratch.
    ///
    /// # Safety
    /// The caller must satisfy all requirements of [`Self::run`]. `scratch`
    /// must be exclusively owned by the calling worker until execution
    /// returns.
    pub unsafe fn run_with_scratch(&self, scratch: &mut PackedScratch, run: PackedRun) {
        assert_eq!(run.packed_regions, self.factors.len());
        assert!(run.live_regions <= run.packed_regions);
        if run.live_regions == 0 {
            return;
        }
        if self.factors[..run.live_regions]
            .iter()
            .all(|&factor| factor == 0)
        {
            return;
        }
        if self.factors[..run.live_regions]
            .iter()
            .all(|&factor| factor == 1)
        {
            add_packed(run);
            return;
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
                    if let Some(prefetch) = prefetch {
                        body.prefetch_code
                            .run_muladd_prefetch(source, run.dst, run.len, prefetch);
                    } else {
                        body.code.run_muladd(source, run.dst, run.len);
                    }
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
        let src = [0x22u8; 260];
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
        assert!(dst.iter().all(|&byte| byte == 0x33));
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
    fn packed_batch_deduplicates_avx2_factor_bodies() {
        let first = [1u16, 2, 0];
        let second = [2u16, 1, 0];
        let one = PackedJitBatch::estimate(JitWidth::Avx2, &[&first]).unwrap();
        let two = PackedJitBatch::estimate(JitWidth::Avx2, &[&first, &second]).unwrap();
        assert_eq!(one, two);

        let batch = PackedJitBatch::new(JitWidth::Avx2, &[&first, &second]).unwrap();
        assert!(super::memory::shares_mapping(
            &batch.rows[0].avx2[0].code,
            &batch.rows[1].avx2[0].code,
        ));
    }

    #[test]
    fn packed_batch_shares_avx512_arena_for_row_specific_bodies() {
        let first = [1u16, 2, 3];
        let second = [4u16, 5, 6];
        let batch = PackedJitBatch::new(JitWidth::Avx512, &[&first, &second]).unwrap();
        assert!(super::memory::shares_mapping(
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
        assert_eq!(generated.codes.len(), 1);
        assert_eq!(generated.size, accepted_size);
    }
}
