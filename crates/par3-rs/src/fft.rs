//! Low-rate FFT geometry and bounded stripe execution.

use reedsolomon_rs::fft::{TransformError, TransformField};

use crate::runtime::{EngineError, EngineResult, ExecutionOptions, MemoryCategory, Reservation};

/// Validated codec geometry for one cohort. Dummy input slots are supplied as
/// zero by the layout adapter; they are not unavailable source bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FftGeometry {
    inputs: usize,
    capacity: usize,
    domain: usize,
    bits: u32,
}

impl FftGeometry {
    /// Validate the actual low-rate field limits. The capacity exponent is part
    /// of matrix identity and cannot be changed when more recovery arrives.
    pub fn new(inputs: u64, capacity_log2: i8) -> EngineResult<Self> {
        if !(0..=15).contains(&capacity_log2) {
            return Err(EngineError::Unsupported(
                "high-rate or oversized FFT matrix",
            ));
        }
        let inputs =
            usize::try_from(inputs).map_err(|_| EngineError::resource_limit("FFT inputs"))?;
        let capacity = 1usize << capacity_log2;
        let domain = inputs
            .checked_add(capacity)
            .and_then(usize::checked_next_power_of_two)
            .filter(|domain| *domain <= 65536)
            .ok_or(EngineError::Unsupported(
                "FFT cohort exceeds field geometry",
            ))?;
        if inputs == 0 {
            return Err(EngineError::InvalidState("empty FFT cohort"));
        }
        Ok(Self {
            inputs,
            capacity,
            domain,
            bits: if domain <= 256 { 8 } else { 16 },
        })
    }
    /// Padded input slots in this cohort.
    #[must_use]
    pub fn inputs(self) -> usize {
        self.inputs
    }
    /// Compatible recovery indices lie in `0..capacity`.
    #[must_use]
    pub fn capacity(self) -> usize {
        self.capacity
    }
    /// Size of the additive transform domain.
    #[must_use]
    pub fn domain(self) -> usize {
        self.domain
    }
    /// Required field size in bytes, including its Cantor representation.
    #[must_use]
    pub fn field_bytes(self) -> usize {
        (self.bits / 8) as usize
    }

    pub(crate) fn validate_field(self, field: crate::packet::GaloisField) -> EngineResult<()> {
        let compatible = if field.size == 0 {
            self.is_trivial() && field.generator == 0
        } else {
            field.size as usize == self.field_bytes()
                && matches!((field.size, field.generator), (1, 0x1d) | (2, 0x2d))
        };
        if !compatible {
            return Err(EngineError::Unsupported("FFT field representation"));
        }
        Ok(())
    }

    /// A single input is copied; a single recovery row is the XOR of inputs.
    /// These geometries need no field arithmetic and accept byte alignment.
    #[must_use]
    pub fn is_trivial(self) -> bool {
        self.inputs == 1 || self.capacity == 1
    }
}

/// A source row consumed by FFT decoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FftInput {
    /// Original logical block, relative to this cohort.
    Original(usize),
    /// Recovery index relative to this cohort.
    Recovery(usize),
}

/// Butterflies one full additive transform over `rows` rows performs.
fn butterflies(rows: usize) -> u64 {
    (rows as u64 / 2) * u64::from(rows.trailing_zeros())
}

/// Which of a decode's final forward transform the lost rows actually depend
/// on.
///
/// The forward transform runs its stages from the widest stride down to the
/// narrowest. A stage of stride `2^j` or wider never joins two rows whose low
/// `j` bits differ, so those stages together are `2^j` independent transforms,
/// one over each set of rows sharing its low `j` bits. Every stage narrower
/// than that stays inside one aligned block of `2^j` rows. A decode reads only
/// the lost rows, so only the blocks holding them need their narrow stages at
/// all: the rest of that work produces rows nobody reads.
///
/// The plan is the choice of `j` and the list of blocks. `j = 0` means the
/// whole transform is one block and nothing is pruned.
struct ForwardPlan {
    /// Rows per block the narrow stages are confined to, as an exponent.
    block_log2: u32,
    /// Block indices, ascending, that hold a row the caller will read.
    blocks: Vec<usize>,
    /// Visited bits for the row-handle transposes.
    visited: Vec<u64>,
    /// Butterflies this plan removes from the full transform.
    skipped: u64,
    _reservation: Reservation,
}

/// What one transform call costs beyond its butterflies, in symbol operations.
///
/// A plan replaces one transform call with `2^j + blocks` of them, and each
/// carries a fixed setup the butterflies do not pay for. Measured on this host
/// (`tests/codec_measurements.rs`): the pinned `fft16` reference geometry — a
/// 512-row domain, 32 symbols a row — skipped 1024 butterflies but took 256
/// more calls to do it, and ran about 0.2 ms slower for it, a few thousand
/// symbol operations a call. This is the conservative end of that measurement:
/// below it the plan stands aside and the full transform runs, which is what
/// the same probe now measures for both pinned reference geometries.
const PLAN_CALL_SYMBOLS: u64 = 8192;

impl ForwardPlan {
    /// Cost model, in butterflies: every wide stage in full, plus the narrow
    /// stages of the blocks that are kept.
    fn cost(domain: usize, levels: u32, block_log2: u32, blocks: u64) -> u64 {
        let wide = (domain as u64 / 2) * u64::from(levels - block_log2);
        let narrow = blocks * butterflies(1usize << block_log2);
        wide + narrow
    }

    /// The same cost in symbol operations, plus what the split itself costs:
    /// one call's setup per transform, and one handle move per row per
    /// transpose for a plan that has to gather its classes.
    fn work(cost: u64, calls: u64, domain: usize, symbols: usize) -> u64 {
        cost.saturating_mul(symbols as u64)
            .saturating_add(calls.saturating_mul(PLAN_CALL_SYMBOLS))
            .saturating_add(if calls > 1 { 2 * domain as u64 } else { 0 })
    }

    /// Choose the block width that costs the fewest butterflies for this loss
    /// pattern, and charge what the plan holds. Widths are compared, not
    /// guessed: heavy damage spreads across every block and the model then
    /// picks `j = 0`, which is the unpruned transform.
    fn new(
        geometry: FftGeometry,
        lost: &[usize],
        symbols: usize,
        options: &ExecutionOptions,
    ) -> EngineResult<Self> {
        let domain = geometry.domain;
        let levels = domain.trailing_zeros();
        let full = butterflies(domain);
        // The unpruned transform is one call over the whole domain, and a split
        // has to beat it on total work, not on butterflies alone.
        let mut best = (0u32, full, Self::work(full, 1, domain, symbols));
        for block_log2 in 1..=levels {
            let mut blocks = 0u64;
            let mut previous = None;
            // `lost` is validated distinct and ascending by the caller, so the
            // blocks it touches arrive in order and a single compare counts them.
            for &index in lost {
                let block = (geometry.capacity + index) >> block_log2;
                if previous != Some(block) {
                    blocks += 1;
                    previous = Some(block);
                }
            }
            let cost = Self::cost(domain, levels, block_log2, blocks);
            let calls = (1u64 << block_log2) + blocks;
            let work = Self::work(cost, calls, domain, symbols);
            if work < best.2 {
                best = (block_log2, cost, work);
            }
        }
        let (mut block_log2, mut cost, _) = best;
        let mut blocks = Vec::new();
        let mut visited = Vec::new();
        let bytes = if block_log2 == 0 {
            0
        } else {
            lost.len()
                .checked_mul(size_of::<usize>())
                .and_then(|bytes| bytes.checked_add(domain.div_ceil(8)))
                .and_then(|bytes| bytes.checked_add(64))
                .ok_or(EngineError::resource_limit("FFT transform plan"))?
        };
        // The plan is an optimisation, so a budget that cannot hold it narrows
        // to the unpruned transform instead of refusing the decode. That shows
        // in the diagnostics as a decode that skipped no butterflies.
        let reservation = match options
            .memory
            .reserve_as(MemoryCategory::CodecScratch, bytes)
        {
            Ok(reservation) => reservation,
            Err(EngineError::ResourceLimit(_)) => {
                block_log2 = 0;
                cost = full;
                options.memory.reserve_as(MemoryCategory::CodecScratch, 0)?
            }
            Err(error) => return Err(error),
        };
        if block_log2 > 0 {
            let mut previous = None;
            for &index in lost {
                let block = (geometry.capacity + index) >> block_log2;
                if previous != Some(block) {
                    blocks.push(block);
                    previous = Some(block);
                }
            }
            visited = vec![0; domain.div_ceil(64)];
        }
        Ok(Self {
            block_log2,
            blocks,
            visited,
            skipped: full.saturating_sub(cost),
            _reservation: reservation,
        })
    }
}

/// Move row handles so that a `rows`-by-`columns` row-major arrangement becomes
/// a `columns`-by-`rows` one. Only the handles move; no symbol is copied.
fn transpose(handles: &mut [Vec<u16>], rows: usize, columns: usize, visited: &mut [u64]) {
    debug_assert_eq!(handles.len(), rows * columns);
    let mark = |visited: &mut [u64], at: usize| visited[at / 64] |= 1 << (at % 64);
    let seen = |visited: &[u64], at: usize| visited[at / 64] >> (at % 64) & 1 == 1;
    visited.fill(0);
    for start in 0..handles.len() {
        if seen(visited, start) {
            continue;
        }
        let mut at = start;
        let mut carry = std::mem::take(&mut handles[start]);
        loop {
            mark(visited, at);
            let to = (at % columns) * rows + at / columns;
            carry = std::mem::replace(&mut handles[to], carry);
            if to == start {
                break;
            }
            at = to;
        }
    }
}

/// Bounded synchronous FFT execution. Byte streams use the PAR3 on-disk layout:
/// one byte per GF8 symbol and little-endian pairs per GF16 symbol.
pub struct FftCodec {
    geometry: FftGeometry,
    field: Option<TransformField>,
    options: ExecutionOptions,
    _tables: Option<Reservation>,
    workers: Option<crate::runtime::WorkerPool>,
}

impl FftCodec {
    /// Allocate the field only after its memory requirement is admitted.
    pub fn new(geometry: FftGeometry, options: ExecutionOptions) -> EngineResult<Self> {
        options.validate()?;
        if geometry.is_trivial() {
            return Ok(Self {
                geometry,
                field: None,
                options,
                _tables: None,
                workers: None,
            });
        }
        let reservation = options.memory.reserve_as(
            MemoryCategory::CodecTables,
            TransformField::allocation_bytes(geometry.bits).map_err(transform_error)?,
        )?;
        let field = TransformField::new(geometry.bits).map_err(transform_error)?;
        // Keep enough admission space for locator bookkeeping and a minimal
        // stripe; a worker limit is a ceiling, not a request to exhaust memory.
        let workers = crate::runtime::WorkerPool::for_work(
            &options,
            geometry.domain / 2,
            geometry.domain * 96 + 64,
        )?;
        Ok(Self {
            geometry,
            field: Some(field),
            options,
            _tables: Some(reservation),
            workers,
        })
    }

    /// Admit the repair adapter's two source buffers only after tables and
    /// worker stacks, leaving room for a minimally sized decode operation.
    /// This is a sizing floor, not a lease on future decode allocations: shared
    /// contention can still return ResourceLimit, and the caller may retry.
    pub(crate) fn reserve_source_stripes(
        &mut self,
        block_size: u64,
        recovery_count: usize,
    ) -> EngineResult<(usize, Reservation)> {
        let g = self.geometry;
        let unit = if g.is_trivial() { 1 } else { g.field_bytes() };
        let decode_floor = if g.is_trivial() {
            recovery_count.min(g.capacity) * size_of::<usize>() + 64 + 2
        } else {
            // Locator, row metadata, and the smallest field-aligned row/input
            // buffers. These are the same layouts admitted by decode/buffers.
            g.domain * 32 + g.domain * 32 + (g.domain * (2 / unit) + 2) * unit
        };
        let _decode = self
            .options
            .memory
            .reserve_as(MemoryCategory::CodecScratch, decode_floor)?;
        let target = self
            .options
            .stripe_bytes
            .min(usize::try_from(block_size).unwrap_or(usize::MAX))
            .min(self.options.memory.available() / 4);
        let (stripe, reservation) =
            self.options
                .memory
                .reserve_stripes(MemoryCategory::CodecScratch, target, 2, unit)?;
        self.options.diagnostics.note_stripe(stripe, 2, target);
        self.options.diagnostics.note_window(stripe);
        self.options.stripe_bytes = stripe;
        Ok((stripe, reservation))
    }

    /// Admitted execution workers. One runs on the caller's thread; larger
    /// counts use a private pool whose stacks remain charged until joined.
    #[must_use]
    pub fn worker_count(&self) -> usize {
        self.workers
            .as_ref()
            .map_or(1, |workers| workers.pool().current_num_threads())
    }

    fn transform(&self, rows: &mut [Vec<u16>], origin: usize, inverse: bool) -> EngineResult<()> {
        self.transform_counted(rows, origin, inverse, 0)
    }

    /// One additive transform, counted. `skipped` is the butterflies a plan
    /// removed from what this call would otherwise have had to perform, so the
    /// diagnostics can report the pruned and unpruned costs side by side.
    fn transform_counted(
        &self,
        rows: &mut [Vec<u16>],
        origin: usize,
        inverse: bool,
        skipped: u64,
    ) -> EngineResult<()> {
        let field = self.field.as_ref().expect("nontrivial FFT field");
        let cancelled = || self.options.cancel.check().is_err();
        self.options.diagnostics.note_transform(
            1,
            butterflies(rows.len()),
            rows.first().map_or(0, Vec::len),
            skipped,
        );
        if let Some(workers) = &self.workers {
            field.transform_in_pool(
                rows,
                origin,
                inverse,
                self.options.fft_backend,
                workers.pool(),
                &cancelled,
            )
        } else {
            field.transform_with_backend(
                rows,
                origin,
                inverse,
                self.options.fft_backend,
                &cancelled,
            )
        }
        .map_err(transform_error)
    }

    /// The final forward transform of a decode, pruned to `plan`.
    ///
    /// The wide stages run as `2^j` independent transforms over the rows that
    /// share their low `j` bits; those rows are strided, so their handles are
    /// gathered and put back afterwards — pointer moves, never symbol copies.
    /// The narrow stages then run only on the blocks the plan kept. Every
    /// butterfly this performs is one the full transform would have performed,
    /// with the same factor, in the same order relative to the rows it touches,
    /// so the rows the caller reads come out byte for byte identical.
    fn transform_forward(&self, rows: &mut [Vec<u16>], plan: &mut ForwardPlan) -> EngineResult<()> {
        use rayon::prelude::*;
        if plan.block_log2 == 0 {
            return self.transform_counted(rows, 0, false, 0);
        }
        let field = self.field.as_ref().expect("nontrivial FFT field");
        let backend = self.options.fft_backend;
        let cancelled = || self.options.cancel.check().is_err();
        // `width` rows to a block, and equally `width` classes; each class holds
        // the `span` rows that share its low bits.
        let width = 1usize << plan.block_log2;
        let span = rows.len() >> plan.block_log2;
        let symbols = rows.first().map_or(0, Vec::len);
        let blocks = &plan.blocks;
        let wide = |rows: &mut [Vec<u16>]| -> EngineResult<()> {
            let run = |class: &mut [Vec<u16>]| {
                field
                    .transform_with_backend(class, 0, false, backend, &cancelled)
                    .map_err(transform_error)
            };
            match &self.workers {
                Some(workers) => workers
                    .pool()
                    .install(|| rows.par_chunks_mut(span).try_for_each(run)),
                None => rows.chunks_mut(span).try_for_each(run),
            }
        };
        let narrow = |rows: &mut [Vec<u16>]| -> EngineResult<()> {
            let run = |(block, at): (usize, &mut [Vec<u16>])| {
                if blocks.binary_search(&block).is_err() {
                    return Ok(());
                }
                field
                    .transform_with_backend(at, block * width, false, backend, &cancelled)
                    .map_err(transform_error)
            };
            match &self.workers {
                Some(workers) => workers
                    .pool()
                    .install(|| rows.par_chunks_mut(width).enumerate().try_for_each(run)),
                None => rows.chunks_mut(width).enumerate().try_for_each(run),
            }
        };
        transpose(rows, span, width, &mut plan.visited);
        let result = wide(rows);
        transpose(rows, width, span, &mut plan.visited);
        result?;
        narrow(rows)?;
        let performed =
            (width as u64) * butterflies(span) + blocks.len() as u64 * butterflies(width);
        self.options.diagnostics.note_transform(
            width as u64 + blocks.len() as u64,
            performed,
            symbols,
            plan.skipped,
        );
        Ok(())
    }

    /// Encode a compatible recovery range. Input and output callbacks receive
    /// positioned byte stripes; neither whole input nor recovery blocks are kept.
    pub fn encode(
        &self,
        block_size: u64,
        first: usize,
        count: usize,
        mut read: impl FnMut(usize, u64, &mut [u8]) -> EngineResult<()>,
        mut write: impl FnMut(usize, u64, &[u8]) -> EngineResult<()>,
    ) -> EngineResult<()> {
        let mut progress = self.options.stage(crate::runtime::Stage::Encode)?;
        let mut write = |index, offset, bytes: &[u8]| {
            write(index, offset, bytes)?;
            progress.advance(bytes.len() as u64);
            self.options.cancel.check()
        };
        let g = self.geometry;
        if first.checked_add(count).is_none_or(|end| end > g.capacity) {
            return Err(EngineError::InvalidState(
                "FFT recovery range exceeds capacity",
            ));
        }
        if g.is_trivial() {
            return self.encode_trivial(block_size, first, count, read, write);
        }
        let rows = g
            .capacity
            .checked_mul(2)
            .ok_or(EngineError::resource_limit("FFT encoder rows"))?;
        let (stripe, _buffers) = self.buffers(block_size, rows)?;
        let symbols = stripe / g.field_bytes();
        let mut work = vec![vec![0u16; symbols]; g.capacity];
        let mut sum = vec![vec![0u16; symbols]; g.capacity];
        let mut bytes = vec![0; stripe];
        let mut offset = 0;
        while offset < block_size {
            self.options.cancel.check()?;
            let take = (block_size - offset).min(stripe as u64) as usize;
            for row in &mut sum {
                row.fill(0);
            }
            for base in (0..g.inputs).step_by(g.capacity) {
                for (at, row) in work.iter_mut().enumerate() {
                    self.options.cancel.check()?;
                    row.fill(0);
                    if base + at >= g.inputs {
                        continue;
                    }
                    bytes.fill(0);
                    read(base + at, offset, &mut bytes[..take])?;
                    unpack(g.field_bytes(), &bytes, row);
                }
                self.transform(&mut work, g.capacity + base, true)?;
                for (to, from) in sum.iter_mut().zip(&work) {
                    for (to, from) in to.iter_mut().zip(from) {
                        *to ^= from;
                    }
                }
            }
            self.transform(&mut sum, 0, false)?;
            for (index, row) in sum.iter().enumerate().skip(first).take(count) {
                pack(g.field_bytes(), row, &mut bytes);
                write(index, offset, &bytes[..take])?;
            }
            offset += take as u64;
        }
        Ok(())
    }

    /// Recover missing original rows using precisely the admitted recovery
    /// indices. Unused transform positions are authenticated geometry padding.
    pub fn decode(
        &self,
        block_size: u64,
        lost: &[usize],
        recovery: &[usize],
        mut read: impl FnMut(FftInput, u64, &mut [u8]) -> EngineResult<()>,
        mut write: impl FnMut(usize, u64, &[u8]) -> EngineResult<()>,
    ) -> EngineResult<()> {
        let mut progress = self.options.stage(crate::runtime::Stage::Decode)?;
        let mut write = |index, offset, bytes: &[u8]| {
            write(index, offset, bytes)?;
            self.options.diagnostics.note_reconstructed(bytes.len());
            progress.advance(bytes.len() as u64);
            self.options.cancel.check()
        };
        let g = self.geometry;
        if lost.is_empty() {
            return Ok(());
        }
        if lost.len() > recovery.len() {
            return Err(EngineError::InvalidState("insufficient FFT recovery"));
        }
        if g.is_trivial() {
            return self.decode_trivial(block_size, lost, recovery, read, write);
        }
        let field = self.field.as_ref().expect("nontrivial FFT field");
        let _plan = self.options.memory.reserve_as(
            MemoryCategory::CodecScratch,
            g.domain
                .checked_mul(32)
                .ok_or(EngineError::resource_limit("FFT locator"))?,
        )?;
        let mut erased = vec![false; g.domain];
        erased[..g.capacity].fill(true);
        for &index in recovery {
            if index >= g.capacity || !erased[index] {
                return Err(EngineError::InvalidState(
                    "invalid or duplicate FFT recovery index",
                ));
            }
            erased[index] = false;
        }
        for &index in lost {
            if index >= g.inputs || erased[g.capacity + index] {
                return Err(EngineError::InvalidState("invalid or duplicate FFT loss"));
            }
            erased[g.capacity + index] = true;
        }
        let cancelled = || self.options.cancel.check().is_err();
        let factors = field
            .erasure_factors(&erased, &cancelled)
            .map_err(transform_error)?;
        let (stripe, _buffers) = self.buffers(block_size, g.domain)?;
        let symbols = stripe / g.field_bytes();
        let mut plan = ForwardPlan::new(g, lost, symbols, &self.options)?;
        let mut rows = vec![vec![0u16; symbols]; g.domain];
        let mut bytes = vec![0; stripe];
        let mut offset = 0;
        while offset < block_size {
            self.options.cancel.check()?;
            let take = (block_size - offset).min(stripe as u64) as usize;
            for (index, row) in rows.iter_mut().enumerate() {
                self.options.cancel.check()?;
                row.fill(0);
                if erased[index] || index >= g.capacity + g.inputs {
                    continue;
                }
                bytes.fill(0);
                let source = if index < g.capacity {
                    FftInput::Recovery(index)
                } else {
                    FftInput::Original(index - g.capacity)
                };
                read(source, offset, &mut bytes[..take])?;
                unpack(g.field_bytes(), &bytes, row);
                field
                    .scale_with_backend(row, factors[index], self.options.fft_backend, &cancelled)
                    .map_err(transform_error)?;
            }
            self.transform(&mut rows, 0, true)?;
            field
                .derivative(&mut rows, &cancelled)
                .map_err(transform_error)?;
            self.transform_forward(&mut rows, &mut plan)?;
            for &index in lost {
                let factor = field
                    .inverse(factors[g.capacity + index])
                    .ok_or(EngineError::InvalidState("singular FFT locator"))?;
                let row = &mut rows[g.capacity + index];
                field
                    .scale_with_backend(row, factor, self.options.fft_backend, &cancelled)
                    .map_err(transform_error)?;
                pack(g.field_bytes(), row, &mut bytes);
                write(index, offset, &bytes[..take])?;
            }
            offset += take as u64;
        }
        Ok(())
    }

    fn encode_trivial(
        &self,
        block_size: u64,
        first: usize,
        count: usize,
        mut read: impl FnMut(usize, u64, &mut [u8]) -> EngineResult<()>,
        mut write: impl FnMut(usize, u64, &[u8]) -> EngineResult<()>,
    ) -> EngineResult<()> {
        let (stripe, _buffers) = self.byte_buffers(block_size)?;
        let mut sum = vec![0; stripe];
        let mut bytes = vec![0; stripe];
        let mut offset = 0;
        while offset < block_size {
            self.options.cancel.check()?;
            let take = (block_size - offset).min(stripe as u64) as usize;
            sum[..take].fill(0);
            for index in 0..self.geometry.inputs {
                self.options.cancel.check()?;
                read(index, offset, &mut bytes[..take])?;
                for (to, from) in sum[..take].iter_mut().zip(&bytes[..take]) {
                    *to ^= from;
                }
            }
            for index in first..first + count {
                self.options.cancel.check()?;
                write(index, offset, &sum[..take])?;
            }
            offset += take as u64;
        }
        Ok(())
    }

    fn decode_trivial(
        &self,
        block_size: u64,
        lost: &[usize],
        recovery: &[usize],
        mut read: impl FnMut(FftInput, u64, &mut [u8]) -> EngineResult<()>,
        mut write: impl FnMut(usize, u64, &[u8]) -> EngineResult<()>,
    ) -> EngineResult<()> {
        if lost.len() != 1 || lost[0] >= self.geometry.inputs {
            return Err(EngineError::InvalidState("invalid or duplicate FFT loss"));
        }
        // Charge only supplied indices; a large copy geometry needs no locator.
        let _indices = self.options.memory.reserve_as(
            MemoryCategory::CodecScratch,
            recovery
                .len()
                .checked_mul(size_of::<usize>())
                .ok_or(EngineError::resource_limit("FFT recovery indices"))?,
        )?;
        let mut indices = recovery.to_vec();
        indices.sort_unstable();
        if indices
            .last()
            .is_none_or(|index| *index >= self.geometry.capacity)
            || indices.windows(2).any(|pair| pair[0] == pair[1])
        {
            return Err(EngineError::InvalidState(
                "invalid or duplicate FFT recovery index",
            ));
        }
        let (stripe, _buffers) = self.byte_buffers(block_size)?;
        let mut sum = vec![0; stripe];
        let mut bytes = vec![0; stripe];
        let mut offset = 0;
        while offset < block_size {
            self.options.cancel.check()?;
            let take = (block_size - offset).min(stripe as u64) as usize;
            read(FftInput::Recovery(recovery[0]), offset, &mut sum[..take])?;
            for index in 0..self.geometry.inputs {
                self.options.cancel.check()?;
                if index == lost[0] {
                    continue;
                }
                read(FftInput::Original(index), offset, &mut bytes[..take])?;
                for (to, from) in sum[..take].iter_mut().zip(&bytes[..take]) {
                    *to ^= from;
                }
            }
            self.options.cancel.check()?;
            write(lost[0], offset, &sum[..take])?;
            offset += take as u64;
        }
        Ok(())
    }

    fn byte_buffers(&self, block_size: u64) -> EngineResult<(usize, Reservation)> {
        self.options.validate()?;
        if block_size == 0 {
            return Err(EngineError::InvalidState("FFT block alignment"));
        }
        let target = self
            .options
            .stripe_bytes
            .min(usize::try_from(block_size).unwrap_or(usize::MAX));
        let admitted = self.options.memory.reserve_stripes_with_overhead(
            MemoryCategory::CodecScratch,
            target,
            2,
            1,
            64,
        )?;
        self.options.diagnostics.note_stripe(admitted.0, 2, target);
        Ok(admitted)
    }

    fn buffers(&self, block_size: u64, rows: usize) -> EngineResult<(usize, Reservation)> {
        self.options.validate()?;
        let unit = self.geometry.field_bytes();
        if block_size == 0 || !block_size.is_multiple_of(unit as u64) {
            return Err(EngineError::InvalidState("FFT block alignment"));
        }
        let overhead = rows
            .checked_mul(32)
            .ok_or(EngineError::resource_limit("FFT rows"))?;
        let per_byte = rows
            .checked_mul(2 / unit)
            .and_then(|n| n.checked_add(2))
            .ok_or(EngineError::resource_limit("FFT stripes"))?;
        let target = self
            .options
            .stripe_bytes
            .min(usize::try_from(block_size).unwrap_or(usize::MAX));
        let buffers = self.options.memory.reserve_stripes_with_overhead(
            MemoryCategory::CodecScratch,
            target,
            per_byte,
            unit,
            overhead,
        )?;
        self.options
            .diagnostics
            .note_stripe(buffers.0, per_byte, target);
        tracing::debug!(stripe_bytes = buffers.0, rows, "PAR3 FFT stripes admitted");
        Ok(buffers)
    }
}

fn unpack(unit: usize, bytes: &[u8], out: &mut [u16]) {
    if unit == 1 {
        for (to, from) in out.iter_mut().zip(bytes) {
            *to = *from as u16;
        }
    } else {
        for (to, from) in out.iter_mut().zip(bytes.chunks_exact(2)) {
            *to = u16::from_le_bytes([from[0], from[1]]);
        }
    }
}
fn pack(unit: usize, symbols: &[u16], out: &mut [u8]) {
    if unit == 1 {
        for (to, from) in out.iter_mut().zip(symbols) {
            *to = *from as u8;
        }
    } else {
        for (to, from) in out.chunks_exact_mut(2).zip(symbols) {
            to.copy_from_slice(&from.to_le_bytes());
        }
    }
}
fn transform_error(error: TransformError) -> EngineError {
    match error {
        TransformError::Cancelled => EngineError::Cancelled,
        TransformError::Field => EngineError::Unsupported("FFT field"),
        TransformError::Geometry => EngineError::InvalidState("FFT transform geometry"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::GaloisField;

    #[test]
    fn declared_fft_fields_must_match_the_reference_representation() {
        for (inputs, size, generator) in [(4, 1, 0x1d), (300, 2, 0x2d)] {
            let geometry = FftGeometry::new(inputs, 2).unwrap();
            assert!(
                geometry
                    .validate_field(GaloisField { size, generator })
                    .is_ok()
            );
            for generator in [0, 0x1b, 0x100b, generator | (1 << (size * 8))] {
                assert!(matches!(
                    geometry.validate_field(GaloisField { size, generator }),
                    Err(EngineError::Unsupported("FFT field representation"))
                ));
            }
            assert!(
                geometry
                    .validate_field(GaloisField {
                        size: 0,
                        generator: 0
                    })
                    .is_err()
            );
        }
        let xor = FftGeometry::new(4, 0).unwrap();
        assert!(
            xor.validate_field(GaloisField {
                size: 0,
                generator: 0
            })
            .is_ok()
        );
        assert!(
            xor.validate_field(GaloisField {
                size: 0,
                generator: 1
            })
            .is_err()
        );
    }
}

#[cfg(test)]
mod charge_tests {
    use super::*;
    use crate::runtime::{MemoryBudget, MemoryCategory};

    fn options(limit: usize) -> ExecutionOptions {
        ExecutionOptions {
            memory: MemoryBudget::new(limit),
            workers: 1,
            stripe_bytes: 64 << 10,
            ..ExecutionOptions::default()
        }
    }

    /// The transform field's charge must cover building it, not just holding
    /// it: `TransformField::new` fills a polynomial-log table that is freed
    /// again before the constructor returns.
    #[test]
    fn transform_field_charge_covers_setup_and_the_tables_it_leaves() {
        for bits in [8u32, 16] {
            let order = 1usize << bits;
            let charge = TransformField::allocation_bytes(bits).unwrap();
            // log and exp survive; polynomial_log does not.
            let retained = (order + 2 * (order - 1)) * size_of::<u16>();
            let peak = retained + order * size_of::<u16>();
            assert!(
                charge >= peak,
                "{bits}-bit field charges {charge} for a {peak} peak"
            );
            assert!(
                charge < peak * 2,
                "{bits}-bit field charges {charge}, more than twice its {peak} peak"
            );

            let geometry = FftGeometry::new(order as u64 / 4, 1).unwrap();
            assert_eq!(geometry.bits, bits);
            let options = options(64 << 20);
            let codec = FftCodec::new(geometry, options.clone()).unwrap();
            let tables = options
                .memory
                .ledger()
                .category(MemoryCategory::CodecTables);
            assert_eq!(tables.current, charge as u64);
            drop(codec);
            assert_eq!(
                options
                    .memory
                    .ledger()
                    .category(MemoryCategory::CodecTables)
                    .current,
                0
            );
        }
    }

    /// One cohort's row workspace is `domain` transform rows plus one byte
    /// stripe. The charge is taken before any of it is allocated, so it must
    /// cover every row's capacity and its vector header.
    #[test]
    fn row_workspace_charge_matches_the_rows_a_cohort_allocates() {
        for inputs in [200u64, 5_000] {
            let geometry = FftGeometry::new(inputs, 1).unwrap();
            let options = options(256 << 20);
            let codec = FftCodec::new(geometry, options.clone()).unwrap();
            let unit = geometry.field_bytes();
            let block_size = 1 << 16;
            let before = options.memory.used();
            let (stripe, buffers) = codec.buffers(block_size, geometry.domain).unwrap();
            assert_eq!(options.memory.used() - before, buffers.bytes());

            // Exactly what `decode` allocates once the charge is granted.
            let symbols = stripe / unit;
            let rows = vec![vec![0u16; symbols]; geometry.domain];
            let bytes = vec![0u8; stripe];
            let measured = rows.capacity() * size_of::<Vec<u16>>()
                + rows
                    .iter()
                    .map(|row| row.capacity() * size_of::<u16>())
                    .sum::<usize>()
                + bytes.capacity();
            assert!(
                buffers.bytes() >= measured,
                "{inputs} inputs charge {} for a {measured} byte workspace",
                buffers.bytes()
            );
            assert!(
                buffers.bytes() < measured * 2,
                "{inputs} inputs charge {}, more than twice their {measured} byte workspace",
                buffers.bytes()
            );
            drop(buffers);
            drop(rows);
            assert_eq!(options.memory.used(), before);
            drop(codec);
            assert_eq!(options.memory.used(), 0);
        }
    }

    /// The repair adapter keeps two byte buffers for the whole reconstruction
    /// and briefly reserves a decode floor while sizing them. The floor must be
    /// released again, and the buffers charged for exactly what they hold.
    #[test]
    fn source_adapter_buffers_outlive_the_decode_floor_they_were_sized_against() {
        let geometry = FftGeometry::new(1_000, 1).unwrap();
        let options = options(64 << 20);
        let mut codec = FftCodec::new(geometry, options.clone()).unwrap();
        let tables = options.memory.used();
        let (stripe, buffers) = codec.reserve_source_stripes(1 << 16, 4).unwrap();
        let held = options.memory.used() - tables;
        assert_eq!(held, buffers.bytes(), "the decode floor was not released");

        let first = vec![0u8; stripe];
        let second = vec![0u8; stripe];
        let measured = first.capacity() + second.capacity();
        assert!(
            buffers.bytes() >= measured,
            "adapter buffers charge {} for {measured} bytes",
            buffers.bytes()
        );
        assert!(
            buffers.bytes() < measured * 2,
            "adapter buffers charge {}, more than twice their {measured} bytes",
            buffers.bytes()
        );
        let peak = options
            .memory
            .ledger()
            .category(MemoryCategory::CodecScratch)
            .peak;
        assert!(
            peak > buffers.bytes() as u64,
            "the decode floor must show in the ledger's peak"
        );
        drop(buffers);
        drop(codec);
        assert_eq!(options.memory.used(), 0);
    }
}

#[cfg(test)]
mod plan_tests {
    use super::*;
    use crate::runtime::MemoryBudget;

    fn rows(count: usize, symbols: usize, bits: u32, seed: u64) -> Vec<Vec<u16>> {
        let mut state = seed | 1;
        let mask = if bits == 8 { 0xff } else { 0xffff };
        (0..count)
            .map(|_| {
                (0..symbols)
                    .map(|_| {
                        state ^= state << 13;
                        state ^= state >> 7;
                        state ^= state << 17;
                        (state & mask) as u16
                    })
                    .collect()
            })
            .collect()
    }

    #[test]
    fn a_transposed_row_order_matches_the_naive_one_and_returns_to_itself() {
        for (rows, columns) in [
            (1usize, 8usize),
            (8, 1),
            (2, 4),
            (4, 2),
            (8, 8),
            (16, 4),
            (3, 5),
        ] {
            let mut handles: Vec<Vec<u16>> = (0..rows * columns).map(|i| vec![i as u16]).collect();
            let original = handles.clone();
            let mut visited = vec![0u64; (rows * columns).div_ceil(64)];
            transpose(&mut handles, rows, columns, &mut visited);
            for y in 0..rows {
                for x in 0..columns {
                    assert_eq!(
                        handles[x * rows + y],
                        original[y * columns + x],
                        "{rows}x{columns} at ({y},{x})"
                    );
                }
            }
            transpose(&mut handles, columns, rows, &mut visited);
            assert_eq!(handles, original, "{rows}x{columns} did not return");
        }
    }

    /// A budget with no room for the plan narrows to the unpruned transform
    /// rather than refusing the decode, and charges nothing for the plan it did
    /// not take.
    #[test]
    fn a_budget_too_small_for_a_plan_falls_back_to_the_full_transform() {
        let geometry = FftGeometry::new(900, 7).unwrap();
        let options = ExecutionOptions {
            memory: MemoryBudget::new(64 << 20),
            ..ExecutionOptions::default()
        };
        // Hold everything but a handful of bytes, which is less than the plan
        // for 2048 rows and one loss needs.
        let _held = options
            .memory
            .reserve(options.memory.available() - 8)
            .unwrap();
        let plan = ForwardPlan::new(geometry, &[5], 4096, &options).unwrap();
        assert_eq!(plan.block_log2, 0, "a refused plan must not be taken");
        assert_eq!(plan.skipped, 0, "a refused plan skips nothing");
        assert!(plan.blocks.is_empty());
        assert_eq!(
            options.memory.available(),
            8,
            "it charged for a plan anyway"
        );
    }

    /// Cancellation inside the pruned transform gives back exactly what the
    /// plan holds. The token is set before the call, so the transform stops at
    /// its first check with the plan's mask, block list and charge all live.
    #[test]
    fn a_cancelled_pruned_transform_gives_back_everything_the_plan_held() {
        let geometry = FftGeometry::new(900, 7).unwrap();
        let options = ExecutionOptions {
            memory: MemoryBudget::new(64 << 20),
            ..ExecutionOptions::default()
        };
        let before = options.memory.available();
        let codec = FftCodec::new(geometry, options.clone()).unwrap();
        let mut plan = ForwardPlan::new(geometry, &[5], 4096, &options).unwrap();
        assert!(plan.block_log2 > 0, "this geometry should plan a split");
        assert!(options.memory.used() > 0, "the plan charged nothing");
        let mut workspace = rows(geometry.domain, 4096, geometry.bits, 0x51ed);
        options.cancel.cancel();
        assert!(
            matches!(
                codec.transform_forward(&mut workspace, &mut plan),
                Err(EngineError::Cancelled)
            ),
            "a cancelled transform did not report it"
        );
        drop(plan);
        drop(codec);
        assert_eq!(options.memory.used(), 0);
        assert_eq!(options.memory.available(), before);
        for (category, entry) in options.memory.ledger().iter() {
            assert_eq!(entry.current, 0, "{} leaked", category.name());
        }
    }

    /// The oracle for the pruned transform is the full one: every row a plan
    /// keeps must come out exactly as the unpruned transform leaves it, at
    /// every block width, in both fields, at widths either side of the SIMD
    /// threshold.
    #[test]
    fn every_block_a_plan_keeps_holds_what_the_full_transform_would_have_left() {
        for (inputs, capacity_log2, symbols) in [
            (5u64, 2i8, 4usize),
            (5, 2, 64),
            (200, 6, 65),
            (200, 6, 128),
            (900, 7, 16),
            (900, 7, 64),
        ] {
            let geometry = FftGeometry::new(inputs, capacity_log2).unwrap();
            let options = ExecutionOptions {
                memory: MemoryBudget::new(64 << 20),
                ..ExecutionOptions::default()
            };
            let codec = FftCodec::new(geometry, options.clone()).unwrap();
            let levels = geometry.domain.trailing_zeros();
            let start = rows(geometry.domain, symbols, geometry.bits, 0x9e37 + inputs);
            let mut expected = start.clone();
            codec.transform(&mut expected, 0, false).unwrap();
            for block_log2 in 1..=levels {
                let width = 1usize << block_log2;
                for first in [0usize, 1, geometry.domain / 2] {
                    if first + width > geometry.domain {
                        continue;
                    }
                    let block = first >> block_log2;
                    let mut plan = ForwardPlan {
                        block_log2,
                        blocks: vec![block],
                        visited: vec![0; geometry.domain.div_ceil(64)],
                        skipped: 0,
                        _reservation: options.memory.reserve(0).unwrap(),
                    };
                    let mut actual = start.clone();
                    codec.transform_forward(&mut actual, &mut plan).unwrap();
                    let kept = block * width..block * width + width;
                    assert_eq!(
                        actual[kept.clone()],
                        expected[kept],
                        "domain {} width {width} block {block} symbols {symbols}",
                        geometry.domain
                    );
                }
            }
        }
    }

    #[test]
    fn the_plan_never_costs_more_than_the_transform_it_replaces() {
        for (inputs, capacity_log2) in [(5u64, 2i8), (200, 6), (900, 7), (30_000, 10)] {
            let geometry = FftGeometry::new(inputs, capacity_log2).unwrap();
            let options = ExecutionOptions {
                memory: MemoryBudget::new(64 << 20),
                ..ExecutionOptions::default()
            };
            let levels = geometry.domain.trailing_zeros();
            let full = butterflies(geometry.domain);
            for count in [1usize, 2, 8, geometry.inputs / 2, geometry.inputs] {
                let lost: Vec<usize> = (0..count.min(geometry.inputs)).collect();
                let plan = ForwardPlan::new(geometry, &lost, 4096, &options).unwrap();
                let width = 1u64 << plan.block_log2;
                let performed = if plan.block_log2 == 0 {
                    full
                } else {
                    width * butterflies(geometry.domain >> plan.block_log2)
                        + plan.blocks.len() as u64 * butterflies(width as usize)
                };
                assert_eq!(performed + plan.skipped, full, "{inputs} losing {count}");
                assert!(performed <= full, "{inputs} losing {count}");
                assert!(plan.block_log2 <= levels);
            }
            drop(options);
        }
    }
}
