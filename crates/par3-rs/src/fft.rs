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
        let field = self.field.as_ref().expect("nontrivial FFT field");
        let cancelled = || self.options.cancel.check().is_err();
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
            self.transform(&mut rows, 0, false)?;
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
