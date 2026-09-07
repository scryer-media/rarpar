//! Low-rate FFT geometry and bounded stripe execution.

use reedsolomon_rs::fft::{TransformError, TransformField};

use crate::runtime::{EngineError, EngineResult, ExecutionOptions, Reservation};

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
            usize::try_from(inputs).map_err(|_| EngineError::ResourceLimit("FFT inputs"))?;
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
    field: TransformField,
    options: ExecutionOptions,
    _tables: Reservation,
}

impl FftCodec {
    /// Allocate the field only after its memory requirement is admitted.
    pub fn new(geometry: FftGeometry, options: ExecutionOptions) -> EngineResult<Self> {
        options.validate()?;
        let reservation = options
            .memory
            .reserve(TransformField::allocation_bytes(geometry.bits).map_err(transform_error)?)?;
        let field = TransformField::new(geometry.bits).map_err(transform_error)?;
        Ok(Self {
            geometry,
            field,
            options,
            _tables: reservation,
        })
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
        let g = self.geometry;
        if first.checked_add(count).is_none_or(|end| end > g.capacity) {
            return Err(EngineError::InvalidState(
                "FFT recovery range exceeds capacity",
            ));
        }
        let rows = g
            .capacity
            .checked_mul(2)
            .ok_or(EngineError::ResourceLimit("FFT encoder rows"))?;
        let (stripe, _buffers) = self.buffers(block_size, rows)?;
        let symbols = stripe / g.field_bytes();
        let mut work = vec![vec![0u16; symbols]; g.capacity];
        let mut sum = vec![vec![0u16; symbols]; g.capacity];
        let mut bytes = vec![0; stripe];
        let cancelled = || self.options.cancel.check().is_err();
        let mut offset = 0;
        while offset < block_size {
            self.options.cancel.check()?;
            let take = (block_size - offset).min(stripe as u64) as usize;
            for row in &mut sum {
                row.fill(0);
            }
            if g.inputs == 1 {
                read(0, offset, &mut bytes[..take])?;
                for index in first..first + count {
                    write(index, offset, &bytes[..take])?;
                }
                offset += take as u64;
                continue;
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
                self.field
                    .transform(&mut work, g.capacity + base, true, &cancelled)
                    .map_err(transform_error)?;
                for (to, from) in sum.iter_mut().zip(&work) {
                    for (to, from) in to.iter_mut().zip(from) {
                        *to ^= from;
                    }
                }
            }
            self.field
                .transform(&mut sum, 0, false, &cancelled)
                .map_err(transform_error)?;
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
        let g = self.geometry;
        if lost.is_empty() {
            return Ok(());
        }
        if lost.len() > recovery.len() {
            return Err(EngineError::InvalidState("insufficient FFT recovery"));
        }
        let _plan = self.options.memory.reserve(
            g.domain
                .checked_mul(32)
                .ok_or(EngineError::ResourceLimit("FFT locator"))?,
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
        let factors = self
            .field
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
            if g.inputs == 1 {
                read(FftInput::Recovery(recovery[0]), offset, &mut bytes[..take])?;
                write(0, offset, &bytes[..take])?;
                offset += take as u64;
                continue;
            }
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
                for value in row {
                    *value = self.field.mul(*value, factors[index]);
                }
            }
            self.field
                .transform(&mut rows, 0, true, &cancelled)
                .map_err(transform_error)?;
            self.field
                .derivative(&mut rows, &cancelled)
                .map_err(transform_error)?;
            self.field
                .transform(&mut rows, 0, false, &cancelled)
                .map_err(transform_error)?;
            for &index in lost {
                let factor = self
                    .field
                    .inverse(factors[g.capacity + index])
                    .ok_or(EngineError::InvalidState("singular FFT locator"))?;
                let row = &mut rows[g.capacity + index];
                for value in row.iter_mut() {
                    *value = self.field.mul(*value, factor);
                }
                pack(g.field_bytes(), row, &mut bytes);
                write(index, offset, &bytes[..take])?;
            }
            offset += take as u64;
        }
        Ok(())
    }

    fn buffers(&self, block_size: u64, rows: usize) -> EngineResult<(usize, Reservation)> {
        self.options.validate()?;
        let unit = self.geometry.field_bytes();
        if block_size == 0 || !block_size.is_multiple_of(unit as u64) {
            return Err(EngineError::InvalidState("FFT block alignment"));
        }
        let overhead = rows
            .checked_mul(32)
            .ok_or(EngineError::ResourceLimit("FFT rows"))?;
        let per_byte = rows
            .checked_mul(2 / unit)
            .and_then(|n| n.checked_add(2))
            .ok_or(EngineError::ResourceLimit("FFT stripes"))?;
        let available = self.options.memory.available().saturating_sub(overhead);
        let stripe = self
            .options
            .stripe_bytes
            .min(available / per_byte)
            .min(usize::try_from(block_size).unwrap_or(usize::MAX));
        let stripe = stripe / unit * unit;
        if stripe == 0 {
            return Err(EngineError::ResourceLimit("minimum FFT stripe"));
        }
        Ok((
            stripe,
            self.options.memory.reserve(overhead + stripe * per_byte)?,
        ))
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
