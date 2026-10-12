//! Low-rate FFT geometry and bounded stripe execution.

use reedsolomon_rs::fft::{TransformError, TransformField};
use reedsolomon_rs::gf_simd::LinearBackend;

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

    /// Check the field a set's Start packet declares against this geometry.
    ///
    /// The transform's field follows from the geometry alone, so the declared
    /// field is a label rather than an input. The reference labels a set with
    /// no field (size and generator zero) whenever it carries a single recovery
    /// block, even when the FFT matrix reserves a wider capacity; that block is
    /// still the first transform parity of the declared capacity, computed in
    /// the geometry's own field. Any other label must name that field exactly.
    pub(crate) fn validate_field(self, field: crate::packet::GaloisField) -> EngineResult<()> {
        let compatible = if field.size == 0 {
            field.generator == 0
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

/// A consumer of decoded input stripes, as [`FftCodec::decode_with`] hands
/// them out: the row, the stripe's byte offset within the block, and the
/// bytes the input callback filled.
pub type FftConsumer<'a> = dyn Fn(FftInput, u64, &[u8]) -> EngineResult<()> + Sync + 'a;

/// Budget a decode's caller needs beside the decode for as long as it runs,
/// and which depends on the stripe the decode admits: a repair's proof of
/// its staged writes holds a hash frontier for every extent the stripes
/// split. The decode reserves it once its stripe is known, before it reads
/// anything, and narrows the stripe to leave room for it when it does not
/// fit beside the bank.
pub(crate) trait StripeHold {
    /// Bytes the caller needs at `stripe`, or `None` when they overflow.
    fn bytes(&self, stripe: usize) -> Option<usize>;
    /// Reserve what the caller needs at `stripe`; `false` when the budget
    /// refuses it.
    fn reserve(&self, stripe: usize) -> bool;
}

/// Butterflies one full additive transform over `rows` rows performs.
fn butterflies(rows: usize) -> u64 {
    (rows as u64 / 2) * u64::from(rows.trailing_zeros())
}

/// Symbol storage for a cohort's transform rows.
///
/// GF(2^8) rows are `u8`: a row is the stripe's own bytes, read into and
/// written from directly. GF(2^16) rows are `u16`, whose little-endian pairs
/// on disk are the rows' own bytes on a little-endian target, and convert
/// through one byte buffer elsewhere. The `u16` lane also accepts 8-bit
/// symbols, zero-extended, which is how GF(2^8) used to run; the tests keep
/// it as the reference the byte lane must match.
trait Lane: reedsolomon_rs::fft::Symbol + std::ops::BitXorAssign {
    /// Rows of `unit`-byte symbols are the stripe's byte image; no
    /// conversion buffer is needed.
    fn is_direct(unit: usize) -> bool;
    /// The row's byte image when [`Self::is_direct`].
    fn direct(unit: usize, row: &mut [Self]) -> Option<&mut [u8]>;
    fn direct_ref(unit: usize, row: &[Self]) -> Option<&[u8]>;
    fn unpack(unit: usize, bytes: &[u8], row: &mut [Self]);
    fn pack(unit: usize, row: &[Self], bytes: &mut [u8]);
    /// [`TransformField::transform_rows`], or with `sum`
    /// [`TransformField::transform_rows_adding`]. `zero` flags rows the
    /// layout leaves all zero; see
    /// [`TransformField::transform_known_zero_with_backend`].
    #[allow(clippy::too_many_arguments)]
    fn transform(
        field: &TransformField,
        rows: &mut [&mut [Self]],
        zero: Option<&[bool]>,
        origin: usize,
        inverse: bool,
        backend: LinearBackend,
        pool: Option<&rayon::ThreadPool>,
        sum: Option<&mut [&mut [Self]]>,
        cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<(), TransformError>;
    fn scale(
        field: &TransformField,
        row: &mut [Self],
        factor: u16,
        backend: LinearBackend,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), TransformError>;
}

impl Lane for u16 {
    fn is_direct(unit: usize) -> bool {
        unit == 2 && cfg!(target_endian = "little")
    }
    fn direct(unit: usize, row: &mut [Self]) -> Option<&mut [u8]> {
        if unit == 2 {
            TransformField::le_image_mut(row)
        } else {
            None
        }
    }
    fn direct_ref(unit: usize, row: &[Self]) -> Option<&[u8]> {
        if unit == 2 {
            TransformField::le_image(row)
        } else {
            None
        }
    }
    fn unpack(unit: usize, bytes: &[u8], row: &mut [Self]) {
        unpack(unit, bytes, row);
    }
    fn pack(unit: usize, row: &[Self], bytes: &mut [u8]) {
        pack(unit, row, bytes);
    }
    fn transform(
        field: &TransformField,
        rows: &mut [&mut [Self]],
        zero: Option<&[bool]>,
        origin: usize,
        inverse: bool,
        backend: LinearBackend,
        pool: Option<&rayon::ThreadPool>,
        sum: Option<&mut [&mut [Self]]>,
        cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<(), TransformError> {
        match sum {
            Some(sum) => field
                .transform_rows_adding(rows, zero, origin, inverse, backend, pool, sum, cancelled),
            None => field.transform_rows(rows, zero, origin, inverse, backend, pool, cancelled),
        }
    }
    fn scale(
        field: &TransformField,
        row: &mut [Self],
        factor: u16,
        backend: LinearBackend,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), TransformError> {
        field.scale_with_backend(row, factor, backend, cancelled)
    }
}

impl Lane for u8 {
    fn is_direct(_: usize) -> bool {
        true
    }
    fn direct(_: usize, row: &mut [Self]) -> Option<&mut [u8]> {
        Some(row)
    }
    fn direct_ref(_: usize, row: &[Self]) -> Option<&[u8]> {
        Some(row)
    }
    fn unpack(_: usize, _: &[u8], _: &mut [Self]) {
        unreachable!("byte rows are read directly")
    }
    fn pack(_: usize, _: &[Self], _: &mut [u8]) {
        unreachable!("byte rows are written directly")
    }
    fn transform(
        field: &TransformField,
        rows: &mut [&mut [Self]],
        zero: Option<&[bool]>,
        origin: usize,
        inverse: bool,
        backend: LinearBackend,
        pool: Option<&rayon::ThreadPool>,
        sum: Option<&mut [&mut [Self]]>,
        cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<(), TransformError> {
        match sum {
            Some(sum) => field.transform_u8_rows_adding(
                rows, zero, origin, inverse, backend, pool, sum, cancelled,
            ),
            None => field.transform_u8_rows(rows, zero, origin, inverse, backend, pool, cancelled),
        }
    }
    fn scale(
        field: &TransformField,
        row: &mut [Self],
        factor: u16,
        backend: LinearBackend,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), TransformError> {
        field.scale_u8_with_backend(row, factor, backend, cancelled)
    }
}

/// Bytes of workspace per stripe byte for `rows` transform rows of lane `L`
/// over a field of `unit` bytes: the rows themselves, the conversion buffer
/// when the lane needs one, and one stripe of slack.
fn workspace_per_byte<L: Lane>(rows: usize, unit: usize) -> Option<usize> {
    rows.checked_mul(size_of::<L>() / unit)?
        .checked_add(usize::from(!L::is_direct(unit)) + 1)
}

/// What the two banks of a codec's rows may round up to whole pages beyond
/// their symbols; see [`reedsolomon_rs::fft::RowBank::allocation_bytes`].
const BANK_SLACK: usize = 2 * reedsolomon_rs::fft::RowBank::<u8>::ALIGN;

/// What each row of a codec's banks costs beside its symbols: its handle,
/// with room to spare, and the cache line of padding a bank may put after
/// it; see [`reedsolomon_rs::fft::RowBank::ROW_PAD`].
const ROW_BYTES: usize = 32 + reedsolomon_rs::fft::RowBank::<u8>::ROW_PAD;

/// A zeroed page-aligned bank of `rows` rows of `width` symbols; see
/// [`reedsolomon_rs::fft::RowBank`].
fn bank<L: Lane>(rows: usize, width: usize) -> EngineResult<reedsolomon_rs::fft::RowBank<L>> {
    reedsolomon_rs::fft::RowBank::zeroed(rows, width)
        .ok_or(EngineError::resource_limit("FFT transform rows"))
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
        let mut field = TransformField::new(geometry.bits).map_err(transform_error)?;
        // Four-step transforms where they measured faster; see
        // `reedsolomon_rs::fft::four_step_admits`. Output is identical.
        field.set_four_step(reedsolomon_rs::fft::four_step_preferred(
            options.fft_backend,
        ));
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
            // buffers. These are the same layouts admitted by decode/buffers:
            // the decode's two banks of capacity rows each.
            let rows = 2 * g.capacity;
            let per_byte = if g.bits == 8 {
                workspace_per_byte::<u8>(rows, unit)
            } else {
                workspace_per_byte::<u16>(rows, unit)
            }
            .ok_or(EngineError::resource_limit("FFT stripes"))?;
            g.domain * 32 + rows * 32 + per_byte * unit
        };
        let _decode = self
            .options
            .memory
            .reserve_as(MemoryCategory::CodecScratch, decode_floor)?;
        let wanted = self
            .options
            .stripe_bytes
            .min(usize::try_from(block_size).unwrap_or(usize::MAX));
        let room = self.options.memory.available() / 4;
        let target = if room < wanted {
            crate::runtime::budget_stripe(room, unit)
        } else {
            wanted
        };
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

    /// One additive transform. `zero` flags the rows the layout leaves all
    /// zero, so the backend can skip the butterflies that cannot change them;
    /// the diagnostics still count the transform's full butterfly total.
    fn transform<L: Lane>(
        &self,
        rows: &mut [&mut [L]],
        zero: Option<&[bool]>,
        origin: usize,
        inverse: bool,
    ) -> EngineResult<()> {
        self.transform_counted(rows, zero, origin, inverse, None, 0)
    }

    /// One additive transform, counted. `skipped` feeds
    /// `CodecSnapshot::butterflies_skipped`; nothing prunes a transform, so
    /// every caller passes zero.
    /// With `sum`, every row of the result is added into the same row of it
    /// as the transform leaves it; see
    /// [`TransformField::transform_rows_adding`].
    fn transform_counted<L: Lane>(
        &self,
        rows: &mut [&mut [L]],
        zero: Option<&[bool]>,
        origin: usize,
        inverse: bool,
        sum: Option<&mut [&mut [L]]>,
        skipped: u64,
    ) -> EngineResult<()> {
        let field = self.field.as_ref().expect("nontrivial FFT field");
        let cancelled = || self.options.cancel.check().is_err();
        // Measured before the call, which consumes the borrow, but reported
        // only once the backend has actually done the work. A cancelled or
        // failed transform performed no butterflies, and counting it as though
        // it had would inflate the codec totals exactly where a host looks to
        // find out why an operation cost what it did.
        let performed = butterflies(rows.len());
        let symbols = rows.first().map_or(0, |row| row.len());
        L::transform(
            field,
            rows,
            zero,
            origin,
            inverse,
            self.options.fft_backend,
            self.workers.as_ref().map(crate::runtime::WorkerPool::pool),
            sum,
            &cancelled,
        )
        .map_err(transform_error)?;
        self.options
            .diagnostics
            .note_transform(1, performed, symbols, skipped);
        Ok(())
    }

    /// Encode a compatible recovery range. Input and output callbacks receive
    /// positioned byte stripes; neither whole input nor recovery blocks are kept.
    /// The input callback must fill every byte of the stripe it is handed,
    /// zeros past the end of a short input included: the stripe is not
    /// cleared beforehand.
    pub fn encode(
        &self,
        block_size: u64,
        first: usize,
        count: usize,
        read: impl FnMut(usize, u64, &mut [u8]) -> EngineResult<()>,
        mut write: impl FnMut(usize, u64, &[u8]) -> EngineResult<()>,
    ) -> EngineResult<()> {
        let mut progress = self.options.stage(crate::runtime::Stage::Encode)?;
        let write = |index, offset, bytes: &[u8]| {
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
        if g.bits == 8 {
            self.encode_rows::<u8>(block_size, first, count, read, write)
        } else {
            self.encode_rows::<u16>(block_size, first, count, read, write)
        }
    }

    fn encode_rows<L: Lane>(
        &self,
        block_size: u64,
        first: usize,
        count: usize,
        mut read: impl FnMut(usize, u64, &mut [u8]) -> EngineResult<()>,
        mut write: impl FnMut(usize, u64, &[u8]) -> EngineResult<()>,
    ) -> EngineResult<()> {
        let g = self.geometry;
        let rows = g
            .capacity
            .checked_mul(2)
            .ok_or(EngineError::resource_limit("FFT encoder rows"))?;
        let (stripe, _buffers) = self.buffers::<L>(block_size, rows)?;
        let symbols = stripe / g.field_bytes();
        let mut work = bank::<L>(g.capacity, symbols)?;
        let mut sum = bank::<L>(g.capacity, symbols)?;
        let (mut work, mut sum) = (work.rows_mut(), sum.rows_mut());
        let mut bytes = vec![
            0;
            if L::is_direct(g.field_bytes()) {
                0
            } else {
                stripe
            }
        ];
        // The last chunk's rows past the final input are zero.
        let tail = g.inputs % g.capacity;
        let tail: Vec<bool> = (0..g.capacity).map(|at| tail != 0 && at >= tail).collect();
        let unit = g.field_bytes();
        let mut offset = 0;
        while offset < block_size {
            self.options.cancel.check()?;
            let take = (block_size - offset).min(stripe as u64) as usize;
            // Symbols holding stripe bytes; the read fills those bytes, so
            // only the symbols past them are cleared.
            let used = take.div_ceil(unit);
            for base in (0..g.inputs).step_by(g.capacity) {
                // The first chunk is transformed in the sum rows themselves,
                // which therefore need no clearing and no addition.
                let rows = if base == 0 { &mut sum } else { &mut work };
                for (at, row) in rows.iter_mut().enumerate() {
                    let row: &mut [L] = row;
                    self.options.cancel.check()?;
                    if base + at >= g.inputs {
                        row.fill(L::default());
                        continue;
                    }
                    if let Some(row) = L::direct(unit, row) {
                        read(base + at, offset, &mut row[..take])?;
                    } else {
                        read(base + at, offset, &mut bytes[..take])?;
                        bytes[take..used * unit].fill(0);
                        L::unpack(unit, &bytes[..used * unit], &mut row[..used]);
                    }
                    row[used..].fill(L::default());
                }
                let zero = (base + g.capacity > g.inputs).then_some(tail.as_slice());
                if base == 0 {
                    self.transform(&mut sum, zero, g.capacity, true)?;
                } else {
                    // Each tile of the chunk is added into the sum as the
                    // transform finishes it, while it is still in the cache.
                    self.transform_counted(
                        &mut work,
                        zero,
                        g.capacity + base,
                        true,
                        Some(&mut sum),
                        0,
                    )?;
                }
            }
            self.transform(&mut sum, None, 0, false)?;
            for (index, row) in sum.iter().enumerate().skip(first).take(count) {
                let out = match L::direct_ref(unit, row) {
                    Some(row) => row,
                    None => {
                        L::pack(g.field_bytes(), row, &mut bytes);
                        &bytes
                    }
                };
                write(index, offset, &out[..take])?;
            }
            offset += take as u64;
        }
        Ok(())
    }

    /// Recover missing original rows using precisely the admitted recovery
    /// indices. Unused transform positions are authenticated geometry padding.
    /// As for [`Self::encode`], the input callback must fill every byte of
    /// the stripe it is handed.
    pub fn decode(
        &self,
        block_size: u64,
        lost: &[usize],
        recovery: &[usize],
        read: impl FnMut(FftInput, u64, &mut [u8]) -> EngineResult<()>,
        write: impl FnMut(usize, u64, &[u8]) -> EngineResult<()>,
    ) -> EngineResult<()> {
        self.decode_with(block_size, lost, recovery, read, None, write)
    }

    /// [`Self::decode`], handing every input stripe's bytes, as `read`
    /// filled them, to `consume` as well: each stripe of each surviving
    /// input and supplied recovery row exactly once, the stripes of a row
    /// in offset order. With workers the stripes of a batch of rows are
    /// consumed in parallel, in no particular order among themselves, while
    /// `read`, still on the calling thread and in row order, fills the next
    /// batch. Without workers, or when no room is left for the batch, each
    /// stripe is consumed right after it is read. A failing `consume` or
    /// `read` ends the decode with its error; when both fail in one batch
    /// the consumer's is returned.
    pub fn decode_with(
        &self,
        block_size: u64,
        lost: &[usize],
        recovery: &[usize],
        read: impl FnMut(FftInput, u64, &mut [u8]) -> EngineResult<()>,
        consume: Option<&FftConsumer<'_>>,
        write: impl FnMut(usize, u64, &[u8]) -> EngineResult<()>,
    ) -> EngineResult<()> {
        self.decode_held(block_size, lost, recovery, read, consume, write, None)
    }

    /// [`Self::decode_with`], reserving `hold` at the admitted stripe; see
    /// [`StripeHold`].
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn decode_held(
        &self,
        block_size: u64,
        lost: &[usize],
        recovery: &[usize],
        mut read: impl FnMut(FftInput, u64, &mut [u8]) -> EngineResult<()>,
        consume: Option<&FftConsumer<'_>>,
        mut write: impl FnMut(usize, u64, &[u8]) -> EngineResult<()>,
        hold: Option<&dyn StripeHold>,
    ) -> EngineResult<()> {
        let mut progress = self.options.stage(crate::runtime::Stage::Decode)?;
        let write = |index, offset, bytes: &[u8]| {
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
            let none = |_: FftInput, _: u64, _: &[u8]| Ok(());
            let consume: &FftConsumer<'_> = consume.unwrap_or(&none);
            return self.decode_trivial(
                block_size,
                lost,
                recovery,
                |row, offset, out| {
                    read(row, offset, out)?;
                    consume(row, offset, out)
                },
                write,
            );
        }
        if g.bits == 8 {
            self.decode_rows::<u8>(block_size, lost, recovery, read, consume, write, hold)
        } else {
            self.decode_rows::<u16>(block_size, lost, recovery, read, consume, write, hold)
        }
    }

    /// Algorithm 5 of Chen, Lin, Tang, Han, Cai, Yu, Li, Bai and Bai, "Two
    /// Fast Erasure Decoding Algorithms for Reed-Solomon Codes Based on
    /// LCH-FFT", IEEE Trans. Inf. Theory 72(6), 2026,
    /// doi:10.1109/TIT.2026.3685291 (see ATTRIBUTION.md at the repository
    /// root), original outputs only.
    /// The code dimension includes known-zero padding: N - capacity, not inputs.
    /// In the reference Cantor basis the subspace polynomials are monic and
    /// s_j(v_j) = 1, so the paper's normalization product is one.
    #[allow(clippy::too_many_arguments)]
    fn decode_rows<L: Lane>(
        &self,
        block_size: u64,
        lost: &[usize],
        recovery: &[usize],
        mut read: impl FnMut(FftInput, u64, &mut [u8]) -> EngineResult<()>,
        consume: Option<&FftConsumer<'_>>,
        mut write: impl FnMut(usize, u64, &[u8]) -> EngineResult<()>,
        hold: Option<&dyn StripeHold>,
    ) -> EngineResult<()> {
        let g = self.geometry;
        let c = g.capacity;
        let field = self.field.as_ref().expect("nontrivial FFT field");
        // Locator construction peaks below 32N bytes. The same reservation
        // also covers the live masks, output indices and inverse factors.
        let _plan = self
            .options
            .memory
            .reserve_as(MemoryCategory::CodecScratch, g.domain * 32)?;
        let mut erased = vec![false; g.domain];
        erased[..c].fill(true);
        for &index in recovery {
            if index >= c || !erased[index] {
                return Err(EngineError::InvalidState(
                    "invalid or duplicate FFT recovery index",
                ));
            }
            erased[index] = false;
        }
        for &index in lost {
            if index >= g.inputs || erased[c + index] {
                return Err(EngineError::InvalidState("invalid or duplicate FFT loss"));
            }
            erased[c + index] = true;
        }
        let cancelled = || self.options.cancel.check().is_err();
        let factors = field
            .erasure_factors(&erased, &cancelled)
            .map_err(transform_error)?;
        let mut targets: Vec<_> = lost.iter().map(|&index| c + index).collect();
        targets.sort_unstable();
        let inverse: Vec<_> = targets
            .iter()
            .map(|&index| {
                let mut subspace = index as u16;
                for _ in 0..c.trailing_zeros() {
                    subspace = field.mul(subspace, subspace) ^ subspace;
                }
                field
                    .inverse(field.mul(subspace, factors[index]))
                    .ok_or(EngineError::InvalidState("singular capacity FFT locator"))
            })
            .collect::<EngineResult<_>>()?;
        let mut admitted = self.buffers::<L>(block_size, c * 2)?;
        if let Some(hold) = hold
            && !hold.reserve(admitted.0)
            && let Some(spare) = hold.bytes(g.field_bytes())
        {
            drop(admitted);
            admitted = match self.buffers_leaving::<L>(block_size, c * 2, spare) {
                Ok(narrower) => narrower,
                Err(EngineError::ResourceLimit(_)) => self.buffers::<L>(block_size, c * 2)?,
                Err(error) => return Err(error),
            };
            hold.reserve(admitted.0);
        }
        let (stripe, _buffers) = admitted;
        let unit = g.field_bytes();
        let symbols = stripe / unit;
        let mut work = bank::<L>(c, symbols)?;
        let mut sum = bank::<L>(c, symbols)?;
        let (mut work, mut sum) = (work.rows_mut(), sum.rows_mut());
        let mut bytes = vec![0; if L::is_direct(unit) { 0 } else { stripe }];
        let zero: Vec<_> = (0..g.domain)
            .map(|i| erased[i] || i >= c + g.inputs)
            .collect();
        // Optional third bank, admitted only after the original stripe and
        // proof frontiers. Refusal preserves the two-bank path and its reads.
        let ahead_charge = if self.workers.is_some() && L::is_direct(unit) && g.domain > c * 2 {
            let bytes = reedsolomon_rs::fft::RowBank::<L>::allocation_bytes(c, symbols)
                .and_then(|bytes| bytes.checked_add(c * size_of::<&mut [L]>()));
            match bytes {
                Some(bytes) => match self
                    .options
                    .memory
                    .reserve_as(MemoryCategory::CodecScratch, bytes)
                {
                    Ok(reservation) => Some(reservation),
                    Err(EngineError::ResourceLimit(_)) => None,
                    Err(error) => return Err(error),
                },
                None => None,
            }
        } else {
            None
        };
        let mut ahead = if ahead_charge.is_some() {
            Some(bank::<L>(c, symbols)?)
        } else {
            None
        };
        let mut ahead_rows = ahead.as_mut().map(|bank| bank.rows_mut());
        let mut offset = 0;
        while offset < block_size {
            self.options.cancel.check()?;
            let take = (block_size - offset).min(stripe as u64) as usize;
            let used = take.div_ceil(unit);
            if let Some(ahead) = &mut ahead_rows {
                use rayon::prelude::*;
                let pool = self.workers.as_ref().expect("pipeline workers").pool();
                let input = |index: usize| {
                    if index < c {
                        FftInput::Recovery(index)
                    } else {
                        FftInput::Original(index - c)
                    }
                };
                let mut fill = |rows: &mut [&mut [L]], base: usize| -> EngineResult<()> {
                    for (slot, row) in rows.iter_mut().enumerate() {
                        self.options.cancel.check()?;
                        if zero[base + slot] {
                            row.fill(L::default());
                        } else {
                            let out = L::direct(unit, row).expect("direct pipeline lane");
                            read(input(base + slot), offset, &mut out[..take])?;
                            out[take..].fill(0);
                        }
                    }
                    Ok(())
                };
                let consumed = |rows: &mut [&mut [L]], base: usize| -> EngineResult<()> {
                    if let Some(consume) = consume {
                        rows.par_iter_mut().enumerate().try_for_each(
                            |(slot, row)| -> EngineResult<()> {
                                self.options.cancel.check()?;
                                if !zero[base + slot] {
                                    consume(
                                        input(base + slot),
                                        offset,
                                        &L::direct_ref(unit, row).expect("direct lane")[..take],
                                    )?;
                                }
                                Ok(())
                            },
                        )?;
                    }
                    Ok(())
                };
                fill(&mut sum, 0)?;
                pool.install(|| consumed(&mut sum, 0))?;
                self.transform(&mut sum, Some(&zero[..c]), 0, true)?;
                fill(&mut work, c)?;
                let mut base = c;
                while base < g.domain {
                    let mut computed = Ok(());
                    let mut loaded = Ok(());
                    let next = base + c;
                    let pending = &mut work;
                    let sum = &mut sum;
                    let flags = &zero[base..base + c];
                    let consume_rows = &consumed;
                    pool.in_place_scope(|scope| {
                        let computed = &mut computed;
                        scope.spawn(move |_| {
                            *computed = consume_rows(pending, base).and_then(|()| {
                                self.transform_counted(
                                    pending,
                                    Some(flags),
                                    base,
                                    true,
                                    Some(sum),
                                    0,
                                )
                            });
                        });
                        if next < g.domain {
                            loaded = fill(ahead, next);
                        }
                    });
                    computed?;
                    loaded?;
                    std::mem::swap(&mut work, ahead);
                    base = next;
                }
            } else {
                for base in (0..g.domain).step_by(c) {
                    let rows = if base == 0 { &mut sum } else { &mut work };
                    for (slot, row) in rows.iter_mut().enumerate() {
                        self.options.cancel.check()?;
                        let index = base + slot;
                        if zero[index] {
                            row.fill(L::default());
                            continue;
                        }
                        let input = if index < c {
                            FftInput::Recovery(index)
                        } else {
                            FftInput::Original(index - c)
                        };
                        if let Some(out) = L::direct(unit, row) {
                            read(input, offset, &mut out[..take])?;
                            if let Some(consume) = consume {
                                consume(input, offset, &out[..take])?;
                            }
                        } else {
                            read(input, offset, &mut bytes[..take])?;
                            if let Some(consume) = consume {
                                consume(input, offset, &bytes[..take])?;
                            }
                            bytes[take..used * unit].fill(0);
                            L::unpack(unit, &bytes[..used * unit], &mut row[..used]);
                        }
                        row[used..].fill(L::default());
                    }
                    if base == 0 {
                        self.transform(&mut sum, Some(&zero[base..base + c]), base, true)?;
                    } else {
                        self.transform_counted(
                            &mut work,
                            Some(&zero[base..base + c]),
                            base,
                            true,
                            Some(&mut sum),
                            0,
                        )?;
                    }
                }
            }
            self.transform(&mut sum, None, 0, false)?;
            for (i, row) in sum.iter_mut().enumerate() {
                // At an erased parity coordinate the locator is zero, while
                // erasure_factors returns its derivative; do not confuse them.
                if erased[i] {
                    row.fill(L::default());
                } else {
                    L::scale(field, row, factors[i], self.options.fft_backend, &cancelled)
                        .map_err(transform_error)?;
                }
            }
            self.transform(&mut sum, None, 0, true)?;
            let mut first = 0;
            while first < targets.len() {
                let base = targets[first] / c * c;
                let end = first + targets[first..].partition_point(|&index| index < base + c);
                for (dst, src) in work.iter_mut().zip(&sum) {
                    dst.copy_from_slice(src);
                }
                self.transform(&mut work, None, base, false)?;
                for slot in first..end {
                    let index = targets[slot];
                    let row = &mut *work[index - base];
                    L::scale(
                        field,
                        row,
                        inverse[slot],
                        self.options.fft_backend,
                        &cancelled,
                    )
                    .map_err(transform_error)?;
                    let out = match L::direct_ref(unit, row) {
                        Some(row) => row,
                        None => {
                            L::pack(unit, row, &mut bytes);
                            &bytes
                        }
                    };
                    write(index - c, offset, &out[..take])?;
                }
                first = end;
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

    /// What `encode` reserves for its stripes when memory does not narrow
    /// them, by the same layout it charges: `byte_buffers` for a trivial
    /// geometry, otherwise `buffers` on the lane `encode` runs (byte rows for
    /// GF(2^8), word rows for GF(2^16)). A caller holding output beside the
    /// encode leaves this much so the stripe stays at its configured width.
    pub(crate) fn encode_stripe_bytes(&self, block_size: u64) -> usize {
        let target = self
            .options
            .stripe_bytes
            .min(usize::try_from(block_size).unwrap_or(usize::MAX));
        if self.geometry.is_trivial() {
            return target.saturating_mul(2).saturating_add(64);
        }
        let unit = self.geometry.field_bytes();
        let rows = self.geometry.capacity.saturating_mul(2);
        let per_byte = if self.geometry.bits == 8 {
            workspace_per_byte::<u8>(rows, unit)
        } else {
            workspace_per_byte::<u16>(rows, unit)
        }
        .unwrap_or(usize::MAX);
        let lane = if self.geometry.bits == 8 { 1 } else { 2 };
        (target / unit * unit)
            .saturating_mul(per_byte)
            .saturating_add(rows.saturating_mul(ROW_BYTES))
            .saturating_add(BANK_SLACK)
            .saturating_add(self.walk_units_bytes(rows, target, lane))
    }

    /// What a walked transform of `rows` rows of `lane`-byte symbols over a
    /// `stripe`-byte stripe, or any narrower one the budget admits, keeps
    /// beside the scratch: the units of its sweeps, most for the inverse
    /// over every row. A narrower stripe never needs more of them under the
    /// same sweeps, but rows under 64 symbols take radix-2 sweeps, which
    /// keep different units and may walk where the wider rows would not, so
    /// the wider of the two is charged. Nothing when neither tiles.
    fn walk_units_bytes(&self, rows: usize, stripe: usize, lane: usize) -> usize {
        let Some(field) = &self.field else {
            return 0;
        };
        let unit = self.geometry.field_bytes();
        let units = |stripe: usize| {
            field.walk_units_bytes(
                rows,
                stripe / unit,
                lane,
                true,
                self.options.fft_backend,
                self.worker_count(),
            )
        };
        units(stripe).max(units(stripe.min(63 * unit)))
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

    /// Admit `rows` transform rows of lane `L`, plus its conversion buffer.
    /// Byte rows charge one byte per stripe byte, so a GF(2^8) cohort gets
    /// twice the stripe the same budget admitted for zero-extended rows.
    fn buffers<L: Lane>(&self, block_size: u64, rows: usize) -> EngineResult<(usize, Reservation)> {
        self.buffers_leaving::<L>(block_size, rows, 0)
    }

    /// [`Self::buffers`], narrowing the stripe until `spare` bytes of the
    /// budget stay free beside them.
    fn buffers_leaving<L: Lane>(
        &self,
        block_size: u64,
        rows: usize,
        spare: usize,
    ) -> EngineResult<(usize, Reservation)> {
        self.options.validate()?;
        let unit = self.geometry.field_bytes();
        if block_size == 0 || !block_size.is_multiple_of(unit as u64) {
            return Err(EngineError::InvalidState("FFT block alignment"));
        }
        let target = self
            .options
            .stripe_bytes
            .min(usize::try_from(block_size).unwrap_or(usize::MAX));
        let (per_byte, overhead) = self.bank_charge::<L>(rows, target, spare)?;
        let mut buffers = self.options.memory.reserve_stripes_with_overhead(
            MemoryCategory::CodecScratch,
            target,
            per_byte,
            unit,
            overhead,
        )?;
        buffers.1.shrink_to(buffers.1.bytes() - spare);
        self.options
            .diagnostics
            .note_stripe(buffers.0, per_byte, target);
        tracing::debug!(stripe_bytes = buffers.0, rows, "PAR3 FFT stripes admitted");
        Ok(buffers)
    }

    /// What [`Self::buffers`] charges for `rows` rows of lane `L` at the
    /// configured `target`, `spare` included: (bytes per stripe byte, fixed
    /// overhead). The row handles, the pages the banks round up to, and the
    /// units a tiled transform keeps are what the rows cost whatever the
    /// stripe.
    fn bank_charge<L: Lane>(
        &self,
        rows: usize,
        target: usize,
        spare: usize,
    ) -> EngineResult<(usize, usize)> {
        let unit = self.geometry.field_bytes();
        let per_byte = workspace_per_byte::<L>(rows, unit)
            .ok_or(EngineError::resource_limit("FFT stripes"))?;
        let kept = rows
            .checked_mul(ROW_BYTES)
            .and_then(|handles| handles.checked_add(BANK_SLACK))
            .and_then(|handles| {
                handles.checked_add(self.walk_units_bytes(rows, target, size_of::<L>()))
            })
            .and_then(|kept| kept.checked_add(spare))
            .ok_or(EngineError::resource_limit("FFT rows"))?;
        Ok((per_byte, kept))
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
            // The reference's label for a set holding one recovery block,
            // whatever capacity the matrix reserves.
            assert!(
                geometry
                    .validate_field(GaloisField {
                        size: 0,
                        generator: 0
                    })
                    .is_ok()
            );
            assert!(
                geometry
                    .validate_field(GaloisField { size: 0, generator })
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

    /// One cohort's row workspace is `domain` transform rows plus, for 16-bit
    /// rows, one byte stripe. The charge is taken before any of it is
    /// allocated, so it must cover every row's capacity and its vector header.
    #[test]
    fn row_workspace_charge_matches_the_rows_a_cohort_allocates() {
        fn check<L: Lane>(inputs: u64) {
            let geometry = FftGeometry::new(inputs, 1).unwrap();
            let options = options(256 << 20);
            let codec = FftCodec::new(geometry, options.clone()).unwrap();
            let unit = geometry.field_bytes();
            let block_size = 1 << 16;
            let before = options.memory.used();
            let (stripe, buffers) = codec.buffers::<L>(block_size, geometry.domain).unwrap();
            assert_eq!(options.memory.used() - before, buffers.bytes());

            // Exactly what `decode` allocates once the charge is granted.
            let symbols = stripe / unit;
            let rows = vec![vec![L::default(); symbols]; geometry.domain];
            let bytes = vec![0u8; if L::is_direct(unit) { 0 } else { stripe }];
            let measured = rows.capacity() * size_of::<Vec<L>>()
                + rows
                    .iter()
                    .map(|row| row.capacity() * size_of::<L>())
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
        // The byte lane GF(2^8) runs on, the zero-extended reference it
        // replaced, and GF(2^16).
        check::<u8>(200);
        check::<u16>(200);
        check::<u16>(5_000);
    }

    /// A budget too small for full-width stripes narrows them to whole
    /// granules of the target's page, in the decode workspace and in the
    /// repair adapter's source buffers alike, so every stripe offset in a
    /// page-aligned block stays on a page boundary.
    #[test]
    fn budget_narrowed_fft_stripes_are_whole_granules() {
        let granule = crate::runtime::STRIPE_GRANULES[0];
        // 400 inputs and capacity 64 pad to a 512-row GF(2^16) domain.
        let geometry = FftGeometry::new(400, 6).unwrap();
        assert_eq!((geometry.domain, geometry.field_bytes()), (512, 2));
        let codec = FftCodec::new(geometry, options(24 << 20)).unwrap();
        let (stripe, buffers) = codec.buffers::<u16>(1 << 20, geometry.domain).unwrap();
        assert!(stripe < 64 << 10, "the budget did not narrow: {stripe}");
        assert!(stripe.is_multiple_of(granule), "unaligned stripe {stripe}");
        drop(buffers);
        drop(codec);

        let mut codec = FftCodec::new(geometry, options(768 << 10)).unwrap();
        let (stripe, _buffers) = codec.reserve_source_stripes(1 << 20, 4).unwrap();
        assert!(stripe < 64 << 10, "the budget did not narrow: {stripe}");
        assert!(stripe.is_multiple_of(granule), "unaligned stripe {stripe}");
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
mod lane_tests {
    use super::*;
    use crate::runtime::MemoryBudget;

    fn bytes(count: usize, seed: u64) -> Vec<u8> {
        let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
        (0..count)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 32) as u8
            })
            .collect()
    }

    fn codec(geometry: FftGeometry, stripe: usize, workers: usize, scalar: bool) -> FftCodec {
        let options = ExecutionOptions {
            memory: MemoryBudget::new(256 << 20),
            workers,
            stripe_bytes: stripe,
            fft_backend: if scalar {
                LinearBackend::Scalar
            } else {
                LinearBackend::Auto
            },
            ..ExecutionOptions::default()
        };
        FftCodec::new(geometry, options).unwrap()
    }

    /// Recovery rows `0..capacity` through the public entry point (the byte
    /// lane for GF(2^8)) and through the zero-extended `u16` reference.
    fn encode_both(
        codec: &FftCodec,
        block: usize,
        data: &[Vec<u8>],
    ) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let capacity = codec.geometry.capacity();
        let read = |index: usize, offset: u64, out: &mut [u8]| {
            let offset = offset as usize;
            out.copy_from_slice(&data[index][offset..offset + out.len()]);
            Ok(())
        };
        let mut lane = vec![vec![0u8; block]; capacity];
        let mut reference = lane.clone();
        codec
            .encode(block as u64, 0, capacity, read, |index, offset, bytes| {
                let offset = offset as usize;
                lane[index][offset..offset + bytes.len()].copy_from_slice(bytes);
                Ok(())
            })
            .unwrap();
        codec
            .encode_rows::<u16>(block as u64, 0, capacity, read, |index, offset, bytes| {
                let offset = offset as usize;
                reference[index][offset..offset + bytes.len()].copy_from_slice(bytes);
                Ok(())
            })
            .unwrap();
        (lane, reference)
    }

    fn decode_with(
        codec: &FftCodec,
        reference: bool,
        block: usize,
        data: &[Vec<u8>],
        recovery_rows: &[Vec<u8>],
        lost: &[usize],
        recovery: &[usize],
    ) -> Vec<Vec<u8>> {
        let read = |source: FftInput, offset: u64, out: &mut [u8]| {
            let offset = offset as usize;
            let row = match source {
                FftInput::Original(index) => {
                    assert!(!lost.contains(&index), "read a lost row");
                    &data[index]
                }
                FftInput::Recovery(index) => &recovery_rows[index],
            };
            out.copy_from_slice(&row[offset..offset + out.len()]);
            Ok(())
        };
        let mut out = vec![vec![0u8; block]; data.len()];
        let write = |index: usize, offset: u64, bytes: &[u8]| {
            let offset = offset as usize;
            out[index][offset..offset + bytes.len()].copy_from_slice(bytes);
            Ok(())
        };
        if reference {
            // The word lane over bytes is not the stripe's own image, so with
            // workers its consumer takes the batched ring path; every stripe
            // read must reach it once, as read, and nothing else.
            let consumed = std::sync::Mutex::new(vec![0u64; data.len() + recovery_rows.len()]);
            let consume = |source: FftInput, offset: u64, bytes: &[u8]| {
                let (slot, row) = match source {
                    FftInput::Original(index) => (index, &data[index]),
                    FftInput::Recovery(index) => (data.len() + index, &recovery_rows[index]),
                };
                let offset = offset as usize;
                assert_eq!(
                    bytes,
                    &row[offset..offset + bytes.len()],
                    "consumed {source:?}"
                );
                consumed.lock().unwrap()[slot] += bytes.len() as u64;
                Ok(())
            };
            codec
                .decode_rows::<u16>(
                    block as u64,
                    lost,
                    recovery,
                    read,
                    Some(&consume),
                    write,
                    None,
                )
                .unwrap();
            let consumed = consumed.into_inner().unwrap();
            for (index, count) in consumed[..data.len()].iter().enumerate() {
                let expected = if lost.contains(&index) {
                    0
                } else {
                    block as u64
                };
                assert_eq!(*count, expected, "original {index} consumed {count} bytes");
            }
            for (index, count) in consumed[data.len()..].iter().enumerate() {
                let expected = if recovery.contains(&index) {
                    block as u64
                } else {
                    0
                };
                assert_eq!(*count, expected, "recovery {index} consumed {count} bytes");
            }
        } else {
            codec
                .decode(block as u64, lost, recovery, read, write)
                .unwrap();
        }
        out
    }

    /// A codec takes four-step exactly where the CPU gate admits it: never
    /// with the scalar kernels, and with the detected ones only on an AMD
    /// CPU running the AVX2 kernels.
    #[test]
    fn a_codec_takes_four_step_only_where_the_cpu_gate_admits_it() {
        let geometry = FftGeometry::new(600, 7).unwrap();
        let scalar = codec(geometry, 4096, 1, true);
        assert!(!scalar.field.as_ref().unwrap().four_step());
        let detected = codec(geometry, 4096, 1, false);
        assert_eq!(
            detected.field.as_ref().unwrap().four_step(),
            reedsolomon_rs::fft::four_step_admits(
                reedsolomon_rs::gf_simd::cpu_is_amd(),
                LinearBackend::Auto.kernel()
            )
        );
    }

    /// The four-step gate changes speed only: encode and decode emit the
    /// same bytes with it on and off, in both fields, on one worker (rows of
    /// 16 KiB, where one thread takes four-step) and on a pool (128-row
    /// transforms, where a pool takes it). The gate is forced either way, so
    /// this runs on every CPU, not only where it is admitted.
    #[test]
    fn the_four_step_gate_does_not_change_a_byte() {
        for (inputs, capacity_log2) in [(100u64, 7i8), (600, 7)] {
            let geometry = FftGeometry::new(inputs, capacity_log2).unwrap();
            let capacity = geometry.capacity();
            let block = 32 << 10;
            let data: Vec<_> = (0..inputs as usize)
                .map(|index| bytes(block, index as u64 + 1))
                .collect();
            let lost: Vec<usize> = (0..capacity).map(|i| i * 3 % inputs as usize).collect();
            let mut lost = lost;
            lost.sort_unstable();
            lost.dedup();
            let recovery: Vec<usize> = (0..lost.len()).collect();
            for workers in [1, 4] {
                let mut outputs = Vec::new();
                for on in [false, true] {
                    let mut codec = codec(geometry, block, workers, false);
                    codec.field.as_mut().unwrap().set_four_step(on);
                    let field = codec.field.as_ref().unwrap();
                    // Either lane's rows are the stripe's own width in bytes.
                    assert_eq!(
                        field.four_step_runs(capacity, block, workers > 1),
                        on,
                        "{inputs} w{workers}: the fixture must exercise the gate"
                    );
                    let (encoded, _) = encode_both(&codec, block, &data);
                    let decoded =
                        decode_with(&codec, false, block, &data, &encoded, &lost, &recovery);
                    for &index in &lost {
                        assert_eq!(decoded[index], data[index], "{inputs} w{workers} {on}");
                    }
                    outputs.push((encoded, decoded));
                }
                assert!(
                    outputs[0] == outputs[1],
                    "{inputs} w{workers}: four-step changed the output"
                );
            }
        }
    }

    /// The byte lane must emit exactly what the zero-extended 16-bit lane
    /// emitted for GF(2^8): every recovery row on encode and every
    /// reconstructed row on decode, across cohort shapes (one and several
    /// input bases, full and padded domains), block lengths that are odd,
    /// below one vector and split across several stripes, both backends, and
    /// serial and pooled execution.
    #[test]
    fn the_byte_lane_matches_the_word_lane_bit_for_bit() {
        let shapes = [
            (2u64, 1i8),
            (5, 2),
            (13, 3),
            (40, 3),
            (100, 5),
            (150, 6),
            (192, 6),
            (64, 7),
        ];
        let mut cases = 0;
        for (shape, &(inputs, capacity_log2)) in shapes.iter().enumerate() {
            let geometry = FftGeometry::new(inputs, capacity_log2).unwrap();
            assert_eq!(geometry.field_bytes(), 1);
            assert!(!geometry.is_trivial());
            let capacity = geometry.capacity();
            let inputs = geometry.inputs();
            for (block, stripe) in [
                (1usize, 1 << 16),
                (3, 2),
                (15, 1 << 16),
                (17, 16),
                (65, 64),
                (1000, 333),
                (4097, 1 << 16),
            ] {
                let data: Vec<Vec<u8>> = (0..inputs)
                    .map(|index| bytes(block, (shape * 1_000_003 + block * 131 + index) as u64))
                    .collect();
                // Loss patterns: one row, a leading run, scattered rows, and
                // as many rows as the recovery can carry.
                let all = capacity.min(inputs);
                let patterns: Vec<Vec<usize>> = vec![
                    vec![inputs / 2],
                    (0..all.div_ceil(2)).collect(),
                    (0..inputs).step_by(3).take(all).collect(),
                    (inputs - all..inputs).rev().collect(),
                ];
                for workers in [1usize, 4] {
                    for scalar in [false, true] {
                        let codec = codec(geometry, stripe, workers, scalar);
                        let (lane, reference) = encode_both(&codec, block, &data);
                        assert_eq!(
                            lane, reference,
                            "encode {inputs}+{capacity} block {block} stripe {stripe} \
                             workers {workers} scalar {scalar}"
                        );
                        for lost in &patterns {
                            // Recovery rows, highest first, so decodes do not
                            // always draw the same prefix.
                            let recovery: Vec<usize> =
                                (0..capacity).rev().take(lost.len() + 1).collect();
                            let recovery = &recovery[..lost.len().max(1).min(capacity)];
                            let actual =
                                decode_with(&codec, false, block, &data, &lane, lost, recovery);
                            let expected =
                                decode_with(&codec, true, block, &data, &lane, lost, recovery);
                            assert_eq!(
                                actual, expected,
                                "decode {inputs}+{capacity} block {block} lost {lost:?} \
                                 workers {workers} scalar {scalar}"
                            );
                            for &index in lost {
                                assert_eq!(actual[index], data[index], "row {index} not repaired");
                            }
                            cases += 1;
                        }
                    }
                }
            }
        }
        assert_eq!(cases, shapes.len() * 7 * 4 * 2 * 2);
    }

    /// Byte rows are charged at one byte per stripe byte, so a budget that
    /// narrows the zero-extended rows admits the byte lane a wider stripe:
    /// twice the word lane's before each is rounded down to a whole page
    /// granule, which takes less than one granule from either. The budget
    /// leaves both stripes many granules wide, so that rounding stays small
    /// next to the factor of two on 4 KiB and 16 KiB granule targets alike.
    #[test]
    fn a_gf8_cohort_gets_twice_the_stripe_under_the_same_budget() {
        let granule = crate::runtime::STRIPE_GRANULES[0];
        let geometry = FftGeometry::new(150, 6).unwrap();
        let options = ExecutionOptions {
            memory: MemoryBudget::new(96 << 20),
            workers: 1,
            stripe_bytes: 1 << 20,
            ..ExecutionOptions::default()
        };
        let codec = FftCodec::new(geometry, options).unwrap();
        let (bytes, held) = codec.buffers::<u8>(1 << 20, geometry.domain()).unwrap();
        drop(held);
        let (words, _held) = codec.buffers::<u16>(1 << 20, geometry.domain()).unwrap();
        assert!(bytes < 1 << 20, "the budget should narrow the byte stripe");
        assert!(
            words >= 8 * granule,
            "word lane {words} spans fewer than 8 granules of {granule}"
        );
        assert!(
            bytes + 2 * granule >= 2 * words && bytes <= 2 * words + 2 * granule,
            "byte lane admitted {bytes}, word lane {words}, granule {granule}"
        );
    }

    /// `encode_stripe_bytes` promises what `encode` reserves for its stripes,
    /// by the layout `buffers` charges, on both fields.
    #[test]
    fn encode_stripe_bytes_matches_the_encode_reservation() {
        for ((inputs, capacity_log2), workers) in [(100u64, 7i8), (150, 6), (300, 8), (40, 4)]
            .into_iter()
            .flat_map(|shape| [(shape, 1), (shape, 3)])
        {
            let geometry = FftGeometry::new(inputs, capacity_log2).unwrap();
            let options = ExecutionOptions {
                memory: MemoryBudget::new(1 << 30),
                workers,
                stripe_bytes: 1 << 16,
                ..ExecutionOptions::default()
            };
            let codec = FftCodec::new(geometry, options.clone()).unwrap();
            let rows = geometry.capacity * 2;
            let before = options.memory.used();
            let held = if geometry.bits == 8 {
                codec.buffers::<u8>(1 << 20, rows).unwrap()
            } else {
                codec.buffers::<u16>(1 << 20, rows).unwrap()
            };
            let reserved = options.memory.used() - before;
            drop(held);
            assert_eq!(
                codec.encode_stripe_bytes(1 << 20),
                reserved,
                "GF(2^{}) inputs {inputs} capacity 2^{capacity_log2}, {workers} workers",
                geometry.bits
            );
        }
    }
}
