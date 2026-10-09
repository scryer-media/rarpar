//! Additive finite-field transforms in the reference PAR3 Cantor bases.
//!
//! The transforms operate on caller-owned symbol stripes. Packet interpretation,
//! interleaving, padding and memory admission belong to the consuming codec.

/// A transform rejected its geometry or observed cancellation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransformError {
    /// Only the 8- and 16-bit reference fields are supported.
    Field,
    /// Rows must have equal widths and a valid power-of-two transform domain.
    Geometry,
    /// Cooperative cancellation was requested.
    Cancelled,
}

impl std::fmt::Display for TransformError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Field => "unsupported transform field",
            Self::Geometry => "invalid transform geometry",
            Self::Cancelled => "transform cancelled",
        })
    }
}
impl std::error::Error for TransformError {}

/// Arithmetic in the Cantor representation used by low-rate PAR3 FFT matrices.
/// These tables differ from the polynomial representation used by Cauchy codes.
pub struct TransformField {
    bits: u32,
    log: Vec<u16>,
    exp: Vec<u16>,
    four_step: bool,
}

/// Rows at or below which a four-step transform runs the butterfly kernels
/// directly: `2^FOUR_STEP_LEAF`.
const FOUR_STEP_LEAF: u32 = 6;

/// Narrowest row, in bytes, a four-step transform takes on one thread.
/// Narrower rows keep the tiled sweeps, which on 1 KiB rows measured faster
/// than four-step on one thread; 16 KiB rows measured faster four-step.
pub const FOUR_STEP_SERIAL_MIN_ROW_BYTES: usize = 16 << 10;

/// Whether a CPU takes four-step transforms: an AMD CPU running the AVX2
/// kernels (including their GFNI and 512-bit shuffle forms). Four-step
/// measured faster there only; on Intel and Graviton it was a wash or slower.
#[must_use]
pub fn four_step_admits(amd: bool, kernel: crate::gf_simd::LinearKernel) -> bool {
    amd && kernel == crate::gf_simd::LinearKernel::Avx2
}

/// [`four_step_admits`] on the executing CPU with `backend`.
#[must_use]
pub fn four_step_preferred(backend: crate::gf_simd::LinearBackend) -> bool {
    four_step_admits(crate::gf_simd::cpu_is_amd(), backend.kernel())
}

impl TransformField {
    /// Conservative storage required by the field's retained tables and setup.
    pub fn allocation_bytes(bits: u32) -> Result<usize, TransformError> {
        if !matches!(bits, 8 | 16) {
            return Err(TransformError::Field);
        }
        Ok((1usize << bits) * 8)
    }

    /// Build arithmetic tables. Basis constants and primitive polynomials are
    /// wire-format facts from the pinned reference, not its arithmetic code.
    pub fn new(bits: u32) -> Result<Self, TransformError> {
        let (polynomial, basis): (u32, &[u16]) = match bits {
            8 => (0x11d, &[1, 214, 152, 146, 86, 200, 88, 230]),
            16 => (
                0x1002d,
                &[
                    0x0001, 0xacca, 0x3c0e, 0x163e, 0xc582, 0xed2e, 0x914c, 0x4012, 0x6c98, 0x10d8,
                    0x6a72, 0xb900, 0xfdb8, 0xfb34, 0xff38, 0x991e,
                ],
            ),
            _ => return Err(TransformError::Field),
        };
        let order = 1usize << bits;
        let mut polynomial_log = vec![0u16; order];
        let mut value = 1u32;
        for exponent in 0..order - 1 {
            polynomial_log[value as usize] = exponent as u16;
            value <<= 1;
            if value & order as u32 != 0 {
                value ^= polynomial;
            }
        }
        let mut log = vec![0; order];
        let mut exp = vec![0; (order - 1) * 2];
        for (cantor, entry) in log.iter_mut().enumerate().skip(1) {
            let polynomial = basis
                .iter()
                .enumerate()
                .filter(|(bit, _)| cantor & (1 << bit) != 0)
                .fold(0u16, |value, (_, basis)| value ^ basis);
            let exponent = polynomial_log[polynomial as usize];
            *entry = exponent;
            exp[exponent as usize] = cantor as u16;
            exp[exponent as usize + order - 1] = cantor as u16;
        }
        Ok(Self {
            bits,
            log,
            exp,
            four_step: false,
        })
    }

    /// Run transforms through the four-step LCH factorization where it
    /// applies; see [`Self::four_step_runs`]. Off by default. Output is
    /// identical either way; [`four_step_preferred`] says where it is faster.
    pub fn set_four_step(&mut self, enabled: bool) {
        self.four_step = enabled;
    }

    /// Whether [`Self::set_four_step`] enabled the four-step factorization.
    #[must_use]
    pub fn four_step(&self) -> bool {
        self.four_step
    }

    /// Whether a transform of `n` rows of `row_bytes` takes the four-step
    /// factorization: enabled, and on a pool more than `2^6` rows (smaller
    /// transforms run their leaf serially, losing the pool's column tiles),
    /// on one thread rows of at least [`FOUR_STEP_SERIAL_MIN_ROW_BYTES`].
    #[must_use]
    pub fn four_step_runs(&self, n: usize, row_bytes: usize, pooled: bool) -> bool {
        self.four_step
            && n > 1
            && if pooled {
                n > 1 << FOUR_STEP_LEAF
            } else {
                row_bytes >= FOUR_STEP_SERIAL_MIN_ROW_BYTES
            }
    }

    /// Bytes beside the rows a four-step transform of `n` rows keeps: the
    /// row views, the transpose bitmaps and the flags its leaves carry.
    fn four_step_bytes(n: usize) -> usize {
        n.saturating_mul(size_of::<FourRow<'_, u16>>() + 2)
            .saturating_add(256)
    }

    /// `rows` as four-step views, transformed by `run`; then, with `sum`,
    /// each row not known zero after it added into the same row of `sum`.
    fn four_step_rows<S: Lane, R: AsMut<[S]>, T: AsMut<[S]>>(
        rows: &mut [R],
        zero: Option<&[bool]>,
        sum: Option<&mut [T]>,
        run: impl FnOnce(&mut [FourRow<'_, S>]) -> Result<(), TransformError>,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), TransformError> {
        let mut views: Vec<_> = rows
            .iter_mut()
            .enumerate()
            .map(|(i, row)| FourRow {
                row: row.as_mut(),
                zero: zero.is_some_and(|flags| flags[i]),
            })
            .collect();
        run(&mut views)?;
        if let Some(sum) = sum {
            for (to, from) in sum.iter_mut().zip(&views) {
                if cancelled() {
                    return Err(TransformError::Cancelled);
                }
                if !from.zero {
                    xor_into(to.as_mut(), from.row);
                }
            }
        }
        Ok(())
    }

    /// The balanced split of an `n`-row four-step transform.
    fn four_step_split(n: usize) -> u32 {
        let levels = n.trailing_zeros();
        (levels / 2).clamp(1, levels - 1)
    }

    /// LCH-basis form of the row/column factorization (arXiv:2608.20855,
    /// section V). Projection by the low subspace polynomial shifts a Cantor
    /// coordinate right by the split. Inverse reverses the two passes.
    fn four_step_serial<S: Lane>(
        &self,
        rows: &mut [FourRow<'_, S>],
        origin: usize,
        inverse: bool,
        backend: crate::gf_simd::LinearBackend,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), TransformError> {
        if cancelled() {
            return Err(TransformError::Cancelled);
        }
        let n = rows.len();
        if n <= 1 || rows.iter().all(|row| row.zero) {
            return Ok(());
        }
        if n <= 1 << FOUR_STEP_LEAF {
            return self.four_step_leaf(rows, origin, inverse, backend, cancelled);
        }
        let split = Self::four_step_split(n);
        let low = 1 << split;
        let high = n / low;
        if inverse {
            for (index, row) in rows.chunks_mut(low).enumerate() {
                self.four_step_serial(row, origin ^ (index * low), inverse, backend, cancelled)?;
            }
        }
        four_transpose(rows, high, low);
        for column in rows.chunks_mut(high) {
            self.four_step_serial(column, origin >> split, inverse, backend, cancelled)?;
        }
        four_transpose(rows, low, high);
        if !inverse {
            for (index, row) in rows.chunks_mut(low).enumerate() {
                self.four_step_serial(row, origin ^ (index * low), inverse, backend, cancelled)?;
            }
        }
        Ok(())
    }

    /// [`Self::four_step_serial`] with each pass's independent transforms
    /// spread over the current pool.
    fn four_step_parallel<S: Lane>(
        &self,
        rows: &mut [FourRow<'_, S>],
        origin: usize,
        inverse: bool,
        backend: crate::gf_simd::LinearBackend,
        cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<(), TransformError> {
        use rayon::prelude::*;
        if cancelled() {
            return Err(TransformError::Cancelled);
        }
        let n = rows.len();
        if n <= 1 << FOUR_STEP_LEAF {
            return self.four_step_serial(rows, origin, inverse, backend, cancelled);
        }
        let split = Self::four_step_split(n);
        let low = 1 << split;
        let high = n / low;
        if inverse {
            rows.par_chunks_mut(low)
                .enumerate()
                .try_for_each(|(index, row)| {
                    self.four_step_serial(row, origin ^ (index * low), inverse, backend, cancelled)
                })?;
        }
        four_transpose(rows, high, low);
        rows.par_chunks_mut(high).try_for_each(|column| {
            self.four_step_serial(column, origin >> split, inverse, backend, cancelled)
        })?;
        four_transpose(rows, low, high);
        if !inverse {
            rows.par_chunks_mut(low)
                .enumerate()
                .try_for_each(|(index, row)| {
                    self.four_step_serial(row, origin ^ (index * low), inverse, backend, cancelled)
                })?;
        }
        Ok(())
    }

    /// A four-step leaf: the transform's sweeps over whole rows.
    fn four_step_leaf<S: Lane>(
        &self,
        rows: &mut [FourRow<'_, S>],
        origin: usize,
        inverse: bool,
        backend: crate::gf_simd::LinearBackend,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), TransformError> {
        let width = rows[0].row.len();
        let schedule = Schedule {
            origin,
            inverse,
            backend,
            radix4: Self::fused(width, backend),
        };
        for sweep in sweeps(rows.len().trailing_zeros(), inverse, schedule.radix4) {
            match sweep {
                Sweep::Radix2(level) => {
                    let half = 1 << level;
                    for (group, chunk) in rows.chunks_mut(2 * half).enumerate() {
                        let base = group * 2 * half;
                        let pair = self.pair(&schedule, level, base, width);
                        let factor_zero = (origin ^ base) >> level == 0;
                        let (left, right) = chunk.split_at_mut(half);
                        for (left, right) in left.iter_mut().zip(right) {
                            if cancelled() {
                                return Err(TransformError::Cancelled);
                            }
                            let flags = [left.zero, right.zero];
                            pair(left.row, right.row, flags);
                            [left.zero, right.zero] = Step::of(flags, factor_zero, inverse).1;
                        }
                    }
                }
                Sweep::Radix4(level) => {
                    let quarter = 1 << level;
                    for (group, chunk) in rows.chunks_mut(4 * quarter).enumerate() {
                        let base = group * 4 * quarter;
                        let quad = self.quad(&schedule, base, level);
                        let factors = [
                            (origin ^ base) >> (level + 1),
                            (origin ^ base) >> level,
                            (origin ^ (base + 2 * quarter)) >> level,
                        ];
                        let [a, b, c, d] = quarters(chunk);
                        for (((a, b), c), d) in a.iter_mut().zip(b).zip(c).zip(d) {
                            if cancelled() {
                                return Err(TransformError::Cancelled);
                            }
                            let mut flags = [a.zero, b.zero, c.zero, d.zero];
                            quad([a.row, b.row, c.row, d.row], flags);
                            let order = if inverse {
                                [(0, 1, 1), (2, 3, 2), (0, 2, 0), (1, 3, 0)]
                            } else {
                                [(0, 2, 0), (1, 3, 0), (0, 1, 1), (2, 3, 2)]
                            };
                            for (left, right, factor) in order {
                                [flags[left], flags[right]] = Step::of(
                                    [flags[left], flags[right]],
                                    factors[factor] == 0,
                                    inverse,
                                )
                                .1;
                            }
                            [a.zero, b.zero, c.zero, d.zero] = flags;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Number of distinct field elements.
    #[must_use]
    pub fn order(&self) -> usize {
        1 << self.bits
    }

    /// Multiply two Cantor-representation symbols.
    #[must_use]
    pub fn mul(&self, left: u16, right: u16) -> u16 {
        assert!((left as usize) < self.order() && (right as usize) < self.order());
        if left == 0 || right == 0 {
            0
        } else {
            self.exp[self.log[left as usize] as usize + self.log[right as usize] as usize]
        }
    }

    /// Multiply a stripe by one Cantor-representation factor in place.
    /// Each symbol is loaded and stored once by the selected shuffle backend,
    /// with a scalar fallback; no scratch is used. Cancellation is checked at
    /// most 256 symbols apart; cancelled calls may have modified a prefix.
    /// Invalid symbols or factors return `Geometry` before modifying the
    /// stripe. Only the 8-bit field can be handed invalid symbols, so only it
    /// reads the stripe once beforehand to check them.
    pub fn scale_with_backend(
        &self,
        values: &mut [u16],
        factor: u16,
        backend: crate::gf_simd::LinearBackend,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), TransformError> {
        self.scale_lane(values, factor, backend, cancelled)
    }

    /// [`Self::scale_with_backend`] on a byte stripe of the 8-bit field. Every
    /// byte is a symbol, so no range validation pass runs; any other field
    /// returns `Field`.
    pub fn scale_u8_with_backend(
        &self,
        values: &mut [u8],
        factor: u16,
        backend: crate::gf_simd::LinearBackend,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), TransformError> {
        self.byte_lane()?;
        self.scale_lane(values, factor, backend, cancelled)
    }

    fn scale_lane<S: Lane>(
        &self,
        values: &mut [S],
        factor: u16,
        backend: crate::gf_simd::LinearBackend,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), TransformError> {
        if factor as usize >= self.order() {
            return Err(TransformError::Geometry);
        }
        if cancelled() {
            return Err(TransformError::Cancelled);
        }
        if S::ranged(self) {
            for stripe in values.chunks(256) {
                if cancelled() {
                    return Err(TransformError::Cancelled);
                }
                if !S::admits(self, stripe) {
                    return Err(TransformError::Geometry);
                }
            }
        }
        if factor == 1 {
            return Ok(());
        }
        let plan =
            (backend != crate::gf_simd::LinearBackend::Scalar && values.len() >= 64 && factor > 1)
                .then(|| S::map(self, factor, backend));
        for stripe in values.chunks_mut(256) {
            if cancelled() {
                return Err(TransformError::Cancelled);
            }
            if factor == 0 {
                stripe.fill(S::default());
            } else if let Some(plan) = &plan {
                S::map_in_place(plan, stripe);
            } else {
                for value in stripe {
                    *value = S::mul(self, *value, factor);
                }
            }
        }
        Ok(())
    }

    /// Set `destination` to `factor` times the 16-bit symbols stored as
    /// little-endian pairs in `source`, the on-disk layout: unpacking and
    /// [`Self::scale_with_backend`] in one pass, each symbol loaded and
    /// stored once. `source` must hold two bytes per destination symbol and
    /// `factor` must be a symbol (`Geometry` otherwise); any field but the
    /// 16-bit one returns `Field`. Cancellation is checked at most 256
    /// symbols apart; cancelled calls may have written a prefix.
    pub fn scale_le_bytes_with_backend(
        &self,
        source: &[u8],
        destination: &mut [u16],
        factor: u16,
        backend: crate::gf_simd::LinearBackend,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), TransformError> {
        if self.bits != 16 {
            return Err(TransformError::Field);
        }
        if source.len() != destination.len().saturating_mul(2) || factor as usize >= self.order() {
            return Err(TransformError::Geometry);
        }
        if cancelled() {
            return Err(TransformError::Cancelled);
        }
        let plan = (backend != crate::gf_simd::LinearBackend::Scalar
            && destination.len() >= 64
            && factor > 1)
            .then(|| <u16 as Lane>::map(self, factor, backend));
        for (to, from) in destination.chunks_mut(256).zip(source.chunks(512)) {
            if cancelled() {
                return Err(TransformError::Cancelled);
            }
            match &plan {
                _ if factor == 0 => to.fill(0),
                Some(plan) => plan.map_le_bytes(from, to),
                None => {
                    for (to, from) in to.iter_mut().zip(from.chunks_exact(2)) {
                        let value = u16::from_le_bytes([from[0], from[1]]);
                        *to = if factor == 1 {
                            value
                        } else {
                            self.mul(value, factor)
                        };
                    }
                }
            }
        }
        Ok(())
    }

    /// The bytes of `row`'s 16-bit symbols on a little-endian target, where
    /// each symbol's little-endian pair is its own representation, so the
    /// on-disk layout can be read into and written from the row itself;
    /// `None` on other targets.
    #[must_use]
    pub fn le_image(row: &[u16]) -> Option<&[u8]> {
        if !cfg!(target_endian = "little") {
            return None;
        }
        // SAFETY: `u8` has alignment 1 and every bit pattern is a `u8`; the
        // view covers exactly the row's `2 * len` initialized bytes and
        // borrows the row for as long as it lives.
        Some(unsafe { std::slice::from_raw_parts(row.as_ptr().cast(), row.len() * 2) })
    }

    /// [`Self::le_image`], writable: every byte pattern is a symbol, so
    /// writing the view writes the row.
    #[must_use]
    pub fn le_image_mut(row: &mut [u16]) -> Option<&mut [u8]> {
        if !cfg!(target_endian = "little") {
            return None;
        }
        // SAFETY: as `le_image`; the exclusive borrow of the row is held by
        // the view for as long as it lives.
        Some(unsafe { std::slice::from_raw_parts_mut(row.as_mut_ptr().cast(), row.len() * 2) })
    }

    /// Byte rows hold 8-bit symbols only.
    fn byte_lane(&self) -> Result<(), TransformError> {
        if self.bits == 8 {
            Ok(())
        } else {
            Err(TransformError::Field)
        }
    }

    /// Multiplicative inverse. Zero has no inverse.
    #[must_use]
    pub fn inverse(&self, value: u16) -> Option<u16> {
        if value == 0 || value as usize >= self.order() {
            None
        } else {
            Some(self.exp[self.order() - 1 - self.log[value as usize] as usize])
        }
    }

    /// Evaluate (`inverse = false`) or interpolate (`inverse = true`) the novel
    /// polynomial basis on a power-of-two additive coset. `origin` must be aligned
    /// to the row count. Cancellation is checked between butterfly groups.
    pub fn transform(
        &self,
        rows: &mut [Vec<u16>],
        origin: usize,
        inverse: bool,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), TransformError> {
        self.transform_with_backend(
            rows,
            origin,
            inverse,
            crate::gf_simd::LinearBackend::Auto,
            cancelled,
        )
    }

    /// Evaluate or interpolate with explicit CPU selection. The scalar path is
    /// the log-table oracle; automatic execution uses Cantor-derived SIMD maps.
    pub fn transform_with_backend(
        &self,
        rows: &mut [Vec<u16>],
        origin: usize,
        inverse: bool,
        backend: crate::gf_simd::LinearBackend,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), TransformError> {
        self.transform_lane(rows, None, origin, inverse, backend, cancelled)
    }

    /// [`Self::transform_with_backend`] on byte rows of the 8-bit field: one
    /// byte per symbol, so a stripe needs half the storage of 16-bit rows and
    /// each butterfly runs a two-table byte shuffle. Every butterfly, factor
    /// and order is the same as on 16-bit rows, so the symbols are identical.
    /// Any other field returns `Field`.
    pub fn transform_u8_with_backend(
        &self,
        rows: &mut [Vec<u8>],
        origin: usize,
        inverse: bool,
        backend: crate::gf_simd::LinearBackend,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), TransformError> {
        self.byte_lane()?;
        self.transform_lane(rows, None, origin, inverse, backend, cancelled)
    }

    /// [`Self::transform_with_backend`] with rows the caller knows to be zero:
    /// `zero[row]` set promises that `rows[row]` holds only zeros. The flags
    /// come from the layout (padding, erasures), never from reading the rows.
    /// Each butterfly between two known-zero rows is skipped, and one between
    /// a known-zero row and another degrades to a copy, a single product, or
    /// nothing wherever that gives the same bytes; the rows come out exactly
    /// as the dense transform leaves them. `zero` must have one flag per row.
    pub fn transform_known_zero_with_backend(
        &self,
        rows: &mut [Vec<u16>],
        zero: &[bool],
        origin: usize,
        inverse: bool,
        backend: crate::gf_simd::LinearBackend,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), TransformError> {
        self.transform_lane(rows, Some(zero), origin, inverse, backend, cancelled)
    }

    /// [`Self::transform_known_zero_with_backend`] on byte rows of the 8-bit
    /// field. Any other field returns `Field`.
    pub fn transform_u8_known_zero_with_backend(
        &self,
        rows: &mut [Vec<u8>],
        zero: &[bool],
        origin: usize,
        inverse: bool,
        backend: crate::gf_simd::LinearBackend,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), TransformError> {
        self.byte_lane()?;
        self.transform_lane(rows, Some(zero), origin, inverse, backend, cancelled)
    }

    fn transform_lane<S: Lane, R: AsRef<[S]> + AsMut<[S]>>(
        &self,
        rows: &mut [R],
        zero: Option<&[bool]>,
        origin: usize,
        inverse: bool,
        backend: crate::gf_simd::LinearBackend,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), TransformError> {
        self.transform_sum(
            rows,
            zero,
            origin,
            inverse,
            backend,
            None::<&mut [&mut [S]]>,
            cancelled,
        )
    }

    /// [`Self::transform_lane`], then, with `sum`, each row added into the
    /// same row of `sum`: tile by tile where the transform tiles, so each
    /// tile is added while it is still in the cache. Rows known zero after
    /// the transform are not added. `sum` must hold as many rows, as wide.
    #[allow(clippy::too_many_arguments)]
    fn transform_sum<S: Lane, R: AsRef<[S]> + AsMut<[S]>, T: AsRef<[S]> + AsMut<[S]>>(
        &self,
        rows: &mut [R],
        zero: Option<&[bool]>,
        origin: usize,
        inverse: bool,
        backend: crate::gf_simd::LinearBackend,
        mut sum: Option<&mut [T]>,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), TransformError> {
        self.validate_transform(rows, zero, origin, cancelled)?;
        validate_sum(rows, sum.as_deref())?;
        let n = rows.len();
        let width = rows.first().map_or(0, |row| row.as_ref().len());
        let schedule = Schedule {
            origin,
            inverse,
            backend,
            radix4: Self::fused(width, backend),
        };
        if self.four_step_runs(n, width * size_of::<S>(), false) {
            return Self::four_step_rows(
                rows,
                zero,
                sum,
                |views| self.four_step_serial(views, origin, inverse, backend, cancelled),
                cancelled,
            );
        }
        // A bank beyond a tile, on a target that tiles, runs tile by tile
        // in place: every sweep of a pass over one tile while it stays in
        // the cache; see `Walk`.
        if let Some(walk) = Walk::engaged(n, width, size_of::<S>(), &schedule, 1) {
            let flags = sweep_flags(n, zero, &schedule);
            return self.transform_tiles_alone(
                rows,
                &schedule,
                flags.as_deref(),
                &walk,
                sum,
                cancelled,
            );
        }
        let known = self.sweep_rows(rows, zero, &schedule, cancelled)?;
        if let Some(sum) = &mut sum {
            for (index, (to, from)) in sum.iter_mut().zip(rows.iter()).enumerate() {
                if cancelled() {
                    return Err(TransformError::Cancelled);
                }
                if !known.as_ref().is_some_and(|known| known[index]) {
                    xor_into(to.as_mut(), from.as_ref());
                }
            }
        }
        Ok(())
    }

    /// The transform of `schedule` over whole rows, sweep by sweep, with
    /// the known-zero flags after it. Each unit is made as its group comes
    /// and the flags are carried sweep to sweep; a tiled transform keeps
    /// every sweep's units and flags, as it runs them all over each tile.
    fn sweep_rows<S: Lane, R: AsMut<[S]>>(
        &self,
        rows: &mut [R],
        zero: Option<&[bool]>,
        schedule: &Schedule,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Option<Vec<bool>>, TransformError> {
        let n = rows.len();
        let width = rows.first_mut().map_or(0, |row| row.as_mut().len());
        let mut known = zero.map(<[bool]>::to_vec);
        for sweep in sweeps(n.trailing_zeros(), schedule.inverse, schedule.radix4) {
            let units = FreshUnits {
                field: self,
                schedule,
                sweep,
                width,
            };
            let flags = known.as_ref().map(std::slice::from_ref);
            self.run_sweeps(
                rows,
                std::slice::from_ref(&units),
                flags,
                Place::WHOLE,
                cancelled,
            )?;
            if let Some(known) = &mut known {
                advance(known, sweep, schedule.origin, schedule.inverse, &mut |_| {});
            }
        }
        Ok(known)
    }

    /// Bytes beside the rows that a transform of `n` rows `width` wide of
    /// `size`-byte symbols, `inverse` or forward with `backend`, keeps on
    /// `threads` workers (one for the calling thread alone) while it runs
    /// the bank tile by tile: the butterflies of every sweep, prepared once
    /// for all the tiles, the known-zero flags before each, and each
    /// worker's list of the rows of its tile. None when it does not tile;
    /// see [`walks`].
    pub fn walk_units_bytes(
        &self,
        n: usize,
        width: usize,
        size: usize,
        inverse: bool,
        backend: crate::gf_simd::LinearBackend,
        threads: usize,
    ) -> usize {
        let pooled = threads > 1 && width.saturating_mul(size).saturating_mul(n) >= 65536;
        if self.four_step_runs(n, width.saturating_mul(size), pooled) {
            return Self::four_step_bytes(n);
        }
        let schedule = Schedule {
            origin: 0,
            inverse,
            backend,
            radix4: Self::fused(width, backend),
        };
        let threads = threads.max(1);
        let Some(walk) = Walk::engaged(n, width, size, &schedule, threads) else {
            return 0;
        };
        let views = walk
            .passes
            .iter()
            .map(|(_, pass)| pass.rows)
            .max()
            .unwrap_or(0)
            .saturating_mul(size_of::<&mut [u16]>())
            .saturating_mul(threads);
        match size {
            1 => self.units_bytes::<u8>(n, &schedule),
            _ => self.units_bytes::<u16>(n, &schedule),
        }
        .saturating_add(views)
    }

    /// Bytes [`Self::units`] of `schedule` over `n` rows take, with the
    /// flags of [`sweep_flags`]: one unit is made to measure.
    fn units_bytes<S: Lane>(&self, n: usize, schedule: &Schedule) -> usize {
        let pair = size_of_val(&self.pair::<S>(schedule, 0, 0, 64)) + size_of::<Box<PairUnit<S>>>();
        let quad = size_of_val(&self.quad::<S>(schedule, 0, 0)) + size_of::<Box<QuadUnit<S>>>();
        let sweeps: Vec<Sweep> =
            sweeps(n.trailing_zeros(), schedule.inverse, schedule.radix4).collect();
        let units: usize = sweeps
            .iter()
            .map(|sweep| match *sweep {
                Sweep::Radix2(level) => (n >> (level + 1)) * pair,
                Sweep::Radix4(low) => (n >> (low + 2)) * quad,
            })
            .sum();
        units + (sweeps.len() + 1) * n
    }

    /// The butterflies of every sweep of `schedule` over `n` rows `width`
    /// wide, prepared once and kept: their maps are what a sweep costs
    /// beyond its rows, and a tiled transform runs the same ones over every
    /// tile.
    fn units<S: Lane>(&self, n: usize, width: usize, schedule: &Schedule) -> Vec<KeptUnits<'_, S>> {
        self.units_of(
            n,
            width,
            schedule,
            sweeps(n.trailing_zeros(), schedule.inverse, schedule.radix4),
        )
    }

    /// [`Self::units`] for the sweeps `sweeps` only, a range of the levels
    /// of a transform over `n` rows; see [`sweeps_between`].
    fn units_of<S: Lane>(
        &self,
        n: usize,
        width: usize,
        schedule: &Schedule,
        sweeps: impl Iterator<Item = Sweep>,
    ) -> Vec<KeptUnits<'_, S>> {
        sweeps
            .map(|sweep| match sweep {
                Sweep::Radix2(level) => KeptUnits::Radix2(
                    level,
                    (0..n)
                        .step_by(2 << level)
                        .map(|base| {
                            Box::new(self.pair(schedule, level, base, width)) as Box<PairUnit<S>>
                        })
                        .collect(),
                ),
                Sweep::Radix4(low) => KeptUnits::Radix4(
                    low,
                    (0..n)
                        .step_by(4 << low)
                        .map(|base| Box::new(self.quad(schedule, base, low)) as Box<QuadUnit<S>>)
                        .collect(),
                ),
            })
            .collect()
    }

    /// Whether the transform runs fused radix-4 sweeps: whenever the vector
    /// maps run at all. The scalar backend and narrow rows keep the radix-2
    /// table-walk oracle.
    fn fused(width: usize, backend: crate::gf_simd::LinearBackend) -> bool {
        backend != crate::gf_simd::LinearBackend::Scalar && width >= 64
    }

    /// The sweeps `units` over `rows`: the whole rows, or windows of the
    /// group of them `place` names, each sweep's units those of its groups
    /// of rows there. `flags` are the known-zero flags of all the rows
    /// before each of these sweeps, from [`sweep_flags`], or none.
    fn run_sweeps<S: Lane, R: AsMut<[S]>, U: Units<S>>(
        &self,
        rows: &mut [R],
        units: &[U],
        flags: Option<&[Vec<bool>]>,
        place: Place,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), TransformError> {
        let n = rows.len();
        for (index, units) in units.iter().enumerate() {
            // The zero flags as this sweep finds them; it reads, never writes them.
            let before = flags.map(|flags| flags[index].as_slice());
            let zero = |row: usize| before.is_some_and(|known| known[place.row(row)]);
            match units.sweep() {
                Sweep::Radix2(level) => {
                    let half = (1 << level) / place.stride;
                    let first = place.first >> (level + 1);
                    for (group, base) in (0..n).step_by(half * 2).enumerate() {
                        if cancelled() {
                            return Err(TransformError::Cancelled);
                        }
                        let pair = units.pair(first + group);
                        let (left, right) = rows[base..base + half * 2].split_at_mut(half);
                        for (at, (left, right)) in left.iter_mut().zip(right).enumerate() {
                            if cancelled() {
                                return Err(TransformError::Cancelled);
                            }
                            pair(
                                left.as_mut(),
                                right.as_mut(),
                                [zero(base + at), zero(base + half + at)],
                            );
                        }
                    }
                }
                Sweep::Radix4(low) => {
                    let quarter = (1 << low) / place.stride;
                    let first = place.first >> (low + 2);
                    for (group, base) in (0..n).step_by(quarter * 4).enumerate() {
                        if cancelled() {
                            return Err(TransformError::Cancelled);
                        }
                        let quad = units.quad(first + group);
                        let [a, b, c, d] = quarters(&mut rows[base..base + quarter * 4]);
                        let units = a.iter_mut().zip(b).zip(c).zip(d).enumerate();
                        for (at, (((a, b), c), d)) in units {
                            if cancelled() {
                                return Err(TransformError::Cancelled);
                            }
                            let flags = match before {
                                None => [false; 4],
                                Some(_) => std::array::from_fn(|k| zero(base + k * quarter + at)),
                            };
                            quad([a, b, c, d].map(AsMut::as_mut), flags);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// [`Self::transform_tiles`] on the calling thread alone, tile after
    /// tile.
    fn transform_tiles_alone<S: Lane, R: AsMut<[S]>, T: AsMut<[S]>>(
        &self,
        rows: &mut [R],
        schedule: &Schedule,
        flags: Option<&[Vec<bool>]>,
        walk: &Walk,
        sum: Option<&mut [T]>,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), TransformError> {
        let units = self.units(rows.len(), walk.window, schedule);
        let shared = SharedRows::of(rows);
        let sum = sum.map(|sum| SharedRows::of(sum));
        let after = flags.and_then(<[Vec<bool>]>::last);
        let last = walk.passes.len() - 1;
        for (index, (sweeps, pass)) in walk.passes.iter().enumerate() {
            let flags = flags.map(|flags| &flags[sweeps.clone()]);
            let sum = sum.as_ref().filter(|_| index == last);
            let next = std::sync::atomic::AtomicUsize::new(0);
            tile_tasks(
                &shared,
                &next,
                *pass,
                None,
                0,
                |views, _, place, columns| {
                    self.run_sweeps(views, &units[sweeps.clone()], flags, place, cancelled)?;
                    if let Some(sum) = sum {
                        add_tile(sum, views, place, columns, after);
                    }
                    Ok(())
                },
                cancelled,
            )?;
        }
        Ok(())
    }

    /// A pooled transform of a bank beyond a tile: the workers share the
    /// tiles of each pass of `walk`, each running the pass's sweeps over its
    /// tile in place; see [`Walk`] and [`tile_tasks`]. A pass ends on every
    /// worker before the next begins. With `sum`, each tile of the last
    /// pass is then added into the same columns of the same rows of `sum`,
    /// rows still known zero after the last sweep skipped.
    #[allow(clippy::too_many_arguments)]
    fn transform_tiles<S: Lane, R: AsMut<[S]>, T: AsMut<[S]>>(
        &self,
        rows: &mut [R],
        schedule: &Schedule,
        flags: Option<&[Vec<bool>]>,
        walk: &Walk,
        pool: &rayon::ThreadPool,
        sum: Option<&mut [T]>,
        cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<(), TransformError> {
        let units = self.units(rows.len(), walk.window, schedule);
        let shared = SharedRows::of(rows);
        let sum = sum.map(|sum| SharedRows::of(sum));
        let after = flags.and_then(<[Vec<bool>]>::last);
        let last = walk.passes.len() - 1;
        for (index, (sweeps, pass)) in walk.passes.iter().enumerate() {
            let flags = flags.map(|flags| &flags[sweeps.clone()]);
            let sum = sum.as_ref().filter(|_| index == last);
            let work = |views: &mut [&mut [S]], _: &mut [S], place: Place, columns: &_| {
                self.run_sweeps(views, &units[sweeps.clone()], flags, place, cancelled)?;
                if let Some(sum) = sum {
                    add_tile(sum, views, place, columns, after);
                }
                Ok(())
            };
            let next = std::sync::atomic::AtomicUsize::new(0);
            pool.broadcast(|_| tile_tasks(&shared, &next, *pass, None, 0, work, cancelled))
                .into_iter()
                .collect::<Result<(), TransformError>>()?;
        }
        Ok(())
    }

    /// Rows `at` of the forward transform of the formal derivative of the
    /// polynomial that `rows` interpolate, all at origin 0: what an erasure
    /// decode reads after its inverse transform, derivative and forward
    /// transform. `out` takes one row per entry of `at`, which must ascend;
    /// `rows` is left holding intermediate values. `zero` flags rows known
    /// zero, as for [`Self::transform_known_zero_with_backend`].
    ///
    /// The three steps never run over the whole bank one after another.
    /// With the levels split at `h`, the inverse transform is its levels
    /// below `h`, inside blocks of `2^h` consecutive rows, then those at `h`
    /// and above, the same map applied to every class of rows `2^h` apart;
    /// the forward transform is the same two halves in the other order, and
    /// the derivative the sum of one over the low bits of a row's index,
    /// inside each block, and one over the high bits, inside each class.
    /// The block-wise derivative commutes with the class-wise halves of
    /// both transforms, which undo each other, so the rows read are
    ///
    /// ```text
    /// forward_low(derivative_low(X)) + forward_low(forward_high(
    ///     derivative_high(inverse_high(X)))),   X = inverse_low(rows)
    /// ```
    ///
    /// and that takes three passes, each running a tile of a block or a
    /// class, in place, through every step it applies: blocks (inverse low
    /// half, and for a block holding a row of `at` the whole first term),
    /// classes (the inner part of the second term), then only the blocks
    /// holding a row of `at` (its last half). The derivative and what
    /// follows it run in scratch as large as the tile, so it never reaches
    /// the bank, and the bank is read and written once per pass, instead of
    /// once per pass of each step and once per set bit of every row index
    /// for the derivative. Every butterfly takes the factor and order the
    /// separate steps take, and the arithmetic is exact, so `out` holds
    /// exactly the rows the separate steps would leave.
    ///
    /// With `pool` the workers share each pass's tiles, each taking scratch
    /// of at most half [`TRANSFORM_TILE_BYTES`] of its own; without, the
    /// calling thread runs them. A domain under 16 rows runs the separate
    /// steps. Rows may be any equally wide slices of 16-bit words: `Vec`s,
    /// or the rows of a [`RowBank`].
    #[allow(clippy::too_many_arguments)]
    pub fn derivative_at<R: AsRef<[u16]> + AsMut<[u16]>, O: AsRef<[u16]> + AsMut<[u16]>>(
        &self,
        rows: &mut [R],
        zero: Option<&[bool]>,
        at: &[usize],
        out: &mut [O],
        backend: crate::gf_simd::LinearBackend,
        pool: Option<&rayon::ThreadPool>,
        cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<DerivativeWork, TransformError> {
        self.derivative_at_lane(rows, zero, at, out, backend, pool, cancelled)
    }

    /// [`Self::derivative_at`] on byte rows of the 8-bit field. Any other
    /// field returns `Field`.
    #[allow(clippy::too_many_arguments)]
    pub fn derivative_u8_at<R: AsRef<[u8]> + AsMut<[u8]>, O: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        rows: &mut [R],
        zero: Option<&[bool]>,
        at: &[usize],
        out: &mut [O],
        backend: crate::gf_simd::LinearBackend,
        pool: Option<&rayon::ThreadPool>,
        cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<DerivativeWork, TransformError> {
        self.byte_lane()?;
        self.derivative_at_lane(rows, zero, at, out, backend, pool, cancelled)
    }

    /// Bytes [`Self::derivative_at`] keeps beside the rows and `out` for `n`
    /// rows `width` wide of `size`-byte symbols with `backend` on `threads`
    /// workers (one without a pool): the butterflies of its sweeps, prepared
    /// once, the known-zero and block flags, the workers' scratch and row
    /// lists, and the bookkeeping of the call and of each worker. A narrower width never
    /// needs more. Zero where it runs the separate steps, including any
    /// `size` but 1 or 2.
    pub fn derivative_at_bytes(
        &self,
        n: usize,
        width: usize,
        size: usize,
        backend: crate::gf_simd::LinearBackend,
        threads: usize,
    ) -> usize {
        let Some(split) = Split::of(n, width, size, threads) else {
            return 0;
        };
        // Either sweep grouping, whichever keeps more: a narrower width may
        // fall under the radix-4 threshold.
        let units = |radix4: bool| {
            let schedule = |inverse| Schedule {
                origin: 0,
                inverse,
                backend,
                radix4,
            };
            let (low, levels) = (split.low, split.levels);
            match size {
                1 => {
                    self.units_bytes_of::<u8>(
                        n,
                        &schedule(true),
                        sweeps_between(0, levels, true, radix4),
                    ) + self.units_bytes_of::<u8>(
                        n,
                        &schedule(false),
                        sweeps_between(low, levels, false, radix4),
                    ) + self.units_bytes_of::<u8>(
                        n,
                        &schedule(false),
                        sweeps_between(0, low, false, radix4),
                    )
                }
                _ => {
                    self.units_bytes_of::<u16>(
                        n,
                        &schedule(true),
                        sweeps_between(0, levels, true, radix4),
                    ) + self.units_bytes_of::<u16>(
                        n,
                        &schedule(false),
                        sweeps_between(low, levels, false, radix4),
                    ) + self.units_bytes_of::<u16>(
                        n,
                        &schedule(false),
                        sweeps_between(0, low, false, radix4),
                    )
                }
            }
        };
        let sweeps = split.levels as usize + 1;
        // The flags of each sweep and their list, the rows left idle and
        // done, and the slots and kept blocks per block.
        let flags = (sweeps + 2)
            .saturating_mul(n)
            .saturating_add((sweeps + 1) * size_of::<Vec<bool>>())
            .saturating_add(2 * ((n >> split.low) + 1) * size_of::<usize>());
        // Each worker's scratch beside its tile, the lists of its tile's
        // rows and of the scratch's, and the pool's bookkeeping to hand it a
        // pass; then the sweep lists and the rest of a call's own
        // bookkeeping.
        let worker = split
            .window
            .saturating_mul(split.group())
            .saturating_mul(size)
            .saturating_add(2 * split.group() * size_of::<&mut [u16]>())
            .saturating_add(DERIVATIVE_WORKER_BYTES);
        let call = 4 * sweeps * size_of::<Sweep>() + DERIVATIVE_CALL_BYTES;
        units(true)
            .max(units(false))
            .saturating_add(flags)
            .saturating_add(threads.max(1).saturating_mul(worker))
            .saturating_add(call)
    }

    /// [`Self::units_bytes`] for the sweeps `sweeps` alone.
    fn units_bytes_of<S: Lane>(
        &self,
        n: usize,
        schedule: &Schedule,
        sweeps: impl Iterator<Item = Sweep>,
    ) -> usize {
        let pair = size_of_val(&self.pair::<S>(schedule, 0, 0, 64)) + size_of::<Box<PairUnit<S>>>();
        let quad = size_of_val(&self.quad::<S>(schedule, 0, 0)) + size_of::<Box<QuadUnit<S>>>();
        sweeps
            .map(|sweep| match sweep {
                Sweep::Radix2(level) => (n >> (level + 1)) * pair,
                Sweep::Radix4(low) => (n >> (low + 2)) * quad,
            })
            .sum::<usize>()
            + size_of::<KeptUnits<'_, S>>() * 64
    }

    #[allow(clippy::too_many_arguments)]
    fn derivative_at_lane<S: Lane, R: AsRef<[S]> + AsMut<[S]>, O: AsRef<[S]> + AsMut<[S]>>(
        &self,
        rows: &mut [R],
        zero: Option<&[bool]>,
        at: &[usize],
        out: &mut [O],
        backend: crate::gf_simd::LinearBackend,
        pool: Option<&rayon::ThreadPool>,
        cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<DerivativeWork, TransformError> {
        self.validate_transform(rows, zero, 0, cancelled)?;
        let n = rows.len();
        let width = rows.first().map_or(0, |row| row.as_ref().len());
        if out.len() != at.len()
            || out.iter().any(|row| row.as_ref().len() != width)
            || at.windows(2).any(|pair| pair[0] >= pair[1])
            || at.last().is_some_and(|&row| row >= n)
        {
            return Err(TransformError::Geometry);
        }
        let levels = n.trailing_zeros();
        let threads = pool.map_or(1, rayon::ThreadPool::current_num_threads);
        let Some(split) = Split::of(n, width, size_of::<S>(), threads) else {
            self.transform_lane(rows, zero, 0, true, backend, cancelled)?;
            derivative_rows(rows, cancelled)?;
            self.transform_lane(rows, None, 0, false, backend, cancelled)?;
            for (out, &row) in out.iter_mut().zip(at) {
                out.as_mut().copy_from_slice(rows[row].as_ref());
            }
            let full = (n as u64 / 2) * u64::from(levels);
            return Ok(DerivativeWork {
                transforms: 2,
                butterflies: 2 * full,
            });
        };
        let (low, window) = (split.low, split.window);
        let block = 1usize << low;
        let span = n >> low;
        let radix4 = Self::fused(window, backend);
        let inverse = Schedule {
            origin: 0,
            inverse: true,
            backend,
            radix4,
        };
        let forward = Schedule {
            inverse: false,
            ..inverse
        };
        let inverse_low: Vec<Sweep> = sweeps_between(0, low, true, radix4).collect();
        let inverse_high: Vec<Sweep> = sweeps_between(low, levels, true, radix4).collect();
        let units = |schedule: &Schedule, from: u32, to: u32| {
            self.units_of::<S>(
                n,
                window,
                schedule,
                sweeps_between(from, to, schedule.inverse, radix4),
            )
        };
        let inverse_low_units = units(&inverse, 0, low);
        let inverse_high_units = units(&inverse, low, levels);
        let forward_high_units = units(&forward, low, levels);
        let forward_low_units = units(&forward, 0, low);
        // The known-zero flags before each inverse sweep, low half then high,
        // and after the last.
        let flags = zero.map(|zero| {
            let mut known = zero.to_vec();
            let mut flags = Vec::with_capacity(inverse_low.len() + inverse_high.len() + 1);
            for &sweep in inverse_low.iter().chain(&inverse_high) {
                flags.push(known.clone());
                advance(&mut known, sweep, 0, true, &mut |_| {});
            }
            flags.push(known);
            flags
        });
        let low_flags = flags.as_deref().map(|flags| &flags[..=inverse_low.len()]);
        let high_flags = flags.as_deref().map(|flags| &flags[inverse_low.len()..]);
        // Rows still known zero after each half of the inverse hold zero and
        // are not read by the derivative.
        let low_after = low_flags.and_then(<[Vec<bool>]>::last);
        let high_after = high_flags.and_then(<[Vec<bool>]>::last);
        // The rows of `at` each block holds: slots `first[b]..first[b + 1]`.
        let mut first = vec![0usize; span + 1];
        for &row in at {
            first[(row >> low) + 1] += 1;
        }
        for b in 0..span {
            first[b + 1] += first[b];
        }
        let kept: Vec<usize> = (0..span).filter(|&b| first[b] < first[b + 1]).collect();
        // Rows a later pass never reads are not stored: outside the kept
        // blocks after the classes.
        let idle: Vec<bool> = (0..n)
            .map(|row| first[row >> low] == first[(row >> low) + 1])
            .collect();
        let shared = SharedRows::of(rows);
        let results = SharedRows::of(out);
        fn windows<S>(rows: &mut [S], window: usize) -> Vec<&mut [S]> {
            rows.chunks_exact_mut(window).collect()
        }
        let slots = |place: Place| {
            let b = place.first >> low;
            (first[b]..first[b + 1]).map(move |slot| (slot, at[slot] - place.first))
        };

        // Blocks: the inverse low half; then, for a kept block, the first
        // term in the spare scratch, stored to its rows of `at`.
        let blocks = Pass {
            window,
            rows: block,
            stride: 1,
        };
        self.run_pass(
            &shared,
            pool,
            blocks,
            None,
            block * window,
            |views: &mut [&mut [S]],
             spare: &mut [S],
             place: Place,
             columns: &std::ops::Range<usize>| {
                self.run_sweeps(views, &inverse_low_units, low_flags, place, cancelled)?;
                if slots(place).next().is_none() {
                    return Ok(());
                }
                let w = columns.len();
                let spare = &mut spare[..block * w];
                let zero = |k: usize| low_after.is_some_and(|after| after[place.row(k)]);
                derivative_views(views, spare, zero, cancelled)?;
                self.run_sweeps(
                    &mut windows(spare, w),
                    &forward_low_units,
                    None,
                    place,
                    cancelled,
                )?;
                for (slot, local) in slots(place) {
                    // SAFETY: this task alone holds these columns of the
                    // result rows of its block.
                    unsafe { results.columns_mut(slot, columns) }
                        .copy_from_slice(&spare[local * w..][..w]);
                }
                Ok(())
            },
            cancelled,
        )?;
        // Classes: inverse high half in place, then the high-bit derivative
        // and forward high half in scratch; stored only where a kept block
        // reads it.
        let classes = Pass {
            window,
            rows: span,
            stride: block,
        };
        self.run_pass(
            &shared,
            pool,
            classes,
            None,
            span * window,
            |views: &mut [&mut [S]],
             spare: &mut [S],
             place: Place,
             columns: &std::ops::Range<usize>| {
                self.run_sweeps(views, &inverse_high_units, high_flags, place, cancelled)?;
                let w = columns.len();
                let spare = &mut spare[..span * w];
                let zero = |k: usize| high_after.is_some_and(|after| after[place.row(k)]);
                derivative_views(views, spare, zero, cancelled)?;
                self.run_sweeps(
                    &mut windows(spare, w),
                    &forward_high_units,
                    None,
                    place,
                    cancelled,
                )?;
                for (k, (view, from)) in views.iter_mut().zip(spare.chunks_exact(w)).enumerate() {
                    if !idle[place.row(k)] {
                        view.copy_from_slice(from);
                    }
                }
                Ok(())
            },
            cancelled,
        )?;
        // Kept blocks: the forward low half of the second term, added to
        // the first in the rows of `at`.
        self.run_pass(
            &shared,
            pool,
            blocks,
            Some(&kept),
            0,
            |views: &mut [&mut [S]],
             _: &mut [S],
             place: Place,
             columns: &std::ops::Range<usize>| {
                self.run_sweeps(views, &forward_low_units, None, place, cancelled)?;
                for (slot, local) in slots(place) {
                    // SAFETY: as in the first pass.
                    let result = unsafe { results.columns_mut(slot, columns) };
                    add_into(result, views[local]);
                }
                Ok(())
            },
            cancelled,
        )?;
        let half = n as u64 / 2;
        let kept_low = kept.len() as u64 * (block as u64 / 2) * u64::from(low);
        Ok(DerivativeWork {
            transforms: 1 + block as u64 + 2 * kept.len() as u64,
            butterflies: half * u64::from(levels) + half * u64::from(levels - low) + 2 * kept_low,
        })
    }

    /// One pass of [`Self::derivative_at`]: its tiles shared by the pool's
    /// workers, or run by the calling thread; see [`tile_tasks`].
    #[allow(clippy::too_many_arguments)]
    fn run_pass<S: Lane>(
        &self,
        shared: &SharedRows<S>,
        pool: Option<&rayon::ThreadPool>,
        pass: Pass,
        groups: Option<&[usize]>,
        spare: usize,
        work: impl Fn(
            &mut [&mut [S]],
            &mut [S],
            Place,
            &std::ops::Range<usize>,
        ) -> Result<(), TransformError>
        + Sync,
        cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<(), TransformError> {
        let next = std::sync::atomic::AtomicUsize::new(0);
        let tasks = || tile_tasks(shared, &next, pass, groups, spare, &work, cancelled);
        match pool {
            Some(pool) if pool.current_num_threads() > 1 => {
                pool.broadcast(|_| tasks()).into_iter().collect()
            }
            _ => tasks(),
        }
    }

    /// A transform of equally wide slices of 16-bit words: `Vec`s, or the
    /// rows of a [`RowBank`]. `zero` flags rows known zero, as for
    /// [`Self::transform_known_zero_with_backend`]; with `pool` it runs as
    /// [`Self::transform_in_pool`] does, and without, on the calling thread
    /// as [`Self::transform_with_backend`] does. A bank beyond
    /// [`TRANSFORM_TILE_BYTES`] runs in column tiles on a target that
    /// tiles; see [`walks`].
    #[allow(clippy::too_many_arguments)]
    pub fn transform_rows<R: AsRef<[u16]> + AsMut<[u16]> + Send>(
        &self,
        rows: &mut [R],
        zero: Option<&[bool]>,
        origin: usize,
        inverse: bool,
        backend: crate::gf_simd::LinearBackend,
        pool: Option<&rayon::ThreadPool>,
        cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<(), TransformError> {
        self.transform_rows_lane(
            rows,
            zero,
            origin,
            inverse,
            backend,
            pool,
            None::<&mut [&mut [u16]]>,
            cancelled,
        )
    }

    /// [`Self::transform_rows`] on byte rows of the 8-bit field. Any other
    /// field returns `Field`.
    #[allow(clippy::too_many_arguments)]
    pub fn transform_u8_rows<R: AsRef<[u8]> + AsMut<[u8]> + Send>(
        &self,
        rows: &mut [R],
        zero: Option<&[bool]>,
        origin: usize,
        inverse: bool,
        backend: crate::gf_simd::LinearBackend,
        pool: Option<&rayon::ThreadPool>,
        cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<(), TransformError> {
        self.byte_lane()?;
        self.transform_rows_lane(
            rows,
            zero,
            origin,
            inverse,
            backend,
            pool,
            None::<&mut [&mut [u8]]>,
            cancelled,
        )
    }

    /// [`Self::transform_rows`], then every row of the result added (XORed)
    /// into the same row of `sum`, which must hold as many rows, as wide.
    /// Where the transform tiles, each tile is added as its last pass
    /// leaves it, while it is still in the cache, so the sum costs no pass
    /// over the bank of its own. Rows known zero after the transform are
    /// not added. A cancelled call leaves `sum` with some tiles added.
    #[allow(clippy::too_many_arguments)]
    pub fn transform_rows_adding<
        R: AsRef<[u16]> + AsMut<[u16]> + Send,
        T: AsRef<[u16]> + AsMut<[u16]> + Send,
    >(
        &self,
        rows: &mut [R],
        zero: Option<&[bool]>,
        origin: usize,
        inverse: bool,
        backend: crate::gf_simd::LinearBackend,
        pool: Option<&rayon::ThreadPool>,
        sum: &mut [T],
        cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<(), TransformError> {
        self.transform_rows_lane(
            rows,
            zero,
            origin,
            inverse,
            backend,
            pool,
            Some(sum),
            cancelled,
        )
    }

    /// [`Self::transform_rows_adding`] on byte rows of the 8-bit field. Any
    /// other field returns `Field`.
    #[allow(clippy::too_many_arguments)]
    pub fn transform_u8_rows_adding<
        R: AsRef<[u8]> + AsMut<[u8]> + Send,
        T: AsRef<[u8]> + AsMut<[u8]> + Send,
    >(
        &self,
        rows: &mut [R],
        zero: Option<&[bool]>,
        origin: usize,
        inverse: bool,
        backend: crate::gf_simd::LinearBackend,
        pool: Option<&rayon::ThreadPool>,
        sum: &mut [T],
        cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<(), TransformError> {
        self.byte_lane()?;
        self.transform_rows_lane(
            rows,
            zero,
            origin,
            inverse,
            backend,
            pool,
            Some(sum),
            cancelled,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn transform_rows_lane<
        S: Lane,
        R: AsRef<[S]> + AsMut<[S]> + Send,
        T: AsRef<[S]> + AsMut<[S]> + Send,
    >(
        &self,
        rows: &mut [R],
        zero: Option<&[bool]>,
        origin: usize,
        inverse: bool,
        backend: crate::gf_simd::LinearBackend,
        pool: Option<&rayon::ThreadPool>,
        sum: Option<&mut [T]>,
        cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<(), TransformError> {
        match pool {
            Some(pool) => self
                .transform_sum_in_pool(rows, zero, origin, inverse, backend, pool, sum, cancelled),
            None => self.transform_sum(rows, zero, origin, inverse, backend, sum, cancelled),
        }
    }

    /// [`Self::derivative`] of equally wide slices of 16-bit words, as for
    /// [`Self::transform_rows`]: with `pool` as [`Self::derivative_in_pool`]
    /// runs, and without, on the calling thread.
    pub fn differentiate_rows<R: AsRef<[u16]> + AsMut<[u16]>>(
        &self,
        rows: &mut [R],
        pool: Option<&rayon::ThreadPool>,
        cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<(), TransformError> {
        match pool {
            Some(pool) => self.derivative_lane_in_pool(rows, pool, cancelled),
            None => self.derivative_lane(rows, cancelled),
        }
    }

    /// [`Self::differentiate_rows`] on byte rows of the 8-bit field. Any
    /// other field returns `Field`.
    pub fn differentiate_u8_rows<R: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        rows: &mut [R],
        pool: Option<&rayon::ThreadPool>,
        cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<(), TransformError> {
        self.byte_lane()?;
        match pool {
            Some(pool) => self.derivative_lane_in_pool(rows, pool, cancelled),
            None => self.derivative_lane(rows, cancelled),
        }
    }

    /// Run transform stages inside a caller-owned, bounded worker pool. No
    /// global pool is used. Small stripes execute synchronously to avoid task
    /// overhead; cancellation is checked before each butterfly pair. A bank
    /// beyond [`TRANSFORM_TILE_BYTES`] runs in column tiles, in place, on a
    /// target that tiles (see [`walks`]), the workers sharing the tiles of
    /// each pass; a cancelled transform leaves the rows with some tiles
    /// done and some not, so they hold no transform of anything, as a
    /// cancelled sweep over whole rows leaves them with some butterflies
    /// done.
    pub fn transform_in_pool(
        &self,
        rows: &mut [Vec<u16>],
        origin: usize,
        inverse: bool,
        backend: crate::gf_simd::LinearBackend,
        pool: &rayon::ThreadPool,
        cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<(), TransformError> {
        self.transform_lane_in_pool(rows, None, origin, inverse, backend, pool, cancelled)
    }

    /// [`Self::transform_in_pool`] on byte rows of the 8-bit field; see
    /// [`Self::transform_u8_with_backend`]. Any other field returns `Field`.
    pub fn transform_u8_in_pool(
        &self,
        rows: &mut [Vec<u8>],
        origin: usize,
        inverse: bool,
        backend: crate::gf_simd::LinearBackend,
        pool: &rayon::ThreadPool,
        cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<(), TransformError> {
        self.byte_lane()?;
        self.transform_lane_in_pool(rows, None, origin, inverse, backend, pool, cancelled)
    }

    /// [`Self::transform_known_zero_with_backend`] inside a caller-owned pool;
    /// see [`Self::transform_in_pool`].
    #[allow(clippy::too_many_arguments)]
    pub fn transform_known_zero_in_pool(
        &self,
        rows: &mut [Vec<u16>],
        zero: &[bool],
        origin: usize,
        inverse: bool,
        backend: crate::gf_simd::LinearBackend,
        pool: &rayon::ThreadPool,
        cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<(), TransformError> {
        self.transform_lane_in_pool(rows, Some(zero), origin, inverse, backend, pool, cancelled)
    }

    /// [`Self::transform_u8_known_zero_with_backend`] inside a caller-owned
    /// pool. Any other field returns `Field`.
    #[allow(clippy::too_many_arguments)]
    pub fn transform_u8_known_zero_in_pool(
        &self,
        rows: &mut [Vec<u8>],
        zero: &[bool],
        origin: usize,
        inverse: bool,
        backend: crate::gf_simd::LinearBackend,
        pool: &rayon::ThreadPool,
        cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<(), TransformError> {
        self.byte_lane()?;
        self.transform_lane_in_pool(rows, Some(zero), origin, inverse, backend, pool, cancelled)
    }

    #[allow(clippy::too_many_arguments)]
    fn transform_lane_in_pool<S: Lane, R: AsRef<[S]> + AsMut<[S]> + Send>(
        &self,
        rows: &mut [R],
        zero: Option<&[bool]>,
        origin: usize,
        inverse: bool,
        backend: crate::gf_simd::LinearBackend,
        pool: &rayon::ThreadPool,
        cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<(), TransformError> {
        self.transform_sum_in_pool(
            rows,
            zero,
            origin,
            inverse,
            backend,
            pool,
            None::<&mut [&mut [S]]>,
            cancelled,
        )
    }

    /// [`Self::transform_sum`] inside a caller-owned pool.
    #[allow(clippy::too_many_arguments)]
    fn transform_sum_in_pool<
        S: Lane,
        R: AsRef<[S]> + AsMut<[S]> + Send,
        T: AsRef<[S]> + AsMut<[S]> + Send,
    >(
        &self,
        rows: &mut [R],
        zero: Option<&[bool]>,
        origin: usize,
        inverse: bool,
        backend: crate::gf_simd::LinearBackend,
        pool: &rayon::ThreadPool,
        sum: Option<&mut [T]>,
        cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<(), TransformError> {
        let n = rows.len();
        let width = rows.first().map_or(0, |row| row.as_ref().len());
        // The synchronous cutoff is 64 KiB of row storage in either lane.
        if pool.current_num_threads() == 1 || (size_of::<S>() * width).saturating_mul(n) < 65536 {
            return self.transform_sum(rows, zero, origin, inverse, backend, sum, cancelled);
        }
        self.validate_transform(rows, zero, origin, cancelled)?;
        validate_sum(rows, sum.as_deref())?;
        let schedule = Schedule {
            origin,
            inverse,
            backend,
            radix4: Self::fused(width, backend),
        };
        let threads = pool.current_num_threads();
        if self.four_step_runs(n, width * size_of::<S>(), true) {
            return Self::four_step_rows(
                rows,
                zero,
                sum,
                |views| {
                    pool.install(|| {
                        self.four_step_parallel(views, origin, inverse, backend, cancelled)
                    })
                },
                cancelled,
            );
        }
        if let Some(walk) = Walk::engaged(n, width, size_of::<S>(), &schedule, threads) {
            let flags = sweep_flags(n, zero, &schedule);
            return self.transform_tiles(
                rows,
                &schedule,
                flags.as_deref(),
                &walk,
                pool,
                sum,
                cancelled,
            );
        }
        self.sweep_lane_in_pool(rows, zero, origin, inverse, backend, pool, cancelled)?;
        let Some(sum) = sum else {
            return Ok(());
        };
        // Untiled, the sum is added on the calling thread, a row at a time:
        // handing the rows to the pool once more costs its workers another
        // rendezvous per transform, more than the adds themselves.
        let after = sweep_flags(n, zero, &schedule).and_then(|mut flags| flags.pop());
        for (index, (to, from)) in sum.iter_mut().zip(rows.iter()).enumerate() {
            if cancelled() {
                return Err(TransformError::Cancelled);
            }
            if !after.as_ref().is_some_and(|after| after[index]) {
                add_into(to.as_mut(), from.as_ref());
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn sweep_lane_in_pool<S: Lane, R: AsMut<[S]> + Send>(
        &self,
        rows: &mut [R],
        zero: Option<&[bool]>,
        origin: usize,
        inverse: bool,
        backend: crate::gf_simd::LinearBackend,
        pool: &rayon::ThreadPool,
        cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<(), TransformError> {
        use rayon::prelude::*;
        let n = rows.len();
        let width = rows.first_mut().map_or(0, |row| row.as_mut().len());
        let schedule = Schedule {
            origin,
            inverse,
            backend,
            radix4: Self::fused(width, backend),
        };
        let mut known = zero.map(<[bool]>::to_vec);
        pool.install(|| {
            for sweep in sweeps(n.trailing_zeros(), inverse, schedule.radix4) {
                let before = known.clone();
                let zero = |row: usize| before.as_ref().is_some_and(|known| known[row]);
                match sweep {
                    Sweep::Radix2(level) => {
                        let half = 1 << level;
                        rows.par_chunks_mut(half * 2).enumerate().try_for_each(
                            |(group, rows)| {
                                let base = group * half * 2;
                                let pair = self.pair(&schedule, level, base, width);
                                let (left, right) = rows.split_at_mut(half);
                                left.par_iter_mut()
                                    .zip(right.par_iter_mut())
                                    .enumerate()
                                    .try_for_each(|(at, (left, right))| {
                                        if cancelled() {
                                            return Err(TransformError::Cancelled);
                                        }
                                        pair(
                                            left.as_mut(),
                                            right.as_mut(),
                                            [zero(base + at), zero(base + half + at)],
                                        );
                                        Ok(())
                                    })
                            },
                        )?;
                    }
                    Sweep::Radix4(low) => {
                        let quarter = 1 << low;
                        rows.par_chunks_mut(quarter * 4).enumerate().try_for_each(
                            |(group, rows)| {
                                let base = group * quarter * 4;
                                let quad = self.quad(&schedule, base, low);
                                let [a, b, c, d] = quarters(rows);
                                a.par_iter_mut()
                                    .zip(b.par_iter_mut())
                                    .zip(c.par_iter_mut())
                                    .zip(d.par_iter_mut())
                                    .enumerate()
                                    .try_for_each(|(at, (((a, b), c), d))| {
                                        if cancelled() {
                                            return Err(TransformError::Cancelled);
                                        }
                                        let flags = match &before {
                                            None => [false; 4],
                                            Some(_) => std::array::from_fn(|k| {
                                                zero(base + k * quarter + at)
                                            }),
                                        };
                                        quad([a, b, c, d].map(AsMut::as_mut), flags);
                                        Ok(())
                                    })
                            },
                        )?;
                    }
                }
                if let Some(known) = &mut known {
                    advance(known, sweep, origin, inverse, &mut |_| {});
                }
            }
            Ok(())
        })
    }

    fn validate_transform<S: Lane, R: AsRef<[S]>>(
        &self,
        rows: &[R],
        zero: Option<&[bool]>,
        origin: usize,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), TransformError> {
        let n = rows.len();
        if !n.is_power_of_two()
            || n > self.order()
            || !origin.is_multiple_of(n)
            || origin > self.order() - n
            || zero.is_some_and(|zero| zero.len() != n)
        {
            return Err(TransformError::Geometry);
        }
        for row in rows {
            if cancelled() {
                return Err(TransformError::Cancelled);
            }
            let row = row.as_ref();
            if row.len() != rows[0].as_ref().len() || (S::ranged(self) && !S::admits(self, row)) {
                return Err(TransformError::Geometry);
            }
        }
        debug_assert!(
            zero.is_none_or(|zero| {
                rows.iter().zip(zero).all(|(row, &zero)| {
                    !zero || row.as_ref().iter().all(|&value| value == S::default())
                })
            }),
            "a row flagged as known zero holds a nonzero symbol"
        );
        Ok(())
    }

    /// The butterfly of the radix-2 group at `base` on `level`, given whether
    /// each of its two rows is known zero. A single product writes only the
    /// zero left row, as the radix-4 units do; the right row is not stored.
    fn pair<S: Lane>(
        &self,
        schedule: &Schedule,
        level: u32,
        base: usize,
        width: usize,
    ) -> impl Fn(&mut [S], &mut [S], [bool; 2]) + Sync + '_ {
        use crate::gf_simd::LinearBackend;
        let factor = ((schedule.origin ^ base) >> level) as u16;
        let inverse = schedule.inverse;
        let backend = schedule.backend;
        let plan = (backend != LinearBackend::Scalar && width >= 64 && factor > 1)
            .then(|| S::map(self, factor, backend));
        move |left, right, zero| match Step::of(zero, factor == 0, inverse).0 {
            Step::Skip | Step::Keep => {}
            Step::Copy => right.copy_from_slice(left),
            // The left row is zero and the factor is not.
            Step::Scale => match &plan {
                Some(plan) => S::accumulate(plan, right, left),
                None if factor == 1 => left.copy_from_slice(right),
                None => {
                    for (a, b) in left.iter_mut().zip(right) {
                        *a = S::mul(self, *b, factor);
                    }
                }
            },
            Step::Full => {
                if factor == 0 && backend != LinearBackend::Scalar {
                    for (a, b) in left.iter().zip(right) {
                        *b ^= *a;
                    }
                } else if let Some(plan) = &plan {
                    S::butterfly(plan, left, right, inverse);
                } else if inverse {
                    for (a, b) in left.iter_mut().zip(right) {
                        *b ^= *a;
                        *a ^= S::mul(self, *b, factor);
                    }
                } else {
                    for (a, b) in left.iter_mut().zip(right) {
                        *a ^= S::mul(self, *b, factor);
                        *b ^= *a;
                    }
                }
            }
        }
    }

    /// The radix-4 unit of the group at `base` for the stage pair `low + 1`
    /// and `low`: rows `[a, b, c, d]` spaced `2^low` apart, given whether each
    /// is known zero. The outer stage's factor is that of the group at `base`,
    /// the inner stage's those of its two halves, exactly as the radix-2
    /// sweeps compute them. A zero factor maps to zero, so it needs no special
    /// case to stay exact. A unit with some rows known zero and some not runs
    /// its four butterflies one at a time, in radix-2 order, so each can take
    /// its degenerate form.
    fn quad<S: Lane>(
        &self,
        schedule: &Schedule,
        base: usize,
        low: u32,
    ) -> impl Fn([&mut [S]; 4], [bool; 4]) + Sync + '_ {
        let quarter = 1 << low;
        let origin = schedule.origin;
        let factors = [
            ((origin ^ base) >> (low + 1)) as u16,
            ((origin ^ base) >> low) as u16,
            ((origin ^ (base + quarter * 2)) >> low) as u16,
        ];
        let maps = factors.map(|factor| S::map(self, factor, schedule.backend));
        let inverse = schedule.inverse;
        move |mut rows, mut zero| {
            if zero == [false; 4] {
                S::radix4(&maps[0], [&maps[1], &maps[2]], rows, inverse);
                return;
            }
            // (left, right, map) per butterfly; map 0 is the outer stage's.
            let order = if inverse {
                [(0, 1, 1), (2, 3, 2), (0, 2, 0), (1, 3, 0)]
            } else {
                [(0, 2, 0), (1, 3, 0), (0, 1, 1), (2, 3, 2)]
            };
            for (l, r, m) in order {
                let (step, next) = Step::of([zero[l], zero[r]], factors[m] == 0, inverse);
                let (front, back) = rows.split_at_mut(r);
                let (left, right) = (&mut *front[l], &mut *back[0]);
                match step {
                    Step::Skip | Step::Keep => {}
                    Step::Copy => right.copy_from_slice(left),
                    Step::Scale => S::accumulate(&maps[m], right, left),
                    Step::Full => S::butterfly(&maps[m], left, right, inverse),
                }
                [zero[l], zero[r]] = next;
            }
        }
    }

    /// Differentiate a polynomial in place. In this Cantor basis each normalized
    /// subspace polynomial has derivative one, so the product rule is an XOR of
    /// coefficients whose index has exactly one additional set bit.
    pub fn derivative(
        &self,
        rows: &mut [Vec<u16>],
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), TransformError> {
        self.derivative_lane(rows, cancelled)
    }

    /// [`Self::derivative`] on byte rows of the 8-bit field. Any other field
    /// returns `Field`.
    pub fn derivative_u8(
        &self,
        rows: &mut [Vec<u8>],
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), TransformError> {
        self.byte_lane()?;
        self.derivative_lane(rows, cancelled)
    }

    /// [`Self::derivative`] inside a caller-owned, bounded worker pool: the
    /// columns are split between tasks, each running the sequential
    /// derivative on its own columns of every row, so the rows come out
    /// exactly as [`Self::derivative`] leaves them. Small stripes execute
    /// synchronously, as in [`Self::transform_in_pool`]. On a target that
    /// tiles, a bank beyond half [`TRANSFORM_TILE_BYTES`] runs a tile of a
    /// window of every row at a time, each worker differentiating into
    /// scratch as large as its tile, at most that much, and all of them
    /// together at most the bank.
    pub fn derivative_in_pool(
        &self,
        rows: &mut [Vec<u16>],
        pool: &rayon::ThreadPool,
        cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<(), TransformError> {
        self.derivative_lane_in_pool(rows, pool, cancelled)
    }

    /// [`Self::derivative_in_pool`] on byte rows of the 8-bit field. Any
    /// other field returns `Field`.
    pub fn derivative_u8_in_pool(
        &self,
        rows: &mut [Vec<u8>],
        pool: &rayon::ThreadPool,
        cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<(), TransformError> {
        self.byte_lane()?;
        self.derivative_lane_in_pool(rows, pool, cancelled)
    }

    fn derivative_lane_in_pool<S: Lane, R: AsRef<[S]> + AsMut<[S]>>(
        &self,
        rows: &mut [R],
        pool: &rayon::ThreadPool,
        cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<(), TransformError> {
        use rayon::prelude::*;
        let n = rows.len();
        let width = rows.first().map_or(0, |row| row.as_ref().len());
        let threads = pool.current_num_threads();
        // The same 64 KiB synchronous cutoff as the pooled transforms, and
        // no column share narrower than one 64-byte cache line.
        let share = width
            .div_ceil(threads)
            .next_multiple_of(64 / size_of::<S>());
        if threads == 1 || size_of::<S>() * width * n < 65536 || share >= width {
            return self.derivative_lane(rows, cancelled);
        }
        self.validate_derivative(rows)?;
        // Tiled where the transforms tile, for the same reason: every row is
        // read once per set bit of its index, and within a tile those reads
        // hit the cache; see `Self::derivative_pass`.
        if let Some(pass) = COLUMN_TILES
            .then(|| Self::derivative_pass::<S>(n, width, threads))
            .flatten()
        {
            return Self::derivative_tiled(rows, pass, pool, cancelled);
        }
        // One pointer per row, the same size as the row handles themselves.
        let shared = SharedRows::of(rows);
        pool.install(|| {
            (0..width.div_ceil(share))
                .into_par_iter()
                .try_for_each(|task| {
                    let columns = task * share..width.min((task + 1) * share);
                    for index in 0..n {
                        if cancelled() {
                            return Err(TransformError::Cancelled);
                        }
                        let mut sources = [&[] as &[S]; 16];
                        let mut count = 0;
                        for bit in (0..n.trailing_zeros()).filter(|bit| index & (1 << bit) == 0) {
                            // SAFETY: rows `index | 1 << bit` lie past `index`,
                            // so none is the target; see `SharedRows::columns`.
                            sources[count] =
                                unsafe { shared.columns(index | (1 << bit), &columns) };
                            count += 1;
                        }
                        // SAFETY: the one mutable slice this task holds; see
                        // `SharedRows::columns`.
                        let target = unsafe { shared.columns_mut(index, &columns) };
                        xor_sum(target, &sources[..count]);
                    }
                    Ok(())
                })
        })
    }

    fn validate_derivative<S: Lane, R: AsRef<[S]>>(
        &self,
        rows: &[R],
    ) -> Result<(), TransformError> {
        let n = rows.len();
        if !n.is_power_of_two()
            || n > self.order()
            || rows
                .iter()
                .any(|row| row.as_ref().len() != rows[0].as_ref().len())
        {
            return Err(TransformError::Geometry);
        }
        Ok(())
    }

    fn derivative_lane<S: Lane, R: AsRef<[S]> + AsMut<[S]>>(
        &self,
        rows: &mut [R],
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), TransformError> {
        self.validate_derivative(rows)?;
        // Whole rows: alone, the XORs are bound by their own work.
        derivative_rows(rows, cancelled)
    }

    /// The pass a derivative of a bank beyond a tile runs in on `threads`
    /// workers: every row at once, at a window narrow enough for the tile
    /// and a second copy of it to share [`TRANSFORM_TILE_BYTES`], and for
    /// the workers' copies together to stay within the bank; none when the
    /// tile-sized windows, or whole cache lines, would leave a worker idle,
    /// and the pool shares the columns instead.
    fn derivative_pass<S: Lane>(n: usize, width: usize, threads: usize) -> Option<Pass> {
        Pass::narrow::<S>(n, width, TRANSFORM_TILE_BYTES / 2, threads)
    }

    /// A pooled derivative of validated `rows`, tiled in `pass`: the workers
    /// share its tiles, each differentiating its tile into scratch of its
    /// own, as long, and copying the result back over the tile; see
    /// [`tile_tasks`].
    fn derivative_tiled<S: Lane, R: AsMut<[S]>>(
        rows: &mut [R],
        pass: Pass,
        pool: &rayon::ThreadPool,
        cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<(), TransformError> {
        let n = rows.len();
        let shared = SharedRows::of(rows);
        let next = std::sync::atomic::AtomicUsize::new(0);
        let work = |views: &mut [&mut [S]],
                    spare: &mut [S],
                    _: Place,
                    columns: &std::ops::Range<usize>| {
            let spare = &mut spare[..n * columns.len()];
            derivative_views(views, spare, |_| false, cancelled)?;
            for (view, from) in views.iter_mut().zip(spare.chunks_exact(columns.len())) {
                view.copy_from_slice(from);
            }
            Ok(())
        };
        pool.broadcast(|_| tile_tasks(&shared, &next, pass, None, n * pass.window, work, cancelled))
            .into_iter()
            .collect()
    }

    /// Evaluate an erasure locator at received positions and its derivative at
    /// erased positions. XOR convolution of discrete logarithms computes all
    /// products in O(N log N), including when most recovery rows are absent.
    pub fn erasure_factors(
        &self,
        erased: &[bool],
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Vec<u16>, TransformError> {
        let n = erased.len();
        if !n.is_power_of_two() || n > self.order() {
            return Err(TransformError::Geometry);
        }
        let modulus = (self.order() - 1) as u64;
        let mut logs: Vec<u64> = self.log[..n].iter().map(|value| *value as u64).collect();
        let mut mask: Vec<u64> = erased.iter().map(|erased| u64::from(*erased)).collect();
        walsh(&mut logs, modulus, cancelled)?;
        walsh(&mut mask, modulus, cancelled)?;
        let mut scale = 1;
        for _ in 0..n.trailing_zeros() {
            scale = scale * modulus.div_ceil(2) % modulus;
        }
        for (value, mask) in logs.iter_mut().zip(mask) {
            *value = *value * mask % modulus * scale % modulus;
        }
        walsh(&mut logs, modulus, cancelled)?;
        Ok(logs
            .into_iter()
            .map(|exponent| self.exp[exponent as usize])
            .collect())
    }
}

/// Symbol storage a transform runs on: 16-bit words for either field, or one
/// byte per symbol for the 8-bit field. The butterfly schedule is shared; a
/// lane supplies only its multiply-accumulate kernel and its scalar oracle.
trait Lane:
    Copy
    + Default
    + PartialEq
    + Send
    + Sync
    + std::ops::BitXor<Output = Self>
    + std::ops::BitXorAssign
    + 'static
{
    /// Prepared multiplication by one Cantor-representation factor.
    type Map: Sync;
    /// Whether this lane can store values outside `field`, which must then
    /// be checked: 16-bit words holding 8-bit symbols.
    fn ranged(field: &TransformField) -> bool;
    fn map(
        field: &TransformField,
        factor: u16,
        backend: crate::gf_simd::LinearBackend,
    ) -> Self::Map;
    fn accumulate(map: &Self::Map, source: &[Self], destination: &mut [Self]);
    /// Replace each value by its image, each loaded and stored once.
    fn map_in_place(map: &Self::Map, values: &mut [Self]);
    /// One butterfly, each row loaded and stored once.
    fn butterfly(map: &Self::Map, left: &mut [Self], right: &mut [Self], inverse: bool);
    /// Two consecutive stages over four rows, each loaded and stored once.
    fn radix4(outer: &Self::Map, inner: [&Self::Map; 2], rows: [&mut [Self]; 4], inverse: bool);
    fn mul(field: &TransformField, value: Self, factor: u16) -> Self;
    fn admits(field: &TransformField, values: &[Self]) -> bool;
}

impl Lane for u16 {
    type Map = crate::gf_simd::LinearMap16;
    fn ranged(field: &TransformField) -> bool {
        field.bits < 16
    }
    fn map(
        field: &TransformField,
        factor: u16,
        backend: crate::gf_simd::LinearBackend,
    ) -> Self::Map {
        crate::gf_simd::LinearMap16::new(
            std::array::from_fn(|bit| {
                if bit < field.bits as usize {
                    field.mul(1 << bit, factor)
                } else {
                    0
                }
            }),
            backend,
        )
    }
    fn accumulate(map: &Self::Map, source: &[Self], destination: &mut [Self]) {
        map.accumulate(source, destination);
    }
    fn map_in_place(map: &Self::Map, values: &mut [Self]) {
        map.map_in_place(values);
    }
    fn butterfly(map: &Self::Map, left: &mut [Self], right: &mut [Self], inverse: bool) {
        map.butterfly(left, right, inverse);
    }
    fn radix4(outer: &Self::Map, inner: [&Self::Map; 2], rows: [&mut [Self]; 4], inverse: bool) {
        crate::gf_simd::LinearMap16::radix4(outer, inner, rows, inverse);
    }
    fn mul(field: &TransformField, value: Self, factor: u16) -> Self {
        field.mul(value, factor)
    }
    /// The order is a power of two, so every value is below it exactly when
    /// their OR is; the reduction has no early exit and vectorizes.
    fn admits(field: &TransformField, values: &[Self]) -> bool {
        (values.iter().fold(0, |any, &value| any | value) as usize) < field.order()
    }
}

/// Only reachable through the `u8` entry points, which admit the 8-bit field
/// alone, so every byte is a symbol.
impl Lane for u8 {
    type Map = crate::gf_simd::LinearMap8;
    fn ranged(_: &TransformField) -> bool {
        false
    }
    fn map(
        field: &TransformField,
        factor: u16,
        backend: crate::gf_simd::LinearBackend,
    ) -> Self::Map {
        crate::gf_simd::LinearMap8::new(
            std::array::from_fn(|bit| field.mul(1 << bit, factor) as u8),
            backend,
        )
    }
    fn accumulate(map: &Self::Map, source: &[Self], destination: &mut [Self]) {
        map.accumulate(source, destination);
    }
    fn map_in_place(map: &Self::Map, values: &mut [Self]) {
        map.map_in_place(values);
    }
    fn butterfly(map: &Self::Map, left: &mut [Self], right: &mut [Self], inverse: bool) {
        map.butterfly(left, right, inverse);
    }
    fn radix4(outer: &Self::Map, inner: [&Self::Map; 2], rows: [&mut [Self]; 4], inverse: bool) {
        crate::gf_simd::LinearMap8::radix4(outer, inner, rows, inverse);
    }
    fn mul(field: &TransformField, value: Self, factor: u16) -> Self {
        field.mul(value.into(), factor) as u8
    }
    fn admits(_: &TransformField, _: &[Self]) -> bool {
        true
    }
}

/// One row of a four-step transform and whether it is known zero.
struct FourRow<'a, S> {
    row: &'a mut [S],
    zero: bool,
}

impl<S> Default for FourRow<'_, S> {
    fn default() -> Self {
        Self {
            row: &mut [],
            zero: true,
        }
    }
}

/// Permute disjoint views, including their zero flags, from `rows` by
/// `columns` to `columns` by `rows`. The data stays in its bank; the second
/// transpose of a pass returns the caller's row order.
fn four_transpose<S>(views: &mut [FourRow<'_, S>], rows: usize, columns: usize) {
    let mut seen = vec![0u64; views.len().div_ceil(64)];
    for first in 0..views.len() {
        if seen[first / 64] >> (first % 64) & 1 != 0 {
            continue;
        }
        let mut at = first;
        let mut carry = std::mem::take(&mut views[at]);
        loop {
            seen[at / 64] |= 1 << (at % 64);
            let next = (at % columns) * rows + at / columns;
            carry = std::mem::replace(&mut views[next], carry);
            if next == first {
                break;
            }
            at = next;
        }
    }
}

/// The fixed parameters of one transform's sweeps.
#[derive(Clone, Copy)]
struct Schedule {
    origin: usize,
    inverse: bool,
    backend: crate::gf_simd::LinearBackend,
    radix4: bool,
}

/// What one butterfly does given which of its two rows are known zero
/// (forward `left ^= c·right; right ^= left`, inverse `right ^= left;
/// left ^= c·right`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    /// Both rows are zero and stay zero.
    Skip,
    /// The zero row stays zero and the other is unchanged: a zero factor.
    Keep,
    /// The left row is copied into the zero right row.
    Copy,
    /// Inverse only: the zero left row becomes the factor times the right.
    Scale,
    /// The whole butterfly.
    Full,
}

impl Step {
    /// The step for rows `[left, right]` known zero as flagged, with the
    /// flags after it. A flag stays set only where the row stays zero.
    fn of(zero: [bool; 2], factor_zero: bool, inverse: bool) -> (Self, [bool; 2]) {
        match (zero, inverse) {
            ([true, true], _) => (Self::Skip, zero),
            ([true, false], _) if factor_zero => (Self::Keep, zero),
            ([true, false], true) => (Self::Scale, [false; 2]),
            ([false, true], false) => (Self::Copy, [false; 2]),
            ([false, true], true) if factor_zero => (Self::Copy, [false; 2]),
            _ => (Self::Full, [false; 2]),
        }
    }
}

/// Carry the known-zero row flags `zero` across one sweep, reporting each
/// butterfly's step to `observe` in the order the sweep runs them.
fn advance(
    zero: &mut [bool],
    sweep: Sweep,
    origin: usize,
    inverse: bool,
    observe: &mut dyn FnMut(Step),
) {
    let levels = match (sweep, inverse) {
        (Sweep::Radix2(level), _) => [Some(level), None],
        (Sweep::Radix4(low), true) => [Some(low), Some(low + 1)],
        (Sweep::Radix4(low), false) => [Some(low + 1), Some(low)],
    };
    for level in levels.into_iter().flatten() {
        let half = 1 << level;
        for base in (0..zero.len()).step_by(half * 2) {
            let factor_zero = (origin ^ base) >> level == 0;
            for left in base..base + half {
                let (step, next) = Step::of([zero[left], zero[left + half]], factor_zero, inverse);
                observe(step);
                [zero[left], zero[left + half]] = next;
            }
        }
    }
}

/// Differentiate whole `rows` in place; see [`TransformField::derivative`].
fn derivative_rows<S: Lane, R: AsRef<[S]> + AsMut<[S]>>(
    rows: &mut [R],
    cancelled: &dyn Fn() -> bool,
) -> Result<(), TransformError> {
    let n = rows.len();
    // Coefficient `index` becomes the XOR of the coefficients one set bit
    // above it, all of which lie later in the rows, so ascending order
    // reads each before it is overwritten. Each target is stored once,
    // its sources folded two at a time, rather than cleared and then
    // rewritten once per source.
    for index in 0..n {
        if cancelled() {
            return Err(TransformError::Cancelled);
        }
        let (done, remaining) = rows.split_at_mut(index + 1);
        let mut sources = [&[] as &[S]; 16];
        let mut count = 0;
        for bit in (0..n.trailing_zeros()).filter(|bit| index & (1 << bit) == 0) {
            sources[count] = remaining[(index | (1 << bit)) - index - 1].as_ref();
            count += 1;
        }
        xor_sum(done[index].as_mut(), &sources[..count]);
    }
    Ok(())
}

/// Differentiate the equally wide rows `from`, one tile of a bank, into
/// `into`, as many rows as long, one after another; see
/// [`TransformField::derivative`]. Each row is stored once, the XOR of the
/// rows one set bit above it; rows `zero` flags by their index in `from`
/// hold zero and are not read.
fn derivative_views<S: Lane>(
    from: &[&mut [S]],
    into: &mut [S],
    zero: impl Fn(usize) -> bool,
    cancelled: &dyn Fn() -> bool,
) -> Result<(), TransformError> {
    let n = from.len();
    let width = from.first().map_or(0, |row| row.len());
    debug_assert!(into.len() == n * width);
    if width == 0 {
        return Ok(());
    }
    for (index, out) in into.chunks_exact_mut(width).enumerate() {
        if cancelled() {
            return Err(TransformError::Cancelled);
        }
        let mut sources = [&[] as &[S]; 16];
        let mut count = 0;
        for bit in (0..n.trailing_zeros()).filter(|bit| index & (1 << bit) == 0) {
            let source = index | (1 << bit);
            if !zero(source) {
                sources[count] = &*from[source];
                count += 1;
            }
        }
        xor_sum(out, &sources[..count]);
    }
    Ok(())
}

/// Add `from` into `into`, as long: the AVX2 form where it runs.
fn add_into<S: Lane>(into: &mut [S], from: &[S]) {
    #[cfg(target_arch = "x86_64")]
    if is_x86_feature_detected!("avx2") {
        // SAFETY: AVX2 was detected.
        unsafe { xor_into_avx2(into, from) };
        return;
    }
    xor_into(into, from);
}

/// Add the tile `views`, the rows of `place` at `columns`, into the same
/// columns of the same rows of `sum`, but for rows `after` flags known zero.
fn add_tile<S: Lane>(
    sum: &SharedRows<S>,
    views: &[&mut [S]],
    place: Place,
    columns: &std::ops::Range<usize>,
    after: Option<&Vec<bool>>,
) {
    for (k, view) in views.iter().enumerate() {
        let row = place.row(k);
        if after.is_some_and(|after| after[row]) {
            continue;
        }
        // SAFETY: the task adding this tile alone holds these columns of
        // these rows of `sum`; see `SharedRows::columns`.
        add_into(unsafe { sum.columns_mut(row, columns) }, view);
    }
}

/// Check that `sum`, when given, has a row as wide for every row of `rows`.
fn validate_sum<S, R: AsRef<[S]>, T: AsRef<[S]>>(
    rows: &[R],
    sum: Option<&[T]>,
) -> Result<(), TransformError> {
    if let Some(sum) = sum
        && (sum.len() != rows.len()
            || sum
                .iter()
                .zip(rows)
                .any(|(to, from)| to.as_ref().len() != from.as_ref().len()))
    {
        return Err(TransformError::Geometry);
    }
    Ok(())
}

/// XOR `from` into `into`, as long.
#[inline(always)]
fn xor_into<S: Lane>(into: &mut [S], from: &[S]) {
    for (into, &from) in into.iter_mut().zip(from) {
        *into ^= from;
    }
}

/// [`xor_into`] compiled for AVX2, which the vectorizer then uses.
///
/// # Safety
/// AVX2 must be available.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn xor_into_avx2<S: Lane>(into: &mut [S], from: &[S]) {
    xor_into(into, from)
}

/// The bytes of rows one tile of a tiled transform holds, at most: a bank
/// beyond this, on a target that tiles, runs a tile at a time; see
/// [`COLUMN_TILES`]. A tiled transform takes no scratch; a tiled
/// derivative, and each pass of [`TransformField::derivative_at`], takes
/// as much again per worker for what it computes beside the tile.
pub const TRANSFORM_TILE_BYTES: usize = 512 << 10;

/// What [`TransformField::derivative_at_bytes`] allows each worker beyond
/// its scratch and row lists, for the pool's handing it each pass.
const DERIVATIVE_WORKER_BYTES: usize = 2 << 10;

/// What [`TransformField::derivative_at_bytes`] allows a call beyond the
/// sweeps, flags and workers it counts: the lists of its prepared units
/// and the passes' small state.
const DERIVATIVE_CALL_BYTES: usize = 4 << 10;

/// Whether the transforms and derivatives of this target run a bank beyond
/// [`TRANSFORM_TILE_BYTES`] in column tiles, in place: each tile, a group
/// of rows at a window of columns, takes every sweep of a pass while it
/// stays in the cache. On x86_64 that runs a transform in two thirds to
/// three quarters of the time the whole-row sweeps take on one worker, and
/// in under half of it on eight, where the sweeps are bound by memory.
/// Apple silicon streams the whole-row sweeps about as fast as the tiles
/// run, on one worker and on a pool, so there every transform and
/// derivative sweeps whole rows, and a pool sweeps them a level at a time
/// across the workers. It is also the default for whether a caller takes
/// the split steps of [`TransformField::derivative_at`] at all, on one
/// worker as on a pool, since they tile the same way; see
/// [`derivative_at_walks`].
pub const COLUMN_TILES: bool = !cfg!(target_vendor = "apple");

/// Whether a transform of `n` rows `width` wide of `size`-byte symbols
/// (one for the 8-bit field's byte rows, two for 16-bit words), `inverse`
/// or forward with `backend`, on `threads` workers (one for the calling
/// thread alone, as without a pool), runs the bank in column tiles: a bank
/// beyond [`TRANSFORM_TILE_BYTES`] over three levels or more, on a target
/// that tiles, when every pass has a tile for every worker. Otherwise the
/// rows are swept whole, a level at a time, across the workers of a pool.
pub fn walks(
    n: usize,
    width: usize,
    size: usize,
    inverse: bool,
    backend: crate::gf_simd::LinearBackend,
    threads: usize,
) -> bool {
    let schedule = Schedule {
        origin: 0,
        inverse,
        backend,
        radix4: TransformField::fused(width, backend),
    };
    Walk::engaged(n, width, size, &schedule, threads.max(1)).is_some()
}

/// Where the rows of a tile's group come from: local row `k` is row
/// `first + k * stride` of the bank.
#[derive(Clone, Copy)]
struct Place {
    first: usize,
    stride: usize,
}

impl Place {
    /// The rows as they are: whole rows, in order.
    const WHOLE: Place = Place {
        first: 0,
        stride: 1,
    };

    /// The bank's row behind local row `k`.
    fn row(self, k: usize) -> usize {
        self.first + k * self.stride
    }
}

/// One pass of a walk over the bank: each task takes a tile, a group of
/// `rows` rows, consecutive or `stride` apart, at a window of `window`
/// columns, in place.
#[derive(Clone, Copy)]
struct Pass {
    window: usize,
    rows: usize,
    stride: usize,
}

impl Pass {
    /// One pass over every row of `n` rows `width` wide at once, with the
    /// widest window of whole cache lines whose scratch over every row
    /// fits `budget` bytes: none when the rows are no wider than that
    /// window, the domain is so tall that even one line a row overflows
    /// the budget, or the windows, or whole lines, would leave some of
    /// `threads` workers without one. The window is then no wider than the
    /// rows split across the workers, so their scratch together never
    /// exceeds the bank's worth.
    fn narrow<S: Lane>(n: usize, width: usize, budget: usize, threads: usize) -> Option<Pass> {
        let line = 64 / size_of::<S>();
        let window = (budget / (n * size_of::<S>()) / line * line).max(line);
        let share = width / line / threads.max(1);
        if window * n * size_of::<S>() > budget
            || width <= window
            || width.div_ceil(window) < threads
            || share == 0
        {
            return None;
        }
        Some(Pass {
            window: window.min(share * line),
            rows: n,
            stride: 1,
        })
    }

    /// The bank's row where local row 0 of group `group` lies.
    fn place(self, group: usize) -> Place {
        Place {
            first: if self.stride == 1 {
                group * self.rows
            } else {
                group
            },
            stride: self.stride,
        }
    }

    /// The tasks of this pass over `n` rows `width` wide.
    fn tasks(self, n: usize, width: usize) -> usize {
        (n / self.rows) * width.div_ceil(self.window)
    }
}

/// Where [`TransformField::derivative_at`] splits a domain's levels, and
/// the tile its passes take: `low` levels inside each block, the rest
/// inside each class, and a window of columns narrow enough for the larger
/// of the two groups and its derivative to stay in the cache.
#[derive(Clone, Copy)]
struct Split {
    low: u32,
    levels: u32,
    window: usize,
}

impl Split {
    /// The split for `n` rows `width` wide of `size`-byte symbols on
    /// `threads` workers: the levels halved, the window the widest run of
    /// whole 64-symbol runs the scratch holds twice over the larger group,
    /// and, with more workers than groups in the narrower pass, no wider
    /// than an even share of the width between the workers on each group,
    /// rounded up to whole runs; so a narrow width can still leave some
    /// workers without a tile. None below 16 rows, where a block or class
    /// would be under four, and for any `size` but 1 or 2.
    fn of(n: usize, width: usize, size: usize, threads: usize) -> Option<Split> {
        let levels = n.trailing_zeros();
        if !n.is_power_of_two() || levels < 4 || width == 0 || !(1..=2).contains(&size) {
            return None;
        }
        let low = levels / 2;
        let group = 1usize << (levels - low);
        let mut window = (TRANSFORM_TILE_BYTES / (2 * group * size) / 64 * 64).max(64);
        let groups = 1usize << low;
        if threads > groups {
            let share = width.div_ceil(threads.div_ceil(groups));
            window = window.min(share.checked_next_multiple_of(64).unwrap_or(share));
        }
        Some(Split {
            low,
            levels,
            window: window.min(width),
        })
    }

    /// Rows in the larger of a block and a class.
    fn group(self) -> usize {
        1 << (self.levels - self.low)
    }
}

/// What [`TransformField::derivative_at`] performed: transform calls and
/// the butterflies they ran.
///
/// The split steps count the whole inverse once, but the forward per class
/// and per block: one high half per class and two low halves for every
/// block holding a row read, one per term of the derivative. The forward
/// low half thus runs twice over each such block, so once more than half
/// the blocks hold a row read the butterflies exceed those of the two
/// whole transforms the separate steps run. The separate steps count two
/// transforms and their butterflies.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DerivativeWork {
    /// Additive transforms: the inverse, one forward high half per class,
    /// and two forward low halves per block holding a row read.
    pub transforms: u64,
    /// Butterflies across them, as performed.
    pub butterflies: u64,
}

/// Whether [`TransformField::derivative_at`] over `n` rows `width` wide of
/// `size`-byte symbols splits the domain and walks it in tiles, rather than
/// running the separate steps: from 16 rows of 1- or 2-byte symbols, and
/// only for a bank beyond [`TRANSFORM_TILE_BYTES`], where the passes it
/// saves are passes over memory rather than over the cache. It says nothing
/// of the target: a caller deciding whether to take the split steps at all,
/// with a pool or one worker alone, also asks [`COLUMN_TILES`].
pub fn derivative_at_walks(n: usize, width: usize, size: usize) -> bool {
    Split::of(n, width, size, 1).is_some()
        && n.saturating_mul(width).saturating_mul(size) > TRANSFORM_TILE_BYTES
}

/// How a transform of a bank beyond [`TRANSFORM_TILE_BYTES`] walks it: each
/// pass takes tiles, groups of rows at a window of columns, in place, and
/// runs a range of the sweeps over each tile while it stays in the cache.
/// The bank is thus read and written once per pass instead of once per
/// sweep, and the kernels run over whole windows. One pass over every row when the domain
/// is short enough for that window to be wide; otherwise two, split at a
/// level `h`: the sweeps below `h` touch only rows within one block of
/// `2^h` consecutive rows, and those at `h` and above only rows `2^h`
/// apart, so each pass takes those groups, in the order the sweeps run.
struct Walk {
    /// The window of every pass, in symbols; the units are built this wide.
    window: usize,
    /// The sweeps of each pass, in order, and the pass.
    passes: Vec<(std::ops::Range<usize>, Pass)>,
}

impl Walk {
    /// Rows at least this wide, in bytes, are walked in one pass.
    const WIDE_ROW_BYTES: usize = 2048;

    /// The tiles a transform of `schedule` over `n` rows `width` wide of
    /// `size`-byte symbols takes on `threads` workers: [`Self::of`] on a
    /// target that tiles, when every pass of it has tiles enough to keep
    /// the workers busy; otherwise none, and the rows are swept whole.
    fn engaged(
        n: usize,
        width: usize,
        size: usize,
        schedule: &Schedule,
        threads: usize,
    ) -> Option<Walk> {
        COLUMN_TILES
            .then(|| Self::of(n, width, size, schedule, threads))
            .flatten()
    }

    /// The walk of `schedule` over `n` rows `width` wide of `size`-byte
    /// symbols on `threads` workers: [`Self::planned`], when every pass of
    /// it has a tile per worker, with each window then no wider than the
    /// runs split across the workers a pass's groups leave without one, so
    /// the workers' tiles together never outreach the bank's rows rounded
    /// up to whole runs, whatever the tile size would let each take. None
    /// when there is no walk or its tiles would leave workers idle.
    fn of(
        n: usize,
        width: usize,
        size: usize,
        schedule: &Schedule,
        threads: usize,
    ) -> Option<Walk> {
        let mut walk = Self::planned(n, width, size, schedule)?;
        if walk.tasks(n, width) < threads {
            return None;
        }
        let share = |rows: usize| {
            let groups = n / rows;
            (width.div_ceil(64) / threads.max(1).div_ceil(groups)).max(1) * 64
        };
        let window = walk
            .passes
            .iter()
            .map(|(_, pass)| share(pass.rows))
            .fold(walk.window, usize::min);
        walk.window = window;
        for (_, pass) in &mut walk.passes {
            pass.window = window;
        }
        Some(walk)
    }

    /// The walk of `schedule` over `n` rows `width` wide of `size`-byte
    /// symbols with the widest tiles [`TRANSFORM_TILE_BYTES`] holds, or none
    /// when the bank fits one tile or the domain has fewer than three
    /// levels, so tiling would cost as much as the sweeps it saves.
    fn planned(n: usize, width: usize, size: usize, schedule: &Schedule) -> Option<Walk> {
        let budget = TRANSFORM_TILE_BYTES;
        let levels = n.trailing_zeros();
        if levels < 3 || n * width * size <= budget {
            return None;
        }
        let sweeps: Vec<Sweep> = sweeps(levels, schedule.inverse, schedule.radix4).collect();
        // The widest window of whole 64-symbol runs whose scratch over
        // `rows` rows fits; a pass never has rows enough for one run to
        // overflow it (at most twice the square root of the domain's, or a
        // whole domain short enough for wide rows).
        let window = |rows: usize| width.min((budget / (rows * size) / 64 * 64).max(64));
        let one = window(n);
        if one * size >= Self::WIDE_ROW_BYTES {
            let pass = Pass {
                window: one,
                rows: n,
                stride: 1,
            };
            return Some(Walk {
                window: one,
                passes: vec![(0..sweeps.len(), pass)],
            });
        }
        // The levels each sweep touches, and the level the sweeps `..s`
        // and `s..` are split at: the sweeps run from the top down forward
        // and from the bottom up inverse, so the split is wherever two
        // sweeps meet, and the one nearest the middle keeps both groups
        // short. A boundary always exists past the first sweep.
        let span = |sweep: &Sweep| match *sweep {
            Sweep::Radix2(level) => (level, level),
            Sweep::Radix4(low) => (low, low + 1),
        };
        let (s, h) = (1..sweeps.len())
            .map(|s| {
                let h = if schedule.inverse {
                    span(&sweeps[s]).0
                } else {
                    span(&sweeps[s]).1 + 1
                };
                (s, h)
            })
            .min_by_key(|&(_, h)| (2 * h).abs_diff(levels))
            .expect("a walk has at least two sweeps");
        let low = Pass {
            window: 0,
            rows: 1 << h,
            stride: 1,
        };
        let high = Pass {
            window: 0,
            rows: n >> h,
            stride: 1 << h,
        };
        let window = window(low.rows.max(high.rows));
        let widen = |pass: Pass| Pass { window, ..pass };
        let passes = if schedule.inverse {
            vec![(0..s, widen(low)), (s..sweeps.len(), widen(high))]
        } else {
            vec![(0..s, widen(high)), (s..sweeps.len(), widen(low))]
        };
        Some(Walk { window, passes })
    }

    /// The fewest tasks any pass has over `n` rows `width` wide.
    fn tasks(&self, n: usize, width: usize) -> usize {
        self.passes
            .iter()
            .map(|(_, pass)| pass.tasks(n, width))
            .min()
            .unwrap_or(0)
    }
}

/// One worker's share of `pass` over `shared`, in place: tasks taken from
/// `next` until none remain, each a tile, a group of `pass.rows` rows at a
/// window of columns, handed to `work` as one slice of each row, straight
/// into the bank, with `spare` symbols of scratch of this worker's own, where
/// the group lies and the columns it holds. A short last window is just
/// narrower. One worker alone runs every task in order; several share them,
/// and no two tasks of one pass share a symbol. `groups`, when given, names
/// the only groups the pass visits, in order.
#[allow(clippy::too_many_arguments)]
fn tile_tasks<S: Lane, C: Fn() -> bool + ?Sized>(
    shared: &SharedRows<S>,
    next: &std::sync::atomic::AtomicUsize,
    pass: Pass,
    groups: Option<&[usize]>,
    spare: usize,
    work: impl Fn(
        &mut [&mut [S]],
        &mut [S],
        Place,
        &std::ops::Range<usize>,
    ) -> Result<(), TransformError>,
    cancelled: &C,
) -> Result<(), TransformError> {
    use std::sync::atomic::Ordering;
    let (n, width) = (shared.0.len(), shared.1);
    let windows = width.div_ceil(pass.window);
    let tasks = groups.map_or_else(|| pass.tasks(n, width), |groups| groups.len() * windows);
    let mut spare = vec![S::default(); spare];
    let mut views = Vec::with_capacity(pass.rows);
    loop {
        let task = next.fetch_add(1, Ordering::Relaxed);
        if task >= tasks {
            return Ok(());
        }
        if cancelled() {
            return Err(TransformError::Cancelled);
        }
        let group = task / windows;
        let place = pass.place(groups.map_or(group, |groups| groups[group]));
        let at = task % windows;
        let columns = at * pass.window..width.min((at + 1) * pass.window);
        views.clear();
        // SAFETY: this task alone touches these columns of these rows, and
        // the group's rows are distinct; see `SharedRows::columns`.
        views.extend((0..pass.rows).map(|k| unsafe { shared.columns_mut(place.row(k), &columns) }));
        work(&mut views, &mut spare, place, &columns)?;
    }
}

/// The known-zero flags `schedule` finds before each of its sweeps over `n`
/// rows, and after the last, from the flags `zero` the caller gave; none
/// when the caller gave none.
fn sweep_flags(n: usize, zero: Option<&[bool]>, schedule: &Schedule) -> Option<Vec<Vec<bool>>> {
    let mut known = zero?.to_vec();
    let mut flags = Vec::new();
    for sweep in sweeps(n.trailing_zeros(), schedule.inverse, schedule.radix4) {
        flags.push(known.clone());
        advance(
            &mut known,
            sweep,
            schedule.origin,
            schedule.inverse,
            &mut |_| {},
        );
    }
    flags.push(known);
    Some(flags)
}

/// One radix-2 butterfly, prepared for its group: see [`TransformField::pair`].
type PairUnit<'a, S> = dyn Fn(&mut [S], &mut [S], [bool; 2]) + Sync + 'a;
/// One radix-4 unit, prepared for its group: see [`TransformField::quad`].
type QuadUnit<'a, S> = dyn Fn([&mut [S]; 4], [bool; 4]) + Sync + 'a;

/// The butterflies of one sweep, as [`TransformField::run_sweeps`] takes
/// them: the unit of each group of rows, numbered over the whole domain.
/// A sweep asks for a pair or a quad as its kind says.
trait Units<S: Lane> {
    fn sweep(&self) -> Sweep;
    fn pair(&self, group: usize) -> impl Fn(&mut [S], &mut [S], [bool; 2]) + '_;
    fn quad(&self, group: usize) -> impl Fn([&mut [S]; 4], [bool; 4]) + '_;
}

/// The units of one sweep prepared for every group and kept, for the tiled
/// walk to run over every tile.
enum KeptUnits<'a, S> {
    Radix2(u32, Vec<Box<PairUnit<'a, S>>>),
    Radix4(u32, Vec<Box<QuadUnit<'a, S>>>),
}

impl<S: Lane> Units<S> for KeptUnits<'_, S> {
    fn sweep(&self) -> Sweep {
        match self {
            Self::Radix2(level, _) => Sweep::Radix2(*level),
            Self::Radix4(low, _) => Sweep::Radix4(*low),
        }
    }
    fn pair(&self, group: usize) -> impl Fn(&mut [S], &mut [S], [bool; 2]) + '_ {
        match self {
            Self::Radix2(_, pairs) => &*pairs[group],
            Self::Radix4(..) => unreachable!("a radix-4 sweep runs quads"),
        }
    }
    fn quad(&self, group: usize) -> impl Fn([&mut [S]; 4], [bool; 4]) + '_ {
        match self {
            Self::Radix4(_, quads) => &*quads[group],
            Self::Radix2(..) => unreachable!("a radix-2 sweep runs pairs"),
        }
    }
}

/// The units of one sweep made as each group comes, for a sequential
/// transform over whole rows, which runs each once and keeps nothing.
struct FreshUnits<'a> {
    field: &'a TransformField,
    schedule: &'a Schedule,
    sweep: Sweep,
    width: usize,
}

impl<S: Lane> Units<S> for FreshUnits<'_> {
    fn sweep(&self) -> Sweep {
        self.sweep
    }
    fn pair(&self, group: usize) -> impl Fn(&mut [S], &mut [S], [bool; 2]) + '_ {
        let Sweep::Radix2(level) = self.sweep else {
            unreachable!("a radix-4 sweep runs quads")
        };
        self.field
            .pair(self.schedule, level, group << (level + 1), self.width)
    }
    fn quad(&self, group: usize) -> impl Fn([&mut [S]; 4], [bool; 4]) + '_ {
        let Sweep::Radix4(low) = self.sweep else {
            unreachable!("a radix-2 sweep runs pairs")
        };
        self.field.quad(self.schedule, group << (low + 2), low)
    }
}

/// One sweep over every row: a radix-2 stage at a level, or the stages
/// `low + 1` and `low` fused into one radix-4 sweep.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sweep {
    Radix2(u32),
    Radix4(u32),
}

/// The stage order of a transform over `2^levels` rows, widest level first
/// forward and narrowest first inverse, grouped into radix-4 sweeps of two
/// consecutive stages when `radix4` is set. An odd stage count leaves the
/// last stage as a radix-2 sweep. Every grouping runs the same butterflies in
/// the same order relative to the rows each one touches.
fn sweeps(levels: u32, inverse: bool, radix4: bool) -> impl Iterator<Item = Sweep> {
    let mut stage = 0;
    std::iter::from_fn(move || {
        if stage >= levels {
            return None;
        }
        let fused = radix4 && levels - stage >= 2;
        let sweep = match (fused, inverse) {
            (true, true) => Sweep::Radix4(stage),
            (true, false) => Sweep::Radix4(levels - 2 - stage),
            (false, true) => Sweep::Radix2(stage),
            (false, false) => Sweep::Radix2(levels - 1 - stage),
        };
        stage += if fused { 2 } else { 1 };
        Some(sweep)
    })
}

/// [`sweeps`] of the levels `from..to` alone of a larger transform, in the
/// same order and grouping a transform over `2^(to - from)` rows takes.
fn sweeps_between(from: u32, to: u32, inverse: bool, radix4: bool) -> impl Iterator<Item = Sweep> {
    sweeps(to - from, inverse, radix4).map(move |sweep| match sweep {
        Sweep::Radix2(level) => Sweep::Radix2(level + from),
        Sweep::Radix4(low) => Sweep::Radix4(low + from),
    })
}

/// Equally wide rows, taken mutably for the duration of a tiled walk or a
/// pooled derivative whose tasks each touch only their own range of columns.
struct SharedRows<S>(Vec<*mut S>, usize);

// SAFETY: the pointers come from an exclusive borrow of the rows held for as
// long as this exists, and every access goes through the methods below,
// whose callers keep concurrent slices disjoint.
unsafe impl<S: Send + Sync> Sync for SharedRows<S> {}

impl<S> SharedRows<S> {
    /// The rows, which the caller leaves alone while this lives: one pointer
    /// per row, the same size as the row handles themselves.
    fn of<R: AsMut<[S]>>(rows: &mut [R]) -> Self {
        let width = rows.first_mut().map_or(0, |row| row.as_mut().len());
        Self(
            rows.iter_mut()
                .map(|row| row.as_mut().as_mut_ptr())
                .collect(),
            width,
        )
    }

    /// Columns `columns` of row `row`.
    ///
    /// # Safety
    /// `row` must be in bounds and `columns` within the width, and no mutable
    /// slice may overlap the result while it lives. A tiled walk gives each
    /// task its own columns; a pooled derivative does too, and within them
    /// reads only rows past the one it writes.
    unsafe fn columns(&self, row: usize, columns: &std::ops::Range<usize>) -> &[S] {
        debug_assert!(columns.end <= self.1);
        // SAFETY: as documented above.
        unsafe { std::slice::from_raw_parts(self.0[row].add(columns.start), columns.len()) }
    }

    /// [`Self::columns`], mutably.
    ///
    /// # Safety
    /// As for [`Self::columns`], and no other slice may overlap the result.
    #[allow(clippy::mut_from_ref)]
    unsafe fn columns_mut(&self, row: usize, columns: &std::ops::Range<usize>) -> &mut [S] {
        debug_assert!(columns.end <= self.1);
        // SAFETY: as documented above.
        unsafe { std::slice::from_raw_parts_mut(self.0[row].add(columns.start), columns.len()) }
    }
}

/// Store the XOR of `sources` (zero when there are none) in `out`, which is
/// written once. With AVX2 every source (the derivative hands at most one per
/// bit of a row index, so 16) is folded into each 64-byte block in one pass;
/// the portable fold, which also finishes the AVX2 remainder and takes any
/// longer list, folds two sources per pass. Sources must be as long as `out`.
fn xor_sum<S: Lane>(out: &mut [S], sources: &[&[S]]) {
    #[cfg(target_arch = "x86_64")]
    if (2..=16).contains(&sources.len()) && is_x86_feature_detected!("avx2") {
        assert!(sources.iter().all(|source| source.len() == out.len()));
        let bytes = |values: &[S]| {
            // SAFETY: `Lane` is implemented only for `u8` and `u16`, plain
            // integers without padding; their bytes are initialized.
            unsafe { std::slice::from_raw_parts(values.as_ptr().cast::<u8>(), size_of_val(values)) }
        };
        let mut views = [&[] as &[u8]; 16];
        for (view, source) in views.iter_mut().zip(sources) {
            *view = bytes(source);
        }
        let length = size_of_val(out);
        // SAFETY: AVX2 was detected; `out` is exclusively borrowed, so its
        // byte view aliases nothing, and every byte pattern is a value of
        // either lane type. All views are `length` bytes long.
        let done = unsafe {
            xor_sum_avx2(
                std::slice::from_raw_parts_mut(out.as_mut_ptr().cast::<u8>(), length),
                &views[..sources.len()],
            )
        } / size_of::<S>();
        let mut tails = [&[] as &[S]; 16];
        for (tail, source) in tails.iter_mut().zip(sources) {
            *tail = &source[done..];
        }
        return xor_sum_portable(&mut out[done..], &tails[..sources.len()]);
    }
    xor_sum_portable(out, sources)
}

/// Store the XOR of at least two equally long `sources` in `out`, each
/// 64-byte block loaded from every source and stored once; returns the bytes
/// done, a multiple of 64.
///
/// # Safety
/// AVX2 must be available and every source must be as long as `out`.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn xor_sum_avx2(out: &mut [u8], sources: &[&[u8]]) -> usize {
    use std::arch::x86_64::*;
    let [first, rest @ ..] = sources else {
        return 0;
    };
    let mut at = 0;
    while out.len() - at >= 64 {
        // SAFETY: `out` and, by the caller's contract, every source hold 64
        // bytes from `at`.
        unsafe {
            let mut low = _mm256_loadu_si256(first.as_ptr().add(at).cast());
            let mut high = _mm256_loadu_si256(first.as_ptr().add(at + 32).cast());
            for source in rest {
                low = _mm256_xor_si256(low, _mm256_loadu_si256(source.as_ptr().add(at).cast()));
                high = _mm256_xor_si256(
                    high,
                    _mm256_loadu_si256(source.as_ptr().add(at + 32).cast()),
                );
            }
            _mm256_storeu_si256(out.as_mut_ptr().add(at).cast(), low);
            _mm256_storeu_si256(out.as_mut_ptr().add(at + 32).cast(), high);
        }
        at += 64;
    }
    at
}

/// [`xor_sum`] on the portable path, folding two sources per pass.
fn xor_sum_portable<S: Lane>(out: &mut [S], sources: &[&[S]]) {
    match sources {
        [] => out.fill(S::default()),
        [only] => out.copy_from_slice(only),
        [first, second, rest @ ..] => {
            for ((to, &a), &b) in out.iter_mut().zip(*first).zip(*second) {
                *to = a ^ b;
            }
            for pair in rest.chunks(2) {
                match pair {
                    [a, b] => {
                        for ((to, &a), &b) in out.iter_mut().zip(*a).zip(*b) {
                            *to ^= a ^ b;
                        }
                    }
                    [a] => {
                        for (to, &a) in out.iter_mut().zip(*a) {
                            *to ^= a;
                        }
                    }
                    _ => unreachable!("chunks of two"),
                }
            }
        }
    }
}

/// Split a radix-4 group into its four equal quarters.
fn quarters<T>(group: &mut [T]) -> [&mut [T]; 4] {
    let (front, back) = group.split_at_mut(group.len() / 2);
    let (a, b) = front.split_at_mut(front.len() / 2);
    let (c, d) = back.split_at_mut(back.len() / 2);
    [a, b, c, d]
}

fn walsh(
    values: &mut [u64],
    modulus: u64,
    cancelled: &dyn Fn() -> bool,
) -> Result<(), TransformError> {
    let mut half = 1;
    while half < values.len() {
        for group in values.chunks_exact_mut(half * 2) {
            if cancelled() {
                return Err(TransformError::Cancelled);
            }
            let (left, right) = group.split_at_mut(half);
            for (a, b) in left.iter_mut().zip(right) {
                let sum = (*a + *b) % modulus;
                *b = (*a + modulus - *b) % modulus;
                *a = sum;
            }
        }
        half *= 2;
    }
    Ok(())
}

/// The symbols a [`RowBank`] holds: the 8-bit field's bytes and the 16-bit
/// field's words. Sealed.
pub trait Symbol: Copy + Default + Send + Sync + sealed::Sealed + 'static {}

impl Symbol for u8 {}
impl Symbol for u16 {}

mod sealed {
    pub trait Sealed {}
    impl Sealed for u8 {}
    impl Sealed for u16 {}
}

/// Equally wide rows of symbols in one zeroed, page-aligned allocation, row
/// after row: a transform bank without an allocation, a header and a page
/// boundary per row. [`Self::rows_mut`] hands out one slice per row, which
/// every row-slice method of [`TransformField`] takes.
///
/// A row whose bytes are a whole multiple of 512 is followed by a cache
/// line of padding, at most [`Self::ROW_PAD`] bytes, so rows a power of two
/// apart do not start in the same cache set: a tile of such rows, which a
/// tiled transform runs in place, would otherwise evict itself from the
/// cache's ways long before it outgrew its capacity.
///
/// The memory comes from the allocator zeroed, so a bank costs no pass over
/// its rows to clear them, and pages no row has touched yet need not be
/// resident.
pub struct RowBank<S: Symbol> {
    base: std::ptr::NonNull<S>,
    rows: usize,
    width: usize,
    bytes: usize,
    /// The mapping behind a bank of [`HUGE_PAGE_BYTES`] or more on Linux
    /// x86_64, which owns the memory in place of the allocator.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    mapping: Option<memmap2::MmapMut>,
}

/// The bytes of a transparent huge page: a bank at least this large on
/// Linux x86_64 is mapped on its own and asks for huge pages, so a tile's
/// rows, each in a page of its own at base pages, share a handful of
/// translations instead of taking one each.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const HUGE_PAGE_BYTES: usize = 2 << 20;

// SAFETY: a bank owns its symbols, which are plain integers; shared and
// exclusive access go through `&self` and `&mut self` as for a `Vec`.
unsafe impl<S: Symbol> Send for RowBank<S> {}
// SAFETY: as above.
unsafe impl<S: Symbol> Sync for RowBank<S> {}

impl<S: Symbol> RowBank<S> {
    /// The alignment of a bank's first row: a page on every target this
    /// crate serves, and a multiple of every cache line.
    pub const ALIGN: usize = 4096;

    /// The most padding a bank puts after each row, in bytes.
    pub const ROW_PAD: usize = 64;

    /// The symbols from the start of one row to the start of the next.
    fn pitch(width: usize) -> Option<usize> {
        let bytes = width.checked_mul(size_of::<S>())?;
        Some(if bytes != 0 && bytes.is_multiple_of(512) {
            width + Self::ROW_PAD / size_of::<S>()
        } else {
            width
        })
    }

    /// The bytes a bank of `rows` rows `width` symbols wide allocates: the
    /// rows and their padding, rounded up to whole pages. None when that
    /// overflows. Never more than `rows * (width * size + ROW_PAD)` rounded
    /// up to a page.
    #[must_use]
    pub fn allocation_bytes(rows: usize, width: usize) -> Option<usize> {
        rows.checked_mul(Self::pitch(width)?)?
            .checked_mul(size_of::<S>())?
            .checked_next_multiple_of(Self::ALIGN)
    }

    /// A bank of `rows` rows `width` symbols wide, every symbol zero. None
    /// when its size overflows or the allocator refuses it.
    #[must_use]
    pub fn zeroed(rows: usize, width: usize) -> Option<Self> {
        let bytes = Self::allocation_bytes(rows, width)?;
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        if bytes >= HUGE_PAGE_BYTES {
            // An anonymous mapping is zeroed and page-aligned; the advice is
            // a hint, and the bank works the same without it.
            let mut mapping = memmap2::MmapMut::map_anon(bytes).ok()?;
            let _ = mapping.advise(memmap2::Advice::HugePage);
            let base = std::ptr::NonNull::new(mapping.as_mut_ptr().cast::<S>())?;
            return Some(Self {
                base,
                rows,
                width,
                bytes,
                mapping: Some(mapping),
            });
        }
        let base = if bytes == 0 {
            std::ptr::NonNull::dangling()
        } else {
            let layout = std::alloc::Layout::from_size_align(bytes, Self::ALIGN).ok()?;
            // SAFETY: the layout has a nonzero size.
            std::ptr::NonNull::new(unsafe { std::alloc::alloc_zeroed(layout) }.cast::<S>())?
        };
        Some(Self {
            base,
            rows,
            width,
            bytes,
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            mapping: None,
        })
    }

    /// Rows in the bank.
    #[must_use]
    pub fn rows(&self) -> usize {
        self.rows
    }

    /// Symbols in each row.
    #[must_use]
    pub fn width(&self) -> usize {
        self.width
    }

    /// The symbols from the start of one row to the start of the next.
    fn stride(&self) -> usize {
        Self::pitch(self.width).expect("a pitch that fitted when the bank was made")
    }

    /// Every symbol, row after row with each row's padding.
    fn symbols_mut(&mut self) -> &mut [S] {
        let len = self.rows * self.stride();
        // SAFETY: the allocation holds `rows * stride` symbols, zeroed when
        // made and initialized ever since, and `&mut self` makes this the
        // only reference to them; a bank of no bytes has a dangling, aligned
        // base and no symbols.
        unsafe { std::slice::from_raw_parts_mut(self.base.as_ptr(), len) }
    }

    /// Row `row`.
    ///
    /// # Panics
    /// When `row` is not below [`Self::rows`].
    #[must_use]
    pub fn row(&self, row: usize) -> &[S] {
        assert!(row < self.rows, "row {row} of a bank of {}", self.rows);
        // SAFETY: as in `symbols_mut`, for shared access to one row.
        unsafe {
            std::slice::from_raw_parts(self.base.as_ptr().add(row * self.stride()), self.width)
        }
    }

    /// One slice per row, in order, each [`Self::width`] symbols.
    pub fn rows_mut(&mut self) -> Vec<&mut [S]> {
        let (rows, width, stride) = (self.rows, self.width, self.stride());
        if width == 0 {
            return (0..rows).map(|_| <&mut [S]>::default()).collect();
        }
        self.symbols_mut()
            .chunks_exact_mut(stride)
            .map(|row| &mut row[..width])
            .collect()
    }
}

impl<S: Symbol> Drop for RowBank<S> {
    fn drop(&mut self) {
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        if self.mapping.is_some() {
            return;
        }
        if self.bytes != 0 {
            let layout = std::alloc::Layout::from_size_align(self.bytes, Self::ALIGN)
                .expect("the layout the bank was allocated with");
            // SAFETY: allocated in `zeroed` with this layout.
            unsafe { std::alloc::dealloc(self.base.as_ptr().cast(), layout) };
        }
    }
}

impl<S: Symbol + std::fmt::Debug> std::fmt::Debug for RowBank<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RowBank")
            .field("rows", &self.rows)
            .field("width", &self.width)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn four_step_is_admitted_on_amd_with_the_avx2_kernels_only() {
        use crate::gf_simd::LinearKernel;
        for kernel in [
            LinearKernel::Scalar,
            LinearKernel::Neon,
            LinearKernel::Ssse3,
            LinearKernel::Avx2,
        ] {
            assert!(!four_step_admits(false, kernel), "{kernel:?}");
            assert_eq!(
                four_step_admits(true, kernel),
                kernel == LinearKernel::Avx2,
                "{kernel:?}"
            );
        }
        assert!(!four_step_preferred(crate::gf_simd::LinearBackend::Scalar));
    }
    #[test]
    fn four_step_runs_only_where_it_measured_faster() {
        let mut field = TransformField::new(16).unwrap();
        assert!(!field.four_step_runs(1 << 12, 64 << 10, true));
        field.set_four_step(true);
        // On a pool: more than 2^6 rows, at any width.
        assert!(!field.four_step_runs(64, 64 << 10, true));
        assert!(field.four_step_runs(128, 1 << 10, true));
        // On one thread: rows of 16 KiB or more, at any count.
        assert!(!field.four_step_runs(1 << 15, 1 << 10, false));
        assert!(!field.four_step_runs(1 << 15, (16 << 10) - 2, false));
        assert!(field.four_step_runs(16, 16 << 10, false));
        assert!(!field.four_step_runs(1, 64 << 10, false));
    }
    #[test]
    fn four_step_matches_existing_transform_across_sizes_and_cosets() {
        use crate::gf_simd::LinearBackend;
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .unwrap();
        for bits in [8, 16] {
            let baseline = TransformField::new(bits).unwrap();
            let mut field = TransformField::new(bits).unwrap();
            field.set_four_step(true);
            for count in [8, 32, 128, 512, 8192] {
                if count > baseline.order() {
                    continue;
                }
                // Wide enough that the serial path takes four-step too.
                let width = if count <= 512 { 8 << 10 } else { 8 };
                let zero: Vec<_> = (0..count).map(|i| i % 5 < 2).collect();
                let original: Vec<Vec<u16>> = (0..count)
                    .map(|r| {
                        (0..width)
                            .map(|c| {
                                if zero[r] {
                                    0
                                } else {
                                    ((r * 7919 + c * 103) % baseline.order()) as u16
                                }
                            })
                            .collect()
                    })
                    .collect();
                for origin in [0, baseline.order() - count] {
                    for inverse in [false, true] {
                        let mut expected = original.clone();
                        baseline
                            .transform(&mut expected, origin, inverse, &|| false)
                            .unwrap();
                        let mut actual = original.clone();
                        field
                            .transform_known_zero_with_backend(
                                &mut actual,
                                &zero,
                                origin,
                                inverse,
                                LinearBackend::Auto,
                                &|| false,
                            )
                            .unwrap();
                        assert_eq!(actual, expected, "{bits} {count} {origin} {inverse}");
                        let mut actual = original.clone();
                        field
                            .transform_known_zero_in_pool(
                                &mut actual,
                                &zero,
                                origin,
                                inverse,
                                LinearBackend::Auto,
                                &pool,
                                &|| false,
                            )
                            .unwrap();
                        assert_eq!(actual, expected, "{bits} {count} {origin} {inverse} pool");
                        if bits == 8 {
                            let mut bytes: Vec<Vec<u8>> = original
                                .iter()
                                .map(|r| r.iter().map(|&v| v as u8).collect())
                                .collect();
                            field
                                .transform_u8_known_zero_in_pool(
                                    &mut bytes,
                                    &zero,
                                    origin,
                                    inverse,
                                    LinearBackend::Auto,
                                    &pool,
                                    &|| false,
                                )
                                .unwrap();
                            assert_eq!(widen(&bytes), expected);
                        }
                    }
                }
            }
        }
    }
    #[test]
    fn transforms_match_direct_polynomial_evaluation_and_round_trip() {
        for bits in [8, 16] {
            let field = TransformField::new(bits).unwrap();
            let original: Vec<Vec<u16>> = (0..16).map(|i| vec![(i * 13) as u16]).collect();
            for origin in [0, 16, 64] {
                let mut rows = original.clone();
                field
                    .transform(&mut rows, origin, false, &|| false)
                    .unwrap();
                for (at, row) in rows.iter().enumerate() {
                    let x = (origin + at) as u16;
                    let expected =
                        original
                            .iter()
                            .enumerate()
                            .fold(0, |sum, (index, coefficient)| {
                                let mut basis = 1;
                                let mut subspace = x;
                                for bit in 0..4 {
                                    if index & (1 << bit) != 0 {
                                        basis = field.mul(basis, subspace);
                                    }
                                    subspace = field.mul(subspace, subspace) ^ subspace;
                                }
                                sum ^ field.mul(coefficient[0], basis)
                            });
                    assert_eq!(
                        row[0], expected,
                        "field {bits}, origin {origin}, position {at}"
                    );
                }
                field.transform(&mut rows, origin, true, &|| false).unwrap();
                assert_eq!(rows, original);
            }
        }
    }
    #[test]
    fn dispatched_scaling_matches_field_products_and_cancellation_boundaries() {
        use crate::gf_simd::LinearBackend;
        for bits in [8, 16] {
            let field = TransformField::new(bits).unwrap();
            let original = (0..field.order()).map(|v| v as u16).collect::<Vec<_>>();
            let factors = if bits == 8 {
                (0..256).collect::<Vec<u16>>()
            } else {
                vec![0, 1, 2, 42, 32768, 65535]
            };
            for factor in factors {
                let expected = original
                    .iter()
                    .map(|&v| field.mul(v, factor))
                    .collect::<Vec<_>>();
                let mut actual = original.clone();
                field
                    .scale_with_backend(&mut actual, factor, LinearBackend::Auto, &|| false)
                    .unwrap();
                assert_eq!(actual, expected);
            }
            for width in [0, 1, 15, 16, 31, 32, 63, 64, 65, 255, 256, 257, 4097] {
                let mut scalar = (0..width)
                    .map(|v| (v % field.order()) as u16)
                    .collect::<Vec<_>>();
                let mut dispatched = scalar.clone();
                field
                    .scale_with_backend(&mut scalar, 42, LinearBackend::Scalar, &|| false)
                    .unwrap();
                field
                    .scale_with_backend(&mut dispatched, 42, LinearBackend::Auto, &|| false)
                    .unwrap();
                assert_eq!(scalar, dispatched);
            }
            let calls = std::cell::Cell::new(0);
            let mut values = vec![1; 1024];
            assert_eq!(
                field.scale_with_backend(&mut values, 2, LinearBackend::Auto, &|| {
                    calls.set(calls.get() + 1);
                    // Initial check, four validation chunks on the 8-bit
                    // field (every word is a 16-bit symbol), one scaled chunk.
                    calls.get() == if bits == 8 { 7 } else { 3 }
                }),
                Err(TransformError::Cancelled)
            );
            assert!(values[..256].iter().all(|&v| v == 2));
            assert!(values[256..].iter().all(|&v| v == 1));
        }
        let field = TransformField::new(8).unwrap();
        let mut invalid = [1, 256];
        assert_eq!(
            field.scale_with_backend(&mut invalid, 2, LinearBackend::Auto, &|| false),
            Err(TransformError::Geometry)
        );
        assert_eq!(invalid, [1, 256]);
    }

    #[test]
    fn dispatched_transforms_match_scalar_at_simd_boundaries_and_cosets() {
        use crate::gf_simd::LinearBackend;
        for bits in [8, 16] {
            let field = TransformField::new(bits).unwrap();
            for width in [0, 1, 15, 16, 31, 32, 63, 64, 65, 127, 129] {
                let original: Vec<Vec<u16>> = (0..32)
                    .map(|row| {
                        (0..width)
                            .map(|at| ((row * 7919 + at * 103) % field.order()) as u16)
                            .collect()
                    })
                    .collect();
                for origin in [0, 32, field.order() - 32] {
                    let mut expected = original.clone();
                    field
                        .transform_with_backend(
                            &mut expected,
                            origin,
                            false,
                            LinearBackend::Scalar,
                            &|| false,
                        )
                        .unwrap();
                    let mut actual = original.clone();
                    field
                        .transform(&mut actual, origin, false, &|| false)
                        .unwrap();
                    assert_eq!(
                        actual, expected,
                        "bits {bits}, width {width}, origin {origin}"
                    );
                    field
                        .transform(&mut actual, origin, true, &|| false)
                        .unwrap();
                    assert_eq!(actual, original);
                }
            }
        }
    }

    fn random_bytes(count: usize, seed: u64) -> Vec<u8> {
        let mut state = seed | 1;
        (0..count)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect()
    }

    fn widen(rows: &[Vec<u8>]) -> Vec<Vec<u16>> {
        rows.iter()
            .map(|row| row.iter().map(|&value| value.into()).collect())
            .collect()
    }

    /// Every factor of the 8-bit Cantor field, every byte value, on the
    /// dispatched kernel and the scalar table walk, at lengths and offsets
    /// that leave every vector tail and an unaligned start.
    #[test]
    fn byte_maps_match_cantor_products_for_every_factor_and_kernel() {
        use crate::gf_simd::LinearBackend;
        let field = TransformField::new(8).unwrap();
        let source: Vec<u8> = (0..1100u32).map(|i| (i * 167 + i / 5) as u8).collect();
        let seed = random_bytes(1100, 0x5eed);
        for factor in 0..256u16 {
            for backend in [LinearBackend::Auto, LinearBackend::Scalar] {
                let map = <u8 as Lane>::map(&field, factor, backend);
                for offset in [0usize, 1, 3] {
                    for length in [
                        0, 1, 2, 7, 15, 16, 17, 31, 32, 33, 63, 64, 65, 255, 256, 257, 1024,
                    ] {
                        let input = &source[offset..offset + length];
                        let mut actual = seed[offset..offset + length].to_vec();
                        map.accumulate(input, &mut actual);
                        let expected: Vec<u8> = seed[offset..offset + length]
                            .iter()
                            .zip(input)
                            .map(|(&to, &from)| to ^ field.mul(from.into(), factor) as u8)
                            .collect();
                        assert_eq!(
                            actual, expected,
                            "factor {factor}, {backend:?}, offset {offset}, length {length}"
                        );
                    }
                }
            }
        }
    }

    /// The byte lane against the 16-bit lane on the same 8-bit symbols: every
    /// transform direction, coset, backend and width either side of the
    /// vector and plan thresholds, including widths below one vector.
    #[test]
    fn byte_rows_transform_exactly_like_word_rows() {
        use crate::gf_simd::LinearBackend;
        let field = TransformField::new(8).unwrap();
        for count in [2usize, 4, 16, 64, 256] {
            for width in [0usize, 1, 3, 15, 16, 17, 33, 63, 64, 65, 127, 129, 1000] {
                let original: Vec<Vec<u8>> = (0..count)
                    .map(|row| random_bytes(width, (count * 7919 + width * 131 + row) as u64))
                    .collect();
                let origins = [0, count, 256 - count];
                for origin in origins.into_iter().filter(|origin| origin + count <= 256) {
                    for inverse in [false, true] {
                        let mut reference = widen(&original);
                        field
                            .transform_with_backend(
                                &mut reference,
                                origin,
                                inverse,
                                LinearBackend::Scalar,
                                &|| false,
                            )
                            .unwrap();
                        for backend in [LinearBackend::Scalar, LinearBackend::Auto] {
                            let mut words = widen(&original);
                            field
                                .transform_with_backend(
                                    &mut words,
                                    origin,
                                    inverse,
                                    backend,
                                    &|| false,
                                )
                                .unwrap();
                            assert_eq!(words, reference);
                            let mut bytes = original.clone();
                            field
                                .transform_u8_with_backend(
                                    &mut bytes,
                                    origin,
                                    inverse,
                                    backend,
                                    &|| false,
                                )
                                .unwrap();
                            assert_eq!(
                                widen(&bytes),
                                reference,
                                "{count} rows of {width}, origin {origin}, \
                                 inverse {inverse}, {backend:?}"
                            );
                        }
                    }
                }
            }
        }
    }

    /// The pooled byte transform splits work across threads at 64 KiB of row
    /// storage; both sides of that cutoff must still match the word lane.
    #[test]
    fn pooled_byte_rows_transform_exactly_like_word_rows() {
        use crate::gf_simd::LinearBackend;
        let field = TransformField::new(8).unwrap();
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .unwrap();
        for (count, width) in [(256usize, 100usize), (256, 300), (128, 1031), (64, 4096)] {
            let original: Vec<Vec<u8>> = (0..count)
                .map(|row| random_bytes(width, (row * 31 + width) as u64))
                .collect();
            for inverse in [false, true] {
                for backend in [LinearBackend::Scalar, LinearBackend::Auto] {
                    let mut words = widen(&original);
                    field
                        .transform_in_pool(&mut words, 0, inverse, backend, &pool, &|| false)
                        .unwrap();
                    let mut bytes = original.clone();
                    field
                        .transform_u8_in_pool(&mut bytes, 0, inverse, backend, &pool, &|| false)
                        .unwrap();
                    assert_eq!(widen(&bytes), words, "{count}x{width} {backend:?}");
                }
            }
        }
    }

    #[test]
    fn byte_scaling_and_derivative_match_the_word_lane() {
        use crate::gf_simd::LinearBackend;
        let field = TransformField::new(8).unwrap();
        for width in [0usize, 1, 15, 16, 63, 64, 65, 255, 256, 257, 4097] {
            let original = random_bytes(width, width as u64 + 3);
            for factor in 0..256u16 {
                for backend in [LinearBackend::Scalar, LinearBackend::Auto] {
                    let mut words: Vec<u16> = original.iter().map(|&v| v.into()).collect();
                    field
                        .scale_with_backend(&mut words, factor, backend, &|| false)
                        .unwrap();
                    let mut bytes = original.clone();
                    field
                        .scale_u8_with_backend(&mut bytes, factor, backend, &|| false)
                        .unwrap();
                    assert!(
                        bytes.iter().zip(&words).all(|(&b, &w)| u16::from(b) == w),
                        "width {width}, factor {factor}, {backend:?}"
                    );
                }
            }
        }
        for count in [1usize, 2, 32, 256] {
            let original: Vec<Vec<u8>> = (0..count)
                .map(|row| random_bytes(77, row as u64 + 11))
                .collect();
            let mut words = widen(&original);
            field.derivative(&mut words, &|| false).unwrap();
            let mut bytes = original.clone();
            field.derivative_u8(&mut bytes, &|| false).unwrap();
            assert_eq!(widen(&bytes), words);
        }
    }

    /// Byte rows exist only for the 8-bit field, and byte scaling has no
    /// validation pass: one initial check, then one per 256-byte chunk.
    #[test]
    fn byte_lane_rejects_the_16_bit_field_and_checks_cancellation_per_chunk() {
        use crate::gf_simd::LinearBackend;
        let wide = TransformField::new(16).unwrap();
        let mut rows = vec![vec![0u8; 4]; 4];
        let never = || false;
        assert_eq!(
            wide.transform_u8_with_backend(&mut rows, 0, false, LinearBackend::Auto, &never),
            Err(TransformError::Field)
        );
        assert_eq!(
            wide.derivative_u8(&mut rows, &never),
            Err(TransformError::Field)
        );
        assert_eq!(
            wide.scale_u8_with_backend(&mut rows[0], 2, LinearBackend::Auto, &never),
            Err(TransformError::Field)
        );
        let field = TransformField::new(8).unwrap();
        assert_eq!(
            field.scale_u8_with_backend(&mut rows[0], 256, LinearBackend::Auto, &never),
            Err(TransformError::Geometry)
        );
        let calls = std::cell::Cell::new(0);
        let mut values = vec![1u8; 1024];
        assert_eq!(
            field.scale_u8_with_backend(&mut values, 2, LinearBackend::Auto, &|| {
                calls.set(calls.get() + 1);
                // Initial check, one scaled chunk, then the second chunk's.
                calls.get() == 3
            }),
            Err(TransformError::Cancelled)
        );
        let two = field.mul(1, 2) as u8;
        assert!(values[..256].iter().all(|&v| v == two));
        assert!(values[256..].iter().all(|&v| v == 1));
    }

    /// Radix-4 sweeps against radix-2 sweeps on the same dispatched kernels,
    /// and both against the scalar table-walk oracle: every power-of-two row
    /// count of each field (odd stage counts end on a radix-2 sweep), both
    /// directions, the first, second and last coset, and widths below one
    /// vector, at vector multiples and with odd tails. Radix-2 sweeps take
    /// the fused vector butterfly from 64 symbols; radix-4 sweeps take the
    /// fused vector kernels at every width here.
    #[test]
    fn radix4_sweeps_match_radix2_sweeps_bit_for_bit() {
        use crate::gf_simd::LinearBackend;
        let never = || false;
        for bits in [8u32, 16] {
            let field = TransformField::new(bits).unwrap();
            let mask = (field.order() - 1) as u16;
            for levels in 1..=bits {
                let count = 1usize << levels;
                let widths: &[usize] = match count {
                    ..=256 => &[1, 3, 15, 16, 17, 31, 32, 33, 64, 65, 100],
                    257..=4096 => &[17, 64],
                    _ => &[5],
                };
                let mut origins = vec![0, field.order() - count];
                if count <= 4096 && 2 * count < field.order() {
                    origins.push(count);
                }
                for &width in widths {
                    let original: Vec<Vec<u16>> = (0..count)
                        .map(|row| {
                            random_bytes(
                                width * 2,
                                (levels as usize * 7919 + width * 131 + row) as u64,
                            )
                            .chunks_exact(2)
                            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]) & mask)
                            .collect()
                        })
                        .collect();
                    for &origin in &origins {
                        for inverse in [false, true] {
                            let what = format!(
                                "GF(2^{bits}) {count} rows of {width}, origin {origin}, inverse {inverse}"
                            );
                            let run = |backend, radix4| {
                                let mut rows = original.clone();
                                let schedule = schedule(origin, inverse, backend, radix4);
                                let units = field.units(count, width, &schedule);
                                field
                                    .run_sweeps(&mut rows, &units, None, Place::WHOLE, &never)
                                    .unwrap();
                                rows
                            };
                            let oracle = run(LinearBackend::Scalar, false);
                            assert_eq!(run(LinearBackend::Auto, false), oracle, "radix-2, {what}");
                            assert_eq!(run(LinearBackend::Auto, true), oracle, "radix-4, {what}");
                            if bits == 8 {
                                let mut bytes: Vec<Vec<u8>> = original
                                    .iter()
                                    .map(|row| row.iter().map(|&v| v as u8).collect())
                                    .collect();
                                let schedule = schedule(origin, inverse, LinearBackend::Auto, true);
                                let units = field.units(count, width, &schedule);
                                field
                                    .run_sweeps(&mut bytes, &units, None, Place::WHOLE, &never)
                                    .unwrap();
                                assert_eq!(widen(&bytes), oracle, "byte radix-4, {what}");
                            }
                        }
                    }
                }
            }
        }
    }

    fn schedule(
        origin: usize,
        inverse: bool,
        backend: crate::gf_simd::LinearBackend,
        radix4: bool,
    ) -> Schedule {
        Schedule {
            origin,
            inverse,
            backend,
            radix4,
        }
    }

    /// Known-zero transforms against the dense transform of the same rows:
    /// no zeros, all zeros, an encoder-style zero tail, decoder-style erasures
    /// plus padding, a lone nonzero row and a random pattern, in both fields
    /// and lanes, both directions, several cosets, both backends, sequential
    /// and pooled.
    #[test]
    fn known_zero_transforms_match_dense_transforms() {
        use crate::gf_simd::LinearBackend;
        let never = || false;
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(3)
            .build()
            .unwrap();
        for bits in [8u32, 16] {
            let field = TransformField::new(bits).unwrap();
            let mask = (field.order() - 1) as u16;
            for (count, width) in [
                (2usize, 70usize),
                (4, 17),
                (8, 64),
                (32, 100),
                (64, 65),
                (256, 300),
                // Wide enough for the pool to transform them tile by tile in
                // both lanes, with a short last tile.
                (256, 6200),
                (1024, 1100),
            ] {
                if count > field.order() {
                    continue;
                }
                let noise = random_bytes(count, count as u64);
                let patterns: [Vec<bool>; 6] = [
                    vec![false; count],
                    vec![true; count],
                    (0..count).map(|row| row > count * 5 / 8).collect(),
                    (0..count)
                        .map(|row| row % 7 == 3 || row >= count * 3 / 4)
                        .collect(),
                    (0..count).map(|row| row != count / 2).collect(),
                    (0..count).map(|row| noise[row] & 1 == 0).collect(),
                ];
                let mut origins = vec![0, field.order() - count];
                if 2 * count <= field.order() {
                    origins.push(count);
                }
                for zero in &patterns {
                    let original: Vec<Vec<u16>> = (0..count)
                        .map(|row| {
                            random_bytes(width * 2, (row * 13 + width + count) as u64)
                                .chunks_exact(2)
                                .map(|pair| {
                                    let value = u16::from_le_bytes([pair[0], pair[1]]) & mask;
                                    if zero[row] { 0 } else { value }
                                })
                                .collect()
                        })
                        .collect();
                    let bytes: Vec<Vec<u8>> = original
                        .iter()
                        .map(|row| row.iter().map(|&v| v as u8).collect())
                        .collect();
                    for &origin in &origins {
                        for inverse in [false, true] {
                            for backend in [LinearBackend::Scalar, LinearBackend::Auto] {
                                let what = format!(
                                    "GF(2^{bits}) {count}x{width} {zero:?}, origin {origin}, \
                                     inverse {inverse}, {backend:?}"
                                );
                                let mut dense = original.clone();
                                field
                                    .transform_with_backend(
                                        &mut dense, origin, inverse, backend, &never,
                                    )
                                    .unwrap();
                                let mut rows = original.clone();
                                field
                                    .transform_known_zero_with_backend(
                                        &mut rows, zero, origin, inverse, backend, &never,
                                    )
                                    .unwrap();
                                assert_eq!(rows, dense, "{what}");
                                let mut rows = original.clone();
                                field
                                    .transform_known_zero_in_pool(
                                        &mut rows, zero, origin, inverse, backend, &pool, &never,
                                    )
                                    .unwrap();
                                assert_eq!(rows, dense, "pooled, {what}");
                                if bits == 8 {
                                    let mut rows = bytes.clone();
                                    field
                                        .transform_u8_known_zero_with_backend(
                                            &mut rows, zero, origin, inverse, backend, &never,
                                        )
                                        .unwrap();
                                    assert_eq!(widen(&rows), dense, "bytes, {what}");
                                    let mut rows = bytes.clone();
                                    field
                                        .transform_u8_known_zero_in_pool(
                                            &mut rows, zero, origin, inverse, backend, &pool,
                                            &never,
                                        )
                                        .unwrap();
                                    assert_eq!(widen(&rows), dense, "pooled bytes, {what}");
                                }
                            }
                        }
                    }
                }
            }
        }
        let mut rows = vec![vec![0u16; 4]; 4];
        assert_eq!(
            TransformField::new(8)
                .unwrap()
                .transform_known_zero_with_backend(
                    &mut rows,
                    &[false; 3],
                    0,
                    false,
                    LinearBackend::Auto,
                    &never
                ),
            Err(TransformError::Geometry)
        );
    }

    /// The whole-row sweeps of a transform alone, never tiled: the oracle
    /// every tiled transform must match.
    fn swept<S: Lane>(
        field: &TransformField,
        rows: &mut [Vec<S>],
        origin: usize,
        inverse: bool,
        backend: crate::gf_simd::LinearBackend,
    ) {
        let schedule = Schedule {
            origin,
            inverse,
            backend,
            radix4: TransformField::fused(rows[0].len(), backend),
        };
        field.sweep_rows(rows, None, &schedule, &|| false).unwrap();
    }

    /// A transform or derivative of a bank beyond a tile runs it in column
    /// tiles, in place, in one pass or two, and must come out exactly as the
    /// whole-row sweeps leave it, on one worker and on a pool, over `Vec`
    /// rows and over a [`RowBank`]'s, with and without known zeros, and with
    /// each tile added into a sum. The tiled paths are driven directly as
    /// well as through the entry points, which take them only on a target
    /// that tiles.
    #[test]
    fn tiled_transforms_match_whole_row_sweeps() {
        use crate::gf_simd::LinearBackend;
        let never = || false;
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(3)
            .build()
            .unwrap();
        for bits in [8u32, 16] {
            let field = TransformField::new(bits).unwrap();
            let mask = (field.order() - 1) as u16;
            // One pass with word windows of 1024, 4096 and 16384 symbols
            // and byte windows of 2048 and 8192, each shape ending in a
            // short window; one pass over a bank tiled in three word
            // windows, narrowed to share the rows across the three workers
            // (and in two byte windows, so no pooled byte tiles); then two
            // passes, over a domain of 10 levels, split evenly, and of 9,
            // split unevenly, forward and inverse; and two passes over rows
            // of 65 words of a 12-level domain, which hold fewer whole lines
            // than workers, so the derivative is not tiled.
            for (count, width, passes) in [
                (256usize, 6200usize, 1usize),
                (64, 20000, 1),
                (16, 70000, 1),
                (8, 70000, 1),
                (1024, 1100, 2),
                (512, 3000, 2),
                (4096, 65, 2),
            ] {
                if count > field.order() {
                    continue;
                }
                let threads = pool.current_num_threads();
                for inverse in [false, true] {
                    let schedule = Schedule {
                        origin: 0,
                        inverse,
                        backend: LinearBackend::Auto,
                        radix4: true,
                    };
                    let walk = Walk::of(count, width, 2, &schedule, threads).unwrap();
                    assert_eq!(
                        walk.passes.len(),
                        passes,
                        "{count}x{width} inverse {inverse}"
                    );
                    if passes == 2 {
                        let (low, high) = if inverse { (0, 1) } else { (1, 0) };
                        let low = walk.passes[low].1;
                        let high = walk.passes[high].1;
                        assert_eq!(low.stride, 1);
                        assert_eq!(high.stride, low.rows);
                        assert_eq!(low.rows * high.rows, count);
                    }
                    // Every pass has a tile per worker, and the workers'
                    // tiles together never outreach the bank.
                    for (_, pass) in &walk.passes {
                        assert!(pass.tasks(count, width) >= threads, "{count}x{width}");
                        assert!(
                            threads * pass.rows * pass.window <= count * width.div_ceil(64) * 64,
                            "{count}x{width}: {threads} tiles of {}x{}",
                            pass.rows,
                            pass.window
                        );
                    }
                }
                let pass = TransformField::derivative_pass::<u16>(count, width, threads);
                assert_eq!(pass.is_some(), width / 32 >= threads, "{count}x{width}");
                if let Some(pass) = pass {
                    assert!(pass.tasks(count, width) >= threads, "{count}x{width}");
                    assert!(
                        threads * count * pass.window <= count * width,
                        "{count}x{width}: {threads} derivative windows of {}",
                        pass.window
                    );
                }
                let zero: Vec<bool> = (0..count).map(|row| row % 3 == 1).collect();
                let original: Vec<Vec<u16>> = (0..count)
                    .map(|row| {
                        random_bytes(width * 2, (row * 7 + width) as u64)
                            .chunks_exact(2)
                            .map(|pair| {
                                let value = u16::from_le_bytes([pair[0], pair[1]]) & mask;
                                if zero[row] { 0 } else { value }
                            })
                            .collect()
                    })
                    .collect();
                let bytes: Vec<Vec<u8>> = original
                    .iter()
                    .map(|row| row.iter().map(|&v| v as u8).collect())
                    .collect();
                // What every sum starts from, and a bank of the same rows.
                let base: Vec<Vec<u16>> = (0..count)
                    .map(|row| {
                        random_bytes(width * 2, (row * 11 + 3) as u64)
                            .chunks_exact(2)
                            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]) & mask)
                            .collect()
                    })
                    .collect();
                let bank = |rows: &[Vec<u16>]| {
                    let mut bank = RowBank::<u16>::zeroed(count, width).unwrap();
                    for (to, from) in bank.rows_mut().into_iter().zip(rows) {
                        to.copy_from_slice(from);
                    }
                    bank
                };
                let rows_of = |bank: &RowBank<u16>| -> Vec<Vec<u16>> {
                    (0..count).map(|row| bank.row(row).to_vec()).collect()
                };
                for origin in [0, field.order() - count] {
                    for inverse in [false, true] {
                        for backend in [LinearBackend::Scalar, LinearBackend::Auto] {
                            let what = format!(
                                "GF(2^{bits}) {count}x{width}, origin {origin}, inverse \
                                 {inverse}, {backend:?}"
                            );
                            let mut expected = original.clone();
                            swept(&field, &mut expected, origin, inverse, backend);
                            let added: Vec<Vec<u16>> = base
                                .iter()
                                .zip(&expected)
                                .map(|(a, b)| a.iter().zip(b).map(|(a, b)| a ^ b).collect())
                                .collect();
                            let mut rows = original.clone();
                            field
                                .transform_with_backend(&mut rows, origin, inverse, backend, &never)
                                .unwrap();
                            assert_eq!(rows, expected, "alone, {what}");
                            let mut rows = original.clone();
                            field
                                .transform_in_pool(
                                    &mut rows, origin, inverse, backend, &pool, &never,
                                )
                                .unwrap();
                            assert_eq!(rows, expected, "pooled, {what}");
                            let mut rows = original.clone();
                            field
                                .transform_known_zero_in_pool(
                                    &mut rows, &zero, origin, inverse, backend, &pool, &never,
                                )
                                .unwrap();
                            assert_eq!(rows, expected, "pooled known zero, {what}");
                            for pool in [None, Some(&pool)] {
                                let mut rows = bank(&original);
                                let mut sum = bank(&base);
                                field
                                    .transform_rows_adding(
                                        &mut rows.rows_mut(),
                                        Some(&zero),
                                        origin,
                                        inverse,
                                        backend,
                                        pool,
                                        &mut sum.rows_mut(),
                                        &never,
                                    )
                                    .unwrap();
                                assert_eq!(rows_of(&rows), expected, "bank rows, {what}");
                                assert_eq!(
                                    rows_of(&sum),
                                    added,
                                    "bank sum, pool {}, {what}",
                                    pool.is_some()
                                );
                            }
                            let schedule = Schedule {
                                origin,
                                inverse,
                                backend,
                                radix4: TransformField::fused(width, backend),
                            };
                            for zero in [None, Some(zero.as_slice())] {
                                let flags = sweep_flags(count, zero, &schedule);
                                let what = format!("zero {}, {what}", zero.is_some());
                                let walk = Walk::of(count, width, 2, &schedule, threads).unwrap();
                                let mut rows = original.clone();
                                let mut sum = base.clone();
                                field
                                    .transform_tiles(
                                        &mut rows,
                                        &schedule,
                                        flags.as_deref(),
                                        &walk,
                                        &pool,
                                        Some(&mut sum),
                                        &never,
                                    )
                                    .unwrap();
                                assert_eq!(rows, expected, "pooled tiles, {what}");
                                assert_eq!(sum, added, "pooled tile sum, {what}");
                                let walk = Walk::of(count, width, 2, &schedule, 1).unwrap();
                                let mut rows = bank(&original);
                                let mut sum = base.clone();
                                field
                                    .transform_tiles_alone(
                                        &mut rows.rows_mut(),
                                        &schedule,
                                        flags.as_deref(),
                                        &walk,
                                        Some(&mut sum),
                                        &never,
                                    )
                                    .unwrap();
                                assert_eq!(rows_of(&rows), expected, "tiles alone, {what}");
                                assert_eq!(sum, added, "tile sum alone, {what}");
                                // Byte rows take windows twice as wide, which
                                // at the shortest shape leave a worker idle,
                                // so there are no pooled byte tiles of it.
                                let byte_walk = (bits == 8)
                                    .then(|| Walk::of(count, width, 1, &schedule, threads))
                                    .flatten();
                                if bits == 8 {
                                    assert_eq!(byte_walk.is_some(), count != 8, "{what}");
                                }
                                if let Some(walk) = byte_walk {
                                    let mut rows = bytes.clone();
                                    field
                                        .transform_tiles(
                                            &mut rows,
                                            &schedule,
                                            flags.as_deref(),
                                            &walk,
                                            &pool,
                                            None::<&mut [Vec<u8>]>,
                                            &never,
                                        )
                                        .unwrap();
                                    assert_eq!(widen(&rows), expected, "byte tiles, {what}");
                                }
                            }
                            if bits == 8 {
                                let mut rows = bytes.clone();
                                field
                                    .transform_u8_in_pool(
                                        &mut rows, origin, inverse, backend, &pool, &never,
                                    )
                                    .unwrap();
                                assert_eq!(widen(&rows), expected, "pooled bytes, {what}");
                                let mut rows = bytes.clone();
                                field
                                    .transform_u8_known_zero_in_pool(
                                        &mut rows, &zero, origin, inverse, backend, &pool, &never,
                                    )
                                    .unwrap();
                                assert_eq!(
                                    widen(&rows),
                                    expected,
                                    "pooled bytes known zero, {what}"
                                );
                                let mut rows = bytes.clone();
                                field
                                    .transform_u8_rows(
                                        &mut rows,
                                        Some(&zero),
                                        origin,
                                        inverse,
                                        backend,
                                        None,
                                        &never,
                                    )
                                    .unwrap();
                                assert_eq!(widen(&rows), expected, "byte rows alone, {what}");
                            }
                        }
                    }
                }
                let mut expected = original.clone();
                derivative_rows(&mut expected, &never).unwrap();
                let mut rows = original.clone();
                field.derivative_in_pool(&mut rows, &pool, &never).unwrap();
                assert_eq!(
                    rows, expected,
                    "pooled derivative, GF(2^{bits}) {count}x{width}"
                );
                let mut rows = bank(&original);
                field
                    .differentiate_rows(&mut rows.rows_mut(), Some(&pool), &never)
                    .unwrap();
                assert_eq!(
                    rows_of(&rows),
                    expected,
                    "bank derivative, GF(2^{bits}) {count}x{width}"
                );
                if let Some(pass) = TransformField::derivative_pass::<u16>(count, width, threads) {
                    let mut rows = original.clone();
                    TransformField::derivative_tiled(&mut rows, pass, &pool, &never).unwrap();
                    assert_eq!(
                        rows, expected,
                        "tiled derivative, GF(2^{bits}) {count}x{width}"
                    );
                }
                if bits == 8 {
                    let mut rows = bytes.clone();
                    field
                        .derivative_u8_in_pool(&mut rows, &pool, &never)
                        .unwrap();
                    assert_eq!(
                        widen(&rows),
                        expected,
                        "pooled byte derivative, {count}x{width}"
                    );
                    let pass =
                        TransformField::derivative_pass::<u8>(count, width, threads).unwrap();
                    assert!(
                        threads * count * pass.window <= count * width,
                        "{count}x{width}: {threads} byte derivative windows of {}",
                        pass.window
                    );
                    let mut rows = bytes.clone();
                    TransformField::derivative_tiled(&mut rows, pass, &pool, &never).unwrap();
                    assert_eq!(
                        widen(&rows),
                        expected,
                        "tiled byte derivative, {count}x{width}"
                    );
                }
            }
        }
    }

    /// A bank is zeroed, its rows are distinct, as wide as asked and in
    /// order, and its allocation is whole pages aligned to one.
    #[test]
    fn row_banks_are_zeroed_aligned_rows() {
        assert_eq!(RowBank::<u16>::allocation_bytes(3, 1000), Some(8192));
        assert_eq!(RowBank::<u8>::allocation_bytes(0, 1000), Some(0));
        assert_eq!(RowBank::<u16>::allocation_bytes(usize::MAX, 2), None);
        // Rows of whole multiples of 512 bytes are a cache line apart more.
        assert_eq!(RowBank::<u16>::allocation_bytes(64, 2048), Some(266_240));
        assert_eq!(RowBank::<u8>::allocation_bytes(2, 512), Some(4096));
        for (rows, width) in [(5usize, 1000usize), (4, 0), (0, 7), (1, 2048), (9, 256)] {
            let mut bank = RowBank::<u16>::zeroed(rows, width).unwrap();
            assert_eq!((bank.rows(), bank.width()), (rows, width));
            let mut slices = bank.rows_mut();
            assert_eq!(slices.len(), rows);
            for (index, row) in slices.iter_mut().enumerate() {
                assert_eq!(row.len(), width);
                assert!(row.iter().all(|&value| value == 0));
                row.fill(index as u16 + 1);
            }
            if let Some(first) = slices.first() {
                assert!(
                    (first.as_ptr() as usize).is_multiple_of(RowBank::<u16>::ALIGN) || width == 0
                );
            }
            for pair in slices.windows(2) {
                let gap = pair[1].as_ptr() as usize - pair[0].as_ptr() as usize;
                let bytes = width * 2;
                assert_eq!(
                    gap,
                    if bytes != 0 && bytes.is_multiple_of(512) {
                        bytes + 64
                    } else {
                        bytes
                    }
                );
            }
            drop(slices);
            for row in 0..rows {
                assert!(bank.row(row).iter().all(|&value| value == row as u16 + 1));
            }
        }
    }

    /// The butterflies known zeros remove from the PAR3 encoder's last-chunk
    /// and decoder's inverse transforms at typical shapes, counted by the
    /// same flag walk the transforms run; `--nocapture` prints them.
    #[test]
    fn known_zero_steps_at_par3_shapes() {
        let steps = |zero: &mut [bool], origin: usize| {
            let mut counts = [0u64; 5];
            let levels = zero.len().trailing_zeros();
            for sweep in sweeps(levels, true, false) {
                advance(zero, sweep, origin, true, &mut |step| {
                    counts[step as usize] += 1
                });
            }
            assert_eq!(
                counts.iter().sum::<u64>(),
                u64::from(levels) * zero.len() as u64 / 2
            );
            counts
        };
        // (inputs, capacity, domain, lost): one recovery row per loss.
        for (inputs, capacity, domain, lost) in [
            (150usize, 32usize, 256usize, 15usize),
            (300, 64, 512, 30),
            (1000, 128, 2048, 100),
            (2000, 256, 4096, 200),
        ] {
            let tail = inputs % capacity;
            let mut zero: Vec<bool> = (0..capacity).map(|at| tail != 0 && at >= tail).collect();
            let encoder = steps(&mut zero, capacity + inputs - tail);
            let mut zero = vec![true; domain];
            zero[..lost].fill(false);
            for (index, flag) in zero[capacity..capacity + inputs].iter_mut().enumerate() {
                *flag = index % (inputs / lost) == 1;
            }
            let decoder = steps(&mut zero, 0);
            println!(
                "{inputs} inputs, capacity {capacity}, domain {domain}, {lost} lost: \
                 encoder last chunk [skip, keep, copy, scale, full] {encoder:?}, \
                 decoder {decoder:?}"
            );
            assert!(decoder[Step::Skip as usize] > 0);
        }
    }

    const WIDTHS: [usize; 10] = [0, 1, 3, 15, 16, 17, 63, 64, 65, 1000];

    fn words(width: usize, seed: u64, mask: u16) -> Vec<u16> {
        random_bytes(width * 2, seed)
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]) & mask)
            .collect()
    }

    /// In-place maps against the accumulating maps into zeros, which the
    /// byte-map test checks against field products: every lane and field,
    /// both backends, unaligned starts and every vector tail.
    #[test]
    fn in_place_maps_match_accumulating_maps() {
        use crate::gf_simd::LinearBackend;
        fn check<S: Lane + std::fmt::Debug>(field: &TransformField, values: &[S], factors: &[u16]) {
            for &factor in factors {
                for backend in [LinearBackend::Auto, LinearBackend::Scalar] {
                    let map = S::map(field, factor, backend);
                    for offset in [0usize, 1, 3] {
                        for length in [0, 1, 7, 15, 16, 17, 31, 32, 33, 63, 64, 65, 255, 1000] {
                            let input = &values[offset..offset + length];
                            let mut expected = vec![S::default(); length];
                            S::accumulate(&map, input, &mut expected);
                            let mut actual = input.to_vec();
                            S::map_in_place(&map, &mut actual);
                            assert_eq!(
                                actual, expected,
                                "GF(2^{}) factor {factor}, {backend:?}, offset {offset}, \
                                 length {length}",
                                field.bits
                            );
                        }
                    }
                }
            }
        }
        let small = TransformField::new(8).unwrap();
        let wide = TransformField::new(16).unwrap();
        let all: Vec<u16> = (0..256).collect();
        check(&small, &random_bytes(1100, 7), &all);
        check(&small, &words(1100, 8, 0xff), &all);
        check(
            &wide,
            &words(1100, 9, 0xffff),
            &[0, 1, 2, 3, 42, 255, 256, 32768, 65535],
        );
    }

    /// The fused little-endian load against unpacking then scaling in place,
    /// at every width either side of the vector and plan thresholds, plus
    /// its errors and cancellation points.
    #[test]
    fn fused_le_byte_scaling_matches_unpack_then_scale() {
        use crate::gf_simd::LinearBackend;
        let field = TransformField::new(16).unwrap();
        let never = || false;
        for width in WIDTHS.into_iter().chain([255, 256, 257, 4097]) {
            let bytes = random_bytes(width * 2, width as u64 + 5);
            for factor in [0u16, 1, 2, 3, 42, 255, 256, 32768, 65535] {
                for backend in [LinearBackend::Scalar, LinearBackend::Auto] {
                    let mut expected: Vec<u16> = bytes
                        .chunks_exact(2)
                        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                        .collect();
                    field
                        .scale_with_backend(&mut expected, factor, backend, &never)
                        .unwrap();
                    let mut actual = vec![0x5a5a; width];
                    field
                        .scale_le_bytes_with_backend(&bytes, &mut actual, factor, backend, &never)
                        .unwrap();
                    assert_eq!(
                        actual, expected,
                        "width {width}, factor {factor}, {backend:?}"
                    );
                }
            }
        }
        let mut out = vec![0u16; 4];
        assert_eq!(
            TransformField::new(8).unwrap().scale_le_bytes_with_backend(
                &[0; 8],
                &mut out,
                2,
                LinearBackend::Auto,
                &never
            ),
            Err(TransformError::Field)
        );
        assert_eq!(
            field.scale_le_bytes_with_backend(&[0; 7], &mut out, 2, LinearBackend::Auto, &never),
            Err(TransformError::Geometry)
        );
        let calls = std::cell::Cell::new(0);
        let source = [1u8, 0].repeat(1024);
        let mut values = vec![7u16; 1024];
        assert_eq!(
            field.scale_le_bytes_with_backend(
                &source,
                &mut values,
                2,
                LinearBackend::Auto,
                &|| {
                    calls.set(calls.get() + 1);
                    // Initial check, one scaled chunk, then the second chunk's.
                    calls.get() == 3
                }
            ),
            Err(TransformError::Cancelled)
        );
        let two = field.mul(1, 2);
        assert!(values[..256].iter().all(|&v| v == two));
        assert!(values[256..].iter().all(|&v| v == 7));
    }

    /// Radix-2 sweeps whose butterflies reduce to a single product — the
    /// left row known zero, the factor not, the inverse direction — against
    /// the dense transform: every power-of-two row count from 2 to 512, the
    /// usual widths, both directions, fields, lanes and backends, sequential
    /// and pooled. The scalar backend and rows under 64 symbols run radix-2
    /// sweeps throughout; wider rows reach them on odd stage counts.
    #[test]
    fn radix2_single_products_match_dense_transforms() {
        use crate::gf_simd::LinearBackend;
        let never = || false;
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(3)
            .build()
            .unwrap();
        for bits in [8u32, 16] {
            let field = TransformField::new(bits).unwrap();
            let mask = (field.order() - 1) as u16;
            for levels in 1..=bits.min(9) {
                let count = 1usize << levels;
                let noise = random_bytes(count, count as u64 + 1);
                let patterns: [Vec<bool>; 2] = [
                    (0..count).map(|row| row < count / 2).collect(),
                    (0..count).map(|row| noise[row] & 3 != 0).collect(),
                ];
                for width in WIDTHS.into_iter().filter(|&w| w < 1000 || count <= 64) {
                    for zero in &patterns {
                        let original: Vec<Vec<u16>> = (0..count)
                            .map(|row| {
                                let values = words(width, (row * 17 + width + count) as u64, mask);
                                if zero[row] { vec![0; width] } else { values }
                            })
                            .collect();
                        let bytes: Vec<Vec<u8>> = original
                            .iter()
                            .map(|row| row.iter().map(|&v| v as u8).collect())
                            .collect();
                        let origin = if 2 * count <= field.order() { count } else { 0 };
                        for inverse in [false, true] {
                            for backend in [LinearBackend::Scalar, LinearBackend::Auto] {
                                let what = format!(
                                    "GF(2^{bits}) {count}x{width}, origin {origin}, \
                                     inverse {inverse}, {backend:?}"
                                );
                                let mut dense = original.clone();
                                field
                                    .transform_with_backend(
                                        &mut dense, origin, inverse, backend, &never,
                                    )
                                    .unwrap();
                                let mut rows = original.clone();
                                field
                                    .transform_known_zero_with_backend(
                                        &mut rows, zero, origin, inverse, backend, &never,
                                    )
                                    .unwrap();
                                assert_eq!(rows, dense, "{what}");
                                let mut rows = original.clone();
                                field
                                    .transform_known_zero_in_pool(
                                        &mut rows, zero, origin, inverse, backend, &pool, &never,
                                    )
                                    .unwrap();
                                assert_eq!(rows, dense, "pooled, {what}");
                                if bits == 8 {
                                    let mut rows = bytes.clone();
                                    field
                                        .transform_u8_known_zero_with_backend(
                                            &mut rows, zero, origin, inverse, backend, &never,
                                        )
                                        .unwrap();
                                    assert_eq!(widen(&rows), dense, "bytes, {what}");
                                    let mut rows = bytes.clone();
                                    field
                                        .transform_u8_known_zero_in_pool(
                                            &mut rows, zero, origin, inverse, backend, &pool,
                                            &never,
                                        )
                                        .unwrap();
                                    assert_eq!(widen(&rows), dense, "pooled bytes, {what}");
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// The single-store derivative against its definition computed out of
    /// place, and the pooled derivative against the sequential one on both
    /// sides of the 64 KiB cutoff, in both lanes.
    #[test]
    fn derivatives_match_the_definition_sequential_and_pooled() {
        let never = || false;
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .unwrap();
        let field = TransformField::new(8).unwrap();
        let wide = TransformField::new(16).unwrap();
        let definition = |rows: &[Vec<u16>]| -> Vec<Vec<u16>> {
            let n = rows.len();
            (0..n)
                .map(|index| {
                    let mut out = vec![0u16; rows[0].len()];
                    for bit in 0..n.trailing_zeros() {
                        if index & (1 << bit) == 0 {
                            for (to, &from) in out.iter_mut().zip(&rows[index | (1 << bit)]) {
                                *to ^= from;
                            }
                        }
                    }
                    out
                })
                .collect()
        };
        let shapes = (0..=9)
            .flat_map(|levels| WIDTHS.map(|width| (1usize << levels, width)))
            // The last two are wide enough for the pool to take them tile by
            // tile, in both lanes, with a short last tile.
            .chain([
                (256, 300),
                (128, 1031),
                (64, 4096),
                (512, 129),
                (256, 6200),
                (1024, 1100),
            ]);
        for (count, width) in shapes {
            let bytes: Vec<Vec<u8>> = (0..count)
                .map(|row| random_bytes(width, (row * 29 + width + count) as u64))
                .collect();
            let wide_rows: Vec<Vec<u16>> = (0..count)
                .map(|row| words(width, (row * 31 + width) as u64, 0xffff))
                .collect();
            for (field, original) in [(&field, widen(&bytes)), (&wide, wide_rows)] {
                if count > field.order() {
                    continue;
                }
                let expected = definition(&original);
                let what = format!("GF(2^{}) {count}x{width}", field.bits);
                let mut rows = original.clone();
                field.derivative(&mut rows, &never).unwrap();
                assert_eq!(rows, expected, "{what}");
                let mut rows = original.clone();
                field.derivative_in_pool(&mut rows, &pool, &never).unwrap();
                assert_eq!(rows, expected, "pooled, {what}");
            }
            if count <= field.order() {
                let mut rows = bytes.clone();
                field
                    .derivative_u8_in_pool(&mut rows, &pool, &never)
                    .unwrap();
                let mut sequential = bytes.clone();
                field.derivative_u8(&mut sequential, &never).unwrap();
                assert_eq!(rows, sequential, "bytes {count}x{width}");
            }
        }
        let mut rows = vec![vec![0u8; 4096]; 3];
        assert_eq!(
            field.derivative_u8_in_pool(&mut rows, &pool, &never),
            Err(TransformError::Geometry)
        );
        let mut rows = vec![vec![0u8; 4096]; 64];
        assert_eq!(
            wide.derivative_u8_in_pool(&mut rows, &pool, &never),
            Err(TransformError::Field)
        );
        rows[1].pop();
        assert_eq!(
            field.derivative_u8_in_pool(&mut rows, &pool, &never),
            Err(TransformError::Geometry)
        );
        let mut rows = vec![vec![0u8; 4096]; 64];
        assert_eq!(
            field.derivative_u8_in_pool(&mut rows, &pool, &|| true),
            Err(TransformError::Cancelled)
        );
    }

    /// The dispatched source fold against the portable one for every source
    /// count a derivative can hand it and two past it, at lengths either side of the 64-byte
    /// block and an unaligned start, in both lanes.
    #[test]
    fn xor_sums_match_the_portable_fold() {
        fn check<S: Lane + std::fmt::Debug>(pool: &[S]) {
            for count in 0..=18usize {
                for length in [0usize, 1, 31, 32, 33, 63, 64, 65, 127, 128, 129, 1000] {
                    for offset in [0usize, 1] {
                        let sources: Vec<&[S]> = (0..count)
                            .map(|at| &pool[offset + at * 1031..offset + at * 1031 + length])
                            .collect();
                        let mut actual = pool[pool.len() - length..].to_vec();
                        let mut expected = actual.clone();
                        xor_sum(&mut actual, &sources);
                        xor_sum_portable(&mut expected, &sources);
                        assert_eq!(actual, expected, "{count} sources, length {length}");
                        let direct = (0..length).map(|at| {
                            sources
                                .iter()
                                .fold(S::default(), |sum, source| sum ^ source[at])
                        });
                        assert!(actual.iter().copied().eq(direct), "{count} sources");
                    }
                }
            }
        }
        check(&random_bytes(20000, 5));
        check(&words(20000, 6, 0xffff));
    }

    #[test]
    fn locator_factors_match_direct_products() {
        for bits in [8, 16] {
            let field = TransformField::new(bits).unwrap();
            let erased: Vec<bool> = (0..128).map(|i| i % 3 == 1).collect();
            let factors = field.erasure_factors(&erased, &|| false).unwrap();
            for (at, factor) in factors.iter().enumerate() {
                let expected = erased
                    .iter()
                    .enumerate()
                    .filter(|(i, erased)| **erased && *i != at)
                    .fold(1, |value, (i, _)| field.mul(value, (at ^ i) as u16));
                assert_eq!(*factor, expected);
            }
        }
    }
}
