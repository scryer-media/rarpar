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
        Ok(Self { bits, log, exp })
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

    fn transform_lane<S: Lane>(
        &self,
        rows: &mut [Vec<S>],
        zero: Option<&[bool]>,
        origin: usize,
        inverse: bool,
        backend: crate::gf_simd::LinearBackend,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), TransformError> {
        self.validate_transform(rows, zero, origin, cancelled)?;
        let width = rows.first().map_or(0, Vec::len);
        let schedule = Schedule {
            origin,
            inverse,
            backend,
            radix4: Self::fused(width, backend),
        };
        self.run_sweeps(rows, &schedule, zero, cancelled)
    }

    /// Whether the transform runs fused radix-4 sweeps: whenever the vector
    /// maps run at all. The scalar backend and narrow rows keep the radix-2
    /// table-walk oracle.
    fn fused(width: usize, backend: crate::gf_simd::LinearBackend) -> bool {
        backend != crate::gf_simd::LinearBackend::Scalar && width >= 64
    }

    fn run_sweeps<S: Lane>(
        &self,
        rows: &mut [Vec<S>],
        schedule: &Schedule,
        zero: Option<&[bool]>,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), TransformError> {
        let n = rows.len();
        let width = rows.first().map_or(0, Vec::len);
        let mut known = zero.map(<[bool]>::to_vec);
        for sweep in sweeps(n.trailing_zeros(), schedule.inverse, schedule.radix4) {
            // The zero flags as this sweep finds them; it reads, never writes them.
            let before = known.clone();
            let zero = |row: usize| before.as_ref().is_some_and(|known| known[row]);
            match sweep {
                Sweep::Radix2(level) => {
                    let half = 1 << level;
                    for base in (0..n).step_by(half * 2) {
                        if cancelled() {
                            return Err(TransformError::Cancelled);
                        }
                        let (left, right) = rows[base..base + half * 2].split_at_mut(half);
                        let pair = self.pair(schedule, level, base, width);
                        for (at, (left, right)) in left.iter_mut().zip(right).enumerate() {
                            if cancelled() {
                                return Err(TransformError::Cancelled);
                            }
                            pair(left, right, [zero(base + at), zero(base + half + at)]);
                        }
                    }
                }
                Sweep::Radix4(low) => {
                    let quarter = 1 << low;
                    for base in (0..n).step_by(quarter * 4) {
                        if cancelled() {
                            return Err(TransformError::Cancelled);
                        }
                        let quad = self.quad(schedule, base, low);
                        let [a, b, c, d] = quarters(&mut rows[base..base + quarter * 4]);
                        let units = a.iter_mut().zip(b).zip(c).zip(d).enumerate();
                        for (at, (((a, b), c), d)) in units {
                            if cancelled() {
                                return Err(TransformError::Cancelled);
                            }
                            let flags = match &before {
                                None => [false; 4],
                                Some(_) => std::array::from_fn(|k| zero(base + k * quarter + at)),
                            };
                            quad([a, b, c, d].map(Vec::as_mut_slice), flags);
                        }
                    }
                }
            }
            if let Some(known) = &mut known {
                advance(known, sweep, schedule.origin, schedule.inverse, &mut |_| {});
            }
        }
        Ok(())
    }

    /// Run transform stages inside a caller-owned, bounded worker pool. No
    /// global pool is used. Small stripes execute synchronously to avoid task
    /// overhead; cancellation is checked before each butterfly pair.
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
    fn transform_lane_in_pool<S: Lane>(
        &self,
        rows: &mut [Vec<S>],
        zero: Option<&[bool]>,
        origin: usize,
        inverse: bool,
        backend: crate::gf_simd::LinearBackend,
        pool: &rayon::ThreadPool,
        cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<(), TransformError> {
        use rayon::prelude::*;
        let n = rows.len();
        // The synchronous cutoff is 64 KiB of row storage in either lane.
        if pool.current_num_threads() == 1
            || rows
                .first()
                .is_none_or(|row| size_of_val(row.as_slice()).saturating_mul(n) < 65536)
        {
            return self.transform_lane(rows, zero, origin, inverse, backend, cancelled);
        }
        self.validate_transform(rows, zero, origin, cancelled)?;
        let width = rows.first().map_or(0, Vec::len);
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
                                            left,
                                            right,
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
                                        quad([a, b, c, d].map(Vec::as_mut_slice), flags);
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

    fn validate_transform<S: Lane>(
        &self,
        rows: &[Vec<S>],
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
            if row.len() != rows[0].len() || (S::ranged(self) && !S::admits(self, row)) {
                return Err(TransformError::Geometry);
            }
        }
        debug_assert!(
            zero.is_none_or(|zero| {
                rows.iter()
                    .zip(zero)
                    .all(|(row, &zero)| !zero || row.iter().all(|&value| value == S::default()))
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
    /// synchronously, as in [`Self::transform_in_pool`].
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

    fn derivative_lane_in_pool<S: Lane>(
        &self,
        rows: &mut [Vec<S>],
        pool: &rayon::ThreadPool,
        cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<(), TransformError> {
        use rayon::prelude::*;
        let n = rows.len();
        let width = rows.first().map_or(0, Vec::len);
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
        // One pointer per row, the same size as the row handles themselves.
        let shared = SharedRows(rows.iter_mut().map(|row| row.as_mut_ptr()).collect(), width);
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

    fn validate_derivative<S: Lane>(&self, rows: &[Vec<S>]) -> Result<(), TransformError> {
        let n = rows.len();
        if !n.is_power_of_two()
            || n > self.order()
            || rows.iter().any(|row| row.len() != rows[0].len())
        {
            return Err(TransformError::Geometry);
        }
        Ok(())
    }

    fn derivative_lane<S: Lane>(
        &self,
        rows: &mut [Vec<S>],
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), TransformError> {
        self.validate_derivative(rows)?;
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
                sources[count] = &remaining[(index | (1 << bit)) - index - 1];
                count += 1;
            }
            xor_sum(&mut done[index], &sources[..count]);
        }
        Ok(())
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

/// Equally wide rows, taken mutably for the duration of a pooled derivative
/// whose tasks each touch only their own range of columns.
struct SharedRows<S>(Vec<*mut S>, usize);

// SAFETY: the pointers come from an exclusive borrow of the rows held for as
// long as this exists, and every access goes through the methods below,
// whose callers keep concurrent slices disjoint.
unsafe impl<S: Send + Sync> Sync for SharedRows<S> {}

impl<S> SharedRows<S> {
    /// Columns `columns` of row `row`.
    ///
    /// # Safety
    /// `row` must be in bounds and `columns` within the width, and no mutable
    /// slice may overlap the result while it lives. A pooled derivative gives
    /// each task its own columns, and within them reads only rows past the
    /// one it writes.
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

#[cfg(test)]
mod tests {
    use super::*;
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
                                field
                                    .run_sweeps(&mut rows, &schedule, None, &never)
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
                                field
                                    .run_sweeps(&mut bytes, &schedule, None, &never)
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
            ] {
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
            .chain([(256, 300), (128, 1031), (64, 4096), (512, 129)]);
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
