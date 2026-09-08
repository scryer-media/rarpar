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
        self.validate_transform(rows, origin, cancelled)?;
        let n = rows.len();
        let levels = n.trailing_zeros();
        for stage in 0..levels {
            let level = if inverse { stage } else { levels - 1 - stage };
            let half = 1 << level;
            for base in (0..n).step_by(half * 2) {
                if cancelled() {
                    return Err(TransformError::Cancelled);
                }
                let factor = ((origin ^ base) >> level) as u16;
                let (left, right) = rows[base..base + half * 2].split_at_mut(half);
                let butterfly = self.butterfly(factor, inverse, backend, left[0].len());
                for (left, right) in left.iter_mut().zip(right) {
                    if cancelled() {
                        return Err(TransformError::Cancelled);
                    }
                    butterfly(left, right);
                }
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
        use rayon::prelude::*;
        let n = rows.len();
        if pool.current_num_threads() == 1
            || rows
                .first()
                .is_none_or(|row| row.len().saturating_mul(n) < 32768)
        {
            return self.transform_with_backend(rows, origin, inverse, backend, cancelled);
        }
        self.validate_transform(rows, origin, cancelled)?;
        let levels = n.trailing_zeros();
        pool.install(|| {
            for stage in 0..levels {
                let level = if inverse { stage } else { levels - 1 - stage };
                let half = 1 << level;
                rows.par_chunks_mut(half * 2)
                    .enumerate()
                    .try_for_each(|(group, rows)| {
                        let factor = ((origin ^ (group * half * 2)) >> level) as u16;
                        let (left, right) = rows.split_at_mut(half);
                        let butterfly = self.butterfly(factor, inverse, backend, left[0].len());
                        left.par_iter_mut().zip(right.par_iter_mut()).try_for_each(
                            |(left, right)| {
                                if cancelled() {
                                    return Err(TransformError::Cancelled);
                                }
                                butterfly(left, right);
                                Ok(())
                            },
                        )
                    })?;
            }
            Ok(())
        })
    }

    fn validate_transform(
        &self,
        rows: &[Vec<u16>],
        origin: usize,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), TransformError> {
        let n = rows.len();
        if !n.is_power_of_two()
            || n > self.order()
            || !origin.is_multiple_of(n)
            || origin > self.order() - n
        {
            return Err(TransformError::Geometry);
        }
        for row in rows {
            if cancelled() {
                return Err(TransformError::Cancelled);
            }
            if row.len() != rows[0].len()
                || (self.bits == 8 && row.iter().any(|value| *value > 255))
            {
                return Err(TransformError::Geometry);
            }
        }
        Ok(())
    }

    fn butterfly(
        &self,
        factor: u16,
        inverse: bool,
        backend: crate::gf_simd::LinearBackend,
        width: usize,
    ) -> impl Fn(&mut [u16], &mut [u16]) + Sync + '_ {
        let plan = (backend != crate::gf_simd::LinearBackend::Scalar && width >= 64 && factor > 1)
            .then(|| {
                crate::gf_simd::LinearMap16::new(
                    std::array::from_fn(|bit| {
                        if bit < self.bits as usize {
                            self.mul(1 << bit, factor)
                        } else {
                            0
                        }
                    }),
                    backend,
                )
            });
        move |left, right| {
            if factor == 0 && backend != crate::gf_simd::LinearBackend::Scalar {
                for (a, b) in left.iter().zip(right) {
                    *b ^= *a;
                }
            } else if let Some(plan) = &plan {
                if inverse {
                    for (a, b) in left.iter().zip(right.iter_mut()) {
                        *b ^= *a;
                    }
                    plan.accumulate(right, left);
                } else {
                    plan.accumulate(right, left);
                    for (a, b) in left.iter().zip(right.iter_mut()) {
                        *b ^= *a;
                    }
                }
            } else {
                for (a, b) in left.iter_mut().zip(right) {
                    if inverse {
                        *b ^= *a;
                        *a ^= self.mul(*b, factor);
                    } else {
                        *a ^= self.mul(*b, factor);
                        *b ^= *a;
                    }
                }
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
        let n = rows.len();
        if !n.is_power_of_two()
            || n > self.order()
            || rows.iter().any(|row| row.len() != rows[0].len())
        {
            return Err(TransformError::Geometry);
        }
        for index in 0..n {
            if cancelled() {
                return Err(TransformError::Cancelled);
            }
            let (done, remaining) = rows.split_at_mut(index + 1);
            let target = &mut done[index];
            target.fill(0);
            for bit in 0..n.trailing_zeros() {
                if index & (1 << bit) != 0 {
                    continue;
                }
                let source = &remaining[(index | (1 << bit)) - index - 1];
                for (to, from) in target.iter_mut().zip(source) {
                    *to ^= from;
                }
            }
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
