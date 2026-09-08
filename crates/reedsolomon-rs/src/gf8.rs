//! Runtime-dispatched GF(2⁸) multiply-accumulate for polynomial 0x11d.

/// A reusable nibble-shuffle multiplication plan for one coefficient.
#[derive(Clone)]
pub struct MulPlan {
    low: [u8; 16],
    high: [u8; 16],
}

/// Scalar multiplication, also used as the portable arithmetic oracle.
#[must_use]
pub fn mul(mut left: u8, mut right: u8) -> u8 {
    let mut result = 0;
    for _ in 0..8 {
        result ^= left & 0u8.wrapping_sub(right & 1);
        left = (left << 1) ^ (0x1d & 0u8.wrapping_sub(left >> 7));
        right >>= 1;
    }
    result
}

impl MulPlan {
    /// Precompute the two 16-entry tables for a coefficient.
    #[must_use]
    pub fn new(factor: u8) -> Self {
        Self {
            low: std::array::from_fn(|n| mul(n as u8, factor)),
            high: std::array::from_fn(|n| mul((n << 4) as u8, factor)),
        }
    }

    /// Accumulate `source * factor` into `destination`. Buffers must have equal
    /// lengths and may be unaligned; CPU dispatch always has a scalar fallback.
    pub fn accumulate(&self, source: &[u8], destination: &mut [u8]) {
        assert_eq!(source.len(), destination.len());
        #[cfg(target_arch = "aarch64")]
        if std::arch::is_aarch64_feature_detected!("neon") {
            // SAFETY: NEON was detected and the implementation bounds every load.
            unsafe { self.neon(source, destination) };
            return;
        }
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            if std::arch::is_x86_feature_detected!("avx2") {
                // SAFETY: AVX2 was detected; all loads are unaligned and bounded.
                unsafe { self.avx2(source, destination) };
                return;
            }
            if std::arch::is_x86_feature_detected!("ssse3") {
                // SAFETY: SSSE3 was detected; all loads are unaligned and bounded.
                unsafe { self.ssse3(source, destination) };
                return;
            }
        }
        self.scalar(source, destination);
    }

    /// Explicit scalar execution for reproducibility and backend comparisons.
    pub fn scalar(&self, source: &[u8], destination: &mut [u8]) {
        assert_eq!(source.len(), destination.len());
        for (to, from) in destination.iter_mut().zip(source) {
            *to ^= self.low[(from & 15) as usize] ^ self.high[(from >> 4) as usize];
        }
    }

    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon")]
    unsafe fn neon(&self, source: &[u8], destination: &mut [u8]) {
        use std::arch::aarch64::*;
        // SAFETY: the caller checks NEON and equal lengths. The loop stops before
        // each 16-byte load/store could cross either slice, including table loads.
        unsafe {
            let low = vld1q_u8(self.low.as_ptr());
            let high = vld1q_u8(self.high.as_ptr());
            let mask = vdupq_n_u8(15);
            let mut at = 0;
            while source.len() - at >= 16 {
                let value = vld1q_u8(source.as_ptr().add(at));
                let product = veorq_u8(
                    vqtbl1q_u8(low, vandq_u8(value, mask)),
                    vqtbl1q_u8(high, vshrq_n_u8::<4>(value)),
                );
                let previous = vld1q_u8(destination.as_ptr().add(at));
                vst1q_u8(
                    destination.as_mut_ptr().add(at),
                    veorq_u8(previous, product),
                );
                at += 16;
            }
            self.scalar(&source[at..], &mut destination[at..]);
        }
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[target_feature(enable = "avx2")]
    unsafe fn avx2(&self, source: &[u8], destination: &mut [u8]) {
        #[cfg(target_arch = "x86")]
        use std::arch::x86::*;
        #[cfg(target_arch = "x86_64")]
        use std::arch::x86_64::*;
        // SAFETY: equal slice lengths and AVX2 are established by the caller;
        // table loads cover exactly 16 bytes, data loads/stores exactly 32.
        unsafe {
            let low = _mm256_broadcastsi128_si256(_mm_loadu_si128(self.low.as_ptr().cast()));
            let high = _mm256_broadcastsi128_si256(_mm_loadu_si128(self.high.as_ptr().cast()));
            let mask = _mm256_set1_epi8(15);
            let mut at = 0;
            while source.len() - at >= 32 {
                let value = _mm256_loadu_si256(source.as_ptr().add(at).cast());
                let lo = _mm256_shuffle_epi8(low, _mm256_and_si256(value, mask));
                let hi = _mm256_shuffle_epi8(
                    high,
                    _mm256_and_si256(_mm256_srli_epi16::<4>(value), mask),
                );
                let previous = _mm256_loadu_si256(destination.as_ptr().add(at).cast());
                _mm256_storeu_si256(
                    destination.as_mut_ptr().add(at).cast(),
                    _mm256_xor_si256(previous, _mm256_xor_si256(lo, hi)),
                );
                at += 32;
            }
            self.scalar(&source[at..], &mut destination[at..]);
        }
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[target_feature(enable = "ssse3")]
    unsafe fn ssse3(&self, source: &[u8], destination: &mut [u8]) {
        #[cfg(target_arch = "x86")]
        use std::arch::x86::*;
        #[cfg(target_arch = "x86_64")]
        use std::arch::x86_64::*;
        // SAFETY: the detected ISA and equal lengths are established by the
        // caller. Each table and bounded data load/store spans exactly 16 bytes.
        unsafe {
            let low = _mm_loadu_si128(self.low.as_ptr().cast());
            let high = _mm_loadu_si128(self.high.as_ptr().cast());
            let mask = _mm_set1_epi8(15);
            let mut at = 0;
            while source.len() - at >= 16 {
                let value = _mm_loadu_si128(source.as_ptr().add(at).cast());
                let lo = _mm_shuffle_epi8(low, _mm_and_si128(value, mask));
                let hi = _mm_shuffle_epi8(high, _mm_and_si128(_mm_srli_epi16::<4>(value), mask));
                let previous = _mm_loadu_si128(destination.as_ptr().add(at).cast());
                _mm_storeu_si128(
                    destination.as_mut_ptr().add(at).cast(),
                    _mm_xor_si128(previous, _mm_xor_si128(lo, hi)),
                );
                at += 16;
            }
            self.scalar(&source[at..], &mut destination[at..]);
        }
    }
}

/// Multiply-accumulate using a transient plan. Retain [`MulPlan`] when a
/// coefficient will be reused across many stripes.
pub fn mul_acc_region(factor: u8, source: &[u8], destination: &mut [u8]) {
    MulPlan::new(factor).accumulate(source, destination);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dispatched_arithmetic_matches_scalar_for_all_coefficients_and_tails() {
        let source: Vec<u8> = (0..1027).map(|i| (i * 103 + i / 19) as u8).collect();
        for factor in 0..=255 {
            let plan = MulPlan::new(factor);
            for length in [0, 1, 15, 16, 17, 31, 32, 33, 1025] {
                let mut actual = vec![37; length];
                let expected: Vec<u8> = source[1..1 + length]
                    .iter()
                    .map(|value| 37 ^ mul(*value, factor))
                    .collect();
                plan.accumulate(&source[1..1 + length], &mut actual);
                assert_eq!(actual, expected, "factor {factor}, length {length}");
            }
        }
    }
}
