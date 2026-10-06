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

    /// A plan for any GF(2)-linear byte map, given the images of the sixteen
    /// low and sixteen high nibbles. The kernels never consult the polynomial,
    /// so other representations, such as the Cantor basis of the FFT
    /// transforms, run on the same shuffles.
    pub(crate) fn from_tables(low: [u8; 16], high: [u8; 16]) -> Self {
        Self { low, high }
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
        // wasm has no runtime feature detection: an artifact is built with a
        // fixed `target_feature` set, so the tier is chosen here at compile
        // time instead. relaxed-simd takes precedence over plain simd128 — it
        // is the richer build — and a wasm build without simd128 keeps falling
        // through to the scalar path below, exactly as it did before this tier
        // existed. This mirrors the GF(2¹⁶) dispatch in `gf_simd`.
        #[cfg(all(target_arch = "wasm32", target_feature = "relaxed-simd"))]
        {
            // SAFETY: the kernel only exists in a simd128 build, which
            // relaxed-simd implies, and it bounds every load and store.
            unsafe { self.wasm_simd128::<true>(source, destination) };
            return;
        }
        #[cfg(all(
            target_arch = "wasm32",
            target_feature = "simd128",
            not(target_feature = "relaxed-simd")
        ))]
        {
            // SAFETY: as above, for the plain-simd128 build.
            unsafe { self.wasm_simd128::<false>(source, destination) };
            return;
        }
        #[allow(unreachable_code)]
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
    pub(crate) unsafe fn neon(&self, source: &[u8], destination: &mut [u8]) {
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
    pub(crate) unsafe fn avx2(&self, source: &[u8], destination: &mut [u8]) {
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
    pub(crate) unsafe fn ssse3(&self, source: &[u8], destination: &mut [u8]) {
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

    /// The image of one byte under this plan's map.
    fn apply(&self, value: u8) -> u8 {
        self.low[(value & 15) as usize] ^ self.high[(value >> 4) as usize]
    }

    /// One additive-FFT butterfly per byte on the portable table walk: forward
    /// `left ^= map(right); right ^= left`, inverse `right ^= left;
    /// left ^= map(right)`. Rows must have equal lengths.
    pub(crate) fn butterfly_scalar<const INVERSE: bool>(&self, left: &mut [u8], right: &mut [u8]) {
        for (l, r) in left.iter_mut().zip(right) {
            let (mut x, mut y) = (*l, *r);
            crate::gf_simd::fused_butterfly!(
                INVERSE,
                x,
                y,
                self,
                std::ops::BitXor::bitxor,
                Self::apply
            );
            (*l, *r) = (x, y);
        }
    }

    /// Two butterfly stages per byte over four rows on the portable table
    /// walk; `plans` are the outer map and the two inner maps, in the order
    /// of `gf_simd::fused_radix4`. Rows must have equal lengths.
    pub(crate) fn radix4_scalar<const INVERSE: bool>(plans: [&Self; 3], rows: [&mut [u8]; 4]) {
        let [outer, inner_a, inner_b] = plans;
        let [a, b, c, d] = rows;
        for at in 0..a.len() {
            let (mut w, mut x, mut y, mut z) = (a[at], b[at], c[at], d[at]);
            crate::gf_simd::fused_radix4!(
                INVERSE,
                [w, x, y, z],
                outer,
                inner_a,
                inner_b,
                std::ops::BitXor::bitxor,
                Self::apply
            );
            (a[at], b[at], c[at], d[at]) = (w, x, y, z);
        }
    }

    /// [`Self::butterfly_scalar`] on NEON; returns the bytes processed.
    ///
    /// # Safety
    /// NEON must be available and the rows must have equal lengths.
    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon")]
    pub(crate) unsafe fn butterfly_neon<const INVERSE: bool>(
        &self,
        left: &mut [u8],
        right: &mut [u8],
    ) -> usize {
        use std::arch::aarch64::*;
        let t = fused_neon::tables(self);
        let mut at = 0;
        while left.len() - at >= 16 {
            // SAFETY: both rows hold 16 bytes from `at`.
            unsafe {
                let mut l = vld1q_u8(left.as_ptr().add(at));
                let mut r = vld1q_u8(right.as_ptr().add(at));
                crate::gf_simd::fused_butterfly!(INVERSE, l, r, &t, veorq_u8, fused_neon::map);
                vst1q_u8(left.as_mut_ptr().add(at), l);
                vst1q_u8(right.as_mut_ptr().add(at), r);
            }
            at += 16;
        }
        at
    }

    /// [`Self::radix4_scalar`] on NEON; returns the bytes processed.
    ///
    /// # Safety
    /// NEON must be available and all four rows must have equal lengths.
    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon")]
    pub(crate) unsafe fn radix4_neon<const INVERSE: bool>(
        plans: [&Self; 3],
        rows: [&mut [u8]; 4],
    ) -> usize {
        use std::arch::aarch64::*;
        let [outer, inner_a, inner_b] = [
            fused_neon::tables(plans[0]),
            fused_neon::tables(plans[1]),
            fused_neon::tables(plans[2]),
        ];
        let [ra, rb, rc, rd] = rows;
        let mut at = 0;
        while ra.len() - at >= 16 {
            // SAFETY: all four rows hold 16 bytes from `at`.
            unsafe {
                let mut a = vld1q_u8(ra.as_ptr().add(at));
                let mut b = vld1q_u8(rb.as_ptr().add(at));
                let mut c = vld1q_u8(rc.as_ptr().add(at));
                let mut d = vld1q_u8(rd.as_ptr().add(at));
                crate::gf_simd::fused_radix4!(
                    INVERSE,
                    [a, b, c, d],
                    &outer,
                    &inner_a,
                    &inner_b,
                    veorq_u8,
                    fused_neon::map
                );
                vst1q_u8(ra.as_mut_ptr().add(at), a);
                vst1q_u8(rb.as_mut_ptr().add(at), b);
                vst1q_u8(rc.as_mut_ptr().add(at), c);
                vst1q_u8(rd.as_mut_ptr().add(at), d);
            }
            at += 16;
        }
        at
    }

    /// [`Self::butterfly_scalar`] on AVX2; returns the bytes processed.
    ///
    /// # Safety
    /// AVX2 must be available and the rows must have equal lengths.
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    pub(crate) unsafe fn butterfly_avx2<const INVERSE: bool>(
        &self,
        left: &mut [u8],
        right: &mut [u8],
    ) -> usize {
        use std::arch::x86_64::*;
        let t = fused_x86::tables256(self);
        let mut at = 0;
        while left.len() - at >= 32 {
            // SAFETY: both rows hold 32 bytes from `at`.
            unsafe {
                let mut l = _mm256_loadu_si256(left.as_ptr().add(at).cast());
                let mut r = _mm256_loadu_si256(right.as_ptr().add(at).cast());
                crate::gf_simd::fused_butterfly!(
                    INVERSE,
                    l,
                    r,
                    &t,
                    _mm256_xor_si256,
                    fused_x86::map256
                );
                _mm256_storeu_si256(left.as_mut_ptr().add(at).cast(), l);
                _mm256_storeu_si256(right.as_mut_ptr().add(at).cast(), r);
            }
            at += 32;
        }
        // SAFETY: AVX2 implies SSSE3; the remainders have equal lengths.
        at + unsafe { self.butterfly_ssse3::<INVERSE>(&mut left[at..], &mut right[at..]) }
    }

    /// [`Self::butterfly_scalar`] on SSSE3; returns the bytes processed.
    ///
    /// # Safety
    /// SSSE3 must be available and the rows must have equal lengths.
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "ssse3")]
    pub(crate) unsafe fn butterfly_ssse3<const INVERSE: bool>(
        &self,
        left: &mut [u8],
        right: &mut [u8],
    ) -> usize {
        use std::arch::x86_64::*;
        let t = fused_x86::tables128(self);
        let mut at = 0;
        while left.len() - at >= 16 {
            // SAFETY: both rows hold 16 bytes from `at`.
            unsafe {
                let mut l = _mm_loadu_si128(left.as_ptr().add(at).cast());
                let mut r = _mm_loadu_si128(right.as_ptr().add(at).cast());
                crate::gf_simd::fused_butterfly!(
                    INVERSE,
                    l,
                    r,
                    &t,
                    _mm_xor_si128,
                    fused_x86::map128
                );
                _mm_storeu_si128(left.as_mut_ptr().add(at).cast(), l);
                _mm_storeu_si128(right.as_mut_ptr().add(at).cast(), r);
            }
            at += 16;
        }
        at
    }

    /// [`Self::radix4_scalar`] on AVX2; returns the bytes processed.
    ///
    /// # Safety
    /// AVX2 must be available and all four rows must have equal lengths.
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    pub(crate) unsafe fn radix4_avx2<const INVERSE: bool>(
        plans: [&Self; 3],
        rows: [&mut [u8]; 4],
    ) -> usize {
        use std::arch::x86_64::*;
        let [outer, inner_a, inner_b] = [
            fused_x86::tables256(plans[0]),
            fused_x86::tables256(plans[1]),
            fused_x86::tables256(plans[2]),
        ];
        let [ra, rb, rc, rd] = rows;
        let mut at = 0;
        while ra.len() - at >= 32 {
            // SAFETY: all four rows hold 32 bytes from `at`.
            unsafe {
                let mut a = _mm256_loadu_si256(ra.as_ptr().add(at).cast());
                let mut b = _mm256_loadu_si256(rb.as_ptr().add(at).cast());
                let mut c = _mm256_loadu_si256(rc.as_ptr().add(at).cast());
                let mut d = _mm256_loadu_si256(rd.as_ptr().add(at).cast());
                crate::gf_simd::fused_radix4!(
                    INVERSE,
                    [a, b, c, d],
                    &outer,
                    &inner_a,
                    &inner_b,
                    _mm256_xor_si256,
                    fused_x86::map256
                );
                _mm256_storeu_si256(ra.as_mut_ptr().add(at).cast(), a);
                _mm256_storeu_si256(rb.as_mut_ptr().add(at).cast(), b);
                _mm256_storeu_si256(rc.as_mut_ptr().add(at).cast(), c);
                _mm256_storeu_si256(rd.as_mut_ptr().add(at).cast(), d);
            }
            at += 32;
        }
        // SAFETY: AVX2 implies SSSE3; the remainders have equal lengths.
        at + unsafe {
            Self::radix4_ssse3::<INVERSE>(
                plans,
                [&mut ra[at..], &mut rb[at..], &mut rc[at..], &mut rd[at..]],
            )
        }
    }

    /// [`Self::radix4_scalar`] on SSSE3; returns the bytes processed.
    ///
    /// # Safety
    /// SSSE3 must be available and all four rows must have equal lengths.
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "ssse3")]
    pub(crate) unsafe fn radix4_ssse3<const INVERSE: bool>(
        plans: [&Self; 3],
        rows: [&mut [u8]; 4],
    ) -> usize {
        use std::arch::x86_64::*;
        let [outer, inner_a, inner_b] = [
            fused_x86::tables128(plans[0]),
            fused_x86::tables128(plans[1]),
            fused_x86::tables128(plans[2]),
        ];
        let [ra, rb, rc, rd] = rows;
        let mut at = 0;
        while ra.len() - at >= 16 {
            // SAFETY: all four rows hold 16 bytes from `at`.
            unsafe {
                let mut a = _mm_loadu_si128(ra.as_ptr().add(at).cast());
                let mut b = _mm_loadu_si128(rb.as_ptr().add(at).cast());
                let mut c = _mm_loadu_si128(rc.as_ptr().add(at).cast());
                let mut d = _mm_loadu_si128(rd.as_ptr().add(at).cast());
                crate::gf_simd::fused_radix4!(
                    INVERSE,
                    [a, b, c, d],
                    &outer,
                    &inner_a,
                    &inner_b,
                    _mm_xor_si128,
                    fused_x86::map128
                );
                _mm_storeu_si128(ra.as_mut_ptr().add(at).cast(), a);
                _mm_storeu_si128(rb.as_mut_ptr().add(at).cast(), b);
                _mm_storeu_si128(rc.as_mut_ptr().add(at).cast(), c);
                _mm_storeu_si128(rd.as_mut_ptr().add(at).cast(), d);
            }
            at += 16;
        }
        at
    }

    /// wasm simd128: 16 bytes per iteration, the same split-nibble shape the
    /// NEON tier uses. The two 16-byte product tables are the swizzle operands,
    /// so one `i8x16.swizzle` per nibble replaces sixteen table indexings.
    ///
    /// Two flavors share one body through the `lookup!` macro parameter, as in
    /// the GF(2¹⁶) kernel in `gf_simd`:
    ///
    /// * `i8x16_swizzle` (simd128) clears a lane whose index is out of range,
    ///   which never happens here: the low index is masked to 0..=15 and the
    ///   high index is a logical shift right by four.
    /// * `i8x16_relaxed_swizzle` (relaxed-simd) produces the same bytes; it
    ///   only drops the lane clamp the plain form must emit on x86 hosts.
    ///
    /// Dispatch is compile-time — see `accumulate` — so this function exists
    /// only in a `+simd128` build.
    #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
    unsafe fn wasm_simd128<const RELAXED: bool>(&self, source: &[u8], destination: &mut [u8]) {
        use core::arch::wasm32::*;

        // `i8x16_relaxed_swizzle` is only defined when relaxed-simd is enabled,
        // so without it the `RELAXED` arm is compiled out entirely.
        macro_rules! lookup {
            ($table:expr, $index:expr) => {{
                #[cfg(target_feature = "relaxed-simd")]
                {
                    if RELAXED {
                        i8x16_relaxed_swizzle($table, $index)
                    } else {
                        i8x16_swizzle($table, $index)
                    }
                }
                #[cfg(not(target_feature = "relaxed-simd"))]
                {
                    let _ = RELAXED;
                    i8x16_swizzle($table, $index)
                }
            }};
        }

        // SAFETY: the caller established equal lengths. The loop stops before a
        // 16-byte load or store could cross either slice, and each table load
        // spans exactly the sixteen bytes of its array.
        unsafe {
            let low = v128_load(self.low.as_ptr() as *const v128);
            let high = v128_load(self.high.as_ptr() as *const v128);
            let mask = u8x16_splat(15);
            let mut at = 0;
            while source.len() - at >= 16 {
                let value = v128_load(source.as_ptr().add(at) as *const v128);
                let product = v128_xor(
                    lookup!(low, v128_and(value, mask)),
                    lookup!(high, u8x16_shr(value, 4)),
                );
                let previous = v128_load(destination.as_ptr().add(at) as *const v128);
                v128_store(
                    destination.as_mut_ptr().add(at) as *mut v128,
                    v128_xor(previous, product),
                );
                at += 16;
            }
            self.scalar(&source[at..], &mut destination[at..]);
        }
    }
}

/// Table registers and the split-nibble map of the fused NEON kernels.
#[cfg(target_arch = "aarch64")]
mod fused_neon {
    use super::MulPlan;
    use std::arch::aarch64::*;

    #[target_feature(enable = "neon")]
    #[inline]
    pub(super) fn tables(plan: &MulPlan) -> (uint8x16_t, uint8x16_t) {
        // SAFETY: each load reads exactly one 16-byte table.
        unsafe { (vld1q_u8(plan.low.as_ptr()), vld1q_u8(plan.high.as_ptr())) }
    }

    #[target_feature(enable = "neon")]
    #[inline]
    pub(super) fn map(tables: &(uint8x16_t, uint8x16_t), value: uint8x16_t) -> uint8x16_t {
        veorq_u8(
            vqtbl1q_u8(tables.0, vandq_u8(value, vdupq_n_u8(15))),
            vqtbl1q_u8(tables.1, vshrq_n_u8::<4>(value)),
        )
    }
}

/// Table registers and the split-nibble maps of the fused x86 kernels.
#[cfg(target_arch = "x86_64")]
mod fused_x86 {
    use super::MulPlan;
    use std::arch::x86_64::*;

    #[target_feature(enable = "avx2")]
    #[inline]
    pub(super) fn tables256(plan: &MulPlan) -> (__m256i, __m256i) {
        // SAFETY: each load reads exactly one 16-byte table.
        unsafe {
            (
                _mm256_broadcastsi128_si256(_mm_loadu_si128(plan.low.as_ptr().cast())),
                _mm256_broadcastsi128_si256(_mm_loadu_si128(plan.high.as_ptr().cast())),
            )
        }
    }

    #[target_feature(enable = "avx2")]
    #[inline]
    pub(super) fn map256(tables: &(__m256i, __m256i), value: __m256i) -> __m256i {
        let mask = _mm256_set1_epi8(15);
        _mm256_xor_si256(
            _mm256_shuffle_epi8(tables.0, _mm256_and_si256(value, mask)),
            _mm256_shuffle_epi8(
                tables.1,
                _mm256_and_si256(_mm256_srli_epi16::<4>(value), mask),
            ),
        )
    }

    #[target_feature(enable = "ssse3")]
    #[inline]
    pub(super) fn tables128(plan: &MulPlan) -> (__m128i, __m128i) {
        // SAFETY: each load reads exactly one 16-byte table.
        unsafe {
            (
                _mm_loadu_si128(plan.low.as_ptr().cast()),
                _mm_loadu_si128(plan.high.as_ptr().cast()),
            )
        }
    }

    #[target_feature(enable = "ssse3")]
    #[inline]
    pub(super) fn map128(tables: &(__m128i, __m128i), value: __m128i) -> __m128i {
        let mask = _mm_set1_epi8(15);
        _mm_xor_si128(
            _mm_shuffle_epi8(tables.0, _mm_and_si128(value, mask)),
            _mm_shuffle_epi8(tables.1, _mm_and_si128(_mm_srli_epi16::<4>(value), mask)),
        )
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

    #[test]
    fn the_dispatched_tier_matches_the_scalar_tier_at_every_alignment() {
        // Whatever tier this build dispatches to — NEON, AVX2, SSSE3, the wasm
        // simd128 or relaxed-simd kernel, or scalar itself — has to agree with
        // `scalar` byte for byte. Comparing the two tiers directly, rather than
        // both against `mul`, is what covers the lane bookkeeping: a swizzle
        // index that leaves the 0..=15 range clears its lane, and a misplaced
        // lane moves a product, and either shows up as a changed byte here.
        //
        // The offsets walk both slices off a 16-byte boundary, so the vector
        // loads are unaligned and the lengths chosen around 16, 32 and 64 leave
        // every tail the kernels can produce.
        let source: Vec<u8> = (0..2048u32).map(|i| (i * 181 + i / 7) as u8).collect();
        let seed: Vec<u8> = (0..2048u32).map(|i| (i * 97 + 11) as u8).collect();
        for factor in 0..=255u8 {
            let plan = MulPlan::new(factor);
            for offset in 0..4usize {
                for length in [
                    0, 1, 2, 3, 7, 8, 15, 16, 17, 23, 31, 32, 33, 47, 63, 64, 65, 127, 129, 1023,
                    1024,
                ] {
                    let input = &source[offset..offset + length];
                    let mut dispatched = seed[offset..offset + length].to_vec();
                    let mut reference = dispatched.clone();
                    plan.accumulate(input, &mut dispatched);
                    plan.scalar(input, &mut reference);
                    assert_eq!(
                        dispatched, reference,
                        "factor {factor}, offset {offset}, length {length}"
                    );
                }
            }
        }
    }
}
