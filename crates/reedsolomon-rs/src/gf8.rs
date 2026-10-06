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

/// The 8×8 bit matrix `gf2p8affineqb` applies for the byte map that sends
/// input bit `col` to `images[col]`: byte `7 - row` of the qword is output
/// bit `row`, and its bit `col` is bit `row` of `images[col]`. Read with byte
/// `col` as row `col`, the images are that matrix transposed and in reverse
/// byte order, so three delta swaps and a byte swap build it.
pub(crate) fn affine_from_images(images: [u8; 8]) -> u64 {
    let mut bits = u64::from_le_bytes(images);
    for (shift, mask) in [
        (7, 0x00aa_00aa_00aa_00aa_u64),
        (14, 0x0000_cccc_0000_cccc),
        (28, 0x0000_0000_f0f0_f0f0),
    ] {
        let swap = (bits ^ (bits >> shift)) & mask;
        bits ^= swap ^ (swap << shift);
    }
    bits.swap_bytes()
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
        #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
        if crate::sve2::enabled() {
            // SAFETY: SVE2 was detected and the lengths are equal.
            unsafe { self.sve2(source, destination) };
            return;
        }
        #[cfg(target_arch = "aarch64")]
        if std::arch::is_aarch64_feature_detected!("neon") {
            // SAFETY: NEON was detected and the implementation bounds every load.
            unsafe { self.neon(source, destination) };
            return;
        }
        #[cfg(target_arch = "x86_64")]
        match gfni_tier() {
            GfniTier::Avx512 => {
                // SAFETY: the tier was detected; all loads are unaligned and bounded.
                unsafe { self.accumulate_gfni_avx512(self.affine(), source, destination) };
                return;
            }
            GfniTier::Avx2 => {
                // SAFETY: as above.
                unsafe { self.accumulate_gfni(self.affine(), source, destination) };
                return;
            }
            GfniTier::None => {}
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
        // time instead. A `+relaxed-simd` build takes the relaxed swizzle
        // inside the same kernel (see `fused_wasm::swizzle`), and a wasm build
        // without simd128 keeps falling through to the scalar path below.
        // This mirrors the GF(2¹⁶) dispatch in `gf_simd`.
        #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
        {
            self.wasm_simd128(source, destination);
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

    /// [`Self::accumulate`] on SVE2, over the whole slice.
    ///
    /// # Safety
    /// SVE2 must be available and the slices must have equal lengths.
    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
    pub(crate) unsafe fn sve2(&self, source: &[u8], destination: &mut [u8]) {
        debug_assert_eq!(source.len(), destination.len());
        // SAFETY: the caller checks SVE2 and equal lengths; distinct borrows
        // cannot overlap.
        unsafe {
            crate::sve2::map8_acc(
                &self.low,
                &self.high,
                source.as_ptr(),
                destination.as_mut_ptr(),
                source.len(),
            );
        }
    }

    /// [`Self::butterfly_scalar`] on SVE2 over the whole rows; returns their
    /// length.
    ///
    /// # Safety
    /// SVE2 must be available and the rows must have equal lengths.
    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
    pub(crate) unsafe fn butterfly_sve2<const INVERSE: bool>(
        &self,
        left: &mut [u8],
        right: &mut [u8],
    ) -> usize {
        debug_assert_eq!(left.len(), right.len());
        // SAFETY: the caller's contract; distinct borrows cannot overlap.
        unsafe {
            crate::sve2::map8_butterfly::<INVERSE>(
                &self.low,
                &self.high,
                left.as_mut_ptr(),
                right.as_mut_ptr(),
                left.len(),
            );
        }
        left.len()
    }

    /// [`Self::radix4_scalar`] on SVE2 over the whole rows; returns their
    /// length.
    ///
    /// # Safety
    /// SVE2 must be available and all four rows must have equal lengths.
    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
    pub(crate) unsafe fn radix4_sve2<const INVERSE: bool>(
        plans: [&Self; 3],
        rows: [&mut [u8]; 4],
    ) -> usize {
        let width = rows[0].len();
        debug_assert!(rows.iter().all(|row| row.len() == width));
        let [a, b, c, d] = rows;
        // SAFETY: the caller's contract; distinct borrows cannot overlap.
        unsafe {
            crate::sve2::map8_radix4::<INVERSE>(
                plans.map(|plan| (&plan.low, &plan.high)),
                [
                    a.as_mut_ptr(),
                    b.as_mut_ptr(),
                    c.as_mut_ptr(),
                    d.as_mut_ptr(),
                ],
                width,
            );
        }
        width
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

    /// This plan's map as the 8×8 bit matrix `gf2p8affineqb` applies (see
    /// [`affine_from_images`]), built from the table entries of the eight unit
    /// bits. Like the tables, it never consults the polynomial.
    #[cfg(any(target_arch = "x86_64", test))]
    pub(crate) fn affine(&self) -> u64 {
        let [l, h] = [&self.low, &self.high];
        affine_from_images([l[1], l[2], l[4], l[8], h[1], h[2], h[4], h[8]])
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

    /// [`Self::butterfly_scalar`] on GFNI, one affine transform per 32 bytes
    /// with `affine`, this plan's [`Self::affine`] matrix; returns the bytes
    /// processed.
    ///
    /// # Safety
    /// GFNI and AVX2 must be available and the rows must have equal lengths.
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "gfni,avx2")]
    pub(crate) unsafe fn butterfly_gfni<const INVERSE: bool>(
        &self,
        affine: u64,
        left: &mut [u8],
        right: &mut [u8],
    ) -> usize {
        use std::arch::x86_64::*;
        let m = fused_x86::matrix256(affine);
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
                    &m,
                    _mm256_xor_si256,
                    fused_x86::affine256
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

    /// [`Self::radix4_scalar`] on GFNI; `affine` holds the [`Self::affine`]
    /// matrices of `plans`, in the same order. Returns the bytes processed.
    ///
    /// # Safety
    /// GFNI and AVX2 must be available and all four rows must have equal
    /// lengths.
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "gfni,avx2")]
    pub(crate) unsafe fn radix4_gfni<const INVERSE: bool>(
        plans: [&Self; 3],
        affine: [u64; 3],
        rows: [&mut [u8]; 4],
    ) -> usize {
        use std::arch::x86_64::*;
        let [outer, inner_a, inner_b] = [
            fused_x86::matrix256(affine[0]),
            fused_x86::matrix256(affine[1]),
            fused_x86::matrix256(affine[2]),
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
                    fused_x86::affine256
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

    /// Replace every byte of `row` by its image under this plan's map, on the
    /// portable table walk.
    pub(crate) fn map_scalar(&self, row: &mut [u8]) {
        for value in row {
            *value = self.apply(*value);
        }
    }

    /// [`Self::map_scalar`] on NEON; returns the bytes processed.
    ///
    /// # Safety
    /// NEON must be available.
    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon")]
    pub(crate) unsafe fn map_neon(&self, row: &mut [u8]) -> usize {
        use std::arch::aarch64::*;
        let t = fused_neon::tables(self);
        let mut at = 0;
        while row.len() - at >= 16 {
            // SAFETY: the row holds 16 bytes from `at`.
            unsafe {
                let value = vld1q_u8(row.as_ptr().add(at));
                vst1q_u8(row.as_mut_ptr().add(at), fused_neon::map(&t, value));
            }
            at += 16;
        }
        at
    }

    /// [`Self::map_scalar`] on AVX2; returns the bytes processed.
    ///
    /// # Safety
    /// AVX2 must be available.
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    pub(crate) unsafe fn map_avx2(&self, row: &mut [u8]) -> usize {
        use std::arch::x86_64::*;
        let t = fused_x86::tables256(self);
        let mut at = 0;
        while row.len() - at >= 32 {
            // SAFETY: the row holds 32 bytes from `at`.
            unsafe {
                let value = _mm256_loadu_si256(row.as_ptr().add(at).cast());
                _mm256_storeu_si256(
                    row.as_mut_ptr().add(at).cast(),
                    fused_x86::map256(&t, value),
                );
            }
            at += 32;
        }
        // SAFETY: AVX2 implies SSSE3.
        at + unsafe { self.map_ssse3(&mut row[at..]) }
    }

    /// [`Self::map_scalar`] on GFNI with `affine`, this plan's
    /// [`Self::affine`] matrix; returns the bytes processed.
    ///
    /// # Safety
    /// GFNI and AVX2 must be available.
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "gfni,avx2")]
    pub(crate) unsafe fn map_gfni(&self, affine: u64, row: &mut [u8]) -> usize {
        use std::arch::x86_64::*;
        let m = fused_x86::matrix256(affine);
        let mut at = 0;
        while row.len() - at >= 32 {
            // SAFETY: the row holds 32 bytes from `at`.
            unsafe {
                let value = _mm256_loadu_si256(row.as_ptr().add(at).cast());
                _mm256_storeu_si256(
                    row.as_mut_ptr().add(at).cast(),
                    fused_x86::affine256(&m, value),
                );
            }
            at += 32;
        }
        // SAFETY: AVX2 implies SSSE3.
        at + unsafe { self.map_ssse3(&mut row[at..]) }
    }

    /// [`Self::scalar`] on GFNI with `affine`, this plan's [`Self::affine`]
    /// matrix: one affine transform per 32 bytes, the remainder on SSSE3.
    ///
    /// # Safety
    /// GFNI and AVX2 must be available and the slices must have equal lengths.
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "gfni,avx2")]
    pub(crate) unsafe fn accumulate_gfni(
        &self,
        affine: u64,
        source: &[u8],
        destination: &mut [u8],
    ) {
        use std::arch::x86_64::*;
        let m = fused_x86::matrix256(affine);
        let mut at = 0;
        while source.len() - at >= 32 {
            // SAFETY: both slices hold 32 bytes from `at`.
            unsafe {
                let value = _mm256_loadu_si256(source.as_ptr().add(at).cast());
                let previous = _mm256_loadu_si256(destination.as_ptr().add(at).cast());
                _mm256_storeu_si256(
                    destination.as_mut_ptr().add(at).cast(),
                    _mm256_xor_si256(previous, fused_x86::affine256(&m, value)),
                );
            }
            at += 32;
        }
        // SAFETY: AVX2 implies SSSE3; the remainders have equal lengths.
        unsafe { self.ssse3(&source[at..], &mut destination[at..]) };
    }

    /// [`Self::accumulate_gfni`] with 512-bit vectors: one affine transform
    /// per 64 bytes, the remainder on the 256-bit kernel.
    ///
    /// # Safety
    /// GFNI, AVX512BW and AVX512VL must be available and the slices must have
    /// equal lengths.
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "gfni,avx512bw,avx512vl")]
    pub(crate) unsafe fn accumulate_gfni_avx512(
        &self,
        affine: u64,
        source: &[u8],
        destination: &mut [u8],
    ) {
        use std::arch::x86_64::*;
        let m = _mm512_set1_epi64(affine as i64);
        let mut at = 0;
        while source.len() - at >= 64 {
            // SAFETY: both slices hold 64 bytes from `at`.
            unsafe {
                let value = _mm512_loadu_si512(source.as_ptr().add(at).cast());
                let previous = _mm512_loadu_si512(destination.as_ptr().add(at).cast());
                _mm512_storeu_si512(
                    destination.as_mut_ptr().add(at).cast(),
                    _mm512_xor_si512(previous, _mm512_gf2p8affine_epi64_epi8::<0>(value, m)),
                );
            }
            at += 64;
        }
        // SAFETY: AVX512VL implies AVX2; the remainders have equal lengths.
        unsafe { self.accumulate_gfni(affine, &source[at..], &mut destination[at..]) };
    }

    /// [`Self::map_scalar`] on SSSE3; returns the bytes processed.
    ///
    /// # Safety
    /// SSSE3 must be available.
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "ssse3")]
    pub(crate) unsafe fn map_ssse3(&self, row: &mut [u8]) -> usize {
        use std::arch::x86_64::*;
        let t = fused_x86::tables128(self);
        let mut at = 0;
        while row.len() - at >= 16 {
            // SAFETY: the row holds 16 bytes from `at`.
            unsafe {
                let value = _mm_loadu_si128(row.as_ptr().add(at).cast());
                _mm_storeu_si128(
                    row.as_mut_ptr().add(at).cast(),
                    fused_x86::map128(&t, value),
                );
            }
            at += 16;
        }
        at
    }

    /// wasm simd128: the split-nibble shape the NEON tier uses. The two
    /// 16-byte product tables are the swizzle operands, so one
    /// `i8x16.swizzle` per nibble replaces sixteen table indexings; see
    /// [`fused_wasm::swizzle`] for the relaxed-simd flavour and
    /// [`fused_wasm::UNROLL`] for the block shape.
    ///
    /// Dispatch is compile-time — see `accumulate` — so this function exists
    /// only in a `+simd128` build.
    #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
    pub(crate) fn wasm_simd128(&self, source: &[u8], destination: &mut [u8]) {
        assert_eq!(source.len(), destination.len());
        let t = fused_wasm::tables(self);
        let (from, to) = (source.as_ptr(), destination.as_mut_ptr());
        // SAFETY: `drive!` hands each block an offset with `U` whole vectors
        // of both equally long slices from it.
        let at = fused_wasm::drive!(source.len(), 16, |at, U| unsafe {
            fused_wasm::accumulate::<U>(&t, from.add(at), to.add(at))
        });
        self.scalar(&source[at..], &mut destination[at..]);
    }

    /// [`Self::butterfly_scalar`] on wasm simd128; returns the bytes
    /// processed. Rows must have equal lengths.
    #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
    pub(crate) fn butterfly_wasm<const INVERSE: bool>(
        &self,
        left: &mut [u8],
        right: &mut [u8],
    ) -> usize {
        assert_eq!(left.len(), right.len());
        let t = fused_wasm::tables(self);
        let (l, r) = (left.as_mut_ptr(), right.as_mut_ptr());
        // SAFETY: as in `wasm_simd128`, for two distinct rows.
        fused_wasm::drive!(left.len(), 16, |at, U| unsafe {
            fused_wasm::butterfly::<INVERSE, U>(&t, l.add(at), r.add(at))
        })
    }

    /// [`Self::radix4_scalar`] on wasm simd128; returns the bytes processed.
    /// All four rows must have equal lengths.
    #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
    pub(crate) fn radix4_wasm<const INVERSE: bool>(
        plans: [&Self; 3],
        rows: [&mut [u8]; 4],
    ) -> usize {
        let tables = plans.map(fused_wasm::tables);
        let width = rows[0].len();
        assert!(rows.iter().all(|row| row.len() == width));
        let rows = rows.map(<[u8]>::as_mut_ptr);
        // SAFETY: as in `wasm_simd128`, for four distinct rows.
        fused_wasm::drive!(width, 16, |at, U| unsafe {
            fused_wasm::radix4::<INVERSE, U>(&tables, rows.map(|row| row.add(at)))
        })
    }

    /// [`Self::map_scalar`] on wasm simd128; returns the bytes processed.
    #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
    pub(crate) fn map_wasm(&self, row: &mut [u8]) -> usize {
        let t = fused_wasm::tables(self);
        let pointer = row.as_mut_ptr();
        // SAFETY: as in `wasm_simd128`, for one row rewritten in place.
        fused_wasm::drive!(row.len(), 16, |at, U| unsafe {
            fused_wasm::map_block::<U>(&t, pointer.add(at))
        })
    }
}

/// Table registers, the split-nibble map and the block kernels of the wasm
/// simd128 tier. Compile-time selected: the module exists only in a
/// `+simd128` build.
#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
pub(crate) mod fused_wasm {
    use super::MulPlan;
    use core::arch::wasm32::*;

    /// Vectors per block. Every kernel loads a whole block, maps it, then
    /// stores it, so the work of one vector never waits on the stores of
    /// the one before. Measured under wasmtime on an Apple M5 Max, the
    /// fused 8-bit butterfly runs 27 GiB/s one vector at a time and 40 at
    /// two; the other kernels gain less or hold, except the 16-bit radix-4,
    /// whose 24 table vectors leave no room for a second block: it runs 16
    /// GiB/s one block at a time and 12 at two, so it passes 1.
    pub(crate) const UNROLL: usize = 2;

    /// Run `$body` over `$len` bytes in blocks of `$unroll` (by default
    /// [`UNROLL`]) vectors of `$vector` bytes, then single vectors, with
    /// `$at` the block's offset and `$u` a `const` holding its vector count;
    /// evaluates to the bytes done, a multiple of `$vector`.
    macro_rules! drive {
        ($len:expr, $vector:expr, |$at:ident, $u:ident| $body:expr) => {
            $crate::gf8::fused_wasm::drive!(
                $len,
                $vector,
                $crate::gf8::fused_wasm::UNROLL,
                |$at, $u| $body
            )
        };
        ($len:expr, $vector:expr, $unroll:expr, |$at:ident, $u:ident| $body:expr) => {{
            let len: usize = $len;
            let mut $at = 0usize;
            {
                const $u: usize = $unroll;
                while len - $at >= $u * $vector {
                    $body;
                    $at += $u * $vector;
                }
            }
            {
                const $u: usize = 1;
                while len - $at >= $vector {
                    $body;
                    $at += $vector;
                }
            }
            $at
        }};
    }
    pub(crate) use drive;

    /// One 16-entry table lookup. Every caller masks or shifts its indices
    /// into 0..=15, where `i8x16.swizzle` and `i8x16.relaxed_swizzle` agree
    /// exactly; the relaxed form only drops the lane clamp the plain form
    /// must emit on x86 hosts, so a `+relaxed-simd` build takes it.
    #[inline(always)]
    pub(crate) fn swizzle(table: v128, index: v128) -> v128 {
        #[cfg(target_feature = "relaxed-simd")]
        {
            i8x16_relaxed_swizzle(table, index)
        }
        #[cfg(not(target_feature = "relaxed-simd"))]
        {
            i8x16_swizzle(table, index)
        }
    }

    #[inline(always)]
    pub(super) fn tables(plan: &MulPlan) -> (v128, v128) {
        // SAFETY: each load reads exactly one 16-byte table.
        unsafe {
            (
                v128_load(plan.low.as_ptr().cast()),
                v128_load(plan.high.as_ptr().cast()),
            )
        }
    }

    #[inline(always)]
    pub(super) fn map(tables: &(v128, v128), value: v128) -> v128 {
        v128_xor(
            swizzle(tables.0, v128_and(value, u8x16_splat(15))),
            swizzle(tables.1, u8x16_shr(value, 4)),
        )
    }

    /// # Safety
    /// `at` must address `16 * U` readable bytes.
    #[inline(always)]
    unsafe fn load<const U: usize>(at: *const u8) -> [v128; U] {
        // SAFETY: the caller's bound; wasm loads have no alignment requirement.
        std::array::from_fn(|k| unsafe { v128_load(at.add(16 * k).cast()) })
    }

    /// # Safety
    /// `at` must address `16 * U` writable bytes.
    #[inline(always)]
    unsafe fn store<const U: usize>(at: *mut u8, value: [v128; U]) {
        for (k, value) in value.into_iter().enumerate() {
            // SAFETY: the caller's bound.
            unsafe { v128_store(at.add(16 * k).cast(), value) };
        }
    }

    /// # Safety
    /// Both pointers must address `16 * U` bytes, readable and writable
    /// respectively, and must not overlap.
    #[inline(always)]
    pub(super) unsafe fn accumulate<const U: usize>(
        tables: &(v128, v128),
        source: *const u8,
        destination: *mut u8,
    ) {
        // SAFETY: the caller's bounds.
        unsafe {
            let value = load::<U>(source);
            let mut sum = load::<U>(destination);
            for k in 0..U {
                sum[k] = v128_xor(sum[k], map(tables, value[k]));
            }
            store(destination, sum);
        }
    }

    /// # Safety
    /// Both pointers must address `16 * U` writable bytes and must not
    /// overlap.
    #[inline(always)]
    pub(super) unsafe fn butterfly<const INVERSE: bool, const U: usize>(
        tables: &(v128, v128),
        left: *mut u8,
        right: *mut u8,
    ) {
        // SAFETY: the caller's bounds.
        unsafe {
            let (mut l, mut r) = (load::<U>(left), load::<U>(right));
            for k in 0..U {
                let (mut x, mut y) = (l[k], r[k]);
                crate::gf_simd::fused_butterfly!(INVERSE, x, y, tables, v128_xor, map);
                (l[k], r[k]) = (x, y);
            }
            store(left, l);
            store(right, r);
        }
    }

    /// # Safety
    /// Every pointer must address `16 * U` writable bytes; no two overlap.
    #[inline(always)]
    pub(super) unsafe fn radix4<const INVERSE: bool, const U: usize>(
        tables: &[(v128, v128); 3],
        rows: [*mut u8; 4],
    ) {
        let [outer, inner_a, inner_b] = tables;
        // SAFETY: the caller's bounds.
        let mut values = rows.map(|row| unsafe { load::<U>(row) });
        for k in 0..U {
            let [mut a, mut b, mut c, mut d] = values.map(|row| row[k]);
            crate::gf_simd::fused_radix4!(
                INVERSE,
                [a, b, c, d],
                outer,
                inner_a,
                inner_b,
                v128_xor,
                map
            );
            for (row, value) in values.iter_mut().zip([a, b, c, d]) {
                row[k] = value;
            }
        }
        for (row, value) in rows.into_iter().zip(values) {
            // SAFETY: the caller's bounds.
            unsafe { store(row, value) };
        }
    }

    /// # Safety
    /// `row` must address `16 * U` writable bytes.
    #[inline(always)]
    pub(super) unsafe fn map_block<const U: usize>(tables: &(v128, v128), row: *mut u8) {
        // SAFETY: the caller's bound.
        unsafe { store(row, load::<U>(row).map(|value| map(tables, value))) };
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

    /// A [`MulPlan::affine`] matrix in every qword lane.
    #[target_feature(enable = "gfni,avx2")]
    #[inline]
    pub(super) fn matrix256(affine: u64) -> __m256i {
        _mm256_set1_epi64x(affine as i64)
    }

    /// The map of the fused GFNI kernels: one affine transform replaces the
    /// nibble split, both shuffles and their XOR.
    #[target_feature(enable = "gfni,avx2")]
    #[inline]
    pub(super) fn affine256(matrix: &__m256i, value: __m256i) -> __m256i {
        _mm256_gf2p8affine_epi64_epi8::<0>(value, *matrix)
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

/// The widest GFNI form the one-source and grouped kernels take on this
/// machine. Setting `WEAVER_GF8_GFNI=0` pins the nibble-shuffle kernels so a
/// GFNI host can A/B the two without a rebuild; the variable is read once and
/// never enables a kernel whose features are absent.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum GfniTier {
    None,
    Avx2,
    Avx512,
}

#[cfg(target_arch = "x86_64")]
fn gfni_tier() -> GfniTier {
    static TIER: std::sync::OnceLock<GfniTier> = std::sync::OnceLock::new();
    *TIER.get_or_init(|| {
        if std::env::var_os("WEAVER_GF8_GFNI").is_some_and(|v| v == "0")
            || !(std::arch::is_x86_feature_detected!("gfni")
                && std::arch::is_x86_feature_detected!("avx2"))
        {
            GfniTier::None
        } else if std::arch::is_x86_feature_detected!("avx512bw")
            && std::arch::is_x86_feature_detected!("avx512vl")
        {
            GfniTier::Avx512
        } else {
            GfniTier::Avx2
        }
    })
}

/// A (plan, source) pair for grouped-input multiply-accumulate into one
/// destination.
#[derive(Clone, Copy)]
pub struct PlanSrc<'a> {
    pub plan: &'a MulPlan,
    pub src: &'a [u8],
}

/// Sources a grouped kernel streams per pass over the destination: the same
/// bound on concurrent read streams the GF(2¹⁶) kernels settled on (eight
/// keeps the strips of every stream inside a 32 KiB L1).
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const BATCH_GROUP: usize = 8;

/// How many sources a caller should hand [`mul_acc_input_batch`] per call:
/// the group a host kernel folds per pass over the destination, or 1 where
/// no grouped kernel exists (the call then folds source by source through
/// [`MulPlan::accumulate`]), so a caller whose grouping costs anything can
/// skip it there. Setting `WEAVER_GF8_BATCH=0` reports 1 on every host, so a
/// caller's one-source walk can be A/B'd against the grouped kernel without
/// a rebuild.
#[must_use]
pub fn input_batch_width() -> usize {
    static WIDTH: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *WIDTH.get_or_init(|| {
        if std::env::var_os("WEAVER_GF8_BATCH").is_some_and(|v| v == "0") {
            return 1;
        }
        #[cfg(target_arch = "x86_64")]
        {
            if std::arch::is_x86_feature_detected!("avx2") {
                return BATCH_GROUP;
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            if std::arch::is_aarch64_feature_detected!("neon") {
                return BATCH_GROUP;
            }
        }
        1
    })
}

/// `destination[i] ^= Σ plan_k(source_k[i])` over every pair: the destination
/// strip stays in registers while a group of sources streams past it, so it
/// is read and written once per group instead of once per source. Every
/// slice must have the destination's length.
pub fn mul_acc_input_batch(destination: &mut [u8], inputs: &[PlanSrc<'_>]) {
    for input in inputs {
        assert_eq!(input.src.len(), destination.len());
    }
    #[cfg(target_arch = "x86_64")]
    {
        match gfni_tier() {
            GfniTier::Avx512 => {
                // SAFETY: the tier was detected; the kernel bounds every load.
                unsafe {
                    if gf8_prefetch_enabled() {
                        batch_gfni_avx512::<GF8_PREFETCH_BYTES>(destination, inputs)
                    } else {
                        batch_gfni_avx512::<0>(destination, inputs)
                    }
                };
                return;
            }
            GfniTier::Avx2 => {
                // SAFETY: as above.
                unsafe { batch_gfni_avx2(destination, inputs) };
                return;
            }
            GfniTier::None => {}
        }
        if std::arch::is_x86_feature_detected!("avx2") {
            // SAFETY: AVX2 was detected; the kernel bounds every load.
            unsafe { batch_avx2(destination, inputs) };
            return;
        }
    }
    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
    if crate::sve2::enabled() {
        // SAFETY: SVE2 was detected; every slice has the destination's length.
        unsafe { batch_sve2(destination, inputs) };
        return;
    }
    #[cfg(target_arch = "aarch64")]
    if std::arch::is_aarch64_feature_detected!("neon") {
        // SAFETY: NEON was detected; the kernel bounds every load.
        unsafe { batch_neon(destination, inputs) };
        return;
    }
    // wasm simd128 folds source by source through the unrolled
    // `MulPlan::accumulate`: under wasmtime on an Apple M5 Max a grouped
    // kernel ties it at 64 KiB and loses a third at 1 MiB and above with
    // sixteen sources, so `input_batch_width` stays 1 there.
    #[allow(unreachable_code)]
    for input in inputs {
        input.plan.accumulate(input.src, destination);
    }
}

/// The grouped loop shared by every kernel: `$strip` bytes of the
/// destination are held in `$lanes` vector registers while each source of a
/// group of [`BATCH_GROUP`] streams past them; the remainder shorter than a
/// strip goes to the one-source kernel `$tail`. `$load`, `$store` and `$xor`
/// are the tier's vector operations, `$prepare` turns a plan into the
/// operand `$map` applies to a loaded vector of source bytes. The closures
/// are safe closures over raw pointers that carry their own `unsafe`
/// blocks; that is sound only because they never leave this module-private
/// macro, where every load and store is bounded by the strip arithmetic
/// below and every tail by the equal lengths.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
macro_rules! grouped_accumulate {
    (
        $destination:expr, $inputs:expr, strip = $strip:literal, lanes = $lanes:literal,
        vector = $vector:ty, load = $load:expr, store = $store:expr, xor = $xor:expr,
        prepare = $prepare:expr, map = $map:expr, tail = $tail:expr
        $(, prefetch = $prefetch:expr)? $(,)?
    ) => {{
        let destination: &mut [u8] = $destination;
        let inputs: &[PlanSrc<'_>] = $inputs;
        const LANE: usize = $strip / $lanes;
        const _: () = assert!(
            ($strip as usize).is_power_of_two()
                && LANE * $lanes == $strip
                && LANE == std::mem::size_of::<$vector>(),
            "a strip is a power of two of whole vectors"
        );
        let vec_len = destination.len() & !($strip - 1);
        for group in inputs.chunks(BATCH_GROUP) {
            // One operand per source; the slots past a short group repeat the
            // first source's operand and are never visited, since the walk
            // below is bounded by the group. No allocation per call.
            let prepared: [_; BATCH_GROUP] =
                std::array::from_fn(|k| $prepare(group.get(k).unwrap_or(&group[0]).plan));
            let mut at = 0;
            while at < vec_len {
                let mut acc: [$vector; $lanes] = std::array::from_fn(|lane| {
                    $load(destination.as_ptr().wrapping_add(at + lane * LANE))
                });
                for (input, operand) in group.iter().zip(prepared.iter()) {
                    $(
                        // See `GF8_PREFETCH_BYTES`. A hint past the slice is
                        // architecturally harmless, and the wrapping arithmetic
                        // keeps the pointer unused.
                        let prefetch: usize = $prefetch;
                        if prefetch > 0 {
                            let ahead = input.src.as_ptr().wrapping_add(at + prefetch);
                            for line in 0..$strip / 64 {
                                prefetch_line(ahead.wrapping_add(line * 64));
                            }
                        }
                    )?
                    for (lane, acc) in acc.iter_mut().enumerate() {
                        let value = $load(input.src.as_ptr().wrapping_add(at + lane * LANE));
                        *acc = $xor(*acc, $map(operand, value));
                    }
                }
                for (lane, acc) in acc.iter().enumerate() {
                    $store(
                        destination.as_mut_ptr().wrapping_add(at + lane * LANE),
                        *acc,
                    );
                }
                at += $strip;
            }
        }
        if vec_len < destination.len() {
            for input in inputs {
                $tail(
                    input.plan,
                    &input.src[vec_len..],
                    &mut destination[vec_len..],
                );
            }
        }
    }};
}

/// Four affine transforms per 256-byte strip per source.
///
/// # Safety
/// GFNI, AVX512BW and AVX512VL must be available and the slices must have
/// equal lengths.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "gfni,avx512bw,avx512vl")]
unsafe fn batch_gfni_avx512<const PREFETCH: usize>(destination: &mut [u8], inputs: &[PlanSrc<'_>]) {
    use std::arch::x86_64::*;
    #[inline]
    #[target_feature(enable = "sse")]
    fn prefetch_line(p: *const u8) {
        _mm_prefetch::<_MM_HINT_T0>(p.cast());
    }
    grouped_accumulate!(
        destination,
        inputs,
        strip = 256,
        lanes = 4,
        vector = __m512i,
        // SAFETY: the strip arithmetic keeps every load and store in bounds.
        load = |p: *const u8| unsafe { _mm512_loadu_si512(p.cast()) },
        store = |p: *mut u8, v| unsafe { _mm512_storeu_si512(p.cast(), v) },
        xor = _mm512_xor_si512,
        // The matrix stays a qword and is broadcast at the use site: one
        // register per strip instead of eight live operands.
        prepare = |plan: &MulPlan| plan.affine() as i64,
        map = |m: &i64, v| _mm512_gf2p8affine_epi64_epi8::<0>(v, _mm512_set1_epi64(*m)),
        // SAFETY: the tier was detected by the caller; equal lengths.
        tail = |plan: &MulPlan, s, d| unsafe { plan.accumulate_gfni_avx512(plan.affine(), s, d) },
        prefetch = PREFETCH,
    );
}

/// Whether the 512-bit grouped kernel prefetches each source two strips
/// ahead of its loads. Setting `WEAVER_GF8_PF=0` pins the plain loop so a
/// host can A/B the hint without a rebuild.
#[cfg(target_arch = "x86_64")]
fn gf8_prefetch_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| !std::env::var_os("WEAVER_GF8_PF").is_some_and(|v| v == "0"))
}

/// Bytes ahead of its loads the 512-bit grouped kernel prefetches each
/// source: two 256-byte strips, every line of the strip. One load
/// instruction streaming eight sources defeats an IP-stride prefetcher.
/// Measured at one worker, 1 GiB, 100 rows, 8 MiB blocks, against no hint
/// (medians of three): create encode Sapphire Rapids 2.07 → 1.87 s and
/// Zen 4 2.10 → 2.03 s; repair decode of 50 blocks Sapphire Rapids 1.97 →
/// 1.87 s, Zen 4 1.58 → 1.58 s. One strip ahead took two thirds of the
/// Sapphire Rapids gain and little of Zen 4's; four strips ahead tied with
/// two on Sapphire Rapids and gave Zen 4 nothing. The kernel-ceiling bench
/// shows the hint costing Zen 4 on resident data (72 → 62 GiB/s at 4 KiB
/// strips, 30 → 19 at 16 MiB), which the short stripes of create and repair
/// never reach: both measured at or below the plain loop there.
#[cfg(target_arch = "x86_64")]
const GF8_PREFETCH_BYTES: usize = 512;

/// Four affine transforms per 128-byte strip per source.
///
/// # Safety
/// GFNI and AVX2 must be available and the slices must have equal lengths.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "gfni,avx2")]
unsafe fn batch_gfni_avx2(destination: &mut [u8], inputs: &[PlanSrc<'_>]) {
    use std::arch::x86_64::*;
    grouped_accumulate!(
        destination,
        inputs,
        strip = 128,
        lanes = 4,
        vector = __m256i,
        // SAFETY: the strip arithmetic keeps every load and store in bounds.
        load = |p: *const u8| unsafe { _mm256_loadu_si256(p.cast()) },
        store = |p: *mut u8, v| unsafe { _mm256_storeu_si256(p.cast(), v) },
        xor = _mm256_xor_si256,
        prepare = |plan: &MulPlan| fused_x86::matrix256(plan.affine()),
        map = fused_x86::affine256,
        // SAFETY: the tier was detected by the caller; equal lengths.
        tail = |plan: &MulPlan, s, d| unsafe { plan.accumulate_gfni(plan.affine(), s, d) },
    );
}

/// The split-nibble map, two shuffles and an XOR, per 32 bytes per source.
///
/// # Safety
/// AVX2 must be available and the slices must have equal lengths.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn batch_avx2(destination: &mut [u8], inputs: &[PlanSrc<'_>]) {
    use std::arch::x86_64::*;
    grouped_accumulate!(
        destination,
        inputs,
        strip = 128,
        lanes = 4,
        vector = __m256i,
        // SAFETY: the strip arithmetic keeps every load and store in bounds.
        load = |p: *const u8| unsafe { _mm256_loadu_si256(p.cast()) },
        store = |p: *mut u8, v| unsafe { _mm256_storeu_si256(p.cast(), v) },
        xor = _mm256_xor_si256,
        prepare = fused_x86::tables256,
        map = fused_x86::map256,
        // SAFETY: AVX2 was detected by the caller; equal lengths.
        tail = |plan: &MulPlan, s, d| unsafe { plan.avx2(s, d) },
    );
}

/// The split-nibble map, two table lookups and an XOR, per 16 bytes per
/// source.
///
/// # Safety
/// NEON must be available and the slices must have equal lengths.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn batch_neon(destination: &mut [u8], inputs: &[PlanSrc<'_>]) {
    use std::arch::aarch64::*;
    grouped_accumulate!(
        destination,
        inputs,
        strip = 64,
        lanes = 4,
        vector = uint8x16_t,
        // SAFETY: the strip arithmetic keeps every load and store in bounds.
        load = |p: *const u8| unsafe { vld1q_u8(p) },
        store = |p: *mut u8, v| unsafe { vst1q_u8(p, v) },
        xor = veorq_u8,
        prepare = fused_neon::tables,
        map = fused_neon::map,
        // SAFETY: NEON was detected by the caller; equal lengths.
        tail = |plan: &MulPlan, s, d| unsafe { plan.neon(s, d) },
    );
}

/// The grouped SVE2 kernel: up to [`crate::sve2::MAP8_BATCH`] table pairs
/// stay in registers while every source of the group streams past two
/// destination vectors, with no tail.
///
/// # Safety
/// SVE2 must be available and the slices must have equal lengths.
#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
unsafe fn batch_sve2(destination: &mut [u8], inputs: &[PlanSrc<'_>]) {
    use crate::sve2::MAP8_BATCH;
    for group in inputs.chunks(MAP8_BATCH) {
        let mut tables = [[0; 32]; MAP8_BATCH];
        let mut sources = [std::ptr::null(); MAP8_BATCH];
        for ((table, source), input) in tables.iter_mut().zip(&mut sources).zip(group) {
            table[..16].copy_from_slice(&input.plan.low);
            table[16..].copy_from_slice(&input.plan.high);
            *source = input.src.as_ptr();
        }
        // SAFETY: the caller checks SVE2 and equal lengths; the sources are
        // shared borrows, so none overlaps the exclusive destination.
        unsafe {
            crate::sve2::map8_batch(
                destination.as_mut_ptr(),
                destination.len(),
                &tables[..group.len()],
                &sources[..group.len()],
            );
        }
    }
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

    /// `gf2p8affineqb` on one byte, as Intel defines it: output bit `row` is
    /// the parity of the input masked by byte `7 - row` of the matrix.
    fn affine_scalar(matrix: u64, value: u8) -> u8 {
        (0..8).fold(0, |out, row| {
            let mask = (matrix >> ((7 - row) * 8)) as u8;
            out | ((((mask & value).count_ones() & 1) as u8) << row)
        })
    }

    #[test]
    fn affine_matrices_reproduce_every_plan_on_every_byte() {
        for factor in 0..=255u8 {
            let plan = MulPlan::new(factor);
            let matrix = plan.affine();
            for value in 0..=255u8 {
                assert_eq!(
                    affine_scalar(matrix, value),
                    mul(value, factor),
                    "factor {factor}, value {value}"
                );
            }
        }
    }

    /// Every one of the 64 bit positions of the packed matrix, from a map
    /// with a single nonzero image bit: input bit `col` sent to output bit
    /// `row` lands at byte `7 - row`, bit `col`, Intel's layout, and nowhere
    /// else. Field-multiplication matrices alone cannot prove this: their
    /// diagonals are constant before reduction, so a swap along one passes.
    #[test]
    fn affine_from_images_places_every_unit_bit() {
        for col in 0..8 {
            for row in 0..8 {
                let mut images = [0u8; 8];
                images[col] = 1 << row;
                let matrix = affine_from_images(images);
                assert_eq!(matrix, 1u64 << ((7 - row) * 8 + col), "col {col} row {row}");
                for value in 0..=255u8 {
                    let expected = if value & (1 << col) != 0 { 1 << row } else { 0 };
                    assert_eq!(
                        affine_scalar(matrix, value),
                        expected,
                        "col {col} row {row} value {value}"
                    );
                }
            }
        }
    }

    /// The GFNI kernels against the scalar tier for every factor, on rows
    /// that hold every byte value, at lengths either side of each vector
    /// width and an unaligned start.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn gfni_kernels_match_the_scalar_tier_for_every_factor() {
        if !(std::arch::is_x86_feature_detected!("gfni")
            && std::arch::is_x86_feature_detected!("avx2"))
        {
            eprintln!(
                "SKIP gfni_kernels_match_the_scalar_tier_for_every_factor: host lacks gfni+avx2"
            );
            return;
        }
        let source: Vec<u8> = (0..1100u32).map(|i| (i * 167 + i / 256) as u8).collect();
        let seed: Vec<u8> = (0..1100u32).map(|i| (i * 89 + 5) as u8).collect();
        for factor in 0..=255u8 {
            let plan = MulPlan::new(factor);
            let affine = plan.affine();
            for offset in [0usize, 1] {
                for length in [0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 256, 1025] {
                    let what = format!("factor {factor}, offset {offset}, length {length}");
                    let input = &source[offset..offset + length];
                    let mut actual = seed[offset..offset + length].to_vec();
                    let mut expected = actual.clone();
                    // SAFETY: GFNI and AVX2 were detected; equal lengths.
                    unsafe { plan.accumulate_gfni(affine, input, &mut actual) };
                    plan.scalar(input, &mut expected);
                    assert_eq!(actual, expected, "accumulate, {what}");
                    if std::arch::is_x86_feature_detected!("avx512bw")
                        && std::arch::is_x86_feature_detected!("avx512vl")
                    {
                        let mut actual = seed[offset..offset + length].to_vec();
                        // SAFETY: AVX512BW/VL were detected too; equal lengths.
                        unsafe { plan.accumulate_gfni_avx512(affine, input, &mut actual) };
                        assert_eq!(actual, expected, "accumulate avx512, {what}");
                    }

                    let mut actual = input.to_vec();
                    let mut expected = actual.clone();
                    // SAFETY: as above.
                    let done = unsafe { plan.map_gfni(affine, &mut actual) };
                    plan.map_scalar(&mut actual[done..]);
                    plan.map_scalar(&mut expected);
                    assert_eq!(actual, expected, "map, {what}");
                }
            }
        }
    }

    /// The dispatched grouped kernel and every grouped kernel the host can
    /// run against the per-source scalar walk: group widths either side of
    /// `BATCH_GROUP`, factors including 0 (source 0) and 1 (source 1),
    /// lengths either side of every strip width, and unaligned starts that
    /// differ between the destination and each source.
    #[test]
    fn grouped_kernels_match_the_scalar_sum_at_every_alignment() {
        let sources: Vec<Vec<u8>> = (0..19u32)
            .map(|k| (0..1400u32).map(|i| (i * (3 + 7 * k) + k) as u8).collect())
            .collect();
        let seed: Vec<u8> = (0..1400u32).map(|i| (i * 53 + 7) as u8).collect();
        let plans: Vec<MulPlan> = (0..19u8)
            .map(|k| MulPlan::new(if k == 1 { 1 } else { k.wrapping_mul(37) }))
            .collect();
        for count in [1usize, 2, 3, 7, 8, 9, 16, 17, 19] {
            for offset in [0usize, 1, 3] {
                for length in [
                    0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 255, 256, 257, 300, 1024, 1281,
                ] {
                    let what = format!("count {count}, offset {offset}, length {length}");
                    let inputs: Vec<PlanSrc<'_>> = (0..count)
                        .map(|k| {
                            let start = (offset + 5 * k) % 7;
                            PlanSrc {
                                plan: &plans[k],
                                src: &sources[k][start..start + length],
                            }
                        })
                        .collect();
                    let mut expected = seed[offset..offset + length].to_vec();
                    for input in &inputs {
                        input.plan.scalar(input.src, &mut expected);
                    }
                    let mut actual = seed[offset..offset + length].to_vec();
                    mul_acc_input_batch(&mut actual, &inputs);
                    assert_eq!(actual, expected, "dispatched, {what}");

                    #[cfg(target_arch = "x86_64")]
                    {
                        if std::arch::is_x86_feature_detected!("avx2") {
                            let mut actual = seed[offset..offset + length].to_vec();
                            // SAFETY: AVX2 was detected; equal lengths.
                            unsafe { batch_avx2(&mut actual, &inputs) };
                            assert_eq!(actual, expected, "avx2, {what}");
                        }
                        if std::arch::is_x86_feature_detected!("gfni")
                            && std::arch::is_x86_feature_detected!("avx2")
                        {
                            let mut actual = seed[offset..offset + length].to_vec();
                            // SAFETY: GFNI and AVX2 were detected; equal lengths.
                            unsafe { batch_gfni_avx2(&mut actual, &inputs) };
                            assert_eq!(actual, expected, "gfni avx2, {what}");
                            if std::arch::is_x86_feature_detected!("avx512bw")
                                && std::arch::is_x86_feature_detected!("avx512vl")
                            {
                                let mut actual = seed[offset..offset + length].to_vec();
                                // SAFETY: AVX512BW/VL were detected too; equal lengths.
                                unsafe { batch_gfni_avx512::<0>(&mut actual, &inputs) };
                                assert_eq!(actual, expected, "gfni avx512, {what}");
                                let mut actual = seed[offset..offset + length].to_vec();
                                // SAFETY: as above.
                                unsafe {
                                    batch_gfni_avx512::<GF8_PREFETCH_BYTES>(&mut actual, &inputs)
                                };
                                assert_eq!(actual, expected, "gfni avx512 prefetch, {what}");
                            }
                        }
                    }
                    #[cfg(target_arch = "aarch64")]
                    if std::arch::is_aarch64_feature_detected!("neon") {
                        let mut actual = seed[offset..offset + length].to_vec();
                        // SAFETY: NEON was detected; equal lengths.
                        unsafe { batch_neon(&mut actual, &inputs) };
                        assert_eq!(actual, expected, "neon, {what}");
                    }
                }
            }
        }
    }

    /// The wasm simd128 fused kernels against the scalar tier for every
    /// factor (0 and 1 included), at lengths either side of the 16-byte
    /// vector and unaligned starts: map, butterfly both ways, and radix-4
    /// both ways with three distinct plans.
    #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
    #[test]
    fn wasm_fused_kernels_match_the_scalar_tier_for_every_factor() {
        let source: Vec<u8> = (0..4 * 1100u32)
            .map(|i| (i * 167 + i / 256) as u8)
            .collect();
        for factor in 0..=255u8 {
            let plans = [
                MulPlan::new(factor),
                MulPlan::new(factor.wrapping_mul(7) ^ 1),
                MulPlan::new(factor.wrapping_add(91)),
            ];
            let plan = &plans[0];
            for offset in [0usize, 1, 3] {
                for length in [0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 257] {
                    let what = format!("factor {factor}, offset {offset}, length {length}");
                    let rows: [Vec<u8>; 4] = std::array::from_fn(|row| {
                        let start = row * 1100 + offset;
                        source[start..start + length].to_vec()
                    });

                    let (mut actual, mut expected) = (rows[0].clone(), rows[0].clone());
                    let done = plan.map_wasm(&mut actual);
                    plan.map_scalar(&mut actual[done..]);
                    plan.map_scalar(&mut expected);
                    assert_eq!(actual, expected, "map, {what}");

                    for inverse in [false, true] {
                        let (mut l, mut r) = (rows[0].clone(), rows[1].clone());
                        let (mut el, mut er) = (l.clone(), r.clone());
                        let done = if inverse {
                            plan.butterfly_wasm::<true>(&mut l, &mut r)
                        } else {
                            plan.butterfly_wasm::<false>(&mut l, &mut r)
                        };
                        if inverse {
                            plan.butterfly_scalar::<true>(&mut l[done..], &mut r[done..]);
                            plan.butterfly_scalar::<true>(&mut el, &mut er);
                        } else {
                            plan.butterfly_scalar::<false>(&mut l[done..], &mut r[done..]);
                            plan.butterfly_scalar::<false>(&mut el, &mut er);
                        }
                        assert_eq!((l, r), (el, er), "butterfly inverse {inverse}, {what}");

                        let mut actual = rows.clone();
                        let mut expected = rows.clone();
                        let refs = [&plans[0], &plans[1], &plans[2]];
                        let [a, b, c, d] = actual.each_mut().map(Vec::as_mut_slice);
                        let done = if inverse {
                            MulPlan::radix4_wasm::<true>(refs, [a, b, c, d])
                        } else {
                            MulPlan::radix4_wasm::<false>(refs, [a, b, c, d])
                        };
                        let [a, b, c, d] = actual.each_mut().map(|row| &mut row[done..]);
                        let [w, x, y, z] = expected.each_mut().map(Vec::as_mut_slice);
                        if inverse {
                            MulPlan::radix4_scalar::<true>(refs, [a, b, c, d]);
                            MulPlan::radix4_scalar::<true>(refs, [w, x, y, z]);
                        } else {
                            MulPlan::radix4_scalar::<false>(refs, [a, b, c, d]);
                            MulPlan::radix4_scalar::<false>(refs, [w, x, y, z]);
                        }
                        assert_eq!(actual, expected, "radix-4 inverse {inverse}, {what}");
                    }
                }
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
