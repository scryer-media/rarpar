//! Runtime-dispatched GF(2⁸) multiply-accumulate for polynomial 0x11d.

/// A reusable nibble-shuffle multiplication plan for one coefficient.
#[derive(Clone)]
pub struct MulPlan {
    low: [u8; 16],
    high: [u8; 16],
    /// The map as the 8×8 bit matrix `gf2p8affineqb` applies, built once with
    /// the tables so no GFNI call rebuilds it.
    #[cfg(target_arch = "x86_64")]
    affine: u64,
    kind: Kind,
}

/// What a plan's map is, decided when the plan is built: the zero map is a
/// no-op for every accumulate and the identity a plain XOR, so neither runs
/// a multiplication kernel.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Zero,
    Identity,
    General,
}

/// Scalar multiplication, also used as the portable arithmetic oracle.
#[must_use]
pub const fn mul(mut left: u8, mut right: u8) -> u8 {
    let mut result = 0;
    let mut step = 0;
    while step < 8 {
        result ^= left & 0u8.wrapping_sub(right & 1);
        left = (left << 1) ^ (0x1d & 0u8.wrapping_sub(left >> 7));
        right >>= 1;
        step += 1;
    }
    result
}

/// The 8×8 bit matrix `gf2p8affineqb` applies for the byte map that sends
/// input bit `col` to `images[col]`: byte `7 - row` of the qword is output
/// bit `row`, and its bit `col` is bit `row` of `images[col]`. Read with byte
/// `col` as row `col`, the images are that matrix transposed and in reverse
/// byte order, so three delta swaps and a byte swap build it.
pub(crate) const fn affine_from_images(images: [u8; 8]) -> u64 {
    let mut bits = u64::from_le_bytes(images);
    let steps = [
        (7, 0x00aa_00aa_00aa_00aa_u64),
        (14, 0x0000_cccc_0000_cccc),
        (28, 0x0000_0000_f0f0_f0f0),
    ];
    let mut at = 0;
    while at < steps.len() {
        let (shift, mask) = steps[at];
        let swap = (bits ^ (bits >> shift)) & mask;
        bits ^= swap ^ (swap << shift);
        at += 1;
    }
    bits.swap_bytes()
}

/// The plan of every coefficient, built at compile time, so a caller that
/// starts from a factor pays no table construction: see [`MulPlan::cached`].
static PLANS: [MulPlan; 256] = {
    // `MulPlan` is not `Copy`, so the array is filled one slot at a time from
    // a placeholder rather than by a repeat expression of a non-const value.
    const ZERO: MulPlan = MulPlan::new(0);
    let mut plans = [ZERO; 256];
    let mut factor = 1;
    while factor < 256 {
        plans[factor] = MulPlan::new(factor as u8);
        factor += 1;
    }
    plans
};

impl MulPlan {
    /// Precompute the two 16-entry tables for a coefficient.
    #[must_use]
    pub const fn new(factor: u8) -> Self {
        let mut low = [0u8; 16];
        let mut high = [0u8; 16];
        let mut n = 0;
        while n < 16 {
            low[n] = mul(n as u8, factor);
            high[n] = mul((n << 4) as u8, factor);
            n += 1;
        }
        let kind = match factor {
            0 => Kind::Zero,
            1 => Kind::Identity,
            _ => Kind::General,
        };
        Self::with_kind(low, high, kind)
    }

    /// The compile-time plan for `factor`: the same tables [`Self::new`]
    /// builds, without building them. Hot loops that start from a factor
    /// should take this instead of a transient plan.
    #[must_use]
    pub fn cached(factor: u8) -> &'static Self {
        &PLANS[usize::from(factor)]
    }

    const fn with_kind(low: [u8; 16], high: [u8; 16], kind: Kind) -> Self {
        Self {
            #[cfg(target_arch = "x86_64")]
            affine: affine_from_images([
                low[1], low[2], low[4], low[8], high[1], high[2], high[4], high[8],
            ]),
            low,
            high,
            kind,
        }
    }

    /// A plan for any GF(2)-linear byte map, given the images of the sixteen
    /// low and sixteen high nibbles. The kernels never consult the polynomial,
    /// so other representations, such as the Cantor basis of the FFT
    /// transforms, run on the same shuffles.
    pub(crate) fn from_tables(low: [u8; 16], high: [u8; 16]) -> Self {
        let kind = if low == [0; 16] && high == [0; 16] {
            Kind::Zero
        } else if low == std::array::from_fn(|n| n as u8)
            && high == std::array::from_fn(|n| (n << 4) as u8)
        {
            Kind::Identity
        } else {
            Kind::General
        };
        Self::with_kind(low, high, kind)
    }

    /// Whether this plan's map sends every byte to zero, so accumulating it
    /// changes nothing.
    pub(crate) fn is_zero(&self) -> bool {
        self.kind == Kind::Zero
    }

    /// Accumulate `source * factor` into `destination`. Buffers must have equal
    /// lengths and may be unaligned; CPU dispatch always has a scalar fallback.
    /// Factor 0 returns without touching either buffer and factor 1 is a plain
    /// XOR, on every tier.
    pub fn accumulate(&self, source: &[u8], destination: &mut [u8]) {
        assert_eq!(source.len(), destination.len());
        match self.kind {
            Kind::Zero => return,
            Kind::Identity => {
                xor_into(source, destination);
                return;
            }
            Kind::General => {}
        }
        #[cfg(target_arch = "aarch64")]
        if std::arch::is_aarch64_feature_detected!("neon") {
            // SAFETY: NEON was detected and the implementation bounds every load.
            unsafe { self.neon(source, destination) };
            return;
        }
        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY (every arm): `x86_tier` reports a tier only after
            // detecting its features; every kernel bounds its loads and
            // stores by the equal lengths asserted above.
            match x86_tier() {
                X86Tier::GfniAvx512 => unsafe {
                    self.accumulate_gfni_avx512(self.affine, source, destination)
                },
                X86Tier::GfniAvx2 => unsafe {
                    self.accumulate_gfni(self.affine, source, destination)
                },
                X86Tier::Avx512 => unsafe { self.avx512(source, destination) },
                X86Tier::Avx2 => unsafe { self.avx2(source, destination) },
                X86Tier::Ssse3 => unsafe { self.ssse3(source, destination) },
                X86Tier::Scalar => self.scalar(source, destination),
            }
            return;
        }
        #[cfg(target_arch = "x86")]
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

    /// This plan's map as the 8×8 bit matrix `gf2p8affineqb` applies (see
    /// [`affine_from_images`]), built from the table entries of the eight unit
    /// bits. Like the tables, it never consults the polynomial.
    #[cfg(any(target_arch = "x86_64", test))]
    pub(crate) fn affine(&self) -> u64 {
        #[cfg(target_arch = "x86_64")]
        return self.affine;
        #[cfg(not(target_arch = "x86_64"))]
        {
            let [l, h] = [&self.low, &self.high];
            affine_from_images([l[1], l[2], l[4], l[8], h[1], h[2], h[4], h[8]])
        }
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

    /// [`Self::avx2`] with 512-bit vectors: the split-nibble map on
    /// `vpshufb` over whole 64-byte blocks, the remainder on the 256-bit
    /// kernel. The tier for AVX-512 hosts without GFNI.
    ///
    /// # Safety
    /// AVX512BW and AVX512VL must be available and the slices must have equal
    /// lengths.
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx512bw,avx512vl")]
    pub(crate) unsafe fn avx512(&self, source: &[u8], destination: &mut [u8]) {
        use std::arch::x86_64::*;
        let t = fused_x86::tables512(self);
        let mut at = 0;
        while source.len() - at >= 64 {
            // SAFETY: both slices hold 64 bytes from `at`.
            unsafe {
                let value = _mm512_loadu_si512(source.as_ptr().add(at).cast());
                let previous = _mm512_loadu_si512(destination.as_ptr().add(at).cast());
                _mm512_storeu_si512(
                    destination.as_mut_ptr().add(at).cast(),
                    _mm512_xor_si512(previous, fused_x86::map512(&t, value)),
                );
            }
            at += 64;
        }
        // SAFETY: AVX512BW implies AVX2; the remainders have equal lengths.
        unsafe { self.avx2(&source[at..], &mut destination[at..]) };
    }

    /// [`Self::butterfly_avx2`] with 512-bit vectors; returns the bytes
    /// processed.
    ///
    /// # Safety
    /// AVX512BW and AVX512VL must be available and the rows must have equal
    /// lengths.
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx512bw,avx512vl")]
    pub(crate) unsafe fn butterfly_avx512<const INVERSE: bool>(
        &self,
        left: &mut [u8],
        right: &mut [u8],
    ) -> usize {
        use std::arch::x86_64::*;
        let t = fused_x86::tables512(self);
        let mut at = 0;
        while left.len() - at >= 64 {
            // SAFETY: both rows hold 64 bytes from `at`.
            unsafe {
                let mut l = _mm512_loadu_si512(left.as_ptr().add(at).cast());
                let mut r = _mm512_loadu_si512(right.as_ptr().add(at).cast());
                crate::gf_simd::fused_butterfly!(
                    INVERSE,
                    l,
                    r,
                    &t,
                    _mm512_xor_si512,
                    fused_x86::map512
                );
                _mm512_storeu_si512(left.as_mut_ptr().add(at).cast(), l);
                _mm512_storeu_si512(right.as_mut_ptr().add(at).cast(), r);
            }
            at += 64;
        }
        // SAFETY: AVX512BW implies AVX2; the remainders have equal lengths.
        at + unsafe { self.butterfly_avx2::<INVERSE>(&mut left[at..], &mut right[at..]) }
    }

    /// [`Self::radix4_avx2`] with 512-bit vectors; returns the bytes
    /// processed.
    ///
    /// # Safety
    /// AVX512BW and AVX512VL must be available and all four rows must have
    /// equal lengths.
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx512bw,avx512vl")]
    pub(crate) unsafe fn radix4_avx512<const INVERSE: bool>(
        plans: [&Self; 3],
        rows: [&mut [u8]; 4],
    ) -> usize {
        use std::arch::x86_64::*;
        let [outer, inner_a, inner_b] = [
            fused_x86::tables512(plans[0]),
            fused_x86::tables512(plans[1]),
            fused_x86::tables512(plans[2]),
        ];
        let [ra, rb, rc, rd] = rows;
        let mut at = 0;
        while ra.len() - at >= 64 {
            // SAFETY: all four rows hold 64 bytes from `at`.
            unsafe {
                let mut a = _mm512_loadu_si512(ra.as_ptr().add(at).cast());
                let mut b = _mm512_loadu_si512(rb.as_ptr().add(at).cast());
                let mut c = _mm512_loadu_si512(rc.as_ptr().add(at).cast());
                let mut d = _mm512_loadu_si512(rd.as_ptr().add(at).cast());
                crate::gf_simd::fused_radix4!(
                    INVERSE,
                    [a, b, c, d],
                    &outer,
                    &inner_a,
                    &inner_b,
                    _mm512_xor_si512,
                    fused_x86::map512
                );
                _mm512_storeu_si512(ra.as_mut_ptr().add(at).cast(), a);
                _mm512_storeu_si512(rb.as_mut_ptr().add(at).cast(), b);
                _mm512_storeu_si512(rc.as_mut_ptr().add(at).cast(), c);
                _mm512_storeu_si512(rd.as_mut_ptr().add(at).cast(), d);
            }
            at += 64;
        }
        // SAFETY: AVX512BW implies AVX2; the remainders have equal lengths.
        at + unsafe {
            Self::radix4_avx2::<INVERSE>(
                plans,
                [&mut ra[at..], &mut rb[at..], &mut rc[at..], &mut rd[at..]],
            )
        }
    }

    /// [`Self::map_avx2`] with 512-bit vectors; returns the bytes processed.
    ///
    /// # Safety
    /// AVX512BW and AVX512VL must be available.
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx512bw,avx512vl")]
    pub(crate) unsafe fn map_avx512(&self, row: &mut [u8]) -> usize {
        use std::arch::x86_64::*;
        let t = fused_x86::tables512(self);
        let mut at = 0;
        while row.len() - at >= 64 {
            // SAFETY: the row holds 64 bytes from `at`.
            unsafe {
                let value = _mm512_loadu_si512(row.as_ptr().add(at).cast());
                _mm512_storeu_si512(
                    row.as_mut_ptr().add(at).cast(),
                    fused_x86::map512(&t, value),
                );
            }
            at += 64;
        }
        // SAFETY: AVX512BW implies AVX2.
        at + unsafe { self.map_avx2(&mut row[at..]) }
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

    #[target_feature(enable = "avx512bw,avx512vl")]
    #[inline]
    pub(super) fn tables512(plan: &MulPlan) -> (__m512i, __m512i) {
        // SAFETY: each load reads exactly one 16-byte table.
        unsafe {
            (
                _mm512_broadcast_i32x4(_mm_loadu_si128(plan.low.as_ptr().cast())),
                _mm512_broadcast_i32x4(_mm_loadu_si128(plan.high.as_ptr().cast())),
            )
        }
    }

    /// The split-nibble map on 512-bit vectors: `vpshufb` looks up within
    /// each 128-bit lane, and every lane holds the same two tables.
    #[target_feature(enable = "avx512bw,avx512vl")]
    #[inline]
    pub(super) fn map512(tables: &(__m512i, __m512i), value: __m512i) -> __m512i {
        let mask = _mm512_set1_epi8(15);
        _mm512_xor_si512(
            _mm512_shuffle_epi8(tables.0, _mm512_and_si512(value, mask)),
            _mm512_shuffle_epi8(
                tables.1,
                _mm512_and_si512(_mm512_srli_epi16::<4>(value), mask),
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

/// Multiply-accumulate by `factor`, through its compile-time plan
/// ([`MulPlan::cached`]): no tables are built per call, factor 0 returns at
/// once and factor 1 is a plain XOR.
pub fn mul_acc_region(factor: u8, source: &[u8], destination: &mut [u8]) {
    MulPlan::cached(factor).accumulate(source, destination);
}

/// `destination ^= source`, the identity plan's accumulate: whole vectors on
/// the widest tier the host dispatches to, then a byte loop.
fn xor_into(source: &[u8], destination: &mut [u8]) {
    // SAFETY (both vector arms): the tier was detected and both slices have
    // the length the caller asserted.
    #[cfg(target_arch = "x86_64")]
    let done = match x86_tier() {
        X86Tier::GfniAvx512 | X86Tier::Avx512 => unsafe { xor_avx512(source, destination) },
        X86Tier::GfniAvx2 | X86Tier::Avx2 => unsafe { xor_avx2(source, destination) },
        X86Tier::Ssse3 | X86Tier::Scalar => 0,
    };
    #[cfg(not(target_arch = "x86_64"))]
    let done = 0;
    for (to, from) in destination[done..].iter_mut().zip(&source[done..]) {
        *to ^= from;
    }
}

/// [`xor_into`] over whole 64-byte blocks; returns the bytes processed.
///
/// # Safety
/// AVX512F must be available and the slices must have equal lengths.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f")]
unsafe fn xor_avx512(source: &[u8], destination: &mut [u8]) -> usize {
    use std::arch::x86_64::*;
    let mut at = 0;
    while source.len() - at >= 64 {
        // SAFETY: both slices hold 64 bytes from `at`.
        unsafe {
            let value = _mm512_loadu_si512(source.as_ptr().add(at).cast());
            let previous = _mm512_loadu_si512(destination.as_ptr().add(at).cast());
            _mm512_storeu_si512(
                destination.as_mut_ptr().add(at).cast(),
                _mm512_xor_si512(previous, value),
            );
        }
        at += 64;
    }
    at
}

/// [`xor_into`] over whole 32-byte blocks; returns the bytes processed.
///
/// # Safety
/// AVX2 must be available and the slices must have equal lengths.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn xor_avx2(source: &[u8], destination: &mut [u8]) -> usize {
    use std::arch::x86_64::*;
    let mut at = 0;
    while source.len() - at >= 32 {
        // SAFETY: both slices hold 32 bytes from `at`.
        unsafe {
            let value = _mm256_loadu_si256(source.as_ptr().add(at).cast());
            let previous = _mm256_loadu_si256(destination.as_ptr().add(at).cast());
            _mm256_storeu_si256(
                destination.as_mut_ptr().add(at).cast(),
                _mm256_xor_si256(previous, value),
            );
        }
        at += 32;
    }
    at
}

/// The kernel family the one-source and grouped GF(2⁸) multiply-accumulate
/// take on this x86_64 host, widest first. Two variables pin a lower tier so
/// one host can A/B every form without a rebuild: `WEAVER_GF8_GFNI=0` drops
/// the GFNI affine forms for the nibble shuffles, and `WEAVER_GF8_AVX512=0`
/// drops the 512-bit forms for the 256-bit ones. Both are read once, and
/// neither ever enables a kernel whose features are absent.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum X86Tier {
    /// `vgf2p8affineqb` on 512-bit vectors.
    GfniAvx512,
    /// `vgf2p8affineqb` on 256-bit vectors.
    GfniAvx2,
    /// The split-nibble `vpshufb` map on 512-bit vectors: AVX-512 without
    /// GFNI (Skylake-SP through Cooper Lake).
    Avx512,
    /// The split-nibble map on 256-bit vectors.
    Avx2,
    Ssse3,
    Scalar,
}

#[cfg(target_arch = "x86_64")]
fn x86_tier() -> X86Tier {
    static TIER: std::sync::OnceLock<X86Tier> = std::sync::OnceLock::new();
    *TIER.get_or_init(|| {
        let pinned = |name: &str| std::env::var_os(name).is_some_and(|v| v == "0");
        let avx2 = std::arch::is_x86_feature_detected!("avx2");
        let gfni =
            avx2 && !pinned("WEAVER_GF8_GFNI") && std::arch::is_x86_feature_detected!("gfni");
        let wide = avx2
            && !pinned("WEAVER_GF8_AVX512")
            && std::arch::is_x86_feature_detected!("avx512bw")
            && std::arch::is_x86_feature_detected!("avx512vl");
        match (gfni, wide) {
            (true, true) => X86Tier::GfniAvx512,
            (true, false) => X86Tier::GfniAvx2,
            (false, true) => X86Tier::Avx512,
            (false, false) if avx2 => X86Tier::Avx2,
            _ if std::arch::is_x86_feature_detected!("ssse3") => X86Tier::Ssse3,
            _ => X86Tier::Scalar,
        }
    })
}

/// The kernel family [`MulPlan::accumulate`] and [`mul_acc_input_batch`] run
/// on this host, after the `WEAVER_GF8_*` pins: a diagnostic for benches and
/// logs, not a stable identifier.
#[must_use]
pub fn kernel_name() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    return match x86_tier() {
        X86Tier::GfniAvx512 => "gfni-avx512",
        X86Tier::GfniAvx2 => "gfni-avx2",
        X86Tier::Avx512 => "avx512",
        X86Tier::Avx2 => "avx2",
        X86Tier::Ssse3 => "ssse3",
        X86Tier::Scalar => "scalar",
    };
    #[cfg(target_arch = "aarch64")]
    if std::arch::is_aarch64_feature_detected!("neon") {
        return "neon";
    }
    #[cfg(all(target_arch = "wasm32", target_feature = "relaxed-simd"))]
    return "wasm-relaxed-simd";
    #[cfg(all(
        target_arch = "wasm32",
        target_feature = "simd128",
        not(target_feature = "relaxed-simd")
    ))]
    return "wasm-simd128";
    #[allow(unreachable_code)]
    "scalar"
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
/// slice must have the destination's length. Sources whose plan is the zero
/// map are skipped, and a group left with one source runs the one-source
/// kernel, which takes the plain XOR for the identity.
pub fn mul_acc_input_batch(destination: &mut [u8], inputs: &[PlanSrc<'_>]) {
    for input in inputs {
        assert_eq!(input.src.len(), destination.len());
    }
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY (every arm): `x86_tier` reports a tier only after detecting
        // its features; each kernel bounds every load and store by the equal
        // lengths asserted above.
        match x86_tier() {
            X86Tier::GfniAvx512 if gf8_prefetch_enabled() => {
                for_each_group(destination, inputs, |d, g| unsafe {
                    batch_gfni_avx512::<GF8_PREFETCH_BYTES>(d, g)
                })
            }
            X86Tier::GfniAvx512 => for_each_group(destination, inputs, |d, g| unsafe {
                batch_gfni_avx512::<0>(d, g)
            }),
            X86Tier::GfniAvx2 => {
                for_each_group(destination, inputs, |d, g| unsafe { batch_gfni_avx2(d, g) })
            }
            X86Tier::Avx512 => {
                for_each_group(destination, inputs, |d, g| unsafe { batch_avx512(d, g) })
            }
            X86Tier::Avx2 => {
                for_each_group(destination, inputs, |d, g| unsafe { batch_avx2(d, g) })
            }
            X86Tier::Ssse3 | X86Tier::Scalar => {
                for input in inputs {
                    input.plan.accumulate(input.src, destination);
                }
            }
        }
        return;
    }
    #[cfg(target_arch = "aarch64")]
    if std::arch::is_aarch64_feature_detected!("neon") {
        // SAFETY: NEON was detected; the kernel bounds every load.
        for_each_group(destination, inputs, |d, g| unsafe { batch_neon(d, g) });
        return;
    }
    #[allow(unreachable_code)]
    for input in inputs {
        input.plan.accumulate(input.src, destination);
    }
}

/// Hand `kernel` the inputs in groups of at most [`BATCH_GROUP`], leaving out
/// every zero-map source; a group of one goes to [`MulPlan::accumulate`]
/// instead, whose one-source kernel the grouped strips cannot beat. No
/// allocation: a set with zero maps is regrouped through a stack array.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn for_each_group(
    destination: &mut [u8],
    inputs: &[PlanSrc<'_>],
    mut kernel: impl FnMut(&mut [u8], &[PlanSrc<'_>]),
) {
    let mut run = |destination: &mut [u8], group: &[PlanSrc<'_>]| match group {
        [] => {}
        [one] => one.plan.accumulate(one.src, destination),
        _ => kernel(destination, group),
    };
    if !inputs.iter().any(|input| input.plan.is_zero()) {
        for group in inputs.chunks(BATCH_GROUP) {
            run(destination, group);
        }
        return;
    }
    let mut live = inputs.iter().filter(|input| !input.plan.is_zero());
    let Some(first) = live.next() else {
        return;
    };
    let mut group = [*first; BATCH_GROUP];
    let mut held = 1;
    for input in live {
        if held == BATCH_GROUP {
            run(destination, &group);
            held = 0;
        }
        group[held] = *input;
        held += 1;
    }
    run(destination, &group[..held]);
}

/// The grouped loop shared by every kernel, over one group of at most
/// [`BATCH_GROUP`] sources: `$strip` bytes of the destination are held in
/// `$lanes` vector registers while each source of the group streams past
/// them; the remainder shorter than a strip goes to the one-source kernel
/// `$tail`. `$load`, `$store` and `$xor` are the tier's vector operations,
/// `$prepare` turns a plan into the operand `$map` applies to a loaded vector
/// of source bytes. The closures are safe closures over raw pointers that
/// carry their own `unsafe` blocks; that is sound only because they never
/// leave this module-private macro, where every load and store is bounded by
/// the strip arithmetic below and every tail by the equal lengths.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
macro_rules! grouped_accumulate {
    (
        $destination:expr, $inputs:expr, strip = $strip:literal, lanes = $lanes:literal,
        vector = $vector:ty, load = $load:expr, store = $store:expr, xor = $xor:expr,
        prepare = $prepare:expr, map = $map:expr, tail = $tail:expr
        $(, prefetch = $prefetch:expr)? $(,)?
    ) => {{
        let destination: &mut [u8] = $destination;
        let group: &[PlanSrc<'_>] = $inputs;
        debug_assert!(!group.is_empty() && group.len() <= BATCH_GROUP);
        const LANE: usize = $strip / $lanes;
        const _: () = assert!(
            ($strip as usize).is_power_of_two()
                && LANE * $lanes == $strip
                && LANE == std::mem::size_of::<$vector>(),
            "a strip is a power of two of whole vectors"
        );
        let vec_len = destination.len() & !($strip - 1);
        // One operand per source; the slots past a short group repeat the
        // first source's operand and are never visited, since the walk below
        // is bounded by the group. No allocation per call.
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
        if vec_len < destination.len() {
            for input in group {
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

/// The split-nibble map, two shuffles and an XOR, per 64 bytes per source:
/// the grouped kernel of AVX-512 hosts without GFNI. Thirty-two vector
/// registers hold the two tables of all eight sources beside the four
/// accumulators, which the sixteen of AVX2 cannot.
///
/// # Safety
/// AVX512BW and AVX512VL must be available and the slices must have equal
/// lengths.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512bw,avx512vl")]
unsafe fn batch_avx512(destination: &mut [u8], inputs: &[PlanSrc<'_>]) {
    use std::arch::x86_64::*;
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
        prepare = fused_x86::tables512,
        map = fused_x86::map512,
        // SAFETY: the tier was detected by the caller; equal lengths.
        tail = |plan: &MulPlan, s, d| unsafe { plan.avx512(s, d) },
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

                    // Every grouped kernel the host can run, each fed its
                    // groups by the dispatcher's own grouping. SAFETY (every
                    // call): the kernel's features were detected just before
                    // and every slice has the destination's length.
                    let check = |name: &str, kernel: &dyn Fn(&mut [u8], &[PlanSrc<'_>])| {
                        let mut actual = seed[offset..offset + length].to_vec();
                        for_each_group(&mut actual, &inputs, kernel);
                        assert_eq!(actual, expected, "{name}, {what}");
                    };
                    #[cfg(target_arch = "x86_64")]
                    {
                        let avx2 = std::arch::is_x86_feature_detected!("avx2");
                        let gfni = avx2 && std::arch::is_x86_feature_detected!("gfni");
                        let wide = avx2
                            && std::arch::is_x86_feature_detected!("avx512bw")
                            && std::arch::is_x86_feature_detected!("avx512vl");
                        if avx2 {
                            check("avx2", &|d, g| unsafe { batch_avx2(d, g) });
                        }
                        if wide {
                            check("avx512", &|d, g| unsafe { batch_avx512(d, g) });
                        }
                        if gfni {
                            check("gfni avx2", &|d, g| unsafe { batch_gfni_avx2(d, g) });
                        }
                        if gfni && wide {
                            check("gfni avx512", &|d, g| unsafe {
                                batch_gfni_avx512::<0>(d, g)
                            });
                            check("gfni avx512 prefetch", &|d, g| unsafe {
                                batch_gfni_avx512::<GF8_PREFETCH_BYTES>(d, g)
                            });
                        }
                    }
                    #[cfg(target_arch = "aarch64")]
                    if std::arch::is_aarch64_feature_detected!("neon") {
                        check("neon", &|d, g| unsafe { batch_neon(d, g) });
                    }
                    let _ = check;
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

    /// Deterministic pseudo-random bytes (xorshift64).
    fn noise(seed: u64, len: usize) -> Vec<u8> {
        let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect()
    }

    /// The factors every kernel test covers: the two short-circuited ones,
    /// the generator, the top bit, all ones, and a few from the noise.
    fn test_factors() -> Vec<u8> {
        let mut factors = vec![0u8, 1, 2, 0x80, 0xff];
        factors.extend(noise(91, 6));
        factors
    }

    /// Lengths either side of every vector and strip width, plus odd ones.
    const LENGTHS: [usize; 22] = [
        0, 1, 2, 15, 16, 17, 31, 32, 33, 63, 64, 65, 95, 127, 128, 129, 191, 255, 257, 1000, 4095,
        4161,
    ];

    #[test]
    fn cached_plans_are_the_built_plans() {
        for factor in 0..=255u8 {
            let (cached, built) = (MulPlan::cached(factor), MulPlan::new(factor));
            assert_eq!(cached.low, built.low, "factor {factor}");
            assert_eq!(cached.high, built.high, "factor {factor}");
            assert_eq!(cached.kind, built.kind, "factor {factor}");
            assert_eq!(cached.affine(), built.affine(), "factor {factor}");
            let expected = match factor {
                0 => Kind::Zero,
                1 => Kind::Identity,
                _ => Kind::General,
            };
            assert_eq!(cached.kind, expected, "factor {factor}");
            for value in 0..=255u8 {
                assert_eq!(cached.apply(value), mul(value, factor), "factor {factor}");
            }
        }
        // A table plan is classified by its map, not by how it was built.
        let identity = MulPlan::from_tables(
            std::array::from_fn(|n| n as u8),
            std::array::from_fn(|n| (n << 4) as u8),
        );
        assert_eq!(identity.kind, Kind::Identity);
        assert_eq!(MulPlan::from_tables([0; 16], [0; 16]).kind, Kind::Zero);
        let mut low = [0u8; 16];
        low[3] = 1;
        assert_eq!(MulPlan::from_tables(low, [0; 16]).kind, Kind::General);
    }

    /// Factor 0 leaves the destination as it was and factor 1 XORs the
    /// source in, through the plan, the cached plan and the free function,
    /// at every length and offset; the identity table plan does the same.
    #[test]
    fn factor_zero_and_one_take_their_short_paths() {
        let source = noise(5, 4400);
        let seed = noise(6, 4400);
        let identity = MulPlan::from_tables(
            std::array::from_fn(|n| n as u8),
            std::array::from_fn(|n| (n << 4) as u8),
        );
        for offset in 0..4 {
            for length in LENGTHS {
                let input = &source[offset..offset + length];
                let start = &seed[offset..offset + length];
                let xored: Vec<u8> = start.iter().zip(input).map(|(d, s)| d ^ s).collect();
                for (factor, expected) in [(0u8, start.to_vec()), (1, xored.clone())] {
                    let what = format!("factor {factor} offset {offset} length {length}");
                    let mut actual = start.to_vec();
                    MulPlan::new(factor).accumulate(input, &mut actual);
                    assert_eq!(actual, expected, "plan, {what}");
                    let mut actual = start.to_vec();
                    MulPlan::cached(factor).accumulate(input, &mut actual);
                    assert_eq!(actual, expected, "cached, {what}");
                    let mut actual = start.to_vec();
                    mul_acc_region(factor, input, &mut actual);
                    assert_eq!(actual, expected, "region, {what}");
                }
                let mut actual = start.to_vec();
                identity.accumulate(input, &mut actual);
                assert_eq!(
                    actual, xored,
                    "identity tables, offset {offset} length {length}"
                );
                let mut actual = start.to_vec();
                xor_into(input, &mut actual);
                assert_eq!(actual, xored, "xor_into, offset {offset} length {length}");
            }
        }
    }

    /// Every one-source accumulate kernel the host can run, by name.
    #[allow(clippy::type_complexity)]
    fn accumulate_kernels() -> Vec<(&'static str, fn(&MulPlan, &[u8], &mut [u8]))> {
        let mut kernels: Vec<(&'static str, fn(&MulPlan, &[u8], &mut [u8]))> = vec![
            ("dispatched", MulPlan::accumulate),
            ("scalar", MulPlan::scalar),
        ];
        #[cfg(target_arch = "aarch64")]
        if std::arch::is_aarch64_feature_detected!("neon") {
            // SAFETY (all kernel entries): each is pushed only after its
            // features were detected, and every caller passes equal lengths.
            kernels.push(("neon", |p, s, d| unsafe { p.neon(s, d) }));
        }
        #[cfg(target_arch = "x86_64")]
        {
            let has = |f: &str| match f {
                "ssse3" => std::arch::is_x86_feature_detected!("ssse3"),
                "avx2" => std::arch::is_x86_feature_detected!("avx2"),
                "gfni" => std::arch::is_x86_feature_detected!("gfni"),
                _ => {
                    std::arch::is_x86_feature_detected!("avx512bw")
                        && std::arch::is_x86_feature_detected!("avx512vl")
                }
            };
            if has("ssse3") {
                kernels.push(("ssse3", |p, s, d| unsafe { p.ssse3(s, d) }));
            }
            if has("avx2") {
                kernels.push(("avx2", |p, s, d| unsafe { p.avx2(s, d) }));
                if has("gfni") {
                    kernels.push(("gfni avx2", |p, s, d| unsafe {
                        p.accumulate_gfni(p.affine(), s, d)
                    }));
                }
                if has("avx512") {
                    kernels.push(("avx512", |p, s, d| unsafe { p.avx512(s, d) }));
                    if has("gfni") {
                        kernels.push(("gfni avx512", |p, s, d| unsafe {
                            p.accumulate_gfni_avx512(p.affine(), s, d)
                        }));
                    }
                } else {
                    eprintln!("SKIP gf8 512-bit kernels: host lacks avx512bw+vl");
                }
            }
        }
        kernels
    }

    /// Every one-source kernel against the scalar oracle on pseudo-random
    /// rows, at every test factor, length and a spread of offsets.
    #[test]
    fn every_accumulate_kernel_matches_the_scalar_oracle_on_random_rows() {
        let source = noise(11, 4400);
        let seed = noise(12, 4400);
        let kernels = accumulate_kernels();
        for factor in test_factors() {
            let plan = MulPlan::new(factor);
            for offset in [0usize, 1, 5, 63] {
                for length in LENGTHS {
                    let input = &source[offset..offset + length];
                    let start = &seed[(offset * 3) % 7..(offset * 3) % 7 + length];
                    let expected: Vec<u8> = start
                        .iter()
                        .zip(input)
                        .map(|(d, s)| d ^ mul(*s, factor))
                        .collect();
                    for (name, kernel) in &kernels {
                        let mut actual = start.to_vec();
                        kernel(&plan, input, &mut actual);
                        assert_eq!(
                            actual, expected,
                            "{name}, factor {factor:#x}, offset {offset}, length {length}"
                        );
                    }
                }
            }
        }
    }

    /// An in-place row kernel that returns the bytes it processed.
    #[cfg(target_arch = "x86_64")]
    type RowKernel<'a> = Box<dyn Fn(&mut [u8]) -> usize + 'a>;

    /// The fused map, butterfly and radix-4 kernels of every x86 tier against
    /// their scalar walks on pseudo-random rows; each returns the bytes it
    /// processed and the scalar walk finishes the rest, as `LinearMap8` does.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn every_fused_x86_kernel_matches_the_scalar_walk_on_random_rows() {
        let avx2 = std::arch::is_x86_feature_detected!("avx2");
        let gfni = avx2 && std::arch::is_x86_feature_detected!("gfni");
        let wide = avx2
            && std::arch::is_x86_feature_detected!("avx512bw")
            && std::arch::is_x86_feature_detected!("avx512vl");
        if !avx2 {
            eprintln!("SKIP every_fused_x86_kernel_matches_the_scalar_walk: host lacks avx2");
            return;
        }
        let factors = test_factors();
        for (at, &factor) in factors.iter().enumerate() {
            let plans = [
                MulPlan::new(factor),
                MulPlan::new(factors[(at + 3) % factors.len()]),
                MulPlan::new(factors[(at + 7) % factors.len()]),
            ];
            let plan = &plans[0];
            let affine = plans.each_ref().map(MulPlan::affine);
            for offset in [0usize, 1, 33] {
                for length in LENGTHS {
                    let what = format!("factor {factor:#x}, offset {offset}, length {length}");
                    let rows: [Vec<u8>; 4] = std::array::from_fn(|row| {
                        noise(at as u64 * 97 + row as u64, length + offset)[offset..].to_vec()
                    });

                    // SAFETY (every kernel call below): the kernel's
                    // features were detected above; rows have equal lengths.
                    let mut maps: Vec<(&str, RowKernel<'_>)> =
                        vec![("avx2", Box::new(|r: &mut [u8]| unsafe { plan.map_avx2(r) }))];
                    if gfni {
                        maps.push((
                            "gfni",
                            Box::new(|r: &mut [u8]| unsafe { plan.map_gfni(affine[0], r) }),
                        ));
                    }
                    if wide {
                        maps.push((
                            "avx512",
                            Box::new(|r: &mut [u8]| unsafe { plan.map_avx512(r) }),
                        ));
                    }
                    let mut expected = rows[0].clone();
                    plan.map_scalar(&mut expected);
                    for (name, map) in &maps {
                        let mut actual = rows[0].clone();
                        let done = map(&mut actual);
                        plan.map_scalar(&mut actual[done..]);
                        assert_eq!(actual, expected, "map {name}, {what}");
                    }

                    for inverse in [false, true] {
                        let (mut el, mut er) = (rows[0].clone(), rows[1].clone());
                        let (mut ea, mut eb, mut ec, mut ed) = (
                            rows[0].clone(),
                            rows[1].clone(),
                            rows[2].clone(),
                            rows[3].clone(),
                        );
                        let refs = [&plans[0], &plans[1], &plans[2]];
                        if inverse {
                            plan.butterfly_scalar::<true>(&mut el, &mut er);
                            MulPlan::radix4_scalar::<true>(
                                refs,
                                [&mut ea, &mut eb, &mut ec, &mut ed],
                            );
                        } else {
                            plan.butterfly_scalar::<false>(&mut el, &mut er);
                            MulPlan::radix4_scalar::<false>(
                                refs,
                                [&mut ea, &mut eb, &mut ec, &mut ed],
                            );
                        }
                        let tiers: Vec<&str> = [
                            Some("avx2"),
                            gfni.then_some("gfni"),
                            wide.then_some("avx512"),
                        ]
                        .into_iter()
                        .flatten()
                        .collect();
                        for tier in tiers {
                            let what = format!("{tier}, inverse {inverse}, {what}");
                            let (mut l, mut r) = (rows[0].clone(), rows[1].clone());
                            let [mut a, mut b, mut c, mut d] = rows.clone();
                            macro_rules! run {
                                ($inv:literal) => {
                                    unsafe {
                                        match tier {
                                            "avx2" => (
                                                plan.butterfly_avx2::<$inv>(&mut l, &mut r),
                                                MulPlan::radix4_avx2::<$inv>(
                                                    refs,
                                                    [&mut a, &mut b, &mut c, &mut d],
                                                ),
                                            ),
                                            "gfni" => (
                                                plan.butterfly_gfni::<$inv>(
                                                    affine[0], &mut l, &mut r,
                                                ),
                                                MulPlan::radix4_gfni::<$inv>(
                                                    refs,
                                                    affine,
                                                    [&mut a, &mut b, &mut c, &mut d],
                                                ),
                                            ),
                                            _ => (
                                                plan.butterfly_avx512::<$inv>(&mut l, &mut r),
                                                MulPlan::radix4_avx512::<$inv>(
                                                    refs,
                                                    [&mut a, &mut b, &mut c, &mut d],
                                                ),
                                            ),
                                        }
                                    }
                                };
                            }
                            let (pair, quad) = if inverse { run!(true) } else { run!(false) };
                            if inverse {
                                plan.butterfly_scalar::<true>(&mut l[pair..], &mut r[pair..]);
                                MulPlan::radix4_scalar::<true>(
                                    refs,
                                    [
                                        &mut a[quad..],
                                        &mut b[quad..],
                                        &mut c[quad..],
                                        &mut d[quad..],
                                    ],
                                );
                            } else {
                                plan.butterfly_scalar::<false>(&mut l[pair..], &mut r[pair..]);
                                MulPlan::radix4_scalar::<false>(
                                    refs,
                                    [
                                        &mut a[quad..],
                                        &mut b[quad..],
                                        &mut c[quad..],
                                        &mut d[quad..],
                                    ],
                                );
                            }
                            assert_eq!((&l, &r), (&el, &er), "butterfly {what}");
                            assert_eq!([&a, &b, &c, &d], [&ea, &eb, &ec, &ed], "radix-4 {what}");
                        }
                    }
                }
            }
        }
    }

    /// Sets with zero-map sources scattered through them, including whole
    /// groups of them and a set of nothing else, fold to the per-source sum
    /// on the dispatched grouped kernel, whichever way the zeros regroup the
    /// rest.
    #[test]
    fn zero_sources_drop_out_of_the_grouping() {
        let length = 1300;
        let sources: Vec<Vec<u8>> = (0..27).map(|k| noise(300 + k, length)).collect();
        let seed = noise(299, length);
        let factors = test_factors();
        for pattern in 0..6usize {
            let plans: Vec<&MulPlan> = (0..sources.len())
                .map(|k| {
                    let zero = match pattern {
                        0 => true,
                        1 => k % 3 == 0,
                        2 => k < 9,
                        3 => k % 9 != 4,
                        4 => (8..16).contains(&k),
                        _ => k % 2 == 1,
                    };
                    MulPlan::cached(if zero { 0 } else { factors[k % factors.len()] })
                })
                .collect();
            for count in [1usize, 2, 8, 9, 17, 27] {
                let inputs: Vec<PlanSrc<'_>> = (0..count)
                    .map(|k| PlanSrc {
                        plan: plans[k],
                        src: &sources[k],
                    })
                    .collect();
                let mut expected = seed.clone();
                for input in &inputs {
                    input.plan.scalar(input.src, &mut expected);
                }
                let mut actual = seed.clone();
                mul_acc_input_batch(&mut actual, &inputs);
                assert_eq!(actual, expected, "pattern {pattern}, count {count}");
            }
        }
    }
}
