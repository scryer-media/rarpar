//! BLAKE2sp on x86-64 uses eight 32-bit lanes in 256-bit registers on
//! AVX-512VL hosts. Other x86 hosts use upstream streaming SIMD on
//! SSE4.1/AVX2, local four-leaf groups on SSE2/SSSE3, or scalar code.
//! Runtime detection includes OS register-state support.

#[cfg(target_arch = "x86")]
use std::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];
const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Backend {
    Portable,
    Sse2,
    Ssse3,
    Upstream,
    #[cfg(target_arch = "x86_64")]
    Avx512Vl,
}
impl Backend {
    fn detect() -> Self {
        #[cfg(target_arch = "x86_64")]
        if avx512vl_available() {
            return Self::Avx512Vl;
        }
        Self::select(
            is_x86_feature_detected!("sse2"),
            is_x86_feature_detected!("ssse3"),
            is_x86_feature_detected!("sse4.1"),
            is_x86_feature_detected!("avx2"),
        )
    }
    fn select(sse2: bool, ssse3: bool, sse41: bool, avx2: bool) -> Self {
        if sse41 || avx2 {
            Self::Upstream
        } else if ssse3 && sse2 {
            Self::Ssse3
        } else if sse2 {
            Self::Sse2
        } else {
            Self::Portable
        }
    }

    fn compress(
        self,
        h: &mut [[u32; 8]; 8],
        block: &[u8; 512],
        counts: [u64; 8],
        f0: [u32; 8],
        f1: [u32; 8],
    ) {
        // SAFETY: backend is selected only after runtime CPU/OS detection.
        // All loads/stores below operate on full initialized fixed-size arrays.
        unsafe {
            match self {
                Self::Portable => compress::<Scalar, 8>(h, block, counts, f0, f1),
                Self::Sse2 => compress_sse2(h, block, counts, f0, f1),
                Self::Ssse3 => compress_ssse3(h, block, counts, f0, f1),
                #[cfg(target_arch = "x86_64")]
                Self::Avx512Vl => {
                    let low = counts.map(|count| count as u32);
                    let high = counts.map(|count| (count >> 32) as u32);
                    compress_avx512vl(h, block, &[low, high, f0, f1]);
                }
                Self::Upstream => unreachable!("upstream owns its complete streaming state"),
            }
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn avx512vl_available() -> bool {
    is_x86_feature_detected!("avx2")
        && is_x86_feature_detected!("avx512f")
        && is_x86_feature_detected!("avx512vl")
}

/// Whole-stream state with runtime-selected compression.
/// Both variants use fixed-size inline storage without per-update allocation.
#[derive(Clone, Debug)]
pub(crate) struct State(Hasher);

#[derive(Clone, Debug)]
enum Hasher {
    Upstream(blake2s_simd::blake2sp::State),
    Local(LocalState),
}

impl State {
    pub(crate) fn new() -> Self {
        Self::with_backend(Backend::detect())
    }

    fn with_backend(backend: Backend) -> Self {
        Self(match backend {
            Backend::Upstream => Hasher::Upstream(blake2s_simd::blake2sp::State::new()),
            backend => Hasher::Local(LocalState::new(backend)),
        })
    }

    pub(crate) fn update(&mut self, input: &[u8]) {
        match &mut self.0 {
            Hasher::Upstream(state) => {
                state.update(input);
            }
            Hasher::Local(state) => state.update(input),
        }
    }

    pub(crate) fn finalize(&self) -> [u8; 32] {
        match &self.0 {
            Hasher::Upstream(state) => *state.finalize().as_array(),
            Hasher::Local(state) => state.finalize(),
        }
    }
}

/// Fixed-space state for the local compression kernels.
/// Accepts the full eight-leaf stream in arbitrary chunks.
#[derive(Clone)]
struct LocalState {
    // Transposed so each vector holds one word from multiple leaves.
    h: [[u32; 8]; 8],
    tail: [u8; 1024],
    len: usize,
    count: u64,
    backend: Backend,
}
impl std::fmt::Debug for LocalState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Blake2spState")
            .field("backend", &self.backend)
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}
impl LocalState {
    fn new(backend: Backend) -> Self {
        debug_assert_ne!(backend, Backend::Upstream);
        let mut h = IV.map(|word| [word; 8]);
        h[0] = [IV[0] ^ (32 | (8 << 16) | (2 << 24)); 8];
        h[2] = std::array::from_fn(|leaf| IV[2] ^ leaf as u32);
        h[3] = [IV[3] ^ (32 << 24); 8];
        Self {
            h,
            tail: [0; 1024],
            len: 0,
            count: 0,
            backend,
        }
    }
    pub(crate) fn update(&mut self, mut input: &[u8]) {
        // Keep each leaf's final block: a complete superblock is non-final
        // only when at least 449 bytes follow it (seven blocks plus one byte).
        // Drain buffered blocks first so the rest can be read directly.
        while self.len != 0 && input.len() >= 961 - self.len {
            let fill = 512usize.saturating_sub(self.len);
            self.tail[self.len..self.len + fill].copy_from_slice(&input[..fill]);
            let block = self.tail[..512].try_into().unwrap();
            self.compress_nonfinal(std::slice::from_ref(&block));
            self.tail.copy_within(512..self.len + fill, 0);
            self.len = self.len + fill - 512;
            input = &input[fill..];
        }
        if self.len == 0 && input.len() >= 961 {
            let direct_len = (input.len() - 449) / 512 * 512;
            let (direct, remaining) = input.split_at(direct_len);
            let (blocks, _) = direct.as_chunks::<512>();
            self.compress_nonfinal(blocks);
            input = remaining;
        }
        self.tail[self.len..self.len + input.len()].copy_from_slice(input);
        self.len += input.len();
    }
    fn compress_nonfinal(&mut self, blocks: &[[u8; 512]]) {
        #[cfg(target_arch = "x86_64")]
        if self.backend == Backend::Avx512Vl {
            // SAFETY: this backend is selected after CPU/OS detection.
            unsafe { compress_many_avx512vl(&mut self.h, blocks, &mut self.count) };
            return;
        }
        for block in blocks {
            self.count = self.count.wrapping_add(64);
            self.backend
                .compress(&mut self.h, block, [self.count; 8], [0; 8], [0; 8]);
        }
    }
    pub(crate) fn finalize_leaves(&self) -> [[u8; 32]; 8] {
        let mut h = self.h;
        let mut done = [[0u32; 8]; 8];
        let steps = 1 + usize::from(self.len > 512);
        for step in 0..steps {
            let mut block = [0u8; 512];
            let mut counts = [0; 8];
            let mut final_flags = [0; 8];
            let mut last_flags = [0; 8];
            for leaf in 0..8 {
                let offset = step * 512 + leaf * 64;
                let take = self.len.saturating_sub(offset).min(64);
                if take != 0 {
                    block[leaf * 64..leaf * 64 + take]
                        .copy_from_slice(&self.tail[offset..offset + take]);
                }
                counts[leaf] = self.count.wrapping_add((step * 64 + take) as u64);
                if self.len <= offset + 512 {
                    final_flags[leaf] = !0;
                    if leaf == 7 {
                        last_flags[leaf] = !0;
                    }
                }
            }
            self.backend
                .compress(&mut h, &block, counts, final_flags, last_flags);
            for (leaf, words) in done.iter_mut().enumerate() {
                if (step == 0 && self.len <= 512 + leaf * 64)
                    || (step == 1 && self.len > 512 + leaf * 64)
                {
                    *words = std::array::from_fn(|word| h[word][leaf]);
                }
            }
        }
        std::array::from_fn(|leaf| {
            let mut out = [0; 32];
            for (bytes, word) in out.chunks_exact_mut(4).zip(done[leaf]) {
                bytes.copy_from_slice(&word.to_le_bytes());
            }
            out
        })
    }
    pub(crate) fn finalize(&self) -> [u8; 32] {
        let mut root = blake2s_simd::Params::new();
        root.hash_length(32)
            .fanout(8)
            .max_depth(2)
            .node_depth(1)
            .inner_hash_length(32)
            .last_node(true);
        *root.hash(self.finalize_leaves().as_flattened()).as_array()
    }
}

trait Vector<const N: usize> {
    type V: Copy;
    unsafe fn load(a: &[u32; N]) -> Self::V;
    unsafe fn store(v: Self::V, a: &mut [u32; N]);
    unsafe fn add(a: Self::V, b: Self::V) -> Self::V;
    unsafe fn xor(a: Self::V, b: Self::V) -> Self::V;
    unsafe fn rotate<const R: i32>(v: Self::V) -> Self::V;
}

#[inline(always)]
unsafe fn mix<S: Vector<N>, const N: usize>(v: &mut [S::V; 16], idx: [usize; 4], x: S::V, y: S::V) {
    let [a, b, c, d] = idx;
    unsafe {
        v[a] = S::add(S::add(v[a], v[b]), x);
        v[d] = S::rotate::<16>(S::xor(v[d], v[a]));
        v[c] = S::add(v[c], v[d]);
        v[b] = S::rotate::<12>(S::xor(v[b], v[c]));
        v[a] = S::add(S::add(v[a], v[b]), y);
        v[d] = S::rotate::<8>(S::xor(v[d], v[a]));
        v[c] = S::add(v[c], v[d]);
        v[b] = S::rotate::<7>(S::xor(v[b], v[c]));
    }
}

#[inline(always)]
unsafe fn round<S: Vector<N>, const N: usize>(v: &mut [S::V; 16], m: &[S::V; 16], p: [usize; 16]) {
    unsafe {
        mix::<S, N>(v, [0, 4, 8, 12], m[p[0]], m[p[1]]);
        mix::<S, N>(v, [1, 5, 9, 13], m[p[2]], m[p[3]]);
        mix::<S, N>(v, [2, 6, 10, 14], m[p[4]], m[p[5]]);
        mix::<S, N>(v, [3, 7, 11, 15], m[p[6]], m[p[7]]);
        mix::<S, N>(v, [0, 5, 10, 15], m[p[8]], m[p[9]]);
        mix::<S, N>(v, [1, 6, 11, 12], m[p[10]], m[p[11]]);
        mix::<S, N>(v, [2, 7, 8, 13], m[p[12]], m[p[13]]);
        mix::<S, N>(v, [3, 4, 9, 14], m[p[14]], m[p[15]]);
    }
}

#[inline(always)]
unsafe fn compress<S: Vector<N>, const N: usize>(
    h: &mut [[u32; 8]; 8],
    block: &[u8; 512],
    counts: [u64; 8],
    f0: [u32; 8],
    f1: [u32; 8],
) {
    unsafe {
        for base in (0..8).step_by(N) {
            let mut hv = [S::load(&[0; N]); 8];
            for j in 0..8 {
                hv[j] = S::load(h[j][base..base + N].try_into().unwrap());
            }
            let mut m = [hv[0]; 16];
            for (j, word) in m.iter_mut().enumerate() {
                *word = S::load(&std::array::from_fn(|i| {
                    let off = (base + i) * 64 + j * 4;
                    u32::from_le_bytes(block[off..off + 4].try_into().unwrap())
                }));
            }
            let mut v = [hv[0]; 16];
            v[..8].copy_from_slice(&hv);
            for j in 0..8 {
                v[j + 8] = S::load(&[IV[j]; N]);
            }
            v[12] = S::xor(
                v[12],
                S::load(&std::array::from_fn(|i| counts[base + i] as u32)),
            );
            v[13] = S::xor(
                v[13],
                S::load(&std::array::from_fn(|i| (counts[base + i] >> 32) as u32)),
            );
            v[14] = S::xor(v[14], S::load(&std::array::from_fn(|i| f0[base + i])));
            v[15] = S::xor(v[15], S::load(&std::array::from_fn(|i| f1[base + i])));
            for p in SIGMA {
                round::<S, N>(&mut v, &m, p);
            }
            for j in 0..8 {
                let mut lanes = [0; N];
                S::store(S::xor(hv[j], S::xor(v[j], v[j + 8])), &mut lanes);
                h[j][base..base + N].copy_from_slice(&lanes);
            }
        }
    }
}

struct Scalar;
impl<const N: usize> Vector<N> for Scalar {
    type V = [u32; N];
    #[inline(always)]
    unsafe fn load(a: &[u32; N]) -> Self::V {
        *a
    }
    #[inline(always)]
    unsafe fn store(v: Self::V, a: &mut [u32; N]) {
        *a = v;
    }
    #[inline(always)]
    unsafe fn add(a: Self::V, b: Self::V) -> Self::V {
        std::array::from_fn(|i| a[i].wrapping_add(b[i]))
    }
    #[inline(always)]
    unsafe fn xor(a: Self::V, b: Self::V) -> Self::V {
        std::array::from_fn(|i| a[i] ^ b[i])
    }
    #[inline(always)]
    unsafe fn rotate<const R: i32>(v: Self::V) -> Self::V {
        v.map(|x| x.rotate_right(R as u32))
    }
}

// Operations inline into feature-qualified compression wrappers. No intrinsic
// entrypoint is called without the matching runtime feature/OS-state check.
macro_rules! vector {
    ($name:ident, $n:literal, $v:ty, $load:ident, $store:ident, $add:ident, $xor:ident, $rotate:ident) => {
        struct $name;
        impl Vector<$n> for $name {
            type V = $v;
            #[inline(always)]
            unsafe fn load(a: &[u32; $n]) -> Self::V {
                unsafe { $load(a.as_ptr().cast()) }
            }
            #[inline(always)]
            unsafe fn store(v: Self::V, a: &mut [u32; $n]) {
                unsafe { $store(a.as_mut_ptr().cast(), v) }
            }
            #[inline(always)]
            unsafe fn add(a: Self::V, b: Self::V) -> Self::V {
                unsafe { $add(a, b) }
            }
            #[inline(always)]
            unsafe fn xor(a: Self::V, b: Self::V) -> Self::V {
                unsafe { $xor(a, b) }
            }
            #[inline(always)]
            unsafe fn rotate<const R: i32>(v: Self::V) -> Self::V {
                unsafe { $rotate::<R>(v) }
            }
        }
    };
}
#[inline(always)]
unsafe fn rotate_sse2<const R: i32>(v: __m128i) -> __m128i {
    unsafe {
        _mm_or_si128(
            _mm_srl_epi32(v, _mm_cvtsi32_si128(R)),
            _mm_sll_epi32(v, _mm_cvtsi32_si128(32 - R)),
        )
    }
}
#[inline(always)]
unsafe fn rotate_ssse3<const R: i32>(v: __m128i) -> __m128i {
    unsafe {
        if R == 8 || R == 16 {
            let mask: [u8; 16] =
                std::array::from_fn(|i| ((i / 4) * 4 + (i % 4 + R as usize / 8) % 4) as u8);
            _mm_shuffle_epi8(v, _mm_loadu_si128(mask.as_ptr().cast()))
        } else {
            rotate_sse2::<R>(v)
        }
    }
}
vector!(
    Sse2,
    4,
    __m128i,
    _mm_loadu_si128,
    _mm_storeu_si128,
    _mm_add_epi32,
    _mm_xor_si128,
    rotate_sse2
);
vector!(
    Ssse3,
    4,
    __m128i,
    _mm_loadu_si128,
    _mm_storeu_si128,
    _mm_add_epi32,
    _mm_xor_si128,
    rotate_ssse3
);
#[cfg(target_arch = "x86_64")]
vector!(
    Avx512Vl,
    8,
    __m256i,
    _mm256_loadu_si256,
    _mm256_storeu_si256,
    _mm256_add_epi32,
    _mm256_xor_si256,
    _mm256_ror_epi32
);
macro_rules! entry {
    ($name:ident, $features:literal, $backend:ty, $n:literal) => {
        #[target_feature(enable = $features)]
        unsafe fn $name(
            h: &mut [[u32; 8]; 8],
            b: &[u8; 512],
            c: [u64; 8],
            f0: [u32; 8],
            f1: [u32; 8],
        ) {
            unsafe { compress::<$backend, $n>(h, b, c, f0, f1) }
        }
    };
}
entry!(compress_sse2, "sse2", Sse2, 4);
entry!(compress_ssse3, "ssse3", Ssse3, 4);

// One vector per message word. Unpack pairs of leaves within each 128-bit
// half, then join corresponding words from leaves 0–3 and 4–7.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn transpose_message<const OFFSET: usize>(block: &[u8; 512]) -> [__m256i; 8] {
    const { assert!(OFFSET <= 32) };
    unsafe {
        let [a, b, c, d, e, f, g, h] = std::array::from_fn(|lane| {
            _mm256_loadu_si256(block.as_ptr().add(lane * 64 + OFFSET).cast())
        });
        let ab_low = _mm256_unpacklo_epi32(a, b);
        let ab_high = _mm256_unpackhi_epi32(a, b);
        let cd_low = _mm256_unpacklo_epi32(c, d);
        let cd_high = _mm256_unpackhi_epi32(c, d);
        let ef_low = _mm256_unpacklo_epi32(e, f);
        let ef_high = _mm256_unpackhi_epi32(e, f);
        let gh_low = _mm256_unpacklo_epi32(g, h);
        let gh_high = _mm256_unpackhi_epi32(g, h);

        let left = [
            _mm256_unpacklo_epi64(ab_low, cd_low),
            _mm256_unpackhi_epi64(ab_low, cd_low),
            _mm256_unpacklo_epi64(ab_high, cd_high),
            _mm256_unpackhi_epi64(ab_high, cd_high),
        ];
        let right = [
            _mm256_unpacklo_epi64(ef_low, gh_low),
            _mm256_unpackhi_epi64(ef_low, gh_low),
            _mm256_unpacklo_epi64(ef_high, gh_high),
            _mm256_unpackhi_epi64(ef_high, gh_high),
        ];
        std::array::from_fn(|word| match word {
            0..=3 => _mm256_permute2x128_si256::<0x20>(left[word], right[word]),
            _ => _mm256_permute2x128_si256::<0x31>(left[word - 4], right[word - 4]),
        })
    }
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn compress_words_avx512vl(h: &mut [__m256i; 8], block: &[u8; 512], params: [__m256i; 4]) {
    unsafe {
        let halves = [
            transpose_message::<0>(block),
            transpose_message::<32>(block),
        ];
        let m = halves.as_flattened().try_into().unwrap();
        let mut v = std::array::from_fn(|j| {
            if j < 8 {
                h[j]
            } else {
                _mm256_set1_epi32(IV[j - 8] as i32)
            }
        });
        for (word, param) in v[12..].iter_mut().zip(params) {
            *word = _mm256_xor_si256(*word, param);
        }
        // Constant schedules let the compiler address message vectors directly.
        round::<Avx512Vl, 8>(&mut v, m, SIGMA[0]);
        round::<Avx512Vl, 8>(&mut v, m, SIGMA[1]);
        round::<Avx512Vl, 8>(&mut v, m, SIGMA[2]);
        round::<Avx512Vl, 8>(&mut v, m, SIGMA[3]);
        round::<Avx512Vl, 8>(&mut v, m, SIGMA[4]);
        round::<Avx512Vl, 8>(&mut v, m, SIGMA[5]);
        round::<Avx512Vl, 8>(&mut v, m, SIGMA[6]);
        round::<Avx512Vl, 8>(&mut v, m, SIGMA[7]);
        round::<Avx512Vl, 8>(&mut v, m, SIGMA[8]);
        round::<Avx512Vl, 8>(&mut v, m, SIGMA[9]);
        for j in 0..8 {
            h[j] = _mm256_ternarylogic_epi32::<0x96>(h[j], v[j], v[j + 8]);
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2,avx512f,avx512vl")]
unsafe fn compress_avx512vl(h: &mut [[u32; 8]; 8], block: &[u8; 512], params: &[[u32; 8]; 4]) {
    unsafe {
        let mut words = h.each_ref().map(|lanes| Avx512Vl::load(lanes));
        compress_words_avx512vl(
            &mut words,
            block,
            params.each_ref().map(|p| Avx512Vl::load(p)),
        );
        for (lanes, word) in h.iter_mut().zip(words) {
            Avx512Vl::store(word, lanes);
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2,avx512f,avx512vl")]
unsafe fn compress_many_avx512vl(h: &mut [[u32; 8]; 8], blocks: &[[u8; 512]], count: &mut u64) {
    unsafe {
        let mut words = h.each_ref().map(|lanes| Avx512Vl::load(lanes));
        let zero = _mm256_setzero_si256();
        for block in blocks {
            *count = count.wrapping_add(64);
            let low = _mm256_set1_epi32(*count as i32);
            let high = _mm256_set1_epi32((*count >> 32) as i32);
            compress_words_avx512vl(&mut words, block, [low, high, zero, zero]);
        }
        for (lanes, word) in h.iter_mut().zip(words) {
            Avx512Vl::store(word, lanes);
        }
    }
}

#[cfg(test)]
#[path = "blake2sp_x86/tests.rs"]
mod tests;
