//! BLAKE2sp on x86 uses upstream streaming SIMD on SSE4.1/AVX2 hosts.
//! Older SSE2/SSSE3 hosts retain two local four-leaf groups. Runtime
//! detection includes OS register-state support; unsupported CPUs stay portable.

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
}
impl Backend {
    fn detect() -> Self {
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
}

/// Whole-stream state: upstream retains its vector state across input blocks.
/// Both variants use fixed-size inline storage without per-update allocation.
#[derive(Clone, Debug)]
pub(crate) struct State(Hasher);

#[derive(Clone, Debug)]
enum Hasher {
    Upstream(blake2s_simd::blake2sp::State),
    Legacy(LegacyState),
}

impl State {
    pub(crate) fn new() -> Self {
        Self::with_backend(Backend::detect())
    }

    fn with_backend(backend: Backend) -> Self {
        Self(match backend {
            Backend::Upstream => Hasher::Upstream(blake2s_simd::blake2sp::State::new()),
            backend => Hasher::Legacy(LegacyState::new(backend)),
        })
    }

    pub(crate) fn update(&mut self, input: &[u8]) {
        match &mut self.0 {
            Hasher::Upstream(state) => {
                state.update(input);
            }
            Hasher::Legacy(state) => state.update(input),
        }
    }

    pub(crate) fn finalize(&self) -> [u8; 32] {
        match &self.0 {
            Hasher::Upstream(state) => *state.finalize().as_array(),
            Hasher::Legacy(state) => state.finalize(),
        }
    }
}

/// Fixed-space fallback for hosts without upstream SIMD support.
/// Input to this group is the full eight-leaf stream, with arbitrary chunks.
#[derive(Clone)]
struct LegacyState {
    h: [[u32; 8]; 8],
    tail: [u8; 1024],
    len: usize,
    count: u64,
    backend: Backend,
}
impl std::fmt::Debug for LegacyState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Blake2spState")
            .field("backend", &self.backend)
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}
impl LegacyState {
    fn new(backend: Backend) -> Self {
        debug_assert_ne!(backend, Backend::Upstream);
        let mut h = [IV; 8];
        for (leaf, words) in h.iter_mut().enumerate() {
            words[0] ^= 32 | (8 << 16) | (2 << 24);
            words[2] ^= leaf as u32;
            words[3] ^= 32 << 24;
        }
        Self {
            h,
            tail: [0; 1024],
            len: 0,
            count: 0,
            backend,
        }
    }
    fn compress(&mut self, block: &[u8; 512], counts: [u64; 8], f0: [u32; 8], f1: [u32; 8]) {
        // SAFETY: backend is selected only after runtime CPU/OS detection.
        // All loads/stores below operate on full initialized fixed-size arrays.
        unsafe {
            match self.backend {
                Backend::Portable => compress::<Scalar, 8>(&mut self.h, block, counts, f0, f1),
                Backend::Sse2 => compress_sse2(&mut self.h, block, counts, f0, f1),
                Backend::Ssse3 => compress_ssse3(&mut self.h, block, counts, f0, f1),
                Backend::Upstream => unreachable!("upstream owns its complete streaming state"),
            }
        }
    }
    pub(crate) fn update(&mut self, mut input: &[u8]) {
        // Keep each leaf's final block: a complete superblock is non-final
        // only when at least 449 bytes follow it (seven blocks plus one byte).
        while !input.is_empty() {
            if self.len == 0 && input.len() >= 961 {
                self.count = self.count.wrapping_add(64);
                self.compress(
                    input[..512].try_into().unwrap(),
                    [self.count; 8],
                    [0; 8],
                    [0; 8],
                );
                input = &input[512..];
            } else {
                let take = input.len().min(961 - self.len);
                self.tail[self.len..self.len + take].copy_from_slice(&input[..take]);
                self.len += take;
                input = &input[take..];
                if self.len == 961 {
                    let block: [u8; 512] = self.tail[..512].try_into().unwrap();
                    self.count = self.count.wrapping_add(64);
                    self.compress(&block, [self.count; 8], [0; 8], [0; 8]);
                    self.tail.copy_within(512..self.len, 0);
                    self.len -= 512;
                }
            }
        }
    }
    pub(crate) fn finalize_leaves(&self) -> [[u8; 32]; 8] {
        let mut state = self.clone();
        let mut done = [[0u32; 8]; 8];
        for step in 0..2 {
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
            state.compress(&block, counts, final_flags, last_flags);
            for (leaf, words) in done.iter_mut().enumerate() {
                if (step == 0 && self.len <= 512 + leaf * 64)
                    || (step == 1 && self.len > 512 + leaf * 64)
                {
                    *words = state.h[leaf];
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
        let mut root = root.to_state();
        for leaf in self.finalize_leaves() {
            root.update(&leaf);
        }
        *root.finalize().as_array()
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
                hv[j] = S::load(&std::array::from_fn(|i| h[base + i][j]));
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
                mix::<S, N>(&mut v, [0, 4, 8, 12], m[p[0]], m[p[1]]);
                mix::<S, N>(&mut v, [1, 5, 9, 13], m[p[2]], m[p[3]]);
                mix::<S, N>(&mut v, [2, 6, 10, 14], m[p[4]], m[p[5]]);
                mix::<S, N>(&mut v, [3, 7, 11, 15], m[p[6]], m[p[7]]);
                mix::<S, N>(&mut v, [0, 5, 10, 15], m[p[8]], m[p[9]]);
                mix::<S, N>(&mut v, [1, 6, 11, 12], m[p[10]], m[p[11]]);
                mix::<S, N>(&mut v, [2, 7, 8, 13], m[p[12]], m[p[13]]);
                mix::<S, N>(&mut v, [3, 4, 9, 14], m[p[14]], m[p[15]]);
            }
            for j in 0..8 {
                let mut lanes = [0; N];
                S::store(S::xor(hv[j], S::xor(v[j], v[j + 8])), &mut lanes);
                for i in 0..N {
                    h[base + i][j] = lanes[i];
                }
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

#[cfg(test)]
#[path = "blake2sp_x86/tests.rs"]
mod tests;
