use crate::crc_simd;
#[cfg(par2_md5_asm)]
use crate::md5_asm::Md5 as NativeMd5;
use crc_fast::{CrcAlgorithm, Digest as FastCrcDigest};
#[cfg(par2_md5_rustcrypto)]
use md5::{Digest as Md5Digest, Md5 as RustCryptoMd5};

const ZERO_PAD_CHUNK: [u8; 8192] = [0u8; 8192];

/// Streaming CRC-32/ISO-HDLC.
///
/// Wraps [`crc_fast::Digest`], with one detour: on hosts where
/// [`crate::crc_simd`] has a tier `crc-fast` does not (VPCLMULQDQ without
/// AVX-512VL — see that module for why the hole exists), updates at or above
/// [`crc_simd::MIN_UPDATE`] are folded by the local kernel instead.
///
/// While the kernel is carrying the stream the authoritative value is the plain
/// `u32` in `accel` — which is in the finalized (post-xor) domain — and `inner`
/// is stale. `inner` is re-seeded from `accel` only when a below-threshold
/// update arrives. PAR2 slices are hundreds of kilobytes, so a slice pass
/// normally touches the digest exactly once, at construction.
///
/// Because `accel` is not a digest, [`crc_fast::Digest::get_amount`] and
/// [`crc_fast::Digest::combine`] would see a byte counter that stopped
/// advancing the moment the kernel engaged. Neither is surfaced through this
/// wrapper, and neither may be added without tracking the folded byte count
/// here first. [`Crc32CombineOp`] is unaffected — it takes an explicit `len2`.
#[derive(Clone)]
pub(crate) struct Crc32Hasher {
    inner: FastCrcDigest,
    /// Carried CRC in the finalized domain. `Some` means `inner` is stale.
    accel: Option<u32>,
    /// Resolved once per hasher rather than per update, so the hot path is a
    /// register test and not a `OnceLock` load. Always `false` on targets and
    /// hosts with no tier, where it constant-folds the branch away entirely.
    use_accel: bool,
}

impl Crc32Hasher {
    pub(crate) fn new() -> Self {
        Self {
            inner: FastCrcDigest::new(CrcAlgorithm::Crc32IsoHdlc),
            accel: None,
            use_accel: crc_simd::available(),
        }
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        if self.use_accel && data.len() >= crc_simd::MIN_UPDATE {
            // Both the kernel's input and its output are the finalized domain,
            // so consecutive folded updates just carry a `u32`.
            let initial = match self.accel {
                Some(crc) => crc,
                None => self.inner.finalize() as u32,
            };
            self.accel = Some(crc_simd::update(initial, data));
            return;
        }

        // Leaving the folding path: materialize the carried value back into the
        // resident digest exactly once, not once per update.
        if let Some(crc) = self.accel.take() {
            self.inner =
                FastCrcDigest::new_with_init_state(CrcAlgorithm::Crc32IsoHdlc, u64::from(!crc));
        }

        self.inner.update(data);
    }

    pub(crate) fn finalize(self) -> u32 {
        match self.accel {
            Some(crc) => crc,
            None => self.inner.finalize() as u32,
        }
    }
}

// MD5 backends. The assembly one (`md5_asm`) exists because RustCrypto `md-5`
// dropped its assembly after 0.10.0 and the pure-Rust code is too slow for
// PAR2's serial hashing on x86-64, while linking `aws-lc-sys` for one block
// function was too heavy and split consumers' dependency graphs; see
// `md5_asm.rs` for the full reasoning.
//
// With both backends compiled, only the assembly one is ever selected outside
// the tests, so the RustCrypto arm is dead in a non-test build of that
// configuration.
#[cfg_attr(all(par2_md5_asm, par2_md5_rustcrypto), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Par2Md5Backend {
    #[cfg(par2_md5_rustcrypto)]
    RustCrypto,
    #[cfg(par2_md5_asm)]
    Native,
}

const fn default_md5_backend() -> Par2Md5Backend {
    #[cfg(par2_md5_asm)]
    {
        Par2Md5Backend::Native
    }
    #[cfg(not(par2_md5_asm))]
    {
        Par2Md5Backend::RustCrypto
    }
}

#[derive(Clone)]
enum Md5StateInner {
    #[cfg(par2_md5_rustcrypto)]
    RustCrypto(RustCryptoMd5),
    #[cfg(par2_md5_asm)]
    Native(NativeMd5),
}

#[derive(Clone)]
pub(crate) struct Md5State {
    inner: Md5StateInner,
}

impl Md5State {
    pub(crate) fn new() -> Self {
        Self::new_with_backend(default_md5_backend())
    }

    fn new_with_backend(backend: Par2Md5Backend) -> Self {
        let inner = match backend {
            #[cfg(par2_md5_rustcrypto)]
            Par2Md5Backend::RustCrypto => Md5StateInner::RustCrypto(RustCryptoMd5::new()),
            #[cfg(par2_md5_asm)]
            Par2Md5Backend::Native => Md5StateInner::Native(NativeMd5::new()),
        };
        Self { inner }
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        match &mut self.inner {
            #[cfg(par2_md5_rustcrypto)]
            Md5StateInner::RustCrypto(state) => state.update(data),
            #[cfg(par2_md5_asm)]
            Md5StateInner::Native(state) => state.update(data),
        }
    }

    #[allow(irrefutable_let_patterns)]
    fn update_pair(&mut self, other: &mut Self, data: &[u8]) {
        #[cfg(par2_md5_asm)]
        if let (Md5StateInner::Native(left), Md5StateInner::Native(right)) =
            (&mut self.inner, &mut other.inner)
        {
            left.update_pair(right, data);
            return;
        }
        self.update(data);
        other.update(data);
    }

    pub(crate) fn finalize(self) -> [u8; 16] {
        match self.inner {
            #[cfg(par2_md5_rustcrypto)]
            Md5StateInner::RustCrypto(state) => state.finalize().into(),
            #[cfg(par2_md5_asm)]
            Md5StateInner::Native(state) => state.finalize(),
        }
    }
}

fn md5_with_backend(backend: Par2Md5Backend, data: &[u8]) -> [u8; 16] {
    let mut hasher = Md5State::new_with_backend(backend);
    hasher.update(data);
    hasher.finalize()
}

/// Streaming CRC32 + MD5 checksum state for a single file slice.
///
/// Feeds data incrementally and produces the final (CRC32, MD5) pair that can
/// be compared against PAR2 IFSC checksum entries.
///
/// For the last slice of a file (which may be shorter than slice_size), the
/// PAR2 spec requires the remaining bytes to be zero-padded for checksum
/// computation. Call [`finalize`](SliceChecksumState::finalize) with the
/// `pad_to` parameter to handle this.
#[derive(Clone)]
pub struct SliceChecksumState {
    crc32: Crc32Hasher,
    md5: Md5State,
    bytes_fed: u64,
}

impl SliceChecksumState {
    /// Create a new checksum state.
    pub fn new() -> Self {
        Self {
            crc32: Crc32Hasher::new(),
            md5: Md5State::new(),
            bytes_fed: 0,
        }
    }

    /// Feed data into the checksum accumulators.
    pub fn update(&mut self, data: &[u8]) {
        self.crc32.update(data);
        self.md5.update(data);
        self.bytes_fed += data.len() as u64;
    }

    /// Feed the same bytes to the independent file and slice MD5 chains,
    /// interleaving their rounds where the native backend permits it.
    pub(crate) fn update_with_file_hash(&mut self, file: &mut FileHashState, data: &[u8]) {
        self.crc32.update(data);
        self.md5.update_pair(&mut file.md5, data);
        self.bytes_fed += data.len() as u64;
        file.bytes_fed += data.len() as u64;
    }

    /// How many bytes have been fed so far.
    pub fn bytes_fed(&self) -> u64 {
        self.bytes_fed
    }

    /// Finalize and return (CRC32, MD5).
    ///
    /// If `pad_to` is specified and greater than `bytes_fed`, zero bytes are
    /// fed to reach that length (for the last slice of a file).
    pub fn finalize(mut self, pad_to: Option<u64>) -> (u32, [u8; 16]) {
        if let Some(target) = pad_to
            && target > self.bytes_fed
        {
            let mut remaining = target - self.bytes_fed;
            while remaining > 0 {
                let take = remaining.min(ZERO_PAD_CHUNK.len() as u64) as usize;
                self.crc32.update(&ZERO_PAD_CHUNK[..take]);
                self.md5.update(&ZERO_PAD_CHUNK[..take]);
                remaining -= take as u64;
            }
        }
        let crc = self.crc32.finalize();
        let md5 = self.md5.finalize();
        (crc, md5)
    }
}

impl Default for SliceChecksumState {
    fn default() -> Self {
        Self::new()
    }
}

/// Streaming full-file MD5 hash state.
#[derive(Clone)]
pub struct FileHashState {
    md5: Md5State,
    bytes_fed: u64,
}

impl FileHashState {
    pub fn new() -> Self {
        Self {
            md5: Md5State::new(),
            bytes_fed: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.md5.update(data);
        self.bytes_fed += data.len() as u64;
    }

    pub fn bytes_fed(&self) -> u64 {
        self.bytes_fed
    }

    pub fn finalize(self) -> [u8; 16] {
        self.md5.finalize()
    }
}

impl Default for FileHashState {
    fn default() -> Self {
        Self::new()
    }
}

/// Combine two CRC32 values as if the underlying data were concatenated.
const CRC32_COMBINE_POLY: u32 = 0xEDB8_8320;

#[derive(Debug, Clone)]
pub struct Crc32CombineOp {
    op: Option<[u32; 32]>,
}

impl Crc32CombineOp {
    pub fn new(len2: u64) -> Self {
        if len2 == 0 {
            return Self { op: None };
        }

        let mut op = [0u32; 32];
        op[0] = CRC32_COMBINE_POLY;
        for (n, item) in op.iter_mut().enumerate().skip(1) {
            *item = 1 << (n - 1);
        }

        let mut tmp = [0u32; 32];
        for _ in 0..3 {
            crc32_mat_square(&mut tmp, &op);
            op = tmp;
        }

        let mut remaining = len2;
        let mut combined = [0u32; 32];
        for (n, item) in combined.iter_mut().enumerate() {
            *item = 1 << n;
        }
        while remaining > 0 {
            if remaining & 1 != 0 {
                let previous = combined;
                for n in 0..32 {
                    combined[n] = crc32_mat_vec(&op, previous[n]);
                }
            }
            remaining >>= 1;
            if remaining > 0 {
                crc32_mat_square(&mut tmp, &op);
                op = tmp;
            }
        }

        Self { op: Some(combined) }
    }

    pub fn combine(&self, crc1: u32, crc2: u32) -> u32 {
        match &self.op {
            Some(op) => crc32_mat_vec(op, crc1) ^ crc2,
            None => crc1,
        }
    }
}

/// Reverses a CRC32 concatenation operation for a fixed suffix length.
///
/// Given the CRC32 of `prefix || suffix` and the CRC32 of `suffix`, this
/// operator recovers the CRC32 of `prefix`. This is useful for PAR2's final
/// input slice, whose IFSC CRC includes zero-padding that is not part of the
/// file itself.
#[derive(Debug, Clone)]
pub struct Crc32UncombineOp {
    inverse: Option<[u32; 32]>,
}

impl Crc32UncombineOp {
    /// Create an inverse operator for a suffix with `len2` bytes.
    pub fn new(len2: u64) -> Self {
        let inverse = Crc32CombineOp::new(len2)
            .op
            .as_ref()
            .and_then(crc32_mat_invert);
        Self { inverse }
    }

    /// Recover the CRC32 before a suffix from the concatenated CRC32.
    ///
    /// `combined` must be the CRC32 of the concatenated data and `crc2` the
    /// CRC32 of its `len2`-byte suffix. For a zero-byte suffix this returns
    /// `combined` unchanged.
    pub fn uncombine(&self, combined: u32, crc2: u32) -> u32 {
        match &self.inverse {
            Some(inverse) => crc32_mat_vec(inverse, combined ^ crc2),
            None => combined,
        }
    }
}

#[inline]
fn crc32_mat_vec(mat: &[u32; 32], vec: u32) -> u32 {
    let mut result = 0u32;
    let mut v = vec;
    let mut i = 0;
    while v != 0 {
        if v & 1 != 0 {
            result ^= mat[i];
        }
        v >>= 1;
        i += 1;
    }
    result
}

fn crc32_mat_square(square: &mut [u32; 32], mat: &[u32; 32]) {
    for n in 0..32 {
        square[n] = crc32_mat_vec(mat, mat[n]);
    }
}

/// Invert a GF(2) matrix stored as the output vector for each input bit.
fn crc32_mat_invert(mat: &[u32; 32]) -> Option<[u32; 32]> {
    // Gaussian elimination is more convenient on rows, while the CRC helper
    // above stores columns. Transpose into rows first.
    let mut left = [0u32; 32];
    for (column, &column_bits) in mat.iter().enumerate() {
        for (row, row_bits) in left.iter_mut().enumerate() {
            if column_bits & (1 << row) != 0 {
                *row_bits |= 1 << column;
            }
        }
    }
    let mut right = [0u32; 32];
    for (row, item) in right.iter_mut().enumerate() {
        *item = 1 << row;
    }

    for column in 0..32 {
        let pivot = (column..32).find(|&row| left[row] & (1 << column) != 0)?;
        left.swap(column, pivot);
        right.swap(column, pivot);

        for row in 0..32 {
            if row != column && left[row] & (1 << column) != 0 {
                left[row] ^= left[column];
                right[row] ^= right[column];
            }
        }
    }

    debug_assert!(left.iter().enumerate().all(|(row, &bits)| bits == 1 << row));

    // Transpose the inverse back to the CRC helper's column representation.
    let mut inverse = [0u32; 32];
    for (input, inverse_column) in inverse.iter_mut().enumerate() {
        for (output, &row_bits) in right.iter().enumerate() {
            if row_bits & (1 << input) != 0 {
                *inverse_column |= 1 << output;
            }
        }
    }
    Some(inverse)
}

pub fn crc32_combine(crc1: u32, crc2: u32, len2: u64) -> u32 {
    Crc32CombineOp::new(len2).combine(crc1, crc2)
}

/// Undo [`crc32_combine`] for a known suffix CRC and length.
pub fn crc32_uncombine(combined: u32, crc2: u32, len2: u64) -> u32 {
    Crc32UncombineOp::new(len2).uncombine(combined, crc2)
}

/// Compute CRC32 of a byte slice.
pub fn crc32(data: &[u8]) -> u32 {
    let mut hasher = Crc32Hasher::new();
    hasher.update(data);
    hasher.finalize()
}

/// Compute CRC32 of a byte slice, zero-padding to `pad_to` bytes.
pub(crate) fn crc32_padded(data: &[u8], pad_to: u64) -> u32 {
    let mut hasher = Crc32Hasher::new();
    hasher.update(data);
    let mut remaining = pad_to.saturating_sub(data.len() as u64);
    while remaining > 0 {
        let chunk = remaining.min(ZERO_PAD_CHUNK.len() as u64) as usize;
        hasher.update(&ZERO_PAD_CHUNK[..chunk]);
        remaining -= chunk as u64;
    }
    hasher.finalize()
}

/// Compute MD5 of a byte slice.
pub fn md5(data: &[u8]) -> [u8; 16] {
    md5_with_backend(default_md5_backend(), data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[cfg(all(par2_md5_rustcrypto, not(par2_md5_asm)))]
    #[test]
    fn rust_only_md5_keeps_safe_streaming_pair_fallback() {
        use md5::Digest as _;
        assert_eq!(default_md5_backend(), Par2Md5Backend::RustCrypto);
        let data: Vec<u8> = (0..70000).map(|i| (i * 37 + 11) as u8).collect();
        for (prefix, other_prefix) in [(0, 0), (1, 63), (64, 64), (65, 129)] {
            for len in [0, 1, 55, 56, 63, 64, 65, 4097, 65536] {
                let (mut a, mut b) = (Md5State::new(), Md5State::new());
                let (mut ra, mut rb) = (md5::Md5::new(), md5::Md5::new());
                a.update(&data[..prefix]);
                ra.update(&data[..prefix]);
                b.update(&data[129..129 + other_prefix]);
                rb.update(&data[129..129 + other_prefix]);
                for chunk in data[256..256 + len].chunks(137) {
                    a.update_pair(&mut b, chunk);
                    ra.update(chunk);
                    rb.update(chunk);
                }
                assert_eq!(a.finalize(), <[u8; 16]>::from(ra.finalize()));
                assert_eq!(b.finalize(), <[u8; 16]>::from(rb.finalize()));
            }
        }
    }

    #[cfg(par2_md5_asm)]
    #[test]
    fn paired_assembly_matches_scalar_states_and_rust_pairs() {
        let before = crate::md5_pair_asm::executions();
        let mut seed = 0xf0c3_19b8_8457_2d61;
        let mut x = vec![0; 1024 + 64];
        let mut y = vec![0; 1024 + 64];
        for byte in x.iter_mut().chain(&mut y) {
            *byte = (next_pseudorandom(&mut seed) >> 32) as u8;
        }
        for offset in 0..64 {
            for other_offset in 0..64 {
                for len in [0, 64, 128, 192, 1024] {
                    let left = std::array::from_fn(|_| (next_pseudorandom(&mut seed) >> 16) as u32);
                    let right =
                        std::array::from_fn(|_| (next_pseudorandom(&mut seed) >> 16) as u32);
                    let x = &x[offset..offset + len];
                    let y = &y[other_offset..other_offset + len];
                    let (mut scalar_left, mut scalar_right) = (left, right);
                    crate::md5_simd::compress_scalar_state(&mut scalar_left, x);
                    crate::md5_simd::compress_scalar_state(&mut scalar_right, y);
                    let (mut rust_left, mut rust_right) = (left, right);
                    crate::md5_simd::compress_pair(&mut rust_left, &mut rust_right, x, y);
                    assert_eq!((rust_left, rust_right), (scalar_left, scalar_right));
                    let (mut actual_left, mut actual_right) = (left, right);
                    crate::md5_pair_asm::compress_pair(&mut actual_left, &mut actual_right, x, y);
                    assert_eq!(
                        (actual_left, actual_right),
                        (scalar_left, scalar_right),
                        "alignment {offset}/{other_offset}, len {len}"
                    );
                    #[cfg(target_arch = "x86_64")]
                    {
                        let (mut actual_left, mut actual_right) = (left, right);
                        crate::md5_pair_asm::compress_baseline(
                            &mut actual_left,
                            &mut actual_right,
                            x,
                            y,
                        );
                        assert_eq!((actual_left, actual_right), (scalar_left, scalar_right));
                    }
                }
            }
        }
        assert_assembly_executions(before, true);
    }

    #[cfg(par2_md5_asm)]
    #[test]
    fn paired_native_streaming_uses_selected_assembly() {
        assert_eq!(default_md5_backend(), Par2Md5Backend::Native);
        let before = crate::md5_pair_asm::executions();
        let (mut left, mut right) = (Md5State::new(), Md5State::new());
        left.update_pair(&mut right, &[0x5a; 129]);
        let after = crate::md5_pair_asm::executions();
        #[cfg(target_arch = "aarch64")]
        let backend = 0;
        #[cfg(target_arch = "x86_64")]
        let backend = if std::is_x86_feature_detected!("bmi1") {
            2
        } else {
            1
        };
        assert!(after[backend] > before[backend]);
        let memcheck = {
            #[cfg(target_os = "linux")]
            {
                std::fs::read_to_string("/proc/self/maps")
                    .expect("read own mappings for CI instrumentation evidence")
                    .contains("vgpreload_memcheck")
            }
            #[cfg(not(target_os = "linux"))]
            {
                false
            }
        };
        match std::env::var("PAR2_CI_MD5_RUN").as_deref() {
            Ok("native") => assert!(!memcheck, "native dispatch pass must be uninstrumented"),
            Ok("memcheck") => assert!(memcheck, "Memcheck runner did not instrument the test"),
            Err(std::env::VarError::NotPresent) => {}
            other => panic!("unsupported MD5 CI instrumentation mode: {other:?}"),
        }
        #[cfg(target_arch = "aarch64")]
        let selected = "aarch64-baseline";
        #[cfg(target_arch = "x86_64")]
        let selected = if backend == 2 {
            "x86-bmi1"
        } else {
            "x86-baseline"
        };
        eprintln!(
            "MD5 assembly execution: arch={}, selected={selected}, counts={after:?}, memcheck={memcheck}",
            std::env::consts::ARCH
        );
        assert_eq!(left.finalize(), right.finalize());
    }

    #[cfg(par2_md5_asm)]
    #[test]
    fn paired_streams_random_chunks_match_rustcrypto() {
        use md5::Digest as _;
        let mut seed = 0x9568_ae75_e59c_24bd;
        for case in 0..256 {
            let offset = (next_pseudorandom(&mut seed) >> 32) as usize % 64;
            let len = (next_pseudorandom(&mut seed) >> 32) as usize % 131073;
            let mut data = vec![0; len + offset + 512];
            for byte in &mut data {
                *byte = (next_pseudorandom(&mut seed) >> 32) as u8;
            }
            let first_prefix = (next_pseudorandom(&mut seed) >> 32) as usize % 256;
            let second_prefix = if case % 2 == 0 {
                first_prefix
            } else {
                (next_pseudorandom(&mut seed) >> 32) as usize % 256
            };
            let (mut left, mut right) = (Md5State::new(), Md5State::new());
            let (mut ref_left, mut ref_right) = (md5::Md5::new(), md5::Md5::new());
            left.update(&data[..first_prefix]);
            ref_left.update(&data[..first_prefix]);
            right.update(&data[256..256 + second_prefix]);
            ref_right.update(&data[256..256 + second_prefix]);
            let mut rest = &data[offset..offset + len];
            while !rest.is_empty() {
                let chunk =
                    ((next_pseudorandom(&mut seed) >> 32) as usize % 8192 + 1).min(rest.len());
                left.update_pair(&mut right, &rest[..chunk]);
                ref_left.update(&rest[..chunk]);
                ref_right.update(&rest[..chunk]);
                rest = &rest[chunk..];
            }
            assert_eq!(
                left.finalize(),
                <[u8; 16]>::from(ref_left.finalize()),
                "case {case}"
            );
            assert_eq!(
                right.finalize(),
                <[u8; 16]>::from(ref_right.finalize()),
                "case {case}"
            );
        }
    }

    /// Heap redzones give Memcheck byte-exact upper bounds even when an
    /// unaligned complete-block stream cannot end at a page boundary.
    #[cfg(par2_md5_asm)]
    #[test]
    fn paired_assembly_respects_exact_allocations() {
        let before = crate::md5_pair_asm::executions();
        for offset in 0..64 {
            for len in [64, 128, 4096] {
                let other_offset = 63 - offset;
                let x = vec![0x39; offset + len].into_boxed_slice();
                let y = vec![0xa7; other_offset + len].into_boxed_slice();
                let (x, y) = (&x[offset..], &y[other_offset..]);
                let (mut left, mut right) = ([0x12345678; 4], [0xfedcba98; 4]);
                let (mut expected_left, mut expected_right) = (left, right);
                crate::md5_simd::compress_scalar_state(&mut expected_left, x);
                crate::md5_simd::compress_scalar_state(&mut expected_right, y);
                crate::md5_pair_asm::compress_pair(&mut left, &mut right, x, y);
                assert_eq!((left, right), (expected_left, expected_right));
                #[cfg(target_arch = "x86_64")]
                {
                    let (mut left, mut right) = ([0x12345678; 4], [0xfedcba98; 4]);
                    crate::md5_pair_asm::compress_baseline(&mut left, &mut right, x, y);
                    assert_eq!((left, right), (expected_left, expected_right));
                }
            }
        }
        assert_assembly_executions(before, true);
    }

    #[cfg(par2_md5_asm)]
    fn assert_assembly_executions(before: [usize; 3], baseline: bool) {
        let after = crate::md5_pair_asm::executions();
        #[cfg(target_arch = "aarch64")]
        assert!(after[0] > before[0], "AArch64 assembly must execute");
        #[cfg(target_arch = "x86_64")]
        {
            if baseline {
                assert!(after[1] > before[1], "baseline x86 assembly must execute");
            }
            if std::is_x86_feature_detected!("bmi1") {
                assert!(
                    after[2] > before[2],
                    "advertised BMI1 assembly must execute"
                );
            } else {
                assert_eq!(
                    after[2], before[2],
                    "BMI1 must not execute without detection"
                );
            }
        }
        #[cfg(target_arch = "aarch64")]
        let _ = baseline;
        eprintln!("MD5 assembly differential/bounds execution: before={before:?}, after={after:?}");
    }

    #[cfg(all(par2_md5_asm, unix))]
    #[test]
    fn paired_assembly_stops_at_guard_page() {
        struct Guard {
            address: *mut libc::c_void,
            page: usize,
        }
        impl Guard {
            fn new(value: u8) -> Self {
                // SAFETY: query-only sysconf, followed by a private mapping.
                let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
                assert!(page >= 128);
                let page = page as usize;
                // SAFETY: allocate three anonymous pages; replace no mapping.
                let address = unsafe {
                    libc::mmap(
                        std::ptr::null_mut(),
                        page * 3,
                        libc::PROT_NONE,
                        libc::MAP_PRIVATE | libc::MAP_ANON,
                        -1,
                        0,
                    )
                };
                assert_ne!(address, libc::MAP_FAILED);
                let guard = Self { address, page };
                // SAFETY: only the middle page is made writable and initialized;
                // inaccessible pages on both sides catch under/over-reads.
                unsafe {
                    let middle = address.cast::<u8>().add(page);
                    assert_eq!(
                        libc::mprotect(middle.cast(), page, libc::PROT_READ | libc::PROT_WRITE),
                        0
                    );
                    std::ptr::write_bytes(middle, value, page);
                }
                guard
            }
            fn blocks(&self, len: usize, offset: usize, at_end: bool) -> &[u8] {
                assert!(len + offset <= self.page);
                let start = if at_end {
                    self.page * 2 - len - offset
                } else {
                    self.page + offset
                };
                // SAFETY: this initialized range lies entirely in the middle
                // page, and the mapping outlives the returned borrow.
                unsafe { std::slice::from_raw_parts(self.address.cast::<u8>().add(start), len) }
            }
        }
        impl Drop for Guard {
            fn drop(&mut self) {
                // SAFETY: this object uniquely owns all three pages.
                unsafe {
                    libc::munmap(self.address, self.page * 3);
                }
            }
        }
        let before = crate::md5_pair_asm::executions();
        let (x, y) = (Guard::new(0x39), Guard::new(0xa7));
        for at_end in [false, true] {
            for offset in 0..64 {
                for len in [64, 128, x.page - 64] {
                    let (x, y) = (
                        x.blocks(len, offset, at_end),
                        y.blocks(len, 63 - offset, !at_end),
                    );
                    let (mut left, mut right) = ([0x12345678; 4], [0xfedcba98; 4]);
                    let (mut expected_left, mut expected_right) = (left, right);
                    crate::md5_simd::compress_scalar_state(&mut expected_left, x);
                    crate::md5_simd::compress_scalar_state(&mut expected_right, y);
                    crate::md5_pair_asm::compress_pair(&mut left, &mut right, x, y);
                    assert_eq!((left, right), (expected_left, expected_right));
                    #[cfg(target_arch = "x86_64")]
                    {
                        let (mut left, mut right) = ([0x12345678; 4], [0xfedcba98; 4]);
                        crate::md5_pair_asm::compress_baseline(&mut left, &mut right, x, y);
                        assert_eq!((left, right), (expected_left, expected_right));
                    }
                }
            }
        }
        assert_assembly_executions(before, true);
    }

    #[cfg(par2_md5_asm)]
    #[test]
    fn stitched_md5_matches_independent_states_at_every_offset() {
        use md5::Digest as _;
        let data: Vec<u8> = (0..70000).map(|i| (i * 37 + 11) as u8).collect();
        for prefix in 0..128 {
            for other_prefix in [0, prefix, 63, 64, 65] {
                for len in [0, 1, 55, 56, 63, 64, 65, 127, 128, 129, 4097, 65536] {
                    let mut a = Md5State::new();
                    let mut b = Md5State::new();
                    a.update(&data[..prefix]);
                    b.update(&data[129..129 + other_prefix]);
                    let mut ra = md5::Md5::new();
                    let mut rb = md5::Md5::new();
                    ra.update(&data[..prefix]);
                    rb.update(&data[129..129 + other_prefix]);
                    // Chunking crosses buffer-fill and block boundaries.
                    for chunk in data[256..256 + len].chunks(137) {
                        a.update_pair(&mut b, chunk);
                        ra.update(chunk);
                        rb.update(chunk);
                    }
                    assert_eq!(a.finalize(), <[u8; 16]>::from(ra.finalize()));
                    assert_eq!(b.finalize(), <[u8; 16]>::from(rb.finalize()));
                }
            }
        }
    }

    #[test]
    fn md5_default_backend_matches_reference_vector() {
        assert_eq!(hex(&md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
    }

    /// The assembly backend against an MD5 the build did not select: the
    /// reference comes from the dev-dependency, so this runs on a default
    /// build that links no RustCrypto backend at all.
    #[cfg(par2_md5_asm)]
    #[test]
    fn md5_native_backend_matches_independent_reference() {
        use md5::Digest as _;
        let sample = b"par2-md5-native-vs-reference";
        let native = md5_with_backend(Par2Md5Backend::Native, sample);
        let reference: [u8; 16] = md5::Md5::digest(sample).into();
        assert_eq!(native, reference);
    }

    /// Every length through five blocks (each padding case, one- and
    /// two-block tails), fed whole and in random pieces, plus multi-block
    /// updates that start part-way into a buffered block.
    #[cfg(par2_md5_asm)]
    #[test]
    fn md5_native_backend_matches_reference_at_every_length_and_split() {
        use md5::Digest as _;
        let mut seed = 0x6d64_355f_6173_6d21u64;
        let mut data = vec![0u8; 70_000];
        fill_pseudorandom(&mut data, &mut seed);
        let lengths = (0..=320).chain([4095, 4096, 4097, 65_535, 65_536, 70_000]);
        for len in lengths {
            let sample = &data[..len];
            let reference: [u8; 16] = md5::Md5::digest(sample).into();
            assert_eq!(
                md5_with_backend(Par2Md5Backend::Native, sample),
                reference,
                "len={len}"
            );
            for _ in 0..4 {
                let mut state = Md5State::new_with_backend(Par2Md5Backend::Native);
                let mut offset = 0;
                while offset < len {
                    let take =
                        1 + (next_pseudorandom(&mut seed) as usize % (len - offset).min(200));
                    state.update(&sample[offset..offset + take]);
                    offset += take;
                }
                assert_eq!(state.finalize(), reference, "len={len} split");
            }
        }
    }

    #[cfg(all(par2_md5_asm, par2_md5_rustcrypto))]
    #[test]
    fn md5_native_backend_matches_rustcrypto_backend() {
        let sample = b"par2-md5-native-vs-rustcrypto";
        let rustcrypto = md5_with_backend(Par2Md5Backend::RustCrypto, sample);
        let native = md5_with_backend(Par2Md5Backend::Native, sample);
        assert_eq!(native, rustcrypto);
    }

    #[test]
    fn file_hash_state_matches_one_shot_md5() {
        let mut state = FileHashState::new();
        state.update(b"par2");
        state.update(b"-state");
        assert_eq!(state.finalize(), md5(b"par2-state"));
    }

    #[test]
    fn crc32_combine_op_matches_one_shot_combine() {
        let first = crc32(b"short-tail");
        let padding = [0u8; 17];
        let second = crc32(&padding);
        let mut concatenated = b"short-tail".to_vec();
        concatenated.extend_from_slice(&padding);

        let op = Crc32CombineOp::new(padding.len() as u64);
        assert_eq!(op.combine(first, second), crc32_combine(first, second, 17));
        assert_eq!(op.combine(first, second), crc32(&concatenated));
    }

    #[test]
    fn crc32_uncombine_recovers_randomized_prefixes() {
        let mut seed = 0x5eed_cafe_dead_beefu64;

        for _ in 0..128 {
            let prefix_len = (next_pseudorandom(&mut seed) % 513) as usize;
            let suffix_len = (next_pseudorandom(&mut seed) % 513) as usize;
            let mut prefix = vec![0u8; prefix_len];
            let mut suffix = vec![0u8; suffix_len];
            fill_pseudorandom(&mut prefix, &mut seed);
            fill_pseudorandom(&mut suffix, &mut seed);

            let mut joined = prefix.clone();
            joined.extend_from_slice(&suffix);

            let prefix_crc = crc32(&prefix);
            let suffix_crc = crc32(&suffix);
            let joined_crc = crc32(&joined);
            let uncombine = Crc32UncombineOp::new(suffix_len as u64);

            assert_eq!(uncombine.uncombine(joined_crc, suffix_crc), prefix_crc);
            assert_eq!(
                crc32_uncombine(joined_crc, suffix_crc, suffix_len as u64),
                prefix_crc
            );
        }
    }

    #[test]
    fn crc32_uncombine_removes_randomized_zero_padding() {
        let mut seed = 0x8bad_f00d_0123_4567u64;

        for _ in 0..128 {
            let data_len = (next_pseudorandom(&mut seed) % 1025) as usize;
            let padding_len = (next_pseudorandom(&mut seed) % 1025) as usize;
            let mut data = vec![0u8; data_len];
            fill_pseudorandom(&mut data, &mut seed);

            let mut padded = data.clone();
            padded.resize(data_len + padding_len, 0);

            assert_eq!(
                crc32_uncombine(
                    crc32(&padded),
                    crc32(&vec![0u8; padding_len]),
                    padding_len as u64,
                ),
                crc32(&data)
            );
        }
    }

    // =======================================================================
    // The accelerated CRC tier's seam. Every assertion below uses
    // `crc_fast::crc32_iso_hdlc` as the oracle rather than this module's own
    // `crc32`, so the tier is pinned against an external implementation and
    // never against itself.
    // =======================================================================

    /// A randomized sequence of chunk sizes (each >= 1) summing to `total`,
    /// stressing the seam's update chaining across many boundaries.
    fn random_splits(total: usize, seed: &mut u64) -> Vec<usize> {
        let mut remaining = total;
        let mut sizes = Vec::new();
        while remaining > 0 {
            let take = 1 + (next_pseudorandom(seed) % remaining.min(4096) as u64) as usize;
            sizes.push(take);
            remaining -= take;
        }
        sizes
    }

    /// Feed `data` through [`Crc32Hasher`] in the given `splits`.
    fn hasher_over_splits(data: &[u8], splits: &[usize]) -> u32 {
        let mut hasher = Crc32Hasher::new();
        let mut offset = 0usize;
        for &size in splits {
            hasher.update(&data[offset..offset + size]);
            offset += size;
        }
        assert_eq!(offset, data.len(), "splits must cover the whole buffer");
        hasher.finalize()
    }

    /// The hasher over randomized chunk splits (and the all-1-byte and
    /// whole-buffer extremes) must equal the one-shot checksum at every length.
    #[test]
    fn crc32_hasher_matches_one_shot_over_random_splits() {
        let mut seed = 0x00C3_2000_ABCD_EF01u64;
        let mut cases = 0usize;

        for &len in &[
            0usize, 1, 2, 15, 16, 17, 63, 64, 255, 256, 1023, 1024, 4095, 4096, 4097, 65_535,
            65_536, 65_537, 1_000_003,
        ] {
            let mut data = vec![0u8; len];
            fill_pseudorandom(&mut data, &mut seed);
            let reference = crc_fast::crc32_iso_hdlc(&data);

            let all_1: Vec<usize> = vec![1usize; len];
            let random = random_splits(len, &mut seed);
            let whole = if len == 0 { vec![] } else { vec![len] };

            for (label, splits) in [("all-1", &all_1), ("random", &random), ("whole", &whole)] {
                assert_eq!(
                    hasher_over_splits(&data, splits),
                    reference,
                    "Crc32Hasher diverged from one-shot CRC: len={len}, split={label}"
                );
            }

            cases += 1;
        }

        assert!(cases >= 10, "expected >= 10 CRC cases, ran {cases}");
    }

    /// Update sequences that bounce across [`crc_simd::MIN_UPDATE`] in both
    /// directions, checked at *every prefix* rather than only at the end, so a
    /// bad hand-off is attributed to the update that introduced it.
    ///
    /// This is the load-bearing test for the tier's interaction with the
    /// digest: entering the fold, leaving it, re-entering it, and the exact
    /// threshold boundary (255 vs 256). On a host with no tier it still runs
    /// and proves the seam unchanged, so it is never a silent skip.
    #[test]
    fn crc32_hasher_survives_updates_straddling_the_tier_threshold() {
        const LEN: usize = 64 * 1024;
        let mut seed = 0x00C3_2000_5111_D001u64;
        let mut data = vec![0u8; LEN];
        fill_pseudorandom(&mut data, &mut seed);

        let min = crc_simd::MIN_UPDATE;
        let sequences: [&[usize]; 8] = [
            &[1, 64, 255, 256, 300, 4096, 7],
            &[4096, 7, 256, 1, 300, 255, 64],
            &[256, 256, 256, 1, 1, 1, 4096],
            &[7, 7, 7, 300, 7, 4096, 255, 256],
            &[300, 1, 4096, 64, 256, 255, 7, 256],
            &[4096, 4096, 1, 4096, 255, 300, 256],
            &[8192, 8192, 8192, 1],
            &[1, 8192, 1, 8192, 1],
        ];

        let mut prefixes = 0usize;
        for seq in sequences {
            assert!(
                seq.iter().any(|&len| len >= min) && seq.iter().any(|&len| len < min),
                "sequence {seq:?} must straddle MIN_UPDATE ({min}) to be useful"
            );
            let total: usize = seq.iter().sum();
            assert!(total <= LEN, "sequence {seq:?} exceeds the fixture");

            let mut hasher = Crc32Hasher::new();
            let mut offset = 0usize;
            for &len in seq {
                hasher.update(&data[offset..offset + len]);
                offset += len;
                assert_eq!(
                    hasher.clone().finalize(),
                    crc_fast::crc32_iso_hdlc(&data[..offset]),
                    "sequence {seq:?} diverged at prefix {offset}"
                );
                prefixes += 1;
            }
        }

        assert!(
            prefixes >= 50,
            "expected >= 50 prefix checks, ran {prefixes}"
        );
    }

    /// The public one-shot [`crc32`] takes the tier for buffers at or above the
    /// threshold and `crc-fast` below it; both arms must agree with `crc-fast`.
    #[test]
    fn crc32_one_shot_matches_crc_fast_across_the_threshold() {
        let mut seed = 0x00C3_2000_5111_D002u64;
        let mut data = vec![0u8; 8192];
        fill_pseudorandom(&mut data, &mut seed);

        let min = crc_simd::MIN_UPDATE;
        for len in [
            0,
            1,
            min.saturating_sub(2),
            min.saturating_sub(1),
            min,
            min + 1,
            min + 2,
            1024,
            8192,
        ] {
            assert_eq!(
                crc32(&data[..len]),
                crc_fast::crc32_iso_hdlc(&data[..len]),
                "len {len}"
            );
        }
    }

    /// The zero-padding loops in [`crc32_padded`] and
    /// [`SliceChecksumState::finalize`] feed 8 KiB chunks, which fold through
    /// the tier. Both must match the CRC of an explicitly padded buffer, with
    /// the data portion sized either side of the threshold.
    #[test]
    fn padded_crc_paths_fold_zero_padding_through_the_tier() {
        let mut seed = 0x00C3_2000_5111_D003u64;
        let min = crc_simd::MIN_UPDATE as u64;

        let mut cases = 0usize;
        for data_len in [0u64, 1, min - 1, min, min + 1, 4096, 20_000] {
            for pad_to in [data_len, data_len + 1, data_len + 8192, data_len + 20_001] {
                let mut data = vec![0u8; data_len as usize];
                fill_pseudorandom(&mut data, &mut seed);

                let mut expanded = data.clone();
                expanded.resize(pad_to as usize, 0);
                let reference = crc_fast::crc32_iso_hdlc(&expanded);

                assert_eq!(
                    crc32_padded(&data, pad_to),
                    reference,
                    "crc32_padded: data_len {data_len} pad_to {pad_to}"
                );

                // The same padding, reached through the streaming state, fed in
                // chunks that straddle the threshold in both directions.
                let mut state = SliceChecksumState::new();
                let mut offset = 0usize;
                for chunk in [1usize, 300, 7, 4096] {
                    let take = chunk.min(data.len() - offset);
                    state.update(&data[offset..offset + take]);
                    offset += take;
                }
                state.update(&data[offset..]);
                let (crc, md5_digest) = state.finalize(Some(pad_to));
                assert_eq!(
                    crc, reference,
                    "SliceChecksumState: data_len {data_len} pad_to {pad_to}"
                );
                assert_eq!(
                    md5_digest,
                    md5(&expanded),
                    "SliceChecksumState MD5: data_len {data_len} pad_to {pad_to}"
                );

                cases += 1;
            }
        }

        assert!(cases >= 28, "expected >= 28 padding cases, ran {cases}");
    }

    fn next_pseudorandom(seed: &mut u64) -> u64 {
        *seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        *seed
    }

    fn fill_pseudorandom(bytes: &mut [u8], seed: &mut u64) {
        for byte in bytes {
            *byte = next_pseudorandom(seed) as u8;
        }
    }
}
