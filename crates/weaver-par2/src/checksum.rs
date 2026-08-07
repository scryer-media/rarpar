#[cfg(feature = "native-crypto")]
use aws_lc_sys::{MD5_CTX, MD5_Final, MD5_Init, MD5_Update};
use crc_fast::{CrcAlgorithm, Digest as FastCrcDigest};
use md5::{Digest as Md5Digest, Md5 as RustCryptoMd5};
#[cfg(feature = "native-crypto")]
use std::mem::MaybeUninit;

const ZERO_PAD_CHUNK: [u8; 8192] = [0u8; 8192];

#[derive(Clone)]
pub(crate) struct Crc32Hasher {
    inner: FastCrcDigest,
}

impl Crc32Hasher {
    pub(crate) fn new() -> Self {
        Self {
            inner: FastCrcDigest::new(CrcAlgorithm::Crc32IsoHdlc),
        }
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub(crate) fn finalize(self) -> u32 {
        self.inner.finalize() as u32
    }
}

#[cfg_attr(feature = "native-crypto", allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Par2Md5Backend {
    RustCrypto,
    #[cfg(feature = "native-crypto")]
    NativeAwsLc,
}

const fn default_md5_backend() -> Par2Md5Backend {
    #[cfg(feature = "native-crypto")]
    {
        Par2Md5Backend::NativeAwsLc
    }
    #[cfg(not(feature = "native-crypto"))]
    {
        Par2Md5Backend::RustCrypto
    }
}

#[cfg(feature = "native-crypto")]
#[derive(Clone)]
struct AwsLcMd5State {
    ctx: MD5_CTX,
}

#[cfg(feature = "native-crypto")]
impl AwsLcMd5State {
    fn new() -> Self {
        let mut ctx = MaybeUninit::<MD5_CTX>::uninit();
        let result = unsafe { MD5_Init(ctx.as_mut_ptr()) };
        assert_eq!(result, 1, "aws-lc MD5_Init must succeed");
        Self {
            ctx: unsafe { ctx.assume_init() },
        }
    }

    fn update(&mut self, data: &[u8]) {
        let result = unsafe { MD5_Update(&mut self.ctx, data.as_ptr().cast(), data.len()) };
        assert_eq!(result, 1, "aws-lc MD5_Update must succeed");
    }

    fn finalize(mut self) -> [u8; 16] {
        let mut out = [0u8; 16];
        let result = unsafe { MD5_Final(out.as_mut_ptr(), &mut self.ctx) };
        assert_eq!(result, 1, "aws-lc MD5_Final must succeed");
        out
    }
}

#[derive(Clone)]
enum Md5StateInner {
    RustCrypto(RustCryptoMd5),
    #[cfg(feature = "native-crypto")]
    NativeAwsLc(AwsLcMd5State),
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
            Par2Md5Backend::RustCrypto => Md5StateInner::RustCrypto(RustCryptoMd5::new()),
            #[cfg(feature = "native-crypto")]
            Par2Md5Backend::NativeAwsLc => Md5StateInner::NativeAwsLc(AwsLcMd5State::new()),
        };
        Self { inner }
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        match &mut self.inner {
            Md5StateInner::RustCrypto(state) => state.update(data),
            #[cfg(feature = "native-crypto")]
            Md5StateInner::NativeAwsLc(state) => state.update(data),
        }
    }

    pub(crate) fn finalize(self) -> [u8; 16] {
        match self.inner {
            Md5StateInner::RustCrypto(state) => state.finalize().into(),
            #[cfg(feature = "native-crypto")]
            Md5StateInner::NativeAwsLc(state) => state.finalize(),
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

    #[test]
    fn md5_default_backend_matches_reference_vector() {
        assert_eq!(hex(&md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[cfg(feature = "native-crypto")]
    #[test]
    fn md5_native_backend_matches_rustcrypto_backend() {
        let sample = b"par2-md5-native-vs-rustcrypto";
        let rustcrypto = md5_with_backend(Par2Md5Backend::RustCrypto, sample);
        let native = md5_with_backend(Par2Md5Backend::NativeAwsLc, sample);
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
