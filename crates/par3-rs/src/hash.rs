//! The two hashes PAR3 is built on.
//!
//! * The **fingerprint** is the first 16 bytes of a BLAKE3 digest. It appears in
//!   every packet header, in File packets (as the hash of the protected file
//!   data), and in External Data packets (as the hash of an input block).
//! * The **rolling hash** is CRC-64/GO-ISO. PAR3 uses it as a cheap locator: for
//!   the first 16 KiB of a file, for each input block, and for the first 40 bytes
//!   of a chunk tail.
//!
//! Both come in a one-shot function and an incremental hasher, so a large file
//! can be hashed without being held in memory.
//!
//! ```
//! use par3_rs::hash::{fingerprint, rolling_hash};
//!
//! // CRC-64/GO-ISO check value.
//! assert_eq!(rolling_hash(b"123456789"), 0xB909_56C7_75A4_1001);
//! assert_eq!(fingerprint(b"qrstuvwxyz").len(), 16);
//! ```

use crc_fast::{CrcAlgorithm, Digest};

/// Length of a PAR3 fingerprint hash, in bytes.
pub const FINGERPRINT_LEN: usize = 16;

/// A 16-byte BLAKE3 fingerprint, the checksum PAR3 uses everywhere.
pub type Fingerprint = [u8; FINGERPRINT_LEN];

/// Number of leading file bytes covered by a File packet's rolling hash.
///
/// The field holds the rolling hash of the whole file when the file is shorter
/// than this.
pub const QUICK_HASH_LEN: usize = 16 * 1024;

/// Bytes of a chunk tail covered by the tail's rolling hash.
///
/// A tail shorter than this is stored inline in the chunk description instead of
/// being described by hashes.
pub const TAIL_HASH_LEN: usize = 40;

/// The fingerprint of `data`: the first 16 bytes of its BLAKE3 digest.
///
/// For a file whose data is entirely protected, this equals the first 16 bytes
/// of what `b3sum` reports for the same file.
#[must_use]
pub fn fingerprint(data: &[u8]) -> Fingerprint {
    let mut hasher = FingerprintHasher::new();
    hasher.update(data);
    hasher.finalize()
}

/// Incremental form of [`fingerprint`].
///
/// ```
/// use par3_rs::hash::{FingerprintHasher, fingerprint};
///
/// let mut hasher = FingerprintHasher::new();
/// hasher.update(b"qrstu");
/// hasher.update(b"vwxyz");
/// assert_eq!(hasher.finalize(), fingerprint(b"qrstuvwxyz"));
/// ```
#[derive(Clone, Default)]
pub struct FingerprintHasher {
    inner: blake3::Hasher,
}

impl FingerprintHasher {
    /// Start a new fingerprint hash.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed more bytes into the hash.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Feed `count` zero bytes into the hash.
    ///
    /// Unprotected chunks and the unused tail of a partially filled input block
    /// are both hashed as zeros, so this is a common enough operation to be worth
    /// doing without allocating a zero buffer per call.
    pub fn update_zeros(&mut self, count: u64) {
        const ZEROS: [u8; 4096] = [0u8; 4096];
        let mut remaining = count;
        while remaining > 0 {
            let take = remaining.min(ZEROS.len() as u64) as usize;
            self.inner.update(&ZEROS[..take]);
            remaining -= take as u64;
        }
    }

    /// Finish the hash and take its first 16 bytes.
    #[must_use]
    pub fn finalize(&self) -> Fingerprint {
        let digest = self.inner.finalize();
        let mut out = [0u8; FINGERPRINT_LEN];
        out.copy_from_slice(&digest.as_bytes()[..FINGERPRINT_LEN]);
        out
    }
}

impl std::fmt::Debug for FingerprintHasher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FingerprintHasher").finish_non_exhaustive()
    }
}

/// The CRC-64/GO-ISO rolling hash of `data`.
///
/// Reflected polynomial `0xD800000000000000` (normal `0x1B`), initial value and
/// final XOR both all-ones, input and output reflected. The check value for
/// `"123456789"` is `0xB90956C775A41001`.
///
/// PAR3 stores this value as a little-endian `u64`.
#[must_use]
pub fn rolling_hash(data: &[u8]) -> u64 {
    crc_fast::checksum(CrcAlgorithm::Crc64GoIso, data)
}

/// The rolling hash a File packet stores for the first [`QUICK_HASH_LEN`] bytes.
///
/// Shorter inputs are hashed whole, which is what the format asks for.
#[must_use]
pub fn quick_rolling_hash(data: &[u8]) -> u64 {
    rolling_hash(&data[..data.len().min(QUICK_HASH_LEN)])
}

/// Incremental form of [`rolling_hash`].
///
/// ```
/// use par3_rs::hash::{RollingHasher, rolling_hash};
///
/// let mut hasher = RollingHasher::new();
/// hasher.update(b"12345");
/// hasher.update(b"6789");
/// assert_eq!(hasher.finalize(), rolling_hash(b"123456789"));
/// ```
#[derive(Clone)]
pub struct RollingHasher {
    inner: Digest,
}

impl RollingHasher {
    /// Start a new rolling hash.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Digest::new(CrcAlgorithm::Crc64GoIso),
        }
    }

    /// Feed more bytes into the hash.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Feed `count` zero bytes into the hash.
    ///
    /// An input block that is not completely filled is hashed as if the unused
    /// bytes were zeros.
    pub fn update_zeros(&mut self, count: u64) {
        const ZEROS: [u8; 4096] = [0u8; 4096];
        let mut remaining = count;
        while remaining > 0 {
            let take = remaining.min(ZEROS.len() as u64) as usize;
            self.inner.update(&ZEROS[..take]);
            remaining -= take as u64;
        }
    }

    /// Finish the hash.
    #[must_use]
    pub fn finalize(&self) -> u64 {
        self.inner.finalize()
    }
}

impl Default for RollingHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for RollingHasher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RollingHasher").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The check value published in the CRC catalogue for CRC-64/GO-ISO.
    #[test]
    fn rolling_hash_matches_the_catalogue_check_value() {
        assert_eq!(rolling_hash(b"123456789"), 0xB909_56C7_75A4_1001);
    }

    /// Reproduces the reference implementation's bytewise CRC-64 loop from its
    /// documented parameters, and compares it against the accelerated one.
    #[test]
    fn rolling_hash_matches_a_bytewise_reference_loop() {
        fn bytewise(data: &[u8]) -> u64 {
            let mut crc = u64::MAX;
            for &byte in data {
                let a = (crc ^ u64::from(byte)) << 56;
                crc = (crc >> 8) ^ a ^ (a >> 1) ^ (a >> 3) ^ (a >> 4);
            }
            !crc
        }

        let mut data = Vec::new();
        for i in 0..1024u32 {
            data.push((i.wrapping_mul(37).wrapping_add(11) & 0xff) as u8);
            assert_eq!(
                rolling_hash(&data),
                bytewise(&data),
                "length {}",
                data.len()
            );
        }
    }

    /// Vector taken from the oracle set's File packet for `b.txt`.
    #[test]
    fn rolling_hash_matches_the_oracle_vector() {
        assert_eq!(rolling_hash(b"qrstuvwxyz"), 0x7004_253A_AB19_C87C);
        assert_eq!(
            rolling_hash(b"qrstuvwxyz").to_le_bytes(),
            [0x7c, 0xc8, 0x19, 0xab, 0x3a, 0x25, 0x04, 0x70]
        );
    }

    #[test]
    fn rolling_hash_incremental_matches_one_shot() {
        let data: Vec<u8> = (0..5000u32)
            .map(|i| (i.wrapping_mul(7) & 0xff) as u8)
            .collect();
        for split in [0, 1, 39, 40, 4095, 4096, 4999, 5000] {
            let mut hasher = RollingHasher::new();
            hasher.update(&data[..split]);
            hasher.update(&data[split..]);
            assert_eq!(hasher.finalize(), rolling_hash(&data), "split {split}");
        }
    }

    #[test]
    fn rolling_hasher_zeros_match_an_explicit_zero_buffer() {
        let mut streamed = RollingHasher::new();
        streamed.update(b"abc");
        streamed.update_zeros(9000);
        let mut explicit = Vec::from(*b"abc");
        explicit.extend(std::iter::repeat_n(0u8, 9000));
        assert_eq!(streamed.finalize(), rolling_hash(&explicit));
    }

    #[test]
    fn fingerprint_incremental_matches_one_shot() {
        let data: Vec<u8> = (0..4000u32)
            .map(|i| (i.wrapping_mul(13) & 0xff) as u8)
            .collect();
        for split in [0, 1, 1023, 1024, 3999, 4000] {
            let mut hasher = FingerprintHasher::new();
            hasher.update(&data[..split]);
            hasher.update(&data[split..]);
            assert_eq!(hasher.finalize(), fingerprint(&data), "split {split}");
        }
    }

    #[test]
    fn fingerprint_hasher_zeros_match_an_explicit_zero_buffer() {
        let mut streamed = FingerprintHasher::new();
        streamed.update(b"abc");
        streamed.update_zeros(9000);
        let mut explicit = Vec::from(*b"abc");
        explicit.extend(std::iter::repeat_n(0u8, 9000));
        assert_eq!(streamed.finalize(), fingerprint(&explicit));
    }

    #[test]
    fn quick_rolling_hash_covers_at_most_16_kib() {
        let data: Vec<u8> = (0..40_000u32).map(|i| (i & 0xff) as u8).collect();
        assert_eq!(
            quick_rolling_hash(&data),
            rolling_hash(&data[..QUICK_HASH_LEN])
        );
        assert_eq!(quick_rolling_hash(&data[..10]), rolling_hash(&data[..10]));
    }
}
