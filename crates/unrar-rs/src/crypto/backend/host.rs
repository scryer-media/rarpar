//! Host-delegated crypto backend (wasm guest side).
//!
//! Selected on `wasm32` when the `crypto-host` feature is on. It mirrors the
//! other backends' 8-item seam, but the *bulk* AES-CBC decrypt crosses the wasm
//! boundary to the embedding host's AES, while the KDF primitives
//! (HMAC-SHA256 / SHA-256 / the test encrypt helpers) stay in-wasm and are
//! re-exported verbatim from the portable RustCrypto backend. Delegating only
//! the AES keeps the hot bulk path on the host's AES-NI, and leaves the
//! RAR5/RAR4 key-derivation loops running locally where their clone-per-sign
//! HMAC reuse is cheap.
//!
//! ## The seam
//!
//! The bulk decrypt reaches the host through the embedder-installed
//! `aes_cbc_decrypt` hook (see `crate::hooks`): `(key, iv, data) ->
//! plaintext`, AES-CBC, no padding, `key` 16 (AES-128) or 32 (AES-256) bytes,
//! `iv` 16 bytes, `data` a whole number of blocks (may be empty). The hook is
//! STATELESS per call and returns a fresh buffer, which this module copies back
//! over `data` so the IV-chaining logic below keeps its in-place shape.
//!
//! ## Guest-tracked CBC IV chaining (the load-bearing subtlety)
//!
//! Because the hook is stateless per call, this guest must thread the CBC IV
//! across chunks itself. The in-place decrypt overwrites the ciphertext with
//! plaintext, so before each call we SAVE the last 16 bytes of the *input*
//! (the ciphertext) — that block is the IV for the next chunk — then set it as
//! `self.iv` afterwards. This reproduces exactly what the stateful aws-lc/rust
//! CBC contexts do internally, but here it is explicit. The correctness of this
//! chaining is proven natively (no wasm host needed) by the differential test
//! at the bottom of this file, which swaps the per-chunk primitive for a
//! reference `cbc` decrypt and compares randomized chunk splits against a
//! one-shot reference.

// The KDF surface stays in-wasm: re-export it unchanged from the RustCrypto
// backend so `crate::crypto` sees an identical seam. Only the two AES CBC
// decryptors below differ (they call the host). `HmacSha256Key` is part of the
// seam for parity with the other backends even though the shared crypto code
// only names the `hmac_sha256*` functions, so allow it to ride along unused.
// The two `Aes*CbcEnc` encryptors ride along with them: re-encryption is not a
// decrypt path, so there is no host call to delegate it to and no reason to
// invent one — the portable encryptors are already in the guest.
#[allow(unused_imports)]
pub(crate) use super::rust::{
    Aes128CbcEnc, Aes256CbcEnc, HmacSha256Key, encrypt_aes128_cbc_for_test,
    encrypt_aes256_cbc_for_test, hmac_sha256, hmac_sha256_key, sha256,
};

use crate::crypto::AES_BLOCK;

// ---------------------------------------------------------------------------
// The embedder hook (the real seam) and its native test-reference stand-in.
//
// `decrypt_chunk` is the single seam point the `Aes*CbcDec` IV-chaining logic
// calls. With `crypto-host` it is the embedder-installed hook; in a native
// `#[cfg(test)]` build without the feature it is a reference CBC decrypt
// (RustCrypto `cbc`) so the chaining logic is exercised end-to-end without a
// host. Exactly one of the two definitions is compiled.
// ---------------------------------------------------------------------------

/// Decrypt one block-aligned chunk through the embedder-installed hook (see
/// `crate::hooks`).
///
/// The hook returns a fresh buffer rather than decrypting in place — that is
/// the shape every transport can satisfy, including ones that cannot hand the
/// host a guest pointer. Copying the result back over `data` restores the
/// in-place contract the shared IV-chaining logic below is written against.
/// Panics on a hook error or a wrong-length result: that is an embedder
/// contract violation, not a recoverable condition.
///
/// `fn` pointers link on any target, which is what lets the chaining
/// differential at the bottom of this file exercise the real hook path
/// natively.
#[cfg(feature = "crypto-host")]
#[inline]
fn decrypt_chunk(key: &[u8], iv: &[u8; AES_BLOCK], data: &mut [u8]) {
    debug_assert!(key.len() == 16 || key.len() == 32);
    debug_assert!(data.len().is_multiple_of(AES_BLOCK));

    let hooks = crate::hooks::hooks();
    let plaintext = match (hooks.aes_cbc_decrypt)(key, iv.as_slice(), data) {
        Ok(plaintext) => plaintext,
        Err(error) => panic!("host aes-cbc-decrypt failed (contract violation): {error}"),
    };
    assert_eq!(
        plaintext.len(),
        data.len(),
        "host aes-cbc-decrypt returned {} bytes for a {}-byte input (contract violation)",
        plaintext.len(),
        data.len(),
    );
    data.copy_from_slice(&plaintext);
}

/// Native `#[cfg(test)]` reference stand-in for the hook: a one-shot RustCrypto
/// `cbc` decrypt of `data` in place with a FRESH context seeded by `iv`
/// (stateless per call, exactly like the hook). This lets the differential
/// test drive the real `Aes*CbcDec` IV-chaining logic on a native target.
///
/// Compiled only without `crypto-host` — with the feature the differential
/// drives the hook itself, which is strictly better coverage than a stand-in.
#[cfg(all(test, not(feature = "crypto-host")))]
#[inline]
fn decrypt_chunk(key: &[u8], iv: &[u8; AES_BLOCK], data: &mut [u8]) {
    use aes::cipher::block::BlockModeDecrypt;
    use aes::cipher::{Array, KeyIvInit};

    debug_assert!(data.len().is_multiple_of(AES_BLOCK));
    let (blocks, rest) = Array::<u8, _>::slice_as_chunks_mut(data);
    debug_assert!(rest.is_empty());
    match key.len() {
        32 => {
            let key: &[u8; 32] = key.try_into().expect("key is 32 bytes");
            let mut dec = cbc::Decryptor::<aes::Aes256>::new(key.into(), iv.into());
            dec.decrypt_blocks(blocks);
        }
        16 => {
            let key: &[u8; 16] = key.try_into().expect("key is 16 bytes");
            let mut dec = cbc::Decryptor::<aes::Aes128>::new(key.into(), iv.into());
            dec.decrypt_blocks(blocks);
        }
        other => unreachable!("unsupported AES key length {other}"),
    }
}

/// Shared IV-chaining decrypt: split `data` into per-chunk `decrypt_chunk`
/// calls, threading the CBC IV across them. The host (and the test reference)
/// is stateless per call, so before decrypting each chunk we save its LAST 16
/// input bytes (the ciphertext) as the next chunk's IV, then advance `iv` after
/// the in-place decrypt has consumed the current one. A single call already
/// carries the whole slice, so the loop is trivially one iteration in practice;
/// it is written generally so the invariant is obvious and testable.
#[inline]
fn decrypt_cbc_chained(key: &[u8], iv: &mut [u8; AES_BLOCK], data: &mut [u8]) {
    debug_assert!(data.len().is_multiple_of(AES_BLOCK));
    if data.is_empty() {
        return;
    }
    // Save the last input block BEFORE the in-place decrypt destroys it: that
    // ciphertext block is the IV for whatever comes next.
    let next_iv: [u8; AES_BLOCK] = data[data.len() - AES_BLOCK..]
        .try_into()
        .expect("slice is exactly one block");
    decrypt_chunk(key, iv, data);
    *iv = next_iv;
}

/// AES-256-CBC block decryptor that delegates to the host. Holds the key (raw,
/// zeroized on drop) and the running CBC IV, threaded across `decrypt_blocks`
/// calls exactly like the stateful native backends carry it internally.
pub(crate) struct Aes256CbcDec {
    key: [u8; 32],
    iv: [u8; AES_BLOCK],
}

impl Aes256CbcDec {
    #[inline]
    pub(crate) fn new(key: &[u8; 32], iv: &[u8; AES_BLOCK]) -> Self {
        Self { key: *key, iv: *iv }
    }

    #[inline]
    pub(crate) fn decrypt_blocks(&mut self, data: &mut [u8]) {
        decrypt_cbc_chained(&self.key, &mut self.iv, data);
    }
}

impl Drop for Aes256CbcDec {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key.zeroize();
    }
}

/// AES-128-CBC block decryptor (RAR4) that delegates to the host. Same
/// guest-tracked IV chaining as [`Aes256CbcDec`].
pub(crate) struct Aes128CbcDec {
    key: [u8; 16],
    iv: [u8; AES_BLOCK],
}

impl Aes128CbcDec {
    #[inline]
    pub(crate) fn new(key: &[u8; 16], iv: &[u8; AES_BLOCK]) -> Self {
        Self { key: *key, iv: *iv }
    }

    #[inline]
    pub(crate) fn decrypt_blocks(&mut self, data: &mut [u8]) {
        decrypt_cbc_chained(&self.key, &mut self.iv, data);
    }
}

impl Drop for Aes128CbcDec {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key.zeroize();
    }
}

// ===========================================================================
// NATIVE differential test: proves the guest CBC IV chaining is correct across
// arbitrary block-aligned chunk splits WITHOUT a wasm host, by backing the
// per-chunk primitive with a reference `cbc` decrypt (see `decrypt_chunk`
// above, `#[cfg(test)]` variant) and comparing the host-backend `Aes*CbcDec`
// output — fed in randomized splits — against a one-shot reference decrypt.
//
// This is the executable proof of the save-last-block + IV-thread logic; the
// wasm smoke test (examples/host_aes_smoke.rs + tests/wasm_host_aes_smoke.rs)
// separately proves the whole chain — hook, guest import, host function —
// links end to end in a real wasm guest.
// ===========================================================================
#[cfg(all(test, not(all(target_arch = "wasm32", feature = "crypto-host"))))]
mod chaining_tests {
    use super::*;

    /// Make `decrypt_chunk` callable in this build.
    ///
    /// With `crypto-host` the per-chunk primitive is the embedder hook, so the
    /// differential below is only meaningful once a hook is installed — and
    /// installing the reference pair turns these tests into the hook path's
    /// end-to-end proof. Without the feature `decrypt_chunk` is the local
    /// reference stand-in and this is a no-op.
    fn prepare_chunk_primitive() {
        #[cfg(feature = "crypto-host")]
        crate::hooks::install_reference_hooks_for_test();
    }

    /// Deterministic xorshift64* PRNG — reproducible, adds no dependency.
    struct XorShift64 {
        state: u64,
    }

    impl XorShift64 {
        fn new(seed: u64) -> Self {
            Self {
                state: seed | 0x9E37_79B9_7F4A_7C15,
            }
        }

        fn next_u64(&mut self) -> u64 {
            let mut x = self.state;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.state = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        fn fill(&mut self, buf: &mut [u8]) {
            let mut chunks = buf.chunks_exact_mut(8);
            for chunk in &mut chunks {
                chunk.copy_from_slice(&self.next_u64().to_le_bytes());
            }
            let rem = chunks.into_remainder();
            if !rem.is_empty() {
                let bytes = self.next_u64().to_le_bytes();
                rem.copy_from_slice(&bytes[..rem.len()]);
            }
        }

        fn next_usize(&mut self, bound: usize) -> usize {
            (self.next_u64() % bound as u64) as usize
        }
    }

    /// One-shot reference AES-256-CBC decrypt in place (RustCrypto `cbc`), fresh
    /// context — the ground truth the chunked host-backend decrypt must equal.
    fn reference_decrypt_256(key: &[u8; 32], iv: &[u8; AES_BLOCK], data: &mut [u8]) {
        use aes::cipher::block::BlockModeDecrypt;
        use aes::cipher::{Array, KeyIvInit};
        let mut dec = cbc::Decryptor::<aes::Aes256>::new(key.into(), iv.into());
        let (blocks, rest) = Array::<u8, _>::slice_as_chunks_mut(data);
        debug_assert!(rest.is_empty());
        dec.decrypt_blocks(blocks);
    }

    /// One-shot reference AES-128-CBC decrypt in place (RustCrypto `cbc`).
    fn reference_decrypt_128(key: &[u8; 16], iv: &[u8; AES_BLOCK], data: &mut [u8]) {
        use aes::cipher::block::BlockModeDecrypt;
        use aes::cipher::{Array, KeyIvInit};
        let mut dec = cbc::Decryptor::<aes::Aes128>::new(key.into(), iv.into());
        let (blocks, rest) = Array::<u8, _>::slice_as_chunks_mut(data);
        debug_assert!(rest.is_empty());
        dec.decrypt_blocks(blocks);
    }

    /// A randomized sequence of block-multiple chunk sizes summing to `total`.
    /// Includes single-block (16), odd multi-block, and (via the caller) the
    /// whole-buffer case, to stress the IV carry across `decrypt_blocks` calls.
    fn block_multiple_splits(total: usize, rng: &mut XorShift64) -> Vec<usize> {
        debug_assert!(total.is_multiple_of(AES_BLOCK));
        let mut remaining_blocks = total / AES_BLOCK;
        let mut sizes = Vec::new();
        while remaining_blocks > 0 {
            let take = 1 + rng.next_usize(7.min(remaining_blocks));
            sizes.push(take * AES_BLOCK);
            remaining_blocks -= take;
        }
        sizes
    }

    /// Feed `ciphertext` through the host-backend `Aes256CbcDec` in the given
    /// `splits`, returning the recovered plaintext.
    fn chunked_256(
        key: &[u8; 32],
        iv: &[u8; AES_BLOCK],
        ciphertext: &[u8],
        splits: &[usize],
    ) -> Vec<u8> {
        let mut dec = Aes256CbcDec::new(key, iv);
        let mut buf = ciphertext.to_vec();
        let mut offset = 0;
        for &size in splits {
            dec.decrypt_blocks(&mut buf[offset..offset + size]);
            offset += size;
        }
        assert_eq!(offset, buf.len());
        buf
    }

    /// Feed `ciphertext` through the host-backend `Aes128CbcDec` in the given
    /// `splits`, returning the recovered plaintext.
    fn chunked_128(
        key: &[u8; 16],
        iv: &[u8; AES_BLOCK],
        ciphertext: &[u8],
        splits: &[usize],
    ) -> Vec<u8> {
        let mut dec = Aes128CbcDec::new(key, iv);
        let mut buf = ciphertext.to_vec();
        let mut offset = 0;
        for &size in splits {
            dec.decrypt_blocks(&mut buf[offset..offset + size]);
            offset += size;
        }
        assert_eq!(offset, buf.len());
        buf
    }

    /// AES-256: for >= 50 random (key, iv, multi-block plaintext) cases, feed
    /// the ciphertext through the host-backend decryptor in randomized splits
    /// (16-byte, odd multi-block, AND whole-buffer) and assert every split
    /// recovers the exact plaintext — i.e. equals a one-shot reference decrypt.
    /// A mismatch reports the exact diverging split so a broken chaining hook is
    /// never silently landed.
    #[test]
    fn aes256_cbc_chaining_matches_reference() {
        prepare_chunk_primitive();
        let mut rng = XorShift64::new(0x2565_AE50_1234_9001);
        let mut cases = 0usize;

        for case in 0..64u32 {
            // Block-aligned length in [16, 64 KiB], with several small sizes to
            // guarantee many chunk boundaries.
            let max_blocks = (64 * 1024) / AES_BLOCK;
            let blocks = 1 + rng.next_usize(max_blocks);
            let len = blocks * AES_BLOCK;

            let mut plaintext = vec![0u8; len];
            rng.fill(&mut plaintext);
            let mut key = [0u8; 32];
            rng.fill(&mut key);
            let mut iv = [0u8; AES_BLOCK];
            rng.fill(&mut iv);

            // Build ciphertext via the in-wasm (RustCrypto) encrypt helper —
            // the same one shipped in this backend.
            let ciphertext = encrypt_aes256_cbc_for_test(&key, &iv, &plaintext);

            // Reference: one-shot decrypt.
            let mut reference = ciphertext.clone();
            reference_decrypt_256(&key, &iv, &mut reference);
            assert_eq!(reference, plaintext, "reference self-check, case {case}");

            // Candidate splits: all-16 (max boundaries), a randomized split,
            // and whole-buffer (single call, no chaining).
            let all_16: Vec<usize> = vec![AES_BLOCK; blocks];
            let random_split = block_multiple_splits(len, &mut rng);
            let whole = vec![len];

            for (label, splits) in [
                ("all-16", &all_16),
                ("random", &random_split),
                ("whole", &whole),
            ] {
                let out = chunked_256(&key, &iv, &ciphertext, splits);
                assert_eq!(
                    out, plaintext,
                    "aes256 host-backend chaining diverged: case {case}, split={label}, \
                     sizes={splits:?}"
                );
            }

            cases += 1;
        }

        assert!(cases >= 50, "expected >= 50 AES-256 cases, ran {cases}");
    }

    /// AES-128 (RAR4): same randomized-split chaining differential as AES-256.
    #[test]
    fn aes128_cbc_chaining_matches_reference() {
        prepare_chunk_primitive();
        let mut rng = XorShift64::new(0x2565_AE50_1234_9128);
        let mut cases = 0usize;

        for case in 0..64u32 {
            let max_blocks = (64 * 1024) / AES_BLOCK;
            let blocks = 1 + rng.next_usize(max_blocks);
            let len = blocks * AES_BLOCK;

            let mut plaintext = vec![0u8; len];
            rng.fill(&mut plaintext);
            let mut key = [0u8; 16];
            rng.fill(&mut key);
            let mut iv = [0u8; AES_BLOCK];
            rng.fill(&mut iv);

            let ciphertext = encrypt_aes128_cbc_for_test(&key, &iv, &plaintext);

            let mut reference = ciphertext.clone();
            reference_decrypt_128(&key, &iv, &mut reference);
            assert_eq!(reference, plaintext, "reference self-check, case {case}");

            let all_16: Vec<usize> = vec![AES_BLOCK; blocks];
            let random_split = block_multiple_splits(len, &mut rng);
            let whole = vec![len];

            for (label, splits) in [
                ("all-16", &all_16),
                ("random", &random_split),
                ("whole", &whole),
            ] {
                let out = chunked_128(&key, &iv, &ciphertext, splits);
                assert_eq!(
                    out, plaintext,
                    "aes128 host-backend chaining diverged: case {case}, split={label}, \
                     sizes={splits:?}"
                );
            }

            cases += 1;
        }

        assert!(cases >= 50, "expected >= 50 AES-128 cases, ran {cases}");
    }
}
