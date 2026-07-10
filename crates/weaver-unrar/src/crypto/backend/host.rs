//! Host-delegated crypto backend (wasm guest side).
//!
//! Selected on `wasm32` when the `crypto-host` feature is on. It mirrors the
//! other backends' 7-item seam, but the *bulk* AES-CBC decrypt crosses the wasm
//! boundary to a host function (the embedding host's AES), while the KDF primitives
//! (HMAC-SHA256 / SHA-256 / the test encrypt helpers) stay in-wasm and are
//! re-exported verbatim from the portable RustCrypto backend. Delegating only
//! the AES keeps the hot bulk path on the host's AES-NI without a copy, and
//! leaves the RAR5/RAR4 key-derivation loops running locally where their
//! clone-per-sign HMAC reuse is cheap.
//!
//! ## The host ABI (fixed contract, shared with the host side)
//!
//! Import module (namespace): `host` — embedder-neutral, satisfiable by any
//! wasm runtime that can register imports (wasmtime, wasmer, …). The
//! `host-abi-extism` feature switches only the namespace to
//! `extism:host/user`, for Extism SDKs whose user host functions are pinned
//! to that module; the function name and signature are identical in both.
//! One import is declared:
//!
//! ```text
//! host_aes_cbc_decrypt(key_ptr, key_len, iv_ptr, buf_ptr, buf_len) -> i64
//! ```
//!
//! All args/returns are raw `i64`; every `*_ptr` is a byte offset into the
//! plugin's own linear memory, which the host slices in place (zero-copy — no
//! SDK `Vec<u8>` marshalling). AES-CBC, no padding, decrypt IN PLACE.
//! `key_len` is 16 (AES-128) or 32 (AES-256); `iv` is 16 bytes at `iv_ptr`;
//! `buf_len` must be a multiple of 16 and may be 0. The host is STATELESS per
//! call. Returns `0` ok, `-1` bad `key_len`, `-2` `buf_len % 16 != 0`, `-3`
//! out-of-bounds.
//!
//! ## Guest-tracked CBC IV chaining (the load-bearing subtlety)
//!
//! Because the host is stateless per call, this guest must thread the CBC IV
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
#[allow(unused_imports)]
pub(crate) use super::rust::{
    HmacSha256Key, encrypt_aes128_cbc_for_test, encrypt_aes256_cbc_for_test, hmac_sha256,
    hmac_sha256_key, sha256,
};

use crate::crypto::AES_BLOCK;

// ---------------------------------------------------------------------------
// The host import (real, wasm-only) and its native test-reference stand-in.
//
// `decrypt_chunk` is the single seam point the `Aes*CbcDec` IV-chaining logic
// calls. On `wasm32 + crypto-host` it is the raw host import; in a native
// `#[cfg(test)]` build it is a reference CBC decrypt (RustCrypto `cbc`) so the
// chaining logic is exercised end-to-end without a wasm host. Exactly one of
// the two definitions is compiled.
// ---------------------------------------------------------------------------

// Raw host import: a bare `#[link]` extern (no embedder SDK dependency), so
// any wasm runtime satisfies it by exposing a function of this name in the
// import namespace. The namespace is `host` unless `host-abi-extism` retargets
// it for Extism SDKs. (A `//` comment, not `///`: doc comments are not allowed
// on the items inside a `#[link]` extern block.)
#[cfg(all(target_arch = "wasm32", feature = "crypto-host"))]
#[cfg_attr(
    feature = "host-abi-extism",
    link(wasm_import_module = "extism:host/user")
)]
#[cfg_attr(not(feature = "host-abi-extism"), link(wasm_import_module = "host"))]
unsafe extern "C" {
    fn host_aes_cbc_decrypt(
        key_ptr: u64,
        key_len: u64,
        iv_ptr: u64,
        buf_ptr: u64,
        buf_len: u64,
    ) -> i64;
}

/// Decrypt one block-aligned `data` chunk in place with (`key`, `iv`) via the
/// host, using the raw offset ABI (zero-copy: the host reads/writes the
/// plugin's linear memory at these offsets). Panics on any negative return —
/// that is a host contract violation, not a recoverable condition.
#[cfg(all(target_arch = "wasm32", feature = "crypto-host"))]
#[inline]
fn decrypt_chunk(key: &[u8], iv: &[u8; AES_BLOCK], data: &mut [u8]) {
    debug_assert!(key.len() == 16 || key.len() == 32);
    debug_assert!(data.len().is_multiple_of(AES_BLOCK));
    // SAFETY: all pointers are valid offsets into this module's own linear
    // memory for the stated lengths; the host slices them in place and never
    // retains them past the call. `key`/`iv` are read-only to the host;
    // `data` is written in place.
    let rc = unsafe {
        host_aes_cbc_decrypt(
            key.as_ptr() as u64,
            key.len() as u64,
            iv.as_ptr() as u64,
            data.as_mut_ptr() as u64,
            data.len() as u64,
        )
    };
    assert_eq!(
        rc, 0,
        "host_aes_cbc_decrypt failed (contract violation): rc={rc}"
    );
}

/// Native `#[cfg(test)]` reference stand-in for the host import: a one-shot
/// RustCrypto `cbc` decrypt of `data` in place with a FRESH context seeded by
/// `iv` (stateless per call, exactly like the host). This lets the differential
/// test drive the real `Aes*CbcDec` IV-chaining logic on a native target.
#[cfg(all(test, not(all(target_arch = "wasm32", feature = "crypto-host"))))]
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
// separately proves the raw import links end-to-end over the real ABI.
// ===========================================================================
#[cfg(all(test, not(all(target_arch = "wasm32", feature = "crypto-host"))))]
mod chaining_tests {
    use super::*;

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
