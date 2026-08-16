//! The HMAC-SHA256 primitive the RAR5 key derivation runs on — and *only* that
//! derivation.
//!
//! # Why the KDF has its own HMAC
//!
//! RAR5's PBKDF2 signs a 32-byte message up to 2^24 times under one key, so the
//! derivation's cost is the per-tag overhead, not the bytes hashed. Two shapes
//! matter:
//!
//! * **Cached ipad/opad.** UnRAR's own form (`crypt5.cpp:22-46,51-76`:
//!   `ICtxOpt`/`RCtxOpt`) absorbs the `key ⊕ 0x36…` and `key ⊕ 0x5c…` blocks
//!   into two SHA-256 states **once**; every tag then resumes from a copy of
//!   those. Per tag that is exactly two SHA-256 compressions — one inner, one
//!   outer — with no allocation and no key re-derivation. That is what
//!   [`KdfHmacKey`] holds.
//! * **No FFI on the per-iteration path.** The compression itself goes through
//!   the `sha2` crate's [`compress256`] on *every* backend, not through the
//!   selected [`crate::crypto::backend`]. `sha2` picks a hardware SHA-256
//!   backend at runtime (ARMv8 `sha256h`/`sha256h2`/`sha256su0`/`sha256su1` on
//!   `aarch64`, SHA-NI on x86), so the compressions are the same instructions
//!   aws-lc would issue — but each iteration is a plain call instead of two
//!   `SHA256_Update` + two `SHA256_Final` crossings into C, and the resumable
//!   state is a bare `[u32; 8]` instead of a 112-byte `SHA256_CTX`. On aarch64
//!   the aws-lc-backed form measured ~62 ns/iter against ~47 ns/iter for the
//!   RustCrypto one; routing only the KDF here removes that gap on every
//!   backend at once.
//!
//! Nothing else moves: AES, SHA-1, and the non-KDF SHA-256 / HMAC uses stay on
//! whichever backend the target selected. This module is the *sole* HMAC used
//! inside the derivation loop, and its output is plain HMAC-SHA256 (RFC 2104) —
//! proven against the active backend's HMAC over a wide corpus in the tests
//! below.

use sha2::block_api::compress256;
use zeroize::Zeroize;

/// SHA-256 block size in bytes — the HMAC key-padding width (RFC 4868).
const BLOCK: usize = 64;
/// SHA-256 digest size in bytes.
const OUT: usize = 32;

/// SHA-256 initial state (FIPS 180-4 §5.3.3).
const SHA256_IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// A key with its ipad/opad SHA-256 states already absorbed.
///
/// Build it once per derivation ([`KdfHmacKey::new`]) and sign every PBKDF2
/// iteration from it ([`KdfHmacKey::sign`]); signing never mutates it.
pub(crate) struct KdfHmacKey {
    /// State after absorbing `key ⊕ 0x36…` (UnRAR's `ICtxOpt`).
    inner: [u32; 8],
    /// State after absorbing `key ⊕ 0x5c…` (UnRAR's `RCtxOpt`).
    outer: [u32; 8],
}

impl Drop for KdfHmacKey {
    fn drop(&mut self) {
        // Both states are password-derived; wipe them on the way out.
        self.inner.zeroize();
        self.outer.zeroize();
    }
}

/// Absorb one `key ⊕ pad_byte` block from the SHA-256 IV and return the state.
///
/// `key` must be at most [`BLOCK`] bytes; bytes past its end keep the bare pad
/// byte, which is HMAC's zero-padding rule.
fn primed_state(pad_byte: u8, key: &[u8]) -> [u32; 8] {
    debug_assert!(key.len() <= BLOCK);
    let mut pad = [pad_byte; BLOCK];
    for (slot, byte) in pad.iter_mut().zip(key) {
        *slot ^= *byte;
    }
    let mut state = SHA256_IV;
    compress256(&mut state, core::slice::from_ref(&pad));
    pad.zeroize();
    state
}

/// Absorb `data` into `state` and apply SHA-256's length padding, where
/// `prefix` bytes have already been absorbed into `state` (the ipad/opad block,
/// or 0 for a bare SHA-256). Returns the digest as big-endian bytes.
///
/// # Hygiene
///
/// This runs up to 2^24 times per derivation and deliberately does **not**
/// `zeroize` its scratch. Per-tag wiping cost more than the hashing did: a
/// volatile 128-byte scrub plus compiler fences on every call measured the whole
/// KDF *slower* than the aws-lc HMAC it replaced. The material worth wiping is
/// the key, and that is wiped once, in [`KdfHmacKey`]'s `Drop`; the caller
/// (`derive_rar5_material`) likewise wipes its own chain values once. This
/// matches the primitive it replaced, whose per-tag `SHA256_CTX` copies and
/// inner digest were also plain stack values.
#[inline]
fn absorb_and_finish(mut state: [u32; 8], prefix: usize, data: &[u8]) -> [u8; OUT] {
    let total_bits = (prefix as u64 + data.len() as u64) * 8;

    let mut blocks = data.chunks_exact(BLOCK);
    for block in &mut blocks {
        let block: &[u8; BLOCK] = block.try_into().expect("chunks_exact yields BLOCK bytes");
        compress256(&mut state, core::slice::from_ref(block));
    }
    let rest = blocks.remainder();

    // Padding: 0x80, zeros, then the 64-bit big-endian bit length. `block`
    // starts zeroed and only `rest` and the 0x80 are ever written into it, so
    // the zero fill is already correct. The length field fits in this same
    // block when at least 9 bytes are free; otherwise it takes one more. RAR5
    // only ever signs 20- or 32-byte messages, so the single-block arm is the
    // hot one, and only that arm touches one 64-byte buffer.
    let mut block = [0u8; BLOCK];
    block[..rest.len()].copy_from_slice(rest);
    block[rest.len()] = 0x80;
    if rest.len() + 1 + 8 <= BLOCK {
        block[BLOCK - 8..].copy_from_slice(&total_bits.to_be_bytes());
        compress256(&mut state, core::slice::from_ref(&block));
    } else {
        compress256(&mut state, core::slice::from_ref(&block));
        let mut last = [0u8; BLOCK];
        last[BLOCK - 8..].copy_from_slice(&total_bits.to_be_bytes());
        compress256(&mut state, core::slice::from_ref(&last));
    }

    let mut out = [0u8; OUT];
    for (word, chunk) in state.iter().zip(out.chunks_exact_mut(4)) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    out
}

impl KdfHmacKey {
    /// Build the key: precompute and retain the ipad/opad states. Called once
    /// per derivation, never inside its loop.
    pub(crate) fn new(secret: &[u8]) -> Self {
        // RFC 2104 / UnRAR `crypt5.cpp:9-18`: over-long keys are replaced by
        // their own digest; shorter ones are zero-padded, which
        // `primed_state` does by XORing only over `secret.len()` bytes.
        if secret.len() > BLOCK {
            let mut hashed = sha256(secret);
            let key = Self {
                inner: primed_state(0x36, &hashed),
                outer: primed_state(0x5C, &hashed),
            };
            hashed.zeroize();
            key
        } else {
            Self {
                inner: primed_state(0x36, secret),
                outer: primed_state(0x5C, secret),
            }
        }
    }

    /// HMAC-SHA256 over `data`. Two SHA-256 compressions for the message sizes
    /// RAR5 signs, and no mutation of `self` — the whole point of the cached
    /// states is that the next iteration resumes from them again.
    #[inline]
    pub(crate) fn sign(&self, data: &[u8]) -> [u8; OUT] {
        let inner_digest = absorb_and_finish(self.inner, BLOCK, data);
        absorb_and_finish(self.outer, BLOCK, &inner_digest)
    }
}

/// SHA-256 over `data`, on the same `sha2` compression the KDF uses.
///
/// Only reachable from [`KdfHmacKey::new`]'s over-long-key branch (RAR5
/// passwords are capped well under a block, so archives do not take it) — but
/// HMAC is only HMAC if that branch is right, and the tests exercise it.
fn sha256(data: &[u8]) -> [u8; OUT] {
    absorb_and_finish(SHA256_IV, 0, data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::backend;

    /// Deterministic xorshift64* PRNG — reproducible, adds no dependency.
    struct XorShift64(u64);

    impl XorShift64 {
        fn fill(&mut self, buf: &mut [u8]) {
            for chunk in buf.chunks_mut(8) {
                let mut x = self.0;
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                self.0 = x;
                let bytes = x.wrapping_mul(0x2545_F491_4F6C_DD1D).to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
        }
    }

    /// The KDF HMAC must equal the ACTIVE backend's HMAC-SHA256 bit for bit —
    /// otherwise every RAR5 key derived before this existed would stop
    /// decrypting. Covers every key-length regime HMAC treats differently
    /// (short/zero-padded, exactly one block, over-long and therefore hashed
    /// down) crossed with message lengths straddling the SHA-256 block and
    /// padding boundaries, including the 20-byte salt block and 32-byte `U`
    /// RAR5 actually signs, and lengths that force the two-block padding tail.
    #[test]
    fn kdf_hmac_matches_the_active_backend_hmac() {
        let mut rng = XorShift64(0x5EED_0BAD_C0FF_EE11);
        let mut cases = 0usize;

        let key_lens = [
            0usize, 1, 8, 20, 32, 55, 56, 63, 64, 65, 96, 127, 128, 129, 200, 381,
        ];
        let data_lens = [
            0usize, 1, 16, 20, 31, 32, 33, 55, 56, 57, 63, 64, 65, 119, 120, 128, 129, 1000,
        ];

        for key_len in key_lens {
            let mut secret = vec![0u8; key_len];
            rng.fill(&mut secret);
            let kdf_key = KdfHmacKey::new(&secret);
            let backend_key = backend::hmac_sha256_key(&secret);

            for data_len in data_lens {
                let mut data = vec![0u8; data_len];
                rng.fill(&mut data);
                assert_eq!(
                    kdf_key.sign(&data),
                    backend::hmac_sha256(&backend_key, &data),
                    "kdf hmac diverged from the backend: key_len {key_len}, data_len {data_len}"
                );
                cases += 1;
            }

            // The key is reused across every PBKDF2 iteration, so prove a chain
            // of tags from the SAME key still tracks the backend — i.e. the
            // cached states are neither consumed nor mutated by signing.
            let mut u = [0u8; 32];
            rng.fill(&mut u);
            for round in 0..4 {
                let expected = backend::hmac_sha256(&backend_key, &u);
                u = kdf_key.sign(&u);
                assert_eq!(u, expected, "reused-key chain diverged at round {round}");
            }
        }

        assert!(cases >= 200, "expected >= 200 cases, ran {cases}");
    }

    /// The private SHA-256 that only the over-long-key branch reaches must be a
    /// real SHA-256, checked against the active backend's.
    #[test]
    fn kdf_sha256_matches_the_active_backend_sha256() {
        let mut rng = XorShift64(0x1234_5678_9ABC_DEF1);
        for len in [
            0usize, 1, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 129, 4096,
        ] {
            let mut data = vec![0u8; len];
            rng.fill(&mut data);
            assert_eq!(
                sha256(&data),
                backend::sha256(&data),
                "sha256 mismatch at len {len}"
            );
        }
    }
}
