//! Differential tests: AWS-LC backend vs pure-Rust backend.
//!
//! Compiled only when BOTH backends are built (native, both features on), so
//! we can call `backend::aws_lc` and `backend::rust` side by side and assert
//! they agree bit-for-bit on the primitives the RAR crypto paths are built
//! from. This is the cross-check that lets the pure-Rust backend inherit the
//! trust already established for the AWS-LC one.
//!
//! Uses a self-contained deterministic xorshift PRNG so the corpus is
//! reproducible and adds no dependencies.

use crate::crypto::AES_BLOCK;
use crate::crypto::backend::{aws_lc, rust};

/// Deterministic xorshift64* PRNG — reproducible, no external deps.
struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        // Avoid the all-zero state, which xorshift cannot escape.
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

/// (a) HMAC-SHA256 and SHA-256 must agree across random keys and random-length
/// messages (0..4096), covering well over 200 cases.
#[test]
fn hmac_and_sha256_match_across_backends() {
    let mut rng = XorShift64::new(0xA5A5_1234_DEAD_BEEF);
    let mut cases = 0usize;

    for len in 0..=4096usize {
        // Sample a subset of lengths but guarantee >= 200 cases, always
        // including the block-boundary sizes that matter most for SHA-256.
        let boundary = matches!(len, 0 | 1 | 55 | 56 | 63 | 64 | 65 | 127 | 128 | 129);
        if !boundary && rng.next_usize(16) != 0 {
            continue;
        }

        let mut data = vec![0u8; len];
        rng.fill(&mut data);

        // SHA-256 equality.
        assert_eq!(
            aws_lc::sha256(&data),
            rust::sha256(&data),
            "sha256 mismatch at len {len}"
        );

        // HMAC-SHA256 equality with a random-length key (incl. > block size,
        // which HMAC hashes down, and short keys, which it zero-pads).
        let key_len = rng.next_usize(200);
        let mut key = vec![0u8; key_len];
        rng.fill(&mut key);
        let aws_key = aws_lc::hmac_sha256_key(&key);
        let rust_key = rust::hmac_sha256_key(&key);
        assert_eq!(
            aws_lc::hmac_sha256(&aws_key, &data),
            rust::hmac_sha256(&rust_key, &data),
            "hmac_sha256 mismatch at len {len}, key_len {key_len}"
        );

        cases += 1;
    }

    assert!(cases >= 200, "expected >= 200 cases, ran {cases}");
}

/// (b) `derive_rar5_material` runs on the ACTIVE backend, so we cannot invoke
/// both variants of it. Instead we cross-check the two primitives it is built
/// from — a keyed-HMAC PBKDF2 chain over SHA-256 — reproducing the exact call
/// shape of its inner loop (repeated `hmac_sha256(&key, &u)` with XOR folding)
/// and asserting both backends produce the same derived block. The known
/// reference vector for the full KDF is separately asserted in the unit tests
/// (`test_rar5_aws_lc_material_matches_reference_vector`).
#[test]
fn rar5_kdf_primitive_chain_matches_across_backends() {
    let mut rng = XorShift64::new(0x0F0F_7777_C0DE_2024);

    for case in 0..64u32 {
        let mut secret = [0u8; 24];
        rng.fill(&mut secret);
        let mut salt_block = [0u8; 20];
        rng.fill(&mut salt_block);

        let aws_key = aws_lc::hmac_sha256_key(&secret);
        let rust_key = rust::hmac_sha256_key(&secret);

        // Seed the chain exactly like derive_rar5_material does.
        let mut aws_u = aws_lc::hmac_sha256(&aws_key, &salt_block);
        let mut rust_u = rust::hmac_sha256(&rust_key, &salt_block);
        assert_eq!(aws_u, rust_u, "seed mismatch, case {case}");

        let mut aws_fn = aws_u;
        let mut rust_fn = rust_u;

        // A short PBKDF2-style fold; the clone-per-sign key reuse in each
        // backend's `hmac_sha256` is what this exercises.
        let rounds = 8 + rng.next_usize(40);
        for _ in 0..rounds {
            aws_u = aws_lc::hmac_sha256(&aws_key, &aws_u);
            rust_u = rust::hmac_sha256(&rust_key, &rust_u);
            for (acc, next) in aws_fn.iter_mut().zip(aws_u.iter()) {
                *acc ^= *next;
            }
            for (acc, next) in rust_fn.iter_mut().zip(rust_u.iter()) {
                *acc ^= *next;
            }
        }

        assert_eq!(aws_u, rust_u, "chain U mismatch, case {case}");
        assert_eq!(aws_fn, rust_fn, "chain fold mismatch, case {case}");
    }
}

/// (c) AES-CBC: for random keys/IVs and block-aligned plaintext of random size
/// (16 bytes .. 1 MiB), encrypt with one backend's helper, then decrypt with
/// BOTH backends' streaming decryptors using randomized chunk splits (each a
/// multiple of the block size, including single-block and odd multi-block
/// chunks). Every result must equal the original plaintext. Runs >= 50 cases
/// per cipher width.
#[test]
fn aes_cbc_decrypt_matches_across_backends() {
    let mut rng = XorShift64::new(0xCBC0_1122_3344_5566);

    for case in 0..64u32 {
        // Block-aligned length in [16, 1 MiB].
        let max_blocks = (1024 * 1024) / AES_BLOCK;
        let blocks = 1 + rng.next_usize(max_blocks);
        let len = blocks * AES_BLOCK;

        let mut plaintext = vec![0u8; len];
        rng.fill(&mut plaintext);
        let mut iv = [0u8; 16];
        rng.fill(&mut iv);

        // ---- AES-256 ----
        {
            let mut key = [0u8; 32];
            rng.fill(&mut key);
            // Encrypt with aws-lc on even cases, rust on odd — so the encrypt
            // helpers of both backends are exercised as the source of truth.
            let ciphertext = if case % 2 == 0 {
                aws_lc::encrypt_aes256_cbc_for_test(&key, &iv, &plaintext)
            } else {
                rust::encrypt_aes256_cbc_for_test(&key, &iv, &plaintext)
            };

            let aws_out = decrypt_chunked_aws256(&key, &iv, &ciphertext, &mut rng);
            let rust_out = decrypt_chunked_rust256(&key, &iv, &ciphertext, &mut rng);
            assert_eq!(aws_out, plaintext, "aes256 aws-lc decrypt, case {case}");
            assert_eq!(rust_out, plaintext, "aes256 rust decrypt, case {case}");
        }

        // ---- AES-128 (RAR4) ----
        {
            let mut key = [0u8; 16];
            rng.fill(&mut key);
            let ciphertext = if case % 2 == 0 {
                rust::encrypt_aes128_cbc_for_test(&key, &iv, &plaintext)
            } else {
                aws_lc::encrypt_aes128_cbc_for_test(&key, &iv, &plaintext)
            };

            let aws_out = decrypt_chunked_aws128(&key, &iv, &ciphertext, &mut rng);
            let rust_out = decrypt_chunked_rust128(&key, &iv, &ciphertext, &mut rng);
            assert_eq!(aws_out, plaintext, "aes128 aws-lc decrypt, case {case}");
            assert_eq!(rust_out, plaintext, "aes128 rust decrypt, case {case}");
        }
    }
}

/// Yield a randomized sequence of block-multiple chunk sizes summing to `total`
/// (a multiple of `AES_BLOCK`). Includes single-block (16) and odd multi-block
/// chunks to stress IV-state carry across `decrypt_blocks` calls.
fn block_multiple_splits(total: usize, rng: &mut XorShift64) -> Vec<usize> {
    debug_assert!(total.is_multiple_of(AES_BLOCK));
    let mut remaining_blocks = total / AES_BLOCK;
    let mut sizes = Vec::new();
    while remaining_blocks > 0 {
        // 1..=7 blocks per chunk, capped at what's left.
        let take = 1 + rng.next_usize(7.min(remaining_blocks));
        sizes.push(take * AES_BLOCK);
        remaining_blocks -= take;
    }
    sizes
}

macro_rules! chunked_decrypt {
    ($name:ident, $decty:path, $key_len:literal) => {
        fn $name(
            key: &[u8; $key_len],
            iv: &[u8; 16],
            ciphertext: &[u8],
            rng: &mut XorShift64,
        ) -> Vec<u8> {
            let mut dec = <$decty>::new(key, iv);
            let mut buf = ciphertext.to_vec();
            let splits = block_multiple_splits(buf.len(), rng);
            let mut offset = 0;
            for size in splits {
                dec.decrypt_blocks(&mut buf[offset..offset + size]);
                offset += size;
            }
            buf
        }
    };
}

chunked_decrypt!(decrypt_chunked_aws256, aws_lc::Aes256CbcDec, 32);
chunked_decrypt!(decrypt_chunked_rust256, rust::Aes256CbcDec, 32);
chunked_decrypt!(decrypt_chunked_aws128, aws_lc::Aes128CbcDec, 16);
chunked_decrypt!(decrypt_chunked_rust128, rust::Aes128CbcDec, 16);
