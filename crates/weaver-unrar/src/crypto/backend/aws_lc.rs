//! AWS-LC crypto backend.
//!
//! Every aws-lc-touching primitive lives here behind the minimal backend
//! seam consumed by the shared code in [`crate::crypto`]. Adding a second
//! backend later means providing another module with the same surface — the
//! shared code never references aws-lc directly.

use std::mem::MaybeUninit;
use std::ptr::null_mut;

use aws_lc_rs::digest as aws_digest;
use aws_lc_sys::{
    EVP_CIPHER, EVP_CIPHER_CTX, EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_new,
    EVP_CIPHER_CTX_set_padding, EVP_DecryptInit_ex, EVP_DecryptUpdate, EVP_EncryptInit_ex,
    EVP_EncryptUpdate, EVP_aes_128_cbc, EVP_aes_256_cbc, SHA256_CTX, SHA256_Final, SHA256_Init,
    SHA256_Update,
};
use zeroize::Zeroize;

use crate::crypto::AES_BLOCK;

/// SHA-256 block size in bytes — the HMAC key-padding width (RFC 4868).
const SHA256_BLOCK: usize = 64;

/// HMAC-SHA256 key handle used for MAC conversion
/// ([`crate::crypto::convert_crc32_to_mac`] / `convert_blake2_to_mac`).
///
/// **Not** the RAR5 key derivation: that moved to [`crate::crypto::kdf_hmac`],
/// which runs on `sha2` on every backend so its 2^24-iteration loop never
/// crosses FFI. The cached-context shape below is kept anyway — it is strictly
/// cheaper than the alternative even for the one tag per call the MAC
/// conversions take, and it is what the pre-change differential test pins.
///
/// This is deliberately **not** `aws_lc_rs::hmac::Key`. That type's only way to
/// produce a tag is `hmac::sign` / `hmac::Context::with_key`, both of which
/// clone the whole `HMAC_CTX` (`HMAC_CTX_init` + `HMAC_CTX_copy_ex` over three
/// `EVP_MD_CTX`s, then `HMAC_CTX_cleanup` / `OPENSSL_cleanse` on drop) for every
/// single tag. When this backend still carried the derivation, that per-tag
/// context churn — not the SHA-256 compressions — dominated it.
///
/// Instead this is UnRAR's own shape (`crypt5.cpp:22-46,51-76`: `ICtxOpt` /
/// `SetIOpt` and `RCtxOpt` / `SetROpt`): the key⊕ipad and key⊕opad blocks are
/// absorbed into two SHA-256 contexts **once**, and each tag resumes from a
/// *copy* of those already-primed contexts. Per tag that is 2 SHA-256
/// compressions and 2 struct copies, with no allocation and no cleanse.
///
/// The copies are plain value assignments of `SHA256_CTX`, a 112-byte
/// `#[repr(C)]` POD — the exact `ICtx=*ICtxOpt` the oracle performs. The other
/// candidate, `aws_lc_rs::digest::Context`, is also `Clone`, but its clone is an
/// `EVP_MD_CTX_copy`: a malloc, a copy, then a free and cleanse on drop. That
/// form was built and measured first and reached only 1.33x (137 -> 103
/// ns/iter); this one reaches 2.4x (137 -> 58 ns/iter), which is the whole
/// distance back to the oracle. The SHA-256 is aws-lc's either way — only HMAC's
/// ipad/opad framing (one XOR and two block absorptions) is expressed here, as
/// it is in the oracle.
pub(crate) struct HmacSha256Key {
    /// SHA-256 state after absorbing `key ⊕ 0x36…` (UnRAR's `ICtxOpt`).
    inner: SHA256_CTX,
    /// SHA-256 state after absorbing `key ⊕ 0x5c…` (UnRAR's `RCtxOpt`).
    outer: SHA256_CTX,
}

impl Drop for HmacSha256Key {
    fn drop(&mut self) {
        // The primed contexts carry password-derived state; wipe it on the way
        // out, the way the `HMAC_CTX` this replaced was cleansed by aws-lc.
        for ctx in [&mut self.inner, &mut self.outer] {
            ctx.h.zeroize();
            ctx.data.zeroize();
            ctx.Nl.zeroize();
            ctx.Nh.zeroize();
        }
    }
}

/// Absorb one 64-byte `key ⊕ pad_byte` block into a fresh SHA-256 context and
/// return it primed. `key` must already be at most `SHA256_BLOCK` bytes; bytes
/// past its end keep the bare pad byte, which is HMAC's zero-padding rule.
fn primed_context(pad_byte: u8, key: &[u8]) -> SHA256_CTX {
    debug_assert!(key.len() <= SHA256_BLOCK);
    let mut pad = [pad_byte; SHA256_BLOCK];
    for (slot, byte) in pad.iter_mut().zip(key) {
        *slot ^= *byte;
    }

    // SAFETY: `SHA256_Init` fully initializes the context it is handed, and the
    // update reads exactly `SHA256_BLOCK` bytes from a stack buffer of that
    // size. Both return 1 on success and cannot fail for a valid context.
    let ctx = unsafe {
        let mut ctx = MaybeUninit::<SHA256_CTX>::uninit();
        assert_eq!(
            SHA256_Init(ctx.as_mut_ptr()),
            1,
            "aws-lc SHA256_Init failed"
        );
        let mut ctx = ctx.assume_init();
        assert_eq!(
            SHA256_Update(&mut ctx, pad.as_ptr().cast(), SHA256_BLOCK),
            1,
            "aws-lc SHA256_Update failed"
        );
        ctx
    };

    pad.zeroize();
    ctx
}

/// Build an HMAC-SHA256 key from raw secret bytes: precompute and retain the
/// ipad/opad contexts. Called once per derivation, never inside its loop.
pub(crate) fn hmac_sha256_key(secret: &[u8]) -> HmacSha256Key {
    // RFC 2104 / UnRAR `crypt5.cpp:9-18`: over-long keys are replaced by their
    // own digest; shorter ones are zero-padded, which `primed_context` does by
    // XORing only over `key.len()` bytes of an all-pad block.
    if secret.len() > SHA256_BLOCK {
        let mut hashed = sha256(secret);
        let material = HmacSha256Key {
            inner: primed_context(0x36, &hashed),
            outer: primed_context(0x5C, &hashed),
        };
        // Hoisted secret hygiene: the key digest is wiped once per key, never
        // per tag. (`primed_context` wipes its own padded block.)
        hashed.zeroize();
        material
    } else {
        HmacSha256Key {
            inner: primed_context(0x36, secret),
            outer: primed_context(0x5C, secret),
        }
    }
}

/// Compute HMAC-SHA256 over `data` with the given key.
///
/// The per-tag half of the cached-context shape, and the direct transcription
/// of the oracle's inner loop: copy the primed inner context, absorb `data`,
/// finalize; copy the primed outer context, absorb that digest, finalize. No
/// allocation, no re-derivation of the ipad/opad blocks, no cleanse.
pub(crate) fn hmac_sha256(key: &HmacSha256Key, data: &[u8]) -> [u8; 32] {
    // SAFETY: both contexts are fully initialized (`primed_context`) and are
    // copied by value here, so the originals are never mutated and stay valid
    // for the next tag — this is the whole point of the cached-context shape.
    // Each `SHA256_Update` reads exactly the length of a live slice, and each
    // `SHA256_Final` writes exactly 32 bytes into a 32-byte buffer.
    unsafe {
        let mut inner = key.inner;
        SHA256_Update(&mut inner, data.as_ptr().cast(), data.len());
        let mut inner_digest = [0u8; 32];
        SHA256_Final(inner_digest.as_mut_ptr(), &mut inner);

        let mut outer = key.outer;
        SHA256_Update(&mut outer, inner_digest.as_ptr().cast(), inner_digest.len());
        let mut out = [0u8; 32];
        SHA256_Final(out.as_mut_ptr(), &mut outer);
        out
    }
}

/// Compute a SHA-256 digest over `data`.
pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = aws_digest::digest(&aws_digest::SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

/// CBC-encrypt block-aligned `plaintext` with no padding. Not part of the RAR
/// decrypt path — used only to build ciphertext for round-trip and
/// differential tests via [`crate::test_support`], so it is always compiled
/// but hidden from docs. Panics on any aws-lc failure (test-only inputs).
fn encrypt_cbc_for_test(
    cipher: *const EVP_CIPHER,
    key: &[u8],
    iv: &[u8; AES_BLOCK],
    plaintext: &[u8],
) -> Vec<u8> {
    assert!(plaintext.len().is_multiple_of(AES_BLOCK));
    assert!(plaintext.len() <= i32::MAX as usize);

    let ctx = unsafe { EVP_CIPHER_CTX_new() };
    assert!(!ctx.is_null(), "aws-lc EVP_CIPHER_CTX_new must succeed");

    let init = unsafe { EVP_EncryptInit_ex(ctx, cipher, null_mut(), key.as_ptr(), iv.as_ptr()) };
    assert_eq!(init, 1, "aws-lc EVP_EncryptInit_ex must succeed");

    let no_padding = unsafe { EVP_CIPHER_CTX_set_padding(ctx, 0) };
    assert_eq!(
        no_padding, 1,
        "aws-lc EVP_CIPHER_CTX_set_padding(0) must succeed"
    );

    let mut ciphertext = vec![0u8; plaintext.len()];
    let mut out_len = 0_i32;
    let result = unsafe {
        EVP_EncryptUpdate(
            ctx,
            ciphertext.as_mut_ptr(),
            &mut out_len,
            plaintext.as_ptr(),
            plaintext.len() as i32,
        )
    };
    unsafe { EVP_CIPHER_CTX_free(ctx) };

    assert_eq!(result, 1, "aws-lc EVP_EncryptUpdate must succeed");
    assert_eq!(
        out_len as usize,
        plaintext.len(),
        "aws-lc CBC encrypt must write the full block-aligned input"
    );
    ciphertext
}

pub(crate) fn encrypt_aes128_cbc_for_test(
    key: &[u8; 16],
    iv: &[u8; AES_BLOCK],
    plaintext: &[u8],
) -> Vec<u8> {
    encrypt_cbc_for_test(unsafe { EVP_aes_128_cbc() }, key, iv, plaintext)
}

pub(crate) fn encrypt_aes256_cbc_for_test(
    key: &[u8; 32],
    iv: &[u8; AES_BLOCK],
    plaintext: &[u8],
) -> Vec<u8> {
    encrypt_cbc_for_test(unsafe { EVP_aes_256_cbc() }, key, iv, plaintext)
}

struct AwsLcCbcDecryptor {
    ctx: *mut EVP_CIPHER_CTX,
}

const AWS_LC_MAX_UPDATE_LEN: usize = (i32::MAX as usize / AES_BLOCK) * AES_BLOCK;

unsafe impl Send for AwsLcCbcDecryptor {}

impl AwsLcCbcDecryptor {
    fn new_aes256(key: &[u8; 32], iv: &[u8; AES_BLOCK]) -> Self {
        Self::new(unsafe { EVP_aes_256_cbc() }, key, iv)
    }

    fn new_aes128(key: &[u8; 16], iv: &[u8; AES_BLOCK]) -> Self {
        Self::new(unsafe { EVP_aes_128_cbc() }, key, iv)
    }

    fn new(cipher: *const EVP_CIPHER, key: &[u8], iv: &[u8; AES_BLOCK]) -> Self {
        let ctx = unsafe { EVP_CIPHER_CTX_new() };
        assert!(!ctx.is_null(), "aws-lc EVP_CIPHER_CTX_new must succeed");

        let init =
            unsafe { EVP_DecryptInit_ex(ctx, cipher, null_mut(), key.as_ptr(), iv.as_ptr()) };
        assert_eq!(init, 1, "aws-lc EVP_DecryptInit_ex must succeed");

        let no_padding = unsafe { EVP_CIPHER_CTX_set_padding(ctx, 0) };
        assert_eq!(
            no_padding, 1,
            "aws-lc EVP_CIPHER_CTX_set_padding(0) must succeed"
        );

        Self { ctx }
    }

    fn decrypt_blocks(&mut self, data: &mut [u8]) {
        debug_assert!(data.len().is_multiple_of(AES_BLOCK));
        for chunk in data.chunks_mut(AWS_LC_MAX_UPDATE_LEN) {
            let mut out_len = 0_i32;
            let input_len = chunk.len() as i32;
            let result = unsafe {
                EVP_DecryptUpdate(
                    self.ctx,
                    chunk.as_mut_ptr(),
                    &mut out_len,
                    chunk.as_ptr(),
                    input_len,
                )
            };
            assert_eq!(result, 1, "aws-lc EVP_DecryptUpdate must succeed");
            assert!(out_len >= 0, "aws-lc output length must be non-negative");
            assert_eq!(
                out_len as usize,
                chunk.len(),
                "aws-lc CBC decrypt must write the full block-aligned input"
            );
        }
    }
}

impl Drop for AwsLcCbcDecryptor {
    fn drop(&mut self) {
        unsafe { EVP_CIPHER_CTX_free(self.ctx) };
    }
}

/// AES-CBC block **encryptor**, in place, no padding.
///
/// Unlike [`encrypt_cbc_for_test`] this is a real seam item: it is what
/// [`crate::crypto::MemberCipherKey::encrypt_range`] runs on, so it allocates
/// nothing, chunks its input the way the decryptor does rather than asserting a
/// length, and reports a backend failure to its caller instead of panicking.
struct AwsLcCbcEncryptor {
    ctx: *mut EVP_CIPHER_CTX,
}

unsafe impl Send for AwsLcCbcEncryptor {}

impl AwsLcCbcEncryptor {
    fn new(cipher: *const EVP_CIPHER, key: &[u8], iv: &[u8; AES_BLOCK]) -> Self {
        let ctx = unsafe { EVP_CIPHER_CTX_new() };
        assert!(!ctx.is_null(), "aws-lc EVP_CIPHER_CTX_new must succeed");

        let init =
            unsafe { EVP_EncryptInit_ex(ctx, cipher, null_mut(), key.as_ptr(), iv.as_ptr()) };
        assert_eq!(init, 1, "aws-lc EVP_EncryptInit_ex must succeed");

        let no_padding = unsafe { EVP_CIPHER_CTX_set_padding(ctx, 0) };
        assert_eq!(
            no_padding, 1,
            "aws-lc EVP_CIPHER_CTX_set_padding(0) must succeed"
        );

        Self { ctx }
    }

    /// Encrypts `data` in place as whole blocks. `false` if aws-lc refused,
    /// which the caller turns into an error rather than a panic; `data` may then
    /// hold a partial transform and must not be used.
    fn encrypt_blocks(&mut self, data: &mut [u8]) -> bool {
        debug_assert!(data.len().is_multiple_of(AES_BLOCK));
        for chunk in data.chunks_mut(AWS_LC_MAX_UPDATE_LEN) {
            let mut out_len = 0_i32;
            let input_len = chunk.len() as i32;
            let result = unsafe {
                EVP_EncryptUpdate(
                    self.ctx,
                    chunk.as_mut_ptr(),
                    &mut out_len,
                    chunk.as_ptr(),
                    input_len,
                )
            };
            if result != 1 || out_len < 0 || out_len as usize != chunk.len() {
                return false;
            }
        }
        true
    }
}

impl Drop for AwsLcCbcEncryptor {
    fn drop(&mut self) {
        unsafe { EVP_CIPHER_CTX_free(self.ctx) };
    }
}

/// AES-256-CBC block encryptor (RAR5).
pub(crate) struct Aes256CbcEnc(AwsLcCbcEncryptor);

impl Aes256CbcEnc {
    #[inline]
    pub(crate) fn new(key: &[u8; 32], iv: &[u8; AES_BLOCK]) -> Self {
        Self(AwsLcCbcEncryptor::new(
            unsafe { EVP_aes_256_cbc() },
            key,
            iv,
        ))
    }

    #[inline]
    pub(crate) fn encrypt_blocks(&mut self, data: &mut [u8]) -> bool {
        self.0.encrypt_blocks(data)
    }
}

/// AES-128-CBC block encryptor (RAR4).
pub(crate) struct Aes128CbcEnc(AwsLcCbcEncryptor);

impl Aes128CbcEnc {
    #[inline]
    pub(crate) fn new(key: &[u8; 16], iv: &[u8; AES_BLOCK]) -> Self {
        Self(AwsLcCbcEncryptor::new(
            unsafe { EVP_aes_128_cbc() },
            key,
            iv,
        ))
    }

    #[inline]
    pub(crate) fn encrypt_blocks(&mut self, data: &mut [u8]) -> bool {
        self.0.encrypt_blocks(data)
    }
}

/// AES-256-CBC block decryptor. Thin newtype over the aws-lc EVP decryptor.
pub(crate) struct Aes256CbcDec(AwsLcCbcDecryptor);

impl Aes256CbcDec {
    #[inline]
    pub(crate) fn new(key: &[u8; 32], iv: &[u8; 16]) -> Self {
        Self(AwsLcCbcDecryptor::new_aes256(key, iv))
    }

    #[inline]
    pub(crate) fn decrypt_blocks(&mut self, data: &mut [u8]) {
        self.0.decrypt_blocks(data);
    }
}

/// AES-128-CBC block decryptor (RAR4). Thin newtype over the aws-lc EVP decryptor.
pub(crate) struct Aes128CbcDec(AwsLcCbcDecryptor);

impl Aes128CbcDec {
    #[inline]
    pub(crate) fn new(key: &[u8; 16], iv: &[u8; 16]) -> Self {
        Self(AwsLcCbcDecryptor::new_aes128(key, iv))
    }

    #[inline]
    pub(crate) fn decrypt_blocks(&mut self, data: &mut [u8]) {
        self.0.decrypt_blocks(data);
    }
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::hmac as aws_hmac;

    use super::*;

    #[test]
    fn test_aws_lc_update_chunk_limit_is_i32_aligned() {
        assert_eq!(AWS_LC_MAX_UPDATE_LEN % AES_BLOCK, 0);
        assert!(AWS_LC_MAX_UPDATE_LEN <= i32::MAX as usize);
        assert!(AWS_LC_MAX_UPDATE_LEN + AES_BLOCK > i32::MAX as usize);
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
    }

    /// The pre-change primitive, transcribed verbatim as the reference: a fresh
    /// `aws_lc_rs::hmac::Key` signed with `hmac::sign` (one full `HMAC_CTX`
    /// build per tag). The cached-context [`hmac_sha256`] that replaced it must
    /// agree with it byte-for-byte on every input, because RAR5 key material
    /// derived before this change must still decrypt every existing archive.
    fn reference_hmac_sha256_pre_change(secret: &[u8], data: &[u8]) -> [u8; 32] {
        let key = aws_hmac::Key::new(aws_hmac::HMAC_SHA256, secret);
        let mut out = [0u8; 32];
        out.copy_from_slice(aws_hmac::sign(&key, data).as_ref());
        out
    }

    /// Exhaustive-ish agreement between the cached-context HMAC and the
    /// `hmac::sign` form it replaced, across every key-length regime HMAC
    /// treats differently (short/zero-padded, exactly one block, over-long and
    /// therefore hashed down) and across the message lengths that straddle
    /// SHA-256 block and padding boundaries — including the 20-byte salt block
    /// and 32-byte `U` that RAR5's PBKDF2 actually signs.
    #[test]
    fn cached_context_hmac_matches_pre_change_hmac_sign() {
        let mut rng = XorShift64::new(0x5EED_0BAD_C0FF_EE01);
        let mut cases = 0usize;

        let key_lens = [
            0usize, 1, 8, 20, 32, 55, 56, 63, 64, 65, 96, 127, 128, 129, 200, 381,
        ];
        let data_lens = [
            0usize, 1, 16, 20, 31, 32, 33, 55, 56, 63, 64, 65, 119, 120, 128, 1000,
        ];

        for key_len in key_lens {
            let mut secret = vec![0u8; key_len];
            rng.fill(&mut secret);
            for data_len in data_lens {
                let mut data = vec![0u8; data_len];
                rng.fill(&mut data);

                let key = hmac_sha256_key(&secret);
                assert_eq!(
                    hmac_sha256(&key, &data),
                    reference_hmac_sha256_pre_change(&secret, &data),
                    "hmac diverged from the pre-change primitive: \
                     key_len {key_len}, data_len {data_len}"
                );

                // The key object is reused across tags in the PBKDF2 loop, so
                // prove a second (and third) tag from the SAME key is still
                // correct — i.e. the cached contexts are not consumed or
                // mutated by signing.
                let mut u = [0u8; 32];
                rng.fill(&mut u);
                for round in 0..3 {
                    let expected = reference_hmac_sha256_pre_change(&secret, &u);
                    u = hmac_sha256(&key, &u);
                    assert_eq!(
                        u, expected,
                        "reused-key chain diverged at round {round}: key_len {key_len}"
                    );
                }

                cases += 1;
            }
        }

        assert!(cases >= 200, "expected >= 200 cases, ran {cases}");
    }
}
