//! AWS-LC crypto backend.
//!
//! Every aws-lc-touching primitive lives here behind the minimal backend
//! seam consumed by the shared code in [`crate::crypto`]. Adding a second
//! backend later means providing another module with the same surface — the
//! shared code never references aws-lc directly.

use std::ptr::null_mut;

use aws_lc_rs::{digest as aws_digest, hmac as aws_hmac};
use aws_lc_sys::{
    EVP_CIPHER, EVP_CIPHER_CTX, EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_new,
    EVP_CIPHER_CTX_set_padding, EVP_DecryptInit_ex, EVP_DecryptUpdate, EVP_EncryptInit_ex,
    EVP_EncryptUpdate, EVP_aes_128_cbc, EVP_aes_256_cbc,
};

use crate::crypto::AES_BLOCK;

/// HMAC-SHA256 key handle used for RAR5 key derivation and MAC conversion.
pub(crate) type HmacSha256Key = aws_hmac::Key;

/// Build an HMAC-SHA256 key from raw secret bytes.
pub(crate) fn hmac_sha256_key(secret: &[u8]) -> HmacSha256Key {
    aws_hmac::Key::new(aws_hmac::HMAC_SHA256, secret)
}

/// Compute HMAC-SHA256 over `data` with the given key.
pub(crate) fn hmac_sha256(key: &HmacSha256Key, data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(aws_hmac::sign(key, data).as_ref());
    out
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

const AWS_LC_MAX_DECRYPT_UPDATE_LEN: usize = (i32::MAX as usize / AES_BLOCK) * AES_BLOCK;

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
        for chunk in data.chunks_mut(AWS_LC_MAX_DECRYPT_UPDATE_LEN) {
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
    use super::*;

    #[test]
    fn test_aws_lc_decrypt_update_chunk_limit_is_i32_aligned() {
        assert_eq!(AWS_LC_MAX_DECRYPT_UPDATE_LEN % AES_BLOCK, 0);
        assert!(AWS_LC_MAX_DECRYPT_UPDATE_LEN <= i32::MAX as usize);
        assert!(AWS_LC_MAX_DECRYPT_UPDATE_LEN + AES_BLOCK > i32::MAX as usize);
    }
}
