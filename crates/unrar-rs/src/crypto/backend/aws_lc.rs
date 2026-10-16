//! AWS-LC crypto backend.
//!
//! Every aws-lc-touching primitive lives here behind the minimal backend
//! seam consumed by the shared code in [`crate::crypto`]. Adding a second
//! backend later means providing another module with the same surface — the
//! shared code never references aws-lc directly. Everything goes through
//! `aws-lc-rs`; the crate names no `aws-lc-sys` symbol, so a consumer's graph
//! carries the one AWS-LC its own `aws-lc-rs` links.

use aws_lc_rs::cipher::{
    AES_128, AES_256, Algorithm, DecryptingKey, DecryptionContext, EncryptingKey,
    EncryptionContext, UnboundCipherKey,
};
use aws_lc_rs::digest as aws_digest;
use aws_lc_rs::hmac;
use aws_lc_rs::iv::FixedLength;

use crate::crypto::AES_BLOCK;

/// HMAC-SHA256 key handle used for MAC conversion
/// ([`crate::crypto::convert_crc32_to_mac`] / `convert_blake2_to_mac`).
///
/// **Not** the RAR5 key derivation: that lives in [`crate::crypto::kdf_hmac`],
/// which runs on `sha2` on every backend so its 2^24-iteration loop never
/// crosses FFI. The MAC conversions take one tag per key, so `hmac::sign`'s
/// per-tag context copy is paid once per member, not per byte.
pub(crate) struct HmacSha256Key(hmac::Key);

/// Build an HMAC-SHA256 key from raw secret bytes.
pub(crate) fn hmac_sha256_key(secret: &[u8]) -> HmacSha256Key {
    HmacSha256Key(hmac::Key::new(hmac::HMAC_SHA256, secret))
}

/// Compute HMAC-SHA256 over `data` with the given key.
pub(crate) fn hmac_sha256(key: &HmacSha256Key, data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(hmac::sign(&key.0, data).as_ref());
    out
}

/// Compute a SHA-256 digest over `data`.
pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = aws_digest::digest(&aws_digest::SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

fn cipher_key(algorithm: &'static Algorithm, key: &[u8]) -> UnboundCipherKey {
    UnboundCipherKey::new(algorithm, key).expect("aws-lc AES key length is fixed by the caller")
}

/// CBC-encrypt block-aligned `plaintext` with no padding. Not part of the RAR
/// decrypt path — used only to build ciphertext for round-trip and
/// differential tests via [`crate::test_support`], so it is always compiled
/// but hidden from docs. Panics on any aws-lc failure (test-only inputs).
fn encrypt_cbc_for_test(
    algorithm: &'static Algorithm,
    key: &[u8],
    iv: &[u8; AES_BLOCK],
    plaintext: &[u8],
) -> Vec<u8> {
    assert!(plaintext.len().is_multiple_of(AES_BLOCK));
    let mut encryptor = AwsLcCbcEncryptor::new(algorithm, key, iv);
    let mut ciphertext = plaintext.to_vec();
    assert!(
        encryptor.encrypt_blocks(&mut ciphertext),
        "aws-lc CBC encrypt must succeed"
    );
    ciphertext
}

pub(crate) fn encrypt_aes128_cbc_for_test(
    key: &[u8; 16],
    iv: &[u8; AES_BLOCK],
    plaintext: &[u8],
) -> Vec<u8> {
    encrypt_cbc_for_test(&AES_128, key, iv, plaintext)
}

pub(crate) fn encrypt_aes256_cbc_for_test(
    key: &[u8; 32],
    iv: &[u8; AES_BLOCK],
    plaintext: &[u8],
) -> Vec<u8> {
    encrypt_cbc_for_test(&AES_256, key, iv, plaintext)
}

/// AES-CBC block decryptor, in place, no padding. `aws-lc-rs` takes the IV
/// per call, so the chain is carried here: the next IV is the last
/// ciphertext block of the previous call.
struct AwsLcCbcDecryptor {
    key: DecryptingKey,
    iv: [u8; AES_BLOCK],
}

impl AwsLcCbcDecryptor {
    fn new(algorithm: &'static Algorithm, key: &[u8], iv: &[u8; AES_BLOCK]) -> Self {
        let key = DecryptingKey::cbc(cipher_key(algorithm, key))
            .expect("aws-lc CBC decrypting key must build");
        Self { key, iv: *iv }
    }

    fn decrypt_blocks(&mut self, data: &mut [u8]) {
        debug_assert!(data.len().is_multiple_of(AES_BLOCK));
        let Some(last) = data.len().checked_sub(AES_BLOCK) else {
            return;
        };
        let mut next_iv = [0u8; AES_BLOCK];
        next_iv.copy_from_slice(&data[last..]);
        let context = DecryptionContext::Iv128(FixedLength::from(self.iv));
        self.key
            .decrypt(data, context)
            .expect("aws-lc CBC decrypt of whole blocks must succeed");
        self.iv = next_iv;
    }
}

/// AES-CBC block **encryptor**, in place, no padding.
///
/// Unlike [`encrypt_cbc_for_test`] this is a real seam item: it is what
/// [`crate::crypto::MemberCipherKey::encrypt_range`] runs on, so it allocates
/// nothing and reports a backend failure to its caller instead of panicking.
/// The IV chain is carried here, as in the decryptor.
struct AwsLcCbcEncryptor {
    key: EncryptingKey,
    iv: [u8; AES_BLOCK],
}

impl AwsLcCbcEncryptor {
    fn new(algorithm: &'static Algorithm, key: &[u8], iv: &[u8; AES_BLOCK]) -> Self {
        let key = EncryptingKey::cbc(cipher_key(algorithm, key))
            .expect("aws-lc CBC encrypting key must build");
        Self { key, iv: *iv }
    }

    /// Encrypts `data` in place as whole blocks. `false` if aws-lc refused,
    /// which the caller turns into an error rather than a panic; `data` may then
    /// hold a partial transform and must not be used.
    fn encrypt_blocks(&mut self, data: &mut [u8]) -> bool {
        debug_assert!(data.len().is_multiple_of(AES_BLOCK));
        let Some(last) = data.len().checked_sub(AES_BLOCK) else {
            return true;
        };
        let context = EncryptionContext::Iv128(FixedLength::from(self.iv));
        if self.key.less_safe_encrypt(data, context).is_err() {
            return false;
        }
        self.iv.copy_from_slice(&data[last..]);
        true
    }
}

/// AES-256-CBC block encryptor (RAR5).
pub(crate) struct Aes256CbcEnc(AwsLcCbcEncryptor);

impl Aes256CbcEnc {
    #[inline]
    pub(crate) fn new(key: &[u8; 32], iv: &[u8; AES_BLOCK]) -> Self {
        Self(AwsLcCbcEncryptor::new(&AES_256, key, iv))
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
        Self(AwsLcCbcEncryptor::new(&AES_128, key, iv))
    }

    #[inline]
    pub(crate) fn encrypt_blocks(&mut self, data: &mut [u8]) -> bool {
        self.0.encrypt_blocks(data)
    }
}

/// AES-256-CBC block decryptor (RAR5).
pub(crate) struct Aes256CbcDec(AwsLcCbcDecryptor);

impl Aes256CbcDec {
    #[inline]
    pub(crate) fn new(key: &[u8; 32], iv: &[u8; 16]) -> Self {
        Self(AwsLcCbcDecryptor::new(&AES_256, key, iv))
    }

    #[inline]
    pub(crate) fn decrypt_blocks(&mut self, data: &mut [u8]) {
        self.0.decrypt_blocks(data);
    }
}

/// AES-128-CBC block decryptor (RAR4).
pub(crate) struct Aes128CbcDec(AwsLcCbcDecryptor);

impl Aes128CbcDec {
    #[inline]
    pub(crate) fn new(key: &[u8; 16], iv: &[u8; 16]) -> Self {
        Self(AwsLcCbcDecryptor::new(&AES_128, key, iv))
    }

    #[inline]
    pub(crate) fn decrypt_blocks(&mut self, data: &mut [u8]) {
        self.0.decrypt_blocks(data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Splitting a CBC stream across calls must give the bytes one call over
    /// the whole buffer gives: the carried IV is the whole of the chaining.
    #[test]
    fn cbc_chain_survives_arbitrary_block_splits() {
        let key = [0x42u8; 32];
        let iv = [0x17u8; AES_BLOCK];
        let plaintext: Vec<u8> = (0..AES_BLOCK * 37).map(|i| (i * 131 + 7) as u8).collect();
        let whole = encrypt_aes256_cbc_for_test(&key, &iv, &plaintext);

        for split in [0usize, 1, 2, 5, 36, 37] {
            let at = split * AES_BLOCK;
            let mut enc = Aes256CbcEnc::new(&key, &iv);
            let mut ciphertext = plaintext.clone();
            let (head, tail) = ciphertext.split_at_mut(at);
            assert!(enc.encrypt_blocks(head));
            assert!(enc.encrypt_blocks(tail));
            assert_eq!(ciphertext, whole, "encrypt split at block {split}");

            let mut dec = Aes256CbcDec::new(&key, &iv);
            let (head, tail) = ciphertext.split_at_mut(at);
            dec.decrypt_blocks(head);
            dec.decrypt_blocks(tail);
            assert_eq!(ciphertext, plaintext, "decrypt split at block {split}");
        }
    }
}
