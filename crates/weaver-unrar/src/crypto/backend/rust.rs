//! Portable pure-Rust crypto backend (RustCrypto).
//!
//! Mirrors the AWS-LC backend's seam exactly — same 7 items, same semantics —
//! using `sha2`, `hmac`, `aes`, and `cbc`. This backend has no C dependency,
//! so it compiles for `wasm32` and any other target the RustCrypto crates
//! support. On native targets it also compiles alongside the AWS-LC backend
//! (only one is re-exported as active) so the two can be compared directly in
//! the differential tests.

use aes::cipher::block::{BlockModeDecrypt, BlockModeEncrypt};
use aes::cipher::{Array, KeyIvInit};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

use crate::crypto::AES_BLOCK;

/// HMAC-SHA256 key handle. Unlike the AWS-LC backend (where the key is a raw
/// handle), here the *pre-keyed HMAC instance itself* is the key: it carries
/// the precomputed ipad/opad inner/outer state. Cloning it per signature (see
/// [`hmac_sha256`]) preserves that state, which is what makes the hand-rolled
/// PBKDF2 loop in `derive_rar5_material` cheap — do not restructure that.
pub(crate) type HmacSha256Key = Hmac<Sha256>;

/// Build an HMAC-SHA256 key (a pre-keyed instance) from raw secret bytes.
pub(crate) fn hmac_sha256_key(secret: &[u8]) -> HmacSha256Key {
    // HMAC accepts a key of ANY length (it hashes over-long keys and
    // zero-pads short ones), so `new_from_slice` is infallible here.
    Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts keys of any length")
}

/// Compute HMAC-SHA256 over `data` with the given key.
pub(crate) fn hmac_sha256(key: &HmacSha256Key, data: &[u8]) -> [u8; 32] {
    // Clone the pre-keyed instance so the precomputed ipad/opad state is
    // reused rather than recomputed — load-bearing for the PBKDF2 inner loop.
    let mut mac = key.clone();
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Compute a SHA-256 digest over `data`.
pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// CBC-encrypt block-aligned `plaintext` with no padding. Not part of the RAR
/// decrypt path — used only to build ciphertext for round-trip and
/// differential tests via [`crate::test_support`], so it is always compiled
/// but hidden from docs.
fn encrypt_cbc_for_test<C>(key: &[u8], iv: &[u8; AES_BLOCK], plaintext: &[u8]) -> Vec<u8>
where
    C: KeyIvInit + BlockModeEncrypt,
{
    debug_assert!(plaintext.len().is_multiple_of(AES_BLOCK));
    let mut enc = C::new_from_slices(key, iv).expect("valid key/iv lengths");
    let mut buf = plaintext.to_vec();
    let (blocks, rest) = Array::<u8, _>::slice_as_chunks_mut(&mut buf);
    debug_assert!(rest.is_empty());
    enc.encrypt_blocks(blocks);
    buf
}

pub(crate) fn encrypt_aes128_cbc_for_test(
    key: &[u8; 16],
    iv: &[u8; AES_BLOCK],
    plaintext: &[u8],
) -> Vec<u8> {
    encrypt_cbc_for_test::<cbc::Encryptor<aes::Aes128>>(key, iv, plaintext)
}

pub(crate) fn encrypt_aes256_cbc_for_test(
    key: &[u8; 32],
    iv: &[u8; AES_BLOCK],
    plaintext: &[u8],
) -> Vec<u8> {
    encrypt_cbc_for_test::<cbc::Encryptor<aes::Aes256>>(key, iv, plaintext)
}

/// AES-256-CBC block decryptor. Thin newtype over the RustCrypto CBC mode,
/// carrying IV state across `decrypt_blocks` calls exactly like the AWS-LC
/// EVP decryptor.
pub(crate) struct Aes256CbcDec(cbc::Decryptor<aes::Aes256>);

impl Aes256CbcDec {
    #[inline]
    pub(crate) fn new(key: &[u8; 32], iv: &[u8; 16]) -> Self {
        Self(cbc::Decryptor::<aes::Aes256>::new(key.into(), iv.into()))
    }

    #[inline]
    pub(crate) fn decrypt_blocks(&mut self, data: &mut [u8]) {
        decrypt_blocks_in_place(&mut self.0, data);
    }
}

/// AES-128-CBC block decryptor (RAR4). Thin newtype over the RustCrypto CBC
/// mode.
pub(crate) struct Aes128CbcDec(cbc::Decryptor<aes::Aes128>);

impl Aes128CbcDec {
    #[inline]
    pub(crate) fn new(key: &[u8; 16], iv: &[u8; 16]) -> Self {
        Self(cbc::Decryptor::<aes::Aes128>::new(key.into(), iv.into()))
    }

    #[inline]
    pub(crate) fn decrypt_blocks(&mut self, data: &mut [u8]) {
        decrypt_blocks_in_place(&mut self.0, data);
    }
}

/// Decrypt `data` in place as whole 16-byte CBC blocks, mutating `dec`'s IV
/// state so subsequent calls chain correctly (matching EVP semantics).
#[inline]
fn decrypt_blocks_in_place<C: BlockModeDecrypt>(dec: &mut C, data: &mut [u8]) {
    debug_assert!(data.len().is_multiple_of(AES_BLOCK));
    // Zero-copy reinterpret of the block-aligned byte slice as `[Block]`; the
    // remainder is empty because the length is a multiple of the block size.
    let (blocks, rest) = Array::<u8, _>::slice_as_chunks_mut(data);
    debug_assert!(rest.is_empty());
    dec.decrypt_blocks(blocks);
}
