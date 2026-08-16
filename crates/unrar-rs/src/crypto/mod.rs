//! AES key derivation and decryption for RAR archives.
//!
//! - RAR5: AES-256-CBC with PBKDF2-HMAC-SHA256 key derivation
//! - RAR4: AES-128-CBC with custom iterative SHA-1 key derivation
//!
//! Provides both batch decryption (`decrypt_data`) and streaming decryption
//! via [`DecryptingReader`], which wraps any `Read` source and decrypts
//! AES-CBC on-the-fly using the cipher backend's block-mode implementation.
//!
//! Includes a [`KdfCache`] that avoids re-deriving keys when the same
//! password+salt combination is used across multiple members (which is
//! the common case).
//!
//! All cryptographic primitives that touch the underlying crypto library live
//! behind the `backend` seam; the code in this module only ever calls that
//! seam, so a second backend can be added without editing shared logic.
//!
//! One deliberate exception: the RAR5 PBKDF2 loop. Its per-iteration
//! HMAC-SHA256 is [`kdf_hmac`], which runs on the `sha2` crate on *every*
//! backend so that a derivation of up to 2^24 iterations never crosses FFI.
//! That module is not a backend and has no alternative implementation; see its
//! docs. Everything else — AES, SHA-1, the non-KDF SHA-256 and HMAC uses — is
//! the selected backend's, unchanged.

mod backend;

// The RAR5 KDF's HMAC-SHA256. Deliberately NOT part of the backend seam: the
// derivation's inner loop runs on `sha2` regardless of which backend supplies
// AES / SHA-1 / the non-KDF SHA-256 uses. See the module docs for why.
mod kdf_hmac;

// Multi-way SIMD BLAKE2sp kernel (NEON + wasm simd128). Only compiled on the
// targets where `blake2s_simd` itself lacks a vector BLAKE2sp backend and this
// module is actually selected below.
#[cfg(any(
    target_arch = "aarch64",
    all(target_arch = "wasm32", target_feature = "simd128")
))]
mod blake2sp_simd;

// Differential tests comparing the two backends bit-for-bit; only compiled
// when both are built (native, both features enabled).
#[cfg(all(
    test,
    feature = "crypto-aws-lc",
    feature = "crypto-rust",
    not(target_family = "wasm")
))]
mod differential_tests;

use std::borrow::Cow;
use std::io::Read;
use std::sync::Mutex;

// The upstream BLAKE2sp is only used where the in-crate SIMD kernel is not
// selected (see `Blake2spHasher` below); gate the import to that config so it
// does not read as unused on aarch64 / wasm-simd128 builds.
#[cfg(not(any(
    target_arch = "aarch64",
    all(target_arch = "wasm32", target_feature = "simd128")
)))]
use blake2s_simd::blake2sp;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

// Always-compiled so `crate::test_support` can expose them to integration
// tests; the internal unit tests below also use these via `super::*`. They
// delegate to whichever crypto backend is active.
pub(crate) use backend::{encrypt_aes128_cbc_for_test, encrypt_aes256_cbc_for_test};

use crate::error::{RarError, RarResult};
use crate::rar4::types::Rar4EncryptionMethod;

pub const CRYPT5_KDF_LG2_COUNT_MAX: u8 = 24;

/// RAR standard crypto uses AWS-LC on supported targets. RAR4's
/// custom RAR29 SHA-1 KDF and legacy RAR 1.5/2.0 ciphers are RAR-specific
/// legacy algorithms, so they stay as local implementations.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rar5KeyMaterial {
    pub key: [u8; 32],
    pub hash_key: [u8; 32],
    pub psw_check: [u8; 8],
}

impl Drop for Rar5KeyMaterial {
    fn drop(&mut self) {
        self.key.zeroize();
        self.hash_key.zeroize();
        self.psw_check.zeroize();
    }
}

#[inline]
pub(crate) fn sha256_digest(data: &[u8]) -> [u8; 32] {
    backend::sha256(data)
}

fn fold_password_check(value: &[u8; 32]) -> [u8; 8] {
    let mut psw_check = [0u8; 8];
    for (index, byte) in value.iter().copied().enumerate() {
        psw_check[index % psw_check.len()] ^= byte;
    }
    psw_check
}

const MAXPASSWORD_RAR: usize = 128;
const RAR_PASSWORD_MAX_UNITS: usize = MAXPASSWORD_RAR - 1;

fn rar_password_compat(password: &str) -> Cow<'_, str> {
    let mut units = 0usize;
    for (index, ch) in password.char_indices() {
        let next = units + ch.len_utf16();
        if next > RAR_PASSWORD_MAX_UNITS {
            return Cow::Owned(password[..index].to_string());
        }
        units = next;
    }
    Cow::Borrowed(password)
}

const CP437_HIGH_CODEPOINTS: [u16; 128] = [
    0x00C7, 0x00FC, 0x00E9, 0x00E2, 0x00E4, 0x00E0, 0x00E5, 0x00E7, 0x00EA, 0x00EB, 0x00E8, 0x00EF,
    0x00EE, 0x00EC, 0x00C4, 0x00C5, 0x00C9, 0x00E6, 0x00C6, 0x00F4, 0x00F6, 0x00F2, 0x00FB, 0x00F9,
    0x00FF, 0x00D6, 0x00DC, 0x00A2, 0x00A3, 0x00A5, 0x20A7, 0x0192, 0x00E1, 0x00ED, 0x00F3, 0x00FA,
    0x00F1, 0x00D1, 0x00AA, 0x00BA, 0x00BF, 0x2310, 0x00AC, 0x00BD, 0x00BC, 0x00A1, 0x00AB, 0x00BB,
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556, 0x2555, 0x2563, 0x2551, 0x2557,
    0x255D, 0x255C, 0x255B, 0x2510, 0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x255E, 0x255F,
    0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x2567, 0x2568, 0x2564, 0x2565, 0x2559,
    0x2558, 0x2552, 0x2553, 0x256B, 0x256A, 0x2518, 0x250C, 0x2588, 0x2584, 0x258C, 0x2590, 0x2580,
    0x03B1, 0x00DF, 0x0393, 0x03C0, 0x03A3, 0x03C3, 0x00B5, 0x03C4, 0x03A6, 0x0398, 0x03A9, 0x03B4,
    0x221E, 0x03C6, 0x03B5, 0x2229, 0x2261, 0x00B1, 0x2265, 0x2264, 0x2320, 0x2321, 0x00F7, 0x2248,
    0x00B0, 0x2219, 0x00B7, 0x221A, 0x207F, 0x00B2, 0x25A0, 0x00A0,
];

fn encode_cp437_char(ch: char) -> u8 {
    let codepoint = ch as u32;
    if codepoint <= 0x7f {
        return codepoint as u8;
    }

    CP437_HIGH_CODEPOINTS
        .iter()
        .position(|&mapped| u32::from(mapped) == codepoint)
        .map(|index| 0x80u8 + index as u8)
        .unwrap_or(b'?')
}

fn rar_password_oem_bytes_compat(password: &str) -> Vec<u8> {
    rar_password_compat(password)
        .chars()
        .map(encode_cp437_char)
        .collect()
}

pub fn derive_rar5_material(
    password: &str,
    salt: &[u8; 16],
    kdf_count: u8,
) -> RarResult<Rar5KeyMaterial> {
    if kdf_count > CRYPT5_KDF_LG2_COUNT_MAX {
        return Err(RarError::UnsupportedEncryptionKdf {
            count: kdf_count,
            max: CRYPT5_KDF_LG2_COUNT_MAX,
        });
    }

    let count = 1u32 << kdf_count;
    let password = rar_password_compat(password);
    // The derivation's HMAC is `crypto::kdf_hmac`, not the backend seam: this
    // loop runs up to 2^24 times, so it goes straight to `sha2`'s SHA-256
    // compression on every backend rather than crossing FFI twice per
    // iteration. Everything else in this module still uses the backend.
    let password_mac = kdf_hmac::KdfHmacKey::new(password.as_bytes());

    let mut salt_block = [0u8; 20];
    salt_block[..salt.len()].copy_from_slice(salt);
    salt_block[19] = 1;

    let mut u = password_mac.sign(&salt_block);
    let mut fn_value = u;

    let mut key = [0u8; 32];
    let mut hash_key = [0u8; 32];
    let mut psw_check_value = [0u8; 32];

    for (rounds, output) in [
        (count.saturating_sub(1), &mut key),
        (16, &mut hash_key),
        (16, &mut psw_check_value),
    ] {
        for _ in 0..rounds {
            u = password_mac.sign(&u);
            for (acc, next) in fn_value.iter_mut().zip(u.iter()) {
                *acc ^= *next;
            }
        }
        *output = fn_value;
    }

    let mut psw_check = fold_password_check(&psw_check_value);
    let material = Rar5KeyMaterial {
        key,
        hash_key,
        psw_check,
    };

    salt_block.zeroize();
    u.zeroize();
    fn_value.zeroize();
    key.zeroize();
    hash_key.zeroize();
    psw_check_value.zeroize();
    psw_check.zeroize();

    Ok(material)
}

/// Derive AES-256 key from password and salt using PBKDF2-HMAC-SHA256.
///
/// RAR5 KDF: iterations = 1 << kdf_count.
/// Returns only the 32-byte key. IVs in RAR5 are read from the stream
/// (each encrypted block is preceded by a 16-byte IV), not derived.
pub fn derive_key(
    password: &str,
    salt: &[u8; 16],
    kdf_count: u8,
) -> RarResult<([u8; 32], [u8; 16])> {
    // IV is not derived — return zeros. Callers that need an IV read it
    // from the stream (header encryption) or from the file header (file
    // data encryption).
    let mut material = derive_rar5_material(password, salt, kdf_count)?;
    let key = material.key;
    material.key.zeroize();
    material.hash_key.zeroize();
    material.psw_check.zeroize();

    Ok((key, [0u8; 16]))
}

/// Decrypt data using AES-256-CBC.
///
/// The input must be a multiple of 16 bytes (AES block size).
/// Returns the decrypted data (no padding removal — RAR5 tracks exact sizes separately).
pub fn decrypt_data(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> RarResult<Vec<u8>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    if !data.len().is_multiple_of(16) {
        return Err(RarError::CorruptArchive {
            detail: format!(
                "encrypted data length {} is not a multiple of AES block size (16)",
                data.len()
            ),
        });
    }

    let mut buf = data.to_vec();
    let mut decryptor = CbcDecryptor::new(key, iv);
    decryptor.decrypt_blocks(&mut buf);

    Ok(buf)
}

/// Verify a password using the optional check value from the encryption header.
///
/// RAR5 uses a continuous PBKDF2 chain:
///   Key       = PBKDF2(password, salt, Count)       — AES-256 key
///   V1        = PBKDF2(password, salt, Count + 16)   — HashKey (for HMAC CRC)
///   V2        = PBKDF2(password, salt, Count + 32)   — PswCheckValue (for password check)
///   PswCheck  = XOR-fold V2 from 32 bytes into 8 bytes
///
/// The check_data field is 12 bytes: first 8 = PswCheck, last 4 = SHA256 checksum.
pub fn verify_password_check(
    password: &str,
    salt: &[u8; 16],
    kdf_count: u8,
    check_data: &[u8; 12],
) -> bool {
    derive_rar5_material(password, salt, kdf_count)
        .map(|mut material| {
            let matches = password_check_matches(&material.psw_check, check_data);
            material.key.zeroize();
            material.hash_key.zeroize();
            material.psw_check.zeroize();
            matches
        })
        .unwrap_or(false)
}

fn password_check_matches(psw_check: &[u8; 8], check_data: &[u8; 12]) -> bool {
    psw_check.as_slice().ct_eq(&check_data[..8]).into()
}

/// What a member's header lets a caller conclude about a candidate password,
/// **before** any of that member's bytes are decrypted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordCheck {
    /// The header carried a password-check value and this password reproduces
    /// it.
    ///
    /// That is the whole of the claim: the password matches what *this header
    /// states*. It is not a guarantee that decrypting yields the writer's
    /// plaintext, because the check value is 8 unauthenticated bytes in a
    /// header a hostile writer chooses. Forging them to the value a different
    /// password derives makes this variant say `Verified` for that password
    /// while every decrypted byte is garbage — see
    /// `forged_password_check_admits_a_wrong_password_and_the_keyed_member_gate_still_catches_it`
    /// in `tests/stored_layout_fixtures.rs`.
    ///
    /// The authority over the plaintext is the member's checksum, folded with
    /// the same password's hash key when the header keys it
    /// ([`convert_crc32_to_mac`] / [`convert_blake2_to_mac`]). A caller may use
    /// this variant to admit a password cheaply and to reject one for free; it
    /// must not use it to skip that gate before anything is kept.
    Verified,
    /// The header carried a password-check value and this password does not
    /// reproduce it. Every byte decrypted with it would be garbage, so nothing
    /// should be written on the strength of it.
    Wrong,
    /// The header carried no usable password-check value — the writer omitted
    /// it, or the value failed its own SHA-256 tag — so nothing can be
    /// concluded here. The password may still be right; the member's checksum
    /// gates are then the earliest detector.
    Unverifiable,
}

/// Check a candidate password against one member's RAR5 crypt facts.
///
/// The E-D1 admission surface: three outcomes, no key handed out, and a
/// [`KdfCache`] so a set whose members share a KDF tuple pays for the
/// derivation once. `psw_check` is
/// [`crate::RarVolumeMemberEncryptionFacts::psw_check`] — already validated
/// against its own tag by the parser, which is why the "claimed but corrupt"
/// case arrives here as `None` and reads as [`PasswordCheck::Unverifiable`].
///
/// A KDF count the crate refuses (over [`CRYPT5_KDF_LG2_COUNT_MAX`]) also
/// yields `Unverifiable`: the derivation never runs, so the password is
/// neither confirmed nor refuted. Such a member cannot be decrypted at all —
/// the caller learns that from the facts, not from here.
pub fn check_member_password(
    cache: &KdfCache,
    password: &str,
    salt: &[u8; 16],
    kdf_count_lg2: u8,
    psw_check: Option<&[u8; 12]>,
) -> PasswordCheck {
    let Some(psw_check) = psw_check else {
        return PasswordCheck::Unverifiable;
    };
    if kdf_count_lg2 > CRYPT5_KDF_LG2_COUNT_MAX {
        return PasswordCheck::Unverifiable;
    }
    match cache.derive_material_rar5(password, salt, kdf_count_lg2) {
        Ok(mut material) => {
            let matches = password_check_matches(&material.psw_check, psw_check);
            material.key.zeroize();
            material.hash_key.zeroize();
            material.psw_check.zeroize();
            if matches {
                PasswordCheck::Verified
            } else {
                PasswordCheck::Wrong
            }
        }
        Err(_) => PasswordCheck::Unverifiable,
    }
}

pub fn convert_crc32_to_mac(value: u32, key: &[u8; 32]) -> u32 {
    let digest = backend::hmac_sha256(&backend::hmac_sha256_key(key), &value.to_le_bytes());
    let mut mac = 0u32;
    for (index, byte) in digest.iter().copied().enumerate() {
        mac ^= (byte as u32) << ((index & 3) * 8);
    }
    mac
}

pub fn convert_blake2_to_mac(value: [u8; 32], key: &[u8; 32]) -> [u8; 32] {
    backend::hmac_sha256(&backend::hmac_sha256_key(key), &value)
}

/// Incremental BLAKE2sp hasher.
///
/// The public API (`new` / `update` / `finalize`) and its byte output are the
/// same on every target; only the backend differs. `blake2s_simd` ships only
/// AVX2/SSE4.1/portable backends, so on `aarch64` and `wasm32 + simd128` its
/// BLAKE2sp runs scalar; on exactly those targets we substitute the in-crate
/// `blake2sp_simd` NEON / `simd128` kernel.
/// Everywhere else (x86 AVX2, wasm without simd, other arches) it keeps calling
/// `blake2s_simd` unchanged. The output is byte-identical either way.
#[cfg(any(
    target_arch = "aarch64",
    all(target_arch = "wasm32", target_feature = "simd128")
))]
#[derive(Clone, Debug)]
pub struct Blake2spHasher {
    inner: blake2sp_simd::Blake2spState,
}

#[cfg(not(any(
    target_arch = "aarch64",
    all(target_arch = "wasm32", target_feature = "simd128")
)))]
#[derive(Clone, Debug)]
pub struct Blake2spHasher {
    inner: blake2sp::State,
}

impl Default for Blake2spHasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(
    target_arch = "aarch64",
    all(target_arch = "wasm32", target_feature = "simd128")
))]
impl Blake2spHasher {
    pub fn new() -> Self {
        Self {
            inner: blake2sp_simd::Blake2spState::new(),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub fn finalize(&self) -> [u8; 32] {
        self.inner.finalize()
    }
}

#[cfg(not(any(
    target_arch = "aarch64",
    all(target_arch = "wasm32", target_feature = "simd128")
)))]
impl Blake2spHasher {
    pub fn new() -> Self {
        Self {
            inner: blake2sp::State::new(),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub fn finalize(&self) -> [u8; 32] {
        *self.inner.clone().finalize().as_array()
    }
}

#[cfg(any(
    target_arch = "aarch64",
    all(target_arch = "wasm32", target_feature = "simd128")
))]
pub fn blake2sp_hash(data: &[u8]) -> [u8; 32] {
    blake2sp_simd::hash(data)
}

#[cfg(not(any(
    target_arch = "aarch64",
    all(target_arch = "wasm32", target_feature = "simd128")
)))]
pub fn blake2sp_hash(data: &[u8]) -> [u8; 32] {
    *blake2sp::blake2sp(data).as_array()
}

/// Re-export of the in-crate SIMD BLAKE2sp differential-corpus runner, used by
/// the `wasm32` validation harness (an example) to exercise the `simd128`
/// backend under `wasmtime`. `#[doc(hidden)]`: not part of the public API.
#[doc(hidden)]
#[cfg(any(
    target_arch = "aarch64",
    all(target_arch = "wasm32", target_feature = "simd128")
))]
pub use blake2sp_simd::{CorpusReport, differential_corpus};

/// The in-crate kernel's 4-leaf NEON group state, for the off-thread hash
/// pipeline's aarch64 worker arrangement (see
/// `crate::hash_pipeline::LEAVES_PER_WORKER`). Not public API: the pipeline is
/// the only caller, and `Blake2spHasher` remains the whole-tree entry point.
#[cfg(target_arch = "aarch64")]
#[cfg_attr(not(test), allow(unused_imports))]
pub(crate) use blake2sp_simd::{Blake2spLeafGroup, GROUP_LEAVES};

// =============================================================================
// KDF cache — avoids re-deriving keys for repeated password+salt combinations
// =============================================================================

const KDF_CACHE_SLOTS: usize = 4;

/// Cached RAR5 key derivation result.
#[derive(Debug)]
struct Kdf5Entry {
    password: String,
    salt: [u8; 16],
    kdf_count: u8,
    key: [u8; 32],
    hash_key: [u8; 32],
    psw_check: [u8; 8],
}

impl Drop for Kdf5Entry {
    fn drop(&mut self) {
        self.password.zeroize();
        self.salt.zeroize();
        self.kdf_count.zeroize();
        self.key.zeroize();
        self.hash_key.zeroize();
        self.psw_check.zeroize();
    }
}

/// Cached RAR4 key derivation result.
#[derive(Debug)]
struct Kdf3Entry {
    password: String,
    salt: Option<[u8; 8]>,
    key: [u8; 16],
    iv: [u8; 16],
}

impl Drop for Kdf3Entry {
    fn drop(&mut self) {
        self.password.zeroize();
        if let Some(salt) = self.salt.as_mut() {
            salt.zeroize();
        }
        self.salt = None;
        self.key.zeroize();
        self.iv.zeroize();
    }
}

/// Thread-safe KDF cache for repeated RAR3/RAR5 key derivations.
///
/// Stores the most recent key derivation results and returns cached values
/// when the same password+salt combination is requested again. This avoids
/// re-running expensive KDF iterations (262k SHA-1 for RAR4, up to 2^24
/// PBKDF2 rounds for RAR5) on every member in an encrypted archive.
#[derive(Debug)]
pub struct KdfCache {
    rar5: Mutex<(Vec<Kdf5Entry>, usize)>,
    rar4: Mutex<(Vec<Kdf3Entry>, usize)>,
}

impl KdfCache {
    pub fn new() -> Self {
        Self {
            rar5: Mutex::new((Vec::with_capacity(KDF_CACHE_SLOTS), 0)),
            rar4: Mutex::new((Vec::with_capacity(KDF_CACHE_SLOTS), 0)),
        }
    }

    pub fn derive_material_rar5(
        &self,
        password: &str,
        salt: &[u8; 16],
        kdf_count: u8,
    ) -> RarResult<Rar5KeyMaterial> {
        let mut guard = self.rar5.lock().unwrap();
        let (entries, pos) = &mut *guard;

        for entry in entries.iter() {
            if entry.password == password && entry.salt == *salt && entry.kdf_count == kdf_count {
                return Ok(Rar5KeyMaterial {
                    key: entry.key,
                    hash_key: entry.hash_key,
                    psw_check: entry.psw_check,
                });
            }
        }

        let material = derive_rar5_material(password, salt, kdf_count)?;

        let entry = Kdf5Entry {
            password: password.to_string(),
            salt: *salt,
            kdf_count,
            key: material.key,
            hash_key: material.hash_key,
            psw_check: material.psw_check,
        };

        if entries.len() < KDF_CACHE_SLOTS {
            entries.push(entry);
        } else {
            entries[*pos] = entry;
        }
        *pos = (*pos + 1) % KDF_CACHE_SLOTS;

        Ok(material)
    }

    /// Derive (or return cached) RAR5 AES-256 key.
    pub fn derive_key_rar5(
        &self,
        password: &str,
        salt: &[u8; 16],
        kdf_count: u8,
    ) -> RarResult<[u8; 32]> {
        Ok(self.derive_material_rar5(password, salt, kdf_count)?.key)
    }

    pub fn derive_hash_key_rar5(
        &self,
        password: &str,
        salt: &[u8; 16],
        kdf_count: u8,
    ) -> RarResult<[u8; 32]> {
        Ok(self
            .derive_material_rar5(password, salt, kdf_count)?
            .hash_key)
    }

    /// Verify password check value using cached data (avoids separate PBKDF2).
    pub fn verify_password_rar5(
        &self,
        password: &str,
        salt: &[u8; 16],
        kdf_count: u8,
        check_data: &[u8; 12],
    ) -> bool {
        self.derive_material_rar5(password, salt, kdf_count)
            .map(|material| password_check_matches(&material.psw_check, check_data))
            .unwrap_or(false)
    }

    /// Derive (or return cached) RAR4 AES-128 key and IV.
    pub fn derive_key_rar4(&self, password: &str, salt: Option<&[u8; 8]>) -> ([u8; 16], [u8; 16]) {
        let mut guard = self.rar4.lock().unwrap();
        let (entries, pos) = &mut *guard;

        // Check cache.
        for entry in entries.iter() {
            if entry.password == password && entry.salt.as_ref() == salt {
                return (entry.key, entry.iv);
            }
        }

        // Cache miss — derive key.
        let (key, iv) = rar4_derive_key(password, salt);

        let entry = Kdf3Entry {
            password: password.to_string(),
            salt: salt.copied(),
            key,
            iv,
        };

        if entries.len() < KDF_CACHE_SLOTS {
            entries.push(entry);
        } else {
            entries[*pos] = entry;
        }
        *pos = (*pos + 1) % KDF_CACHE_SLOTS;

        (key, iv)
    }

    #[cfg(test)]
    pub(crate) fn rar4_cached_entry_count(&self) -> usize {
        self.rar4.lock().unwrap().0.len()
    }

    #[cfg(test)]
    pub(crate) fn rar5_cached_entry_count(&self) -> usize {
        self.rar5.lock().unwrap().0.len()
    }
}

impl Default for KdfCache {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Legacy RAR4 file encryption and RAR30 AES key derivation
// =============================================================================

fn crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    for (index, entry) in table.iter_mut().enumerate() {
        let mut crc = index as u32;
        for _ in 0..8 {
            crc = if (crc & 1) != 0 {
                0xEDB8_8320 ^ (crc >> 1)
            } else {
                crc >> 1
            };
        }
        *entry = crc;
    }
    table
}

fn raw_get_u32(data: &[u8]) -> u32 {
    u32::from_le_bytes([data[0], data[1], data[2], data[3]])
}

fn raw_put_u32(value: u32, data: &mut [u8]) {
    data[..4].copy_from_slice(&value.to_le_bytes());
}

#[derive(Clone)]
struct Rar13Decryptor {
    key: [u8; 3],
}

impl Rar13Decryptor {
    fn new(password: &str) -> Self {
        let password = rar_password_compat(password);
        Self::new_from_bytes(password.as_bytes())
    }

    fn new_dos(password: &str) -> Self {
        let mut password = rar_password_oem_bytes_compat(password);
        let decryptor = Self::new_from_bytes(&password);
        password.zeroize();
        decryptor
    }

    fn new_from_bytes(password: &[u8]) -> Self {
        let mut key = [0u8; 3];
        for &byte in password {
            key[0] = key[0].wrapping_add(byte);
            key[1] ^= byte;
            key[2] = key[2].wrapping_add(byte).rotate_left(1);
        }
        Self { key }
    }

    fn new_comment() -> Self {
        Self { key: [0, 7, 77] }
    }

    fn decrypt(&mut self, data: &mut [u8]) {
        for byte in data {
            self.key[1] = self.key[1].wrapping_add(self.key[2]);
            self.key[0] = self.key[0].wrapping_add(self.key[1]);
            *byte = byte.wrapping_sub(self.key[0]);
        }
    }
}

pub(crate) fn decrypt_rar14_packed_comment(data: &mut [u8]) {
    Rar13Decryptor::new_comment().decrypt(data);
}

impl Drop for Rar13Decryptor {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[derive(Clone)]
struct Rar15Decryptor {
    key: [u16; 4],
    crc_tab: [u32; 256],
}

impl Rar15Decryptor {
    fn new(password: &str) -> Self {
        let password = rar_password_compat(password);
        Self::new_from_bytes(password.as_bytes())
    }

    fn new_dos(password: &str) -> Self {
        let mut password = rar_password_oem_bytes_compat(password);
        let decryptor = Self::new_from_bytes(&password);
        password.zeroize();
        decryptor
    }

    fn new_from_bytes(password: &[u8]) -> Self {
        let crc_tab = crc32_table();
        let psw_crc = !crc32fast::hash(password);
        let mut key = [(psw_crc & 0xFFFF) as u16, (psw_crc >> 16) as u16, 0, 0];

        for &byte in password {
            key[2] ^= (byte as u16) ^ (crc_tab[byte as usize] as u16);
            key[3] = key[3].wrapping_add(byte as u16 + ((crc_tab[byte as usize] >> 16) as u16));
        }

        Self { key, crc_tab }
    }

    fn decrypt(&mut self, data: &mut [u8]) {
        for byte in data {
            self.key[0] = self.key[0].wrapping_add(0x1234);
            let crc = self.crc_tab[((self.key[0] & 0x01FE) >> 1) as usize];
            self.key[1] ^= crc as u16;
            self.key[2] = self.key[2].wrapping_sub((crc >> 16) as u16);
            self.key[0] ^= self.key[2];
            self.key[3] = self.key[3].rotate_right(1) ^ self.key[1];
            self.key[3] = self.key[3].rotate_right(1);
            self.key[0] ^= self.key[3];
            *byte ^= (self.key[0] >> 8) as u8;
        }
    }
}

impl Drop for Rar15Decryptor {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[derive(Clone)]
struct Rar20Decryptor {
    key: [u32; 4],
    subst: [u8; 256],
    crc_tab: [u32; 256],
}

impl Rar20Decryptor {
    fn new(password: &str) -> Self {
        let password = rar_password_compat(password);
        Self::new_from_bytes(password.as_bytes())
    }

    fn new_dos(password: &str) -> Self {
        let mut password = rar_password_oem_bytes_compat(password);
        let decryptor = Self::new_from_bytes(&password);
        password.zeroize();
        decryptor
    }

    fn new_from_bytes(pwd_bytes: &[u8]) -> Self {
        const INIT_SUBST_TABLE20: [u8; 256] = [
            215, 19, 149, 35, 73, 197, 192, 205, 249, 28, 16, 119, 48, 221, 2, 42, 232, 1, 177,
            233, 14, 88, 219, 25, 223, 195, 244, 90, 87, 239, 153, 137, 255, 199, 147, 70, 92, 66,
            246, 13, 216, 40, 62, 29, 217, 230, 86, 6, 71, 24, 171, 196, 101, 113, 218, 123, 93,
            91, 163, 178, 202, 67, 44, 235, 107, 250, 75, 234, 49, 167, 125, 211, 83, 114, 157,
            144, 32, 193, 143, 36, 158, 124, 247, 187, 89, 214, 141, 47, 121, 228, 61, 130, 213,
            194, 174, 251, 97, 110, 54, 229, 115, 57, 152, 94, 105, 243, 212, 55, 209, 245, 63, 11,
            164, 200, 31, 156, 81, 176, 227, 21, 76, 99, 139, 188, 127, 17, 248, 51, 207, 120, 189,
            210, 8, 226, 41, 72, 183, 203, 135, 165, 166, 60, 98, 7, 122, 38, 155, 170, 69, 172,
            252, 238, 39, 134, 59, 128, 236, 27, 240, 80, 131, 3, 85, 206, 145, 79, 154, 142, 159,
            220, 201, 133, 74, 64, 20, 129, 224, 185, 138, 103, 173, 182, 43, 34, 254, 82, 198,
            151, 231, 180, 58, 10, 118, 26, 102, 12, 50, 132, 22, 191, 136, 111, 162, 179, 45, 4,
            148, 108, 161, 56, 78, 126, 242, 222, 15, 175, 146, 23, 33, 241, 181, 190, 77, 225, 0,
            46, 169, 186, 68, 95, 237, 65, 53, 208, 253, 168, 9, 18, 100, 52, 116, 184, 160, 96,
            109, 37, 30, 106, 140, 104, 150, 5, 204, 117, 112, 84,
        ];

        let crc_tab = crc32_table();
        let key = [0xD3A3_B879, 0x3F6D_12F7, 0x7515_A235, 0xA4E7_F123];
        let mut subst = INIT_SUBST_TABLE20;

        for j in 0..256u32 {
            let mut i = 0usize;
            while i < pwd_bytes.len() {
                let left = pwd_bytes[i];
                let right = pwd_bytes.get(i + 1).copied().unwrap_or(0);
                let mut n1 = (crc_tab[left.wrapping_sub(j as u8) as usize] & 0xFF) as u8;
                let n2 = (crc_tab[right.wrapping_add(j as u8) as usize] & 0xFF) as u8;
                let mut k = 1usize;
                while n1 != n2 {
                    let swap_index = (n1 as usize + i + k) & 0xFF;
                    subst.swap(n1 as usize, swap_index);
                    n1 = n1.wrapping_add(1);
                    k += 1;
                }
                i += 2;
            }
        }

        let mut padded = pwd_bytes.to_vec();
        let remainder = padded.len() & (AES_BLOCK - 1);
        if remainder != 0 {
            padded.resize((padded.len() + AES_BLOCK - 1) & !(AES_BLOCK - 1), 0);
        }

        let mut decryptor = Self {
            key,
            subst,
            crc_tab,
        };
        for chunk in padded.chunks_exact_mut(AES_BLOCK) {
            decryptor.encrypt_block(chunk);
        }
        padded.zeroize();
        decryptor
    }

    fn subst_long(&self, value: u32) -> u32 {
        self.subst[(value & 0xFF) as usize] as u32
            | ((self.subst[((value >> 8) & 0xFF) as usize] as u32) << 8)
            | ((self.subst[((value >> 16) & 0xFF) as usize] as u32) << 16)
            | ((self.subst[((value >> 24) & 0xFF) as usize] as u32) << 24)
    }

    fn update_keys(&mut self, data: &[u8; AES_BLOCK]) {
        for chunk in data.chunks_exact(4) {
            self.key[0] ^= self.crc_tab[chunk[0] as usize];
            self.key[1] ^= self.crc_tab[chunk[1] as usize];
            self.key[2] ^= self.crc_tab[chunk[2] as usize];
            self.key[3] ^= self.crc_tab[chunk[3] as usize];
        }
    }

    fn encrypt_block(&mut self, block: &mut [u8]) {
        const NROUNDS: usize = 32;

        let mut a = raw_get_u32(&block[0..4]) ^ self.key[0];
        let mut b = raw_get_u32(&block[4..8]) ^ self.key[1];
        let mut c = raw_get_u32(&block[8..12]) ^ self.key[2];
        let mut d = raw_get_u32(&block[12..16]) ^ self.key[3];

        for round in 0..NROUNDS {
            let t = (c.wrapping_add(d.rotate_left(11))) ^ self.key[round & 3];
            let ta = a ^ self.subst_long(t);
            let t = (d ^ c.rotate_left(17)).wrapping_add(self.key[round & 3]);
            let tb = b ^ self.subst_long(t);
            a = c;
            b = d;
            c = ta;
            d = tb;
        }

        raw_put_u32(c ^ self.key[0], &mut block[0..4]);
        raw_put_u32(d ^ self.key[1], &mut block[4..8]);
        raw_put_u32(a ^ self.key[2], &mut block[8..12]);
        raw_put_u32(b ^ self.key[3], &mut block[12..16]);

        let mut ciphertext = [0u8; AES_BLOCK];
        ciphertext.copy_from_slice(block);
        self.update_keys(&ciphertext);
    }

    fn decrypt_block(&mut self, block: &mut [u8]) {
        const NROUNDS: i32 = 32;

        let mut ciphertext = [0u8; AES_BLOCK];
        ciphertext.copy_from_slice(block);

        let mut a = raw_get_u32(&block[0..4]) ^ self.key[0];
        let mut b = raw_get_u32(&block[4..8]) ^ self.key[1];
        let mut c = raw_get_u32(&block[8..12]) ^ self.key[2];
        let mut d = raw_get_u32(&block[12..16]) ^ self.key[3];

        for round in (0..NROUNDS).rev() {
            let t = (c.wrapping_add(d.rotate_left(11))) ^ self.key[(round as usize) & 3];
            let ta = a ^ self.subst_long(t);
            let t = (d ^ c.rotate_left(17)).wrapping_add(self.key[(round as usize) & 3]);
            let tb = b ^ self.subst_long(t);
            a = c;
            b = d;
            c = ta;
            d = tb;
        }

        raw_put_u32(c ^ self.key[0], &mut block[0..4]);
        raw_put_u32(d ^ self.key[1], &mut block[4..8]);
        raw_put_u32(a ^ self.key[2], &mut block[8..12]);
        raw_put_u32(b ^ self.key[3], &mut block[12..16]);
        self.update_keys(&ciphertext);
    }
}

impl Drop for Rar20Decryptor {
    fn drop(&mut self) {
        self.key.zeroize();
        self.subst.zeroize();
    }
}

/// RAR4 key derivation iteration count.
const RAR4_KDF_ITERATIONS: u32 = 0x40000; // 262144

/// Copy a compile-time-constant `N`-byte window at `off`. Constant width, so
/// this lowers to plain loads/stores — never a `memcpy` call.
#[inline(always)]
#[cfg(not(target_arch = "aarch64"))]
fn cp<const N: usize>(dst: &mut [u8], src: &[u8], off: usize) {
    let chunk: [u8; N] = src[off..off + N]
        .try_into()
        .expect("cp: constant-size window");
    dst[off..off + N].copy_from_slice(&chunk);
}

/// Copy `src` into `dst` (equal lengths, `n <= 64`) without reaching libc.
///
/// The RAR3/RAR4 KDF drives `Rar29Sha1` through 262144 rounds of 1..63-byte
/// partial-block fills. Expressed as `copy_from_slice` those become one
/// dynamic-length `memcpy` call each. musl services short copies with
/// `rep movs`, whose startup cost is severely penalized on Intel Golden Cove
/// (Alder Lake / Sapphire Rapids): profiling a musl-static build put 53% of
/// all encrypted-extraction cycles in memcpy, 44.9% on the `rep movsq` itself,
/// while the SHA-NI transform ran nearly free. glibc builds hide this behind
/// their own inline small-copy path, which is why only static fleet builds
/// showed the tax.
///
/// Every copy below is constant-width and there is no loop, so nothing here
/// can be turned back into a `memcpy` call by LLVM's loop-idiom pass. Size
/// classes use the standard two-overlapping-blocks trick, so at most two
/// stores cover any length in a class.
#[inline(always)]
fn copy_small(dst: &mut [u8], src: &[u8]) {
    let n = src.len();
    debug_assert_eq!(dst.len(), n, "copy_small: length mismatch");
    debug_assert!(n <= 64, "copy_small: {n} exceeds the 64-byte size classes");
    // On aarch64 the plain libc path wins: musl's aarch64 memcpy is good, and
    // fleet round 2 measured this cascade 1.7-4.0% SLOWER than memcpy on the
    // encrypted cases across three ARM microarchitectures (A72/N1/V2, all-case
    // medians flat). The cascade exists for x86, where musl's rep-movs memcpy
    // is what cost the KDF 2x on Intel cores.
    #[cfg(target_arch = "aarch64")]
    {
        dst.copy_from_slice(src);
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        if n >= 32 {
            cp::<32>(dst, src, 0);
            cp::<32>(dst, src, n - 32);
        } else if n >= 16 {
            cp::<16>(dst, src, 0);
            cp::<16>(dst, src, n - 16);
        } else if n >= 8 {
            cp::<8>(dst, src, 0);
            cp::<8>(dst, src, n - 8);
        } else if n >= 4 {
            cp::<4>(dst, src, 0);
            cp::<4>(dst, src, n - 4);
        } else if n >= 2 {
            cp::<2>(dst, src, 0);
            cp::<2>(dst, src, n - 2);
        } else if n == 1 {
            dst[0] = src[0];
        }
    }
}

#[derive(Clone)]
struct Rar29Sha1 {
    state: [u32; 5],
    buffer: [u8; 64],
    count: u64,
}

impl Drop for Rar29Sha1 {
    fn drop(&mut self) {
        self.state.zeroize();
        self.buffer.zeroize();
        self.count.zeroize();
    }
}

impl Rar29Sha1 {
    fn new() -> Self {
        Self {
            state: [
                0x6745_2301,
                0xefcd_ab89,
                0x98ba_dcfe,
                0x1032_5476,
                0xc3d2_e1f0,
            ],
            buffer: [0; 64],
            count: 0,
        }
    }

    fn process(&mut self, data: &[u8]) {
        let mut i = 0usize;
        let mut j = (self.count & 63) as usize;
        self.count += data.len() as u64;

        if j + data.len() > 63 {
            i = 64 - j;
            copy_small(&mut self.buffer[j..64], &data[..i]);
            self.transform_buffer();

            while i + 63 < data.len() {
                self.transform_block((&data[i..i + 64]).try_into().unwrap());
                i += 64;
            }
            j = 0;
        }

        if data.len() > i {
            let len = data.len() - i;
            copy_small(&mut self.buffer[j..j + len], &data[i..]);
        }
    }

    fn process_rar29(&mut self, data: &mut [u8]) {
        let mut i = 0usize;
        let mut j = (self.count & 63) as usize;
        self.count += data.len() as u64;

        if j + data.len() > 63 {
            i = 64 - j;
            copy_small(&mut self.buffer[j..64], &data[..i]);
            self.transform_buffer();

            while i + 63 < data.len() {
                let workspace = self.transform_block((&data[i..i + 64]).try_into().unwrap());
                for (chunk, word) in data[i..i + 64].chunks_exact_mut(4).zip(workspace) {
                    chunk.copy_from_slice(&word.to_le_bytes());
                }
                i += 64;
            }
            j = 0;
        }

        if data.len() > i {
            let len = data.len() - i;
            copy_small(&mut self.buffer[j..j + len], &data[i..]);
        }
    }

    fn finish_words(mut self) -> [u32; 5] {
        let bit_length = self.count * 8;
        let mut buf_pos = (self.count & 63) as usize;
        self.buffer[buf_pos] = 0x80;
        buf_pos += 1;

        if buf_pos != 56 {
            if buf_pos > 56 {
                self.buffer[buf_pos..64].fill(0);
                self.transform_buffer();
                buf_pos = 0;
            }
            self.buffer[buf_pos..56].fill(0);
        }

        self.buffer[56..60].copy_from_slice(&((bit_length >> 32) as u32).to_be_bytes());
        self.buffer[60..64].copy_from_slice(&(bit_length as u32).to_be_bytes());
        self.transform_buffer();
        self.state
    }

    fn transform_buffer(&mut self) -> [u32; 16] {
        let block = self.buffer;
        self.transform_block(&block)
    }

    /// One SHA-1 block. Returns the final 16 message-schedule words
    /// W[64..80) — `process_rar29` writes them back over the input to
    /// replicate WinRAR's buggy in-place RAR29 SHA-1.
    fn transform_block(&mut self, block: &[u8; 64]) -> [u32; 16] {
        #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
        {
            if sha1_hw_enabled() {
                // SAFETY: the required target features were verified at runtime.
                return unsafe { sha1_hw::transform_block(&mut self.state, block) };
            }
        }
        // Below the SHA-extension line x86-64 gets the interleaved vector
        // schedule ported from AWS-LC (see `sha1_x86_vec`). The shape is
        // load-bearing: an earlier SSSE3 variant with the schedule computed
        // 4-wide *up front* lost to this unrolled scalar on native x86 —
        // 0.788x on Golden Cove, 0.860x on Gracemont (i5-1240P, 400k-block
        // probe, 2026-08-15) — because the scalar's schedule work already
        // rides in the round chain's ILP slack, so hoisting it into vector
        // registers only added domain-crossing overhead with nothing to
        // overlap. Do not rebuild that shape.
        #[cfg(target_arch = "x86_64")]
        {
            match sha1_x86_vec::tier() {
                // SAFETY: `tier()` proved the CPU carries the exact feature
                // set each entry point is declared with.
                sha1_x86_vec::Tier::Avx2 => {
                    return unsafe { sha1_x86_vec::transform_block_avx2(&mut self.state, block) };
                }
                sha1_x86_vec::Tier::Ssse3 => {
                    return unsafe { sha1_x86_vec::transform_block_ssse3(&mut self.state, block) };
                }
                sha1_x86_vec::Tier::None => {}
            }
        }
        self.transform_block_scalar(block)
    }

    /// Fully unrolled: the KDF spends 79-93% of encrypted rar3/rar4 wall time
    /// in this function on hosts without SHA extensions, and a rolled loop
    /// cannot be competitive there — the per-iteration round-class dispatch
    /// and the a..e rotation cost ~30 instructions and ~5 branches per round,
    /// where unrar's own unrolled SHA-1 spends ~13 and none (measured from
    /// both shipped binaries; rar3/4-encrypted ran 0.55-0.73x oracle on every
    /// no-SHA-NI x86 host until this was unrolled to the same shape). The
    /// rotation is absorbed by static argument order, the section constants
    /// are baked, and the W ring uses literal indices so its addressing folds
    /// to constant offsets.
    fn transform_block_scalar(&mut self, block: &[u8; 64]) -> [u32; 16] {
        let mut w = [0u32; 16];
        for (word, chunk) in w.iter_mut().zip(block.chunks_exact(4)) {
            *word = u32::from_be_bytes(chunk.try_into().unwrap());
        }

        let [mut a, mut b, mut c, mut d, mut e] = self.state;

        macro_rules! sched {
            ($i:literal) => {{
                let value = (w[($i + 13) & 15] ^ w[($i + 8) & 15] ^ w[($i + 2) & 15] ^ w[$i & 15])
                    .rotate_left(1);
                w[$i & 15] = value;
                value
            }};
        }
        macro_rules! rnd {
            ($a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $f:expr, $k:literal, $w:expr) => {{
                $e = $e
                    .wrapping_add($a.rotate_left(5))
                    .wrapping_add($f)
                    .wrapping_add($k)
                    .wrapping_add($w);
                $b = $b.rotate_left(30);
            }};
        }
        macro_rules! r1 {
            ($a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $w:expr) => {
                rnd!(
                    $a,
                    $b,
                    $c,
                    $d,
                    $e,
                    ($b & ($c ^ $d)) ^ $d,
                    0x5a82_7999u32,
                    $w
                )
            };
        }
        macro_rules! r2 {
            ($a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $w:expr) => {
                rnd!($a, $b, $c, $d, $e, $b ^ $c ^ $d, 0x6ed9_eba1u32, $w)
            };
        }
        macro_rules! r3 {
            ($a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $w:expr) => {
                rnd!(
                    $a,
                    $b,
                    $c,
                    $d,
                    $e,
                    (($b | $c) & $d) | ($b & $c),
                    0x8f1b_bcdcu32,
                    $w
                )
            };
        }
        macro_rules! r4 {
            ($a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $w:expr) => {
                rnd!($a, $b, $c, $d, $e, $b ^ $c ^ $d, 0xca62_c1d6u32, $w)
            };
        }

        r1!(a, b, c, d, e, w[0]);
        r1!(e, a, b, c, d, w[1]);
        r1!(d, e, a, b, c, w[2]);
        r1!(c, d, e, a, b, w[3]);
        r1!(b, c, d, e, a, w[4]);
        r1!(a, b, c, d, e, w[5]);
        r1!(e, a, b, c, d, w[6]);
        r1!(d, e, a, b, c, w[7]);
        r1!(c, d, e, a, b, w[8]);
        r1!(b, c, d, e, a, w[9]);
        r1!(a, b, c, d, e, w[10]);
        r1!(e, a, b, c, d, w[11]);
        r1!(d, e, a, b, c, w[12]);
        r1!(c, d, e, a, b, w[13]);
        r1!(b, c, d, e, a, w[14]);
        r1!(a, b, c, d, e, w[15]);
        r1!(e, a, b, c, d, sched!(16));
        r1!(d, e, a, b, c, sched!(17));
        r1!(c, d, e, a, b, sched!(18));
        r1!(b, c, d, e, a, sched!(19));

        r2!(a, b, c, d, e, sched!(20));
        r2!(e, a, b, c, d, sched!(21));
        r2!(d, e, a, b, c, sched!(22));
        r2!(c, d, e, a, b, sched!(23));
        r2!(b, c, d, e, a, sched!(24));
        r2!(a, b, c, d, e, sched!(25));
        r2!(e, a, b, c, d, sched!(26));
        r2!(d, e, a, b, c, sched!(27));
        r2!(c, d, e, a, b, sched!(28));
        r2!(b, c, d, e, a, sched!(29));
        r2!(a, b, c, d, e, sched!(30));
        r2!(e, a, b, c, d, sched!(31));
        r2!(d, e, a, b, c, sched!(32));
        r2!(c, d, e, a, b, sched!(33));
        r2!(b, c, d, e, a, sched!(34));
        r2!(a, b, c, d, e, sched!(35));
        r2!(e, a, b, c, d, sched!(36));
        r2!(d, e, a, b, c, sched!(37));
        r2!(c, d, e, a, b, sched!(38));
        r2!(b, c, d, e, a, sched!(39));

        r3!(a, b, c, d, e, sched!(40));
        r3!(e, a, b, c, d, sched!(41));
        r3!(d, e, a, b, c, sched!(42));
        r3!(c, d, e, a, b, sched!(43));
        r3!(b, c, d, e, a, sched!(44));
        r3!(a, b, c, d, e, sched!(45));
        r3!(e, a, b, c, d, sched!(46));
        r3!(d, e, a, b, c, sched!(47));
        r3!(c, d, e, a, b, sched!(48));
        r3!(b, c, d, e, a, sched!(49));
        r3!(a, b, c, d, e, sched!(50));
        r3!(e, a, b, c, d, sched!(51));
        r3!(d, e, a, b, c, sched!(52));
        r3!(c, d, e, a, b, sched!(53));
        r3!(b, c, d, e, a, sched!(54));
        r3!(a, b, c, d, e, sched!(55));
        r3!(e, a, b, c, d, sched!(56));
        r3!(d, e, a, b, c, sched!(57));
        r3!(c, d, e, a, b, sched!(58));
        r3!(b, c, d, e, a, sched!(59));

        r4!(a, b, c, d, e, sched!(60));
        r4!(e, a, b, c, d, sched!(61));
        r4!(d, e, a, b, c, sched!(62));
        r4!(c, d, e, a, b, sched!(63));
        r4!(b, c, d, e, a, sched!(64));
        r4!(a, b, c, d, e, sched!(65));
        r4!(e, a, b, c, d, sched!(66));
        r4!(d, e, a, b, c, sched!(67));
        r4!(c, d, e, a, b, sched!(68));
        r4!(b, c, d, e, a, sched!(69));
        r4!(a, b, c, d, e, sched!(70));
        r4!(e, a, b, c, d, sched!(71));
        r4!(d, e, a, b, c, sched!(72));
        r4!(c, d, e, a, b, sched!(73));
        r4!(b, c, d, e, a, sched!(74));
        r4!(a, b, c, d, e, sched!(75));
        r4!(e, a, b, c, d, sched!(76));
        r4!(d, e, a, b, c, sched!(77));
        r4!(c, d, e, a, b, sched!(78));
        r4!(b, c, d, e, a, sched!(79));

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);

        w
    }

    /// The pre-unroll rolled loop, kept verbatim as the differential-test
    /// reference for `transform_block_scalar` — including the RAR29 contract
    /// that the returned array is the final schedule words W[64..80).
    #[cfg(test)]
    fn transform_block_scalar_reference(&mut self, block: &[u8; 64]) -> [u32; 16] {
        let mut workspace = [0u32; 16];
        for (word, chunk) in workspace.iter_mut().zip(block.chunks_exact(4)) {
            *word = u32::from_be_bytes(chunk.try_into().unwrap());
        }

        let [mut a, mut b, mut c, mut d, mut e] = self.state;
        for i in 0..80 {
            let w = if i < 16 {
                workspace[i]
            } else {
                let value = (workspace[(i + 13) & 15]
                    ^ workspace[(i + 8) & 15]
                    ^ workspace[(i + 2) & 15]
                    ^ workspace[i & 15])
                    .rotate_left(1);
                workspace[i & 15] = value;
                value
            };
            let (f, k) = match i {
                0..=19 => (((b & (c ^ d)) ^ d), 0x5a82_7999),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                40..=59 => ((((b | c) & d) | (b & c)), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);

        workspace
    }
}

/// Setting `WEAVER_UNRAR_SHA1_HW=0` pins the scalar fallback so SHA-capable
/// hardware can A/B the no-SHA-extension tier without a rebuild.
#[cfg(target_arch = "aarch64")]
fn sha1_hw_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| {
        if std::env::var_os("WEAVER_UNRAR_SHA1_HW").is_some_and(|v| v == "0") {
            return false;
        }
        std::arch::is_aarch64_feature_detected!("sha2")
    })
}

/// Setting `WEAVER_UNRAR_SHA1_HW=0` pins the scalar fallback so SHA-capable
/// hardware can A/B the no-SHA-NI tier without a rebuild. Setting
/// `WEAVER_UNRAR_SHA1_X86` to a tier name stands this path down too — without
/// that, the vector tiers below would be unmeasurable end to end on exactly
/// the hosts most likely to be doing the measuring, since SHA-NI would always
/// take the block first.
#[cfg(target_arch = "x86_64")]
fn sha1_hw_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| {
        if std::env::var_os("WEAVER_UNRAR_SHA1_HW").is_some_and(|v| v == "0") {
            return false;
        }
        if std::env::var_os("WEAVER_UNRAR_SHA1_X86").is_some_and(|v| v == "ssse3" || v == "avx2") {
            return false;
        }
        std::arch::is_x86_feature_detected!("sha")
            && std::arch::is_x86_feature_detected!("sse4.1")
            && std::arch::is_x86_feature_detected!("ssse3")
    })
}

/// Portable fallback: no hardware SHA-1 block transform exists off x86_64 /
/// aarch64 (e.g. wasm32), so the scalar path is always taken there. On such
/// targets the sole caller in `transform_block` is `cfg`-compiled out, so this
/// is a deliberately-unused portability placeholder that keeps the symbol
/// defined for every architecture.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[allow(dead_code)]
fn sha1_hw_enabled() -> bool {
    false
}

/// x86 SHA-extension (SHA-NI) SHA-1 block transform — the x86 twin of the
/// aarch64 module below; see its docs for the schedule-writeback contract.
#[cfg(target_arch = "x86_64")]
mod sha1_hw {
    use std::arch::x86_64::*;

    /// Process one 64-byte block, updating `state` and returning the final
    /// 16 message-schedule words W[64..80).
    #[target_feature(enable = "sha,sse4.1,ssse3")]
    pub fn transform_block(state: &mut [u32; 5], block: &[u8; 64]) -> [u32; 16] {
        unsafe {
            // Byte shuffle producing big-endian dwords with W0 in the high
            // lane: each message register holds [W3, W2, W1, W0].
            let mask = _mm_set_epi64x(0x0001_0203_0405_0607, 0x0809_0a0b_0c0d_0e0f);

            let mut abcd = _mm_loadu_si128(state.as_ptr() as *const __m128i);
            abcd = _mm_shuffle_epi32::<0x1B>(abcd);
            let mut e0 = _mm_set_epi32(state[4] as i32, 0, 0, 0);
            let abcd_save = abcd;
            let e_save = e0;
            let mut e1;

            let ptr = block.as_ptr() as *const __m128i;
            let mut m0 = _mm_shuffle_epi8(_mm_loadu_si128(ptr), mask);
            let mut m1 = _mm_shuffle_epi8(_mm_loadu_si128(ptr.add(1)), mask);
            let mut m2 = _mm_shuffle_epi8(_mm_loadu_si128(ptr.add(2)), mask);
            let mut m3 = _mm_shuffle_epi8(_mm_loadu_si128(ptr.add(3)), mask);

            // Rounds 0-3
            e0 = _mm_add_epi32(e0, m0);
            e1 = abcd;
            abcd = _mm_sha1rnds4_epu32::<0>(abcd, e0);
            // Rounds 4-7
            e1 = _mm_sha1nexte_epu32(e1, m1);
            e0 = abcd;
            abcd = _mm_sha1rnds4_epu32::<0>(abcd, e1);
            m0 = _mm_sha1msg1_epu32(m0, m1);
            // Rounds 8-11
            e0 = _mm_sha1nexte_epu32(e0, m2);
            e1 = abcd;
            abcd = _mm_sha1rnds4_epu32::<0>(abcd, e0);
            m1 = _mm_sha1msg1_epu32(m1, m2);
            m0 = _mm_xor_si128(m0, m2);
            // Rounds 12-15
            e1 = _mm_sha1nexte_epu32(e1, m3);
            e0 = abcd;
            m0 = _mm_sha1msg2_epu32(m0, m3);
            abcd = _mm_sha1rnds4_epu32::<0>(abcd, e1);
            m2 = _mm_sha1msg1_epu32(m2, m3);
            m1 = _mm_xor_si128(m1, m3);
            // Rounds 16-19
            e0 = _mm_sha1nexte_epu32(e0, m0);
            e1 = abcd;
            m1 = _mm_sha1msg2_epu32(m1, m0);
            abcd = _mm_sha1rnds4_epu32::<0>(abcd, e0);
            m3 = _mm_sha1msg1_epu32(m3, m0);
            m2 = _mm_xor_si128(m2, m0);
            // Rounds 20-23
            e1 = _mm_sha1nexte_epu32(e1, m1);
            e0 = abcd;
            m2 = _mm_sha1msg2_epu32(m2, m1);
            abcd = _mm_sha1rnds4_epu32::<1>(abcd, e1);
            m0 = _mm_sha1msg1_epu32(m0, m1);
            m3 = _mm_xor_si128(m3, m1);
            // Rounds 24-27
            e0 = _mm_sha1nexte_epu32(e0, m2);
            e1 = abcd;
            m3 = _mm_sha1msg2_epu32(m3, m2);
            abcd = _mm_sha1rnds4_epu32::<1>(abcd, e0);
            m1 = _mm_sha1msg1_epu32(m1, m2);
            m0 = _mm_xor_si128(m0, m2);
            // Rounds 28-31
            e1 = _mm_sha1nexte_epu32(e1, m3);
            e0 = abcd;
            m0 = _mm_sha1msg2_epu32(m0, m3);
            abcd = _mm_sha1rnds4_epu32::<1>(abcd, e1);
            m2 = _mm_sha1msg1_epu32(m2, m3);
            m1 = _mm_xor_si128(m1, m3);
            // Rounds 32-35
            e0 = _mm_sha1nexte_epu32(e0, m0);
            e1 = abcd;
            m1 = _mm_sha1msg2_epu32(m1, m0);
            abcd = _mm_sha1rnds4_epu32::<1>(abcd, e0);
            m3 = _mm_sha1msg1_epu32(m3, m0);
            m2 = _mm_xor_si128(m2, m0);
            // Rounds 36-39
            e1 = _mm_sha1nexte_epu32(e1, m1);
            e0 = abcd;
            m2 = _mm_sha1msg2_epu32(m2, m1);
            abcd = _mm_sha1rnds4_epu32::<1>(abcd, e1);
            m0 = _mm_sha1msg1_epu32(m0, m1);
            m3 = _mm_xor_si128(m3, m1);
            // Rounds 40-43
            e0 = _mm_sha1nexte_epu32(e0, m2);
            e1 = abcd;
            m3 = _mm_sha1msg2_epu32(m3, m2);
            abcd = _mm_sha1rnds4_epu32::<2>(abcd, e0);
            m1 = _mm_sha1msg1_epu32(m1, m2);
            m0 = _mm_xor_si128(m0, m2);
            // Rounds 44-47
            e1 = _mm_sha1nexte_epu32(e1, m3);
            e0 = abcd;
            m0 = _mm_sha1msg2_epu32(m0, m3);
            abcd = _mm_sha1rnds4_epu32::<2>(abcd, e1);
            m2 = _mm_sha1msg1_epu32(m2, m3);
            m1 = _mm_xor_si128(m1, m3);
            // Rounds 48-51
            e0 = _mm_sha1nexte_epu32(e0, m0);
            e1 = abcd;
            m1 = _mm_sha1msg2_epu32(m1, m0);
            abcd = _mm_sha1rnds4_epu32::<2>(abcd, e0);
            m3 = _mm_sha1msg1_epu32(m3, m0);
            m2 = _mm_xor_si128(m2, m0);
            // Rounds 52-55
            e1 = _mm_sha1nexte_epu32(e1, m1);
            e0 = abcd;
            m2 = _mm_sha1msg2_epu32(m2, m1);
            abcd = _mm_sha1rnds4_epu32::<2>(abcd, e1);
            m0 = _mm_sha1msg1_epu32(m0, m1);
            m3 = _mm_xor_si128(m3, m1);
            // Rounds 56-59
            e0 = _mm_sha1nexte_epu32(e0, m2);
            e1 = abcd;
            m3 = _mm_sha1msg2_epu32(m3, m2);
            abcd = _mm_sha1rnds4_epu32::<2>(abcd, e0);
            m1 = _mm_sha1msg1_epu32(m1, m2);
            m0 = _mm_xor_si128(m0, m2);
            // Rounds 60-63
            e1 = _mm_sha1nexte_epu32(e1, m3);
            e0 = abcd;
            m0 = _mm_sha1msg2_epu32(m0, m3);
            abcd = _mm_sha1rnds4_epu32::<3>(abcd, e1);
            m2 = _mm_sha1msg1_epu32(m2, m3);
            m1 = _mm_xor_si128(m1, m3);
            // Rounds 64-67
            e0 = _mm_sha1nexte_epu32(e0, m0);
            e1 = abcd;
            m1 = _mm_sha1msg2_epu32(m1, m0);
            abcd = _mm_sha1rnds4_epu32::<3>(abcd, e0);
            m3 = _mm_sha1msg1_epu32(m3, m0);
            m2 = _mm_xor_si128(m2, m0);
            // Rounds 68-71
            e1 = _mm_sha1nexte_epu32(e1, m1);
            e0 = abcd;
            m2 = _mm_sha1msg2_epu32(m2, m1);
            abcd = _mm_sha1rnds4_epu32::<3>(abcd, e1);
            m3 = _mm_xor_si128(m3, m1);
            // Rounds 72-75
            e0 = _mm_sha1nexte_epu32(e0, m2);
            e1 = abcd;
            m3 = _mm_sha1msg2_epu32(m3, m2);
            abcd = _mm_sha1rnds4_epu32::<3>(abcd, e0);
            // Rounds 76-79
            e1 = _mm_sha1nexte_epu32(e1, m3);
            e0 = abcd;
            abcd = _mm_sha1rnds4_epu32::<3>(abcd, e1);

            // Combine with saved state.
            e0 = _mm_sha1nexte_epu32(e0, e_save);
            abcd = _mm_add_epi32(abcd, abcd_save);
            abcd = _mm_shuffle_epi32::<0x1B>(abcd);
            _mm_storeu_si128(state.as_mut_ptr() as *mut __m128i, abcd);
            state[4] = _mm_extract_epi32::<3>(e0) as u32;

            // Final schedule words: [W3,W2,W1,W0] lane order per register,
            // so reverse each before storing.
            let mut workspace = [0u32; 16];
            let out = workspace.as_mut_ptr() as *mut __m128i;
            _mm_storeu_si128(out, _mm_shuffle_epi32::<0x1B>(m0));
            _mm_storeu_si128(out.add(1), _mm_shuffle_epi32::<0x1B>(m1));
            _mm_storeu_si128(out.add(2), _mm_shuffle_epi32::<0x1B>(m2));
            _mm_storeu_si128(out.add(3), _mm_shuffle_epi32::<0x1B>(m3));
            workspace
        }
    }
}

/// SSSE3 / AVX2 SHA-1 block transform for x86-64 hosts below the
/// SHA-extension line.
///
/// # Provenance
///
/// Ported from `crypto/fipsmodule/sha/asm/sha1-x86_64.pl` in the AWS-LC tree
/// vendored by `aws-lc-sys` — Andy Polyakov's OpenSSL perlasm, carried there
/// under `SPDX-License-Identifier: Apache-2.0`, so portable with attribution.
/// What is taken is the message-schedule structure: the
/// `Xupdate_ssse3_16_31` and `Xupdate_ssse3_32_79` recurrences, the lane-3
/// fixup that makes the 1-step recurrence computable four wide, and the
/// interleaving of one schedule group against one quad of rounds through a
/// rotating 16-word W+K frame. The round bodies, the tier gate, the
/// W[64..80) return contract, and the tests are this tree's own.
///
/// Calling AWS-LC's SHA-1 instead is not an option, which is why this is a
/// port and not a dependency: every AWS-LC entry point yields digest state
/// only, and RAR29 needs the final schedule words W[64..80) — WinRAR writes
/// them back over the input, and no public API can hand them out. That is the
/// same "UnRAR-specific legacy algorithm AWS-LC does not provide" carve-out
/// the rest of `Rar29Sha1` already stands on.
///
/// AWS-LC's own header table, cycles per byte, lower is better:
///
/// ```text
///                 scalar    SSSE3          AVX2+BMI
/// Haswell         5.45      4.15 (+31%)    3.57 (+53%)
/// Skylake         5.18      4.06 (+28%)    3.54 (+46%)
/// ```
///
/// # Why interleaved, and why the earlier attempt lost
///
/// SHA-1's round chain is strictly serial and short per round, so a wide
/// machine spends most of a round waiting. The schedule is the only work
/// available to fill that slack. A vector schedule computed *up front* takes
/// the slack away instead of filling it — which is exactly what the deleted
/// 0.788x/0.860x variant did (see the note in
/// `Rar29Sha1::transform_block`). Every group here is therefore emitted
/// against the four rounds it runs beside, and the group is written to the
/// frame slot the same quad has just finished reading, so the read-then-write
/// order is what keeps a 16-word frame sufficient.
///
/// # Why AVX2 is the same 128-bit kernel and not a 256-bit one
///
/// `W[i]` depends on `W[i-3]`, so at most three words are independent; the
/// 2-step form `W[i] = rol2(W[i-6] ^ W[i-16] ^ W[i-28] ^ W[i-32])` reaches
/// six, which is what makes the four-wide step above legal. Eight-wide would
/// need the 4-step form, whose shortest back-reference is `W[i-12]` and which
/// is only reachable from `W[64]` on — too late to pay for itself. AWS-LC
/// gets its 256 bits the only other way there is: by scheduling *two blocks*
/// at once, one per 128-bit lane. That needs two blocks in hand, and the sole
/// consumer of this transform is the RAR3/RAR4 KDF: its fast path absorbs
/// 1..63 bytes per round, so a block can only ever complete inside the
/// buffered path, one at a time. (The long-password path can present a
/// multi-block absorb, but only from about 61 password units up, which is not
/// the shape to build a second kernel around. Batching the fast path's
/// absorbs would change that, and *is* the prerequisite for porting AWS-LC's
/// two-block shape — a separate change, with its own equivalence argument and
/// its own measurements.) So the AVX2 tier here is the same kernel
/// codegenned against a richer ISA, which is exactly the two levers AWS-LC
/// pulls in the same file: its AVX path is the SSSE3 kernel re-encoded VEX,
/// and its AVX2 path is the one that also switches the round bodies to BMI.
/// Both fall out of the target features here, and the emitted difference is
/// real — per block, `71 movdqa` register copies go to zero under VEX,
/// `160 roll` becomes `160 rorx` (non-destructive), and one and/xor pair per
/// section-1 round becomes `andn`. Neither instantiation issues anything
/// wider than 128 bits, so there is no AVX-SSE transition penalty and no
/// `vzeroupper` obligation either way. Which tier wins by how much is a
/// hardware question, and `rar29_sha1_scalar_vs_x86_vector_throughput` is the
/// probe that answers it; the default ordering below is by measurement, not
/// ISA width — the evidence is cited at the decision point in `select_tier`.
///
/// # Tier policy
///
/// * SHA extensions present — this module stands aside;
///   the `sha1_hw` module is strictly better.
/// * SSSE3 — [`Tier::Ssse3`]. Preferred over AVX2 by measurement on every
///   no-SHA-NI x86 part tested to date (Alder Lake P+E, Haswell).
/// * AVX2 + BMI1 + BMI2 — [`Tier::Avx2`], reachable through the override
///   below (and as the default only on an AVX2-without-SSSE3 part, which
///   does not exist in practice).
/// * Otherwise — [`Tier::None`], and the unrolled scalar runs. That is the
///   x86-64 parts predating SSSE3: Intel before Core 2, AMD before K10.
///
/// `WEAVER_UNRAR_SHA1_HW=0` keeps its existing whole-ladder meaning and pins
/// plain scalar. `WEAVER_UNRAR_SHA1_X86` selects within this module: `0`
/// stands the module down, `ssse3` and `avx2` force one tier so a single
/// binary can A/B them — and a named tier also stands the SHA-extension path
/// down, so the A/B works on a SHA-capable host instead of being silently
/// overridden by it. The ISA probe is never bypassed in either direction —
/// forcing a tier the CPU cannot execute would be an undefined opcode, so the
/// override widens the *policy* and leaves the *capability* check intact.
/// Same `OnceLock` + `WEAVER_*` shape as [`crate::crc_simd`].
#[cfg(target_arch = "x86_64")]
mod sha1_x86_vec {
    // Each kernel is one contiguous unsafe region under a single precondition
    // (the target features proved by `tier`). Per-intrinsic `unsafe` blocks
    // would add hundreds of tokens without adding a distinct safety
    // obligation, so the module opts out of the per-operation requirement and
    // documents the one obligation at each `#[target_feature]` entry point
    // instead. Same convention as `crate::crc_simd::x86_vpclmul`.
    #![allow(unsafe_op_in_unsafe_fn)]

    use std::arch::x86_64::*;
    use std::sync::OnceLock;

    /// The four SHA-1 section constants, folded into the schedule here rather
    /// than added per round.
    const K: [u32; 4] = [0x5a82_7999, 0x6ed9_eba1, 0x8f1b_bcdc, 0xca62_c1d6];

    /// Override knob for the tier gate, read once. See the module docs.
    const FORCE_ENV: &str = "WEAVER_UNRAR_SHA1_X86";

    /// The selected vector tier for this process.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub(super) enum Tier {
        /// No vector tier; the caller runs the unrolled scalar.
        None,
        /// [`transform_block_ssse3`].
        Ssse3,
        /// [`transform_block_avx2`].
        Avx2,
    }

    /// Resolve the tier once and cache it.
    pub(super) fn tier() -> Tier {
        static TIER: OnceLock<Tier> = OnceLock::new();
        *TIER.get_or_init(|| {
            let hw_pinned_off =
                std::env::var_os("WEAVER_UNRAR_SHA1_HW").is_some_and(|value| value == "0");
            let forced = std::env::var_os(FORCE_ENV);

            // Capability floor. Never widened by the override below: these
            // are the instructions the kernels actually issue.
            let ssse3 = is_x86_feature_detected!("ssse3");
            let avx2 = ssse3
                && is_x86_feature_detected!("avx2")
                && is_x86_feature_detected!("bmi1")
                && is_x86_feature_detected!("bmi2");

            select_tier(
                hw_pinned_off,
                forced.as_deref().and_then(|value| value.to_str()),
                ssse3,
                avx2,
            )
        })
    }

    /// The tier policy, split out from the environment and the CPUID probe so
    /// the matrix is testable on any host.
    ///
    /// `hw_pinned_off` is `WEAVER_UNRAR_SHA1_HW=0`, which predates this module
    /// and means "plain scalar" — not "one tier down" — so it wins over
    /// everything. `forced` is `WEAVER_UNRAR_SHA1_X86`. An unknown value is
    /// ignored rather than fatal, and a forced tier the CPU cannot execute
    /// stands the module down instead of issuing an undefined opcode.
    fn select_tier(hw_pinned_off: bool, forced: Option<&str>, ssse3: bool, avx2: bool) -> Tier {
        if hw_pinned_off || forced == Some("0") {
            return Tier::None;
        }

        match forced {
            Some("ssse3") => return if ssse3 { Tier::Ssse3 } else { Tier::None },
            Some("avx2") => return if avx2 { Tier::Avx2 } else { Tier::None },
            _ => {}
        }

        // Measured preference, not widest-first: on every no-SHA-NI x86 part
        // measured so far the SSSE3 kernel outruns the AVX2 one on this
        // workload — Alder Lake P/E cores (codex-x86, 2026-08-15: AVX2
        // 1.002x/1.20-1.24x vs SSSE3 1.265x/1.37-1.38x) and Haswell (fleet
        // run c4reval-20260815T200644Z: SSSE3 1.284-1.335 vs AVX2
        // 1.211-1.247 against the oracle, all four encrypted cases). The
        // AVX2 kernel stays selectable via WEAVER_UNRAR_SHA1_X86=avx2 for
        // silicon that upends this ordering.
        if ssse3 {
            Tier::Ssse3
        } else if avx2 {
            Tier::Avx2
        } else {
            Tier::None
        }
    }

    #[cfg(test)]
    mod tier_tests {
        use super::{Tier, select_tier};

        #[test]
        fn hw_pin_wins_over_every_capability_and_override() {
            for forced in [None, Some("0"), Some("ssse3"), Some("avx2"), Some("junk")] {
                assert_eq!(select_tier(true, forced, true, true), Tier::None);
            }
        }

        #[test]
        fn default_policy_prefers_the_measured_faster_tier() {
            // SSSE3 outruns AVX2 on every no-SHA-NI x86 measured (Alder Lake
            // and Haswell); AVX2 is reachable only through the override.
            assert_eq!(select_tier(false, None, true, true), Tier::Ssse3);
            assert_eq!(select_tier(false, None, true, false), Tier::Ssse3);
            assert_eq!(select_tier(false, None, false, false), Tier::None);
        }

        #[test]
        fn override_forces_one_tier_but_never_past_the_capability_floor() {
            assert_eq!(select_tier(false, Some("ssse3"), true, true), Tier::Ssse3);
            assert_eq!(select_tier(false, Some("avx2"), true, true), Tier::Avx2);
            // Capability floor holds: forcing a tier the CPU lacks stands the
            // module down rather than issuing an undefined opcode.
            assert_eq!(select_tier(false, Some("avx2"), true, false), Tier::None);
            assert_eq!(select_tier(false, Some("ssse3"), false, false), Tier::None);
        }

        #[test]
        fn zero_stands_down_and_an_unknown_value_is_ignored() {
            assert_eq!(select_tier(false, Some("0"), true, true), Tier::None);
            // Unknown values fall through to the default ladder, which
            // prefers SSSE3 by measurement.
            assert_eq!(select_tier(false, Some("junk"), true, true), Tier::Ssse3);
        }
    }

    /// Four rounds of section 1, `f = (b & (c ^ d)) ^ d`.
    ///
    /// `wk` carries W+K for the four rounds, so no round constant is added
    /// here. The four-position rotation SHA-1 applies to `a..e` is absorbed by
    /// static argument order exactly as in `Rar29Sha1::transform_block_scalar`
    /// — the returned array is the canonical `[a, b, c, d, e]` again, because
    /// four rounds rotate the five roles by four.
    #[inline(always)]
    fn quad_choose(v: [u32; 5], wk: [u32; 4]) -> [u32; 5] {
        let [mut a, mut b, mut c, mut d, mut e] = v;
        e = e
            .wrapping_add(a.rotate_left(5))
            .wrapping_add((b & (c ^ d)) ^ d)
            .wrapping_add(wk[0]);
        b = b.rotate_left(30);
        d = d
            .wrapping_add(e.rotate_left(5))
            .wrapping_add((a & (b ^ c)) ^ c)
            .wrapping_add(wk[1]);
        a = a.rotate_left(30);
        c = c
            .wrapping_add(d.rotate_left(5))
            .wrapping_add((e & (a ^ b)) ^ b)
            .wrapping_add(wk[2]);
        e = e.rotate_left(30);
        b = b
            .wrapping_add(c.rotate_left(5))
            .wrapping_add((d & (e ^ a)) ^ a)
            .wrapping_add(wk[3]);
        d = d.rotate_left(30);
        [b, c, d, e, a]
    }

    /// Four rounds of sections 2 and 4, `f = b ^ c ^ d`. The two sections
    /// differ only in their constant, and the constant is already in `wk`.
    #[inline(always)]
    fn quad_parity(v: [u32; 5], wk: [u32; 4]) -> [u32; 5] {
        let [mut a, mut b, mut c, mut d, mut e] = v;
        e = e
            .wrapping_add(a.rotate_left(5))
            .wrapping_add(b ^ c ^ d)
            .wrapping_add(wk[0]);
        b = b.rotate_left(30);
        d = d
            .wrapping_add(e.rotate_left(5))
            .wrapping_add(a ^ b ^ c)
            .wrapping_add(wk[1]);
        a = a.rotate_left(30);
        c = c
            .wrapping_add(d.rotate_left(5))
            .wrapping_add(e ^ a ^ b)
            .wrapping_add(wk[2]);
        e = e.rotate_left(30);
        b = b
            .wrapping_add(c.rotate_left(5))
            .wrapping_add(d ^ e ^ a)
            .wrapping_add(wk[3]);
        d = d.rotate_left(30);
        [b, c, d, e, a]
    }

    /// Four rounds of section 3, `f = ((b | c) & d) | (b & c)`.
    #[inline(always)]
    fn quad_majority(v: [u32; 5], wk: [u32; 4]) -> [u32; 5] {
        let [mut a, mut b, mut c, mut d, mut e] = v;
        e = e
            .wrapping_add(a.rotate_left(5))
            .wrapping_add(((b | c) & d) | (b & c))
            .wrapping_add(wk[0]);
        b = b.rotate_left(30);
        d = d
            .wrapping_add(e.rotate_left(5))
            .wrapping_add(((a | b) & c) | (a & b))
            .wrapping_add(wk[1]);
        a = a.rotate_left(30);
        c = c
            .wrapping_add(d.rotate_left(5))
            .wrapping_add(((e | a) & b) | (e & a))
            .wrapping_add(wk[2]);
        e = e.rotate_left(30);
        b = b
            .wrapping_add(c.rotate_left(5))
            .wrapping_add(((d | e) & a) | (d & e))
            .wrapping_add(wk[3]);
        d = d.rotate_left(30);
        [b, c, d, e, a]
    }

    /// Schedule group for W[16..32): the 1-step recurrence
    /// `W[i] = rol1(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16])`.
    ///
    /// Lane 3 wants `W[i+3-3] = W[i]`, which this very group produces, so it
    /// is computed short and repaired: `rol1` distributes over xor, so the
    /// missing term is `rol1(W[i])`, and `W[i]` is `rol1` of the pre-rotate
    /// lane 0 — hence folding `rol2` of the pre-rotate lane 0 into lane 3.
    /// `$gi` is the group index over the whole 20-group schedule, so group
    /// `$gi` covers W[4*$gi..4*$gi+4).
    macro_rules! sched_16_31 {
        ($x:ident, $gi:literal) => {{
            let xm4 = $x[($gi - 4) & 7];
            let xm3 = $x[($gi - 3) & 7];
            let xm2 = $x[($gi - 2) & 7];
            let xm1 = $x[($gi - 1) & 7];

            // "X[-14]" = [W[i-14], W[i-13], W[i-12], W[i-11]].
            let m14 = _mm_alignr_epi8::<8>(xm3, xm4);
            // "X[-3]" with lane 3 zeroed: W[i] is not known yet.
            let mut t = _mm_srli_si128::<4>(xm1);
            let mut xn = _mm_xor_si128(m14, xm4);
            t = _mm_xor_si128(t, xm2);
            xn = _mm_xor_si128(xn, t);

            let carry = _mm_srli_epi32::<31>(xn);
            let lane0 = _mm_slli_si128::<12>(xn);
            xn = _mm_add_epi32(xn, xn);
            xn = _mm_or_si128(xn, carry);
            xn = _mm_xor_si128(xn, _mm_srli_epi32::<30>(lane0));
            xn = _mm_xor_si128(xn, _mm_slli_epi32::<2>(lane0));

            $x[$gi & 7] = xn;
            xn
        }};
    }

    /// Schedule group for W[32..80): the 2-step recurrence
    /// `W[i] = rol2(W[i-6] ^ W[i-16] ^ W[i-28] ^ W[i-32])`, whose six-word
    /// back-reference leaves all four lanes independent — no fixup.
    ///
    /// The slot about to receive group `$gi` still holds group `$gi - 8`,
    /// which is `W[i-32..i-28)`, so the ring supplies that term for free.
    macro_rules! sched_32_79 {
        ($x:ident, $gi:literal) => {{
            let xm8 = $x[$gi & 7];
            let xm7 = $x[($gi - 7) & 7];
            let xm4 = $x[($gi - 4) & 7];
            let xm2 = $x[($gi - 2) & 7];
            let xm1 = $x[($gi - 1) & 7];

            // "X[-6]" = [W[i-6], W[i-5], W[i-4], W[i-3]].
            let m6 = _mm_alignr_epi8::<8>(xm1, xm2);
            let mut xn = _mm_xor_si128(xm8, xm4);
            xn = _mm_xor_si128(xn, xm7);
            xn = _mm_xor_si128(xn, m6);

            let spill = _mm_srli_epi32::<30>(xn);
            xn = _mm_slli_epi32::<2>(xn);
            xn = _mm_or_si128(xn, spill);

            $x[$gi & 7] = xn;
            xn
        }};
    }

    /// One interleaved step: read the frame slot the quad consumes, emit the
    /// schedule group beside the quad, then refill that same slot.
    ///
    /// The read-before-write order is the whole reason a 16-word frame is
    /// enough: quad `g` reads slot `g & 3`, and the group it is emitting
    /// beside — W[16+4g..20+4g) — lands in that same slot sixteen rounds
    /// later.
    ///
    /// `$wk` is a raw pointer, not the array, and that is load-bearing — see
    /// the note on the frame in `transform_block_kernel`.
    macro_rules! step {
        ($x:ident, $wk:ident, $v:ident, $slot:literal, $quad:ident, $sched:ident, $gi:literal, $k:expr) => {{
            let base = $slot * 4;
            let wq = [
                *$wk.add(base),
                *$wk.add(base + 1),
                *$wk.add(base + 2),
                *$wk.add(base + 3),
            ];
            let xn = $sched!($x, $gi);
            $v = $quad($v, wq);
            _mm_storeu_si128($wk.add(base) as *mut __m128i, _mm_add_epi32(xn, $k));
        }};
    }

    /// One of the last four quads, which have no schedule work left to do.
    macro_rules! tail_step {
        ($wk:ident, $v:ident, $slot:literal, $quad:ident) => {{
            let base = $slot * 4;
            $v = $quad(
                $v,
                [
                    *$wk.add(base),
                    *$wk.add(base + 1),
                    *$wk.add(base + 2),
                    *$wk.add(base + 3),
                ],
            );
        }};
    }

    /// The single-block kernel, instantiated once per ISA tier.
    ///
    /// A macro and not a shared function because `#[target_feature]` does not
    /// compose: the body has to be *codegenned* twice, once per feature set,
    /// for the AVX2 instantiation to get VEX encodings and BMI2 round bodies
    /// at all. The scalar quads above are ordinary `#[inline(always)]`
    /// functions and need no duplication — they carry no intrinsics, so they
    /// inherit whichever instantiation inlines them.
    macro_rules! transform_block_kernel {
        ($state:ident, $block:ident) => {{
            // Byte-reverse within each dword: SHA-1 words are big-endian.
            let bswap = _mm_set_epi64x(
                0x0c0d_0e0f_0809_0a0bu64 as i64,
                0x0405_0607_0001_0203u64 as i64,
            );
            let k0 = _mm_set1_epi32(K[0] as i32);
            let k1 = _mm_set1_epi32(K[1] as i32);
            let k2 = _mm_set1_epi32(K[2] as i32);
            let k3 = _mm_set1_epi32(K[3] as i32);

            // Ring of the last eight schedule groups; group `gi` lives at
            // `x[gi & 7]`.
            let mut x = [_mm_setzero_si128(); 8];
            let src = $block.as_ptr() as *const __m128i;
            x[0] = _mm_shuffle_epi8(_mm_loadu_si128(src), bswap);
            x[1] = _mm_shuffle_epi8(_mm_loadu_si128(src.add(1)), bswap);
            x[2] = _mm_shuffle_epi8(_mm_loadu_si128(src.add(2)), bswap);
            x[3] = _mm_shuffle_epi8(_mm_loadu_si128(src.add(3)), bswap);

            // Rotating W+K frame the rounds read from.
            //
            // The frame is reached through a deliberately opaque pointer, and
            // that is the single most load-bearing line in this module. Left
            // as a plain local array it never reaches memory at all: LLVM
            // promotes it, forwards each vector store into the loads that
            // follow, and hands the rounds their W+K word by extracting it
            // from a vector register — `pshufd` + `movd` per word on SSSE3,
            // `vpextrd` on AVX2. That is 140 extra operations per block on
            // the same execution ports the schedule itself is competing for,
            // and it is very probably what sank the earlier SSSE3 attempt.
            // AWS-LC does not do that: its round bodies read the frame with
            // a memory operand ("X[]+K xfer to IALU"), which spends the
            // otherwise-idle load ports instead. Escaping the pointer is what
            // reproduces that. Measured on the same source, per block:
            // SSSE3 1245 -> 1110 instructions with the vector-to-GPR
            // extractions gone entirely (140 -> 17), AVX2 trading 81
            // `vpextrd`/`vmovd` for loads that no longer contend with the ALU
            // ports. `black_box` is documented as best-effort, so if a future
            // toolchain sees through it this silently reverts to the shape
            // that loses; `rar29_sha1_scalar_vs_x86_vector_throughput` is the
            // tripwire.
            let mut wk_frame = [0u32; 16];
            let wk = std::hint::black_box(wk_frame.as_mut_ptr());
            _mm_storeu_si128(wk as *mut __m128i, _mm_add_epi32(x[0], k0));
            _mm_storeu_si128(wk.add(4) as *mut __m128i, _mm_add_epi32(x[1], k0));
            _mm_storeu_si128(wk.add(8) as *mut __m128i, _mm_add_epi32(x[2], k0));
            _mm_storeu_si128(wk.add(12) as *mut __m128i, _mm_add_epi32(x[3], k0));

            let mut v = *$state;

            // Sixteen interleaved steps: quads 0..16 beside groups 4..20.
            // The constant a group is paid is the one its rounds use, so the
            // section boundaries land at groups 5, 10 and 15.
            step!(x, wk, v, 0, quad_choose, sched_16_31, 4, k0);
            step!(x, wk, v, 1, quad_choose, sched_16_31, 5, k1);
            step!(x, wk, v, 2, quad_choose, sched_16_31, 6, k1);
            step!(x, wk, v, 3, quad_choose, sched_16_31, 7, k1);
            step!(x, wk, v, 0, quad_choose, sched_32_79, 8, k1);
            step!(x, wk, v, 1, quad_parity, sched_32_79, 9, k1);
            step!(x, wk, v, 2, quad_parity, sched_32_79, 10, k2);
            step!(x, wk, v, 3, quad_parity, sched_32_79, 11, k2);
            step!(x, wk, v, 0, quad_parity, sched_32_79, 12, k2);
            step!(x, wk, v, 1, quad_parity, sched_32_79, 13, k2);
            step!(x, wk, v, 2, quad_majority, sched_32_79, 14, k2);
            step!(x, wk, v, 3, quad_majority, sched_32_79, 15, k3);
            step!(x, wk, v, 0, quad_majority, sched_32_79, 16, k3);
            step!(x, wk, v, 1, quad_majority, sched_32_79, 17, k3);
            step!(x, wk, v, 2, quad_majority, sched_32_79, 18, k3);
            step!(x, wk, v, 3, quad_parity, sched_32_79, 19, k3);

            // Rounds 64..79 consume the last four groups.
            tail_step!(wk, v, 0, quad_parity);
            tail_step!(wk, v, 1, quad_parity);
            tail_step!(wk, v, 2, quad_parity);
            tail_step!(wk, v, 3, quad_parity);

            $state[0] = $state[0].wrapping_add(v[0]);
            $state[1] = $state[1].wrapping_add(v[1]);
            $state[2] = $state[2].wrapping_add(v[2]);
            $state[3] = $state[3].wrapping_add(v[3]);
            $state[4] = $state[4].wrapping_add(v[4]);

            // Groups 16..19 are W[64..80), and they are exactly ring slots
            // 0..3 — the RAR29 write-back contract, in raw W and not W+K.
            let mut workspace = [0u32; 16];
            let out = workspace.as_mut_ptr() as *mut __m128i;
            _mm_storeu_si128(out, x[0]);
            _mm_storeu_si128(out.add(1), x[1]);
            _mm_storeu_si128(out.add(2), x[2]);
            _mm_storeu_si128(out.add(3), x[3]);

            workspace
        }};
    }

    /// Process one 64-byte block, updating `state` and returning the final 16
    /// message-schedule words W[64..80).
    ///
    /// # Safety
    ///
    /// The CPU must support SSSE3. [`tier`] establishes exactly that.
    #[target_feature(enable = "ssse3")]
    pub(super) unsafe fn transform_block_ssse3(
        state: &mut [u32; 5],
        block: &[u8; 64],
    ) -> [u32; 16] {
        transform_block_kernel!(state, block)
    }

    /// The same kernel under VEX encodings and BMI2 round bodies.
    ///
    /// # Safety
    ///
    /// The CPU must support AVX2, BMI1 and BMI2. [`tier`] establishes exactly
    /// that.
    #[target_feature(enable = "avx2,bmi1,bmi2")]
    pub(super) unsafe fn transform_block_avx2(state: &mut [u32; 5], block: &[u8; 64]) -> [u32; 16] {
        transform_block_kernel!(state, block)
    }
}

/// ARMv8 crypto-extension SHA-1 block transform.
///
/// The RAR29 KDF runs 262,144 iterations, so the block transform dominates
/// key derivation. The schedule the hardware path computes is the standard
/// SHA-1 schedule; WinRAR's bug is only WHERE those words end up (written
/// back over the input), so returning W[64..80) keeps bug-for-bug parity
/// with the scalar path.
#[cfg(target_arch = "aarch64")]
mod sha1_hw {
    use std::arch::aarch64::*;

    /// Process one 64-byte block, updating `state` and returning the final
    /// 16 message-schedule words W[64..80).
    #[target_feature(enable = "sha2")]
    pub fn transform_block(state: &mut [u32; 5], block: &[u8; 64]) -> [u32; 16] {
        unsafe {
            let k0 = vdupq_n_u32(0x5a82_7999);
            let k1 = vdupq_n_u32(0x6ed9_eba1);
            let k2 = vdupq_n_u32(0x8f1b_bcdc);
            let k3 = vdupq_n_u32(0xca62_c1d6);

            let mut m0 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block.as_ptr())));
            let mut m1 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block.as_ptr().add(16))));
            let mut m2 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block.as_ptr().add(32))));
            let mut m3 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block.as_ptr().add(48))));

            let abcd_saved = vld1q_u32(state.as_ptr());
            let e_saved = state[4];
            let mut abcd = abcd_saved;
            let mut e0 = e_saved;
            let mut e1;

            let mut t0 = vaddq_u32(m0, k0);
            let mut t1 = vaddq_u32(m1, k0);

            // Rounds 0-3
            e1 = vsha1h_u32(vgetq_lane_u32::<0>(abcd));
            abcd = vsha1cq_u32(abcd, e0, t0);
            t0 = vaddq_u32(m2, k0);
            m0 = vsha1su0q_u32(m0, m1, m2);
            // Rounds 4-7
            e0 = vsha1h_u32(vgetq_lane_u32::<0>(abcd));
            abcd = vsha1cq_u32(abcd, e1, t1);
            t1 = vaddq_u32(m3, k0);
            m0 = vsha1su1q_u32(m0, m3);
            m1 = vsha1su0q_u32(m1, m2, m3);
            // Rounds 8-11
            e1 = vsha1h_u32(vgetq_lane_u32::<0>(abcd));
            abcd = vsha1cq_u32(abcd, e0, t0);
            t0 = vaddq_u32(m0, k0);
            m1 = vsha1su1q_u32(m1, m0);
            m2 = vsha1su0q_u32(m2, m3, m0);
            // Rounds 12-15
            e0 = vsha1h_u32(vgetq_lane_u32::<0>(abcd));
            abcd = vsha1cq_u32(abcd, e1, t1);
            t1 = vaddq_u32(m1, k1);
            m2 = vsha1su1q_u32(m2, m1);
            m3 = vsha1su0q_u32(m3, m0, m1);
            // Rounds 16-19
            e1 = vsha1h_u32(vgetq_lane_u32::<0>(abcd));
            abcd = vsha1cq_u32(abcd, e0, t0);
            t0 = vaddq_u32(m2, k1);
            m3 = vsha1su1q_u32(m3, m2);
            m0 = vsha1su0q_u32(m0, m1, m2);
            // Rounds 20-23
            e0 = vsha1h_u32(vgetq_lane_u32::<0>(abcd));
            abcd = vsha1pq_u32(abcd, e1, t1);
            t1 = vaddq_u32(m3, k1);
            m0 = vsha1su1q_u32(m0, m3);
            m1 = vsha1su0q_u32(m1, m2, m3);
            // Rounds 24-27
            e1 = vsha1h_u32(vgetq_lane_u32::<0>(abcd));
            abcd = vsha1pq_u32(abcd, e0, t0);
            t0 = vaddq_u32(m0, k1);
            m1 = vsha1su1q_u32(m1, m0);
            m2 = vsha1su0q_u32(m2, m3, m0);
            // Rounds 28-31
            e0 = vsha1h_u32(vgetq_lane_u32::<0>(abcd));
            abcd = vsha1pq_u32(abcd, e1, t1);
            t1 = vaddq_u32(m1, k1);
            m2 = vsha1su1q_u32(m2, m1);
            m3 = vsha1su0q_u32(m3, m0, m1);
            // Rounds 32-35
            e1 = vsha1h_u32(vgetq_lane_u32::<0>(abcd));
            abcd = vsha1pq_u32(abcd, e0, t0);
            t0 = vaddq_u32(m2, k2);
            m3 = vsha1su1q_u32(m3, m2);
            m0 = vsha1su0q_u32(m0, m1, m2);
            // Rounds 36-39
            e0 = vsha1h_u32(vgetq_lane_u32::<0>(abcd));
            abcd = vsha1pq_u32(abcd, e1, t1);
            t1 = vaddq_u32(m3, k2);
            m0 = vsha1su1q_u32(m0, m3);
            m1 = vsha1su0q_u32(m1, m2, m3);
            // Rounds 40-43
            e1 = vsha1h_u32(vgetq_lane_u32::<0>(abcd));
            abcd = vsha1mq_u32(abcd, e0, t0);
            t0 = vaddq_u32(m0, k2);
            m1 = vsha1su1q_u32(m1, m0);
            m2 = vsha1su0q_u32(m2, m3, m0);
            // Rounds 44-47
            e0 = vsha1h_u32(vgetq_lane_u32::<0>(abcd));
            abcd = vsha1mq_u32(abcd, e1, t1);
            t1 = vaddq_u32(m1, k2);
            m2 = vsha1su1q_u32(m2, m1);
            m3 = vsha1su0q_u32(m3, m0, m1);
            // Rounds 48-51
            e1 = vsha1h_u32(vgetq_lane_u32::<0>(abcd));
            abcd = vsha1mq_u32(abcd, e0, t0);
            t0 = vaddq_u32(m2, k2);
            m3 = vsha1su1q_u32(m3, m2);
            m0 = vsha1su0q_u32(m0, m1, m2);
            // Rounds 52-55
            e0 = vsha1h_u32(vgetq_lane_u32::<0>(abcd));
            abcd = vsha1mq_u32(abcd, e1, t1);
            t1 = vaddq_u32(m3, k3);
            m0 = vsha1su1q_u32(m0, m3);
            m1 = vsha1su0q_u32(m1, m2, m3);
            // Rounds 56-59
            e1 = vsha1h_u32(vgetq_lane_u32::<0>(abcd));
            abcd = vsha1mq_u32(abcd, e0, t0);
            t0 = vaddq_u32(m0, k3);
            m1 = vsha1su1q_u32(m1, m0);
            m2 = vsha1su0q_u32(m2, m3, m0);
            // Rounds 60-63
            e0 = vsha1h_u32(vgetq_lane_u32::<0>(abcd));
            abcd = vsha1pq_u32(abcd, e1, t1);
            t1 = vaddq_u32(m1, k3);
            m2 = vsha1su1q_u32(m2, m1);
            m3 = vsha1su0q_u32(m3, m0, m1);
            // Rounds 64-67
            e1 = vsha1h_u32(vgetq_lane_u32::<0>(abcd));
            abcd = vsha1pq_u32(abcd, e0, t0);
            t0 = vaddq_u32(m2, k3);
            m3 = vsha1su1q_u32(m3, m2);
            // Rounds 68-71
            e0 = vsha1h_u32(vgetq_lane_u32::<0>(abcd));
            abcd = vsha1pq_u32(abcd, e1, t1);
            t1 = vaddq_u32(m3, k3);
            // Rounds 72-75
            e1 = vsha1h_u32(vgetq_lane_u32::<0>(abcd));
            abcd = vsha1pq_u32(abcd, e0, t0);
            // Rounds 76-79
            e0 = vsha1h_u32(vgetq_lane_u32::<0>(abcd));
            abcd = vsha1pq_u32(abcd, e1, t1);

            let mut new_state = [0u32; 5];
            vst1q_u32(new_state.as_mut_ptr(), vaddq_u32(abcd_saved, abcd));
            new_state[4] = e_saved.wrapping_add(e0);
            *state = new_state;

            // Final schedule words: m0..m3 hold W[64..80) after their last
            // su0/su1 updates.
            let mut workspace = [0u32; 16];
            vst1q_u32(workspace.as_mut_ptr(), m0);
            vst1q_u32(workspace.as_mut_ptr().add(4), m1);
            vst1q_u32(workspace.as_mut_ptr().add(8), m2);
            vst1q_u32(workspace.as_mut_ptr().add(12), m3);
            workspace
        }
    }
}

/// Derive AES-128 key and IV from password and salt using RAR4's custom KDF.
///
/// RAR4 KDF algorithm:
/// - Encodes password as UTF-16LE
/// - Concatenates password_utf16le + salt into a single buffer
/// - Iterates 262144 times, each time hashing: buffer + 3-byte iteration counter
/// - At iterations 0, 16384, 32768, ... (i.e. `i % (262144/16) == 0`), the current
///   SHA-1 intermediate digest word H4's low byte is extracted as an IV byte
/// - After all iterations, the final SHA-1 digest words H0-H3 are extracted as the
///   AES-128 key in little-endian byte order per word
fn rar4_derive_key_material(password: &str, salt: Option<&[u8; 8]>) -> ([u8; 16], [u8; 16]) {
    let password = rar_password_compat(password);
    // Encode password as UTF-16LE, then append salt if present for both salted
    // and saltless RAR30 members.
    let mut raw_psw: Vec<u8> = password
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    if let Some(salt) = salt {
        raw_psw.extend_from_slice(salt);
    }

    let iv_interval = RAR4_KDF_ITERATIONS / 16;
    let mut iv = [0u8; 16];
    let mut sha = Rar29Sha1::new();

    // Fast path: when password+salt plus the 3 counter bytes fit in one SHA-1
    // block, `process_rar29`'s in-place RAR29 write-back loop provably cannot
    // fire — reaching a full block from `data` itself needs >= 65 input bytes,
    // since `i` starts at `64 - j >= 1` and the loop requires `i + 63 < len`.
    // So `raw_psw` is invariant across rounds, and the two absorbs can be fused
    // into one contiguous absorb over a buffer whose only per-round mutation is
    // the 3-byte counter tail. The absorbed byte stream and the `count`
    // progression are identical to the two-call form, so SHA-1 reaches an
    // identical state at every block boundary: same IV bytes, same key.
    // Halves the per-round partial-block copies.
    if raw_psw.len() + 3 <= 64 {
        let mut round = raw_psw.clone();
        round.extend_from_slice(&[0u8; 3]);
        let tail = round.len() - 3;

        for i in 0..RAR4_KDF_ITERATIONS {
            round[tail] = i as u8;
            round[tail + 1] = (i >> 8) as u8;
            round[tail + 2] = (i >> 16) as u8;
            sha.process(&round);

            // Extract one IV byte at each interval boundary.
            if i % iv_interval == 0 {
                let intermediate = sha.clone().finish_words();
                let iv_index = (i / iv_interval) as usize;
                iv[iv_index] = intermediate[4] as u8;
            }
        }

        round.zeroize();
    } else {
        for i in 0..RAR4_KDF_ITERATIONS {
            sha.process_rar29(&mut raw_psw);

            // Append iteration counter as 3 bytes LE.
            let i_bytes = [i as u8, (i >> 8) as u8, (i >> 16) as u8];
            sha.process(&i_bytes);

            // Extract one IV byte at each interval boundary.
            if i % iv_interval == 0 {
                let intermediate = sha.clone().finish_words();
                let iv_index = (i / iv_interval) as usize;
                iv[iv_index] = intermediate[4] as u8;
            }
        }
    }

    let mut digest = sha.finish_words();

    // RAR4 stores key bytes in little-endian order per 32-bit digest word.
    let mut key = [0u8; 16];
    for word in 0..4 {
        key[word * 4..word * 4 + 4].copy_from_slice(&digest[word].to_le_bytes());
    }

    let result = (key, iv);
    raw_psw.zeroize();
    digest.zeroize();
    key.zeroize();
    iv.zeroize();

    result
}

pub fn rar4_derive_key(password: &str, salt: Option<&[u8; 8]>) -> ([u8; 16], [u8; 16]) {
    rar4_derive_key_material(password, salt)
}

/// Decrypt data using AES-128-CBC (RAR4).
///
/// The input must be a multiple of 16 bytes (AES block size).
/// Returns the decrypted data (no padding removal — RAR4 tracks exact sizes via unpacked_size).
pub fn rar4_decrypt_data(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> RarResult<Vec<u8>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    if !data.len().is_multiple_of(16) {
        return Err(RarError::CorruptArchive {
            detail: format!(
                "RAR4 encrypted data length {} is not a multiple of AES block size (16)",
                data.len()
            ),
        });
    }

    let mut buf = data.to_vec();
    let mut decryptor = Rar4CbcDecryptor::new(key, iv);
    decryptor.decrypt_blocks(&mut buf);

    Ok(buf)
}

// =============================================================================
// Streaming AES-CBC decryption
// =============================================================================

pub(crate) const AES_BLOCK: usize = 16;

/// Stateful AES-256-CBC decryptor for incremental (streaming) decryption.
///
/// Unlike `decrypt_data` which requires all data at once, this carries the
/// CBC IV state across calls to `decrypt_blocks`.
pub struct CbcDecryptor {
    decryptor: backend::Aes256CbcDec,
}

impl CbcDecryptor {
    pub fn new(key: &[u8; 32], iv: &[u8; AES_BLOCK]) -> Self {
        Self {
            decryptor: backend::Aes256CbcDec::new(key, iv),
        }
    }

    /// Decrypt `data` in-place. `data.len()` MUST be a multiple of 16.
    /// Updates internal IV state for subsequent calls.
    pub fn decrypt_blocks(&mut self, data: &mut [u8]) {
        debug_assert!(data.len().is_multiple_of(AES_BLOCK));
        self.decryptor.decrypt_blocks(data);
    }
}

/// Decrypt one arbitrary range of a RAR5 member's cipher stream, in place.
///
/// The whole of E-D2 in one call: AES-CBC decrypts block *N* from block *N*
/// and block *N−1* alone, so a range's plaintext depends only on its own
/// cipher bytes plus the 16 immediately before them. No archive object, no
/// chain state, no forward-only constraint — a router that has cipher bytes
/// out of order can decrypt each span the moment its predecessor block has
/// landed.
///
/// - `key` is the member's AES-256 key, from
///   [`KdfCache::derive_key_rar5`] over its `FHEXTRA_CRYPT` salt and KDF count.
/// - `preceding_block` is the 16 cipher bytes immediately before `cipher`'s
///   first byte, or the member's header IV
///   ([`crate::RarVolumeMemberEncryptionFacts::iv`]) when `cipher` starts at
///   member-logical offset 0. Passing the wrong 16 bytes corrupts exactly the
///   first block and leaves the rest correct — it is not a detectable error
///   here, so the caller owns getting it right.
/// - `cipher` is a whole number of blocks, so both its start offset and its
///   length are multiples of 16. Cipher offset and member-logical offset are
///   the same number for a stored member.
///
/// Errors only on a length that is not a multiple of 16; an empty range is a
/// no-op. Decrypting past the member's declared size is legitimate — the final
/// block's last bytes are its tail padding.
pub fn decrypt_cipher_range(
    key: &[u8; 32],
    preceding_block: &[u8; AES_BLOCK],
    cipher: &mut [u8],
) -> RarResult<()> {
    if cipher.is_empty() {
        return Ok(());
    }
    if !cipher.len().is_multiple_of(AES_BLOCK) {
        return Err(RarError::CorruptArchive {
            detail: format!(
                "encrypted range length {} is not a multiple of AES block size ({AES_BLOCK})",
                cipher.len()
            ),
        });
    }

    CbcDecryptor::new(key, preceding_block).decrypt_blocks(cipher);
    Ok(())
}

/// Encrypt one arbitrary range of a RAR5 member's cipher stream, in place.
///
/// The exact inverse of [`decrypt_cipher_range`], and its mirror in every
/// respect: same argument order, same in-place semantics, same error type, same
/// "the caller owns the predecessor" contract. AES-CBC encryption is
/// deterministic given key, predecessor and plaintext, so a caller holding a
/// member's plaintext can reproduce exactly the bytes that were posted — which
/// is what a reader has to hand back when the archive's own bytes are gone and
/// only the decrypted member is on disk.
///
/// - `key` is the member's AES-256 key, from
///   [`KdfCache::derive_key_rar5`] over its `FHEXTRA_CRYPT` salt and KDF count.
/// - `preceding_block` is the 16 **cipher** bytes immediately before `plain`'s
///   first byte, or the member's header IV
///   ([`crate::RarVolumeMemberEncryptionFacts::iv`]) when `plain` starts at
///   member-logical offset 0. Passing the wrong 16 bytes is not a detectable
///   error here, so the caller owns getting it right — and unlike the decrypt,
///   the damage does **not** stop at the first block: CBC feeds each ciphertext
///   block into the next, so every byte of the range comes out different from
///   what was posted.
/// - `plain` is a whole number of blocks, and holds the ciphertext on return.
///
/// Errors on a length that is not a multiple of 16, and on a backend that
/// refuses the transform; an empty range is a no-op. Both are returned rather
/// than asserted, because the caller is a reader that must be able to answer
/// "these bytes are unavailable" instead of dying. On an error `plain`'s
/// contents are unspecified.
pub fn encrypt_cipher_range(
    key: &[u8; 32],
    preceding_block: &[u8; AES_BLOCK],
    plain: &mut [u8],
) -> RarResult<()> {
    if plain.is_empty() {
        return Ok(());
    }
    if !plain.len().is_multiple_of(AES_BLOCK) {
        return Err(RarError::CorruptArchive {
            detail: format!(
                "encrypted range length {} is not a multiple of AES block size ({AES_BLOCK})",
                plain.len()
            ),
        });
    }

    match backend::Aes256CbcEnc::new(key, preceding_block).encrypt_blocks(plain) {
        true => Ok(()),
        false => Err(RarError::CorruptArchive {
            detail: format!(
                "AES-256-CBC encryption of a {}-byte range was refused by the crypto backend",
                plain.len()
            ),
        }),
    }
}

/// Decrypt one arbitrary range of a **RAR4** member's cipher stream, in place.
///
/// The AES-128 twin of [`decrypt_cipher_range`], with the same contract in every
/// respect — see it for what `preceding_block` must be and what happens when it
/// is wrong. The only difference is the key width, and where the key comes from:
/// RAR4 derives both key and IV together from the password plus the header's
/// optional 8-byte file salt ([`KdfCache::derive_key_rar4`]), where RAR5 derives
/// the key from a `FHEXTRA_CRYPT` record and reads the IV out of it.
///
/// Prefer [`MemberCipherKey::decrypt_range`] where the format is not known
/// statically; this is the direct entry point for a RAR4-only caller.
pub fn decrypt_cipher_range_rar4(
    key: &[u8; 16],
    preceding_block: &[u8; AES_BLOCK],
    cipher: &mut [u8],
) -> RarResult<()> {
    if cipher.is_empty() {
        return Ok(());
    }
    if !cipher.len().is_multiple_of(AES_BLOCK) {
        return Err(RarError::CorruptArchive {
            detail: format!(
                "encrypted range length {} is not a multiple of AES block size ({AES_BLOCK})",
                cipher.len()
            ),
        });
    }

    Rar4CbcDecryptor::new(key, preceding_block).decrypt_blocks(cipher);
    Ok(())
}

/// Encrypt one arbitrary range of a **RAR4** member's cipher stream, in place.
///
/// The AES-128 twin of [`encrypt_cipher_range`], with the same contract: same
/// argument order, same in-place semantics, same fallibility, and the same
/// "the caller owns the predecessor" rule whose damage does *not* stop at the
/// first block.
///
/// Prefer [`MemberCipherKey::encrypt_range`] where the format is not known
/// statically; this is the direct entry point for a RAR4-only caller.
pub fn encrypt_cipher_range_rar4(
    key: &[u8; 16],
    preceding_block: &[u8; AES_BLOCK],
    plain: &mut [u8],
) -> RarResult<()> {
    if plain.is_empty() {
        return Ok(());
    }
    if !plain.len().is_multiple_of(AES_BLOCK) {
        return Err(RarError::CorruptArchive {
            detail: format!(
                "encrypted range length {} is not a multiple of AES block size ({AES_BLOCK})",
                plain.len()
            ),
        });
    }

    match backend::Aes128CbcEnc::new(key, preceding_block).encrypt_blocks(plain) {
        true => Ok(()),
        false => Err(RarError::CorruptArchive {
            detail: format!(
                "AES-128-CBC encryption of a {}-byte range was refused by the crypto backend",
                plain.len()
            ),
        }),
    }
}

/// The AES key that turns one member's cipher stream into its plaintext, and
/// back.
///
/// RAR encrypts a stored member's whole plaintext as **one CBC stream** whatever
/// the format — the difference is only the key width and where the key and IV
/// come from — so a router that has to decrypt at write time and re-encrypt on
/// read wants one type it can carry per member and one pair of calls it can
/// make. That is this: format-agnostic at the call site, exact at the cipher.
///
/// Which variant a member takes is not a guess. [`crate::MemberKeying`] is what
/// the headers state, and it maps one-to-one:
/// [`crate::MemberKeying::Rar5`] is [`Self::Aes256`] over
/// [`KdfCache::derive_key_rar5`], and [`crate::MemberKeying::Rar4`] is
/// [`Self::Aes128`] over [`KdfCache::derive_key_rar4`].
///
/// This is key material. It carries no `Debug`, no `Display` and no
/// serialization, deliberately: a key in a log is a key on disk. `PartialEq` is
/// here for *identity* — "did these two members derive the same key" — and is a
/// plain byte comparison; nothing authenticates against it, and nothing should.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MemberCipherKey {
    /// RAR5 file encryption: AES-256-CBC, keyed by PBKDF2-HMAC-SHA256 over the
    /// `FHEXTRA_CRYPT` salt and iteration count.
    Aes256([u8; 32]),
    /// RAR4/RAR3 "RAR 3.0" file encryption: AES-128-CBC, keyed by the legacy
    /// iterative SHA-1 KDF over the password and the header's optional 8-byte
    /// file salt.
    Aes128([u8; 16]),
}

impl MemberCipherKey {
    /// Decrypt `cipher` in place — see [`decrypt_cipher_range`] for the whole
    /// contract, which is the same for both widths.
    pub fn decrypt_range(
        &self,
        preceding_block: &[u8; AES_BLOCK],
        cipher: &mut [u8],
    ) -> RarResult<()> {
        match self {
            Self::Aes256(key) => decrypt_cipher_range(key, preceding_block, cipher),
            Self::Aes128(key) => decrypt_cipher_range_rar4(key, preceding_block, cipher),
        }
    }

    /// Encrypt `plain` in place — see [`encrypt_cipher_range`] for the whole
    /// contract, which is the same for both widths.
    pub fn encrypt_range(
        &self,
        preceding_block: &[u8; AES_BLOCK],
        plain: &mut [u8],
    ) -> RarResult<()> {
        match self {
            Self::Aes256(key) => encrypt_cipher_range(key, preceding_block, plain),
            Self::Aes128(key) => encrypt_cipher_range_rar4(key, preceding_block, plain),
        }
    }
}

/// Stateful AES-128-CBC decryptor for RAR4 archives.
pub struct Rar4CbcDecryptor {
    decryptor: backend::Aes128CbcDec,
}

impl Rar4CbcDecryptor {
    pub fn new(key: &[u8; 16], iv: &[u8; AES_BLOCK]) -> Self {
        Self {
            decryptor: backend::Aes128CbcDec::new(key, iv),
        }
    }

    /// Decrypt `data` in-place. `data.len()` MUST be a multiple of 16.
    pub fn decrypt_blocks(&mut self, data: &mut [u8]) {
        debug_assert!(data.len().is_multiple_of(AES_BLOCK));
        self.decryptor.decrypt_blocks(data);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DecryptorMode {
    Streaming,
    BlockAligned,
}

/// Decryptor enum that handles RAR5 and all RAR4 file-encryption variants.
enum CbcDecryptorAny {
    Rar5(Box<CbcDecryptor>),
    Rar4(Box<Rar4CbcDecryptor>),
    Rar13(Rar13Decryptor),
    Rar15(Box<Rar15Decryptor>),
    Rar20(Box<Rar20Decryptor>),
}

impl CbcDecryptorAny {
    fn mode(&self) -> DecryptorMode {
        match self {
            Self::Rar13(_) | Self::Rar15(_) => DecryptorMode::Streaming,
            Self::Rar5(_) | Self::Rar4(_) | Self::Rar20(_) => DecryptorMode::BlockAligned,
        }
    }

    pub fn decrypt(&mut self, data: &mut [u8]) {
        match self {
            Self::Rar5(d) => d.decrypt_blocks(data),
            Self::Rar4(d) => d.decrypt_blocks(data),
            Self::Rar13(d) => d.decrypt(data),
            Self::Rar15(d) => d.decrypt(data),
            Self::Rar20(d) => {
                debug_assert!(data.len().is_multiple_of(AES_BLOCK));
                for block in data.chunks_exact_mut(AES_BLOCK) {
                    d.decrypt_block(block);
                }
            }
        }
    }
}

/// A `Read` adapter that decrypts AES-CBC on-the-fly.
///
/// Wraps an inner `Read` source (e.g. `ChainedSegmentReader`) and decrypts
/// data as it flows through. Ciphertext is read straight into the caller's
/// buffer and decrypted in place, matching unrar's `UnpRead` (rdwrfn.cpp),
/// which decrypts the read buffer where it lands. The caller therefore sets
/// the read granularity; nothing here caps it.
///
/// Only two things are carried between calls: ciphertext that does not
/// complete an AES block (a volume boundary can split one), and — for callers
/// whose buffer is smaller than a single block — one staged plaintext block.
///
/// The total data from the inner reader MUST be a multiple of 16 bytes
/// (guaranteed by RAR's archive format for encrypted members).
pub struct DecryptingReader<R: Read> {
    inner: R,
    decryptor: CbcDecryptorAny,
    /// Ciphertext read from inner but not yet forming a complete AES block.
    pending: [u8; AES_BLOCK],
    pending_len: usize,
    /// Plaintext staged for callers whose buffer cannot hold a whole block.
    plain: [u8; AES_BLOCK],
    plain_pos: usize,
    plain_len: usize,
    /// Inner reader hit EOF.
    inner_eof: bool,
}

impl<R: Read> Drop for DecryptingReader<R> {
    fn drop(&mut self) {
        self.pending.zeroize();
        self.plain.zeroize();
    }
}

impl<R: Read> DecryptingReader<R> {
    fn new_with_decryptor(inner: R, decryptor: CbcDecryptorAny) -> Self {
        Self {
            inner,
            decryptor,
            pending: [0u8; AES_BLOCK],
            pending_len: 0,
            plain: [0u8; AES_BLOCK],
            plain_pos: 0,
            plain_len: 0,
            inner_eof: false,
        }
    }

    /// Stage one decrypted block in `plain`, for callers whose buffer is too
    /// small to decrypt in place. Returns 0 at a clean end of stream.
    fn stage_block(&mut self) -> std::io::Result<usize> {
        let mut total = self.pending_len;
        if total > 0 {
            self.plain[..total].copy_from_slice(&self.pending[..total]);
        }
        while total < AES_BLOCK && !self.inner_eof {
            match self.inner.read(&mut self.plain[total..AES_BLOCK]) {
                Ok(0) => {
                    self.inner_eof = true;
                    break;
                }
                Ok(read) => total += read,
                Err(error) => {
                    // Keep what was staged so a retry resumes where it stopped.
                    self.pending[..total].copy_from_slice(&self.plain[..total]);
                    self.pending_len = total;
                    return Err(error);
                }
            }
        }
        self.pending_len = 0;

        if total == 0 {
            return Ok(0);
        }
        if total < AES_BLOCK {
            self.pending[..total].copy_from_slice(&self.plain[..total]);
            self.pending_len = total;
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "encrypted data not aligned to AES block size",
            ));
        }

        self.decryptor.decrypt(&mut self.plain[..]);
        self.plain_pos = 0;
        self.plain_len = AES_BLOCK;
        Ok(AES_BLOCK)
    }

    /// Create a new decrypting reader for RAR5 (AES-256-CBC).
    pub fn new_rar5(inner: R, key: &[u8; 32], iv: &[u8; 16]) -> Self {
        Self::new_with_decryptor(
            inner,
            CbcDecryptorAny::Rar5(Box::new(CbcDecryptor::new(key, iv))),
        )
    }

    /// Create a new decrypting reader for RAR4 (AES-128-CBC).
    pub fn new_rar4(inner: R, key: &[u8; 16], iv: &[u8; 16]) -> Self {
        Self::new_with_decryptor(
            inner,
            CbcDecryptorAny::Rar4(Box::new(Rar4CbcDecryptor::new(key, iv))),
        )
    }

    pub fn new_rar4_legacy(inner: R, method: Rar4EncryptionMethod, password: &str) -> Self {
        let decryptor = match method {
            Rar4EncryptionMethod::Rar13 => CbcDecryptorAny::Rar13(Rar13Decryptor::new(password)),
            Rar4EncryptionMethod::Rar15 => {
                CbcDecryptorAny::Rar15(Box::new(Rar15Decryptor::new(password)))
            }
            Rar4EncryptionMethod::Rar20 => {
                CbcDecryptorAny::Rar20(Box::new(Rar20Decryptor::new(password)))
            }
            Rar4EncryptionMethod::Rar30 => unreachable!("RAR30 must use AES constructor"),
        };
        Self::new_with_decryptor(inner, decryptor)
    }

    pub(crate) fn new_rar4_legacy_dos(
        inner: R,
        method: Rar4EncryptionMethod,
        password: &str,
    ) -> Self {
        let decryptor = match method {
            Rar4EncryptionMethod::Rar13 => {
                CbcDecryptorAny::Rar13(Rar13Decryptor::new_dos(password))
            }
            Rar4EncryptionMethod::Rar15 => {
                CbcDecryptorAny::Rar15(Box::new(Rar15Decryptor::new_dos(password)))
            }
            Rar4EncryptionMethod::Rar20 => {
                CbcDecryptorAny::Rar20(Box::new(Rar20Decryptor::new_dos(password)))
            }
            Rar4EncryptionMethod::Rar30 => unreachable!("RAR30 must use AES constructor"),
        };
        Self::new_with_decryptor(inner, decryptor)
    }
}

impl<R: Read> Read for DecryptingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.decryptor.mode() == DecryptorMode::Streaming {
            let read = self.inner.read(buf)?;
            if read == 0 {
                return Ok(0);
            }
            self.decryptor.decrypt(&mut buf[..read]);
            return Ok(read);
        }

        // Serve plaintext held back from a sub-block-sized read.
        if self.plain_pos < self.plain_len {
            let n = (self.plain_len - self.plain_pos).min(buf.len());
            buf[..n].copy_from_slice(&self.plain[self.plain_pos..self.plain_pos + n]);
            self.plain_pos += n;
            return Ok(n);
        }

        if buf.is_empty() {
            return Ok(0);
        }

        if self.inner_eof && self.pending_len == 0 {
            return Ok(0);
        }

        // A buffer shorter than one AES block cannot be decrypted in place.
        if buf.len() < AES_BLOCK {
            if self.stage_block()? == 0 {
                return Ok(0);
            }
            let n = self.plain_len.min(buf.len());
            buf[..n].copy_from_slice(&self.plain[..n]);
            self.plain_pos = n;
            return Ok(n);
        }

        // Read ciphertext straight into the caller's buffer, prefixed by any
        // partial block carried over from the previous call.
        let mut total = self.pending_len;
        if total > 0 {
            buf[..total].copy_from_slice(&self.pending[..total]);
        }
        while total < buf.len() && !self.inner_eof {
            debug_assert!(total < AES_BLOCK, "fill loop runs only until one block");
            match self.inner.read(&mut buf[total..]) {
                Ok(0) => {
                    self.inner_eof = true;
                    break;
                }
                Ok(read) => {
                    total += read;
                    // One whole block is enough to hand back; keep reading only
                    // while a short read has not yet produced one.
                    if total >= AES_BLOCK {
                        break;
                    }
                }
                Err(error) => {
                    // Carry the staged ciphertext so a retry resumes cleanly.
                    self.pending[..total].copy_from_slice(&buf[..total]);
                    self.pending_len = total;
                    return Err(error);
                }
            }
        }
        self.pending_len = 0;

        let complete = total - (total % AES_BLOCK);
        let leftover = total - complete;
        if leftover > 0 {
            self.pending[..leftover].copy_from_slice(&buf[complete..total]);
            self.pending_len = leftover;
        }

        if complete == 0 {
            // The fill loop stops below one block only at end of stream.
            if leftover > 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "encrypted data not aligned to AES block size",
                ));
            }
            return Ok(0);
        }

        self.decryptor.decrypt(&mut buf[..complete]);
        Ok(complete)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// The hardware SHA-1 path must match the scalar path exactly — both the
    /// digest state and the returned final schedule words that feed the
    /// RAR29 in-place corruption.
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    #[test]
    fn rar29_sha1_hw_transform_matches_scalar() {
        if !sha1_hw_enabled() {
            eprintln!("skipping: SHA extensions not available");
            return;
        }

        let mut seed = 0x1234_5678_9abc_def0u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };

        for round in 0..4096 {
            let mut block = [0u8; 64];
            for chunk in block.chunks_exact_mut(8) {
                chunk.copy_from_slice(&next().to_le_bytes());
            }
            let mut state = [0u32; 5];
            for word in &mut state {
                *word = next() as u32;
            }

            let mut scalar = Rar29Sha1::new();
            scalar.state = state;
            let mut hw = Rar29Sha1::new();
            hw.state = state;

            let ws_scalar = scalar.transform_block_scalar(&block);
            // SAFETY: sha2 availability checked above.
            let ws_hw = unsafe { sha1_hw::transform_block(&mut hw.state, &block) };

            assert_eq!(scalar.state, hw.state, "state diverged at round {round}");
            assert_eq!(ws_scalar, ws_hw, "schedule diverged at round {round}");
        }
    }

    /// Both x86 vector tiers must match the scalar transform exactly — digest
    /// state and the returned final schedule words that feed the RAR29
    /// in-place corruption.
    ///
    /// Each kernel is probed for and entered directly rather than through
    /// `sha1_x86_vec::tier()`, so a host carrying both runs both, and a
    /// process-wide tier pin cannot silently reduce this to one arm. The tier
    /// the dispatch would actually pick is asserted alongside, so a gate that
    /// drifts from the kernels it selects fails here too.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn rar29_sha1_x86_vector_transforms_match_scalar() {
        let ssse3 = is_x86_feature_detected!("ssse3");
        let avx2 = ssse3
            && is_x86_feature_detected!("avx2")
            && is_x86_feature_detected!("bmi1")
            && is_x86_feature_detected!("bmi2");

        if !ssse3 {
            eprintln!("skipping: no SSSE3 on this host");
            return;
        }

        let mut seed = 0x0bad_c0de_1337_f00du64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };

        for round in 0..4096 {
            let mut block = [0u8; 64];
            for chunk in block.chunks_exact_mut(8) {
                chunk.copy_from_slice(&next().to_le_bytes());
            }
            let mut state = [0u32; 5];
            for word in &mut state {
                *word = next() as u32;
            }

            let mut scalar = Rar29Sha1::new();
            scalar.state = state;
            let ws_scalar = scalar.transform_block_scalar(&block);

            let mut vector = Rar29Sha1::new();
            vector.state = state;
            // SAFETY: SSSE3 availability checked above.
            let ws_vector =
                unsafe { sha1_x86_vec::transform_block_ssse3(&mut vector.state, &block) };
            assert_eq!(
                scalar.state, vector.state,
                "ssse3 state diverged at round {round}"
            );
            assert_eq!(
                ws_scalar, ws_vector,
                "ssse3 schedule diverged at round {round}"
            );

            if avx2 {
                let mut wide = Rar29Sha1::new();
                wide.state = state;
                // SAFETY: AVX2 + BMI1 + BMI2 availability checked above.
                let ws_wide =
                    unsafe { sha1_x86_vec::transform_block_avx2(&mut wide.state, &block) };
                assert_eq!(
                    scalar.state, wide.state,
                    "avx2 state diverged at round {round}"
                );
                assert_eq!(
                    ws_scalar, ws_wide,
                    "avx2 schedule diverged at round {round}"
                );
            }
        }

        // The gate and the kernels must agree about what this host can run.
        // Only meaningful when nothing is pinning the ladder off.
        let pinned = std::env::var_os("WEAVER_UNRAR_SHA1_HW").is_some_and(|value| value == "0")
            || std::env::var_os("WEAVER_UNRAR_SHA1_X86").is_some();
        if !pinned {
            let expected = if avx2 {
                sha1_x86_vec::Tier::Avx2
            } else {
                sha1_x86_vec::Tier::Ssse3
            };
            assert_eq!(sha1_x86_vec::tier(), expected);
        }

        eprintln!("NOTE: rar29-sha1 x86 differential ran ssse3=true avx2={avx2}");
    }

    /// Informational probe of each x86 vector tier against the unrolled
    /// scalar; run explicitly with `--ignored` on a real x86 host. Prints
    /// NOTE lines rather than asserting ratios — timings belong to bench
    /// hosts, and an emulated or shared host will lie about them.
    #[cfg(target_arch = "x86_64")]
    #[test]
    #[ignore = "timing probe; run explicitly"]
    fn rar29_sha1_scalar_vs_x86_vector_throughput() {
        const BLOCKS: u32 = 400_000;
        let block = [0xa5u8; 64];

        let ssse3 = is_x86_feature_detected!("ssse3");
        let avx2 = ssse3
            && is_x86_feature_detected!("avx2")
            && is_x86_feature_detected!("bmi1")
            && is_x86_feature_detected!("bmi2");
        if !ssse3 {
            eprintln!("skipping: no SSSE3 on this host");
            return;
        }

        let mut scalar = Rar29Sha1::new();
        let start = std::time::Instant::now();
        for _ in 0..BLOCKS {
            std::hint::black_box(scalar.transform_block_scalar(std::hint::black_box(&block)));
        }
        let scalar_elapsed = start.elapsed();

        let mut state = Rar29Sha1::new().state;
        let start = std::time::Instant::now();
        for _ in 0..BLOCKS {
            // SAFETY: SSSE3 availability checked above.
            std::hint::black_box(unsafe {
                sha1_x86_vec::transform_block_ssse3(&mut state, std::hint::black_box(&block))
            });
        }
        let ssse3_elapsed = start.elapsed();

        eprintln!(
            "NOTE: rar29-sha1 {BLOCKS} blocks: scalar {scalar_elapsed:?}, ssse3 {ssse3_elapsed:?}, scalar/ssse3 = {:.3}",
            scalar_elapsed.as_secs_f64() / ssse3_elapsed.as_secs_f64()
        );

        if avx2 {
            let mut state = Rar29Sha1::new().state;
            let start = std::time::Instant::now();
            for _ in 0..BLOCKS {
                // SAFETY: AVX2 + BMI1 + BMI2 availability checked above.
                std::hint::black_box(unsafe {
                    sha1_x86_vec::transform_block_avx2(&mut state, std::hint::black_box(&block))
                });
            }
            let avx2_elapsed = start.elapsed();
            eprintln!(
                "NOTE: rar29-sha1 {BLOCKS} blocks: scalar {scalar_elapsed:?}, avx2 {avx2_elapsed:?}, scalar/avx2 = {:.3}",
                scalar_elapsed.as_secs_f64() / avx2_elapsed.as_secs_f64()
            );
        } else {
            eprintln!("NOTE: no AVX2+BMI on this host; avx2 arm skipped");
        }
    }

    /// The unrolled scalar transform must match the pre-unroll rolled loop
    /// bit for bit — digest state and the returned W[64..80) schedule words
    /// both, on every host (this differential needs no SHA hardware).
    #[test]
    fn rar29_sha1_unrolled_scalar_matches_rolled_reference() {
        let mut seed = 0xfeed_beef_dead_c0deu64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };

        for round in 0..4096 {
            let mut block = [0u8; 64];
            for chunk in block.chunks_exact_mut(8) {
                chunk.copy_from_slice(&next().to_le_bytes());
            }
            let mut state = [0u32; 5];
            for word in &mut state {
                *word = next() as u32;
            }

            let mut unrolled = Rar29Sha1::new();
            unrolled.state = state;
            let mut reference = Rar29Sha1::new();
            reference.state = state;

            let ws_unrolled = unrolled.transform_block_scalar(&block);
            let ws_reference = reference.transform_block_scalar_reference(&block);

            assert_eq!(
                unrolled.state, reference.state,
                "state diverged at round {round}"
            );
            assert_eq!(
                ws_unrolled, ws_reference,
                "schedule diverged at round {round}"
            );
        }
    }

    /// Informational probe of the unroll's magnitude versus the pre-unroll
    /// rolled loop; run explicitly with `--ignored`. Prints a NOTE line
    /// rather than asserting a ratio — timings belong to real bench hosts.
    #[test]
    #[ignore = "timing probe; run explicitly"]
    fn rar29_sha1_rolled_vs_unrolled_throughput() {
        const BLOCKS: u32 = 400_000;
        let block = [0xa5u8; 64];

        let mut rolled = Rar29Sha1::new();
        let start = std::time::Instant::now();
        for _ in 0..BLOCKS {
            std::hint::black_box(
                rolled.transform_block_scalar_reference(std::hint::black_box(&block)),
            );
        }
        let rolled_elapsed = start.elapsed();

        let mut unrolled = Rar29Sha1::new();
        let start = std::time::Instant::now();
        for _ in 0..BLOCKS {
            std::hint::black_box(unrolled.transform_block_scalar(std::hint::black_box(&block)));
        }
        let unrolled_elapsed = start.elapsed();

        eprintln!(
            "NOTE: rar29-sha1 {BLOCKS} blocks: rolled {:?}, unrolled {:?}, rolled/unrolled = {:.3}",
            rolled_elapsed,
            unrolled_elapsed,
            rolled_elapsed.as_secs_f64() / unrolled_elapsed.as_secs_f64()
        );
    }

    #[test]
    fn test_rar_password_compat_matches_rar_behavior_limit() {
        let exact = "a".repeat(RAR_PASSWORD_MAX_UNITS);
        assert!(matches!(rar_password_compat(&exact), Cow::Borrowed(_)));

        let too_long = format!("{exact}tail");
        assert_eq!(rar_password_compat(&too_long).as_ref(), exact);

        let with_two_unit_scalar = format!("{}😀x", "a".repeat(RAR_PASSWORD_MAX_UNITS - 2));
        let expected = format!("{}😀", "a".repeat(RAR_PASSWORD_MAX_UNITS - 2));
        assert_eq!(
            rar_password_compat(&with_two_unit_scalar).as_ref(),
            expected
        );
    }

    #[test]
    fn test_rar_dos_password_compat_uses_cp437_oem_bytes() {
        assert_eq!(rar_password_oem_bytes_compat("Grüße"), b"Gr\x81\xe1e");
        assert_eq!(rar_password_oem_bytes_compat("€"), b"?");
    }

    #[test]
    fn test_rar_dos_password_compat_truncates_before_oem_encoding() {
        let prefix = "a".repeat(RAR_PASSWORD_MAX_UNITS);
        let long = format!("{prefix}ü");

        assert_eq!(rar_password_oem_bytes_compat(&long), prefix.as_bytes());
    }

    #[test]
    fn test_rar5_kdf_ignores_password_tail_after_rar_behavior_limit() {
        let salt = [0x5Au8; 16];
        let prefix = "p".repeat(RAR_PASSWORD_MAX_UNITS);
        let material = derive_rar5_material(&prefix, &salt, 0).unwrap();

        assert_eq!(
            derive_rar5_material(&format!("{prefix}a"), &salt, 0).unwrap(),
            material
        );
        assert_eq!(
            derive_rar5_material(&format!("{prefix}b"), &salt, 0).unwrap(),
            material
        );
    }

    #[test]
    fn test_rar4_kdf_ignores_password_tail_after_rar_behavior_limit() {
        let salt = [0xA5u8; 8];
        let prefix = "p".repeat(RAR_PASSWORD_MAX_UNITS);
        let expected = rar4_derive_key(&prefix, Some(&salt));

        assert_eq!(
            rar4_derive_key(&format!("{prefix}a"), Some(&salt)),
            expected
        );
    }

    #[test]
    fn test_legacy_rar_decryptors_ignore_password_tail_after_rar_behavior_limit() {
        let prefix = "p".repeat(RAR_PASSWORD_MAX_UNITS);
        let long = format!("{prefix}tail");

        assert_eq!(
            Rar13Decryptor::new(&long).key,
            Rar13Decryptor::new(&prefix).key
        );
        assert_eq!(
            Rar15Decryptor::new(&long).key,
            Rar15Decryptor::new(&prefix).key
        );

        let rar20_long = Rar20Decryptor::new(&long);
        let rar20_prefix = Rar20Decryptor::new(&prefix);
        assert_eq!(rar20_long.key, rar20_prefix.key);
        assert_eq!(rar20_long.subst, rar20_prefix.subst);
    }

    #[test]
    fn test_legacy_rar_dos_password_uses_oem_bytes_for_non_ascii() {
        assert_ne!(
            Rar13Decryptor::new("ü").key,
            Rar13Decryptor::new_dos("ü").key
        );
        assert_eq!(
            Rar13Decryptor::new_dos("ü").key,
            Rar13Decryptor::new_from_bytes(&[0x81]).key
        );

        assert_ne!(
            Rar15Decryptor::new("ü").key,
            Rar15Decryptor::new_dos("ü").key
        );
        assert_eq!(
            Rar15Decryptor::new_dos("ü").key,
            Rar15Decryptor::new_from_bytes(&[0x81]).key
        );

        let rar20_dos = Rar20Decryptor::new_dos("ü");
        let rar20_bytes = Rar20Decryptor::new_from_bytes(&[0x81]);
        assert_ne!(Rar20Decryptor::new("ü").key, rar20_dos.key);
        assert_eq!(rar20_dos.key, rar20_bytes.key);
        assert_eq!(rar20_dos.subst, rar20_bytes.subst);
    }

    #[test]
    fn test_rar14_packed_comment_decrypt_uses_rar_behavior_fixed_key() {
        let mut data = [0x54, 0x55, 0x56];

        decrypt_rar14_packed_comment(&mut data);

        assert_eq!(data, [0x00, 0x60, 0x73]);
    }

    #[test]
    fn test_derive_key_deterministic() {
        let salt = [0xAA; 16];
        let (key1, iv1) = derive_key("password", &salt, 0).unwrap();
        let (key2, iv2) = derive_key("password", &salt, 0).unwrap();
        assert_eq!(key1, key2);
        assert_eq!(iv1, iv2);

        // Different password produces different key
        let (key3, _) = derive_key("other", &salt, 0).unwrap();
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_decrypt_round_trip() {
        let key = [0x42u8; 32];
        let iv = [0x13u8; 16];

        // Plaintext must be a multiple of 16 bytes
        let plaintext = b"Hello RAR world!"; // exactly 16 bytes
        assert_eq!(plaintext.len(), 16);

        let ciphertext = encrypt_aes256_cbc_for_test(&key, &iv, plaintext);

        // Decrypt
        let decrypted = decrypt_data(&key, &iv, &ciphertext).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_empty() {
        let key = [0u8; 32];
        let iv = [0u8; 16];
        let result = decrypt_data(&key, &iv, &[]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_decrypt_bad_length() {
        let key = [0u8; 32];
        let iv = [0u8; 16];
        let result = decrypt_data(&key, &iv, &[0u8; 15]);
        assert!(matches!(result, Err(RarError::CorruptArchive { .. })));
    }

    #[test]
    fn test_verify_password_check_consistent() {
        let salt = [0xBB; 16];
        let kdf_count = 0u8;

        // Derive the password check value using the production RAR5 material
        // builder, which internally follows the Count+32 PBKDF2 chain.
        let psw_check = derive_rar5_material("testpass", &salt, kdf_count)
            .unwrap()
            .psw_check;

        let mut check_data = [0u8; 12];
        check_data[..8].copy_from_slice(&psw_check);

        assert!(verify_password_check(
            "testpass",
            &salt,
            kdf_count,
            &check_data
        ));
        assert!(!verify_password_check(
            "wrongpass",
            &salt,
            kdf_count,
            &check_data
        ));
    }

    #[test]
    fn test_password_check_helper_matches_only_expected_prefix() {
        let psw_check = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut check_data = [0u8; 12];
        check_data[..8].copy_from_slice(&psw_check);

        assert!(password_check_matches(&psw_check, &check_data));

        check_data[7] ^= 0xFF;
        assert!(!password_check_matches(&psw_check, &check_data));
    }

    #[test]
    fn test_rar5_aws_lc_material_matches_reference_vector() {
        let salt = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
            0x1E, 0x1F,
        ];
        let native = derive_rar5_material("e2e-test-password", &salt, 6).unwrap();

        assert_eq!(
            hex(&native.key),
            "4e0cc9bdeddb830e9f03f0720ac32be4c8572ed5d250ae815dff1bf85e2af67e"
        );
        assert_eq!(
            hex(&native.hash_key),
            "7de3c9354ee545c2c1b3e4f0a05ebe177465de87c1d134e8914ace0d7ad73a68"
        );
        assert_eq!(hex(&native.psw_check), "c2599769ca19cc07");
    }

    /// The RAR5 PBKDF2 password matrix, pinned.
    ///
    /// `derive_rar5_material` is a compatibility constant: its three outputs
    /// are what every existing encrypted RAR5 archive was written against, so
    /// they may never move — not for a performance change, not for a backend
    /// swap. These expectations were captured from the **pre-cached-context**
    /// implementation (a fresh `aws_lc_rs::hmac::sign` per PBKDF2 iteration)
    /// and reproduced identically by the pre-change RustCrypto backend, which
    /// is why the same table gates every backend and every target: run it under
    /// `--features crypto-rust` or on wasm and it must still hold.
    ///
    /// The matrix deliberately spans the regimes that make the HMAC key
    /// handling branch — an empty password, keys shorter than / exactly /
    /// longer than the 64-byte SHA-256 block (the over-long ones are hashed
    /// down first), non-ASCII UTF-8, and a password past RAR's 127-unit
    /// truncation limit — crossed with four salts and KDF counts from 2^0 to
    /// 2^17 (the last exercising the long iteration chain, plus both extended
    /// +16 tails that produce the hash key and the password-check value).
    #[test]
    fn test_rar5_material_matches_pinned_pre_change_vectors() {
        let passwords: [String; 11] = [
            String::new(),
            "a".to_string(),
            "password".to_string(),
            "e2e-test-password".to_string(),
            "moonlit-harbour".to_string(),
            "a".repeat(63),
            "b".repeat(64),
            "c".repeat(65),
            "d".repeat(200),
            "Grüße😀 königsallee".to_string(),
            format!("{}tail", "p".repeat(RAR_PASSWORD_MAX_UNITS)),
        ];

        let mut salt_ramp = [0u8; 16];
        for (index, byte) in salt_ramp.iter_mut().enumerate() {
            *byte = 0x10 + index as u8;
        }
        let mut salt_stride = [0u8; 16];
        for (index, byte) in salt_stride.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(37).wrapping_add(11);
        }
        let salts: [[u8; 16]; 4] = [[0x00; 16], [0xFF; 16], salt_ramp, salt_stride];

        // (password index, salt index, lg2 count, key, hash key, psw check)
        const VECTORS: &[(usize, usize, u8, &str, &str, &str)] = &[
            (
                0,
                0,
                0,
                "c8c2ef93624f53f746ad5664441f9e04f1dde6c84f8f0a06689d9f4ef61ec1bd",
                "0e57fdea9ee639376781ae31ee36a7cc62ba390bd38ba5001b494d3ab29d8c42",
                "bbf59e9588c5a77e",
            ),
            (
                1,
                1,
                1,
                "2b63fa5dc13ab42a5ce067ffda3ab2832b5293ff8f78b039c5fae9193baba332",
                "3874db6a501f999439d4913153b64295e1cef289212e67d3470e13179825491b",
                "43aadcb7c595b038",
            ),
            (
                2,
                2,
                4,
                "06c7dc5c1a7771be150f420258cf9e872721b660b4ba9b5b88bf3d2c6ff96fe1",
                "6260b58333bff37c5aafbe2b606e7d1d596ee594a73ae6dde787b2f03f12b123",
                "b9042cd3813975e4",
            ),
            (
                3,
                3,
                6,
                "f1ff8917c7adada118e9847ba69a0d072d4d73a2e5269e5425ce3e7bf8e347f0",
                "f00ed65c6e32630f71dfe33a1219126a2c1c7050347d547f7d23dee9643ab7ee",
                "db985fa3342eef58",
            ),
            (
                4,
                0,
                1,
                "da3f7db328dc4f7426af6630c03db980beff2627e31a8a27181836a6ae89bfab",
                "731a62f6568a6de046ba401cceb45e11c39b09d712ffe528191355590a05bf16",
                "b7b4e9093d6ce428",
            ),
            (
                5,
                1,
                0,
                "a310cbda8cfc7b61e259f96ce89e75cdaf82975fa8ebab8a2be20d164956fe33",
                "f69d31b5667698da5654ee1c36e2850d7438f6a3d6ba0f14447bc38b47662e4e",
                "d6d68a9e41c09dcc",
            ),
            (
                6,
                2,
                1,
                "0500aa6434cff2f4e09b82c2850dbfba5981c87e9229eced2dbdbd061ce4832b",
                "9344239fc495265ede3cdcc4f6b3753aa33289af6185fb97bdebbcc6f4c8d785",
                "4dfea124eae718d8",
            ),
            (
                7,
                3,
                4,
                "e067f683b36f4d53cd690e08a2b8e29efaef476f3da7a991bb3ac4d760382b30",
                "4fe93b5074a20c153e653872520020ffe75a18250c8cd55b1221265a1c84f085",
                "8a93b816a550a2e4",
            ),
            (
                8,
                0,
                4,
                "9ae5c957a46bffb1242ba22c84d24e8de1b84c65fb3d845a2d386e96b00c31c7",
                "5e04833957290cbc29a688dfe1fd488dc8743446da273e1127a3791d39568145",
                "307a00f99661b27f",
            ),
            (
                9,
                1,
                6,
                "75e57fe515e799945ee5b52af60d65232614565d333bf5b8e090c35ee38803e3",
                "a1841a38f916aa5fe0d27070d61c42f2551d8e68b8faa694e956a65aea18707b",
                "0eb7d5fdf27b165a",
            ),
            (
                10,
                2,
                0,
                "c5ba853db1e9a53dad321baa11dcea0d5a9ada4111bb012ee56d51bc0727a6df",
                "18085f5c2165b70e5f84e18b96560139f29c963ecccecd4ae1388d5219255317",
                "52ddfca0643ae491",
            ),
            (
                2,
                3,
                0,
                "c9f7abe7f1b2a505e650bea511329ecf8b7ebe59023b45d31fc73aa04763c8fb",
                "f5144338da4e13b63954cf34517fddeab95b55faf7eb5c379d90f98c27f6163c",
                "1e277388536fab24",
            ),
            (
                3,
                0,
                15,
                "09b929115a2f66f650330cde4410088ba62244ce7c33983c7ab252efc963234f",
                "5e61aea2b17d01e53879445d894f1609aca9bb70daee573119497a8564afd721",
                "b089d8b2987a2125",
            ),
            (
                9,
                1,
                16,
                "4ef1f48c1324fba00a6b40a8d8e821fb98c39588f2be20bd4678d063a0de9754",
                "b946e9545a6cfd41199102d32d85533eb8df0440a8eb4cce8ef36602a686461c",
                "8accb57e06f2d95d",
            ),
            (
                7,
                2,
                17,
                "ce82fc96c2e8300c9ea4606dee63e82f31fdbf994ca0015db5d477b5655df896",
                "a798401f41e64686bb4390dee0c36150a59ac467401aea80676fd97530416387",
                "665f3487f57a4431",
            ),
            (
                0,
                3,
                1,
                "a704da2baf23134e62ef3d18c362019d1b649856bdbd8316144b2f7adf4de91d",
                "afb8e4732f7cb1c05ae373cb0d35ed3725030f7ff9277c200cf8bd3c2ab85f08",
                "556d4acdf211afb9",
            ),
            (
                1,
                0,
                4,
                "883ac9bd895d7849fc13338c6b222be4d0548ac5505acfc9d2c72862a71eed57",
                "b92fa9eaaf5e85af5b314cbacb309f6a288e6816a2a7dd05bbf53c6a406bec52",
                "d7ea3732123f0b04",
            ),
            (
                4,
                1,
                15,
                "9afaedcba0da93d5057f946c3585c40b482165cc1b0fe3c2d97f97312ce188c9",
                "997046660233aac933e1ea63a51b01e228a139c0d109f3730abd19e9623a807b",
                "bbef6ca08106b0c8",
            ),
            (
                6,
                3,
                6,
                "7b5ed7043e3756ea899fc45345e86241902548c3a4fa80dc3fe71263e8f43f3f",
                "0d1df12d24fda06e39209401a1732d46fc2f5029a31da0ac1073bf027ddba2a9",
                "8ec473eb4a95a3af",
            ),
            (
                8,
                2,
                1,
                "9b171ebde79c39cee02239aa323a4cdda5324ae0bf68ec5a7d325e6d6f101b6a",
                "afe545a594bd2d561ba2a925d07037c868b4ff638d8b3f8aa4c10402e8138050",
                "efefdf70cd9ae47f",
            ),
        ];

        for &(password, salt, lg2, key, hash_key, psw_check) in VECTORS {
            let material = derive_rar5_material(&passwords[password], &salts[salt], lg2).unwrap();
            let case = format!("password {password}, salt {salt}, lg2 {lg2}");
            assert_eq!(hex(&material.key), key, "key moved: {case}");
            assert_eq!(hex(&material.hash_key), hash_key, "hash key moved: {case}");
            assert_eq!(
                hex(&material.psw_check),
                psw_check,
                "password check moved: {case}"
            );
        }
    }

    #[test]
    fn test_rar5_kdf_count_above_rar_behavior_limit_is_unsupported() {
        let salt = [0xAB; 16];
        let result = derive_rar5_material(
            "cache-pass",
            &salt,
            CRYPT5_KDF_LG2_COUNT_MAX.saturating_add(1),
        );

        assert!(matches!(
            result,
            Err(RarError::UnsupportedEncryptionKdf { count, max })
                if count == CRYPT5_KDF_LG2_COUNT_MAX + 1
                    && max == CRYPT5_KDF_LG2_COUNT_MAX
        ));
    }

    #[test]
    fn test_rar5_kdf_cache_reuses_cached_material() {
        let cache = KdfCache::new();
        let salt = [0xAB; 16];

        cache.derive_material_rar5("cache-pass", &salt, 4).unwrap();
        assert_eq!(cache.rar5.lock().unwrap().0.len(), 1);

        cache.derive_material_rar5("cache-pass", &salt, 4).unwrap();
        assert_eq!(cache.rar5.lock().unwrap().0.len(), 1);
    }

    // RAR4 crypto tests

    #[test]
    fn test_rar4_derive_key_deterministic() {
        let salt = [0xCC; 8];
        let (key1, iv1) = rar4_derive_key("password", Some(&salt));
        let (key2, iv2) = rar4_derive_key("password", Some(&salt));
        assert_eq!(key1, key2);
        assert_eq!(iv1, iv2);

        // Different password produces different key.
        let (key3, _) = rar4_derive_key("other", Some(&salt));
        assert_ne!(key1, key3);

        // Different salt produces different key.
        let (key4, _) = rar4_derive_key("password", Some(&[0xDD; 8]));
        assert_ne!(key1, key4);
    }

    #[test]
    fn test_rar4_derive_key_matches_rar_behavior_rar29_sha1() {
        let salt = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let (short_key, short_iv) = rar4_derive_key("password", Some(&salt));
        assert_eq!(hex(&short_key), "6dc5de01e3b2dbe3be10be0a04a61451");
        assert_eq!(hex(&short_iv), "28578a432b367b73dccfd439911f9584");

        let long_password = "abcdefghijklmnopqrstuvwxyzabcdef";
        let (long_key, long_iv) = rar4_derive_key(long_password, Some(&salt));
        assert_eq!(hex(&long_key), "d74f5e96dd94aa870efe4fdcd3d3e155");
        assert_eq!(hex(&long_iv), "4b12f8f5e926761d3ab3a3c98cc00d48");

        let (saltless_key, saltless_iv) = rar4_derive_key(long_password, None);
        assert_eq!(hex(&saltless_key), "a067cc19f522570c5440adfabc8ae733");
        assert_eq!(hex(&saltless_iv), "1a1eb51d88c1905a6c09328074c39f42");
    }

    #[test]
    fn test_rar4_long_password_kdf_matches_reference_vector() {
        // Generated from the RAR4 KDF and RAR29 SHA-1 reference algorithm.
        let salt = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let password = "abcdefghijklmnopqrstuvwxyzabcdef";

        let (key, iv) = rar4_derive_key(password, Some(&salt));

        assert_eq!(hex(&key), "6409b206ed974788e3d4819e4edba9b1");
        assert_eq!(hex(&iv), "87bbc0bf98daa1aa13e010cf14ced6ce");
    }

    #[test]
    fn test_rar4_derive_key_saltless_differs_from_salted() {
        let salt = [0xCC; 8];
        let (saltless_key, saltless_iv) = rar4_derive_key("password", None);
        let (salted_key, salted_iv) = rar4_derive_key("password", Some(&salt));
        assert_ne!(saltless_key, salted_key);
        assert_ne!(saltless_iv, salted_iv);
    }

    #[test]
    fn test_rar4_decrypt_round_trip() {
        let key = [0x42u8; 16];
        let iv = [0x13u8; 16];

        let plaintext = b"RAR4 encrypted!!"; // 16 bytes
        assert_eq!(plaintext.len(), 16);

        let ciphertext = encrypt_aes128_cbc_for_test(&key, &iv, plaintext);

        // Decrypt
        let decrypted = rar4_decrypt_data(&key, &iv, &ciphertext).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_rar4_decrypt_empty() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let result = rar4_decrypt_data(&key, &iv, &[]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_rar4_decrypt_bad_length() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let result = rar4_decrypt_data(&key, &iv, &[0u8; 15]);
        assert!(matches!(result, Err(RarError::CorruptArchive { .. })));
    }

    #[test]
    fn test_rar4_kdf_with_derived_key_round_trip() {
        let salt = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let (key, iv) = rar4_derive_key("testpassword", Some(&salt));

        // Encrypt 32 bytes of plaintext.
        let plaintext = b"Hello from RAR4 encryption test!"; // 32 bytes
        assert_eq!(plaintext.len(), 32);

        let ciphertext = encrypt_aes128_cbc_for_test(&key, &iv, plaintext);

        assert_ne!(&ciphertext, plaintext);

        let decrypted = rar4_decrypt_data(&key, &iv, &ciphertext).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_rar4_custom_kdf_matches_reference_vector() {
        let salt = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let (key, iv) = rar4_derive_key("e2e-test-password", Some(&salt));

        assert_eq!(hex(&key), "36b07b37fb4e20e63b54fd54aa00ede9");
        assert_eq!(hex(&iv), "57ea4f82b145f2aa06f7c23f546d9561");
    }

    struct ChunkedCursor {
        cursor: std::io::Cursor<Vec<u8>>,
        max_chunk: usize,
    }

    impl ChunkedCursor {
        fn new(bytes: Vec<u8>, max_chunk: usize) -> Self {
            Self {
                cursor: std::io::Cursor::new(bytes),
                max_chunk,
            }
        }
    }

    impl Read for ChunkedCursor {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let limit = buf.len().min(self.max_chunk);
            self.cursor.read(&mut buf[..limit])
        }
    }

    #[test]
    fn test_rar4_streaming_reader_multi_block_round_trip() {
        let key = [0x21u8; 16];
        let iv = [0x43u8; 16];
        let plaintext = [0x52u8; AES_BLOCK * 4];
        let ciphertext = encrypt_aes128_cbc_for_test(&key, &iv, &plaintext);

        let inner = ChunkedCursor::new(ciphertext, 23);
        let mut reader = DecryptingReader::new_rar4(inner, &key, &iv);
        let mut actual = Vec::new();
        let mut chunk = [0u8; 19];
        loop {
            let read = reader.read(&mut chunk).unwrap();
            if read == 0 {
                break;
            }
            actual.extend_from_slice(&chunk[..read]);
        }

        assert_eq!(actual, plaintext);
    }

    #[test]
    fn test_rar5_streaming_reader_multi_block_round_trip() {
        let key = [0x34u8; 32];
        let iv = [0x56u8; 16];
        let plaintext = [0x35u8; AES_BLOCK * 4];
        let ciphertext = encrypt_aes256_cbc_for_test(&key, &iv, &plaintext);

        let inner = ChunkedCursor::new(ciphertext, 29);
        let mut reader = DecryptingReader::new_rar5(inner, &key, &iv);
        let mut actual = Vec::new();
        let mut chunk = [0u8; 17];
        loop {
            let read = reader.read(&mut chunk).unwrap();
            if read == 0 {
                break;
            }
            actual.extend_from_slice(&chunk[..read]);
        }

        assert_eq!(actual, plaintext);
    }

    /// Inner reader that returns a scripted (cycling) number of bytes per
    /// call, so an AES block can be split across inner reads the way a volume
    /// boundary splits one.
    struct ScriptedCursor {
        data: Vec<u8>,
        pos: usize,
        sizes: Vec<usize>,
        next: usize,
    }

    impl ScriptedCursor {
        fn new(data: Vec<u8>, sizes: Vec<usize>) -> Self {
            Self {
                data,
                pos: 0,
                sizes,
                next: 0,
            }
        }
    }

    impl Read for ScriptedCursor {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.pos >= self.data.len() || buf.is_empty() {
                return Ok(0);
            }
            let want = self.sizes[self.next % self.sizes.len()].max(1);
            self.next += 1;
            let take = want.min(buf.len()).min(self.data.len() - self.pos);
            buf[..take].copy_from_slice(&self.data[self.pos..self.pos + take]);
            self.pos += take;
            Ok(take)
        }
    }

    fn decrypt_test_bytes(len: usize, seed: u64) -> Vec<u8> {
        let mut state = seed | 1;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 27) as u8
            })
            .collect()
    }

    fn read_all_in_steps<R: Read>(reader: &mut R, step: usize) -> std::io::Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut buf = vec![0u8; step];
        loop {
            let read = reader.read(&mut buf)?;
            if read == 0 {
                return Ok(out);
            }
            out.extend_from_slice(&buf[..read]);
        }
    }

    /// In-place decryption must reproduce the plaintext byte for byte no matter
    /// how the inner stream is split or how large the caller's reads are —
    /// including reads shorter than one AES block, which cannot decrypt in
    /// place and take the staged-block path instead.
    #[test]
    fn decrypting_reader_is_byte_identical_across_read_and_split_sizes() {
        let key256 = [0x9au8; 32];
        let key128 = [0x4eu8; 16];
        let iv = [0x1cu8; 16];
        let plaintext = decrypt_test_bytes(AES_BLOCK * 512, 0xfeed);
        let cipher256 = encrypt_aes256_cbc_for_test(&key256, &iv, &plaintext);
        let cipher128 = encrypt_aes128_cbc_for_test(&key128, &iv, &plaintext);

        for &split in &[1usize, 3, 15, 16, 17, 64, 1000, 4096, 65_536] {
            for &step in &[1usize, 2, 15, 16, 17, 31, 97, 1024, 4095, 8192] {
                let inner = ChunkedCursor::new(cipher256.clone(), split);
                let mut reader = DecryptingReader::new_rar5(inner, &key256, &iv);
                assert_eq!(
                    read_all_in_steps(&mut reader, step).unwrap(),
                    plaintext,
                    "rar5 split {split} step {step}"
                );

                let inner = ChunkedCursor::new(cipher128.clone(), split);
                let mut reader = DecryptingReader::new_rar4(inner, &key128, &iv);
                assert_eq!(
                    read_all_in_steps(&mut reader, step).unwrap(),
                    plaintext,
                    "rar4 split {split} step {step}"
                );
            }
        }
    }

    #[test]
    fn decrypting_reader_matches_plaintext_under_randomized_read_sizes() {
        let key = [0x5du8; 32];
        let iv = [0xa7u8; 16];
        let plaintext = decrypt_test_bytes(AES_BLOCK * 2048, 0xc0ffee);
        let ciphertext = encrypt_aes256_cbc_for_test(&key, &iv, &plaintext);

        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut next = |bound: usize| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state % bound as u64) as usize + 1
        };

        for round in 0..8 {
            let inner_sizes: Vec<usize> = (0..64).map(|_| next(9_001)).collect();
            let read_sizes: Vec<usize> = (0..64).map(|_| next(8_192)).collect();
            let inner = ScriptedCursor::new(ciphertext.clone(), inner_sizes);
            let mut reader = DecryptingReader::new_rar5(inner, &key, &iv);

            let mut actual = Vec::new();
            let mut buf = vec![0u8; 8_192];
            let mut index = 0usize;
            loop {
                let want = read_sizes[index % read_sizes.len()];
                index += 1;
                let read = reader.read(&mut buf[..want]).unwrap();
                if read == 0 {
                    break;
                }
                actual.extend_from_slice(&buf[..read]);
            }
            assert_eq!(actual, plaintext, "round {round}");
        }
    }

    /// The reader must not impose a staging cap of its own: a caller asking for
    /// a megabyte from a source that can supply it gets a megabyte.
    #[test]
    fn decrypting_reader_fills_large_buffers_in_one_call() {
        let key = [0x11u8; 32];
        let iv = [0x22u8; 16];
        let plaintext = decrypt_test_bytes(1 << 20, 7);
        let ciphertext = encrypt_aes256_cbc_for_test(&key, &iv, &plaintext);

        let mut reader = DecryptingReader::new_rar5(std::io::Cursor::new(ciphertext), &key, &iv);
        let mut buf = vec![0u8; 1 << 20];
        let read = reader.read(&mut buf).unwrap();
        assert_eq!(read, 1 << 20);
        assert_eq!(buf, plaintext);
    }

    #[test]
    fn decrypting_reader_rejects_a_stream_that_is_not_block_aligned() {
        let key = [0x77u8; 32];
        let iv = [0x88u8; 16];
        let plaintext = decrypt_test_bytes(AES_BLOCK * 3, 5);
        let mut ciphertext = encrypt_aes256_cbc_for_test(&key, &iv, &plaintext);
        ciphertext.truncate(AES_BLOCK * 2 + 5);

        // Both the in-place path (step >= block) and the staged path.
        for step in [4usize, 64] {
            let inner = std::io::Cursor::new(ciphertext.clone());
            let mut reader = DecryptingReader::new_rar5(inner, &key, &iv);
            let error = read_all_in_steps(&mut reader, step).unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData, "step {step}");
        }
    }

    // -----------------------------------------------------------------------
    // E-D2 range decryption and E-D1 password admission
    // -----------------------------------------------------------------------

    #[test]
    fn decrypt_cipher_range_matches_a_whole_stream_decrypt_from_any_block() {
        // The property the whole write transform rests on: decrypting block N
        // needs block N-1 and nothing else. Every block boundary of a stream is
        // tried, so this is the general statement, not one lucky offset.
        let key = [0x21u8; 32];
        let iv = [0x9Cu8; 16];
        let plaintext: Vec<u8> = (0..AES_BLOCK * 8).map(|i| (i * 7 + 3) as u8).collect();
        let ciphertext = encrypt_aes256_cbc_for_test(&key, &iv, &plaintext);

        for start in (0..ciphertext.len()).step_by(AES_BLOCK) {
            for end in ((start + AES_BLOCK)..=ciphertext.len()).step_by(AES_BLOCK) {
                let preceding: [u8; AES_BLOCK] = if start == 0 {
                    iv
                } else {
                    ciphertext[start - AES_BLOCK..start].try_into().unwrap()
                };
                let mut range = ciphertext[start..end].to_vec();
                decrypt_cipher_range(&key, &preceding, &mut range).unwrap();
                assert_eq!(range, plaintext[start..end], "range {start}..{end}");
            }
        }
    }

    #[test]
    fn decrypt_cipher_range_corrupts_only_its_first_block_on_a_wrong_predecessor() {
        // Stated because it is the failure mode a router has to reason about:
        // the wrong preceding block is not an error anyone can raise here, it
        // is one block of garbage and a correct remainder.
        let key = [0x21u8; 32];
        let iv = [0x9Cu8; 16];
        let plaintext: Vec<u8> = (0..AES_BLOCK * 4).map(|i| (i * 5 + 1) as u8).collect();
        let ciphertext = encrypt_aes256_cbc_for_test(&key, &iv, &plaintext);

        let mut range = ciphertext[AES_BLOCK..].to_vec();
        decrypt_cipher_range(&key, &[0u8; AES_BLOCK], &mut range).unwrap();

        assert_ne!(range[..AES_BLOCK], plaintext[AES_BLOCK..AES_BLOCK * 2]);
        assert_eq!(range[AES_BLOCK..], plaintext[AES_BLOCK * 2..]);
    }

    #[test]
    fn decrypt_cipher_range_refuses_a_partial_block_and_accepts_an_empty_one() {
        let key = [0x21u8; 32];
        let mut partial = vec![0u8; AES_BLOCK + 1];
        assert!(matches!(
            decrypt_cipher_range(&key, &[0u8; AES_BLOCK], &mut partial),
            Err(RarError::CorruptArchive { .. })
        ));
        assert!(decrypt_cipher_range(&key, &[0u8; AES_BLOCK], &mut []).is_ok());
    }

    #[test]
    fn encrypt_cipher_range_is_the_exact_inverse_of_decrypt_cipher_range() {
        // The property a reader that holds only the plaintext rests on: the
        // posted bytes are reproducible from any block boundary, given that
        // block's predecessor and nothing else. Every boundary of a stream is
        // tried, in both directions, so this is the general statement.
        let key = [0x21u8; 32];
        let iv = [0x9Cu8; 16];
        let plaintext: Vec<u8> = (0..AES_BLOCK * 8).map(|i| (i * 7 + 3) as u8).collect();
        let ciphertext = encrypt_aes256_cbc_for_test(&key, &iv, &plaintext);

        for start in (0..plaintext.len()).step_by(AES_BLOCK) {
            for end in ((start + AES_BLOCK)..=plaintext.len()).step_by(AES_BLOCK) {
                let preceding: [u8; AES_BLOCK] = if start == 0 {
                    iv
                } else {
                    ciphertext[start - AES_BLOCK..start].try_into().unwrap()
                };
                let mut range = plaintext[start..end].to_vec();
                encrypt_cipher_range(&key, &preceding, &mut range).unwrap();
                assert_eq!(range, ciphertext[start..end], "range {start}..{end}");

                // And straight back, through the decrypt this is the inverse of.
                decrypt_cipher_range(&key, &preceding, &mut range).unwrap();
                assert_eq!(range, plaintext[start..end], "round trip {start}..{end}");
            }
        }
    }

    #[test]
    fn encrypt_cipher_range_diverges_from_the_posted_stream_on_a_wrong_predecessor() {
        // The mirror of the decrypt's wrong-predecessor test, and deliberately
        // **not** the same statement. Decryption is self-healing: a wrong
        // predecessor spoils one block and the rest come out right. Encryption
        // is not — each ciphertext block is the next one's chaining input — so
        // every block from the first onwards differs from what was posted.
        // Nothing here can raise that as an error, which is why the caller owns
        // the predecessor and why the docs say so.
        let key = [0x21u8; 32];
        let iv = [0x9Cu8; 16];
        let plaintext: Vec<u8> = (0..AES_BLOCK * 4).map(|i| (i * 5 + 1) as u8).collect();
        let ciphertext = encrypt_aes256_cbc_for_test(&key, &iv, &plaintext);

        let mut range = plaintext[AES_BLOCK..].to_vec();
        encrypt_cipher_range(&key, &[0u8; AES_BLOCK], &mut range).unwrap();

        for block in 0..range.len() / AES_BLOCK {
            let at = block * AES_BLOCK;
            assert_ne!(
                range[at..at + AES_BLOCK],
                ciphertext[AES_BLOCK + at..AES_BLOCK + at + AES_BLOCK],
                "block {block} must not happen to match the posted stream"
            );
        }
        // And the right predecessor reproduces it exactly, so the divergence is
        // the predecessor's doing and nothing else's.
        let mut range = plaintext[AES_BLOCK..].to_vec();
        let preceding: [u8; AES_BLOCK] = ciphertext[..AES_BLOCK].try_into().unwrap();
        encrypt_cipher_range(&key, &preceding, &mut range).unwrap();
        assert_eq!(range, ciphertext[AES_BLOCK..]);
    }

    #[test]
    fn encrypt_cipher_range_refuses_a_partial_block_and_accepts_an_empty_one() {
        // Returned, never asserted: the caller is a reader on a blocking pool,
        // and a contract violation has to come back as a refusal it can report
        // as unavailable bytes rather than as a panicked task.
        let key = [0x21u8; 32];
        for length in [1usize, AES_BLOCK - 1, AES_BLOCK + 1, AES_BLOCK * 2 + 3] {
            let mut partial = vec![0u8; length];
            assert!(
                matches!(
                    encrypt_cipher_range(&key, &[0u8; AES_BLOCK], &mut partial),
                    Err(RarError::CorruptArchive { .. })
                ),
                "a {length}-byte range must be refused rather than panic"
            );
        }
        assert!(encrypt_cipher_range(&key, &[0u8; AES_BLOCK], &mut []).is_ok());
    }

    #[test]
    fn the_rar4_cipher_range_pair_is_an_exact_inverse_at_every_block_boundary() {
        // The AES-128 twin of the two properties above, stated as
        // one test because the RAR4 pair is the same claim over the same shape.
        // The key and IV are a real derivation rather than constants, so what is
        // exercised is the key a router would actually hold.
        let (key, iv) = rar4_derive_key("moonlit-harbour", Some(&[0x11u8; 8]));
        let plaintext: Vec<u8> = (0..AES_BLOCK * 8).map(|i| (i * 11 + 5) as u8).collect();
        let ciphertext = encrypt_aes128_cbc_for_test(&key, &iv, &plaintext);

        for start in (0..plaintext.len()).step_by(AES_BLOCK) {
            for end in ((start + AES_BLOCK)..=plaintext.len()).step_by(AES_BLOCK) {
                let preceding: [u8; AES_BLOCK] = if start == 0 {
                    iv
                } else {
                    ciphertext[start - AES_BLOCK..start].try_into().unwrap()
                };
                let mut range = plaintext[start..end].to_vec();
                encrypt_cipher_range_rar4(&key, &preceding, &mut range).unwrap();
                assert_eq!(range, ciphertext[start..end], "encrypt {start}..{end}");
                decrypt_cipher_range_rar4(&key, &preceding, &mut range).unwrap();
                assert_eq!(range, plaintext[start..end], "round trip {start}..{end}");
            }
        }
    }

    #[test]
    fn the_rar4_cipher_range_pair_refuses_a_partial_block_and_accepts_an_empty_one() {
        let (key, _) = rar4_derive_key("moonlit-harbour", None);
        for length in [1usize, AES_BLOCK - 1, AES_BLOCK + 1, AES_BLOCK * 2 + 3] {
            let mut partial = vec![0u8; length];
            assert!(matches!(
                encrypt_cipher_range_rar4(&key, &[0u8; AES_BLOCK], &mut partial),
                Err(RarError::CorruptArchive { .. })
            ));
            assert!(matches!(
                decrypt_cipher_range_rar4(&key, &[0u8; AES_BLOCK], &mut partial),
                Err(RarError::CorruptArchive { .. })
            ));
        }
        assert!(encrypt_cipher_range_rar4(&key, &[0u8; AES_BLOCK], &mut []).is_ok());
        assert!(decrypt_cipher_range_rar4(&key, &[0u8; AES_BLOCK], &mut []).is_ok());
    }

    #[test]
    fn member_cipher_key_dispatches_to_the_width_its_variant_names() {
        // The one thing a dispatching enum can get wrong is dispatching: an
        // `Aes128` that quietly ran AES-256 over the first 16 bytes of a wider
        // key would decrypt nothing correctly, and an `Aes256` that truncated
        // would be worse. Both variants are held to the free functions they
        // stand for, byte for byte.
        let plaintext: Vec<u8> = (0..AES_BLOCK * 6).map(|i| (i * 13 + 7) as u8).collect();
        let preceding = [0x3Cu8; 16];

        let (rar4_key, _) = rar4_derive_key("moonlit-harbour", Some(&[0x22u8; 8]));
        let mut through_enum = plaintext.clone();
        MemberCipherKey::Aes128(rar4_key)
            .encrypt_range(&preceding, &mut through_enum)
            .unwrap();
        assert_eq!(
            through_enum,
            encrypt_aes128_cbc_for_test(&rar4_key, &preceding, &plaintext)
        );
        MemberCipherKey::Aes128(rar4_key)
            .decrypt_range(&preceding, &mut through_enum)
            .unwrap();
        assert_eq!(through_enum, plaintext);

        let rar5_key = derive_rar5_material("moonlit-harbour", &[0x5Au8; 16], 4)
            .unwrap()
            .key;
        let mut through_enum = plaintext.clone();
        MemberCipherKey::Aes256(rar5_key)
            .encrypt_range(&preceding, &mut through_enum)
            .unwrap();
        assert_eq!(
            through_enum,
            encrypt_aes256_cbc_for_test(&rar5_key, &preceding, &plaintext)
        );
        MemberCipherKey::Aes256(rar5_key)
            .decrypt_range(&preceding, &mut through_enum)
            .unwrap();
        assert_eq!(through_enum, plaintext);
    }

    #[test]
    fn check_member_password_separates_wrong_from_unverifiable() {
        let salt = [0x5Au8; 16];
        let kdf_count = 4;
        let cache = KdfCache::new();

        let psw_check = derive_rar5_material("testpass123", &salt, kdf_count)
            .unwrap()
            .psw_check;
        let mut check_data = [0u8; 12];
        check_data[..8].copy_from_slice(&psw_check);
        check_data[8..].copy_from_slice(&sha256_digest(&psw_check)[..4]);

        assert_eq!(
            check_member_password(&cache, "testpass123", &salt, kdf_count, Some(&check_data)),
            PasswordCheck::Verified
        );
        assert_eq!(
            check_member_password(&cache, "testpass124", &salt, kdf_count, Some(&check_data)),
            PasswordCheck::Wrong
        );
        // No check value at all: the password may be right, but nothing here
        // can say so — which is a different answer from `Wrong`, and the whole
        // reason the two are distinct variants.
        assert_eq!(
            check_member_password(&cache, "testpass124", &salt, kdf_count, None),
            PasswordCheck::Unverifiable
        );
        // A KDF count the crate refuses never runs a derivation, so it cannot
        // refute the password either.
        assert_eq!(
            check_member_password(
                &cache,
                "testpass123",
                &salt,
                CRYPT5_KDF_LG2_COUNT_MAX + 1,
                Some(&check_data)
            ),
            PasswordCheck::Unverifiable
        );
    }
}
