//! Component-model host delegation: the embedder-supplied crypto/CRC hooks.
//!
//! `crypto-host` and `crc-host` delegate the bulk AES-CBC decrypt and the bulk
//! member-data CRC-32 to the embedding host. The `host-abi-extism` /
//! default-`host` namespaces reach the host through raw wasm imports that take
//! guest pointers, which works for a core wasm module because the host can
//! slice the guest's exported linear memory in place.
//!
//! A **WASI Preview 2 component** cannot do that: a component has no exported
//! memory the host may address, and every value crosses the boundary through
//! the canonical ABI. The `host-abi-component` feature therefore replaces the
//! raw imports with plain Rust function pointers that the embedding *plugin*
//! installs at startup. The plugin owns the transport — typically a
//! `wit_bindgen`-generated import such as `scryer:archive/crypto@1.0.0` — and
//! this crate never learns what that transport is. `unrar-rs` depends on
//! neither `wit-bindgen` nor any WIT world; it only calls the two `fn` pointers
//! it was handed.
//!
//! ## The seam
//!
//! ```ignore
//! use unrar_rs::component_abi::{HostAesError, HostCryptoHooks, install_host_crypto_hooks};
//!
//! fn aes(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, HostAesError> {
//!     // forward to the component's `crypto.aes-cbc-decrypt` import
//! }
//! fn crc(seed: u32, data: &[u8]) -> u32 {
//!     // forward to the component's `crypto.crc32` import
//! }
//!
//! install_host_crypto_hooks(HostCryptoHooks { aes_cbc_decrypt: aes, crc32: crc });
//! ```
//!
//! ## Contract the hooks must satisfy
//!
//! * `aes_cbc_decrypt(key, iv, data)` returns the AES-CBC decryption of `data`
//!   under `key`/`iv`, **no padding**, as a fresh buffer of exactly `data.len()`
//!   bytes. `key` is 16 or 32 bytes, `iv` is exactly 16, `data` is a whole
//!   number of 16-byte blocks and may be empty. The hook is STATELESS per call:
//!   this crate threads the CBC IV across chunks itself (see
//!   `crate::crypto::backend::host`), exactly as the raw-import backend does.
//! * `crc32(seed, data)` returns the reflected IEEE CRC-32 (polynomial
//!   `0xEDB88320`) of `data` resumed from `seed`. Empty `data` returns `seed`.
//!   It must chain: `crc32(crc32(0, a), b) == crc32(0, a ++ b)`.
//!
//! A hook that reports an error, returns the wrong length, or is missing
//! entirely is a host contract violation and panics — matching the raw-import
//! backend, which likewise treats a negative status as unrecoverable.

// The two host ABIs are alternatives, not layers: one declares raw wasm imports
// in a namespace, the other declares none at all. Cargo features must stay
// additive (feature unification across a dependency graph, `--all-features`
// tooling such as cargo-semver-checks and rustdoc), so enabling both is not an
// error: this feature takes precedence. Every raw-import declaration in
// `crate::crc` and `crate::crypto::backend::host` is compiled only under
// `not(feature = "host-abi-component")`, which leaves `host-abi-extism` with
// nothing to rename — it selects a namespace for imports that are not declared.

use std::sync::RwLock;

/// Why the embedder's AES-CBC hook refused a call.
///
/// These mirror the length/alignment rejections a host may report; each one is
/// a contract violation on this crate's side, because the callers below only
/// ever pass 16/32-byte keys, 16-byte IVs, and block-aligned buffers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostAesError {
    /// `key` was neither 16 nor 32 bytes.
    BadKeyLength,
    /// `data` was not a whole number of 16-byte AES blocks.
    BadBlockLength,
    /// `iv` was not exactly 16 bytes.
    BadIvLength,
}

impl std::fmt::Display for HostAesError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::BadKeyLength => "host rejected the AES key length",
            Self::BadBlockLength => "host rejected the AES block alignment",
            Self::BadIvLength => "host rejected the AES IV length",
        })
    }
}

impl std::error::Error for HostAesError {}

/// Decrypt `data` (block-aligned, may be empty) under `key`/`iv`, returning a
/// buffer of the same length. Stateless per call.
pub type AesCbcDecryptHook =
    fn(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, HostAesError>;

/// Resume a reflected IEEE CRC-32 from `seed` over `data`.
pub type Crc32Hook = fn(seed: u32, data: &[u8]) -> u32;

/// The pair of embedder-supplied delegation hooks.
///
/// Both are plain `fn` pointers rather than trait objects or closures: they
/// carry no state, are `Copy`, and can therefore be read on the hot path
/// without allocation. State the hooks need belongs to the embedding plugin,
/// which is a single component instance per invocation.
#[derive(Clone, Copy)]
pub struct HostCryptoHooks {
    /// Bulk AES-CBC decrypt (consumed when `crypto-host` is enabled).
    pub aes_cbc_decrypt: AesCbcDecryptHook,
    /// Bulk member-data CRC-32 (consumed when `crc-host` is enabled).
    pub crc32: Crc32Hook,
}

impl std::fmt::Debug for HostCryptoHooks {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("HostCryptoHooks { .. }")
    }
}

/// Process-wide hook registry.
///
/// A component instance is single-threaded and short-lived, so this is written
/// exactly once per instantiation in the shipping configuration. The lock keeps
/// the seam sound in native builds (where this crate's own tests are
/// multi-threaded) without any `unsafe`; a read guard per bulk chunk is
/// negligible next to the AES/CRC work the chunk represents.
static HOOKS: RwLock<Option<HostCryptoHooks>> = RwLock::new(None);

/// Install (or replace) the embedder's crypto/CRC hooks.
///
/// Call this before any extraction that could touch an encrypted member or
/// verify a member CRC — in practice, once at the top of the component's
/// exported entry point.
pub fn install_host_crypto_hooks(hooks: HostCryptoHooks) {
    let mut slot = HOOKS
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *slot = Some(hooks);
}

/// Whether hooks have been installed. Embedders can assert this in their own
/// start-up tests rather than discovering the gap inside a decrypt.
pub fn host_crypto_hooks_installed() -> bool {
    HOOKS
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .is_some()
}

/// Remove any installed hooks. Intended for embedder tests that need to prove
/// their wiring is what makes delegation work.
pub fn clear_host_crypto_hooks() {
    let mut slot = HOOKS
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *slot = None;
}

/// The installed hooks, or a panic naming the missing wiring.
///
/// Panicking matches the raw-import backends: a guest that reaches bulk crypto
/// without a working host has no recoverable state, and a silent in-guest
/// fallback would quietly defeat the whole point of delegation.
#[cfg_attr(
    not(any(
        all(feature = "crypto-host", feature = "host-abi-component"),
        all(feature = "crc-host", feature = "host-abi-component"),
    )),
    allow(dead_code)
)]
pub(crate) fn hooks() -> HostCryptoHooks {
    HOOKS
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .expect(
            "unrar-rs host-abi-component: no host crypto hooks installed; the embedding component \
             must call unrar_rs::component_abi::install_host_crypto_hooks before extraction",
        )
}

/// A reference hook pair backed by this crate's own portable primitives.
///
/// It is what a correct host does, so the backend tests can drive the real
/// delegation path — registry lookup, buffer round trip, IV threading, CRC
/// chaining — on a native target with no wasm runtime in sight. Every test
/// installs this same pair, which keeps a parallel `cargo test` deterministic.
#[cfg(all(test, not(target_family = "wasm")))]
pub(crate) fn install_reference_hooks_for_test() {
    fn aes_cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, HostAesError> {
        use aes::cipher::block::BlockModeDecrypt;
        use aes::cipher::{Array, KeyIvInit};

        if key.len() != 16 && key.len() != 32 {
            return Err(HostAesError::BadKeyLength);
        }
        if iv.len() != 16 {
            return Err(HostAesError::BadIvLength);
        }
        if !data.len().is_multiple_of(16) {
            return Err(HostAesError::BadBlockLength);
        }

        let mut out = data.to_vec();
        let iv: &[u8; 16] = iv.try_into().expect("iv is 16 bytes");
        let (blocks, rest) = Array::<u8, _>::slice_as_chunks_mut(&mut out);
        debug_assert!(rest.is_empty());
        if key.len() == 32 {
            let key: &[u8; 32] = key.try_into().expect("key is 32 bytes");
            cbc::Decryptor::<aes::Aes256>::new(key.into(), iv.into()).decrypt_blocks(blocks);
        } else {
            let key: &[u8; 16] = key.try_into().expect("key is 16 bytes");
            cbc::Decryptor::<aes::Aes128>::new(key.into(), iv.into()).decrypt_blocks(blocks);
        }
        Ok(out)
    }

    fn crc32(seed: u32, data: &[u8]) -> u32 {
        let mut hasher = crc_fast::Digest::new_with_init_state(
            crc_fast::CrcAlgorithm::Crc32IsoHdlc,
            u64::from(!seed),
        );
        hasher.update(data);
        hasher.finalize() as u32
    }

    install_host_crypto_hooks(HostCryptoHooks {
        aes_cbc_decrypt,
        crc32,
    });
}

#[cfg(all(test, not(target_family = "wasm")))]
mod tests {
    use super::*;

    /// The registry hands back exactly what was installed, and reports its own
    /// state honestly — the two facts an embedder's wiring test depends on.
    #[test]
    fn installed_hooks_are_visible_and_dispatch() {
        install_reference_hooks_for_test();
        assert!(host_crypto_hooks_installed());

        let hooks = hooks();
        // "123456789" is the standard CRC-32 check vector.
        assert_eq!((hooks.crc32)(0, b"123456789"), 0xcbf4_3926);
        // NIST SP 800-38A AES-128-CBC, first block.
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let iv = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let ciphertext = [
            0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9,
            0x19, 0x7d,
        ];
        let plaintext = (hooks.aes_cbc_decrypt)(&key, &iv, &ciphertext).expect("reference decrypt");
        assert_eq!(
            plaintext,
            vec![
                0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
                0x17, 0x2a,
            ]
        );
    }

    /// An empty buffer is legal and decrypts to nothing, so a zero-length
    /// member never trips the length assertions on the calling side.
    #[test]
    fn empty_data_decrypts_to_empty() {
        install_reference_hooks_for_test();
        let hooks = hooks();
        assert_eq!(
            (hooks.aes_cbc_decrypt)(&[0u8; 32], &[0u8; 16], &[]),
            Ok(Vec::new())
        );
        assert_eq!((hooks.crc32)(0x1234_5678, &[]), 0x1234_5678);
    }
}
