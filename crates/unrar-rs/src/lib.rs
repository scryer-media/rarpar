//! `unrar-rs` -- RAR archive reader and extractor.
//!
//! UnRAR source code may be used in any software to handle
//! RAR archives without limitations free of charge, but cannot be
//! used to develop RAR (WinRAR) compatible archiver and to
//! re-create RAR compression algorithm, which is proprietary.
//! Distribution of modified UnRAR source code in separate form
//! or as a part of other software is permitted, provided that
//! full text of this paragraph, starting from "UnRAR source code"
//! words, is included in license, or in documentation if license
//! is not available, and in source code comments of resulting package.
//!
//! This crate provides reading, decompression, and extraction of existing RAR
//! archives only. It intentionally exposes no archive writer, builder, or
//! creation API — the restriction above is why.
//!
//! # Listing an archive
//!
//! [`RarArchive::open`] takes anything `Read + Seek`, so an archive can come
//! from a file, a buffer, or your own source. Reading headers decompresses
//! nothing, so listing a 50 GB set costs only its headers.
//!
//! ```no_run
//! use unrar_rs::RarArchive;
//!
//! # fn main() -> unrar_rs::RarResult<()> {
//! let archive = RarArchive::open(std::fs::File::open("release.part01.rar")?)?;
//! for member in archive.entries() {
//!     // `unpacked_size` is `None` until the header that states it arrives,
//!     // which for a split member is its final part.
//!     println!("{} ({:?} bytes)", member.name, member.unpacked_size);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Extracting
//!
//! Take an [`Entry`] for the member you want, then say where its bytes go.
//! [`by_index`](RarArchive::by_index) and [`by_name`](RarArchive::by_name)
//! decode nothing on their own; the handle they return is consumed by exactly
//! one of [`copy_to`](Entry::copy_to), [`unpack_to`](Entry::unpack_to),
//! [`unpack_in`](Entry::unpack_in),
//! [`copy_to_volumes`](Entry::copy_to_volumes), [`skip`](Entry::skip), or
//! reading it as a `Read`.
//!
//! ```no_run
//! use unrar_rs::RarArchive;
//!
//! # fn main() -> unrar_rs::RarResult<()> {
//! let mut archive = RarArchive::open(std::fs::File::open("release.rar")?)?;
//!
//! for index in 0..archive.len() {
//!     let mut sink = std::io::sink();
//!     archive.by_index(index)?.copy_to(&mut sink)?;
//! }
//! # Ok(())
//! # }
//! ```
//!
//! `copy_to` hands each span the decoder produces straight to the writer:
//! nothing is buffered in memory or spooled to a temporary file on the way.
//! When there is no writer to give — a caller that wants a `Read` — the entry
//! is itself a `Read`, served from a spool it fills on the first read.
//!
//! Verification is part of extraction and is on by default: a member whose
//! CRC32 or BLAKE2sp does not match is an error rather than a silently wrong
//! result. [`set_verify`](RarArchive::set_verify) turns it off.
//!
//! To land a member on disk with the metadata the archive carries — times,
//! permissions, Windows attributes, and symlinks and hardlinks as such — use
//! [`unpack_to`](Entry::unpack_to):
//!
//! ```no_run
//! use unrar_rs::RarArchive;
//!
//! # fn main() -> unrar_rs::RarResult<()> {
//! let mut archive = RarArchive::open(std::fs::File::open("release.rar")?)?;
//! archive
//!     .by_name("movie.mkv")?
//!     .unpack_to(std::path::Path::new("movie.mkv"))?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Volumes that are not files yet
//!
//! [`by_index_via`](RarArchive::by_index_via) reads a member's volumes from a
//! [`volume::VolumeProvider`] instead of from the archive's own — which is how
//! a member is extracted while its volumes are still arriving, or from volumes
//! that never exist as files at all. [`StaticVolumeProvider`] wraps a list of
//! paths:
//!
//! ```no_run
//! use unrar_rs::{RarArchive, StaticVolumeProvider};
//!
//! # fn main() -> unrar_rs::RarResult<()> {
//! let path = std::path::PathBuf::from("release.rar");
//! let mut archive = RarArchive::open(std::fs::File::open(&path)?)?;
//! let provider = StaticVolumeProvider::from_ordered(vec![path]);
//!
//! for index in 0..archive.len() {
//!     let mut sink = std::io::sink();
//!     archive.by_index_via(index, &provider)?.copy_to(&mut sink)?;
//! }
//! # Ok(())
//! # }
//! ```
//!
//! Volumes are addressed in the **set's own numbering** throughout, the same
//! one [`RarVolumeFacts`] reports and `add_volume` accepts: a member whose
//! first segment lives in volume 5 asks the provider for volume 5. Do not
//! re-key a provider to the member's first volume.
//!
//! [`copy_to_volumes`](Entry::copy_to_volumes) takes that further and gives
//! each volume its own writer, so a member spanning five volumes lands as five
//! pieces attributed to the volumes they came from. The writer type is yours:
//! it needs neither `Send` nor `'static`, so writers sharing one sink through
//! a borrow are fine.
//!
//! ## Solid archives
//!
//! Every call above handles solid and non-solid archives alike. What solidity
//! adds is an order: a solid archive compresses its members against one shared
//! dictionary, so they are consumed in ascending index order. Reaching forward
//! decodes the members in between for you; reaching backwards raises
//! [`RarError::SolidOrderViolation`]. [`skip`](Entry::skip) walks past a member
//! you do not want without producing its bytes, and dropping an entry
//! unconsumed costs nothing.
//!
//! If a solid member fails partway — a decode error, or a writer that returns
//! one — the carried-over dictionary no longer lines up with any member
//! boundary, so the archive is poisoned: later solid extractions raise
//! [`RarError::SolidStatePoisoned`] until
//! [`reset_solid_state`](RarArchive::reset_solid_state) clears it and
//! extraction restarts from the first member.
//!
//! # Encrypted archives
//!
//! Both shapes are supported: file-data encryption (`rar -p`) and encrypted
//! headers (`rar -hp`). Set the password with
//! [`set_password`](RarArchive::set_password), or open with
//! [`RarArchive::open_with_password`] when the headers themselves are
//! encrypted. A single member can override it with
//! [`with_password`](Entry::with_password).
//!
//! For callers that route bytes themselves rather than extracting, the [`crypto`]
//! module exposes the pieces directly — derive a member's key from header facts,
//! prove a password *before* decrypting anything with
//! [`check_member_password`], and decrypt or re-encrypt an arbitrary range.
//! Note that a candidate can be `Verified`, `Wrong`, or `Unverifiable`, and the
//! third must never be treated as the first: an archive whose stored check value
//! is malformed rejects nothing for any password.
//!
//! # Integrity
//!
//! Verification matches what the format actually provides. A member carries a
//! whole-member CRC32 or BLAKE2sp; a member split across volumes additionally
//! carries a packed checksum in every non-final part, so damage is caught at the
//! part that carries it rather than at the end of the member. `-htb` archives
//! replace CRC32 with BLAKE2sp entirely rather than adding it.
//!
//! # Safety
//!
//! [`sanitize_path`] is applied to member names so a hostile archive cannot
//! traverse out of its destination directory, and [`Limits`] bounds what a
//! header may declare — a crafted dictionary size cannot make extraction
//! allocate without bound.
//!
//! # Supported formats
//!
//! - All five RAR5 header types (main, file, service, encryption, end), vint
//!   decoding, header CRC32 validation
//! - RAR4, including legacy RAR 1.5 / 2.0 / 2.9 decompression
//! - SFX (self-extracting) archives
//! - Store, LZ (methods 1–5) with Huffman decoding and a sliding window, and
//!   PPMd variant H
//! - Post-decompression filters: Delta, E8, E8E9, ARM
//! - Multi-volume topology tracking
//!
//! # Feature flags
//!
//! - `crypto-aws-lc` *(default)*: AWS-LC-backed AES and hashing.
//! - `crypto-rust`: pure-Rust backend (`aes`, `cbc`, `sha2`, `hmac`), for
//!   targets where AWS-LC will not build.
//! - `crypto-host`: on `wasm32`, delegate the bulk AES-CBC decrypt to an
//!   embedder-installed hook (see `hooks`); implies `crypto-rust` for the
//!   in-guest key derivation. Accepted but inert on native targets.
//! - `crc-host`: on `wasm32`, delegate the bulk member CRC-32 to an
//!   embedder-installed hook (see `hooks`). Accepted but inert on native
//!   targets.
//! - `ppmd-debug`: compile the per-symbol PPMd trace hooks, enabled at run
//!   time by `UNRAR_RS_RAR4_DEBUG_PPM`.
//! - `slow-tests`: opt in to the long-running parts of the test suite.
//!
//! # Provenance
//!
//! A Rust port of RARLAB's reference UnRAR implementation, with additional
//! optimisations: runtime-dispatched SIMD, a streaming extraction path, and
//! cross-volume layout assembly that the reference implementation does not
//! provide. The format is documented in RARLAB's
//! [technical note](https://www.rarlab.com/technote.htm).
//!
//! # Benchmarks
//!
//! Extraction against reference UnRAR, from the deterministic 43-case
//! `rarpar-bench` corpus. Each figure is the geometric mean of
//! `reference wall time / rarpar wall time` over a workload class, so `2.0x`
//! means half the time. **binary** is store-mode extraction of uncompressible
//! media payloads, including the encrypted and BLAKE2sp variants; **text** is
//! compressed extraction across the LZ and PPMd decode paths, including
//! compressed machine code and the encrypted compressed cases.
//!
//! | CPU | Arch | Instruction set | binary | text |
//! |---|---|---|---:|---:|
//! | AMD EPYC 9R14 (Zen 4) | x86-64 | GFNI + AVX-512 | 2.0x | 1.5x |
//! | Intel Xeon Platinum 8488C (Sapphire Rapids) | x86-64 | GFNI + AVX-512 | 1.9x | 1.4x |
//! | Intel Core i5-1240P (Alder Lake) | x86-64 | GFNI + AVX2 | 1.5x | 1.2x |
//! | AMD Ryzen 5 3600 (Zen 2) | x86-64 | AVX2 | 1.6x | 1.5x |
//! | Intel Atom C3538 (Denverton) | x86-64 | SSSE3 (no AVX) | 1.2x | 1.3x |
//! | Apple M5 Max | arm64 | NEON | 1.4x | 1.5x |
//! | Arm Cortex-A72 | arm64 | NEON | 2.1x | 1.4x |
//! | Arm Neoverse N1 | arm64 | NEON | 2.6x | 1.5x |
//! | Arm Neoverse V2 | arm64 | NEON | 3.1x | 1.6x |
//!
//! The text class includes RAR4 PPMd, an archaic mode deliberately left
//! unoptimized, which loses on every machine.
//!
//! Per-case charts for every machine, the full methodology, and the versions
//! these numbers were measured with are in
//! [rarpar benchmarks](https://github.com/scryer-media/rarpar/blob/main/docs/benchmark.md).

pub mod archive;
pub(crate) mod crc;
pub(crate) mod crc_simd;
#[cfg(any(feature = "crypto-host", feature = "crc-host"))]
pub mod hooks;
extern crate self as crc32fast;
pub(crate) use crc::{Crc32 as Hasher, hash};
pub mod crypto;
// The decoders. Nothing outside this crate drives them directly — an archive is
// read through `RarArchive` and its `Entry` handle — and their surface is the
// crate's largest by a wide margin, so it is not part of the public API.
pub(crate) mod decompress;
pub mod early;
pub mod error;
pub mod extract;
pub(crate) mod hash_pipeline;
pub mod header;
pub mod limits;
pub mod path;
pub mod probe;
pub mod progress;
// RAR4/RAR1.4 header parsing and decode entry points, reached through
// `RarArchive`. `header` stays public because a caller can legitimately walk a
// RAR5 volume's headers without opening it; there is no such use for these.
pub(crate) mod rar4;
pub mod recovery;
pub mod signature;
pub mod stored_layout;
pub mod types;
pub(crate) mod vint;
pub mod volume;

/// Internals exposed for this crate's own benches and examples.
///
/// Not public API, not covered by semver, and absent unless the non-default
/// `unstable-internals` feature is on. Nothing outside this repository should
/// name it.
#[cfg(feature = "unstable-internals")]
#[doc(hidden)]
pub mod __internals {
    pub use crate::decompress::lz::filter::apply_e8e9;
    pub use crate::rar4::{parse_rar4_headers, parse_rar14_headers};
}

/// Test-only helpers exposed for integration tests in this crate.
///
/// These build AES-CBC ciphertext by delegating to whichever crypto backend
/// is active, so tests can construct encrypted fixtures without hand-rolling
/// FFI or depending on a specific backend. Not part of the public API —
/// hidden from docs and intended solely for `unrar-rs`'s own tests.
#[doc(hidden)]
pub mod test_support {
    /// CBC-encrypt block-aligned `plaintext` with AES-128 (no padding).
    pub fn encrypt_aes128_cbc(key: &[u8; 16], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
        crate::crypto::encrypt_aes128_cbc_for_test(key, iv, plaintext)
    }

    /// CBC-encrypt block-aligned `plaintext` with AES-256 (no padding).
    pub fn encrypt_aes256_cbc(key: &[u8; 32], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
        crate::crypto::encrypt_aes256_cbc_for_test(key, iv, plaintext)
    }
}

// Re-export primary public API types
pub use archive::{
    CachedArchiveHeaders, DataSegment, Entry, RarArchive, RarVolumeFacts,
    RarVolumeHeaderEncryption, RarVolumeHeaderEncryptionFacts, RarVolumeHostOs,
    RarVolumeMemberEncryptionFacts, RarVolumeMemberFacts, RarVolumeServiceFacts,
    RarVolumeUnixOwnerFacts, ReadSeek,
};
/// The encrypted-member surface a one-pass router needs: derive a member's key
/// material from a password and the facts its headers state, decide up front
/// whether that password is right, decrypt an arbitrary cipher range — or
/// re-encrypt one, for a reader that holds the plaintext and owes its caller the
/// bytes that were posted — and fold a checksum the way a keyed header states
/// it.
///
/// Both formats are covered, and [`MemberKeying`] is the discriminant:
/// RAR5 through [`RarVolumeMemberEncryptionFacts`] and
/// [`KdfCache::derive_key_rar5`], RAR4 through its 8-byte file salt and
/// [`KdfCache::derive_key_rar4`]. [`MemberCipherKey`] carries whichever key came
/// out and dispatches the range calls, so a caller writes the transform once.
///
/// None of this needs an archive object; all of it is driven by header facts
/// plus bytes.
pub use crypto::{
    CRYPT5_KDF_LG2_COUNT_MAX, KdfCache, MemberCipherKey, PasswordCheck, Rar5KeyMaterial,
    check_member_password, convert_blake2_to_mac, convert_crc32_to_mac, decrypt_cipher_range,
    decrypt_cipher_range_rar4, derive_rar5_material, encrypt_cipher_range,
    encrypt_cipher_range_rar4, rar4_derive_key,
};
pub use early::{EncryptionStatus, detect_encryption};
pub use error::{RarError, RarResult};
pub use extract::{ExtractOptions, ExtractedMember, ExtractedMemberReader};
pub use limits::Limits;
pub use path::sanitize_path;
pub use probe::{ProbeFile, VolumeProbe, probe_volume};
pub use progress::{NoProgress, ProgressHandler};
pub use recovery::{RecoveryOptions, RecoveryReport, restore_volumes_from_paths};
pub use stored_layout::{
    EncryptedStore, IneligibilityReason, MalformedReason, MappedSlice, MemberEligibility,
    MemberKeying, StoredLayoutBuilder, StoredLayoutError, StoredMember, StoredMemberPart,
    VolumeSplitEvidence,
};
pub use types::{
    ArchiveFormat, ArchiveMetadata, CompressionInfo, CompressionMethod, FileHash, HostOs,
    MemberInfo, TopologyMemberInfo, UnixOwnerInfo, VolumeSpan,
};
pub use volume::{StaticVolumeProvider, VolumeProvider, VolumeProviderError, VolumeSet};
