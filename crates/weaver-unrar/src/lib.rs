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
//! # Reading an archive
//!
//! [`RarArchive::open`] takes anything `Read + Seek`, so an archive can come
//! from a file, a buffer, or your own source.
//!
//! ```no_run
//! use unrar_rs::RarArchive;
//!
//! # fn main() -> unrar_rs::RarResult<()> {
//! let archive = RarArchive::open(std::fs::File::open("release.part01.rar")?)?;
//! for member in &archive.metadata().members {
//!     // `unpacked_size` is `None` until the header that states it arrives,
//!     // which for a split member is its final part.
//!     println!("{} ({:?} bytes)", member.name, member.unpacked_size);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! Reading headers never decompresses anything, so listing a 50 GB set costs
//! only its headers. Extraction verifies by default:
//!
//! ```no_run
//! use unrar_rs::{ExtractOptions, RarArchive};
//!
//! # fn main() -> unrar_rs::RarResult<()> {
//! let mut archive = RarArchive::open(std::fs::File::open("release.rar")?)?;
//! let index = archive.find_member("movie.mkv").expect("member present");
//! archive.extract_member_to_file(
//!     index,
//!     &ExtractOptions { verify: true, password: None, restore_owners: false },
//!     None, // optional `&dyn ProgressHandler`
//!     std::path::Path::new("movie.mkv"),
//! )?;
//! # Ok(())
//! # }
//! ```
//!
//! # Extracting from volumes that are not files
//!
//! [`extract_member_streaming`](RarArchive::extract_member_streaming) reads
//! through a [`volume::VolumeProvider`] instead of the
//! filesystem, so a member can be extracted while its volumes are still
//! arriving — or from volumes that never exist as files at all.
//!
//! Volumes are addressed in the **set's own numbering** throughout, the same
//! one [`RarVolumeFacts`] reports and `add_volume` accepts: a member whose first
//! segment lives in volume 5 asks the provider for volume 5. Do not re-key a
//! provider to the member's first volume.
//!
//! # Encrypted archives
//!
//! Both shapes are supported: file-data encryption (`rar -p`) and encrypted
//! headers (`rar -hp`). Pass the password through
//! [`ExtractOptions::password`], or [`RarArchive::open_with_password`] when the
//! headers themselves are encrypted.
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
//! - `crypto-host`: host-provided crypto, implying `crypto-rust`.
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
//! Relative-speed charts against reference `unrar 7.23` from the
//! deterministic `rarpar-bench` corpus (methodology in the crate README).
//! Click any chart to open it full size.
//!
//! [![RAR workloads on AMD Ryzen 5 3600 with Windows x86-64](https://raw.githubusercontent.com/scryer-media/rarpar/main/crates/weaver-unrar/docs/rarpar-rar-benchmark-windows-x86_64.svg)](https://raw.githubusercontent.com/scryer-media/rarpar/main/crates/weaver-unrar/docs/rarpar-rar-benchmark-windows-x86_64.svg)
//!
//! [![RAR workloads on Intel Core i5-1240P with Linux x86-64](https://raw.githubusercontent.com/scryer-media/rarpar/main/crates/weaver-unrar/docs/rarpar-rar-benchmark-linux-x86_64.svg)](https://raw.githubusercontent.com/scryer-media/rarpar/main/crates/weaver-unrar/docs/rarpar-rar-benchmark-linux-x86_64.svg)
//!
//! [![RAR workloads on AMD EPYC 9R14 with Linux x86-64 and AVX-512](https://raw.githubusercontent.com/scryer-media/rarpar/main/crates/weaver-unrar/docs/rarpar-rar-benchmark-linux-x86_64-avx512.svg)](https://raw.githubusercontent.com/scryer-media/rarpar/main/crates/weaver-unrar/docs/rarpar-rar-benchmark-linux-x86_64-avx512.svg)
//!
//! [![RAR workloads on Intel Atom C3538 with Linux x86-64 and no AVX](https://raw.githubusercontent.com/scryer-media/rarpar/main/crates/weaver-unrar/docs/rarpar-rar-benchmark-linux-x86_64-noavx.svg)](https://raw.githubusercontent.com/scryer-media/rarpar/main/crates/weaver-unrar/docs/rarpar-rar-benchmark-linux-x86_64-noavx.svg)
//!
//! [![RAR workloads on Apple M5 Max with macOS arm64](https://raw.githubusercontent.com/scryer-media/rarpar/main/crates/weaver-unrar/docs/rarpar-rar-benchmark-macos-arm64.svg)](https://raw.githubusercontent.com/scryer-media/rarpar/main/crates/weaver-unrar/docs/rarpar-rar-benchmark-macos-arm64.svg)

pub mod archive;
pub(crate) mod crc;
extern crate self as crc32fast;
pub(crate) use crc::{Crc32 as Hasher, hash};
pub mod crypto;
pub mod decompress;
pub mod early;
pub mod error;
pub mod extract;
pub(crate) mod hash_pipeline;
pub mod header;
pub mod limits;
pub mod path;
pub mod probe;
pub mod progress;
pub mod rar4;
pub mod recovery;
pub mod signature;
pub mod stored_layout;
pub mod types;
pub mod vint;
pub mod volume;

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
    CachedArchiveHeaders, DataSegment, RarArchive, RarVolumeFacts, RarVolumeHeaderEncryption,
    RarVolumeHeaderEncryptionFacts, RarVolumeHostOs, RarVolumeMemberEncryptionFacts,
    RarVolumeMemberFacts, RarVolumeServiceFacts, RarVolumeUnixOwnerFacts, ReadSeek,
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
pub use extract::{ExtractOptions, ExtractedMember};
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
