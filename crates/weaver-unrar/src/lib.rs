//! `weaver-unrar` -- RAR archive reader and extractor.
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
//! creation APIs. It supports:
//! - Parsing all 5 RAR5 header types (main, file, service, encryption, end)
//! - Variable-length integer (vint) decoding
//! - Header CRC32 validation
//! - Metadata extraction (header-only mode)
//! - Store (method 0) extraction with CRC32 verification
//! - Multi-volume topology tracking
//! - Detection and extraction of supported encrypted archives
//! - RAR4 archive support, including legacy RAR 1.5/2.0/2.9 decompression
//! - SFX (self-extracting) archive support
//! - AES decryption with RAR-compatible key derivation
//! - LZ decompression (methods 1-5) with Huffman decoding and sliding window
//! - PPMd decompression (variant H)
//! - Post-decompression filters (Delta, E8, E8E9, ARM)
//! - Path sanitization to prevent traversal attacks

pub mod archive;
pub(crate) mod crc;
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
pub mod types;
pub mod vint;
pub mod volume;

/// Test-only helpers exposed for integration tests in this crate.
///
/// These build AES-CBC ciphertext by delegating to whichever crypto backend
/// is active, so tests can construct encrypted fixtures without hand-rolling
/// FFI or depending on a specific backend. Not part of the public API —
/// hidden from docs and intended solely for `weaver-unrar`'s own tests.
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
    CachedArchiveHeaders, DataSegment, RarArchive, RarVolumeFacts, RarVolumeHostOs,
    RarVolumeMemberFacts, RarVolumeServiceFacts, RarVolumeUnixOwnerFacts, ReadSeek,
};
pub use early::{EncryptionStatus, detect_encryption};
pub use error::{RarError, RarResult};
pub use extract::{ExtractOptions, ExtractedMember};
pub use limits::Limits;
pub use path::sanitize_path;
pub use probe::{ProbeFile, VolumeProbe, probe_volume};
pub use progress::{NoProgress, ProgressHandler};
pub use recovery::{RecoveryOptions, RecoveryReport, restore_volumes_from_paths};
pub use types::{
    ArchiveFormat, ArchiveMetadata, CompressionInfo, CompressionMethod, FileHash, HostOs,
    MemberInfo, TopologyMemberInfo, UnixOwnerInfo, VolumeSpan,
};
pub use volume::{StaticVolumeProvider, VolumeProvider, VolumeProviderError, VolumeSet};
