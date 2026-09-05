use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use super::{RarArchive, ReadSeek};
use crate::error::RarResult;
use crate::signature;
use crate::types::{ArchiveFormat, CompressionMethod};

/// Host OS families this crate needs to reason about.
///
/// RAR4 has additional historical host identifiers such as MS-DOS, OS/2 and
/// BeOS. Only Darwin/macOS, Linux/Unix and Windows behavior is supported, so
/// volume facts leave the legacy targets unmapped instead of pretending they
/// are supported modern archive origins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RarVolumeHostOs {
    Windows,
    Unix,
    Darwin,
}

/// The RAR5 per-file encryption record (`FHEXTRA_CRYPT`), exactly as one
/// volume's header states it.
///
/// Facts, not keys: nothing here is derived, and no password is involved in
/// producing it. A caller that wants a key feeds `salt` and `kdf_count_lg2`
/// (with its own password) to [`crate::crypto::KdfCache::derive_material_rar5`],
/// and checks the password with [`crate::crypto::check_member_password`].
///
/// Two fields deliberately absent:
///
/// - The hash-MAC flag (`enc_flags & 0x0002`) is already this header's
///   [`RarVolumeMemberFacts::use_hash_mac`]. It is also the one field that
///   genuinely differs between the parts of a single split member — RARLAB
///   `rar` 7.20 sets it on the final part only, because only that part's
///   checksum is the whole-member one — so keeping it out of this record lets
///   the record be compared across parts for equality.
/// - The AES key, hash key and password-check value, all of which need the
///   password.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RarVolumeMemberEncryptionFacts {
    /// Encryption version the record states. Only 0 (AES-256) is supported;
    /// the value is reported rather than validated.
    pub version: u64,
    /// PBKDF2 iteration count as its base-2 logarithm, exactly as stored.
    pub kdf_count_lg2: u8,
    /// 16-byte KDF salt.
    pub salt: [u8; 16],
    /// 16-byte AES-CBC initialisation vector for this member's data.
    pub iv: [u8; 16],
    /// Whether the record's flags claim a password-check value
    /// (`enc_flags & 0x0001`).
    pub psw_check_present: bool,
    /// The 12-byte password-check field — 8 check bytes plus a 4-byte SHA-256
    /// tag over them — kept only when the flag is set *and* the tag matched.
    /// `psw_check_present` with `None` here means the writer claimed a check
    /// this parse could not trust.
    pub psw_check: Option<[u8; 12]>,
}

/// The RAR5 **archive-level** encryption record (`HEAD_CRYPT`, type 4) a
/// header-encrypted (`-hp`) volume states, exactly as it states it.
///
/// Facts, not keys, and — this is the whole point of the type — obtainable with
/// **no password**. `-hp` encrypts every header after this one, so the layout
/// (member names, offsets, sizes) is unreadable without a key; the record that
/// says how to *make* that key is plaintext and sits at the front of the
/// volume. A caller with a list of candidate passwords can therefore prove one
/// against [`Self::psw_check`] through
/// [`crate::crypto::check_member_password`] before it decrypts anything, and
/// only then re-parse with [`super::RarArchive::parse_volume_facts`].
///
/// The same shape as [`RarVolumeMemberEncryptionFacts`] minus the IV, which
/// this record does not carry: each encrypted header stores its own IV inline,
/// ahead of its ciphertext.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RarVolumeHeaderEncryptionFacts {
    /// Encryption version the record states. Only 0 (AES-256) is supported, and
    /// unlike the per-member record this one *is* validated — a version this
    /// build does not implement is an error rather than a reported number,
    /// because nothing past it can be read at all.
    pub version: u64,
    /// PBKDF2 iteration count as its base-2 logarithm, exactly as stored.
    /// Bounded by [`crate::crypto::CRYPT5_KDF_LG2_COUNT_MAX`] at parse time: the
    /// count is the *archive's* claim, so an unbounded one would let a hostile
    /// post choose how much work a candidate loop does.
    pub kdf_count_lg2: u8,
    /// 16-byte KDF salt.
    pub salt: [u8; 16],
    /// Whether the record's flags claim a password-check value
    /// (`enc_flags & 0x0001`).
    pub psw_check_present: bool,
    /// The 12-byte password-check field — 8 check bytes plus a 4-byte SHA-256
    /// tag over them — kept only when the flag is set *and* the tag matched.
    /// `psw_check_present` with `None` here means the writer claimed a check
    /// this parse could not trust, which refutes no password and must never be
    /// read as confirming one.
    pub psw_check: Option<[u8; 12]>,
}

/// What one volume's headers say about **archive-level** (`-hp`) encryption,
/// read with no password.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RarVolumeHeaderEncryption {
    /// No `-hp`: this volume's headers are readable as they stand. A `-p`
    /// archive — file data encrypted, headers in the clear — answers this, and
    /// so does an unencrypted one.
    None,
    /// RAR5 `-hp`. The type-4 record is plaintext and comes back whole.
    Rar5(RarVolumeHeaderEncryptionFacts),
    /// RAR4/RAR3 `-hp`, which states only that it *is* header-encrypted.
    ///
    /// There is deliberately nothing else to report. RAR4 derives a fresh key
    /// per header from that header's own 8-byte salt and carries **no
    /// password-check value anywhere** in the format, so a wrong password is
    /// detected only by walking off the end of the archive. Nothing here can
    /// prove a candidate before something is decrypted, which is why a caller
    /// that requires proof must refuse this variant rather than guess.
    Rar4,
}

/// Unix owner/group metadata from RAR5 `FHEXTRA_UOWNER`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RarVolumeUnixOwnerFacts {
    #[serde(default)]
    pub user_name: Option<String>,
    #[serde(default)]
    pub group_name: Option<String>,
    #[serde(default)]
    pub user_name_raw: Option<Vec<u8>>,
    #[serde(default)]
    pub group_name_raw: Option<Vec<u8>>,
    #[serde(default)]
    pub uid: Option<u64>,
    #[serde(default)]
    pub gid: Option<u64>,
}

/// Immutable header facts parsed from a single physical RAR volume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RarVolumeFacts {
    pub format: u8,
    /// The volume index the headers themselves state, when the format states
    /// one. RAR5 carries it in the main header behind `MAIN_VOLNR`; RAR4
    /// carries it only in an end record behind `VOLUME_NUMBER`. An
    /// old-numbering RAR4 set (`.rar`/`.rNN`) states nothing anywhere, and a
    /// RAR5 first volume routinely omits the field — `None` in both cases,
    /// which is a different fact from "the header said volume 0". A caller
    /// that needs an identity for an unnumbered volume must take it from the
    /// layout (the filename), not from here.
    ///
    /// Cache compatibility: facts encoded by pre-0.6 binaries carry a bare
    /// integer (their parse defaulted an absent number to 0) and decode here
    /// as `Some(n)`. `None` encodes as nil, which pre-0.6 readers reject —
    /// they drop that cached row and re-parse.
    pub volume_number: Option<u32>,
    pub more_volumes: bool,
    pub is_solid: bool,
    pub is_encrypted: bool,
    #[serde(default)]
    pub is_volume: bool,
    #[serde(default)]
    pub has_recovery_record: bool,
    #[serde(default)]
    pub is_locked: bool,
    #[serde(default)]
    pub has_authenticity_verification: bool,
    #[serde(default)]
    pub has_locator: bool,
    #[serde(default)]
    pub quick_open_offset: Option<u64>,
    /// Whether these facts were read out of the volume's Quick Open cache
    /// instead of off its physical header chain.
    ///
    /// `true` only when the parse answered wholly from the `QO` service block.
    /// It is `false` for every physically walked volume — including one whose
    /// `QO` block was present but rejected, and every RAR4/RAR1.4 volume,
    /// which has no such cache.
    ///
    /// **Cache-derived facts are not authoritative.** Nothing in RAR5 binds a
    /// `QO` record to the physical header it claims to describe, and the
    /// format's own specification warns the cached copies may deliberately
    /// differ. A caller deciding where bytes are written — member names, data
    /// offsets, what is admitted downstream — should re-parse the volume with
    /// `HeaderParseOptions { allow_quick_open: false }` when this is `true`,
    /// and can skip that second walk when it is `false`.
    ///
    /// This, not `quick_open_offset`, is the provenance answer.
    /// `quick_open_offset.is_some()` says a locator record exists in the main
    /// header; it says nothing about where these facts came from, because a
    /// located cache may still have been rejected.
    ///
    /// Cache compatibility, and the one sharp edge here: facts encoded by a
    /// binary from before this field existed carry no value for it and decode
    /// as `false`. Those binaries did consult the Quick Open cache by default,
    /// so such a row can claim a physical walk it never performed. The field
    /// is only load-bearing for rows this version or later wrote; a store that
    /// persists these facts across an upgrade should key its entries by crate
    /// version and re-parse anything older rather than read provenance out of
    /// them.
    #[serde(default)]
    pub headers_from_quick_open: bool,
    #[serde(default)]
    pub recovery_record_offset: Option<u64>,
    #[serde(default)]
    pub original_name: Option<String>,
    #[serde(default)]
    pub original_name_raw: Option<Vec<u8>>,
    #[serde(default)]
    pub original_creation_time_ns: Option<u64>,
    pub members: Vec<RarVolumeMemberFacts>,
    #[serde(default)]
    pub services: Vec<RarVolumeServiceFacts>,
}

/// A single ordered file-header record from one physical RAR volume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RarVolumeMemberFacts {
    pub order: u32,
    pub name: String,
    #[serde(default)]
    pub name_raw: Option<Vec<u8>>,
    pub unpacked_size: Option<u64>,
    pub data_crc32: Option<u32>,
    #[serde(default)]
    pub data_blake2_hash: Option<[u8; 32]>,
    #[serde(default)]
    pub version: Option<u64>,
    /// Checksums of the packed bytes this volume holds, from a split-after
    /// header. A RAR5 header may state both, and both are kept: CRC32 composes
    /// across out-of-order ranges where BLAKE2sp does not. Facts cached by
    /// older binaries carry at most one of them.
    #[serde(default)]
    pub packed_crc32: Option<u32>,
    #[serde(default)]
    pub packed_blake2_hash: Option<[u8; 32]>,
    #[serde(default)]
    pub packed_hash_uses_mac: bool,
    pub split_before: bool,
    pub split_after: bool,
    pub is_directory: bool,
    pub is_encrypted: bool,
    /// The RAR5 file-encryption record this header carries, when it carries
    /// one. Facts cached by older binaries decode to `None` even for an
    /// encrypted member, so `is_encrypted` stays the encryption predicate and
    /// this field is only ever read as "the key material, if we have it".
    #[serde(default)]
    pub encryption: Option<RarVolumeMemberEncryptionFacts>,
    /// RAR4's 8-byte per-file KDF salt, when the header states one. RAR4 has
    /// no counterpart to the RAR5 record: its key and IV are derived from
    /// password plus this salt alone, and it carries no password check.
    #[serde(default)]
    pub rar4_salt: Option<[u8; 8]>,
    #[serde(default)]
    pub host_os: Option<RarVolumeHostOs>,
    #[serde(default)]
    pub attributes: Option<u64>,
    #[serde(default)]
    pub owner: Option<RarVolumeUnixOwnerFacts>,
    #[serde(default)]
    pub mtime_ns: Option<u64>,
    #[serde(default)]
    pub ctime_ns: Option<u64>,
    #[serde(default)]
    pub atime_ns: Option<u64>,
    pub data_offset: u64,
    pub data_size: u64,
    pub compression_method: u8,
    pub compression_version: u8,
    pub compression_solid: bool,
    pub dict_size: u64,
    pub use_hash_mac: bool,
    pub redirection_type: Option<u64>,
    pub redirection_target: Option<String>,
    #[serde(default)]
    pub redirection_target_raw: Option<Vec<u8>>,
    pub redirection_target_is_directory: bool,
}

/// A service-header record from one physical RAR volume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RarVolumeServiceFacts {
    pub order: u32,
    pub name: String,
    #[serde(default)]
    pub name_raw: Option<Vec<u8>>,
    #[serde(default)]
    pub subtype: Option<u16>,
    #[serde(default)]
    pub level: Option<u8>,
    #[serde(default)]
    pub is_child: bool,
    #[serde(default)]
    pub is_inherited: bool,
    pub unpacked_size: Option<u64>,
    pub data_crc32: Option<u32>,
    #[serde(default)]
    pub data_blake2_hash: Option<[u8; 32]>,
    #[serde(default)]
    pub version: Option<u64>,
    #[serde(default)]
    pub comment_crc16: Option<u16>,
    #[serde(default)]
    pub packed_crc32: Option<u32>,
    #[serde(default)]
    pub packed_blake2_hash: Option<[u8; 32]>,
    #[serde(default)]
    pub packed_hash_uses_mac: bool,
    pub split_before: bool,
    pub split_after: bool,
    pub is_encrypted: bool,
    #[serde(default)]
    pub host_os: Option<RarVolumeHostOs>,
    #[serde(default)]
    pub attributes: Option<u64>,
    #[serde(default)]
    pub mtime_ns: Option<u64>,
    #[serde(default)]
    pub ctime_ns: Option<u64>,
    #[serde(default)]
    pub atime_ns: Option<u64>,
    pub data_offset: u64,
    pub data_size: u64,
    pub compression_method: u8,
    pub compression_version: u8,
    pub compression_solid: bool,
    pub dict_size: u64,
    pub use_hash_mac: bool,
    #[serde(default)]
    pub stream_name: Option<String>,
    #[serde(default)]
    pub stream_name_raw: Option<Vec<u8>>,
}

impl RarVolumeFacts {
    pub fn archive_format(&self) -> ArchiveFormat {
        match self.format {
            14 => ArchiveFormat::Rar14,
            4 => ArchiveFormat::Rar4,
            _ => ArchiveFormat::Rar5,
        }
    }
}

fn supported_host_os(host_os: crate::types::HostOs) -> Option<RarVolumeHostOs> {
    match host_os {
        crate::types::HostOs::Windows => Some(RarVolumeHostOs::Windows),
        crate::types::HostOs::Unix => Some(RarVolumeHostOs::Unix),
        crate::types::HostOs::Darwin => Some(RarVolumeHostOs::Darwin),
        crate::types::HostOs::Unknown(_) => None,
    }
}

fn supported_rar4_host_os(host_os: crate::rar4::types::Rar4HostOs) -> Option<RarVolumeHostOs> {
    match host_os {
        crate::rar4::types::Rar4HostOs::Windows => Some(RarVolumeHostOs::Windows),
        crate::rar4::types::Rar4HostOs::Unix => Some(RarVolumeHostOs::Unix),
        // RAR4's Mac host id is the only Mac-family archive marker available.
        // Only supported Darwin/macOS, Linux/Unix, and Windows targets are
        // distinguished, so older MS-DOS/OS2/BeOS host ids stay unmapped.
        crate::rar4::types::Rar4HostOs::MacOs => Some(RarVolumeHostOs::Darwin),
        crate::rar4::types::Rar4HostOs::MsDos
        | crate::rar4::types::Rar4HostOs::Os2
        | crate::rar4::types::Rar4HostOs::BeOs
        | crate::rar4::types::Rar4HostOs::Unknown(_) => None,
    }
}

fn encode_system_time(time: Option<SystemTime>) -> Option<u64> {
    time.and_then(|value| {
        value
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| u64::try_from(duration.as_nanos()).ok())
    })
}

fn file_hash_blake2(hash: Option<&crate::types::FileHash>) -> Option<[u8; 32]> {
    hash.map(|hash| match hash {
        crate::types::FileHash::Blake2sp(value) => *value,
    })
}

fn member_encryption_facts(
    params: Option<&crate::header::FileEncryptionParams>,
) -> Option<RarVolumeMemberEncryptionFacts> {
    params.map(|params| RarVolumeMemberEncryptionFacts {
        version: params.version,
        kdf_count_lg2: params.kdf_count,
        salt: params.salt,
        iv: params.iv,
        psw_check_present: params.psw_check_present,
        psw_check: params.check_data,
    })
}

fn unix_owner_facts(owner: Option<crate::types::UnixOwnerInfo>) -> Option<RarVolumeUnixOwnerFacts> {
    owner.map(|owner| RarVolumeUnixOwnerFacts {
        user_name: owner.user_name,
        group_name: owner.group_name,
        user_name_raw: owner.user_name_raw,
        group_name_raw: owner.group_name_raw,
        uid: owner.uid,
        gid: owner.gid,
    })
}

impl RarVolumeServiceFacts {
    fn from_rar4_service(order: usize, fh: &crate::rar4::types::Rar4FileHeader) -> Self {
        let file_header = RarArchive::rar4_to_file_header(fh, false);
        let packed_hashes = RarArchive::packed_hashes_for_split_segment(&file_header, None);
        Self {
            order: order as u32,
            name: fh.name.clone(),
            name_raw: fh.name_raw.clone(),
            subtype: None,
            level: None,
            is_child: false,
            is_inherited: false,
            unpacked_size: fh.unpacked_size,
            data_crc32: Some(fh.crc32),
            data_blake2_hash: None,
            version: file_header.version,
            comment_crc16: None,
            packed_crc32: packed_hashes.crc32,
            packed_blake2_hash: packed_hashes.blake2sp,
            packed_hash_uses_mac: false,
            split_before: fh.split_before,
            split_after: fh.split_after,
            is_encrypted: fh.is_encrypted,
            host_os: supported_rar4_host_os(fh.host_os),
            attributes: Some(u64::from(fh.attributes)),
            mtime_ns: encode_system_time(file_header.mtime),
            ctime_ns: encode_system_time(file_header.ctime),
            atime_ns: encode_system_time(file_header.atime),
            data_offset: fh.data_offset,
            data_size: fh.packed_size,
            compression_method: file_header.compression.method.code(),
            compression_version: fh.unpack_version,
            compression_solid: file_header.compression.solid,
            dict_size: fh.dict_size,
            use_hash_mac: false,
            stream_name: None,
            stream_name_raw: None,
        }
    }

    fn from_rar4_comment(order: usize, comment: &crate::rar4::types::Rar4CommentHeader) -> Self {
        Self {
            order: order as u32,
            name: "CMT".to_string(),
            name_raw: Some(b"CMT".to_vec()),
            subtype: None,
            level: None,
            is_child: false,
            is_inherited: false,
            unpacked_size: Some(u64::from(comment.unpacked_size)),
            data_crc32: None,
            data_blake2_hash: None,
            version: None,
            comment_crc16: Some(comment.crc16),
            packed_crc32: None,
            packed_blake2_hash: None,
            packed_hash_uses_mac: false,
            split_before: false,
            split_after: false,
            is_encrypted: false,
            host_os: None,
            attributes: None,
            mtime_ns: None,
            ctime_ns: None,
            atime_ns: None,
            data_offset: comment.data_offset,
            data_size: comment.packed_size,
            compression_method: rar4_method_to_compression_method(comment.method).code(),
            compression_version: comment.unpack_version,
            compression_solid: false,
            dict_size: 0,
            use_hash_mac: false,
            stream_name: None,
            stream_name_raw: None,
        }
    }

    fn from_rar4_old_service(
        order: usize,
        service: &crate::rar4::types::Rar4OldServiceHeader,
    ) -> Self {
        use crate::rar4::types::Rar4OldServiceData;

        let (
            name,
            unpacked_size,
            data_crc32,
            compression_method,
            compression_version,
            stream_name,
            stream_name_raw,
        ) = match &service.data {
            Rar4OldServiceData::UnixOwner => (
                "UOW".to_string(),
                Some(service.data_size),
                None,
                CompressionMethod::Store.code(),
                0,
                None,
                None,
            ),
            Rar4OldServiceData::NtAcl {
                unpacked_size,
                unpack_version,
                method,
                crc32,
            } => (
                "ACL".to_string(),
                Some(u64::from(*unpacked_size)),
                Some(*crc32),
                rar4_method_to_compression_method(*method).code(),
                *unpack_version,
                None,
                None,
            ),
            Rar4OldServiceData::Stream {
                unpacked_size,
                unpack_version,
                method,
                crc32,
                stream_name,
                stream_name_raw,
            } => (
                "STM".to_string(),
                Some(u64::from(*unpacked_size)),
                Some(*crc32),
                rar4_method_to_compression_method(*method).code(),
                *unpack_version,
                Some(stream_name.clone()),
                Some(stream_name_raw.clone()),
            ),
            Rar4OldServiceData::Unknown => (
                format!("0x{:04x}", service.subtype),
                None,
                None,
                CompressionMethod::Store.code(),
                0,
                None,
                None,
            ),
        };

        Self {
            order: order as u32,
            name,
            name_raw: None,
            subtype: Some(service.subtype),
            level: Some(service.level),
            is_child: false,
            is_inherited: false,
            unpacked_size,
            data_crc32,
            data_blake2_hash: None,
            version: None,
            comment_crc16: None,
            packed_crc32: None,
            packed_blake2_hash: None,
            packed_hash_uses_mac: false,
            split_before: false,
            split_after: false,
            is_encrypted: false,
            host_os: None,
            attributes: None,
            mtime_ns: None,
            ctime_ns: None,
            atime_ns: None,
            data_offset: service.data_offset,
            data_size: service.data_size,
            compression_method,
            compression_version,
            compression_solid: false,
            dict_size: 0x10000,
            use_hash_mac: false,
            stream_name,
            stream_name_raw,
        }
    }

    fn from_rar5_service(order: usize, service: crate::header::ParsedService) -> Self {
        let packed_hashes = RarArchive::packed_hashes_for_split_segment(
            &service.header.inner,
            service.hash.as_ref(),
        );
        let packed_hash_uses_mac = packed_hashes.is_present()
            && service
                .file_encryption
                .as_ref()
                .is_some_and(|info| info.use_hash_mac);
        Self {
            order: order as u32,
            name: service.header.service_name().to_string(),
            name_raw: service.header.inner.name_raw.clone(),
            subtype: None,
            level: None,
            is_child: service.header.is_child,
            is_inherited: service.header.is_inherited,
            unpacked_size: service.header.inner.unpacked_size,
            data_crc32: service.header.inner.data_crc32,
            data_blake2_hash: file_hash_blake2(service.hash.as_ref()),
            version: service.header.inner.version,
            comment_crc16: None,
            packed_crc32: packed_hashes.crc32,
            packed_blake2_hash: packed_hashes.blake2sp,
            packed_hash_uses_mac,
            split_before: service.header.inner.split_before,
            split_after: service.header.inner.split_after,
            is_encrypted: service.is_encrypted,
            host_os: supported_host_os(service.header.inner.host_os),
            attributes: Some(service.header.inner.attributes.0),
            mtime_ns: encode_system_time(service.header.inner.mtime),
            ctime_ns: encode_system_time(service.header.inner.ctime),
            atime_ns: encode_system_time(service.header.inner.atime),
            data_offset: service.header.inner.data_offset,
            data_size: service.header.inner.data_size,
            compression_method: service.header.inner.compression.method.code(),
            compression_version: service.header.inner.compression.version,
            compression_solid: service.header.inner.compression.solid,
            dict_size: service.header.inner.compression.dict_size,
            use_hash_mac: service
                .file_encryption
                .as_ref()
                .is_some_and(|info| info.use_hash_mac),
            stream_name: None,
            stream_name_raw: None,
        }
    }
}

fn rar4_method_to_compression_method(method: crate::rar4::types::Rar4Method) -> CompressionMethod {
    match method {
        crate::rar4::types::Rar4Method::Store => CompressionMethod::Store,
        crate::rar4::types::Rar4Method::Fastest => CompressionMethod::Fastest,
        crate::rar4::types::Rar4Method::Fast => CompressionMethod::Fast,
        crate::rar4::types::Rar4Method::Normal => CompressionMethod::Normal,
        crate::rar4::types::Rar4Method::Good => CompressionMethod::Good,
        crate::rar4::types::Rar4Method::Best => CompressionMethod::Best,
        crate::rar4::types::Rar4Method::Unknown(code) => CompressionMethod::Unknown(code),
    }
}

impl RarArchive {
    /// Parse immutable facts from a single physical RAR volume without
    /// building a live multi-volume archive graph.
    pub fn parse_volume_facts(
        reader: impl std::io::Read + std::io::Seek + Send + 'static,
        password: Option<&str>,
    ) -> RarResult<RarVolumeFacts> {
        let reader: Box<dyn ReadSeek> = Box::new(reader);
        Self::parse_volume_facts_boxed(reader, password)
    }

    /// Read one physical volume's **archive-level** encryption record with no
    /// password.
    ///
    /// The companion to [`Self::parse_volume_facts`] for the one case that
    /// function cannot answer: a header-encrypted (`-hp`) volume, whose headers
    /// it refuses with `RarError::EncryptedArchive`. `-hp` withholds *layout*
    /// facts, not *keying* facts, and this returns the keying facts.
    ///
    /// Errors are the walk's own, and a refused record — an encryption version
    /// this build does not implement, or a KDF count over
    /// [`crate::crypto::CRYPT5_KDF_LG2_COUNT_MAX`] — is one of them rather than
    /// [`RarVolumeHeaderEncryption::None`].
    pub fn parse_volume_header_encryption(
        reader: impl std::io::Read + std::io::Seek + Send + 'static,
    ) -> RarResult<RarVolumeHeaderEncryption> {
        let reader: Box<dyn ReadSeek> = Box::new(reader);
        Self::parse_volume_header_encryption_boxed(reader)
    }

    pub(crate) fn parse_volume_header_encryption_boxed(
        mut reader: Box<dyn ReadSeek>,
    ) -> RarResult<RarVolumeHeaderEncryption> {
        use std::io::{Seek, SeekFrom};

        reader
            .seek(SeekFrom::Start(0))
            .map_err(crate::error::RarError::Io)?;
        let format = signature::read_signature(&mut reader)?;

        if format.is_rar4_family() {
            // RAR 1.4 has no header encryption; RAR3/RAR4 signal it with the
            // archive header's `ENCRYPTED_HEADERS` flag, which is the *only*
            // thing the format states in the clear. `parse_rar4_headers` stops
            // at that flag with no password, and it is the first header after
            // the signature, so this costs one header read.
            if format == ArchiveFormat::Rar14 {
                return Ok(RarVolumeHeaderEncryption::None);
            }
            return match crate::rar4::parse_rar4_headers(&mut reader, None) {
                Ok(_) => Ok(RarVolumeHeaderEncryption::None),
                Err(crate::error::RarError::EncryptedArchive) => {
                    Ok(RarVolumeHeaderEncryption::Rar4)
                }
                Err(error) => Err(error),
            };
        }

        Ok(match crate::header::parse_header_encryption(&mut reader)? {
            Some(encryption) => RarVolumeHeaderEncryption::Rar5(RarVolumeHeaderEncryptionFacts {
                version: encryption.version,
                kdf_count_lg2: encryption.kdf_count,
                salt: encryption.salt,
                psw_check_present: encryption.has_password_check,
                psw_check: encryption.check_data,
            }),
            None => RarVolumeHeaderEncryption::None,
        })
    }

    pub(crate) fn parse_volume_facts_boxed(
        mut reader: Box<dyn ReadSeek>,
        password: Option<&str>,
    ) -> RarResult<RarVolumeFacts> {
        use std::io::{Seek, SeekFrom};

        reader
            .seek(SeekFrom::Start(0))
            .map_err(crate::error::RarError::Io)?;
        let format = signature::read_signature(&mut reader)?;

        if format.is_rar4_family() {
            let parsed = if format == ArchiveFormat::Rar14 {
                crate::rar4::parse_rar14_headers(&mut reader)?
            } else {
                crate::rar4::parse_rar4_headers(&mut reader, password)?
            };
            let volume_number = parsed
                .end
                .as_ref()
                .and_then(|end| end.volume_number)
                .map(u32::from);
            let more_volumes = parsed.end.as_ref().is_some_and(|end| end.more_volumes)
                || (format == ArchiveFormat::Rar14 && parsed.files.iter().any(|f| f.split_after));
            let has_rar4_uowner_payload =
                parsed.services.iter().any(|service| service.name == "UOW")
                    || parsed.old_services.iter().any(|service| {
                        matches!(
                            &service.data,
                            crate::rar4::types::Rar4OldServiceData::UnixOwner
                        )
                    });
            let member_owner_facts: Vec<_> = if has_rar4_uowner_payload {
                let archive = Self::open_rar4_parsed(
                    reader,
                    password,
                    std::sync::Arc::new(crate::crypto::KdfCache::new()),
                    format,
                    parsed.clone(),
                )?;
                archive
                    .members
                    .iter()
                    .map(|member| unix_owner_facts(member.owner.clone()))
                    .collect()
            } else {
                parsed
                    .files
                    .iter()
                    .map(|fh| unix_owner_facts(fh.owner.clone()))
                    .collect()
            };
            let members = parsed
                .files
                .iter()
                .enumerate()
                .map(|(order, fh)| {
                    let file_header =
                        RarArchive::rar4_to_file_header(fh, parsed.archive_header.is_solid);
                    let packed_hashes =
                        RarArchive::packed_hashes_for_split_segment(&file_header, None);
                    RarVolumeMemberFacts {
                        order: order as u32,
                        name: fh.name.clone(),
                        name_raw: fh.name_raw.clone(),
                        unpacked_size: fh.unpacked_size,
                        data_crc32: (!fh.is_rar14).then_some(fh.crc32),
                        data_blake2_hash: None,
                        version: file_header.version,
                        packed_crc32: packed_hashes.crc32,
                        packed_blake2_hash: packed_hashes.blake2sp,
                        packed_hash_uses_mac: false,
                        split_before: fh.split_before,
                        split_after: fh.split_after,
                        is_directory: fh.is_directory,
                        is_encrypted: fh.is_encrypted,
                        encryption: None,
                        rar4_salt: fh.salt,
                        host_os: supported_rar4_host_os(fh.host_os),
                        attributes: Some(u64::from(fh.attributes)),
                        owner: member_owner_facts.get(order).cloned().flatten(),
                        mtime_ns: encode_system_time(file_header.mtime),
                        ctime_ns: encode_system_time(file_header.ctime),
                        atime_ns: encode_system_time(file_header.atime),
                        data_offset: fh.data_offset,
                        data_size: fh.packed_size,
                        compression_method: file_header.compression.method.code(),
                        compression_version: fh.unpack_version,
                        compression_solid: RarArchive::rar4_effective_solid(
                            fh,
                            parsed.archive_header.is_solid,
                        ),
                        dict_size: fh.dict_size,
                        use_hash_mac: false,
                        redirection_type: None,
                        redirection_target: None,
                        redirection_target_raw: None,
                        redirection_target_is_directory: false,
                    }
                })
                .collect();
            let mut services: Vec<_> = parsed
                .services
                .iter()
                .enumerate()
                .map(|(order, service)| RarVolumeServiceFacts::from_rar4_service(order, service))
                .collect();
            let base_order = services.len();
            services.extend(parsed.comments.iter().enumerate().map(|(order, comment)| {
                RarVolumeServiceFacts::from_rar4_comment(base_order + order, comment)
            }));
            let base_order = services.len();
            services.extend(
                parsed
                    .old_services
                    .iter()
                    .enumerate()
                    .map(|(order, service)| {
                        RarVolumeServiceFacts::from_rar4_old_service(base_order + order, service)
                    }),
            );
            return Ok(RarVolumeFacts {
                format: if format == ArchiveFormat::Rar14 {
                    14
                } else {
                    4
                },
                volume_number,
                more_volumes,
                is_solid: parsed.archive_header.is_solid,
                is_encrypted: parsed.archive_header.is_encrypted,
                is_volume: parsed.archive_header.is_volume,
                has_recovery_record: parsed.archive_header.has_recovery_record,
                is_locked: parsed.archive_header.is_locked,
                has_authenticity_verification: parsed.archive_header.has_authenticity_verification,
                has_locator: false,
                quick_open_offset: None,
                // RAR4 and RAR1.4 have no Quick Open cache; this walk is
                // physical by construction.
                headers_from_quick_open: false,
                recovery_record_offset: None,
                original_name: None,
                original_name_raw: None,
                original_creation_time_ns: None,
                members,
                services,
            });
        }

        let parsed = crate::header::parse_all_headers(&mut reader, password)?;
        let main = parsed.main.as_ref();
        let volume_number = main
            .and_then(|main| main.volume_number)
            .map(|value| value as u32);
        let more_volumes = parsed.end.as_ref().is_some_and(|end| end.more_volumes);
        let is_solid = main.is_some_and(|main| main.is_solid);
        let is_volume = main.is_some_and(|main| main.is_volume);
        let has_recovery_record = main.is_some_and(|main| main.has_recovery_record);
        let is_locked = main.is_some_and(|main| main.is_locked);
        let has_locator = main.is_some_and(|main| main.has_locator);
        let quick_open_offset = main.and_then(|main| main.quick_open_offset);
        // Provenance, not the mere presence of a locator: a volume can carry
        // `quick_open_offset` and still be answered by the physical walk when
        // its `QO` block was rejected.
        let headers_from_quick_open = parsed.headers_from_quick_open;
        let recovery_record_offset = main.and_then(|main| main.recovery_record_offset);
        let original_name = main.and_then(|main| main.original_name.clone());
        let original_name_raw = main.and_then(|main| main.original_name_raw.clone());
        let original_creation_time_ns =
            encode_system_time(main.and_then(|main| main.original_creation_time));
        let services = parsed
            .services
            .into_iter()
            .enumerate()
            .map(|(order, service)| RarVolumeServiceFacts::from_rar5_service(order, service))
            .collect();
        let members = parsed
            .files
            .into_iter()
            .enumerate()
            .map(|(order, parsed_file)| {
                let packed_hashes = RarArchive::packed_hashes_for_split_segment(
                    &parsed_file.header,
                    parsed_file.hash.as_ref(),
                );
                let packed_hash_uses_mac = packed_hashes.is_present()
                    && parsed_file
                        .file_encryption
                        .as_ref()
                        .is_some_and(|info| info.use_hash_mac);
                RarVolumeMemberFacts {
                    order: order as u32,
                    name: parsed_file.header.name,
                    name_raw: parsed_file.header.name_raw,
                    unpacked_size: parsed_file.header.unpacked_size,
                    data_crc32: parsed_file.header.data_crc32,
                    data_blake2_hash: file_hash_blake2(parsed_file.hash.as_ref()),
                    version: parsed_file.header.version,
                    packed_crc32: packed_hashes.crc32,
                    packed_blake2_hash: packed_hashes.blake2sp,
                    packed_hash_uses_mac,
                    split_before: parsed_file.header.split_before,
                    split_after: parsed_file.header.split_after,
                    is_directory: parsed_file.header.is_directory,
                    is_encrypted: parsed_file.is_encrypted,
                    encryption: member_encryption_facts(parsed_file.file_encryption.as_ref()),
                    rar4_salt: None,
                    host_os: supported_host_os(parsed_file.header.host_os),
                    attributes: Some(parsed_file.header.attributes.0),
                    owner: unix_owner_facts(parsed_file.owner),
                    mtime_ns: encode_system_time(parsed_file.header.mtime),
                    ctime_ns: encode_system_time(parsed_file.header.ctime),
                    atime_ns: encode_system_time(parsed_file.header.atime),
                    data_offset: parsed_file.header.data_offset,
                    data_size: parsed_file.header.data_size,
                    compression_method: parsed_file.header.compression.method.code(),
                    compression_version: parsed_file.header.compression.version,
                    compression_solid: parsed_file.header.compression.solid,
                    dict_size: parsed_file.header.compression.dict_size,
                    use_hash_mac: parsed_file
                        .file_encryption
                        .as_ref()
                        .is_some_and(|info| info.use_hash_mac),
                    redirection_type: parsed_file.redirection.as_ref().map(|redir| {
                        match redir.redir_type {
                            crate::header::RedirectionType::UnixSymlink => 1,
                            crate::header::RedirectionType::WindowsSymlink => 2,
                            crate::header::RedirectionType::WindowsJunction => 3,
                            crate::header::RedirectionType::Hardlink => 4,
                            crate::header::RedirectionType::FileCopy => 5,
                            crate::header::RedirectionType::Unknown(value) => value,
                        }
                    }),
                    redirection_target: parsed_file
                        .redirection
                        .as_ref()
                        .map(|redir| redir.target.clone()),
                    redirection_target_raw: parsed_file
                        .redirection
                        .as_ref()
                        .and_then(|redir| redir.target_raw.clone()),
                    redirection_target_is_directory: parsed_file
                        .redirection
                        .as_ref()
                        .is_some_and(|redir| redir.target_is_directory),
                }
            })
            .collect();

        Ok(RarVolumeFacts {
            format: 5,
            volume_number,
            more_volumes,
            is_solid,
            is_encrypted: parsed.is_encrypted,
            is_volume,
            has_recovery_record,
            is_locked,
            has_authenticity_verification: false,
            has_locator,
            quick_open_offset,
            headers_from_quick_open,
            recovery_record_offset,
            original_name,
            original_name_raw,
            original_creation_time_ns,
            members,
            services,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[derive(Serialize)]
    struct LegacyVolumeFacts {
        format: u8,
        volume_number: u32,
        more_volumes: bool,
        is_solid: bool,
        is_encrypted: bool,
        members: Vec<LegacyMemberFacts>,
    }

    #[derive(Serialize)]
    struct LegacyMemberFacts {
        order: u32,
        name: String,
        unpacked_size: Option<u64>,
        data_crc32: Option<u32>,
        split_before: bool,
        split_after: bool,
        is_directory: bool,
        is_encrypted: bool,
        data_offset: u64,
        data_size: u64,
        compression_method: u8,
        compression_version: u8,
        compression_solid: bool,
        dict_size: u64,
        use_hash_mac: bool,
        redirection_type: Option<u64>,
        redirection_target: Option<String>,
        redirection_target_is_directory: bool,
    }

    fn build_rar4_header(header_type: u8, flags: u16, body: &[u8]) -> Vec<u8> {
        let mut header = Vec::with_capacity(7 + body.len());
        header.extend_from_slice(&[0, 0]);
        header.push(header_type);
        header.extend_from_slice(&flags.to_le_bytes());
        header.extend_from_slice(&((7 + body.len()) as u16).to_le_bytes());
        header.extend_from_slice(body);
        let crc16 = (crate::crc::hash(&header[2..]) & 0xffff) as u16;
        header[0..2].copy_from_slice(&crc16.to_le_bytes());
        header
    }

    fn build_rar4_main_header(flags: u16, high_pos_av: u16, pos_av: u32) -> Vec<u8> {
        let mut body = Vec::with_capacity(6);
        body.extend_from_slice(&high_pos_av.to_le_bytes());
        body.extend_from_slice(&pos_av.to_le_bytes());
        build_rar4_header(0x73, flags, &body)
    }

    fn signed_rar4_archive_bytes() -> Vec<u8> {
        let mut bytes = crate::signature::RAR4_SIGNATURE.to_vec();
        bytes.extend_from_slice(&build_rar4_main_header(0, 0x1234, 0x5678_9abc));
        bytes.extend_from_slice(&build_rar4_header(0x7b, 0, &[]));
        bytes
    }

    /// Assemble one RAR5 block. `sizes` carries the optional extra-area and
    /// data-area sizes, in the order their header flags select them.
    fn build_rar5_block(
        header_type: u64,
        header_flags: u64,
        sizes: &[u64],
        type_body: &[u8],
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&crate::vint::encode_vint(header_type));
        body.extend_from_slice(&crate::vint::encode_vint(header_flags));
        for size in sizes {
            body.extend_from_slice(&crate::vint::encode_vint(*size));
        }
        body.extend_from_slice(type_body);

        let header_size = crate::vint::encode_vint(body.len() as u64);
        let mut hasher = crate::crc::Crc32::new();
        hasher.update(&header_size);
        hasher.update(&body);

        let mut raw = Vec::new();
        raw.extend_from_slice(&hasher.finalize().to_le_bytes());
        raw.extend_from_slice(&header_size);
        raw.extend_from_slice(&body);
        raw
    }

    /// A one-volume RAR5 archive whose only file header is a split-after
    /// stored part carrying both a Pack-CRC32 field and a BLAKE2sp record.
    fn rar5_split_after_archive_bytes(
        name: &str,
        payload: &[u8],
        unpacked_size: u64,
        packed_crc32: u32,
        blake2: [u8; 32],
    ) -> Vec<u8> {
        let mut hash_body = crate::vint::encode_vint(0); // BLAKE2sp hash type.
        hash_body.extend_from_slice(&blake2);
        let hash_type = crate::vint::encode_vint(crate::header::extra::record_type::FILE_HASH);
        let mut extra_area = crate::vint::encode_vint((hash_type.len() + hash_body.len()) as u64);
        extra_area.extend_from_slice(&hash_type);
        extra_area.extend_from_slice(&hash_body);

        let mut file_body = Vec::new();
        file_body.extend_from_slice(&crate::vint::encode_vint(
            crate::header::file::flags::CRC32_PRESENT,
        ));
        file_body.extend_from_slice(&crate::vint::encode_vint(unpacked_size));
        file_body.extend_from_slice(&crate::vint::encode_vint(0o644)); // attributes.
        file_body.extend_from_slice(&packed_crc32.to_le_bytes());
        file_body.extend_from_slice(&crate::vint::encode_vint(0)); // RAR5 Store.
        file_body.extend_from_slice(&crate::vint::encode_vint(1)); // Unix host OS.
        file_body.extend_from_slice(&crate::vint::encode_vint(name.len() as u64));
        file_body.extend_from_slice(name.as_bytes());
        file_body.extend_from_slice(&extra_area);

        let mut bytes = crate::signature::RAR5_SIGNATURE.to_vec();
        bytes.extend_from_slice(&build_rar5_block(
            1,
            0,
            &[],
            &crate::vint::encode_vint(crate::header::main_archive::flags::VOLUME),
        ));
        bytes.extend_from_slice(&build_rar5_block(
            2,
            crate::header::common::flags::EXTRA_AREA
                | crate::header::common::flags::DATA_AREA
                | crate::header::common::flags::SPLIT_AFTER,
            &[extra_area.len() as u64, payload.len() as u64],
            &file_body,
        ));
        bytes.extend_from_slice(payload);
        bytes.extend_from_slice(&build_rar5_block(5, 0, &[], &crate::vint::encode_vint(1)));
        bytes
    }

    #[test]
    fn named_messagepack_legacy_volume_facts_default_new_fields() {
        let legacy = LegacyVolumeFacts {
            format: 5,
            volume_number: 2,
            more_volumes: true,
            is_solid: false,
            is_encrypted: false,
            members: vec![LegacyMemberFacts {
                order: 0,
                name: "legacy.part03.rar".to_string(),
                unpacked_size: Some(123),
                data_crc32: Some(0x1234_5678),
                split_before: true,
                split_after: false,
                is_directory: false,
                is_encrypted: false,
                data_offset: 44,
                data_size: 55,
                compression_method: 0,
                compression_version: 0,
                compression_solid: false,
                dict_size: 0,
                use_hash_mac: false,
                redirection_type: None,
                redirection_target: None,
                redirection_target_is_directory: false,
            }],
        };
        let encoded = rmp_serde::to_vec_named(&legacy).unwrap();

        let decoded: RarVolumeFacts = rmp_serde::from_slice(&encoded).unwrap();

        // A pre-0.6 cache states a bare integer — its parse defaulted an
        // absent number to 0 — and it decodes as a stated number.
        assert_eq!(decoded.volume_number, Some(2));
        assert!(decoded.services.is_empty());
        assert!(!decoded.is_volume);
        assert!(!decoded.has_recovery_record);
        assert!(!decoded.is_locked);
        assert!(!decoded.has_authenticity_verification);
        assert!(!decoded.has_locator);
        assert_eq!(decoded.quick_open_offset, None);
        assert_eq!(decoded.recovery_record_offset, None);
        assert_eq!(decoded.original_name, None);
        assert_eq!(decoded.original_name_raw, None);
        assert_eq!(decoded.original_creation_time_ns, None);
        assert_eq!(decoded.members.len(), 1);
        assert_eq!(decoded.members[0].name_raw, None);
        assert_eq!(decoded.members[0].data_blake2_hash, None);
        assert_eq!(decoded.members[0].version, None);
        assert_eq!(decoded.members[0].redirection_target_raw, None);
        assert_eq!(decoded.members[0].host_os, None);
        assert_eq!(decoded.members[0].attributes, None);
        assert_eq!(decoded.members[0].owner, None);
        assert_eq!(decoded.members[0].mtime_ns, None);
        assert_eq!(decoded.members[0].ctime_ns, None);
        assert_eq!(decoded.members[0].atime_ns, None);
        assert_eq!(decoded.members[0].packed_crc32, None);
        assert_eq!(decoded.members[0].packed_blake2_hash, None);
        assert!(!decoded.members[0].packed_hash_uses_mac);
        assert_eq!(decoded.members[0].encryption, None);
        assert_eq!(decoded.members[0].rar4_salt, None);
    }

    #[test]
    fn named_messagepack_legacy_service_facts_default_child_flags() {
        #[derive(Serialize)]
        struct LegacyServiceVolumeFacts {
            format: u8,
            volume_number: u32,
            more_volumes: bool,
            is_solid: bool,
            is_encrypted: bool,
            members: Vec<LegacyMemberFacts>,
            services: Vec<LegacyServiceFacts>,
        }

        #[derive(Serialize)]
        struct LegacyServiceFacts {
            order: u32,
            name: String,
            unpacked_size: Option<u64>,
            data_crc32: Option<u32>,
            split_before: bool,
            split_after: bool,
            is_encrypted: bool,
            data_offset: u64,
            data_size: u64,
            compression_method: u8,
            compression_version: u8,
            compression_solid: bool,
            dict_size: u64,
            use_hash_mac: bool,
            stream_name: Option<String>,
            stream_name_raw: Option<Vec<u8>>,
        }

        let legacy = LegacyServiceVolumeFacts {
            format: 5,
            volume_number: 0,
            more_volumes: false,
            is_solid: false,
            is_encrypted: false,
            members: Vec::new(),
            services: vec![LegacyServiceFacts {
                order: 0,
                name: "CMT".to_string(),
                unpacked_size: Some(3),
                data_crc32: None,
                split_before: false,
                split_after: false,
                is_encrypted: false,
                data_offset: 123,
                data_size: 3,
                compression_method: CompressionMethod::Store.code(),
                compression_version: 0,
                compression_solid: false,
                dict_size: 0,
                use_hash_mac: false,
                stream_name: None,
                stream_name_raw: None,
            }],
        };
        let encoded = rmp_serde::to_vec_named(&legacy).unwrap();

        let decoded: RarVolumeFacts = rmp_serde::from_slice(&encoded).unwrap();

        assert_eq!(decoded.services.len(), 1);
        assert!(!decoded.services[0].is_child);
        assert!(!decoded.services[0].is_inherited);
    }

    #[test]
    fn rar5_split_after_facts_keep_packed_crc32_alongside_blake2() {
        let payload = vec![0xA5u8; 64];
        let packed_crc32 = crate::crc::hash(&payload);
        let blake2 = [0x7Bu8; 32];
        let bytes = rar5_split_after_archive_bytes(
            "Silver.Horizon.S01E01.mkv",
            &payload,
            4096,
            packed_crc32,
            blake2,
        );

        let facts = RarArchive::parse_volume_facts(Cursor::new(bytes), None).unwrap();

        let member = &facts.members[0];
        assert!(member.split_after);
        assert_eq!(member.data_size, payload.len() as u64);
        // Both packed checksums survive: the CRC32 is no longer discarded just
        // because the header also carried a BLAKE2sp record.
        assert_eq!(member.packed_crc32, Some(packed_crc32));
        assert_eq!(member.packed_blake2_hash, Some(blake2));
        assert_eq!(member.data_crc32, Some(packed_crc32));
        assert_eq!(member.data_blake2_hash, Some(blake2));
    }

    #[test]
    fn rar4_volume_facts_preserve_signed_main_header_like_rar_behavior() {
        let facts =
            RarArchive::parse_volume_facts(Cursor::new(signed_rar4_archive_bytes()), None).unwrap();

        assert_eq!(facts.format, 4);
        assert!(facts.has_authenticity_verification);
        // The end record carries no `VOLUME_NUMBER` flag: the format stated
        // nothing, which is a different fact from "the header said volume 0".
        assert_eq!(facts.volume_number, None);
    }

    /// Key material the encrypted synthetic archives below state. Distinct
    /// fills, so a test cannot pass by confusing the salt with the IV.
    const CRYPT_SALT: [u8; 16] = [0x5A; 16];
    const CRYPT_IV: [u8; 16] = [0x1F; 16];
    const CRYPT_KDF_LG2: u8 = 15;

    /// A one-volume RAR5 archive whose only file header is an encrypted,
    /// unsplit stored member carrying an `FHEXTRA_CRYPT` record.
    ///
    /// The bytes are not real ciphertext — no test here decrypts them — but
    /// the record is laid out exactly as the format states it, so the parse it
    /// exercises is the real one.
    fn rar5_encrypted_store_archive_bytes(
        name: &str,
        cipher_len: u64,
        unpacked_size: u64,
        enc_flags: u64,
        check_data: Option<[u8; 12]>,
    ) -> Vec<u8> {
        let mut crypt_body = crate::vint::encode_vint(0); // version = AES-256.
        crypt_body.extend_from_slice(&crate::vint::encode_vint(enc_flags));
        crypt_body.push(CRYPT_KDF_LG2);
        crypt_body.extend_from_slice(&CRYPT_SALT);
        crypt_body.extend_from_slice(&CRYPT_IV);
        if let Some(check_data) = check_data {
            crypt_body.extend_from_slice(&check_data);
        }
        let crypt_type =
            crate::vint::encode_vint(crate::header::extra::record_type::FILE_ENCRYPTION);
        let mut extra_area = crate::vint::encode_vint((crypt_type.len() + crypt_body.len()) as u64);
        extra_area.extend_from_slice(&crypt_type);
        extra_area.extend_from_slice(&crypt_body);

        let mut file_body = Vec::new();
        file_body.extend_from_slice(&crate::vint::encode_vint(
            crate::header::file::flags::CRC32_PRESENT,
        ));
        file_body.extend_from_slice(&crate::vint::encode_vint(unpacked_size));
        file_body.extend_from_slice(&crate::vint::encode_vint(0o644)); // attributes.
        file_body.extend_from_slice(&0x1234_5678u32.to_le_bytes());
        file_body.extend_from_slice(&crate::vint::encode_vint(0)); // RAR5 Store.
        file_body.extend_from_slice(&crate::vint::encode_vint(1)); // Unix host OS.
        file_body.extend_from_slice(&crate::vint::encode_vint(name.len() as u64));
        file_body.extend_from_slice(name.as_bytes());
        file_body.extend_from_slice(&extra_area);

        let mut bytes = crate::signature::RAR5_SIGNATURE.to_vec();
        bytes.extend_from_slice(&build_rar5_block(1, 0, &[], &crate::vint::encode_vint(0)));
        bytes.extend_from_slice(&build_rar5_block(
            2,
            crate::header::common::flags::EXTRA_AREA | crate::header::common::flags::DATA_AREA,
            &[extra_area.len() as u64, cipher_len],
            &file_body,
        ));
        bytes.extend_from_slice(&vec![0xE7u8; cipher_len as usize]);
        bytes.extend_from_slice(&build_rar5_block(5, 0, &[], &crate::vint::encode_vint(0)));
        bytes
    }

    /// The 12-byte password-check field: 8 check bytes plus the SHA-256 tag the
    /// parser validates them against.
    fn tagged_password_check(check: [u8; 8]) -> [u8; 12] {
        let digest = crate::crypto::sha256_digest(&check);
        let mut field = [0u8; 12];
        field[..8].copy_from_slice(&check);
        field[8..].copy_from_slice(&digest[..4]);
        field
    }

    #[test]
    fn rar5_file_encryption_record_reaches_member_facts_verbatim() {
        let check_data = tagged_password_check([0xC4; 8]);
        let bytes = rar5_encrypted_store_archive_bytes(
            "Silver.Horizon.S02E09.mkv",
            304,
            290,
            0x0001 | 0x0002, // password check present, checksums keyed.
            Some(check_data),
        );

        let facts = RarArchive::parse_volume_facts(Cursor::new(bytes), None).unwrap();

        let member = &facts.members[0];
        assert!(member.is_encrypted);
        assert!(member.use_hash_mac, "0x0002 keys the header's checksums");
        assert_eq!(member.data_size, 304, "packed bytes are the padded cipher");
        assert_eq!(member.unpacked_size, Some(290));
        assert_eq!(
            member.encryption,
            Some(RarVolumeMemberEncryptionFacts {
                version: 0,
                kdf_count_lg2: CRYPT_KDF_LG2,
                salt: CRYPT_SALT,
                iv: CRYPT_IV,
                psw_check_present: true,
                psw_check: Some(check_data),
            })
        );
        assert_eq!(member.rar4_salt, None);
    }

    #[test]
    fn rar5_encryption_record_without_a_password_check_reports_it_absent() {
        let bytes = rar5_encrypted_store_archive_bytes(
            "Silver.Horizon.S02E10.mkv",
            16,
            10,
            0, // neither flag.
            None,
        );

        let facts = RarArchive::parse_volume_facts(Cursor::new(bytes), None).unwrap();

        let encryption = facts.members[0].encryption.expect("record present");
        assert!(!encryption.psw_check_present);
        assert_eq!(encryption.psw_check, None);
        assert!(!facts.members[0].use_hash_mac);
    }

    #[test]
    fn rar5_encryption_record_with_a_corrupt_password_check_claims_one_it_lost() {
        // The flag says a check is there; its SHA-256 tag says the bytes are
        // not trustworthy. Facts must report both halves, because "the writer
        // omitted it" and "we could not read it" are different diagnoses.
        let mut check_data = tagged_password_check([0xC4; 8]);
        check_data[11] ^= 0xFF;
        let bytes = rar5_encrypted_store_archive_bytes(
            "Silver.Horizon.S02E11.mkv",
            16,
            10,
            0x0001,
            Some(check_data),
        );

        let facts = RarArchive::parse_volume_facts(Cursor::new(bytes), None).unwrap();

        let encryption = facts.members[0].encryption.expect("record present");
        assert!(encryption.psw_check_present);
        assert_eq!(encryption.psw_check, None);
    }

    #[test]
    fn named_messagepack_new_volume_facts_decode_under_a_reader_without_the_crypt_fields() {
        // The other direction of the cached-facts contract: a cache written by
        // this binary must still load in one that predates the encryption
        // record. Such a reader ignores `encryption` and `rar4_salt` — it
        // keeps `is_encrypted`, which is the field it classified on — so an
        // encrypted member reads exactly as it did before.
        #[derive(Deserialize)]
        struct OldVolumeFacts {
            format: u8,
            is_encrypted: bool,
            members: Vec<OldMemberFacts>,
        }

        #[derive(Deserialize)]
        struct OldMemberFacts {
            name: String,
            unpacked_size: Option<u64>,
            data_crc32: Option<u32>,
            is_encrypted: bool,
            data_size: u64,
            compression_method: u8,
            use_hash_mac: bool,
        }

        let check_data = tagged_password_check([0xC4; 8]);
        let bytes = rar5_encrypted_store_archive_bytes(
            "Silver.Horizon.S02E12.mkv",
            304,
            290,
            0x0001 | 0x0002,
            Some(check_data),
        );
        let facts = RarArchive::parse_volume_facts(Cursor::new(bytes), None).unwrap();
        assert!(facts.members[0].encryption.is_some(), "non-vacuity");

        let encoded = rmp_serde::to_vec_named(&facts).unwrap();
        let decoded: OldVolumeFacts = rmp_serde::from_slice(&encoded).unwrap();

        assert_eq!(decoded.format, 5);
        assert!(!decoded.is_encrypted, "-p leaves the headers plain");
        assert_eq!(decoded.members.len(), 1);
        let member = &decoded.members[0];
        assert_eq!(member.name, "Silver.Horizon.S02E12.mkv");
        assert_eq!(member.unpacked_size, Some(290));
        assert_eq!(member.data_crc32, Some(0x1234_5678));
        assert!(member.is_encrypted);
        assert_eq!(member.data_size, 304);
        assert_eq!(member.compression_method, 0);
        assert!(member.use_hash_mac);

        // And the round trip through this binary's own reader is lossless.
        let round_tripped: RarVolumeFacts = rmp_serde::from_slice(&encoded).unwrap();
        assert_eq!(
            round_tripped.members[0].encryption,
            facts.members[0].encryption
        );
        assert_eq!(round_tripped.members[0].rar4_salt, None);
    }
}
