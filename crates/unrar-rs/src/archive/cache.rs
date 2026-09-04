//! Serializable archive header cache for journal persistence.
//!
//! Enables reconstructing a `RarArchive` without reading volume 0 from disk.
//! Headers are serialized as named MessagePack maps so added metadata fields
//! remain backward-compatible.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use super::{
    DataSegment, FileEncryptionInfo, MemberEntry, PackedDataHashes, RarArchive, ServiceEntry,
};
use crate::header::file::FileHeader;
use crate::header::{Redirection, RedirectionType};
use crate::limits::Limits;
use crate::types::{
    ArchiveFormat, CompressionInfo, CompressionMethod, FileAttributes, FileHash, HostOs,
    RecoveryRecordInfo, UnixOwnerInfo,
};
use crate::volume::VolumeSet;

/// Serializable snapshot of parsed archive headers.
#[derive(Serialize, Deserialize)]
pub struct CachedArchiveHeaders {
    pub format: u8, // 4=Rar4, 5=Rar5
    pub is_solid: bool,
    pub is_encrypted: bool,
    #[serde(default)]
    pub has_recovery_record: bool,
    #[serde(default)]
    pub recovery_records: Vec<RecoveryRecordInfo>,
    #[serde(default)]
    pub is_locked: bool,
    #[serde(default)]
    pub has_authenticity_verification: bool,
    #[serde(default)]
    pub has_locator: bool,
    #[serde(default)]
    pub quick_open_offset: Option<u64>,
    #[serde(default)]
    pub recovery_record_offset: Option<u64>,
    #[serde(default)]
    pub original_name: Option<String>,
    #[serde(default)]
    pub original_name_raw: Option<Vec<u8>>,
    #[serde(default)]
    pub original_creation_time_ns: Option<u64>,
    pub more_volumes: bool,
    #[serde(default)]
    pub volume_presence: Vec<bool>,
    #[serde(default)]
    pub last_volume_seen: bool,
    pub members: Vec<CachedMember>,
    #[serde(default)]
    pub services: Vec<CachedService>,
}

#[derive(Serialize, Deserialize)]
pub struct CachedMember {
    pub name: String,
    #[serde(default)]
    pub name_raw: Option<Vec<u8>>,
    pub unpacked_size: Option<u64>,
    #[serde(default)]
    pub mtime_ns: Option<u64>,
    #[serde(default)]
    pub ctime_ns: Option<u64>,
    #[serde(default)]
    pub atime_ns: Option<u64>,
    pub data_crc32: Option<u32>,
    pub compression_method: u8,
    #[serde(default)]
    pub compression_version: u8,
    pub compression_solid: bool,
    pub dict_size: u64,
    pub split_before: bool,
    pub split_after: bool,
    pub is_directory: bool,
    pub is_encrypted: bool,
    pub encryption: Option<CachedEncryption>,
    #[serde(default)]
    pub rar4_salt: Option<[u8; 8]>,
    #[serde(default)]
    pub version: Option<u64>,
    #[serde(default)]
    pub blake2_hash: Option<[u8; 32]>,
    #[serde(default)]
    pub redirection_type: Option<u64>,
    #[serde(default)]
    pub redirection_target: Option<String>,
    #[serde(default)]
    pub redirection_target_raw: Option<Vec<u8>>,
    #[serde(default)]
    pub redirection_target_is_directory: bool,
    #[serde(default)]
    pub attributes: u64,
    #[serde(default = "default_host_os_code")]
    pub host_os: u64,
    #[serde(default)]
    pub owner_user_name: Option<String>,
    #[serde(default)]
    pub owner_group_name: Option<String>,
    #[serde(default)]
    pub owner_user_name_raw: Option<Vec<u8>>,
    #[serde(default)]
    pub owner_group_name_raw: Option<Vec<u8>>,
    #[serde(default)]
    pub owner_uid: Option<u64>,
    #[serde(default)]
    pub owner_gid: Option<u64>,
    pub segments: Vec<CachedSegment>,
}

#[derive(Serialize, Deserialize)]
pub struct CachedService {
    #[serde(default)]
    pub header_offset: u64,
    pub name: String,
    #[serde(default)]
    pub name_raw: Option<Vec<u8>>,
    pub unpacked_size: Option<u64>,
    #[serde(default)]
    pub mtime_ns: Option<u64>,
    #[serde(default)]
    pub ctime_ns: Option<u64>,
    #[serde(default)]
    pub atime_ns: Option<u64>,
    pub data_crc32: Option<u32>,
    pub compression_method: u8,
    #[serde(default)]
    pub compression_version: u8,
    pub compression_solid: bool,
    pub dict_size: u64,
    pub split_before: bool,
    pub split_after: bool,
    #[serde(default)]
    pub is_child: bool,
    #[serde(default)]
    pub is_inherited: bool,
    pub is_encrypted: bool,
    pub encryption: Option<CachedEncryption>,
    #[serde(default)]
    pub rar4_salt: Option<[u8; 8]>,
    #[serde(default)]
    pub version: Option<u64>,
    #[serde(default)]
    pub blake2_hash: Option<[u8; 32]>,
    #[serde(default)]
    pub comment_crc16: Option<u16>,
    #[serde(default)]
    pub attributes: u64,
    #[serde(default = "default_host_os_code")]
    pub host_os: u64,
    #[serde(default)]
    pub service_subdata: Option<Vec<u8>>,
    #[serde(default)]
    pub ntfs_stream_name: Option<String>,
    pub segments: Vec<CachedSegment>,
}

#[derive(Serialize, Deserialize)]
pub struct CachedEncryption {
    #[serde(default)]
    pub version: u64,
    pub kdf_count: u8,
    pub salt: [u8; 16],
    pub iv: [u8; 16],
    pub check_data: Option<[u8; 12]>,
    /// Whether the header's flags claimed a password check. Caches written
    /// before this field existed decode to `false`; `check_data` is the field
    /// that decides whether a password can be verified, and it is unaffected.
    #[serde(default)]
    pub psw_check_present: bool,
    pub use_hash_mac: bool,
}

/// One volume's slice of a member, as persisted in the header cache.
///
/// Both packed-hash fields are populated whenever the header carried both.
/// Caches written by older binaries recorded at most one of them, so both stay
/// `#[serde(default)]` and decode to `None` when absent.
#[derive(Serialize, Deserialize)]
pub struct CachedSegment {
    pub volume_index: usize,
    pub data_offset: u64,
    pub data_size: u64,
    #[serde(default)]
    pub packed_crc32: Option<u32>,
    #[serde(default)]
    pub packed_blake2_hash: Option<[u8; 32]>,
    #[serde(default)]
    pub packed_hash_uses_mac: bool,
}

/// The pre-named cache shape, decoded positionally.
///
/// **Frozen.** MessagePack without field names is a bare array, so every one of
/// these structs is a field *count* as much as a field list: a decode reads
/// element *n* into field *n* and fails the moment the counts disagree. They
/// therefore mirror the historical layout and must never track the current
/// structs — widening `CachedArchiveHeaders`, `CachedMember` or
/// `CachedEncryption` must leave this side alone, or every legacy blob stops
/// decoding (a cache miss and a re-parse, so benign, but silent).
///
/// `deserialize_headers_accepts_legacy_compact_cache` pins that by building its
/// input from its own frozen mirrors rather than from these or from the current
/// structs.
#[derive(Deserialize)]
struct LegacyCachedArchiveHeaders {
    format: u8,
    is_solid: bool,
    is_encrypted: bool,
    more_volumes: bool,
    #[serde(default)]
    volume_presence: Vec<bool>,
    #[serde(default)]
    last_volume_seen: bool,
    members: Vec<LegacyCachedMember>,
}

#[derive(Deserialize)]
struct LegacyCachedMember {
    name: String,
    unpacked_size: Option<u64>,
    data_crc32: Option<u32>,
    compression_method: u8,
    compression_version: u8,
    compression_solid: bool,
    dict_size: u64,
    split_before: bool,
    split_after: bool,
    is_directory: bool,
    is_encrypted: bool,
    encryption: Option<LegacyCachedEncryption>,
    rar4_salt: Option<[u8; 8]>,
    blake2_hash: Option<[u8; 32]>,
    segments: Vec<CachedSegment>,
}

/// The six-field encryption record a pre-named cache carries — everything the
/// current [`CachedEncryption`] has except `psw_check_present`, which did not
/// exist when anything wrote this shape.
#[derive(Deserialize)]
struct LegacyCachedEncryption {
    version: u64,
    kdf_count: u8,
    salt: [u8; 16],
    iv: [u8; 16],
    check_data: Option<[u8; 12]>,
    use_hash_mac: bool,
}

impl From<LegacyCachedEncryption> for CachedEncryption {
    fn from(value: LegacyCachedEncryption) -> Self {
        Self {
            version: value.version,
            kdf_count: value.kdf_count,
            salt: value.salt,
            iv: value.iv,
            check_data: value.check_data,
            // The parser only ever kept a check value whose flag was set and
            // whose tag validated, so a stored value implies the claim. The
            // reverse — a claim whose value failed its tag — is not recoverable
            // from a cache that predates the field, and under-reports as
            // `false`; `file_encryption` states the same rule for the named
            // shape's defaulted field.
            psw_check_present: value.check_data.is_some(),
            use_hash_mac: value.use_hash_mac,
        }
    }
}

impl From<LegacyCachedArchiveHeaders> for CachedArchiveHeaders {
    fn from(value: LegacyCachedArchiveHeaders) -> Self {
        Self {
            format: value.format,
            is_solid: value.is_solid,
            is_encrypted: value.is_encrypted,
            has_recovery_record: false,
            is_locked: false,
            has_authenticity_verification: false,
            has_locator: false,
            quick_open_offset: None,
            recovery_record_offset: None,
            original_name: None,
            original_name_raw: None,
            original_creation_time_ns: None,
            more_volumes: value.more_volumes,
            volume_presence: value.volume_presence,
            last_volume_seen: value.last_volume_seen,
            recovery_records: Vec::new(),
            members: value.members.into_iter().map(CachedMember::from).collect(),
            services: Vec::new(),
        }
    }
}

impl From<LegacyCachedMember> for CachedMember {
    fn from(value: LegacyCachedMember) -> Self {
        Self {
            name: value.name,
            name_raw: None,
            unpacked_size: value.unpacked_size,
            mtime_ns: None,
            ctime_ns: None,
            atime_ns: None,
            data_crc32: value.data_crc32,
            compression_method: value.compression_method,
            compression_version: value.compression_version,
            compression_solid: value.compression_solid,
            dict_size: value.dict_size,
            split_before: value.split_before,
            split_after: value.split_after,
            is_directory: value.is_directory,
            is_encrypted: value.is_encrypted,
            encryption: value.encryption.map(CachedEncryption::from),
            rar4_salt: value.rar4_salt,
            version: None,
            blake2_hash: value.blake2_hash,
            redirection_type: None,
            redirection_target: None,
            redirection_target_raw: None,
            redirection_target_is_directory: false,
            attributes: 0,
            host_os: default_host_os_code(),
            owner_user_name: None,
            owner_group_name: None,
            owner_user_name_raw: None,
            owner_group_name_raw: None,
            owner_uid: None,
            owner_gid: None,
            segments: value.segments,
        }
    }
}

fn default_host_os_code() -> u64 {
    CACHED_HOST_OS_UNIX
}

fn decode_cached_headers(data: &[u8]) -> Result<CachedArchiveHeaders, rmp_serde::decode::Error> {
    let current_error = match rmp_serde::from_slice::<CachedArchiveHeaders>(data) {
        Ok(cached) => return Ok(cached),
        Err(error) => error,
    };

    match rmp_serde::from_slice::<LegacyCachedArchiveHeaders>(data) {
        Ok(cached) => Ok(cached.into()),
        Err(_) => Err(current_error),
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

fn decode_system_time(time_ns: Option<u64>) -> Option<SystemTime> {
    time_ns.and_then(|value| {
        let secs = value / 1_000_000_000;
        let nanos = (value % 1_000_000_000) as u32;
        UNIX_EPOCH.checked_add(Duration::new(secs, nanos))
    })
}

fn encode_redirection_type(redirection: &RedirectionType) -> u64 {
    match redirection {
        RedirectionType::UnixSymlink => 1,
        RedirectionType::WindowsSymlink => 2,
        RedirectionType::WindowsJunction => 3,
        RedirectionType::Hardlink => 4,
        RedirectionType::FileCopy => 5,
        RedirectionType::Unknown(value) => *value,
    }
}

const CACHED_HOST_OS_WINDOWS: u64 = u64::MAX - 3;
const CACHED_HOST_OS_UNIX: u64 = u64::MAX - 2;
const CACHED_HOST_OS_DARWIN: u64 = u64::MAX - 1;
const CACHED_HOST_OS_UNKNOWN_FLAG: u64 = 1 << 63;

fn encode_host_os(host_os: HostOs) -> u64 {
    match host_os {
        HostOs::Windows => CACHED_HOST_OS_WINDOWS,
        HostOs::Unix => CACHED_HOST_OS_UNIX,
        HostOs::Darwin => CACHED_HOST_OS_DARWIN,
        // Only supported extraction targets are mapped here: Darwin/macOS,
        // Linux/Unix, and Windows. Older RAR4 origins are not supported
        // targets, and the cache uses a private marker so raw IDs like
        // 0 (MS-DOS) do not round-trip as supported Windows.
        HostOs::Unknown(value) => CACHED_HOST_OS_UNKNOWN_FLAG | value,
    }
}

fn decode_host_os(host_os: u64) -> HostOs {
    match host_os {
        // Legacy caches encoded RAR5 Windows/Unix directly.
        0 => HostOs::Windows,
        1 => HostOs::Unix,
        CACHED_HOST_OS_WINDOWS => HostOs::Windows,
        CACHED_HOST_OS_UNIX => HostOs::Unix,
        CACHED_HOST_OS_DARWIN => HostOs::Darwin,
        value if (value & CACHED_HOST_OS_UNKNOWN_FLAG) != 0 => {
            HostOs::Unknown(value & !CACHED_HOST_OS_UNKNOWN_FLAG)
        }
        value => HostOs::Unknown(value),
    }
}

fn cached_segments(segments: &[DataSegment]) -> Vec<CachedSegment> {
    segments
        .iter()
        .map(|s| CachedSegment {
            volume_index: s.volume_index,
            data_offset: s.data_offset,
            data_size: s.data_size,
            packed_crc32: s.packed_hashes.crc32,
            packed_blake2_hash: s.packed_hashes.blake2sp,
            packed_hash_uses_mac: s.packed_hash_uses_mac,
        })
        .collect()
}

fn data_segments(segments: Vec<CachedSegment>) -> Vec<DataSegment> {
    segments
        .into_iter()
        .map(|s| {
            DataSegment::with_packed_hashes(
                s.volume_index,
                s.data_offset,
                s.data_size,
                PackedDataHashes {
                    crc32: s.packed_crc32,
                    blake2sp: s.packed_blake2_hash,
                },
                s.packed_hash_uses_mac,
            )
        })
        .collect()
}

fn cached_encryption(encryption: &FileEncryptionInfo) -> CachedEncryption {
    CachedEncryption {
        version: encryption.version,
        kdf_count: encryption.kdf_count,
        salt: encryption.salt,
        iv: encryption.iv,
        check_data: encryption.check_data,
        psw_check_present: encryption.psw_check_present,
        use_hash_mac: encryption.use_hash_mac,
    }
}

fn file_encryption(encryption: CachedEncryption) -> FileEncryptionInfo {
    FileEncryptionInfo {
        version: encryption.version,
        kdf_count: encryption.kdf_count,
        salt: encryption.salt,
        iv: encryption.iv,
        check_data: encryption.check_data,
        // A cache written before this field existed states `false` here while
        // still carrying a check value; keep the two consistent rather than
        // reporting a member whose check is usable as having none claimed.
        psw_check_present: encryption.psw_check_present || encryption.check_data.is_some(),
        use_hash_mac: encryption.use_hash_mac,
    }
}

impl RarArchive {
    /// Export parsed headers for journal persistence.
    pub fn export_headers(&self) -> CachedArchiveHeaders {
        CachedArchiveHeaders {
            format: match self.format {
                ArchiveFormat::Rar14 => 14,
                ArchiveFormat::Rar4 => 4,
                ArchiveFormat::Rar5 => 5,
            },
            is_solid: self.is_solid,
            is_encrypted: self.is_encrypted,
            has_recovery_record: self.has_recovery_record,
            recovery_records: self.recovery_records.clone(),
            is_locked: self.is_locked,
            has_authenticity_verification: self.has_authenticity_verification,
            has_locator: self.has_locator,
            quick_open_offset: self.quick_open_offset,
            recovery_record_offset: self.recovery_record_offset,
            original_name: self.original_name.clone(),
            original_name_raw: self.original_name_raw.clone(),
            original_creation_time_ns: encode_system_time(self.original_creation_time),
            more_volumes: self.more_volumes,
            volume_presence: self.volume_set.presence(),
            last_volume_seen: self.volume_set.last_volume_seen(),
            members: self
                .members
                .iter()
                .map(|m| CachedMember {
                    name: m.file_header.name.clone(),
                    name_raw: m.file_header.name_raw.clone(),
                    unpacked_size: m.file_header.unpacked_size,
                    mtime_ns: encode_system_time(m.file_header.mtime),
                    ctime_ns: encode_system_time(m.file_header.ctime),
                    atime_ns: encode_system_time(m.file_header.atime),
                    data_crc32: m.file_header.data_crc32,
                    compression_method: m.file_header.compression.method.code(),
                    compression_version: m.file_header.compression.version,
                    compression_solid: m.file_header.compression.solid,
                    dict_size: m.file_header.compression.dict_size,
                    split_before: m.file_header.split_before,
                    split_after: m.file_header.split_after,
                    is_directory: m.file_header.is_directory,
                    is_encrypted: m.is_encrypted,
                    encryption: m.file_encryption.as_ref().map(cached_encryption),
                    rar4_salt: m.rar4_salt,
                    version: m.file_header.version,
                    blake2_hash: m.hash.as_ref().map(|h| match h {
                        FileHash::Blake2sp(b) => *b,
                    }),
                    redirection_type: m
                        .redirection
                        .as_ref()
                        .map(|redir| encode_redirection_type(&redir.redir_type)),
                    redirection_target: m.redirection.as_ref().map(|redir| redir.target.clone()),
                    redirection_target_raw: m
                        .redirection
                        .as_ref()
                        .and_then(|redir| redir.target_raw.clone()),
                    redirection_target_is_directory: m
                        .redirection
                        .as_ref()
                        .is_some_and(|redir| redir.target_is_directory),
                    attributes: m.file_header.attributes.0,
                    host_os: encode_host_os(m.file_header.host_os),
                    owner_user_name: m.owner.as_ref().and_then(|owner| owner.user_name.clone()),
                    owner_group_name: m.owner.as_ref().and_then(|owner| owner.group_name.clone()),
                    owner_user_name_raw: m
                        .owner
                        .as_ref()
                        .and_then(|owner| owner.user_name_raw.clone()),
                    owner_group_name_raw: m
                        .owner
                        .as_ref()
                        .and_then(|owner| owner.group_name_raw.clone()),
                    owner_uid: m.owner.as_ref().and_then(|owner| owner.uid),
                    owner_gid: m.owner.as_ref().and_then(|owner| owner.gid),
                    segments: cached_segments(&m.segments),
                })
                .collect(),
            services: self
                .services
                .iter()
                .map(|service| CachedService {
                    header_offset: service.header_offset,
                    name: service.file_header.name.clone(),
                    name_raw: service.file_header.name_raw.clone(),
                    unpacked_size: service.file_header.unpacked_size,
                    mtime_ns: encode_system_time(service.file_header.mtime),
                    ctime_ns: encode_system_time(service.file_header.ctime),
                    atime_ns: encode_system_time(service.file_header.atime),
                    data_crc32: service.file_header.data_crc32,
                    compression_method: service.file_header.compression.method.code(),
                    compression_version: service.file_header.compression.version,
                    compression_solid: service.file_header.compression.solid,
                    dict_size: service.file_header.compression.dict_size,
                    split_before: service.file_header.split_before,
                    split_after: service.file_header.split_after,
                    is_child: service.is_child,
                    is_inherited: service.is_inherited,
                    is_encrypted: service.is_encrypted,
                    encryption: service.file_encryption.as_ref().map(cached_encryption),
                    rar4_salt: service.rar4_salt,
                    version: service.file_header.version,
                    blake2_hash: service.hash.as_ref().map(|h| match h {
                        FileHash::Blake2sp(b) => *b,
                    }),
                    comment_crc16: service.comment_crc16,
                    attributes: service.file_header.attributes.0,
                    host_os: encode_host_os(service.file_header.host_os),
                    service_subdata: service.file_header.service_subdata.clone(),
                    ntfs_stream_name: service.ntfs_stream_name.clone(),
                    segments: cached_segments(&service.segments),
                })
                .collect(),
        }
    }

    /// Reconstruct a `RarArchive` from cached headers (no volume readers).
    ///
    /// The reconstructed archive has no volume readers attached. It can be used
    /// with `extract_member_streaming_chunked` which obtains volumes via a
    /// `VolumeProvider` instead of pre-loaded readers.
    pub fn from_cached_headers(cached: CachedArchiveHeaders) -> Self {
        Self::from_cached_headers_with_password_and_shared_kdf_cache(
            cached,
            None::<String>,
            Arc::new(crate::crypto::KdfCache::new()),
        )
    }

    /// Reconstruct a `RarArchive` from cached headers and optionally restore
    /// the password required for parsing additional encrypted volumes.
    pub fn from_cached_headers_with_password(
        cached: CachedArchiveHeaders,
        password: impl Into<Option<String>>,
    ) -> Self {
        Self::from_cached_headers_with_password_and_shared_kdf_cache(
            cached,
            password,
            Arc::new(crate::crypto::KdfCache::new()),
        )
    }

    pub fn from_cached_headers_with_password_and_shared_kdf_cache(
        cached: CachedArchiveHeaders,
        password: impl Into<Option<String>>,
        kdf_cache: Arc<crate::crypto::KdfCache>,
    ) -> Self {
        let format = match cached.format {
            14 => ArchiveFormat::Rar14,
            4 => ArchiveFormat::Rar4,
            _ => ArchiveFormat::Rar5,
        };

        let members: Vec<MemberEntry> = cached
            .members
            .into_iter()
            .map(|cm| {
                let compression = CompressionInfo {
                    format,
                    version: cm.compression_version,
                    solid: cm.compression_solid,
                    method: CompressionMethod::from_code(cm.compression_method),
                    dict_size: cm.dict_size,
                };

                MemberEntry {
                    file_header: FileHeader {
                        name: cm.name,
                        name_raw: cm.name_raw,
                        unpacked_size: cm.unpacked_size,
                        attributes: FileAttributes(cm.attributes),
                        mtime: decode_system_time(cm.mtime_ns),
                        ctime: decode_system_time(cm.ctime_ns),
                        atime: decode_system_time(cm.atime_ns),
                        data_crc32: cm.data_crc32,
                        data_hash: cm.data_crc32.map(crate::types::DataHash::Crc32),
                        compression,
                        host_os: decode_host_os(cm.host_os),
                        is_directory: cm.is_directory,
                        file_flags: 0,
                        data_size: 0,
                        split_before: cm.split_before,
                        split_after: cm.split_after,
                        data_offset: 0,
                        is_encrypted: cm.is_encrypted,
                        version: cm.version,
                        service_subdata: None,
                    },
                    is_encrypted: cm.is_encrypted,
                    file_encryption: cm.encryption.map(file_encryption),
                    rar4_salt: cm.rar4_salt,
                    hash: cm.blake2_hash.map(FileHash::Blake2sp),
                    redirection: cm.redirection_type.map(|redir_type| Redirection {
                        redir_type: RedirectionType::from(redir_type),
                        target: cm.redirection_target.unwrap_or_default(),
                        target_raw: cm.redirection_target_raw,
                        target_is_directory: cm.redirection_target_is_directory,
                    }),
                    owner: (cm.owner_user_name.is_some()
                        || cm.owner_group_name.is_some()
                        || cm.owner_user_name_raw.is_some()
                        || cm.owner_group_name_raw.is_some()
                        || cm.owner_uid.is_some()
                        || cm.owner_gid.is_some())
                    .then_some(UnixOwnerInfo {
                        user_name: cm.owner_user_name,
                        group_name: cm.owner_group_name,
                        user_name_raw: cm.owner_user_name_raw,
                        group_name_raw: cm.owner_group_name_raw,
                        uid: cm.owner_uid,
                        gid: cm.owner_gid,
                    }),
                    segments: data_segments(cm.segments),
                }
            })
            .collect();
        let services: Vec<ServiceEntry> = cached
            .services
            .into_iter()
            .map(|service| {
                let compression = CompressionInfo {
                    format,
                    version: service.compression_version,
                    solid: service.compression_solid,
                    method: CompressionMethod::from_code(service.compression_method),
                    dict_size: service.dict_size,
                };

                ServiceEntry {
                    header_offset: service.header_offset,
                    is_child: service.is_child,
                    is_inherited: service.is_inherited,
                    file_header: FileHeader {
                        name: service.name,
                        name_raw: service.name_raw,
                        unpacked_size: service.unpacked_size,
                        attributes: FileAttributes(service.attributes),
                        mtime: decode_system_time(service.mtime_ns),
                        ctime: decode_system_time(service.ctime_ns),
                        atime: decode_system_time(service.atime_ns),
                        data_crc32: service.data_crc32,
                        data_hash: service.data_crc32.map(crate::types::DataHash::Crc32),
                        compression,
                        host_os: decode_host_os(service.host_os),
                        is_directory: false,
                        file_flags: 0,
                        data_size: 0,
                        split_before: service.split_before,
                        split_after: service.split_after,
                        data_offset: 0,
                        is_encrypted: service.is_encrypted,
                        version: service.version,
                        service_subdata: service.service_subdata,
                    },
                    is_encrypted: service.is_encrypted,
                    file_encryption: service.encryption.map(file_encryption),
                    rar4_salt: service.rar4_salt,
                    hash: service.blake2_hash.map(FileHash::Blake2sp),
                    comment_crc16: service.comment_crc16,
                    ntfs_stream_name: service.ntfs_stream_name,
                    segments: data_segments(service.segments),
                }
            })
            .collect();
        let mut archive = RarArchive {
            format,
            is_solid: cached.is_solid,
            is_encrypted: cached.is_encrypted,
            has_recovery_record: cached.has_recovery_record,
            recovery_records: cached.recovery_records,
            is_locked: cached.is_locked,
            has_authenticity_verification: cached.has_authenticity_verification,
            has_locator: cached.has_locator,
            quick_open_offset: cached.quick_open_offset,
            recovery_record_offset: cached.recovery_record_offset,
            original_name: cached.original_name,
            original_name_raw: cached.original_name_raw,
            original_creation_time: decode_system_time(cached.original_creation_time_ns),
            volume_set: VolumeSet::from_presence(cached.volume_presence, cached.last_volume_seen),
            members,
            services,
            more_volumes: cached.more_volumes,
            volumes: Vec::new(),
            solid_decoder: None,
            solid_decoder_rar4: None,
            solid_next_index: 0,
            solid_poison: None,
            verify: true,
            restore_owners: false,
            limits: Limits::default(),
            password: password.into(),
            kdf_cache,
        };
        archive.sort_members_by_physical_order();
        archive
    }

    /// Serialize headers to MessagePack bytes.
    pub fn serialize_headers(&self) -> Vec<u8> {
        let cached = self.export_headers();
        rmp_serde::to_vec_named(&cached).expect("header serialization should not fail")
    }

    /// Deserialize headers from MessagePack bytes and reconstruct archive.
    pub fn deserialize_headers(data: &[u8]) -> Result<Self, rmp_serde::decode::Error> {
        Self::deserialize_headers_with_password(data, None::<String>)
    }

    /// Deserialize headers from MessagePack bytes and restore a password for
    /// subsequent encrypted volume parsing if needed.
    pub fn deserialize_headers_with_password(
        data: &[u8],
        password: impl Into<Option<String>>,
    ) -> Result<Self, rmp_serde::decode::Error> {
        Self::deserialize_headers_with_password_and_shared_kdf_cache(
            data,
            password,
            Arc::new(crate::crypto::KdfCache::new()),
        )
    }

    pub fn deserialize_headers_with_password_and_shared_kdf_cache(
        data: &[u8],
        password: impl Into<Option<String>>,
        kdf_cache: Arc<crate::crypto::KdfCache>,
    ) -> Result<Self, rmp_serde::decode::Error> {
        let cached = decode_cached_headers(data)?;
        Ok(
            Self::from_cached_headers_with_password_and_shared_kdf_cache(
                cached, password, kdf_cache,
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use serde::Serialize;

    use super::*;
    use crate::archive::PackedDataHash;

    #[derive(Serialize)]
    struct OldCachedArchiveHeaders {
        format: u8,
        is_solid: bool,
        is_encrypted: bool,
        more_volumes: bool,
        volume_presence: Vec<bool>,
        last_volume_seen: bool,
        members: Vec<OldCachedMember>,
    }

    #[derive(Serialize)]
    struct PriorNamedCachedArchiveHeaders {
        format: u8,
        is_solid: bool,
        is_encrypted: bool,
        has_recovery_record: bool,
        recovery_records: Vec<RecoveryRecordInfo>,
        is_locked: bool,
        has_authenticity_verification: bool,
        has_locator: bool,
        quick_open_offset: Option<u64>,
        recovery_record_offset: Option<u64>,
        original_name: Option<String>,
        original_creation_time_ns: Option<u64>,
        more_volumes: bool,
        volume_presence: Vec<bool>,
        last_volume_seen: bool,
        members: Vec<CachedMember>,
    }

    /// The historical member shape, frozen.
    ///
    /// Its nested records are frozen mirrors too, deliberately: building the
    /// "old" input out of the *current* `CachedEncryption` / `CachedSegment`
    /// made this test vacuous — it re-encoded today's field count and so could
    /// never catch a widening, which is exactly the regression it exists to
    /// catch. Nothing here may be replaced by a current struct.
    #[derive(Serialize)]
    struct OldCachedMember {
        name: String,
        unpacked_size: Option<u64>,
        data_crc32: Option<u32>,
        compression_method: u8,
        compression_version: u8,
        compression_solid: bool,
        dict_size: u64,
        split_before: bool,
        split_after: bool,
        is_directory: bool,
        is_encrypted: bool,
        encryption: Option<OldCachedEncryption>,
        rar4_salt: Option<[u8; 8]>,
        blake2_hash: Option<[u8; 32]>,
        segments: Vec<OldCachedSegment>,
    }

    /// Six fields: the encryption record as it was before `psw_check_present`.
    #[derive(Serialize)]
    struct OldCachedEncryption {
        version: u64,
        kdf_count: u8,
        salt: [u8; 16],
        iv: [u8; 16],
        check_data: Option<[u8; 12]>,
        use_hash_mac: bool,
    }

    /// Three fields: the segment record as it was before the packed hashes.
    #[derive(Serialize)]
    struct OldCachedSegment {
        volume_index: usize,
        data_offset: u64,
        data_size: u64,
    }

    /// A cache in the pre-named positional shape still decodes, *including* its
    /// encryption record.
    ///
    /// The input is built from the frozen mirrors above, so the blob really
    /// carries the historical field counts. Built from the current structs
    /// instead — as this test once was — it re-encodes today's shape and proves
    /// nothing: it would have passed unchanged while `psw_check_present`
    /// silently broke every real legacy blob carrying an encryption record.
    #[test]
    fn deserialize_headers_accepts_legacy_compact_cache() {
        let blake2_hash = [0x42; 32];
        let cached = OldCachedArchiveHeaders {
            format: 5,
            is_solid: true,
            is_encrypted: true,
            more_volumes: true,
            volume_presence: vec![true, false],
            last_volume_seen: false,
            members: vec![OldCachedMember {
                name: "episode.mkv".to_string(),
                unpacked_size: Some(4096),
                data_crc32: Some(0x1234_5678),
                compression_method: CompressionMethod::Normal.code(),
                compression_version: 1,
                compression_solid: true,
                dict_size: 8 * 1024 * 1024,
                split_before: false,
                split_after: true,
                is_directory: false,
                is_encrypted: true,
                encryption: Some(OldCachedEncryption {
                    version: 0,
                    kdf_count: 15,
                    salt: [1; 16],
                    iv: [2; 16],
                    check_data: Some([3; 12]),
                    use_hash_mac: true,
                }),
                rar4_salt: None,
                blake2_hash: Some(blake2_hash),
                segments: vec![OldCachedSegment {
                    volume_index: 0,
                    data_offset: 128,
                    data_size: 256,
                }],
            }],
        };

        // Non-vacuity, stated in the encoding rather than in the type: a
        // positional record is its element count, so pin the counts the
        // historical shape had. `0x9N` is MessagePack's fixarray marker.
        let encryption_bytes = rmp_serde::to_vec(&cached.members[0].encryption)
            .expect("record should serialize positionally");
        assert_eq!(
            encryption_bytes[0], 0x96,
            "the legacy encryption record is a six-element array, not today's seven"
        );
        let segment_bytes = rmp_serde::to_vec(&cached.members[0].segments[0])
            .expect("record should serialize positionally");
        assert_eq!(
            segment_bytes[0], 0x93,
            "the legacy segment record is a three-element array, not today's six"
        );

        let bytes = rmp_serde::to_vec(&cached).expect("legacy compact cache should serialize");

        let archive = RarArchive::deserialize_headers(&bytes).expect("legacy cache should decode");

        let member = &archive.members[0];
        assert_eq!(member.file_header.compression.version, 1);
        assert_eq!(member.hash, Some(FileHash::Blake2sp(blake2_hash)));
        let encryption = member.file_encryption.as_ref().expect("record decoded");
        assert!(encryption.use_hash_mac);
        assert_eq!(encryption.check_data, Some([3; 12]));
        assert!(
            encryption.psw_check_present,
            "a stored check value implies the header claimed one, and the \
             legacy shape has no field to say otherwise"
        );
        // The fields the legacy segment shape omits arrive as their defaults,
        // not as garbage read out of neighbouring fields.
        let segment = &member.segments[0];
        assert_eq!((segment.data_offset, segment.data_size), (128, 256));
        assert_eq!(segment.packed_hashes.crc32, None);
        assert_eq!(segment.packed_hashes.blake2sp, None);
        assert!(!segment.packed_hash_uses_mac);
        assert!(member.file_header.mtime.is_none());
        assert!(member.redirection.is_none());
    }

    /// The `psw_check_present || check_data.is_some()` rule in
    /// [`file_encryption`], over the shape that actually triggers it: a named
    /// cache written before the field existed, so the field defaults to `false`
    /// while a usable check value is right there beside it.
    ///
    /// Without the rule the pair contradicts itself downstream —
    /// [`EncryptedStore::claims_password_check`] would say the header claims no
    /// check while [`EncryptedStore::password_check`] hands one out. Both cache
    /// tests above set the flag explicitly, so neither reaches this path.
    #[test]
    fn named_cache_without_the_psw_check_flag_infers_it_from_the_check_value() {
        /// The encryption record as the named encoding wrote it before
        /// `psw_check_present`. Frozen, for the same reason as the mirrors above.
        #[derive(Serialize)]
        struct NamedCachedEncryptionWithoutFlag {
            version: u64,
            kdf_count: u8,
            salt: [u8; 16],
            iv: [u8; 16],
            check_data: Option<[u8; 12]>,
            use_hash_mac: bool,
        }

        #[derive(Serialize)]
        struct MemberWithOldEncryption {
            name: String,
            unpacked_size: Option<u64>,
            data_crc32: Option<u32>,
            compression_method: u8,
            compression_solid: bool,
            dict_size: u64,
            split_before: bool,
            split_after: bool,
            is_directory: bool,
            is_encrypted: bool,
            encryption: Option<NamedCachedEncryptionWithoutFlag>,
            segments: Vec<CachedSegment>,
        }

        #[derive(Serialize)]
        struct HeadersWithOldEncryption {
            format: u8,
            is_solid: bool,
            is_encrypted: bool,
            more_volumes: bool,
            members: Vec<MemberWithOldEncryption>,
        }

        let check_data = [0x7C; 12];
        let cached = HeadersWithOldEncryption {
            format: 5,
            is_solid: false,
            is_encrypted: false,
            more_volumes: false,
            members: vec![MemberWithOldEncryption {
                name: "Silver.Horizon.S02E01.mkv".to_string(),
                unpacked_size: Some(20_001),
                data_crc32: Some(0x1234_5678),
                compression_method: CompressionMethod::Store.code(),
                compression_solid: false,
                dict_size: 0,
                split_before: false,
                split_after: false,
                is_directory: false,
                is_encrypted: true,
                encryption: Some(NamedCachedEncryptionWithoutFlag {
                    version: 0,
                    kdf_count: 15,
                    salt: [0x5A; 16],
                    iv: [0x1F; 16],
                    check_data: Some(check_data),
                    use_hash_mac: true,
                }),
                segments: vec![CachedSegment {
                    volume_index: 0,
                    data_offset: 128,
                    data_size: 20_016,
                    packed_crc32: None,
                    packed_blake2_hash: None,
                    packed_hash_uses_mac: false,
                }],
            }],
        };
        let bytes = rmp_serde::to_vec_named(&cached).expect("old named cache should serialize");
        assert!(
            !String::from_utf8_lossy(&bytes).contains("psw_check_present"),
            "non-vacuity: the encoded cache must not carry the field at all"
        );

        let archive = RarArchive::deserialize_headers(&bytes).expect("old named cache decodes");
        let encryption = archive.members[0]
            .file_encryption
            .as_ref()
            .expect("record decoded");

        assert_eq!(encryption.check_data, Some(check_data));
        assert!(encryption.psw_check_present);

        // Stated as the consumer sees it: the two accessors must never
        // disagree about whether this member has a password check.
        let store = crate::stored_layout::EncryptedStore {
            format: ArchiveFormat::Rar5,
            crypt: Some(crate::RarVolumeMemberEncryptionFacts {
                version: encryption.version,
                kdf_count_lg2: encryption.kdf_count,
                salt: encryption.salt,
                iv: encryption.iv,
                psw_check_present: encryption.psw_check_present,
                psw_check: encryption.check_data,
            }),
            rar4_salt: None,
            cipher_size: Some(20_016),
            tail_padding: Some(15),
            resolved: true,
        };
        assert_eq!(
            store.claims_password_check(),
            store.password_check().is_some(),
            "a decoded cache must not claim no check while handing one out"
        );
        assert!(store.claims_password_check());
    }

    #[test]
    fn cached_headers_preserve_recovery_record_metadata() {
        let record = RecoveryRecordInfo {
            format: ArchiveFormat::Rar5,
            kind: crate::types::RecoveryRecordKind::Rar5Service,
            offset: 1024,
            data_offset: 2048,
            data_size: 4096,
            protected_size: Some(1024),
            recovery_sectors: None,
            total_blocks: None,
            recovery_percent: Some(7),
        };
        let cached = CachedArchiveHeaders {
            format: 5,
            is_solid: false,
            is_encrypted: false,
            has_recovery_record: true,
            recovery_records: vec![record.clone()],
            is_locked: false,
            has_authenticity_verification: false,
            has_locator: false,
            quick_open_offset: None,
            recovery_record_offset: None,
            original_name: None,
            original_name_raw: None,
            original_creation_time_ns: None,
            more_volumes: false,
            volume_presence: vec![true],
            last_volume_seen: true,
            members: Vec::new(),
            services: Vec::new(),
        };
        let bytes = rmp_serde::to_vec(&cached).expect("cache should serialize");

        let archive = RarArchive::deserialize_headers(&bytes).expect("cache should decode");
        let metadata = archive.metadata();

        assert!(metadata.has_recovery_record);
        assert_eq!(metadata.recovery_records, vec![record]);
    }

    #[test]
    fn deserialize_headers_accepts_named_cache_without_services() {
        let cached = PriorNamedCachedArchiveHeaders {
            format: 5,
            is_solid: false,
            is_encrypted: false,
            has_recovery_record: false,
            recovery_records: Vec::new(),
            is_locked: false,
            has_authenticity_verification: false,
            has_locator: false,
            quick_open_offset: None,
            recovery_record_offset: None,
            original_name: None,
            original_creation_time_ns: None,
            more_volumes: false,
            volume_presence: vec![true],
            last_volume_seen: true,
            members: Vec::new(),
        };
        let bytes = rmp_serde::to_vec_named(&cached).expect("prior cache should serialize");

        let archive = RarArchive::deserialize_headers(&bytes).expect("prior cache should decode");

        assert!(archive.services.is_empty());
    }

    #[test]
    fn cached_headers_preserve_service_entries() {
        let blake2_hash = [0x5a; 32];
        let cached = CachedArchiveHeaders {
            format: 5,
            is_solid: false,
            is_encrypted: false,
            has_recovery_record: false,
            recovery_records: Vec::new(),
            is_locked: false,
            has_authenticity_verification: false,
            has_locator: false,
            quick_open_offset: None,
            recovery_record_offset: None,
            original_name: None,
            original_name_raw: None,
            original_creation_time_ns: None,
            more_volumes: false,
            volume_presence: vec![true],
            last_volume_seen: true,
            members: Vec::new(),
            services: vec![CachedService {
                header_offset: 0x1234,
                name: "CMT".to_string(),
                name_raw: Some(b"CMT".to_vec()),
                unpacked_size: Some(12),
                mtime_ns: None,
                ctime_ns: None,
                atime_ns: None,
                data_crc32: Some(0xA1B2_C3D4),
                compression_method: CompressionMethod::Store.code(),
                compression_version: 5,
                compression_solid: false,
                dict_size: 0,
                split_before: false,
                split_after: true,
                is_child: true,
                is_inherited: true,
                is_encrypted: true,
                encryption: Some(CachedEncryption {
                    version: 0,
                    kdf_count: 12,
                    salt: [0x11; 16],
                    iv: [0x22; 16],
                    check_data: Some([0x33; 12]),
                    psw_check_present: true,
                    use_hash_mac: true,
                }),
                rar4_salt: None,
                version: Some(7),
                blake2_hash: Some(blake2_hash),
                comment_crc16: Some(0x4567),
                attributes: 0x20,
                host_os: encode_host_os(HostOs::Unix),
                service_subdata: Some(vec![1, 2, 3]),
                ntfs_stream_name: Some(":stream".to_string()),
                segments: vec![CachedSegment {
                    volume_index: 3,
                    data_offset: 4096,
                    data_size: 8192,
                    packed_crc32: Some(0x0102_0304),
                    packed_blake2_hash: None,
                    packed_hash_uses_mac: true,
                }],
            }],
        };
        let bytes = rmp_serde::to_vec_named(&cached).expect("cache should serialize");

        let archive = RarArchive::deserialize_headers(&bytes).expect("cache should decode");
        let service = &archive.services[0];

        assert_eq!(service.header_offset, 0x1234);
        assert_eq!(service.file_header.name, "CMT");
        assert_eq!(service.file_header.name_raw.as_deref(), Some(&b"CMT"[..]));
        assert!(service.is_child);
        assert!(service.is_inherited);
        assert_eq!(service.file_header.unpacked_size, Some(12));
        assert_eq!(service.file_header.data_crc32, Some(0xA1B2_C3D4));
        assert_eq!(
            service.file_header.compression.method,
            CompressionMethod::Store
        );
        assert_eq!(service.file_header.version, Some(7));
        assert_eq!(
            service.file_header.service_subdata.as_deref(),
            Some(&[1, 2, 3][..])
        );
        assert_eq!(service.hash, Some(FileHash::Blake2sp(blake2_hash)));
        assert_eq!(service.comment_crc16, Some(0x4567));
        assert_eq!(service.ntfs_stream_name.as_deref(), Some(":stream"));
        assert!(service.is_encrypted);
        assert!(
            service
                .file_encryption
                .as_ref()
                .is_some_and(|enc| enc.use_hash_mac)
        );
        assert_eq!(service.segments.len(), 1);
        assert_eq!(service.segments[0].volume_index, 3);
        assert_eq!(
            service.segments[0].packed_hashes,
            PackedDataHashes {
                crc32: Some(0x0102_0304),
                blake2sp: None,
            }
        );
        assert!(service.segments[0].packed_hash_uses_mac);
    }

    #[test]
    fn cached_segments_round_trip_both_packed_hashes_and_older_single_hash_caches() {
        let blake2 = [0x3C; 32];
        let both = DataSegment::with_packed_hashes(
            0,
            64,
            256,
            PackedDataHashes {
                crc32: Some(0x0A0B_0C0D),
                blake2sp: Some(blake2),
            },
            false,
        );

        let cached = cached_segments(&[both]);
        assert_eq!(cached[0].packed_crc32, Some(0x0A0B_0C0D));
        assert_eq!(cached[0].packed_blake2_hash, Some(blake2));
        let restored = data_segments(cached);
        assert_eq!(restored[0].packed_hashes.crc32, Some(0x0A0B_0C0D));
        assert_eq!(restored[0].packed_hashes.blake2sp, Some(blake2));
        // Extraction still verifies exactly one hash, BLAKE2sp first.
        assert_eq!(
            restored[0].packed_hashes.preferred(),
            Some(PackedDataHash::Blake2sp(blake2))
        );

        // A cache written before the widening recorded only the preferred hash.
        let legacy = data_segments(vec![CachedSegment {
            volume_index: 0,
            data_offset: 64,
            data_size: 256,
            packed_crc32: None,
            packed_blake2_hash: Some(blake2),
            packed_hash_uses_mac: false,
        }]);
        assert_eq!(legacy[0].packed_hashes.crc32, None);
        assert_eq!(
            legacy[0].packed_hashes.preferred(),
            Some(PackedDataHash::Blake2sp(blake2))
        );
    }

    #[test]
    fn cached_headers_preserve_raw_unix_owner_names() {
        let cached = CachedArchiveHeaders {
            format: 5,
            is_solid: false,
            is_encrypted: false,
            has_recovery_record: false,
            recovery_records: Vec::new(),
            is_locked: false,
            has_authenticity_verification: false,
            has_locator: false,
            quick_open_offset: None,
            recovery_record_offset: None,
            original_name: None,
            original_name_raw: None,
            original_creation_time_ns: None,
            more_volumes: false,
            volume_presence: vec![true],
            last_volume_seen: true,
            members: vec![CachedMember {
                name: "file.txt".to_string(),
                name_raw: Some(b"file.txt".to_vec()),
                unpacked_size: Some(0),
                mtime_ns: None,
                ctime_ns: None,
                atime_ns: None,
                data_crc32: None,
                compression_method: CompressionMethod::Store.code(),
                compression_version: 5,
                compression_solid: false,
                dict_size: 0,
                split_before: false,
                split_after: false,
                is_directory: false,
                is_encrypted: false,
                encryption: None,
                rar4_salt: None,
                version: None,
                blake2_hash: None,
                redirection_type: Some(1),
                redirection_target: Some("a\u{fffd}b".to_string()),
                redirection_target_raw: Some(b"a\xed\xa0\x80b".to_vec()),
                redirection_target_is_directory: false,
                attributes: 0,
                host_os: encode_host_os(HostOs::Darwin),
                owner_user_name: Some("al\u{fffd}ice".to_string()),
                owner_group_name: Some("gr\u{fffd}up".to_string()),
                owner_user_name_raw: Some(b"al\xffice".to_vec()),
                owner_group_name_raw: Some(b"gr\xf0up".to_vec()),
                owner_uid: None,
                owner_gid: None,
                segments: Vec::new(),
            }],
            services: Vec::new(),
        };
        let bytes = rmp_serde::to_vec_named(&cached).expect("cache should serialize");

        let archive = RarArchive::deserialize_headers(&bytes).expect("cache should decode");
        let owner = archive.members[0].owner.as_ref().expect("owner restored");

        assert_eq!(
            archive.members[0].file_header.name_raw.as_deref(),
            Some(&b"file.txt"[..])
        );
        assert_eq!(archive.members[0].file_header.host_os, HostOs::Darwin);
        assert_eq!(owner.user_name_raw.as_deref(), Some(&b"al\xffice"[..]));
        assert_eq!(owner.group_name_raw.as_deref(), Some(&b"gr\xf0up"[..]));
        let redirection = archive.members[0]
            .redirection
            .as_ref()
            .expect("redirection restored");
        assert_eq!(redirection.target, "a\u{fffd}b");
        assert_eq!(
            redirection.target_raw.as_deref(),
            Some(&b"a\xed\xa0\x80b"[..])
        );
    }

    #[test]
    fn cached_host_os_codec_maps_only_supported_os_targets() {
        for host_os in [
            HostOs::Windows,
            HostOs::Unix,
            HostOs::Darwin,
            HostOs::Unknown(0),
            HostOs::Unknown(1),
            HostOs::Unknown(5),
            HostOs::Unknown(42),
        ] {
            assert_eq!(decode_host_os(encode_host_os(host_os)), host_os);
        }
    }

    #[test]
    fn cached_host_os_decode_accepts_legacy_windows_and_unix_codes() {
        assert_eq!(decode_host_os(0), HostOs::Windows);
        assert_eq!(decode_host_os(1), HostOs::Unix);
    }

    #[test]
    fn cached_headers_preserve_main_header_locator_and_metadata() {
        let ctime = UNIX_EPOCH + Duration::new(1_700_000_123, 456_789_000);
        let cached = CachedArchiveHeaders {
            format: 5,
            is_solid: false,
            is_encrypted: false,
            has_recovery_record: true,
            recovery_records: Vec::new(),
            is_locked: false,
            has_authenticity_verification: false,
            has_locator: true,
            quick_open_offset: Some(4096),
            recovery_record_offset: Some(8192),
            original_name: Some("release.rar".to_string()),
            original_name_raw: Some(b"release.rar".to_vec()),
            original_creation_time_ns: encode_system_time(Some(ctime)),
            more_volumes: false,
            volume_presence: vec![true],
            last_volume_seen: true,
            members: Vec::new(),
            services: Vec::new(),
        };
        let bytes = rmp_serde::to_vec_named(&cached).expect("cache should serialize");

        let archive = RarArchive::deserialize_headers(&bytes).expect("cache should decode");
        let metadata = archive.metadata();

        assert!(metadata.has_locator);
        assert_eq!(metadata.quick_open_offset, Some(4096));
        assert_eq!(metadata.recovery_record_offset, Some(8192));
        assert_eq!(metadata.original_name.as_deref(), Some("release.rar"));
        assert_eq!(
            metadata.original_name_bytes.as_deref(),
            Some(&b"release.rar"[..])
        );
        assert_eq!(metadata.original_creation_time, Some(ctime));
    }
}
