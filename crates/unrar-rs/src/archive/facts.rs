use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use super::{RarArchive, ReadSeek};
use crate::error::RarResult;
use crate::short_read::ShortRead;
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

/// One volume-facts walk's result: the facts, plus where the walk ran out of
/// bytes.
///
/// Deliberately not the same type as [`RarVolumeFacts`] and deliberately not
/// serializable. The facts describe the *volume* and are worth persisting;
/// `short_at` describes one walk over one image of it and is worth nothing
/// once the image grows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RarVolumeFactsWalk {
    /// What the headers this walk reached state. Identical to what
    /// [`RarArchive::parse_volume_facts`] returns for the same bytes.
    pub facts: RarVolumeFacts,
    /// The first offset the walk could not read, when it stopped because the
    /// image ended underneath it; `None` when it stopped for a reason more
    /// bytes will not change — an end-of-archive record or a Quick Open
    /// answer.
    ///
    /// Every way an image can end under the walk reports here: between two
    /// headers, inside a header, and — on an image whose length is known —
    /// inside a member's declared data. The last two are where
    /// [`RarArchive::parse_volume_facts`] fails instead; this walk keeps the
    /// headers it reached and says where the image has to grow to.
    ///
    /// This is what makes re-reading a still-arriving volume cheap. A caller
    /// staging a volume image as its pieces arrive otherwise has no way to
    /// tell "this parse failed and the next one will too" from "one more byte
    /// would have finished it", so it re-walks on every arrival; a store
    /// volume's end-of-archive record lives past all of its payload, so that
    /// is a full walk per piece for the whole volume. With this, the caller
    /// re-walks only once the image covers `short_at`.
    ///
    /// It is a **lower** bound: the walk reports the least it would need to
    /// make any progress at all, never a guess at where the next header ends.
    /// Waiting for it can therefore cost a parse that still comes up short,
    /// and can never skip the parse that would have succeeded.
    ///
    /// `Some(_)` alongside complete-looking facts is normal and is not an
    /// error: a volume whose headers all parsed can still be missing its end
    /// record, which is exactly the case this field exists for.
    pub short_at: Option<u64>,
}

/// What one facts walk produced, before a caller decides how to treat a walk
/// that ran out of image. See [`RarArchive::facts_walk_boxed`].
struct FactsWalkOutcome {
    walk: RarVolumeFactsWalk,
    /// The error a decode-bound parse raises for the same image, when the walk
    /// stopped somewhere such a parse does not tolerate: inside a header, or
    /// inside a member's declared data on an image whose length is known.
    strict_error: Option<crate::error::RarError>,
}

impl FactsWalkOutcome {
    fn new(short: Option<ShortRead>, facts: RarVolumeFacts) -> Self {
        let (short_at, strict_error) = match short {
            Some(short) => (Some(short.at), short.strict_error),
            None => (None, None),
        };
        Self {
            walk: RarVolumeFactsWalk { facts, short_at },
            strict_error,
        }
    }

    /// The facts as `parse_volume_facts` has always reported them: a walk
    /// that stopped where a strict parse fails is that failure.
    fn strict(self) -> RarResult<RarVolumeFacts> {
        match self.strict_error {
            Some(error) => Err(error),
            None => Ok(self.walk.facts),
        }
    }
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
    ///
    /// Every derivation this walk needs runs against a cache created for the
    /// call and dropped with it. A caller that parses the *same* encrypted
    /// volume more than once — a volume image that grows as it arrives, say —
    /// should use [`Self::parse_volume_facts_with_shared_kdf_cache`] instead,
    /// which is the same walk against a cache the caller keeps.
    pub fn parse_volume_facts(
        reader: impl std::io::Read + std::io::Seek + Send + 'static,
        password: Option<&str>,
    ) -> RarResult<RarVolumeFacts> {
        let reader: Box<dyn ReadSeek> = Box::new(reader);
        Self::parse_volume_facts_boxed(reader, password)
    }

    /// [`Self::parse_volume_facts`] against a caller-owned KDF cache.
    ///
    /// Identical facts, one difference in cost: the archive key of a
    /// header-encrypted (`-hp`) volume comes from a PBKDF2 run of up to 2^24
    /// iterations over (password, salt, KDF count), and all three are
    /// properties of the *volume*, not of the parse. Passing a cache that
    /// outlives the parse therefore makes the first walk of a volume pay that
    /// derivation and every later walk of the same volume pay a lookup.
    ///
    /// The cache is keyed by password as well as salt, so sharing one across
    /// unrelated archives is safe; it holds derived key material, so its
    /// lifetime should be the caller's unit of work, not the process.
    pub fn parse_volume_facts_with_shared_kdf_cache(
        reader: impl std::io::Read + std::io::Seek + Send + 'static,
        password: Option<&str>,
        kdf_cache: std::sync::Arc<crate::crypto::KdfCache>,
    ) -> RarResult<RarVolumeFacts> {
        let reader: Box<dyn ReadSeek> = Box::new(reader);
        Self::facts_walk_boxed(reader, password, kdf_cache)?.strict()
    }

    /// [`Self::parse_volume_facts`], additionally reporting where the header
    /// walk ran out of bytes.
    ///
    /// Same headers, one difference in what a stopped walk is: where
    /// [`Self::parse_volume_facts`] fails on an image that ends inside a
    /// header, this returns the headers it reached and says where the image
    /// has to grow to. See [`RarVolumeFactsWalk::short_at`].
    pub fn parse_volume_facts_walk(
        reader: impl std::io::Read + std::io::Seek + Send + 'static,
        password: Option<&str>,
    ) -> RarResult<RarVolumeFactsWalk> {
        let reader: Box<dyn ReadSeek> = Box::new(reader);
        Self::parse_volume_facts_walk_boxed(
            reader,
            password,
            std::sync::Arc::new(crate::crypto::KdfCache::new()),
        )
    }

    /// [`Self::parse_volume_facts_walk`] against a caller-owned KDF cache.
    ///
    /// The entry point for reading a volume image that is still arriving: the
    /// shared cache removes the repeated derivation, and
    /// [`RarVolumeFactsWalk::short_at`] removes most of the repeated walks.
    pub fn parse_volume_facts_walk_with_shared_kdf_cache(
        reader: impl std::io::Read + std::io::Seek + Send + 'static,
        password: Option<&str>,
        kdf_cache: std::sync::Arc<crate::crypto::KdfCache>,
    ) -> RarResult<RarVolumeFactsWalk> {
        let reader: Box<dyn ReadSeek> = Box::new(reader);
        Self::parse_volume_facts_walk_boxed(reader, password, kdf_cache)
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

        reader.seek(SeekFrom::Start(0))?;
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
            // The facts walk: nothing here is decoded from, so a reader with no
            // known length — a volume still arriving — is accepted.
            return match crate::rar4::parse_rar4_headers_for_facts(&mut reader, None) {
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
        reader: Box<dyn ReadSeek>,
        password: Option<&str>,
    ) -> RarResult<RarVolumeFacts> {
        Self::facts_walk_boxed(
            reader,
            password,
            std::sync::Arc::new(crate::crypto::KdfCache::new()),
        )?
        .strict()
    }

    pub(crate) fn parse_volume_facts_walk_boxed(
        reader: Box<dyn ReadSeek>,
        password: Option<&str>,
        kdf_cache: std::sync::Arc<crate::crypto::KdfCache>,
    ) -> RarResult<RarVolumeFactsWalk> {
        Ok(Self::facts_walk_boxed(reader, password, kdf_cache)?.walk)
    }

    /// The one walk behind every `parse_volume_facts*` entry point.
    ///
    /// The walk itself is the facts walk: it accepts a reader with no known
    /// length and stops, rather than fails, where the image ends. The two
    /// public shapes differ only in what they do with that stop:
    /// [`FactsWalkOutcome::walk`] reports it as [`RarVolumeFactsWalk::short_at`];
    /// [`FactsWalkOutcome::strict`] re-raises the error a decode-bound parse of
    /// the same bytes raises, so `parse_volume_facts` fails on a truncated
    /// volume exactly as it always has.
    ///
    /// A walk from the signature is [`Self::facts_step`] with nothing to
    /// resume, so a [`RarVolumeFactsCursor`] and the one-shot walk share every
    /// line of the walk.
    fn facts_walk_boxed(
        reader: Box<dyn ReadSeek>,
        password: Option<&str>,
        kdf_cache: std::sync::Arc<crate::crypto::KdfCache>,
    ) -> RarResult<FactsWalkOutcome> {
        Self::facts_step(reader, password, kdf_cache, None).0
    }

    /// One facts walk, from the signature when `resume` is `None` and from
    /// where an earlier walk stopped otherwise, with what the next walk can
    /// resume from: `None` when it has to begin at the signature again.
    ///
    /// A walk that fails at a header still hands back where it began, or for
    /// RAR4 the header it failed at with that header's effect undone. A walk
    /// from the signature fails there in the same way over the same bytes, so
    /// the next walk may begin there once the failing bytes change.
    fn facts_step(
        mut reader: Box<dyn ReadSeek>,
        password: Option<&str>,
        kdf_cache: std::sync::Arc<crate::crypto::KdfCache>,
        resume: Option<FactsResume>,
    ) -> (RarResult<FactsWalkOutcome>, Option<FactsResume>) {
        use std::io::{Seek, SeekFrom};

        // Set by the walks below when the staged image ended underneath them;
        // left `None` when the walk stopped on an end-of-archive record.
        let mut short: Option<ShortRead> = None;
        let resume = match resume {
            Some(resume) => resume,
            None => {
                let format = reader
                    .seek(SeekFrom::Start(0))
                    .map_err(crate::error::RarError::from)
                    .and_then(|_| signature::read_signature(&mut reader))
                    .and_then(|format| Ok((format, reader.stream_position()?)));
                match format {
                    Err(error) => return (Err(error), None),
                    // A RAR 1.4 volume is walked whole every time: its headers
                    // are few and the format is long gone from the wild.
                    Ok((ArchiveFormat::Rar14, _)) => {
                        // The `_for_facts` walks accept a reader with no known
                        // length — a sparse image of a volume still arriving —
                        // because the result is reported and never decoded
                        // from; every extraction-bound parse still refuses one.
                        let outcome =
                            crate::rar4::parse_rar14_headers_for_facts(&mut reader, &mut short)
                                .and_then(|parsed| {
                                    Self::rar4_facts(
                                        reader,
                                        password,
                                        &kdf_cache,
                                        ArchiveFormat::Rar14,
                                        &parsed,
                                        short,
                                    )
                                });
                        return (outcome, None);
                    }
                    Ok((ArchiveFormat::Rar4, at)) => {
                        FactsResume::Rar4(crate::rar4::Rar4Walk::starting_at(at))
                    }
                    Ok((ArchiveFormat::Rar5, at)) => FactsResume::Rar5(Rar5Resume::starting_at(at)),
                }
            }
        };
        match resume {
            FactsResume::Rar4(mut walk) => {
                let walked = reader
                    .seek(SeekFrom::Start(walk.at()))
                    .map_err(crate::error::RarError::from)
                    .and_then(|_| {
                        crate::rar4::walk_rar4_headers_for_facts(
                            &mut reader,
                            password,
                            &kdf_cache,
                            &mut short,
                            &mut walk,
                        )
                    })
                    .and_then(|()| walk.take_volume(true));
                let outcome = match walked {
                    Ok(parsed) => {
                        let outcome = Self::rar4_facts(
                            reader,
                            password,
                            &kdf_cache,
                            ArchiveFormat::Rar4,
                            &parsed,
                            short,
                        );
                        walk.give_back(parsed);
                        outcome
                    }
                    Err(error) => {
                        walk.rewind();
                        Err(error)
                    }
                };
                (outcome, Some(FactsResume::Rar4(walk)))
            }
            FactsResume::Rar5(mut state) => {
                let mut stop = state.at;
                let parsed = match crate::header::resume_headers_for_facts(
                    &mut reader,
                    password,
                    &kdf_cache,
                    crate::header::HeaderParseOptions::default(),
                    &mut short,
                    state.at,
                    state.main.clone(),
                    state.encryption.clone(),
                    &mut stop,
                ) {
                    Ok(parsed) => parsed,
                    Err(error) => return (Err(error), Some(FactsResume::Rar5(state))),
                };
                if parsed.headers_from_quick_open {
                    // An answer from the Quick Open cache holds every header
                    // at once; the next walk asks the cache again from the
                    // signature, as a walk without a cursor does.
                    let outcome = FactsWalkOutcome::new(
                        short,
                        rar5_volume_facts(
                            parsed.main.as_ref(),
                            parsed.end.as_ref(),
                            parsed.is_encrypted,
                            true,
                            rar5_member_facts(0, parsed.files),
                            rar5_service_facts(0, parsed.services),
                        ),
                    );
                    return (Ok(outcome), None);
                }
                let services = rar5_service_facts(state.services.len(), parsed.services);
                state.services.extend(services);
                let members = rar5_member_facts(state.members.len(), parsed.files);
                state.members.extend(members);
                let facts = rar5_volume_facts(
                    parsed.main.as_ref(),
                    parsed.end.as_ref(),
                    parsed.is_encrypted,
                    false,
                    state.members.clone(),
                    state.services.clone(),
                );
                state.main = parsed.main;
                state.encryption = parsed.encryption;
                state.at = stop;
                (
                    Ok(FactsWalkOutcome::new(short, facts)),
                    Some(FactsResume::Rar5(state)),
                )
            }
        }
    }

    /// The facts a RAR4-family walk's headers state.
    fn rar4_facts(
        reader: Box<dyn ReadSeek>,
        password: Option<&str>,
        kdf_cache: &std::sync::Arc<crate::crypto::KdfCache>,
        format: ArchiveFormat,
        parsed: &crate::rar4::Rar4ParsedVolume,
        short: Option<ShortRead>,
    ) -> RarResult<FactsWalkOutcome> {
        let volume_number = parsed
            .end
            .as_ref()
            .and_then(|end| end.volume_number)
            .map(u32::from);
        let more_volumes = parsed.end.as_ref().is_some_and(|end| end.more_volumes)
            || (format == ArchiveFormat::Rar14 && parsed.files.iter().any(|f| f.split_after));
        let has_rar4_uowner_payload = parsed.services.iter().any(|service| service.name == "UOW")
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
                std::sync::Arc::clone(kdf_cache),
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
                let packed_hashes = RarArchive::packed_hashes_for_split_segment(&file_header, None);
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
        Ok(FactsWalkOutcome::new(
            short,
            RarVolumeFacts {
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
            },
        ))
    }
}

/// A volume-facts walk that can be continued over a grown image of the same
/// volume, from the header the previous walk stopped at.
///
/// A caller staging a volume as its pieces arrive reads its facts again after
/// each piece. [`RarArchive::parse_volume_facts_walk_with_shared_kdf_cache`]
/// reads every header from the signature each time, so a volume with many
/// headers costs a walk of all of them per piece. [`Self::step`] reads from
/// the header the last step stopped at and keeps what the headers before it
/// said.
///
/// **A step returns exactly what the one-shot walk returns** over the same
/// bytes — the same facts in the same order, the same
/// [`RarVolumeFactsWalk::short_at`], the same error — provided no byte before
/// [`Self::resumes_at`] changed since the last step. That proviso is the
/// caller's to keep, because only the caller knows which of its bytes
/// changed: when one before that offset did (a repaired piece, a damaged one
/// it now lets the walk read), call [`Self::restart`] first. Bytes at or past
/// it may change or arrive freely: a hole at the cursor filled, a damaged
/// header at it repaired in place, more of the volume staged. So may a byte
/// arriving before it where the image held none: the walk read nothing
/// before the cursor but whole headers, and seeked over the data between
/// them, so a byte it never had is one it never read. Only a byte the image
/// held, changed, calls for the restart. A step with a different password
/// than the last begins at the signature on its own.
///
/// A change before [`Self::resumes_at`] without [`Self::restart`] is a bug
/// in the caller, and the cursor does not detect it: the step keeps what the
/// headers before the cursor said when they were read and adds what the bytes
/// from the cursor on say now, so it can report a header the image no longer
/// holds, miss one it now does, or fail where a walk from the signature
/// would not.
///
/// A step that fails keeps the cursor where that walk began, or for RAR4 at
/// the header it failed at: a walk from the signature fails there the same
/// way, so the step after the failing bytes change continues from there.
///
/// RAR5 and RAR4 volumes resume, `-hp` header encryption included. A RAR 1.4
/// volume and a RAR5 volume the Quick Open cache answered leave nothing to
/// resume: the next step begins at the signature.
///
/// The cursor holds the headers read so far as facts and the password the
/// walk was keyed with, and nothing derived from it.
#[derive(Default)]
pub struct RarVolumeFactsCursor {
    state: Option<(Option<zeroize::Zeroizing<String>>, FactsResume)>,
}

/// What a walk carries to the next one over the same volume.
enum FactsResume {
    Rar4(crate::rar4::Rar4Walk),
    Rar5(Rar5Resume),
}

struct Rar5Resume {
    /// The start of the header the last walk stopped at: the one it ran short
    /// in, or the end-of-archive record. Every header before it was read
    /// whole.
    at: u64,
    main: Option<crate::header::main_archive::MainArchiveHeader>,
    encryption: Option<crate::header::encryption::EncryptionHeader>,
    members: Vec<RarVolumeMemberFacts>,
    services: Vec<RarVolumeServiceFacts>,
}

impl Rar5Resume {
    fn starting_at(at: u64) -> Self {
        Self {
            at,
            main: None,
            encryption: None,
            members: Vec::new(),
            services: Vec::new(),
        }
    }
}

impl FactsResume {
    fn at(&self) -> u64 {
        match self {
            Self::Rar4(walk) => walk.at(),
            Self::Rar5(state) => state.at,
        }
    }
}

impl RarVolumeFactsCursor {
    /// A cursor whose first step walks from the signature.
    pub fn new() -> Self {
        Self::default()
    }

    /// Walk the volume's headers from where the last step stopped, or from
    /// the signature on the first step, after [`Self::restart`], or under a
    /// different password than the last step's.
    ///
    /// The result is the one
    /// [`RarArchive::parse_volume_facts_walk_with_shared_kdf_cache`] gives
    /// for the same reader, password and cache; see the type's documentation
    /// for the one condition on the caller.
    pub fn step(
        &mut self,
        reader: impl std::io::Read + std::io::Seek + Send + 'static,
        password: Option<&str>,
        kdf_cache: std::sync::Arc<crate::crypto::KdfCache>,
    ) -> RarResult<RarVolumeFactsWalk> {
        let resume = self
            .state
            .take()
            .filter(|(keyed, _)| keyed.as_deref().map(String::as_str) == password)
            .map(|(_, resume)| resume);
        let (outcome, resume) =
            RarArchive::facts_step(Box::new(reader), password, kdf_cache, resume);
        self.state = resume.map(|resume| {
            (
                password.map(|password| zeroize::Zeroizing::new(password.to_owned())),
                resume,
            )
        });
        Ok(outcome?.walk)
    }

    /// The offset the next step begins at, or `None` when it begins at the
    /// signature. A change to any byte before it calls for [`Self::restart`].
    pub fn resumes_at(&self) -> Option<u64> {
        self.state.as_ref().map(|(_, resume)| resume.at())
    }

    /// Walk from the signature on the next step.
    pub fn restart(&mut self) {
        self.state = None;
    }
}

impl std::fmt::Debug for RarVolumeFactsCursor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RarVolumeFactsCursor")
            .field("resumes_at", &self.resumes_at())
            .finish_non_exhaustive()
    }
}

fn rar5_service_facts(
    first: usize,
    services: Vec<crate::header::ParsedService>,
) -> Vec<RarVolumeServiceFacts> {
    services
        .into_iter()
        .enumerate()
        .map(|(order, service)| RarVolumeServiceFacts::from_rar5_service(first + order, service))
        .collect()
}

fn rar5_member_facts(
    first: usize,
    files: Vec<crate::header::ParsedFile>,
) -> Vec<RarVolumeMemberFacts> {
    files
        .into_iter()
        .enumerate()
        .map(|(order, parsed_file)| {
            let order = first + order;
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
        .collect()
}

fn rar5_volume_facts(
    main: Option<&crate::header::main_archive::MainArchiveHeader>,
    end: Option<&crate::header::end_archive::EndArchiveHeader>,
    is_encrypted: bool,
    headers_from_quick_open: bool,
    members: Vec<RarVolumeMemberFacts>,
    services: Vec<RarVolumeServiceFacts>,
) -> RarVolumeFacts {
    RarVolumeFacts {
        format: 5,
        volume_number: main
            .and_then(|main| main.volume_number)
            .map(|value| value as u32),
        more_volumes: end.is_some_and(|end| end.more_volumes),
        is_solid: main.is_some_and(|main| main.is_solid),
        is_encrypted,
        is_volume: main.is_some_and(|main| main.is_volume),
        has_recovery_record: main.is_some_and(|main| main.has_recovery_record),
        is_locked: main.is_some_and(|main| main.is_locked),
        has_authenticity_verification: false,
        has_locator: main.is_some_and(|main| main.has_locator),
        quick_open_offset: main.and_then(|main| main.quick_open_offset),
        // Provenance, not the mere presence of a locator: a volume can carry
        // `quick_open_offset` and still be answered by the physical walk when
        // its `QO` block was rejected.
        headers_from_quick_open,
        recovery_record_offset: main.and_then(|main| main.recovery_record_offset),
        original_name: main.and_then(|main| main.original_name.clone()),
        original_name_raw: main.and_then(|main| main.original_name_raw.clone()),
        original_creation_time_ns: encode_system_time(
            main.and_then(|main| main.original_creation_time),
        ),
        members,
        services,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::Arc;

    /// Read one checked-in corpus fixture, or `None` when the corpus has not
    /// been hydrated into this checkout. The fixture bytes are not part of the
    /// published crate, so a test that needs them says so and steps aside
    /// rather than failing where they cannot exist.
    fn corpus_fixture(parts: &[&str]) -> Option<Vec<u8>> {
        let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        for part in parts {
            path.push(part);
        }
        match std::fs::read(&path) {
            Ok(bytes) => Some(bytes),
            Err(_) => {
                eprintln!("skipping: corpus fixture {} is not present", path.display());
                None
            }
        }
    }

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

    #[test]
    fn repeated_rar5_hp_facts_parses_through_one_cache_derive_once() {
        let Some(data) = corpus_fixture(&["tests", "fixtures", "rar5", "rar5_hp_store.rar"]) else {
            return;
        };
        let cache = Arc::new(crate::crypto::KdfCache::new());
        assert_eq!(cache.rar5_derivation_count(), 0);

        let first = RarArchive::parse_volume_facts_with_shared_kdf_cache(
            Cursor::new(data.clone()),
            Some("secretpass"),
            Arc::clone(&cache),
        )
        .unwrap();
        let after_first = cache.rar5_derivation_count();
        assert_eq!(
            after_first, 1,
            "a `-hp` volume's archive key is one derivation"
        );

        let second = RarArchive::parse_volume_facts_with_shared_kdf_cache(
            Cursor::new(data),
            Some("secretpass"),
            Arc::clone(&cache),
        )
        .unwrap();
        assert_eq!(
            cache.rar5_derivation_count(),
            after_first,
            "the second walk of the same volume must derive nothing"
        );
        assert_eq!(first, second);
    }

    #[test]
    fn a_fresh_cache_per_parse_pays_the_rar5_hp_derivation_every_time() {
        // The other half of the claim above: without a shared cache the cost
        // is per parse, which is what makes the shared entry point worth
        // having.
        let Some(data) = corpus_fixture(&["tests", "fixtures", "rar5", "rar5_hp_store.rar"]) else {
            return;
        };
        for _ in 0..2 {
            let cache = Arc::new(crate::crypto::KdfCache::new());
            RarArchive::parse_volume_facts_with_shared_kdf_cache(
                Cursor::new(data.clone()),
                Some("secretpass"),
                Arc::clone(&cache),
            )
            .unwrap();
            assert_eq!(cache.rar5_derivation_count(), 1);
        }
    }

    #[test]
    fn shared_cache_rar5_hp_facts_match_the_owned_cache_walk() {
        let Some(data) = corpus_fixture(&["tests", "fixtures", "rar5", "rar5_hp_store.rar"]) else {
            return;
        };
        let owned = RarArchive::parse_volume_facts(Cursor::new(data.clone()), Some("secretpass"))
            .expect("owned-cache walk");
        assert!(owned.is_encrypted, "non-vacuity: the fixture is `-hp`");
        assert!(!owned.members.is_empty(), "non-vacuity: it holds members");

        let shared = RarArchive::parse_volume_facts_with_shared_kdf_cache(
            Cursor::new(data.clone()),
            Some("secretpass"),
            Arc::new(crate::crypto::KdfCache::new()),
        )
        .expect("shared-cache walk");
        assert_eq!(owned, shared);

        let walk = RarArchive::parse_volume_facts_walk(Cursor::new(data), Some("secretpass"))
            .expect("reporting walk");
        assert_eq!(owned, walk.facts);
    }

    #[test]
    fn repeated_rar4_hp_facts_parses_through_one_cache_derive_once_per_salt() {
        let Some(data) = corpus_fixture(&["tests", "fixtures", "rar4", "rar4_hp_large.rar"]) else {
            return;
        };
        let cache = Arc::new(crate::crypto::KdfCache::new());
        let first = RarArchive::parse_volume_facts_with_shared_kdf_cache(
            Cursor::new(data.clone()),
            Some("e2e-test-password"),
            Arc::clone(&cache),
        )
        .unwrap();
        // RAR4 salts each header separately, so one walk derives more than
        // once; what matters is that the next walk derives nothing.
        let after_first = cache.rar4_derivation_count();
        assert!(after_first > 0, "non-vacuity: the fixture is `-hp`");

        let second = RarArchive::parse_volume_facts_with_shared_kdf_cache(
            Cursor::new(data.clone()),
            Some("e2e-test-password"),
            Arc::clone(&cache),
        )
        .unwrap();
        assert_eq!(cache.rar4_derivation_count(), after_first);
        assert_eq!(first, second);

        let owned =
            RarArchive::parse_volume_facts(Cursor::new(data), Some("e2e-test-password")).unwrap();
        assert_eq!(owned, first);
    }

    #[test]
    fn a_complete_volume_walk_reports_no_short_read() {
        let payload = vec![0xA5u8; 512];
        let bytes = rar5_split_after_archive_bytes(
            "Silver.Horizon.S02E12.mkv",
            &payload,
            4096,
            0x1234_5678,
            [0x11; 32],
        );
        let walk = RarArchive::parse_volume_facts_walk(Cursor::new(bytes), None).unwrap();
        assert_eq!(
            walk.short_at, None,
            "a walk that reached the end-of-archive record needs nothing more"
        );
        assert_eq!(walk.facts.members.len(), 1);
    }

    #[test]
    fn a_short_volume_image_reports_the_offset_its_walk_ran_out_at() {
        let payload = vec![0xA5u8; 512];
        let bytes = rar5_split_after_archive_bytes(
            "Silver.Horizon.S02E12.mkv",
            &payload,
            4096,
            0x1234_5678,
            [0x11; 32],
        );
        // Where the payload ends is where the next header begins, so that is
        // the offset a short image has to reach before another walk can learn
        // anything.
        let end_block = build_rar5_block(5, 0, &[], &crate::vint::encode_vint(1));
        let payload_end = bytes.len() - end_block.len();

        for staged in [payload_end - 400, payload_end - 1, payload_end] {
            let walk =
                RarArchive::parse_volume_facts_walk(Cursor::new(bytes[..staged].to_vec()), None)
                    .unwrap_or_else(|err| panic!("walk over {staged} staged bytes: {err}"));
            assert_eq!(
                walk.short_at,
                Some(payload_end as u64 + 6),
                "short image of {staged} bytes"
            );
            assert!(
                walk.short_at.unwrap() > staged as u64,
                "the reported offset must be past what is staged, or a caller \
                 waiting for it would spin"
            );
            // The headers it did reach are still the volume's own.
            assert_eq!(walk.facts.members.len(), 1);
            assert_eq!(walk.facts.members[0].name, "Silver.Horizon.S02E12.mkv");
            assert!(
                !walk.facts.more_volumes,
                "the end record that states this was never reached"
            );
        }
    }

    #[test]
    fn an_image_cut_inside_a_header_is_short_to_the_walk_and_truncated_to_the_parse() {
        let payload = vec![0xA5u8; 512];
        let bytes = rar5_split_after_archive_bytes(
            "Silver.Horizon.S02E12.mkv",
            &payload,
            4096,
            0x1234_5678,
            [0x11; 32],
        );
        let end_block = build_rar5_block(5, 0, &[], &crate::vint::encode_vint(1));
        let header_start = bytes.len() - end_block.len();
        // Five bytes into the end record: its CRC32 and header-size vint are
        // staged, its body is not. This is the cut a piece boundary makes when
        // it lands inside a header rather than between two.
        let staged = header_start + 5;

        let walk = RarArchive::parse_volume_facts_walk(Cursor::new(bytes[..staged].to_vec()), None)
            .expect("the walk stops where the image ends rather than failing");
        let short_at = walk.short_at.expect("and says where");
        assert!(
            short_at > staged as u64,
            "reported offset {short_at} must be past the {staged} staged bytes"
        );
        assert!(
            short_at <= bytes.len() as u64,
            "a lower bound never points past the complete volume"
        );
        assert_eq!(
            walk.facts.members.len(),
            1,
            "the headers before the cut are kept"
        );
        assert!(!walk.facts.more_volumes, "the cut record was not read");

        let err = RarArchive::parse_volume_facts(Cursor::new(bytes[..staged].to_vec()), None)
            .expect_err("the plain parse still fails on a header the image cuts");
        assert!(
            matches!(err, crate::error::RarError::TruncatedHeader { offset } if offset == header_start as u64),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn a_rar4_image_ending_inside_a_members_data_is_short_to_the_walk_and_corrupt_to_the_parse() {
        let Some(data) = corpus_fixture(&[
            "tests",
            "fixtures",
            "rar4",
            "generated_matrix_rar4_store_plain.part7.rar",
        ]) else {
            return;
        };
        let whole = RarArchive::parse_volume_facts_walk(Cursor::new(data.clone()), None).unwrap();
        assert_eq!(whole.short_at, None, "the fixture is complete");
        let member = whole
            .facts
            .members
            .iter()
            .find(|member| !member.split_after)
            .expect("the last volume of a set closes a member");
        let data_end = member.data_offset + member.data_size;
        let staged = (member.data_offset + member.data_size / 2) as usize;

        // A `Cursor` states its length, so the decode-bound check sees a member
        // whose declared data runs past the end of the image. To the facts
        // walk that is the image ending inside the member: short, at its data
        // end plus the next header's fixed block.
        let walk = RarArchive::parse_volume_facts_walk(Cursor::new(data[..staged].to_vec()), None)
            .expect("the walk stops where the image ends rather than failing");
        assert_eq!(walk.short_at, Some(data_end + 7));
        assert!(
            walk.facts.members.iter().any(|m| m.name == member.name),
            "the member whose data the image cuts is still reported"
        );

        let err = RarArchive::parse_volume_facts(Cursor::new(data[..staged].to_vec()), None)
            .expect_err("the plain parse still rejects data the volume cannot hold");
        assert!(
            matches!(err, crate::error::RarError::CorruptArchive { .. }),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn a_short_rar5_hp_volume_image_reports_an_offset_past_what_is_staged() {
        let Some(data) = corpus_fixture(&["tests", "fixtures", "rar5", "rar5_hp_store.rar"]) else {
            return;
        };
        let whole =
            RarArchive::parse_volume_facts_walk(Cursor::new(data.clone()), Some("secretpass"))
                .unwrap();
        assert_eq!(whole.short_at, None, "the fixture is complete");

        // Cut inside the member's payload, the state a volume image is in for
        // every article but its last: the headers before the payload are all
        // staged, the end-of-archive record after it is not.
        let member = whole.facts.members.first().expect("fixture holds a member");
        let payload_end = member.data_offset + member.data_size;
        assert!(
            member.data_size >= 2 && (payload_end as usize) < data.len(),
            "fixture shape: a store member followed by an end record"
        );

        for staged in [
            member.data_offset as usize + member.data_size as usize / 2,
            payload_end as usize,
        ] {
            let walk = RarArchive::parse_volume_facts_walk(
                Cursor::new(data[..staged].to_vec()),
                Some("secretpass"),
            )
            .unwrap_or_else(|err| panic!("short `-hp` image of {staged} bytes: {err}"));
            let short_at = walk
                .short_at
                .expect("a walk that ran out of bytes must say where");
            assert_eq!(
                short_at,
                payload_end + 32,
                "the next encrypted header needs its IV and one cipher block"
            );
            assert!(
                short_at > staged as u64,
                "reported offset {short_at} must be past the {staged} staged bytes"
            );
            assert_eq!(walk.facts.members.len(), whole.facts.members.len());
        }
    }

    /// The resumable walk against the one-shot walk it is built on: every
    /// step over every image a caller can stage, compared with a fresh walk
    /// from the signature over the same bytes.
    mod resumable {
        use super::*;
        use crate::short_read::header_reads;
        use std::io::{Read, Seek, SeekFrom};
        use std::ops::Range;

        /// A volume image as a caller stages it: the volume's bytes, and
        /// which of them it holds so far.
        struct Image {
            bytes: Vec<u8>,
            have: Vec<bool>,
        }

        impl Image {
            fn empty(bytes: &[u8]) -> Self {
                Self {
                    bytes: bytes.to_vec(),
                    have: vec![false; bytes.len()],
                }
            }

            fn whole(bytes: &[u8]) -> Self {
                let mut image = Self::empty(bytes);
                image.stage(0..bytes.len());
                image
            }

            fn stage(&mut self, range: Range<usize>) {
                self.have[range].fill(true);
            }

            fn unstage(&mut self, range: Range<usize>) {
                self.have[range].fill(false);
            }

            /// Overwrite one byte the image holds: a damaged article, or its
            /// repair.
            fn put(&mut self, at: usize, byte: u8) {
                self.bytes[at] = byte;
            }

            fn reader(&self, view: View) -> Staged {
                match view {
                    View::Sparse => Staged {
                        bytes: self.bytes.clone(),
                        have: self.have.clone(),
                        pos: 0,
                        len: None,
                    },
                    View::Prefix => {
                        let held = self.have.iter().take_while(|held| **held).count();
                        Staged {
                            bytes: self.bytes[..held].to_vec(),
                            have: vec![true; held],
                            pos: 0,
                            len: Some(held as u64),
                        }
                    }
                }
            }
        }

        /// The two ways a caller hands the walk a partial volume.
        #[derive(Debug, Clone, Copy)]
        enum View {
            /// Every byte held so far at its own offset; a byte not held reads
            /// as the end of the stream, and the length is unknown.
            Sparse,
            /// The bytes held from the signature up to the first one not held,
            /// with that length known, as a `Cursor` over them states it.
            Prefix,
        }

        struct Staged {
            bytes: Vec<u8>,
            have: Vec<bool>,
            pos: u64,
            len: Option<u64>,
        }

        impl Read for Staged {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let from = usize::try_from(self.pos).unwrap_or(usize::MAX);
                let mut read = 0;
                while read < buf.len() && from + read < self.bytes.len() && self.have[from + read] {
                    buf[read] = self.bytes[from + read];
                    read += 1;
                }
                self.pos += read as u64;
                Ok(read)
            }
        }

        impl Seek for Staged {
            fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
                let pos = match to {
                    SeekFrom::Start(at) => Some(at),
                    SeekFrom::Current(delta) => self.pos.checked_add_signed(delta),
                    SeekFrom::End(delta) => match self.len {
                        Some(len) => len.checked_add_signed(delta),
                        None => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::Unsupported,
                                "a sparse image has no known end",
                            ));
                        }
                    },
                };
                self.pos = pos.ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, "seek before start")
                })?;
                Ok(self.pos)
            }
        }

        fn same(
            what: &str,
            resumed: &RarResult<RarVolumeFactsWalk>,
            fresh: &RarResult<RarVolumeFactsWalk>,
        ) {
            match (resumed, fresh) {
                (Ok(resumed), Ok(fresh)) => assert_eq!(resumed, fresh, "{what}"),
                (Err(resumed), Err(fresh)) => {
                    assert_eq!(format!("{resumed:?}"), format!("{fresh:?}"), "{what}")
                }
                _ => panic!("{what}: resumed {resumed:?}, fresh {fresh:?}"),
            }
        }

        fn fresh(
            image: &Image,
            view: View,
            password: Option<&str>,
            cache: &Arc<crate::crypto::KdfCache>,
        ) -> RarResult<RarVolumeFactsWalk> {
            RarArchive::parse_volume_facts_walk_with_shared_kdf_cache(
                image.reader(view),
                password,
                Arc::clone(cache),
            )
        }

        /// One cursor stepped over an image, each step checked against a
        /// fresh walk, with the headers each side read counted.
        struct Run {
            cursor: RarVolumeFactsCursor,
            cache: Arc<crate::crypto::KdfCache>,
            password: Option<&'static str>,
            view: View,
            steps: usize,
            resumed_headers: usize,
            fresh_headers: usize,
        }

        impl Run {
            fn new(password: Option<&'static str>, view: View) -> Self {
                Self {
                    cursor: RarVolumeFactsCursor::new(),
                    cache: Arc::new(crate::crypto::KdfCache::new()),
                    password,
                    view,
                    steps: 0,
                    resumed_headers: 0,
                    fresh_headers: 0,
                }
            }

            /// Step without comparing: the caller asserts what it expects.
            fn step_only(&mut self, image: &Image) -> RarResult<RarVolumeFactsWalk> {
                self.cursor.step(
                    image.reader(self.view),
                    self.password,
                    Arc::clone(&self.cache),
                )
            }

            fn step(&mut self, image: &Image, what: &str) -> RarResult<RarVolumeFactsWalk> {
                let from = self.cursor.resumes_at();
                header_reads::take();
                let resumed = self.step_only(image);
                let read = header_reads::take();
                if let Some(from) = from {
                    assert!(
                        read.iter().all(|at| *at >= from),
                        "{what}: a step resuming at {from} read headers at {read:?}"
                    );
                }
                self.steps += 1;
                self.resumed_headers += read.len();
                let fresh = fresh(image, self.view, self.password, &self.cache);
                self.fresh_headers += header_reads::take().len();
                same(what, &resumed, &fresh);
                resumed
            }
        }

        fn gcd(a: usize, b: usize) -> usize {
            if b == 0 { a } else { gcd(b, a % b) }
        }

        /// The volume cut into `piece`-byte pieces, in the orders a caller
        /// can come to hold them in.
        fn schedules(len: usize, piece: usize) -> Vec<(&'static str, Vec<Range<usize>>)> {
            let pieces: Vec<Range<usize>> = (0..len)
                .step_by(piece)
                .map(|start| start..(start + piece).min(len))
                .collect();
            let n = pieces.len();
            let stride = (n / 3 + 1..n).find(|k| gcd(*k, n) == 1).unwrap_or(1);
            vec![
                ("in order", pieces.clone()),
                ("reversed", pieces.iter().rev().cloned().collect()),
                (
                    "even then odd",
                    pieces
                        .iter()
                        .step_by(2)
                        .chain(pieces.iter().skip(1).step_by(2))
                        .cloned()
                        .collect(),
                ),
                (
                    "strided",
                    (0..n).map(|i| pieces[(i * stride) % n].clone()).collect(),
                ),
            ]
        }

        /// Feed `bytes` piece by piece under every schedule and both views,
        /// stepping after each piece with no restart, and check every step
        /// against a fresh walk and the last against the whole volume's walk.
        /// Returns the in-order sparse run, for its header counts.
        fn feed(name: &str, bytes: &[u8], password: Option<&'static str>, piece: usize) -> Run {
            let cache = Arc::new(crate::crypto::KdfCache::new());
            let whole = fresh(&Image::whole(bytes), View::Sparse, password, &cache)
                .unwrap_or_else(|err| panic!("{name}: the whole volume walks: {err:?}"));
            assert_eq!(whole.short_at, None, "{name}: the volume is complete");
            let mut kept = None;
            for view in [View::Sparse, View::Prefix] {
                for (order, pieces) in schedules(bytes.len(), piece) {
                    let mut image = Image::empty(bytes);
                    let mut run = Run::new(password, view);
                    let mut last = None;
                    for (index, range) in pieces.into_iter().enumerate() {
                        image.stage(range.clone());
                        last = Some(run.step(
                            &image,
                            &format!("{name}, {view:?}, {order}, piece {index} at {range:?}"),
                        ));
                    }
                    let last = last.expect("a volume has a piece").unwrap();
                    assert_eq!(last, whole, "{name}, {view:?}, {order}: the whole volume");
                    if kept.is_none() {
                        kept = Some(run);
                    }
                }
            }
            kept.expect("the in-order sparse run")
        }

        /// The header starts a fresh walk over the whole volume reads, in
        /// order.
        fn header_starts(bytes: &[u8], password: Option<&str>) -> Vec<usize> {
            header_reads::take();
            fresh(
                &Image::whole(bytes),
                View::Sparse,
                password,
                &Arc::new(crate::crypto::KdfCache::new()),
            )
            .expect("the whole volume walks");
            header_reads::take()
                .into_iter()
                .map(|at| at as usize)
                .collect()
        }

        /// A synthetic volume and where each of its member headers starts.
        struct Synthetic {
            bytes: Vec<u8>,
            members: Vec<usize>,
            headers: usize,
        }

        impl Synthetic {
            /// The offset of the `index`th member's name, which only that
            /// header holds.
            fn name_at(&self, index: usize) -> usize {
                let name = member_name(index);
                let from = self.members[index];
                from + self.bytes[from..]
                    .windows(name.len())
                    .position(|window| window == name.as_bytes())
                    .expect("the header holds its name")
            }
        }

        fn member_name(index: usize) -> String {
            format!("Lantern.Bay.S01E{index:02}.mkv")
        }

        fn rar5_store_block(header_type: u64, name: &str, data_len: u64) -> Vec<u8> {
            let mut body = Vec::new();
            body.extend_from_slice(&crate::vint::encode_vint(0)); // file flags.
            body.extend_from_slice(&crate::vint::encode_vint(data_len)); // unpacked.
            body.extend_from_slice(&crate::vint::encode_vint(0o644)); // attributes.
            body.extend_from_slice(&crate::vint::encode_vint(0)); // RAR5 Store.
            body.extend_from_slice(&crate::vint::encode_vint(1)); // Unix host OS.
            body.extend_from_slice(&crate::vint::encode_vint(name.len() as u64));
            body.extend_from_slice(name.as_bytes());
            let mut block = build_rar5_block(
                header_type,
                crate::header::common::flags::DATA_AREA,
                &[data_len],
                &body,
            );
            block.extend(std::iter::repeat_n(0x5A, data_len as usize));
            block
        }

        /// A RAR5 volume of `files` stored members with a comment service
        /// among them and an end record stating more volumes follow.
        fn synthetic_rar5(files: usize) -> Synthetic {
            let mut bytes = crate::signature::RAR5_SIGNATURE.to_vec();
            bytes.extend_from_slice(&build_rar5_block(
                1,
                0,
                &[],
                &crate::vint::encode_vint(crate::header::main_archive::flags::VOLUME),
            ));
            let mut members = Vec::new();
            let mut headers = 1;
            for index in 0..files {
                members.push(bytes.len());
                bytes.extend_from_slice(&rar5_store_block(
                    2,
                    &member_name(index),
                    (index * 13 + 5) as u64,
                ));
                headers += 1;
                if index == 2 {
                    bytes.extend_from_slice(&rar5_store_block(3, "CMT", 24));
                    headers += 1;
                }
            }
            bytes.extend_from_slice(&build_rar5_block(5, 0, &[], &crate::vint::encode_vint(1)));
            Synthetic {
                bytes,
                members,
                headers: headers + 1,
            }
        }

        fn rar4_store_body(name: &[u8], data_len: u32, trailer: &[u8]) -> Vec<u8> {
            let mut body = Vec::new();
            body.extend_from_slice(&data_len.to_le_bytes()); // packed.
            body.extend_from_slice(&data_len.to_le_bytes()); // unpacked.
            body.push(3); // Unix host OS.
            body.extend_from_slice(&0u32.to_le_bytes()); // data CRC32.
            body.extend_from_slice(&0u32.to_le_bytes()); // time.
            body.push(29); // version.
            body.push(0x30); // Store.
            body.extend_from_slice(&(name.len() as u16).to_le_bytes());
            body.extend_from_slice(&0u32.to_le_bytes()); // attributes.
            body.extend_from_slice(name);
            body.extend_from_slice(trailer);
            body
        }

        /// A RAR4 first volume of `files` stored members, an owner service
        /// after the second, a comment service after the fourth, and an end
        /// record stating more volumes follow.
        fn synthetic_rar4(files: usize) -> Synthetic {
            let mut bytes = crate::signature::RAR4_SIGNATURE.to_vec();
            bytes.extend_from_slice(&build_rar4_main_header(0x0001 | 0x0100, 0, 0));
            let mut members = Vec::new();
            let mut headers = 1;
            for index in 0..files {
                let len = (index * 13 + 5) as u32;
                members.push(bytes.len());
                bytes.extend_from_slice(&build_rar4_header(
                    0x74,
                    0x8000,
                    &rar4_store_body(member_name(index).as_bytes(), len, &[]),
                ));
                bytes.extend(std::iter::repeat_n(0x5A, len as usize));
                headers += 1;
                if index == 1 {
                    bytes.extend_from_slice(&build_rar4_header(
                        0x7A,
                        0x4000,
                        &rar4_store_body(b"UOW", 0, b"harbour\0crew"),
                    ));
                    headers += 1;
                }
                if index == 3 {
                    bytes.extend_from_slice(&build_rar4_header(
                        0x7A,
                        0x8000 | 0x4000,
                        &rar4_store_body(b"CMT", 24, &[]),
                    ));
                    bytes.extend(std::iter::repeat_n(0x43, 24));
                    headers += 1;
                }
            }
            bytes.extend_from_slice(&build_rar4_header(0x7b, 0x0001, &[]));
            Synthetic {
                bytes,
                members,
                headers: headers + 1,
            }
        }

        fn synthetics() -> [(&'static str, Synthetic); 2] {
            [("RAR5", synthetic_rar5(24)), ("RAR4", synthetic_rar4(24))]
        }

        #[test]
        fn synthetic_volumes_fed_in_any_order_step_to_what_a_fresh_walk_reads() {
            for (name, volume) in synthetics() {
                for piece in [5, 11, 37] {
                    let run = feed(&format!("{name} / {piece}"), &volume.bytes, None, piece);
                    // Each step reads the header it resumes at again and what
                    // the new bytes let it reach, never one before the cursor
                    // (checked per step in `Run::step`).
                    assert!(
                        run.resumed_headers <= volume.headers + run.steps,
                        "{name} / {piece}: {} headers over {} steps of a {}-header volume",
                        run.resumed_headers,
                        run.steps,
                        volume.headers
                    );
                    assert!(
                        run.resumed_headers * 4 < run.fresh_headers,
                        "{name} / {piece}: resumed {} vs fresh {}",
                        run.resumed_headers,
                        run.fresh_headers
                    );
                }
            }
        }

        #[test]
        fn corpus_volumes_fed_in_any_order_step_to_what_a_fresh_walk_reads() {
            let volumes: [(&str, &str, Option<&'static str>); 19] = [
                ("rar4", "rar4_multifile_store.rar", None),
                ("rar4", "rar4_multifile_lz.rar", None),
                ("rar4", "rar4_dirs.rar", None),
                ("rar4", "rar4_comment.rar", None),
                ("rar4", "rar4_enc_store.rar", Some("testpass123")),
                ("rar4", "rar4_hp_store.rar", Some("secretpass")),
                ("rar4", "rar4_hp_lz.rar", Some("secretpass")),
                ("rar4", "generated_matrix_rar4_store_plain.part1.rar", None),
                (
                    "rar4",
                    "generated_matrix_rar4_store_enc.part1.rar",
                    Some("testpass123"),
                ),
                (
                    "rar4",
                    "generated_matrix_rar4_lz_enc.part2.rar",
                    Some("testpass123"),
                ),
                ("rar5", "rar5_best.rar", None),
                ("rar5", "rar5_comment.rar", None),
                ("rar5", "rar5_dirs.rar", None),
                ("rar5", "rar5_hp_store.rar", Some("secretpass")),
                ("rar5", "rar5_enc_store_pair.rar", Some("testpass123")),
                ("rar5", "generated_matrix_rar5_store_plain.part1.rar", None),
                (
                    "rar5",
                    "generated_matrix_rar5_store_enc.part1.rar",
                    Some("testpass123"),
                ),
                ("rar5", "generated_matrix_rar5_lz_plain.part1.rar", None),
                (
                    "rar5",
                    "generated_matrix_rar5_lz_enc.part2.rar",
                    Some("testpass123"),
                ),
            ];
            for (dir, file, password) in volumes {
                let Some(bytes) = corpus_fixture(&["tests", "fixtures", dir, file]) else {
                    continue;
                };
                let pieces: &[usize] = if bytes.len() < 4096 {
                    &[7, 61]
                } else {
                    &[997, 16411]
                };
                for piece in pieces {
                    let run = feed(&format!("{file} / {piece}"), &bytes, password, *piece);
                    assert!(
                        run.resumed_headers <= run.fresh_headers,
                        "{file} / {piece}: resumed {} vs fresh {}",
                        run.resumed_headers,
                        run.fresh_headers
                    );
                }
            }
        }

        /// A step over an image missing bytes of the header at `header`
        /// stopped there, short. Where the one-shot walk fails over that
        /// image instead (a RAR4 archive header cut, or a hole reaching into
        /// the bytes the signature check reads past the RAR4 signature), the
        /// step failed the same way (`Run::step` compared them) and the
        /// cursor resumes no later than the header.
        fn stopped_at(name: &str, held: &RarResult<RarVolumeFactsWalk>, run: &Run, header: usize) {
            match held {
                Ok(walk) => {
                    assert!(walk.short_at.is_some(), "{name}: short at {header}");
                    assert_eq!(run.cursor.resumes_at(), Some(header as u64), "{name}");
                }
                Err(_) => assert!(
                    run.cursor.resumes_at() <= Some(header as u64),
                    "{name}: a failed step at {header} resumes at {:?}",
                    run.cursor.resumes_at()
                ),
            }
        }

        /// Every header of a volume with a hole over its first bytes, then
        /// one cut by the image ending inside it: the step stops at it, and
        /// once the bytes arrive the next step, with no restart, reads on
        /// from it.
        fn hole_and_split_at_each_header(name: &str, bytes: &[u8], password: Option<&'static str>) {
            let starts = header_starts(bytes, password);
            let whole = fresh(
                &Image::whole(bytes),
                View::Sparse,
                password,
                &Arc::new(crate::crypto::KdfCache::new()),
            )
            .unwrap();
            for window in starts.windows(2) {
                let (header, next) = (window[0], window[1]);
                for view in [View::Sparse, View::Prefix] {
                    // A hole at the cursor, filled later.
                    let mut image = Image::whole(bytes);
                    image.unstage(header..(header + 3).min(next));
                    let mut run = Run::new(password, view);
                    let held = run.step(&image, &format!("{name}: hole at {header}"));
                    stopped_at(name, &held, &run, header);
                    image.stage(0..bytes.len());
                    let filled = run.step(&image, &format!("{name}: hole at {header} filled"));
                    assert_eq!(filled.unwrap(), whole, "{name}: hole at {header} filled");

                    // A header split across two pieces: the image ends five
                    // bytes into it, inside its fixed block, then the rest of
                    // it arrives.
                    let cut = (header + 5).min(next - 1);
                    let mut image = Image::empty(bytes);
                    image.stage(0..cut);
                    let mut run = Run::new(password, view);
                    let held = run.step(&image, &format!("{name}: cut at {cut}"));
                    stopped_at(name, &held, &run, header);
                    image.stage(cut..bytes.len());
                    let rest = run.step(&image, &format!("{name}: cut at {cut} completed"));
                    assert_eq!(rest.unwrap(), whole, "{name}: cut at {cut} completed");
                }
            }
        }

        #[test]
        fn a_hole_or_cut_at_the_cursor_resumes_there_once_filled() {
            for (name, volume) in synthetics() {
                hole_and_split_at_each_header(name, &volume.bytes, None);
            }
            for (dir, file, password) in [
                ("rar5", "rar5_hp_store.rar", Some("secretpass")),
                ("rar4", "rar4_hp_store.rar", Some("secretpass")),
                ("rar4", "rar4_multifile_store.rar", None),
            ] {
                if let Some(bytes) = corpus_fixture(&["tests", "fixtures", dir, file]) {
                    hole_and_split_at_each_header(file, &bytes, password);
                }
            }
        }

        /// Case 1: a header the walk read damaged — its CRC fails, the walk
        /// parses it anyway — is repaired once the cursor is past it. The
        /// caller restarts and the next step is the fresh walk; without the
        /// restart the cursor keeps the damaged name, undetected.
        #[test]
        fn a_repair_behind_the_cursor_takes_a_restart() {
            for (name, volume) in synthetics() {
                let damaged_at = volume.name_at(5);
                let original = volume.bytes[damaged_at];
                let staged = volume.members[9] + 3;
                for view in [View::Sparse, View::Prefix] {
                    for restart in [true, false] {
                        let mut image = Image::empty(&volume.bytes);
                        image.stage(0..staged);
                        image.put(damaged_at, b'#');
                        let mut run = Run::new(None, view);
                        let damaged = run.step(&image, &format!("{name}: damaged")).unwrap();
                        assert!(
                            damaged.facts.members[5].name.starts_with('#'),
                            "{name}: the walk reads the damaged header as it is"
                        );
                        assert!(run.cursor.resumes_at() > Some(volume.members[5] as u64));

                        image.put(damaged_at, original);
                        let fresh_now = fresh(&image, view, None, &run.cache).unwrap();
                        assert_eq!(fresh_now.facts.members[5].name, member_name(5));
                        if restart {
                            run.cursor.restart();
                            run.step(&image, &format!("{name}: repaired, restarted"))
                                .unwrap();
                            image.stage(0..volume.bytes.len());
                            run.step(&image, &format!("{name}: repaired, rest staged"))
                                .unwrap();
                        } else {
                            let stale = run.step_only(&image).unwrap();
                            assert_ne!(stale, fresh_now, "{name}: not detected");
                            assert!(
                                stale.facts.members[5].name.starts_with('#'),
                                "{name}: the facts before the cursor are kept as read"
                            );
                        }
                    }
                }
            }
        }

        /// Case 2: the header at the cursor arrives damaged so that it cannot
        /// be parsed. The failing step returns what a fresh walk returns for
        /// that image; the header is repaired in place and the next step,
        /// with no restart, is the fresh walk.
        #[test]
        fn a_header_at_the_cursor_repaired_in_place_steps_on_without_a_restart() {
            for (name, volume) in synthetics() {
                let header = volume.members[6];
                // The header-size field, zeroed: RAR5 states it as the vint
                // after the CRC32, RAR4 as the u16 after CRC16, type and flags.
                let field = if name == "RAR5" {
                    header + 4
                } else {
                    header + 5
                };
                let damage = 0;
                let original = volume.bytes[field];
                for view in [View::Sparse, View::Prefix] {
                    let mut image = Image::empty(&volume.bytes);
                    image.stage(0..header);
                    let mut run = Run::new(None, view);
                    run.step(&image, &format!("{name}: up to member 6"))
                        .unwrap();
                    assert_eq!(run.cursor.resumes_at(), Some(header as u64), "{name}");

                    image.stage(header..volume.members[8]);
                    image.put(field, damage);
                    let failed = run.step(&image, &format!("{name}: member 6 damaged"));
                    assert!(
                        failed.is_err(),
                        "{name}: the damaged header fails: {failed:?}"
                    );
                    assert!(
                        run.cursor.resumes_at() <= Some(header as u64),
                        "{name}: a failed step keeps the cursor at or before the header"
                    );

                    image.put(field, original);
                    run.step(&image, &format!("{name}: member 6 repaired"))
                        .unwrap();
                    image.stage(0..volume.bytes.len());
                    let whole = run.step(&image, &format!("{name}: whole")).unwrap();
                    assert_eq!(whole.facts.members.len(), 24, "{name}");
                    assert_eq!(whole.short_at, None, "{name}");
                }
            }
        }

        /// A different password begins at the signature on its own.
        #[test]
        fn a_new_password_walks_from_the_signature() {
            let Some(bytes) = corpus_fixture(&["tests", "fixtures", "rar5", "rar5_hp_store.rar"])
            else {
                return;
            };
            let cache = Arc::new(crate::crypto::KdfCache::new());
            let mut cursor = RarVolumeFactsCursor::new();
            let image = Image::whole(&bytes);
            let wrong = cursor.step(
                image.reader(View::Sparse),
                Some("not-it"),
                Arc::clone(&cache),
            );
            same(
                "wrong password",
                &wrong,
                &fresh(&image, View::Sparse, Some("not-it"), &cache),
            );
            let right = cursor.step(
                image.reader(View::Sparse),
                Some("secretpass"),
                Arc::clone(&cache),
            );
            same(
                "right password",
                &right,
                &fresh(&image, View::Sparse, Some("secretpass"), &cache),
            );
            assert!(right.is_ok());
        }
    }
}
