use std::io;

/// Errors that can occur when parsing or extracting RAR archives.
///
/// The set of variants grows with the formats and failure modes the crate
/// recognises, so a `match` over it needs a wildcard arm.
///
/// No variant has a [`source`]: `Io` renders its I/O error, the way
/// `io::Error` renders the error it carries, so a reporter that walks the
/// chain prints it once. A caller reaches the I/O error by matching `Io`.
///
/// [`source`]: std::error::Error::source
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RarError {
    #[error("I/O error: {0}")]
    Io(io::Error),

    #[error("not a RAR archive (bad signature)")]
    InvalidSignature,

    #[error("unsupported RAR format version: {version}")]
    UnsupportedFormat { version: u8 },

    #[error("corrupt archive: {detail}")]
    CorruptArchive { detail: String },

    /// A container modification ([`crate::container`]) was refused: the
    /// archive or the request does not allow it, and nothing was written.
    #[error("modification refused: {detail}")]
    ModificationRefused { detail: String },

    // The display keeps the wording this failure had while it was reported as
    // `CorruptArchive`, so logs read the same.
    #[non_exhaustive]
    #[error(
        "corrupt archive: RAR5 block header checksum mismatch: expected {expected:#04x}, got {actual:#04x}"
    )]
    BlockHeaderChecksumMismatch { expected: u8, actual: u8 },

    #[error("header CRC mismatch: expected {expected:#010x}, got {actual:#010x}")]
    HeaderCrcMismatch { expected: u32, actual: u32 },

    #[error("data CRC mismatch for {member}: expected {expected:#010x}, got {actual:#010x}")]
    DataCrcMismatch {
        member: String,
        expected: u32,
        actual: u32,
    },

    #[error(
        "packed data CRC mismatch for {member} in volume {volume}: expected {expected:#010x}, got {actual:#010x}"
    )]
    PackedDataCrcMismatch {
        member: String,
        volume: usize,
        expected: u32,
        actual: u32,
    },

    #[error("BLAKE2 hash mismatch for {member}")]
    Blake2Mismatch { member: String },

    #[error("packed data BLAKE2 hash mismatch for {member} in volume {volume}")]
    PackedDataBlake2Mismatch { member: String, volume: usize },

    #[error("missing volume {volume} required for member {member}")]
    MissingVolume { volume: usize, member: String },

    #[error("archive is encrypted (header-level encryption)")]
    EncryptedArchive,

    #[error("member {member} is encrypted")]
    EncryptedMember { member: String },

    #[error("invalid password for encrypted archive")]
    InvalidPassword,

    #[error("wrong password for member {member}")]
    WrongPassword { member: String },

    #[error("unsupported compression method {method} version {version}")]
    UnsupportedCompression { method: u8, version: u8 },

    #[error("unsupported encryption version {version}")]
    UnsupportedEncryption { version: u64 },

    #[error("unsupported encryption KDF log2 count {count} (maximum {max})")]
    UnsupportedEncryptionKdf { count: u8, max: u8 },

    #[error("unsupported filter type {filter_type}")]
    UnsupportedFilter { filter_type: u8 },

    #[error("dictionary size {size} exceeds maximum allowed {max}")]
    DictionaryTooLarge { size: u64, max: u64 },

    #[error("truncated header at offset {offset}")]
    TruncatedHeader { offset: u64 },

    #[error("truncated data at offset {offset}")]
    TruncatedData { offset: u64 },

    #[error("invalid vint encoding at offset {offset}")]
    InvalidVint { offset: u64 },

    #[error("Huffman table construction failed")]
    InvalidHuffmanTable,

    /// A size or count the archive declares, or that decoding reached, is
    /// above a limit: one the caller set in [`Limits`](crate::Limits), one
    /// built into the crate, or what this platform can address.
    /// [`RarError::resource_limit`] builds one.
    #[non_exhaustive]
    #[error(
        "resource limit exceeded: {kind} {requested} is above the limit of {max}{}",
        for_member(.member)
    )]
    ResourceLimit {
        /// Which limit.
        kind: LimitKind,
        /// The size or count that was asked for.
        requested: u64,
        /// The limit it is above.
        max: u64,
        /// The member it was asked for, when it belongs to one.
        member: Option<String>,
    },

    /// The allocator refused memory the archive's parameters called for,
    /// though no limit refused them.
    #[error("failed to allocate {bytes} bytes")]
    AllocationFailed { bytes: u64 },

    /// A worker thread panicked or stopped early, or an invariant of this
    /// crate's own failed. Neither the archive nor the caller is at fault.
    #[error("internal error: {detail}")]
    Internal { detail: String },

    #[error("member not found: {name}")]
    MemberNotFound { name: String },

    #[error("member index {index} is out of range: the archive lists {len} members")]
    MemberIndexOutOfRange { index: usize, len: usize },

    #[error(
        "per-volume extraction of {member} needs a volume provider: the archive is not solid, so volume attribution comes from the provider's segment stream (acquire the entry with by_index_via)"
    )]
    VolumeProviderRequired { member: String },

    #[error(
        "solid archive requires sequential extraction: must extract {required} before {requested}"
    )]
    SolidOrderViolation { required: String, requested: String },

    #[error("unsafe link target for {member}: {target}")]
    UnsafeLinkTarget { member: String, target: String },

    #[error("unsupported link type for {member}: {link_type}")]
    UnsupportedLinkType { member: String, link_type: String },

    #[error(
        "solid decoder state was left mid-member by {member} and no longer describes the archive: {detail}"
    )]
    SolidStatePoisoned { member: String, detail: String },

    /// A volume's recovery record cannot rebuild every damaged unit it
    /// protects, so [`repair_from_recovery_record`] rebuilt none of them.
    /// [`assess_recovery_record`] reports the whole damage.
    ///
    /// [`repair_from_recovery_record`]: crate::repair_from_recovery_record
    /// [`assess_recovery_record`]: crate::assess_recovery_record
    #[non_exhaustive]
    #[error("the recovery record cannot rebuild {} damaged unit(s)", units.len())]
    RecoveryRecordInsufficient {
        /// The damaged units it cannot rebuild, ascending.
        units: Vec<u64>,
    },
}

/// The limit a [`RarError::ResourceLimit`] is above.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LimitKind {
    /// [`Limits::max_data_segment`](crate::Limits): one member's packed
    /// data in one volume.
    DataSegment,
    /// [`Limits::max_unpacked_size`](crate::Limits): one member's output.
    UnpackedSize,
    /// The most an in-memory extraction holds for one member.
    MemoryExtraction,
    /// The most memory this platform can address.
    AddressSpace,
    /// The headers one volume may declare.
    HeadersPerVolume,
    /// One header's size.
    HeaderSize,
    /// The highest volume number an archive may declare.
    VolumeNumber,
    /// An archive comment's size.
    Comment,
    /// A link target's size, the reference implementation's MAXPATHSIZE.
    LinkTarget,
    /// [`Limits::max_ppmd_arena_size`](crate::Limits): a PPMd model's arena.
    PpmdArena,
}

impl std::fmt::Display for LimitKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::DataSegment => "packed data segment size",
            Self::UnpackedSize => "unpacked size",
            Self::MemoryExtraction => "in-memory extraction size",
            Self::AddressSpace => "addressable size",
            Self::HeadersPerVolume => "header count per volume",
            Self::HeaderSize => "header size",
            Self::VolumeNumber => "volume number",
            Self::Comment => "comment size",
            Self::LinkTarget => "link target size",
            Self::PpmdArena => "PPMd model arena size",
        })
    }
}

fn for_member(member: &Option<String>) -> String {
    member
        .as_deref()
        .map_or_else(String::new, |member| format!(" for {member}"))
}

impl RarError {
    /// A [`RarError::ResourceLimit`].
    #[must_use]
    pub fn resource_limit(
        kind: LimitKind,
        requested: u64,
        max: u64,
        member: Option<String>,
    ) -> Self {
        Self::ResourceLimit {
            kind,
            requested,
            max,
            member,
        }
    }

    pub(crate) fn corrupt(detail: impl Into<String>) -> Self {
        Self::CorruptArchive {
            detail: detail.into(),
        }
    }

    pub(crate) fn internal(detail: impl Into<String>) -> Self {
        Self::Internal {
            detail: detail.into(),
        }
    }

    /// This error inside an [`io::Error`] whose kind matches it, for a
    /// `Read` or `Write` path. The error comes back out with
    /// [`io::Error::downcast`].
    pub(crate) fn into_io(self) -> io::Error {
        let kind = match &self {
            Self::Io(error) => error.kind(),
            Self::CorruptArchive { .. }
            | Self::BlockHeaderChecksumMismatch { .. }
            | Self::HeaderCrcMismatch { .. }
            | Self::DataCrcMismatch { .. }
            | Self::PackedDataCrcMismatch { .. }
            | Self::Blake2Mismatch { .. }
            | Self::PackedDataBlake2Mismatch { .. }
            | Self::TruncatedHeader { .. }
            | Self::TruncatedData { .. }
            | Self::InvalidVint { .. }
            | Self::InvalidHuffmanTable => io::ErrorKind::InvalidData,
            Self::MissingVolume { .. } => io::ErrorKind::NotFound,
            Self::AllocationFailed { .. } => io::ErrorKind::OutOfMemory,
            _ => io::ErrorKind::Other,
        };
        io::Error::new(kind, self)
    }
}

// An I/O error that carries a `RarError`, as one from a `Read` or `Write`
// path does, is that error; any other is kept whole as `Io`, its kind, OS
// error code and payload included. Written out rather than `#[from]`, which
// would also make the I/O error the variant's source and so render it twice
// along the chain.
impl From<io::Error> for RarError {
    fn from(error: io::Error) -> Self {
        error.downcast::<Self>().unwrap_or_else(Self::Io)
    }
}

pub type RarResult<T> = Result<T, RarError>;

#[cfg(test)]
mod tests {
    use super::*;

    // An error carried through a `Read` path comes back out as itself, with
    // its limit as fields rather than words.
    #[test]
    fn a_limit_rides_an_io_error_and_comes_back_typed() {
        let io =
            RarError::resource_limit(LimitKind::DataSegment, 9, 4, Some("a.bin".into())).into_io();
        assert_eq!(io.kind(), io::ErrorKind::Other);
        let error = io.downcast::<RarError>().expect("the crate's own error");
        assert!(matches!(
            error,
            RarError::ResourceLimit {
                kind: LimitKind::DataSegment,
                requested: 9,
                max: 4,
                ref member,
            } if member.as_deref() == Some("a.bin")
        ));
        assert_eq!(
            error.to_string(),
            "resource limit exceeded: packed data segment size 9 is above the limit of 4 for a.bin"
        );
        assert!(matches!(
            RarError::from(RarError::internal("worker stopped").into_io()),
            RarError::Internal { .. }
        ));
        assert!(matches!(
            RarError::from(io::Error::from(io::ErrorKind::UnexpectedEof)),
            RarError::Io(_)
        ));
        assert_eq!(
            RarError::corrupt("x").into_io().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            RarError::AllocationFailed { bytes: 1 }.into_io().kind(),
            io::ErrorKind::OutOfMemory
        );
    }

    // Every error renders a cause it carries or returns it, never both, so a
    // chain reporter prints each cause once.
    #[test]
    fn an_io_error_is_rendered_once_along_the_chain() {
        let provider = crate::volume::VolumeProviderError::Io {
            volume: 3,
            error: io::Error::from_raw_os_error(2),
        };
        let error = RarError::from(io::Error::other(provider));
        let mut chain = vec![error.to_string()];
        let mut next = std::error::Error::source(&error);
        while let Some(cause) = next {
            chain.push(cause.to_string());
            next = cause.source();
        }
        assert_eq!(
            chain,
            [format!(
                "I/O error: volume 3 I/O error: {}",
                io::Error::from_raw_os_error(2)
            )]
        );
    }
}
