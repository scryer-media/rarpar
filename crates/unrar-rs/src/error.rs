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

    #[error("resource limit exceeded: {detail}")]
    ResourceLimit { detail: String },

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
}

// Written out rather than `#[from]`, which would also make the I/O error the
// variant's source and so render it twice along the chain.
impl From<io::Error> for RarError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub type RarResult<T> = Result<T, RarError>;

#[cfg(test)]
mod tests {
    use super::*;

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
