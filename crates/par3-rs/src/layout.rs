//! Logical block placement independent of filesystem ownership.

use std::collections::BTreeMap;
use std::ops::Range;

use crate::packet::{ChunkDescription, ChunkTail};
use crate::runtime::{EngineError, EngineResult, ExecutionOptions, Reservation};
use crate::{Fingerprint, Par3Set};

/// What supplies a protected-file extent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExtentKind {
    /// A slice of one logical input block. Multiple files may name the same bytes.
    Block {
        /// Input block index.
        index: u64,
        /// Offset within the logical block.
        offset: u64,
        /// Strong checksum of this extent, when supplied by metadata.
        fingerprint: Option<Fingerprint>,
        /// Locator checksum; full extent for blocks, first 40 bytes for tails.
        rolling_hash: Option<u64>,
    },
    /// A short tail whose bytes are stored directly in authenticated metadata.
    Inline(Vec<u8>),
    /// Bytes excluded from protection. Their value is never implied to be zero.
    Unprotected,
}

/// A contiguous region in file coordinates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileExtent {
    /// Half-open byte range within the protected file.
    pub range: Range<u64>,
    /// Mapping or inline bytes for this range.
    pub kind: ExtentKind,
}

/// All extents of a file, in file-offset order.
#[derive(Clone, Debug)]
pub struct FileLayout {
    /// Resolved relative path, for display and explicit output installation.
    pub path: String,
    /// Authenticated File packet identity.
    pub packet_hash: Fingerprint,
    /// Whole protected-data fingerprint; zero means unset.
    pub fingerprint: Fingerprint,
    /// Logical length, including unprotected ranges.
    pub len: u64,
    /// Disjoint file-coordinate regions.
    pub extents: Vec<FileExtent>,
}

/// One reference from a block to a file extent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExtentLocation {
    /// Index into `BlockLayout::files`.
    pub file: usize,
    /// Index into that file's extents.
    pub extent: usize,
}

/// Authenticated layout supporting packed tails, aliases and unprotected regions.
#[derive(Debug)]
pub struct BlockLayout {
    /// File layouts, in the same order as `Par3Set::files`.
    pub(crate) files: Vec<FileLayout>,
    /// Every file extent which names a block. Aliases are not additional losses.
    pub(crate) blocks: BTreeMap<u64, Vec<ExtentLocation>>,
    /// Bytes in a logical block.
    pub(crate) block_size: u64,
    /// Number of logical input blocks, independent of file count.
    pub(crate) block_count: u64,
    /// Fingerprint binding this layout to its root and checksum metadata.
    pub(crate) identity: Fingerprint,
    _reservation: Reservation,
}

impl BlockLayout {
    /// Authenticated file layouts; mutation cannot manufacture verification evidence.
    #[must_use]
    pub fn files(&self) -> &[FileLayout] {
        &self.files
    }

    /// Aliases which reference each logical block.
    #[must_use]
    pub fn blocks(&self) -> &BTreeMap<u64, Vec<ExtentLocation>> {
        &self.blocks
    }

    /// Bytes per logical block.
    #[must_use]
    pub fn block_size(&self) -> u64 {
        self.block_size
    }

    /// Number of logical blocks.
    #[must_use]
    pub fn block_count(&self) -> u64 {
        self.block_count
    }

    /// Identity binding all authenticated layout and checksum descriptions.
    #[must_use]
    pub fn identity(&self) -> Fingerprint {
        self.identity
    }

    /// Conservative retained allocation charged for this layout.
    #[must_use]
    pub fn retained_bytes(&self) -> usize {
        self._reservation.bytes()
    }

    /// Resolve a set without reading any protected source bytes.
    pub fn new(set: &Par3Set, options: &ExecutionOptions) -> EngineResult<Self> {
        options.validate()?;
        if set.block_size() == 0 {
            return Err(EngineError::InvalidState("zero block size"));
        }
        if set.parent_input_set_id().is_some() {
            return Err(EngineError::Unsupported("incremental parent sets"));
        }
        let mut count = 0u64;
        let mut path_bytes = 0usize;
        for file in set.files() {
            path_bytes = path_bytes
                .checked_add(file.path().len())
                .ok_or(EngineError::ResourceLimit("layout paths"))?;
            for chunk in file.chunks() {
                let amount = match chunk {
                    ChunkDescription::Protected { length, .. } => {
                        length / set.block_size() + u64::from(length % set.block_size() != 0)
                    }
                    ChunkDescription::Unprotected { .. } => 1,
                };
                count = count
                    .checked_add(amount)
                    .ok_or(EngineError::ResourceLimit("layout extents"))?;
            }
        }
        let cost = usize::try_from(count)
            .ok()
            .and_then(|n| n.checked_mul(512))
            .and_then(|n| n.checked_add(set.files().len().checked_mul(256)?))
            .and_then(|n| n.checked_add(path_bytes))
            .ok_or(EngineError::ResourceLimit("layout extents"))?;
        if cost > options.retained_bytes {
            return Err(EngineError::ResourceLimit("retained layout"));
        }
        let reservation = options.memory.reserve(cost)?;
        let mut result = Self {
            files: Vec::with_capacity(set.files().len()),
            blocks: BTreeMap::new(),
            block_size: set.block_size(),
            block_count: set.block_count(),
            identity: [0; 16],
            _reservation: reservation,
        };
        let mut identity = crate::FingerprintHasher::new();
        identity.update(set.input_set_id().as_bytes());
        identity.update(&set.root_hash());
        identity.update(&set.block_size().to_le_bytes());
        for (index, checksum) in set.block_checksums() {
            identity.update(&index.to_le_bytes());
            identity.update(&checksum.fingerprint);
            identity.update(&checksum.rolling_hash.to_le_bytes());
        }
        for (file_index, file) in set.files().iter().enumerate() {
            options.cancel.check()?;
            identity.update(&file.packet_hash());
            let mut layout = FileLayout {
                path: file.path().to_owned(),
                packet_hash: file.packet_hash(),
                fingerprint: file.fingerprint(),
                len: file.size(),
                extents: Vec::new(),
            };
            let mut at = 0;
            for chunk in file.chunks() {
                match chunk {
                    ChunkDescription::Unprotected { length } => {
                        let end = at + length;
                        layout.extents.push(FileExtent {
                            range: at..end,
                            kind: ExtentKind::Unprotected,
                        });
                        at = end;
                    }
                    ChunkDescription::Protected {
                        length,
                        first_block_index,
                        tail,
                    } => {
                        for step in 0..length / result.block_size {
                            let block = first_block_index
                                .ok_or(EngineError::InvalidState("full block has no index"))?
                                .checked_add(step)
                                .ok_or(EngineError::InvalidState("block index overflow"))?;
                            let checksum = set.block_checksum(block);
                            layout.extents.push(FileExtent {
                                range: at..at + result.block_size,
                                kind: ExtentKind::Block {
                                    index: block,
                                    offset: 0,
                                    fingerprint: checksum.map(|v| v.fingerprint),
                                    rolling_hash: checksum.map(|v| v.rolling_hash),
                                },
                            });
                            at += result.block_size;
                        }
                        let remainder = length % result.block_size;
                        if remainder != 0 {
                            let kind = match tail {
                                ChunkTail::Inline(bytes) if bytes.len() as u64 == remainder => {
                                    ExtentKind::Inline(bytes.clone())
                                }
                                ChunkTail::Described {
                                    block_index,
                                    offset,
                                    fingerprint,
                                    rolling_hash,
                                } => {
                                    if offset
                                        .checked_add(remainder)
                                        .is_none_or(|end| end > result.block_size)
                                    {
                                        return Err(EngineError::InvalidState(
                                            "tail exceeds its input block",
                                        ));
                                    }
                                    ExtentKind::Block {
                                        index: *block_index,
                                        offset: *offset,
                                        fingerprint: Some(*fingerprint),
                                        rolling_hash: Some(*rolling_hash),
                                    }
                                }
                                _ => return Err(EngineError::InvalidState("invalid chunk tail")),
                            };
                            layout.extents.push(FileExtent {
                                range: at..at + remainder,
                                kind,
                            });
                            at += remainder;
                        }
                    }
                }
            }
            for (extent_index, extent) in layout.extents.iter().enumerate() {
                if let ExtentKind::Block { index, .. } = extent.kind {
                    if index >= result.block_count {
                        return Err(EngineError::InvalidState("extent beyond block count"));
                    }
                    result
                        .blocks
                        .entry(index)
                        .or_default()
                        .push(ExtentLocation {
                            file: file_index,
                            extent: extent_index,
                        });
                }
            }
            result.files.push(layout);
        }
        // Identical aliases must describe identical content. Partially overlapping
        // tails are checked against actual bytes when a block is assembled.
        for locations in result.blocks.values() {
            let mut descriptions = BTreeMap::new();
            for location in locations {
                let extent = &result.files[location.file].extents[location.extent];
                if let ExtentKind::Block {
                    offset,
                    fingerprint: Some(hash),
                    ..
                } = extent.kind
                {
                    let key = (offset, extent.range.end - extent.range.start);
                    if descriptions
                        .insert(key, hash)
                        .is_some_and(|previous| previous != hash)
                    {
                        return Err(EngineError::InvalidState("contradictory block aliases"));
                    }
                }
            }
        }
        result.identity = identity.finalize();
        Ok(result)
    }
}
