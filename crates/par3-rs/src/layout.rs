//! Logical block placement independent of filesystem ownership.
//!
//! A protected file is described by chunks, and a chunk that covers whole
//! blocks maps a contiguous span of file bytes onto a contiguous span of block
//! indices. Storing one materialised extent per block repeated that arithmetic
//! and, worse, copied the fingerprint and rolling hash the set's checksum
//! storage already owns. This module keeps the mapping as *runs* and expands an
//! extent only when one is asked for; the exceptions a run cannot express —
//! described tails, inline tail bytes, unprotected ranges, and blocks named by
//! more than one extent — are stored individually and charged individually.
//!
//! Nothing about what a layout *means* changes: [`FileExtent`] and
//! [`ExtentKind`] are the same values they always were, in the same order.

use std::collections::BTreeMap;
use std::ops::{Deref, Range};
use std::sync::Arc;

use crate::checksums::BlockChecksums;
use crate::packet::{ChunkDescription, ChunkTail, btree_entry_bytes};
use crate::runtime::{EngineError, EngineResult, ExecutionOptions, MemoryCategory, Reservation};
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

/// A described chunk tail: its own fingerprint, not the block's.
///
/// A tail names part of an input block, so the set's block checksum does not
/// describe it. These are the charged exceptions to shared checksum ownership.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TailDescription {
    block: u64,
    offset: u64,
    fingerprint: Fingerprint,
    rolling_hash: u64,
}

/// What one run of consecutive extents maps onto.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RunKind {
    /// `count` whole blocks starting at `first_block`, one extent each.
    Blocks { first_block: u64, count: u64 },
    /// One described tail; its description lives in `FileExtents::tails`.
    Tail { at: usize, len: u64 },
    /// One inline tail; its bytes live in `FileExtents::inline`.
    Inline { at: usize, len: u64 },
    /// One unprotected range.
    Unprotected { len: u64 },
}

/// One run of consecutive extents in one file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExtentRun {
    /// Index of this run's first extent within the file.
    first_extent: usize,
    /// File-coordinate byte offset where this run starts.
    start: u64,
    kind: RunKind,
}

/// A file's extents, held as runs and expanded on demand.
///
/// This behaves like the extent vector it replaces for every read a caller
/// makes — `len`, `iter`, indexed access — but yields [`FileExtent`] *by value*
/// because no such value is stored. Fingerprints and rolling hashes for whole
/// blocks come from the shared checksum storage this container holds a
/// reference to, so the same authenticated bytes are never copied per extent.
#[derive(Clone, Debug)]
pub struct FileExtents {
    runs: Vec<ExtentRun>,
    tails: Vec<TailDescription>,
    inline: Vec<Vec<u8>>,
    checksums: Arc<BlockChecksums>,
    block_size: u64,
    count: usize,
}

impl FileExtents {
    /// Number of extents this file has.
    #[must_use]
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether the file has no extents at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Number of runs the extents collapse into.
    #[must_use]
    pub fn runs(&self) -> usize {
        self.runs.len()
    }

    /// Runs a contiguous block mapping could not express: described tails,
    /// inline tails and unprotected ranges.
    #[must_use]
    pub fn exceptions(&self) -> usize {
        self.runs
            .iter()
            .filter(|run| !matches!(run.kind, RunKind::Blocks { .. }))
            .count()
    }

    fn bytes(&self, run: &ExtentRun) -> u64 {
        match run.kind {
            RunKind::Blocks { count, .. } => count.saturating_mul(self.block_size),
            RunKind::Tail { len, .. } | RunKind::Inline { len, .. } => len,
            RunKind::Unprotected { len } => len,
        }
    }

    fn run_end(&self, run: &ExtentRun) -> u64 {
        run.start.saturating_add(self.bytes(run))
    }

    fn run_of(&self, index: usize) -> Option<&ExtentRun> {
        if index >= self.count {
            return None;
        }
        let at = self.runs.partition_point(|run| run.first_extent <= index);
        self.runs.get(at.checked_sub(1)?)
    }

    fn expand(&self, run: &ExtentRun, step: usize) -> FileExtent {
        match run.kind {
            RunKind::Blocks { first_block, .. } => {
                let block = first_block + step as u64;
                let start = run.start + step as u64 * self.block_size;
                let checksum = self.checksums.get(block);
                FileExtent {
                    range: start..start + self.block_size,
                    kind: ExtentKind::Block {
                        index: block,
                        offset: 0,
                        fingerprint: checksum.map(|value| value.fingerprint),
                        rolling_hash: checksum.map(|value| value.rolling_hash),
                    },
                }
            }
            RunKind::Tail { at, len } => {
                let tail = self.tails[at];
                FileExtent {
                    range: run.start..run.start + len,
                    kind: ExtentKind::Block {
                        index: tail.block,
                        offset: tail.offset,
                        fingerprint: Some(tail.fingerprint),
                        rolling_hash: Some(tail.rolling_hash),
                    },
                }
            }
            RunKind::Inline { at, len } => FileExtent {
                range: run.start..run.start + len,
                kind: ExtentKind::Inline(self.inline[at].clone()),
            },
            RunKind::Unprotected { len } => FileExtent {
                range: run.start..run.start + len,
                kind: ExtentKind::Unprotected,
            },
        }
    }

    /// One extent by index, materialised from the run that describes it.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<FileExtent> {
        let run = self.run_of(index)?;
        Some(self.expand(run, index - run.first_extent))
    }

    /// One extent's byte range, without materialising its checksums.
    #[must_use]
    pub fn range(&self, index: usize) -> Option<Range<u64>> {
        let run = self.run_of(index)?;
        let step = (index - run.first_extent) as u64;
        let (start, len) = match run.kind {
            RunKind::Blocks { .. } => (run.start + step * self.block_size, self.block_size),
            RunKind::Tail { len, .. } | RunKind::Inline { len, .. } => (run.start, len),
            RunKind::Unprotected { len } => (run.start, len),
        };
        Some(start..start + len)
    }

    /// The block one extent names, with the offset inside it, when it names one.
    #[must_use]
    pub fn block_at(&self, index: usize) -> Option<(u64, u64)> {
        let run = self.run_of(index)?;
        match run.kind {
            RunKind::Blocks { first_block, .. } => {
                Some((first_block + (index - run.first_extent) as u64, 0))
            }
            RunKind::Tail { at, .. } => Some((self.tails[at].block, self.tails[at].offset)),
            RunKind::Inline { .. } | RunKind::Unprotected { .. } => None,
        }
    }

    /// Whether one extent is a deliberately unprotected range.
    #[must_use]
    pub fn is_unprotected(&self, index: usize) -> bool {
        self.run_of(index)
            .is_some_and(|run| matches!(run.kind, RunKind::Unprotected { .. }))
    }

    /// Inline tail bytes held in authenticated metadata for one extent.
    #[must_use]
    pub fn inline_bytes(&self, index: usize) -> Option<&[u8]> {
        match self.run_of(index)?.kind {
            RunKind::Inline { at, .. } => Some(&self.inline[at]),
            _ => None,
        }
    }

    /// Index of the first extent that ends after `offset`, or `len` when none
    /// does. This is what `partition_point` over a materialised extent slice
    /// answered, without materialising anything.
    #[must_use]
    pub fn first_after(&self, offset: u64) -> usize {
        let at = self.runs.partition_point(|run| self.run_end(run) <= offset);
        let Some(run) = self.runs.get(at) else {
            return self.count;
        };
        if offset <= run.start {
            return run.first_extent;
        }
        match run.kind {
            RunKind::Blocks { .. } => {
                run.first_extent + ((offset - run.start) / self.block_size) as usize
            }
            _ => run.first_extent,
        }
    }

    /// Whether every extent that ends after `start` and begins before `end` is
    /// unprotected. An extent that begins exactly at `end` is not one of them,
    /// so an empty interval on an extent boundary is vacuously unprotected.
    #[must_use]
    pub fn all_unprotected(&self, start: u64, end: u64) -> bool {
        let mut index = self.first_after(start);
        while index < self.count {
            let range = self.range(index).expect("bounded extent");
            if range.start >= end {
                return true;
            }
            if !self.is_unprotected(index) {
                return false;
            }
            index += 1;
        }
        true
    }

    /// Every extent in file-offset order, materialised one at a time.
    #[must_use]
    pub fn iter(&self) -> FileExtentIter<'_> {
        FileExtentIter {
            extents: self,
            run: 0,
            next: 0,
            end: self.count,
        }
    }

    /// Bytes these containers hold, from their real capacities. The shared
    /// checksum storage is charged by the set that owns it, not here.
    fn capacity_bytes(&self) -> usize {
        self.runs
            .capacity()
            .saturating_mul(size_of::<ExtentRun>())
            .saturating_add(
                self.tails
                    .capacity()
                    .saturating_mul(size_of::<TailDescription>()),
            )
            .saturating_add(self.inline.capacity().saturating_mul(size_of::<Vec<u8>>()))
            .saturating_add(self.inline.iter().map(Vec::capacity).sum::<usize>())
    }
}

impl<'a> IntoIterator for &'a FileExtents {
    type Item = FileExtent;
    type IntoIter = FileExtentIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Expands a file's runs into extents in file-offset order.
#[derive(Clone, Debug)]
pub struct FileExtentIter<'a> {
    extents: &'a FileExtents,
    run: usize,
    next: usize,
    end: usize,
}

impl Iterator for FileExtentIter<'_> {
    type Item = FileExtent;

    fn next(&mut self) -> Option<FileExtent> {
        if self.next >= self.end {
            return None;
        }
        while self.run + 1 < self.extents.runs.len()
            && self.extents.runs[self.run + 1].first_extent <= self.next
        {
            self.run += 1;
        }
        let run = &self.extents.runs[self.run];
        let value = self.extents.expand(run, self.next - run.first_extent);
        self.next += 1;
        Some(value)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.end - self.next;
        (remaining, Some(remaining))
    }
}

impl DoubleEndedIterator for FileExtentIter<'_> {
    fn next_back(&mut self) -> Option<FileExtent> {
        if self.end <= self.next {
            return None;
        }
        self.end -= 1;
        self.extents.get(self.end)
    }
}

impl ExactSizeIterator for FileExtentIter<'_> {}

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
    pub extents: FileExtents,
}

/// One reference from a block to a file extent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExtentLocation {
    /// Index into `BlockLayout::files`.
    pub file: usize,
    /// Index into that file's extents.
    pub extent: usize,
}

/// Every extent that names one logical block.
///
/// A block named exactly once — the common case — is answered without any
/// stored list; a block named more than once carries a charged alias list.
#[derive(Clone, Copy, Debug)]
pub struct BlockLocations<'a> {
    one: [ExtentLocation; 1],
    many: &'a [ExtentLocation],
}

impl Deref for BlockLocations<'_> {
    type Target = [ExtentLocation];

    fn deref(&self) -> &[ExtentLocation] {
        if self.many.is_empty() {
            &self.one
        } else {
            self.many
        }
    }
}

/// A run of consecutive blocks each named by exactly one extent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BlockSpan {
    first_block: u64,
    count: u64,
    file: usize,
    first_extent: usize,
}

/// Which extents name each logical block.
///
/// Contiguous block mappings referenced once are kept as spans; every block
/// named by more than one extent is an exception with its own charged list.
#[derive(Debug, Default)]
pub(crate) struct BlockIndex {
    spans: Vec<BlockSpan>,
    aliases: BTreeMap<u64, Vec<ExtentLocation>>,
    referenced: u64,
}

impl BlockIndex {
    fn locations(&self, block: u64) -> Option<BlockLocations<'_>> {
        if let Some(many) = self.aliases.get(&block) {
            return Some(BlockLocations {
                one: [ExtentLocation { file: 0, extent: 0 }],
                many,
            });
        }
        let at = self.spans.partition_point(|span| span.first_block <= block);
        let span = self.spans.get(at.checked_sub(1)?)?;
        let step = block - span.first_block;
        (step < span.count).then(|| BlockLocations {
            one: [ExtentLocation {
                file: span.file,
                extent: span.first_extent + step as usize,
            }],
            many: &[],
        })
    }

    fn widest(&self) -> usize {
        self.aliases
            .values()
            .map(Vec::len)
            .max()
            .unwrap_or(usize::from(!self.spans.is_empty()))
    }

    fn capacity_bytes(&self) -> usize {
        self.spans
            .capacity()
            .saturating_mul(size_of::<BlockSpan>())
            .saturating_add(
                self.aliases
                    .len()
                    .saturating_mul(btree_entry_bytes::<u64, Vec<ExtentLocation>>()),
            )
            .saturating_add(
                self.aliases
                    .values()
                    .map(|locations| locations.capacity() * size_of::<ExtentLocation>())
                    .sum::<usize>(),
            )
    }
}

/// Every referenced block and the extents that name it, in block order.
pub struct BlockEntries<'a> {
    index: &'a BlockIndex,
    span: usize,
    step: u64,
    aliases: std::iter::Peekable<std::collections::btree_map::Iter<'a, u64, Vec<ExtentLocation>>>,
}

impl<'a> Iterator for BlockEntries<'a> {
    type Item = (u64, BlockLocations<'a>);

    fn next(&mut self) -> Option<(u64, BlockLocations<'a>)> {
        let next_span = loop {
            let Some(span) = self.index.spans.get(self.span) else {
                break None;
            };
            if self.step < span.count {
                break Some((span.first_block + self.step, span));
            }
            self.span += 1;
            self.step = 0;
        };
        let next_alias = self.aliases.peek().map(|(block, _)| **block);
        match (next_span, next_alias) {
            (Some((block, span)), alias) if alias.is_none_or(|other| block < other) => {
                let location = ExtentLocation {
                    file: span.file,
                    extent: span.first_extent + self.step as usize,
                };
                self.step += 1;
                Some((
                    block,
                    BlockLocations {
                        one: [location],
                        many: &[],
                    },
                ))
            }
            (_, Some(_)) => {
                let (block, many) = self.aliases.next().expect("peeked alias");
                Some((
                    *block,
                    BlockLocations {
                        one: [ExtentLocation { file: 0, extent: 0 }],
                        many,
                    },
                ))
            }
            (_, None) => None,
        }
    }
}

/// Fixed allowance for a layout's own value and its containers' headers.
const LAYOUT_BASE_BYTES: usize = 4096;

/// Authenticated layout supporting packed tails, aliases and unprotected regions.
#[derive(Debug)]
pub struct BlockLayout {
    /// File layouts, in the same order as `Par3Set::files`.
    pub(crate) files: Vec<FileLayout>,
    /// Which extents name each logical block. Aliases are not additional losses.
    pub(crate) index: BlockIndex,
    /// Shared ownership of the set's authenticated block checksums, so extents
    /// reference them instead of copying them and can never dangle.
    pub(crate) checksums: Arc<BlockChecksums>,
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

    /// Every extent that names one logical block, or `None` when no file does.
    #[must_use]
    pub fn locations(&self, block: u64) -> Option<BlockLocations<'_>> {
        self.index.locations(block)
    }

    /// Every referenced block with the extents that name it, in block order.
    #[must_use]
    pub fn blocks(&self) -> BlockEntries<'_> {
        BlockEntries {
            index: &self.index,
            span: 0,
            step: 0,
            aliases: self.index.aliases.iter().peekable(),
        }
    }

    /// Number of logical blocks some file extent names.
    #[must_use]
    pub fn referenced_blocks(&self) -> u64 {
        self.index.referenced
    }

    /// Number of blocks named by more than one extent.
    #[must_use]
    pub fn aliased_blocks(&self) -> usize {
        self.index.aliases.len()
    }

    /// Most extents any one block is named by.
    #[must_use]
    pub fn widest_block(&self) -> usize {
        self.index.widest()
    }

    /// The authenticated block checksums this layout shares with its set.
    #[must_use]
    pub fn checksums(&self) -> &BlockChecksums {
        &self.checksums
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

    /// Retained allocation charged for this layout, which after construction is
    /// its measured container capacity.
    #[must_use]
    pub fn retained_bytes(&self) -> usize {
        self._reservation.bytes()
    }

    /// Bytes this layout's containers hold, from their real capacities.
    ///
    /// The shared checksum storage is deliberately absent: it is owned and
    /// charged by the [`Par3Set`] this layout was resolved from, and held alive
    /// here through shared ownership so the same bytes are charged exactly once.
    pub(crate) fn capacity_bytes(&self) -> usize {
        let files = self
            .files
            .capacity()
            .saturating_mul(size_of::<FileLayout>())
            .saturating_add(
                self.files
                    .iter()
                    .map(|file| file.path.capacity() + file.extents.capacity_bytes())
                    .sum::<usize>(),
            );
        files
            .saturating_add(self.index.capacity_bytes())
            .saturating_add(LAYOUT_BASE_BYTES)
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
        let plan = Plan::measure(set)?;
        // Measured from the containers this layout builds. A contiguous block
        // mapping costs one run and one span however many blocks it covers;
        // tails, inline bytes and unprotected ranges cost one entry each. The
        // alias exceptions are not knowable until the spans are laid out, so
        // they are charged where they are discovered, below.
        let cost = plan
            .bytes()
            .ok_or(EngineError::resource_limit("layout runs"))?;
        if cost > options.retained_bytes {
            return Err(EngineError::budget_limit(
                "retained layout",
                cost,
                options.retained_bytes,
                options.retained_bytes,
            ));
        }
        let reservation = options
            .memory
            .reserve_as(MemoryCategory::LayoutEvidence, cost)?;
        let mut result = Self {
            files: Vec::with_capacity(set.files().len()),
            index: BlockIndex::default(),
            checksums: set.shared_block_checksums(),
            block_size: set.block_size(),
            block_count: set.block_count(),
            identity: [0; 16],
            _reservation: reservation,
        };
        let mut identity = crate::FingerprintHasher::new();
        identity.update(set.input_set_id().as_bytes());
        identity.update(&set.root_hash());
        identity.update(&set.block_size().to_le_bytes());
        for (index, checksum) in set.block_checksums().iter() {
            identity.update(&index.to_le_bytes());
            identity.update(&checksum.fingerprint);
            identity.update(&checksum.rolling_hash.to_le_bytes());
        }
        let mut spans: Vec<BlockSpan> = Vec::with_capacity(plan.spans);
        for (file_index, file) in set.files().iter().enumerate() {
            options.cancel.check()?;
            identity.update(&file.packet_hash());
            let mut extents = FileExtents {
                runs: Vec::with_capacity(runs_of(file)),
                tails: Vec::new(),
                inline: Vec::new(),
                checksums: Arc::clone(&result.checksums),
                block_size: result.block_size,
                count: 0,
            };
            let mut at = 0;
            for chunk in file.chunks() {
                match chunk {
                    ChunkDescription::Unprotected { length } => {
                        extents.runs.push(ExtentRun {
                            first_extent: extents.count,
                            start: at,
                            kind: RunKind::Unprotected { len: *length },
                        });
                        extents.count += 1;
                        at += length;
                    }
                    ChunkDescription::Protected {
                        length,
                        first_block_index,
                        tail,
                    } => {
                        let whole = length / result.block_size;
                        if whole != 0 {
                            let first = first_block_index
                                .ok_or(EngineError::InvalidState("full block has no index"))?;
                            first
                                .checked_add(whole)
                                .filter(|end| *end <= result.block_count)
                                .ok_or(EngineError::InvalidState("extent beyond block count"))?;
                            spans.push(BlockSpan {
                                first_block: first,
                                count: whole,
                                file: file_index,
                                first_extent: extents.count,
                            });
                            extents.runs.push(ExtentRun {
                                first_extent: extents.count,
                                start: at,
                                kind: RunKind::Blocks {
                                    first_block: first,
                                    count: whole,
                                },
                            });
                            extents.count += usize::try_from(whole)
                                .map_err(|_| EngineError::resource_limit("layout extents"))?;
                            at += whole * result.block_size;
                        }
                        let remainder = length % result.block_size;
                        if remainder != 0 {
                            let kind = match tail {
                                ChunkTail::Inline(bytes) if bytes.len() as u64 == remainder => {
                                    extents.inline.push(bytes.clone());
                                    RunKind::Inline {
                                        at: extents.inline.len() - 1,
                                        len: remainder,
                                    }
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
                                    if *block_index >= result.block_count {
                                        return Err(EngineError::InvalidState(
                                            "extent beyond block count",
                                        ));
                                    }
                                    spans.push(BlockSpan {
                                        first_block: *block_index,
                                        count: 1,
                                        file: file_index,
                                        first_extent: extents.count,
                                    });
                                    extents.tails.push(TailDescription {
                                        block: *block_index,
                                        offset: *offset,
                                        fingerprint: *fingerprint,
                                        rolling_hash: *rolling_hash,
                                    });
                                    RunKind::Tail {
                                        at: extents.tails.len() - 1,
                                        len: remainder,
                                    }
                                }
                                _ => return Err(EngineError::InvalidState("invalid chunk tail")),
                            };
                            extents.runs.push(ExtentRun {
                                first_extent: extents.count,
                                start: at,
                                kind,
                            });
                            extents.count += 1;
                            at += remainder;
                        }
                    }
                }
            }
            extents.runs.shrink_to_fit();
            extents.tails.shrink_to_fit();
            extents.inline.shrink_to_fit();
            result.files.push(FileLayout {
                path: file.path().to_owned(),
                packet_hash: file.packet_hash(),
                fingerprint: file.fingerprint(),
                len: file.size(),
                extents,
            });
        }
        result.index = build_index(spans, &result, options)?;
        result.identity = identity.finalize();
        // Resize to what was actually built. The estimate above is an upper
        // bound taken from the descriptions; this is the capacity the layout
        // will hold for as long as it lives.
        let actual = result.capacity_bytes();
        if let Some(growth) = actual.checked_sub(result._reservation.bytes()) {
            result._reservation.grow_by(growth)?;
        } else {
            result._reservation.shrink_to(actual);
        }
        Ok(result)
    }
}

/// The container sizes a layout will need, measured from chunk descriptions.
struct Plan {
    files: usize,
    path_bytes: usize,
    runs: usize,
    spans: usize,
    tails: usize,
    inline: usize,
    inline_bytes: usize,
}

impl Plan {
    fn measure(set: &Par3Set) -> EngineResult<Self> {
        let mut plan = Self {
            files: set.files().len(),
            path_bytes: 0,
            runs: 0,
            spans: 0,
            tails: 0,
            inline: 0,
            inline_bytes: 0,
        };
        for file in set.files() {
            plan.path_bytes = plan
                .path_bytes
                .checked_add(file.path().len())
                .ok_or(EngineError::resource_limit("layout paths"))?;
            for chunk in file.chunks() {
                match chunk {
                    ChunkDescription::Unprotected { .. } => plan.runs += 1,
                    ChunkDescription::Protected { length, tail, .. } => {
                        let remainder = length % set.block_size();
                        if length / set.block_size() != 0 {
                            plan.runs += 1;
                            plan.spans += 1;
                        }
                        if remainder != 0 {
                            plan.runs += 1;
                            match tail {
                                ChunkTail::Inline(bytes) if bytes.len() as u64 == remainder => {
                                    plan.inline += 1;
                                    plan.inline_bytes =
                                        plan.inline_bytes.checked_add(bytes.len()).ok_or(
                                            EngineError::resource_limit("layout inline tails"),
                                        )?;
                                }
                                _ => {
                                    plan.tails += 1;
                                    plan.spans += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(plan)
    }

    fn bytes(&self) -> Option<usize> {
        self.files
            .checked_mul(size_of::<FileLayout>())?
            .checked_add(self.path_bytes)?
            .checked_add(self.runs.checked_mul(size_of::<ExtentRun>())?)?
            .checked_add(self.spans.checked_mul(size_of::<BlockSpan>())?)?
            .checked_add(self.tails.checked_mul(size_of::<TailDescription>())?)?
            .checked_add(self.inline.checked_mul(size_of::<Vec<u8>>())?)?
            .checked_add(self.inline_bytes)?
            .checked_add(LAYOUT_BASE_BYTES)
    }
}

/// The most runs one file's chunk descriptions can produce: a protected chunk
/// contributes a block run and a tail, an unprotected chunk contributes one.
fn runs_of(file: &crate::Par3File) -> usize {
    file.chunks()
        .iter()
        .map(|chunk| match chunk {
            ChunkDescription::Unprotected { .. } => 1,
            ChunkDescription::Protected { .. } => 2,
        })
        .sum()
}

/// Lay the collected spans out, splitting off every block more than one extent
/// names into a charged alias list.
fn build_index(
    mut spans: Vec<BlockSpan>,
    layout: &BlockLayout,
    options: &ExecutionOptions,
) -> EngineResult<BlockIndex> {
    spans.sort_unstable_by_key(|span| (span.first_block, span.count, span.file, span.first_extent));
    // Depth over block indices: any block two spans cover is an alias and
    // leaves the run form. A sweep over span boundaries finds them without
    // materialising anything per block.
    let mut boundaries: Vec<(u64, i64)> = Vec::with_capacity(spans.len() * 2);
    for span in &spans {
        boundaries.push((span.first_block, 1));
        boundaries.push((span.first_block + span.count, -1));
    }
    boundaries.sort_unstable();
    let mut contested: Vec<Range<u64>> = Vec::new();
    let mut depth = 0i64;
    let mut open: Option<u64> = None;
    for (at, delta) in boundaries {
        let was = depth;
        depth += delta;
        if was < 2 && depth >= 2 {
            open = Some(at);
        } else if was >= 2
            && depth < 2
            && let Some(start) = open.take()
        {
            match contested.last_mut() {
                Some(last) if last.end == start => last.end = at,
                _ => contested.push(start..at),
            }
        }
    }
    let aliased = contested
        .iter()
        .try_fold(0usize, |total, range| {
            usize::try_from(range.end - range.start)
                .ok()
                .and_then(|width| total.checked_add(width))
        })
        .ok_or(EngineError::resource_limit("layout aliases"))?;
    let mut index = BlockIndex::default();
    if aliased != 0 {
        // Every aliased block leaves the compact form, so it is charged at what
        // an ordered-map entry and its location list actually cost.
        let extra = aliased
            .checked_mul(btree_entry_bytes::<u64, Vec<ExtentLocation>>())
            .and_then(|bytes| {
                bytes.checked_add(
                    spans
                        .len()
                        .checked_mul(2 * size_of::<ExtentLocation>())?
                        .checked_add(aliased.checked_mul(2 * size_of::<ExtentLocation>())?)?,
                )
            })
            .ok_or(EngineError::resource_limit("layout aliases"))?;
        if layout._reservation.bytes().saturating_add(extra) > options.retained_bytes {
            return Err(EngineError::budget_limit(
                "retained layout aliases",
                layout._reservation.bytes().saturating_add(extra),
                options.retained_bytes,
                options.retained_bytes,
            ));
        }
        for span in &spans {
            options.cancel.check()?;
            for range in &contested {
                let start = span.first_block.max(range.start);
                let end = (span.first_block + span.count).min(range.end);
                for block in start..end {
                    index
                        .aliases
                        .entry(block)
                        .or_default()
                        .push(ExtentLocation {
                            file: span.file,
                            extent: span.first_extent
                                + usize::try_from(block - span.first_block)
                                    .map_err(|_| EngineError::resource_limit("layout aliases"))?,
                        });
                }
            }
        }
        for locations in index.aliases.values_mut() {
            locations.sort_unstable_by_key(|location| (location.file, location.extent));
        }
    }
    // Whatever the aliases took is no longer a span; the rest stays compact.
    for span in spans {
        let mut at = span.first_block;
        let end = span.first_block + span.count;
        for range in &contested {
            if range.end <= at || range.start >= end {
                continue;
            }
            if range.start > at {
                push_span(&mut index.spans, span, at, range.start)?;
            }
            at = at.max(range.end);
        }
        if at < end {
            push_span(&mut index.spans, span, at, end)?;
        }
    }
    index
        .spans
        .sort_unstable_by_key(|span| (span.first_block, span.count));
    index.spans.shrink_to_fit();
    index.referenced = index
        .spans
        .iter()
        .map(|span| span.count)
        .sum::<u64>()
        .saturating_add(index.aliases.len() as u64);
    // Identical aliases must describe identical content. Partially overlapping
    // tails are checked against actual bytes when a block is assembled.
    let mut descriptions = BTreeMap::new();
    for locations in index.aliases.values() {
        options.cancel.check()?;
        descriptions.clear();
        for location in locations {
            let Some(extent) = layout.files[location.file].extents.get(location.extent) else {
                continue;
            };
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
    Ok(index)
}

fn push_span(
    spans: &mut Vec<BlockSpan>,
    span: BlockSpan,
    first: u64,
    end: u64,
) -> EngineResult<()> {
    spans.push(BlockSpan {
        first_block: first,
        count: end - first,
        file: span.file,
        first_extent: span.first_extent
            + usize::try_from(first - span.first_block)
                .map_err(|_| EngineError::resource_limit("layout spans"))?,
    });
    Ok(())
}
