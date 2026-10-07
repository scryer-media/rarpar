//! A PAR3 set over one file whose bytes arrive once, in order.
//!
//! par3-rs builds sets from files it can open and size up front. Two callers
//! here cannot work that way: the one-pass archive writer, which protects a 7z
//! archive while it is being written and must not read it back, and the
//! PAR-inside commands, which append a set to the very file it protects. Both
//! describe a single file, so this module assembles par3cmdline's packets for
//! one file from par3-rs's public pieces — its packet types, its hashes, its
//! Galois fields and its Cauchy matrix element — while the bytes stream past.
//!
//! The Cauchy recovery block for row `r` is the sum over input blocks `i` of
//! `element(i, r) * block_i`, and the element depends only on the two indices,
//! never on how many input blocks the set ends up with. That is what lets a
//! recovery row be accumulated before the file's length is known, and lets a
//! block whose first bytes are written last (a 7z start header) be corrected
//! afterwards by adding the difference.

use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use blake3::hazmat::{
    ChainingValue, HasherExt, Mode, merge_subtrees_non_root, merge_subtrees_root,
};
use par3_rs::Fingerprint;
use par3_rs::cauchy::element;
use par3_rs::gf::{AnyField, Field, for_set};
use par3_rs::hash::{FingerprintHasher, QUICK_HASH_LEN, TAIL_HASH_LEN, fingerprint, rolling_hash};
use par3_rs::packet::{
    BlockChecksum, BlockRange, CauchyMatrixPacket, ChunkDescription, ChunkTail, CreatorPacket,
    ExternalDataPacket, FilePacket, GaloisField, InputSetId, Packet, PacketBody,
    RecoveryDataPacket, RootPacket, StartPacket,
};

/// The Creator text rarpar writes, the same text `rarpar par3 create` and the
/// par3cmdline facade write.
pub(crate) fn default_creator() -> String {
    par3_rs::create::CreateOptions::default_creator()
}

/// The Creator text to write: rarpar's own, unless `RARPAR_PAR3_CREATOR_TEXT`
/// names another. PAR-inside layouts size an unprotected chunk by the whole
/// packet run, Creator packet included, so only a run with the same Creator
/// text can be compared byte for byte with par3cmdline's.
pub(crate) fn creator_text() -> String {
    std::env::var("RARPAR_PAR3_CREATOR_TEXT").unwrap_or_else(|_| default_creator())
}

/// par3cmdline's Galois field for a Cauchy set: GF(2^16) with 0x1100B when
/// there are more than 128 input blocks and no declared maximum, or when the
/// blocks with either the created or the declared recovery rows pass 256;
/// GF(2^8) with 0x11D otherwise.
pub(crate) fn reference_field(
    blocks: u64,
    first: u64,
    recovery: u64,
    max_recovery: u64,
) -> GaloisField {
    if (blocks > 128 && max_recovery == 0)
        || blocks + first + recovery > 256
        || blocks + max_recovery > 256
    {
        GaloisField {
            size: 2,
            generator: 0x100b,
        }
    } else {
        GaloisField {
            size: 1,
            generator: 0x1d,
        }
    }
}

/// Recovery rows being summed in one field.
pub(crate) struct Coding {
    field: AnyField,
    galois: GaloisField,
    first: u64,
    rows: Vec<Vec<u8>>,
}

impl Coding {
    pub(crate) fn new(
        galois: GaloisField,
        first: u64,
        count: u64,
        block_size: u64,
    ) -> Result<Self, String> {
        let field = for_set(&galois).map_err(|error| error.to_string())?;
        if !block_size.is_multiple_of(field.symbol_bytes() as u64) {
            return Err(format!(
                "a block size of {block_size} bytes is not a whole number of field symbols"
            ));
        }
        let size = usize::try_from(block_size).map_err(|_| "block size too large".to_owned())?;
        let rows = (0..count).map(|_| vec![0u8; size]).collect();
        Ok(Self {
            field,
            galois,
            first,
            rows,
        })
    }

    pub(crate) fn galois(&self) -> GaloisField {
        self.galois
    }

    pub(crate) fn rows(&self) -> &[Vec<u8>] {
        &self.rows
    }

    /// Whether input block `index` still has a field value of its own: the
    /// Cauchy matrix gives input blocks the low values and recovery rows the
    /// high ones, so they must not meet.
    pub(crate) fn fits(&self, index: u64) -> bool {
        let order = 1u64 << (8 * self.field.symbol_bytes());
        index
            .saturating_add(self.first)
            .saturating_add(self.rows.len() as u64)
            < order
    }

    /// Drop the rows past `count`; rows never depend on how many follow.
    pub(crate) fn truncate(&mut self, count: u64) {
        self.rows.truncate(count as usize);
    }

    /// Add `data`, which sits at `offset` within input block `index`, to every
    /// row. `offset` and `data.len()` are whole symbols.
    pub(crate) fn add(&mut self, index: u64, offset: usize, data: &[u8]) -> Result<(), String> {
        if self.rows.is_empty() || data.is_empty() {
            return Ok(());
        }
        let field = &self.field;
        let first = self.first;
        let work = data.len().saturating_mul(self.rows.len());
        let threads = if work >= 8 << 20 && self.rows.len() > 1 {
            std::thread::available_parallelism()
                .map_or(1, usize::from)
                .min(self.rows.len())
        } else {
            1
        };
        let span = self.rows.len().div_ceil(threads);
        if threads <= 1 {
            return add_rows(field, first, 0, &mut self.rows, index, offset, data);
        }
        std::thread::scope(|scope| {
            let handles: Vec<_> = self
                .rows
                .chunks_mut(span)
                .enumerate()
                .map(|(part, rows)| {
                    scope.spawn(move || {
                        add_rows(field, first, part * span, rows, index, offset, data)
                    })
                })
                .collect();
            handles.into_iter().try_for_each(|handle| {
                handle
                    .join()
                    .unwrap_or_else(|_| Err("a worker panicked".to_owned()))
            })
        })
    }
}

fn add_rows(
    field: &AnyField,
    first: u64,
    base: usize,
    rows: &mut [Vec<u8>],
    index: u64,
    offset: usize,
    data: &[u8],
) -> Result<(), String> {
    for (position, row) in rows.iter_mut().enumerate() {
        let recovery = first + (base + position) as u64;
        let dst = &mut row[offset..offset + data.len()];
        match field {
            AnyField::Gf8(gf) => {
                let factor = element(gf, index, recovery).map_err(|error| error.to_string())?;
                gf.mul_acc(dst, data, factor);
            }
            AnyField::Gf16(gf) => {
                let factor = element(gf, index, recovery).map_err(|error| error.to_string())?;
                gf.mul_acc(dst, data, factor);
            }
        }
    }
    Ok(())
}

/// A tail block still open for packing.
struct OpenTail {
    index: u64,
    data: Vec<u8>,
}

/// Memory a lane keeps for every input block: its `full` flag and checksum
/// slot, and the checksum's copy when the set is built from them.
pub(crate) const LANE_BYTES_PER_BLOCK: u64 = (1
    + std::mem::size_of::<Option<BlockChecksum>>()
    + std::mem::size_of::<BlockChecksum>()) as u64;

/// One block size's view of the file: block checksums, chunk descriptions and
/// the recovery rows of every field it is coding in.
pub(crate) struct Lane {
    block_size: u64,
    next_block: u64,
    partial: Vec<u8>,
    chunk_len: u64,
    chunk_first: u64,
    /// Whether each block so far holds full-size data (`true`) or tails.
    full: Vec<bool>,
    /// Checksums of full-size blocks, by block index.
    checksums: Vec<Option<BlockChecksum>>,
    open_tail: Option<OpenTail>,
    /// Block 0 as fed, kept while its first bytes may still be patched.
    first_block: Option<Vec<u8>>,
    keep_first: bool,
    chunks: Vec<ChunkDescription>,
    /// Tails packed into an open block wait for it to close.
    pack_tails: bool,
    codings: Vec<Coding>,
    /// File offset where the current protected chunk started.
    chunk_offset: u64,
    /// File offset of the next byte fed.
    offset: u64,
}

impl Lane {
    /// A lane for blocks of `block_size` bytes. `keep_first` holds block 0 so
    /// that a patch to its first bytes can be applied after it completes.
    pub(crate) fn new(block_size: u64, keep_first: bool, pack_tails: bool) -> Self {
        Self {
            block_size,
            next_block: 0,
            partial: Vec::new(),
            chunk_len: 0,
            chunk_first: 0,
            full: Vec::new(),
            checksums: Vec::new(),
            open_tail: None,
            first_block: None,
            keep_first,
            chunks: Vec::new(),
            pack_tails,
            codings: Vec::new(),
            chunk_offset: 0,
            offset: 0,
        }
    }

    pub(crate) fn block_size(&self) -> u64 {
        self.block_size
    }

    pub(crate) fn add_coding(&mut self, coding: Coding) {
        self.codings.push(coding);
    }

    pub(crate) fn codings(&self) -> &[Coding] {
        &self.codings
    }

    pub(crate) fn codings_mut(&mut self) -> &mut Vec<Coding> {
        &mut self.codings
    }

    /// Blocks used so far, the open tail block included.
    pub(crate) fn block_count(&self) -> u64 {
        self.next_block
    }

    pub(crate) fn chunks(&self) -> &[ChunkDescription] {
        &self.chunks
    }

    /// Start a protected chunk.
    pub(crate) fn begin_chunk(&mut self) {
        self.partial.clear();
        self.chunk_len = 0;
        self.chunk_first = self.next_block;
        self.chunk_offset = self.offset;
    }

    /// Feed the next bytes of the current protected chunk.
    pub(crate) fn feed(&mut self, mut data: &[u8]) -> Result<(), String> {
        let size = self.block_size as usize;
        while !data.is_empty() {
            if self.partial.is_empty() && data.len() >= size {
                let (block, rest) = data.split_at(size);
                self.full_block(block)?;
                data = rest;
                continue;
            }
            let take = (size - self.partial.len()).min(data.len());
            self.partial.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.partial.len() == size {
                let block = std::mem::take(&mut self.partial);
                self.full_block(&block)?;
                self.partial = block;
                self.partial.clear();
            }
        }
        Ok(())
    }

    fn full_block(&mut self, block: &[u8]) -> Result<(), String> {
        let index = self.next_block;
        self.next_block += 1;
        self.chunk_len += block.len() as u64;
        self.offset += block.len() as u64;
        self.full.push(true);
        if index == 0 && self.keep_first {
            self.first_block = Some(block.to_vec());
            self.checksums.push(None);
        } else {
            self.checksums.push(Some(BlockChecksum {
                rolling_hash: rolling_hash(block),
                fingerprint: fingerprint(block),
            }));
        }
        // A field too small for this many blocks cannot be the set's field.
        self.codings.retain(|coding| coding.fits(index));
        for coding in &mut self.codings {
            coding.add(index, 0, block)?;
        }
        Ok(())
    }

    /// Replace bytes at file offset `at` that were fed as zeros. Only block 0
    /// and the bytes still buffered can be patched.
    pub(crate) fn patch(&mut self, at: u64, bytes: &[u8]) -> Result<(), String> {
        let end = at + bytes.len() as u64;
        let partial_start = self.offset;
        if let Some(first) = self.first_block.as_mut()
            && end <= self.block_size
        {
            first[at as usize..end as usize].copy_from_slice(bytes);
            for coding in &mut self.codings {
                // The block was summed with zeros here; add the difference.
                let symbol = coding.field.symbol_bytes() as u64;
                let start = at / symbol * symbol;
                let stop = end.div_ceil(symbol) * symbol;
                let mut delta = vec![0u8; (stop - start) as usize];
                delta[(at - start) as usize..(end - start) as usize].copy_from_slice(bytes);
                coding.add(0, start as usize, &delta)?;
            }
            return Ok(());
        }
        if at >= partial_start && end <= partial_start + self.partial.len() as u64 {
            let from = (at - partial_start) as usize;
            self.partial[from..from + bytes.len()].copy_from_slice(bytes);
            return Ok(());
        }
        Err(format!("cannot patch {} bytes at offset {at}", bytes.len()))
    }

    /// Finish the current protected chunk and return its description.
    pub(crate) fn end_chunk(&mut self) -> Result<ChunkDescription, String> {
        let tail = std::mem::take(&mut self.partial);
        let tail_len = tail.len() as u64;
        self.chunk_len += tail_len;
        self.offset += tail_len;
        let length = self.chunk_len;
        let first_block_index = (length >= self.block_size).then_some(self.chunk_first);
        let tail = if tail.is_empty() {
            ChunkTail::None
        } else if tail.len() < TAIL_HASH_LEN {
            ChunkTail::Inline(tail)
        } else {
            let rolling = rolling_hash(&tail[..TAIL_HASH_LEN]);
            let print = fingerprint(&tail);
            let packable = self.pack_tails
                && self
                    .open_tail
                    .as_ref()
                    .is_some_and(|open| open.data.len() + tail.len() <= self.block_size as usize);
            let (block_index, offset) = if packable {
                let open = self.open_tail.as_mut().expect("checked above");
                let offset = open.data.len() as u64;
                open.data.extend_from_slice(&tail);
                (open.index, offset)
            } else {
                self.close_tail()?;
                let index = self.next_block;
                self.next_block += 1;
                self.full.push(false);
                self.checksums.push(None);
                self.open_tail = Some(OpenTail { index, data: tail });
                (index, 0)
            };
            ChunkTail::Described {
                rolling_hash: rolling,
                fingerprint: print,
                block_index,
                offset,
            }
        };
        let chunk = ChunkDescription::Protected {
            length,
            first_block_index,
            tail,
        };
        self.chunks.push(chunk.clone());
        Ok(chunk)
    }

    /// Record a chunk no block covers.
    pub(crate) fn unprotected(&mut self, length: u64) {
        self.chunks.push(ChunkDescription::Unprotected { length });
        self.offset += length;
    }

    /// Record a protected chunk whose bytes repeat an earlier chunk's, as
    /// the copy of a ZIP footer after the packets: it maps to the same blocks.
    pub(crate) fn repeat_chunk(&mut self, chunk: &ChunkDescription) {
        if let ChunkDescription::Protected { length, .. } = chunk {
            self.offset += length;
        }
        self.chunks.push(chunk.clone());
    }

    fn close_tail(&mut self) -> Result<(), String> {
        if let Some(open) = self.open_tail.take() {
            let mut block = open.data;
            block.resize(self.block_size as usize, 0);
            self.codings.retain(|coding| coding.fits(open.index));
            for coding in &mut self.codings {
                coding.add(open.index, 0, &block)?;
            }
        }
        Ok(())
    }

    /// Close every open block. Call once all chunks are described.
    pub(crate) fn finish(&mut self) -> Result<(), String> {
        self.close_tail()?;
        if let Some(first) = self.first_block.take() {
            self.checksums[0] = Some(BlockChecksum {
                rolling_hash: rolling_hash(&first),
                fingerprint: fingerprint(&first),
            });
        }
        Ok(())
    }

    /// Runs of full-size blocks: (first index, checksums).
    pub(crate) fn checksum_runs(&self) -> Vec<(u64, Vec<BlockChecksum>)> {
        let mut runs: Vec<(u64, Vec<BlockChecksum>)> = Vec::new();
        let mut current: Option<(u64, Vec<BlockChecksum>)> = None;
        for (index, full) in self.full.iter().enumerate() {
            if *full {
                let checksum =
                    self.checksums[index].expect("full blocks are checksummed by finish");
                match current.as_mut() {
                    Some((_, run)) => run.push(checksum),
                    None => current = Some((index as u64, vec![checksum])),
                }
            } else if let Some(run) = current.take() {
                runs.push(run);
            }
        }
        runs.extend(current);
        runs
    }
}

/// BLAKE3 over a stream whose first bytes are written last.
///
/// The first 1024-byte chunk is buffered and the rest is hashed as the
/// complete left-spine subtrees `[1024·2^j, 1024·2^(j+1))`, which are the same
/// whatever the final length turns out to be; the first chunk joins them at
/// the end.
pub(crate) struct DeferredBlake3 {
    head: Vec<u8>,
    spine: Vec<ChainingValue>,
    current: Option<blake3::Hasher>,
    current_cap: u64,
    current_len: u64,
    len: u64,
}

const CHUNK: u64 = 1024;

impl DeferredBlake3 {
    pub(crate) fn new() -> Self {
        Self {
            head: Vec::with_capacity(CHUNK as usize),
            spine: Vec::new(),
            current: None,
            current_cap: 0,
            current_len: 0,
            len: 0,
        }
    }

    pub(crate) fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            if self.len < CHUNK {
                let take = ((CHUNK - self.len) as usize).min(data.len());
                self.head.extend_from_slice(&data[..take]);
                self.len += take as u64;
                data = &data[take..];
                continue;
            }
            if self.current.is_none() {
                let mut hasher = blake3::Hasher::new();
                hasher.set_input_offset(self.len);
                self.current = Some(hasher);
                self.current_cap = self.len;
                self.current_len = 0;
            }
            let take = ((self.current_cap - self.current_len) as usize).min(data.len());
            let hasher = self.current.as_mut().expect("opened above");
            hasher.update(&data[..take]);
            self.current_len += take as u64;
            self.len += take as u64;
            data = &data[take..];
            if self.current_len == self.current_cap {
                let hasher = self.current.take().expect("open");
                self.spine.push(hasher.finalize_non_root());
            }
        }
    }

    /// Replace bytes inside the first chunk.
    pub(crate) fn patch(&mut self, at: usize, bytes: &[u8]) {
        self.head[at..at + bytes.len()].copy_from_slice(bytes);
    }

    pub(crate) fn finalize(&self) -> Fingerprint {
        let digest = if self.len <= CHUNK {
            blake3::hash(&self.head)
        } else {
            let mut first = blake3::Hasher::new();
            first.update(&self.head);
            let mut left = first.finalize_non_root();
            let right = if let Some(current) = &self.current {
                for cv in &self.spine {
                    left = merge_subtrees_non_root(&left, cv, Mode::Hash);
                }
                current.finalize_non_root()
            } else {
                let (last, rest) = self.spine.split_last().expect("more than one chunk");
                for cv in rest {
                    left = merge_subtrees_non_root(&left, cv, Mode::Hash);
                }
                *last
            };
            merge_subtrees_root(&left, &right, Mode::Hash)
        };
        let mut out = [0u8; 16];
        out.copy_from_slice(&digest.as_bytes()[..16]);
        out
    }
}

/// The whole-file hashes a File packet carries.
pub(crate) struct FileDigest {
    hasher: DeferredBlake3,
    quick: Vec<u8>,
    len: u64,
}

impl FileDigest {
    pub(crate) fn new() -> Self {
        Self {
            hasher: DeferredBlake3::new(),
            quick: Vec::with_capacity(QUICK_HASH_LEN),
            len: 0,
        }
    }

    /// Feed protected bytes. `quick` says whether they still count toward the
    /// 16 KiB quick hash.
    pub(crate) fn update(&mut self, data: &[u8], quick: bool) {
        if quick && self.quick.len() < QUICK_HASH_LEN {
            let take = (QUICK_HASH_LEN - self.quick.len()).min(data.len());
            self.quick.extend_from_slice(&data[..take]);
        }
        self.hasher.update(data);
        self.len += data.len() as u64;
    }

    pub(crate) fn patch(&mut self, at: usize, bytes: &[u8]) {
        self.hasher.patch(at, bytes);
        let end = (at + bytes.len()).min(self.quick.len());
        if at < end {
            self.quick[at..end].copy_from_slice(&bytes[..end - at]);
        }
    }

    pub(crate) fn fingerprint(&self) -> Fingerprint {
        self.hasher.finalize()
    }

    pub(crate) fn quick_hash(&self) -> u64 {
        rolling_hash(&self.quick)
    }
}

/// Everything a single-file set's packets are built from.
pub(crate) struct SetSpec<'a> {
    /// The name the InputSetID digests: the path relative to the base.
    pub id_name: &'a str,
    /// The single path component the File packet stores.
    pub name: &'a str,
    pub file_size: u64,
    pub block_size: u64,
    pub galois: GaloisField,
    /// The Matrix packet's recovery hint, or `None` for a set without one.
    pub matrix_hint: Option<u64>,
    pub quick_hash: u64,
    pub fingerprint: Fingerprint,
    pub chunks: &'a [ChunkDescription],
    pub runs: &'a [(u64, Vec<BlockChecksum>)],
    pub block_count: u64,
    pub creator: &'a str,
}

/// A single-file set's packets.
pub(crate) struct BuiltSet {
    pub set_id: InputSetId,
    pub creator: Vec<u8>,
    pub common: Vec<Vec<u8>>,
    pub root_hash: Fingerprint,
    pub matrix_hash: Option<Fingerprint>,
}

impl BuiltSet {
    pub(crate) fn recovery_packet(&self, index: u64, data: &[u8]) -> Vec<u8> {
        Packet::new(
            self.set_id,
            PacketBody::RecoveryData(RecoveryDataPacket {
                root_hash: self.root_hash,
                matrix_hash: self
                    .matrix_hash
                    .expect("a set with recovery data has a matrix"),
                recovery_block_index: index,
                data: data.to_vec(),
            }),
        )
        .to_bytes()
    }
}

/// par3cmdline's InputSetID for one file and no directories.
fn input_set_id(spec: &SetSpec<'_>, start_body: &[u8]) -> InputSetId {
    let mut hasher = FingerprintHasher::new();
    hasher.update(spec.id_name.as_bytes());
    hasher.update(&[0]);
    hasher.update(&spec.file_size.to_le_bytes());
    hasher.update(&spec.fingerprint);
    if spec.file_size > 0 {
        for chunk in spec.chunks {
            match chunk {
                ChunkDescription::Unprotected { length } => {
                    hasher.update(&0u64.to_le_bytes());
                    hasher.update(&length.to_le_bytes());
                }
                ChunkDescription::Protected {
                    length,
                    first_block_index,
                    tail,
                } => {
                    hasher.update(&length.to_le_bytes());
                    if *length >= spec.block_size {
                        hasher.update(&first_block_index.unwrap_or(0).to_le_bytes());
                    }
                    if let ChunkTail::Described {
                        block_index,
                        offset,
                        ..
                    } = tail
                    {
                        hasher.update(&block_index.to_le_bytes());
                        hasher.update(&offset.to_le_bytes());
                    }
                }
                _ => {}
            }
        }
    }
    let seed = hasher.finalize();
    let mut hasher = FingerprintHasher::new();
    hasher.update(&seed[..8]);
    hasher.update(start_body);
    let digest = hasher.finalize();
    InputSetId(digest[..8].try_into().expect("8 bytes"))
}

/// Build the packets of a single-file set.
pub(crate) fn build_set(spec: &SetSpec<'_>) -> BuiltSet {
    let start = StartPacket {
        parent_input_set_id: InputSetId::ZERO,
        parent_root_hash: [0u8; 16],
        block_size: spec.block_size,
        galois_field: spec.galois,
        legacy_random: None,
    };
    let set_id = input_set_id(spec, &start.to_body_bytes());
    let mut common = vec![Packet::new(set_id, PacketBody::Start(start)).to_bytes()];
    let matrix_hash = spec.matrix_hint.map(|hint| {
        let matrix = Packet::new(
            set_id,
            PacketBody::CauchyMatrix(CauchyMatrixPacket {
                range: BlockRange { first: 0, end: 0 },
                recovery_block_hint: hint,
            }),
        );
        common.push(matrix.to_bytes());
        matrix.hash()
    });
    let file = Packet::new(
        set_id,
        PacketBody::File(FilePacket {
            name: spec.name.to_owned(),
            quick_rolling_hash: spec.quick_hash,
            fingerprint: spec.fingerprint,
            option_hashes: Vec::new(),
            chunks: spec.chunks.to_vec(),
        }),
    );
    let file_hash = file.hash();
    common.push(file.to_bytes());
    let root = Packet::new(
        set_id,
        PacketBody::Root(RootPacket {
            lowest_unused_block_index: spec.block_count,
            attributes: 0,
            option_hashes: Vec::new(),
            children: vec![file_hash],
        }),
    );
    let root_hash = root.hash();
    common.push(root.to_bytes());
    for (first, checksums) in spec.runs {
        common.push(
            Packet::new(
                set_id,
                PacketBody::ExternalData(ExternalDataPacket {
                    first_block_index: *first,
                    checksums: checksums.clone(),
                }),
            )
            .to_bytes(),
        );
    }
    BuiltSet {
        set_id,
        creator: Packet::new(
            set_id,
            PacketBody::Creator(CreatorPacket::new(spec.creator)),
        )
        .to_bytes(),
        common,
        root_hash,
        matrix_hash,
    }
}

// ---------------------------------------------------------------------------
// Geometry.

/// `floor(10 * sqrt(n))`, exactly.
fn ten_sqrt(n: u64) -> u64 {
    let target = u128::from(n) * 100;
    let mut root = (target as f64).sqrt() as u128;
    while root * root > target {
        root -= 1;
    }
    while (root + 1) * (root + 1) <= target {
        root += 1;
    }
    root as u64
}

/// par3cmdline's input block count for one file of `size` bytes.
pub(crate) fn block_count(size: u64, block_size: u64) -> u64 {
    if size == 0 {
        return 0;
    }
    size / block_size + u64::from(size % block_size >= 40)
}

/// par3cmdline's `suggest_block_size` for a single file of `size` bytes.
pub(crate) fn suggest_block_size(size: u64) -> u64 {
    par3_rs::create::suggest_block_size(std::iter::once(size))
}

/// How a sibling set's recovery count is chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecoveryChoice {
    /// An explicit count (`-c`), or none.
    Count(u64),
    /// A percentage of the input blocks, rounded up (`-r`).
    Percent(u64),
}

impl RecoveryChoice {
    pub(crate) fn rows(self, blocks: u64) -> u64 {
        if blocks == 0 {
            return 0;
        }
        match self {
            Self::Count(count) => count,
            Self::Percent(percent) => (blocks * percent).div_ceil(100),
        }
    }
}

/// A sibling set's geometry over a file of `size` bytes, as par3cmdline `c`
/// settles it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SiblingGeometry {
    pub block_size: u64,
    pub blocks: u64,
    pub recovery: u64,
    pub galois: GaloisField,
}

pub(crate) fn sibling_geometry(
    size: u64,
    block_size: Option<u64>,
    choice: RecoveryChoice,
) -> SiblingGeometry {
    let block_size = match block_size {
        Some(value) if value & 1 == 1 => value + 1,
        Some(value) => value,
        None => suggest_block_size(size),
    };
    let blocks = block_count(size, block_size);
    let recovery = choice.rows(blocks);
    SiblingGeometry {
        block_size,
        blocks,
        recovery,
        galois: reference_field(blocks, 0, recovery, 0),
    }
}

/// par3cmdline's starting block size for PAR inside.
fn initial_inside_block_size(size: u64) -> u64 {
    if size <= 40 {
        return 40;
    }
    let mut block_size = ten_sqrt(size);
    if size / block_size < 128 {
        block_size = next_pow2(size / 256);
    }
    if block_size <= 40 {
        return 40;
    }
    block_size = next_pow2(block_size);
    while size / block_size > 2048 {
        block_size *= 2;
    }
    block_size
}

pub(crate) fn next_pow2(value: u64) -> u64 {
    if value <= 1 {
        return 1;
    }
    value.next_power_of_two()
}

pub(crate) fn roundup_log2(value: u64) -> u32 {
    let mut bits = 0;
    while (1u64 << bits) < value {
        bits += 1;
    }
    bits
}

/// What par3cmdline's `inside_zip_size` works out for one block size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InsideShape {
    pub block_size: u64,
    pub total_packet_size: u64,
    pub blocks: u64,
    pub recovery: u64,
    pub repeat: u64,
}

/// Inputs to the PAR-inside layout search that do not depend on block size.
#[derive(Debug, Clone, Copy)]
pub(crate) struct InsideParams {
    pub file_size: u64,
    /// ZIP footer bytes copied after the packets; 0 for 7z.
    pub footer: u64,
    /// Bytes of the PAR file name as par3cmdline stores it.
    pub name_len: u64,
    pub creator_packet_size: u64,
    /// `-r`, or 0.
    pub redundancy: u64,
    /// `-lp`, or 0.
    pub repetition_limit: u64,
}

pub(crate) fn inside_size(params: &InsideParams, block_size: u64) -> InsideShape {
    let redundancy = if params.redundancy <= 250 {
        params.redundancy
    } else {
        0
    };
    let footer = params.footer;
    let data_size = params.file_size - footer;
    let mut tail_blocks = 0u64;
    let data_blocks = data_size / block_size;
    let data_tail = data_size % block_size;
    if data_tail >= 40 {
        tail_blocks += 1;
    }
    let footer_blocks = footer / block_size;
    let footer_tail = footer % block_size;
    if footer_tail >= 40 && !(data_tail >= 40 && data_tail + footer_tail <= block_size) {
        tail_blocks += 1;
    }
    let blocks = data_blocks + footer_blocks + tail_blocks;
    let recovery = if redundancy == 0 {
        1
    } else {
        (blocks * redundancy).div_ceil(100).max(1)
    };
    let mut common = 48 + 33 + 1;
    if blocks + recovery > 256 {
        common += 1;
    }
    let mut ext = 48 + 8 + 24 * data_blocks;
    if footer_blocks > 0 {
        ext += 48 + 8 + 24 * footer_blocks;
    }
    common += ext;
    common += 48 + 24;
    let recovery_packet = 48 + 40 + block_size;
    let mut file = 48 + 2 + params.name_len + 25;
    file += 8;
    if data_size >= block_size {
        file += 8;
    }
    file += if data_tail >= 40 { 40 } else { data_tail };
    let footer_desc = |file: &mut u64| {
        *file += 8;
        if footer >= block_size {
            *file += 8;
        }
        *file += if footer_tail >= 40 { 40 } else { footer_tail };
    };
    if footer > 0 {
        footer_desc(&mut file);
    }
    file += 16;
    if footer > 0 {
        footer_desc(&mut file);
    }
    common += file;
    common += 48 + 13 + 16;
    let mut repeat = 2u64;
    let mut step = 4u64;
    while step <= recovery {
        repeat += 1;
        step *= 2;
    }
    if redundancy <= 8 {
        repeat = repeat.min(3);
    } else {
        repeat = repeat.min(u64::from(roundup_log2(redundancy)));
    }
    if params.repetition_limit > 0 {
        repeat = repeat.min(params.repetition_limit - 1);
    }
    InsideShape {
        block_size,
        total_packet_size: params.creator_packet_size
            + common * repeat
            + recovery_packet * recovery,
        blocks,
        recovery,
        repeat,
    }
}

/// par3cmdline's block size search for PAR inside.
pub(crate) fn inside_geometry(params: &InsideParams) -> InsideShape {
    let size = params.file_size;
    let mut block_size = initial_inside_block_size(size);
    let mut best = inside_size(params, block_size);
    block_size = if block_size == 40 { 64 } else { block_size * 2 };
    while block_size * 2 <= size {
        let shape = inside_size(params, block_size);
        if (u128::from(size) + u128::from(shape.total_packet_size)) * 64
            < (u128::from(size) + u128::from(best.total_packet_size)) * 63
        {
            best = shape;
        } else {
            break;
        }
        block_size *= 2;
    }
    best
}

// ---------------------------------------------------------------------------
// Writing.

/// Write the PAR-inside packet run par3cmdline appends: common packets,
/// recovery packets with a copy of the common packets after every
/// `each_max` of them, a last copy, then the Creator packet.
pub(crate) fn write_inside(
    out: &mut impl Write,
    set: &BuiltSet,
    rows: &[Vec<u8>],
    first: u64,
    repeat: u64,
) -> std::io::Result<u64> {
    let mut written = 0u64;
    let mut put = |out: &mut dyn Write, bytes: &[u8]| -> std::io::Result<()> {
        written += bytes.len() as u64;
        out.write_all(bytes)
    };
    let common: Vec<u8> = set.common.concat();
    put(out, &common)?;
    let count = rows.len() as u64;
    let each_max = if repeat <= 2 {
        count
    } else {
        (count + repeat - 2) / (repeat - 1)
    };
    let mut each = 0u64;
    for (position, row) in rows.iter().enumerate() {
        put(out, &set.recovery_packet(first + position as u64, row))?;
        each += 1;
        if each == each_max {
            put(out, &common)?;
            each = 0;
        }
    }
    if each > 0 {
        put(out, &common)?;
    }
    put(out, &set.creator)?;
    Ok(written)
}

/// Recovery volumes of 1, 2, 4, … rows.
pub(crate) fn split_volumes(rows: u64) -> Vec<(u64, u64)> {
    let mut splits = Vec::new();
    let mut remaining = rows;
    let mut start = 0u64;
    let mut size = 1u64;
    while remaining > 0 {
        let count = size.min(remaining);
        splits.push((start, count));
        start += count;
        remaining -= count;
        size = size.saturating_mul(2);
    }
    splits
}

/// The index file and volume paths of a sibling set named by `stem`.
pub(crate) fn sibling_paths(stem: &Path, rows: u64) -> (PathBuf, Vec<(u64, u64, PathBuf)>) {
    let directory = stem.parent().unwrap_or(Path::new(""));
    let name = stem
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let base = name.strip_suffix(".par3").unwrap_or(&name).to_owned();
    let splits = split_volumes(rows);
    let start_width = splits
        .last()
        .map_or(0, |(start, _)| start.to_string().len());
    let count_width = splits
        .iter()
        .map(|(_, count)| *count)
        .max()
        .map_or(0, |count| count.to_string().len());
    let volumes = splits
        .into_iter()
        .map(|(start, count)| {
            (
                start,
                count,
                directory.join(format!(
                    "{base}.vol{start:0start_width$}+{count:0count_width$}.par3"
                )),
            )
        })
        .collect();
    (directory.join(format!("{base}.par3")), volumes)
}

/// Write a sibling set: the index file and its recovery volumes, laid out as
/// par3cmdline lays them out.
pub(crate) fn write_sibling(
    stem: &Path,
    set: &BuiltSet,
    rows: &[Vec<u8>],
    overwrite: bool,
) -> std::io::Result<Vec<PathBuf>> {
    let (index, volumes) = sibling_paths(stem, rows.len() as u64);
    for path in std::iter::once(&index).chain(volumes.iter().map(|(_, _, path)| path)) {
        // Look at the name itself: a link, dangling or not, is never
        // written through, and overwriting replaces only a real file.
        match std::fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("refusing a symlinked output: {}", path.display()),
                ));
            }
            Ok(_) if !overwrite => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!("{} already exists", path.display()),
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    let mut written = Vec::new();
    write_file(&index, |out| {
        out.write_all(&set.creator)?;
        for packet in &set.common {
            out.write_all(packet)?;
        }
        Ok(())
    })?;
    written.push(index);
    for (start, count, path) in volumes {
        write_file(&path, |out| {
            out.write_all(&set.creator)?;
            for packet in &set.common {
                out.write_all(packet)?;
            }
            let total = u64::from(count.ilog2()) * set.common.len() as u64;
            let mut emitted = 0u64;
            let mut cursor = 0usize;
            for done in 1..=count {
                let index = start + done - 1;
                out.write_all(&set.recovery_packet(index, &rows[index as usize]))?;
                let target = (u128::from(total) * u128::from(done) / u128::from(count)) as u64;
                while emitted < target {
                    out.write_all(&set.common[cursor])?;
                    cursor = (cursor + 1) % set.common.len();
                    emitted += 1;
                }
            }
            Ok(())
        })?;
        written.push(path);
    }
    Ok(written)
}

fn write_file(
    path: &Path,
    body: impl FnOnce(&mut BufWriter<std::fs::File>) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NOFOLLOW);
    let file = options.open(path)?;
    let mut out = BufWriter::new(file);
    body(&mut out)?;
    out.flush()?;
    out.into_inner()
        .map_err(|error| error.into_error())?
        .sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_deferred_hash_matches_blake3_at_every_tree_shape() {
        let data: Vec<u8> = (0..20_000u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        for len in [
            0usize, 1, 32, 1023, 1024, 1025, 2047, 2048, 2049, 3000, 4096, 4097, 8192, 9000,
            16_384, 20_000,
        ] {
            let mut real = data[..len].to_vec();
            let mut hasher = DeferredBlake3::new();
            // Feed with the first 32 bytes zeroed, then patch them in.
            let head = 32.min(len);
            let mut fed = real.clone();
            fed[..head].fill(0);
            for piece in fed.chunks(700) {
                hasher.update(piece);
            }
            hasher.patch(0, &real[..head]);
            let expect = blake3::hash(&real);
            assert_eq!(
                &hasher.finalize()[..],
                &expect.as_bytes()[..16],
                "length {len}"
            );
            real.clear();
        }
    }

    #[test]
    fn suggested_block_sizes_follow_par3cmdline() {
        assert_eq!(suggest_block_size(40), 40);
        assert_eq!(suggest_block_size(41), 32);
        // 300205 bytes: 10*sqrt = 5479 -> 4096, 74 blocks, no halving.
        assert_eq!(suggest_block_size(300_205), 4096);
        // 1 MiB: 10240 -> 8192, 128 blocks.
        assert_eq!(suggest_block_size(1 << 20), 8192);
    }

    #[test]
    fn the_inside_search_matches_a_reference_run() {
        // par3cmdline `i` over a 300205-byte 7z named demo_i.7z chose 2048-byte
        // blocks, 147 of them, one recovery block.
        let creator = CreatorPacket::new(
            "par3cmdline version 0.0.1\n(https://github.com/Parchive/par3cmdline)",
        );
        let params = InsideParams {
            file_size: 300_205,
            footer: 0,
            name_len: "demo_i.7z".len() as u64,
            creator_packet_size: 48 + creator.to_body_bytes().len() as u64,
            redundancy: 0,
            repetition_limit: 0,
        };
        let shape = inside_geometry(&params);
        assert_eq!(
            (shape.block_size, shape.blocks, shape.recovery),
            (2048, 147, 1)
        );
        assert_eq!(shape.total_packet_size, 310_350 - 300_205);
    }
}
