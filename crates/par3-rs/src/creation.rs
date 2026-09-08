//! Explicit advanced creation plans over stable source identities.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::fft::{FftCodec, FftGeometry};
use crate::gf::Field;
use crate::packet::{
    BlockChecksum, BlockRange, CauchyMatrixPacket, ChunkDescription, ChunkTail, CreatorPacket,
    DirectoryPacket, ExternalDataPacket, FftMatrixPacket, FilePacket, GaloisField, PacketBody,
    PacketHeader, PacketType, RootPacket, StartPacket,
};
use crate::runtime::{EngineError, EngineResult, ExecutionOptions, Reservation};
use crate::source::{SourceAccess, SourceId, SourceSnapshot, ensure_snapshot, read_exact_at};
use crate::{Fingerprint, FingerprintHasher, InputSetId, Packet, RollingHasher};

/// Codec selection. Existing `create::create` defaults remain unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreationCodec {
    /// Default Cauchy matrix, with a field chosen from the required indices.
    Cauchy,
    /// Reference-compatible low-rate FFT, optionally interleaved.
    Fft {
        /// Log2 of recovery capacity per cohort, not the number being written.
        capacity_log2: i8,
        /// Extra cohorts; zero means one cohort.
        interleave: u64,
    },
}

/// Full-block deduplication policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Deduplication {
    /// Every input region has its own logical block.
    None,
    /// Reuse blocks and tails with identical strong fingerprints and lengths.
    Aligned,
    /// Search arbitrary byte alignments for previously seen full blocks, using
    /// CRC64 localization followed by BLAKE3 confirmation.
    Sliding,
}

/// Explicit recovery-volume layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VolumeLayout {
    /// Volumes grow by powers of two.
    Variable,
    /// Every volume contains at most this many recovery packets.
    Uniform(u64),
    /// Bound each recovery carrier's bytes, including its metadata copy.
    SizeLimited(u64),
}

/// Advanced creation options. Recovery indices are global across cohorts.
#[derive(Clone, Debug)]
pub struct CreationOptions {
    /// Block size, in bytes; must be nonzero and field aligned.
    pub block_size: u64,
    /// Matrix family and geometry.
    pub codec: CreationCodec,
    /// First global recovery index to create.
    pub first_recovery: u64,
    /// Number of recovery packets to create.
    pub recovery_count: u64,
    /// Repeated-data treatment.
    pub deduplication: Deduplication,
    /// Also write authenticated original Data packets.
    pub store_data: bool,
    /// Recovery carrier sizing.
    pub volumes: VolumeLayout,
    /// Creator packet text.
    pub creator: String,
    /// Execution budgets and cancellation.
    pub execution: ExecutionOptions,
}

impl Default for CreationOptions {
    fn default() -> Self {
        Self {
            block_size: 1 << 20,
            codec: CreationCodec::Cauchy,
            first_recovery: 0,
            recovery_count: 1,
            deduplication: Deduplication::None,
            store_data: false,
            volumes: VolumeLayout::Variable,
            creator: crate::create::CreateOptions::default_creator(),
            execution: ExecutionOptions::default(),
        }
    }
}

/// One explicitly named input. No directory discovery is performed.
#[derive(Clone, Debug)]
pub struct CreationSource {
    /// Relative path encoded in authenticated metadata.
    pub name: String,
    /// Identity resolved by the supplied source provider.
    pub source: SourceId,
}

#[derive(Clone)]
struct Piece {
    source: SourceId,
    snapshot: SourceSnapshot,
    at: u64,
    length: u64,
    offset: u64,
}
struct Block {
    pieces: Vec<Piece>,
    used: u64,
    checksum: Option<BlockChecksum>,
}
struct PlannedFile {
    name: String,
    source: SourceId,
    snapshot: SourceSnapshot,
    packet: FilePacket,
}

/// Read-only requirements available before any output or scratch file is created.
#[derive(Clone, Debug)]
pub struct CreationRequirements {
    /// Logical blocks after deduplication and tail packing.
    pub blocks: u64,
    /// Total original bytes described by the set.
    pub source_bytes: u64,
    /// Full blocks reused by deduplication.
    pub reused_blocks: u64,
    /// Exact recovery scratch size.
    pub scratch_bytes: u64,
    /// Complete metadata bytes repeated in each carrier.
    pub metadata_bytes: u64,
    /// Exact index and carrier lengths, in execution order.
    pub output_sizes: Vec<u64>,
    /// Field stored in the Start packet.
    pub field: GaloisField,
    /// Number of cohorts, one for Cauchy.
    pub cohorts: u64,
}

/// A plan retains metadata and source slices, never complete source blocks.
pub struct CreationPlan {
    access: Arc<dyn SourceAccess>,
    options: CreationOptions,
    files: Vec<PlannedFile>,
    blocks: Vec<Block>,
    metadata: Vec<Vec<u8>>,
    id: InputSetId,
    root: Fingerprint,
    matrix: Fingerprint,
    volumes: Vec<(u64, u64)>,
    data_volumes: Vec<(u64, u64)>,
    requirements: CreationRequirements,
    _reservation: Reservation,
}

impl CreationPlan {
    /// Read and hash explicit sources, then expose exact output and scratch
    /// requirements. Holes and changed generations are typed failures.
    pub fn build(
        access: Arc<dyn SourceAccess>,
        sources: &[CreationSource],
        options: CreationOptions,
    ) -> EngineResult<Self> {
        options.execution.validate()?;
        if options.block_size == 0 {
            return Err(EngineError::InvalidState("zero creation block size"));
        }
        let entry_bytes = sources
            .len()
            .checked_mul(64)
            .ok_or(EngineError::ResourceLimit("creation source entries"))?;
        if entry_bytes > options.execution.retained_bytes {
            return Err(EngineError::ResourceLimit("creation source entries"));
        }
        let _entries = options.execution.memory.reserve(entry_bytes)?;
        let mut estimate = usize::try_from(options.recovery_count)
            .ok()
            .and_then(|n| n.checked_mul(128))
            .and_then(|n| n.checked_add(options.creator.len().checked_mul(4)?))
            .and_then(|n| n.checked_add(4096))
            .ok_or(EngineError::ResourceLimit("creation plan"))?;
        let mut source_bytes = 0u64;
        let mut snapshots = Vec::with_capacity(sources.len());
        for source in sources {
            validate_name(&source.name)?;
            let snapshot = access
                .snapshot(source.source)?
                .ok_or(EngineError::Unavailable {
                    source_id: source.source,
                    offset: 0,
                })?;
            let blocks = usize::try_from(snapshot.len.div_ceil(options.block_size))
                .map_err(|_| EngineError::ResourceLimit("creation blocks"))?;
            estimate = estimate
                .checked_add(
                    blocks
                        .checked_mul(1024)
                        .ok_or(EngineError::ResourceLimit("creation plan"))?,
                )
                .and_then(|n| n.checked_add(source.name.len().checked_mul(16)?))
                .and_then(|n| n.checked_add(2048))
                .ok_or(EngineError::ResourceLimit("creation plan"))?;
            source_bytes = source_bytes
                .checked_add(snapshot.len)
                .ok_or(EngineError::ResourceLimit("creation source size"))?;
            snapshots.push(snapshot);
        }
        if estimate > options.execution.retained_bytes {
            return Err(EngineError::ResourceLimit("retained creation plan"));
        }
        let reservation = options.execution.memory.reserve(estimate)?;
        let stripe = options.execution.stripe_bytes.min(64 << 10);
        let _scratch = options.execution.memory.reserve(stripe)?;
        let mut buffer = vec![0; stripe];
        let mut files = Vec::new();
        let mut blocks: Vec<Block> = Vec::new();
        let mut full = BTreeMap::<Fingerprint, u64>::new();
        let mut locators = BTreeMap::<u64, Vec<Fingerprint>>::new();
        let mut tails = BTreeMap::<(u64, Fingerprint), (u64, u64)>::new();
        let mut packing: Option<usize> = None;
        let mut reused = 0;
        let mut names = BTreeMap::new();
        for (source, snapshot) in sources.iter().zip(snapshots) {
            if names.insert(source.name.clone(), ()).is_some() {
                return Err(EngineError::InvalidState("duplicate creation path"));
            }
            let (fingerprint, _) = hash_range(
                access.as_ref(),
                source.source,
                snapshot,
                0,
                snapshot.len,
                &mut buffer,
                &options.execution,
            )?;
            let (_, quick_rolling_hash) = hash_range(
                access.as_ref(),
                source.source,
                snapshot,
                0,
                snapshot.len.min(16384),
                &mut buffer,
                &options.execution,
            )?;
            let mut chunks = Vec::new();
            let mut at = 0;
            while at < snapshot.len {
                options.execution.cancel.check()?;
                let mut length = (snapshot.len - at).min(options.block_size);
                if options.deduplication == Deduplication::Sliding
                    && length == options.block_size
                    && !locators.is_empty()
                    && let Some(shift) = find_shift(
                        access.as_ref(),
                        source.source,
                        snapshot,
                        at,
                        options.block_size,
                        &locators,
                        &options.execution,
                    )?
                    && shift != 0
                {
                    length = shift;
                }
                let piece = Piece {
                    source: source.source,
                    snapshot,
                    at,
                    length,
                    offset: 0,
                };
                if length == options.block_size {
                    let (hash, rolling_hash) = hash_range(
                        access.as_ref(),
                        source.source,
                        snapshot,
                        at,
                        length,
                        &mut buffer,
                        &options.execution,
                    )?;
                    let alias = (options.deduplication != Deduplication::None)
                        .then(|| full.get(&hash).copied())
                        .flatten();
                    let index = if let Some(index) = alias {
                        reused += 1;
                        index
                    } else {
                        let index = blocks.len() as u64;
                        blocks.push(Block {
                            pieces: vec![piece],
                            used: length,
                            checksum: Some(BlockChecksum {
                                fingerprint: hash,
                                rolling_hash,
                            }),
                        });
                        full.insert(hash, index);
                        locators.entry(rolling_hash).or_default().push(hash);
                        index
                    };
                    append_full(&mut chunks, index, options.block_size);
                } else if length < 40 {
                    let mut bytes = vec![0; length as usize];
                    read_exact_at(access.as_ref(), source.source, at, &mut bytes)?;
                    append_tail(
                        &mut chunks,
                        length,
                        ChunkTail::Inline(bytes),
                        options.block_size,
                    );
                } else {
                    let (hash, _) = hash_range(
                        access.as_ref(),
                        source.source,
                        snapshot,
                        at,
                        length,
                        &mut buffer,
                        &options.execution,
                    )?;
                    let (_, rolling_hash) = hash_range(
                        access.as_ref(),
                        source.source,
                        snapshot,
                        at,
                        40,
                        &mut buffer,
                        &options.execution,
                    )?;
                    let alias = (options.deduplication != Deduplication::None)
                        .then(|| tails.get(&(length, hash)).copied())
                        .flatten();
                    let (index, offset) = if let Some(alias) = alias {
                        alias
                    } else {
                        let index = packing
                            .filter(|index| options.block_size - blocks[*index].used >= length)
                            .unwrap_or_else(|| {
                                let index = blocks.len();
                                blocks.push(Block {
                                    pieces: Vec::new(),
                                    used: 0,
                                    checksum: None,
                                });
                                packing = Some(index);
                                index
                            });
                        let offset = blocks[index].used;
                        blocks[index].pieces.push(Piece { offset, ..piece });
                        blocks[index].used += length;
                        tails.insert((length, hash), (index as u64, offset));
                        (index as u64, offset)
                    };
                    append_tail(
                        &mut chunks,
                        length,
                        ChunkTail::Described {
                            rolling_hash,
                            fingerprint: hash,
                            block_index: index,
                            offset,
                        },
                        options.block_size,
                    );
                }
                at += length;
            }
            ensure_snapshot(access.as_ref(), source.source, snapshot)?;
            files.push(PlannedFile {
                name: source.name.clone(),
                source: source.source,
                snapshot,
                packet: FilePacket {
                    name: source
                        .name
                        .rsplit('/')
                        .next()
                        .expect("validated path")
                        .to_owned(),
                    quick_rolling_hash,
                    fingerprint,
                    option_hashes: Vec::new(),
                    chunks,
                },
            });
        }
        files.sort_by(|left, right| left.name.cmp(&right.name));
        for file in &files {
            let mut ancestor = parent(&file.name);
            while !ancestor.is_empty() {
                if names.contains_key(ancestor) {
                    return Err(EngineError::InvalidState(
                        "creation path is both a file and a directory",
                    ));
                }
                ancestor = parent(ancestor);
            }
        }
        let cohorts = match options.codec {
            CreationCodec::Cauchy => 1,
            CreationCodec::Fft { interleave, .. } => interleave
                .checked_add(1)
                .ok_or(EngineError::InvalidState("creation cohort overflow"))?,
        };
        let last = options
            .first_recovery
            .checked_add(options.recovery_count)
            .ok_or(EngineError::InvalidState(
                "creation recovery range overflow",
            ))?;
        let field = match options.codec {
            CreationCodec::Cauchy => {
                let total = (blocks.len() as u64)
                    .checked_add(last)
                    .ok_or(EngineError::InvalidState("Cauchy geometry overflow"))?;
                if total > 65536 {
                    return Err(EngineError::Unsupported("Cauchy geometry exceeds field"));
                }
                if blocks.is_empty() {
                    GaloisField {
                        size: 0,
                        generator: 0,
                    }
                } else if total <= 256 {
                    GaloisField {
                        size: 1,
                        generator: 0x1d,
                    }
                } else {
                    GaloisField {
                        size: 2,
                        generator: 0x100b,
                    }
                }
            }
            CreationCodec::Fft { capacity_log2, .. } => {
                let geometry =
                    FftGeometry::new((blocks.len() as u64).div_ceil(cohorts), capacity_log2)?;
                if last
                    > (geometry.capacity() as u64)
                        .checked_mul(cohorts)
                        .ok_or(EngineError::InvalidState("FFT capacity overflow"))?
                {
                    return Err(EngineError::InvalidState(
                        "requested recovery exceeds FFT capacity",
                    ));
                }
                GaloisField {
                    size: geometry.field_bytes() as u8,
                    generator: if geometry.field_bytes() == 1 {
                        0x1d
                    } else {
                        0x2d
                    },
                }
            }
        };
        if field.size == 2 && !options.block_size.is_multiple_of(2) {
            return Err(EngineError::InvalidState(
                "creation block is not field aligned",
            ));
        }
        if blocks.is_empty() && options.recovery_count != 0 {
            return Err(EngineError::InvalidState(
                "recovery requested for a set with no blocks",
            ));
        }
        let requirements = CreationRequirements {
            blocks: blocks.len() as u64,
            source_bytes,
            reused_blocks: reused,
            scratch_bytes: options
                .block_size
                .checked_mul(options.recovery_count)
                .ok_or(EngineError::ResourceLimit("recovery scratch size"))?,
            metadata_bytes: 0,
            output_sizes: Vec::new(),
            field,
            cohorts,
        };
        let mut plan = Self {
            access,
            options,
            files,
            blocks,
            metadata: Vec::new(),
            id: InputSetId::ZERO,
            root: [0; 16],
            matrix: [0; 16],
            volumes: Vec::new(),
            data_volumes: Vec::new(),
            requirements,
            _reservation: reservation,
        };
        plan.build_metadata()?;
        plan.plan_volumes()?;
        Ok(plan)
    }

    /// Exact metadata, volume and scratch requirements before writing.
    #[must_use]
    pub fn requirements(&self) -> &CreationRequirements {
        &self.requirements
    }

    /// Opaque identifier shared by every packet the plan will emit.
    #[must_use]
    pub fn input_set_id(&self) -> InputSetId {
        self.id
    }

    // Assemble a single embedded file from the original body and optional ZIP
    // footer views. The appended footer aliases its existing protected chunks.
    pub(crate) fn embedded_layout(&mut self) -> EngineResult<u64> {
        if self.options.codec != CreationCodec::Cauchy
            || self.options.store_data
            || self.options.recovery_count == 0
            || self.files.is_empty()
            || self.files.len() > 2
        {
            return Err(EngineError::Unsupported("embedded creation geometry"));
        }
        let footer = self
            .files
            .iter()
            .position(|file| file.source == SourceId(1))
            .map(|index| self.files.remove(index));
        if self.files.len() != 1 || self.files[0].source != SourceId(0) {
            return Err(EngineError::InvalidState("embedded source views"));
        }
        let duplicate = footer
            .as_ref()
            .map(|file| file.packet.chunks.clone())
            .unwrap_or_default();
        self.files[0]
            .packet
            .chunks
            .extend(duplicate.iter().cloned());
        let gap = self.files[0].packet.chunks.len();
        self.files[0]
            .packet
            .chunks
            .push(ChunkDescription::Unprotected { length: 1 });
        self.files[0].packet.chunks.extend(duplicate);
        self.files[0].packet.quick_rolling_hash = 0;
        self.files[0].packet.fingerprint = [0; 16];
        self.build_metadata()?;
        let metadata_size = self.requirements.metadata_bytes;
        let packet_bytes = self
            .options
            .block_size
            .checked_add(88)
            .and_then(|size| size.checked_mul(self.options.recovery_count))
            .and_then(|size| size.checked_add(metadata_size))
            .ok_or(EngineError::ResourceLimit("embedded packet bytes"))?;
        self.files[0].packet.chunks[gap] = ChunkDescription::Unprotected {
            length: packet_bytes,
        };
        let size = self.options.execution.stripe_bytes.min(64 << 10);
        let _memory = self.options.execution.memory.reserve(size)?;
        let mut buffer = vec![0; size];
        let mut hash = FingerprintHasher::new();
        let mut feed = |source: SourceId, snapshot: SourceSnapshot| -> EngineResult<()> {
            let mut at = 0;
            while at < snapshot.len {
                self.options.execution.cancel.check()?;
                let take = (snapshot.len - at).min(size as u64) as usize;
                read_exact_at(self.access.as_ref(), source, at, &mut buffer[..take])?;
                hash.update(&buffer[..take]);
                at += take as u64;
            }
            ensure_snapshot(self.access.as_ref(), source, snapshot)
        };
        feed(self.files[0].source, self.files[0].snapshot)?;
        if let Some(footer) = &footer {
            feed(footer.source, footer.snapshot)?;
        }
        // The reference concatenates protected chunks for the file hash.
        // Embedded packet bytes contribute neither bytes nor zero padding.
        if let Some(footer) = &footer {
            let mut at = 0;
            while at < footer.snapshot.len {
                self.options.execution.cancel.check()?;
                let take = (footer.snapshot.len - at).min(size as u64) as usize;
                read_exact_at(self.access.as_ref(), footer.source, at, &mut buffer[..take])?;
                hash.update(&buffer[..take]);
                at += take as u64;
            }
            ensure_snapshot(self.access.as_ref(), footer.source, footer.snapshot)?;
        }
        self.files[0].packet.fingerprint = hash.finalize();
        self.build_metadata()?;
        if self.requirements.metadata_bytes != metadata_size {
            return Err(EngineError::InvalidState(
                "embedded metadata length changed",
            ));
        }
        self.options.volumes = VolumeLayout::Uniform(self.options.recovery_count);
        self.volumes.clear();
        self.data_volumes.clear();
        self.requirements.output_sizes.clear();
        self.plan_volumes()?;
        self.requirements.source_bytes =
            self.files[0]
                .packet
                .chunks
                .iter()
                .try_fold(0u64, |total, chunk| {
                    total
                        .checked_add(chunk.length())
                        .ok_or(EngineError::ResourceLimit("embedded file length"))
                })?;
        Ok(packet_bytes)
    }

    /// Execute into explicit local output and scratch directories. Existing
    /// destinations are never replaced. Every carrier is staged and authenticated
    /// before installation; scratch storage is removed after success.
    pub fn execute(&self, stem: &Path, scratch_directory: &Path) -> EngineResult<Vec<PathBuf>> {
        self.options.execution.validate()?;
        if self.options.execution.open_handles < 3 {
            return Err(EngineError::ResourceLimit(
                "creation requires three open handles",
            ));
        }
        for file in &self.files {
            ensure_snapshot(self.access.as_ref(), file.source, file.snapshot)?;
        }
        let mut destinations = vec![suffix(stem, ".par3")];
        destinations.extend(
            self.volumes
                .iter()
                .map(|(first, count)| suffix(stem, &format!(".vol{first}+{count}.par3"))),
        );
        destinations.extend(
            self.data_volumes
                .iter()
                .map(|(first, count)| suffix(stem, &format!(".part{first}+{count}.par3"))),
        );
        for destination in &destinations {
            match std::fs::symlink_metadata(destination) {
                Ok(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        format!("output exists: {}", destination.display()),
                    )
                    .into());
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        let scratch_path =
            crate::session_repair::stage_path(&scratch_directory.join("recovery-spool"))?;
        let mut scratch = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&scratch_path)?;
        scratch.set_len(self.requirements.scratch_bytes)?;
        if self.options.recovery_count != 0 {
            match self.options.codec {
                CreationCodec::Cauchy => {
                    let _field = self.options.execution.memory.reserve(
                        if self.requirements.field.size == 2 {
                            512 << 10
                        } else {
                            4096
                        },
                    )?;
                    match crate::gf::for_set(&self.requirements.field)? {
                        crate::gf::AnyField::Gf8(field) => {
                            self.encode_cauchy(field, &mut scratch)?
                        }
                        crate::gf::AnyField::Gf16(field) => {
                            self.encode_cauchy(field, &mut scratch)?
                        }
                    }
                }
                CreationCodec::Fft { capacity_log2, .. } => {
                    let cohorts = self.requirements.cohorts;
                    let geometry = FftGeometry::new(
                        (self.blocks.len() as u64).div_ceil(cohorts),
                        capacity_log2,
                    )?;
                    let codec = FftCodec::new(geometry, self.options.execution.clone())?;
                    let end = self.options.first_recovery + self.options.recovery_count;
                    for cohort in 0..cohorts.min(self.options.recovery_count) {
                        let cohort = (cohort + self.options.first_recovery) % cohorts;
                        let first = self.options.first_recovery
                            + (cohort + cohorts - self.options.first_recovery % cohorts) % cohorts;
                        if first >= end {
                            continue;
                        }
                        let count = (end - first).div_ceil(cohorts);
                        codec.encode(
                            self.options.block_size,
                            (first / cohorts) as usize,
                            count as usize,
                            |index, offset, out| {
                                let global = cohort + index as u64 * cohorts;
                                if global >= self.blocks.len() as u64 {
                                    out.fill(0);
                                    Ok(())
                                } else {
                                    self.read_block(global as usize, offset, out)
                                }
                            },
                            |index, offset, bytes| {
                                let global = cohort + index as u64 * cohorts;
                                scratch.seek(SeekFrom::Start(
                                    (global - self.options.first_recovery)
                                        * self.options.block_size
                                        + offset,
                                ))?;
                                scratch.write_all(bytes)?;
                                Ok(())
                            },
                        )?;
                    }
                }
            }
        }
        scratch.sync_all()?;
        let mut staged = Vec::new();
        for (number, destination) in destinations.iter().enumerate() {
            self.options.execution.cancel.check()?;
            let temporary = crate::session_repair::stage_path(destination)?;
            let mut out = OpenOptions::new().write(true).open(&temporary)?;
            for packet in &self.metadata {
                out.write_all(packet)?;
            }
            if number > 0 && number <= self.volumes.len() {
                let (first, count) = self.volumes[number - 1];
                for index in first..first + count {
                    let mut prefix = Vec::with_capacity(40);
                    prefix.extend_from_slice(&self.root);
                    prefix.extend_from_slice(&self.matrix);
                    prefix.extend_from_slice(&index.to_le_bytes());
                    self.write_payload(
                        &mut out,
                        PacketType::RecoveryData,
                        &prefix,
                        |offset, bytes| {
                            scratch.seek(SeekFrom::Start(
                                (index - self.options.first_recovery) * self.options.block_size
                                    + offset,
                            ))?;
                            scratch.read_exact(bytes)?;
                            Ok(())
                        },
                    )?;
                }
            } else if number > self.volumes.len() {
                let (first, count) = self.data_volumes[number - self.volumes.len() - 1];
                for index in first..first + count {
                    self.write_payload(
                        &mut out,
                        PacketType::Data,
                        &index.to_le_bytes(),
                        |offset, bytes| self.read_block(index as usize, offset, bytes),
                    )?;
                }
            }
            out.sync_all()?;
            drop(out);
            if std::fs::metadata(&temporary)?.len() != self.requirements.output_sizes[number] {
                return Err(EngineError::InvalidState("creation size differs from plan"));
            }
            let mut source = crate::source::DiskSourceAccess::default();
            source.insert(SourceId(0), temporary.clone());
            let mut scanner = crate::ingest::PacketScanner::new(
                Arc::new(source),
                SourceId(0),
                self.options.execution.clone(),
                crate::ScanLimits::default(),
            )?;
            let mut authenticated_end = 0;
            loop {
                match scanner.poll()? {
                    crate::ingest::ScanEvent::Packet(packet) => {
                        let origin = packet.origin();
                        if origin.offset != authenticated_end || packet.input_set_id() != self.id {
                            return Err(EngineError::InvalidState(
                                "staged carrier has unauthenticated bytes",
                            ));
                        }
                        authenticated_end = origin
                            .offset
                            .checked_add(origin.length)
                            .ok_or(EngineError::ResourceLimit("staged carrier length"))?;
                    }
                    crate::ingest::ScanEvent::End => break,
                    crate::ingest::ScanEvent::NeedData { .. } => {
                        return Err(EngineError::InvalidState(
                            "created carrier has unavailable bytes",
                        ));
                    }
                }
            }
            if authenticated_end != self.requirements.output_sizes[number] {
                return Err(EngineError::InvalidState(
                    "staged carrier authentication is incomplete",
                ));
            }
            staged.push(temporary);
        }
        for file in &self.files {
            ensure_snapshot(self.access.as_ref(), file.source, file.snapshot)?;
        }
        for (temporary, destination) in staged.iter().zip(&destinations) {
            self.options.execution.cancel.check()?;
            std::fs::hard_link(temporary, destination)?;
            std::fs::remove_file(temporary)?;
        }
        drop(scratch);
        std::fs::remove_file(scratch_path)?;
        Ok(destinations)
    }

    fn read_block(&self, index: usize, offset: u64, out: &mut [u8]) -> EngineResult<()> {
        out.fill(0);
        for piece in &self.blocks[index].pieces {
            let start = offset.max(piece.offset);
            let end = (offset + out.len() as u64).min(piece.offset + piece.length);
            if start >= end {
                continue;
            }
            ensure_snapshot(self.access.as_ref(), piece.source, piece.snapshot)?;
            read_exact_at(
                self.access.as_ref(),
                piece.source,
                piece.at + start - piece.offset,
                &mut out[(start - offset) as usize..(end - offset) as usize],
            )?;
            ensure_snapshot(self.access.as_ref(), piece.source, piece.snapshot)?;
        }
        Ok(())
    }

    fn encode_cauchy<F: Field>(&self, field: F, scratch: &mut File) -> EngineResult<()> {
        let count = usize::try_from(self.options.recovery_count)
            .map_err(|_| EngineError::ResourceLimit("Cauchy output count"))?;
        let unit = F::SYMBOL_BYTES;
        let stripe = self
            .options
            .execution
            .stripe_bytes
            .min(64 << 10)
            .min(self.options.block_size as usize);
        let stripe = stripe / unit * unit;
        if stripe == 0 {
            return Err(EngineError::ResourceLimit("minimum Cauchy encoding stripe"));
        }
        let batch = count.min(
            self.options
                .execution
                .memory
                .available()
                .saturating_sub(stripe)
                / (stripe + 64),
        );
        if batch == 0 {
            return Err(EngineError::ResourceLimit("Cauchy encoding buffers"));
        }
        let _memory = self
            .options
            .execution
            .memory
            .reserve(batch * (stripe + 64) + stripe)?;
        let mut rows = vec![vec![0; stripe]; batch];
        let mut bytes = vec![0; stripe];
        for first in (0..count).step_by(batch) {
            let amount = batch.min(count - first);
            let mut offset = 0;
            while offset < self.options.block_size {
                let take = (self.options.block_size - offset).min(stripe as u64) as usize;
                for row in &mut rows[..amount] {
                    row.fill(0);
                }
                for block in 0..self.blocks.len() {
                    self.options.execution.cancel.check()?;
                    self.read_block(block, offset, &mut bytes[..take])?;
                    for (index, row) in rows[..amount].iter_mut().enumerate() {
                        let factor = crate::cauchy::element(
                            &field,
                            block as u64,
                            self.options.first_recovery + (first + index) as u64,
                        )?;
                        field.mul_acc(&mut row[..take], &bytes[..take], factor);
                    }
                }
                for (index, row) in rows[..amount].iter().enumerate() {
                    scratch.seek(SeekFrom::Start(
                        (first + index) as u64 * self.options.block_size + offset,
                    ))?;
                    scratch.write_all(&row[..take])?;
                }
                offset += take as u64;
            }
        }
        Ok(())
    }

    fn write_payload(
        &self,
        out: &mut File,
        kind: PacketType,
        prefix: &[u8],
        mut read: impl FnMut(u64, &mut [u8]) -> EngineResult<()>,
    ) -> EngineResult<()> {
        let size = self.options.execution.stripe_bytes.min(64 << 10);
        let _buffer = self.options.execution.memory.reserve(size + 512)?;
        let mut bytes = vec![0; size];
        let mut header = PacketHeader {
            hash: [0; 16],
            length: 48 + prefix.len() as u64 + self.options.block_size,
            input_set_id: self.id,
            packet_type: kind,
        };
        let mut encoded = Vec::with_capacity(48);
        header.write(&mut encoded);
        let mut hash = FingerprintHasher::new();
        hash.update(&encoded[24..]);
        hash.update(prefix);
        let mut offset = 0;
        while offset < self.options.block_size {
            self.options.execution.cancel.check()?;
            let take = (self.options.block_size - offset).min(size as u64) as usize;
            read(offset, &mut bytes[..take])?;
            hash.update(&bytes[..take]);
            offset += take as u64;
        }
        header.hash = hash.finalize();
        encoded.clear();
        header.write(&mut encoded);
        out.write_all(&encoded)?;
        out.write_all(prefix)?;
        let mut offset = 0;
        while offset < self.options.block_size {
            self.options.execution.cancel.check()?;
            let take = (self.options.block_size - offset).min(size as u64) as usize;
            read(offset, &mut bytes[..take])?;
            out.write_all(&bytes[..take])?;
            offset += take as u64;
        }
        Ok(())
    }

    fn build_metadata(&mut self) -> EngineResult<()> {
        let mut identity = FingerprintHasher::new();
        identity.update(&self.options.block_size.to_le_bytes());
        identity.update(&[self.requirements.field.size]);
        identity.update(&self.requirements.field.generator.to_le_bytes());
        for file in &self.files {
            identity.update(file.name.as_bytes());
            identity.update(
                &Packet::new(InputSetId::ZERO, PacketBody::File(file.packet.clone())).to_bytes(),
            );
        }
        self.id = InputSetId(identity.finalize()[..8].try_into().expect("eight bytes"));
        let mut packets = vec![
            Packet::new(
                self.id,
                PacketBody::Creator(CreatorPacket::new(&self.options.creator)),
            ),
            Packet::new(
                self.id,
                PacketBody::Start(StartPacket {
                    parent_input_set_id: InputSetId::ZERO,
                    parent_root_hash: [0; 16],
                    block_size: self.options.block_size,
                    galois_field: self.requirements.field,
                    legacy_random: None,
                }),
            ),
        ];
        if self.options.recovery_count != 0 {
            let body = match self.options.codec {
                CreationCodec::Cauchy => PacketBody::CauchyMatrix(CauchyMatrixPacket {
                    range: BlockRange { first: 0, end: 0 },
                    recovery_block_hint: 0,
                }),
                CreationCodec::Fft {
                    capacity_log2,
                    interleave,
                } => PacketBody::FftMatrix(FftMatrixPacket {
                    range: BlockRange { first: 0, end: 0 },
                    max_recovery_blocks_log2: capacity_log2,
                    interleave,
                    interleave_len: if interleave == 0 {
                        0
                    } else {
                        (64 - interleave.leading_zeros()).div_ceil(8) as u8
                    },
                }),
            };
            let packet = Packet::new(self.id, body);
            self.matrix = packet.hash();
            packets.push(packet);
        }
        let mut children: BTreeMap<String, Vec<Fingerprint>> = BTreeMap::new();
        for file in &self.files {
            let packet = Packet::new(self.id, PacketBody::File(file.packet.clone()));
            let parent = parent(&file.name);
            children
                .entry(parent.to_owned())
                .or_default()
                .push(packet.hash());
            packets.push(packet);
            let mut ancestor = parent;
            while !ancestor.is_empty() {
                children.entry(ancestor.to_owned()).or_default();
                ancestor = parent_of(ancestor);
            }
        }
        let mut directories: Vec<String> = children
            .keys()
            .filter(|name| !name.is_empty())
            .cloned()
            .collect();
        directories.sort_by_key(|name| std::cmp::Reverse(name.matches('/').count()));
        for directory in directories {
            let packet = Packet::new(
                self.id,
                PacketBody::Directory(DirectoryPacket {
                    name: directory.rsplit('/').next().expect("directory").to_owned(),
                    option_hashes: Vec::new(),
                    children: children.remove(&directory).unwrap_or_default(),
                }),
            );
            children
                .entry(parent(&directory).to_owned())
                .or_default()
                .push(packet.hash());
            packets.push(packet);
        }
        let root = Packet::new(
            self.id,
            PacketBody::Root(RootPacket {
                lowest_unused_block_index: self.blocks.len() as u64,
                attributes: 0,
                option_hashes: Vec::new(),
                children: children.remove("").unwrap_or_default(),
            }),
        );
        self.root = root.hash();
        packets.push(root);
        let mut start = 0;
        while start < self.blocks.len() {
            if self.blocks[start].checksum.is_none() {
                start += 1;
                continue;
            }
            let mut end = start + 1;
            while end < self.blocks.len() && self.blocks[end].checksum.is_some() {
                end += 1;
            }
            packets.push(Packet::new(
                self.id,
                PacketBody::ExternalData(ExternalDataPacket {
                    first_block_index: start as u64,
                    checksums: self.blocks[start..end]
                        .iter()
                        .map(|block| block.checksum.expect("full block"))
                        .collect(),
                }),
            ));
            start = end;
        }
        self.metadata = packets
            .into_iter()
            .map(|packet| packet.to_bytes())
            .collect();
        self.requirements.metadata_bytes =
            self.metadata.iter().map(|packet| packet.len() as u64).sum();
        Ok(())
    }

    fn plan_volumes(&mut self) -> EngineResult<()> {
        if let VolumeLayout::SizeLimited(bytes) = self.options.volumes
            && bytes < self.requirements.metadata_bytes
        {
            return Err(EngineError::ResourceLimit(
                "volume limit is smaller than metadata",
            ));
        }
        self.requirements
            .output_sizes
            .push(self.requirements.metadata_bytes);
        for (extra, mut first, mut remaining, volumes) in [
            (
                88,
                self.options.first_recovery,
                self.options.recovery_count,
                &mut self.volumes,
            ),
            (
                56,
                0,
                if self.options.store_data {
                    self.blocks.len() as u64
                } else {
                    0
                },
                &mut self.data_volumes,
            ),
        ] {
            let packet = self
                .options
                .block_size
                .checked_add(extra)
                .ok_or(EngineError::ResourceLimit("payload packet size"))?;
            let cap = match self.options.volumes {
                VolumeLayout::Variable => u64::MAX,
                VolumeLayout::Uniform(count) => count,
                VolumeLayout::SizeLimited(bytes) => {
                    bytes.saturating_sub(self.requirements.metadata_bytes) / packet
                }
            };
            if cap == 0 && remaining != 0 {
                return Err(EngineError::ResourceLimit(
                    "volume cannot hold one payload packet",
                ));
            }
            let mut growth = 1u64;
            while remaining != 0 {
                self.options.execution.cancel.check()?;
                let count = remaining.min(if self.options.volumes == VolumeLayout::Variable {
                    growth
                } else {
                    cap
                });
                volumes.push((first, count));
                self.requirements.output_sizes.push(
                    self.requirements
                        .metadata_bytes
                        .checked_add(
                            packet
                                .checked_mul(count)
                                .ok_or(EngineError::ResourceLimit("volume size"))?,
                        )
                        .ok_or(EngineError::ResourceLimit("volume size"))?,
                );
                first += count;
                remaining -= count;
                growth = growth.saturating_mul(2);
            }
        }
        Ok(())
    }
}

fn validate_name(name: &str) -> EngineResult<()> {
    if name.is_empty()
        || name.split('/').any(|part| {
            part.is_empty()
                || part == "."
                || part == ".."
                || part.contains(['\\', ':', '\0'])
                || part.len() > u16::MAX as usize
        })
    {
        return Err(EngineError::InvalidState("invalid creation path"));
    }
    Ok(())
}
fn suffix(stem: &Path, suffix: &str) -> PathBuf {
    let mut name = stem.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}
fn parent(name: &str) -> &str {
    name.rsplit_once('/').map_or("", |(parent, _)| parent)
}
fn parent_of(name: &str) -> &str {
    parent(name)
}
fn append_full(chunks: &mut Vec<ChunkDescription>, index: u64, size: u64) {
    if let Some(ChunkDescription::Protected {
        length,
        first_block_index: Some(first),
        tail: ChunkTail::None,
    }) = chunks.last_mut()
        && *first + *length / size == index
    {
        *length += size;
        return;
    }
    chunks.push(ChunkDescription::Protected {
        length: size,
        first_block_index: Some(index),
        tail: ChunkTail::None,
    });
}
fn append_tail(chunks: &mut Vec<ChunkDescription>, length: u64, tail: ChunkTail, size: u64) {
    if let Some(ChunkDescription::Protected {
        length: previous,
        tail: previous_tail,
        ..
    }) = chunks.last_mut()
        && previous.is_multiple_of(size)
        && matches!(previous_tail, ChunkTail::None)
    {
        *previous += length;
        *previous_tail = tail;
        return;
    }
    chunks.push(ChunkDescription::Protected {
        length,
        first_block_index: None,
        tail,
    });
}
fn find_shift(
    access: &dyn SourceAccess,
    source: SourceId,
    snapshot: SourceSnapshot,
    start: u64,
    size: u64,
    locators: &BTreeMap<u64, Vec<Fingerprint>>,
    options: &ExecutionOptions,
) -> EngineResult<Option<u64>> {
    use crate::placement::SlidingCrc;
    let window = usize::try_from(size)
        .map_err(|_| EngineError::ResourceLimit("sliding deduplication window"))?;
    let stripe = options.stripe_bytes.min(64 << 10);
    let _memory = options.memory.reserve(
        window
            .checked_add(stripe)
            .and_then(|n| n.checked_add(4096))
            .ok_or(EngineError::ResourceLimit("sliding deduplication buffers"))?,
    )?;
    let mut ring = vec![0; window];
    let mut input = vec![0; stripe];
    read_exact_at(access, source, start, &mut ring)?;
    let rolling = SlidingCrc::new(size);
    let mut state = SlidingCrc::raw(&ring);
    let maximum = (snapshot.len - start - size).min(size - 1);
    let mut shift = 0;
    let mut cursor = 0;
    let mut buffered = 0;
    let mut consumed = 0;
    loop {
        if let Some(hashes) = locators.get(&rolling.finish(state)) {
            let mut hash = FingerprintHasher::new();
            hash.update(&ring[cursor..]);
            hash.update(&ring[..cursor]);
            if hashes.contains(&hash.finalize()) {
                ensure_snapshot(access, source, snapshot)?;
                return Ok(Some(shift));
            }
        }
        if shift == maximum {
            break;
        }
        if consumed == buffered {
            options.cancel.check()?;
            buffered = (maximum - shift).min(stripe as u64) as usize;
            read_exact_at(access, source, start + size + shift, &mut input[..buffered])?;
            consumed = 0;
        }
        let byte = input[consumed];
        consumed += 1;
        state = rolling.advance(state, byte, ring[cursor]);
        ring[cursor] = byte;
        cursor = (cursor + 1) % window;
        shift += 1;
    }
    ensure_snapshot(access, source, snapshot)?;
    Ok(None)
}

fn hash_range(
    access: &dyn SourceAccess,
    source: SourceId,
    snapshot: SourceSnapshot,
    start: u64,
    length: u64,
    buffer: &mut [u8],
    options: &ExecutionOptions,
) -> EngineResult<(Fingerprint, u64)> {
    ensure_snapshot(access, source, snapshot)?;
    let mut hash = FingerprintHasher::new();
    let mut crc = RollingHasher::new();
    let mut offset = 0;
    while offset < length {
        options.cancel.check()?;
        let take = (length - offset).min(buffer.len() as u64) as usize;
        read_exact_at(access, source, start + offset, &mut buffer[..take])?;
        hash.update(&buffer[..take]);
        crc.update(&buffer[..take]);
        offset += take as u64;
    }
    ensure_snapshot(access, source, snapshot)?;
    Ok((hash.finalize(), crc.finalize()))
}
