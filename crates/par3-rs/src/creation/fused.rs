//! Planning fused with the Cauchy encode.
//!
//! Without deduplication nothing in the block layout depends on a hash: every
//! full block, every packed tail and every inline tail follows from the
//! source sizes alone. So when the recovery rows fit the budget resident
//! beside a worker pool, the plan lays the blocks out first, then reads each
//! source once, front to back, and from the same bytes takes the planning
//! hashes and folds the blocks into the rows. `execute` then writes those rows instead of reading the sources a
//! second time to encode them.
//!
//! The walk differs from the serial one only in the order the arithmetic sees
//! the blocks: planning order instead of block order, a group of blocks at a
//! time across the whole block width instead of one stripe of every block at
//! a time. Recovery rows are sums over the blocks, so the order changes no
//! byte. The hashes are taken over the same bytes in the same order.

use super::*;

/// Blocks one pass over the rows folds. Every pass reads and writes each row
/// once, so a wider group costs fewer passes, but 32 and 64 measured no
/// faster than 16 and held two and four times the group buffers.
const MAX_GROUP: usize = 16;

/// Bytes of source a tile of every active block should come to, so a tile's
/// sources stay cache-resident while every row folds them.
const TILE_SOURCE_BYTES: usize = 512 << 10;

/// Where one region of a source file goes.
#[derive(Clone, Copy)]
pub(super) enum Kind {
    /// A whole block, by index.
    Full(usize),
    /// A tail packed into a block at an offset.
    Tail { block: usize, offset: u64 },
    /// A tail short enough to be stored inline in the chunk description.
    Inline,
}

/// One chunk of a source file, in the order the walk reads it.
#[derive(Clone, Copy)]
pub(super) struct Region {
    at: u64,
    length: u64,
    kind: Kind,
}

/// A source file in planning order, with the regions it reads.
pub(super) struct Laid {
    regions: Vec<Region>,
}

/// The decided shape of a fused walk.
struct Admitted {
    group: usize,
    sets: usize,
}

/// Lay out the blocks of `sources` in planning order without reading a byte,
/// exactly as the serial walk lays them out without deduplication. Hashes and
/// inline bytes are placeholders, filled in by the walk.
pub(super) fn layout(
    sources: &[CreationSource],
    order: &[usize],
    snapshots: &[SourceSnapshot],
    options: &CreationOptions,
    names: &mut BTreeMap<String, ()>,
) -> EngineResult<(Vec<Laid>, Vec<PlannedFile>, Vec<Block>)> {
    let block_size = options.block_size;
    let mut laid = Vec::with_capacity(order.len());
    let mut files = Vec::with_capacity(order.len());
    let mut blocks: Vec<Block> = Vec::new();
    let mut packing = TailSlots::default();
    for &index in order {
        let (source, snapshot) = (&sources[index], snapshots[index]);
        if names.insert(source.name.clone(), ()).is_some() {
            return Err(EngineError::InvalidState("duplicate creation path"));
        }
        let mut chunks = Vec::new();
        let mut regions = Vec::new();
        let mut at = 0;
        while at < snapshot.len {
            options.execution.cancel.check()?;
            let length = (snapshot.len - at).min(block_size);
            let piece = Piece {
                source: source.source,
                snapshot,
                at,
                length,
                offset: 0,
            };
            let kind = if length == block_size {
                let block = blocks.len();
                blocks.push(Block {
                    pieces: vec![piece],
                    used: length,
                    checksum: Some(BlockChecksum {
                        fingerprint: [0; 16],
                        rolling_hash: 0,
                    }),
                });
                append_full(&mut chunks, block as u64, block_size);
                Kind::Full(block)
            } else if length < TAIL_HASH_LEN as u64 {
                append_tail(
                    &mut chunks,
                    length,
                    ChunkTail::Inline(Vec::new()),
                    block_size,
                );
                Kind::Inline
            } else {
                let block = packing.take(length).unwrap_or_else(|| {
                    blocks.push(Block {
                        pieces: Vec::new(),
                        used: 0,
                        checksum: None,
                    });
                    blocks.len() - 1
                });
                let offset = blocks[block].used;
                blocks[block].pieces.push(Piece { offset, ..piece });
                blocks[block].used += length;
                packing.place(block, block_size - blocks[block].used);
                append_tail(
                    &mut chunks,
                    length,
                    ChunkTail::Described {
                        rolling_hash: 0,
                        fingerprint: [0; 16],
                        block_index: block as u64,
                        offset,
                    },
                    block_size,
                );
                Kind::Tail { block, offset }
            };
            regions.push(Region { at, length, kind });
            at += length;
        }
        laid.push(Laid { regions });
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
                // An empty file is read by no region; its hashes are of
                // nothing, as the serial walk leaves them.
                quick_rolling_hash: RollingHasher::new().finalize(),
                fingerprint: FingerprintHasher::new().finalize(),
                option_hashes: Vec::new(),
                chunks,
            },
        });
    }
    Ok((laid, files, blocks))
}

/// Admit a group of blocks, with a second set of group buffers for reading
/// ahead where it fits, beside the resident rows, the field, the carrier
/// stage `execute` will still need while the rows are held, and a full pool.
/// The fold passes over every row once per group, where the serial encode
/// keeps a stripe of each row in cache across all the blocks; only a pool
/// repays that, so one worker, or a budget with no room for the pool and one
/// set, falls back to the serial walk and the encode reads the sources again.
fn admit(plan: &CreationPlan) -> Option<Admitted> {
    let execution = &plan.options.execution;
    if execution.workers < 2 {
        return None;
    }
    let block = usize::try_from(plan.options.block_size).ok()?;
    let rows = usize::try_from(plan.requirements.scratch_bytes).ok()?;
    let count = usize::try_from(plan.options.recovery_count).ok()?;
    let blocks = plan.blocks.len().max(1);
    let fixed = rows
        .checked_add(crate::gf::construction_cost(&plan.requirements.field))?
        .checked_add(plan.carrier_stage_bytes())?
        .checked_add(crate::runtime::SOURCE_GROUP_SLACK)?;
    let need = |group: usize, sets: usize| -> Option<usize> {
        fixed
            .checked_add(sets.checked_mul(group)?.checked_mul(block)?)?
            .checked_add(count.checked_mul(group)?.checked_mul(2)?)
    };
    let pool = |group: usize| {
        crate::runtime::WorkerPool::unnarrowed_bytes(
            execution,
            count.saturating_mul(group).saturating_mul(block) >> 20,
        )
    };
    let available = execution.memory.available();
    let group = MAX_GROUP.min(blocks);
    for sets in [2, 1] {
        let Some(bytes) = need(group, sets) else {
            continue;
        };
        if bytes.saturating_add(pool(group)) <= available {
            return Some(Admitted { group, sets });
        }
    }
    None
}

/// What a fused plan hands back when the budget has no room for it: the
/// options and the plan's reservation, for the serial walk to use instead.
pub(super) struct Declined {
    pub(super) options: CreationOptions,
    pub(super) reservation: Reservation,
}

impl CreationPlan {
    /// Plan with the encode fused into the planning read, or decline and
    /// return what the serial walk needs. The caller has checked that
    /// deduplication is off, the codec is Cauchy and recovery is requested.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn build_fused(
        access: Arc<dyn SourceAccess>,
        sources: &[CreationSource],
        order: &[usize],
        snapshots: &[SourceSnapshot],
        options: CreationOptions,
        source_bytes: u64,
        reservation: Reservation,
    ) -> EngineResult<Result<Self, Declined>> {
        let mut names = BTreeMap::new();
        let (laid, files, blocks) = layout(sources, order, snapshots, &options, &mut names)?;
        // The metadata built from placeholder hashes has every packet's real
        // length, which is all the carrier stage's admission reads.
        let mut plan = Self::finish(
            access,
            options,
            files,
            blocks,
            0,
            source_bytes,
            &names,
            reservation,
        )?;
        let Some(admitted) = admit(&plan) else {
            let Self {
                options,
                _reservation: reservation,
                ..
            } = plan;
            return Ok(Err(Declined {
                options,
                reservation,
            }));
        };
        let execution = plan.options.execution.clone();
        let _field = execution.memory.reserve_as(
            MemoryCategory::CodecTables,
            crate::gf::construction_cost(&plan.requirements.field),
        )?;
        let rows = match crate::gf::for_set(&plan.requirements.field)? {
            crate::gf::AnyField::Gf8(field) => plan.walk(field, &laid, &admitted)?,
            crate::gf::AnyField::Gf16(field) => plan.walk(field, &laid, &admitted)?,
        };
        plan.requirements.output_sizes.clear();
        plan.volumes.clear();
        plan.data_volumes.clear();
        plan.build_metadata()?;
        plan.plan_volumes()?;
        *plan
            .encoded
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(rows);
        tracing::debug!(
            group = admitted.group,
            sets = admitted.sets,
            "PAR3 creation planning fused with the encode"
        );
        Ok(Ok(plan))
    }

    /// Read every source once in planning order, filling in the plan's hashes
    /// and inline tails and folding each group of blocks into resident rows.
    fn walk<F: MulAccBatch<Symbol: Sync> + Sync>(
        &mut self,
        field: F,
        laid: &[Laid],
        admitted: &Admitted,
    ) -> EngineResult<RecoverySpool> {
        let execution = self.options.execution.clone();
        let block = self.options.block_size as usize;
        let count = self.options.recovery_count as usize;
        let rows_reservation = execution
            .memory
            .reserve_as(MemoryCategory::OutputStaging, count * block)?;
        let mut scratch = execution.memory.reserve_as(
            MemoryCategory::SourceScratch,
            admitted.sets * admitted.group * block,
        )?;
        let _factors = execution.memory.reserve_as(
            MemoryCategory::CodecScratch,
            count * admitted.group * std::mem::size_of::<F::Symbol>(),
        )?;
        let pool = crate::runtime::WorkerPool::for_work(
            &execution,
            count.saturating_mul(admitted.group).saturating_mul(block) >> 20,
            crate::runtime::SOURCE_GROUP_SLACK,
        )?;
        // Reading ahead needs a pool to hash and fold beside the reads; on
        // the calling thread alone the second set would only sit there.
        let sets_wanted = if pool.is_some() { admitted.sets } else { 1 };
        scratch.shrink_to(sets_wanted * admitted.group * block);
        let mut rows = vec![0u8; count * block];
        let mut sets: Vec<Set> = (0..sets_wanted)
            .map(|_| Set {
                slots: vec![vec![0; block]; admitted.group],
                items: Vec::new(),
            })
            .collect();
        let access = self.access.clone();
        let identities: Vec<(SourceId, SourceSnapshot)> = self
            .files
            .iter()
            .map(|file| (file.source, file.snapshot))
            .collect();
        let mut reader = Reader {
            access: access.as_ref(),
            files: &identities,
            laid,
            options: &execution,
            unit: F::SYMBOL_BYTES as u64,
            block: self.options.block_size,
            group: admitted.group,
            file: 0,
            region: 0,
            forward: None,
        };
        let mut hashes = Hashes {
            file: None,
            done: Vec::new(),
        };
        let fold = Fold {
            field: &field,
            block,
            first: self.options.first_recovery,
            unit: F::SYMBOL_BYTES,
        };
        let mut verify = execution.stage(crate::runtime::Stage::Verify)?;
        let mut encode = execution.stage(crate::runtime::Stage::Encode)?;
        let mut current = 0;
        // Whether regions remain unread after the sets filled so far.
        let mut pending = reader.fill(&mut sets[0])?;
        let mut outcomes = Vec::new();
        loop {
            execution.cancel.check()?;
            let other = (current + 1) % sets.len();
            let overlap = pending && other != current;
            let (now, next) = if current == 0 {
                let (low, high) = sets.split_at_mut(1);
                (&low[0], high.first_mut())
            } else {
                let (low, high) = sets.split_at_mut(1);
                (&high[0], Some(&mut low[0]))
            };
            let mut processed = None;
            let mut filled = None;
            match &pool {
                // The pool hashes and folds this set while the calling
                // thread reads the next one into the other.
                Some(pool) => pool.pool().in_place_scope(|scope| {
                    scope.spawn(|_| {
                        processed = Some(process(now, &mut hashes, &mut rows, &fold, laid, true));
                    });
                    if overlap && let Some(next) = next {
                        filled = Some(reader.fill(next));
                    }
                }),
                None => {
                    processed = Some(process(now, &mut hashes, &mut rows, &fold, laid, false));
                }
            }
            let (bytes, results) = processed.expect("processed set")?;
            verify.advance(bytes);
            encode.advance(bytes);
            outcomes.clear();
            outcomes.extend(
                now.items
                    .iter()
                    .zip(results)
                    .map(|(item, result)| (item.file, item.region, result, item.inline.clone())),
            );
            self.apply(&outcomes, &mut hashes.done, laid);
            if let Some(result) = filled {
                pending = result?;
                current = other;
            } else if pending {
                pending = reader.fill(&mut sets[current])?;
            } else {
                break;
            }
        }
        drop(sets);
        Ok(RecoverySpool::Memory {
            rows,
            _reservation: rows_reservation,
        })
    }

    /// Record what one processed set produced: block checksums, tail
    /// descriptions, inline bytes, and the hashes of the files it finished.
    #[allow(clippy::type_complexity)]
    fn apply(
        &mut self,
        outcomes: &[(usize, usize, Option<(Fingerprint, u64)>, Vec<u8>)],
        done: &mut Vec<(usize, Fingerprint, u64)>,
        laid: &[Laid],
    ) {
        for (file, region, result, inline) in outcomes {
            let region = laid[*file].regions[*region];
            match (region.kind, result) {
                (Kind::Full(block), Some((fingerprint, rolling_hash))) => {
                    self.blocks[block].checksum = Some(BlockChecksum {
                        fingerprint: *fingerprint,
                        rolling_hash: *rolling_hash,
                    });
                }
                (Kind::Tail { .. }, Some((hash, crc))) => {
                    if let Some(ChunkDescription::Protected {
                        tail:
                            ChunkTail::Described {
                                rolling_hash,
                                fingerprint,
                                ..
                            },
                        ..
                    }) = self.files[*file].packet.chunks.last_mut()
                    {
                        *rolling_hash = *crc;
                        *fingerprint = *hash;
                    }
                }
                (Kind::Inline, _) => {
                    if let Some(ChunkDescription::Protected {
                        tail: ChunkTail::Inline(bytes),
                        ..
                    }) = self.files[*file].packet.chunks.last_mut()
                    {
                        bytes.clone_from(inline);
                    }
                }
                _ => {}
            }
        }
        for (file, fingerprint, quick) in done.drain(..) {
            self.files[file].packet.fingerprint = fingerprint;
            self.files[file].packet.quick_rolling_hash = quick;
        }
    }
}

/// One region read into a set: a block-sized slot for blocks and packed
/// tails, or its bytes for an inline tail.
struct Item {
    file: usize,
    region: usize,
    slot: Option<usize>,
    /// The region's bytes within its slot.
    bytes: std::ops::Range<usize>,
    /// The block and the unit-aligned columns the slot contributes to it.
    block: usize,
    columns: std::ops::Range<usize>,
    inline: Vec<u8>,
}

/// One group's buffers and the regions read into them.
struct Set {
    slots: Vec<Vec<u8>>,
    items: Vec<Item>,
}

/// The calling thread's side of the walk: the forward reader and its place.
struct Reader<'a> {
    access: &'a dyn SourceAccess,
    /// Each file's source and snapshot, in planning order.
    files: &'a [(SourceId, SourceSnapshot)],
    laid: &'a [Laid],
    options: &'a ExecutionOptions,
    unit: u64,
    block: u64,
    group: usize,
    file: usize,
    region: usize,
    forward: Option<Box<dyn Read + Send>>,
}

impl Reader<'_> {
    /// Read the next regions into `set` until its slots are used or the
    /// sources end. Each file is checked against its snapshot once its last
    /// region is read, as the serial walk checks it after its last chunk.
    /// Returns whether regions remain.
    fn fill(&mut self, set: &mut Set) -> EngineResult<bool> {
        set.items.clear();
        let mut used = 0;
        let (files, laid) = (self.files, self.laid);
        while self.file < laid.len() {
            let file = &files[self.file];
            let regions = &laid[self.file].regions;
            if self.region == regions.len() {
                // An empty file has nothing to read; any other was read up
                // to here already.
                self.forward = None;
                ensure_snapshot(self.access, file.0, file.1)?;
                self.file += 1;
                self.region = 0;
                continue;
            }
            let region = regions[self.region];
            let slotted = !matches!(region.kind, Kind::Inline);
            if (slotted && used == self.group) || set.items.len() == 2 * self.group {
                break;
            }
            self.options.cancel.check()?;
            if self.region == 0 {
                self.forward = self.access.open_sequential(file.0)?;
            }
            let length = region.length as usize;
            let (slot, bytes, block, columns, inline) = match region.kind {
                Kind::Full(block) => (Some(used), 0..length, block, 0..length, Vec::new()),
                Kind::Tail { block, offset } => {
                    let start = offset as usize;
                    let low = (offset / self.unit * self.unit) as usize;
                    let high = (offset + region.length).div_ceil(self.unit) * self.unit;
                    let high = high.min(self.block) as usize;
                    (
                        Some(used),
                        start..start + length,
                        block,
                        low..high,
                        Vec::new(),
                    )
                }
                Kind::Inline => (None, 0..length, 0, 0..0, vec![0; length]),
            };
            let item = Item {
                file: self.file,
                region: self.region,
                slot,
                bytes: bytes.clone(),
                block,
                columns: columns.clone(),
                inline,
            };
            set.items.push(item);
            let item = set.items.last_mut().expect("pushed");
            let out = match slot {
                Some(slot) => {
                    let buffer = &mut set.slots[slot];
                    // A packed tail's unit-aligned columns beyond its own
                    // bytes are zero, as the block's padding is.
                    buffer[columns.start..bytes.start].fill(0);
                    buffer[bytes.end..columns.end].fill(0);
                    &mut buffer[bytes]
                }
                None => item.inline.as_mut_slice(),
            };
            if let Err(error) = fetch(
                self.access,
                file.0,
                self.options,
                &mut self.forward,
                region.at,
                out,
            ) {
                ensure_snapshot(self.access, file.0, file.1)?;
                return Err(error);
            }
            used += slotted as usize;
            self.region += 1;
            if self.region == regions.len() {
                self.forward = None;
                ensure_snapshot(self.access, file.0, file.1)?;
                self.file += 1;
                self.region = 0;
            }
        }
        Ok(self.file < laid.len())
    }
}

/// The file hash in progress, carried from set to set because a file's
/// regions are contiguous in the walk, and the files finished so far.
struct Hashes {
    /// File index, its fingerprint and quick hashers.
    file: Option<(usize, FingerprintHasher, RollingHasher)>,
    /// Finished files: index, fingerprint, quick rolling hash.
    done: Vec<(usize, Fingerprint, u64)>,
}

impl Hashes {
    /// Feed one region, in file order, finishing the file at its last.
    fn feed(&mut self, file: usize, region: Region, bytes: &[u8], last: bool, parallel: bool) {
        if self.file.as_ref().is_none_or(|(index, ..)| *index != file) {
            self.file = Some((file, FingerprintHasher::new(), RollingHasher::new()));
        }
        let (_, hash, quick) = self.file.as_mut().expect("file hash");
        hash.update_admitted(bytes, parallel);
        let take = (QUICK_HASH_LEN as u64)
            .saturating_sub(region.at)
            .min(bytes.len() as u64) as usize;
        quick.update(&bytes[..take]);
        if last {
            let (index, hash, quick) = self.file.take().expect("file hash");
            self.done.push((index, hash.finalize(), quick.finalize()));
        }
    }
}

/// The bytes `item` read: in its slot, or inline.
fn bytes_of<'s>(set: &'s Set, item: &'s Item) -> &'s [u8] {
    match item.slot {
        Some(slot) => &set.slots[slot][item.bytes.clone()],
        None => &item.inline,
    }
}

/// The arithmetic shared by every set.
struct Fold<'a, F> {
    field: &'a F,
    block: usize,
    first: u64,
    unit: usize,
}

/// Hash and fold one set: the file hashes in order, each slot's block or tail
/// hash, and every slot into every row. Returns the bytes read into the set
/// and each item's `(fingerprint, rolling hash)` where it has one.
#[allow(clippy::type_complexity)]
fn process<F: MulAccBatch<Symbol: Sync> + Sync>(
    set: &Set,
    hashes: &mut Hashes,
    rows: &mut [u8],
    fold: &Fold<'_, F>,
    laid: &[Laid],
    parallel: bool,
) -> EngineResult<(u64, Vec<Option<(Fingerprint, u64)>>)> {
    use rayon::prelude::*;
    let total = set.items.iter().map(|item| item.bytes.len() as u64).sum();
    let file_hashes = |hashes: &mut Hashes| {
        for item in &set.items {
            let regions = &laid[item.file].regions;
            hashes.feed(
                item.file,
                regions[item.region],
                bytes_of(set, item),
                item.region + 1 == regions.len(),
                parallel,
            );
        }
    };
    let block_hash = |item: &Item| -> Option<(Fingerprint, u64)> {
        item.slot?;
        let bytes = bytes_of(set, item);
        let full = matches!(laid[item.file].regions[item.region].kind, Kind::Full(_));
        let mut hash = FingerprintHasher::new();
        hash.update(bytes);
        let mut crc = RollingHasher::new();
        crc.update(if full { bytes } else { &bytes[..TAIL_HASH_LEN] });
        Some((hash.finalize(), crc.finalize()))
    };
    let mut results = Vec::new();
    let mut folded = Ok(());
    if parallel {
        rayon::join(
            || file_hashes(hashes),
            || {
                rayon::join(
                    || results.par_extend(set.items.par_iter().map(block_hash)),
                    || folded = fold_set(set, rows, fold, true),
                )
            },
        );
    } else {
        file_hashes(hashes);
        results.extend(set.items.iter().map(block_hash));
        folded = fold_set(set, rows, fold, false);
    }
    folded?;
    Ok((total, results))
}

/// Fold every slot of `set` into every row: `row ^= factor(block, row) *
/// slot` over the columns the slot covers. The columns are cut where any
/// slot starts or stops, so every cut has one set of sources, and each cut
/// is tiled so its sources stay in cache while the rows pass over them.
fn fold_set<F: MulAccBatch<Symbol: Sync> + Sync>(
    set: &Set,
    rows: &mut [u8],
    fold: &Fold<'_, F>,
    parallel: bool,
) -> EngineResult<()> {
    use rayon::prelude::*;
    let sources: Vec<&Item> = set
        .items
        .iter()
        .filter(|item| item.slot.is_some())
        .collect();
    if sources.is_empty() {
        return Ok(());
    }
    let count = rows.len() / fold.block;
    // factors[row * sources + k]
    let mut factors = Vec::with_capacity(count * sources.len());
    for row in 0..count as u64 {
        for source in &sources {
            factors.push(crate::cauchy::element(
                fold.field,
                source.block as u64,
                fold.first + row,
            )?);
        }
    }
    let mut cuts: Vec<usize> = sources
        .iter()
        .flat_map(|source| [source.columns.start, source.columns.end])
        .collect();
    cuts.sort_unstable();
    cuts.dedup();
    for window in cuts.windows(2) {
        let (start, end) = (window[0], window[1]);
        let active: Vec<usize> = (0..sources.len())
            .filter(|&k| sources[k].columns.start <= start && sources[k].columns.end >= end)
            .collect();
        if active.is_empty() {
            continue;
        }
        let tile = (TILE_SOURCE_BYTES / active.len())
            .next_power_of_two()
            .clamp(4 << 10, 64 << 10)
            / fold.unit
            * fold.unit;
        let mut at = start;
        while at < end {
            let stop = (at + tile).min(end);
            let mut inputs: [&[u8]; MAX_GROUP] = [&[]; MAX_GROUP];
            for (input, &k) in inputs.iter_mut().zip(&active) {
                let slot = sources[k].slot.expect("slotted");
                *input = &set.slots[slot][at..stop];
            }
            let inputs = &inputs[..active.len()];
            let apply = |(row, out): (usize, &mut [u8])| {
                let mut chosen = [F::Symbol::default(); MAX_GROUP];
                for (factor, &k) in chosen.iter_mut().zip(&active) {
                    *factor = factors[row * sources.len() + k];
                }
                let out = &mut out[at..stop];
                if let [input] = inputs {
                    fold.field.mul_acc(out, input, chosen[0]);
                } else {
                    fold.field
                        .mul_acc_batch(out, inputs, &chosen[..active.len()]);
                }
            };
            if parallel {
                rows.par_chunks_mut(fold.block).enumerate().for_each(apply);
            } else {
                rows.chunks_mut(fold.block).enumerate().for_each(apply);
            }
            at = stop;
        }
    }
    Ok(())
}
