//! Rebuilding lost input blocks, and writing the files that needed them.
//!
//! Two passes over the surviving data. The first feeds every input block that
//! still exists, plus the chosen recovery blocks, to the Cauchy decoder and
//! solves for the ones that do not; the second walks each damaged or missing
//! file's chunk descriptions and writes it out, taking each piece from the
//! original file where that piece survived and from a rebuilt block where it did
//! not. Neither pass holds a file: they hold one input block.

use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

use super::layout::{Layout, Region};
use super::{RepairLimits, RepairOptions, RepairPlan, RepairedFile, geometry_for, resolve};
use crate::cauchy::{CodecLimits, Decoder, Geometry, RecoveredBlock};
use crate::error::{Par3Error, Result};
use crate::gf::{AnyField, Gf8, Gf16, for_set};
use crate::packet::{ChunkDescription, ChunkTail, GaloisField};
use crate::repair_tree::{Destination, RepairTree};
use crate::set::Par3Set;
use crate::verify::{FileVerdict, verify_file_handle};

/// Rebuild every lost input block, keyed by index.
///
/// Returns an empty map when nothing was lost, without touching the codec: a
/// file may need rewriting for damage that costs no block at all, such as a
/// chunk tail short enough to live in its File packet.
pub(super) fn solve_lost_blocks(
    set: &Par3Set,
    base: &Path,
    layout: &Layout,
    plan: &RepairPlan,
    limits: &RepairLimits,
) -> Result<BTreeMap<u64, Vec<u8>>> {
    let lost = plan.lost_blocks();
    if lost.is_empty() {
        return Ok(BTreeMap::new());
    }

    let block_len = block_len(layout.block_size, limits)?;
    let geometry = geometry_for(set, plan.recovery_to_use())?;
    let mut decoder = AnyDecoder::new(
        set.galois_field(),
        geometry,
        lost,
        plan.recovery_to_use(),
        &limits.codec,
    )?;

    let mut pending = TailBlocks::new(block_len, limits.max_tail_buffer_bytes);
    let mut buffer = vec![0u8; block_len];

    for (index, file) in set.files().iter().enumerate() {
        let regions = &layout.per_file[index];
        // A file every one of whose blocks was lost — a missing one, above all —
        // has nothing to contribute, and must not be opened to find that out.
        if regions
            .iter()
            .all(|region| is_lost(lost, region.block_index))
        {
            continue;
        }
        let path = resolve(base, file.path());
        let mut handle = open(&path)?;
        for region in regions {
            if is_lost(lost, region.block_index) {
                continue;
            }
            let length = usize::try_from(region.length).expect("a region fits inside a block");
            read_at(
                &mut handle,
                &path,
                region.file_offset,
                &mut buffer[..length],
            )?;
            // A region that starts at the top of its block and is the only
            // writer of it *is* the block, short of the zero padding the decoder
            // supplies itself. Anything else — a packed tail block, or a lone
            // tail the packer put at an offset — has to be laid out first.
            if region.block_offset == 0 && layout.writers_of(region.block_index) == 1 {
                decoder.add_input_block(region.block_index, &buffer[..length])?;
            } else if let Some(block) = pending.fill(region, &buffer[..length], layout)? {
                decoder.add_input_block(region.block_index, &block)?;
            }
        }
    }
    pending.finish()?;

    // A recovery index is only unique within one matrix, so the row is looked up
    // against the matrix the plan chose rather than by index alone.
    let matrix = super::cauchy_matrix_hash(set)?;
    for index in plan.recovery_to_use() {
        let block = set
            .recovery_blocks()
            .iter()
            .find(|block| block.index() == *index && Some(block.matrix_hash()) == matrix)
            .ok_or_else(|| Par3Error::CodecBlock {
                index: *index,
                reason: "was chosen for the repair but is no longer in the set".to_string(),
            })?;
        decoder.add_recovery_block(*index, block.data())?;
    }

    Ok(decoder
        .solve()?
        .into_iter()
        .map(|block| (block.index(), block.into_data()))
        .collect())
}

/// Write back every file that was missing or damaged.
///
/// Each is built under a private staging directory, checked there through its
/// held file handle, and only then moved into place through the held root
/// capability. A rebuild that does not check out stays under its temporary name
/// and the file it was to replace is left where it is.
pub(super) fn write_files(
    set: &Par3Set,
    base: &Path,
    layout: &Layout,
    plan: &RepairPlan,
    recovered: &BTreeMap<u64, Vec<u8>>,
    options: &RepairOptions,
) -> Result<Vec<RepairedFile>> {
    let block_len = block_len(layout.block_size, &options.limits)?;
    let mut buffer = vec![0u8; block_len];
    let mut repaired = Vec::with_capacity(plan.files_to_rewrite().len());
    let tree = RepairTree::new(base, set.files().iter().map(|file| file.path()))
        .map_err(|source| io_error(base, source))?;
    refuse_aliased_destinations(&tree, set, plan, base)?;

    for (index, report) in plan.verify().files().iter().enumerate() {
        if report.verdict().is_complete() {
            continue;
        }
        let file = &set.files()[index];
        let target = tree
            .unresolved_destination(file.path())
            .map_err(|source| io_error(&resolve(base, file.path()), source))?;
        tree.check_existing_destination(&target)
            .map_err(|source| io_error(&target.display, source))?;
        let (stage_name, temporary, output) = tree
            .create_stage_file(index)
            .map_err(|source| io_error(base, source))?;
        build(
            file,
            &tree,
            &target,
            output,
            &temporary,
            layout,
            recovered,
            &mut buffer,
        )?;

        // Checking the rebuild before anything is moved is what makes a failed
        // repair cost nothing: the damaged file is still there, and the bytes
        // that did not add up are still there to be looked at.
        let staged = tree
            .open_stage_file(&stage_name, true, false)
            .map_err(|source| io_error(&temporary, source))?;
        let verified = verify_file_handle(set, file, staged)? == FileVerdict::Complete;
        let backup = if verified {
            tree.install_with_moved_backup(&stage_name, &target, options.backup)
                .map_err(|source| io_error(&target.display, source))?
        } else {
            None
        };

        repaired.push(RepairedFile {
            path: file.path().to_owned(),
            backup,
            verified,
        });
    }
    Ok(repaired)
}

fn destination_collision(
    set: &Par3Set,
    plan: &RepairPlan,
    key: fn(&str) -> String,
) -> Option<(usize, usize)> {
    let mut seen = HashMap::with_capacity(set.files().len());
    for (index, file) in set.files().iter().enumerate() {
        if let Some(first) = seen.insert(key(file.path()), index)
            && (!plan.verify().files()[first].verdict().is_complete()
                || !plan.verify().files()[index].verdict().is_complete())
        {
            return Some((first, index));
        }
    }
    None
}

fn collision_aliases(
    tree: &RepairTree,
    set: &Par3Set,
    collision: Option<(usize, usize)>,
    base: &Path,
) -> Result<bool> {
    let Some((first, second)) = collision else {
        return Ok(false);
    };
    tree.paths_alias(set.files()[first].path(), set.files()[second].path())
        .map_err(|source| io_error(base, source))
}

fn refuse_aliased_destinations(
    tree: &RepairTree,
    set: &Par3Set,
    plan: &RepairPlan,
    base: &Path,
) -> Result<()> {
    if destination_collision(set, plan, str::to_owned).is_some()
        || collision_aliases(
            tree,
            set,
            destination_collision(set, plan, crate::paths::case_folded),
            base,
        )?
        || collision_aliases(
            tree,
            set,
            destination_collision(set, plan, crate::repair_tree::normalization_key),
            base,
        )?
        || collision_aliases(
            tree,
            set,
            destination_collision(set, plan, crate::repair_tree::case_normalization_key),
            base,
        )?
    {
        return Err(Par3Error::UnrepairableSet {
            reason: "repair destinations resolve to the same filesystem path".into(),
        });
    }
    Ok(())
}

/// Write one file's bytes under `temporary`, from whatever survives and whatever
/// was rebuilt.
#[expect(
    clippy::too_many_arguments,
    reason = "the staging handles and rebuild inputs remain distinct security boundaries"
)]
fn build(
    file: &crate::set::Par3File,
    tree: &RepairTree,
    target: &Destination,
    output: File,
    temporary: &Path,
    layout: &Layout,
    recovered: &BTreeMap<u64, Vec<u8>>,
    buffer: &mut [u8],
) -> Result<()> {
    let block_size = layout.block_size;
    let mut source: Option<File> = None;
    let mut out = BufWriter::new(output);
    let mut offset: u64 = 0;

    for chunk in file.chunks() {
        let ChunkDescription::Protected {
            length,
            first_block_index,
            tail,
        } = chunk
        else {
            // The layout refuses a set with unprotected chunks long before this.
            unreachable!("a repairable set has only protected chunks");
        };

        let full_blocks = length / block_size;
        for step in 0..full_blocks {
            let index = first_block_index
                .expect("a chunk of a block or more names its first")
                .wrapping_add(step);
            let at = offset.saturating_add(step * block_size);
            let bytes = piece(
                &mut source,
                tree,
                target,
                recovered,
                index,
                0,
                block_size,
                at,
                buffer,
            )?;
            write_all(&mut out, temporary, bytes)?;
        }

        let tail_size = length % block_size;
        let at = offset.saturating_add(full_blocks * block_size);
        match tail {
            ChunkTail::None => {}
            ChunkTail::Inline(bytes) => write_all(&mut out, temporary, bytes)?,
            ChunkTail::Described {
                block_index,
                offset: block_offset,
                ..
            } => {
                let bytes = piece(
                    &mut source,
                    tree,
                    target,
                    recovered,
                    *block_index,
                    *block_offset,
                    tail_size,
                    at,
                    buffer,
                )?;
                write_all(&mut out, temporary, bytes)?;
            }
        }
        offset = offset.saturating_add(*length);
    }

    let mut out = out.into_inner().map_err(|error| Par3Error::FileIo {
        path: temporary.display().to_string(),
        source: error.into_error(),
    })?;
    out.flush().map_err(|source| Par3Error::FileIo {
        path: temporary.display().to_string(),
        source,
    })?;
    Ok(())
}

/// One stretch of a file: from the rebuilt block when that block was lost, and
/// from the file as it stands when it was not.
#[expect(
    clippy::too_many_arguments,
    reason = "every argument names one of the two places the bytes can come from"
)]
fn piece<'a>(
    source: &mut Option<File>,
    tree: &RepairTree,
    target: &Destination,
    recovered: &'a BTreeMap<u64, Vec<u8>>,
    block_index: u64,
    block_offset: u64,
    length: u64,
    file_offset: u64,
    buffer: &'a mut [u8],
) -> Result<&'a [u8]> {
    let length = usize::try_from(length).expect("a region fits inside a block");
    if let Some(block) = recovered.get(&block_index) {
        let start = usize::try_from(block_offset).expect("an offset inside a block");
        return block
            .get(start..start + length)
            .ok_or_else(|| Par3Error::UnrepairableSet {
                reason: format!(
                    "rebuilt input block {block_index} is {} bytes, too short for a chunk tail at \
                     {block_offset}",
                    block.len()
                ),
            });
    }
    let handle = match source {
        Some(handle) => handle,
        none => none.insert(
            tree.open_destination(target)
                .map_err(|source| io_error(&target.display, source))?,
        ),
    };
    read_at(handle, &target.display, file_offset, &mut buffer[..length])?;
    Ok(&buffer[..length])
}

/// The blocks of packed chunk tails that are still filling.
///
/// A block written by more than one file cannot go to the decoder until the last
/// of them has been read, so it waits here. What that costs depends on how the
/// tails were packed rather than on the size of the set, so it is metered.
struct TailBlocks {
    block_len: usize,
    open: BTreeMap<u64, (Vec<u8>, u32)>,
    budget: u64,
}

impl TailBlocks {
    fn new(block_len: usize, budget: u64) -> Self {
        Self {
            block_len,
            open: BTreeMap::new(),
            budget,
        }
    }

    /// Put one tail in its place, and hand back the block once it is whole.
    fn fill(&mut self, region: &Region, data: &[u8], layout: &Layout) -> Result<Option<Vec<u8>>> {
        if !self.open.contains_key(&region.block_index) {
            let held = (self.open.len() as u64 + 1).saturating_mul(self.block_len as u64);
            if held > self.budget {
                return Err(Par3Error::RepairLimitExceeded {
                    reason: format!(
                        "the blocks of packed chunk tails still filling would need more than the \
                         {} bytes the limits allow",
                        self.budget
                    ),
                });
            }
            // A tail block is zero-padded to the block size, and that padding is
            // part of what was encoded.
            self.open.insert(
                region.block_index,
                (
                    vec![0u8; self.block_len],
                    layout.writers_of(region.block_index),
                ),
            );
        }
        let (block, remaining) = self
            .open
            .get_mut(&region.block_index)
            .expect("just inserted");
        let at = usize::try_from(region.block_offset).expect("an offset inside a block");
        block[at..at + data.len()].copy_from_slice(data);
        *remaining = remaining.saturating_sub(1);
        if *remaining == 0 {
            let (block, _) = self.open.remove(&region.block_index).expect("just seen");
            return Ok(Some(block));
        }
        Ok(None)
    }

    fn finish(self) -> Result<()> {
        match self.open.keys().next() {
            None => Ok(()),
            Some(index) => Err(Par3Error::UnrepairableSet {
                reason: format!(
                    "input block {index} was not lost, but no surviving file supplies all of it"
                ),
            }),
        }
    }
}

/// The decoder for whichever field the set declared.
enum AnyDecoder {
    Gf8(Box<Decoder<Gf8>>),
    Gf16(Box<Decoder<Gf16>>),
}

impl AnyDecoder {
    fn new(
        field: GaloisField,
        geometry: Geometry,
        lost: &[u64],
        rows: &[u64],
        limits: &CodecLimits,
    ) -> Result<Self> {
        Ok(match for_set(&field)? {
            AnyField::Gf8(field) => Self::Gf8(Box::new(Decoder::with_limits(
                field, geometry, lost, rows, limits,
            )?)),
            AnyField::Gf16(field) => Self::Gf16(Box::new(Decoder::with_limits(
                field, geometry, lost, rows, limits,
            )?)),
        })
    }

    fn add_input_block(&mut self, index: u64, data: &[u8]) -> Result<()> {
        match self {
            Self::Gf8(decoder) => decoder.add_input_block(index, data),
            Self::Gf16(decoder) => decoder.add_input_block(index, data),
        }
    }

    fn add_recovery_block(&mut self, index: u64, data: &[u8]) -> Result<()> {
        match self {
            Self::Gf8(decoder) => decoder.add_recovery_block(index, data),
            Self::Gf16(decoder) => decoder.add_recovery_block(index, data),
        }
    }

    fn solve(self) -> Result<Vec<RecoveredBlock>> {
        match self {
            Self::Gf8(decoder) => decoder.solve(),
            Self::Gf16(decoder) => decoder.solve(),
        }
    }
}

/// One block's worth of buffer, refused rather than allocated when the set's
/// block size is beyond what the codec is allowed to hold anyway.
fn block_len(block_size: u64, limits: &RepairLimits) -> Result<usize> {
    if block_size > limits.codec.max_buffer_bytes {
        return Err(Par3Error::RepairLimitExceeded {
            reason: format!(
                "a block size of {block_size} bytes is over the {} byte codec budget",
                limits.codec.max_buffer_bytes
            ),
        });
    }
    usize::try_from(block_size).map_err(|_| Par3Error::RepairLimitExceeded {
        reason: format!("a block size of {block_size} bytes does not fit in memory"),
    })
}

fn is_lost(lost: &[u64], block: u64) -> bool {
    lost.binary_search(&block).is_ok()
}

fn open(path: &Path) -> Result<File> {
    File::open(path).map_err(|source| Par3Error::FileIo {
        path: path.display().to_string(),
        source,
    })
}

fn io_error(path: &Path, source: std::io::Error) -> Par3Error {
    Par3Error::FileIo {
        path: path.display().to_string(),
        source,
    }
}

fn read_at(handle: &mut File, path: &Path, at: u64, into: &mut [u8]) -> Result<()> {
    handle
        .seek(SeekFrom::Start(at))
        .and_then(|_| handle.read_exact(into))
        .map_err(|source| Par3Error::FileIo {
            path: path.display().to_string(),
            source,
        })
}

fn write_all(out: &mut BufWriter<File>, path: &Path, bytes: &[u8]) -> Result<()> {
    out.write_all(bytes).map_err(|source| Par3Error::FileIo {
        path: path.display().to_string(),
        source,
    })
}
