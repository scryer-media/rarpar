//! Putting a set's protected files back from whatever survives.
//!
//! [`repair_set`] verifies the files a set describes, works out which input
//! blocks were lost, rebuilds them from the recovery blocks the set carries, and
//! writes each missing or damaged file back. Files that verify complete are
//! never touched — not rewritten, not renamed, not opened for writing.
//!
//! Everything streams. A file is read a block at a time and written a block at a
//! time; the peak cost is the lost blocks themselves, which the codec has to
//! hold, plus the input blocks still waiting for a chunk tail. Nothing is
//! proportional to the size of a file.
//!
//! ```no_run
//! use par3_rs::repair::{RepairOptions, repair_set};
//! use par3_rs::{Par3Set, scan_packets_from_path};
//! use std::path::Path;
//!
//! # fn main() -> par3_rs::Result<()> {
//! let packets = scan_packets_from_path(Path::new("archive.par3"))?
//!     .into_iter()
//!     .map(|(_offset, packet)| packet)
//!     .collect();
//! let set = &Par3Set::from_packets(packets)?[0];
//!
//! let report = repair_set(set, Path::new("."), &RepairOptions::default())?;
//! for file in report.repaired() {
//!     println!("rebuilt {} ({})", file.path(), if file.verified() { "good" } else { "still wrong" });
//! }
//! assert!(report.verify_after().is_complete());
//! # Ok(())
//! # }
//! ```
//!
//! # What it does not do
//!
//! A file whose bytes are all present but at the wrong offset — content inserted
//! or removed rather than overwritten — is rebuilt from recovery data like any
//! other damage, because finding the moved bytes needs the sliding rolling-hash
//! search this crate does not implement. A file that has been renamed or moved
//! counts as missing, and the file that replaced it is not looked at. Damaged
//! recovery volumes are not themselves repaired: a recovery block that does not
//! parse is simply not available. And recovery data computed with anything but a
//! Cauchy matrix is refused, because nothing here can interpret it.

mod layout;
mod rebuild;

use std::path::{Path, PathBuf};

use layout::Layout;

use crate::cauchy::{CodecLimits, Geometry};
use crate::error::{Par3Error, Result};
use crate::hash::Fingerprint;
use crate::packet::PacketBody;
use crate::set::Par3Set;
use crate::verify::{FileVerdict, VerifyReport, verify_set};

/// Bounds on what a repair may allocate, and on how large a set it will work on.
///
/// A repair sizes its buffers from numbers a `.par3` file chose — the block
/// size, the block count, how many tails share a block — so they are metered
/// rather than trusted, the same way [`ScanLimits`](crate::scan::ScanLimits),
/// [`SetLimits`](crate::set::SetLimits) and
/// [`CreateLimits`](crate::create::CreateLimits) meter theirs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RepairLimits {
    /// Bounds on the decoder, which holds one syndrome per lost block, the
    /// matrix it inverts, and the blocks it rebuilds.
    pub codec: CodecLimits,
    /// Most input blocks a set may have for a repair to be attempted.
    ///
    /// This bounds the block ownership table, which has an entry per block. The
    /// default is the format's own ceiling, so no set a Cauchy code can address
    /// is excluded by it.
    pub max_input_blocks: u64,
    /// Most bytes held for input blocks that are still waiting for a chunk tail.
    ///
    /// A block of packed tails cannot be handed to the decoder until every file
    /// that writes part of it has been read, so it is buffered in between. What
    /// that costs depends on how the tails were packed, not on the size of the
    /// set.
    pub max_tail_buffer_bytes: u64,
}

impl RepairLimits {
    /// 65,536 input blocks: the most a PAR3 code matrix can address.
    pub const DEFAULT_MAX_INPUT_BLOCKS: u64 = 65_536;

    /// 256 MiB of half-filled tail blocks, matching
    /// [`CreateLimits::DEFAULT_MAX_TAIL_BUFFER_BYTES`](crate::create::CreateLimits::DEFAULT_MAX_TAIL_BUFFER_BYTES).
    pub const DEFAULT_MAX_TAIL_BUFFER_BYTES: u64 = 256 << 20;

    /// The bounds the decoder runs under.
    #[must_use]
    pub fn with_codec(mut self, codec: CodecLimits) -> Self {
        self.codec = codec;
        self
    }

    /// The largest set this repair will attempt.
    #[must_use]
    pub fn with_max_input_blocks(mut self, blocks: u64) -> Self {
        self.max_input_blocks = blocks;
        self
    }

    /// The most memory this repair will hold for chunk tails.
    #[must_use]
    pub fn with_max_tail_buffer_bytes(mut self, bytes: u64) -> Self {
        self.max_tail_buffer_bytes = bytes;
        self
    }
}

impl Default for RepairLimits {
    fn default() -> Self {
        Self {
            codec: CodecLimits::default(),
            max_input_blocks: Self::DEFAULT_MAX_INPUT_BLOCKS,
            max_tail_buffer_bytes: Self::DEFAULT_MAX_TAIL_BUFFER_BYTES,
        }
    }
}

/// How a repair should treat the files it replaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RepairOptions {
    /// Whether a damaged file is kept before its rebuilt copy takes its place.
    ///
    /// On by default. The damaged file is renamed to `<name>.1`, or `.2`, and so
    /// on up to the first free number, the way the reference implementation does
    /// it. With this off nothing is ever deleted either: the rebuilt file is
    /// renamed over the damaged one, which on POSIX replaces it in one step, and
    /// the damaged bytes are simply not kept.
    pub backup: bool,
    /// What this repair may allocate.
    pub limits: RepairLimits,
}

impl RepairOptions {
    /// Keep, or do not keep, the damaged file.
    #[must_use]
    pub fn with_backup(mut self, backup: bool) -> Self {
        self.backup = backup;
        self
    }

    /// Run under these limits.
    #[must_use]
    pub fn with_limits(mut self, limits: RepairLimits) -> Self {
        self.limits = limits;
        self
    }
}

impl Default for RepairOptions {
    fn default() -> Self {
        Self {
            backup: true,
            limits: RepairLimits::default(),
        }
    }
}

/// What a repair would do, worked out without writing anything.
///
/// This is the dry run: it says what is wrong, which input blocks have to be
/// rebuilt, which recovery blocks would be spent on them, and which files would
/// be written. A set that cannot be repaired produces a plan rather than an
/// error, so a caller can say how much more recovery data would be needed.
#[derive(Debug, Clone)]
pub struct RepairPlan {
    verify: VerifyReport,
    lost_blocks: Vec<u64>,
    recovery_to_use: Vec<u64>,
    available_recovery: u64,
    files_to_rewrite: Vec<String>,
}

impl RepairPlan {
    /// What verifying every file found.
    #[must_use]
    pub fn verify(&self) -> &VerifyReport {
        &self.verify
    }

    /// The input blocks that have to be rebuilt, ascending.
    #[must_use]
    pub fn lost_blocks(&self) -> &[u64] {
        &self.lost_blocks
    }

    /// The recovery blocks that would be used, ascending.
    ///
    /// Exactly as many as there are lost blocks; empty when nothing was lost,
    /// and empty when there are not enough to go round.
    #[must_use]
    pub fn recovery_to_use(&self) -> &[u64] {
        &self.recovery_to_use
    }

    /// How many recovery blocks the set has on hand for this repair.
    ///
    /// Counts only blocks computed with the set's Cauchy matrix, stored at full
    /// block size, and not excluded for contradicting another copy of
    /// themselves.
    #[must_use]
    pub fn available_recovery(&self) -> u64 {
        self.available_recovery
    }

    /// The files that would be written, as paths within the set.
    #[must_use]
    pub fn files_to_rewrite(&self) -> &[String] {
        &self.files_to_rewrite
    }

    /// Whether any file would be written at all.
    #[must_use]
    pub fn needs_repair(&self) -> bool {
        !self.files_to_rewrite.is_empty()
    }

    /// Whether there is enough recovery data to rebuild what was lost.
    #[must_use]
    pub fn is_possible(&self) -> bool {
        self.lost_blocks.len() as u64 <= self.available_recovery
    }

    /// How many more recovery blocks would be needed; zero when the repair can
    /// go ahead.
    #[must_use]
    pub fn missing_recovery_blocks(&self) -> u64 {
        (self.lost_blocks.len() as u64).saturating_sub(self.available_recovery)
    }
}

/// One file a repair wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairedFile {
    path: String,
    backup: Option<PathBuf>,
    verified: bool,
}

impl RepairedFile {
    /// The file's path within the set.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Where the damaged file was kept, if there was one and it was kept.
    #[must_use]
    pub fn backup(&self) -> Option<&Path> {
        self.backup.as_deref()
    }

    /// Whether the rebuilt bytes matched the File packet.
    ///
    /// A rebuild that does not is left where it was written, under its temporary
    /// name, and the file it was meant to replace is not touched — so a repair
    /// that goes wrong costs nothing that was still there.
    #[must_use]
    pub fn verified(&self) -> bool {
        self.verified
    }
}

/// What a repair did.
#[derive(Debug, Clone)]
pub struct RepairReport {
    plan: RepairPlan,
    repaired: Vec<RepairedFile>,
    verify_after: VerifyReport,
}

impl RepairReport {
    /// What the repair set out to do.
    #[must_use]
    pub fn plan(&self) -> &RepairPlan {
        &self.plan
    }

    /// The files it wrote, in the set's path order.
    #[must_use]
    pub fn repaired(&self) -> &[RepairedFile] {
        &self.repaired
    }

    /// Verifying every file again afterwards.
    ///
    /// When nothing needed repairing this is the plan's own verification rather
    /// than a second reading of every file.
    #[must_use]
    pub fn verify_after(&self) -> &VerifyReport {
        &self.verify_after
    }

    /// Whether every file in the set is now complete.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.verify_after.is_complete()
    }
}

/// Work out what repairing a set under `base` would take, without writing
/// anything.
///
/// Every file is verified, which reads all of them. A set that has more losses
/// than recovery blocks is *not* an error here: the plan reports it, so a caller
/// can say how many more blocks would be needed.
///
/// # Errors
///
/// [`Par3Error::UnrepairableSet`] when the set's own packets do not describe a
/// layout to work from — overlapping chunk tails, a block no file writes, a file
/// that cannot be checked at all, or recovery data from a matrix this crate does
/// not implement; [`Par3Error::RepairLimitExceeded`] when the set is larger than
/// [`RepairLimits`] allow; and an I/O error for anything the file system refused
/// other than a missing input file, which is a verdict rather than a failure.
pub fn plan_repair(set: &Par3Set, base: &Path, limits: &RepairLimits) -> Result<RepairPlan> {
    Ok(prepare(set, base, limits)?.1)
}

/// Repair a set's files under `base`.
///
/// Verifies, rebuilds the lost input blocks from the recovery blocks the set
/// carries, and writes back every file that was missing or damaged. Each is
/// built under a temporary name beside the set, checked against its File packet
/// there, and only then moved into place — over a backup of the damaged file
/// unless [`RepairOptions::backup`] is off. A rebuild that does not check out is
/// left under its temporary name and reported, and the file it was to replace is
/// left alone.
///
/// The temporary is created exclusively: a link planted under its name before
/// the repair is refused rather than followed and truncated, while a plain file
/// an interrupted repair left there is replaced. A directory of the set that has
/// been replaced by a link is refused before the file under it is rebuilt. Both
/// guard against what was put in place before the repair started; `base` itself
/// is trusted as far as the caller trusts it, and a tree that changes under a
/// running repair is not defended against.
///
/// A set whose files are all complete is not touched at all: no temporary file
/// is created, nothing is renamed, and the report carries the verification that
/// was already done.
///
/// # Errors
///
/// [`Par3Error::InsufficientRecovery`] when more input blocks were lost than
/// there are recovery blocks to rebuild them with — nothing is written in that
/// case; everything [`plan_repair`] can return; and
/// [`Par3Error::FileIo`] for anything the file system refused while a file was
/// being read or written, naming it.
pub fn repair_set(set: &Par3Set, base: &Path, options: &RepairOptions) -> Result<RepairReport> {
    let (layout, plan) = prepare(set, base, &options.limits)?;
    if !plan.is_possible() {
        return Err(Par3Error::InsufficientRecovery {
            lost: plan.lost_blocks.len() as u64,
            available: plan.available_recovery,
        });
    }
    if !plan.needs_repair() {
        let verify_after = plan.verify.clone();
        return Ok(RepairReport {
            plan,
            repaired: Vec::new(),
            verify_after,
        });
    }

    let recovered = rebuild::solve_lost_blocks(set, base, &layout, &plan, &options.limits)?;
    let repaired = rebuild::write_files(set, base, &layout, &plan, &recovered, options)?;
    drop(recovered);
    let verify_after = verify_set(set, base)?;
    Ok(RepairReport {
        plan,
        repaired,
        verify_after,
    })
}

/// The block table and the plan, which every entry point needs.
fn prepare(set: &Par3Set, base: &Path, limits: &RepairLimits) -> Result<(Layout, RepairPlan)> {
    let layout = Layout::build(set, limits.max_input_blocks)?;
    let verify = verify_set(set, base)?;
    let plan = plan_from(set, &layout, verify)?;
    Ok((layout, plan))
}

/// Turn a verification into the list of blocks to rebuild and files to write.
fn plan_from(set: &Par3Set, layout: &Layout, verify: VerifyReport) -> Result<RepairPlan> {
    let mut lost_blocks: Vec<u64> = Vec::new();
    let mut files_to_rewrite: Vec<String> = Vec::new();

    for (index, report) in verify.files().iter().enumerate() {
        let regions = &layout.per_file[index];
        match report.verdict() {
            FileVerdict::Complete => {}
            FileVerdict::Missing => {
                lost_blocks.extend(regions.iter().map(|region| region.block_index));
                files_to_rewrite.push(report.path().to_owned());
            }
            FileVerdict::Damaged {
                actual_size,
                damaged_blocks,
                unchecked_blocks,
                damaged_tail_blocks,
                ..
            } => {
                lost_blocks.extend_from_slice(damaged_blocks);
                lost_blocks.extend_from_slice(damaged_tail_blocks);
                // A block the set carries no checksum for is not known to be
                // good, and this file is known to be wrong somewhere. The
                // reference writes a checksum for every full block, so this is a
                // corner rather than the rule.
                lost_blocks.extend_from_slice(unchecked_blocks);
                // Verification reports the blocks a file still reaches; the ones
                // a truncation took away are read off the two sizes, which is
                // where they are read off here.
                lost_blocks.extend(
                    regions
                        .iter()
                        .filter(|region| region.file_end() > *actual_size)
                        .map(|region| region.block_index),
                );
                files_to_rewrite.push(report.path().to_owned());
            }
            FileVerdict::Unverifiable { reason } => {
                return Err(Par3Error::UnrepairableSet {
                    reason: format!("{} cannot be checked: {reason}", report.path()),
                });
            }
        }
    }

    lost_blocks.sort_unstable();
    lost_blocks.dedup();

    let matrix = cauchy_matrix_hash(set)?;
    let available: Vec<u64> = available_recovery(set, matrix);
    let available_recovery = available.len() as u64;
    let recovery_to_use: Vec<u64> = if lost_blocks.len() as u64 <= available_recovery {
        available.into_iter().take(lost_blocks.len()).collect()
    } else {
        Vec::new()
    };

    Ok(RepairPlan {
        verify,
        lost_blocks,
        recovery_to_use,
        available_recovery,
        files_to_rewrite,
    })
}

/// The hash of the set's one Cauchy Matrix packet, if it has one.
///
/// A set with no matrix packet at all carries no usable recovery data, which is
/// a shortage rather than a contradiction: an index file on its own still
/// repairs damage that needs no recovery block. Anything else is refused,
/// because a recovery block only means something against the matrix its packet
/// names, and nothing here can interpret the other three kinds.
fn cauchy_matrix_hash(set: &Par3Set) -> Result<Option<Fingerprint>> {
    match set.matrix_packets() {
        [] => Ok(None),
        [only] => match only.body() {
            PacketBody::CauchyMatrix(_) => Ok(Some(only.hash())),
            _ => Err(Par3Error::UnrepairableSet {
                reason: format!(
                    "its recovery data was computed with a {} matrix, which this crate does not \
                     implement",
                    String::from_utf8_lossy(&only.packet_type().signature())
                        .trim_end_matches('\0')
                        .trim()
                        .to_owned()
                ),
            }),
        },
        many => Err(Par3Error::UnrepairableSet {
            reason: format!(
                "it carries {} matrix packets, and nothing stored says which one the recovery \
                 blocks that name neither of them were computed with",
                many.len()
            ),
        }),
    }
}

/// The recovery block indices this repair may spend, ascending.
fn available_recovery(set: &Par3Set, matrix: Option<Fingerprint>) -> Vec<u64> {
    let Some(matrix) = matrix else {
        return Vec::new();
    };
    set.recovery_blocks()
        .iter()
        .filter(|block| {
            block.matrix_hash() == matrix
                && block.matrix_present()
                && block.data_len() as u64 == set.block_size()
        })
        .map(crate::set::RecoveryBlock::index)
        .collect()
}

/// The code's shape, as the decoder has to see it.
///
/// The recovery blocks a repair holds are whichever ones happened to survive, so
/// the geometry has to be wide enough to name the highest of them, counting from
/// zero — not as wide as the number of blocks on hand.
fn geometry_for(set: &Par3Set, rows: &[u64]) -> Result<Geometry> {
    let recovery_blocks = match rows.last() {
        Some(highest) => highest.checked_add(1).ok_or(Par3Error::CodecGeometry {
            reason: "a recovery block index of u64::MAX has no row after it".to_string(),
        })?,
        None => 0,
    };
    Ok(Geometry {
        block_size: set.block_size(),
        input_blocks: set.block_count(),
        recovery_blocks,
        first_recovery: 0,
    })
}

/// Where one of the set's files lives under `base`.
///
/// Names were refused at parse time if they were empty, `.`, `..`, or held a
/// separator, so joining them component by component cannot leave `base`.
fn resolve(base: &Path, path: &str) -> PathBuf {
    let mut resolved = PathBuf::from(base);
    for component in path.split('/') {
        resolved.push(component);
    }
    resolved
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_defaults_keep_the_damaged_file() {
        let options = RepairOptions::default();
        assert!(options.backup);
        assert_eq!(
            options.limits.max_input_blocks,
            RepairLimits::DEFAULT_MAX_INPUT_BLOCKS
        );
    }

    #[test]
    fn options_are_built_by_setters_because_the_structs_are_non_exhaustive() {
        let options = RepairOptions::default().with_backup(false).with_limits(
            RepairLimits::default()
                .with_codec(CodecLimits::new(4096))
                .with_max_input_blocks(8)
                .with_max_tail_buffer_bytes(1024),
        );
        assert!(!options.backup);
        assert_eq!(options.limits.codec.max_buffer_bytes, 4096);
        assert_eq!(options.limits.max_input_blocks, 8);
        assert_eq!(options.limits.max_tail_buffer_bytes, 1024);
    }

    #[test]
    fn a_path_inside_the_set_resolves_under_the_base_directory() {
        let resolved = resolve(Path::new("/tmp/base"), "sub/dir/file.bin");
        assert_eq!(resolved, Path::new("/tmp/base/sub/dir/file.bin"));
    }
}
