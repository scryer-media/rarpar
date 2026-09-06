//! Writing a PAR3 set: an index file and the recovery volumes beside it.
//!
//! [`create`] protects a list of files under a base directory. It plans the set
//! from their sizes alone — block size, chunk map, tail packing, block count,
//! Galois field, recovery count — then reads each file exactly once, hashing it
//! and feeding the Cauchy encoder as the bytes go past, and writes
//! `<stem>.par3` plus `<stem>.vol<start>+<count>.par3` volumes.
//!
//! # What it writes
//!
//! What the reference implementation writes with no options beyond a block size
//! and a recovery amount: a Cauchy Reed-Solomon code over GF(2^8) or GF(2^16),
//! chunk tails packed into shared input blocks, and recovery volumes holding
//! 1, 2, 4, … blocks. It writes no Data packets, no permission or link packets,
//! no parent set, and it neither deduplicates nor splits a file into more than
//! one chunk.
//!
//! ```
//! use par3_rs::create::{CreateOptions, InputSpec, RecoveryAmount, create};
//! use std::path::{Path, PathBuf};
//!
//! # fn main() -> par3_rs::Result<()> {
//! # let base = std::env::temp_dir().join(format!("par3-rs-doc-{}", std::process::id()));
//! # std::fs::create_dir_all(&base)?;
//! # std::fs::write(base.join("notes.txt"), vec![7u8; 4096])?;
//! // A directory holding `notes.txt`, and somewhere to put the set.
//! let base: &Path = &base;
//! let files = [PathBuf::from("notes.txt")];
//! let inputs = InputSpec::new(base, &files);
//!
//! let options = CreateOptions::default()
//!     .with_block_size(1024)
//!     .with_recovery(RecoveryAmount::Blocks(2));
//! let report = create(&inputs, &base.join("notes.par3"), &options)?;
//!
//! assert_eq!(report.block_count, 4);
//! assert_eq!(report.files_written.len(), 3); // the index and two volumes
//! # std::fs::remove_dir_all(base)?;
//! # Ok(())
//! # }
//! ```
//!
//! # Bounds
//!
//! Everything a caller or a file system can inflate is metered by
//! [`CreateLimits`]: the block size, the number of input files, the bytes of
//! path text, the buffers held for chunk tails still being filled, and — through
//! [`CodecLimits`] — the recovery blocks the encoder holds. The number of input
//! blocks is capped at 65,536, which is the most a PAR3 code matrix can address.

mod encode;
mod map;
mod packets;
mod plan;
mod write;

pub use plan::suggest_block_size;

use std::path::{Path, PathBuf};

use crate::cauchy::CodecLimits;
use crate::error::Result;
use crate::packet::{GaloisField, InputSetId};

/// How much recovery data to compute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryAmount {
    /// Exactly this many recovery blocks. Zero writes an index file alone.
    Blocks(u64),
    /// This percentage of the set's input blocks, rounded up. At most 250.
    Percent(u32),
}

impl Default for RecoveryAmount {
    fn default() -> Self {
        Self::Blocks(0)
    }
}

/// Bounds on what a create may allocate, and on how large a set it will build.
///
/// The defaults are generous enough that ordinary use never meets them, and
/// small enough that a caller passing on a number from somewhere else — a
/// configuration file, a request — cannot turn it into an allocation the process
/// cannot survive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct CreateLimits {
    /// Largest block size, in bytes. One block is held in memory while it is
    /// read, and every recovery row is one block wide, so this is the unit
    /// everything else is a multiple of.
    pub max_block_size: u64,
    /// Most input files one set may protect.
    pub max_files: u64,
    /// Most bytes of relative path text across all inputs.
    pub max_path_bytes: u64,
    /// Most bytes held for chunk-tail blocks that are still being filled.
    ///
    /// A tail block is buffered from the first tail written into it until the
    /// last, which is bounded by how many tail blocks are open at once rather
    /// than by the size of the set.
    pub max_tail_buffer_bytes: u64,
    /// Bounds on the encoder, which holds every recovery block it is building.
    pub codec: CodecLimits,
}

impl CreateLimits {
    /// 1 GiB: the same ceiling [`CodecLimits`] puts on a codec's buffers, since
    /// one block that large already fills it.
    pub const DEFAULT_MAX_BLOCK_SIZE: u64 = 1 << 30;

    /// One million files, matching [`SetLimits::max_entries`](crate::set::SetLimits).
    pub const DEFAULT_MAX_FILES: u64 = 1_000_000;

    /// 64 MiB of path text, matching
    /// [`SetLimits::max_path_bytes`](crate::set::SetLimits).
    pub const DEFAULT_MAX_PATH_BYTES: u64 = 64 << 20;

    /// 256 MiB of tail blocks, which is 65,536 open tail blocks at 4 KiB or
    /// 256 at 1 MiB — far more than tail packing ever leaves open at once.
    pub const DEFAULT_MAX_TAIL_BUFFER_BYTES: u64 = 256 << 20;

    /// The largest block size this create will use.
    #[must_use]
    pub fn with_max_block_size(mut self, bytes: u64) -> Self {
        self.max_block_size = bytes;
        self
    }

    /// The most input files this create will protect.
    #[must_use]
    pub fn with_max_files(mut self, files: u64) -> Self {
        self.max_files = files;
        self
    }

    /// The most path text this create will accept.
    #[must_use]
    pub fn with_max_path_bytes(mut self, bytes: u64) -> Self {
        self.max_path_bytes = bytes;
        self
    }

    /// The most memory this create will hold for chunk tails.
    #[must_use]
    pub fn with_max_tail_buffer_bytes(mut self, bytes: u64) -> Self {
        self.max_tail_buffer_bytes = bytes;
        self
    }

    /// The bounds the encoder runs under.
    #[must_use]
    pub fn with_codec(mut self, codec: CodecLimits) -> Self {
        self.codec = codec;
        self
    }
}

impl Default for CreateLimits {
    fn default() -> Self {
        Self {
            max_block_size: Self::DEFAULT_MAX_BLOCK_SIZE,
            max_files: Self::DEFAULT_MAX_FILES,
            max_path_bytes: Self::DEFAULT_MAX_PATH_BYTES,
            max_tail_buffer_bytes: Self::DEFAULT_MAX_TAIL_BUFFER_BYTES,
            codec: CodecLimits::default(),
        }
    }
}

/// Everything about a set that is not the input files themselves.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CreateOptions {
    /// Bytes per input block, or `None` to take [`suggest_block_size`].
    ///
    /// An odd size is rounded up by one, because GF(2^16) reads a block as
    /// 16-bit symbols.
    pub block_size: Option<u64>,
    /// How much recovery data to compute.
    pub recovery: RecoveryAmount,
    /// The Creator packet's text, which every PAR3 file must carry.
    pub creator: String,
    /// A Comment packet, when there is something to say.
    pub comment: Option<String>,
    /// Whether to replace files that are already there. Off by default: a create
    /// never silently destroys an existing set.
    pub overwrite: bool,
    /// What this create may allocate.
    pub limits: CreateLimits,
}

impl CreateOptions {
    /// The Creator text this crate writes unless told otherwise.
    #[must_use]
    pub fn default_creator() -> String {
        format!("par3-rs {}", env!("CARGO_PKG_VERSION"))
    }

    /// Use this block size rather than the suggested one.
    #[must_use]
    pub fn with_block_size(mut self, block_size: u64) -> Self {
        self.block_size = Some(block_size);
        self
    }

    /// Compute this much recovery data.
    #[must_use]
    pub fn with_recovery(mut self, recovery: RecoveryAmount) -> Self {
        self.recovery = recovery;
        self
    }

    /// Name the client that wrote the set.
    #[must_use]
    pub fn with_creator(mut self, creator: impl Into<String>) -> Self {
        self.creator = creator.into();
        self
    }

    /// Add a Comment packet.
    #[must_use]
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    /// Replace an index file or volume that is already there.
    #[must_use]
    pub fn with_overwrite(mut self, overwrite: bool) -> Self {
        self.overwrite = overwrite;
        self
    }

    /// Run under these limits.
    #[must_use]
    pub fn with_limits(mut self, limits: CreateLimits) -> Self {
        self.limits = limits;
        self
    }
}

impl Default for CreateOptions {
    fn default() -> Self {
        Self {
            block_size: None,
            recovery: RecoveryAmount::default(),
            creator: Self::default_creator(),
            comment: None,
            overwrite: false,
            limits: CreateLimits::default(),
        }
    }
}

/// The files a set protects, named relative to one base directory.
///
/// Names are stored in the set exactly as given here, with `/` separators, so a
/// set created from `sub/c.bin` verifies against `sub/c.bin` under whatever base
/// directory the reader chooses. Absolute paths, `.` and `..` components, and
/// names a reader would refuse are all rejected.
#[derive(Debug, Clone, Copy)]
pub struct InputSpec<'a> {
    /// The directory the relative names are resolved against for reading.
    pub base: &'a Path,
    /// The files to protect, relative to `base`. Sub-directories are fine.
    pub files: &'a [PathBuf],
    /// Directories that hold no protected file but should still exist after a
    /// repair. The directories that contain the files need not be listed: they
    /// are derived from the names.
    pub directories: &'a [PathBuf],
}

impl<'a> InputSpec<'a> {
    /// Protect these files, and no empty directories.
    #[must_use]
    pub fn new(base: &'a Path, files: &'a [PathBuf]) -> Self {
        Self {
            base,
            files,
            directories: &[],
        }
    }

    /// Also record these directories, which need hold no protected file.
    #[must_use]
    pub fn with_directories(mut self, directories: &'a [PathBuf]) -> Self {
        self.directories = directories;
        self
    }
}

/// What a create ended up building.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CreateReport {
    /// The set's identifier, which every packet written carries.
    pub set_id: InputSetId,
    /// Bytes per input and recovery block, after any rounding.
    pub block_size: u64,
    /// Input blocks the set stores, after tail packing.
    pub block_count: u64,
    /// Recovery blocks computed.
    pub recovery_count: u64,
    /// The Galois field the recovery data was computed in. A set with no input
    /// blocks declares no field, and its size is then zero.
    pub field: GaloisField,
    /// How many chunk tails share a block with an earlier tail.
    pub packed_tails: u64,
    /// Everything written, the index file first.
    pub files_written: Vec<PathBuf>,
}

/// Create a PAR3 set.
///
/// Writes `<output_stem>.par3` and, when there is recovery data,
/// `<output_stem>.vol<start>+<count>.par3` beside it; a stem that already ends
/// in `.par3` is not given a second suffix. Nothing is written until every
/// target has been checked, so a refusal to overwrite leaves the directory
/// untouched.
///
/// # Example
///
/// The same code as the crate README's "Creating a set" section, which is why
/// it is checked here: ten percent recovery over two files, with the block size
/// left to [`suggest_block_size`].
///
/// ```no_run
/// use par3_rs::create::{CreateOptions, InputSpec, RecoveryAmount, create};
/// use std::path::{Path, PathBuf};
///
/// # fn main() -> par3_rs::Result<()> {
/// let base = Path::new("/srv/releases/2026-09");
/// let files = [PathBuf::from("disc.iso"), PathBuf::from("notes/readme.txt")];
///
/// let report = create(
///     &InputSpec::new(base, &files),
///     &base.join("disc.par3"),
///     &CreateOptions::default()
///         .with_recovery(RecoveryAmount::Percent(10))
///         .with_comment("2026-09 release"),
/// )?;
///
/// println!("{} blocks of {} bytes, {} recovery blocks",
///     report.block_count, report.block_size, report.recovery_count);
/// for path in &report.files_written {
///     println!("wrote {}", path.display());
/// }
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// Returns [`Par3Error::CreateInput`](crate::Par3Error::CreateInput) for an unusable input path, an empty file
/// list, a block size of zero, a set too large for the format, or an output file
/// that already exists; [`Par3Error::CreateLimitExceeded`](crate::Par3Error::CreateLimitExceeded) or
/// [`Par3Error::CodecLimitExceeded`](crate::Par3Error::CodecLimitExceeded) when the set would exceed
/// [`CreateLimits`]; and [`Par3Error::FileIo`](crate::Par3Error::FileIo) for anything the file system
/// refused, naming the file it happened on.
pub fn create(
    inputs: &InputSpec<'_>,
    output_stem: &Path,
    options: &CreateOptions,
) -> Result<CreateReport> {
    let limits = &options.limits;
    let mut files = plan::collect_files(inputs, limits)?;
    let extra_directories = plan::collect_directories(inputs, limits)?;

    let sizes: Vec<u64> = files.iter().map(|file| file.size).collect();
    let block_size = plan::settle_block_size(options.block_size, &sizes, limits)?;
    plan::sort_files(&mut files, block_size);

    let map = map::BlockMap::plan(&files, block_size)?;
    let directories = plan::directories_of(&files, &extra_directories);
    let (recovery_count, field) = plan::settle_recovery(options.recovery, map.block_count())?;

    let (index_path, volumes) = write::plan_paths(output_stem, recovery_count)?;

    let outcome = encode::read_inputs(&files, &map, block_size, field, recovery_count, limits)?;
    let built = packets::build(
        &files,
        &directories,
        &map,
        &outcome,
        packets::SetShape {
            block_size,
            field,
            recovery_count,
        },
        &options.creator,
        options.comment.as_deref(),
    );

    let files_written = write::write_set(
        &index_path,
        &volumes,
        &built,
        &outcome.recovery,
        block_size,
        options.overwrite,
    )?;

    Ok(CreateReport {
        set_id: built.set_id,
        block_size,
        block_count: map.block_count(),
        recovery_count,
        field,
        packed_tails: map.packed_tails,
        files_written,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_options_write_an_index_alone() {
        let options = CreateOptions::default();
        assert_eq!(options.recovery, RecoveryAmount::Blocks(0));
        assert!(!options.overwrite);
        assert!(options.creator.starts_with("par3-rs "));
        assert_eq!(options.comment, None);
    }

    #[test]
    fn options_are_built_by_setters_because_the_struct_is_non_exhaustive() {
        let options = CreateOptions::default()
            .with_block_size(2000)
            .with_recovery(RecoveryAmount::Percent(10))
            .with_creator("something else")
            .with_comment("hello")
            .with_overwrite(true)
            .with_limits(CreateLimits::default().with_max_files(4));
        assert_eq!(options.block_size, Some(2000));
        assert_eq!(options.recovery, RecoveryAmount::Percent(10));
        assert_eq!(options.creator, "something else");
        assert_eq!(options.comment.as_deref(), Some("hello"));
        assert!(options.overwrite);
        assert_eq!(options.limits.max_files, 4);
    }
}
