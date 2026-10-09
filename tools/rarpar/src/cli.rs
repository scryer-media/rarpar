use std::path::{Path, PathBuf};

use clap::{Args, Parser, Subcommand, ValueEnum};

pub const ROOT_LONG_ABOUT: &str = "\
rarpar is a smart RAR/PAR2/PAR3 repair and extraction tool.

The normal workflow is `rarpar <path>`. Point it at a file or directory and it
will discover archive/parity sets, verify or repair PAR2/PAR3 data when available,
restore RAR recovery volumes when possible, and extract with verification
enabled.

Use `rarpar inspect --json <path>` to see the planned work before mutation, and
`rarpar cleanup --dry-run <path>` to review cleanup candidates without deleting
anything.";

pub const ROOT_AFTER_LONG_HELP: &str = "\
Examples:
  rarpar ./release
  rarpar auto ./release
  rarpar inspect --json ./release
  rarpar auto --output ./out ./release
  rarpar cleanup --dry-run ./release
  rarpar --password-file passwords.txt ./release
  rarpar xz compress --level 9 data.tar
  rarpar xz decompress data.tar.xz

rarpar is not an official RAR, UnRAR, or PAR2 utility and does not create or
recompress RAR archives. `rarpar par3 inside` adds or removes a PAR3 region in
a copy of an existing RAR5 archive without changing the archive's own bytes.";

#[derive(Clone, Debug, Parser)]
#[command(
    name = "rarpar",
    version,
    about = "Smart RAR/PAR2/PAR3 repair and extraction CLI",
    long_about = ROOT_LONG_ABOUT,
    after_long_help = ROOT_AFTER_LONG_HELP
)]
pub struct Cli {
    /// Emit machine-readable JSON reports for planning and automation.
    #[arg(long, global = true)]
    pub json: bool,

    /// Suppress human-readable progress and summaries.
    #[arg(long, global = true)]
    pub quiet: bool,

    /// Inspect only the paths given; do not recurse into directories.
    #[arg(long, global = true)]
    pub no_recursive: bool,

    /// Maximum recursive directory scan depth.
    #[arg(long, global = true, default_value_t = 8)]
    pub max_depth: usize,

    /// Maximum number of files to inspect during discovery.
    #[arg(long, global = true, default_value_t = 20_000)]
    pub max_files: usize,

    /// Plan/report work without creating, repairing, extracting, or deleting files.
    #[arg(long, global = true)]
    pub dry_run: bool,

    /// Extraction output directory; multiple detected sets get separate subdirectories. For `xz
    /// compress`, `xz decompress`, `par create`, `par3 create` and `par3 archive`, a relative
    /// OUTPUT is placed under it.
    #[arg(short = 'o', long, global = true, value_name = "DIR")]
    pub output: Option<PathBuf>,

    /// Repair/read-write working directory for PAR2 and PAR3 operations.
    #[arg(short = 'C', long, global = true, value_name = "DIR")]
    pub working_dir: Option<PathBuf>,

    /// Additional directory to search for parity-protected data files.
    #[arg(long, global = true, value_name = "DIR")]
    pub search_dir: Vec<PathBuf>,

    /// Parity file placement policy: smart scans by content; canonical uses recorded paths only.
    #[arg(long, global = true, value_enum, default_value_t = ParPlacement::Smart)]
    pub par_placement: ParPlacement,

    /// File containing candidate archive passwords, one per line; values are never printed.
    #[arg(long, global = true, value_name = "PATH")]
    pub password_file: Option<PathBuf>,

    /// Environment variable containing one archive password candidate.
    #[arg(long, global = true, value_name = "NAME")]
    pub password_env: Option<String>,

    /// File descriptor containing candidate archive passwords, one per line.
    #[arg(long, global = true, value_name = "FD")]
    pub password_fd: Option<i32>,

    /// Allow extraction and parity creation to overwrite existing output files.
    #[arg(long, global = true)]
    pub overwrite: bool,

    /// Delete consumed source files only after verified successful extraction.
    #[arg(long, global = true)]
    pub delete_sources: bool,

    /// Permanently delete cleanup candidates instead of using the OS trash/recycle bin.
    #[arg(long, global = true)]
    pub permanent_delete: bool,

    /// Total PAR3 engine allocation budget in MiB, including retained state.
    #[arg(long, global = true, default_value_t = 256)]
    pub par3_memory_mib: usize,

    /// Maximum PAR3 arithmetic workers (defaults to available CPUs).
    #[arg(long, global = true)]
    pub par3_workers: Option<usize>,

    /// Maximum lost blocks accepted by a PAR3 Cauchy solve.
    #[arg(long, global = true, default_value_t = 4096)]
    pub par3_max_lost_blocks: u64,

    #[command(subcommand)]
    pub command: Option<Command>,

    /// Input paths for default auto mode.
    #[arg(value_name = "PATH")]
    pub paths: Vec<PathBuf>,
}

impl Cli {
    /// Where a command's positional OUTPUT lands: under the global `-o`
    /// directory when one is given and OUTPUT is relative (so `sub/out` lands
    /// in `DIR/sub/out`), as given otherwise. An absolute OUTPUT wins over
    /// `-o`, and `-` (standard output) is never moved.
    pub fn place_output(&self, output: &Path) -> PathBuf {
        match &self.output {
            Some(directory) if output != Path::new("-") => directory.join(output),
            _ => output.to_path_buf(),
        }
    }
}

#[derive(Debug, Clone, Subcommand)]
pub enum Command {
    /// Discover, repair, restore, and extract what is safe to process.
    #[command(long_about = "\
Discover archive and parity sets, repair with PAR2/PAR3 when possible, restore RAR
recovery volumes when available, and extract with verification enabled.")]
    Auto(PathArgs),
    /// Inspect input paths and print the planned work.
    #[command(long_about = "\
Discover the same action graph that auto mode would use, but do not repair,
extract, restore, or delete files. Use --json for automation.")]
    Inspect(PathArgs),
    /// Delete source archive files after validating extracted outputs.
    #[command(long_about = "\
Validate expected extracted outputs from archive metadata, then delete only
positively identified consumed source files. Use --dry-run to review the
manifest before deletion.")]
    Cleanup(PathArgs),
    /// RAR archive operations.
    Rar {
        #[command(subcommand)]
        command: RarCommand,
    },
    /// PAR2 verification and repair operations.
    Par {
        #[command(subcommand)]
        command: ParCommand,
    },
    /// PAR3 creation, verification and repair, including FFT and Data packets.
    Par3 {
        #[command(subcommand)]
        command: Par3Command,
    },
    /// .xz compression, decompression, integrity testing and listing.
    #[command(long_about = "\
Compress to and decompress from the .xz format with lzma-turbo. INPUT and OUTPUT
may be `-` for standard input and output, and an absent INPUT is standard input
when that is not a terminal. Pipes are read and written as they flow, in memory
that does not depend on their length. Inputs are never deleted, and an existing
output is rejected unless --overwrite is given. Multi-block input is compressed
and decompressed on several threads; concatenated streams decode as one output.")]
    Xz {
        #[command(subcommand)]
        command: XzCommand,
    },
}

#[derive(Debug, Clone, Subcommand)]
pub enum XzCommand {
    /// Compress a file or standard input to .xz.
    #[command(long_about = "\
Compress INPUT to OUTPUT. OUTPUT defaults to INPUT with `.xz` appended, beside
INPUT or in the global --output directory; standard input defaults to standard
output. --level and --extreme select the xz preset of the same number. The
stream is cut into blocks of --block-size bytes, which defaults to three times
the preset's dictionary as xz's threaded mode does, so the output bytes do not
depend on --threads.")]
    Compress(XzCompressArgs),
    /// Decompress an .xz file or standard input.
    #[command(long_about = "\
Decompress INPUT to OUTPUT. OUTPUT defaults to INPUT without its `.xz` suffix
(`.txz` becomes `.tar`), beside INPUT or in the global --output directory;
standard input defaults to standard output. Every block's integrity check is
verified. A file with more than one block is decoded on up to --threads threads
within --memory-mib from its index. A pipe is decoded as it arrives: on several
threads, each block whose header records its sizes goes to a worker, and other
blocks are decoded in order; with --threads 1 it is decoded in one pass.")]
    Decompress(XzDecompressArgs),
    /// Decode an .xz file and verify its integrity checks without writing output.
    #[command(long_about = "\
Decode INPUT as decompress does, verifying every block's integrity check and
the stream indexes, and write nothing. Exits 1 when the data is damaged.")]
    Test(XzTestArgs),
    /// Show the stream and block layout, check type, sizes and ratio of an .xz file.
    #[command(long_about = "\
Show the streams and blocks of an .xz file: offsets, sizes, check types,
padding and ratio, read from the index at the end of every stream without
decoding. A forward-only input (standard input or a pipe) has no index to seek
to, so it is decoded once instead: the report then has the sizes, the stream
and block counts, each block's uncompressed size and the first stream's check,
and names what it cannot know (`unknown`).")]
    List(XzListArgs),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum XzCheck {
    /// No integrity check.
    None,
    /// CRC-32.
    Crc32,
    /// CRC-64, the xz default.
    Crc64,
    /// SHA-256.
    Sha256,
}

#[derive(Debug, Clone, Args)]
pub struct XzCompressArgs {
    /// File to compress, or `-` for standard input (the default when it is not a terminal).
    #[arg(value_name = "INPUT")]
    pub input: Option<PathBuf>,
    /// Output file or directory, or `-` for standard output; a relative OUTPUT is placed under
    /// the global -o directory when one is given.
    #[arg(id = "destination", value_name = "OUTPUT")]
    pub output: Option<PathBuf>,
    /// Compression level: the xz preset, 0 (fastest) to 9.
    #[arg(long, default_value_t = 6, value_parser = clap::value_parser!(u32).range(0..=9))]
    pub level: u32,
    /// Use the slower extreme variant of the preset (xz's `-e`).
    #[arg(long)]
    pub extreme: bool,
    /// Uncompressed bytes per block; defaults to three times the preset's dictionary, at least 1 MiB.
    #[arg(short = 's', long, value_name = "BYTES", value_parser = clap::value_parser!(u64).range(1..))]
    pub block_size: Option<u64>,
    /// Integrity check stored with every block.
    #[arg(long, value_enum, default_value_t = XzCheck::Crc64)]
    pub check: XzCheck,
    /// Blocks compressed at once (defaults to available CPUs); the output bytes do not depend on it.
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..=256))]
    pub threads: Option<u32>,
    /// Memory budget in MiB; fewer threads are used to stay within it. No limit by default.
    #[arg(long, value_name = "MIB", value_parser = clap::value_parser!(u64).range(1..))]
    pub memory_mib: Option<u64>,
    #[command(flatten)]
    pub sidecar: SidecarArgs,
}

/// A recovery set written beside the output in the same pass, from the bytes
/// as they are written.
#[derive(Debug, Clone, Args)]
pub struct SidecarArgs {
    /// Also write a PAR2 or PAR3 set for the output beside it, computed as it is written.
    #[arg(long, value_enum, value_name = "FORMAT")]
    pub sidecar: Option<SidecarFormat>,
    /// Block (slice) size of the set in bytes; required with --sidecar.
    #[arg(long, value_name = "BYTES", requires = "sidecar", value_parser = clap::value_parser!(u64).range(1..))]
    pub sidecar_block_size: Option<u64>,
    /// Recovery blocks in the set; required with --sidecar.
    #[arg(long, value_name = "COUNT", requires = "sidecar")]
    pub sidecar_recovery_count: Option<u64>,
    /// With standard output, the name it will be saved under: the set records it and is named
    /// after it, placed under -o like an OUTPUT.
    #[arg(long, value_name = "NAME", requires = "sidecar")]
    pub sidecar_name: Option<String>,
}

#[derive(Debug, Clone, Args)]
pub struct XzDecodeArgs {
    /// Decoder threads for a multi-block file (defaults to available CPUs).
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..=256))]
    pub threads: Option<u32>,
    /// Memory limit in MiB: threads are reduced to fit, and a stream whose
    /// dictionary alone exceeds it is refused.
    #[arg(long, value_name = "MIB", default_value_t = 1024, value_parser = clap::value_parser!(u64).range(1..))]
    pub memory_mib: u64,
}

#[derive(Debug, Clone, Args)]
pub struct XzDecompressArgs {
    /// .xz file to decompress, or `-` for standard input (the default when it is not a terminal).
    #[arg(value_name = "INPUT")]
    pub input: Option<PathBuf>,
    /// Output file or directory, or `-` for standard output; a relative OUTPUT is placed under
    /// the global -o directory when one is given.
    #[arg(id = "destination", value_name = "OUTPUT")]
    pub output: Option<PathBuf>,
    #[command(flatten)]
    pub decode: XzDecodeArgs,
}

#[derive(Debug, Clone, Args)]
pub struct XzTestArgs {
    /// .xz file to test, or `-` for standard input (the default when it is not a terminal).
    #[arg(value_name = "INPUT")]
    pub input: Option<PathBuf>,
    #[command(flatten)]
    pub decode: XzDecodeArgs,
}

#[derive(Debug, Clone, Args)]
pub struct XzListArgs {
    /// .xz file to list, or `-` for standard input (the default when it is not a terminal).
    #[arg(value_name = "INPUT")]
    pub input: Option<PathBuf>,
    /// Memory limit in MiB for the decode a forward-only stream is listed by.
    #[arg(long, value_name = "MIB", default_value_t = 1024, value_parser = clap::value_parser!(u64).range(1..))]
    pub memory_mib: u64,
}

#[derive(Debug, Clone, Subcommand)]
pub enum Par3Command {
    /// Create a standalone PAR3 set from explicit files.
    Create(Par3CreateArgs),
    /// Verify protected files and report per-cohort recovery requirements.
    Verify(Par3Args),
    /// Rebuild damaged files in the working directory, keeping numbered backups.
    Repair(Par3Args),
    /// Write a 7z archive and protect it with PAR3 in the same pass.
    #[cfg(feature = "sevenz")]
    #[command(long_about = "\
Write a 7z archive of the given files and directories and compute its PAR3
recovery data from the bytes as they are written, without reading the archive
back. By default the set is written beside the archive as OUTPUT.par3 and
recovery volumes; --inside appends it after the archive's end header instead,
where 7z readers ignore it and PAR3 tools find it.")]
    Archive(Par3ArchiveArgs),
    /// EXPERIMENTAL: PAR-inside for RAR5 archives and volume sets made by RARLAB rar.
    #[command(
        subcommand,
        long_about = "\
EXPERIMENTAL: the on-disk layout of the embedded PAR3 region may change before
it is stable, and output from this version may not verify with a later one.

Embed PAR3 recovery inside existing RAR5 archives, verify and repair them from
that embedded recovery, and remove it again. The archive's own bytes are never
changed: insertion writes a new copy with a PAR3 region added, and removal
restores the original byte for byte. RAR archives are never created or
recompressed."
    )]
    Inside(Par3InsideCommand),
}

#[derive(Debug, Clone, Subcommand)]
pub enum Par3InsideCommand {
    /// EXPERIMENTAL: add a PAR3 region to a RAR5 archive or every volume of a RAR5 set.
    Insert(Par3InsideInsertArgs),
    /// EXPERIMENTAL: verify archive data and embedded regions.
    Verify(Par3InsideArgs),
    /// EXPERIMENTAL: rebuild damaged or missing volumes and regions from embedded recovery.
    Repair(Par3InsideRepairArgs),
    /// EXPERIMENTAL: write the archives without their PAR3 regions, byte-identical to the originals.
    Remove(Par3InsideRemoveArgs),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Par3InsideLayout {
    /// After the end-of-archive header; the archive itself is untouched.
    Trailing,
    /// A skippable block of an unassigned type before the end-of-archive header.
    Block,
    /// A skippable `PAR3` service header before the end-of-archive header.
    Service,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Par3InsidePlacement {
    /// One set; every volume carries the metadata and an even share of recovery.
    Spread,
    /// One set; every volume carries the metadata, the last carries all recovery.
    Last,
    /// A separate set inside each volume.
    Independent,
}

#[derive(Debug, Clone, Args)]
pub struct Par3InsideInsertArgs {
    /// Archive, or any volume of a `.partN.rar` set (the other volumes are found by name).
    #[arg(required = true, num_args = 1..)]
    pub archives: Vec<PathBuf>,
    /// Directory for the protected copies; required unless --in-place.
    #[arg(
        short = 'd',
        long,
        value_name = "DIR",
        required_unless_present = "in_place"
    )]
    pub output_dir: Option<PathBuf>,
    /// Replace each archive with its protected copy.
    #[arg(long, conflicts_with = "output_dir")]
    pub in_place: bool,
    /// Logical block size in bytes; defaults to the smallest power of two from 4096 keeping at most 2048 blocks.
    #[arg(short = 's', long, value_parser = clap::value_parser!(u64).range(1..))]
    pub block_size: Option<u64>,
    /// Number of recovery packets in the set (per volume with --placement independent).
    #[arg(short = 'c', long, conflicts_with = "recovery_percent")]
    pub recovery_count: Option<u64>,
    /// Recovery percentage of protected blocks (default 5).
    #[arg(short = 'r', long, conflicts_with = "recovery_count")]
    pub recovery_percent: Option<u32>,
    #[arg(long, value_enum, default_value_t = Par3InsideLayout::Trailing)]
    pub layout: Par3InsideLayout,
    #[arg(long, value_enum, default_value_t = Par3InsidePlacement::Spread)]
    pub placement: Par3InsidePlacement,
    /// Scratch directory for recovery encoding; defaults to the output directory.
    #[arg(long)]
    pub scratch_dir: Option<PathBuf>,
    /// Flush buffers without requesting durable storage barriers.
    #[arg(long)]
    pub buffered: bool,
}

#[derive(Debug, Clone, Args)]
pub struct Par3InsideArgs {
    /// Archive or volumes; the rest of a volume set is found by recorded name.
    #[arg(required = true, num_args = 1..)]
    pub archives: Vec<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct Par3InsideRepairArgs {
    #[command(flatten)]
    pub inputs: Par3InsideArgs,
    /// Write rebuilt volumes here instead of replacing them in place.
    #[arg(short = 'd', long, value_name = "DIR")]
    pub output_dir: Option<PathBuf>,
    /// Replace damaged volumes without keeping numbered backups.
    #[arg(long, conflicts_with = "output_dir")]
    pub no_backup: bool,
    /// Scratch directory for staging; defaults to the output directory.
    #[arg(long)]
    pub scratch_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct Par3InsideRemoveArgs {
    #[command(flatten)]
    pub inputs: Par3InsideArgs,
    /// Directory for the stripped archives; required unless --in-place.
    #[arg(
        short = 'd',
        long,
        value_name = "DIR",
        required_unless_present = "in_place"
    )]
    pub output_dir: Option<PathBuf>,
    /// Replace each archive with its stripped original.
    #[arg(long, conflicts_with = "output_dir")]
    pub in_place: bool,
}

#[derive(Debug, Clone, Args)]
pub struct Par3Args {
    /// PAR3 carrier or directory; sibling carriers are matched by authenticated set identity.
    pub input: PathBuf,
    /// Additional protected-data search directories.
    pub search_dirs: Vec<PathBuf>,
    /// Select an input-set ID when a directory or carrier contains multiple sets.
    #[arg(long)]
    pub set_id: Option<String>,
    /// Replace damaged files without keeping numbered backups.
    #[arg(long)]
    pub no_backup: bool,
}

#[derive(Debug, Clone, Args)]
pub struct Par3CreateArgs {
    /// Output PAR3 path or stem, placed under the global -o directory when OUTPUT is relative and
    /// -o is given; with a stream, an existing directory takes the set named by --name.
    #[arg(id = "destination", value_name = "OUTPUT")]
    pub output: PathBuf,
    /// Explicit source files, relative to --base-path (defaults to current directory), or `-` for
    /// one file from standard input (the default when no file is given and it is not a terminal).
    pub files: Vec<PathBuf>,
    #[arg(long)]
    pub base_path: Option<PathBuf>,
    /// Name the set records for the file read from standard input.
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,
    /// Logical block size in bytes (default 1048576; required for standard input).
    #[arg(short = 's', long, value_parser = clap::value_parser!(u64).range(1..))]
    pub block_size: Option<u64>,
    /// Number of global recovery packets (defaults to one); an interleaved set rounds up to whole rows.
    #[arg(short = 'c', long, conflicts_with = "recovery_percent")]
    pub recovery_count: Option<u64>,
    /// Recovery percentage of logical blocks after deduplication, rounded up to whole rows when interleaved; planning requires a second source pass.
    #[arg(short = 'r', long, conflicts_with = "recovery_count")]
    pub recovery_percent: Option<u32>,
    #[arg(long, value_enum, default_value_t = Par3Codec::Cauchy)]
    pub codec: Par3Codec,
    /// Log2 recovery capacity per FFT cohort; required with --codec fft.
    #[arg(long, value_parser = clap::value_parser!(i8).range(0..=15))]
    pub capacity_log2: Option<i8>,
    /// Extra FFT cohorts; zero means one cohort.
    #[arg(long, default_value_t = 0)]
    pub interleave: u64,
    /// First global recovery index; an interleaved set requires a multiple of the cohort count.
    #[arg(short = 'f', long, default_value_t = 0)]
    pub first_recovery: u64,
    #[arg(long, value_enum, default_value_t = Par3Dedup::None)]
    pub dedup: Par3Dedup,
    /// Store original blocks in authenticated Data packets as well.
    #[arg(long)]
    pub data_packets: bool,
    /// Maximum recovery packets per volume; otherwise volumes grow by powers of two.
    #[arg(long, conflicts_with = "volume_bytes", value_parser = clap::value_parser!(u64).range(1..))]
    pub volume_blocks: Option<u64>,
    /// Maximum bytes per recovery volume, including metadata.
    #[arg(long, conflicts_with = "volume_blocks", value_parser = clap::value_parser!(u64).range(1..))]
    pub volume_bytes: Option<u64>,
    /// Scratch directory for recovery encoding; defaults to the output directory.
    #[arg(long)]
    pub scratch_dir: Option<PathBuf>,
    /// Flush buffers without requesting durable storage barriers.
    #[arg(long)]
    pub buffered: bool,
}

#[cfg(feature = "sevenz")]
#[derive(Debug, Clone, Args)]
pub struct Par3ArchiveArgs {
    /// Output archive path.
    #[arg(id = "destination", value_name = "OUTPUT")]
    pub output: PathBuf,
    /// Files and directories to archive, relative to --base-path (defaults to current directory).
    #[arg(required = true, num_args = 1..)]
    pub inputs: Vec<PathBuf>,
    /// Directory archive member names are relative to.
    #[arg(long)]
    pub base_path: Option<PathBuf>,
    /// Archive format: 7z (LZMA2) or zip (deflate).
    #[arg(long, value_enum, default_value_t = ArchiveFormat::SevenZ)]
    pub format: ArchiveFormat,
    /// Compression level, 0 (stored) to 9.
    #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u32).range(0..=9))]
    pub level: u32,
    /// Executable filter applied before compression; 7z only.
    #[arg(long, value_enum, default_value_t = ArchiveFilter::None)]
    pub filter: ArchiveFilter,
    /// Compress every file on its own instead of as one solid block; 7z only.
    #[arg(long)]
    pub no_solid: bool,
    /// Append the PAR3 set inside the archive, after its end header, instead of beside it.
    #[arg(long, conflicts_with_all = ["block_size", "recovery_count", "sidecar"])]
    pub inside: bool,
    /// Format of the set written beside the archive in the same pass: par3 (the default) or par2
    /// (ZIP only, with a fixed -c).
    #[arg(long, value_enum, value_name = "FORMAT")]
    pub sidecar: Option<SidecarFormat>,
    /// Logical block size in bytes for the sibling set; odd sizes are rounded up (PAR2: to a
    /// multiple of 4).
    #[arg(short = 's', long, visible_alias = "sidecar-block-size", default_value_t = 1_048_576, value_parser = clap::value_parser!(u64).range(40..))]
    pub block_size: u64,
    /// Number of recovery packets in the sibling set (defaults to one).
    #[arg(
        short = 'c',
        long,
        visible_alias = "sidecar-recovery-count",
        conflicts_with = "recovery_percent"
    )]
    pub recovery_count: Option<u64>,
    /// Recovery percentage of input blocks, rounded up; with --inside, 0 to 250, and 0 means one block.
    #[arg(short = 'r', long, conflicts_with = "recovery_count")]
    pub recovery_percent: Option<u32>,
}

#[cfg(feature = "sevenz")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ArchiveFormat {
    #[value(name = "7z")]
    SevenZ,
    Zip,
}

#[cfg(feature = "sevenz")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ArchiveFilter {
    None,
    X86,
    Arm,
    ArmThumb,
    Arm64,
    Ia64,
    Sparc,
    Ppc,
    Riscv,
}

/// Format of a recovery set written beside an archive in the same pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SidecarFormat {
    Par2,
    Par3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Par3Codec {
    Cauchy,
    Fft,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Par3Dedup {
    None,
    Aligned,
    Sliding,
}

#[derive(Debug, Clone, Args)]
pub struct PathArgs {
    /// File or directory paths to inspect.
    #[arg(value_name = "PATH", required = true)]
    pub paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Subcommand)]
pub enum RarCommand {
    /// List archive members.
    List { archive: PathBuf },
    /// Test archive integrity.
    Test { archive: PathBuf },
    /// Extract archive members.
    #[command(long_about = "\
Extract archive members with verification enabled. By default existing output
files are rejected unless --overwrite is supplied.")]
    Extract {
        archive: PathBuf,
        #[arg(value_name = "DEST")]
        dest: Option<PathBuf>,
    },
    /// Restore missing RAR data volumes from recovery volumes.
    RestoreVolumes {
        #[arg(value_name = "RAR_OR_REV", required = true)]
        paths: Vec<PathBuf>,
    },
}

#[derive(Debug, Clone, Subcommand)]
pub enum ParCommand {
    /// Create a PAR2 recovery set for explicit input files.
    #[command(
        long_about = "Create a PAR2 recovery set for the explicitly supplied input files. Inputs are resolved relative to --base-path; use --dry-run to inspect the planned packet and volume output without writing it."
    )]
    Create(ParCreateArgs),
    /// Verify files against a PAR2 set.
    #[command(long_about = "\
Verify files against a PAR2 set. The default smart placement mode can locate
renamed or moved protected files by content. Use --par-placement canonical to
verify only the paths recorded by the PAR2 set, which is useful for direct
comparison with conventional PAR2 verification tools.")]
    Verify(ParArgs),
    /// Repair files using a PAR2 set.
    #[command(long_about = "\
Repair files using a PAR2 set, apply unambiguous placement fixes, and verify
the result after repair. Use --dry-run to report planned repair work only.")]
    Repair(ParArgs),
}

#[derive(Debug, Clone, Args)]
pub struct ParArgs {
    /// PAR2 file or directory containing a PAR2 set.
    #[arg(value_name = "PAR2_OR_DIR")]
    pub input: PathBuf,
    /// Additional directories containing protected data files.
    #[arg(value_name = "SEARCH_DIR")]
    pub search_dirs: Vec<PathBuf>,
    /// Verify only the protected file NAME, reading its bytes from standard input (verify only).
    #[arg(long, value_name = "NAME", conflicts_with = "search_dirs")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Args)]
pub struct ParCreateArgs {
    /// Output PAR2 path or stem; recovery volumes use this stem as well.
    #[arg(id = "destination", value_name = "OUTPUT")]
    pub output: PathBuf,

    /// Explicit input files to include in the recovery set; no recursion or file-list expansion is performed.
    #[arg(value_name = "FILE", required = true, num_args = 1..)]
    pub files: Vec<PathBuf>,

    /// Base directory used to make PAR2 names relative and to resolve inputs; defaults to OUTPUT's parent.
    #[arg(long, value_name = "DIR")]
    pub base_path: Option<PathBuf>,

    /// Target PAR2 block size in bytes.
    #[arg(
        short = 's',
        long,
        value_name = "BYTES",
        value_parser = clap::value_parser!(u64).range(1..),
        conflicts_with = "block_count"
    )]
    pub block_size: Option<u64>,

    /// Target number of source blocks.
    #[arg(
        short = 'b',
        long,
        value_name = "COUNT",
        value_parser = clap::value_parser!(u32).range(1..),
        conflicts_with = "block_size"
    )]
    pub block_count: Option<u32>,

    /// Recovery amount as a percentage of source blocks.
    #[arg(
        short = 'r',
        long,
        value_name = "PERCENT",
        value_parser = clap::value_parser!(u32),
        conflicts_with = "recovery_count"
    )]
    pub recovery_percent: Option<u32>,

    /// Exact number of recovery blocks (long option only).
    #[arg(
        long,
        value_name = "COUNT",
        value_parser = clap::value_parser!(u32).range(0..=32_768),
        conflicts_with = "recovery_percent"
    )]
    pub recovery_count: Option<u32>,

    /// Exponent assigned to the first recovery block.
    #[arg(
        short = 'f',
        long,
        default_value_t = 0,
        value_name = "EXPONENT",
        value_parser = clap::value_parser!(u32).range(0..=32_768)
    )]
    pub first_exponent: u32,

    /// Recovery volume sizing scheme.
    #[arg(long, value_enum, default_value_t = ParVolumeScheme::Variable)]
    pub volume_scheme: ParVolumeScheme,

    /// Number of recovery volumes to write.
    #[arg(
        short = 'n',
        long,
        value_name = "COUNT",
        value_parser = clap::value_parser!(u32).range(1..=31)
    )]
    pub volume_count: Option<u32>,

    /// Processing-buffer budget for forward encoding, in MiB; metadata and packet storage are reported separately.
    #[arg(
        long,
        value_name = "MIB",
        value_parser = clap::value_parser!(usize)
    )]
    pub memory_mib: Option<usize>,

    /// Recovery creation backend: cpu or auto. GPU backends are disabled in
    /// this build, so both resolve to the CPU/SIMD creation path.
    #[arg(long, value_enum, default_value_t = ParCreationBackend::Cpu)]
    pub backend: ParCreationBackend,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ParCreationBackend {
    /// Always use the CPU/SIMD creation path.
    Cpu,
    /// Let the library choose. With GPU backends disabled this is the CPU
    /// path; the option is kept so existing invocations keep parsing.
    Auto,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ParVolumeScheme {
    /// Use the library's variable recovery-volume sizing.
    Variable,
    /// Divide recovery blocks as evenly as possible among the volumes.
    Uniform,
    /// Cap each recovery volume at the largest source file's block count.
    Limited,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ParPlacement {
    /// Locate renamed or moved files by content before verification or repair.
    Smart,
    /// Verify only the paths recorded by PAR2 and explicitly supplied search directories.
    Canonical,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_args(arguments: &[&str]) -> ParCreateArgs {
        let mut command = vec!["rarpar", "par", "create"];
        command.extend(arguments);
        let cli = Cli::try_parse_from(command).expect("create arguments should parse");
        match cli.command.expect("a command is required") {
            Command::Par {
                command: ParCommand::Create(args),
            } => args,
            other => panic!("expected par create, got {other:?}"),
        }
    }

    #[test]
    fn create_has_distinct_output_and_explicit_files() {
        let args = create_args(&["release/set", "release/a.bin", "release/b.bin"]);

        assert_eq!(args.output, PathBuf::from("release/set"));
        assert_eq!(
            args.files,
            [
                PathBuf::from("release/a.bin"),
                PathBuf::from("release/b.bin")
            ]
        );
        assert_eq!(args.base_path, None);
        assert_eq!(args.volume_scheme, ParVolumeScheme::Variable);
    }

    #[test]
    fn create_supports_short_sizing_and_recovery_options() {
        let args = create_args(&[
            "set",
            "a.bin",
            "-s",
            "4096",
            "-r",
            "5",
            "-f",
            "7",
            "--volume-scheme",
            "uniform",
            "-n",
            "3",
            "--memory-mib",
            "128",
        ]);

        assert_eq!(args.block_size, Some(4096));
        assert_eq!(args.recovery_percent, Some(5));
        assert_eq!(args.first_exponent, 7);
        assert_eq!(args.volume_scheme, ParVolumeScheme::Uniform);
        assert_eq!(args.volume_count, Some(3));
        assert_eq!(args.memory_mib, Some(128));
    }

    #[test]
    fn create_accepts_explicit_backend_selection() {
        let args = create_args(&["set", "a.bin", "--backend", "auto"]);
        assert_eq!(args.backend, ParCreationBackend::Auto);
    }

    #[test]
    fn create_rejects_gpu_backend_selection() {
        let result = Cli::try_parse_from([
            "rarpar",
            "par",
            "create",
            "set",
            "a.bin",
            "--backend",
            "metal",
        ]);
        assert!(result.is_err(), "metal is no longer a creation backend");
    }

    #[test]
    fn create_recovery_percent_is_integral() {
        let result = Cli::try_parse_from([
            "rarpar",
            "par",
            "create",
            "set",
            "a.bin",
            "--recovery-percent",
            "5.5",
        ]);

        assert!(result.is_err());
    }

    #[test]
    fn create_recovery_percent_allows_values_above_one_hundred() {
        let args = create_args(&["set", "a.bin", "--recovery-percent", "150"]);

        assert_eq!(args.recovery_percent, Some(150));
    }

    #[test]
    fn create_limits_recovery_volume_count_to_thirty_one() {
        let result = Cli::try_parse_from([
            "rarpar",
            "par",
            "create",
            "set",
            "a.bin",
            "--volume-count",
            "32",
        ]);

        assert!(result.is_err());
    }

    fn xz(arguments: &[&str]) -> Result<XzCommand, clap::Error> {
        let mut command = vec!["rarpar", "xz"];
        command.extend(arguments);
        let cli = Cli::try_parse_from(command)?;
        match cli.command.expect("a command is required") {
            Command::Xz { command } => Ok(command),
            other => panic!("expected xz, got {other:?}"),
        }
    }

    #[test]
    fn xz_compress_defaults_follow_xz() {
        let Ok(XzCommand::Compress(args)) = xz(&["compress", "data.tar"]) else {
            panic!("expected xz compress");
        };
        assert_eq!(args.input, Some(PathBuf::from("data.tar")));
        assert_eq!(args.output, None);
        assert_eq!(args.level, 6);
        assert!(!args.extreme);
        assert_eq!(args.check, XzCheck::Crc64);
        assert_eq!(args.block_size, None);
        assert_eq!(args.threads, None);
        assert_eq!(args.memory_mib, None);
    }

    #[test]
    fn xz_compress_takes_every_option() {
        let Ok(XzCommand::Compress(args)) = xz(&[
            "compress",
            "-",
            "out.xz",
            "--level",
            "9",
            "--extreme",
            "-s",
            "65536",
            "--check",
            "sha256",
            "--threads",
            "4",
            "--memory-mib",
            "512",
        ]) else {
            panic!("expected xz compress");
        };
        assert_eq!(args.input, Some(PathBuf::from("-")));
        assert_eq!(args.output, Some(PathBuf::from("out.xz")));
        assert_eq!(args.level, 9);
        assert!(args.extreme);
        assert_eq!(args.block_size, Some(65_536));
        assert_eq!(args.check, XzCheck::Sha256);
        assert_eq!(args.threads, Some(4));
        assert_eq!(args.memory_mib, Some(512));
    }

    #[test]
    fn xz_rejects_out_of_range_values() {
        for arguments in [
            &["compress", "a", "--level", "10"][..],
            &["compress", "a", "--threads", "0"],
            &["compress", "a", "--block-size", "0"],
            &["compress", "a", "--check", "md5"],
            &["decompress", "a.xz", "--memory-mib", "0"],
            &["test", "a.xz", "--threads", "0"],
            &["list", "a.xz", "b.xz"],
        ] {
            assert!(xz(arguments).is_err(), "{arguments:?} should not parse");
        }
    }

    #[test]
    fn xz_decode_actions_share_their_resource_flags() {
        let Ok(XzCommand::Decompress(args)) = xz(&["decompress", "a.xz", "-", "--threads", "2"])
        else {
            panic!("expected xz decompress");
        };
        assert_eq!(args.output, Some(PathBuf::from("-")));
        assert_eq!(args.decode.threads, Some(2));
        assert_eq!(args.decode.memory_mib, 1024);
        let Ok(XzCommand::Test(args)) = xz(&["test", "a.xz", "--memory-mib", "64"]) else {
            panic!("expected xz test");
        };
        assert_eq!(args.decode.threads, None);
        assert_eq!(args.decode.memory_mib, 64);
        let Ok(XzCommand::List(args)) = xz(&["list", "a.xz"]) else {
            panic!("expected xz list");
        };
        assert_eq!(args.input, Some(PathBuf::from("a.xz")));
    }

    #[test]
    fn xz_honours_the_global_flags() {
        let cli = Cli::try_parse_from([
            "rarpar",
            "--json",
            "--overwrite",
            "xz",
            "decompress",
            "a.xz",
            "--dry-run",
        ])
        .expect("global flags parse around xz");
        assert!(cli.json && cli.overwrite && cli.dry_run);
    }

    #[test]
    fn create_keeps_global_working_dir_short_option_unambiguous() {
        let cli = Cli::try_parse_from([
            "rarpar", "-C", "work", "par", "create", "set", "a.bin", "-b", "2",
        ])
        .expect("global working directory and block count should parse together");

        assert_eq!(cli.working_dir, Some(PathBuf::from("work")));
        match cli.command {
            Some(Command::Par {
                command: ParCommand::Create(args),
            }) => assert_eq!(args.block_count, Some(2)),
            other => panic!("expected par create, got {other:?}"),
        }
    }

    #[test]
    fn global_output_directory_and_positional_output_are_both_visible() {
        let parse = |arguments: &[&str]| {
            let mut command = vec!["rarpar", "-o", "dir"];
            command.extend(arguments);
            Cli::try_parse_from(command).expect("-o and OUTPUT should parse together")
        };

        let cli = parse(&["xz", "compress", "in.tar", "out.xz"]);
        assert_eq!(cli.output, Some(PathBuf::from("dir")));
        let Some(Command::Xz {
            command: XzCommand::Compress(args),
        }) = &cli.command
        else {
            panic!("expected xz compress");
        };
        assert_eq!(args.output, Some(PathBuf::from("out.xz")));
        assert_eq!(
            cli.place_output(Path::new("out.xz")),
            Path::new("dir/out.xz")
        );
        assert_eq!(
            cli.place_output(Path::new("sub/out.xz")),
            Path::new("dir/sub/out.xz")
        );
        assert_eq!(
            cli.place_output(Path::new("/abs/out.xz")),
            Path::new("/abs/out.xz")
        );
        assert_eq!(cli.place_output(Path::new("-")), Path::new("-"));

        let cli = parse(&["xz", "decompress", "in.xz", "out.tar"]);
        assert_eq!(cli.output, Some(PathBuf::from("dir")));
        let Some(Command::Xz {
            command: XzCommand::Decompress(args),
        }) = &cli.command
        else {
            panic!("expected xz decompress");
        };
        assert_eq!(args.output, Some(PathBuf::from("out.tar")));

        let cli = parse(&["par3", "create", "set.par3", "a.bin"]);
        assert_eq!(cli.output, Some(PathBuf::from("dir")));
        let Some(Command::Par3 {
            command: Par3Command::Create(args),
        }) = &cli.command
        else {
            panic!("expected par3 create");
        };
        assert_eq!(args.output, PathBuf::from("set.par3"));

        let cli = parse(&["par", "create", "set", "a.bin"]);
        assert_eq!(cli.output, Some(PathBuf::from("dir")));
        let Some(Command::Par {
            command: ParCommand::Create(args),
        }) = &cli.command
        else {
            panic!("expected par create");
        };
        assert_eq!(args.output, PathBuf::from("set"));

        // Without -o, the positional no longer leaks into the global option.
        let cli = Cli::try_parse_from(["rarpar", "xz", "compress", "in.tar", "out.xz"]).unwrap();
        assert_eq!(cli.output, None);
    }
}
