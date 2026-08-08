use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

pub const ROOT_LONG_ABOUT: &str = "\
rarpar is a smart RAR/PAR2 repair and extraction tool.

The normal workflow is `rarpar <path>`. Point it at a file or directory and it
will discover archive/parity sets, verify or repair PAR2 data when available,
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

rarpar is not an official RAR, UnRAR, or PAR2 utility and does not create or
modify RAR archives.";

#[derive(Clone, Debug, Parser)]
#[command(
    name = "rarpar",
    version,
    about = "Smart RAR/PAR2 repair and extraction CLI",
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

    /// Extraction output directory; multiple detected sets get separate subdirectories.
    #[arg(short = 'o', long, global = true, value_name = "DIR")]
    pub output: Option<PathBuf>,

    /// Repair/read-write working directory for PAR2 operations.
    #[arg(short = 'C', long, global = true, value_name = "DIR")]
    pub working_dir: Option<PathBuf>,

    /// Additional directory to search for PAR2-protected data files.
    #[arg(long, global = true, value_name = "DIR")]
    pub search_dir: Vec<PathBuf>,

    /// PAR2 file placement policy: smart scans by content; canonical uses recorded paths only.
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

    /// Allow extraction and PAR2 creation to overwrite existing output files.
    #[arg(long, global = true)]
    pub overwrite: bool,

    /// Delete consumed source files only after verified successful extraction.
    #[arg(long, global = true)]
    pub delete_sources: bool,

    /// Permanently delete cleanup candidates instead of using the OS trash/recycle bin.
    #[arg(long, global = true)]
    pub permanent_delete: bool,

    #[command(subcommand)]
    pub command: Option<Command>,

    /// Input paths for default auto mode.
    #[arg(value_name = "PATH")]
    pub paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Subcommand)]
pub enum Command {
    /// Discover, repair, restore, and extract what is safe to process.
    #[command(long_about = "\
Discover archive and parity sets, repair with PAR2 when possible, restore RAR
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
}

#[derive(Debug, Clone, Args)]
pub struct ParCreateArgs {
    /// Output PAR2 path or stem; recovery volumes use this stem as well.
    #[arg(value_name = "OUTPUT")]
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
}
