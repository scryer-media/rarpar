use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

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

#[derive(Debug, Parser)]
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

    /// Inspect only the paths given; do not recurse into directories.
    #[arg(long, global = true)]
    pub no_recursive: bool,

    /// Maximum recursive directory scan depth.
    #[arg(long, global = true, default_value_t = 8)]
    pub max_depth: usize,

    /// Maximum number of files to inspect during discovery.
    #[arg(long, global = true, default_value_t = 20_000)]
    pub max_files: usize,

    /// Plan/report work without repairing, extracting, or deleting files.
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

    /// File containing candidate archive passwords, one per line; values are never printed.
    #[arg(long, global = true, value_name = "PATH")]
    pub password_file: Option<PathBuf>,

    /// Environment variable containing one archive password candidate.
    #[arg(long, global = true, value_name = "NAME")]
    pub password_env: Option<String>,

    /// File descriptor containing candidate archive passwords, one per line.
    #[arg(long, global = true, value_name = "FD")]
    pub password_fd: Option<i32>,

    /// Allow extraction to overwrite existing output files.
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
    /// Verify files against a PAR2 set.
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
