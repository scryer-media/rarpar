use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "rarpar", about = "Intelligent RAR/PAR2 repair and extraction")]
pub struct Cli {
    /// Emit machine-readable JSON.
    #[arg(long, global = true)]
    pub json: bool,

    /// Do not recurse into input directories.
    #[arg(long, global = true)]
    pub no_recursive: bool,

    /// Maximum directory scan depth.
    #[arg(long, global = true, default_value_t = 8)]
    pub max_depth: usize,

    /// Maximum files to inspect during discovery.
    #[arg(long, global = true, default_value_t = 20_000)]
    pub max_files: usize,

    /// Plan without mutating files.
    #[arg(long, global = true)]
    pub dry_run: bool,

    /// Extraction output directory.
    #[arg(short = 'o', long, global = true, value_name = "DIR")]
    pub output: Option<PathBuf>,

    /// Repair/read-write working directory.
    #[arg(short = 'C', long, global = true, value_name = "DIR")]
    pub working_dir: Option<PathBuf>,

    /// Additional data search directory.
    #[arg(long, global = true, value_name = "DIR")]
    pub search_dir: Vec<PathBuf>,

    /// File containing candidate archive passwords, one per line.
    #[arg(long, global = true, value_name = "PATH")]
    pub password_file: Option<PathBuf>,

    /// Environment variable containing one archive password candidate.
    #[arg(long, global = true, value_name = "NAME")]
    pub password_env: Option<String>,

    /// File descriptor containing candidate archive passwords, one per line.
    #[arg(long, global = true, value_name = "FD")]
    pub password_fd: Option<i32>,

    /// Allow overwriting existing output files.
    #[arg(long, global = true)]
    pub overwrite: bool,

    /// Delete consumed source files after successful extraction.
    #[arg(long, global = true)]
    pub delete_sources: bool,

    /// Permanently delete cleanup candidates instead of moving them to trash.
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
    Auto(PathArgs),
    /// Inspect input paths and print the planned work.
    Inspect(PathArgs),
    /// Delete source archive files after validating extracted outputs.
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
    Repair(ParArgs),
}

#[derive(Debug, Clone, Args)]
pub struct ParArgs {
    #[arg(value_name = "PAR2_OR_DIR")]
    pub input: PathBuf,
    #[arg(value_name = "SEARCH_DIR")]
    pub search_dirs: Vec<PathBuf>,
}
