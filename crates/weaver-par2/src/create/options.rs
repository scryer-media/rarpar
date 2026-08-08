use std::fmt;
use std::path::PathBuf;

use crate::types::{CancellationToken, ProgressCallback};

use super::encode::ForwardKernel;

/// How the creator chooses the source slice size.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum BlockSizing {
    /// Choose a size targeting a moderate number of source slices.
    #[default]
    Auto,
    /// Use an explicit source slice size in bytes.
    Bytes(u64),
    /// Choose a source slice size that produces no more than this many slices.
    Count(u32),
}

/// How the creator chooses the number of recovery slices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryAmount {
    /// Derive recovery slices as a percentage of source slices.
    Percent(u32),
    /// Use an exact recovery-slice count.
    Count(u32),
}

impl Default for RecoveryAmount {
    fn default() -> Self {
        Self::Percent(5)
    }
}

/// How recovery slices are divided between recovery volume files.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum VolumeScheme {
    /// Allocate volume sizes in powers of two, from smallest to largest.
    #[default]
    Variable,
    /// Divide recovery slices as evenly as possible.
    Uniform,
    /// Limit each recovery volume to the number of blocks in the largest source file.
    Limited,
}

/// Inputs and safety controls for PAR2 creation.
///
/// `inputs` contains explicit files only. The creator resolves their names
/// relative to `base_path` and never walks a directory or expands a file list.
#[derive(Clone)]
pub struct Par2CreatorOptions {
    /// Output path or stem. A `.par2` suffix is added when absent.
    pub output: Option<PathBuf>,
    /// Directory against which source names are made relative.
    pub base_path: Option<PathBuf>,
    /// Explicit source file paths.
    pub inputs: Vec<PathBuf>,
    /// Source slice-size selection.
    pub block_sizing: BlockSizing,
    /// Recovery-slice selection.
    pub recovery_amount: RecoveryAmount,
    /// Exponent assigned to the first recovery slice.
    pub first_exponent: u32,
    /// Recovery-volume allocation scheme.
    pub volume_scheme: VolumeScheme,
    /// Explicit recovery-volume count, or automatic when absent.
    pub volume_count: Option<u32>,
    /// Optional bounded forward-processing buffer budget in bytes.
    pub memory_limit: Option<usize>,
    /// Arithmetic path requested for forward recovery encoding.
    pub forward_kernel: ForwardKernel,
    /// Permit replacing existing output files after a successful staged write.
    pub overwrite: bool,
    /// Suppress filesystem writes while retaining validation and planning.
    pub dry_run: bool,
    /// Cooperative cancellation shared with the caller.
    pub cancellation: CancellationToken,
    /// Optional progress observer.
    pub progress: Option<ProgressCallback>,
}

impl fmt::Debug for Par2CreatorOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Par2CreatorOptions")
            .field("output", &self.output)
            .field("base_path", &self.base_path)
            .field("inputs", &self.inputs)
            .field("block_sizing", &self.block_sizing)
            .field("recovery_amount", &self.recovery_amount)
            .field("first_exponent", &self.first_exponent)
            .field("volume_scheme", &self.volume_scheme)
            .field("volume_count", &self.volume_count)
            .field("memory_limit", &self.memory_limit)
            .field("forward_kernel", &self.forward_kernel)
            .field("overwrite", &self.overwrite)
            .field("dry_run", &self.dry_run)
            .field("cancellation", &self.cancellation.is_cancelled())
            .field("progress", &self.progress.as_ref().map(|_| "callback"))
            .finish()
    }
}

impl Par2CreatorOptions {
    /// Construct options with the default creation policy.
    pub fn new(base_path: Option<PathBuf>, inputs: Vec<PathBuf>) -> Self {
        Self {
            output: None,
            base_path,
            inputs,
            block_sizing: BlockSizing::Auto,
            recovery_amount: RecoveryAmount::default(),
            first_exponent: 0,
            volume_scheme: VolumeScheme::default(),
            volume_count: None,
            memory_limit: None,
            forward_kernel: ForwardKernel::Auto,
            overwrite: false,
            dry_run: false,
            cancellation: CancellationToken::new(),
            progress: None,
        }
    }

    /// Construct options with an output path and explicit source files.
    pub fn with_output(output: PathBuf, base_path: Option<PathBuf>, inputs: Vec<PathBuf>) -> Self {
        let mut options = Self::new(base_path, inputs);
        options.output = Some(output);
        options
    }

    /// Set the output path or stem.
    pub fn set_output(&mut self, output: PathBuf) {
        self.output = Some(output);
    }
}

impl Default for Par2CreatorOptions {
    fn default() -> Self {
        Self::new(None, Vec::new())
    }
}
