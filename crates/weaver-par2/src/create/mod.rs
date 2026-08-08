//! Validated PAR2 creation with deterministic packet allocation and transactional outputs.

pub mod options;
pub mod source;
pub mod volume;

mod encode;
mod output;
mod plan;

pub use encode::ForwardKernel;
pub use options::{BlockSizing, Par2CreatorOptions, RecoveryAmount, VolumeScheme};
pub use output::Par2CreateOutcome;
pub use plan::{Par2CreatePlan, Par2MemoryPlan};
pub use source::CreationSource;
pub use volume::RecoveryVolumePlan;

use crate::error::{Par2Error, Result};

use self::output::write_outputs;
use self::plan::build_plan;

/// High-level PAR2 creator.
#[derive(Clone)]
pub struct Par2Creator {
    options: Par2CreatorOptions,
}

impl Par2Creator {
    /// Construct a creator from explicit source and output options.
    pub fn new(options: Par2CreatorOptions) -> Self {
        Self { options }
    }

    /// Borrow the options used by this creator.
    pub fn options(&self) -> &Par2CreatorOptions {
        &self.options
    }

    /// Validate inputs, hash sources, and allocate packets and output volumes.
    pub fn plan(&self) -> Result<Par2CreatePlan> {
        build_plan(&self.options)
    }

    /// Create the outputs described by a validated plan.
    pub fn create(&self, plan: &Par2CreatePlan) -> Result<Par2CreateOutcome> {
        if self.options.cancellation.is_cancelled() {
            return Err(Par2Error::Cancelled);
        }
        plan.validate_integrity()?;
        let canonical = self::plan::build_plan(&self.options)?;
        if plan != &canonical {
            return Err(Par2Error::InvalidCreationOptions {
                reason: "creation plan differs from creator options or current inputs".to_string(),
            });
        }
        if self.options.dry_run {
            return Ok(Par2CreateOutcome {
                recovery_set_id: plan.recovery_set_id,
                main_path: plan.main_path.clone(),
                volume_paths: plan.volume_paths.clone(),
                output_paths: plan.output_paths.clone(),
                source_slice_count: plan.source_slice_count,
                recovery_count: plan.recovery_count,
                bytes_written: 0,
                dry_run: true,
            });
        }

        write_outputs(plan, &canonical.sources, &self.options)
    }
}
