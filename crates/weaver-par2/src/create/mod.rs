//! Validated PAR2 creation with deterministic packet allocation and transactional outputs.
//! Output transactions detect ordinary replacement races, but assume no other process with
//! equivalent filesystem permissions mutates their staging or backup paths.

pub mod options;
pub mod source;
pub mod volume;

mod encode;
mod metal;
mod output;
mod plan;

pub use encode::ForwardKernel;
/// The process-stable worker width, under a name that says why the repairer
/// wants it: sizing rayon's global pool on wasm (see
/// [`reedsolomon_rs::threading::ensure_pool`]). Repair has no width knob of its
/// own, and this value is already the crate's single embedder-supplied answer
/// to "how wide is the host", so both sides agree by construction.
pub(crate) use encode::configured_create_threads as configured_create_threads_for_pool;
pub use options::{BlockSizing, CreationBackend, Par2CreatorOptions, RecoveryAmount, VolumeScheme};
pub use output::Par2CreateOutcome;
pub use plan::{Par2CreatePlan, Par2MemoryPlan};
pub use source::CreationSource;
pub use volume::RecoveryVolumePlan;

use crate::error::{Par2Error, Result};

use self::output::write_outputs;
use self::plan::build_plan_with_cache;

/// High-level PAR2 creator.
#[derive(Clone)]
pub struct Par2Creator {
    options: Par2CreatorOptions,
    /// Source scan shared by this creator's `plan()` and `create()` calls, so
    /// one creation reads and hashes its inputs once rather than once per
    /// plan build. See [`self::source::SourceScanCache`] for what a reused
    /// entry still re-validates. Clones share it: a clone is the same creator
    /// over the same inputs, not a second opinion about them.
    scan: std::sync::Arc<self::source::SourceScanCache>,
}

impl Par2Creator {
    /// Construct a creator from explicit source and output options.
    pub fn new(options: Par2CreatorOptions) -> Self {
        Self {
            options,
            scan: std::sync::Arc::new(self::source::SourceScanCache::new()),
        }
    }

    /// Borrow the options used by this creator.
    pub fn options(&self) -> &Par2CreatorOptions {
        &self.options
    }

    /// Validate inputs, hash sources, and allocate packets and output volumes.
    pub fn plan(&self) -> Result<Par2CreatePlan> {
        build_plan_with_cache(&self.options, Some(&self.scan))
    }

    /// Create the outputs described by a validated plan.
    pub fn create(&self, plan: &Par2CreatePlan) -> Result<Par2CreateOutcome> {
        if self.options.cancellation.is_cancelled() {
            return Err(Par2Error::Cancelled);
        }
        // No-op on native (rayon's default sizing is already right). On
        // `wasm32-wasip1-threads` this is what actually gives the banded
        // accumulation, parallel source hashing, and parallel volume
        // validation a pool wider than one worker — the guest cannot read the
        // host core count, so the width comes from the same process-stable
        // value the band shape uses. Placed on the execution entry point, never
        // on `plan()`, so plan-only callers still never spawn a pool.
        reedsolomon_rs::threading::ensure_pool(self::encode::configured_create_threads);
        plan.validate_integrity()?;
        self::plan::validate_output_targets(
            &plan.output_paths,
            &plan.sources,
            self.options.overwrite,
        )?;
        // Rebuilt from the current inputs, exactly as before: every path is
        // resolved and stat'ed again and every derived quantity recomputed.
        // What the memo removes is the second READ of bytes whose fingerprint
        // has not moved since `plan()` produced them.
        let canonical = self::plan::build_plan_with_cache(&self.options, Some(&self.scan))?;
        if plan != &canonical {
            return Err(Par2Error::InvalidCreationOptions {
                reason: "creation plan differs from creator options or current inputs".to_string(),
            });
        }
        let slice_size =
            usize::try_from(plan.slice_size).map_err(|_| Par2Error::ResourceLimitExceeded {
                reason: "slice size exceeds addressable memory".to_string(),
            })?;
        let selected = metal::select_backend(
            self.options.backend,
            slice_size,
            plan.source_slice_count as usize,
            plan.recovery_count as usize,
            self.options.memory_limit,
        )?;
        let selected_backend = metal::selected_policy(&selected);
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
                requested_backend: self.options.backend,
                selected_backend,
            });
        }

        write_outputs(plan, &canonical.sources, &self.options, selected)
    }
}
