use std::fs;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
#[cfg(all(feature = "metal", target_os = "macos", target_arch = "aarch64"))]
use std::sync::{Mutex, MutexGuard, OnceLock};

#[cfg(all(feature = "metal", target_os = "macos", target_arch = "aarch64"))]
use par2_rs::ProgressStage;
use par2_rs::{
    BlockSizing, CreationBackend, ForwardKernel, Par2CreateOutcome, Par2Creator,
    Par2CreatorOptions, Par2Error, Par2FileSet, RecoveryAmount, VolumeScheme,
};
use tempfile::tempdir;

#[cfg(all(feature = "metal", target_os = "macos", target_arch = "aarch64"))]
static NATIVE_METAL_ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[cfg(all(feature = "metal", target_os = "macos", target_arch = "aarch64"))]
struct NativeMetalEnvGuard {
    _lock: MutexGuard<'static, ()>,
    previous: Option<std::ffi::OsString>,
}

#[cfg(all(feature = "metal", target_os = "macos", target_arch = "aarch64"))]
impl NativeMetalEnvGuard {
    fn set(value: &str) -> Self {
        let lock = NATIVE_METAL_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = std::env::var_os("WEAVER_GF16_METAL");
        unsafe { std::env::set_var("WEAVER_GF16_METAL", value) };
        Self {
            _lock: lock,
            previous,
        }
    }
}

#[cfg(all(feature = "metal", target_os = "macos", target_arch = "aarch64"))]
impl Drop for NativeMetalEnvGuard {
    fn drop(&mut self) {
        match self.previous.take() {
            Some(value) => unsafe { std::env::set_var("WEAVER_GF16_METAL", value) },
            None => unsafe { std::env::remove_var("WEAVER_GF16_METAL") },
        }
    }
}

#[test]
fn create_validates_empty_files_and_writes_critical_set() {
    let directory = tempdir().unwrap();
    let data = directory.path().join("data.bin");
    let empty = directory.path().join("empty.bin");
    fs::write(&data, b"abcdefghijk").unwrap();
    fs::write(&empty, []).unwrap();

    let output = directory.path().join("set.par2");
    let mut options = Par2CreatorOptions::with_output(
        output,
        Some(directory.path().to_path_buf()),
        vec![empty.clone(), data.clone()],
    );
    options.block_sizing = BlockSizing::Bytes(8);
    options.recovery_amount = RecoveryAmount::Count(0);

    let creator = Par2Creator::new(options);
    let plan = creator.plan().unwrap();
    assert_eq!(plan.source_slice_count, 2);
    assert_eq!(plan.sources.len(), 1);
    assert_eq!(plan.sources[0].par2_name, "data.bin");
    assert_eq!(plan.recovery_count, 0);
    // The exclusion must be NAMED, not silent: the set does not protect this
    // file, verify/repair will never look for it, and a caller can only warn
    // about what the plan reports. The reference tool prints this exclusion on
    // every noise level for the same reason. The path is the caller's own
    // spelling, because the warning is for the human who typed it.
    assert_eq!(plan.skipped_empty, vec![empty.clone()]);

    let outcome: Par2CreateOutcome = creator.create(&plan).unwrap();
    assert!(!outcome.dry_run);
    assert!(outcome.volume_paths.is_empty());
    assert_eq!(outcome.output_paths.len(), 1);
    assert!(outcome.main_path.is_file());

    let set = Par2FileSet::from_paths(&outcome.output_paths).unwrap();
    assert_eq!(set.recovery_set_id, outcome.recovery_set_id);
    assert_eq!(set.files.len(), 1);
    assert_eq!(set.recovery_block_count(), 0);
}

/// The creator memoizes its source scan between `plan()` and `create()`, so
/// `create()` reads a source again only when a fresh `stat` says it moved.
/// Every way a source can change that `stat` can see must still reach the
/// "plan differs from current inputs" rejection, and must reach it for a
/// creator that planned first (memo warm) exactly as for a fresh one.
#[test]
fn a_source_changed_after_planning_is_still_rejected_by_create() {
    for (label, rewrite) in [
        ("content and length", &[0x11u8; 512][..]),
        ("content only", &[0x22u8; 400][..]),
    ] {
        let directory = tempdir().unwrap();
        let data = directory.path().join("data.bin");
        fs::write(&data, vec![0x5a; 400]).unwrap();

        let mut options = Par2CreatorOptions::with_output(
            directory.path().join("set"),
            Some(directory.path().to_path_buf()),
            vec![data.clone()],
        );
        options.block_sizing = BlockSizing::Bytes(16);
        options.recovery_amount = RecoveryAmount::Count(2);

        let creator = Par2Creator::new(options);
        let plan = creator.plan().unwrap();
        // A rewrite moves mtime (and, for the first case, the length), which
        // is what the memo's fingerprint guard keys on.
        fs::write(&data, rewrite).unwrap();
        let error = creator.create(&plan).unwrap_err();
        assert!(
            matches!(error, Par2Error::InvalidCreationOptions { .. }),
            "{label}: rewritten source was accepted: {error:?}"
        );
    }
}

/// Planning twice on one creator must answer identically to planning once on
/// two creators: the memo is an implementation detail of where the bytes were
/// read, never of what the plan says.
#[test]
fn a_memoized_replan_matches_a_cold_plan() {
    let directory = tempdir().unwrap();
    let data = directory.path().join("data.bin");
    fs::write(&data, vec![0x5a; 4096]).unwrap();

    let build = || {
        let mut options = Par2CreatorOptions::with_output(
            directory.path().join("set"),
            Some(directory.path().to_path_buf()),
            vec![data.clone()],
        );
        options.block_sizing = BlockSizing::Bytes(64);
        options.recovery_amount = RecoveryAmount::Count(3);
        options
    };

    let warm = Par2Creator::new(build());
    let first = warm.plan().unwrap();
    let second = warm.plan().unwrap();
    let cold = Par2Creator::new(build()).plan().unwrap();
    assert_eq!(first, second, "memoized replan differs from the first plan");
    assert_eq!(first, cold, "memoized plan differs from a cold plan");
}

/// Multiple empty inputs are reported in the order the caller listed them —
/// the list is for a human matching it against what they typed, so it must
/// not come back resorted by resolution order or file id.
#[test]
fn skipped_empty_files_keep_the_caller_input_order() {
    let directory = tempdir().unwrap();
    let z_empty = directory.path().join("z-first-empty.bin");
    let data = directory.path().join("data.bin");
    let a_empty = directory.path().join("a-second-empty.bin");
    fs::write(&z_empty, []).unwrap();
    fs::write(&data, vec![0x5a; 64]).unwrap();
    fs::write(&a_empty, []).unwrap();

    let mut options = Par2CreatorOptions::with_output(
        directory.path().join("set"),
        Some(directory.path().to_path_buf()),
        vec![z_empty.clone(), data, a_empty.clone()],
    );
    options.block_sizing = BlockSizing::Bytes(16);
    options.recovery_amount = RecoveryAmount::Count(0);

    let plan = Par2Creator::new(options).plan().unwrap();
    assert_eq!(plan.sources.len(), 1);
    assert_eq!(plan.skipped_empty, vec![z_empty, a_empty]);
}

/// Being empty must not soften validation: a zero-length input that fails the
/// source checks (here: outside the base directory) is an error, not a skip —
/// otherwise "empty" becomes a hole through which invalid paths pass quietly.
#[test]
fn an_empty_file_outside_the_base_path_is_still_rejected() {
    let base = tempdir().unwrap();
    let outside = tempdir().unwrap();
    let data = base.path().join("data.bin");
    let stray_empty = outside.path().join("stray-empty.bin");
    fs::write(&data, vec![0x5a; 64]).unwrap();
    fs::write(&stray_empty, []).unwrap();

    let options = Par2CreatorOptions::with_output(
        base.path().join("set"),
        Some(base.path().to_path_buf()),
        vec![data, stray_empty],
    );
    assert!(matches!(
        Par2Creator::new(options).plan(),
        Err(Par2Error::UnsafeCreationSource { .. })
    ));
}

#[test]
fn creation_rejects_all_empty_inputs() {
    let directory = tempdir().unwrap();
    let first = directory.path().join("first.bin");
    let second = directory.path().join("second.bin");
    fs::write(&first, []).unwrap();
    fs::write(&second, []).unwrap();

    let options = Par2CreatorOptions::with_output(
        directory.path().join("set"),
        Some(directory.path().to_path_buf()),
        vec![first, second],
    );
    assert!(matches!(
        Par2Creator::new(options).plan(),
        Err(Par2Error::InvalidCreationOptions { .. })
    ));
}

#[test]
fn cancellation_during_encoding_removes_all_staged_outputs() {
    let directory = tempdir().unwrap();
    let data = directory.path().join("data.bin");
    fs::write(&data, b"abcdefghijk").unwrap();
    let cancellation = par2_rs::CancellationToken::new();
    let progress_calls = Arc::new(AtomicUsize::new(0));
    let callback_calls = Arc::clone(&progress_calls);
    let callback_cancellation = cancellation.clone();

    let mut options = Par2CreatorOptions::with_output(
        directory.path().join("cancelled"),
        Some(directory.path().to_path_buf()),
        vec![data],
    );
    options.block_sizing = BlockSizing::Bytes(4);
    options.recovery_amount = RecoveryAmount::Count(1);
    options.cancellation = cancellation;
    options.progress = Some(Arc::new(move |_| {
        if callback_calls.fetch_add(1, Ordering::Relaxed) >= 6 {
            callback_cancellation.cancel();
        }
    }));

    let creator = Par2Creator::new(options);
    let plan = creator.plan().unwrap();
    let error = creator.create(&plan).unwrap_err();
    assert!(matches!(error, Par2Error::Cancelled));
    assert!(progress_calls.load(Ordering::Relaxed) >= 7);
    assert!(fs::read_dir(directory.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".par2-create-")
    }));
}

#[test]
fn explicit_volume_count_is_uniform_and_capped_in_the_library_api() {
    let directory = tempdir().unwrap();
    let data = directory.path().join("data.bin");
    fs::write(&data, vec![0x5a; 400]).unwrap();

    let mut options = Par2CreatorOptions::with_output(
        directory.path().join("set"),
        Some(directory.path().to_path_buf()),
        vec![data.clone()],
    );
    options.block_sizing = BlockSizing::Bytes(4);
    options.recovery_amount = RecoveryAmount::Count(100);
    options.volume_count = Some(10);
    options.volume_scheme = VolumeScheme::Variable;

    let plan = Par2Creator::new(options).plan().unwrap();
    assert_eq!(
        plan.volumes
            .iter()
            .map(|volume| volume.recovery_count)
            .collect::<Vec<_>>(),
        vec![10; 10]
    );
    assert_eq!(plan.volumes[0].filename, "set.vol000+10.par2");
    assert_eq!(plan.volumes[9].filename, "set.vol090+10.par2");

    let mut rejected = Par2CreatorOptions::with_output(
        directory.path().join("rejected"),
        Some(directory.path().to_path_buf()),
        vec![data],
    );
    rejected.block_sizing = BlockSizing::Bytes(4);
    rejected.recovery_amount = RecoveryAmount::Count(100);
    rejected.volume_count = Some(32);
    assert!(matches!(
        Par2Creator::new(rejected).plan(),
        Err(Par2Error::InvalidCreationOptions { .. })
    ));
}

#[test]
fn limited_volume_scheme_caps_recovery_files_at_largest_source() {
    let directory = tempdir().unwrap();
    let data = directory.path().join("data.bin");
    fs::write(&data, vec![0x5a; 40]).unwrap();

    let mut options = Par2CreatorOptions::with_output(
        directory.path().join("limited"),
        Some(directory.path().to_path_buf()),
        vec![data],
    );
    options.block_sizing = BlockSizing::Bytes(4);
    options.recovery_amount = RecoveryAmount::Count(35);
    options.volume_scheme = VolumeScheme::Limited;

    let plan = Par2Creator::new(options).plan().unwrap();
    assert_eq!(plan.volume_scheme, VolumeScheme::Limited);
    assert_eq!(
        plan.volumes
            .iter()
            .map(|volume| volume.recovery_count)
            .collect::<Vec<_>>(),
        vec![1, 2, 4, 8, 10, 10]
    );
}

#[test]
fn unicode_output_stem_with_par2_suffix_is_boundary_safe() {
    let directory = tempdir().unwrap();
    let data = directory.path().join("data.bin");
    fs::write(&data, b"data").unwrap();
    let output = directory.path().join("séт.PAR2");
    let mut options = Par2CreatorOptions::with_output(
        output.clone(),
        Some(directory.path().to_path_buf()),
        vec![data],
    );
    options.recovery_amount = RecoveryAmount::Count(0);
    let plan = Par2Creator::new(options).plan().unwrap();
    assert_eq!(plan.main_path.file_name(), output.file_name());
    assert_eq!(plan.output_stem.file_name().unwrap(), "séт");
}

#[test]
fn dry_run_does_not_create_staged_or_final_files() {
    let directory = tempdir().unwrap();
    let data = directory.path().join("data.bin");
    fs::write(&data, b"data").unwrap();
    let output = directory.path().join("set");

    let mut options = Par2CreatorOptions::with_output(
        output.clone(),
        Some(directory.path().to_path_buf()),
        vec![data],
    );
    options.recovery_amount = RecoveryAmount::Count(0);
    options.dry_run = true;

    let creator = Par2Creator::new(options);
    let plan = creator.plan().unwrap();
    let outcome = creator.create(&plan).unwrap();
    assert!(outcome.dry_run);
    assert!(!output.with_extension("par2").exists());
    assert!(fs::read_dir(directory.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".par2-create-")
    }));
}

#[test]
fn create_streams_recovery_packets_and_backpatches_headers() {
    let directory = tempdir().unwrap();
    let data = directory.path().join("data.bin");
    fs::write(&data, b"abcdefghijk").unwrap();

    let mut options = Par2CreatorOptions::with_output(
        directory.path().join("set"),
        Some(directory.path().to_path_buf()),
        vec![data],
    );
    options.block_sizing = BlockSizing::Bytes(8);
    options.recovery_amount = RecoveryAmount::Count(1);

    let creator = Par2Creator::new(options);
    let plan = creator.plan().unwrap();
    let outcome = creator.create(&plan).unwrap();
    assert_eq!(outcome.recovery_count, 1);
    assert_eq!(outcome.volume_paths.len(), 1);

    let set = Par2FileSet::from_paths(&outcome.output_paths).unwrap();
    assert_eq!(set.recovery_block_count(), 1);
}

#[test]
fn overwrite_replaces_outputs_only_after_a_valid_staged_set() {
    let directory = tempdir().unwrap();
    let data = directory.path().join("data.bin");
    fs::write(&data, b"abcdefgh").unwrap();
    let output = directory.path().join("set.par2");

    let mut first_options = Par2CreatorOptions::with_output(
        output.clone(),
        Some(directory.path().to_path_buf()),
        vec![data.clone()],
    );
    first_options.recovery_amount = RecoveryAmount::Count(0);
    let first_creator = Par2Creator::new(first_options);
    let first_plan = first_creator.plan().unwrap();
    let first = first_creator.create(&first_plan).unwrap();

    let mut second_options =
        Par2CreatorOptions::with_output(output, Some(directory.path().to_path_buf()), vec![data]);
    second_options.recovery_amount = RecoveryAmount::Count(0);
    second_options.overwrite = true;
    let second_creator = Par2Creator::new(second_options);
    let second_plan = second_creator.plan().unwrap();
    let second = second_creator.create(&second_plan).unwrap();
    assert_eq!(first.recovery_set_id, second.recovery_set_id);
    assert!(fs::read_dir(directory.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".par2-create-")
    }));
}

#[test]
fn creation_uses_bounded_disk_backed_stripes_for_large_sources() {
    let directory = tempdir().unwrap();
    let data_path = directory.path().join("large.bin");
    let source_len = 4usize * 1024 * 1024 + 3;
    let data = (0..source_len)
        .map(|index| (index.wrapping_mul(31) ^ (index >> 7)) as u8)
        .collect::<Vec<_>>();
    fs::write(&data_path, &data).unwrap();
    let stale_stage = directory.path().join(".par2-create-stale.tmp");
    fs::write(&stale_stage, b"stale transaction residue").unwrap();

    let mut options = Par2CreatorOptions::with_output(
        directory.path().join("large-set"),
        Some(directory.path().to_path_buf()),
        vec![data_path],
    );
    options.block_sizing = BlockSizing::Bytes(4096);
    options.recovery_amount = RecoveryAmount::Count(1);
    options.memory_limit = Some(64 * 1024);

    let creator = Par2Creator::new(options);
    let plan = creator.plan().unwrap();
    assert!(source_len > plan.memory.processing_buffer_limit_bytes * 32);
    assert!(plan.memory.source_metadata_bytes > 0);
    assert!(plan.memory.source_hash_workspace_bytes >= 256 * 1024);
    assert!(plan.memory.main_file_id_workspace_bytes > 0);
    assert!(plan.memory.critical_packet_bytes > 0);
    assert!(plan.memory.packet_build_workspace_bytes > 0);
    assert!(plan.memory.validation_workspace_bytes >= 512 * 1024);
    assert!(plan.memory.processing_peak_bytes <= plan.memory.processing_buffer_limit_bytes);
    assert_eq!(
        plan.memory.processing_peak_bytes,
        plan.memory.factor_workspace_bytes
            + plan.memory.jit_workspace_bytes
            + plan.memory.stripe_buffer_bytes
    );
    assert!(
        plan.memory.total_creation_peak_bytes
            >= plan.memory.source_metadata_bytes * 2
                + plan.memory.critical_packet_bytes
                + plan.memory.main_file_id_workspace_bytes
                + plan.memory.packet_build_workspace_bytes
                + plan.memory.transaction_workspace_bytes
                + plan.memory.processing_peak_bytes
    );
    assert!(
        plan.memory.total_creation_peak_bytes
            >= plan.memory.source_metadata_bytes * 2
                + plan.memory.critical_packet_bytes
                + plan.memory.main_file_id_workspace_bytes
                + plan.memory.packet_build_workspace_bytes
                + plan.memory.transaction_workspace_bytes
                + plan.memory.validation_workspace_bytes
    );
    assert!(plan.memory.factor_workspace_bytes < 128 * 1024);
    assert_eq!(
        plan.memory.controller_overhead_blocks,
        2 + 24usize.min(plan.source_slice_count as usize + 1)
    );

    let outcome = creator.create(&plan).unwrap();
    let parsed = Par2FileSet::from_paths(&outcome.output_paths).unwrap();
    assert_eq!(parsed.recovery_block_count(), 1);
    assert!(stale_stage.is_file());
}

#[test]
fn create_revalidates_mutated_plan_source_output_collision() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("data.par2");
    fs::write(&source, b"source").unwrap();
    let output = directory.path().join("xxxx.par2");
    let mut options =
        Par2CreatorOptions::with_output(output, Some(directory.path().to_path_buf()), vec![source]);
    options.recovery_amount = RecoveryAmount::Count(0);
    options.forward_kernel = ForwardKernel::Portable;

    let creator = Par2Creator::new(options);
    let mut plan = creator.plan().unwrap();
    plan.sources[0].path = plan.main_path.clone();

    assert!(matches!(
        creator.create(&plan),
        Err(Par2Error::UnsafeCreationOutput { .. })
    ));
}

#[test]
fn create_revalidates_targets_that_appear_after_planning() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("data.bin");
    fs::write(&source, b"source").unwrap();
    let output = directory.path().join("set.par2");
    let mut options =
        Par2CreatorOptions::with_output(output, Some(directory.path().to_path_buf()), vec![source]);
    options.recovery_amount = RecoveryAmount::Count(0);

    let creator = Par2Creator::new(options);
    let plan = creator.plan().unwrap();
    fs::write(&plan.main_path, b"appeared after planning").unwrap();

    assert!(matches!(
        creator.create(&plan),
        Err(Par2Error::CreationOutputExists { .. })
    ));
}

#[cfg(unix)]
#[test]
fn create_rejects_planned_file_replaced_by_a_symlink_to_the_same_file() {
    use std::os::unix::fs::symlink;

    let directory = tempdir().unwrap();
    let source = directory.path().join("data.bin");
    let referent = directory.path().join("original.bin");
    let output = directory.path().join("set.par2");
    fs::write(&source, b"source").unwrap();
    fs::write(&referent, b"original output material").unwrap();
    fs::hard_link(&referent, &output).unwrap();

    let mut options = Par2CreatorOptions::with_output(
        output.clone(),
        Some(directory.path().to_path_buf()),
        vec![source],
    );
    options.overwrite = true;
    options.recovery_amount = RecoveryAmount::Count(0);

    let creator = Par2Creator::new(options);
    let plan = creator.plan().unwrap();
    fs::remove_file(&output).unwrap();
    symlink(&referent, &output).unwrap();

    assert!(matches!(
        creator.create(&plan),
        Err(Par2Error::UnsafeCreationOutput { .. })
    ));
    assert!(
        fs::symlink_metadata(&output)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read_link(&output).unwrap(), referent);
    assert_eq!(fs::read(&referent).unwrap(), b"original output material");
}

#[test]
fn create_rejects_coherent_same_length_output_path_mutation() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("data.bin");
    fs::write(&source, b"source").unwrap();
    let original = directory.path().join("set.par2");
    let redirected = directory.path().join("alt.par2");
    let mut options = Par2CreatorOptions::with_output(
        original.clone(),
        Some(directory.path().to_path_buf()),
        vec![source],
    );
    options.recovery_amount = RecoveryAmount::Count(0);

    let creator = Par2Creator::new(options);
    let mut plan = creator.plan().unwrap();
    plan.output_stem = directory.path().join("alt");
    plan.main_path = redirected.clone();
    plan.output_paths[0] = redirected.clone();

    assert!(matches!(
        creator.create(&plan),
        Err(Par2Error::InvalidCreationOptions { .. })
    ));
    assert!(!original.exists());
    assert!(!redirected.exists());
}

#[test]
fn create_rejects_mutated_dry_run_policy_before_staging() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("data.bin");
    let output = directory.path().join("set.par2");
    fs::write(&source, b"source").unwrap();
    let options = Par2CreatorOptions::with_output(
        output.clone(),
        Some(directory.path().to_path_buf()),
        vec![source],
    );

    let creator = Par2Creator::new(options);
    let mut plan = creator.plan().unwrap();
    plan.dry_run = true;

    assert!(matches!(
        creator.create(&plan),
        Err(Par2Error::InvalidCreationOptions { .. })
    ));
    assert!(!output.exists());
}

#[test]
fn create_rejects_mutated_volume_policy_and_exponent_allocation() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("data.bin");
    fs::write(&source, vec![0x5a; 64]).unwrap();
    let mut options = Par2CreatorOptions::with_output(
        directory.path().join("set"),
        Some(directory.path().to_path_buf()),
        vec![source],
    );
    options.block_sizing = BlockSizing::Bytes(4);
    options.recovery_amount = RecoveryAmount::Count(3);

    let creator = Par2Creator::new(options);
    let plan = creator.plan().unwrap();

    let mut policy_mutation = plan.clone();
    policy_mutation.volume_scheme = VolumeScheme::Uniform;
    assert!(matches!(
        creator.create(&policy_mutation),
        Err(Par2Error::InvalidCreationOptions { .. })
    ));

    let mut exponent_mutation = plan;
    exponent_mutation.first_exponent += 1;
    exponent_mutation.recovery_exponents = exponent_mutation
        .recovery_exponents
        .iter()
        .map(|exponent| exponent + 1)
        .collect();
    let mut next_exponent = exponent_mutation.first_exponent;
    for volume in &mut exponent_mutation.volumes {
        volume.first_exponent = next_exponent;
        next_exponent += volume.recovery_count;
    }
    assert!(matches!(
        creator.create(&exponent_mutation),
        Err(Par2Error::InvalidCreationOptions { .. })
    ));
}

#[test]
fn packet_build_workspace_includes_maximum_ifsc_body_and_is_integrity_bound() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("max.bin");
    fs::write(&source, vec![0x33; 4 * 32_768]).unwrap();
    let mut options = Par2CreatorOptions::with_output(
        directory.path().join("set"),
        Some(directory.path().to_path_buf()),
        vec![source],
    );
    options.block_sizing = BlockSizing::Bytes(4);
    options.recovery_amount = RecoveryAmount::Count(0);

    let creator = Par2Creator::new(options);
    let plan = creator.plan().unwrap();
    assert!(
        plan.memory.packet_build_workspace_bytes
            >= std::mem::size_of::<Vec<u8>>() + 16 + 20 * 32_768
    );

    let mut invalid = plan;
    invalid.memory.packet_build_workspace_bytes -= 1;
    assert!(matches!(
        creator.create(&invalid),
        Err(Par2Error::InvalidCreationOptions { .. })
    ));
}

#[cfg(not(all(feature = "metal", target_os = "macos", target_arch = "aarch64")))]
#[test]
fn auto_backend_falls_back_before_staging_when_metal_is_not_compiled() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("data.bin");
    fs::write(&source, b"backend fallback input").unwrap();
    let mut options = Par2CreatorOptions::with_output(
        directory.path().join("auto-set"),
        Some(directory.path().to_path_buf()),
        vec![source],
    );
    options.block_sizing = BlockSizing::Bytes(8);
    options.recovery_amount = RecoveryAmount::Count(1);
    options.backend = CreationBackend::Auto;

    let creator = Par2Creator::new(options);
    let plan = creator.plan().unwrap();
    let outcome = creator.create(&plan).unwrap();
    assert_eq!(outcome.requested_backend, CreationBackend::Auto);
    assert_eq!(outcome.selected_backend, CreationBackend::Cpu);
    assert!(directory.path().join("auto-set.par2").is_file());
    assert!(fs::read_dir(directory.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".par2-create-")
    }));
}

#[cfg(not(all(feature = "metal", target_os = "macos", target_arch = "aarch64")))]
#[test]
fn strict_metal_reports_typed_unavailable_error_without_staging() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("data.bin");
    fs::write(&source, b"strict backend input").unwrap();
    let mut options = Par2CreatorOptions::with_output(
        directory.path().join("strict-set"),
        Some(directory.path().to_path_buf()),
        vec![source],
    );
    options.block_sizing = BlockSizing::Bytes(8);
    options.recovery_amount = RecoveryAmount::Count(1);
    options.backend = CreationBackend::Metal;

    let creator = Par2Creator::new(options);
    let plan = creator.plan().unwrap();
    assert!(matches!(
        creator.create(&plan),
        Err(Par2Error::MetalUnavailable { .. })
    ));
    assert!(fs::read_dir(directory.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".par2-create-")
    }));
}

#[cfg(all(feature = "metal", target_os = "macos", target_arch = "aarch64"))]
#[test]
#[ignore = "requires native Metal hardware"]
fn native_metal_creation_matches_cpu_with_batching_tiling_and_stripes() {
    let _env_guard = NativeMetalEnvGuard::set("1");
    let directory = tempdir().unwrap();
    let files = (0..67)
        .map(|index| {
            let path = directory.path().join(format!("source-{index:03}.bin"));
            let data = (0..4_999)
                .map(|offset: usize| (offset.wrapping_mul(13) ^ index) as u8)
                .collect::<Vec<_>>();
            fs::write(&path, data).unwrap();
            path
        })
        .collect::<Vec<_>>();

    let make_options = |stem: &str, backend| {
        let mut options = Par2CreatorOptions::with_output(
            directory.path().join(stem),
            Some(directory.path().to_path_buf()),
            files.clone(),
        );
        options.block_sizing = BlockSizing::Bytes(5_000);
        options.recovery_amount = RecoveryAmount::Count(17);
        options.memory_limit = Some(8 * 1024 * 1024 + 512 * 1024);
        options.backend = backend;
        options
    };

    let cpu_creator = Par2Creator::new(make_options("cpu-set", CreationBackend::Cpu));
    let cpu_plan = cpu_creator.plan().unwrap();
    let cpu = cpu_creator.create(&cpu_plan).unwrap();

    let metal_creator = Par2Creator::new(make_options("metal-set", CreationBackend::Metal));
    let metal_plan = metal_creator.plan().unwrap();
    let metal = metal_creator.create(&metal_plan).unwrap();
    assert_eq!(metal.selected_backend, CreationBackend::Metal);
    assert_eq!(metal.source_slice_count, 67);
    assert_eq!(metal.recovery_count, 17);
    assert_eq!(
        metal_plan.memory.factor_workspace_bytes
            + metal_plan.memory.jit_workspace_bytes
            + metal_plan.memory.stripe_buffer_bytes,
        metal_plan.memory.processing_peak_bytes
    );
    assert_eq!(cpu.output_paths.len(), metal.output_paths.len());
    for (cpu_path, metal_path) in cpu.output_paths.iter().zip(&metal.output_paths) {
        assert_eq!(fs::read(cpu_path).unwrap(), fs::read(metal_path).unwrap());
    }
}

#[cfg(all(feature = "metal", target_os = "macos", target_arch = "aarch64"))]
#[test]
#[ignore = "requires native Metal hardware"]
fn native_metal_cancellation_after_encoding_leaves_no_transaction_residue() {
    let _env_guard = NativeMetalEnvGuard::set("1");
    let directory = tempdir().unwrap();
    let files = (0..67)
        .map(|index| {
            let path = directory.path().join(format!("source-{index:03}.bin"));
            let data = (0..4_999)
                .map(|offset: usize| (offset.wrapping_mul(17) ^ index) as u8)
                .collect::<Vec<_>>();
            fs::write(&path, data).unwrap();
            path
        })
        .collect::<Vec<_>>();
    let cancellation = par2_rs::CancellationToken::new();
    let source_phase_complete = Arc::new(AtomicUsize::new(0));
    let gpu_started = Arc::new(AtomicUsize::new(0));
    let phase = Arc::clone(&source_phase_complete);
    let started = Arc::clone(&gpu_started);
    let cancel = cancellation.clone();
    let mut options = Par2CreatorOptions::with_output(
        directory.path().join("metal-cancelled"),
        Some(directory.path().to_path_buf()),
        files,
    );
    options.block_sizing = BlockSizing::Bytes(5_000);
    options.recovery_amount = RecoveryAmount::Count(17);
    options.memory_limit = Some(8 * 1024 * 1024 + 512 * 1024);
    options.backend = CreationBackend::Metal;
    options.cancellation = cancellation;
    options.progress = Some(Arc::new(move |update| {
        if update.stage != ProgressStage::Creating {
            return;
        }
        if update.total > 10 {
            if update.current.saturating_add(1) == update.total {
                phase.store(1, Ordering::Relaxed);
            }
        } else if phase.load(Ordering::Relaxed) == 1 {
            started.fetch_add(1, Ordering::Relaxed);
            cancel.cancel();
        }
    }));

    let creator = Par2Creator::new(options);
    let plan = creator.plan().unwrap();
    let result = creator.create(&plan);
    assert!(matches!(result, Err(Par2Error::Cancelled)));
    assert!(gpu_started.load(Ordering::Relaxed) > 0);
    assert!(plan.output_paths.iter().all(|path| !path.exists()));
    assert!(fs::read_dir(directory.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".par2-create-")
    }));
}

#[cfg(all(feature = "metal", target_os = "macos", target_arch = "aarch64"))]
#[test]
#[ignore = "requires native Metal admission"]
fn native_metal_disabled_policy_reports_unavailable_before_staging() {
    let _env_guard = NativeMetalEnvGuard::set("0");
    let directory = tempdir().unwrap();
    let source = directory.path().join("data.bin");
    fs::write(&source, b"disabled Metal backend").unwrap();
    let mut options = Par2CreatorOptions::with_output(
        directory.path().join("disabled-set"),
        Some(directory.path().to_path_buf()),
        vec![source],
    );
    options.block_sizing = BlockSizing::Bytes(8);
    options.recovery_amount = RecoveryAmount::Count(1);
    options.backend = CreationBackend::Metal;

    let creator = Par2Creator::new(options);
    let plan = creator.plan().unwrap();
    assert!(matches!(
        creator.create(&plan),
        Err(Par2Error::MetalUnavailable { .. })
    ));
    assert!(fs::read_dir(directory.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".par2-create-")
    }));
}
