use std::fs;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use par2_rs::{
    BlockSizing, ForwardKernel, Par2CreateOutcome, Par2Creator, Par2CreatorOptions, Par2Error,
    Par2FileSet, RecoveryAmount, VolumeScheme,
};
use tempfile::tempdir;

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
                + plan.memory.transaction_workspace_bytes
                + plan.memory.processing_peak_bytes
    );
    assert!(
        plan.memory.total_creation_peak_bytes
            >= plan.memory.source_metadata_bytes * 2
                + plan.memory.critical_packet_bytes
                + plan.memory.main_file_id_workspace_bytes
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
