#[path = "support/par2cmdline_turbo_support.rs"]
mod support;

use std::fs;
use std::path::{Path, PathBuf};

use par2_rs::{
    BlockSizing, Par2Creator, Par2CreatorOptions, Par2FileSet, Par2Repairer, Par2RepairerOptions,
    RecoveryAmount, VolumeScheme,
};
use tempfile::tempdir;

fn par2_files(directory: &Path, stem: &str) -> Vec<PathBuf> {
    let mut paths = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("par2"))
                && path
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with(stem))
        })
        .collect::<Vec<_>>();
    paths.sort();
    paths
}

#[test]
#[ignore = "requires a direct PAR2 compatibility executable"]
fn creation_interoperates_in_both_directions() {
    let binaries = support::par2_interop_binaries();
    assert!(
        !binaries.is_empty(),
        "no PAR2 interoperability binary is configured; set PAR2_INTEROP_BINARIES to a platform path list or PAR2_TURBO_BINARY to one executable"
    );

    let directory = tempdir().unwrap();
    fs::write(directory.path().join("empty.bin"), []).unwrap();
    fs::write(directory.path().join("odd.bin"), [1, 2, 3, 4, 5]).unwrap();
    fs::write(
        directory.path().join("payload.bin"),
        (0..4096)
            .map(|index| (index * 17) as u8)
            .collect::<Vec<_>>(),
    )
    .unwrap();

    let mut local_options = Par2CreatorOptions::with_output(
        directory.path().join("local-set"),
        Some(directory.path().to_path_buf()),
        vec![
            directory.path().join("empty.bin"),
            directory.path().join("odd.bin"),
            directory.path().join("payload.bin"),
        ],
    );
    local_options.block_sizing = BlockSizing::Bytes(4);
    local_options.recovery_amount = RecoveryAmount::Count(8);
    local_options.volume_count = Some(3);
    local_options.volume_scheme = VolumeScheme::Variable;
    let local_creator = Par2Creator::new(local_options);
    let local_plan = local_creator.plan().unwrap();
    assert_eq!(local_plan.sources.len(), 2);
    assert!(
        local_plan
            .sources
            .iter()
            .all(|source| source.par2_name != "empty.bin")
    );
    assert_eq!(
        local_plan
            .volumes
            .iter()
            .map(|volume| volume.recovery_count)
            .collect::<Vec<_>>(),
        vec![3, 3, 2]
    );
    let local_outcome = local_creator.create(&local_plan).unwrap();

    for (index, binary) in binaries.iter().enumerate() {
        let binary_label = binary.display();
        let verify_local = support::run_par2_binary(
            binary,
            directory.path(),
            &["verify", local_outcome.main_path.to_str().unwrap()],
        );
        assert!(
            verify_local.status.success(),
            "{binary_label}: external verification of local output failed: {}",
            String::from_utf8_lossy(&verify_local.stderr)
        );

        fs::remove_file(directory.path().join("odd.bin")).unwrap();
        let repair_local = support::run_par2_binary(
            binary,
            directory.path(),
            &["repair", local_outcome.main_path.to_str().unwrap()],
        );
        assert!(
            repair_local.status.success(),
            "{binary_label}: external repair of local output failed: {}",
            String::from_utf8_lossy(&repair_local.stderr)
        );
        assert_eq!(
            fs::read(directory.path().join("odd.bin")).unwrap(),
            [1, 2, 3, 4, 5]
        );

        let external_stem = format!("external-set-{index}");
        let external_output = format!("{external_stem}.par2");
        let external_create_args = vec![
            "create",
            "-r150",
            "-n3",
            external_output.as_str(),
            "empty.bin",
            "odd.bin",
            "payload.bin",
        ];
        let external_create =
            support::run_par2_binary(binary, directory.path(), &external_create_args);
        assert!(
            external_create.status.success(),
            "{binary_label}: external creation failed: {}",
            String::from_utf8_lossy(&external_create.stderr)
        );
        let external_paths = par2_files(directory.path(), &external_stem);
        assert!(external_paths.len() > 1);
        let external_set = Par2FileSet::from_paths(&external_paths).unwrap();
        let mut local_options =
            Par2RepairerOptions::new(directory.path().to_path_buf(), external_paths.clone());
        local_options.file_set = Some(external_set);
        let verified = Par2Repairer::new(local_options).verify_or_repair().unwrap();
        assert_eq!(verified.verification.total_missing_blocks, 0);

        fs::remove_file(directory.path().join("odd.bin")).unwrap();
        let mut repair_options =
            Par2RepairerOptions::new(directory.path().to_path_buf(), external_paths);
        repair_options.repair = true;
        let repaired = Par2Repairer::new(repair_options)
            .verify_or_repair()
            .unwrap();
        assert_eq!(
            fs::read(directory.path().join("odd.bin")).unwrap(),
            [1, 2, 3, 4, 5]
        );
        assert!(matches!(
            repaired.status,
            par2_rs::Par2RepairStatus::Repaired | par2_rs::Par2RepairStatus::Verified
        ));
    }
}
