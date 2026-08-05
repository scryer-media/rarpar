#[allow(dead_code)]
#[path = "support/benchmark_support.rs"]
mod benchmark_support;

use benchmark_support::{crate_bench_scenarios, stage_scenario};
use par2_rs::{Par2RepairSession, Par2RepairSessionOptions, Par2RepairStatus, Par2SessionError};

#[test]
fn recovery_volume_merge_reuses_the_single_source_scan() {
    let scenario = crate_bench_scenarios()
        .into_iter()
        .find(|scenario| scenario.name == "rar4_store_enc_corrupt_middle")
        .expect("stateful benchmark fixture");
    let staged = stage_scenario(&scenario);
    assert!(!staged.recovery_par2.is_empty());

    let mut session = Par2RepairSession::open(Par2RepairSessionOptions {
        base_dir: staged.temp.path().to_path_buf(),
        par2_paths: vec![staged.main_par2.clone()],
        extra_paths: staged.payload_paths.clone(),
        ..Par2RepairSessionOptions::default()
    })
    .expect("open stateful repair session");

    let before_recovery = session.analyze().expect("initial source analysis");
    assert_eq!(
        before_recovery.status,
        Par2RepairStatus::Insufficient,
        "the main PAR2 alone should not have enough recovery data"
    );
    let first = session.diagnostics().clone();
    assert_eq!(first.source_scan_passes, 1);
    assert!(first.scan.bytes_scanned > 0);

    session.analyze().expect("cached source analysis");
    let cached = session.diagnostics().clone();
    assert_eq!(cached.source_scan_passes, first.source_scan_passes);
    assert_eq!(cached.scan.bytes_scanned, first.scan.bytes_scanned);

    session
        .merge_recovery_paths(&staged.recovery_par2)
        .expect("merge recovery volumes");
    let after_merge = session.diagnostics().clone();
    assert_eq!(after_merge.source_scan_passes, first.source_scan_passes);
    assert_eq!(after_merge.scan.bytes_scanned, first.scan.bytes_scanned);

    let repairable = session.analyze().expect("assessment after recovery merge");
    assert_eq!(repairable.status, Par2RepairStatus::RepairPossible);
    let final_diagnostics = session.diagnostics();
    assert_eq!(final_diagnostics.source_scan_passes, 1);
    assert_eq!(
        final_diagnostics.scan.bytes_scanned,
        first.scan.bytes_scanned
    );
    eprintln!(
        "stateful_session_metrics scan_passes={} scan_bytes={} retained_bytes={} recovery_paths_merged={}",
        final_diagnostics.source_scan_passes,
        final_diagnostics.scan.bytes_scanned,
        final_diagnostics.retained_bytes,
        final_diagnostics.recovery_paths_merged,
    );
}

#[test]
fn recovery_merge_budget_rejection_is_transactional() {
    let scenario = crate_bench_scenarios()
        .into_iter()
        .find(|scenario| scenario.name == "rar4_store_enc_corrupt_middle")
        .expect("stateful benchmark fixture");
    let staged = stage_scenario(&scenario);

    let open = |retained_state_limit| {
        Par2RepairSession::open(Par2RepairSessionOptions {
            base_dir: staged.temp.path().to_path_buf(),
            par2_paths: vec![staged.main_par2.clone()],
            extra_paths: staged.payload_paths.clone(),
            retained_state_limit,
            ..Par2RepairSessionOptions::default()
        })
        .expect("open stateful repair session")
    };

    let mut probe = open(usize::MAX);
    let unmerged_bytes = probe.estimated_retained_bytes();
    probe
        .merge_recovery_paths(&staged.recovery_par2)
        .expect("measure merged state");
    let merged_bytes = probe.estimated_retained_bytes();
    assert!(merged_bytes > unmerged_bytes);
    let limit = unmerged_bytes.saturating_add((merged_bytes - unmerged_bytes) / 2);
    drop(probe);

    let mut session = open(limit);
    let before_bytes = session.estimated_retained_bytes();
    let before_diagnostics = session.diagnostics().clone();

    assert!(matches!(
        session.merge_recovery_paths(&staged.recovery_par2),
        Err(Par2SessionError::RetainedStateLimitExceeded { .. })
    ));
    assert_eq!(session.estimated_retained_bytes(), before_bytes);
    assert_eq!(session.diagnostics().source_scan_passes, 0);
    assert_eq!(session.diagnostics().recovery_paths_merged, 0);
    assert_eq!(
        session.diagnostics().packets.packets_loaded,
        before_diagnostics.packets.packets_loaded
    );
    assert_eq!(
        session.diagnostics().packets.duplicate_packets,
        before_diagnostics.packets.duplicate_packets
    );
    assert!(matches!(
        session.assessment(),
        Err(Par2SessionError::InvalidState { .. })
    ));
}
