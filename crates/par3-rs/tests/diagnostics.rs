//! Measured work and cancellation are observable without source rereads.
mod common;
use par3_rs::runtime::{EngineError, ExecutionOptions, ProgressCallback, ProgressPhase, Stage};
use par3_rs::source::{MemorySourceAccess, SourceId};
use std::sync::{Arc, Mutex};

#[test]
fn verification_measures_real_reads_and_balances_stage_events() {
    let mut options = ExecutionOptions::default();
    options.stripe_bytes = 127;
    let events = Arc::new(Mutex::new(Vec::new()));
    let observed = events.clone();
    options.progress = Some(ProgressCallback::new(move |event| {
        observed.lock().unwrap().push(event)
    }));
    let layout = Arc::new(par3_rs::layout::BlockLayout::new(&common::gf8_set(), &options).unwrap());
    let mut source = MemorySourceAccess::default();
    source.insert(SourceId(1), 1, common::a_bin().into());
    let proof = par3_rs::evidence::verify_source(layout.clone(), 0, &source, SourceId(1), &options)
        .unwrap();
    assert!(proof.protected_complete());
    let io = options.diagnostics.source_io();
    assert_eq!(io.read_bytes, 5000);
    assert_eq!(io.read_requested, 5000);
    assert_eq!(io.read_calls, 5000u64.div_ceil(127));
    assert_eq!(options.diagnostics.file_io().read_bytes, 0);
    assert_eq!(options.diagnostics.stage(Stage::Verify).completed, 5000);
    let replay = par3_rs::evidence::verify_arrivals(layout, &proof, &source, &options).unwrap();
    assert!(replay.protected_complete());
    assert_eq!(options.diagnostics.source_io(), io);
    let events = events.lock().unwrap();
    let begins: Vec<_> = events
        .iter()
        .filter(|e| e.phase == ProgressPhase::Begin)
        .map(|e| e.operation)
        .collect();
    let ends: Vec<_> = events
        .iter()
        .filter(|e| e.phase == ProgressPhase::End)
        .map(|e| e.operation)
        .collect();
    assert_eq!(begins, ends);
    assert!(!begins.is_empty());
}

#[test]
fn creation_reports_only_outputs_installed_before_cancellation() {
    use par3_rs::creation::{CreationOptions, CreationPlan, CreationSource};
    let mut options = ExecutionOptions::default();
    options.workers = 1;
    let cancel = options.cancel.clone();
    options.progress = Some(ProgressCallback::new(move |event| {
        if event.stage == Stage::Create && event.phase == ProgressPhase::Advance {
            cancel.cancel();
        }
    }));
    let mut source = MemorySourceAccess::default();
    source.insert(SourceId(1), 1, common::a_bin().into());
    let plan = CreationPlan::build(
        Arc::new(source),
        &[CreationSource {
            source: SourceId(1),
            name: "a.bin".into(),
        }],
        CreationOptions {
            block_size: 1024,
            recovery_count: 2,
            execution: options.clone(),
            ..CreationOptions::default()
        },
    )
    .unwrap();
    let tree = common::TempTree::new("partial-creation");
    match plan
        .execute(&tree.path().join("set"), tree.path())
        .unwrap_err()
    {
        EngineError::OutputInterrupted { installed, cause } => {
            assert_eq!(installed, vec![tree.path().join("set.par3")]);
            assert!(matches!(*cause, EngineError::Cancelled));
            let bytes = std::fs::read(&installed[0]).unwrap();
            assert!(!common::packets_of(&bytes).is_empty());
        }
        error => panic!("partial installation was lost: {error}"),
    }
    assert_eq!(std::fs::read_dir(tree.path()).unwrap().count(), 1);
    assert_eq!(options.handles.used(), 0);
}

#[test]
fn cancelling_encoding_from_progress_cleans_spool_and_staging_for_both_codecs() {
    use par3_rs::creation::{CreationCodec, CreationOptions, CreationPlan, CreationSource};
    for codec in [
        CreationCodec::Cauchy,
        CreationCodec::Fft {
            capacity_log2: 3,
            interleave: 0,
        },
    ] {
        let mut options = ExecutionOptions::default();
        options.workers = 1;
        options.stripe_bytes = 128;
        let cancel = options.cancel.clone();
        options.progress = Some(ProgressCallback::new(move |event| {
            if event.stage == Stage::Encode && event.phase == ProgressPhase::Advance {
                cancel.cancel();
            }
        }));
        let mut source = MemorySourceAccess::default();
        source.insert(SourceId(1), 1, common::a_bin().into());
        let plan = CreationPlan::build(
            Arc::new(source),
            &[CreationSource {
                source: SourceId(1),
                name: "a.bin".into(),
            }],
            CreationOptions {
                codec,
                block_size: 1024,
                recovery_count: 2,
                execution: options.clone(),
                ..CreationOptions::default()
            },
        )
        .unwrap();
        let retained = options.memory.used();
        let tree = common::TempTree::new("cancel-progress");
        let error = plan
            .execute(&tree.path().join("set"), tree.path())
            .unwrap_err();
        assert!(matches!(error, EngineError::Cancelled), "{error}");
        assert_eq!(std::fs::read_dir(tree.path()).unwrap().count(), 0);
        assert_eq!(options.handles.used(), 0);
        assert_eq!(options.memory.used(), retained);
        assert!(options.diagnostics.file_io().write_bytes > 0);
        assert!(options.diagnostics.stage(Stage::Encode).completed > 0);
        assert_eq!(options.diagnostics.stage(Stage::Encode).calls, 1);
        drop(plan);
        assert_eq!(options.memory.used(), 0);
    }
}
