//! Concurrent handle leases and their error boundaries through public APIs.
mod common;

use par3_rs::runtime::{EngineError, ExecutionOptions, HandleBudget};
use par3_rs::source::{DiskSourceAccess, SourceAccess, SourceId};
use std::sync::{Arc, Barrier};

#[test]
fn cauchy_loss_ceiling_is_enforced_before_staging_outputs() {
    use par3_rs::ingest::{PacketScanner, ScanEvent};
    use par3_rs::source::MemorySourceAccess;
    for ceiling in [0, 1] {
        let tree = common::TempTree::new("cauchy-loss-limit");
        let mut options = ExecutionOptions::default();
        options.max_cauchy_lost_blocks = ceiling;
        let mut access = MemorySourceAccess::default();
        let mut damaged = common::a_bin();
        damaged[2300] ^= 1;
        access.insert(SourceId(1), 1, damaged.into());
        access.insert(SourceId(2), 1, common::b_txt().into());
        access.insert(SourceId(3), 1, common::c_bin().into());
        access.insert(SourceId(9), 1, common::set_vol0_par3().into());
        let access = Arc::new(access);
        let mut session =
            par3_rs::Par3RepairSession::new(common::SET_ID, access.clone(), options.clone())
                .unwrap();
        for (name, id) in [("a.bin", 1), ("b.txt", 2), ("sub/c.bin", 3)] {
            session.bind_file(name, SourceId(id)).unwrap();
        }
        let mut scanner = PacketScanner::new(
            access,
            SourceId(9),
            options.clone(),
            par3_rs::ScanLimits::default(),
        )
        .unwrap();
        while let ScanEvent::Packet(packet) = scanner.poll().unwrap() {
            session.merge(packet).unwrap();
        }
        assert_eq!(session.assess().unwrap().lost_blocks, [1]);
        let result = session.repair(tree.path(), false);
        if ceiling == 0 {
            assert!(matches!(
                result,
                Err(EngineError::ResourceLimit("Cauchy lost blocks"))
            ));
            assert_eq!(std::fs::read_dir(tree.path()).unwrap().count(), 0);
        } else {
            assert_eq!(result.unwrap().reconstructed_blocks, 1);
            assert_eq!(
                std::fs::read(tree.path().join("a.bin")).unwrap(),
                common::a_bin()
            );
        }
        assert_eq!(options.handles.used(), 0);
    }
}

#[test]
fn sequential_readers_share_a_ceiling_and_release_on_drop() {
    let tree = common::TempTree::new("shared-handles");
    let path = tree.path().join("source");
    std::fs::write(&path, common::a_bin()).unwrap();
    let mut options = ExecutionOptions::default();
    options.handles = HandleBudget::new(2);
    let mut disk = DiskSourceAccess::with_options(options.clone());
    disk.insert(SourceId(1), path);
    let disk = Arc::new(disk);
    let entered = Arc::new(Barrier::new(3));
    let release = Arc::new(Barrier::new(3));
    std::thread::scope(|scope| {
        for _ in 0..2 {
            let (disk, entered, release) = (disk.clone(), entered.clone(), release.clone());
            scope.spawn(move || {
                let _reader = disk.open_sequential(SourceId(1)).unwrap().unwrap();
                entered.wait();
                release.wait();
            });
        }
        entered.wait();
        assert_eq!(options.handles.used(), 2);
        let error = disk.read_at(SourceId(1), 0, &mut [0; 1]).unwrap_err();
        assert!(matches!(
            EngineError::from(error),
            EngineError::ResourceLimit("open handles")
        ));
        assert_eq!(options.handles.peak(), 2);
        release.wait();
    });
    assert_eq!(options.handles.used(), 0);
    assert_eq!(disk.read_at(SourceId(1), 0, &mut [0; 1]).unwrap(), 1);
    assert_eq!(options.handles.used(), 0);
    options.cancel.cancel();
    let error = disk.read_at(SourceId(1), 0, &mut [0; 1]).unwrap_err();
    assert!(matches!(EngineError::from(error), EngineError::Cancelled));
    assert_eq!(options.handles.used(), 0);
}

#[test]
fn failed_disk_open_preserves_io_error_and_releases_its_lease() {
    let tree = common::TempTree::new("failed-open");
    let options = ExecutionOptions::default();
    let mut disk = DiskSourceAccess::with_options(options.clone());
    disk.insert(SourceId(1), tree.path().join("absent"));
    let error = disk.read_at(SourceId(1), 0, &mut [0; 1]).unwrap_err();
    match EngineError::from(error) {
        EngineError::Io(error) => {
            assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
            assert!(error.raw_os_error().is_some());
        }
        error => panic!("original I/O failure lost: {error}"),
    }
    assert_eq!(options.handles.used(), 0);
}

#[test]
fn resolved_metadata_has_an_independent_budget_and_failed_admission_releases_it() {
    use par3_rs::ingest::{IncrementalSet, PacketScanner, ScanEvent};
    use par3_rs::runtime::MemoryBudget;
    use par3_rs::source::MemorySourceAccess;

    let mut access = MemorySourceAccess::default();
    access.insert(SourceId(99), 1, common::set_par3().into());
    let access = Arc::new(access);
    let mut scanner = PacketScanner::new(
        access.clone(),
        SourceId(99),
        ExecutionOptions::default(),
        par3_rs::ScanLimits::default(),
    )
    .unwrap();
    let mut packets = Vec::new();
    let mut input = IncrementalSet::new(common::SET_ID, ExecutionOptions::default()).unwrap();
    while let ScanEvent::Packet(packet) = scanner.poll().unwrap() {
        input.merge(packet.clone()).unwrap();
        packets.push(packet);
    }
    let packet_bytes = input.retained_bytes();
    drop(input);
    drop(scanner);

    for retained in [packet_bytes + 1, 1 << 20] {
        let mut options = ExecutionOptions::default();
        options.retained_bytes = retained;
        options.memory = MemoryBudget::new(4 << 20);
        let mut session =
            par3_rs::Par3RepairSession::new(common::SET_ID, access.clone(), options.clone())
                .unwrap();
        for packet in &packets {
            session.merge(packet.clone()).unwrap();
        }
        let before = options.memory.used();
        if retained == packet_bytes + 1 {
            for _ in 0..3 {
                assert!(matches!(
                    session.assess(),
                    Err(EngineError::ResourceLimit(_))
                ));
                assert_eq!(options.memory.used(), before);
                assert_eq!(session.retained_bytes(), packet_bytes);
            }
        } else {
            session.assess().unwrap();
            assert!(session.retained_bytes() > packet_bytes);
            assert!(session.retained_bytes() <= retained);
            let steady = options.memory.used();
            session.assess().unwrap();
            assert_eq!(options.memory.used(), steady);
        }
        assert!(options.memory.peak() <= options.memory.limit());
        drop(session);
        assert_eq!(options.memory.used(), 0);
    }
}
