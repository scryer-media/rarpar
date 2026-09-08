//! Concurrent handle leases and their error boundaries through public APIs.
mod common;

use par3_rs::runtime::{EngineError, ExecutionOptions, HandleBudget};
use par3_rs::source::{DiskSourceAccess, SourceAccess, SourceId};
use std::sync::{Arc, Barrier};

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
