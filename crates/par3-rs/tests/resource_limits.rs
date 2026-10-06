//! Concurrent handle leases and their error boundaries through public APIs.
mod common;

use par3_rs::runtime::{EngineError, ExecutionOptions, HandleBudget, ResourceLimit};
use par3_rs::source::{DiskSourceAccess, SourceAccess, SourceId, SourceSnapshot};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};

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
                Err(EngineError::ResourceLimit(ResourceLimit {
                    what: "Cauchy lost blocks",
                    ..
                }))
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
            EngineError::ResourceLimit(ResourceLimit {
                what: "open handles",
                ..
            })
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

// Read handles are cached only on Unix, where a file identity tells a cached
// handle on a replaced file from one on the file the path names.
#[cfg(unix)]
#[test]
fn disk_reads_open_each_source_once_and_close_with_the_registry() {
    let tree = common::TempTree::new("cached-reads");
    let files = [common::a_bin(), common::c_bin()];
    let options = ExecutionOptions::default();
    let mut disk = DiskSourceAccess::with_options(options.clone());
    for (index, bytes) in files.iter().enumerate() {
        let path = tree.path().join(format!("source{index}"));
        std::fs::write(&path, bytes).unwrap();
        disk.insert(SourceId(index as u64 + 1), path);
    }
    for round in 0..64 {
        for (index, bytes) in files.iter().enumerate() {
            let offset = round * 37 % bytes.len();
            let mut out = [0; 31];
            let read = disk
                .read_at(SourceId(index as u64 + 1), offset as u64, &mut out)
                .unwrap();
            assert_eq!(out[..read], bytes[offset..][..read]);
        }
    }
    assert_eq!(options.diagnostics.file_opens(), files.len() as u64);
    assert_eq!(options.handles.used(), files.len());
    drop(disk);
    assert_eq!(options.handles.used(), 0);
}

#[cfg(unix)]
#[test]
fn idle_cached_reads_yield_their_leases_to_other_openers() {
    let tree = common::TempTree::new("reclaimed-reads");
    let path = tree.path().join("source");
    std::fs::write(&path, common::a_bin()).unwrap();
    let mut options = ExecutionOptions::default();
    options.open_handles = 4;
    options.handles = HandleBudget::new(4);
    let mut disk = DiskSourceAccess::with_options(options.clone());
    disk.insert(SourceId(1), path);
    disk.read_at(SourceId(1), 0, &mut [0; 1]).unwrap();
    assert_eq!(options.handles.used(), 1);
    // The fourth reader finds the ceiling held by three readers and the idle
    // cached handle, and gets the cached handle's lease.
    let readers: Vec<_> = (0..4)
        .map(|_| disk.open_sequential(SourceId(1)).unwrap().unwrap())
        .collect();
    assert_eq!(options.handles.used(), 4);
    assert_eq!(options.handles.peak(), 4);
    let error = disk.read_at(SourceId(1), 0, &mut [0; 1]).unwrap_err();
    assert!(matches!(
        EngineError::from(error),
        EngineError::ResourceLimit(ResourceLimit {
            what: "open handles",
            ..
        })
    ));
    drop(readers);
    assert_eq!(options.handles.used(), 0);
    disk.read_at(SourceId(1), 0, &mut [0; 1]).unwrap();
    assert_eq!(options.diagnostics.file_opens(), 6);
}

// Windows scans a pinned carrier that denies writers, so it cannot change.
#[cfg(unix)]
#[test]
fn disk_scans_reject_a_carrier_replaced_or_truncated_mid_scan() {
    use par3_rs::ingest::{PacketScanner, ScanEvent};
    let bytes = common::set_vol0_par3();
    for truncate in [false, true] {
        let tree = common::TempTree::new("changed-carrier");
        let path = tree.path().join("carrier");
        std::fs::write(&path, &bytes).unwrap();
        let mut options = ExecutionOptions::default();
        // One packet header per refill, so the scan reads the file many times.
        options.stripe_bytes = 48;
        let mut disk = DiskSourceAccess::with_options(options.clone());
        disk.insert(SourceId(1), path.clone());
        let disk = Arc::new(disk);
        let mut scanner = PacketScanner::new(
            disk.clone(),
            SourceId(1),
            options.clone(),
            par3_rs::ScanLimits::default(),
        )
        .unwrap();
        assert!(matches!(scanner.poll().unwrap(), ScanEvent::Packet(_)));
        assert!(matches!(scanner.poll().unwrap(), ScanEvent::Packet(_)));
        assert_eq!(options.diagnostics.file_opens(), 1);
        if truncate {
            let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
            file.set_len(bytes.len() as u64 / 2).unwrap();
        } else {
            // Identical bytes in a new file: the cached handle still reads the
            // old one, and only the path's identity tells them apart.
            let replacement = tree.path().join("replacement");
            std::fs::write(&replacement, &bytes).unwrap();
            std::fs::rename(&replacement, &path).unwrap();
        }
        loop {
            match scanner.poll() {
                Ok(ScanEvent::Packet(_)) => {}
                Err(EngineError::SourceChanged(SourceId(1))) => break,
                Err(error) => panic!("unexpected scan error: {error}"),
                Ok(event) => panic!("changed carrier was not rejected: {event:?}"),
            }
        }
        drop(scanner);
        let opens = options.diagnostics.file_opens();
        let mut out = [0; 8];
        assert_eq!(disk.read_at(SourceId(1), 0, &mut out).unwrap(), 8);
        assert_eq!(out, bytes[..8]);
        // A truncated file is still the cached one; a replaced one is opened
        // again because the snapshot that saw it closed the stale handle.
        assert_eq!(
            options.diagnostics.file_opens(),
            opens + u64::from(!truncate)
        );
        assert_eq!(options.handles.used(), 1);
        drop(disk);
        assert_eq!(options.handles.used(), 0);
    }
}

/// Snapshot and read counts, and a file change armed for one read.
#[derive(Default)]
struct Watch {
    snapshots: AtomicUsize,
    reads: AtomicUsize,
    change: Mutex<Option<(usize, std::path::PathBuf, bool)>>,
}

impl Watch {
    /// Count a read, first making the armed change if this is its read.
    fn read(&self) {
        let read = self.reads.fetch_add(1, Ordering::Relaxed);
        let mut change = self.change.lock().unwrap();
        if change.as_ref().is_some_and(|(at, _, _)| *at == read) {
            let (_, path, truncate) = change.take().unwrap();
            if truncate {
                let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
                file.set_len(file.metadata().unwrap().len() / 2).unwrap();
            } else {
                let replacement = path.with_extension("replacement");
                std::fs::copy(&path, &replacement).unwrap();
                std::fs::rename(&replacement, &path).unwrap();
            }
        }
    }
}

/// A disk registry that counts snapshots and reads, positioned or forward,
/// and can change one of its files just before a chosen read.
struct Watched {
    disk: DiskSourceAccess,
    watch: Arc<Watch>,
}

impl Watched {
    fn new(disk: DiskSourceAccess) -> Self {
        Self {
            disk,
            watch: Arc::default(),
        }
    }

    /// Start counting afresh; before read `at` (from zero), replace `path`
    /// with a copy of itself, or truncate it to half its length.
    fn arm(&self, change: Option<(usize, std::path::PathBuf, bool)>) {
        self.watch.snapshots.store(0, Ordering::Relaxed);
        self.watch.reads.store(0, Ordering::Relaxed);
        *self.watch.change.lock().unwrap() = change;
    }

    fn counts(&self) -> (usize, usize) {
        (
            self.watch.snapshots.load(Ordering::Relaxed),
            self.watch.reads.load(Ordering::Relaxed),
        )
    }
}

struct WatchedReader(Box<dyn std::io::Read + Send>, Arc<Watch>);

impl std::io::Read for WatchedReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        self.1.read();
        self.0.read(out)
    }
}

impl SourceAccess for Watched {
    fn snapshot(&self, source: SourceId) -> std::io::Result<Option<SourceSnapshot>> {
        self.watch.snapshots.fetch_add(1, Ordering::Relaxed);
        self.disk.snapshot(source)
    }
    fn read_at(&self, source: SourceId, offset: u64, out: &mut [u8]) -> std::io::Result<usize> {
        self.watch.read();
        self.disk.read_at(source, offset, out)
    }
    fn next_available(
        &self,
        source: SourceId,
        offset: u64,
    ) -> std::io::Result<Option<std::ops::Range<u64>>> {
        self.disk.next_available(source, offset)
    }
    fn open_sequential(
        &self,
        source: SourceId,
    ) -> std::io::Result<Option<Box<dyn std::io::Read + Send>>> {
        Ok(self.disk.open_sequential(source)?.map(|reader| {
            Box::new(WatchedReader(reader, self.watch.clone())) as Box<dyn std::io::Read + Send>
        }))
    }
}

struct Run<T> {
    result: Result<T, EngineError>,
    /// Snapshots and reads during the measured operation alone.
    snapshots: usize,
    reads: usize,
    output: common::TempTree,
    inputs: common::TempTree,
}

/// Repair an input set from disk after flipping one byte at each
/// `(file, offset)`, optionally changing input `file` before read `at`.
fn repair_watched(
    set: &common::ManyBlockSet,
    damage: &[(usize, usize)],
    options: &ExecutionOptions,
    change: Option<(usize, usize, bool)>,
) -> Run<u64> {
    use par3_rs::session::{Par3RepairSession, RepairStatus};
    let inputs = common::TempTree::new("disk-repair-input");
    let mut disk = DiskSourceAccess::with_options(options.clone());
    for (index, (name, bytes)) in set.contents.iter().enumerate() {
        let mut damaged = bytes.clone();
        for &(_, at) in damage.iter().filter(|(file, _)| *file == index) {
            damaged[at] ^= 0x80;
        }
        let path = inputs.path().join(name);
        std::fs::write(&path, damaged).unwrap();
        disk.insert(SourceId(index as u64 + 1), path);
    }
    let watched = Arc::new(Watched::new(disk));
    let mut session = Par3RepairSession::new(set.id, watched.clone(), options.clone()).unwrap();
    for (index, (name, _)) in set.contents.iter().enumerate() {
        session.bind_file(name, SourceId(index as u64 + 1)).unwrap();
    }
    for path in &set.paths {
        for packet in common::scanned_packets(std::fs::read(path).unwrap(), options) {
            session.merge(packet).unwrap();
        }
    }
    assert_eq!(session.assess().unwrap().status, RepairStatus::Ready);
    let output = common::TempTree::new("disk-repair-output");
    watched.arm(
        change
            .map(|(file, at, truncate)| (at, inputs.path().join(&set.contents[file].0), truncate)),
    );
    let result = session
        .repair(output.path(), false)
        .map(|report| report.reconstructed_blocks);
    let (snapshots, reads) = watched.counts();
    drop(session);
    drop(watched);
    assert!(options.handles.peak() <= options.open_handles.min(options.handles.limit()));
    assert_eq!(options.handles.used(), 0);
    Run {
        result,
        snapshots,
        reads,
        output,
        inputs,
    }
}

/// Repair an input set from disk after flipping one byte at each
/// `(file, offset)`, and check the repaired files and the handle ceiling.
fn repair_from_disk(
    set: &common::ManyBlockSet,
    damage: &[(usize, usize)],
    options: &ExecutionOptions,
) -> Run<u64> {
    let run = repair_watched(set, damage, options, None);
    assert!(run.result.is_ok(), "repair failed: {:?}", run.result);
    for &(file, _) in damage {
        let (name, bytes) = &set.contents[file];
        assert_eq!(&std::fs::read(run.output.path().join(name)).unwrap(), bytes);
    }
    run
}

/// Create a one-file Cauchy set from disk in four stripe passes, optionally
/// changing the input before read `at` of planning or of execution, and
/// counting from the start of that phase.
fn create_watched(
    blocks: usize,
    change: Option<(usize, bool)>,
    planning: bool,
) -> Run<Vec<std::path::PathBuf>> {
    use par3_rs::creation::{
        CreationCodec, CreationOptions, CreationPlan, CreationSource, VolumeLayout,
    };
    let inputs = common::TempTree::new("disk-create-input");
    let path = inputs.path().join("input.bin");
    let mut bytes = vec![0; blocks * 4096];
    blake3::Hasher::new()
        .update(b"disk-create")
        .finalize_xof()
        .fill(&mut bytes);
    std::fs::write(&path, bytes).unwrap();
    let mut options = CreationOptions {
        block_size: 4096,
        recovery_count: 4,
        volumes: VolumeLayout::Uniform(1),
        codec: CreationCodec::Cauchy,
        ..CreationOptions::default()
    };
    options.execution.workers = 1;
    options.execution.stripe_bytes = 1024;
    let mut disk = DiskSourceAccess::with_options(options.execution.clone());
    disk.insert(SourceId(1), path.clone());
    let watched = Arc::new(Watched::new(disk));
    let output = common::TempTree::new("disk-create-output");
    let scratch = output.path().join("scratch");
    let carriers = output.path().join("carriers");
    std::fs::create_dir(&scratch).unwrap();
    std::fs::create_dir(&carriers).unwrap();
    let change = change.map(|(at, truncate)| (at, path.clone(), truncate));
    if planning {
        watched.arm(change.clone());
    }
    let result = CreationPlan::build(
        watched.clone(),
        &[CreationSource {
            name: "input.bin".into(),
            source: SourceId(1),
        }],
        options.clone(),
    )
    .and_then(|plan| {
        if !planning {
            watched.arm(change);
        }
        plan.execute(&carriers.join("set"), &scratch)
    });
    let (snapshots, reads) = watched.counts();
    Run {
        result,
        snapshots,
        reads,
        output,
        inputs,
    }
}

#[test]
fn creation_checks_each_source_once_per_stripe_pass() {
    for blocks in [32, 256] {
        let run = create_watched(blocks, None, false);
        run.result.unwrap();
        // Four stripe passes, each reading every block once.
        assert_eq!(run.reads, 4 * blocks);
        // One check before encoding, one after each pass's last read, and
        // one before installation; it was two per read.
        assert_eq!(run.snapshots, 6, "{blocks} blocks");
        drop(run.inputs);
    }
}

#[test]
fn creation_rejects_a_source_changed_within_or_between_stripe_passes() {
    // Read 5 is inside the first pass; read 32 opens the second, after the
    // first pass's rows are already in the spool. A replaced file still reads
    // through the old handle and is caught when that pass settles; a
    // truncated one fails at block 16, the first read past its new end. The
    // read counts show neither waits for the check before installation.
    for (at, truncate, reads) in [
        (5, false, 32),
        (5, true, 17),
        (32, false, 64),
        (32, true, 49),
    ] {
        if !truncate && !cfg!(unix) {
            // A copy keeps its bytes and, on Windows, its mtime; only a Unix
            // file identity tells the replacement apart.
            continue;
        }
        let run = create_watched(32, Some((at, truncate)), false);
        assert!(
            matches!(run.result, Err(EngineError::SourceChanged(SourceId(1)))),
            "change before read {at} (truncate {truncate}): {:?}",
            run.result
        );
        assert_eq!(
            run.reads, reads,
            "change before read {at} (truncate {truncate})"
        );
        let carriers = run.output.path().join("carriers");
        assert_eq!(std::fs::read_dir(&carriers).unwrap().count(), 0);
    }
}

#[test]
fn creation_planning_checks_each_source_once_and_rejects_a_changed_file() {
    let run = create_watched(32, None, true);
    run.result.unwrap();
    // Planning hashes the file through one forward reader in 1 KiB reads and
    // the encode reads it again in four passes.
    assert_eq!(run.reads, 128 + 128);
    // Planning snapshots the file once to start and checks it once after its
    // last chunk; execution adds the six counted above. Checking before and
    // after every block's hash added 64.
    assert_eq!(run.snapshots, 2 + 6);
    // Read 5 is early in planning's first block.
    for truncate in [false, true] {
        if !truncate && !cfg!(unix) {
            continue;
        }
        let run = create_watched(32, Some((5, truncate)), true);
        assert!(
            matches!(run.result, Err(EngineError::SourceChanged(SourceId(1)))),
            "change during planning (truncate {truncate}): {:?}",
            run.result
        );
        let carriers = run.output.path().join("carriers");
        assert_eq!(std::fs::read_dir(&carriers).unwrap().count(), 0);
    }
}

#[test]
fn repair_rejects_a_source_changed_within_or_between_stripe_passes() {
    let tree = common::TempTree::new("disk-repair-changed");
    let set = common::cauchy_block_set(32, 4096, 4, b"disk-repair-changed", &tree);
    let mut options = ExecutionOptions::default();
    options.workers = 1;
    options.stripe_bytes = 1024;
    // Thirty surviving blocks are read per pass: read 5 is inside the first
    // pass, read 30 opens the second, after the first pass was staged. Each
    // surviving stripe is staged as soon as it is read, so the change is
    // caught by the check before that write, one read later.
    for at in [5, 30] {
        for truncate in [false, true] {
            if !truncate && !cfg!(unix) {
                continue;
            }
            let run = repair_watched(
                &set,
                &[(0, 4096 + 5), (0, 9 * 4096 + 7)],
                &options,
                Some((0, at, truncate)),
            );
            // The staged temporary is handed to the host; nothing installed.
            match &run.result {
                Err(EngineError::RepairInterrupted {
                    installed, cause, ..
                }) if installed.is_empty()
                    && matches!(**cause, EngineError::SourceChanged(SourceId(1))) => {}
                result => panic!("change before read {at} (truncate {truncate}): {result:?}"),
            }
            assert_eq!(run.reads, at + 1);
            assert!(!run.output.path().join("input.bin").exists());
        }
    }
}

#[test]
fn repair_checks_sources_it_does_not_write_once_per_pass() {
    let tree = common::TempTree::new("disk-repair-checks");
    let set = common::many_block_set(8, 16, 0, 4, b"disk-repair-checks", &tree);
    let mut options = ExecutionOptions::default();
    options.workers = 1;
    let run = repair_from_disk(&set, &[(1, 70)], &options);
    // One stripe pass reads all 127 surviving blocks in file order, and only
    // the damaged second file is written. Its 15 reads are each checked before
    // the write that follows them; the seven other sources are checked once
    // each, before the next write. The other 32 are the evidence checks before
    // and after reconstruction, four per file. Checking every read cost 159.
    assert_eq!(run.reads, 127);
    assert_eq!(run.snapshots, 32 + 15 + 7);
}

#[cfg(unix)]
#[test]
fn disk_repair_opens_do_not_grow_with_the_number_of_reads() {
    let mut opens = Vec::new();
    for blocks in [32, 256] {
        let tree = common::TempTree::new("disk-repair-opens");
        let set = common::cauchy_block_set(blocks, 1024, 4, b"disk-repair-opens", &tree);
        let mut options = ExecutionOptions::default();
        options.workers = 1;
        options.stripe_bytes = 1024;
        repair_from_disk(&set, &[(0, 5), (0, 3 * 1024 + 7)], &options);
        opens.push(options.diagnostics.file_opens());
    }
    // Eight times the reads and staged writes, the same opens.
    assert_eq!(opens[0], opens[1], "opens per run: {opens:?}");
}

#[test]
fn disk_repair_completes_at_the_minimum_handle_budget() {
    let tree = common::TempTree::new("disk-repair-minimum");
    // Several sources and outputs, so the one cached reader and the one held
    // stage writer are evicted and reopened as the repair moves between them.
    let set = common::many_block_set(6, 16, 0, 4, b"disk-repair-minimum", &tree);
    let mut options = ExecutionOptions::default();
    options.open_handles = 5;
    options.handles = HandleBudget::new(5);
    repair_from_disk(&set, &[(1, 70), (4, 3)], &options);
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
