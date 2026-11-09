//! Caller-supplied LZ window memory ([`unrar_rs::WindowAllocator`]).
//!
//! Every test sets `max_dict_size` below the 256 KiB minimum window, so every
//! LZ window of these fixtures comes from the allocator, and checks the output
//! against the default heap-owned extraction byte for byte.

use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use unrar_rs::{Limits, RarArchive, RarError, RarResult, WindowAllocator, WindowMemory};

/// Below every fixture's window, so the allocator serves all of them.
const TINY_IN_RAM_LIMIT: u64 = 64 * 1024;

/// Heap memory filled with non-zero junk, counted while it lives.
struct JunkMemory {
    bytes: Box<[u8]>,
    live: Arc<AtomicUsize>,
}

// SAFETY: the boxed slice is a heap buffer of `len` bytes that this value
// alone owns; moving the box does not move it.
unsafe impl WindowMemory for JunkMemory {
    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.bytes.as_mut_ptr()
    }

    fn len(&self) -> usize {
        self.bytes.len()
    }
}

impl Drop for JunkMemory {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::SeqCst);
    }
}

#[derive(Default)]
struct TestAllocator {
    live: Arc<AtomicUsize>,
    requests: Mutex<Vec<usize>>,
    /// Fail every request after this many have succeeded.
    fail_after: Option<usize>,
}

impl TestAllocator {
    fn failing_after(successes: usize) -> Self {
        Self {
            fail_after: Some(successes),
            ..Self::default()
        }
    }

    fn live(&self) -> usize {
        self.live.load(Ordering::SeqCst)
    }

    fn requests(&self) -> Vec<usize> {
        self.requests.lock().unwrap().clone()
    }
}

impl WindowAllocator for TestAllocator {
    fn allocate(&self, len: usize) -> io::Result<Box<dyn WindowMemory>> {
        let mut requests = self.requests.lock().unwrap();
        if self.fail_after.is_some_and(|n| requests.len() >= n) {
            requests.push(len);
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "scratch volume is full",
            ));
        }
        requests.push(len);
        // A repeating non-zero pattern: a read of a byte the decoder never
        // wrote would leak it into the output and break the comparison.
        let bytes: Box<[u8]> = (0..len)
            .map(|i| (i as u8).wrapping_mul(31) | 0x81)
            .collect();
        self.live.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(JunkMemory {
            bytes,
            live: Arc::clone(&self.live),
        }))
    }
}

fn limits_with(allocator: &Arc<TestAllocator>) -> Limits {
    let mut limits = Limits::default();
    limits.max_dict_size = TINY_IN_RAM_LIMIT;
    limits.with_window_allocator(allocator.clone())
}

fn fixture_paths(dir: &str, names: &[&str]) -> Option<Vec<PathBuf>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let paths: Vec<PathBuf> = names.iter().map(|name| root.join(dir).join(name)).collect();
    for path in &paths {
        // A missing fixture or an unhydrated LFS pointer skips the case.
        let mut magic = [0u8; 4];
        let present = File::open(path)
            .and_then(|mut file| io::Read::read_exact(&mut file, &mut magic))
            .is_ok();
        if !present || &magic != b"Rar!" {
            eprintln!("skipping: {} not present", path.display());
            return None;
        }
    }
    Some(paths)
}

fn open(paths: &[PathBuf]) -> RarArchive {
    if paths.len() == 1 {
        RarArchive::open(File::open(&paths[0]).unwrap()).unwrap()
    } else {
        let readers: Vec<Box<dyn unrar_rs::ReadSeek>> = paths
            .iter()
            .map(|path| Box::new(File::open(path).unwrap()) as Box<dyn unrar_rs::ReadSeek>)
            .collect();
        RarArchive::open_volumes(readers).unwrap()
    }
}

/// Extract every file member in index order, stopping at the first error.
fn extract_all(archive: &mut RarArchive) -> RarResult<Vec<Vec<u8>>> {
    let files: Vec<usize> = archive
        .entries()
        .enumerate()
        .filter(|(_, member)| !member.is_directory)
        .map(|(index, _)| index)
        .collect();
    let mut outputs = Vec::new();
    for index in files {
        let mut output = Vec::new();
        archive.by_index(index)?.copy_to(&mut output)?;
        outputs.push(output);
    }
    Ok(outputs)
}

/// Extract with the default heap windows and with allocator windows; the
/// outputs must match byte for byte, and every allocator window must be gone
/// once the archive is.
fn assert_allocator_matches_heap(dir: &str, names: &[&str]) {
    let Some(paths) = fixture_paths(dir, names) else {
        return;
    };
    let mut heap = open(&paths);
    let expected = extract_all(&mut heap).expect("heap extraction");
    assert!(!expected.is_empty());

    let allocator = Arc::new(TestAllocator::default());
    let mut archive = open(&paths);
    archive.set_limits(limits_with(&allocator));
    let actual = extract_all(&mut archive).expect("allocator extraction");
    assert_eq!(actual.len(), expected.len(), "{names:?}: member count");
    for (index, (actual, expected)) in actual.iter().zip(&expected).enumerate() {
        assert!(actual == expected, "{names:?}: member {index} differs");
    }
    assert!(
        !allocator.requests().is_empty(),
        "{names:?}: the allocator supplied no window"
    );

    drop(archive);
    assert_eq!(
        allocator.live(),
        0,
        "{names:?}: a window outlived the archive"
    );
}

#[test]
fn rar5_plain_matches_heap() {
    assert_allocator_matches_heap("rar5", &["rar5_lz.rar"]);
}

#[test]
fn rar5_multifile_matches_heap() {
    assert_allocator_matches_heap("rar5", &["rar5_multifile_lz.rar"]);
}

#[test]
fn rar5_solid_matches_heap() {
    assert_allocator_matches_heap("rar5", &["rar5_solid.rar"]);
}

#[test]
fn rar5_multivolume_solid_matches_heap() {
    assert_allocator_matches_heap(
        "rar5",
        &[
            "test_read_format_rar5_multiarchive_solid.part01.rar",
            "test_read_format_rar5_multiarchive_solid.part02.rar",
            "test_read_format_rar5_multiarchive_solid.part03.rar",
            "test_read_format_rar5_multiarchive_solid.part04.rar",
        ],
    );
}

/// Seven non-solid LZ members decoded through one kept decoder: one window,
/// asked of the allocator once and reused for every member.
#[test]
fn rar5_many_members_reuse_one_allocator_window() {
    let names = ["test_read_format_rar5_win32.rar"];
    assert_allocator_matches_heap("rar5", &names);
    let Some(paths) = fixture_paths("rar5", &names) else {
        return;
    };
    let allocator = Arc::new(TestAllocator::default());
    let mut archive = open(&paths);
    archive.set_limits(limits_with(&allocator));
    extract_all(&mut archive).unwrap();
    assert_eq!(allocator.requests().len(), 1);
    assert_eq!(
        allocator.live(),
        1,
        "the archive keeps its window between members"
    );
    drop(archive);
    assert_eq!(allocator.live(), 0);
}

#[test]
fn rar4_lz_matches_heap() {
    assert_allocator_matches_heap("rar4", &["rar4_lz.rar"]);
}

#[test]
fn rar4_multifile_matches_heap() {
    assert_allocator_matches_heap("rar4", &["rar4_multifile_lz.rar"]);
}

#[test]
fn rar4_solid_multivolume_matches_heap() {
    assert_allocator_matches_heap("rar4", &["rar4_lz_solid_mv.rar"]);
}

#[test]
fn rar20_matches_heap() {
    assert_allocator_matches_heap("rar4", &["rar20_lz.rar"]);
}

#[test]
fn rar15_matches_heap() {
    assert_allocator_matches_heap("rar4", &["rar15_lz.rar"]);
}

/// Damaged members decode the same through junk-filled allocator memory as
/// through zeroed heap memory: the same bytes written, the same error. Bytes
/// flipped across the data area drive the decoders into bad distances and
/// lengths, the paths where an unwritten window byte could leak.
#[test]
fn damaged_archives_behave_the_same_on_junk_memory() {
    for (dir, name) in [
        ("rar5", "rar5_lz.rar"),
        ("rar5", "rar5_multifile_lz.rar"),
        ("rar4", "rar4_lz.rar"),
        ("rar4", "rar20_lz.rar"),
        ("rar4", "rar15_lz.rar"),
    ] {
        let Some(paths) = fixture_paths(dir, &[name]) else {
            continue;
        };
        let original = std::fs::read(&paths[0]).unwrap();
        let archive = RarArchive::open(io::Cursor::new(original.clone())).unwrap();
        let segments: Vec<(usize, usize)> = (0..archive.len())
            .filter_map(|index| archive.member_segments(index))
            .flat_map(|segments| segments.iter())
            .filter(|segment| segment.data_size > 16)
            .map(|segment| (segment.data_offset as usize, segment.data_size as usize))
            .collect();
        drop(archive);
        assert!(!segments.is_empty(), "{name}: no packed data");

        for (start, size) in segments {
            for step in 1..8 {
                let at = start + size * step / 8;
                let mut bytes = original.clone();
                bytes[at] ^= 0xa5;
                bytes[at.saturating_sub(1).max(start)] ^= 0x3c;

                let Ok(mut heap) = RarArchive::open(io::Cursor::new(bytes.clone())) else {
                    continue;
                };
                let expected = per_member(&mut heap);

                let allocator = Arc::new(TestAllocator::default());
                let mut archive = RarArchive::open(io::Cursor::new(bytes)).unwrap();
                archive.set_limits(limits_with(&allocator));
                let actual = per_member(&mut archive);
                assert!(
                    actual == expected,
                    "{name}: flip at {at} differs on junk memory"
                );

                drop(archive);
                assert_eq!(allocator.live(), 0, "{name}: flip at {at}");
            }
        }
    }
}

/// Each member's written bytes and error text, if any, extracting every
/// member even after one fails.
fn per_member(archive: &mut RarArchive) -> Vec<(Vec<u8>, Option<String>)> {
    (0..archive.len())
        .map(|index| {
            let mut output = Vec::new();
            let error = archive
                .by_index(index)
                .and_then(|entry| entry.copy_to(&mut output))
                .err()
                .map(|err| err.to_string());
            (output, error)
        })
        .collect()
}

#[test]
fn over_the_in_ram_limit_without_an_allocator_is_too_large() {
    let Some(paths) = fixture_paths("rar5", &["rar5_lz.rar"]) else {
        return;
    };
    let mut archive = open(&paths);
    let mut limits = Limits::default();
    limits.max_dict_size = TINY_IN_RAM_LIMIT;
    archive.set_limits(limits);
    let err = extract_all(&mut archive).unwrap_err();
    assert!(
        matches!(err, RarError::DictionaryTooLarge { max, .. } if max == TINY_IN_RAM_LIMIT),
        "{err:?}"
    );
}

#[test]
fn over_the_allocator_ceiling_is_too_large() {
    for (dir, name) in [("rar5", "rar5_lz.rar"), ("rar4", "rar4_lz.rar")] {
        let Some(paths) = fixture_paths(dir, &[name]) else {
            continue;
        };
        let allocator = Arc::new(TestAllocator::default());
        let mut archive = open(&paths);
        archive.set_limits(limits_with(&allocator).with_max_allocated_dict_size(128 * 1024));
        let err = extract_all(&mut archive).unwrap_err();
        assert!(
            matches!(err, RarError::DictionaryTooLarge { max, .. } if max == 128 * 1024),
            "{name}: {err:?}"
        );
        assert!(allocator.requests().is_empty(), "{name}: never asked");
    }
}

#[test]
fn allocator_failure_is_its_own_error() {
    for (dir, name) in [
        ("rar5", "rar5_lz.rar"),
        ("rar4", "rar4_lz.rar"),
        ("rar4", "rar15_lz.rar"),
    ] {
        let Some(paths) = fixture_paths(dir, &[name]) else {
            continue;
        };
        let allocator = Arc::new(TestAllocator::failing_after(0));
        let mut archive = open(&paths);
        archive.set_limits(limits_with(&allocator));
        let err = extract_all(&mut archive).unwrap_err();
        match &err {
            RarError::WindowAllocatorFailed { bytes, error } => {
                assert_eq!(Some(&(*bytes as usize)), allocator.requests().first());
                assert_eq!(error.kind(), io::ErrorKind::StorageFull);
            }
            other => panic!("{name}: expected WindowAllocatorFailed, got {other:?}"),
        }
        assert_eq!(allocator.live(), 0);
    }
}

/// The last member of seven is damaged: the members before it come out as on
/// the heap, it fails after its window was supplied, and the window goes with
/// the archive.
#[test]
fn window_is_released_when_extraction_fails_midway() {
    let Some(paths) = fixture_paths("rar5", &["test_read_format_rar5_win32.rar"]) else {
        return;
    };
    let mut bytes = std::fs::read(&paths[0]).unwrap();
    let archive = RarArchive::open(io::Cursor::new(bytes.clone())).unwrap();
    let last = archive.len() - 1;
    let segment = archive.member_segments(last).unwrap()[0].clone();
    drop(archive);
    let start = segment.data_offset as usize;
    let end = start + segment.data_size as usize;
    for byte in &mut bytes[start + 2..end] {
        *byte ^= 0x5a;
    }

    let mut heap = RarArchive::open(io::Cursor::new(bytes.clone())).unwrap();
    let expected = per_member(&mut heap);
    assert!(
        expected[last].1.is_some(),
        "the damage must fail the member"
    );
    assert!(expected[..last].iter().all(|(_, error)| error.is_none()));

    let allocator = Arc::new(TestAllocator::default());
    let mut archive = RarArchive::open(io::Cursor::new(bytes)).unwrap();
    archive.set_limits(limits_with(&allocator));
    assert_eq!(per_member(&mut archive), expected);
    assert_eq!(allocator.requests().len(), 1);
    drop(archive);
    assert_eq!(allocator.live(), 0);
}

#[test]
fn limits_debug_hides_the_allocator() {
    let allocator = Arc::new(TestAllocator::default());
    let text = format!("{:?}", limits_with(&allocator));
    assert!(
        text.contains("window_allocator: Some(\"<allocator>\")"),
        "{text}"
    );
    assert!(format!("{:?}", Limits::default()).contains("window_allocator: None"));
}
