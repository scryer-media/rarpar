//! Caller-supplied PPMd model arenas through [`unrar_rs::WindowAllocator`].
//!
//! Every test that lends sets `max_heap_ppmd_arena_size` to zero, so every
//! PPMd arena of these fixtures, the 1 MiB cleanup arena included, comes from
//! the allocator, and keeps the LZ windows on the heap, so every request the
//! allocator sees is an arena. Outputs are checked against the default
//! extraction byte for byte.

use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use unrar_rs::{LimitKind, Limits, RarArchive, RarError, RarResult, WindowAllocator, WindowMemory};

/// The arena the `rar4_ppm_oldmv` member's PPMd block header declares.
const OLDMV_ARENA: u64 = 16 << 20;

const OLDMV: [&str; 4] = [
    "rar4_ppm_oldmv.rar",
    "rar4_ppm_oldmv.r00",
    "rar4_ppm_oldmv.r01",
    "rar4_ppm_oldmv.r02",
];

/// Heap memory filled with non-zero junk, counted while it lives. It may
/// report fewer bytes than it holds.
struct JunkMemory {
    bytes: Box<[u8]>,
    reported: usize,
    live: Arc<AtomicUsize>,
}

// SAFETY: the boxed slice is a heap buffer of at least `reported` bytes that
// this value alone owns; moving the box does not move it.
unsafe impl WindowMemory for JunkMemory {
    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.bytes.as_mut_ptr()
    }

    fn len(&self) -> usize {
        self.reported
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
    /// Refuse every request.
    refuse: bool,
    /// Report this many bytes fewer than were asked for.
    short_by: usize,
}

impl TestAllocator {
    fn live(&self) -> usize {
        self.live.load(Ordering::SeqCst)
    }

    fn requests(&self) -> Vec<usize> {
        self.requests.lock().unwrap().clone()
    }
}

impl WindowAllocator for TestAllocator {
    fn allocate(&self, len: usize) -> io::Result<Box<dyn WindowMemory>> {
        self.requests.lock().unwrap().push(len);
        if self.refuse {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "scratch volume is full",
            ));
        }
        // A repeating non-zero pattern: a read of a byte the model never
        // wrote would change the output and break the comparison.
        let bytes: Box<[u8]> = (0..len)
            .map(|i| (i as u8).wrapping_mul(53) | 0x81)
            .collect();
        self.live.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(JunkMemory {
            bytes,
            reported: len - self.short_by,
            live: Arc::clone(&self.live),
        }))
    }
}

/// Every PPMd arena from `allocator`, every window on the heap.
fn lent_limits(allocator: &Arc<TestAllocator>) -> Limits {
    Limits::default()
        .with_window_allocator(allocator.clone())
        .with_max_heap_ppmd_arena_size(0)
}

fn fixture_paths(names: &[&str]) -> Option<Vec<PathBuf>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rar4");
    let paths: Vec<PathBuf> = names.iter().map(|name| root.join(name)).collect();
    for path in &paths {
        // A missing fixture or an unhydrated pointer skips the case.
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

/// Extract with the decoder's own arenas and with lent ones; the outputs must
/// match byte for byte, the allocator must have been asked, and every lent
/// arena must be gone once the archive is. Returns the allocator's requests.
fn assert_lent_matches_owned(names: &[&str]) -> Option<Vec<usize>> {
    let paths = fixture_paths(names)?;
    let mut owned = open(&paths);
    let expected = extract_all(&mut owned).expect("owned extraction");
    assert!(!expected.is_empty());

    let allocator = Arc::new(TestAllocator::default());
    let mut archive = open(&paths);
    archive.set_limits(lent_limits(&allocator));
    let actual = extract_all(&mut archive).expect("lent extraction");
    assert_eq!(actual.len(), expected.len(), "{names:?}: member count");
    for (index, (actual, expected)) in actual.iter().zip(&expected).enumerate() {
        assert!(actual == expected, "{names:?}: member {index} differs");
    }
    let requests = allocator.requests();
    assert!(!requests.is_empty(), "{names:?}: no arena was lent");

    drop(archive);
    assert_eq!(
        allocator.live(),
        0,
        "{names:?}: an arena outlived the archive"
    );
    Some(requests)
}

#[test]
fn multivolume_member_matches_owned() {
    let requests = assert_lent_matches_owned(&OLDMV);
    if let Some(requests) = requests {
        assert_eq!(requests, [OLDMV_ARENA as usize]);
    }
}

/// Three solid members share one model: its arena is lent once and kept
/// across the member boundaries.
#[test]
fn solid_members_share_one_lent_arena() {
    let names = ["rar4_ppm_solid_mv.rar"];
    let Some(requests) = assert_lent_matches_owned(&names) else {
        return;
    };
    assert_eq!(requests.len(), 1, "{requests:?}");

    let paths = fixture_paths(&names).unwrap();
    let allocator = Arc::new(TestAllocator::default());
    let mut archive = open(&paths);
    archive.set_limits(lent_limits(&allocator));
    extract_all(&mut archive).unwrap();
    assert_eq!(
        allocator.live(),
        1,
        "the archive keeps its arena between members"
    );
    drop(archive);
    assert_eq!(allocator.live(), 0);
}

#[test]
fn grouped_solid_members_match_owned() {
    assert_lent_matches_owned(&["rar4_ppm_s2groups.rar"]);
}

/// A 1 MB model that fills and restarts several times inside its lent arena.
#[test]
fn model_restarts_in_a_lent_arena_match_owned() {
    assert_lent_matches_owned(&["rar4_ppm_solid_restart.rar"]);
}

/// A member that switches between PPMd and LZ blocks.
#[test]
fn mixed_ppmd_and_lz_blocks_match_owned() {
    assert_lent_matches_owned(&["test_read_format_rar_ppmd_lzss_conversion.rar"]);
}

/// Damaged PPMd data drives the decoder into its cleanup path, which
/// restarts the model over a 1 MiB arena, lent here. Junk-filled lent arenas
/// must give the same bytes and the same errors as owned ones.
#[test]
fn damaged_ppmd_behaves_the_same_on_lent_arenas() {
    for name in ["rar4_ppm_solid_restart.rar", "rar4_ppm_solid_mv.rar"] {
        let Some(paths) = fixture_paths(&[name]) else {
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

        let mut lent_requests = 0;
        for (start, size) in segments {
            for step in 1..6 {
                let at = start + size * step / 6;
                let mut bytes = original.clone();
                bytes[at] ^= 0xa5;
                bytes[at - 1] ^= 0x3c;

                let mut owned = RarArchive::open(io::Cursor::new(bytes.clone())).unwrap();
                let expected = per_member(&mut owned);

                let allocator = Arc::new(TestAllocator::default());
                let mut archive = RarArchive::open(io::Cursor::new(bytes)).unwrap();
                archive.set_limits(lent_limits(&allocator));
                let actual = per_member(&mut archive);
                assert!(
                    actual == expected,
                    "{name}: flip at {at} differs on lent arenas"
                );
                lent_requests += allocator.requests().len();

                drop(archive);
                assert_eq!(allocator.live(), 0, "{name}: flip at {at}");
            }
        }
        assert!(lent_requests > 0, "{name}: no arena was lent");
    }
}

/// An arena at the in-RAM limit stays in the decoder's own memory: the
/// allocator is not asked.
#[test]
fn arena_at_the_in_ram_limit_is_not_lent() {
    let Some(paths) = fixture_paths(&OLDMV) else {
        return;
    };
    let mut owned = open(&paths);
    let expected = extract_all(&mut owned).unwrap();

    let allocator = Arc::new(TestAllocator::default());
    let mut archive = open(&paths);
    archive.set_limits(lent_limits(&allocator).with_max_heap_ppmd_arena_size(OLDMV_ARENA));
    assert_eq!(extract_all(&mut archive).unwrap(), expected);
    assert!(allocator.requests().is_empty());
}

/// Without lowering `max_heap_ppmd_arena_size`, a window allocator is never
/// asked for an arena.
#[test]
fn a_window_allocator_alone_lends_no_arena() {
    let Some(paths) = fixture_paths(&OLDMV) else {
        return;
    };
    let allocator = Arc::new(TestAllocator::default());
    let mut archive = open(&paths);
    archive.set_limits(Limits::default().with_window_allocator(allocator.clone()));
    extract_all(&mut archive).unwrap();
    assert!(allocator.requests().is_empty());
}

/// `max_ppmd_arena_size` holds for lent arenas: one above it fails with the
/// arena limit and the allocator is not asked.
#[test]
fn arena_over_the_ceiling_is_refused_without_asking() {
    let Some(paths) = fixture_paths(&OLDMV) else {
        return;
    };
    let allocator = Arc::new(TestAllocator::default());
    let mut archive = open(&paths);
    let mut limits = lent_limits(&allocator);
    limits.max_ppmd_arena_size = OLDMV_ARENA - 1;
    archive.set_limits(limits);
    let err = extract_all(&mut archive).unwrap_err();
    assert!(
        matches!(
            err,
            RarError::ResourceLimit {
                kind: LimitKind::PpmdArena,
                ..
            }
        ),
        "{err:?}"
    );
    assert!(allocator.requests().is_empty());
}

#[test]
fn allocator_failure_is_its_own_error() {
    let Some(paths) = fixture_paths(&OLDMV) else {
        return;
    };
    let allocator = Arc::new(TestAllocator {
        refuse: true,
        ..TestAllocator::default()
    });
    let mut archive = open(&paths);
    archive.set_limits(lent_limits(&allocator));
    let err = extract_all(&mut archive).unwrap_err();
    match &err {
        RarError::WindowAllocatorFailed { bytes, error } => {
            assert_eq!(*bytes, OLDMV_ARENA);
            assert_eq!(error.kind(), io::ErrorKind::StorageFull);
            assert_eq!(error.to_string(), "scratch volume is full");
        }
        other => panic!("expected WindowAllocatorFailed, got {other:?}"),
    }
    assert_eq!(allocator.requests(), [OLDMV_ARENA as usize]);
    assert_eq!(allocator.live(), 0);
}

#[test]
fn short_memory_is_refused_and_released() {
    let Some(paths) = fixture_paths(&OLDMV) else {
        return;
    };
    let allocator = Arc::new(TestAllocator {
        short_by: 1,
        ..TestAllocator::default()
    });
    let mut archive = open(&paths);
    archive.set_limits(lent_limits(&allocator));
    let err = extract_all(&mut archive).unwrap_err();
    match &err {
        RarError::WindowAllocatorFailed { bytes, error } => {
            assert_eq!(*bytes, OLDMV_ARENA);
            assert_eq!(
                error.to_string(),
                format!("allocator returned {} bytes", OLDMV_ARENA - 1)
            );
        }
        other => panic!("expected WindowAllocatorFailed, got {other:?}"),
    }
    assert_eq!(allocator.live(), 0);
}

#[test]
fn limits_debug_shows_the_arena_limit() {
    let text = format!(
        "{:?}",
        Limits::default().with_max_heap_ppmd_arena_size(1 << 20)
    );
    assert!(text.contains("max_heap_ppmd_arena_size: 1048576"), "{text}");
}
