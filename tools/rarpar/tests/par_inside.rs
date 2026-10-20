//! PAR-inside over RAR5 archives made by RARLAB rar, through the library:
//! insertion as a `PAR3` service record, verification, byte-exact self-repair
//! and removal, for single archives, `-hp` archives and volume sets. There
//! is no other tool to check against, so the evidence is the round trip:
//! every repaired archive equals the inserted one byte for byte, every
//! removal gives back the original, and every archive still opens and
//! extracts the same members through unrar-rs. Damage is made in memory on
//! copies. The fixtures are not committed; each test skips when its fixture
//! is absent.
#![cfg(feature = "runtime")]

use std::io::Cursor;
use std::path::{Path, PathBuf};

use par3_rs::carrier::CarrierRestoration;
use par3_rs::creation::CreationOptions;
use par3_rs::runtime::{EngineError, ExecutionOptions};
use par3_rs::session::RepairStatus;
use rarpar::par_inside::{self, InsideError, InsideSet, Passwords, Placement, RECORD_NAME};
use unrar_rs::container::{BlockKind, Rar5Container};
use unrar_rs::{KdfCache, RarArchive, RarError, ReadSeek};

/// The password the `-hp` fixtures were made with.
const PASSWORD: &str = "secretpass";

fn fixture(kind: &str, name: &str) -> Option<PathBuf> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/unrar-rs/tests/fixtures")
        .join(kind)
        .join(name);
    if path.is_file() {
        Some(path)
    } else {
        eprintln!("skipping: fixture {} is not present", path.display());
        None
    }
}

fn volumes(stem: &str, count: usize) -> Option<Vec<PathBuf>> {
    (1..=count)
        .map(|part| fixture("rar5", &format!("{stem}.part{part}.rar")))
        .collect()
}

/// The plain single archive and the `-hp` one, with what opens each.
fn singles() -> Vec<(PathBuf, Option<&'static str>)> {
    [("rar5_lz.rar", None), ("rar5_hp_lz.rar", Some(PASSWORD))]
        .into_iter()
        .filter_map(|(name, password)| fixture("rar5", name).map(|path| (path, password)))
        .collect()
}

fn passwords(password: Option<&str>) -> Passwords {
    Passwords::new(password.map(str::to_owned).into_iter().collect())
}

/// Copy hosts into `dir/original`, insert into `dir/inserted`, and return
/// the inserted files.
fn insert(
    dir: &Path,
    sources: &[PathBuf],
    password: Option<&str>,
    placement: Placement,
    block_size: u64,
    recovery: u64,
) -> Vec<PathBuf> {
    let originals = dir.join("original");
    let inserted = dir.join("inserted");
    let scratch = dir.join("scratch");
    for directory in [&originals, &inserted, &scratch] {
        std::fs::create_dir_all(directory).unwrap();
    }
    let paths: Vec<PathBuf> = sources
        .iter()
        .map(|source| {
            let path = originals.join(source.file_name().unwrap());
            std::fs::copy(source, &path).unwrap();
            path
        })
        .collect();
    let options = ExecutionOptions::default();
    let hosts = par_inside::prepare_hosts(&paths, &passwords(password), &options).unwrap();
    let outputs: Vec<PathBuf> = hosts
        .iter()
        .map(|host| inserted.join(host.name()))
        .collect();
    let creation = |count| CreationOptions {
        block_size,
        recovery_count: count,
        ..CreationOptions::default()
    };
    if placement == Placement::Independent {
        for (host, output) in hosts.iter().zip(&outputs) {
            par_inside::insert_set(
                std::slice::from_ref(host),
                std::slice::from_ref(output),
                &[recovery],
                creation(recovery),
                &scratch,
            )
            .unwrap();
        }
    } else {
        let counts = par_inside::placement_counts(placement, hosts.len(), recovery).unwrap();
        par_inside::insert_set(&hosts, &outputs, &counts, creation(recovery), &scratch).unwrap();
    }
    assert_eq!(std::fs::read_dir(&scratch).unwrap().count(), 0);
    outputs
}

fn open_one(paths: &[PathBuf], password: Option<&str>) -> InsideSet {
    let mut sets =
        par_inside::open(paths, &passwords(password), &ExecutionOptions::default()).unwrap();
    assert_eq!(sets.len(), 1);
    sets.pop().unwrap()
}

fn repair_into(
    set: &mut InsideSet,
    dir: &Path,
    label: &str,
    password: Option<&str>,
) -> Vec<par3_rs::embedded::EmbeddedRepaired> {
    let out = dir.join(format!("repaired-{label}"));
    let scratch = dir.join(format!("scratch-{label}"));
    std::fs::create_dir_all(&out).unwrap();
    std::fs::create_dir_all(&scratch).unwrap();
    let destinations: Vec<PathBuf> = set.hosts.iter().map(|host| out.join(&host.name)).collect();
    let report = set
        .repair(&destinations, &scratch, &passwords(password))
        .unwrap();
    assert_eq!(std::fs::read_dir(&scratch).unwrap().count(), 0);
    report
}

/// Every member's bytes, CRC-checked by unrar-rs, from one archive or
/// volume set.
fn members(paths: &[PathBuf], password: Option<&str>) -> Vec<(String, Vec<u8>)> {
    let mut archive = match password {
        // Encrypted headers need the password before the first volume opens.
        Some(password) => {
            let mut archive = RarArchive::open_with_password(
                Cursor::new(std::fs::read(&paths[0]).unwrap()),
                password,
            )
            .unwrap();
            for (index, path) in paths.iter().enumerate().skip(1) {
                archive
                    .add_volume(index, Box::new(Cursor::new(std::fs::read(path).unwrap())))
                    .unwrap();
            }
            archive
        }
        None => {
            let readers: Vec<Box<dyn ReadSeek>> = paths
                .iter()
                .map(|path| {
                    Box::new(Cursor::new(std::fs::read(path).unwrap())) as Box<dyn ReadSeek>
                })
                .collect();
            RarArchive::open_volumes(readers).unwrap()
        }
    };
    let listed: Vec<_> = archive
        .metadata()
        .members
        .iter()
        .map(|member| (member.name.clone(), member.is_directory))
        .collect();
    assert!(!listed.is_empty());
    let mut out = Vec::new();
    for (index, (name, directory)) in listed.into_iter().enumerate() {
        if directory {
            continue;
        }
        let mut bytes = Vec::new();
        archive
            .by_index(index)
            .unwrap()
            .copy_to(&mut bytes)
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        out.push((name, bytes));
    }
    out
}

/// The archive walks to its end header with exactly one `PAR3` record,
/// immediately before the end header, whose data area is `gap` less the
/// record header.
fn assert_one_record(path: &Path, password: Option<&str>, gap: &std::ops::Range<u64>) {
    let container = Rar5Container::open(path, password, &KdfCache::new()).unwrap();
    let records: Vec<_> = container.service_records(RECORD_NAME).collect();
    assert_eq!(records.len(), 1);
    let record = records[0];
    assert_eq!(record.header.start, gap.start);
    assert_eq!(record.data.end, gap.end);
    assert_eq!(record.data.end, container.end_header().start);
    assert!(matches!(
        container.blocks.last().unwrap().kind,
        BlockKind::End
    ));
}

#[test]
fn round_trip_restores_the_original_bytes_and_reinserts_identically() {
    for (source, password) in singles() {
        let label = source.file_stem().unwrap().to_str().unwrap().to_owned();
        let original = std::fs::read(&source).unwrap();
        let expected = members(std::slice::from_ref(&source), password);
        let tree = tempfile::tempdir().unwrap();
        let inserted = insert(
            tree.path(),
            std::slice::from_ref(&source),
            password,
            Placement::Spread,
            1024,
            8,
        );
        let bytes = std::fs::read(&inserted[0]).unwrap();
        assert!(bytes.len() > original.len());
        // The archive with its record still opens and extracts the same.
        assert_eq!(members(&inserted, password), expected, "{label}");
        let mut set = open_one(&inserted, password);
        assert_eq!(set.status, RepairStatus::Complete, "{label}");
        let host = &set.hosts[0];
        assert!(host.complete && host.region_intact(), "{label}");
        assert_eq!(host.framing_intact, Some(true), "{label}");
        assert_eq!(host.length, bytes.len() as u64);
        assert_one_record(&inserted[0], password, &host.gap);
        assert!(set.needs_repair().is_empty());
        let stripped = tree
            .path()
            .join("stripped")
            .join(source.file_name().unwrap());
        std::fs::create_dir_all(stripped.parent().unwrap()).unwrap();
        set.remove(std::slice::from_ref(&stripped), &passwords(password))
            .unwrap();
        assert_eq!(std::fs::read(&stripped).unwrap(), original, "{label}");
        // Insertion is deterministic, sealed record headers included: the
        // stripped archive inserts to the same bytes again.
        let again = insert(
            &tree.path().join("again"),
            &[stripped],
            password,
            Placement::Spread,
            1024,
            8,
        );
        assert_eq!(std::fs::read(&again[0]).unwrap(), bytes, "{label}");
    }
}

/// Under `-hp` the record header is sealed: walking the archive without the
/// password is refused, and with it the record is found by name.
#[test]
fn a_sealed_archive_hides_its_record_header() {
    let Some(source) = fixture("rar5", "rar5_hp_store.rar") else {
        return;
    };
    let tree = tempfile::tempdir().unwrap();
    let inserted = insert(
        tree.path(),
        &[source],
        Some(PASSWORD),
        Placement::Spread,
        256,
        2,
    );
    let kdf = KdfCache::new();
    assert!(matches!(
        Rar5Container::open(&inserted[0], None, &kdf),
        Err(RarError::EncryptedArchive)
    ));
    let container = Rar5Container::open(&inserted[0], Some(PASSWORD), &kdf).unwrap();
    let record = container.service_records(RECORD_NAME).next().unwrap();
    // The header is IV and ciphertext: the record name is not in it.
    let bytes = std::fs::read(&inserted[0]).unwrap();
    let header = &bytes[record.header.start as usize..record.header.end as usize];
    assert!(!header.windows(4).any(|window| window == b"PAR3"));
}

#[test]
fn damage_in_the_header_middle_and_end_is_repaired_byte_for_byte() {
    for (source, password) in singles() {
        let original_len = std::fs::metadata(&source).unwrap().len() as usize;
        let tree = tempfile::tempdir().unwrap();
        let inserted = insert(
            tree.path(),
            std::slice::from_ref(&source),
            password,
            Placement::Spread,
            1024,
            8,
        );
        let clean = std::fs::read(&inserted[0]).unwrap();
        // The end header follows the record.
        for (label, offset) in [
            ("header", 20),
            ("middle", original_len / 2),
            ("end", clean.len() - 3),
        ] {
            let damaged = tree.path().join(format!("damaged-{label}"));
            std::fs::create_dir_all(&damaged).unwrap();
            let path = damaged.join(inserted[0].file_name().unwrap());
            let mut bytes = clean.clone();
            bytes[offset] ^= 0x5a;
            std::fs::write(&path, &bytes).unwrap();
            let mut set = open_one(std::slice::from_ref(&path), password);
            assert_eq!(set.status, RepairStatus::Ready, "{source:?} {label}");
            assert!(!set.hosts[0].complete);
            assert!(set.hosts[0].region_intact());
            let report = repair_into(&mut set, tree.path(), label, password);
            assert_eq!(report.len(), 1);
            assert!(report[0].data_rebuilt);
            assert_eq!(report[0].restoration, CarrierRestoration::Exact);
            assert_eq!(
                std::fs::read(&report[0].path).unwrap(),
                clean,
                "{source:?} {label}"
            );
        }
    }
}

/// A damaged record header is found by comparing it with the one the
/// archive and password rebuild, and is rebuilt byte for byte.
#[test]
fn a_damaged_record_header_is_reported_and_rebuilt() {
    for (source, password) in singles() {
        let tree = tempfile::tempdir().unwrap();
        let inserted = insert(
            tree.path(),
            std::slice::from_ref(&source),
            password,
            Placement::Spread,
            1024,
            4,
        );
        let clean = std::fs::read(&inserted[0]).unwrap();
        let set = open_one(&inserted, password);
        let gap = set.hosts[0].gap.clone();
        let prefix = set.hosts[0].prefix;
        drop(set);
        assert!(prefix > 0);
        for at in [gap.start, gap.start + prefix - 1] {
            let path = tree
                .path()
                .join(format!("framing-{at}"))
                .join(inserted[0].file_name().unwrap());
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            let mut bytes = clean.clone();
            bytes[at as usize] ^= 0x10;
            std::fs::write(&path, &bytes).unwrap();
            let mut set = open_one(std::slice::from_ref(&path), password);
            let host = &set.hosts[0];
            assert!(host.complete, "protected data is unaffected");
            assert!(host.carrier_intact);
            assert_eq!(host.framing_intact, Some(false));
            assert!(!host.region_intact());
            assert_eq!(set.needs_repair(), vec![0]);
            let report = repair_into(&mut set, tree.path(), &format!("framing-{at}"), password);
            assert_eq!(report.len(), 1);
            assert!(!report[0].data_rebuilt);
            assert_eq!(std::fs::read(&report[0].path).unwrap(), clean);
        }
    }
}

/// Without the password a sealed record header cannot be rebuilt: opening
/// reports it unchecked, and repairing that archive is refused rather than
/// writing a header that may be wrong.
#[test]
fn a_sealed_record_header_without_the_password_is_unchecked() {
    let Some(source) = fixture("rar5", "rar5_hp_lz.rar") else {
        return;
    };
    let original_len = std::fs::metadata(&source).unwrap().len() as usize;
    let tree = tempfile::tempdir().unwrap();
    let inserted = insert(
        tree.path(),
        &[source],
        Some(PASSWORD),
        Placement::Spread,
        1024,
        4,
    );
    for password in [None, Some("not the password")] {
        let set = open_one(&inserted, password);
        assert_eq!(set.status, RepairStatus::Complete);
        assert_eq!(set.hosts[0].framing_intact, None);
        assert!(set.hosts[0].region_intact());
        assert!(set.needs_repair().is_empty());
    }
    let clean = std::fs::read(&inserted[0]).unwrap();
    let path = tree
        .path()
        .join("damaged")
        .join(inserted[0].file_name().unwrap());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut bytes = clean.clone();
    // Inside the archive's own sealed headers, which the set protects.
    bytes[original_len / 2] ^= 0x01;
    std::fs::write(&path, &bytes).unwrap();
    let mut set = open_one(std::slice::from_ref(&path), None);
    assert_eq!(set.status, RepairStatus::Ready);
    let out = tree.path().join("out");
    std::fs::create_dir_all(&out).unwrap();
    let destination = out.join(inserted[0].file_name().unwrap());
    assert!(matches!(
        set.repair(
            std::slice::from_ref(&destination),
            &out,
            &Passwords::default()
        ),
        Err(InsideError::Par3(EngineError::Unsupported(_)))
    ));
    assert!(!destination.exists());
    // With the password the same damage is repaired exactly.
    let mut set = open_one(std::slice::from_ref(&path), Some(PASSWORD));
    let report = repair_into(&mut set, tree.path(), "with-password", Some(PASSWORD));
    assert_eq!(std::fs::read(&report[0].path).unwrap(), clean);
}

#[test]
fn region_damage_is_reported_and_the_region_is_regenerated() {
    for (source, password) in singles() {
        let tree = tempfile::tempdir().unwrap();
        let inserted = insert(
            tree.path(),
            std::slice::from_ref(&source),
            password,
            Placement::Spread,
            1024,
            8,
        );
        let clean = std::fs::read(&inserted[0]).unwrap();
        let gap = open_one(&inserted, password).hosts[0].gap.clone();
        // A byte in the last Recovery Data packet's payload.
        let offset = (gap.end - 10) as usize;
        let path = tree
            .path()
            .join("damaged")
            .join(inserted[0].file_name().unwrap());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut bytes = clean.clone();
        bytes[offset] ^= 0x01;
        std::fs::write(&path, &bytes).unwrap();
        let mut set = open_one(std::slice::from_ref(&path), password);
        let host = &set.hosts[0];
        assert!(host.complete, "protected data is unaffected");
        assert!(!host.region_intact());
        assert_eq!(host.packets_found + 1, host.packets_expected);
        assert_eq!(set.status, RepairStatus::Complete);
        let report = repair_into(&mut set, tree.path(), "region", password);
        assert_eq!(report.len(), 1);
        assert!(!report[0].data_rebuilt);
        assert_eq!(report[0].regenerated, 1);
        assert_eq!(report[0].restoration, CarrierRestoration::Derived);
        assert_eq!(std::fs::read(&report[0].path).unwrap(), clean);
    }
}

/// A region of many small recovery packets is checked slot by slot: two
/// packets swapped out of their slots are both missed even though each is
/// still a valid packet of the set.
#[test]
fn many_small_recovery_packets_are_each_checked_at_their_slot() {
    let Some(source) = fixture("rar5", "rar5_lz.rar") else {
        return;
    };
    const BLOCK: u64 = 64;
    const RECOVERY: u64 = 1024;
    const PACKET: usize = (BLOCK + 48 + 16 + 16 + 8) as usize;
    let tree = tempfile::tempdir().unwrap();
    let inserted = insert(
        tree.path(),
        &[source],
        None,
        Placement::Spread,
        BLOCK,
        RECOVERY,
    );
    let set = open_one(&inserted, None);
    let host = &set.hosts[0];
    assert_eq!(host.recovery, 0..RECOVERY);
    assert!(host.region_intact());
    assert_eq!(host.packets_found, host.packets_expected);
    let gap = host.gap.clone();
    drop(set);
    let mut bytes = std::fs::read(&inserted[0]).unwrap();
    let last = gap.end as usize - PACKET;
    let before = last - PACKET;
    let (head, tail) = bytes.split_at_mut(last);
    head[before..].swap_with_slice(&mut tail[..PACKET]);
    let path = tree
        .path()
        .join("swapped")
        .join(inserted[0].file_name().unwrap());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, &bytes).unwrap();
    let set = open_one(std::slice::from_ref(&path), None);
    let host = &set.hosts[0];
    assert!(host.complete, "protected data is unaffected");
    assert!(!host.region_intact());
    assert_eq!(host.packets_found + 2, host.packets_expected);
}

#[test]
fn any_lost_volume_is_rebuilt_from_the_other_regions() {
    let Some(sources) = volumes("generated_matrix_rar5_store_plain", 7) else {
        return;
    };
    let expected = members(&sources, None);
    // 180 KiB volumes over 4 KiB blocks: 45 blocks each, and the six other
    // regions of a spread placement hold 6 * 8 = 48 recovery blocks.
    let tree = tempfile::tempdir().unwrap();
    let inserted = insert(tree.path(), &sources, None, Placement::Spread, 4096, 56);
    assert_eq!(members(&inserted, None), expected);
    let clean: Vec<Vec<u8>> = inserted
        .iter()
        .map(|path| std::fs::read(path).unwrap())
        .collect();
    for lost in [0, 3, 6] {
        let dir = tree.path().join(format!("lost-{lost}"));
        std::fs::create_dir_all(&dir).unwrap();
        let mut present = Vec::new();
        for (index, path) in inserted.iter().enumerate() {
            if index != lost {
                let copy = dir.join(path.file_name().unwrap());
                std::fs::copy(path, &copy).unwrap();
                present.push(copy);
            }
        }
        // Open from a single surviving volume; the rest are found by name.
        let mut set = open_one(&present[..1], None);
        assert_eq!(set.hosts.len(), 7);
        assert_eq!(set.status, RepairStatus::Ready, "lost {lost}");
        assert_eq!(set.needs_repair(), vec![lost]);
        let report = repair_into(&mut set, tree.path(), &format!("lost-{lost}"), None);
        assert_eq!(report.len(), 1);
        assert_eq!(
            std::fs::read(&report[0].path).unwrap(),
            clean[lost],
            "lost {lost}"
        );
    }
    // Removal gives back every original volume.
    let mut set = open_one(&inserted[..1], None);
    let stripped = tree.path().join("stripped");
    std::fs::create_dir_all(&stripped).unwrap();
    let destinations: Vec<PathBuf> = set
        .hosts
        .iter()
        .map(|host| stripped.join(&host.name))
        .collect();
    set.remove(&destinations, &Passwords::default()).unwrap();
    for (source, output) in sources.iter().zip(&destinations) {
        assert_eq!(
            std::fs::read(output).unwrap(),
            std::fs::read(source).unwrap()
        );
    }
}

/// A lost volume and damage in another: every carrier is derived before any
/// rebuilt host changes, so both come back.
#[test]
fn a_lost_volume_and_a_damaged_one_are_rebuilt_together() {
    let Some(sources) = volumes("generated_matrix_rar5_store_plain", 7) else {
        return;
    };
    let tree = tempfile::tempdir().unwrap();
    let inserted = insert(tree.path(), &sources, None, Placement::Spread, 4096, 70);
    let clean: Vec<Vec<u8>> = inserted
        .iter()
        .map(|path| std::fs::read(path).unwrap())
        .collect();
    let dir = tree.path().join("two");
    std::fs::create_dir_all(&dir).unwrap();
    for (index, path) in inserted.iter().enumerate() {
        let copy = dir.join(path.file_name().unwrap());
        match index {
            2 => {}
            5 => {
                let mut bytes = clean[5].clone();
                bytes[9000] ^= 0x33;
                std::fs::write(&copy, bytes).unwrap();
            }
            _ => {
                std::fs::copy(path, &copy).unwrap();
            }
        }
    }
    let mut set = open_one(&[dir.join(inserted[0].file_name().unwrap())], None);
    assert_eq!(set.status, RepairStatus::Ready);
    assert_eq!(set.needs_repair(), vec![2, 5]);
    let report = repair_into(&mut set, tree.path(), "two", None);
    assert_eq!(report.len(), 2);
    for (repaired, index) in report.iter().zip([2, 5]) {
        assert_eq!(std::fs::read(&repaired.path).unwrap(), clean[index]);
    }
}

#[test]
fn last_placement_cannot_survive_losing_the_last_volume() {
    let Some(sources) = volumes("generated_matrix_rar5_store_plain", 7) else {
        return;
    };
    let tree = tempfile::tempdir().unwrap();
    let inserted = insert(tree.path(), &sources, None, Placement::Last, 4096, 56);
    let dir = tree.path().join("lost-last");
    std::fs::create_dir_all(&dir).unwrap();
    for path in &inserted[..6] {
        std::fs::copy(path, dir.join(path.file_name().unwrap())).unwrap();
    }
    let set = open_one(&[dir.join(inserted[0].file_name().unwrap())], None);
    assert_eq!(set.status, RepairStatus::NeedRecovery);
    let dir = tree.path().join("lost-first");
    std::fs::create_dir_all(&dir).unwrap();
    for path in &inserted[1..] {
        std::fs::copy(path, dir.join(path.file_name().unwrap())).unwrap();
    }
    let mut set = open_one(&[dir.join(inserted[6].file_name().unwrap())], None);
    assert_eq!(set.status, RepairStatus::Ready);
    let report = repair_into(&mut set, tree.path(), "last", None);
    assert_eq!(
        std::fs::read(&report[0].path).unwrap(),
        std::fs::read(&inserted[0]).unwrap()
    );
}

#[test]
fn independent_placement_gives_each_volume_its_own_set() {
    let Some(sources) = volumes("generated_matrix_rar5_store_plain", 7) else {
        return;
    };
    let tree = tempfile::tempdir().unwrap();
    let inserted = insert(tree.path(), &sources, None, Placement::Independent, 4096, 4);
    let sets = par_inside::open(
        &inserted,
        &Passwords::default(),
        &ExecutionOptions::default(),
    )
    .unwrap();
    assert_eq!(sets.len(), 7);
    assert!(
        sets.iter()
            .all(|set| set.hosts.len() == 1 && set.status == RepairStatus::Complete)
    );
    assert!(par_inside::placement_counts(Placement::Independent, 3, 9).is_err());
    assert_eq!(
        par_inside::placement_counts(Placement::Spread, 3, 7).unwrap(),
        [3, 2, 2]
    );
    assert_eq!(
        par_inside::placement_counts(Placement::Last, 3, 7).unwrap(),
        [0, 0, 7]
    );
}

#[test]
fn renamed_hosts_are_matched_and_missing_siblings_found_by_stem() {
    let Some(sources) = volumes("generated_matrix_rar5_store_plain", 7) else {
        return;
    };
    let tree = tempfile::tempdir().unwrap();
    let inserted = insert(tree.path(), &sources, None, Placement::Spread, 4096, 56);
    let dir = tree.path().join("renamed");
    std::fs::create_dir_all(&dir).unwrap();
    let mut renamed = Vec::new();
    for (index, path) in inserted.iter().enumerate() {
        let name = format!("nightjar-survey.part{}.rar", index + 1);
        if index != 2 {
            std::fs::copy(path, dir.join(&name)).unwrap();
        }
        renamed.push(dir.join(name));
    }
    let mut set = open_one(&renamed[..1], None);
    assert_eq!(set.hosts.len(), 7);
    let bound: Vec<_> = set.hosts.iter().map(|host| host.path.is_some()).collect();
    assert_eq!(bound, [true, true, false, true, true, true, true]);
    assert_eq!(set.needs_repair(), vec![2]);
    let report = repair_into(&mut set, tree.path(), "renamed", None);
    assert_eq!(
        std::fs::read(&report[0].path).unwrap(),
        std::fs::read(&inserted[2]).unwrap()
    );

    // A lone renamed archive is matched as the only file of its set.
    for (single, password) in singles() {
        let base = tree.path().join(format!("one-{}", password.is_some()));
        let one = insert(&base, &[single], password, Placement::Spread, 1024, 4);
        let moved = base.join("kestrel-notes.rar");
        std::fs::rename(&one[0], &moved).unwrap();
        let set = open_one(std::slice::from_ref(&moved), password);
        assert_eq!(set.hosts[0].path.as_deref(), Some(moved.as_path()));
        assert!(set.hosts[0].matched_by.is_some_and(|by| by != "name"));
        assert_eq!(set.status, RepairStatus::Complete);
    }
}

#[test]
fn unsuitable_archives_are_refused() {
    let options = ExecutionOptions::default();
    let none = Passwords::default();
    assert!(matches!(
        par_inside::prepare_hosts(&[], &none, &options),
        Err(InsideError::Refused(_))
    ));
    if let Some(rar4) = fixture("rar4", "generated_matrix_rar4_lz_plain.part1.rar") {
        assert!(matches!(
            par_inside::prepare_hosts(&[rar4], &none, &options),
            Err(InsideError::Rar(RarError::InvalidSignature))
        ));
    }
    if let Some(locked) = fixture("rar5", "ssokolow_rar5_locked.rar") {
        assert!(matches!(
            par_inside::prepare_hosts(&[locked], &none, &options),
            Err(InsideError::Refused(detail)) if detail.contains("locked")
        ));
    }
    if let Some(sealed) = fixture("rar5", "rar5_hp_lz.rar") {
        assert!(matches!(
            par_inside::prepare_hosts(std::slice::from_ref(&sealed), &none, &options),
            Err(InsideError::Rar(RarError::EncryptedArchive))
        ));
        assert!(matches!(
            par_inside::prepare_hosts(
                std::slice::from_ref(&sealed),
                &passwords(Some("not the password")),
                &options
            ),
            Err(InsideError::Rar(RarError::InvalidPassword))
        ));
        if let Some(plain) = fixture("rar5", "rar5_store.rar") {
            assert!(matches!(
                par_inside::prepare_hosts(&[sealed, plain], &passwords(Some(PASSWORD)), &options),
                Err(InsideError::Refused(detail)) if detail.contains("mix")
            ));
        }
    }
    if let Some(sources) = volumes("generated_matrix_rar5_store_plain", 7) {
        for hosts in [
            &sources[..6],
            &sources[1..],
            &[sources[1].clone(), sources[0].clone()][..],
        ] {
            assert!(matches!(
                par_inside::prepare_hosts(hosts, &none, &options),
                Err(InsideError::Refused(detail)) if detail.contains("out of order")
            ));
        }
    }
    let Some(source) = fixture("rar5", "rar5_lz.rar") else {
        return;
    };
    let tree = tempfile::tempdir().unwrap();
    let inserted = insert(tree.path(), &[source], None, Placement::Spread, 1024, 2);
    assert!(matches!(
        par_inside::prepare_hosts(&inserted, &none, &options),
        Err(InsideError::Refused(detail)) if detail.contains("already holds")
    ));
}

/// Insertion refuses a recovery base the carrier cannot record, and an
/// archive that changed after it was inspected.
#[test]
fn insertion_refuses_a_recovery_base_and_a_changed_host() {
    let Some(source) = fixture("rar5", "rar5_store.rar") else {
        return;
    };
    let tree = tempfile::tempdir().unwrap();
    let path = tree.path().join("host.rar");
    std::fs::copy(&source, &path).unwrap();
    let options = ExecutionOptions::default();
    let hosts =
        par_inside::prepare_hosts(std::slice::from_ref(&path), &Passwords::default(), &options)
            .unwrap();
    let output = tree.path().join("out.rar");
    let insert = |first_recovery| {
        par_inside::insert_set(
            &hosts,
            std::slice::from_ref(&output),
            &[2],
            CreationOptions {
                block_size: 64,
                recovery_count: 2,
                first_recovery,
                ..CreationOptions::default()
            },
            tree.path(),
        )
    };
    assert!(matches!(
        insert(5),
        Err(InsideError::Par3(EngineError::Unsupported(
            "PAR-inside recovery indices start at zero"
        )))
    ));
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.extend_from_slice(&[0; 32]);
    std::fs::write(&path, &bytes).unwrap();
    assert!(matches!(
        insert(0),
        Err(InsideError::Par3(EngineError::Unsupported(
            "host changed since it was inspected"
        )))
    ));
    assert!(!output.exists());
}

/// Two sets in two directories whose archives share a name each bind their
/// own file, so both open complete.
#[test]
fn same_name_hosts_bind_to_their_own_set() {
    let (Some(first), Some(second)) = (
        fixture("rar5", "rar5_store.rar"),
        fixture("rar5", "rar5_lz.rar"),
    ) else {
        return;
    };
    let tree = tempfile::tempdir().unwrap();
    let mut paths = Vec::new();
    for (label, source) in [("north", &first), ("south", &second)] {
        let dir = tree.path().join(label);
        std::fs::create_dir_all(&dir).unwrap();
        let named = dir.join("shared-name.rar");
        std::fs::copy(source, &named).unwrap();
        let inserted = insert(&dir, &[named], None, Placement::Spread, 256, 2);
        paths.push(inserted[0].clone());
    }
    let sets =
        par_inside::open(&paths, &Passwords::default(), &ExecutionOptions::default()).unwrap();
    assert_eq!(sets.len(), 2);
    for set in &sets {
        assert_eq!(set.status, RepairStatus::Complete);
        assert!(set.needs_repair().is_empty());
    }
    let bound: std::collections::BTreeSet<_> = sets
        .iter()
        .map(|set| set.hosts[0].path.clone().unwrap())
        .collect();
    assert_eq!(bound.len(), 2);
}

/// A `-hp` volume set: every volume's record header is sealed, the set
/// extracts the same with its records, any lost volume is rebuilt from the
/// others byte for byte, and removal gives back every original volume.
#[test]
fn a_sealed_volume_set_round_trips_and_rebuilds_a_lost_volume() {
    let Some(sources) = volumes("rar5_hp_recovery_volumes", 5) else {
        return;
    };
    let password = Some(PASSWORD);
    let expected = members(&sources, password);
    let tree = tempfile::tempdir().unwrap();
    // About 4 KiB volumes over 256-byte blocks: 16 blocks each, and the
    // four other regions of a spread placement hold 4 * 8 = 32.
    let inserted = insert(tree.path(), &sources, password, Placement::Spread, 256, 40);
    assert_eq!(members(&inserted, password), expected);
    let kdf = KdfCache::new();
    for path in &inserted {
        let container = Rar5Container::open(path, password, &kdf).unwrap();
        assert!(container.headers_sealed());
        let record = container.service_records(RECORD_NAME).next().unwrap();
        let bytes = std::fs::read(path).unwrap();
        let header = &bytes[record.header.start as usize..record.header.end as usize];
        assert!(!header.windows(4).any(|window| window == b"PAR3"));
    }
    let clean: Vec<Vec<u8>> = inserted
        .iter()
        .map(|path| std::fs::read(path).unwrap())
        .collect();
    let set = open_one(&inserted, password);
    assert_eq!(set.status, RepairStatus::Complete);
    assert!(
        set.hosts
            .iter()
            .all(|host| host.framing_intact == Some(true))
    );
    for lost in [0, 2, 4] {
        let dir = tree.path().join(format!("lost-{lost}"));
        std::fs::create_dir_all(&dir).unwrap();
        let mut present = Vec::new();
        for (index, path) in inserted.iter().enumerate() {
            if index != lost {
                let copy = dir.join(path.file_name().unwrap());
                std::fs::copy(path, &copy).unwrap();
                present.push(copy);
            }
        }
        let mut set = open_one(&present, password);
        assert_eq!(set.status, RepairStatus::Ready, "lost {lost}");
        assert_eq!(set.needs_repair(), vec![lost]);
        let report = repair_into(&mut set, tree.path(), &format!("lost-{lost}"), password);
        assert_eq!(report.len(), 1);
        assert_eq!(
            std::fs::read(&report[0].path).unwrap(),
            clean[lost],
            "lost {lost}"
        );
    }
    let mut set = open_one(&inserted, password);
    let stripped = tree.path().join("stripped");
    std::fs::create_dir_all(&stripped).unwrap();
    let destinations: Vec<PathBuf> = set
        .hosts
        .iter()
        .map(|host| stripped.join(&host.name))
        .collect();
    set.remove(&destinations, &passwords(password)).unwrap();
    for (source, output) in sources.iter().zip(&destinations) {
        assert_eq!(
            std::fs::read(output).unwrap(),
            std::fs::read(source).unwrap()
        );
    }
}

/// With the right password among the candidates, a damaged header past the
/// main header is reported as damage, not as a wrong password: the next
/// candidate is tried only when a password is rejected.
#[test]
fn damage_under_the_right_password_is_not_a_wrong_password() {
    let Some(source) = fixture("rar5", "rar5_hp_store.rar") else {
        return;
    };
    let original = std::fs::read(&source).unwrap();
    let container = Rar5Container::read(
        &mut Cursor::new(&original),
        Some(PASSWORD),
        &KdfCache::new(),
    )
    .unwrap();
    let member = container
        .blocks
        .iter()
        .find(|block| block.kind == BlockKind::File)
        .unwrap();
    let mut damaged = original.clone();
    damaged[member.header.end as usize - 1] ^= 0x40;
    let tree = tempfile::tempdir().unwrap();
    let path = tree.path().join("damaged.rar");
    std::fs::write(&path, &damaged).unwrap();
    let candidates = Passwords::new(vec![PASSWORD.to_owned(), "another".to_owned()]);
    assert!(matches!(
        par_inside::prepare_hosts(
            std::slice::from_ref(&path),
            &candidates,
            &ExecutionOptions::default()
        ),
        Err(InsideError::Rar(RarError::HeaderCrcMismatch { .. }))
    ));
    // The right password after a wrong one still opens the clean archive.
    let candidates = Passwords::new(vec!["another".to_owned(), PASSWORD.to_owned()]);
    let clean = tree.path().join("clean.rar");
    std::fs::write(&clean, &original).unwrap();
    assert!(candidates.container(&clean).unwrap().headers_sealed());
}

/// Candidate passwords never reach `Debug` output.
#[test]
fn passwords_debug_shows_no_candidate() {
    let shown = format!(
        "{:?}",
        Passwords::new(vec!["hunter2-candidate".to_owned(), PASSWORD.to_owned()])
    );
    assert!(!shown.contains("hunter2-candidate") && !shown.contains(PASSWORD));
    assert!(shown.contains('2'), "{shown}");
}

/// A self-extracting archive is refused before anything is staged.
#[test]
fn a_self_extracting_archive_is_refused() {
    for name in [
        "ssokolow_rar5_linux_sfx.bin",
        "test_read_format_rar5_sfx.exe",
    ] {
        let Some(sfx) = fixture("rar5", name) else {
            continue;
        };
        assert!(matches!(
            par_inside::prepare_hosts(&[sfx], &Passwords::default(), &ExecutionOptions::default()),
            Err(InsideError::Rar(RarError::InvalidSignature))
        ));
    }
}
