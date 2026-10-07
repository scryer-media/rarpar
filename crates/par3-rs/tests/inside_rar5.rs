//! PAR-inside over RAR5 hosts made by RARLAB rar: insertion, verification,
//! byte-exact self-repair and removal, for single archives and volume sets.
//! The fixtures are not committed; each test skips when its fixture is absent.
mod common;

use std::path::{Path, PathBuf};

use par3_rs::carrier::CarrierRestoration;
use par3_rs::creation::{CreationDurability, CreationOptions};
use par3_rs::inside::rar5::{self, Rar5Layout, Rar5Placement};
use par3_rs::runtime::{EngineError, ExecutionOptions};
use par3_rs::session::RepairStatus;

const LAYOUTS: [Rar5Layout; 3] = [Rar5Layout::Trailing, Rar5Layout::Block, Rar5Layout::Service];

fn fixture(kind: &str, name: &str) -> Option<PathBuf> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../unrar-rs/tests/fixtures")
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

/// Copy hosts into `dir`, insert, and return the inserted files.
fn insert(
    dir: &Path,
    sources: &[PathBuf],
    layout: Rar5Layout,
    placement: Rar5Placement,
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
    let hosts = rar5::prepare_hosts(&paths, layout, &options).unwrap();
    let outputs: Vec<PathBuf> = hosts.iter().map(|host| inserted.join(&host.name)).collect();
    let creation = |count| CreationOptions {
        block_size,
        recovery_count: count,
        ..CreationOptions::default()
    };
    if placement == Rar5Placement::Independent {
        for (host, output) in hosts.iter().zip(&outputs) {
            rar5::insert_set(
                std::slice::from_ref(host),
                std::slice::from_ref(output),
                &[recovery],
                layout,
                creation(recovery),
                &scratch,
                CreationDurability::Buffered,
            )
            .unwrap();
        }
    } else {
        let counts = rar5::placement_counts(placement, hosts.len(), recovery).unwrap();
        rar5::insert_set(
            &hosts,
            &outputs,
            &counts,
            layout,
            creation(recovery),
            &scratch,
            CreationDurability::Buffered,
        )
        .unwrap();
    }
    assert_eq!(std::fs::read_dir(&scratch).unwrap().count(), 0);
    outputs
}

fn open_one(paths: &[PathBuf]) -> rar5::Rar5Set {
    let mut sets = rar5::open(paths, &ExecutionOptions::default()).unwrap();
    assert_eq!(sets.len(), 1);
    sets.pop().unwrap()
}

fn repair_into(set: &mut rar5::Rar5Set, dir: &Path, label: &str) -> Vec<rar5::Rar5Repaired> {
    let out = dir.join(format!("repaired-{label}"));
    let scratch = dir.join(format!("scratch-{label}"));
    std::fs::create_dir_all(&out).unwrap();
    std::fs::create_dir_all(&scratch).unwrap();
    let destinations: Vec<PathBuf> = set.hosts.iter().map(|host| out.join(&host.name)).collect();
    let report = set.repair(&destinations, &scratch).unwrap();
    assert_eq!(std::fs::read_dir(&scratch).unwrap().count(), 0);
    report
}

#[test]
fn round_trip_restores_the_original_bytes_and_reinserts_identically() {
    let Some(source) = fixture("rar5", "rar5_lz.rar") else {
        return;
    };
    let original = std::fs::read(&source).unwrap();
    for layout in LAYOUTS {
        let tree = common::TempTree::new(&format!("rar5-round-{layout:?}"));
        let inserted = insert(
            tree.path(),
            std::slice::from_ref(&source),
            layout,
            Rar5Placement::Spread,
            1024,
            8,
        );
        let bytes = std::fs::read(&inserted[0]).unwrap();
        assert!(bytes.len() > original.len());
        let archive = rar5::inspect(
            &disk(&inserted[0]),
            par3_rs::source::SourceId(0),
            &ExecutionOptions::default(),
        )
        .unwrap();
        assert_eq!(
            archive.region.as_ref().map(|(found, _)| *found),
            Some(layout)
        );
        assert_eq!(archive.original_length(), original.len() as u64);
        let mut set = open_one(&inserted);
        assert_eq!(set.layout, layout);
        assert_eq!(set.status, RepairStatus::Complete);
        assert!(set.hosts[0].complete && set.hosts[0].region_intact);
        assert!(set.needs_repair().is_empty());
        let stripped = tree
            .path()
            .join("stripped")
            .join(source.file_name().unwrap());
        std::fs::create_dir_all(stripped.parent().unwrap()).unwrap();
        set.remove(std::slice::from_ref(&stripped)).unwrap();
        assert_eq!(std::fs::read(&stripped).unwrap(), original);
        // Insertion is deterministic: the stripped archive inserts to the
        // same bytes again.
        let again = insert(
            &tree.path().join("again"),
            &[stripped],
            layout,
            Rar5Placement::Spread,
            1024,
            8,
        );
        assert_eq!(std::fs::read(&again[0]).unwrap(), bytes);
    }
}

fn disk(path: &Path) -> par3_rs::source::DiskSourceAccess {
    let mut disk = par3_rs::source::DiskSourceAccess::with_options(ExecutionOptions::default());
    disk.insert(par3_rs::source::SourceId(0), path.to_owned());
    disk
}

#[test]
fn damage_in_the_header_middle_and_end_is_repaired_byte_for_byte() {
    let Some(source) = fixture("rar5", "rar5_lz.rar") else {
        return;
    };
    let original_len = std::fs::metadata(&source).unwrap().len() as usize;
    for layout in LAYOUTS {
        let tree = common::TempTree::new(&format!("rar5-damage-{layout:?}"));
        let inserted = insert(
            tree.path(),
            std::slice::from_ref(&source),
            layout,
            Rar5Placement::Spread,
            1024,
            8,
        );
        let clean = std::fs::read(&inserted[0]).unwrap();
        let end = match layout {
            Rar5Layout::Trailing => original_len - 3,
            // The end header follows the region.
            _ => clean.len() - 3,
        };
        for (label, offset) in [("header", 20), ("middle", original_len / 2), ("end", end)] {
            let damaged = tree.path().join(format!("damaged-{label}"));
            std::fs::create_dir_all(&damaged).unwrap();
            let path = damaged.join(inserted[0].file_name().unwrap());
            let mut bytes = clean.clone();
            bytes[offset] ^= 0x5a;
            std::fs::write(&path, &bytes).unwrap();
            let mut set = open_one(std::slice::from_ref(&path));
            assert_eq!(set.status, RepairStatus::Ready, "{layout:?} {label}");
            assert!(!set.hosts[0].complete);
            assert!(set.hosts[0].region_intact);
            let report = repair_into(&mut set, tree.path(), label);
            assert_eq!(report.len(), 1);
            assert!(report[0].data_rebuilt);
            assert_eq!(report[0].restoration, CarrierRestoration::Exact);
            assert_eq!(
                std::fs::read(&report[0].path).unwrap(),
                clean,
                "{layout:?} {label}"
            );
        }
    }
}

#[test]
fn region_damage_is_reported_and_the_region_is_regenerated() {
    let Some(source) = fixture("rar5", "rar5_lz.rar") else {
        return;
    };
    for layout in LAYOUTS {
        let tree = common::TempTree::new(&format!("rar5-region-{layout:?}"));
        let inserted = insert(
            tree.path(),
            std::slice::from_ref(&source),
            layout,
            Rar5Placement::Spread,
            1024,
            8,
        );
        let clean = std::fs::read(&inserted[0]).unwrap();
        let mut set = open_one(&inserted);
        let gap = set.hosts[0].gap.clone();
        drop(set);
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
        set = open_one(std::slice::from_ref(&path));
        let host = &set.hosts[0];
        assert!(host.complete, "protected data is unaffected");
        assert!(!host.region_intact);
        assert_eq!(host.packets_found + 1, host.packets_expected);
        assert_eq!(set.status, RepairStatus::Complete);
        let report = repair_into(&mut set, tree.path(), "region");
        assert_eq!(report.len(), 1);
        assert!(!report[0].data_rebuilt);
        assert_eq!(report[0].regenerated, 1);
        assert_eq!(report[0].restoration, CarrierRestoration::Derived);
        assert_eq!(std::fs::read(&report[0].path).unwrap(), clean);
    }
}

/// A region of many small recovery packets is checked slot by slot: every
/// packet at its slot counts, and two packets swapped out of their slots are
/// both missed even though each is still a valid packet of the set.
#[test]
fn many_small_recovery_packets_are_each_checked_at_their_slot() {
    let Some(source) = fixture("rar5", "rar5_lz.rar") else {
        return;
    };
    const BLOCK: u64 = 64;
    const RECOVERY: u64 = 1024;
    // A Recovery Data packet: the 48-byte header, root and matrix
    // fingerprints and the recovery index, then one block.
    const PACKET: usize = (BLOCK + 48 + 16 + 16 + 8) as usize;
    let tree = common::TempTree::new("rar5-many-recovery");
    let inserted = insert(
        tree.path(),
        std::slice::from_ref(&source),
        Rar5Layout::Trailing,
        Rar5Placement::Spread,
        BLOCK,
        RECOVERY,
    );
    let set = open_one(&inserted);
    let host = &set.hosts[0];
    assert_eq!(host.recovery, 0..RECOVERY);
    assert!(host.region_intact);
    assert_eq!(host.packets_found, host.packets_expected);
    assert!(host.packets_expected > RECOVERY);
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
    let set = open_one(std::slice::from_ref(&path));
    let host = &set.hosts[0];
    assert!(host.complete, "protected data is unaffected");
    assert!(!host.region_intact);
    assert_eq!(host.packets_found + 2, host.packets_expected);
}

#[test]
fn any_lost_volume_is_rebuilt_from_the_other_regions() {
    let Some(sources) = volumes("generated_matrix_rar5_store_plain", 7) else {
        return;
    };
    // 180 KiB volumes over 4 KiB blocks: 45 blocks each, and the six other
    // regions of a spread placement hold 6 * 8 = 48 recovery blocks.
    for layout in LAYOUTS {
        let tree = common::TempTree::new(&format!("rar5-volumes-{layout:?}"));
        let inserted = insert(
            tree.path(),
            &sources,
            layout,
            Rar5Placement::Spread,
            4096,
            56,
        );
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
            let mut set = open_one(&present[..1]);
            assert_eq!(set.hosts.len(), 7);
            assert_eq!(set.status, RepairStatus::Ready, "{layout:?} lost {lost}");
            assert_eq!(set.needs_repair(), vec![lost]);
            let report = repair_into(&mut set, tree.path(), &format!("lost-{lost}"));
            assert_eq!(report.len(), 1);
            assert_eq!(
                std::fs::read(&report[0].path).unwrap(),
                clean[lost],
                "{layout:?} lost {lost}"
            );
        }
    }
}

#[test]
fn last_placement_cannot_survive_losing_the_last_volume() {
    let Some(sources) = volumes("generated_matrix_rar5_store_plain", 7) else {
        return;
    };
    let tree = common::TempTree::new("rar5-last");
    let inserted = insert(
        tree.path(),
        &sources,
        Rar5Layout::Trailing,
        Rar5Placement::Last,
        4096,
        56,
    );
    let dir = tree.path().join("lost-last");
    std::fs::create_dir_all(&dir).unwrap();
    for path in &inserted[..6] {
        std::fs::copy(path, dir.join(path.file_name().unwrap())).unwrap();
    }
    let set = open_one(&[dir.join(inserted[0].file_name().unwrap())]);
    assert_eq!(set.status, RepairStatus::NeedRecovery);
    // Losing a volume other than the last is repairable.
    let dir = tree.path().join("lost-first");
    std::fs::create_dir_all(&dir).unwrap();
    for path in &inserted[1..] {
        std::fs::copy(path, dir.join(path.file_name().unwrap())).unwrap();
    }
    let mut set = open_one(&[dir.join(inserted[6].file_name().unwrap())]);
    assert_eq!(set.status, RepairStatus::Ready);
    let report = repair_into(&mut set, tree.path(), "last");
    assert_eq!(
        std::fs::read(&report[0].path).unwrap(),
        std::fs::read(&inserted[0]).unwrap()
    );
}

#[test]
fn independent_placement_repairs_damage_within_a_volume() {
    let Some(sources) = volumes("generated_matrix_rar5_store_plain", 7) else {
        return;
    };
    let tree = common::TempTree::new("rar5-independent");
    let inserted = insert(
        tree.path(),
        &sources,
        Rar5Layout::Trailing,
        Rar5Placement::Independent,
        4096,
        4,
    );
    let sets = rar5::open(&inserted, &ExecutionOptions::default()).unwrap();
    assert_eq!(sets.len(), 7);
    assert!(
        sets.iter()
            .all(|set| set.hosts.len() == 1 && set.status == RepairStatus::Complete)
    );
}

#[test]
fn renamed_hosts_are_matched_and_missing_siblings_found_by_stem() {
    let Some(sources) = volumes("generated_matrix_rar5_store_plain", 7) else {
        return;
    };
    let tree = common::TempTree::new("rar5-rename");
    let inserted = insert(
        tree.path(),
        &sources,
        Rar5Layout::Trailing,
        Rar5Placement::Spread,
        4096,
        56,
    );
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
    let mut set = open_one(&renamed[..1]);
    assert_eq!(set.hosts.len(), 7);
    let bound: Vec<_> = set.hosts.iter().map(|host| host.path.is_some()).collect();
    assert_eq!(bound, [true, true, false, true, true, true, true]);
    assert_eq!(set.needs_repair(), vec![2]);
    let report = repair_into(&mut set, tree.path(), "renamed");
    assert_eq!(
        std::fs::read(&report[0].path).unwrap(),
        std::fs::read(&inserted[2]).unwrap()
    );

    // A lone renamed archive is matched as the only file of its set.
    let Some(single) = fixture("rar5", "rar5_lz.rar") else {
        return;
    };
    let one = insert(
        &tree.path().join("one"),
        &[single],
        Rar5Layout::Service,
        Rar5Placement::Spread,
        1024,
        4,
    );
    let moved = tree.path().join("one").join("kestrel-notes.rar");
    std::fs::rename(&one[0], &moved).unwrap();
    let set = open_one(std::slice::from_ref(&moved));
    assert_eq!(set.hosts[0].path.as_deref(), Some(moved.as_path()));
    assert!(set.hosts[0].matched_by.is_some_and(|by| by != "name"));
    assert_eq!(set.status, RepairStatus::Complete);
}

#[test]
fn prepare_hosts_refuses_an_empty_host_list() {
    for layout in LAYOUTS {
        assert!(matches!(
            rar5::prepare_hosts(&[], layout, &ExecutionOptions::default()),
            Err(EngineError::InvalidState("insert host count"))
        ));
    }
}

#[test]
fn rar4_and_double_insertion_are_refused() {
    let options = ExecutionOptions::default();
    if let Some(rar4) = fixture("rar4", "generated_matrix_rar4_lz_plain.part1.rar") {
        assert!(matches!(
            rar5::prepare_hosts(&[rar4], Rar5Layout::Trailing, &options),
            Err(EngineError::Unsupported("RAR4 archives are not supported"))
        ));
    }
    let Some(source) = fixture("rar5", "rar5_lz.rar") else {
        return;
    };
    let tree = common::TempTree::new("rar5-twice");
    let inserted = insert(
        tree.path(),
        &[source],
        Rar5Layout::Trailing,
        Rar5Placement::Spread,
        1024,
        2,
    );
    for layout in LAYOUTS {
        assert!(matches!(
            rar5::prepare_hosts(&inserted, layout, &options),
            Err(EngineError::Unsupported(
                "archive already holds a PAR3 region"
            ))
        ));
    }
}

#[test]
fn encrypted_headers_take_only_the_trailing_layout() {
    let Some(source) = fixture("rar5", "rar5_hp_lz.rar") else {
        return;
    };
    let options = ExecutionOptions::default();
    for layout in [Rar5Layout::Block, Rar5Layout::Service] {
        assert!(rar5::prepare_hosts(std::slice::from_ref(&source), layout, &options).is_err());
    }
    let original = std::fs::read(&source).unwrap();
    let tree = common::TempTree::new("rar5-hp");
    let inserted = insert(
        tree.path(),
        &[source],
        Rar5Layout::Trailing,
        Rar5Placement::Spread,
        64,
        2,
    );
    let mut set = open_one(&inserted);
    assert_eq!(set.status, RepairStatus::Complete);
    let stripped = tree.path().join("stripped.rar");
    set.remove(std::slice::from_ref(&stripped)).unwrap();
    assert_eq!(std::fs::read(&stripped).unwrap(), original);
    assert!(matches!(
        rar5::prepare_hosts(&inserted, Rar5Layout::Trailing, &options),
        Err(EngineError::Unsupported(
            "archive already holds PAR3 packets"
        ))
    ));
}

/// A lost volume and damage in another: every carrier is derived before any
/// rebuilt host changes, so both come back.
#[test]
fn a_lost_volume_and_a_damaged_one_are_rebuilt_together() {
    let Some(sources) = volumes("generated_matrix_rar5_store_plain", 7) else {
        return;
    };
    for layout in LAYOUTS {
        let tree = common::TempTree::new(&format!("rar5-two-{layout:?}"));
        let inserted = insert(
            tree.path(),
            &sources,
            layout,
            Rar5Placement::Spread,
            4096,
            70,
        );
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
        let mut set = open_one(&[dir.join(inserted[0].file_name().unwrap())]);
        assert_eq!(set.status, RepairStatus::Ready, "{layout:?}");
        assert_eq!(set.needs_repair(), vec![2, 5]);
        let report = repair_into(&mut set, tree.path(), "two");
        assert_eq!(report.len(), 2);
        for (repaired, index) in report.iter().zip([2, 5]) {
            assert_eq!(
                std::fs::read(&repaired.path).unwrap(),
                clean[index],
                "{layout:?} {index}"
            );
        }
    }
}

/// Header-encrypted volumes hide their numbers and end flags: a family, or
/// a lone `.partN.rar`, is refused rather than protected incomplete.
#[test]
fn header_encrypted_volume_families_are_refused() {
    let Some(parts) = volumes("rar5_hp_recovery_volumes", 5) else {
        return;
    };
    let options = ExecutionOptions::default();
    for hosts in [&parts[..], &parts[..4], &parts[..1]] {
        assert!(matches!(
            rar5::prepare_hosts(hosts, Rar5Layout::Trailing, &options),
            Err(EngineError::Unsupported(
                "completeness of a header-encrypted RAR5 volume set cannot be checked"
            ))
        ));
    }
}

#[test]
fn independent_placement_has_no_shared_counts() {
    assert!(rar5::placement_counts(Rar5Placement::Independent, 3, 9).is_err());
    assert_eq!(
        rar5::placement_counts(Rar5Placement::Spread, 3, 7).unwrap(),
        [3, 2, 2]
    );
    assert_eq!(
        rar5::placement_counts(Rar5Placement::Last, 3, 7).unwrap(),
        [0, 0, 7]
    );
}

/// Insertion refuses a recovery base the region cannot record, and a host
/// that changed after `prepare_hosts` read its framing.
#[test]
fn insertion_refuses_a_recovery_base_and_a_changed_host() {
    let Some(source) = fixture("rar5", "rar5_store.rar") else {
        return;
    };
    let tree = common::TempTree::new("rar5-refusals");
    let path = tree.path().join("host.rar");
    std::fs::copy(&source, &path).unwrap();
    let options = ExecutionOptions::default();
    let hosts =
        rar5::prepare_hosts(std::slice::from_ref(&path), Rar5Layout::Block, &options).unwrap();
    let output = tree.path().join("out.rar");
    let insert = |first_recovery| {
        rar5::insert_set(
            &hosts,
            std::slice::from_ref(&output),
            &[2],
            Rar5Layout::Block,
            CreationOptions {
                block_size: 64,
                recovery_count: 2,
                first_recovery,
                ..CreationOptions::default()
            },
            tree.path(),
            CreationDurability::Buffered,
        )
    };
    assert!(matches!(
        insert(5),
        Err(EngineError::Unsupported(
            "PAR-inside recovery indices start at zero"
        ))
    ));
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.extend_from_slice(&[0; 32]);
    std::fs::write(&path, &bytes).unwrap();
    assert!(matches!(
        insert(0),
        Err(EngineError::Unsupported(
            "host changed since it was inspected"
        ))
    ));
    assert!(!output.exists());
}

/// Two sets in two directories whose hosts share a name each bind their own
/// file, so both open complete.
#[test]
fn same_name_hosts_bind_to_their_own_set() {
    let (Some(first), Some(second)) = (
        fixture("rar5", "rar5_store.rar"),
        fixture("rar5", "rar5_lz.rar"),
    ) else {
        return;
    };
    let tree = common::TempTree::new("rar5-same-name");
    let mut paths = Vec::new();
    for (label, source) in [("north", &first), ("south", &second)] {
        let dir = tree.path().join(label);
        std::fs::create_dir_all(&dir).unwrap();
        let named = dir.join("shared-name.rar");
        std::fs::copy(source, &named).unwrap();
        let inserted = insert(
            &dir,
            &[named],
            Rar5Layout::Trailing,
            Rar5Placement::Spread,
            256,
            2,
        );
        paths.push(inserted[0].clone());
    }
    let sets = rar5::open(&paths, &ExecutionOptions::default()).unwrap();
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
