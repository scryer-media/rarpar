//! What the compact layout and the compact evidence must still mean.
//!
//! The representation changed; the semantics did not. Every test here states
//! one of those semantics against the compact form: a contiguous mapping is a
//! run, a run's extents still carry the set's authenticated checksums, the
//! exceptions a run cannot express are still named individually, verdicts still
//! distinguish all four states, requirements are still deterministic, and a
//! checkpoint still has exactly the bytes it always had.

mod common;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use common::{TempTree, packets_of};
use par3_rs::Par3Set;
use par3_rs::create::{CreateOptions, InputSpec, RecoveryAmount, create};
use par3_rs::evidence::{ExtentVerdict, ExtentVerdicts, verify_source};
use par3_rs::layout::{BlockLayout, ExtentKind, ExtentLocation};
use par3_rs::runtime::ExecutionOptions;
use par3_rs::session::Par3RepairSession;
use par3_rs::source::{MemorySourceAccess, SourceId};

/// Deterministic bytes so a kept output can be regenerated from the test alone.
fn filler(seed: u32, len: usize) -> Vec<u8> {
    (0..len as u32)
        .map(|i| (i.wrapping_mul(37).wrapping_add(seed.wrapping_mul(101))) as u8)
        .collect()
}

/// A set this crate wrote, with the shapes a run cannot express: packed tail
/// blocks shared between files, an uneven tail, and a file that is only a tail.
fn packed_set(label: &str) -> (TempTree, Par3Set) {
    let contents: Vec<(&str, Vec<u8>)> = vec![
        ("big.bin", filler(1, 4500)),
        ("small/a.bin", filler(2, 500)),
        ("small/b.bin", filler(3, 300)),
        ("small/c.bin", filler(4, 300)),
        ("small/d.bin", filler(5, 300)),
        ("empty.bin", Vec::new()),
    ];
    let tree = TempTree::new(label);
    for (name, data) in &contents {
        tree.write(name, data);
    }
    let names: Vec<PathBuf> = contents
        .iter()
        .map(|(name, _)| PathBuf::from(name))
        .collect();
    let report = create(
        &InputSpec::new(tree.path(), &names),
        &tree.path().join("set.par3"),
        &CreateOptions::default()
            .with_block_size(1000)
            .with_recovery(RecoveryAmount::Blocks(2)),
    )
    .expect("the set is created");
    assert_eq!(report.packed_tails, 3, "the fixture packs three tails");
    let packets = report
        .files_written
        .iter()
        .flat_map(|path| packets_of(&std::fs::read(path).expect("a written file")))
        .collect();
    let set = Par3Set::from_packets_for(packets, report.set_id).expect("the set reads back");
    (tree, set)
}

/// One straight file of `blocks` whole blocks, written by this crate.
fn contiguous_set(label: &str, blocks: usize) -> (TempTree, Par3Set) {
    let tree = TempTree::new(label);
    tree.write("input.bin", &filler(7, blocks * 1000));
    let report = create(
        &InputSpec::new(tree.path(), &[PathBuf::from("input.bin")]),
        &tree.path().join("set.par3"),
        &CreateOptions::default()
            .with_block_size(1000)
            .with_recovery(RecoveryAmount::Blocks(2)),
    )
    .expect("the set is created");
    let packets = report
        .files_written
        .iter()
        .flat_map(|path| packets_of(&std::fs::read(path).expect("a written file")))
        .collect();
    (
        tree,
        Par3Set::from_packets_for(packets, report.set_id).expect("the set reads back"),
    )
}

/// The block index the old representation built, by walking every extent.
fn scanned_index(layout: &BlockLayout) -> BTreeMap<u64, Vec<ExtentLocation>> {
    let mut scanned: BTreeMap<u64, Vec<ExtentLocation>> = BTreeMap::new();
    for (file, description) in layout.files().iter().enumerate() {
        for (extent, value) in description.extents.iter().enumerate() {
            if let ExtentKind::Block { index, .. } = value.kind {
                scanned
                    .entry(index)
                    .or_default()
                    .push(ExtentLocation { file, extent });
            }
        }
    }
    for locations in scanned.values_mut() {
        locations.sort_unstable_by_key(|location| (location.file, location.extent));
    }
    scanned
}

#[test]
fn a_contiguous_protected_file_is_one_run_whatever_its_block_count() {
    let options = ExecutionOptions::default();
    let mut previous: Option<(usize, usize, usize)> = None;
    for blocks in [256usize, 4_096] {
        let (_tree, set) = contiguous_set("compact-contiguous", blocks);
        let layout = BlockLayout::new(&set, &options).expect("a layout");
        let extents = &layout.files()[0].extents;
        assert_eq!(extents.len(), blocks, "one extent per whole block");
        assert_eq!(
            extents.runs(),
            1,
            "a contiguous protected file needs exactly one run"
        );
        assert_eq!(extents.exceptions(), 0, "nothing here is an exception");
        assert_eq!(layout.aliased_blocks(), 0, "nothing here is an alias");
        assert_eq!(layout.referenced_blocks(), blocks as u64);
        if let Some((before_blocks, before_runs, before_bytes)) = previous {
            assert_eq!(before_runs, extents.runs());
            let growth = layout.retained_bytes().saturating_sub(before_bytes);
            let per_block = growth as f64 / (blocks - before_blocks) as f64;
            println!(
                "{before_blocks} -> {blocks} blocks costs {growth} more bytes ({per_block:.3}/block)"
            );
            assert!(
                per_block < 1.0,
                "the layout still charges {per_block:.3} bytes per added block"
            );
        }
        previous = Some((blocks, extents.runs(), layout.retained_bytes()));
    }
}

#[test]
fn every_expanded_extent_still_carries_the_checksum_the_set_owns() {
    let options = ExecutionOptions::default();
    let (_tree, set) = contiguous_set("compact-shared-checksums", 512);
    let layout = BlockLayout::new(&set, &options).expect("a layout");
    let mut checked = 0;
    for extent in layout.files()[0].extents.iter() {
        let ExtentKind::Block {
            index,
            offset,
            fingerprint,
            rolling_hash,
        } = extent.kind
        else {
            continue;
        };
        assert_eq!(offset, 0, "a whole-block extent starts at its block");
        let owned = set.block_checksum(index);
        assert_eq!(fingerprint, owned.map(|value| value.fingerprint));
        assert_eq!(rolling_hash, owned.map(|value| value.rolling_hash));
        checked += 1;
    }
    assert_eq!(checked, 512);
    // The layout shares the set's storage; it does not hold a second copy. Even
    // the fingerprint alone would be 16 bytes a block.
    assert!(
        layout.retained_bytes() < 512 * 16,
        "the layout holds {} bytes for 512 blocks, which is a per-block copy",
        layout.retained_bytes()
    );
    assert_eq!(
        layout.checksums().len(),
        set.block_checksums().len(),
        "the layout sees exactly the set's checksums"
    );
}

#[test]
fn the_layout_outlives_its_set_without_dangling_or_losing_a_checksum() {
    let options = ExecutionOptions::default();
    let (_tree, set) = contiguous_set("compact-outlive", 64);
    let expected: Vec<Option<[u8; 16]>> = (0..64)
        .map(|index| set.block_checksum(index).map(|value| value.fingerprint))
        .collect();
    let layout = BlockLayout::new(&set, &options).expect("a layout");
    drop(set);
    for (index, want) in expected.iter().enumerate() {
        let extent = layout.files()[0]
            .extents
            .get(index)
            .expect("bounded extent");
        let ExtentKind::Block { fingerprint, .. } = extent.kind else {
            panic!("a whole block");
        };
        assert_eq!(&fingerprint, want, "block {index} lost its checksum");
    }
}

#[test]
fn packed_tails_become_alias_exceptions_and_every_extent_is_still_named() {
    let options = ExecutionOptions::default();
    let (_tree, set) = packed_set("compact-packed");
    let layout = BlockLayout::new(&set, &options).expect("a layout");
    assert!(
        layout.aliased_blocks() > 0,
        "the packed fixture produced no aliases"
    );
    assert!(
        layout.widest_block() >= 3,
        "three tails share one block, so the widest block names three extents"
    );

    let scanned = scanned_index(&layout);
    // Every block a full extent walk finds is named, with the same locations.
    for (block, locations) in &scanned {
        let answered = layout.locations(*block).expect("a named block");
        assert_eq!(&answered[..], &locations[..], "block {block}");
    }
    // And nothing else is named.
    let listed: Vec<u64> = layout.blocks().map(|(block, _)| block).collect();
    let mut sorted = listed.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(listed, sorted, "blocks were not listed in ascending order");
    assert_eq!(
        listed,
        scanned.keys().copied().collect::<Vec<_>>(),
        "the index lists different blocks than the extents name"
    );
    assert_eq!(layout.referenced_blocks(), listed.len() as u64);
    for (block, answered) in layout.blocks() {
        assert_eq!(&answered[..], &scanned[&block][..], "block {block}");
    }
}

#[test]
fn an_uneven_tail_keeps_its_own_description_and_an_inline_tail_keeps_its_bytes() {
    let options = ExecutionOptions::default();
    let (_tree, set) = packed_set("compact-tails");
    let layout = BlockLayout::new(&set, &options).expect("a layout");
    let mut tails = 0;
    let mut inline = 0;
    for file in layout.files() {
        for (index, extent) in file.extents.iter().enumerate() {
            let length = extent.range.end - extent.range.start;
            match extent.kind {
                ExtentKind::Block {
                    index: block,
                    offset,
                    fingerprint,
                    rolling_hash,
                } if length != layout.block_size() => {
                    // A described tail names part of a block, so its own
                    // fingerprint is not the block's and is kept beside the run.
                    assert!(fingerprint.is_some() && rolling_hash.is_some());
                    assert!(offset + length <= layout.block_size());
                    assert_eq!(file.extents.block_at(index), Some((block, offset)));
                    tails += 1;
                }
                ExtentKind::Inline(ref bytes) => {
                    assert_eq!(bytes.len() as u64, length);
                    assert_eq!(file.extents.inline_bytes(index), Some(bytes.as_slice()));
                    inline += 1;
                }
                _ => {}
            }
        }
    }
    assert!(tails > 0, "the fixture has described tails");
    let _ = inline;
}

#[test]
fn the_verdicts_keep_every_state_they_ever_exposed_four_to_a_byte() {
    let states = [
        ExtentVerdict::Unknown,
        ExtentVerdict::Intact,
        ExtentVerdict::Damaged,
        ExtentVerdict::Unprotected,
    ];
    let mut verdicts = ExtentVerdicts::new(9);
    assert_eq!(verdicts.len(), 9);
    assert!(!verdicts.is_empty());
    for index in 0..9 {
        assert_eq!(verdicts.get(index), Some(ExtentVerdict::Unknown));
        verdicts.set(index, states[index % 4]);
    }
    assert_eq!(verdicts.get(9), None);
    for index in 0..9 {
        assert_eq!(verdicts.get(index), Some(states[index % 4]), "at {index}");
    }
    assert_eq!(
        verdicts.iter().collect::<Vec<_>>(),
        (0..9).map(|index| states[index % 4]).collect::<Vec<_>>()
    );
    // Rewriting one verdict leaves its neighbours in the same byte alone.
    verdicts.set(1, ExtentVerdict::Damaged);
    assert_eq!(verdicts.get(0), Some(ExtentVerdict::Unknown));
    assert_eq!(verdicts.get(1), Some(ExtentVerdict::Damaged));
    assert_eq!(verdicts.get(2), Some(ExtentVerdict::Damaged));
    assert_eq!(
        verdicts.capacity_bytes(),
        3,
        "nine verdicts fit in three bytes"
    );
    assert_eq!(ExtentVerdicts::new(0).capacity_bytes(), 0);
}

#[test]
fn a_verified_file_reports_the_same_verdicts_through_the_compact_store() {
    let (tree, set) = packed_set("compact-verdicts");
    let options = ExecutionOptions::default();
    let layout = Arc::new(BlockLayout::new(&set, &options).expect("a layout"));
    for (index, file) in layout.files().iter().enumerate() {
        let bytes = std::fs::read(tree.path().join(&file.path)).expect("an input file");
        let mut access = MemorySourceAccess::default();
        access.insert(SourceId(1), 1, bytes.into());
        let proof = verify_source(Arc::clone(&layout), index, &access, SourceId(1), &options)
            .expect("a verification");
        assert_eq!(proof.verdicts().len(), file.extents.len());
        assert!(
            proof.protected_complete(),
            "{} did not verify intact",
            file.path
        );
        for verdict in proof.verdicts().iter() {
            assert!(matches!(
                verdict,
                ExtentVerdict::Intact | ExtentVerdict::Unprotected
            ));
        }
        assert_eq!(proof.verified_prefix(&layout).unwrap(), file.len);
        assert!(proof.unresolved_ranges(&layout).unwrap().is_empty());
    }
}

/// Deliver the same carriers in two different orders and require byte-identical
/// requirements. Nothing about a cohort deficit may depend on arrival order.
#[test]
fn cohort_requirements_do_not_depend_on_the_order_the_carriers_arrive() {
    let tree = TempTree::new("compact-determinism");
    let set = common::many_block_set(2, 512, 2, 6, b"PAR3 compact determinism", &tree);
    let scanning = ExecutionOptions::default();
    let carriers: Vec<_> = set
        .paths
        .iter()
        .flat_map(|path| common::scanned_packets(std::fs::read(path).unwrap(), &scanning))
        .collect();

    let run = |reversed: bool| {
        let mut access = MemorySourceAccess::default();
        for (index, (_, bytes)) in set.contents.iter().enumerate() {
            let mut damaged = bytes.clone();
            for block in [3usize, 11, 200, 511] {
                damaged[block * 64 + 11] ^= 0x80;
            }
            access.insert(SourceId(index as u64 + 1), 2, damaged.into());
        }
        let options = ExecutionOptions::default();
        let mut session =
            Par3RepairSession::new(set.id, Arc::new(access), options.clone()).unwrap();
        for (index, (name, _)) in set.contents.iter().enumerate() {
            session.bind_file(name, SourceId(index as u64 + 1)).unwrap();
        }
        let mut packets = carriers.clone();
        if reversed {
            packets.reverse();
        }
        for packet in packets {
            session.merge(packet).unwrap();
        }
        let assessment = session.assess().unwrap();
        let requirements: Vec<String> = assessment
            .requirements
            .iter()
            .map(|need| {
                format!(
                    "{}:{}:{}:{}:{}:{:?}:{:?}",
                    need.cohort,
                    need.lost,
                    need.additional,
                    need.in_flight,
                    need.outstanding,
                    need.available,
                    need.next_indices
                )
            })
            .collect();
        (
            format!("{:?}", assessment.status),
            assessment.lost_blocks.clone(),
            requirements,
        )
    };

    let forward = run(false);
    let backward = run(true);
    assert_eq!(forward.0, backward.0, "status depended on arrival order");
    assert_eq!(forward.1, backward.1, "losses depended on arrival order");
    assert_eq!(
        forward.2, backward.2,
        "recovery requirements depended on arrival order"
    );
    assert!(!forward.1.is_empty(), "the fixture lost no blocks");
}

/// The checkpoint format did not change: the same magic, the same 73-byte
/// header, and one state byte per extent. A checkpoint written against a
/// layout built before this work package replays against one built after it,
/// because the bytes and the layout identity are the same bytes.
#[test]
fn the_checkpoint_keeps_its_documented_bytes_and_still_replays() {
    let (tree, set) = packed_set("compact-checkpoint");
    let options = ExecutionOptions::default();
    let layout = BlockLayout::new(&set, &options).expect("a layout");
    let path = layout.files()[0].path.clone();
    let extents = layout.files()[0].extents.len();
    let bytes = std::fs::read(tree.path().join(&path)).expect("an input file");

    let mut access = MemorySourceAccess::default();
    access.insert(SourceId(1), 1, bytes.into());
    let access = Arc::new(access);
    let mut session = Par3RepairSession::new(
        set.input_set_id(),
        Arc::clone(&access) as Arc<dyn par3_rs::source::SourceAccess>,
        options.clone(),
    )
    .unwrap();
    let scanning = ExecutionOptions::default();
    let carriers = common::scanned_packets(
        std::fs::read(tree.path().join("set.par3")).expect("the set"),
        &scanning,
    );
    for packet in carriers.clone() {
        session.merge(packet).unwrap();
    }
    session.bind_file(&path, SourceId(1)).unwrap();
    session.assess().unwrap();
    let checkpoint = session
        .checkpoint_file(&path)
        .expect("a checkpoint call")
        .expect("a checkpoint");
    let blob = checkpoint.as_bytes().to_vec();
    let digest = checkpoint.digest();

    assert_eq!(&blob[..8], b"P3EV\x01\0\0\0", "the magic changed");
    assert_eq!(
        blob.len(),
        73 + extents,
        "the checkpoint is no longer a 73-byte header and one state byte per extent"
    );
    assert_eq!(
        &blob[8..24],
        &layout.identity()[..],
        "the layout identity moved"
    );
    assert!(
        blob[73..].iter().all(|state| *state <= 3),
        "a state byte outside the four verdicts"
    );

    // Replay into a second session built from the same metadata.
    let mut restored = Par3RepairSession::new(
        set.input_set_id(),
        Arc::clone(&access) as Arc<dyn par3_rs::source::SourceAccess>,
        options.clone(),
    )
    .unwrap();
    for packet in carriers {
        restored.merge(packet).unwrap();
    }
    restored.bind_file(&path, SourceId(1)).unwrap();
    restored.replay_evidence(&blob, digest).expect("a replay");
    let assessment = restored.assess().unwrap();
    assert!(
        assessment
            .files
            .iter()
            .any(|file| file.path == path && file.complete),
        "the replayed evidence did not certify the file"
    );

    // A checkpoint whose version byte is not this one is refused, not misread.
    let mut versioned = blob.clone();
    versioned[4] = 0x02;
    assert!(
        restored.replay_evidence(&versioned, digest).is_err(),
        "an altered version was accepted"
    );
}
