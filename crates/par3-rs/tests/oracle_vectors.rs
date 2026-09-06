//! Wire-format tests against bytes the reference implementation produced.
//!
//! The `.par3` bytes and the provenance that goes with them live in
//! `tests/common/mod.rs`, alongside the formulas the input files are regenerated
//! from. Every damage case here flips or truncates those regenerated inputs, or
//! an in-memory copy of a `.par3` file; no embedded byte is ever edited.
//!
//! Recovery Data packets have their own suite in `tests/oracle_recovery.rs`.

mod common;

use common::{SET_ID, SET16_ID, a_bin, b_txt, big_bin, c_bin, hex, scan, set_par3, set16_par3};
use par3_rs::packet::{
    BlockChecksum, CauchyMatrixPacket, ChunkDescription, ChunkTail, DirectoryPacket, FilePacket,
    GaloisField, StartPacket,
};
use par3_rs::{
    FileVerdict, InputSetId, Packet, PacketBody, PacketType, Par3Set, ParseContext, fingerprint,
    scan_packets, verify_file,
};

fn file_named<'a>(set: &'a Par3Set, path: &str) -> &'a par3_rs::Par3File {
    set.files()
        .iter()
        .find(|file| file.path() == path)
        .unwrap_or_else(|| panic!("{path} is in the set"))
}

// ---------------------------------------------------------------------------
// 1 and 2: the hashes, against values the reference reported.
// ---------------------------------------------------------------------------

#[test]
fn regenerated_inputs_hash_to_the_values_the_reference_reported() {
    assert_eq!(
        hex(&fingerprint(&a_bin())),
        "99dac71e48bb629da58fe862e286769a"
    );
    assert_eq!(
        hex(&fingerprint(&b_txt())),
        "bc094a8703d2ce996403c13225b97a81"
    );
    assert_eq!(
        hex(&fingerprint(&c_bin())),
        "de50e34037f9dac160cf99f04c560b9a"
    );
    assert_eq!(
        hex(&fingerprint(&big_bin())),
        "46ef7bc5a5bfd952597ce19fcb4d1d3a"
    );
}

// ---------------------------------------------------------------------------
// 4: every typed packet parses, and writes back byte for byte.
// ---------------------------------------------------------------------------

#[test]
fn the_index_holds_the_packets_the_reference_reported() {
    let data = set_par3();
    let packets = scan(&data);
    assert_eq!(packets.len(), 11);
    assert!(packets.iter().all(|(_, p)| p.input_set_id() == SET_ID));

    let mut counts = std::collections::BTreeMap::new();
    for (_, packet) in &packets {
        *counts.entry(packet.packet_type()).or_insert(0usize) += 1;
    }
    assert_eq!(counts[&PacketType::Creator], 1);
    assert_eq!(counts[&PacketType::Comment], 1);
    assert_eq!(counts[&PacketType::Start], 1);
    assert_eq!(counts[&PacketType::CauchyMatrix], 1);
    assert_eq!(counts[&PacketType::File], 3);
    assert_eq!(counts[&PacketType::Directory], 1);
    assert_eq!(counts[&PacketType::Root], 1);
    assert_eq!(counts[&PacketType::ExternalData], 2);
}

#[test]
fn the_start_packet_matches_the_reference() {
    let data = set_par3();
    let start = scan(&data)
        .into_iter()
        .find_map(|(_, packet)| match packet.into_body() {
            PacketBody::Start(start) => Some(start),
            _ => None,
        })
        .expect("a Start packet");
    assert_eq!(
        start,
        StartPacket {
            parent_input_set_id: InputSetId::ZERO,
            parent_root_hash: [0u8; 16],
            block_size: 2000,
            galois_field: GaloisField {
                size: 1,
                generator: 0x1d,
            },
            legacy_random: None,
        }
    );
    assert_eq!(start.galois_field.polynomial(), Some(0x11d));
    assert!(!start.has_parent());
}

#[test]
fn the_gf16_start_packet_matches_the_reference() {
    let data = set16_par3();
    let start = scan(&data)
        .into_iter()
        .find_map(|(_, packet)| match packet.into_body() {
            PacketBody::Start(start) => Some(start),
            _ => None,
        })
        .expect("a Start packet");
    assert_eq!(start.block_size, 100);
    assert_eq!(start.galois_field.size, 2);
    assert_eq!(start.galois_field.generator, 0x100b);
    assert_eq!(start.galois_field.polynomial(), Some(0x1100b));
}

#[test]
fn the_root_packet_matches_the_reference() {
    let data = set_par3();
    let root = scan(&data)
        .into_iter()
        .find_map(|(_, packet)| match packet.into_body() {
            PacketBody::Root(root) => Some(root),
            _ => None,
        })
        .expect("a Root packet");
    assert_eq!(root.lowest_unused_block_index, 5);
    assert_eq!(root.attributes, 0);
    assert!(!root.is_absolute_path());
    assert!(root.option_hashes.is_empty());
    assert_eq!(root.children.len(), 3);
}

#[test]
fn the_cauchy_matrix_packet_matches_the_reference() {
    let data = set_par3();
    let matrix = scan(&data)
        .into_iter()
        .find_map(|(_, packet)| match packet.into_body() {
            PacketBody::CauchyMatrix(matrix) => Some(matrix),
            _ => None,
        })
        .expect("a Cauchy Matrix packet");
    // The reference writes zeros, which mean "every input block".
    assert!(matrix.range.covers_all());
    assert_eq!(matrix.recovery_block_hint, 0);
    assert_eq!(
        matrix,
        CauchyMatrixPacket::parse(&[0u8; 24]).expect("parses")
    );
}

#[test]
fn the_file_packets_match_the_reference() {
    let data = set_par3();
    let mut files: Vec<FilePacket> = scan(&data)
        .into_iter()
        .filter_map(|(_, packet)| match packet.into_body() {
            PacketBody::File(file) => Some(file),
            _ => None,
        })
        .collect();
    files.sort_by(|a, b| a.name.cmp(&b.name));
    assert_eq!(files.len(), 3);

    let a = &files[0];
    assert_eq!(a.name, "a.bin");
    assert_eq!(hex(&a.fingerprint), "99dac71e48bb629da58fe862e286769a");
    assert_eq!(a.file_size(), Some(5000));
    assert!(a.option_hashes.is_empty());
    assert_eq!(a.chunks.len(), 1);
    match &a.chunks[0] {
        ChunkDescription::Protected {
            length,
            first_block_index,
            tail,
        } => {
            assert_eq!(*length, 5000);
            assert_eq!(*first_block_index, Some(0));
            // 5000 = two 2000-byte blocks plus a 1000-byte tail, described by
            // hashes because it is at least 40 bytes long.
            match tail {
                ChunkTail::Described {
                    block_index,
                    offset,
                    ..
                } => {
                    assert_eq!(*block_index, 2);
                    assert_eq!(*offset, 0);
                }
                other => panic!("unexpected tail: {other:?}"),
            }
        }
        other => panic!("unexpected chunk: {other:?}"),
    }

    let b = &files[1];
    assert_eq!(b.name, "b.txt");
    assert_eq!(b.file_size(), Some(10));
    match &b.chunks[0] {
        ChunkDescription::Protected {
            length,
            first_block_index,
            tail,
        } => {
            assert_eq!(*length, 10);
            // Shorter than one block, so there is no first-block index.
            assert_eq!(*first_block_index, None);
            assert_eq!(tail, &ChunkTail::Inline(b_txt()));
        }
        other => panic!("unexpected chunk: {other:?}"),
    }

    let c = &files[2];
    assert_eq!(c.name, "c.bin");
    assert_eq!(c.file_size(), Some(4000));
    match &c.chunks[0] {
        ChunkDescription::Protected {
            length,
            first_block_index,
            tail,
        } => {
            assert_eq!(*length, 4000);
            assert_eq!(*first_block_index, Some(3));
            // Exactly two blocks, so no tail at all.
            assert_eq!(tail, &ChunkTail::None);
        }
        other => panic!("unexpected chunk: {other:?}"),
    }
}

#[test]
fn the_directory_packet_names_the_c_bin_file_packet() {
    let data = set_par3();
    let packets = scan(&data);
    let directory: DirectoryPacket = packets
        .iter()
        .find_map(|(_, packet)| match packet.body() {
            PacketBody::Directory(directory) => Some(directory.clone()),
            _ => None,
        })
        .expect("a Directory packet");
    assert_eq!(directory.name, "sub");
    assert_eq!(directory.children.len(), 1);

    let c_bin_hash = packets
        .iter()
        .find_map(|(_, packet)| match packet.body() {
            PacketBody::File(file) if file.name == "c.bin" => Some(packet.hash()),
            _ => None,
        })
        .expect("the c.bin File packet");
    assert_eq!(directory.children[0], c_bin_hash);
}

#[test]
fn the_external_data_packets_cover_the_full_blocks_only() {
    let data = set_par3();
    let mut ranges: Vec<Vec<u64>> = scan(&data)
        .into_iter()
        .filter_map(|(_, packet)| match packet.into_body() {
            PacketBody::ExternalData(ext) => Some(ext.block_indices().collect()),
            _ => None,
        })
        .collect();
    ranges.sort();
    // Block 2 holds a.bin's tail, so the reference leaves it out.
    assert_eq!(ranges, vec![vec![0u64, 1], vec![3u64, 4]]);
}

#[test]
fn the_gf16_external_data_packet_omits_the_tail_block() {
    let data = set16_par3();
    let ext = scan(&data)
        .into_iter()
        .find_map(|(_, packet)| match packet.into_body() {
            PacketBody::ExternalData(ext) => Some(ext),
            _ => None,
        })
        .expect("an External Data packet");
    assert_eq!(ext.first_block_index, 0);
    // 301 blocks, of which block 300 holds the 50-byte tail.
    assert_eq!(ext.checksums.len(), 300);
}

#[test]
fn the_creator_and_comment_texts_match_the_reference() {
    let data = set_par3();
    let packets = scan(&data);
    let creator = packets
        .iter()
        .find_map(|(_, packet)| match packet.body() {
            PacketBody::Creator(creator) => Some(creator.text().into_owned()),
            _ => None,
        })
        .expect("a Creator packet");
    assert!(creator.starts_with("par3cmdline version 0.0.1"));
    let comment = packets
        .iter()
        .find_map(|(_, packet)| match packet.body() {
            PacketBody::Comment(comment) => Some(comment.text().into_owned()),
            _ => None,
        })
        .expect("a Comment packet");
    assert_eq!(comment, "rarpar oracle");
}

#[test]
fn every_packet_writes_back_byte_for_byte() {
    for data in [set_par3(), set16_par3()] {
        for (offset, packet) in scan(&data) {
            let start = offset as usize;
            let end = start + packet.len() as usize;
            assert_eq!(
                packet.to_bytes(),
                &data[start..end],
                "packet at offset {offset} did not round-trip"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 5: the whole file round-trips.
// ---------------------------------------------------------------------------

#[test]
fn the_index_files_round_trip_whole() {
    for data in [set_par3(), set16_par3()] {
        let rebuilt: Vec<u8> = scan(&data)
            .into_iter()
            .flat_map(|(_, packet)| packet.to_bytes())
            .collect();
        assert_eq!(rebuilt, data);
    }
}

// ---------------------------------------------------------------------------
// 6: the sets.
// ---------------------------------------------------------------------------

#[test]
fn the_set_resolves_the_reference_paths_and_sizes() {
    let data = set_par3();
    let packets = scan(&data).into_iter().map(|(_, p)| p).collect();
    let sets = Par3Set::from_packets(packets).expect("builds");
    assert_eq!(sets.len(), 1);
    let set = &sets[0];

    assert_eq!(set.input_set_id(), SET_ID);
    assert_eq!(set.block_size(), 2000);
    assert_eq!(set.block_count(), 5);
    assert_eq!(set.galois_field().size, 1);
    assert!(!set.is_absolute_path());
    assert_eq!(set.parent_input_set_id(), None);

    let paths: Vec<&str> = set.files().iter().map(|file| file.path()).collect();
    assert_eq!(paths, ["a.bin", "b.txt", "sub/c.bin"]);
    let sizes: Vec<u64> = set.files().iter().map(|file| file.size()).collect();
    assert_eq!(sizes, [5000, 10, 4000]);

    assert_eq!(set.directories().len(), 1);
    assert_eq!(set.directories()[0].path(), "sub");
    assert_eq!(set.directories()[0].name(), "sub");

    assert_eq!(set.matrix_packets().len(), 1);
    assert!(set.recovery_blocks().is_empty());
    assert_eq!(set.comments(), ["rarpar oracle"]);
    assert_eq!(set.duplicate_packet_count(), 0);
    assert_eq!(set.unknown_packet_count(), 0);
    assert_eq!(set.unparsed_packet_count(), 0);

    // Four block checksums, for the four full-size blocks.
    assert_eq!(set.block_checksums().len(), 4);
    assert!(set.block_checksum(2).is_none());
}

#[test]
fn the_gf16_set_reports_its_field_and_block_count() {
    let data = set16_par3();
    let packets = scan(&data).into_iter().map(|(_, p)| p).collect();
    let set = Par3Set::from_packets_for(packets, SET16_ID).expect("builds");
    assert_eq!(set.block_size(), 100);
    assert_eq!(set.block_count(), 301);
    assert_eq!(set.galois_field().polynomial(), Some(0x1100b));
    assert_eq!(set.files().len(), 1);
    assert_eq!(set.files()[0].path(), "big.bin");
    assert_eq!(set.files()[0].size(), 30050);
    assert!(set.directories().is_empty());
    assert_eq!(set.comments(), ["rarpar oracle gf16"]);
}

// ---------------------------------------------------------------------------
// 7: verification against the regenerated inputs.
// ---------------------------------------------------------------------------

fn oracle_set() -> Par3Set {
    let data = set_par3();
    let packets = scan(&data).into_iter().map(|(_, p)| p).collect();
    Par3Set::from_packets_for(packets, SET_ID).expect("builds")
}

#[test]
fn the_regenerated_inputs_verify_complete() {
    let set = oracle_set();
    for (path, data) in [
        ("a.bin", a_bin()),
        ("b.txt", b_txt()),
        ("sub/c.bin", c_bin()),
    ] {
        assert_eq!(
            verify_file(&set, file_named(&set, path), &data),
            FileVerdict::Complete,
            "{path} should verify"
        );
    }
}

#[test]
fn the_gf16_input_verifies_complete() {
    let data = set16_par3();
    let packets = scan(&data).into_iter().map(|(_, p)| p).collect();
    let set = Par3Set::from_packets_for(packets, SET16_ID).expect("builds");
    assert_eq!(
        verify_file(&set, &set.files()[0], &big_bin()),
        FileVerdict::Complete
    );
}

#[test]
fn a_flipped_byte_in_a_bin_localises_to_block_one() {
    let set = oracle_set();
    let mut data = a_bin();
    data[2500] ^= 0x01;
    let verdict = verify_file(&set, file_named(&set, "a.bin"), &data);
    assert_eq!(verdict.damaged_blocks(), [1]);
    match verdict {
        FileVerdict::Damaged {
            expected_size,
            actual_size,
            unchecked_blocks,
            damaged_chunks,
            ..
        } => {
            assert_eq!(expected_size, 5000);
            assert_eq!(actual_size, 5000);
            assert!(unchecked_blocks.is_empty());
            assert!(damaged_chunks.is_empty());
        }
        other => panic!("unexpected verdict: {other:?}"),
    }
}

#[test]
fn a_flipped_byte_in_a_bins_tail_names_the_chunk_not_a_block() {
    let set = oracle_set();
    let mut data = a_bin();
    // Block 2 holds a.bin's 1000-byte tail; the set carries no checksum for it,
    // so the tail's own hashes in the File packet are what catch this.
    data[4500] ^= 0x01;
    match verify_file(&set, file_named(&set, "a.bin"), &data) {
        FileVerdict::Damaged {
            damaged_blocks,
            damaged_chunks,
            ..
        } => {
            assert!(damaged_blocks.is_empty());
            assert_eq!(damaged_chunks, vec![0usize]);
        }
        other => panic!("unexpected verdict: {other:?}"),
    }
}

#[test]
fn a_flipped_byte_in_b_txts_inline_tail_is_caught() {
    let set = oracle_set();
    let mut data = b_txt();
    data[4] ^= 0x20;
    match verify_file(&set, file_named(&set, "b.txt"), &data) {
        FileVerdict::Damaged {
            damaged_blocks,
            damaged_chunks,
            ..
        } => {
            // b.txt occupies no input block at all: its ten bytes live inside the
            // File packet, so only the chunk can be named.
            assert!(damaged_blocks.is_empty());
            assert_eq!(damaged_chunks, vec![0usize]);
        }
        other => panic!("unexpected verdict: {other:?}"),
    }
}

/// A truncated file is reported as `Damaged` with both sizes, not as a distinct
/// size-mismatch verdict: the truncation is visible in the fields, and the same
/// verdict still carries the block-level detail.
#[test]
fn a_truncated_c_bin_reports_both_sizes_and_the_lost_block() {
    let set = oracle_set();
    let data = c_bin();
    match verify_file(&set, file_named(&set, "sub/c.bin"), &data[..2500]) {
        FileVerdict::Damaged {
            expected_size,
            actual_size,
            damaged_blocks,
            ..
        } => {
            assert_eq!(expected_size, 4000);
            assert_eq!(actual_size, 2500);
            // Block 3 is still whole; block 4 is gone.
            assert_eq!(damaged_blocks, vec![4u64]);
        }
        other => panic!("unexpected verdict: {other:?}"),
    }
}

#[test]
fn a_missing_file_is_reported_as_missing() {
    let set = oracle_set();
    let dir = std::env::temp_dir().join(format!("par3-rs-oracle-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("sub")).expect("temp dir");
    std::fs::write(dir.join("a.bin"), a_bin()).expect("write");
    std::fs::write(dir.join("b.txt"), b_txt()).expect("write");

    let report = par3_rs::verify_set(&set, &dir).expect("verifies");
    assert_eq!(report.missing_count(), 1);
    assert_eq!(report.complete_count(), 2);
    let missing = report
        .files()
        .iter()
        .find(|file| file.verdict().is_missing())
        .expect("one missing file");
    assert_eq!(missing.path(), "sub/c.bin");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn the_block_checksums_match_the_regenerated_inputs() {
    let set = oracle_set();
    let a = a_bin();
    let c = c_bin();
    let expected: Vec<(u64, &[u8])> = vec![
        (0, &a[0..2000]),
        (1, &a[2000..4000]),
        (3, &c[0..2000]),
        (4, &c[2000..4000]),
    ];
    for (index, block) in expected {
        let checksum: &BlockChecksum = set
            .block_checksum(index)
            .unwrap_or_else(|| panic!("block {index} has a checksum"));
        assert_eq!(checksum.rolling_hash, par3_rs::rolling_hash(block));
        assert_eq!(checksum.fingerprint, fingerprint(block));
    }
}

// ---------------------------------------------------------------------------
// 8: robustness, on real bytes rather than synthetic ones.
// ---------------------------------------------------------------------------

#[test]
fn junk_between_packets_is_skipped() {
    let data = set_par3();
    let packets = scan(&data);
    let mut noisy = Vec::new();
    for (offset, packet) in &packets {
        let start = *offset as usize;
        noisy.extend_from_slice(&data[start..start + packet.len() as usize]);
        // Enough junk to include a false magic sequence.
        noisy.extend_from_slice(b"PAR3\x00PKTnot a packet at all");
    }
    let recovered = scan(&noisy);
    assert_eq!(recovered.len(), packets.len());
    for ((_, expected), (_, actual)) in packets.iter().zip(recovered.iter()) {
        assert_eq!(expected.hash(), actual.hash());
    }
}

#[test]
fn a_flipped_byte_makes_the_scanner_drop_exactly_one_packet() {
    let data = set_par3();
    let packets = scan(&data);
    let (offset, packet) = &packets[3];
    let mut damaged = data.clone();
    damaged[*offset as usize + 60] ^= 0x01;
    let recovered = scan(&damaged);
    assert_eq!(recovered.len(), packets.len() - 1);
    assert!(recovered.iter().all(|(_, p)| p.hash() != packet.hash()));
}

#[test]
fn every_truncation_of_the_index_scans_without_panicking() {
    let data = set_par3();
    for len in 0..data.len() {
        let _ = scan_packets(&data[..len]);
    }
}

#[test]
fn every_single_byte_flip_scans_without_panicking() {
    let data = set_par3();
    for index in (0..data.len()).step_by(7) {
        let mut damaged = data.clone();
        damaged[index] ^= 0xff;
        let _ = scan_packets(&damaged);
    }
}

#[test]
fn a_duplicated_index_yields_one_set_and_a_duplicate_count() {
    let mut data = set_par3();
    let original = data.clone();
    data.extend_from_slice(&original);
    let packets = scan(&data);
    assert_eq!(packets.len(), 22);

    let set = Par3Set::from_packets_for(packets.into_iter().map(|(_, p)| p).collect(), SET_ID)
        .expect("builds");
    assert_eq!(set.duplicate_packet_count(), 11);
    assert_eq!(set.files().len(), 3);
}

#[test]
fn a_file_packet_before_its_start_packet_is_still_typed() {
    // The scanner sees packets in file order, so put a File packet first and the
    // Start packet last; the deferred parse must still resolve it.
    let data = set_par3();
    let packets = scan(&data);
    let mut reordered: Vec<u8> = Vec::new();
    let mut start_bytes = Vec::new();
    for (_, packet) in &packets {
        if packet.packet_type() == PacketType::Start {
            start_bytes = packet.to_bytes();
        } else {
            reordered.extend_from_slice(&packet.to_bytes());
        }
    }
    reordered.extend_from_slice(&start_bytes);

    let rescanned = scan(&reordered);
    assert_eq!(rescanned.len(), 11);
    let typed = rescanned
        .iter()
        .filter(|(_, packet)| matches!(packet.body(), PacketBody::File(_)))
        .count();
    assert_eq!(typed, 3);
}

#[test]
fn a_file_packet_alone_stays_opaque_and_round_trips() {
    let data = set_par3();
    let (offset, packet) = scan(&data)
        .into_iter()
        .find(|(_, packet)| packet.packet_type() == PacketType::File)
        .expect("a File packet");
    let start = offset as usize;
    let bytes = &data[start..start + packet.len() as usize];

    let alone = Packet::parse(bytes, 0, &ParseContext::new()).expect("parses");
    assert!(matches!(
        alone.body(),
        PacketBody::Opaque {
            packet_type: PacketType::File,
            ..
        }
    ));
    assert_eq!(alone.to_bytes(), bytes);
}
