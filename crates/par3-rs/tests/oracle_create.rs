//! The library's creator, against the sets the reference implementation wrote.
//!
//! Both oracle archives are rebuilt here from the same input files and the same
//! options the reference was given, and the result has to match packet for
//! packet. Packet *bodies* are compared rather than whole packets for the types
//! whose content is fully determined by the inputs; the sequence of packet types
//! in every file, and the volume file names, are compared as well.
//!
//! In fact the match is tighter than that: given the reference's own Creator
//! text, every byte of all six files comes out the same, which every test here
//! asserts as well.
//!
//! Nothing here hand-assembles PAR3 bytes. The reference's bytes are the hex
//! constants in `tests/common`, and ours come out of `par3_rs::create`.

mod common;

use std::collections::BTreeMap;
use std::path::PathBuf;

use common::{
    SET_ID, SET16_ID, TempTree, body_of, hex, packets_of, set_par3, set_vol0_par3, set_vol1_par3,
    set16_par3, set16_vol0_par3, set16_vol1_par3, type_sequence, write_gf8_inputs,
    write_gf16_inputs,
};
use par3_rs::create::{CreateOptions, CreateReport, InputSpec, RecoveryAmount, create};
use par3_rs::{Packet, PacketType};

/// Group a file's packets by type, keeping the order they appear in.
fn by_type(data: &[u8]) -> BTreeMap<PacketType, Vec<Packet>> {
    let mut grouped: BTreeMap<PacketType, Vec<Packet>> = BTreeMap::new();
    for packet in packets_of(data) {
        grouped
            .entry(packet.packet_type())
            .or_default()
            .push(packet);
    }
    grouped
}

/// Require every packet of these types to have the same body in both files.
fn assert_bodies_match(ours: &[u8], theirs: &[u8], types: &[PacketType], what: &str) {
    let ours = by_type(ours);
    let theirs = by_type(theirs);
    for packet_type in types {
        let mine = ours.get(packet_type).map_or(&[][..], Vec::as_slice);
        let reference = theirs.get(packet_type).map_or(&[][..], Vec::as_slice);
        assert_eq!(
            mine.len(),
            reference.len(),
            "{what}: {} packets of type {:?} but the reference wrote {}",
            mine.len(),
            packet_type,
            reference.len()
        );
        for (index, (mine, reference)) in mine.iter().zip(reference).enumerate() {
            let mine = body_of(mine);
            let reference = body_of(reference);
            assert_eq!(
                hex(&mine),
                hex(&reference),
                "{what}: body {index} of type {packet_type:?} differs"
            );
        }
    }
}

/// The Creator text the reference wrote into the oracle archives.
const REFERENCE_CREATOR: &str =
    "par3cmdline version 0.0.1\n(https://github.com/Parchive/par3cmdline)";

/// Every packet type whose body is fixed by the inputs alone, and so has to
/// match byte for byte.
const DETERMINED: &[PacketType] = &[
    PacketType::Start,
    PacketType::CauchyMatrix,
    PacketType::File,
    PacketType::Directory,
    PacketType::Root,
    PacketType::ExternalData,
    PacketType::RecoveryData,
];

/// Rebuild an oracle archive and hand back the report and the file names.
fn rebuild(
    tree: &TempTree,
    names: &[&str],
    stem: &str,
    block_size: u64,
    recovery: u64,
    comment: &str,
) -> (CreateReport, Vec<String>) {
    let files: Vec<PathBuf> = names.iter().map(PathBuf::from).collect();
    let inputs = InputSpec::new(tree.path(), &files);
    let options = CreateOptions::default()
        .with_block_size(block_size)
        .with_recovery(RecoveryAmount::Blocks(recovery))
        .with_comment(comment)
        // The Creator packet is the one packet whose content is the client's
        // own to choose, so ours says what the reference's said.
        .with_creator(REFERENCE_CREATOR);
    let report = create(&inputs, &tree.path().join(stem), &options).expect("the set is created");
    let written = report
        .files_written
        .iter()
        .map(|path| {
            path.file_name()
                .expect("a file name")
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    (report, written)
}

#[test]
fn the_gf8_archive_is_rebuilt_packet_for_packet() {
    let tree = TempTree::new("oracle-gf8");
    write_gf8_inputs(&tree);

    let (report, names) = rebuild(
        &tree,
        &["a.bin", "b.txt", "sub/c.bin"],
        "set.par3",
        2000,
        2,
        "rarpar oracle",
    );

    assert_eq!(
        names,
        ["set.par3", "set.vol0+1.par3", "set.vol1+1.par3"],
        "the volume names the reference chose"
    );
    assert_eq!(report.block_size, 2000);
    assert_eq!(report.block_count, 5);
    assert_eq!(report.recovery_count, 2);
    assert_eq!(report.field.size, 1);
    assert_eq!(report.packed_tails, 0);
    assert_eq!(
        report.set_id, SET_ID,
        "our InputSetID derivation reproduces the reference's"
    );

    let files: [(&str, Vec<u8>); 3] = [
        ("set.par3", set_par3()),
        ("set.vol0+1.par3", set_vol0_par3()),
        ("set.vol1+1.par3", set_vol1_par3()),
    ];
    for (name, reference) in files {
        let ours = tree.read(name);
        assert_eq!(
            type_sequence(&ours),
            type_sequence(&reference),
            "{name}: packet type sequence"
        );
        assert_bodies_match(&ours, &reference, DETERMINED, name);
        assert_eq!(hex(&ours), hex(&reference), "{name}: whole file");
    }
}

#[test]
fn the_gf16_archive_is_rebuilt_packet_for_packet() {
    let tree = TempTree::new("oracle-gf16");
    write_gf16_inputs(&tree);

    let (report, names) = rebuild(
        &tree,
        &["big.bin"],
        "set16.par3",
        100,
        3,
        "rarpar oracle gf16",
    );

    assert_eq!(
        names,
        ["set16.par3", "set16.vol0+1.par3", "set16.vol1+2.par3"]
    );
    assert_eq!(report.block_size, 100);
    assert_eq!(report.block_count, 301);
    assert_eq!(report.recovery_count, 3);
    assert_eq!(report.field.size, 2);
    assert_eq!(report.set_id, SET16_ID);

    let files: [(&str, Vec<u8>); 3] = [
        ("set16.par3", set16_par3()),
        ("set16.vol0+1.par3", set16_vol0_par3()),
        ("set16.vol1+2.par3", set16_vol1_par3()),
    ];
    for (name, reference) in files {
        let ours = tree.read(name);
        assert_eq!(
            type_sequence(&ours),
            type_sequence(&reference),
            "{name}: packet type sequence"
        );
        assert_bodies_match(&ours, &reference, DETERMINED, name);
        assert_eq!(hex(&ours), hex(&reference), "{name}: whole file");
    }
}

#[test]
fn the_reference_writes_no_recovery_external_data_packets() {
    // Recovery External Data describes recovery blocks held outside the set,
    // which the reference does not do by default — so neither do we, and the
    // sequence comparisons above would catch it if either changed.
    for data in [set_par3(), set_vol0_par3(), set16_vol1_par3()] {
        assert!(
            !packets_of(&data)
                .iter()
                .any(|packet| packet.packet_type() == PacketType::RecoveryExternalData),
            "the reference wrote a Recovery External Data packet after all"
        );
    }
}
