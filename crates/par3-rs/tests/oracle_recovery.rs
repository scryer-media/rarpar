//! Recovery Data packets, against the recovery volumes the reference wrote.
//!
//! The `.par3` bytes and their provenance live in `tests/common/mod.rs`. The
//! index files are covered by `tests/oracle_vectors.rs`; this suite is about the
//! `.volXX+YY.par3` volumes: how they are laid out, how a set takes inventory of
//! the recovery blocks they carry, and — the point of the whole file — whether
//! the recovery bytes are exactly what the reference's Cauchy construction
//! produces from the input blocks.
//!
//! The Galois-field arithmetic that last check needs lives here, in [`gf`], and
//! is deliberately not the library's own: it is the independent standard the
//! library's [`par3_rs::gf`] and [`par3_rs::cauchy`] are checked against in
//! `tests/oracle_codec.rs`. Keep it slow, obvious, and separate.
//!
//! Damage cases mutate in-memory copies — a truncated `Vec`, a parsed packet
//! struct written back out through `to_bytes` — and never the embedded bytes.

mod common;

use std::collections::BTreeMap;

use common::{
    SET_ID, SET16_ID, assert_block_eq, gf8_contents, gf8_packets, gf8_set, gf16_contents,
    gf16_packets, gf16_set, hex, input_blocks, packets_of, scan, set_par3, set_vol0_par3,
    set_vol1_par3, set16_vol0_par3, set16_vol1_par3,
};
use par3_rs::packet::{ChunkDescription, ChunkTail};
use par3_rs::{
    Packet, PacketBody, PacketType, Par3Set, RecoveryBlock, RecoveryDataPacket, fingerprint,
    rolling_hash,
};

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

/// Offset, length and type of every packet in a file, in the order they appear.
fn inventory(data: &[u8]) -> Vec<(u64, u64, PacketType)> {
    scan(data)
        .into_iter()
        .map(|(offset, packet)| (offset, packet.len(), packet.packet_type()))
        .collect()
}

// ---------------------------------------------------------------------------
// Test-only Galois-field arithmetic.
// ---------------------------------------------------------------------------

/// Scalar arithmetic in the binary Galois fields PAR3 uses.
///
/// Deliberately the slowest possible implementation — shift and reduce, inverse
/// by exponentiation — because its job is to be obviously the definition rather
/// than to be quick. The library has no Galois-field code, and this must not
/// become it.
mod gf {
    /// A Galois field GF(2^`width`) with the given generator polynomial.
    #[derive(Debug, Clone, Copy)]
    pub struct Field {
        /// Generator polynomial, including the leading term the packet omits.
        pub polynomial: u32,
        /// Field width in bits: 8 or 16.
        pub width: u32,
    }

    impl Field {
        /// GF(2^8) with `0x11d`, what the GF(2^8) oracle archive's Start packet
        /// asks for.
        pub const GF8: Self = Self {
            polynomial: 0x11d,
            width: 8,
        };

        /// GF(2^16) with `0x1100b`, from the GF(2^16) archive's Start packet.
        pub const GF16: Self = Self {
            polynomial: 0x1_100b,
            width: 16,
        };

        /// The largest value in the field, which is also the number of non-zero
        /// elements.
        pub fn max(self) -> u32 {
            (1 << self.width) - 1
        }

        /// Bytes per field element.
        pub fn symbol_size(self) -> usize {
            self.width as usize / 8
        }

        /// Carry-less multiplication reduced modulo the generator polynomial.
        pub fn multiply(self, a: u32, b: u32) -> u32 {
            let overflow = 1u32 << self.width;
            let mut shifted = a;
            let mut remaining = b;
            let mut product = 0u32;
            while remaining != 0 {
                if remaining & 1 != 0 {
                    product ^= shifted;
                }
                remaining >>= 1;
                shifted <<= 1;
                if shifted & overflow != 0 {
                    shifted ^= self.polynomial;
                }
            }
            product
        }

        /// The multiplicative inverse, as `a^(2^width - 2)`.
        ///
        /// Every non-zero element satisfies `a^(2^width - 1) = 1`, so raising to
        /// one power less inverts it.
        pub fn inverse(self, value: u32) -> u32 {
            assert_ne!(value, 0, "zero has no multiplicative inverse");
            let mut result = 1u32;
            let mut base = value;
            let mut exponent = self.max() - 1;
            while exponent != 0 {
                if exponent & 1 != 0 {
                    result = self.multiply(result, base);
                }
                base = self.multiply(base, base);
                exponent >>= 1;
            }
            result
        }
    }
}

/// One recovery block, computed the way the reference implementation does.
///
/// For recovery block `R` and input block `I` the matrix element is
/// `inv(x(I) ^ (MAX - R))`; the recovery block is the exclusive-or over every
/// input block of that element times the block, symbol by symbol. `x` is passed
/// in so that the specification's `I + 1` numbering can be tried as well as the
/// reference's `I`.
fn cauchy_recovery_block(
    field: gf::Field,
    blocks: &BTreeMap<u64, Vec<u8>>,
    block_size: usize,
    recovery_index: u64,
    x: impl Fn(u64) -> u32,
) -> Vec<u8> {
    let symbol = field.symbol_size();
    assert_eq!(
        block_size % symbol,
        0,
        "a block must be a whole number of field elements"
    );
    let y_r = field.max() - u32::try_from(recovery_index).expect("a small recovery index");
    let mut recovery = vec![0u8; block_size];

    for (index, block) in blocks {
        assert_eq!(block.len(), block_size, "input block {index} is not padded");
        let element = field.inverse(x(*index) ^ y_r);
        for (source, destination) in block
            .chunks_exact(symbol)
            .zip(recovery.chunks_exact_mut(symbol))
        {
            let mut value = 0u32;
            for (step, byte) in source.iter().enumerate() {
                value |= u32::from(*byte) << (8 * step);
            }
            let product = field.multiply(element, value).to_le_bytes();
            for (step, byte) in destination.iter_mut().enumerate() {
                *byte ^= product[step];
            }
        }
    }
    recovery
}

#[test]
fn the_field_arithmetic_satisfies_its_own_identities() {
    for field in [gf::Field::GF8, gf::Field::GF16] {
        for value in [1u32, 2, 3, 0x5a, field.max() - 1, field.max()] {
            assert_eq!(field.multiply(value, 1), value);
            assert_eq!(field.multiply(1, value), value);
            assert_eq!(field.multiply(value, 0), 0);
            assert_eq!(field.multiply(value, field.inverse(value)), 1);
        }
    }
    // Doubling the element whose top bit is set folds in the polynomial.
    assert_eq!(gf::Field::GF8.multiply(2, 0x80), 0x1d);
    assert_eq!(gf::Field::GF16.multiply(2, 0x8000), 0x100b);
}

// ---------------------------------------------------------------------------
// 1: the volumes hold what the reference wrote, where it wrote it.
// ---------------------------------------------------------------------------

#[test]
fn the_embedded_volumes_are_the_files_the_reference_wrote() {
    for (data, length, digest) in [
        (set_vol0_par3(), 3138, "154c167420a4c4fc60846105e1f3586c"),
        (set_vol1_par3(), 3138, "83dabe6792824daad15140719e755642"),
        (set16_vol0_par3(), 7995, "488a6ef46f01b52e8c11f7690e52c6a9"),
        (set16_vol1_par3(), 15809, "8d927872fe322f7648914386eac81ee7"),
    ] {
        assert_eq!(data.len(), length);
        assert_eq!(hex(&fingerprint(&data)), digest);
    }
}

#[test]
fn each_recovery_volume_holds_the_packets_the_reference_wrote() {
    use PacketType::{
        CauchyMatrix, Comment, Creator, Directory, ExternalData, File, RecoveryData, Root, Start,
    };

    // One recovery block, wrapped in one copy of the set's common packets. Both
    // GF(2^8) volumes have the same layout; only the recovery block differs.
    let gf8_volume = vec![
        (0, 115, Creator),
        (115, 82, Start),
        (197, 72, CauchyMatrix),
        (269, 136, File),
        (405, 98, File),
        (503, 96, File),
        (599, 73, Directory),
        (672, 109, Root),
        (781, 104, ExternalData),
        (885, 104, ExternalData),
        (989, 2088, RecoveryData),
        (3077, 61, Comment),
    ];
    assert_eq!(inventory(&set_vol0_par3()), gf8_volume);
    assert_eq!(inventory(&set_vol1_par3()), gf8_volume);

    assert_eq!(
        inventory(&set16_vol0_par3()),
        vec![
            (0, 115, Creator),
            (115, 83, Start),
            (198, 72, CauchyMatrix),
            (270, 138, File),
            (408, 77, Root),
            (485, 7256, ExternalData),
            (7741, 188, RecoveryData),
            (7929, 66, Comment),
        ]
    );

    // Two recovery blocks, and a second copy of the common packets spread
    // between them so that the volume can be read on its own.
    assert_eq!(
        inventory(&set16_vol1_par3()),
        vec![
            (0, 115, Creator),
            (115, 83, Start),
            (198, 72, CauchyMatrix),
            (270, 138, File),
            (408, 77, Root),
            (485, 7256, ExternalData),
            (7741, 188, RecoveryData),
            (7929, 83, Start),
            (8012, 72, CauchyMatrix),
            (8084, 188, RecoveryData),
            (8272, 138, File),
            (8410, 77, Root),
            (8487, 7256, ExternalData),
            (15743, 66, Comment),
        ]
    );
}

#[test]
fn the_recovery_data_packets_name_the_root_and_the_matrix() {
    for (data, indices, block_size) in [
        (set_par3(), vec![], 2000usize),
        (set_vol0_par3(), vec![0u64], 2000),
        (set_vol1_par3(), vec![1], 2000),
        (set16_vol0_par3(), vec![0], 100),
        (set16_vol1_par3(), vec![1, 2], 100),
    ] {
        let packets = scan(&data);
        let root_hash = packets
            .iter()
            .find(|(_, packet)| packet.packet_type() == PacketType::Root)
            .expect("a Root packet")
            .1
            .hash();
        let matrix_hash = packets
            .iter()
            .find(|(_, packet)| packet.packet_type() == PacketType::CauchyMatrix)
            .expect("a Cauchy Matrix packet")
            .1
            .hash();

        let recovery: Vec<RecoveryDataPacket> = packets
            .into_iter()
            .filter_map(|(_, packet)| match packet.into_body() {
                PacketBody::RecoveryData(recovery) => Some(recovery),
                _ => None,
            })
            .collect();
        assert_eq!(
            recovery
                .iter()
                .map(|packet| packet.recovery_block_index)
                .collect::<Vec<_>>(),
            indices
        );
        for packet in &recovery {
            assert_eq!(packet.root_hash, root_hash);
            assert_eq!(packet.matrix_hash, matrix_hash);
            assert_eq!(packet.data.len(), block_size);
        }
    }
}

// ---------------------------------------------------------------------------
// 2: the volumes write back byte for byte.
// ---------------------------------------------------------------------------

#[test]
fn every_packet_in_every_volume_writes_back_byte_for_byte() {
    for data in [
        set_vol0_par3(),
        set_vol1_par3(),
        set16_vol0_par3(),
        set16_vol1_par3(),
    ] {
        for (offset, packet) in scan(&data) {
            let start = usize::try_from(offset).expect("a small offset");
            let end = start + usize::try_from(packet.len()).expect("a small length");
            assert_eq!(
                packet.to_bytes(),
                &data[start..end],
                "packet at offset {offset} did not round-trip"
            );
        }
    }
}

#[test]
fn the_recovery_volumes_round_trip_whole() {
    for data in [
        set_vol0_par3(),
        set_vol1_par3(),
        set16_vol0_par3(),
        set16_vol1_par3(),
    ] {
        let rebuilt: Vec<u8> = scan(&data)
            .into_iter()
            .flat_map(|(_, packet)| packet.to_bytes())
            .collect();
        assert_eq!(rebuilt, data);
    }
}

// ---------------------------------------------------------------------------
// 3: the set takes inventory of the recovery blocks.
// ---------------------------------------------------------------------------

#[test]
fn the_gf8_set_lists_both_recovery_blocks() {
    let set = gf8_set();
    let matrix_hash = set.matrix_packets()[0].hash();

    let indices: Vec<u64> = set
        .recovery_blocks()
        .iter()
        .map(RecoveryBlock::index)
        .collect();
    assert_eq!(indices, [0, 1]);
    for block in set.recovery_blocks() {
        assert!(block.matrix_present());
        assert_eq!(block.matrix_hash(), matrix_hash);
        assert_eq!(block.data_len() as u64, set.block_size());
        assert_eq!(block.packet().root_hash, set.root_hash());
    }
    assert!(set.foreign_recovery_packets().is_empty());
    assert_eq!(set.conflicting_recovery_packet_count(), 0);
    assert!(set.recovery_block_checksums().is_empty());

    // 11 + 12 + 12 packets read, of which 11 common packets and 2 recovery
    // blocks are distinct: the volumes repeat the common packets so that either
    // one can be read alone.
    assert_eq!(gf8_packets().len(), 35);
    assert_eq!(set.duplicate_packet_count(), 22);
}

#[test]
fn the_gf16_set_lists_all_three_recovery_blocks() {
    let set = gf16_set();
    let matrix_hash = set.matrix_packets()[0].hash();

    let indices: Vec<u64> = set
        .recovery_blocks()
        .iter()
        .map(RecoveryBlock::index)
        .collect();
    assert_eq!(indices, [0, 1, 2]);
    for block in set.recovery_blocks() {
        assert!(block.matrix_present());
        assert_eq!(block.matrix_hash(), matrix_hash);
        assert_eq!(block.data_len(), 100);
    }
    assert!(set.foreign_recovery_packets().is_empty());
    assert_eq!(set.conflicting_recovery_packet_count(), 0);

    // 7 + 8 + 14 packets, of which 7 common packets and 3 recovery blocks are
    // distinct.
    assert_eq!(gf16_packets().len(), 29);
    assert_eq!(set.duplicate_packet_count(), 19);
}

/// The reference reported "Loaded 2 new packets (found 14 packets)" for this
/// volume: fourteen packets, of which the two recovery blocks and seven common
/// packets are distinct.
#[test]
fn the_two_block_volume_repeats_its_common_packets() {
    let packets = packets_of(&set16_vol1_par3());
    assert_eq!(packets.len(), 14);
    let set = Par3Set::from_packets_for(packets, SET16_ID).expect("builds");
    assert_eq!(set.duplicate_packet_count(), 5);
    assert_eq!(
        set.recovery_blocks()
            .iter()
            .map(RecoveryBlock::index)
            .collect::<Vec<_>>(),
        [1, 2]
    );
}

// ---------------------------------------------------------------------------
// 4 and 5: the volumes stand on their own, damaged or not.
// ---------------------------------------------------------------------------

#[test]
fn the_volumes_alone_describe_the_whole_set() {
    let mut packets = packets_of(&set_vol0_par3());
    packets.extend(packets_of(&set_vol1_par3()));
    let set = Par3Set::from_packets_for(packets, SET_ID).expect("builds without the index file");

    let paths: Vec<&str> = set.files().iter().map(|file| file.path()).collect();
    assert_eq!(paths, ["a.bin", "b.txt", "sub/c.bin"]);
    assert_eq!(set.block_count(), 5);
    assert_eq!(set.block_checksums().len(), 4);
    assert_eq!(
        set.recovery_blocks()
            .iter()
            .map(RecoveryBlock::index)
            .collect::<Vec<_>>(),
        [0, 1]
    );

    let mut packets = packets_of(&set16_vol0_par3());
    packets.extend(packets_of(&set16_vol1_par3()));
    let set = Par3Set::from_packets_for(packets, SET16_ID).expect("builds without the index file");
    assert_eq!(set.files()[0].path(), "big.bin");
    assert_eq!(set.block_count(), 301);
    assert_eq!(
        set.recovery_blocks()
            .iter()
            .map(RecoveryBlock::index)
            .collect::<Vec<_>>(),
        [0, 1, 2]
    );
}

#[test]
fn a_volume_truncated_mid_recovery_block_still_yields_the_rest() {
    let data = set16_vol1_par3();
    // The second Recovery Data packet runs from 8084 to 8272; cut inside it, so
    // that it and everything after it is lost.
    let damaged = &data[..8150];
    let packets = packets_of(damaged);
    assert_eq!(packets.len(), 9);

    let set = Par3Set::from_packets_for(packets, SET16_ID).expect("the surviving packets build");
    assert_eq!(set.files()[0].path(), "big.bin");
    assert_eq!(
        set.recovery_blocks()
            .iter()
            .map(RecoveryBlock::index)
            .collect::<Vec<_>>(),
        [1]
    );
    assert_eq!(set.recovery_blocks()[0].data_len(), 100);
}

// ---------------------------------------------------------------------------
// 6 and 7: recovery packets that do not belong, and ones that contradict.
// ---------------------------------------------------------------------------

/// The first Recovery Data packet of the GF(2^8) archive, as a parsed struct.
fn gf8_recovery_packet(index: u64) -> RecoveryDataPacket {
    let data = if index == 0 {
        set_vol0_par3()
    } else {
        set_vol1_par3()
    };
    scan(&data)
        .into_iter()
        .find_map(|(_, packet)| match packet.into_body() {
            PacketBody::RecoveryData(recovery) => Some(recovery),
            _ => None,
        })
        .expect("a Recovery Data packet")
}

#[test]
fn a_recovery_packet_retagged_to_another_root_is_counted_not_inventoried() {
    let mut foreign = gf8_recovery_packet(0);
    foreign.root_hash = [0x77; 16];
    let foreign = Packet::new(SET_ID, PacketBody::RecoveryData(foreign));

    // The re-serialised packet is a real packet: it scans back with a header
    // hash that covers its new contents.
    let bytes = foreign.to_bytes();
    assert_eq!(scan(&bytes).len(), 1);

    let mut packets = gf8_packets();
    packets.push(foreign);
    let set = Par3Set::from_packets_for(packets, SET_ID).expect("builds");

    assert_eq!(
        set.recovery_blocks()
            .iter()
            .map(RecoveryBlock::index)
            .collect::<Vec<_>>(),
        [0, 1]
    );
    assert_eq!(set.foreign_recovery_packets().len(), 1);
    // Still readable, just not this set's recovery data.
    assert_eq!(set.foreign_recovery_packets()[0].root_hash, [0x77; 16]);
}

/// One junk Recovery Data packet appended to a set — the Root hash it has to
/// name is plaintext in the file, so anyone can write one — must cost the set
/// that recovery block and nothing else.
#[test]
fn two_recovery_packets_for_one_index_are_both_excluded() {
    let mut altered = gf8_recovery_packet(0);
    altered.data[17] ^= 0x01;
    let mut packets = gf8_packets();
    packets.push(Packet::new(SET_ID, PacketBody::RecoveryData(altered)));

    let set = Par3Set::from_packets_for(packets, SET_ID).expect("the set still builds");
    let paths: Vec<&str> = set.files().iter().map(|file| file.path()).collect();
    assert_eq!(paths, ["a.bin", "b.txt", "sub/c.bin"]);
    // Index 0 is claimed twice and nothing says which claim is right, so it is
    // dropped rather than guessed at; index 1 is untouched.
    assert_eq!(
        set.recovery_blocks()
            .iter()
            .map(RecoveryBlock::index)
            .collect::<Vec<_>>(),
        [1]
    );
    assert_eq!(set.conflicting_recovery_packet_count(), 2);
}

// ---------------------------------------------------------------------------
// 8: the block map, derived from the set rather than assumed.
// ---------------------------------------------------------------------------

#[test]
fn the_gf8_block_map_is_the_one_the_reference_reported() {
    let set = gf8_set();
    let contents = gf8_contents();
    let blocks = input_blocks(&set, &contents);
    let (a, c) = (&contents[0].1, &contents[2].1);

    // "Actual block count = 5": a.bin takes 0, 1 and the tail block 2; b.txt's
    // ten bytes are inline and take none; sub/c.bin takes 3 and 4.
    assert_eq!(set.block_count(), 5);
    assert_eq!(blocks.keys().copied().collect::<Vec<_>>(), [0, 1, 2, 3, 4]);
    assert_eq!(blocks[&0], a[0..2000]);
    assert_eq!(blocks[&1], a[2000..4000]);
    let mut tail = a[4000..5000].to_vec();
    tail.resize(2000, 0);
    assert_eq!(blocks[&2], tail);
    assert_eq!(blocks[&3], c[0..2000]);
    assert_eq!(blocks[&4], c[2000..4000]);

    let b_txt_file = set
        .files()
        .iter()
        .find(|file| file.path() == "b.txt")
        .expect("b.txt");
    assert!(matches!(
        &b_txt_file.chunks()[0],
        ChunkDescription::Protected {
            tail: ChunkTail::Inline(_),
            ..
        }
    ));

    assert_block_checksums(&set, &blocks, &[2]);
}

#[test]
fn the_gf16_block_map_covers_three_hundred_and_one_blocks() {
    let set = gf16_set();
    let contents = gf16_contents();
    let blocks = input_blocks(&set, &contents);
    let big = &contents[0].1;

    assert_eq!(set.block_count(), 301);
    assert_eq!(blocks.len(), 301);
    assert_eq!(*blocks.keys().next_back().expect("a last block"), 300);
    assert_eq!(blocks[&0], big[0..100]);
    assert_eq!(blocks[&299], big[29900..30000]);
    let mut tail = big[30000..30050].to_vec();
    tail.resize(100, 0);
    assert_eq!(blocks[&300], tail);

    assert_block_checksums(&set, &blocks, &[300]);
}

/// Every block the set has a checksum for must hash to it, and the blocks named
/// in `without_checksums` — the ones holding chunk tails, which the reference
/// leaves out of its External Data packets — must have none.
fn assert_block_checksums(set: &Par3Set, blocks: &BTreeMap<u64, Vec<u8>>, without: &[u64]) {
    for (index, block) in blocks {
        match set.block_checksum(*index) {
            Some(checksum) => {
                assert!(!without.contains(index), "block {index} has a checksum");
                assert_eq!(checksum.rolling_hash, rolling_hash(block), "block {index}");
                assert_eq!(checksum.fingerprint, fingerprint(block), "block {index}");
            }
            None => assert!(
                without.contains(index),
                "block {index} unexpectedly has no checksum"
            ),
        }
    }
    assert_eq!(
        set.block_checksums().len(),
        blocks.len() - without.len(),
        "unexpected checksum coverage"
    );
}

// ---------------------------------------------------------------------------
// 9: the oracle proof — the recovery bytes are the Cauchy construction.
// ---------------------------------------------------------------------------

#[test]
fn the_gf8_recovery_blocks_are_the_reference_cauchy_construction() {
    let set = gf8_set();
    let contents = gf8_contents();
    let blocks = input_blocks(&set, &contents);
    let block_size = usize::try_from(set.block_size()).expect("a sane block size");
    assert_eq!(
        set.galois_field().polynomial(),
        Some(u64::from(gf::Field::GF8.polynomial))
    );

    for block in set.recovery_blocks() {
        let expected = cauchy_recovery_block(
            gf::Field::GF8,
            &blocks,
            block_size,
            block.index(),
            |index| u32::try_from(index).expect("a small block index"),
        );
        assert_block_eq(
            block.data(),
            &expected,
            &format!("GF(2^8) recovery block {}", block.index()),
        );
    }
}

#[test]
fn the_gf16_recovery_blocks_are_the_reference_cauchy_construction() {
    let set = gf16_set();
    let contents = gf16_contents();
    let blocks = input_blocks(&set, &contents);
    let block_size = usize::try_from(set.block_size()).expect("a sane block size");
    assert_eq!(
        set.galois_field().polynomial(),
        Some(u64::from(gf::Field::GF16.polynomial))
    );

    for block in set.recovery_blocks() {
        let expected = cauchy_recovery_block(
            gf::Field::GF16,
            &blocks,
            block_size,
            block.index(),
            |index| u32::try_from(index).expect("a small block index"),
        );
        assert_block_eq(
            block.data(),
            &expected,
            &format!("GF(2^16) recovery block {}", block.index()),
        );
    }
}

/// The published specification numbers the matrix columns from `I + 1`; the
/// reference numbers them from `I`. Pin the difference, so that a future codec
/// that quietly follows the specification fails here rather than producing
/// recovery data nothing can use.
#[test]
fn the_specifications_column_numbering_does_not_reproduce_the_recovery_bytes() {
    let set = gf8_set();
    let contents = gf8_contents();
    let blocks = input_blocks(&set, &contents);
    let block_size = usize::try_from(set.block_size()).expect("a sane block size");

    for block in set.recovery_blocks() {
        let with_offset = cauchy_recovery_block(
            gf::Field::GF8,
            &blocks,
            block_size,
            block.index(),
            |index| u32::try_from(index).expect("a small block index") + 1,
        );
        assert_ne!(
            block.data(),
            with_offset,
            "x_I = I + 1 reproduced recovery block {}",
            block.index()
        );
    }
}
