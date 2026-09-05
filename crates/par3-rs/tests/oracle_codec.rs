//! The library's Cauchy codec, against the recovery volumes the reference wrote.
//!
//! `tests/oracle_recovery.rs` proves that the reference's recovery bytes are the
//! Cauchy construction, using arithmetic written out longhand inside that test.
//! This suite points the library's own [`par3_rs::cauchy`] encoder at the same
//! bytes and requires it to produce them, and then requires its decoder to put
//! back every input block that could be lost and still be recoverable.
//!
//! Nothing here is damaged on disk: losses are modelled by leaving blocks out of
//! what is handed to the decoder, and the recovery blocks come from the packets
//! the reference wrote.

mod common;

use std::collections::BTreeMap;

use common::{assert_block_eq, gf8_contents, gf8_set, gf16_contents, gf16_set, input_blocks};
use par3_rs::cauchy::{Decoder, Encoder, Geometry, RecoveredBlock};
use par3_rs::gf::{Field, Gf8, Gf16, for_set};
use par3_rs::{Par3Error, Par3Set, Result};

/// A tiny xorshift, so the sampled loss patterns repeat exactly on every run.
struct Rng(u64);

impl Rng {
    fn step(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.step() % bound
    }
}

/// The code geometry a set describes: its block size, its input blocks, and the
/// recovery blocks its volumes carry, which start at index 0 in both oracles.
fn geometry_of(set: &Par3Set) -> Geometry {
    Geometry {
        block_size: set.block_size(),
        input_blocks: set.block_count(),
        recovery_blocks: set.recovery_blocks().len() as u64,
        first_recovery: 0,
    }
}

/// The set's recovery blocks as plain `(index, bytes)` pairs.
fn recovery_of(set: &Par3Set) -> Vec<(u64, Vec<u8>)> {
    set.recovery_blocks()
        .iter()
        .map(|block| (block.index(), block.data().to_vec()))
        .collect()
}

/// Encode every input block and compare the result with what the reference
/// wrote into its recovery volumes.
fn assert_encoder_matches<F: Field>(field: F, set: &Par3Set, blocks: &BTreeMap<u64, Vec<u8>>) {
    let mut encoder = Encoder::new(field, geometry_of(set)).expect("the oracle geometry encodes");
    for (index, block) in blocks {
        encoder.add_input_block(*index, block).expect("input block");
    }
    assert!(encoder.is_complete(), "every input block was supplied");
    let rows = encoder.finish();

    let expected = recovery_of(set);
    assert_eq!(rows.len(), expected.len(), "recovery block count");
    for (row, (index, data)) in rows.iter().zip(&expected) {
        assert_eq!(row.index(), *index, "recovery block order");
        assert_block_eq(data, row.data(), &format!("recovery block {index}"));
    }
}

/// Rebuild `lost` from the surviving input blocks and the named recovery blocks.
fn recover<F: Field>(
    field: F,
    geometry: Geometry,
    blocks: &BTreeMap<u64, Vec<u8>>,
    recovery: &[(u64, Vec<u8>)],
    lost: &[u64],
    available: &[u64],
) -> Result<Vec<RecoveredBlock>> {
    let mut decoder = Decoder::new(field, geometry, lost, available)?;
    for (index, block) in blocks {
        if !lost.contains(index) {
            decoder.add_input_block(*index, block)?;
        }
    }
    let chosen = decoder.recovery_rows().to_vec();
    for (index, data) in recovery {
        if chosen.contains(index) {
            decoder.add_recovery_block(*index, data)?;
        }
    }
    decoder.solve()
}

/// Rebuild `lost` and require every block back byte for byte.
fn assert_recovers<F: Field>(
    field: F,
    geometry: Geometry,
    blocks: &BTreeMap<u64, Vec<u8>>,
    recovery: &[(u64, Vec<u8>)],
    lost: &[u64],
    available: &[u64],
) {
    let rebuilt = recover(field, geometry, blocks, recovery, lost, available)
        .unwrap_or_else(|error| panic!("losing {lost:?} should be recoverable: {error}"));
    let mut sorted = lost.to_vec();
    sorted.sort_unstable();
    assert_eq!(
        rebuilt
            .iter()
            .map(RecoveredBlock::index)
            .collect::<Vec<_>>(),
        sorted,
        "rebuilt blocks are the lost ones, in order"
    );
    for block in &rebuilt {
        assert_block_eq(
            &blocks[&block.index()],
            block.data(),
            &format!(
                "input block {} rebuilt after losing {lost:?}",
                block.index()
            ),
        );
    }
}

// ---------------------------------------------------------------------------
// The encoder reproduces what the reference wrote.
// ---------------------------------------------------------------------------

#[test]
fn the_encoder_reproduces_the_gf8_recovery_blocks() {
    let set = gf8_set();
    let contents = gf8_contents();
    let blocks = input_blocks(&set, &contents);
    assert_eq!(blocks.len(), 5);

    // The field comes out of the set's own Start packet, not out of this test.
    let field = match for_set(&set.galois_field()).expect("GF(2^8)") {
        par3_rs::gf::AnyField::Gf8(field) => field,
        other => panic!("the GF(2^8) oracle asked for {other:?}"),
    };
    assert_eq!(field.generator(), 0x11d);
    assert_encoder_matches(field, &set, &blocks);
}

#[test]
fn the_encoder_reproduces_the_gf16_recovery_blocks() {
    let set = gf16_set();
    let contents = gf16_contents();
    let blocks = input_blocks(&set, &contents);
    assert_eq!(blocks.len(), 301);

    let field = match for_set(&set.galois_field()).expect("GF(2^16)") {
        par3_rs::gf::AnyField::Gf16(field) => field,
        other => panic!("the GF(2^16) oracle asked for {other:?}"),
    };
    assert_eq!(field.generator(), 0x1_100b);
    assert_encoder_matches(field, &set, &blocks);
}

#[test]
fn the_field_rule_picks_the_field_both_oracles_used() {
    let gf8 = gf8_set();
    assert_eq!(
        par3_rs::cauchy::default_field(gf8.block_count(), 2, 0),
        gf8.galois_field()
    );
    let gf16 = gf16_set();
    assert_eq!(
        par3_rs::cauchy::default_field(gf16.block_count(), 3, 0),
        gf16.galois_field()
    );
}

// ---------------------------------------------------------------------------
// The decoder puts back whatever can be put back.
// ---------------------------------------------------------------------------

/// Two recovery blocks and five input blocks: every loss of one or two blocks is
/// recoverable, and there are only fifteen of them, so try all fifteen.
#[test]
fn the_decoder_rebuilds_every_gf8_loss_pattern() {
    let set = gf8_set();
    let contents = gf8_contents();
    let blocks = input_blocks(&set, &contents);
    let geometry = geometry_of(&set);
    let recovery = recovery_of(&set);
    let available = [0u64, 1];

    let mut patterns = 0;
    for first in 0..5u64 {
        assert_recovers(
            Gf8::default(),
            geometry,
            &blocks,
            &recovery,
            &[first],
            &available,
        );
        patterns += 1;
        for second in first + 1..5 {
            assert_recovers(
                Gf8::default(),
                geometry,
                &blocks,
                &recovery,
                &[first, second],
                &available,
            );
            patterns += 1;
        }
    }
    assert_eq!(patterns, 15, "every subset of size one or two");
}

/// 301 input blocks and 3 recovery blocks: every single loss, plus a fixed
/// sample of larger ones, because there are about four and a half million
/// three-block losses.
#[test]
fn the_decoder_rebuilds_sampled_gf16_loss_patterns() {
    let set = gf16_set();
    let contents = gf16_contents();
    let blocks = input_blocks(&set, &contents);
    let geometry = geometry_of(&set);
    let recovery = recovery_of(&set);
    let available = [0u64, 1, 2];

    for index in 0..set.block_count() {
        assert_recovers(
            Gf16::default(),
            geometry,
            &blocks,
            &recovery,
            &[index],
            &available,
        );
    }

    let field = Gf16::default();
    let mut rng = Rng(0x2026_0905_0000_0011);
    for _ in 0..200 {
        let size = 1 + rng.below(3) as usize;
        let mut lost = Vec::with_capacity(size);
        while lost.len() < size {
            let candidate = rng.below(set.block_count());
            if !lost.contains(&candidate) {
                lost.push(candidate);
            }
        }
        assert_recovers(
            field.clone(),
            geometry,
            &blocks,
            &recovery,
            &lost,
            &available,
        );
    }
}

/// The tail block is the interesting one: it is half data and half zero padding,
/// and it must come back with the padding on it.
#[test]
fn a_rebuilt_tail_block_keeps_its_zero_padding() {
    let set = gf16_set();
    let contents = gf16_contents();
    let blocks = input_blocks(&set, &contents);
    let rebuilt = recover(
        Gf16::default(),
        geometry_of(&set),
        &blocks,
        &recovery_of(&set),
        &[300],
        &[0, 1, 2],
    )
    .expect("the tail block is recoverable");
    assert_eq!(rebuilt[0].data().len(), 100);
    assert_eq!(&rebuilt[0].data()[50..], &[0u8; 50]);
    assert_eq!(&rebuilt[0].data()[..50], &contents[0].1[30000..30050]);
}

#[test]
fn recovery_rows_other_than_the_first_ones_work_just_as_well() {
    let set = gf16_set();
    let contents = gf16_contents();
    let blocks = input_blocks(&set, &contents);
    let geometry = geometry_of(&set);
    let recovery = recovery_of(&set);

    // Recovery block 0 is unavailable — its volume is missing — so rows 1 and 2
    // carry the whole repair.
    assert_recovers(
        Gf16::default(),
        geometry,
        &blocks,
        &recovery,
        &[7, 300],
        &[1, 2],
    );
    // A single row, and not the first one.
    assert_recovers(Gf16::default(), geometry, &blocks, &recovery, &[42], &[2]);
    // Offering three rows for two losses uses the first two of them.
    let decoder = Decoder::new(Gf16::default(), geometry, &[7, 300], &[0, 1, 2]).expect("builds");
    assert_eq!(decoder.recovery_rows(), [0, 1]);
}

#[test]
fn losing_more_blocks_than_there_are_recovery_rows_is_refused() {
    let set = gf8_set();
    let geometry = geometry_of(&set);
    let error = Decoder::new(Gf8::default(), geometry, &[0, 1, 2], &[0, 1])
        .expect_err("five inputs, two recovery blocks, three lost");
    assert!(
        matches!(
            error,
            Par3Error::InsufficientRecovery {
                lost: 3,
                available: 2
            }
        ),
        "unexpected error: {error}"
    );

    // The same shape with only one recovery volume on hand.
    let error = Decoder::new(Gf8::default(), geometry, &[0, 1], &[1])
        .expect_err("one recovery block cannot rebuild two");
    assert!(
        matches!(
            error,
            Par3Error::InsufficientRecovery {
                lost: 2,
                available: 1
            }
        ),
        "unexpected error: {error}"
    );
}
