//! Round trips through the Cauchy codec on data no reference implementation
//! ever saw.
//!
//! `tests/oracle_codec.rs` pins the codec to the bytes par3cmdline wrote, which
//! covers two geometries. This suite covers the shapes those two do not: odd
//! block sizes, blocks of a single field symbol, input counts at the edge of
//! what a field can address, blocks arriving in the wrong order, and losses
//! chosen at random. Encode, lose blocks, decode, and require the bytes back.

use std::time::Instant;

use par3_rs::cauchy::{CodecLimits, Decoder, Encoder, Geometry};
use par3_rs::gf::{Field, Gf8, Gf16};
use par3_rs::{Par3Error, RecoveredBlock};

/// A tiny xorshift, so every random case repeats exactly on every run.
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

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.below(256) as u8).collect()
    }
}

/// Random input blocks, the last of them short so that zero padding is always
/// part of the round trip.
fn input_blocks(rng: &mut Rng, geometry: Geometry) -> Vec<Vec<u8>> {
    let size = geometry.block_size as usize;
    (0..geometry.input_blocks)
        .map(|index| {
            let len = if index + 1 == geometry.input_blocks {
                size.div_ceil(2)
            } else {
                size
            };
            rng.bytes(len)
        })
        .collect()
}

/// The same blocks as the encoder sees them: zero-padded to the block size.
fn padded(blocks: &[Vec<u8>], block_size: usize) -> Vec<Vec<u8>> {
    blocks
        .iter()
        .map(|block| {
            let mut padded = block.clone();
            padded.resize(block_size, 0);
            padded
        })
        .collect()
}

/// Encode `blocks` in the order `order` names them.
fn encode<F: Field>(
    field: F,
    geometry: Geometry,
    blocks: &[Vec<u8>],
    order: &[u64],
) -> Vec<Vec<u8>> {
    let mut encoder = Encoder::new(field, geometry).expect("a workable geometry");
    for index in order {
        encoder
            .add_input_block(*index, &blocks[*index as usize])
            .expect("an input block");
    }
    assert!(encoder.is_complete());
    encoder
        .finish()
        .into_iter()
        .map(par3_rs::RecoveryRow::into_data)
        .collect()
}

/// Lose `lost`, rebuild it from `rows`, and require every byte back.
fn assert_round_trip<F: Field>(
    field: F,
    geometry: Geometry,
    blocks: &[Vec<u8>],
    rows: &[Vec<u8>],
    lost: &[u64],
) {
    let available: Vec<u64> =
        (geometry.first_recovery..geometry.first_recovery + geometry.recovery_blocks).collect();

    let mut decoder =
        Decoder::new(field, geometry, lost, &available).expect("enough recovery blocks");
    for index in 0..geometry.input_blocks {
        if !lost.contains(&index) {
            decoder
                .add_input_block(index, &blocks[index as usize])
                .expect("a surviving block");
        }
    }
    for row in decoder.recovery_rows().to_vec() {
        let offset = (row - geometry.first_recovery) as usize;
        decoder
            .add_recovery_block(row, &rows[offset])
            .expect("a recovery block");
    }
    let rebuilt = decoder.solve().expect("a Cauchy system always solves");

    let expected = padded(blocks, geometry.block_size as usize);
    let mut sorted = lost.to_vec();
    sorted.sort_unstable();
    assert_eq!(
        rebuilt
            .iter()
            .map(RecoveredBlock::index)
            .collect::<Vec<_>>(),
        sorted
    );
    for block in &rebuilt {
        assert_eq!(
            block.data(),
            expected[block.index() as usize],
            "block {} after losing {lost:?} of {geometry:?}",
            block.index()
        );
    }
}

/// Random loss patterns, encoding the set once and losing from it repeatedly.
///
/// At most four blocks are lost at a time even where the geometry could survive
/// more: solving for `n` lost blocks costs `n` syndromes over every input block
/// plus an `n × n` inversion, and the geometries here go up to sixty-five
/// thousand blocks.
fn assert_survives_random_losses<F: Field>(field: F, geometry: Geometry, seed: u64) {
    let mut rng = Rng(seed);
    let blocks = input_blocks(&mut rng, geometry);
    let order: Vec<u64> = (0..geometry.input_blocks).collect();
    let rows = encode(field.clone(), geometry, &blocks, &order);

    let largest = geometry.recovery_blocks.min(geometry.input_blocks).min(4);
    for size in 1..=largest {
        let mut lost: Vec<u64> = Vec::new();
        while (lost.len() as u64) < size {
            let candidate = rng.below(geometry.input_blocks);
            if !lost.contains(&candidate) {
                lost.push(candidate);
            }
        }
        assert_round_trip(field.clone(), geometry, &blocks, &rows, &lost);
    }
}

#[test]
fn gf8_round_trips_through_a_range_of_geometries() {
    for (step, (block_size, input_blocks, recovery_blocks, first_recovery)) in [
        (1u64, 4u64, 2u64, 0u64),
        // An odd block size, which GF(2^8) allows and GF(2^16) does not.
        (7, 9, 3, 0),
        (2000, 5, 2, 0),
        (2000, 5, 2, 3),
        (64, 1, 1, 0),
        // Right at the edge of the field: 251 + 0 + 5 uses all 256 values.
        (16, 251, 5, 0),
        (16, 128, 4, 120),
    ]
    .into_iter()
    .enumerate()
    {
        let geometry = Geometry {
            block_size,
            input_blocks,
            recovery_blocks,
            first_recovery,
        };
        assert_survives_random_losses(
            Gf8::default(),
            geometry,
            0x2026_0905_0000_0021 + step as u64,
        );
    }
}

#[test]
fn gf16_round_trips_through_a_range_of_geometries() {
    for (step, (block_size, input_blocks, recovery_blocks, first_recovery)) in [
        // A block of exactly one field symbol.
        (2u64, 4u64, 2u64, 0u64),
        (100, 301, 3, 0),
        (2048, 40, 4, 0),
        (2048, 40, 4, 17),
        // Well past what GF(2^8) could address.
        (8, 1000, 3, 0),
        // Right at the edge of the field: 65000 + 532 + 4 uses all 65536
        // values, so input block 64999 and the last row value 65535 - 535 are
        // one apart.
        (2, 65_000, 4, 532),
    ]
    .into_iter()
    .enumerate()
    {
        let geometry = Geometry {
            block_size,
            input_blocks,
            recovery_blocks,
            first_recovery,
        };
        assert_survives_random_losses(
            Gf16::default(),
            geometry,
            0x2026_0905_0000_0031 + step as u64,
        );
    }
}

#[test]
fn the_order_input_blocks_arrive_in_does_not_matter() {
    let geometry = Geometry {
        block_size: 300,
        input_blocks: 11,
        recovery_blocks: 4,
        first_recovery: 2,
    };
    let mut rng = Rng(0x2026_0905_0000_0041);
    let blocks = input_blocks(&mut rng, geometry);

    let ascending: Vec<u64> = (0..11).collect();
    let expected = encode(Gf8::default(), geometry, &blocks, &ascending);

    let mut shuffled = ascending.clone();
    for position in (1..shuffled.len()).rev() {
        let other = rng.below(position as u64 + 1) as usize;
        shuffled.swap(position, other);
    }
    assert_ne!(shuffled, ascending, "the shuffle did something");
    assert_eq!(
        encode(Gf8::default(), geometry, &blocks, &shuffled),
        expected
    );

    // Descending, for good measure.
    let descending: Vec<u64> = (0..11).rev().collect();
    assert_eq!(
        encode(Gf8::default(), geometry, &blocks, &descending),
        expected
    );
}

#[test]
fn the_gf8_field_boundary_is_where_an_input_index_meets_a_recovery_row() {
    // The last input block is 250 and the last row value is 255 - 4 = 251, so
    // 251 input blocks and 5 recovery blocks use all 256 field values and no
    // two of them collide.
    let geometry = Geometry {
        block_size: 8,
        input_blocks: 251,
        recovery_blocks: 5,
        first_recovery: 0,
    };
    assert!(Encoder::new(Gf8::default(), geometry).is_ok());

    // One more input block and block 251 would need the inverse of
    // 251 ^ 251 = 0.
    let geometry = Geometry {
        input_blocks: 252,
        ..geometry
    };
    let error = Encoder::new(Gf8::default(), geometry).expect_err("no such matrix");
    assert!(
        matches!(error, Par3Error::CodecGeometry { .. }),
        "unexpected error: {error}"
    );
    // The same geometry is unremarkable in the wider field.
    assert!(Encoder::new(Gf16::default(), geometry).is_ok());
}

#[test]
fn a_decoder_that_would_not_fit_in_its_budget_is_refused() {
    let geometry = Geometry {
        block_size: 1 << 20,
        input_blocks: 64,
        recovery_blocks: 32,
        first_recovery: 0,
    };
    let lost: Vec<u64> = (0..32).collect();
    let available: Vec<u64> = (0..32).collect();
    let limits = CodecLimits::new(8 << 20);
    let error = Decoder::with_limits(Gf8::default(), geometry, &lost, &available, &limits)
        .expect_err("32 syndromes of a megabyte do not fit in eight");
    assert!(
        matches!(error, Par3Error::CodecLimitExceeded { .. }),
        "unexpected error: {error}"
    );
    // Four losses do fit.
    assert!(
        Decoder::with_limits(Gf8::default(), geometry, &lost[..2], &available, &limits).is_ok()
    );
}

/// Not a benchmark — a sanity check that the region multiply is table-driven and
/// not accidentally quadratic, printed so a reader can see the number.
///
/// Multiplying by the same factor twice cancels, because addition in the field
/// is exclusive-or, so an even number of passes must leave the buffer where it
/// started.
#[test]
fn mul_acc_moves_a_mebibyte_at_a_sensible_rate() {
    const LEN: usize = 1 << 20;
    const ROUNDS: usize = 8;

    let mut rng = Rng(0x2026_0905_0000_0051);
    let source = rng.bytes(LEN);
    let start = rng.bytes(LEN);

    let field = Gf8::default();
    let mut region = start.clone();
    let began = Instant::now();
    for _ in 0..ROUNDS {
        field.mul_acc(&mut region, &source, 0xb7);
    }
    let elapsed = began.elapsed();
    println!(
        "GF(2^8) mul_acc: {:.0} MiB/s ({ROUNDS} passes over {} MiB in {elapsed:?})",
        (ROUNDS as f64) / elapsed.as_secs_f64(),
        LEN >> 20
    );
    assert_eq!(region, start, "an even number of passes cancels");

    let field = Gf16::default();
    let mut region = start.clone();
    let began = Instant::now();
    for _ in 0..ROUNDS {
        field.mul_acc(&mut region, &source, 0xb71d);
    }
    let elapsed = began.elapsed();
    println!(
        "GF(2^16) mul_acc: {:.0} MiB/s ({ROUNDS} passes over {} MiB in {elapsed:?})",
        (ROUNDS as f64) / elapsed.as_secs_f64(),
        LEN >> 20
    );
    assert_eq!(region, start, "an even number of passes cancels");
}
