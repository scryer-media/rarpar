//! What the codecs actually compute, and what the transform plan removes.
//!
//! The FFT decoder ends with a forward transform over the whole domain, and
//! then reads a handful of its rows. `ForwardPlan` splits that transform into
//! the stages that cannot be avoided and the stages that only produce rows
//! nobody reads, and skips the latter. These tests are the oracle for that:
//! every decode here must return the original bytes, and the diagnostics must
//! show the plan removed work rather than merely rearranging it.
//!
//! Nothing here assembles or edits a PAR3 packet. Recovery rows come from this
//! crate's own encoder and the data from a deterministic byte stream.
mod common;

use par3_rs::fft::{FftCodec, FftGeometry, FftInput};
use par3_rs::runtime::{ExecutionOptions, MemoryBudget};

/// `inputs` blocks of `block_size` bytes from a deterministic stream, with the
/// last block deliberately short so its tail is zero padding.
fn blocks(inputs: usize, block_size: u64) -> Vec<Vec<u8>> {
    let size = block_size as usize;
    let mut all = vec![0u8; inputs * size];
    let mut hash = blake3::Hasher::new();
    hash.update(b"PAR3 transform plan oracle");
    hash.update(&(inputs as u64).to_le_bytes());
    hash.update(&block_size.to_le_bytes());
    hash.finalize_xof().fill(&mut all);
    let mut out: Vec<Vec<u8>> = all.chunks_exact(size).map(<[u8]>::to_vec).collect();
    // A short final block: the encoder pads it, and the decoder must return the
    // padding as the zeros it was.
    if let Some(last) = out.last_mut() {
        last[size / 2..].fill(0);
    }
    out
}

fn options(stripe: usize, workers: usize) -> ExecutionOptions {
    let mut options = ExecutionOptions::default();
    options.stripe_bytes = stripe;
    options.workers = workers;
    options.memory = MemoryBudget::new(256 << 20);
    options
}

/// Encode every compatible recovery row, then decode `lost` from `recovery`
/// and require the original bytes back. Returns what the codec counters said
/// about the decode alone.
fn round_trip(
    inputs: usize,
    capacity_log2: i8,
    block_size: u64,
    stripe: usize,
    lost: &[usize],
    recovery: &[usize],
    workers: usize,
) -> (par3_rs::runtime::CodecSnapshot, usize, u64) {
    let geometry = FftGeometry::new(inputs as u64, capacity_log2).unwrap();
    let data = blocks(inputs, block_size);
    let capacity = geometry.capacity();

    let encode_options = options(stripe, workers);
    let codec = FftCodec::new(geometry, encode_options.clone()).unwrap();
    let mut parity = vec![vec![0u8; block_size as usize]; capacity];
    codec
        .encode(
            block_size,
            0,
            capacity,
            |index, offset, out| {
                out.copy_from_slice(&data[index][offset as usize..offset as usize + out.len()]);
                Ok(())
            },
            |index, offset, bytes| {
                parity[index][offset as usize..offset as usize + bytes.len()]
                    .copy_from_slice(bytes);
                Ok(())
            },
        )
        .unwrap();
    drop(codec);

    let decode_options = options(stripe, workers);
    let codec = FftCodec::new(geometry, decode_options.clone()).unwrap();
    let mut recovered = vec![vec![0u8; block_size as usize]; lost.len()];
    codec
        .decode(
            block_size,
            lost,
            recovery,
            |row, offset, out| {
                let from = match row {
                    FftInput::Original(index) => &data[index],
                    FftInput::Recovery(index) => &parity[index],
                };
                out.copy_from_slice(&from[offset as usize..offset as usize + out.len()]);
                Ok(())
            },
            |index, offset, bytes| {
                let slot = lost.iter().position(|at| *at == index).expect("a lost row");
                recovered[slot][offset as usize..offset as usize + bytes.len()]
                    .copy_from_slice(bytes);
                Ok(())
            },
        )
        .unwrap();
    for (slot, index) in lost.iter().enumerate() {
        assert_eq!(
            recovered[slot], data[*index],
            "inputs {inputs} capacity 2^{capacity_log2} block {block_size} stripe {stripe} \
             lost {lost:?} recovery {recovery:?}"
        );
    }
    drop(codec);
    assert_eq!(decode_options.memory.used(), 0);
    (
        decode_options.diagnostics.codec(),
        geometry.domain(),
        decode_options.diagnostics.admission().stripe_bytes,
    )
}

/// One decode to run: inputs, capacity exponent, block size, stripe, the rows
/// lost and the recovery rows to rebuild them from.
type Case<'a> = (usize, i8, u64, usize, &'a [usize], &'a [usize]);

/// GF8 and GF16, light, heavy and skewed damage, arbitrary recovery choices,
/// and stripe widths on both sides of the 64-symbol SIMD threshold and the
/// 32,768-symbol pool threshold.
#[test]
fn a_pruned_decode_returns_the_original_bytes_in_both_fields() {
    let every: Vec<usize> = (0..128).collect();
    let cases: &[Case<'_>] = &[
        // GF8: domain 256, light damage, one row.
        (200, 5, 4096, 1 << 10, &[3], &[0]),
        // GF8: skewed damage, all losses inside one narrow block.
        (200, 5, 4096, 1 << 10, &[0, 1, 2, 3], &[4, 9, 17, 31]),
        // GF8: damage spread across the domain.
        (200, 5, 4096, 1 << 10, &[0, 61, 122, 183], &[1, 2, 3, 30]),
        // GF8 at the SIMD threshold: 63 and 65 symbols per row.
        (200, 5, 4096, 63, &[7], &[11]),
        (200, 5, 4096, 65, &[7], &[11]),
        // GF16: domain 2048, one row, then heavy damage.
        (900, 7, 8192, 1 << 12, &[5], &[0]),
        (
            900,
            7,
            8192,
            1 << 12,
            &[0, 200, 400, 600, 800],
            &[1, 2, 3, 4, 5],
        ),
        // GF16 around the 32,768-symbol pool threshold: a 2048-row domain needs
        // 16 symbols a row to reach it, so 30 and 34 bytes straddle it.
        (900, 7, 8192, 60, &[5], &[0]),
        (900, 7, 8192, 68, &[5], &[0]),
        // GF16 with every input lost that the capacity can cover.
        (900, 7, 2048, 1 << 10, &every, &every),
    ];
    for (inputs, capacity_log2, block_size, stripe, lost, recovery) in cases {
        for workers in [1, 4] {
            round_trip(
                *inputs,
                *capacity_log2,
                *block_size,
                *stripe,
                lost,
                recovery,
                workers,
            );
        }
    }
}

/// The plan must remove work, not move it. The numbers here are the cost model
/// itself: a 2048-row domain is eleven stages, so one full transform is 11,264
/// butterflies. Losing one row, and with 2048 symbols in a row to spread each
/// call's setup over, the model confines the four narrowest stages to one
/// 128-row block: 1024x4 wide plus 448 narrow, 4544 instead of 11,264. The
/// decode's other transform — the input inverse — is unplanned and runs in
/// full, so the two together are 15,808 a stripe.
#[test]
fn the_plan_skips_what_one_lost_row_does_not_need() {
    let (light, domain, stripe) = round_trip(900, 7, 8192, 4096, &[5], &[0], 1);
    assert_eq!((domain, stripe), (2048, 4096));
    let stripes = 8192 / stripe;
    assert_eq!(light.butterflies, stripes * (11_264 + 4_544), "{light:?}");
    assert_eq!(light.butterflies_skipped, stripes * 6_720, "{light:?}");
    assert_eq!(
        light.butterflies + light.butterflies_skipped,
        stripes * 2 * 11_264,
        "what ran plus what was skipped is two full transforms a stripe"
    );
}

/// The other end of the cost model. Thirty-two losses spread 62 rows apart in
/// the same 2048-row domain touch every block of every wide split, so the plan
/// is driven down to 16-row blocks: seven wide stages over the whole domain
/// (1024x7) plus 32 blocks of 32 butterflies each, 8192 against the full
/// 11,264. That is a real saving but a small one, and far less than the 7168 a
/// single loss removes — the plan tracks the damage rather than claiming a
/// fixed discount.
#[test]
fn spread_damage_prunes_far_less_than_a_single_loss() {
    let spread: Vec<usize> = (0..32).map(|index| index * 62).collect();
    let recovery: Vec<usize> = (0..32).collect();
    let (heavy, domain, stripe) = round_trip(2000, 5, 8192, 4096, &spread, &recovery, 1);
    assert_eq!((domain, stripe), (2048, 4096));
    let stripes = 8192 / stripe;
    assert_eq!(heavy.butterflies, stripes * (11_264 + 8_192), "{heavy:?}");
    assert_eq!(heavy.butterflies_skipped, stripes * 3_072, "{heavy:?}");

    let (light, _, _) = round_trip(2000, 5, 8192, 4096, &[5], &[0], 1);
    assert!(
        light.butterflies_skipped > heavy.butterflies_skipped * 2,
        "one loss should prune far more than 32 spread ones: {light:?} {heavy:?}"
    );
}

#[test]
fn the_plan_does_not_depend_on_the_order_the_caller_names_its_losses() {
    // `decode` checks that `lost` is in range and free of duplicates, but never
    // that it is sorted, and `transform_forward` decides which blocks to keep
    // with a binary search. A plan that inherited the caller's order would
    // prune blocks the decode still needs and return wrong bytes without
    // saying so, which is why `round_trip` asserts the bytes on every call.
    let ascending = [3usize, 40, 41, 200, 613];
    let mut descending = ascending;
    descending.reverse();
    // An order with no run of adjacent losses left intact.
    let shuffled = [200usize, 3, 613, 41, 40];
    let recovery = [0usize, 1, 2, 3, 4];

    let (sorted, domain, stripe) = round_trip(900, 7, 8192, 4096, &ascending, &recovery, 1);
    assert_eq!((domain, stripe), (2048, 4096));
    assert!(
        sorted.butterflies_skipped > 0,
        "the case must select a pruned plan to be worth ordering: {sorted:?}"
    );

    for lost in [&descending[..], &shuffled[..]] {
        let (measured, _, _) = round_trip(900, 7, 8192, 4096, lost, &recovery, 1);
        assert_eq!(
            (measured.butterflies, measured.butterflies_skipped),
            (sorted.butterflies, sorted.butterflies_skipped),
            "{lost:?} must cost exactly what {ascending:?} costs"
        );
    }
}
