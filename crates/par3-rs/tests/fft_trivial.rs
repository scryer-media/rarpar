//! Byte-aligned copy/XOR arithmetic, without allocating a transform domain.
use par3_rs::fft::{FftCodec, FftGeometry, FftInput};
use par3_rs::runtime::{EngineError, ExecutionOptions, MemoryBudget};

fn options() -> ExecutionOptions {
    let mut options = ExecutionOptions::default();
    options.memory = MemoryBudget::new(256);
    options.retained_bytes = 128;
    options.stripe_bytes = 17;
    options.workers = 1;
    options
}

fn value(index: usize, offset: usize) -> u8 {
    (index.wrapping_mul(73) ^ offset.wrapping_mul(29)) as u8
}

#[test]
fn maximal_xor_cohort_uses_two_small_byte_stripes() {
    let options = options();
    let geometry = FftGeometry::new(65535, 0).unwrap();
    let codec = FftCodec::new(geometry, options.clone()).unwrap();
    assert_eq!(options.memory.used(), 0);
    let mut recovery = [0u8; 19];
    codec
        .encode(
            19,
            0,
            1,
            |index, offset, out| {
                for (at, byte) in out.iter_mut().enumerate() {
                    *byte = value(index, offset as usize + at);
                }
                Ok(())
            },
            |index, offset, bytes| {
                assert_eq!(index, 0);
                recovery[offset as usize..offset as usize + bytes.len()].copy_from_slice(bytes);
                Ok(())
            },
        )
        .unwrap();
    for (at, byte) in recovery.iter().enumerate() {
        assert_eq!(
            *byte,
            (0..65535).fold(0, |sum, index| sum ^ value(index, at))
        );
    }
    let mut repaired = [0u8; 19];
    codec
        .decode(
            19,
            &[32767],
            &[0],
            |source, offset, out| {
                match source {
                    FftInput::Recovery(0) => {
                        out.copy_from_slice(&recovery[offset as usize..offset as usize + out.len()])
                    }
                    FftInput::Original(index) => {
                        assert_ne!(index, 32767);
                        for (at, byte) in out.iter_mut().enumerate() {
                            *byte = value(index, offset as usize + at);
                        }
                    }
                    _ => panic!("unexpected recovery row"),
                }
                Ok(())
            },
            |index, offset, bytes| {
                assert_eq!(index, 32767);
                repaired[offset as usize..offset as usize + bytes.len()].copy_from_slice(bytes);
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(repaired, std::array::from_fn(|at| value(32767, at)));
    assert!(options.memory.peak() <= 256);
    assert_eq!(options.memory.used(), 0);
}

#[test]
fn maximal_copy_capacity_accepts_odd_blocks_and_high_recovery_indices() {
    let options = options();
    let codec = FftCodec::new(FftGeometry::new(1, 15).unwrap(), options.clone()).unwrap();
    assert_eq!(options.memory.used(), 0);
    let input: [u8; 101] = std::array::from_fn(|at| value(0, at));
    let mut output = [[0u8; 101]; 2];
    codec
        .encode(
            101,
            32766,
            2,
            |index, offset, out| {
                assert_eq!(index, 0);
                out.copy_from_slice(&input[offset as usize..offset as usize + out.len()]);
                Ok(())
            },
            |index, offset, bytes| {
                output[index - 32766][offset as usize..offset as usize + bytes.len()]
                    .copy_from_slice(bytes);
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(output, [input; 2]);
    let mut repaired = [0u8; 101];
    codec
        .decode(
            101,
            &[0],
            &[32767, 32766],
            |source, offset, out| {
                assert_eq!(source, FftInput::Recovery(32767));
                out.copy_from_slice(&output[1][offset as usize..offset as usize + out.len()]);
                Ok(())
            },
            |index, offset, bytes| {
                assert_eq!(index, 0);
                repaired[offset as usize..offset as usize + bytes.len()].copy_from_slice(bytes);
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(repaired, input);
    assert!(options.memory.peak() <= 256);
    assert_eq!(options.memory.used(), 0);
}

#[test]
fn trivial_decode_rejects_invalid_indices_before_io() {
    for (inputs, capacity, lost, recovery) in [
        (1, 15, vec![0], vec![32768]),
        (1, 15, vec![0], vec![7, 7]),
        (1, 15, vec![1], vec![0]),
        (1, 15, vec![0, 0], vec![0, 1]),
        (65535, 0, vec![0], vec![]),
        (65535, 0, vec![0], vec![1]),
        (65535, 0, vec![65535], vec![0]),
    ] {
        let codec = FftCodec::new(FftGeometry::new(inputs, capacity).unwrap(), options()).unwrap();
        let error = codec
            .decode(
                19,
                &lost,
                &recovery,
                |_, _, _| panic!("invalid input reached reader"),
                |_, _, _| panic!("invalid input reached writer"),
            )
            .unwrap_err();
        assert!(matches!(error, EngineError::InvalidState(_)));
    }
}

#[test]
fn trivial_work_observes_cancellation_between_inputs() {
    let options = options();
    let codec = FftCodec::new(FftGeometry::new(65535, 0).unwrap(), options.clone()).unwrap();
    let mut reads = 0;
    let error = codec
        .encode(
            19,
            0,
            1,
            |_, _, out| {
                reads += 1;
                out.fill(0);
                options.cancel.cancel();
                Ok(())
            },
            |_, _, _| panic!("cancelled work reached writer"),
        )
        .unwrap_err();
    assert!(matches!(error, EngineError::Cancelled));
    assert_eq!(reads, 1);
    assert_eq!(options.memory.used(), 0);
}
