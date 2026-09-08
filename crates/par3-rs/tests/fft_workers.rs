use par3_rs::fft::{FftCodec, FftGeometry, FftInput};
use par3_rs::runtime::{EngineError, ExecutionOptions, MemoryBudget};

#[test]
fn worker_admission_respects_limits_and_joins_before_releasing_memory() {
    for (limit, requested, admitted) in [(128 << 10, 8, 1), (2 << 20, 2, 2)] {
        let mut options = ExecutionOptions::default();
        options.memory = MemoryBudget::new(limit);
        options.workers = requested;
        options.stripe_bytes = 1024;
        let codec = FftCodec::new(FftGeometry::new(120, 7).unwrap(), options.clone()).unwrap();
        assert_eq!(codec.worker_count(), admitted);
        assert!(options.memory.used() > 0);
        let mut encoded = vec![vec![0; 1031]; 2];
        let byte = |index: usize, at: usize| ((index * 7919 + at * 103) % 256) as u8;
        codec
            .encode(
                1031,
                126,
                2,
                |index, offset, out| {
                    for (at, value) in out.iter_mut().enumerate() {
                        *value = byte(index, offset as usize + at);
                    }
                    Ok(())
                },
                |index, offset, bytes| {
                    encoded[index - 126][offset as usize..offset as usize + bytes.len()]
                        .copy_from_slice(bytes);
                    Ok(())
                },
            )
            .unwrap();
        let mut repaired = vec![vec![0; 1031]; 2];
        codec
            .decode(
                1031,
                &[3, 119],
                &[126, 127],
                |source, offset, out| {
                    match source {
                        FftInput::Original(index) => {
                            assert!(![3, 119].contains(&index));
                            for (at, value) in out.iter_mut().enumerate() {
                                *value = byte(index, offset as usize + at);
                            }
                        }
                        FftInput::Recovery(index) => out.copy_from_slice(
                            &encoded[index - 126][offset as usize..offset as usize + out.len()],
                        ),
                    }
                    Ok(())
                },
                |index, offset, bytes| {
                    repaired[usize::from(index == 119)]
                        [offset as usize..offset as usize + bytes.len()]
                        .copy_from_slice(bytes);
                    Ok(())
                },
            )
            .unwrap();
        for (index, output) in [3, 119].into_iter().zip(repaired) {
            assert_eq!(
                output,
                (0..1031).map(|at| byte(index, at)).collect::<Vec<_>>()
            );
        }
        assert!(options.memory.peak() <= limit);
        drop(codec);
        assert_eq!(
            options.memory.used(),
            0,
            "all workers must be joined on drop"
        );
    }
}

#[test]
fn cancelled_fft_releases_worker_stacks_after_codec_drop() {
    let mut options = ExecutionOptions::default();
    options.workers = 3;
    options.memory = MemoryBudget::new(2 << 20);
    let codec = FftCodec::new(FftGeometry::new(120, 7).unwrap(), options.clone()).unwrap();
    assert_eq!(codec.worker_count(), 3);
    let error = codec
        .encode(
            1024,
            0,
            2,
            |_, _, out| {
                out.fill(0);
                options.cancel.cancel();
                Ok(())
            },
            |_, _, _| panic!("cancelled operation wrote output"),
        )
        .unwrap_err();
    assert!(matches!(error, EngineError::Cancelled));
    drop(codec);
    assert_eq!(options.memory.used(), 0);
}
