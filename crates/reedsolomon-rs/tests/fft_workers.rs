use reedsolomon_rs::fft::{TransformError, TransformField};
use reedsolomon_rs::gf_simd::LinearBackend;
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn parallel_cosets_match_serial_and_stay_in_the_supplied_pool() {
    for (bits, count) in [(8, 128), (16, 512)] {
        let field = TransformField::new(bits).unwrap();
        let original: Vec<Vec<u16>> = (0..count)
            .map(|row| {
                (0..1031)
                    .map(|at| ((row * 7919 + at * 103) % field.order()) as u16)
                    .collect()
            })
            .collect();
        let mut expected = original.clone();
        field
            .transform_with_backend(&mut expected, count, false, LinearBackend::Scalar, &|| {
                false
            })
            .unwrap();
        for workers in [1, 2, 3] {
            rayon::ThreadPoolBuilder::new()
                .num_threads(workers)
                .build_scoped(
                    |thread| thread.run(),
                    |pool| {
                        let seen = AtomicUsize::new(0);
                        let cancelled = || {
                            if let Some(index) = rayon::current_thread_index() {
                                assert!(index < workers);
                                assert_eq!(rayon::current_num_threads(), workers);
                                seen.fetch_or(1 << index, Ordering::Relaxed);
                            }
                            false
                        };
                        let mut actual = original.clone();
                        field
                            .transform_in_pool(
                                &mut actual,
                                count,
                                false,
                                LinearBackend::Auto,
                                pool,
                                &cancelled,
                            )
                            .unwrap();
                        assert_eq!(actual, expected);
                        field
                            .transform_in_pool(
                                &mut actual,
                                count,
                                true,
                                LinearBackend::Auto,
                                pool,
                                &cancelled,
                            )
                            .unwrap();
                        assert_eq!(actual, original);
                        if workers > 1 {
                            assert_ne!(seen.load(Ordering::Relaxed), 0);
                        }
                    },
                )
                .unwrap();
        }
    }
}

#[test]
fn parallel_cancellation_is_observed_inside_butterfly_work() {
    let field = TransformField::new(16).unwrap();
    let mut rows = vec![vec![73; 1024]; 512];
    rayon::ThreadPoolBuilder::new()
        .num_threads(2)
        .build_scoped(
            |thread| thread.run(),
            |pool| {
                let checks = AtomicUsize::new(0);
                let error = field
                    .transform_in_pool(&mut rows, 0, false, LinearBackend::Auto, pool, &|| {
                        rayon::current_thread_index().is_some()
                            && checks.fetch_add(1, Ordering::Relaxed) >= 20
                    })
                    .unwrap_err();
                assert_eq!(error, TransformError::Cancelled);
                assert!(checks.load(Ordering::Relaxed) > 20);
            },
        )
        .unwrap();
}
