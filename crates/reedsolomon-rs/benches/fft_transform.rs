//! Native comparisons of Cantor transforms with equal input buffers: one
//! worker, except the `cantor_pool` group.
//! These arithmetic measurements do not establish end-to-end PAR3 parity.
//! On a GFNI host the `Auto` maps take their affine form; run once more with
//! `WEAVER_LINEAR_GFNI=0` to measure the AVX2 shuffle form on the same rows.
//! On an SVE2 host they take their SVE2 form; `WEAVER_SVE2=0` measures NEON.
#[cfg(not(target_family = "wasm"))]
fn main() {
    use criterion::{BatchSize, BenchmarkId, Criterion, Throughput};
    use reedsolomon_rs::fft::TransformField;
    use reedsolomon_rs::gf_simd::LinearBackend;
    use std::hint::black_box;

    eprintln!(
        "linear map kernel: {:?}, GFNI affine form: {}, SVE2 form: {}",
        LinearBackend::Auto.kernel(),
        reedsolomon_rs::gf_simd::linear_uses_gfni(),
        reedsolomon_rs::gf_simd::uses_sve2()
    );
    let mut criterion = Criterion::default().configure_from_args();
    let mut group = criterion.benchmark_group("cantor_transform_pair");
    for (bits, count) in [(8, 128), (16, 1024)] {
        let field = TransformField::new(bits).unwrap();
        for width in [64, 4096] {
            let original: Vec<Vec<u16>> = (0..count)
                .map(|row| {
                    (0..width)
                        .map(|at| ((row * 7919 + at * 103) % field.order()) as u16)
                        .collect()
                })
                .collect();
            // Forward plus inverse, each visiting the entire symbol stripe.
            group.throughput(Throughput::Bytes((count * width * 4) as u64));
            for backend in [LinearBackend::Scalar, LinearBackend::Auto] {
                let mut rows = original.clone();
                group.bench_function(
                    BenchmarkId::new(format!("gf{bits}_{count}x{width}"), format!("{backend:?}")),
                    |b| {
                        b.iter(|| {
                            field
                                .transform_with_backend(
                                    black_box(&mut rows),
                                    0,
                                    false,
                                    backend,
                                    &|| false,
                                )
                                .unwrap();
                            field
                                .transform_with_backend(
                                    black_box(&mut rows),
                                    0,
                                    true,
                                    backend,
                                    &|| false,
                                )
                                .unwrap();
                        });
                    },
                );
                assert_eq!(rows, original);
            }
        }
    }
    group.finish();

    // The same GF(2^8) problem on zero-extended 16-bit rows and on byte rows.
    // Throughput counts data bytes (one per symbol), forward plus inverse.
    let mut group = criterion.benchmark_group("cantor_gf8_lane");
    let field = TransformField::new(8).unwrap();
    for (count, width) in [(256usize, 4096usize), (256, 65536)] {
        let original: Vec<Vec<u8>> = (0..count)
            .map(|row| {
                (0..width)
                    .map(|at| ((row * 7919 + at * 103) % 256) as u8)
                    .collect()
            })
            .collect();
        group.throughput(Throughput::Bytes((count * width * 2) as u64));
        let id = format!("{count}x{width}");
        let mut words: Vec<Vec<u16>> = original
            .iter()
            .map(|row| row.iter().map(|&value| value.into()).collect())
            .collect();
        group.bench_function(BenchmarkId::new("u16", &id), |b| {
            b.iter(|| {
                for inverse in [false, true] {
                    field
                        .transform_with_backend(
                            black_box(&mut words),
                            0,
                            inverse,
                            LinearBackend::Auto,
                            &|| false,
                        )
                        .unwrap();
                }
            });
        });
        let mut bytes = original.clone();
        group.bench_function(BenchmarkId::new("u8", &id), |b| {
            b.iter(|| {
                for inverse in [false, true] {
                    field
                        .transform_u8_with_backend(
                            black_box(&mut bytes),
                            0,
                            inverse,
                            LinearBackend::Auto,
                            &|| false,
                        )
                        .unwrap();
                }
            });
        });
        assert_eq!(bytes, original);
    }
    group.finish();

    // Pooled transforms at the PAR3 engine's stripe shapes: GF(2^8) byte rows
    // (encoder and decoder) and GF(2^16) word rows, each 64 KiB wide, forward
    // plus inverse, in caller-owned pools of one, four and eight workers.
    let mut group = criterion.benchmark_group("cantor_pool");
    let byte_field = TransformField::new(8).unwrap();
    let word_field = TransformField::new(16).unwrap();
    for threads in [1usize, 4, 8] {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap();
        for count in [32usize, 256] {
            let original: Vec<Vec<u8>> = (0..count)
                .map(|row| {
                    (0..65536)
                        .map(|at| ((row * 7919 + at * 103) % 256) as u8)
                        .collect()
                })
                .collect();
            let mut rows = original.clone();
            group.throughput(Throughput::Bytes((count * 65536 * 2) as u64));
            group.bench_function(
                BenchmarkId::new(format!("u8_{count}x65536"), format!("t{threads}")),
                |b| {
                    b.iter(|| {
                        for inverse in [false, true] {
                            byte_field
                                .transform_u8_in_pool(
                                    black_box(&mut rows),
                                    0,
                                    inverse,
                                    LinearBackend::Auto,
                                    &pool,
                                    &|| false,
                                )
                                .unwrap();
                        }
                    });
                },
            );
            assert_eq!(rows, original);
        }
        for count in [64usize, 512] {
            let original: Vec<Vec<u16>> = (0..count)
                .map(|row| {
                    (0..32768)
                        .map(|at| ((row * 7919 + at * 103) % 65536) as u16)
                        .collect()
                })
                .collect();
            let mut rows = original.clone();
            group.throughput(Throughput::Bytes((count * 65536 * 2) as u64));
            group.bench_function(
                BenchmarkId::new(format!("u16_{count}x32768"), format!("t{threads}")),
                |b| {
                    b.iter(|| {
                        for inverse in [false, true] {
                            word_field
                                .transform_in_pool(
                                    black_box(&mut rows),
                                    0,
                                    inverse,
                                    LinearBackend::Auto,
                                    &pool,
                                    &|| false,
                                )
                                .unwrap();
                        }
                    });
                },
            );
            assert_eq!(rows, original);
        }
    }
    group.finish();

    // A PAR3 decoder's inverse transform, one worker, dense and with the rows
    // the layout leaves zero flagged: unused recovery rows, losses and
    // padding past the inputs (capacity 32 with 150 inputs and 15 lost in a
    // 256-row GF(2^8) domain; capacity 64, 300 inputs, 30 lost in 512 rows).
    let mut group = criterion.benchmark_group("cantor_known_zero");
    let decoder = |domain: usize, capacity: usize, inputs: usize, lost: usize| -> Vec<bool> {
        (0..domain)
            .map(|row| {
                (lost..capacity).contains(&row)
                    || (capacity + 45..capacity + 45 + lost).contains(&row)
                    || row >= capacity + inputs
            })
            .collect()
    };
    let zero = decoder(256, 32, 150, 15);
    let mut bytes: Vec<Vec<u8>> = (0..256)
        .map(|row| {
            (0..65536)
                .map(|at| {
                    if zero[row] {
                        0
                    } else {
                        ((row * 7919 + at * 103) % 256) as u8
                    }
                })
                .collect()
        })
        .collect();
    group.throughput(Throughput::Bytes((256 * 65536) as u64));
    for known in [false, true] {
        let original = bytes.clone();
        group.bench_function(BenchmarkId::new("u8_256x65536", known), |b| {
            b.iter(|| {
                bytes.clone_from(&original);
                let rows = black_box(&mut bytes);
                if known {
                    byte_field.transform_u8_known_zero_with_backend(
                        rows,
                        &zero,
                        0,
                        true,
                        LinearBackend::Auto,
                        &|| false,
                    )
                } else {
                    byte_field.transform_u8_with_backend(
                        rows,
                        0,
                        true,
                        LinearBackend::Auto,
                        &|| false,
                    )
                }
                .unwrap();
            });
        });
    }
    let zero = decoder(512, 64, 300, 30);
    let mut words: Vec<Vec<u16>> = (0..512)
        .map(|row| {
            (0..32768)
                .map(|at| {
                    if zero[row] {
                        0
                    } else {
                        ((row * 7919 + at * 103) % 65536) as u16
                    }
                })
                .collect()
        })
        .collect();
    group.throughput(Throughput::Bytes((512 * 65536) as u64));
    for known in [false, true] {
        let original = words.clone();
        group.bench_function(BenchmarkId::new("u16_512x32768", known), |b| {
            b.iter(|| {
                words.clone_from(&original);
                let rows = black_box(&mut words);
                if known {
                    word_field.transform_known_zero_with_backend(
                        rows,
                        &zero,
                        0,
                        true,
                        LinearBackend::Auto,
                        &|| false,
                    )
                } else {
                    word_field.transform_with_backend(rows, 0, true, LinearBackend::Auto, &|| false)
                }
                .unwrap();
            });
        });
    }
    // Known-zero left halves in a radix-2 sweep: an odd stage count ends on
    // one, and with the low half of the rows zero every butterfly of that
    // last inverse stage only scales the right row into the left.
    for (count, width) in [(128usize, 65536usize), (512, 32768)] {
        let zero: Vec<bool> = (0..count).map(|row| row < count / 2).collect();
        let fill = |row: usize, at: usize| ((row * 7919 + at * 103) % 256) as u16;
        group.throughput(Throughput::Bytes((count * width) as u64));
        if count <= 256 {
            let original: Vec<Vec<u8>> = (0..count)
                .map(|row| {
                    (0..width)
                        .map(|at| if zero[row] { 0 } else { fill(row, at) as u8 })
                        .collect()
                })
                .collect();
            let mut rows = original.clone();
            group.bench_function(
                BenchmarkId::new(format!("u8_{count}x{width}_left_zero"), true),
                |b| {
                    b.iter(|| {
                        rows.clone_from(&original);
                        byte_field
                            .transform_u8_known_zero_with_backend(
                                black_box(&mut rows),
                                &zero,
                                0,
                                true,
                                LinearBackend::Auto,
                                &|| false,
                            )
                            .unwrap();
                    });
                },
            );
        } else {
            let original: Vec<Vec<u16>> = (0..count)
                .map(|row| {
                    (0..width)
                        .map(|at| if zero[row] { 0 } else { fill(row, at) * 251 })
                        .collect()
                })
                .collect();
            let mut rows = original.clone();
            group.bench_function(
                BenchmarkId::new(format!("u16_{count}x{width}_left_zero"), true),
                |b| {
                    b.iter(|| {
                        rows.clone_from(&original);
                        word_field
                            .transform_known_zero_with_backend(
                                black_box(&mut rows),
                                &zero,
                                0,
                                true,
                                LinearBackend::Auto,
                                &|| false,
                            )
                            .unwrap();
                    });
                },
            );
        }
    }
    group.finish();

    // Scaling one row in place, one worker: GF(2^8) byte rows, GF(2^16) word
    // rows, and 8-bit symbols on word rows (the one lane that validates).
    // Then a PAR3 decoder's front end, every received row scaled and the
    // known-zero inverse transform run on the result.
    let mut group = criterion.benchmark_group("cantor_scale");
    for width in [4096usize, 65536] {
        let mut bytes: Vec<u8> = (0..width).map(|at| (at * 103 % 251) as u8).collect();
        group.throughput(Throughput::Bytes(width as u64));
        group.bench_function(BenchmarkId::new("u8_gf8", width), |b| {
            b.iter(|| {
                byte_field
                    .scale_u8_with_backend(
                        black_box(&mut bytes),
                        0x53,
                        LinearBackend::Auto,
                        &|| false,
                    )
                    .unwrap();
            });
        });
        let mut words: Vec<u16> = (0..width / 2).map(|at| (at * 7919) as u16).collect();
        group.bench_function(BenchmarkId::new("u16_gf16", width), |b| {
            b.iter(|| {
                word_field
                    .scale_with_backend(black_box(&mut words), 0x1234, LinearBackend::Auto, &|| {
                        false
                    })
                    .unwrap();
            });
        });
        let mut narrow: Vec<u16> = (0..width / 2).map(|at| (at * 103 % 251) as u16).collect();
        group.bench_function(BenchmarkId::new("u16_gf8", width), |b| {
            b.iter(|| {
                byte_field
                    .scale_with_backend(black_box(&mut narrow), 0x53, LinearBackend::Auto, &|| {
                        false
                    })
                    .unwrap();
            });
        });
    }
    // A decoder's formal derivative over every row at the PAR3 stripe shapes.
    // The derivative applied twice is zero, so every iteration starts from a
    // fresh copy of the rows, made outside the timed routine.
    let bytes: Vec<Vec<u8>> = (0..256)
        .map(|row| {
            (0..65536)
                .map(|at| ((row * 7919 + at * 103) % 256) as u8)
                .collect()
        })
        .collect();
    group.throughput(Throughput::Bytes((256 * 65536) as u64));
    group.bench_function(BenchmarkId::new("u8_derivative", "256x65536"), |b| {
        b.iter_batched(
            || bytes.clone(),
            |mut rows| {
                byte_field
                    .derivative_u8(black_box(&mut rows), &|| false)
                    .unwrap();
                rows
            },
            BatchSize::LargeInput,
        );
    });
    let words: Vec<Vec<u16>> = (0..512)
        .map(|row| {
            (0..32768)
                .map(|at| ((row * 7919 + at * 103) % 65536) as u16)
                .collect()
        })
        .collect();
    group.throughput(Throughput::Bytes((512 * 65536) as u64));
    group.bench_function(BenchmarkId::new("u16_derivative", "512x32768"), |b| {
        b.iter_batched(
            || words.clone(),
            |mut rows| {
                word_field
                    .derivative(black_box(&mut rows), &|| false)
                    .unwrap();
                rows
            },
            BatchSize::LargeInput,
        );
    });
    let zero = decoder(256, 32, 150, 15);
    let factors: Vec<u16> = (0..256).map(|row| (row * 37 % 255 + 1) as u16).collect();
    let original: Vec<Vec<u8>> = (0..256)
        .map(|row| {
            (0..65536)
                .map(|at| {
                    if zero[row] {
                        0
                    } else {
                        ((row * 7919 + at * 103) % 256) as u8
                    }
                })
                .collect()
        })
        .collect();
    let mut bytes = original.clone();
    group.throughput(Throughput::Bytes((256 * 65536) as u64));
    group.bench_function(BenchmarkId::new("u8_decode_front", "256x65536"), |b| {
        b.iter(|| {
            bytes.clone_from(&original);
            let rows = black_box(&mut bytes);
            for (row, factor) in rows
                .iter_mut()
                .zip(&factors)
                .zip(&zero)
                .filter_map(|(pair, &zero)| (!zero).then_some(pair))
            {
                byte_field
                    .scale_u8_with_backend(row, *factor, LinearBackend::Auto, &|| false)
                    .unwrap();
            }
            byte_field
                .transform_u8_known_zero_with_backend(
                    rows,
                    &zero,
                    0,
                    true,
                    LinearBackend::Auto,
                    &|| false,
                )
                .unwrap();
        });
    });
    group.finish();
    criterion.final_summary();
}

#[cfg(target_family = "wasm")]
fn main() {}
