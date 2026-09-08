//! Native, one-worker comparisons of Cantor transforms with equal input buffers.
//! These arithmetic measurements do not establish end-to-end PAR3 parity.
#[cfg(not(target_family = "wasm"))]
fn main() {
    use criterion::{BenchmarkId, Criterion, Throughput};
    use reedsolomon_rs::fft::TransformField;
    use reedsolomon_rs::gf_simd::LinearBackend;
    use std::hint::black_box;

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
    criterion.final_summary();
}

#[cfg(target_family = "wasm")]
fn main() {}
