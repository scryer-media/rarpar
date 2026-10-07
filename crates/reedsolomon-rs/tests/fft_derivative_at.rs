use reedsolomon_rs::fft::{TransformField, derivative_at_walks};
use reedsolomon_rs::gf_simd::LinearBackend;

fn next(seed: &mut u64) -> u64 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed
}

/// Rows of random symbols below `order`, those flagged in `zero` cleared,
/// with the flags: every third row from `skip`, and a run at the end.
fn bank(n: usize, width: usize, order: usize, seed: u64) -> (Vec<Vec<u16>>, Vec<bool>) {
    let mut seed = seed | 1;
    let zero: Vec<bool> = (0..n).map(|row| row % 3 == 1 || row >= n - n / 5).collect();
    let rows = (0..n)
        .map(|row| {
            (0..width)
                .map(|_| {
                    let value = (next(&mut seed) % order as u64) as u16;
                    if zero[row] { 0 } else { value }
                })
                .collect()
        })
        .collect();
    (rows, zero)
}

/// The rows `at` that inverse transform, derivative and forward transform
/// leave, one step after another.
fn separate(
    field: &TransformField,
    rows: &[Vec<u16>],
    zero: &[bool],
    at: &[usize],
    backend: LinearBackend,
) -> Vec<Vec<u16>> {
    let mut rows = rows.to_vec();
    let none = || false;
    field
        .transform_known_zero_with_backend(&mut rows, zero, 0, true, backend, &none)
        .unwrap();
    field.derivative(&mut rows, &none).unwrap();
    field
        .transform_with_backend(&mut rows, 0, false, backend, &none)
        .unwrap();
    at.iter().map(|&row| rows[row].clone()).collect()
}

fn check(bits: u32, n: usize, width: usize, at: &[usize], threads: &[usize]) {
    let field = TransformField::new(bits).unwrap();
    let (rows, zero) = bank(n, width, field.order(), (n * 31 + width) as u64);
    for backend in [LinearBackend::Scalar, LinearBackend::Auto] {
        let expected = separate(&field, &rows, &zero, at, backend);
        for &workers in threads {
            for flags in [None, Some(zero.as_slice())] {
                let run = |pool: Option<&rayon::ThreadPool>| {
                    let mut out = vec![vec![0u16; width]; at.len()];
                    if bits == 8 {
                        let mut bytes: Vec<Vec<u8>> = rows
                            .iter()
                            .map(|row| row.iter().map(|&v| v as u8).collect())
                            .collect();
                        let mut out8 = vec![vec![0u8; width]; at.len()];
                        field
                            .derivative_u8_at(
                                &mut bytes,
                                flags,
                                at,
                                &mut out8,
                                backend,
                                pool,
                                &|| false,
                            )
                            .unwrap();
                        for (out, out8) in out.iter_mut().zip(out8) {
                            *out = out8.into_iter().map(u16::from).collect();
                        }
                    } else {
                        let mut rows = rows.clone();
                        field
                            .derivative_at(&mut rows, flags, at, &mut out, backend, pool, &|| false)
                            .unwrap();
                    }
                    out
                };
                let out = if workers == 0 {
                    run(None)
                } else {
                    let pool = rayon::ThreadPoolBuilder::new()
                        .num_threads(workers)
                        .build()
                        .unwrap();
                    run(Some(&pool))
                };
                assert_eq!(
                    out,
                    expected,
                    "bits {bits} n {n} width {width} {backend:?} workers {workers} flags {}",
                    flags.is_some()
                );
            }
        }
    }
}

#[test]
fn derivative_at_matches_the_separate_steps() {
    // Even and odd levels, so blocks and classes may differ; widths below
    // one window, between windows and of several; rows read in one block,
    // spread, and at the edges.
    for (bits, n, width, at) in [
        (16, 16, 70, vec![0, 15]),
        (16, 32, 5, vec![3, 4, 5, 31]),
        (16, 128, 200, vec![1, 64, 65, 66, 127]),
        (16, 512, 1000, vec![7, 300, 301, 511]),
        (16, 2048, 320, vec![0, 1, 2, 1000, 2047]),
        (8, 128, 130, vec![5, 6, 100]),
        (8, 256, 600, vec![0, 128, 255]),
        (16, 8, 70, vec![1, 7]),
        (16, 64, 129, vec![]),
        // Several windows, the last one short.
        (16, 2048, 5000, vec![2, 33, 34, 1500, 2046]),
        (8, 256, 40000, vec![17, 18, 250]),
    ] {
        check(bits, n, width, &at, &[0, 1, 3, 8]);
    }
}

#[test]
fn derivative_at_matches_the_separate_steps_for_every_read_pattern() {
    // Every row but one, every row, one row in each block, and one whole
    // block, at odd and even levels, on worker counts that do and do not
    // divide the groups or the windows.
    for (bits, n, block) in [(16, 256, 16), (16, 512, 16), (8, 128, 8)] {
        let patterns: [Vec<usize>; 4] = [
            (0..n).filter(|&row| row != n / 3).collect(),
            (0..n).collect(),
            (0..n).step_by(block).map(|row| row + 3).collect(),
            (2 * block..3 * block).collect(),
        ];
        for at in patterns {
            check(bits, n, 300, &at, &[0, 2, 4, 5, 6, 7]);
        }
    }
}

#[test]
fn derivative_at_bytes_and_walks_refuse_other_symbol_sizes() {
    let field = TransformField::new(16).unwrap();
    for size in [0, 3, 4, usize::MAX] {
        assert!(!derivative_at_walks(2048, 4096, size));
        assert_eq!(
            field.derivative_at_bytes(2048, 4096, size, LinearBackend::Auto, 8),
            0
        );
    }
    // Extreme shapes saturate rather than overflow.
    assert!(derivative_at_walks(1 << 20, usize::MAX, 2));
    assert!(field.derivative_at_bytes(1 << 20, usize::MAX, 2, LinearBackend::Auto, usize::MAX) > 0);
}

#[test]
fn derivative_at_rejects_unsorted_rows() {
    let field = TransformField::new(16).unwrap();
    let mut rows = vec![vec![0u16; 8]; 16];
    let mut out = vec![vec![0u16; 8]; 2];
    let none = || false;
    for at in [[3usize, 2], [4, 4], [1, 16]] {
        assert!(
            field
                .derivative_at(
                    &mut rows,
                    None,
                    &at,
                    &mut out,
                    LinearBackend::Auto,
                    None,
                    &none
                )
                .is_err()
        );
    }
}

#[test]
fn derivative_at_walks_only_banks_beyond_the_scratch() {
    assert!(!derivative_at_walks(8, 1 << 20, 2));
    assert!(!derivative_at_walks(2048, 64, 2));
    assert!(derivative_at_walks(2048, 4096, 2));
    assert!(derivative_at_walks(65536, 14336, 2));
}
