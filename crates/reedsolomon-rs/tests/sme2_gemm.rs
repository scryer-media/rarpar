//! The SME2 `BMOPA` matrix-product kernels of the `kernel_ceiling` lane
//! against the scalar oracle. Skipped where the host has no SME2.

#![cfg(target_arch = "aarch64")]

#[path = "../benches/support/sme2_gemm.rs"]
mod sme2_gemm;

use sme2_gemm::{CHUNK, Plan, oracle8, oracle16, sme2_available};

fn bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect()
}

/// Factors with 0 and 1 in every row, the rest pseudo-random.
fn factors(rows: usize, sources: usize, seed: u64) -> Vec<Vec<u16>> {
    let noise = bytes(seed, 2 * rows * sources);
    (0..rows)
        .map(|r| {
            (0..sources)
                .map(|s| match (r + s) % 5 {
                    0 => 0,
                    1 => 1,
                    _ => u16::from_le_bytes([
                        noise[2 * (r * sources + s)],
                        noise[2 * (r * sources + s) + 1],
                    ]),
                })
                .collect()
        })
        .collect()
}

#[test]
fn gf8_products_match_the_oracle() {
    if !sme2_available() {
        return;
    }
    // Odd row counts leave a half-empty block; source counts off the
    // four-per-lane packing leave padded slots; the range starts and ends
    // inside the buffers.
    for (sources, rows) in [
        (1, 1),
        (3, 1),
        (5, 2),
        (16, 3),
        (16, 32),
        (17, 33),
        (64, 103),
    ] {
        let len = 6 * CHUNK;
        let srcs: Vec<Vec<u8>> = (0..sources).map(|s| bytes(s as u64 + 1, len)).collect();
        let views: Vec<&[u8]> = srcs.iter().map(Vec::as_slice).collect();
        let coef: Vec<Vec<u8>> = factors(rows, sources, 41)
            .into_iter()
            .map(|row| row.into_iter().map(|f| f as u8).collect())
            .collect();
        let start: Vec<Vec<u8>> = (0..rows).map(|r| bytes(r as u64 + 1000, len)).collect();
        let (from, count) = (CHUNK, 4 * CHUNK);
        let mut want = start.clone();
        let window: Vec<&[u8]> = views.iter().map(|s| &s[from..from + count]).collect();
        let mut part: Vec<Vec<u8>> = want
            .iter()
            .map(|r| r[from..from + count].to_vec())
            .collect();
        oracle8(&coef, &window, &mut part);
        for (row, part) in want.iter_mut().zip(&part) {
            row[from..from + count].copy_from_slice(part);
        }
        let mut got = start;
        let mut rows_out: Vec<&mut [u8]> = got.iter_mut().map(Vec::as_mut_slice).collect();
        Plan::gf8(&coef).apply(&views, &mut rows_out, from, count, &mut Vec::new());
        assert_eq!(got, want, "{sources} sources, {rows} rows");
    }
}

#[test]
fn gf16_products_match_the_oracle() {
    if !sme2_available() {
        return;
    }
    // Twenty rows cross the row-block count where the column correction
    // switches from all-ones outer products to counting the packed input.
    for (sources, rows) in [(1, 1), (3, 2), (12, 10), (17, 20), (101, 3)] {
        let len = 2 * 4 * CHUNK;
        let srcs: Vec<Vec<u8>> = (0..sources).map(|s| bytes(s as u64 + 7, len)).collect();
        let views: Vec<&[u8]> = srcs.iter().map(Vec::as_slice).collect();
        let coef = factors(rows, sources, 43);
        let mut want: Vec<Vec<u8>> = (0..rows).map(|r| bytes(r as u64 + 2000, len)).collect();
        let mut got = want.clone();
        oracle16(&coef, &views, &mut want);
        let mut rows_out: Vec<&mut [u8]> = got.iter_mut().map(Vec::as_mut_slice).collect();
        Plan::gf16(&coef).apply(&views, &mut rows_out, 0, len / 2, &mut Vec::new());
        assert_eq!(got, want, "{sources} sources, {rows} rows");
    }
}

#[test]
fn probes_run() {
    if !sme2_available() {
        return;
    }
    // SAFETY: SME2 is present.
    unsafe {
        sme2_gemm::mode_switch(4);
        sme2_gemm::bmopa_loop(4);
    }
}
