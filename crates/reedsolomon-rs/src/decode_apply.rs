//! Apply a dense erasure-decode matrix to equal-length regions.
//!
//! An erasure decoder for a fixed set of missing positions is a linear map:
//! each restored region is a sum of every present region times one field
//! coefficient. [`apply_decode_matrix_gf8`] and [`apply_decode_matrix_gf16`]
//! run that map with the grouped-input kernels ([`gf8::mul_acc_input_batch`],
//! [`gf_simd::mul_acc_input_batch_prepared`]) over stripes of the regions, one
//! rayon task per (output row, stripe). Each task owns its slice of one output,
//! so the threads never share a destination, and a stripe is small enough that
//! a group of sources plus the destination strip stay in L2.
//!
//! Both RAR recovery eras use this driver: RAR3 with the matrix
//! [`Rar3RsCoder::decode_matrix`](crate::rar3::Rar3RsCoder::decode_matrix)
//! derives, RAR5 with the inverted Cauchy rows of
//! [`Rar5RsCoder`](crate::rar5::Rar5RsCoder). The result depends only on the
//! matrix and the inputs, never on the stripe size, the thread count or the
//! kernel tier.

use rayon::prelude::*;

use crate::{gf_simd, gf8, threading};

/// Smallest stripe a task is given. Below this the per-task setup (grouping
/// the sources, one rayon hand-off) starts to show against the multiply.
const MIN_STRIPE: usize = 16 * 1024;
/// Largest stripe: eight sources of this size plus the destination strip sit
/// well inside a 2 MiB L2.
const MAX_STRIPE: usize = 256 * 1024;
/// Sources handed to one kernel call when the host kernel reports no
/// grouping of its own; the call then folds them one by one.
const FALLBACK_GROUP: usize = 8;

/// Stripe length for `len`-byte regions and `rows` outputs: small enough that
/// every worker gets several tasks, within [`MIN_STRIPE`, `MAX_STRIPE`], and
/// a multiple of 64 so each stripe starts on a vector boundary of the region.
fn stripe_len(len: usize, rows: usize) -> usize {
    let threads = if threading::parallel_enabled() {
        rayon::current_num_threads().max(1)
    } else {
        1
    };
    let wanted_tasks = threads * 4;
    let stripes_per_row = wanted_tasks.div_ceil(rows.max(1)).max(1);
    let stripe = len.div_ceil(stripes_per_row);
    stripe.clamp(MIN_STRIPE, MAX_STRIPE).next_multiple_of(64)
}

/// Check the shapes shared by both fields and return the region length.
fn check_shape(coefficients: usize, inputs: &[&[u8]], outputs: &[&mut [u8]]) -> Option<usize> {
    assert_eq!(
        coefficients,
        outputs.len() * inputs.len(),
        "the matrix must have one row per output and one column per input"
    );
    let len = outputs.first().map(|out| out.len())?;
    for out in outputs {
        assert_eq!(out.len(), len, "every output must have the same length");
    }
    for input in inputs {
        assert_eq!(input.len(), len, "every input must match the outputs");
    }
    Some(len)
}

/// Run `task` for every (output row, stripe) pair, in parallel where the
/// build can.
fn for_each_stripe<F>(outputs: &mut [&mut [u8]], stripe: usize, task: F)
where
    F: Fn(usize, usize, &mut [u8]) + Sync + Send,
{
    let mut jobs = Vec::new();
    for (row, out) in outputs.iter_mut().enumerate() {
        for (index, chunk) in out.chunks_mut(stripe).enumerate() {
            jobs.push((row, index * stripe, chunk));
        }
    }
    if threading::parallel_enabled() && jobs.len() > 1 {
        jobs.into_par_iter()
            .for_each(|(row, start, chunk)| task(row, start, chunk));
    } else {
        for (row, start, chunk) in jobs {
            task(row, start, chunk);
        }
    }
}

/// `outputs[r] = Σ_j matrix[r * inputs.len() + j] · inputs[j]` over GF(2⁸)
/// with polynomial `0x11D`, overwriting each output.
///
/// `matrix` is row-major, one row per output and one column per input. Every
/// input and output must have the same length. Zero coefficients are skipped,
/// so an input whose column is all zero is never read.
pub fn apply_decode_matrix_gf8(matrix: &[u8], inputs: &[&[u8]], outputs: &mut [&mut [u8]]) {
    let Some(len) = check_shape(matrix.len(), inputs, outputs) else {
        return;
    };
    if len == 0 {
        return;
    }
    let columns = inputs.len();
    let group = match gf8::input_batch_width() {
        1 => FALLBACK_GROUP,
        width => width,
    };
    let stripe = stripe_len(len, outputs.len());
    for_each_stripe(outputs, stripe, |row, start, dst| {
        dst.fill(0);
        let end = start + dst.len();
        let coefficients = &matrix[row * columns..(row + 1) * columns];
        let mut batch: Vec<gf8::PlanSrc<'_>> = Vec::with_capacity(group);
        for (&factor, input) in coefficients.iter().zip(inputs) {
            if factor == 0 {
                continue;
            }
            batch.push(gf8::PlanSrc {
                plan: gf8::MulPlan::cached(factor),
                src: &input[start..end],
            });
            if batch.len() == group {
                gf8::mul_acc_input_batch(dst, &batch);
                batch.clear();
            }
        }
        if !batch.is_empty() {
            gf8::mul_acc_input_batch(dst, &batch);
        }
    });
}

/// `outputs[r] = Σ_j matrix[r * inputs.len() + j] · inputs[j]` over GF(2¹⁶)
/// (the [`gf`](crate::gf) field, polynomial `0x1100B`), overwriting each
/// output. Regions are little-endian 16-bit words, so their length must be
/// even.
///
/// `matrix` is row-major, one row per output and one column per input. Every
/// input and output must have the same length. Zero coefficients are skipped,
/// so an input whose column is all zero is never read.
pub fn apply_decode_matrix_gf16(matrix: &[u16], inputs: &[&[u8]], outputs: &mut [&mut [u8]]) {
    let Some(len) = check_shape(matrix.len(), inputs, outputs) else {
        return;
    };
    assert!(
        len.is_multiple_of(2),
        "GF(2^16) regions must have even length"
    );
    if len == 0 {
        return;
    }
    let columns = inputs.len();
    let group = match gf_simd::input_batch_width() {
        1 => FALLBACK_GROUP,
        width => width,
    };
    // Prepared once per matrix entry, not once per stripe: on x86 a
    // preparation is a table or affine-matrix build.
    let prepared = matrix
        .iter()
        .map(|&factor| gf_simd::prepare_input_factor(factor))
        .collect::<Vec<_>>();
    let stripe = stripe_len(len, outputs.len());
    for_each_stripe(outputs, stripe, |row, start, dst| {
        dst.fill(0);
        let end = start + dst.len();
        let row_matrix = &matrix[row * columns..(row + 1) * columns];
        let row_prepared = &prepared[row * columns..(row + 1) * columns];
        let mut batch: Vec<gf_simd::PreparedFactorSrc<'_>> = Vec::with_capacity(group);
        for ((&factor, prepared), input) in row_matrix.iter().zip(row_prepared).zip(inputs) {
            if factor == 0 {
                continue;
            }
            batch.push(gf_simd::PreparedFactorSrc {
                prepared,
                src: &input[start..end],
            });
            if batch.len() == group {
                gf_simd::mul_acc_input_batch_prepared(dst, &batch);
                batch.clear();
            }
        }
        if !batch.is_empty() {
            gf_simd::mul_acc_input_batch_prepared(dst, &batch);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gf;

    fn pseudo_random(len: usize, seed: u64) -> Vec<u8> {
        let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect()
    }

    fn check_gf8(rows: usize, columns: usize, len: usize) {
        let inputs = (0..columns)
            .map(|c| pseudo_random(len, 11 + c as u64))
            .collect::<Vec<_>>();
        let mut matrix = pseudo_random(rows * columns, 7);
        // Some zero and identity coefficients, which take their own paths.
        for (index, value) in matrix.iter_mut().enumerate() {
            match index % 9 {
                2 => *value = 0,
                5 => *value = 1,
                _ => {}
            }
        }
        let input_refs = inputs.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let mut outputs = vec![vec![0xA5u8; len]; rows];
        let mut output_refs = outputs
            .iter_mut()
            .map(Vec::as_mut_slice)
            .collect::<Vec<_>>();
        apply_decode_matrix_gf8(&matrix, &input_refs, &mut output_refs);
        for (row, output) in outputs.iter().enumerate() {
            for pos in 0..len {
                let expected = (0..columns).fold(0u8, |acc, c| {
                    acc ^ gf8::mul(matrix[row * columns + c], inputs[c][pos])
                });
                assert_eq!(output[pos], expected, "row {row} byte {pos}");
            }
        }
    }

    fn check_gf16(rows: usize, columns: usize, len: usize) {
        let inputs = (0..columns)
            .map(|c| pseudo_random(len, 101 + c as u64))
            .collect::<Vec<_>>();
        let mut matrix = pseudo_random(rows * columns * 2, 3)
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        for (index, value) in matrix.iter_mut().enumerate() {
            match index % 7 {
                1 => *value = 0,
                4 => *value = 1,
                _ => {}
            }
        }
        let input_refs = inputs.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let mut outputs = vec![vec![0x5Au8; len]; rows];
        let mut output_refs = outputs
            .iter_mut()
            .map(Vec::as_mut_slice)
            .collect::<Vec<_>>();
        apply_decode_matrix_gf16(&matrix, &input_refs, &mut output_refs);
        for (row, output) in outputs.iter().enumerate() {
            for word in 0..len / 2 {
                let expected = (0..columns).fold(0u16, |acc, c| {
                    let value = u16::from_le_bytes([inputs[c][2 * word], inputs[c][2 * word + 1]]);
                    acc ^ gf::mul(matrix[row * columns + c], value)
                });
                let actual = u16::from_le_bytes([output[2 * word], output[2 * word + 1]]);
                assert_eq!(actual, expected, "row {row} word {word}");
            }
        }
    }

    #[test]
    fn gf8_matches_scalar_sum_across_shapes() {
        // Odd lengths, lengths under one stripe, several stripes, more
        // columns than a kernel group, a single column.
        for (rows, columns, len) in [
            (1, 1, 1),
            (1, 5, 333),
            (3, 17, 70_001),
            (8, 41, 300_007),
            (2, 255, 4_099),
        ] {
            check_gf8(rows, columns, len);
        }
    }

    #[test]
    fn gf16_matches_scalar_sum_across_shapes() {
        for (rows, columns, len) in [
            (1, 1, 2),
            (1, 5, 334),
            (3, 17, 70_002),
            (8, 41, 300_008),
            (2, 100, 4_100),
        ] {
            check_gf16(rows, columns, len);
        }
    }

    #[test]
    fn no_outputs_is_a_no_op() {
        let input = vec![1u8; 8];
        apply_decode_matrix_gf8(&[], &[&input], &mut []);
        apply_decode_matrix_gf16(&[], &[&input], &mut []);
    }
}
