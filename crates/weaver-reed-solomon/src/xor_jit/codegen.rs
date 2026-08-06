//! Dependency-matrix wrappers for the AVX2 XOR-JIT emitter.
//!
//! These entry points accept a canonical multiplication matrix, validate it,
//! recover its coefficient, and delegate to the coefficient-based emitter.

use super::{avx2_emitter, deps, deps::XorDeps};

/// Generate the normal AVX2 MULADD body for a canonical dependency matrix.
pub fn generate_muladd(input: &XorDeps) -> Vec<u8> {
    generate_muladd_with_prefetch(input, false)
}

/// Generate either the normal or dedicated-prefetch AVX2 MULADD body for a
/// canonical dependency matrix.
pub fn generate_muladd_with_prefetch(input: &XorDeps, prefetch: bool) -> Vec<u8> {
    let factor = factor_from_canonical_deps(input);
    let mut body = Vec::with_capacity(avx2_emitter::MAX_BODY_BYTES);
    avx2_emitter::append_muladd_body(&mut body, factor, prefetch)
        .expect("AVX2 body fits its fixed size bound");
    body
}

fn factor_from_canonical_deps(input: &XorDeps) -> u16 {
    let mut factor = 0u16;
    for (output_plane, &row) in input.rows.iter().enumerate() {
        factor |= ((row >> 15) & 1) << (15 - output_plane);
    }
    assert_eq!(
        input.rows,
        deps::compute_deps(factor).rows,
        "AVX2 XOR-JIT requires a canonical multiplication dependency matrix"
    );
    factor
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compatibility_wrapper_matches_coefficient_writer() {
        for factor in [0, 1, 2, 0x1234, 0xa53c, 0xffff] {
            let input = deps::compute_deps(factor);
            for prefetch in [false, true] {
                let actual = generate_muladd_with_prefetch(&input, prefetch);
                let mut expected = Vec::new();
                avx2_emitter::append_muladd_body(&mut expected, factor, prefetch).unwrap();
                assert_eq!(actual, expected);
            }
        }
    }

    #[test]
    #[should_panic(expected = "canonical multiplication dependency matrix")]
    fn compatibility_wrapper_rejects_noncanonical_dependencies() {
        let mut input = deps::compute_deps(0x1234);
        input.rows[0] ^= 1;
        let _ = generate_muladd(&input);
    }
}
