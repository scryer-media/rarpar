use reedsolomon_rs::fft::TransformField;
use reedsolomon_rs::gf_simd::{LinearBackend, LinearKernel, LinearMap16};

#[test]
fn cantor_maps_match_field_products_for_all_symbols_and_vector_tails() {
    assert_eq!(LinearBackend::Scalar.kernel(), LinearKernel::Scalar);
    for bits in [8, 16] {
        let field = TransformField::new(bits).unwrap();
        let factors: Vec<u16> = if bits == 8 {
            (0..256).collect()
        } else {
            vec![0, 1, 2, 15, 16, 255, 256, 0xacca, 0x8000, 0xffff]
        };
        let source: Vec<u16> = (0..=field.order())
            .map(|at| (at % field.order()) as u16)
            .collect();
        for factor in factors {
            let basis = std::array::from_fn(|bit| {
                if bit < bits as usize {
                    field.mul(1 << bit, factor)
                } else {
                    0
                }
            });
            for backend in [LinearBackend::Auto, LinearBackend::Scalar] {
                let map = LinearMap16::new(basis, backend);
                for length in [
                    0,
                    1,
                    15,
                    16,
                    17,
                    31,
                    32,
                    33,
                    field.order() - 1,
                    field.order(),
                ] {
                    let input = &source[1..1 + length];
                    let mut output = vec![0xace1; length + 2];
                    map.accumulate(input, &mut output[1..1 + length]);
                    assert_eq!(output[0], 0xace1);
                    assert_eq!(output[length + 1], 0xace1);
                    for (actual, symbol) in output[1..1 + length].iter().zip(input) {
                        assert_eq!(
                            *actual,
                            0xace1 ^ field.mul(*symbol, factor),
                            "bits {bits}, factor {factor}, length {length}, backend {backend:?}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn arbitrary_binary_map_has_no_implicit_field_polynomial() {
    let basis = std::array::from_fn(|bit| (1u16 << bit).rotate_left(7) ^ 0x87);
    let map = LinearMap16::new(basis, LinearBackend::Auto);
    let source: Vec<u16> = (0..=u16::MAX).collect();
    let mut output = vec![0; source.len()];
    map.accumulate(&source, &mut output);
    for (symbol, actual) in source.iter().zip(output) {
        let expected = basis
            .iter()
            .enumerate()
            .filter(|(bit, _)| *symbol & (1 << bit) != 0)
            .fold(0, |sum, (_, image)| sum ^ image);
        assert_eq!(actual, expected);
    }
}
