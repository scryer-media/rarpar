use super::*;

fn available() -> Vec<Backend> {
    let mut result = vec![Backend::Portable];
    if is_x86_feature_detected!("sse2") {
        result.push(Backend::Sse2);
    }
    if is_x86_feature_detected!("ssse3") {
        result.push(Backend::Ssse3);
    }
    if is_x86_feature_detected!("sse4.1") || is_x86_feature_detected!("avx2") {
        result.push(Backend::Upstream);
    }
    #[cfg(target_arch = "x86_64")]
    if avx512vl_available() {
        result.push(Backend::Avx512Vl);
    }
    eprintln!("exercising x86 hash backends: {result:?}");
    result
}

#[test]
fn ladder_requires_every_feature() {
    assert_eq!(
        Backend::select(false, false, false, false),
        Backend::Portable
    );
    assert_eq!(Backend::select(true, false, false, false), Backend::Sse2);
    assert_eq!(Backend::select(true, true, false, false), Backend::Ssse3);
    assert_eq!(Backend::select(true, true, true, false), Backend::Upstream);
    assert_eq!(Backend::select(true, true, true, true), Backend::Upstream);
}

#[test]
fn all_supported_backends_match_oracle_across_tails_and_chunks() {
    let data: Vec<_> = (0..18000)
        .map(|i| ((i * 157 + i / 13) % 256) as u8)
        .collect();
    for backend in available() {
        for len in (0..1100).chain([4095, 4096, 4097, 8192, 16383, 18000]) {
            let expected = *blake2s_simd::blake2sp::blake2sp(&data[..len]).as_array();
            for chunk in [1, 63, 64, 65, 511, 512, 513, 4096, 18000] {
                let mut state = State::with_backend(backend);
                for part in data[..len].chunks(chunk) {
                    state.update(part);
                }
                assert_eq!(
                    state.finalize(),
                    expected,
                    "{backend:?} len={len} chunk={chunk}"
                );
                assert_eq!(
                    state.finalize(),
                    expected,
                    "finalization must be idempotent"
                );
                if let Hasher::Local(state) = &state.0 {
                    assert!(state.len < 961);
                }
            }
        }
    }
}

#[test]
fn vector_counters_flags_and_unaligned_messages_match_scalar() {
    let data: Vec<_> = (0..513).map(|i| (i * 31) as u8).collect();
    let b: &[u8; 512] = data[1..].try_into().unwrap();
    let counts = [
        0,
        1,
        63,
        64,
        u32::MAX as u64,
        1 << 32,
        (1 << 32) + 64,
        u64::MAX,
    ];
    let f0 = [0, !0, 0, !0, 0, !0, 0, !0];
    let f1 = [!0, 0, 0, 0, 0, 0, 0, !0];
    let mut oracle = LocalState::new(Backend::Portable);
    Backend::Portable.compress(&mut oracle.h, b, counts, f0, f1);
    for backend in available().into_iter().filter(|b| *b != Backend::Upstream) {
        let mut state = LocalState::new(backend);
        backend.compress(&mut state.h, b, counts, f0, f1);
        assert_eq!(state.h, oracle.h, "{backend:?}");
    }
}

#[test]
fn batched_counters_match_scalar_across_word_carry_and_wrap() {
    let blocks = std::array::from_fn::<_, 3, _>(|block| {
        std::array::from_fn(|byte| (block * 53 + byte * 31 + byte / 19) as u8)
    });
    for start in [(1 << 32) - 128, u64::MAX - 127] {
        let mut oracle = LocalState::new(Backend::Portable);
        oracle.count = start;
        oracle.compress_nonfinal(&blocks);
        for backend in available().into_iter().filter(|b| *b != Backend::Upstream) {
            let mut state = LocalState::new(backend);
            state.count = start;
            state.compress_nonfinal(&blocks);
            assert_eq!(state.h, oracle.h, "{backend:?} at {start}");
            assert_eq!(state.count, start.wrapping_add(3 * 64));
        }
    }
}

#[test]
fn runtime_dispatch_prefers_avx512vl_then_upstream() {
    let state = State::new();
    #[cfg(target_arch = "x86_64")]
    if avx512vl_available() {
        assert!(matches!(state.0, Hasher::Local(state) if state.backend == Backend::Avx512Vl));
        return;
    }
    assert_eq!(
        matches!(state.0, Hasher::Upstream(_)),
        is_x86_feature_detected!("sse4.1") || is_x86_feature_detected!("avx2")
    );
}
