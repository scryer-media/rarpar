//! Microbenchmark: XOR-JIT vs shuffle2x multiply throughput on the "6 sources
//! into 1 destination" folded-group unit (the reconstruct primitive), on real
//! AVX2. Prepare/finish are done once (amortized as in streaming repair); only
//! the multiply is timed. Decides whether the XOR-JIT streaming wiring pays off
//! on pre-GFNI x86 before it is built (see scryer-docs/plans/125).
//!
//! Run on SYLIX: `cargo run --release --example xor_jit_micro`.

#[cfg(target_arch = "x86_64")]
fn main() {
    use std::time::Instant;
    use weaver_reed_solomon::gf_simd::{
        self, FOLDED_GROUP, Shuffle2xTables, precompute_shuffle2x_tables, split_encode_scatter,
    };
    use weaver_reed_solomon::xor_jit::{codegen, deps, memory::JitCode, transpose};

    if !std::is_x86_feature_detected!("avx2") {
        println!("AVX2 not available");
        return;
    }
    let gfni = std::is_x86_feature_detected!("gfni");
    println!(
        "avx2=yes gfni={} (XOR-JIT targets non-GFNI boxes)",
        if gfni { "yes" } else { "no" }
    );

    const L: usize = 64 * 1024; // per-source region bytes (multiple of 512 and 32)
    const GROUP: usize = FOLDED_GROUP; // 6 sources -> 1 dst
    const ITERS: usize = 4000;

    let factors: [u16; GROUP] = std::array::from_fn(|i| (0x2F1Du16).wrapping_mul(i as u16 + 3) | 1);

    // ---- shuffle2x setup: split-stage the 6 sources into one group stream ----
    let raw: Vec<Vec<u8>> = (0..GROUP)
        .map(|g| (0..L).map(|i| ((i * (g + 7) + 13) % 256) as u8).collect())
        .collect();
    let mut staging = vec![0u8; L * GROUP];
    for (lane, s) in raw.iter().enumerate() {
        split_encode_scatter(s, &mut staging, lane);
    }
    let tables: Vec<Shuffle2xTables> = factors
        .iter()
        .map(|&f| precompute_shuffle2x_tables(f))
        .collect();
    let table_refs: [&Shuffle2xTables; GROUP] = std::array::from_fn(|i| &tables[i]);
    let staging_slices: [&[u8]; 1] = [&staging];
    let table_sets = [table_refs];
    let mut sh_dst = vec![0u8; L]; // split-layout dst

    let t = Instant::now();
    for _ in 0..ITERS {
        gf_simd::mul_acc_shuffle2x_batch(&mut sh_dst, &staging_slices, &table_sets);
    }
    let sh = t.elapsed();

    // ---- XOR-JIT setup: prepare 6 planar sources + JIT one code per factor ----
    let mut planar: Vec<Vec<u8>> = raw
        .iter()
        .map(|s| {
            let mut p = vec![0u8; L];
            for blk in 0..(L / 512) {
                let src: &[u8; 512] = s[blk * 512..blk * 512 + 512].try_into().unwrap();
                let dst: &mut [u8; 512] = (&mut p[blk * 512..blk * 512 + 512]).try_into().unwrap();
                unsafe { transpose::prepare_block(src, dst) };
            }
            p
        })
        .collect();
    let _ = &mut planar;
    let codes: Vec<JitCode> = factors
        .iter()
        .map(|&f| JitCode::new(&codegen::generate_muladd(&deps::compute_deps(f))).unwrap())
        .collect();
    let mut xj_dst = vec![0u8; L]; // planar dst

    let t = Instant::now();
    for _ in 0..ITERS {
        for (code, src) in codes.iter().zip(planar.iter()) {
            unsafe { code.run_muladd(src.as_ptr(), xj_dst.as_mut_ptr(), L) };
        }
    }
    let xj = t.elapsed();

    // Both process GROUP*L source-bytes per iter.
    let src_bytes = (GROUP * L * ITERS) as f64;
    let sh_gbs = src_bytes / sh.as_secs_f64() / 1e9;
    let xj_gbs = src_bytes / xj.as_secs_f64() / 1e9;
    println!("shuffle2x: {sh_gbs:6.2} GB/s   ({sh:?})");
    println!("XOR-JIT:   {xj_gbs:6.2} GB/s   ({xj:?})");
    println!("XOR-JIT / shuffle2x = {:.2}x", xj_gbs / sh_gbs);
    // Codegen size (per-factor JIT footprint).
    println!(
        "jit code bytes/factor = {}",
        codegen::generate_muladd(&deps::compute_deps(factors[1])).len()
    );
}

#[cfg(not(target_arch = "x86_64"))]
fn main() {
    println!("x86_64 only");
}
