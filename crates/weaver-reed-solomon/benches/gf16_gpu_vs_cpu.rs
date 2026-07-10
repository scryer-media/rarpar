//! GPU (wgpu) vs CPU GF(2^16) mul-acc throughput over identical work.
//!
//! The `gf_kernel` group in weaver-par2's `par2_repair.rs` calls the CPU kernels
//! directly and can never engage the GPU arm; `repairer_repair_workflow` engages
//! it but is dominated by staging I/O and MD5, so a GPU delta drowns there. This
//! bench isolates the one computation both arms actually perform:
//! `dst[j] ^= factor(j, s) * src[s]` for every output `j` and source `s`.
//!
//! It lives in this crate rather than weaver-par2 because it only exercises
//! `gf_simd` + `wgpu_gf16`, while weaver-par2's dev-dependencies drag in
//! `aws-lc-sys` (cmake + NASM), absent on some GPU test hosts.
//!
//! Whether the arm is worth engaging is a property of the HOST, so read the
//! numbers per machine: an integrated GPU sharing DDR with a GFNI-capable CPU
//! loses to a single core, whereas a discrete card with its own VRAM facing a
//! CPU without GFNI is the shape this arm was built for.
//!
//! Fairness notes, because the two numbers are NOT symmetric:
//! - The GPU timing includes the full per-chunk round trip — source upload,
//!   factor-table upload, dispatch, and the staging readback — which is what a
//!   real repair pays. The CPU timing is pure compute on resident buffers, with
//!   no copies at all. The asymmetry favors the CPU.
//! - `cpu_serial` is single-threaded kernel throughput (the GFNI affine kernel
//!   where available, else shuffle/xor-jit). `cpu_rayon` spreads outputs across
//!   cores, which is what the repair path really does, and is the honest number
//!   to compare the GPU against.
//! - Factors are all >= 2, so every lane exercises a real GF multiply rather
//!   than the `factor == 1` plain-XOR shortcut.
//!
//! Run: `cargo bench -p weaver-reed-solomon --features wgpu --bench gf16_gpu_vs_cpu`
//! Pick a backend with `WGPU_BACKEND=vulkan|dx12|metal`; on Linux pin a specific
//! Vulkan device with `VK_DRIVER_FILES=<icd.json>` (e.g. to keep wgpu off the
//! llvmpipe software rasterizer, whose numbers mean nothing).

use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use rayon::prelude::*;
use weaver_reed_solomon::gf_simd::{FactorSrc, mul_acc_input_batch};
use weaver_reed_solomon::wgpu_gf16::WgpuGf16Session;

/// Recovery rows computed per pass (a typical repair fan-out).
const OUTPUTS: usize = 16;
/// Source slices folded per pass; stays under the shader's `MAX_SOURCES` (66).
const SOURCES: usize = 32;

/// Deterministic factors, always >= 2 so no lane takes the XOR fast path.
fn factor(j: usize, s: usize) -> u16 {
    ((j * 7 + s * 13) % 65_534 + 2) as u16
}

fn make_sources(region_bytes: usize) -> Vec<Vec<u8>> {
    (0..SOURCES)
        .map(|s| {
            // `| 1` keeps the xorshift seed odd, so s == 0 is not the fixed point.
            let seed = ((s as u64) * 0x9E37_79B9_7F4A_7C15) | 1;
            let mut state = seed;
            (0..region_bytes)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    (state >> 24) as u8
                })
                .collect()
        })
        .collect()
}

fn cpu_serial(dst_rows: &mut [Vec<u8>], srcs: &[Vec<u8>]) {
    for (j, dst) in dst_rows.iter_mut().enumerate() {
        dst.fill(0);
        let batch: Vec<FactorSrc<'_>> = srcs
            .iter()
            .enumerate()
            .map(|(s, src)| FactorSrc {
                factor: factor(j, s),
                src,
            })
            .collect();
        mul_acc_input_batch(dst, &batch);
    }
}

fn cpu_rayon(dst_rows: &mut [Vec<u8>], srcs: &[Vec<u8>]) {
    dst_rows.par_iter_mut().enumerate().for_each(|(j, dst)| {
        dst.fill(0);
        let batch: Vec<FactorSrc<'_>> = srcs
            .iter()
            .enumerate()
            .map(|(s, src)| FactorSrc {
                factor: factor(j, s),
                src,
            })
            .collect();
        mul_acc_input_batch(dst, &batch);
    });
}

fn gpu_chunk(session: &mut WgpuGf16Session, dst_rows: &mut [Vec<u8>], src_refs: &[&[u8]]) {
    session.begin_chunk(src_refs[0].len()).expect("begin_chunk");
    session.accumulate(src_refs, factor).expect("accumulate");
    session.finish_chunk(dst_rows).expect("finish_chunk");
}

fn bench_gpu_vs_cpu(c: &mut Criterion) {
    let mut group = c.benchmark_group("gf16_gpu_vs_cpu");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(20));

    for region_bytes in [64 * 1024usize, 1024 * 1024usize] {
        // Work per pass: every (output, source) pair touches `region_bytes`.
        let work = (OUTPUTS * SOURCES * region_bytes) as u64;
        group.throughput(Throughput::Bytes(work));

        let srcs = make_sources(region_bytes);
        let src_refs: Vec<&[u8]> = srcs.iter().map(|s| s.as_slice()).collect();
        let fresh_dst = || vec![vec![0u8; region_bytes]; OUTPUTS];

        let label = if region_bytes >= 1024 * 1024 {
            format!("{}MiB", region_bytes / (1024 * 1024))
        } else {
            format!("{}KiB", region_bytes / 1024)
        };

        let mut dst = fresh_dst();
        group.bench_with_input(
            BenchmarkId::new("cpu_serial", &label),
            &region_bytes,
            |b, _| b.iter(|| cpu_serial(black_box(&mut dst), black_box(&srcs))),
        );

        let mut dst = fresh_dst();
        group.bench_with_input(
            BenchmarkId::new("cpu_rayon", &label),
            &region_bytes,
            |b, _| b.iter(|| cpu_rayon(black_box(&mut dst), black_box(&srcs))),
        );

        // `try_new_forced` clears both auto-engage gates — the 256 MiB size gate
        // and the device-type gate that refuses CPU rasterizers — without
        // touching WEAVER_GF16_WGPU, so the bench never perturbs the tier
        // selection the repair path would make. Forced rather than automatic
        // because benchmarking the llvmpipe adapter the automatic path refuses
        // is the whole point: this number is what justifies the refusal.
        let Some(mut session) = WgpuGf16Session::try_new_forced(OUTPUTS, region_bytes) else {
            eprintln!("wgpu adapter unavailable; skipping gpu/{label}");
            continue;
        };
        eprintln!("wgpu adapter: {} (gpu/{label})", session.device_name());

        // Never benchmark a broken path: the GPU must agree with the CPU here.
        let mut gpu_dst = fresh_dst();
        let mut cpu_dst = fresh_dst();
        gpu_chunk(&mut session, &mut gpu_dst, &src_refs);
        cpu_serial(&mut cpu_dst, &srcs);
        assert_eq!(
            gpu_dst, cpu_dst,
            "gpu/{label} disagrees with the CPU kernels"
        );

        let mut dst = fresh_dst();
        group.bench_with_input(BenchmarkId::new("gpu", &label), &region_bytes, |b, _| {
            b.iter(|| gpu_chunk(&mut session, black_box(&mut dst), black_box(&src_refs)))
        });
    }

    group.finish();
}

criterion_group!(benches, bench_gpu_vs_cpu);
criterion_main!(benches);
