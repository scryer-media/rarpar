//! Extraction hot spots, driven through the [`Entry`](unrar_rs::Entry) handle.
//!
//! The two `weaver_*_shape` benches mirror what weaver does in production: a
//! member split across per-volume writers that all share one output sink, once
//! for a solid archive with its volumes attached and once for a non-solid
//! multi-volume set read through a provider. They count bytes rather than
//! writing them, so what they measure is the extraction path and not the
//! filesystem underneath it.

use std::cell::RefCell;
use std::hint::black_box;
use std::io::Write;

use criterion::{Criterion, criterion_group, criterion_main};

fn fixture(dir: &str, name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(dir)
        .join(name)
}

fn open(path: &std::path::Path) -> unrar_rs::RarArchive {
    unrar_rs::RarArchive::open(std::fs::File::open(path).unwrap()).unwrap()
}

/// A sink shared by every per-volume writer, the way weaver shares one output
/// file across the volumes a member spans.
#[derive(Default)]
struct ByteCounter {
    bytes: u64,
}

struct SharedSink<'a>(&'a RefCell<ByteCounter>);

impl Write for SharedSink<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.borrow_mut().bytes += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn bench_solid_extract_all_members(c: &mut Criterion, dir: &str, name: &str, bench_name: &str) {
    let path = fixture(dir, name);
    c.bench_function(bench_name, |b| {
        b.iter(|| {
            let mut archive = open(&path);
            for member_index in 0..archive.len() {
                let mut data = Vec::new();
                archive
                    .by_index(member_index)
                    .unwrap()
                    .copy_to(&mut data)
                    .unwrap();
                black_box(data);
            }
        });
    });
}

fn bench_solid_reopen_later_member(c: &mut Criterion, dir: &str, name: &str, bench_name: &str) {
    let path = fixture(dir, name);
    c.bench_function(bench_name, |b| {
        b.iter(|| {
            let mut archive = open(&path);
            let mut data = Vec::new();
            archive.by_index(1).unwrap().copy_to(&mut data).unwrap();
            black_box(data);
        });
    });
}

fn bench_non_solid_lz_chunked(c: &mut Criterion) {
    let path = fixture("rar5", "rar5_lz.rar");
    c.bench_function("rar_non_solid_lz_chunked_extract", |b| {
        b.iter(|| {
            let mut archive = open(&path);
            let provider = unrar_rs::StaticVolumeProvider::from_ordered(vec![path.clone()]);
            let chunks = archive
                .by_index_via(0, &provider)
                .unwrap()
                .copy_to_volumes(|_| Ok(std::io::sink()))
                .unwrap();
            black_box(chunks)
        });
    });
}

fn bench_solid_lz_chunked(c: &mut Criterion) {
    let path = fixture("rar5", "rar5_solid.rar");
    c.bench_function("rar_solid_lz_chunked_extract", |b| {
        b.iter(|| {
            let mut archive = open(&path);
            for member_index in 0..archive.len() {
                let chunks = archive
                    .by_index(member_index)
                    .unwrap()
                    .copy_to_volumes(|_| Ok(std::io::sink()))
                    .unwrap();
                black_box(chunks);
            }
        });
    });
}

/// Weaver's solid-chunked shape: every member of a solid archive taken in
/// order, each split across per-volume writers that share one sink.
fn bench_weaver_solid_chunked_shape(c: &mut Criterion) {
    let path = fixture("rar5", "rar5_solid.rar");
    c.bench_function("weaver_solid_chunked_shape", |b| {
        b.iter(|| {
            let mut archive = open(&path);
            let sink = RefCell::new(ByteCounter::default());
            for member_index in 0..archive.len() {
                let chunks = archive
                    .by_index(member_index)
                    .unwrap()
                    .copy_to_volumes(|_| Ok(SharedSink(&sink)))
                    .unwrap();
                black_box(chunks);
            }
            black_box(sink.borrow().bytes);
        });
    });
}

/// Weaver's streaming-chunked shape: a non-solid multi-volume member pulled
/// through a borrowed provider, split across per-volume writers sharing a sink.
fn bench_weaver_streaming_chunked_shape(c: &mut Criterion) {
    let ordered_volumes = (1..=7)
        .map(|part| {
            fixture(
                "rar5",
                &format!("generated_matrix_rar5_lz_plain.part{part}.rar"),
            )
        })
        .collect::<Vec<_>>();
    let first_volume = ordered_volumes[0].clone();
    c.bench_function("weaver_streaming_chunked_shape", |b| {
        b.iter(|| {
            let mut archive = open(&first_volume);
            let provider = unrar_rs::StaticVolumeProvider::from_ordered(ordered_volumes.clone());
            let sink = RefCell::new(ByteCounter::default());
            let chunks = archive
                .by_index_via(0, &provider)
                .unwrap()
                .copy_to_volumes(|_| Ok(SharedSink(&sink)))
                .unwrap();
            black_box(chunks);
            black_box(sink.borrow().bytes);
        });
    });
}

fn bench_rar5_encrypted_store_chunked_multivolume(c: &mut Criterion) {
    let ordered_volumes = (1..=7)
        .map(|part| {
            fixture(
                "rar5",
                &format!("generated_matrix_rar5_store_enc.part{part}.rar"),
            )
        })
        .collect::<Vec<_>>();
    let first_volume = ordered_volumes[0].clone();
    c.bench_function("rar5_encrypted_store_chunked_multivolume", |b| {
        b.iter(|| {
            let mut archive = open(&first_volume);
            archive.set_password("testpass123");
            let provider = unrar_rs::StaticVolumeProvider::from_ordered(ordered_volumes.clone());
            let chunks = archive
                .by_index_via(0, &provider)
                .unwrap()
                .copy_to_volumes(|_| Ok(std::io::sink()))
                .unwrap();
            black_box(chunks);
        });
    });
}

fn bench_rar5_reopen_kdf_multivolume(c: &mut Criterion) {
    let ordered_volumes = (1..=7)
        .map(|part| {
            fixture(
                "rar5",
                &format!("generated_matrix_rar5_store_enc.part{part}.rar"),
            )
        })
        .collect::<Vec<_>>();
    let first_volume = ordered_volumes[0].clone();
    let provider = unrar_rs::StaticVolumeProvider::from_ordered(ordered_volumes.clone());
    let shared_cache = std::sync::Arc::new(unrar_rs::crypto::KdfCache::new());

    c.bench_function("rar5_reopen_kdf_multivolume_fresh_cache", |b| {
        b.iter(|| {
            let mut archive = unrar_rs::RarArchive::open_with_password_and_shared_kdf_cache(
                std::fs::File::open(&first_volume).unwrap(),
                "testpass123",
                std::sync::Arc::new(unrar_rs::crypto::KdfCache::new()),
            )
            .unwrap();
            let chunks = archive
                .by_index_via(0, &provider)
                .unwrap()
                .copy_to_volumes(|_| Ok(std::io::sink()))
                .unwrap();
            black_box(chunks);
        });
    });

    c.bench_function("rar5_reopen_kdf_multivolume_shared_cache", |b| {
        b.iter(|| {
            let mut archive = unrar_rs::RarArchive::open_with_password_and_shared_kdf_cache(
                std::fs::File::open(&first_volume).unwrap(),
                "testpass123",
                shared_cache.clone(),
            )
            .unwrap();
            let chunks = archive
                .by_index_via(0, &provider)
                .unwrap()
                .copy_to_volumes(|_| Ok(std::io::sink()))
                .unwrap();
            black_box(chunks);
        });
    });
}

fn bench_rar4_solid_extract_all_members(c: &mut Criterion) {
    bench_solid_extract_all_members(
        c,
        "rar4",
        "rar4_solid.rar",
        "rar4_solid_extract_all_members",
    );
}

fn bench_rar4_ppmd_restart(c: &mut Criterion) {
    bench_solid_extract_all_members(
        c,
        "rar4",
        "rar4_ppm_solid_restart.rar",
        "rar4_ppmd_restart_extract_all_members",
    );
}

fn bench_rar4_ppmd_solid_multi_member(c: &mut Criterion) {
    bench_solid_extract_all_members(
        c,
        "rar4",
        "rar4_ppm_solid_mv.rar",
        "rar4_ppmd_solid_multi_member_extract_all_members",
    );
}

fn bench_rar4_ppmd_order16_32m(c: &mut Criterion) {
    bench_solid_extract_all_members(
        c,
        "rar4",
        "rar4_ppm_order16_32m.rar",
        "rar4_ppmd_order16_32m_extract_all_members",
    );
}

fn bench_rar5_solid_extract_all_members(c: &mut Criterion) {
    bench_solid_extract_all_members(
        c,
        "rar5",
        "rar5_solid.rar",
        "rar5_solid_extract_all_members",
    );
}

fn bench_rar4_solid_reopen_later_member(c: &mut Criterion) {
    bench_solid_reopen_later_member(
        c,
        "rar4",
        "rar4_solid.rar",
        "rar4_solid_reopen_later_member",
    );
}

fn bench_rar5_solid_reopen_later_member(c: &mut Criterion) {
    bench_solid_reopen_later_member(
        c,
        "rar5",
        "rar5_solid.rar",
        "rar5_solid_reopen_later_member",
    );
}

fn bench_archive_planner_view(c: &mut Criterion) {
    let path = fixture("rar5", "rar5_multifile_lz.rar");
    c.bench_function("rar_archive_planner_view", |b| {
        b.iter(|| {
            let archive = unrar_rs::RarArchive::open(std::fs::File::open(&path).unwrap()).unwrap();
            black_box(archive.metadata());
            black_box(archive.topology_members());
            black_box(archive.planner_member_states());
        });
    });
}

fn bench_filter_e8e9(c: &mut Criterion) {
    let mut seed = vec![0u8; 1024 * 1024];
    for i in (0..seed.len().saturating_sub(5)).step_by(64) {
        seed[i] = if (i / 64) % 2 == 0 { 0xE8 } else { 0xE9 };
        let addr = ((i as i32) + 0x1234).to_le_bytes();
        seed[i + 1..i + 5].copy_from_slice(&addr);
    }

    c.bench_function("rar_filter_e8e9", |b| {
        b.iter(|| {
            let mut data = seed.clone();
            unrar_rs::__internals::apply_e8e9(&mut data, 0);
            black_box(data);
        });
    });
}

fn bench_crc_hasher(c: &mut Criterion) {
    let data: Vec<u8> = (0..(8 * 1024 * 1024))
        .map(|i| (i as u8).wrapping_mul(31))
        .collect();

    c.bench_function("rar_crc_fast_baseline", |b| {
        b.iter(|| {
            let mut hasher = crc_fast::Digest::new(crc_fast::CrcAlgorithm::Crc32IsoHdlc);
            hasher.update(black_box(&data));
            black_box(hasher.finalize());
        });
    });
}

criterion_group!(
    benches,
    bench_non_solid_lz_chunked,
    bench_solid_lz_chunked,
    bench_weaver_solid_chunked_shape,
    bench_weaver_streaming_chunked_shape,
    bench_rar5_encrypted_store_chunked_multivolume,
    bench_rar5_reopen_kdf_multivolume,
    bench_rar4_solid_extract_all_members,
    bench_rar4_ppmd_restart,
    bench_rar4_ppmd_solid_multi_member,
    bench_rar4_ppmd_order16_32m,
    bench_rar5_solid_extract_all_members,
    bench_rar4_solid_reopen_later_member,
    bench_rar5_solid_reopen_later_member,
    bench_archive_planner_view,
    bench_filter_e8e9,
    bench_crc_hasher
);
criterion_main!(benches);
