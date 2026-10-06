//! FFT create and repair round trips through the public engine, on files the
//! block layout handles at its edges.
mod common;

use par3_rs::creation::{CreationCodec, CreationOptions, CreationPlan, CreationSource};
use par3_rs::ingest::{PacketScanner, ScanEvent};
use par3_rs::session::RepairStatus;
use par3_rs::source::{DiskSourceAccess, MemorySourceAccess, SourceId};
use std::sync::Arc;

/// Zero-length and one-byte files beside a file with a short odd tail, on
/// both fields, with 1 and 4 workers, repaired after in-memory damage.
#[test]
fn fft_tiny_files_round_trip() {
    for (capacity_log2, field) in [(2i8, 8), (8, 16)] {
        for workers in [1usize, 4] {
            let mut big = vec![0; 5 * 4096 + 3];
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"fft tiny files");
            hasher.finalize_xof().fill(&mut big);
            let files: Vec<(&str, Vec<u8>)> = vec![
                ("empty.bin", Vec::new()),
                ("one.bin", vec![0xa7]),
                ("big.bin", big),
            ];
            let mut access = MemorySourceAccess::default();
            let mut sources = Vec::new();
            for (index, (name, bytes)) in files.iter().enumerate() {
                access.insert(SourceId(index as u64 + 1), 1, bytes.clone().into());
                sources.push(CreationSource {
                    name: (*name).into(),
                    source: SourceId(index as u64 + 1),
                });
            }
            let mut options = CreationOptions {
                block_size: 4096,
                recovery_count: 1 << capacity_log2,
                codec: CreationCodec::Fft {
                    capacity_log2,
                    interleave: 0,
                },
                ..CreationOptions::default()
            };
            options.execution.workers = workers;
            let tree = common::TempTree::new("fft-tiny");
            let plan = CreationPlan::build(Arc::new(access), &sources, options.clone()).unwrap();
            let id = plan.input_set_id();
            let carriers = plan.execute(&tree.path().join("set"), tree.path()).unwrap();

            let mut access = MemorySourceAccess::default();
            let mut damaged = files.clone();
            damaged[1].1[0] ^= 0xff;
            damaged[2].1[2] ^= 0x01;
            damaged[2].1[5 * 4096 + 2] ^= 0x01;
            for (index, (_, bytes)) in damaged.iter().enumerate() {
                access.insert(SourceId(index as u64 + 1), 2, bytes.clone().into());
            }
            let mut session =
                par3_rs::Par3RepairSession::new(id, Arc::new(access), options.execution.clone())
                    .unwrap();
            for (index, (name, _)) in files.iter().enumerate() {
                session.bind_file(name, SourceId(index as u64 + 1)).unwrap();
            }
            for path in &carriers {
                let mut disk = DiskSourceAccess::with_options(options.execution.clone());
                disk.insert(SourceId(99), path.clone());
                let mut scanner = PacketScanner::new(
                    Arc::new(disk),
                    SourceId(99),
                    options.execution.clone(),
                    par3_rs::ScanLimits::default(),
                )
                .unwrap();
                loop {
                    match scanner.poll().unwrap() {
                        ScanEvent::Packet(packet) => {
                            session.merge(packet).unwrap();
                        }
                        ScanEvent::End => break,
                        ScanEvent::NeedData { .. } => panic!("incomplete carrier"),
                    }
                }
            }
            let assessment = session.assess().unwrap();
            assert_eq!(
                assessment.status,
                RepairStatus::Ready,
                "GF(2^{field}) w{workers}"
            );
            let output = common::TempTree::new("fft-tiny-repaired");
            session.repair(output.path(), false).unwrap();
            for (name, bytes) in &files[1..] {
                assert_eq!(
                    &std::fs::read(output.path().join(name)).unwrap(),
                    bytes,
                    "GF(2^{field}) w{workers} {name}"
                );
            }
        }
    }
}
