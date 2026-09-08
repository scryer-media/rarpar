//! Advanced creation through public APIs, preserving the legacy creation tests.
mod common;

use par3_rs::creation::{
    CreationCodec, CreationOptions, CreationPlan, CreationSource, Deduplication, VolumeLayout,
};
use par3_rs::ingest::{PacketScanner, ScanEvent};
use par3_rs::source::{DiskSourceAccess, MemorySourceAccess, SourceId};
use std::sync::Arc;

fn data() -> Vec<u8> {
    (0..3300).map(|i| ((i * 29 + i / 31) % 256) as u8).collect()
}

#[test]
#[ignore = "exports generated sets for an explicitly configured pinned-reference run"]
fn export_reference_interoperability_cases() {
    let directory = std::path::PathBuf::from(
        std::env::var_os("PAR3_ENGINE_ORACLE_OUTPUT").expect("explicit oracle output directory"),
    );
    for (name, block_size, codec, duplicate, data_only) in [
        ("cauchy", 256, CreationCodec::Cauchy, false, false),
        (
            "fft8",
            256,
            CreationCodec::Fft {
                capacity_log2: 4,
                interleave: 0,
            },
            false,
            false,
        ),
        (
            "fft16",
            16,
            CreationCodec::Fft {
                capacity_log2: 6,
                interleave: 0,
            },
            false,
            false,
        ),
        (
            "interleaved",
            256,
            CreationCodec::Fft {
                capacity_log2: 3,
                interleave: 2,
            },
            false,
            false,
        ),
        (
            "wide-fft8",
            1024,
            CreationCodec::Fft {
                capacity_log2: 7,
                interleave: 0,
            },
            false,
            false,
        ),
        (
            "wide-fft16",
            1024,
            CreationCodec::Fft {
                capacity_log2: 6,
                interleave: 0,
            },
            false,
            false,
        ),
        (
            "wide-interleaved",
            1024,
            CreationCodec::Fft {
                capacity_log2: 7,
                interleave: 2,
            },
            false,
            false,
        ),
        ("dedup", 256, CreationCodec::Cauchy, true, false),
        ("data", 256, CreationCodec::Cauchy, true, true),
    ] {
        let path = directory.join(name);
        std::fs::create_dir(&path).unwrap();
        let bytes = if name.starts_with("wide-") {
            let blocks = match name {
                "wide-fft8" => 120,
                "wide-interleaved" => 301,
                _ => 300,
            };
            let mut bytes = vec![0; blocks * 1024 + 37];
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"PAR3 native worker interoperability inputs v1");
            hasher.finalize_xof().fill(&mut bytes);
            bytes
        } else {
            data()
        };
        std::fs::write(path.join("input.bin"), &bytes).unwrap();
        let mut source = MemorySourceAccess::default();
        source.insert(SourceId(1), 1, bytes.clone().into());
        let mut inputs = vec![CreationSource {
            name: "input.bin".into(),
            source: SourceId(1),
        }];
        if duplicate {
            source.insert(SourceId(2), 1, bytes.clone().into());
            std::fs::write(path.join("copy.bin"), &bytes).unwrap();
            inputs.push(CreationSource {
                name: "copy.bin".into(),
                source: SourceId(2),
            });
        }
        let mut options = CreationOptions {
            block_size,
            codec,
            recovery_count: if data_only { 0 } else { 6 },
            store_data: data_only,
            deduplication: if duplicate {
                Deduplication::Aligned
            } else {
                Deduplication::None
            },
            volumes: VolumeLayout::Uniform(3),
            ..CreationOptions::default()
        };
        options.execution.workers = if name.starts_with("wide-") { 2 } else { 1 };
        let plan = CreationPlan::build(Arc::new(source), &inputs, options).unwrap();
        plan.execute(&path.join("set"), &path).unwrap();
    }
}

#[test]
fn sliding_deduplication_reuses_blocks_after_an_unaligned_prefix() {
    let bytes = data();
    let mut shifted = vec![0xa7; 53];
    shifted.extend_from_slice(&bytes[..3072]);
    let mut sources = MemorySourceAccess::default();
    sources.insert(SourceId(1), 1, bytes.into());
    sources.insert(SourceId(2), 1, shifted.into());
    let sources = Arc::new(sources);
    let inputs = [
        CreationSource {
            name: "a.bin".into(),
            source: SourceId(1),
        },
        CreationSource {
            name: "shifted.bin".into(),
            source: SourceId(2),
        },
    ];
    let mut options = CreationOptions {
        block_size: 1024,
        recovery_count: 0,
        deduplication: Deduplication::Aligned,
        ..CreationOptions::default()
    };
    let aligned = CreationPlan::build(sources.clone(), &inputs, options.clone()).unwrap();
    options.deduplication = Deduplication::Sliding;
    let sliding = CreationPlan::build(sources, &inputs, options).unwrap();
    assert!(sliding.requirements().blocks < aligned.requirements().blocks);
    assert_eq!(sliding.requirements().reused_blocks, 3);
    let output = common::TempTree::new("sliding-created");
    let paths = sliding
        .execute(&output.path().join("set"), output.path())
        .unwrap();
    let packets = common::packets_of(&std::fs::read(&paths[0]).unwrap());
    let set = par3_rs::Par3Set::from_packets_for(packets, sliding.input_set_id()).unwrap();
    assert_eq!(set.files().len(), 2);
}

#[test]
fn data_packets_restore_deduplicated_files_from_virtual_sources() {
    let bytes = data();
    let mut sources = MemorySourceAccess::default();
    sources.insert(SourceId(1), 1, bytes.clone().into());
    sources.insert(SourceId(2), 1, bytes.clone().into());
    let mut options = CreationOptions {
        block_size: 1024,
        recovery_count: 0,
        store_data: true,
        deduplication: Deduplication::Aligned,
        ..CreationOptions::default()
    };
    options.execution.workers = 1;
    let inputs = [
        CreationSource {
            name: "a.bin".into(),
            source: SourceId(1),
        },
        CreationSource {
            name: "sub/b.bin".into(),
            source: SourceId(2),
        },
    ];
    let plan = CreationPlan::build(Arc::new(sources), &inputs, options.clone()).unwrap();
    assert_eq!(plan.requirements().blocks, 4);
    assert_eq!(plan.requirements().reused_blocks, 3);
    assert_eq!(plan.requirements().scratch_bytes, 0);
    let carriers = common::TempTree::new("data-carriers");
    let paths = plan
        .execute(&carriers.path().join("set"), carriers.path())
        .unwrap();
    for (path, size) in paths.iter().zip(&plan.requirements().output_sizes) {
        assert_eq!(std::fs::metadata(path).unwrap().len(), *size);
    }
    assert!(
        plan.execute(&carriers.path().join("set"), carriers.path())
            .is_err(),
        "never overwrite a carrier"
    );
    let access = Arc::new(MemorySourceAccess::default());
    let mut session =
        par3_rs::Par3RepairSession::new(plan.input_set_id(), access, options.execution.clone())
            .unwrap();
    for path in paths {
        let mut source = DiskSourceAccess::default();
        source.insert(SourceId(99), path);
        let mut scanner = PacketScanner::new(
            Arc::new(source),
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
                ScanEvent::NeedData { .. } => panic!("complete created carrier"),
            }
        }
    }
    assert_eq!(
        session.assess().unwrap().status,
        par3_rs::session::RepairStatus::Ready
    );
    assert!(session.assess().unwrap().lost_blocks.is_empty());
    let output = common::TempTree::new("data-restored");
    let report = session.repair(output.path(), false).unwrap();
    assert_eq!(report.installed.len(), 2);
    assert_eq!(std::fs::read(output.path().join("a.bin")).unwrap(), bytes);
    assert_eq!(
        std::fs::read(output.path().join("sub/b.bin")).unwrap(),
        bytes
    );
}

#[test]
fn advanced_cauchy_and_fft_sets_repair_and_report_exact_volume_sizes() {
    for (number, codec) in [
        CreationCodec::Cauchy,
        CreationCodec::Fft {
            capacity_log2: 3,
            interleave: 2,
        },
    ]
    .into_iter()
    .enumerate()
    {
        let bytes = data();
        let mut source = MemorySourceAccess::default();
        source.insert(SourceId(1), 1, bytes.clone().into());
        let mut options = CreationOptions {
            block_size: 256,
            recovery_count: 6,
            first_recovery: 3,
            codec,
            volumes: VolumeLayout::Uniform(2),
            ..CreationOptions::default()
        };
        options.execution.workers = 1;
        options.execution.stripe_bytes = 29;
        let plan = CreationPlan::build(
            Arc::new(source),
            &[CreationSource {
                name: "input.bin".into(),
                source: SourceId(1),
            }],
            options.clone(),
        )
        .unwrap();
        let carriers = common::TempTree::new(&format!("advanced-create-{number}"));
        let paths = plan
            .execute(&carriers.path().join("set"), carriers.path())
            .unwrap();
        for (path, size) in paths.iter().zip(&plan.requirements().output_sizes) {
            assert_eq!(std::fs::metadata(path).unwrap().len(), *size);
        }
        let mut damaged = bytes.clone();
        damaged[21] ^= 1;
        damaged[4 * 256 + 41] ^= 1;
        let mut access = MemorySourceAccess::default();
        access.insert(SourceId(1), 2, damaged.into());
        let mut session = par3_rs::Par3RepairSession::new(
            plan.input_set_id(),
            Arc::new(access),
            options.execution.clone(),
        )
        .unwrap();
        session.bind_file("input.bin", SourceId(1)).unwrap();
        for path in paths {
            let mut source = DiskSourceAccess::default();
            source.insert(SourceId(99), path);
            let mut scanner = PacketScanner::new(
                Arc::new(source),
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
                    ScanEvent::NeedData { .. } => panic!("complete carrier"),
                }
            }
        }
        let output = common::TempTree::new(&format!("advanced-restored-{number}"));
        assert_eq!(
            session
                .repair(output.path(), false)
                .unwrap()
                .reconstructed_blocks,
            2
        );
        assert_eq!(
            std::fs::read(output.path().join("input.bin")).unwrap(),
            bytes
        );
    }
}
