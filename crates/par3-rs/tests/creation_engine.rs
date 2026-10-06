//! Advanced creation through public APIs, preserving the legacy creation tests.
mod common;

use par3_rs::PathRule;
use par3_rs::creation::{
    CreationCodec, CreationOptions, CreationPlan, CreationSource, Deduplication, VolumeLayout,
};
use par3_rs::ingest::{PacketScanner, ScanEvent};
use par3_rs::runtime::EngineError;
use par3_rs::source::{DiskSourceAccess, MemorySourceAccess, SourceId};
use std::collections::BTreeMap;
use std::sync::Arc;

fn data() -> Vec<u8> {
    (0..3300).map(|i| ((i * 29 + i / 31) % 256) as u8).collect()
}

#[test]
fn planning_hashes_full_blocks_and_both_tail_forms_in_one_source_pass() {
    for deduplication in [Deduplication::None, Deduplication::Aligned] {
        let mut access = MemorySourceAccess::default();
        let mut sources = Vec::new();
        let lengths = [32768 + 47, 2048 + 13, 32768 + 47, 0];
        for (index, length) in lengths.into_iter().enumerate() {
            let source = SourceId(index as u64);
            access.insert(
                source,
                1,
                (0..length)
                    .map(|i| (i % 251) as u8)
                    .collect::<Vec<_>>()
                    .into(),
            );
            sources.push(CreationSource {
                name: format!("{index}.bin"),
                source,
            });
        }
        let options = CreationOptions {
            block_size: 1024,
            recovery_count: 2,
            deduplication,
            ..CreationOptions::default()
        };
        let diagnostics = options.execution.diagnostics.clone();
        let plan = CreationPlan::build(Arc::new(access), &sources, options).unwrap();
        assert_eq!(
            plan.requirements().source_bytes,
            lengths.iter().sum::<usize>() as u64
        );
        assert_eq!(
            diagnostics.source_io().read_bytes,
            plan.requirements().source_bytes
        );
    }
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
        (
            "many-blocks",
            64,
            CreationCodec::Fft {
                capacity_log2: 0,
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
        let bytes = if name == "many-blocks" {
            let mut bytes = vec![0; 65_539 * 64];
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"PAR3 interleaved logical block boundary v1");
            hasher.finalize_xof().fill(&mut bytes);
            bytes
        } else if name.starts_with("wide-") {
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
            recovery_count: if data_only {
                0
            } else if name == "many-blocks" {
                3
            } else {
                6
            },
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
        if name == "many-blocks" {
            options.execution.retained_bytes = 224 << 20;
        }
        let plan = CreationPlan::build(Arc::new(source), &inputs, options).unwrap();
        plan.execute(&path.join("set"), &path).unwrap();
    }
}

#[test]
fn interleaved_xor_repairs_more_than_65536_logical_blocks() {
    use par3_rs::runtime::MemoryBudget;
    use par3_rs::session::RepairStatus;

    let blocks = 65_539;
    let mut bytes = vec![0; blocks * 64];
    let mut hash = blake3::Hasher::new();
    hash.update(b"PAR3 interleaved logical block boundary v1");
    hash.finalize_xof().fill(&mut bytes);
    let mut access = MemorySourceAccess::default();
    access.insert(SourceId(1), 1, bytes.clone().into());
    let mut options = CreationOptions {
        block_size: 64,
        recovery_count: 3,
        codec: CreationCodec::Fft {
            capacity_log2: 0,
            interleave: 2,
        },
        ..CreationOptions::default()
    };
    options.execution.workers = 1;
    // The logical geometry is allowed; callers still have to budget its many
    // fingerprint and extent descriptions independently of tiny codec stripes.
    options.execution.memory = MemoryBudget::new(256 << 20);
    options.execution.retained_bytes = 224 << 20;
    let plan = CreationPlan::build(
        Arc::new(access),
        &[CreationSource {
            name: "input.bin".into(),
            source: SourceId(1),
        }],
        options.clone(),
    )
    .unwrap();
    assert_eq!(plan.requirements().blocks, blocks as u64);
    let id = plan.input_set_id();
    let carriers = common::TempTree::new("interleaved-block-boundary");
    let paths = plan
        .execute(&carriers.path().join("set"), carriers.path())
        .unwrap();
    drop(plan);
    let mut damaged = bytes.clone();
    for block in [0, 32_767, 65_537] {
        damaged[block * 64 + 13] ^= 0x80;
    }
    let mut access = MemorySourceAccess::default();
    access.insert(SourceId(1), 2, damaged.into());
    let mut session =
        par3_rs::Par3RepairSession::new(id, Arc::new(access), options.execution.clone()).unwrap();
    session.bind_file("input.bin", SourceId(1)).unwrap();
    for path in paths {
        let mut disk = DiskSourceAccess::with_options(options.execution.clone());
        disk.insert(SourceId(99), path);
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
                ScanEvent::NeedData { .. } => panic!("complete created carrier"),
            }
        }
    }
    let assessment = session.assess().unwrap();
    assert_eq!(assessment.status, RepairStatus::Ready);
    assert_eq!(assessment.requirements.len(), 3);
    assert!(
        assessment
            .requirements
            .iter()
            .all(|need| need.lost == 1 && need.additional == 0)
    );
    let output = common::TempTree::new("interleaved-block-boundary-repaired");
    assert_eq!(
        session
            .repair(output.path(), false)
            .unwrap()
            .reconstructed_blocks,
        3
    );
    assert_eq!(
        std::fs::read(output.path().join("input.bin")).unwrap(),
        bytes
    );
    assert!(options.execution.memory.peak() <= options.execution.memory.limit());
    drop(session);
    assert_eq!(options.execution.memory.used(), 0);
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
            // Three packets per carrier is one whole row of the interleaved
            // case and two carriers of the Cauchy one, so both codecs write
            // more than one carrier under the same limit.
            volumes: VolumeLayout::Uniform(3),
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
        // Six 256-byte rows are held resident, so there is no spool file to
        // synchronize: one barrier per carrier and nothing else.
        let synced = options.execution.diagnostics.file_sync();
        assert_eq!(synced.calls, paths.len() as u64);
        assert_eq!(synced.completed, synced.calls);
        let buffered = common::TempTree::new(&format!("advanced-buffered-{number}"));
        let buffered_paths = plan
            .execute_with_durability(
                &buffered.path().join("set"),
                buffered.path(),
                par3_rs::creation::CreationDurability::Buffered,
            )
            .unwrap();
        assert_eq!(
            options.execution.diagnostics.file_sync().calls,
            synced.calls
        );
        assert_eq!(buffered_paths.len(), paths.len());
        for (durable, buffered) in paths.iter().zip(&buffered_paths) {
            assert_eq!(
                std::fs::read(durable).unwrap(),
                std::fs::read(buffered).unwrap()
            );
        }
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

/// Create one Cauchy set and return every carrier's bytes, the admitted worker
/// count, and the source reads the creation made.
fn cauchy_carriers(
    name: &str,
    bytes: &[u8],
    block_size: u64,
    recovery_count: u64,
    workers: usize,
    memory: Option<usize>,
) -> (u8, Vec<Vec<u8>>, u64, u64) {
    let mut access = MemorySourceAccess::default();
    access.insert(SourceId(1), 1, bytes.to_vec().into());
    let mut options = CreationOptions {
        block_size,
        recovery_count,
        first_recovery: 1,
        codec: CreationCodec::Cauchy,
        ..CreationOptions::default()
    };
    options.execution.workers = workers;
    if let Some(memory) = memory {
        options.execution.memory = par3_rs::runtime::MemoryBudget::new(memory);
    }
    let diagnostics = options.execution.diagnostics.clone();
    let plan = CreationPlan::build(
        Arc::new(access),
        &[CreationSource {
            name: "input.bin".into(),
            source: SourceId(1),
        }],
        options,
    )
    .unwrap();
    let reads = diagnostics.source_io().read_calls;
    let tree = common::TempTree::new(&format!("cauchy-workers-{name}-{workers}"));
    let paths = plan
        .execute_with_durability(
            &tree.path().join("set"),
            tree.path(),
            par3_rs::creation::CreationDurability::Buffered,
        )
        .unwrap();
    (
        plan.requirements().field.size,
        paths
            .iter()
            .map(|path| std::fs::read(path).unwrap())
            .collect(),
        diagnostics.admission().workers,
        diagnostics.source_io().read_calls - reads,
    )
}

#[test]
fn cauchy_creation_is_byte_identical_for_every_worker_count() {
    // Each case has 4 MiB of rows behind every source stripe, enough for the
    // encode to admit four workers, and a tail that leaves the last block short.
    let mut one_pass_reads = 0;
    for (name, field, block_size, blocks, recovery_count, memory, widest) in [
        ("gf8", 1, 64 << 10, 8, 64, None, 4),
        ("gf16", 2, 16 << 10, 8, 256, None, 4),
        // Too little memory for one batch of all 256 rows: the encode walks
        // the source twice, 2 MiB of rows at a time, which is room for two
        // workers, and the pool must not make it walk a third time.
        ("gf16-passes", 2, 16 << 10, 8, 256, Some(4 << 20), 2),
    ] {
        let bytes: Vec<u8> = (0..block_size as usize * blocks - 77)
            .map(|i| (i * 131 + i / 977) as u8)
            .collect();
        let (serial_field, serial, serial_workers, serial_reads) =
            cauchy_carriers(name, &bytes, block_size, recovery_count, 1, memory);
        assert_eq!(serial_field, field, "{name}");
        assert_eq!(serial_workers, 1, "{name}");
        if memory.is_none() {
            one_pass_reads = serial_reads;
        } else {
            assert!(serial_reads > one_pass_reads, "{name}: one pass was enough");
        }
        for workers in [2, 4] {
            let (_, parallel, admitted, reads) =
                cauchy_carriers(name, &bytes, block_size, recovery_count, workers, memory);
            assert_eq!(admitted, workers.min(widest) as u64, "{name}: {workers}");
            assert_eq!(reads, serial_reads, "{name}: workers changed the reads");
            assert!(
                parallel == serial,
                "{name}: {workers} workers changed bytes"
            );
        }
    }
}

/// One Cauchy creation under `memory`, or `None` when the budget refuses it:
/// the carriers, the source reads the encode made, and the encode's scratch
/// peak, which is where its source group and staged rows are charged.
fn grouped_carriers(
    bytes: &[u8],
    block_size: u64,
    recovery_count: u64,
    workers: usize,
    memory: usize,
) -> Option<(Vec<Vec<u8>>, u64, usize)> {
    let mut access = MemorySourceAccess::default();
    access.insert(SourceId(1), 1, bytes.to_vec().into());
    let mut options = CreationOptions {
        block_size,
        recovery_count,
        first_recovery: 1,
        codec: CreationCodec::Cauchy,
        ..CreationOptions::default()
    };
    options.execution.workers = workers;
    options.execution.memory = par3_rs::runtime::MemoryBudget::new(memory);
    let execution = options.execution.clone();
    let plan = CreationPlan::build(
        Arc::new(access),
        &[CreationSource {
            name: "input.bin".into(),
            source: SourceId(1),
        }],
        options,
    )
    .ok()?;
    let reads = execution.diagnostics.source_io().read_calls;
    let tree = common::TempTree::new(&format!("cauchy-groups-{block_size}-{memory}-{workers}"));
    let paths = plan
        .execute_with_durability(
            &tree.path().join("set"),
            tree.path(),
            par3_rs::creation::CreationDurability::Buffered,
        )
        .ok()?;
    assert!(execution.memory.peak() <= execution.memory.limit());
    let scratch = execution
        .diagnostics
        .memory()
        .unwrap()
        .category(par3_rs::runtime::MemoryCategory::CodecScratch)
        .peak as usize;
    Some((
        paths
            .iter()
            .map(|path| std::fs::read(path).unwrap())
            .collect(),
        execution.diagnostics.source_io().read_calls - reads,
        scratch,
    ))
}

#[test]
fn cauchy_creation_is_byte_identical_for_every_source_group() {
    // Eight blocks, so the widest group is all of them. At the default budget
    // the rows are resident and every block's stripe is folded in one group.
    // At the smallest budget that still walks the source once, the rows are
    // spooled and nothing is left beyond the batch: one stripe per group,
    // exactly the walk before grouping existed. The bytes must not care, and
    // neither may the reads.
    for (name, block_size, recovery_count) in [("gf8", 4096u64, 64u64), ("gf16", 2048, 256)] {
        let stripe = block_size as usize;
        let rows = recovery_count as usize;
        let bytes: Vec<u8> = (0..stripe * 8 - 77)
            .map(|i| (i * 131 + i / 977) as u8)
            .collect();
        let (wide, one_pass_reads, wide_scratch) =
            grouped_carriers(&bytes, block_size, recovery_count, 1, 256 << 20).unwrap();
        assert_eq!(wide[0][..8], *b"PAR3\0PKT", "{name}");
        // Resident rows charge only their table; the group is all 8 stripes.
        assert_eq!(wide_scratch, rows * 64 + 8 * stripe, "{name}: widest group");
        let (mut low, mut high) = (0usize, 256 << 20);
        while low + 1 < high {
            let middle = low + (high - low) / 2;
            match grouped_carriers(&bytes, block_size, recovery_count, 1, middle) {
                Some((_, reads, _)) if reads == one_pass_reads => high = middle,
                _ => low = middle,
            }
        }
        // Scratch paths are charged too and their names grow with a counter,
        // so stand a little above the edge: far less than the slack and the
        // stripe a second source would need.
        let high = high + 4096;
        let (narrow, reads, narrow_scratch) =
            grouped_carriers(&bytes, block_size, recovery_count, 1, high).unwrap();
        assert_eq!(reads, one_pass_reads, "{name}");
        // Spooled rows charge a stripe each; the group is one stripe.
        assert_eq!(
            narrow_scratch,
            rows * (stripe + 64) + stripe,
            "{name}: single-stripe group"
        );
        assert!(narrow == wide, "{name}: the group width changed bytes");
        for (memory, workers) in [(high, 4), (256 << 20, 4)] {
            let (parallel, reads, _) =
                grouped_carriers(&bytes, block_size, recovery_count, workers, memory).unwrap();
            assert_eq!(
                reads, one_pass_reads,
                "{name}: {workers} workers at {memory}"
            );
            assert!(
                parallel == wide,
                "{name}: {workers} workers at {memory} changed bytes"
            );
        }
    }
}

#[test]
fn staged_resident_rows_write_the_same_carriers() {
    // Blocks wider than the encode stripe: resident rows are then a block
    // apart, and accumulate in contiguous staged stripes when the budget has
    // room, in place when it does not. Both must write what the spooled rows
    // write.
    let (block_size, stripe, rows) = (256u64 << 10, 64usize << 10, 20usize);
    let bytes: Vec<u8> = (0..block_size as usize * 6 - 4099)
        .map(|i| (i * 7 + i / 4093) as u8)
        .collect();
    let mut reference = None;
    // The budget at which resident rows were first folded in place, and
    // whether a larger budget then staged them. Staged rows charge a stripe
    // each, as spooled rows do; in-place rows charge only their table.
    let (mut in_place, mut staged) = (None, false);
    for memory in (2..=28).map(|m| m << 19) {
        for workers in [1, 3] {
            let Some((carriers, _, scratch)) =
                grouped_carriers(&bytes, block_size, rows as u64, workers, memory)
            else {
                continue;
            };
            let group = |charged: usize| {
                let extra = scratch.checked_sub(charged)?;
                (extra % stripe == 0 && (1..=6).contains(&(extra / stripe))).then_some(())
            };
            if group(rows * 64).is_some() {
                in_place.get_or_insert(memory);
            } else if in_place.is_some_and(|first| memory > first) {
                staged |= group(rows * (64 + stripe)).is_some();
            }
            match &reference {
                None => reference = Some(carriers),
                Some(reference) => {
                    assert!(carriers == *reference, "{memory} with {workers} workers")
                }
            }
        }
    }
    assert!(reference.is_some());
    assert!(
        in_place.is_some(),
        "no budget folded resident rows in place"
    );
    assert!(staged, "no budget staged resident rows");
}

#[test]
fn creation_refuses_a_name_repair_would_refuse_to_write() {
    // par3-rs must never produce a set it would later decline to repair, so
    // creation runs the same rule table the repair destination runs. Each of
    // these names is legal on the filesystem this test runs on; the refusal is
    // the engine's own, and it names the rule and the offending component.
    let access = Arc::new({
        let mut access = MemorySourceAccess::default();
        access.insert(SourceId(0), 1, vec![7u8; 4096].into());
        access
    });
    for (name, rule) in [
        ("CON", PathRule::ReservedDevice),
        ("con.txt", PathRule::ReservedDevice),
        ("a:b", PathRule::Absolute),
        ("ab:c", PathRule::Colon),
        ("../escape.bin", PathRule::ParentDirectory),
        ("/absolute.bin", PathRule::Absolute),
        ("trailing.", PathRule::TrailingSpaceOrDot),
        ("nul\u{0}byte.bin", PathRule::Control),
        // PR #73 round 2, finding 3: the six characters Win32 forbids outright.
        ("what?.bin", PathRule::ForbiddenCharacter),
        ("star*.bin", PathRule::ForbiddenCharacter),
        ("quote\".bin", PathRule::ForbiddenCharacter),
        ("less<.bin", PathRule::ForbiddenCharacter),
        ("more>.bin", PathRule::ForbiddenCharacter),
        ("pipe|.bin", PathRule::ForbiddenCharacter),
    ] {
        let sources = vec![CreationSource {
            name: name.to_owned(),
            source: SourceId(0),
        }];
        let options = CreationOptions {
            block_size: 1024,
            recovery_count: 1,
            ..CreationOptions::default()
        };
        match CreationPlan::build(access.clone(), &sources, options) {
            Err(EngineError::UnsafePath(violation)) => {
                assert_eq!(violation.rule, rule, "{name:?}");
                assert!(
                    name.starts_with(&violation.path),
                    "the refusal names the path it refused"
                );
            }
            Err(other) => panic!("{name:?} should be refused as unsafe, got {other:?}"),
            Ok(_) => panic!("{name:?} should be refused as unsafe, but was accepted"),
        }
    }

    // The ordinary name beside them is still accepted.
    let sources = vec![CreationSource {
        name: "ordinary.bin".to_owned(),
        source: SourceId(0),
    }];
    let options = CreationOptions {
        block_size: 1024,
        recovery_count: 1,
        ..CreationOptions::default()
    };
    CreationPlan::build(access, &sources, options)
        .map(|_| ())
        .unwrap();
}

/// The recovery indices each written carrier carries, keyed by file name.
fn carried_indices(paths: &[std::path::PathBuf]) -> Vec<(String, Vec<u64>)> {
    paths
        .iter()
        .map(|path| {
            let bytes = std::fs::read(path).unwrap();
            let indices = common::packets_of(&bytes)
                .into_iter()
                .filter_map(|packet| match packet.body() {
                    par3_rs::packet::PacketBody::RecoveryData(row) => {
                        Some(row.recovery_block_index)
                    }
                    _ => None,
                })
                .collect();
            (
                path.file_name().unwrap().to_string_lossy().into_owned(),
                indices,
            )
        })
        .collect()
}

fn created_indices(
    name: &str,
    codec: CreationCodec,
    recovery_count: u64,
) -> Vec<(String, Vec<u64>)> {
    let bytes = data();
    let mut access = MemorySourceAccess::default();
    access.insert(SourceId(1), 1, bytes.into());
    let inputs = [CreationSource {
        name: "notes.bin".into(),
        source: SourceId(1),
    }];
    let mut options = CreationOptions {
        block_size: 256,
        codec,
        recovery_count,
        ..CreationOptions::default()
    };
    options.execution.workers = 1;
    let plan = CreationPlan::build(Arc::new(access), &inputs, options).unwrap();
    let tree = common::TempTree::new(name);
    let paths = plan.execute(&tree.path().join("set"), tree.path()).unwrap();
    for (path, size) in paths.iter().zip(&plan.requirements().output_sizes) {
        assert_eq!(std::fs::metadata(path).unwrap().len(), *size);
    }
    carried_indices(&paths)
}

#[test]
fn interleaved_carriers_are_named_and_filled_by_row() {
    // Three cohorts, nine recovery blocks: three rows, split one and then two.
    // Each name counts rows, and each carrier holds every cohort's share of the
    // rows it names, so the first carries indices 0..3 and the second 3..9.
    let carriers = created_indices(
        "interleaved-row-names",
        CreationCodec::Fft {
            capacity_log2: 3,
            interleave: 2,
        },
        9,
    );
    let carried: Vec<(&str, &[u64])> = carriers
        .iter()
        .map(|(name, indices)| (name.as_str(), indices.as_slice()))
        .collect();
    assert_eq!(
        carried,
        [
            ("set.par3", &[][..]),
            ("set.vol0+1.par3", &[0, 1, 2][..]),
            ("set.vol1+2.par3", &[3, 4, 5, 6, 7, 8][..]),
        ]
    );
}

#[test]
fn interleaved_carrier_numbers_are_padded_to_the_widest_row_they_reach() {
    // Two cohorts and forty recovery blocks: twenty rows, split 1, 2, 4, 8, 5,
    // so the row starts reach two digits and every name is padded to match.
    let carriers = created_indices(
        "interleaved-row-padding",
        CreationCodec::Fft {
            capacity_log2: 5,
            interleave: 1,
        },
        40,
    );
    let names: Vec<&str> = carriers.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(
        names,
        [
            "set.par3",
            "set.vol00+1.par3",
            "set.vol01+2.par3",
            "set.vol03+4.par3",
            "set.vol07+8.par3",
            "set.vol15+5.par3",
        ]
    );
    // The last carrier still holds both cohorts' shares of its five rows.
    assert_eq!(
        carriers.last().unwrap().1,
        (30..40).collect::<Vec<u64>>(),
        "rows 15..20 of two cohorts"
    );
}

#[test]
fn a_single_cohort_set_is_named_and_filled_as_before() {
    let carriers = created_indices("cauchy-row-names", CreationCodec::Cauchy, 3);
    let carried: Vec<(&str, &[u64])> = carriers
        .iter()
        .map(|(name, indices)| (name.as_str(), indices.as_slice()))
        .collect();
    assert_eq!(
        carried,
        [
            ("set.par3", &[][..]),
            ("set.vol0+1.par3", &[0][..]),
            ("set.vol1+2.par3", &[1, 2][..]),
        ]
    );
}

#[test]
fn a_recovery_range_that_is_not_whole_rows_is_refused() {
    let inputs = [CreationSource {
        name: "notes.bin".into(),
        source: SourceId(1),
    }];
    for (first_recovery, recovery_count) in [(0, 8), (1, 9)] {
        let mut access = MemorySourceAccess::default();
        access.insert(SourceId(1), 1, data().into());
        let options = CreationOptions {
            block_size: 256,
            codec: CreationCodec::Fft {
                capacity_log2: 3,
                interleave: 2,
            },
            first_recovery,
            recovery_count,
            ..CreationOptions::default()
        };
        assert!(
            matches!(
                CreationPlan::build(Arc::new(access), &inputs, options),
                Err(EngineError::InvalidState(
                    "interleaved recovery range is not a whole number of rows"
                ))
            ),
            "{first_recovery}+{recovery_count} is not a whole number of rows"
        );
    }
}

/// What one creation wrote and what it cost on disk.
struct Created {
    carriers: Vec<Vec<u8>>,
    output_bytes: u64,
    scratch_bytes: u64,
    file_io: par3_rs::runtime::IoSnapshot,
    syncs: u64,
    resident_peak: u64,
    field: u8,
}

fn create_under(
    name: &str,
    bytes: &[u8],
    settings: &CreationOptions,
    memory: Option<usize>,
) -> Created {
    let mut access = MemorySourceAccess::default();
    access.insert(SourceId(1), 1, bytes.to_vec().into());
    let mut options = settings.clone();
    options.execution.diagnostics = Default::default();
    if let Some(memory) = memory {
        options.execution.memory = par3_rs::runtime::MemoryBudget::new(memory);
    }
    let execution = options.execution.clone();
    let plan = CreationPlan::build(
        Arc::new(access),
        &[CreationSource {
            name: "input.bin".into(),
            source: SourceId(1),
        }],
        options,
    )
    .unwrap();
    let tree = common::TempTree::new(&format!("spool-{name}-{}", memory.is_some()));
    let paths = plan.execute(&tree.path().join("set"), tree.path()).unwrap();
    assert!(
        execution.memory.peak() <= execution.memory.limit(),
        "{name}"
    );
    let ledger = execution.diagnostics.memory().unwrap();
    Created {
        carriers: paths
            .iter()
            .map(|path| std::fs::read(path).unwrap())
            .collect(),
        output_bytes: plan.requirements().output_sizes.iter().sum(),
        scratch_bytes: plan.requirements().scratch_bytes,
        field: plan.requirements().field.size,
        file_io: execution.diagnostics.file_io(),
        syncs: execution.diagnostics.file_sync().calls,
        resident_peak: ledger
            .category(par3_rs::runtime::MemoryCategory::OutputStaging)
            .peak,
    }
}

#[test]
fn resident_and_spooled_recovery_rows_write_the_same_carriers() {
    // Each case's rows fit the default budget and are held resident, and do
    // not fit the small one beside the carrier stage, so they are spooled.
    // The small budgets still leave the carrier stage room for one payload.
    for (name, codec, blocks, block_size, recovery_count, small) in [
        ("gf8", CreationCodec::Cauchy, 100, 8 << 10, 64, 512 << 10),
        ("gf16", CreationCodec::Cauchy, 300, 8 << 10, 256, 2 << 20),
        (
            "fft",
            CreationCodec::Fft {
                capacity_log2: 4,
                interleave: 0,
            },
            40,
            32 << 10,
            16,
            768 << 10,
        ),
        (
            "interleaved",
            CreationCodec::Fft {
                capacity_log2: 3,
                interleave: 1,
            },
            40,
            32 << 10,
            16,
            768 << 10,
        ),
    ] {
        let bytes: Vec<u8> = (0..block_size * blocks - 77)
            .map(|i| (i * 131 + i / 977) as u8)
            .collect();
        for volumes in [
            VolumeLayout::Uniform(recovery_count),
            VolumeLayout::Variable,
        ] {
            let mut settings = CreationOptions {
                block_size: block_size as u64,
                recovery_count,
                codec,
                volumes,
                ..CreationOptions::default()
            };
            settings.execution.workers = 2;
            let case = format!("{name}-{volumes:?}");
            let resident = create_under(&case, &bytes, &settings, None);
            let spooled = create_under(&case, &bytes, &settings, Some(small));
            assert!(
                resident.carriers == spooled.carriers,
                "{case}: the spool changed the carriers"
            );
            let carriers = resident.carriers.len() as u64;
            assert!(carriers > 1, "{case}");
            if codec == CreationCodec::Cauchy {
                let field = if name == "gf8" { 1 } else { 2 };
                assert_eq!(resident.field, field, "{case}");
            }
            let scratch = resident.scratch_bytes;
            assert_eq!(scratch, recovery_count * block_size as u64, "{case}");

            // Resident rows: only carriers are written, and carriers are
            // authenticated as they are written, so no file is read at all.
            assert_eq!(
                resident.file_io.write_bytes, resident.output_bytes,
                "{case}"
            );
            assert_eq!(
                resident.file_io.read_bytes, 0,
                "{case}: a carrier was read back"
            );
            assert_eq!(resident.syncs, carriers, "{case}: a spool was synchronized");
            assert!(resident.resident_peak >= scratch, "{case}");

            // Spooled rows: each is written once and read back once, where
            // the packet hash used to take a second read of every byte.
            assert_eq!(
                spooled.file_io.write_bytes,
                spooled.output_bytes + scratch,
                "{case}"
            );
            assert_eq!(
                spooled.file_io.read_bytes - resident.file_io.read_bytes,
                scratch,
                "{case}: spooled payloads were not read exactly once"
            );
            // The spool is scratch: only the staged carriers are synchronized.
            assert_eq!(
                spooled.syncs, carriers,
                "{case}: the spool was synchronized"
            );
            assert!(spooled.resident_peak < scratch, "{case}");
        }
    }
}

/// The streaming engine and `create` — which recreates every official
/// reference set in the corpus byte for byte — write the same bytes for a
/// tree that exercises the reference's storage order, its first-fit tail
/// packing and its shared packets: mixed sizes whose tails only pack the
/// reference's way when an earlier tail block is reused ahead of the latest
/// one, an inline tail, a file of whole blocks, and empty files of one name in
/// two directories, which share one File packet, inside subdirectories of one
/// name that share one Directory packet. The sources are listed backwards, so
/// the storage order has to come from the sizes and names.
#[test]
fn the_streaming_engine_writes_what_create_writes_for_mixed_trees() {
    use par3_rs::create::{CreateOptions, InputSpec, RecoveryAmount, create};

    const BLOCK: u64 = 1024;
    let inputs: &[(&str, u64)] = &[
        ("m/a.bin", 3 * BLOCK + 700),
        ("b.bin", 500),
        ("c.bin", 2 * BLOCK + 300),
        ("d.bin", 200),
        ("e.bin", 41),
        ("f.bin", 2 * BLOCK),
        ("g.bin", 10),
        ("x/e.bin", 0),
        ("y/e.bin", 0),
        ("x/z/e.bin", 0),
        ("y/z/e.bin", 0),
    ];
    let tree = common::TempTree::new("creation-two-path");
    for (index, (name, length)) in inputs.iter().enumerate() {
        let bytes: Vec<u8> = (0..*length)
            .map(|i| ((i * 31 + i / 7 + index as u64 * 101) % 251) as u8)
            .collect();
        tree.write(&format!("in/{name}"), &bytes);
    }
    let base = tree.path().join("in");
    let creator = "two-path creator";

    let files: Vec<std::path::PathBuf> = inputs
        .iter()
        .map(|(name, _)| std::path::PathBuf::from(name))
        .collect();
    std::fs::create_dir_all(tree.path().join("create")).unwrap();
    let report = create(
        &InputSpec::new(&base, &files),
        &tree.path().join("create/set.par3"),
        &CreateOptions::default()
            .with_block_size(BLOCK)
            .with_recovery(RecoveryAmount::Blocks(6))
            .with_creator(creator),
    )
    .unwrap();

    let mut access = DiskSourceAccess::with_options(par3_rs::runtime::ExecutionOptions::default());
    let mut sources = Vec::new();
    for (index, (name, _)) in inputs.iter().enumerate().rev() {
        let id = SourceId(index as u64);
        access.insert(id, base.join(name));
        sources.push(CreationSource {
            name: (*name).to_owned(),
            source: id,
        });
    }
    let plan = CreationPlan::build(
        Arc::new(access),
        &sources,
        CreationOptions {
            block_size: BLOCK,
            recovery_count: 6,
            creator: creator.to_owned(),
            ..CreationOptions::default()
        },
    )
    .unwrap();
    let out = tree.path().join("stream");
    std::fs::create_dir_all(&out).unwrap();
    let written = plan.execute(&out.join("set"), tree.path()).unwrap();

    let names = |paths: &[std::path::PathBuf]| -> Vec<String> {
        paths
            .iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
            .collect()
    };
    assert_eq!(names(&written), names(&report.files_written));
    for (ours, theirs) in written.iter().zip(&report.files_written) {
        assert!(
            std::fs::read(ours).unwrap() == std::fs::read(theirs).unwrap(),
            "{} differs from create's",
            ours.display()
        );
    }
    // Shared packets go out once: the four empty `e.bin` files make one File
    // packet beside the seven others, and the two `z` directories one
    // Directory packet beside `m`, `x` and `y`.
    let index = common::packets_of(&std::fs::read(&written[0]).unwrap());
    let count = |kind: fn(&par3_rs::PacketBody) -> bool| {
        index.iter().filter(|packet| kind(packet.body())).count()
    };
    assert_eq!(
        count(|body| matches!(body, par3_rs::PacketBody::File(_))),
        8
    );
    assert_eq!(
        count(|body| matches!(body, par3_rs::PacketBody::Directory(_))),
        4
    );
}

/// The streaming engine writes the reference's FFT sets byte for byte: the
/// GF(2^8) and GF(2^16) single-cohort sets and the three-cohort interleaved
/// one, each recreated from its input with the Creator text, block size and
/// FFT parameters read back from the official index file.
#[test]
fn the_streaming_engine_writes_the_reference_fft_sets_byte_for_byte() {
    let input: Vec<u8> = (0..14000)
        .map(|i| ((i * 73 + i / 29) % 256) as u8)
        .collect();
    let sets: &[&[&str]] = &[
        &[
            "fft.par3",
            "fft.vol0+1.par3",
            "fft.vol1+2.par3",
            "fft.vol3+4.par3",
            "fft.vol7+1.par3",
        ],
        &[
            "fft16.par3",
            "fft16.vol00+1.par3",
            "fft16.vol01+2.par3",
            "fft16.vol03+4.par3",
            "fft16.vol07+8.par3",
            "fft16.vol15+1.par3",
        ],
        &[
            "interleaved.par3",
            "interleaved.vol0+1.par3",
            "interleaved.vol1+2.par3",
        ],
    ];
    for names in sets {
        let reference: Vec<Vec<u8>> = names
            .iter()
            .map(|name| common::advanced_fixture(name))
            .collect();
        let (mut creator, mut block_size, mut fft) = (None, None, None);
        for packet in common::packets_of(&reference[0]) {
            match packet.body() {
                par3_rs::PacketBody::Creator(body) => creator = Some(body.text().into_owned()),
                par3_rs::PacketBody::Start(body) => block_size = Some(body.block_size),
                par3_rs::PacketBody::FftMatrix(body) => {
                    fft = Some((body.max_recovery_blocks_log2, body.interleave));
                }
                _ => {}
            }
        }
        let (capacity_log2, interleave) = fft.expect("an FFT matrix");
        let recovery_count = reference[1..]
            .iter()
            .flat_map(|carrier| common::packets_of(carrier))
            .filter(|packet| matches!(packet.body(), par3_rs::PacketBody::RecoveryData(_)))
            .count() as u64;

        let mut access = MemorySourceAccess::default();
        access.insert(SourceId(0), 1, input.clone().into());
        let plan = CreationPlan::build(
            Arc::new(access),
            &[CreationSource {
                name: "input.bin".to_owned(),
                source: SourceId(0),
            }],
            CreationOptions {
                block_size: block_size.expect("a Start packet"),
                recovery_count,
                codec: CreationCodec::Fft {
                    capacity_log2,
                    interleave,
                },
                creator: creator.expect("a Creator packet"),
                ..CreationOptions::default()
            },
        )
        .unwrap();
        let tree = common::TempTree::new("creation-fft-reference");
        let stem = names[0].trim_end_matches(".par3");
        let written = plan.execute(&tree.path().join(stem), tree.path()).unwrap();
        let written_names: Vec<String> = written
            .iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(written_names, *names);
        for ((ours, theirs), name) in written.iter().zip(&reference).zip(names.iter()) {
            common::assert_block_eq(&std::fs::read(ours).unwrap(), theirs, name);
        }
    }
}

/// Data volumes as well: the reference's capacity-one FFT set with stored Data
/// packets and aligned deduplication of two identical inputs. The index, the
/// recovery volume and the data volumes of whole blocks are recreated byte
/// for byte. The last data volume holds the packed tail block, whose Data
/// packet the reference cuts to the bytes in use while the engine stores the
/// whole block; that volume is only checked to differ by exactly that.
#[test]
fn the_streaming_engine_writes_the_reference_data_volumes_byte_for_byte() {
    let names = [
        "data-dedup.par3",
        "data-dedup.vol0+1.par3",
        "data-dedup.part0+1.par3",
        "data-dedup.part1+2.par3",
        "data-dedup.part3+1.par3",
    ];
    let reference: Vec<Vec<u8>> = names
        .iter()
        .map(|name| common::advanced_fixture(name))
        .collect();
    let (mut creator, mut block_size, mut fft) = (None, None, None);
    for packet in common::packets_of(&reference[0]) {
        match packet.body() {
            par3_rs::PacketBody::Creator(body) => creator = Some(body.text().into_owned()),
            par3_rs::PacketBody::Start(body) => block_size = Some(body.block_size),
            par3_rs::PacketBody::FftMatrix(body) => {
                fft = Some((body.max_recovery_blocks_log2, body.interleave));
            }
            _ => {}
        }
    }
    let (capacity_log2, interleave) = fft.expect("an FFT matrix");
    let mut access = MemorySourceAccess::default();
    let mut sources = Vec::new();
    for (index, name) in ["input.bin", "copy.bin"].into_iter().enumerate() {
        access.insert(SourceId(index as u64), 1, data().into());
        sources.push(CreationSource {
            name: name.to_owned(),
            source: SourceId(index as u64),
        });
    }
    let plan = CreationPlan::build(
        Arc::new(access),
        &sources,
        CreationOptions {
            block_size: block_size.expect("a Start packet"),
            recovery_count: 1,
            codec: CreationCodec::Fft {
                capacity_log2,
                interleave,
            },
            deduplication: Deduplication::Aligned,
            store_data: true,
            creator: creator.expect("a Creator packet"),
            ..CreationOptions::default()
        },
    )
    .unwrap();
    let tree = common::TempTree::new("creation-data-reference");
    let written = plan
        .execute(&tree.path().join("data-dedup"), tree.path())
        .unwrap();
    let mut written_names: Vec<String> = written
        .iter()
        .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    written_names.sort();
    let mut expected: Vec<&str> = names.to_vec();
    expected.sort();
    assert_eq!(written_names, expected);
    for (name, theirs) in names.iter().zip(&reference).take(4) {
        common::assert_block_eq(&tree.read(name), theirs, name);
    }
    // The tail block's Data packet: 3300 bytes leave 228 in block 3.
    let tail = 3300 % 1024;
    let ours = common::packets_of(&tree.read(names[4]));
    let theirs = common::packets_of(&reference[4]);
    assert_eq!(ours.len(), theirs.len());
    for (ours, theirs) in ours.iter().zip(&theirs) {
        match (ours.body(), theirs.body()) {
            (par3_rs::PacketBody::Data(ours), par3_rs::PacketBody::Data(theirs)) => {
                assert_eq!(ours.block_index, theirs.block_index);
                assert_eq!(theirs.data.len(), tail);
                assert_eq!(&ours.data[..tail], &theirs.data[..]);
                assert!(ours.data[tail..].iter().all(|&byte| byte == 0));
            }
            (ours, theirs) => assert_eq!(ours, theirs),
        }
    }
}

/// The reference's FFT input: 14000 bytes, fourteen 1024-byte blocks.
fn fft_input() -> Vec<u8> {
    (0..14000)
        .map(|i| ((i * 73 + i / 29) % 256) as u8)
        .collect()
}

/// Build an FFT set of one recovery block under `capacity_log2`, as the
/// reference's `-c1 -cm<capacity>` does, and return its carriers' bytes.
fn single_recovery_fft_set(name: &str, capacity_log2: i8, creator: &str) -> Vec<(String, Vec<u8>)> {
    let mut access = MemorySourceAccess::default();
    access.insert(SourceId(0), 1, fft_input().into());
    let plan = CreationPlan::build(
        Arc::new(access),
        &[CreationSource {
            name: "input.bin".to_owned(),
            source: SourceId(0),
        }],
        CreationOptions {
            block_size: 1024,
            recovery_count: 1,
            codec: CreationCodec::Fft {
                capacity_log2,
                interleave: 0,
            },
            creator: creator.to_owned(),
            ..CreationOptions::default()
        },
    )
    .unwrap();
    // One recovery block is labelled with no field, whatever the capacity.
    assert_eq!(
        plan.requirements().field,
        par3_rs::packet::GaloisField {
            size: 0,
            generator: 0
        }
    );
    let tree = common::TempTree::new(&format!("single-recovery-{name}"));
    plan.execute(&tree.path().join(name), tree.path())
        .unwrap()
        .iter()
        .map(|path| {
            (
                path.file_name().unwrap().to_string_lossy().into_owned(),
                std::fs::read(path).unwrap(),
            )
        })
        .collect()
}

/// Verify `carriers` against the intact input, then against the input with
/// one block damaged, and repair that block.
fn verify_and_repair_one_block(name: &str, carriers: &[Vec<u8>]) {
    let original = fft_input();
    let id = common::scan(&carriers[0])[0].1.input_set_id();
    for damaged_block in [None, Some(6usize)] {
        let mut input = original.clone();
        if let Some(block) = damaged_block {
            input[block * 1024 + 17] ^= 0x40;
        }
        let mut access = MemorySourceAccess::default();
        access.insert(SourceId(1), 1, input.into());
        let options = par3_rs::runtime::ExecutionOptions::default();
        let mut session =
            par3_rs::Par3RepairSession::new(id, Arc::new(access), options.clone()).unwrap();
        session.bind_file("input.bin", SourceId(1)).unwrap();
        for carrier in carriers {
            let mut source = MemorySourceAccess::default();
            source.insert(SourceId(99), 1, carrier.clone().into());
            let mut scanner = PacketScanner::new(
                Arc::new(source),
                SourceId(99),
                options.clone(),
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
        let assessment = session.assess().unwrap();
        let Some(block) = damaged_block else {
            assert_eq!(
                assessment.status,
                par3_rs::session::RepairStatus::Complete,
                "{name}"
            );
            continue;
        };
        assert_eq!(
            assessment.status,
            par3_rs::session::RepairStatus::Ready,
            "{name}"
        );
        assert_eq!(assessment.lost_blocks, [block as u64], "{name}");
        let output = common::TempTree::new(&format!("single-recovery-repair-{name}"));
        assert_eq!(
            session
                .repair(output.path(), false)
                .unwrap()
                .reconstructed_blocks,
            1,
            "{name}"
        );
        assert_eq!(
            std::fs::read(output.path().join("input.bin")).unwrap(),
            original,
            "{name}"
        );
    }
}

/// The reference writes a set with one recovery block under a wider FFT
/// capacity (`-c1 -cm4`) with no field in its Start packet. The block is not
/// the XOR of the inputs but the first transform parity of the declared
/// capacity: here it equals recovery block 0 of the reference's capacity-16
/// fixture made from the same input. Such a set verifies and repairs.
#[test]
fn a_single_recovery_block_under_a_wider_fft_capacity_records_no_field_and_repairs() {
    let reference_parity = common::packets_of(&common::advanced_fixture("fft.vol0+1.par3"))
        .into_iter()
        .find_map(|packet| match packet.body() {
            par3_rs::PacketBody::RecoveryData(body) => Some(body.data.clone()),
            _ => None,
        })
        .expect("reference recovery block 0");
    for capacity_log2 in [2, 4] {
        let set = single_recovery_fft_set("wide", capacity_log2, "par3-rs test");
        let names: Vec<&str> = set.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, ["wide.par3", "wide.vol0+1.par3"]);
        let recovery = common::packets_of(&set[1].1)
            .into_iter()
            .find_map(|packet| match packet.body() {
                par3_rs::PacketBody::RecoveryData(body) => Some(body.data.clone()),
                _ => None,
            })
            .expect("recovery block 0");
        let xor = fft_input()
            .chunks(1024)
            .fold(vec![0u8; 1024], |mut sum, block| {
                sum.iter_mut()
                    .zip(block)
                    .for_each(|(sum, byte)| *sum ^= byte);
                sum
            });
        assert_ne!(recovery, xor);
        if capacity_log2 == 4 {
            assert_eq!(recovery, reference_parity);
        }
        let carriers: Vec<Vec<u8>> = set.into_iter().map(|(_, bytes)| bytes).collect();
        verify_and_repair_one_block(&format!("capacity-{capacity_log2}"), &carriers);
    }
    // Without recovery blocks the reference (`par3 c -e8 -c0`) records the
    // geometry's field, even at a capacity of one.
    let mut access = MemorySourceAccess::default();
    access.insert(SourceId(0), 1, fft_input().into());
    let plan = CreationPlan::build(
        Arc::new(access),
        &[CreationSource {
            name: "input.bin".to_owned(),
            source: SourceId(0),
        }],
        CreationOptions {
            block_size: 1024,
            recovery_count: 0,
            codec: CreationCodec::Fft {
                capacity_log2: 0,
                interleave: 0,
            },
            ..CreationOptions::default()
        },
    )
    .unwrap();
    assert_eq!(
        plan.requirements().field,
        par3_rs::packet::GaloisField {
            size: 1,
            generator: 0x1d
        }
    );
}

/// A set the reference made with `par3 c -s1024 -e8 -c1 -cm4` over the FFT
/// input is accepted, verified and repaired, and the streaming engine
/// recreates it byte for byte. The carriers are not in the pinned corpus yet,
/// so the run names the directory holding `xor4.par3` and `xor4.vol0+1.par3`.
#[test]
#[ignore = "reads reference carriers from an explicitly configured pinned-reference run"]
fn a_reference_single_recovery_set_under_a_wider_capacity_is_accepted() {
    let directory = std::path::PathBuf::from(
        std::env::var_os("PAR3_REFERENCE_XOR4_DIR").expect("explicit reference directory"),
    );
    let names = ["xor4.par3", "xor4.vol0+1.par3"];
    let reference: Vec<Vec<u8>> = names
        .iter()
        .map(|name| std::fs::read(directory.join(name)).unwrap())
        .collect();
    let creator = common::packets_of(&reference[0])
        .into_iter()
        .find_map(|packet| match packet.body() {
            par3_rs::PacketBody::Creator(body) => Some(body.text().into_owned()),
            _ => None,
        })
        .expect("a Creator packet");
    verify_and_repair_one_block("reference-xor4", &reference);
    let ours = single_recovery_fft_set("xor4", 2, &creator);
    for ((name, ours), (expected, theirs)) in ours.iter().zip(names.iter().zip(&reference)) {
        assert_eq!(name, expected);
        common::assert_block_eq(ours, theirs, name);
    }
}

/// Four inputs of 600, 500, 300 and 90 bytes under 1000-byte blocks, distinct
/// so that nothing deduplicates.
fn packing_inputs() -> Vec<(String, Vec<u8>)> {
    [(600, 3), (500, 5), (300, 7), (90, 11)]
        .into_iter()
        .enumerate()
        .map(|(index, (size, seed))| {
            let number = index + 1;
            (
                format!("t{number}.bin"),
                (0..size)
                    .map(|i| ((i * seed + number * 31 + i / 13) % 256) as u8)
                    .collect(),
            )
        })
        .collect()
}

/// Write the packing inputs as the reference's `par3 c -s1000 -c1 -d<mode>`
/// does and return each carrier by name.
fn packing_set(deduplication: Deduplication, creator: &str) -> Vec<(String, Vec<u8>)> {
    let mut access = MemorySourceAccess::default();
    let mut sources = Vec::new();
    for (index, (name, bytes)) in packing_inputs().into_iter().enumerate() {
        access.insert(SourceId(index as u64), 1, bytes.into());
        sources.push(CreationSource {
            name,
            source: SourceId(index as u64),
        });
    }
    let plan = CreationPlan::build(
        Arc::new(access),
        &sources,
        CreationOptions {
            block_size: 1000,
            recovery_count: 1,
            deduplication,
            creator: creator.to_owned(),
            ..CreationOptions::default()
        },
    )
    .unwrap();
    let tree = common::TempTree::new(&format!("packing-{deduplication:?}"));
    plan.execute(&tree.path().join("pack"), tree.path())
        .unwrap()
        .iter()
        .map(|path| {
            (
                path.file_name().unwrap().to_string_lossy().into_owned(),
                std::fs::read(path).unwrap(),
            )
        })
        .collect()
}

/// Without deduplication the reference packs a tail behind the first open
/// tail in placement order; with it, into the first block by index with room.
/// Stored longest tail first, the 90-byte tail meets block 1 (500 bytes used,
/// its tail placed second) and block 0 (600 + 300 used, its open tail placed
/// third): `-d0` picks block 1, `-d1` and `-d2` pick block 0.
#[test]
fn deduplicating_modes_pack_a_tail_into_the_first_block_by_index_with_room() {
    for (deduplication, expected) in [
        (Deduplication::None, (1, 500)),
        (Deduplication::Aligned, (0, 900)),
        (Deduplication::Sliding, (0, 900)),
    ] {
        let set = packing_set(deduplication, "par3-rs test");
        let placed = common::packets_of(&set[0].1)
            .into_iter()
            .find_map(|packet| match packet.body() {
                par3_rs::PacketBody::File(file) if file.name == "t4.bin" => {
                    match &file.chunks[..] {
                        [
                            par3_rs::packet::ChunkDescription::Protected {
                                tail:
                                    par3_rs::packet::ChunkTail::Described {
                                        block_index,
                                        offset,
                                        ..
                                    },
                                ..
                            },
                        ] => Some((*block_index, *offset)),
                        chunks => panic!("unexpected chunks {chunks:?}"),
                    }
                }
                _ => None,
            })
            .expect("t4.bin");
        assert_eq!(placed, expected, "{deduplication:?}");
    }
}

/// The reference's `par3 c -s1000 -c1 -d<n>` sets over the packing inputs are
/// recreated byte for byte at every deduplication mode. The run names a
/// directory holding `d0/`, `d1/` and `d2/`, each with `pack.par3` and
/// `pack.vol0+1.par3`.
#[test]
#[ignore = "reads reference carriers from an explicitly configured pinned-reference run"]
fn reference_packing_sets_are_recreated_at_every_deduplication_mode() {
    let directory = std::path::PathBuf::from(
        std::env::var_os("PAR3_REFERENCE_PACKING_DIR").expect("explicit reference directory"),
    );
    for (mode, deduplication) in [
        ("d0", Deduplication::None),
        ("d1", Deduplication::Aligned),
        ("d2", Deduplication::Sliding),
    ] {
        let names = ["pack.par3", "pack.vol0+1.par3"];
        let reference: Vec<Vec<u8>> = names
            .iter()
            .map(|name| std::fs::read(directory.join(mode).join(name)).unwrap())
            .collect();
        let creator = common::packets_of(&reference[0])
            .into_iter()
            .find_map(|packet| match packet.body() {
                par3_rs::PacketBody::Creator(body) => Some(body.text().into_owned()),
                _ => None,
            })
            .expect("a Creator packet");
        let ours = packing_set(deduplication, &creator);
        assert_eq!(ours.len(), names.len(), "{mode}");
        for ((name, ours), (expected, theirs)) in ours.iter().zip(names.iter().zip(&reference)) {
            assert_eq!(name, expected, "{mode}");
            common::assert_block_eq(ours, theirs, &format!("{mode}/{name}"));
        }
    }
}

/// Create the reference's `par3 c -s1024 -e8 -i1 -c2 -D` set over the FFT
/// input with the streaming engine and return each carrier by name.
fn interleaved_data_set(creator: &str, capacity_log2: i8) -> Vec<(String, Vec<u8>)> {
    let mut access = MemorySourceAccess::default();
    access.insert(SourceId(0), 1, fft_input().into());
    let plan = CreationPlan::build(
        Arc::new(access),
        &[CreationSource {
            name: "input.bin".to_owned(),
            source: SourceId(0),
        }],
        CreationOptions {
            block_size: 1024,
            recovery_count: 2,
            codec: CreationCodec::Fft {
                capacity_log2,
                interleave: 1,
            },
            store_data: true,
            creator: creator.to_owned(),
            ..CreationOptions::default()
        },
    )
    .unwrap();
    let tree = common::TempTree::new("interleaved-data");
    plan.execute(&tree.path().join("ileave"), tree.path())
        .unwrap()
        .iter()
        .map(|path| {
            (
                path.file_name().unwrap().to_string_lossy().into_owned(),
                std::fs::read(path).unwrap(),
            )
        })
        .collect()
}

/// The reference's interleaved data volumes (`par3 c -s1024 -e8 -i1 -c2 -D`
/// over the FFT input) differ from the engine's exactly as recorded: the index
/// and recovery volume are byte for byte the same, the reference counts data
/// volumes in rows of cohort blocks where the engine counts blocks singly, and
/// it cuts the tail block's Data packet to the bytes in use. The run names the
/// directory holding the reference's `ileave*.par3` carriers.
#[test]
#[ignore = "reads reference carriers from an explicitly configured pinned-reference run"]
fn reference_interleaved_data_volumes_differ_only_as_recorded() {
    let directory = std::path::PathBuf::from(
        std::env::var_os("PAR3_REFERENCE_INTERLEAVED_DATA_DIR")
            .expect("explicit reference directory"),
    );
    let read = |name: &str| std::fs::read(directory.join(name)).unwrap();
    let index = read("ileave.par3");
    let (mut creator, mut fft) = (None, None);
    for packet in common::packets_of(&index) {
        match packet.body() {
            par3_rs::PacketBody::Creator(body) => creator = Some(body.text().into_owned()),
            par3_rs::PacketBody::FftMatrix(body) => {
                assert_eq!(body.interleave, 1);
                fft = Some(body.max_recovery_blocks_log2);
            }
            _ => {}
        }
    }
    let ours = interleaved_data_set(&creator.expect("a Creator packet"), fft.expect("FFT"));
    let ours: BTreeMap<&str, &[u8]> = ours
        .iter()
        .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
        .collect();
    for name in ["ileave.par3", "ileave.vol0+1.par3"] {
        common::assert_block_eq(ours[name], &read(name), name);
    }
    // Data blocks per volume: the reference's `partF+N` counts rows of two
    // blocks, the engine's counts blocks.
    let data = |bytes: &[u8]| -> Vec<(u64, Vec<u8>)> {
        common::packets_of(bytes)
            .into_iter()
            .filter_map(|packet| match packet.body() {
                par3_rs::PacketBody::Data(body) => Some((body.block_index, body.data.clone())),
                _ => None,
            })
            .collect()
    };
    let theirs_layout = [
        ("ileave.part0+1.par3", 0..2),
        ("ileave.part1+2.par3", 2..6),
        ("ileave.part3+4.par3", 6..14),
    ];
    let ours_layout = [
        ("ileave.part0+1.par3", 0..1),
        ("ileave.part1+2.par3", 1..3),
        ("ileave.part3+4.par3", 3..7),
        ("ileave.part7+7.par3", 7..14),
    ];
    assert_eq!(ours.len(), 2 + ours_layout.len());
    let mut theirs_blocks = Vec::new();
    for (name, blocks) in theirs_layout {
        let packets = data(&read(name));
        assert_eq!(
            packets.iter().map(|(index, _)| *index).collect::<Vec<_>>(),
            blocks.collect::<Vec<_>>(),
            "{name}"
        );
        theirs_blocks.extend(packets);
    }
    assert!(!directory.join("ileave.part7+7.par3").exists());
    let mut ours_blocks = Vec::new();
    for (name, blocks) in ours_layout {
        let packets = data(ours[name]);
        assert_eq!(
            packets.iter().map(|(index, _)| *index).collect::<Vec<_>>(),
            blocks.collect::<Vec<_>>(),
            "{name}"
        );
        ours_blocks.extend(packets);
    }
    // The same bytes, but the tail block: 14000 bytes leave 688 in block 13,
    // which the reference stores cut and the engine stores whole.
    let tail = 14000 % 1024;
    assert_eq!(ours_blocks.len(), theirs_blocks.len());
    for ((index, ours), (_, theirs)) in ours_blocks.iter().zip(&theirs_blocks) {
        if *index == 13 {
            assert_eq!(theirs.len(), tail);
            assert_eq!(&ours[..tail], &theirs[..]);
            assert!(ours[tail..].iter().all(|&byte| byte == 0));
        } else {
            assert_eq!(ours, theirs, "block {index}");
        }
    }
}

/// Sources that make a fused plan: past the planning pool's threshold, with
/// tails that pack at odd and even offsets, inline tails, a file of whole
/// blocks and empty files.
fn fused_inputs(block: u64) -> Vec<(&'static str, u64)> {
    vec![
        ("m/a.bin", (4 << 20) + 701),
        ("b.bin", 501),
        ("c.bin", (3 << 20) + 300),
        ("d.bin", 201),
        ("e.bin", 41),
        ("f.bin", 12 * block),
        ("h.bin", (1 << 20) + 1203),
        ("g.bin", 10),
        ("x/e.bin", 0),
        ("y/e.bin", 0),
    ]
}

/// Without deduplication a plan of 8 MiB or more with a worker pool takes
/// the planning hashes and the Cauchy rows from one read of every source. Its carriers are the
/// ones the same plan writes when the budget leaves no room to fuse and the
/// encode reads the sources a second time, and for a GF(2^16) set the ones
/// `create` writes. (`create` writes every Cauchy set in GF(2^16); a plan of
/// at most 256 blocks takes GF(2^8).)
#[test]
fn a_fused_plan_reads_each_source_once_and_writes_the_serial_carriers() {
    use par3_rs::create::{CreateOptions, InputSpec, RecoveryAmount, create};

    // 1 KiB blocks make GF(2^16) sets and the larger ones GF(2^8) sets. Odd
    // tails pack at odd offsets, so two tails share a GF(2^16) symbol.
    // A squeezed budget leaves the rows of the larger blocks no room beside a
    // group of blocks, so the encode reads the sources again; small blocks
    // always fuse.
    for (block, recovery, squeezed) in [
        (1024u64, 6u64, None),
        (1026, 4, None),
        (65_536, 9, Some(1536 << 10)),
        (40_001, 3, Some(1 << 20)),
    ] {
        let inputs = fused_inputs(block);
        let tree = common::TempTree::new(&format!("fused-{block}"));
        let mut total = 0;
        for (index, (name, length)) in inputs.iter().enumerate() {
            let bytes: Vec<u8> = (0..*length)
                .map(|i| ((i * 31 + i / 7 + index as u64 * 101) % 251) as u8)
                .collect();
            tree.write(&format!("in/{name}"), &bytes);
            total += length;
        }
        let base = tree.path().join("in");
        let creator = "fused creator";
        let run = |workers: usize, memory: Option<usize>| {
            let case = format!("{block}-byte blocks, {workers} workers, {memory:?}");
            let mut options = CreationOptions {
                block_size: block,
                recovery_count: recovery,
                creator: creator.to_owned(),
                ..CreationOptions::default()
            };
            options.execution.workers = workers;
            if let Some(memory) = memory {
                options.execution.memory = par3_rs::runtime::MemoryBudget::new(memory);
            }
            let execution = options.execution.clone();
            let mut access = DiskSourceAccess::with_options(execution.clone());
            let mut sources = Vec::new();
            for (index, (name, _)) in inputs.iter().enumerate() {
                let id = SourceId(index as u64);
                access.insert(id, base.join(name));
                sources.push(CreationSource {
                    name: (*name).to_owned(),
                    source: id,
                });
            }
            let plan = CreationPlan::build(Arc::new(access), &sources, options).unwrap();
            let planned = execution.diagnostics.source_io();
            let out = tree
                .path()
                .join(format!("plan-{workers}-{}", memory.is_some()));
            std::fs::create_dir_all(&out).unwrap();
            let written: Vec<Vec<u8>> = plan
                .execute(&out.join("set"), tree.path())
                .unwrap()
                .iter()
                .map(|path| std::fs::read(path).unwrap())
                .collect();
            let executed = execution.diagnostics.source_io();
            assert!(
                execution.memory.peak() <= execution.memory.limit(),
                "{case}"
            );
            // Planning reads every source byte once. Fused, the encode reads
            // nothing more; squeezed, it reads them all again.
            assert_eq!(planned.read_bytes, total, "{case}");
            let encode_reads = executed.read_bytes - planned.read_bytes;
            if memory.is_none() && workers > 1 {
                assert_eq!(encode_reads, 0, "{case}: the encode read the sources");
                assert_eq!(executed.read_calls, planned.read_calls, "{case}");
            } else {
                // One worker, or no room, keeps the serial walk. Inline
                // tails are in no block, so the encode skips them.
                let inline: u64 = inputs
                    .iter()
                    .map(|(_, length)| length % block)
                    .filter(|tail| *tail < 40)
                    .sum();
                assert_eq!(
                    encode_reads,
                    total - inline,
                    "{case}: the squeezed plan fused"
                );
            }
            (case, written, plan.requirements().field.size)
        };
        let expected = match squeezed {
            Some(memory) => {
                let (_, serial, field) = run(2, Some(memory));
                assert_eq!(field, 1, "{block}-byte blocks");
                let (_, pooled, _) = run(4, Some(memory));
                assert!(
                    pooled == serial,
                    "{block}-byte blocks: squeezed pools differ"
                );
                serial
            }
            None => {
                let files: Vec<std::path::PathBuf> = inputs
                    .iter()
                    .map(|(name, _)| std::path::PathBuf::from(name))
                    .collect();
                std::fs::create_dir_all(tree.path().join("create")).unwrap();
                create(
                    &InputSpec::new(&base, &files),
                    &tree.path().join("create/set.par3"),
                    &CreateOptions::default()
                        .with_block_size(block)
                        .with_recovery(RecoveryAmount::Blocks(recovery))
                        .with_creator(creator),
                )
                .unwrap()
                .files_written
                .iter()
                .map(|path| std::fs::read(path).unwrap())
                .collect()
            }
        };
        for workers in [1, 2, 4] {
            let (case, written, _) = run(workers, None);
            assert!(written == expected, "{case}: not the serial carriers");
        }
    }
}
