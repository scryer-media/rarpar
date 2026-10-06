//! Advanced creation through public APIs, preserving the legacy creation tests.
mod common;

use par3_rs::PathRule;
use par3_rs::creation::{
    CreationCodec, CreationOptions, CreationPlan, CreationSource, Deduplication, VolumeLayout,
};
use par3_rs::ingest::{PacketScanner, ScanEvent};
use par3_rs::runtime::EngineError;
use par3_rs::source::{DiskSourceAccess, MemorySourceAccess, SourceId};
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

            // Resident rows: only carriers are written, and the carrier
            // re-scan is the only file read, so no scratch byte moves.
            assert_eq!(
                resident.file_io.write_bytes, resident.output_bytes,
                "{case}"
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
            assert_eq!(spooled.syncs, carriers + 1, "{case}");
            assert!(spooled.resident_peak < scratch, "{case}");
        }
    }
}
