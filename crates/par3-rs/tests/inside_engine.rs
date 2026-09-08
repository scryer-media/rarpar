//! Unmodified reference insertion layouts and their original archives.
mod common;

use par3_rs::inside::{ContainerKind, ContainerLayout, ContainerLimits};
use par3_rs::runtime::{EngineError, ExecutionOptions, MemoryBudget};
use par3_rs::source::{MemorySourceAccess, SourceId};

#[test]
#[ignore = "requires an explicit new output directory for the official reference"]
fn export_inserted_archives_for_reference_validation() {
    use par3_rs::creation::CreationOptions;
    use par3_rs::inside::InsertionPlan;
    use std::sync::Arc;

    let root = std::path::PathBuf::from(
        std::env::var_os("PAR3_INSIDE_ORACLE_OUTPUT").expect("PAR3_INSIDE_ORACLE_OUTPUT"),
    );
    assert!(root.is_absolute());
    std::fs::create_dir(&root).unwrap();
    for (kind, original, _) in cases() {
        let name = match kind {
            ContainerKind::Zip => "inside.zip",
            ContainerKind::Zip64 => "inside64.zip",
            ContainerKind::SevenZip => "inside.7z",
        };
        let scratch = root.join(format!("scratch-{kind:?}"));
        std::fs::create_dir(&scratch).unwrap();
        let mut access = MemorySourceAccess::default();
        access.insert(SourceId(7), 1, original.into());
        let plan = InsertionPlan::build(
            Arc::new(access),
            SourceId(7),
            name,
            CreationOptions {
                block_size: if kind == ContainerKind::Zip64 {
                    32768
                } else {
                    128
                },
                recovery_count: 4,
                ..CreationOptions::default()
            },
            &ContainerLimits::default(),
        )
        .unwrap();
        plan.execute(&root.join(name), &scratch).unwrap();
    }
}

#[test]
fn captured_self_repair_restores_official_archives_with_missing_packets() {
    use par3_rs::ingest::{PacketScanner, ScanEvent};
    use par3_rs::inside::SelfRepairPlan;
    use par3_rs::session::Par3RepairSession;
    use std::sync::Arc;

    for (kind, original, inserted) in cases() {
        let mut options = ExecutionOptions::default();
        options.workers = 1;
        let mut clean = MemorySourceAccess::default();
        clean.insert(SourceId(1), 1, inserted.into());
        let mut scanner = PacketScanner::new(
            Arc::new(clean),
            SourceId(1),
            options.clone(),
            par3_rs::ScanLimits::default(),
        )
        .unwrap();
        let mut packets = Vec::new();
        loop {
            match scanner.poll().unwrap() {
                ScanEvent::Packet(packet) => packets.push(packet),
                ScanEvent::End => break,
                ScanEvent::NeedData { .. } => panic!("complete reference archive"),
            }
        }
        for damage_protected in [false, true] {
            let mut damaged = inserted.to_vec();
            // Only regenerated protected input is damaged; PAR3 packet bytes
            // remain official. Packet loss is represented by an unavailable range.
            if damage_protected {
                damaged[100] ^= 0x80;
            }
            let omitted = if damage_protected {
                packets
                    .iter()
                    .find(|packet| packet.metadata().is_some())
                    .unwrap()
            } else {
                packets
                    .iter()
                    .rev()
                    .find(|packet| packet.payload().is_some())
                    .unwrap()
            };
            let origin = omitted.origin();
            let hole = origin.offset..origin.offset + origin.length;
            let access = Arc::new(HoleyArchive {
                bytes: damaged,
                hole,
            });
            let mut session =
                Par3RepairSession::new(packets[0].input_set_id(), access.clone(), options.clone())
                    .unwrap();
            // Preserve an authenticated manifest before the packet becomes
            // unavailable, but never admit its old payload into current analysis.
            for packet in packets.iter().filter(|packet| packet.metadata().is_some()) {
                session.merge(packet.clone()).unwrap();
            }
            let plan = SelfRepairPlan::capture(&mut session, &packets, ContainerLimits::default())
                .unwrap();
            let layout = session.layout().unwrap().unwrap();
            session
                .bind_file(&layout.files()[0].path, SourceId(1))
                .unwrap();
            assert!(original.len() > 100);
            let mut current = PacketScanner::new(
                access,
                SourceId(1),
                options.clone(),
                par3_rs::ScanLimits::default(),
            )
            .unwrap();
            loop {
                match current.poll().unwrap() {
                    ScanEvent::Packet(packet) => {
                        session.merge(packet).unwrap();
                    }
                    ScanEvent::NeedData { offset } if offset < origin.offset + origin.length => {
                        current.seek(origin.offset + origin.length).unwrap();
                    }
                    ScanEvent::End | ScanEvent::NeedData { .. } => break,
                }
            }
            let tree = common::TempTree::new(&format!("self-repair-{kind:?}-{damage_protected}"));
            let output = tree.path().join("repaired.archive");
            let scratch = tree.path().join("scratch");
            std::fs::create_dir(&scratch).unwrap();
            let assessment = session.assess().unwrap();
            assert!(
                matches!(
                    assessment.status,
                    par3_rs::session::RepairStatus::Complete
                        | par3_rs::session::RepairStatus::Ready
                ),
                "{kind:?} damage={damage_protected}: {assessment:?}"
            );
            let report = plan.execute(&mut session, &output, &scratch).unwrap();
            assert_eq!(report.kind, kind);
            assert_eq!(report.reconstructed_blocks != 0, damage_protected);
            assert_eq!(report.recovery_packets, usize::from(!damage_protected));
            assert_eq!(std::fs::read(&output).unwrap(), inserted);
            assert_eq!(std::fs::read_dir(&scratch).unwrap().count(), 0);
            assert!(matches!(
                plan.execute(&mut session, &output, &scratch),
                Err(EngineError::Io(_))
            ));
            assert!(
                SelfRepairPlan::capture(
                    &mut session,
                    &packets[..packets.len() - 1],
                    ContainerLimits::default()
                )
                .is_err()
            );
        }
    }
}

struct HoleyArchive {
    bytes: Vec<u8>,
    hole: std::ops::Range<u64>,
}
impl par3_rs::source::SourceAccess for HoleyArchive {
    fn snapshot(&self, _: SourceId) -> std::io::Result<Option<par3_rs::source::SourceSnapshot>> {
        Ok(Some(par3_rs::source::SourceSnapshot {
            len: self.bytes.len() as u64,
            generation: 2,
        }))
    }
    fn read_at(&self, _: SourceId, offset: u64, out: &mut [u8]) -> std::io::Result<usize> {
        let end = if offset < self.hole.start {
            self.hole.start
        } else if offset < self.hole.end {
            return Ok(0);
        } else {
            self.bytes.len() as u64
        };
        let count = end.saturating_sub(offset).min(out.len() as u64) as usize;
        if count != 0 {
            out[..count].copy_from_slice(&self.bytes[offset as usize..offset as usize + count]);
        }
        Ok(count)
    }
    fn next_available(
        &self,
        _: SourceId,
        offset: u64,
    ) -> std::io::Result<Option<std::ops::Range<u64>>> {
        let start = if self.hole.contains(&offset) {
            self.hole.end
        } else {
            offset
        };
        let end = if start < self.hole.start {
            self.hole.start
        } else {
            self.bytes.len() as u64
        };
        Ok((start < end).then_some(start..end))
    }
}

fn cases() -> [(ContainerKind, &'static [u8], &'static [u8]); 3] {
    [
        (
            ContainerKind::Zip,
            include_bytes!("fixtures/advanced/inside-original.zip"),
            include_bytes!("fixtures/advanced/inside.zip"),
        ),
        (
            ContainerKind::Zip64,
            include_bytes!("fixtures/advanced/inside64-original.zip"),
            include_bytes!("fixtures/advanced/inside64.zip"),
        ),
        (
            ContainerKind::SevenZip,
            include_bytes!("fixtures/advanced/inside-original.7z"),
            include_bytes!("fixtures/advanced/inside.7z"),
        ),
    ]
}

#[test]
fn reference_containers_preserve_original_bytes_and_duplicate_zip_footers() {
    for (kind, original, inserted) in cases() {
        let mut access = MemorySourceAccess::default();
        access.insert(SourceId(1), 7, original.into());
        let options = ExecutionOptions::default();
        let layout =
            ContainerLayout::inspect(&access, SourceId(1), &options, &ContainerLimits::default())
                .unwrap();
        assert_eq!(layout.kind(), kind);
        assert_eq!(&inserted[..original.len()], original);
        let footer = &original[layout.footer().start as usize..];
        assert_eq!(&inserted[inserted.len() - footer.len()..], footer);
        let packets = common::packets_of(inserted);
        let sets = par3_rs::Par3Set::from_packets(packets).unwrap();
        assert_eq!(sets.len(), 1);
        let file = &sets[0].files()[0];
        assert_eq!(file.size(), inserted.len() as u64);
        assert_eq!(
            file.chunks()
                .iter()
                .filter(|chunk| !chunk.is_protected())
                .count(),
            1
        );
        if kind != ContainerKind::SevenZip {
            assert_eq!(file.chunks().len(), 4);
            assert_eq!(file.chunks()[1], file.chunks()[3]);
        } else {
            assert_eq!(file.chunks().len(), 2);
        }
        access.insert(SourceId(2), 1, inserted.into());
        let protected =
            std::sync::Arc::new(par3_rs::layout::BlockLayout::new(&sets[0], &options).unwrap());
        let proof =
            par3_rs::evidence::verify_source(protected, 0, &access, SourceId(2), &options).unwrap();
        assert!(
            proof.protected_complete(),
            "official protected-chunk file hash must verify"
        );
        drop(proof);
        assert!(matches!(
            ContainerLayout::inspect(&access, SourceId(2), &options, &ContainerLimits::default()),
            Err(EngineError::Unsupported(_))
        ));
        assert_eq!(options.memory.used(), 0);
    }
}

#[test]
fn inspection_refuses_trailing_data_damage_and_exhausted_budgets() {
    for (_, original, _) in cases() {
        let mut access = MemorySourceAccess::default();
        let mut trailing = original.to_vec();
        trailing.extend_from_slice(b"unknown trailing bytes");
        access.insert(SourceId(1), 1, trailing.into());
        let mut options = ExecutionOptions::default();
        assert!(matches!(
            ContainerLayout::inspect(&access, SourceId(1), &options, &ContainerLimits::default()),
            Err(EngineError::Unsupported(_))
        ));
        access.insert(SourceId(1), 2, original.into());
        let limits = ContainerLimits {
            entries: 0,
            read_bytes: 16,
        };
        assert!(matches!(
            ContainerLayout::inspect(&access, SourceId(1), &options, &limits),
            Err(EngineError::ResourceLimit(_))
        ));
        options.memory = MemoryBudget::new(16);
        assert!(matches!(
            ContainerLayout::inspect(&access, SourceId(1), &options, &ContainerLimits::default()),
            Err(EngineError::ResourceLimit(_))
        ));
        options.cancel.cancel();
        assert!(matches!(
            ContainerLayout::inspect(&access, SourceId(1), &options, &ContainerLimits::default()),
            Err(EngineError::Cancelled)
        ));
    }
}

#[test]
fn staged_insertion_preserves_members_and_authenticates_embedded_layout() {
    use par3_rs::creation::CreationOptions;
    use par3_rs::inside::InsertionPlan;
    use std::sync::Arc;

    for (kind, original, _) in cases() {
        let mut access = MemorySourceAccess::default();
        access.insert(SourceId(7), 1, original.into());
        let name = if kind == ContainerKind::SevenZip {
            "archive.7z"
        } else {
            "archive.zip"
        };
        let options = CreationOptions {
            block_size: if kind == ContainerKind::Zip64 {
                32768
            } else {
                128
            },
            recovery_count: 4,
            ..CreationOptions::default()
        };
        let plan = InsertionPlan::build(
            Arc::new(access),
            SourceId(7),
            name,
            options,
            &ContainerLimits::default(),
        )
        .unwrap();
        let tree = common::TempTree::new(&format!("insert-{kind:?}"));
        let output = tree.path().join(name);
        let scratch = tree.path().join("scratch");
        std::fs::create_dir(&scratch).unwrap();
        plan.execute(&output, &scratch).unwrap();
        let inserted = std::fs::read(&output).unwrap();
        assert_eq!(inserted.len() as u64, plan.requirements().output_bytes);
        assert_eq!(&inserted[..original.len()], original);
        let packets = common::packets_of(&inserted);
        let sets = par3_rs::Par3Set::from_packets(packets).unwrap();
        assert_eq!(sets.len(), 1);
        assert_eq!(sets[0].files()[0].size(), inserted.len() as u64);
        assert_eq!(sets[0].recovery_blocks().len(), 4);
        assert!(
            matches!(plan.execute(&output, &scratch), Err(EngineError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists)
        );
        assert_eq!(std::fs::read(&output).unwrap(), inserted);
        assert_eq!(std::fs::read_dir(&scratch).unwrap().count(), 0);
    }
}
