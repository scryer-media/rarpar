//! Unmodified reference insertion layouts and their original archives.
mod common;

use par3_rs::inside::{ContainerKind, ContainerLayout, ContainerLimits};
use par3_rs::runtime::{EngineError, ExecutionOptions, MemoryBudget};
use par3_rs::source::{MemorySourceAccess, SourceId};

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
