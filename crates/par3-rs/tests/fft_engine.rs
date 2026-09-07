//! Interoperability with unmodified pinned-reference FFT packets.
mod common;

use par3_rs::fft::{FftCodec, FftGeometry, FftInput};
use par3_rs::packet::PacketBody;
use par3_rs::runtime::ExecutionOptions;
use std::collections::BTreeMap;

const CARRIERS: &[&[u8]] = &[
    include_bytes!("fixtures/advanced/fft.par3"),
    include_bytes!("fixtures/advanced/fft.vol0+1.par3"),
    include_bytes!("fixtures/advanced/fft.vol1+2.par3"),
    include_bytes!("fixtures/advanced/fft.vol3+4.par3"),
    include_bytes!("fixtures/advanced/fft.vol7+1.par3"),
];

fn inputs() -> Vec<Vec<u8>> {
    let mut data: Vec<u8> = (0..14000)
        .map(|i| ((i * 73 + i / 29) % 256) as u8)
        .collect();
    data.resize(14 * 1024, 0);
    data.chunks_exact(1024).map(<[u8]>::to_vec).collect()
}

#[test]
fn gf16_fft_encoding_and_decoding_match_the_reference() {
    let names = [
        "fft16.par3",
        "fft16.vol00+1.par3",
        "fft16.vol01+2.par3",
        "fft16.vol03+4.par3",
        "fft16.vol07+8.par3",
        "fft16.vol15+1.par3",
    ];
    let mut recovery = BTreeMap::new();
    for name in names {
        let bytes = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/advanced")
                .join(name),
        )
        .unwrap();
        for (_, packet) in common::scan(&bytes) {
            if let PacketBody::RecoveryData(row) = packet.body() {
                let mut bytes = row.data.clone();
                bytes.resize(64, 0);
                recovery.insert(row.recovery_block_index as usize, bytes);
            }
        }
    }
    let mut data: Vec<u8> = (0..14000)
        .map(|i| ((i * 73 + i / 29) % 256) as u8)
        .collect();
    data.resize(219 * 64, 0);
    let input: Vec<_> = data.chunks_exact(64).collect();
    let mut options = ExecutionOptions::default();
    options.stripe_bytes = 17;
    let codec = FftCodec::new(FftGeometry::new(219, 6).unwrap(), options).unwrap();
    let mut actual = vec![vec![0; 64]; 16];
    codec
        .encode(
            64,
            0,
            16,
            |index, offset, out| {
                out.copy_from_slice(&input[index][offset as usize..offset as usize + out.len()]);
                Ok(())
            },
            |index, offset, bytes| {
                actual[index][offset as usize..offset as usize + bytes.len()]
                    .copy_from_slice(bytes);
                Ok(())
            },
        )
        .unwrap();
    for (&index, expected) in &recovery {
        assert_eq!(&actual[index], expected, "recovery {index}");
    }
    let lost = [0, 7, 31, 218];
    let mut rebuilt = vec![vec![0; 64]; lost.len()];
    codec
        .decode(
            64,
            &lost,
            &[0, 5, 9, 15],
            |row, offset, out| {
                let bytes = match row {
                    FftInput::Original(index) => input[index],
                    FftInput::Recovery(index) => &recovery[&index],
                };
                out.copy_from_slice(&bytes[offset as usize..offset as usize + out.len()]);
                Ok(())
            },
            |index, offset, bytes| {
                rebuilt[lost.iter().position(|lost| *lost == index).unwrap()]
                    [offset as usize..offset as usize + bytes.len()]
                    .copy_from_slice(bytes);
                Ok(())
            },
        )
        .unwrap();
    for (index, actual) in lost.into_iter().zip(rebuilt) {
        assert_eq!(actual, input[index]);
    }
}

#[test]
fn retained_interleaved_repair_requires_recovery_in_the_damaged_cohort() {
    use par3_rs::ingest::{PacketScanner, PayloadKind, ScanEvent};
    use par3_rs::session::RepairStatus;
    use par3_rs::source::{MemorySourceAccess, SourceId};
    use std::sync::Arc;
    let original: Vec<u8> = (0..14000)
        .map(|i| ((i * 73 + i / 29) % 256) as u8)
        .collect();
    let mut damaged = original.clone();
    for index in [0, 3, 6] {
        damaged[index * 1024 + 11] ^= 1;
    }
    let mut source = MemorySourceAccess::default();
    source.insert(SourceId(1), 1, damaged.into());
    let options = ExecutionOptions::default();
    let index = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/advanced/interleaved.par3"),
    )
    .unwrap();
    let id = common::scan(&index)[0].1.input_set_id();
    let mut session =
        par3_rs::Par3RepairSession::new(id, Arc::new(source), options.clone()).unwrap();
    session.bind_file("input.bin", SourceId(1)).unwrap();
    let mut pending = Vec::new();
    for name in [
        "interleaved.par3",
        "interleaved.vol0+1.par3",
        "interleaved.vol1+2.par3",
    ] {
        let bytes = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/advanced")
                .join(name),
        )
        .unwrap();
        let mut source = MemorySourceAccess::default();
        source.insert(SourceId(99), 1, bytes.into());
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
                    if packet.payload().is_some_and(|payload| matches!(payload.kind(), PayloadKind::Recovery { index, .. } if index != 0 && index % 3 == 0)) {
                        pending.push(packet);
                    } else { session.merge(packet).unwrap(); }
                }
                ScanEvent::End => break,
                ScanEvent::NeedData { .. } => panic!("complete reference carrier"),
            }
        }
    }
    let assessment = session.assess().unwrap();
    assert_eq!(assessment.status, RepairStatus::NeedRecovery);
    assert_eq!(assessment.requirements.len(), 1);
    assert_eq!(assessment.requirements[0].cohort, 0);
    assert_eq!(assessment.requirements[0].additional, 2);
    for packet in pending {
        session.merge(packet).unwrap();
    }
    assert_eq!(session.assess().unwrap().status, RepairStatus::Ready);
    assert_eq!(session.diagnostics().source_verifications, 1);
    let output = common::TempTree::new("interleaved-session");
    assert_eq!(
        session
            .repair(output.path(), false)
            .unwrap()
            .reconstructed_blocks,
        3
    );
    assert_eq!(
        std::fs::read(output.path().join("input.bin")).unwrap(),
        original
    );
}

fn recovery() -> BTreeMap<usize, Vec<u8>> {
    CARRIERS
        .iter()
        .flat_map(|bytes| common::scan(bytes))
        .filter_map(|(_, packet)| {
            if let PacketBody::RecoveryData(recovery) = packet.body() {
                let mut data = recovery.data.clone();
                data.resize(1024, 0);
                Some((recovery.recovery_block_index as usize, data))
            } else {
                None
            }
        })
        .collect()
}

#[test]
fn bounded_fft_encoding_matches_official_recovery_bytes() {
    let input = inputs();
    let expected = recovery();
    let mut options = ExecutionOptions::default();
    options.stripe_bytes = 37;
    let codec = FftCodec::new(FftGeometry::new(14, 4).unwrap(), options).unwrap();
    let mut actual = vec![vec![0; 1024]; 8];
    codec
        .encode(
            1024,
            0,
            8,
            |index, offset, out| {
                out.copy_from_slice(&input[index][offset as usize..offset as usize + out.len()]);
                Ok(())
            },
            |index, offset, bytes| {
                actual[index][offset as usize..offset as usize + bytes.len()]
                    .copy_from_slice(bytes);
                Ok(())
            },
        )
        .unwrap();
    for (index, expected) in expected {
        assert_eq!(actual[index], expected, "recovery {index}");
    }
}

#[test]
fn bounded_fft_decoding_restores_official_input_with_uneven_losses() {
    let input = inputs();
    let recovery = recovery();
    let mut options = ExecutionOptions::default();
    options.stripe_bytes = 97;
    let codec = FftCodec::new(FftGeometry::new(14, 4).unwrap(), options).unwrap();
    for lost in [&[0][..], &[1, 4, 13], &[0, 2, 3, 5, 7, 8, 11, 13]] {
        let selected: Vec<usize> = recovery.keys().copied().take(lost.len()).collect();
        let mut rebuilt = BTreeMap::new();
        for &index in lost {
            rebuilt.insert(index, vec![0; 1024]);
        }
        codec
            .decode(
                1024,
                lost,
                &selected,
                |row, offset, out| {
                    let data = match row {
                        FftInput::Original(index) => {
                            assert!(!lost.contains(&index));
                            &input[index]
                        }
                        FftInput::Recovery(index) => &recovery[&index],
                    };
                    out.copy_from_slice(&data[offset as usize..offset as usize + out.len()]);
                    Ok(())
                },
                |index, offset, bytes| {
                    rebuilt.get_mut(&index).unwrap()
                        [offset as usize..offset as usize + bytes.len()]
                        .copy_from_slice(bytes);
                    Ok(())
                },
            )
            .unwrap();
        for (index, actual) in rebuilt {
            assert_eq!(actual, input[index], "input {index}");
        }
    }
}
