//! Recovery-carrier restoration using only authenticated official layouts.
mod common;

use par3_rs::carrier::{CarrierPlan, CarrierRestoration};
use par3_rs::ingest::{IngestedPacket, PacketScanner, ScanEvent};
use par3_rs::runtime::ExecutionOptions;
use par3_rs::source::{MemorySourceAccess, SourceId};
use std::sync::Arc;

fn scan(bytes: Vec<u8>, options: &ExecutionOptions) -> Vec<IngestedPacket> {
    let mut source = MemorySourceAccess::default();
    source.insert(SourceId(99), 1, bytes.into());
    let mut scanner = PacketScanner::new(
        Arc::new(source),
        SourceId(99),
        options.clone(),
        par3_rs::ScanLimits::default(),
    )
    .unwrap();
    let mut packets = Vec::new();
    loop {
        match scanner.poll().unwrap() {
            ScanEvent::Packet(packet) => packets.push(packet),
            ScanEvent::End => break,
            ScanEvent::NeedData { .. } => panic!("complete official carrier"),
        }
    }
    packets
}

#[test]
fn cauchy_carrier_is_reconstructed_byte_for_byte_and_unknown_layout_is_explicit() {
    let mut options = ExecutionOptions::default();
    options.stripe_bytes = 137;
    options.workers = 1;
    let mut source = MemorySourceAccess::default();
    source.insert(SourceId(1), 1, common::a_bin().into());
    source.insert(SourceId(2), 1, common::b_txt().into());
    source.insert(SourceId(3), 1, common::c_bin().into());
    let original = common::set_vol1_par3();
    let packets = scan(original.clone(), &options);
    assert!(CarrierPlan::capture(&packets[..packets.len() - 1], &options).is_err());
    let plan = CarrierPlan::capture(&packets, &options).unwrap();
    let mut session =
        par3_rs::Par3RepairSession::new(common::SET_ID, Arc::new(source), options.clone()).unwrap();
    for (path, id) in [("a.bin", 1), ("b.txt", 2), ("sub/c.bin", 3)] {
        session.bind_file(path, SourceId(id)).unwrap();
    }
    for packet in scan(common::set_par3(), &options) {
        session.merge(packet).unwrap();
    }
    let output = common::TempTree::new("carrier-exact");
    let report = plan
        .execute(
            &mut session,
            &output.path().join("restored.par3"),
            output.path(),
        )
        .unwrap();
    assert_eq!(report.restoration, CarrierRestoration::Exact);
    assert_eq!(std::fs::read(report.path).unwrap(), original);
    let matrix = packets
        .iter()
        .find_map(|packet| packet.payload())
        .map(|payload| match payload.kind() {
            par3_rs::ingest::PayloadKind::Recovery { matrix, .. } => matrix,
            _ => panic!("recovery carrier"),
        })
        .unwrap();
    let replacement = CarrierPlan::replacement(&mut session, matrix, &[0, 1]).unwrap();
    assert_eq!(replacement.restoration(), CarrierRestoration::Replacement);
    let report = replacement
        .execute(
            &mut session,
            &output.path().join("replacement.par3"),
            output.path(),
        )
        .unwrap();
    assert_eq!(report.recovery_packets, 2);
    assert_eq!(
        std::fs::metadata(report.path).unwrap().len(),
        replacement.output_bytes()
    );
}

#[test]
#[ignore = "requires the next published advanced PAR3 corpus; enable in the corpus follow-up PR"]
fn interleaved_fft_carrier_is_reconstructed_without_original_recovery_payloads() {
    let mut options = ExecutionOptions::default();
    options.stripe_bytes = 111;
    let original = common::advanced_fixture("interleaved.vol1+2.par3");
    let packets = scan(original.clone(), &options);
    let plan = CarrierPlan::capture(&packets, &options).unwrap();
    let input: Vec<u8> = (0..14000)
        .map(|i| ((i * 73 + i / 29) % 256) as u8)
        .collect();
    let mut source = MemorySourceAccess::default();
    source.insert(SourceId(1), 1, input.into());
    let mut session = par3_rs::Par3RepairSession::new(
        packets[0].input_set_id(),
        Arc::new(source),
        options.clone(),
    )
    .unwrap();
    session.bind_file("input.bin", SourceId(1)).unwrap();
    for packet in scan(common::advanced_fixture("interleaved.par3"), &options) {
        session.merge(packet).unwrap();
    }
    let output = common::TempTree::new("carrier-fft-exact");
    let report = plan
        .execute(
            &mut session,
            &output.path().join("restored.par3"),
            output.path(),
        )
        .unwrap();
    assert_eq!(report.restoration, CarrierRestoration::Exact);
    assert_eq!(std::fs::read(report.path).unwrap(), original);
}
