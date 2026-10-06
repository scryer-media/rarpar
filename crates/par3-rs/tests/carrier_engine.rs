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

/// One single-file Cauchy set whose `recovery` rows, starting at
/// `first_recovery`, all live in one carrier. Every byte comes from this
/// crate's own creation engine. Returns the identity, the protected bytes, the
/// index file and the recovery carrier.
fn one_carrier_cauchy_set(
    blocks: usize,
    block_size: u64,
    first_recovery: u64,
    recovery: u64,
    seed: &[u8],
) -> (par3_rs::InputSetId, Vec<u8>, Vec<u8>, Vec<u8>) {
    use par3_rs::creation::{
        CreationCodec, CreationOptions, CreationPlan, CreationSource, VolumeLayout,
    };
    let tree = common::TempTree::new("carrier-one-pass-set");
    let mut bytes = vec![0; blocks * block_size as usize];
    let mut hash = blake3::Hasher::new();
    hash.update(seed);
    hash.finalize_xof().fill(&mut bytes);
    let mut access = MemorySourceAccess::default();
    access.insert(SourceId(1), 1, bytes.clone().into());
    let mut options = CreationOptions {
        block_size,
        first_recovery,
        recovery_count: recovery,
        volumes: VolumeLayout::Uniform(recovery),
        codec: CreationCodec::Cauchy,
        ..CreationOptions::default()
    };
    options.execution.workers = 1;
    let plan = CreationPlan::build(
        Arc::new(access),
        &[CreationSource {
            name: "input.bin".into(),
            source: SourceId(1),
        }],
        options,
    )
    .unwrap();
    let id = plan.input_set_id();
    let paths = plan.execute(&tree.path().join("set"), tree.path()).unwrap();
    assert_eq!(paths.len(), 2, "an index and one recovery carrier");
    let index = std::fs::read(&paths[0]).unwrap();
    let carrier = std::fs::read(&paths[1]).unwrap();
    (id, bytes, index, carrier)
}

struct Regenerated {
    bytes: Vec<u8>,
    /// Source bytes read by `execute` alone.
    source_read: u64,
    /// Rows regenerated per walk over the source.
    tile: u64,
    /// Budget in use when the encode stage began.
    used_at_encode: usize,
}

/// Restore `carrier` with none of its recovery payloads available, so every
/// row is regenerated from the source.
fn regenerate(
    id: par3_rs::InputSetId,
    source: &[u8],
    index: &[u8],
    carrier: &[u8],
    mut options: ExecutionOptions,
) -> Regenerated {
    use par3_rs::runtime::{ProgressCallback, ProgressPhase, Stage};
    use std::sync::atomic::{AtomicUsize, Ordering};
    let used_at_encode = Arc::new(AtomicUsize::new(0));
    let (memory, seen) = (options.memory.clone(), used_at_encode.clone());
    options.progress = Some(ProgressCallback::new(move |event| {
        if event.stage == Stage::Encode && event.phase == ProgressPhase::Begin {
            seen.store(memory.used(), Ordering::Relaxed);
        }
    }));
    let packets = scan(carrier.to_vec(), &options);
    let plan = CarrierPlan::capture(&packets, &options).unwrap();
    let mut access = MemorySourceAccess::default();
    access.insert(SourceId(1), 1, source.to_vec().into());
    let mut session =
        par3_rs::Par3RepairSession::new(id, Arc::new(access), options.clone()).unwrap();
    session.bind_file("input.bin", SourceId(1)).unwrap();
    for packet in scan(index.to_vec(), &options) {
        session.merge(packet).unwrap();
    }
    assert_eq!(
        session.assess().unwrap().status,
        par3_rs::session::RepairStatus::Complete
    );
    let output = common::TempTree::new("carrier-one-pass");
    let before = options.diagnostics.source_io();
    let report = plan
        .execute(
            &mut session,
            &output.path().join("restored.par3"),
            output.path(),
        )
        .unwrap();
    let source_read = options.diagnostics.source_io().read_bytes - before.read_bytes;
    assert_eq!(report.restoration, CarrierRestoration::Exact);
    Regenerated {
        bytes: std::fs::read(report.path).unwrap(),
        source_read,
        tile: options.diagnostics.admission().output_tile,
        used_at_encode: used_at_encode.load(Ordering::Relaxed),
    }
}

/// Regenerating several recovery rows reads each source stripe once and feeds
/// every row from it. A budget too small for every row splits them into groups
/// and walks the source once per group, never once per row, and the carrier
/// bytes are identical either way, on either field.
#[test]
fn cauchy_rows_are_regenerated_from_one_source_pass_per_admitted_group() {
    // GF(2^8), and GF(2^16) reached through a high first recovery index.
    for (blocks, first_recovery, recovery) in [(24usize, 0u64, 5u64), (12, 300, 4)] {
        let block_size = 64 << 10;
        let (id, source, index, carrier) = one_carrier_cauchy_set(
            blocks,
            block_size,
            first_recovery,
            recovery,
            b"carrier one pass",
        );
        let options = |budget: usize| {
            let mut options = ExecutionOptions::default();
            options.workers = 1;
            options.stripe_bytes = 32 << 10;
            options.memory = par3_rs::runtime::MemoryBudget::new(budget);
            options.retained_bytes = 16 << 20;
            options
        };
        let stripe = 32 << 10;
        let wide = regenerate(id, &source, &index, &carrier, options(256 << 20));
        assert_eq!(wide.bytes, carrier, "first recovery {first_recovery}");
        assert_eq!(wide.tile, recovery, "every row fits in one group");
        assert_eq!(wide.source_read, source.len() as u64, "one source pass");

        // Room for the input and coverage stripes plus two rows, then plus one
        // row, measured from what the same run holds when encoding begins. One
        // row per group is the narrowest admission: a walk per row.
        for rows in [2u64, 1] {
            let budget = wide.used_at_encode + (2 + rows as usize) * stripe;
            let narrow = regenerate(id, &source, &index, &carrier, options(budget));
            assert_eq!(narrow.used_at_encode, wide.used_at_encode);
            assert_eq!(narrow.bytes, carrier, "first recovery {first_recovery}");
            assert_eq!(narrow.tile, rows, "rows per group");
            assert_eq!(
                narrow.source_read,
                recovery.div_ceil(rows) * source.len() as u64,
                "one source pass per group"
            );
        }
    }
}

#[test]
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
