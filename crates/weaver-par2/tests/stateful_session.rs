#[allow(dead_code)]
#[path = "support/benchmark_support.rs"]
mod benchmark_support;

use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use benchmark_support::{crate_bench_scenarios, stage_scenario};
use par2_rs::checksum::{self, SliceChecksumState};
use par2_rs::packet::header;
use par2_rs::{
    CommittedFileEvidence, FileAccess, FileId, MemoryFileAccess, Packet, Par2RepairSession,
    Par2RepairSessionOptions, Par2RepairStatus, Par2SessionError, SliceEvidence,
    VerificationSession, gf_pow, input_slice_constants, mul_acc_region, scan_packets_from_path,
};
use tempfile::TempDir;

#[test]
fn recovery_volume_merge_reuses_the_single_source_scan() {
    let scenario = crate_bench_scenarios()
        .into_iter()
        .find(|scenario| scenario.name == "rar4_store_enc_corrupt_middle")
        .expect("stateful benchmark fixture");
    let staged = stage_scenario(&scenario);
    assert!(!staged.recovery_par2.is_empty());

    // `Par2RepairSessionOptions` is `#[non_exhaustive]`, so callers outside the
    // crate build it through a constructor and set the fields they need.
    let mut options = Par2RepairSessionOptions::new(
        staged.temp.path().to_path_buf(),
        vec![staged.main_par2.clone()],
    );
    options.extra_paths = staged.payload_paths.clone();
    let mut session = Par2RepairSession::open(options).expect("open stateful repair session");

    let before_recovery = session.analyze().expect("initial source analysis");
    assert_eq!(
        before_recovery.status,
        Par2RepairStatus::Insufficient,
        "the main PAR2 alone should not have enough recovery data"
    );
    let first = session.diagnostics().clone();
    assert_eq!(first.source_scan_passes, 1);
    assert!(first.scan.bytes_scanned > 0);

    session.analyze().expect("cached source analysis");
    let cached = session.diagnostics().clone();
    assert_eq!(cached.source_scan_passes, first.source_scan_passes);
    assert_eq!(cached.scan.bytes_scanned, first.scan.bytes_scanned);

    session
        .merge_recovery_paths(&staged.recovery_par2)
        .expect("merge recovery volumes");
    let after_merge = session.diagnostics().clone();
    assert_eq!(after_merge.source_scan_passes, first.source_scan_passes);
    assert_eq!(after_merge.scan.bytes_scanned, first.scan.bytes_scanned);

    let repairable = session.analyze().expect("assessment after recovery merge");
    assert_eq!(repairable.status, Par2RepairStatus::RepairPossible);
    let final_diagnostics = session.diagnostics();
    assert_eq!(final_diagnostics.source_scan_passes, 1);
    assert_eq!(
        final_diagnostics.scan.bytes_scanned,
        first.scan.bytes_scanned
    );
    eprintln!(
        "stateful_session_metrics scan_passes={} scan_bytes={} retained_bytes={} recovery_paths_merged={}",
        final_diagnostics.source_scan_passes,
        final_diagnostics.scan.bytes_scanned,
        final_diagnostics.retained_bytes,
        final_diagnostics.recovery_paths_merged,
    );
}

#[test]
fn recovery_merge_budget_rejection_is_transactional() {
    let scenario = crate_bench_scenarios()
        .into_iter()
        .find(|scenario| scenario.name == "rar4_store_enc_corrupt_middle")
        .expect("stateful benchmark fixture");
    let staged = stage_scenario(&scenario);

    let open = |retained_state_limit| {
        let mut options = Par2RepairSessionOptions::new(
            staged.temp.path().to_path_buf(),
            vec![staged.main_par2.clone()],
        );
        options.extra_paths = staged.payload_paths.clone();
        options.retained_state_limit = retained_state_limit;
        Par2RepairSession::open(options).expect("open stateful repair session")
    };

    let mut probe = open(usize::MAX);
    let unmerged_bytes = probe.estimated_retained_bytes();
    probe
        .merge_recovery_paths(&staged.recovery_par2)
        .expect("measure merged state");
    let merged_bytes = probe.estimated_retained_bytes();
    assert!(merged_bytes > unmerged_bytes);
    let limit = unmerged_bytes.saturating_add((merged_bytes - unmerged_bytes) / 2);
    drop(probe);

    let mut session = open(limit);
    let before_bytes = session.estimated_retained_bytes();
    let before_diagnostics = session.diagnostics().clone();

    assert!(matches!(
        session.merge_recovery_paths(&staged.recovery_par2),
        Err(Par2SessionError::RetainedStateLimitExceeded { .. })
    ));
    assert_eq!(session.estimated_retained_bytes(), before_bytes);
    assert_eq!(session.diagnostics().source_scan_passes, 0);
    assert_eq!(session.diagnostics().recovery_paths_merged, 0);
    assert_eq!(
        session.diagnostics().packets.packets_loaded,
        before_diagnostics.packets.packets_loaded
    );
    assert_eq!(
        session.diagnostics().packets.duplicate_packets,
        before_diagnostics.packets.duplicate_packets
    );
    assert!(matches!(
        session.assessment(),
        Err(Par2SessionError::InvalidState { .. })
    ));
}

// ---------------------------------------------------------------------------
// Access-backed sessions: sources that are not files
// ---------------------------------------------------------------------------

/// A `FileAccess` that counts what it served, so a test can prove the bytes
/// repair consumed came from here and not from the filesystem.
struct CountingAccess {
    inner: MemoryFileAccess,
    reads: AtomicUsize,
    bytes: AtomicU64,
}

impl CountingAccess {
    fn new(inner: MemoryFileAccess) -> Self {
        Self {
            inner,
            reads: AtomicUsize::new(0),
            bytes: AtomicU64::new(0),
        }
    }

    fn reads(&self) -> usize {
        self.reads.load(Ordering::Relaxed)
    }

    fn bytes(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }
}

impl FileAccess for CountingAccess {
    fn read_file_range(&self, file_id: &FileId, offset: u64, len: u64) -> io::Result<Vec<u8>> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        let data = self.inner.read_file_range(file_id, offset, len)?;
        self.bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
        Ok(data)
    }

    fn read_file_range_into(
        &self,
        file_id: &FileId,
        offset: u64,
        dst: &mut [u8],
    ) -> io::Result<usize> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        let read = self.inner.read_file_range_into(file_id, offset, dst)?;
        self.bytes.fetch_add(read as u64, Ordering::Relaxed);
        Ok(read)
    }

    fn file_exists(&self, file_id: &FileId) -> bool {
        self.inner.file_exists(file_id)
    }

    fn file_length(&self, file_id: &FileId) -> Option<u64> {
        self.inner.file_length(file_id)
    }

    fn read_file(&self, file_id: &FileId) -> io::Result<Vec<u8>> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        let data = self.inner.read_file(file_id)?;
        self.bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
        Ok(data)
    }

    fn write_file_range(
        &mut self,
        _file_id: &FileId,
        _offset: u64,
        _data: &[u8],
    ) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "test access is read-only",
        ))
    }
}

fn framed_packet(packet_type: &[u8; 16], body: &[u8], recovery_set_id: &[u8; 16]) -> Vec<u8> {
    let mut hash_input = Vec::new();
    hash_input.extend_from_slice(recovery_set_id);
    hash_input.extend_from_slice(packet_type);
    hash_input.extend_from_slice(body);

    let mut packet = Vec::new();
    packet.extend_from_slice(header::MAGIC);
    packet.extend_from_slice(&((header::HEADER_SIZE + body.len()) as u64).to_le_bytes());
    packet.extend_from_slice(&checksum::md5(&hash_input));
    packet.extend_from_slice(recovery_set_id);
    packet.extend_from_slice(packet_type);
    packet.extend_from_slice(body);
    packet
}

struct VirtualSet {
    temp: TempDir,
    par2_path: PathBuf,
    file_id: FileId,
    filename: String,
    slice_size: u64,
}

/// Build a one-file PAR2 set with `recovery_blocks` recovery slices and write
/// only the `.par2` file to disk. The protected file itself is deliberately
/// *not* written: it is the caller's job to decide what lives at that path.
fn build_virtual_set(payload: &[u8], slice_size: u64, recovery_blocks: u32) -> VirtualSet {
    let temp = tempfile::tempdir().expect("temp dir");
    let filename = "volume.bin".to_owned();
    let hash_16k = checksum::md5(&payload[..payload.len().min(16 * 1024)]);

    let mut id_input = Vec::new();
    id_input.extend_from_slice(&hash_16k);
    id_input.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    id_input.extend_from_slice(filename.as_bytes());
    let file_id_bytes = checksum::md5(&id_input);
    let file_id = FileId::from_bytes(file_id_bytes);

    let mut main_body = Vec::new();
    main_body.extend_from_slice(&slice_size.to_le_bytes());
    main_body.extend_from_slice(&1u32.to_le_bytes());
    main_body.extend_from_slice(&file_id_bytes);
    let recovery_set_id = checksum::md5(&main_body);

    let mut file_desc_body = Vec::new();
    file_desc_body.extend_from_slice(&file_id_bytes);
    file_desc_body.extend_from_slice(&checksum::md5(payload));
    file_desc_body.extend_from_slice(&hash_16k);
    file_desc_body.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    file_desc_body.extend_from_slice(filename.as_bytes());
    while !file_desc_body.len().is_multiple_of(4) {
        file_desc_body.push(0);
    }

    let slice_count = payload.len().div_ceil(slice_size as usize);
    let mut ifsc_body = Vec::new();
    ifsc_body.extend_from_slice(&file_id_bytes);
    let mut padded_slices = Vec::new();
    for index in 0..slice_count {
        let start = index * slice_size as usize;
        let end = (start + slice_size as usize).min(payload.len());
        let mut padded = vec![0u8; slice_size as usize];
        padded[..end - start].copy_from_slice(&payload[start..end]);

        let mut state = SliceChecksumState::new();
        state.update(&payload[start..end]);
        let (crc32, md5) = state.finalize(Some(slice_size));
        ifsc_body.extend_from_slice(&md5);
        ifsc_body.extend_from_slice(&crc32.to_le_bytes());
        padded_slices.push(padded);
    }

    let mut stream = Vec::new();
    stream.extend_from_slice(&framed_packet(
        header::TYPE_MAIN,
        &main_body,
        &recovery_set_id,
    ));
    stream.extend_from_slice(&framed_packet(
        header::TYPE_FILE_DESC,
        &file_desc_body,
        &recovery_set_id,
    ));
    stream.extend_from_slice(&framed_packet(
        header::TYPE_IFSC,
        &ifsc_body,
        &recovery_set_id,
    ));

    let constants = input_slice_constants(slice_count);
    for exponent in 0..recovery_blocks {
        let mut recovery = vec![0u8; slice_size as usize];
        for (index, &constant) in constants.iter().enumerate() {
            mul_acc_region(
                gf_pow(constant, exponent),
                &padded_slices[index],
                &mut recovery,
            );
        }
        let mut body = Vec::new();
        body.extend_from_slice(&exponent.to_le_bytes());
        body.extend_from_slice(&recovery);
        stream.extend_from_slice(&framed_packet(
            header::TYPE_RECOVERY,
            &body,
            &recovery_set_id,
        ));
    }

    let par2_path = temp.path().join("release.par2");
    fs::write(&par2_path, &stream).expect("write par2");

    VirtualSet {
        temp,
        par2_path,
        file_id,
        filename,
        slice_size,
    }
}

/// Settle real slice verdicts the way a live verifier would, so the evidence
/// handed to the repair session is genuine rather than hand-built.
fn settled_evidence(set: &VirtualSet, bytes: &[u8], slice_indexes: &[u32]) -> Vec<SliceEvidence> {
    let packets: Vec<Packet> = scan_packets_from_path(&set.par2_path)
        .expect("scan par2 packets")
        .into_iter()
        .map(|(packet, _offset)| packet)
        .collect();
    let mut verifier = VerificationSession::new();
    verifier.add_par2_data(&packets);

    let mut evidence = Vec::new();
    for &index in slice_indexes {
        let start = index as usize * set.slice_size as usize;
        let end = (start + set.slice_size as usize).min(bytes.len());
        let outcome = verifier.feed_range(&set.file_id, start as u64, &bytes[start..end]);
        evidence.extend_from_slice(outcome.evidence());
    }
    evidence
}

#[test]
fn access_backed_session_repairs_without_reading_the_filesystem_for_sources() {
    let payload: Vec<u8> = (0..48u8).map(|byte| byte.wrapping_mul(7)).collect();
    let set = build_virtual_set(&payload, 16, 1);
    let base_dir = set.temp.path().to_path_buf();

    // The base directory is deliberately hostile: a decoy sits at exactly the
    // name and length the set describes, holding bytes that would corrupt the
    // repair if any source read ever reached it.
    let decoy = vec![0xDEu8; payload.len()];
    let decoy_path = base_dir.join(&set.filename);
    fs::write(&decoy_path, &decoy).expect("write decoy");

    // The served volume is damaged in its middle slice, exactly as a virtual
    // volume with a lost article would be.
    let mut served = payload.clone();
    served[16..32].fill(0xAB);
    let mut memory = MemoryFileAccess::new();
    memory.add_file(set.file_id, served.clone());
    let access = Arc::new(CountingAccess::new(memory));

    let mut options = Par2RepairSessionOptions::with_source_access(
        base_dir.clone(),
        vec![set.par2_path.clone()],
        access.clone(),
    );
    options.memory_limit = Some(8 * 1024 * 1024);
    let mut session = Par2RepairSession::open(options).expect("open access-backed session");
    assert!(session.is_access_backed());

    // Only the intact slices are settled; slice 1 is never named, so nothing
    // seeds it and repair must reconstruct it from recovery data.
    for evidence in settled_evidence(&set, &payload, &[0, 2]) {
        assert!(evidence.is_valid());
        session
            .add_slice_evidence_for_file(evidence)
            .expect("retain access-keyed slice evidence");
    }

    let assessment = session.analyze().expect("analyze access-backed set");
    assert_eq!(assessment.status, Par2RepairStatus::RepairPossible);
    assert_eq!(assessment.missing_blocks, 1);

    // No directory was walked and no candidate file was opened: an
    // access-backed session has nothing on disk to scan.
    let diagnostics = session.diagnostics().clone();
    assert_eq!(diagnostics.source_scan_passes, 0);
    assert_eq!(diagnostics.scan.files_scanned, 0);
    assert_eq!(diagnostics.scan.files_skipped, 0);
    assert_eq!(diagnostics.scan.bytes_scanned, 0);
    assert_eq!(diagnostics.access_slice_evidence, 2);

    let reads_before_repair = access.reads();
    let outcome = session.repair().expect("repair from virtual sources");
    assert_eq!(outcome.status, Par2RepairStatus::Repaired);

    let repaired = fs::read(&decoy_path).expect("read repaired file");
    assert_eq!(
        repaired, payload,
        "repaired bytes must match the true source"
    );
    assert_ne!(repaired, decoy);
    assert_ne!(repaired, served);

    assert!(
        access.reads() > reads_before_repair,
        "repair must consume clean source bytes through the access handle"
    );
    assert!(access.bytes() >= 32, "both intact slices are read back");
}

#[test]
fn access_backed_session_refuses_committed_file_evidence() {
    let payload: Vec<u8> = (0..32u8).collect();
    let set = build_virtual_set(&payload, 16, 1);
    let base_dir = set.temp.path().to_path_buf();
    let staged = base_dir.join(&set.filename);
    fs::write(&staged, &payload).expect("write physical twin");

    let mut memory = MemoryFileAccess::new();
    memory.add_file(set.file_id, payload.clone());
    let access = Arc::new(CountingAccess::new(memory));
    let mut session = Par2RepairSession::open(Par2RepairSessionOptions::with_source_access(
        base_dir,
        vec![set.par2_path.clone()],
        access,
    ))
    .expect("open access-backed session");

    // The file on disk is a byte-perfect twin whose stat fingerprint matches,
    // so the refusal cannot be the stat gate failing incidentally.
    let evidence = CommittedFileEvidence::from_full_md5_path(
        &staged,
        &set.filename,
        payload.len() as u64,
        checksum::md5(&payload),
        Some(set.file_id),
    )
    .expect("build committed evidence");

    match session.add_committed_file(evidence) {
        Err(Par2SessionError::InvalidState { reason }) => {
            assert!(
                reason.contains("physical-only"),
                "refusal must name the reason, got: {reason}"
            );
        }
        other => panic!("expected a named refusal, got {other:?}"),
    }
    assert_eq!(session.diagnostics().committed_sources, 0);
}

#[test]
fn file_keyed_slice_evidence_requires_an_access_backed_session() {
    let payload: Vec<u8> = (0..32u8).collect();
    let set = build_virtual_set(&payload, 16, 1);
    fs::write(set.temp.path().join(&set.filename), &payload).expect("write source");

    let mut session = Par2RepairSession::open(Par2RepairSessionOptions::new(
        set.temp.path().to_path_buf(),
        vec![set.par2_path.clone()],
    ))
    .expect("open filesystem session");
    assert!(!session.is_access_backed());

    let evidence = settled_evidence(&set, &payload, &[0])
        .into_iter()
        .next()
        .expect("settled evidence");
    assert!(matches!(
        session.add_slice_evidence_for_file(evidence),
        Err(Par2SessionError::InvalidState { .. })
    ));
}
