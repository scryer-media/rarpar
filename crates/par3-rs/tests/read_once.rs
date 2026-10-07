//! How many times create and repair read each source and each carrier.
mod common;
use par3_rs::creation::{CreationCodec, CreationOptions, CreationPlan, CreationSource};
use par3_rs::ingest::{PacketScanner, ScanEvent};
use par3_rs::mount::MountKind;
use par3_rs::runtime::{ExecutionOptions, MemoryBudget};
use par3_rs::session::{Par3RepairSession, RepairStatus};
use par3_rs::source::{MemorySourceAccess, SourceAccess, SourceId, SourceSnapshot};
use par3_rs::{InputSetId, ScanLimits};
use std::collections::BTreeMap;
use std::io::Read;
use std::ops::Range;
use std::sync::{Arc, Mutex};

/// A local-mount provider that counts the bytes it hands out per source.
#[derive(Default)]
struct Counting {
    inner: MemorySourceAccess,
    reads: Arc<Mutex<BTreeMap<u64, u64>>>,
    /// Bytes `(source, offset)` that read back flipped, without the snapshot
    /// admitting to it.
    rot: Mutex<Vec<(u64, u64)>>,
}

impl Counting {
    fn insert(&mut self, id: u64, bytes: Vec<u8>) {
        self.inner.insert(SourceId(id), 1, bytes.into());
    }
    fn read(&self, id: u64) -> u64 {
        self.reads.lock().unwrap().get(&id).copied().unwrap_or(0)
    }
    fn reset(&self) {
        self.reads.lock().unwrap().clear();
    }
    fn count(reads: &Mutex<BTreeMap<u64, u64>>, id: SourceId, bytes: usize) {
        *reads.lock().unwrap().entry(id.0).or_default() += bytes as u64;
    }
}

struct CountingReader {
    inner: Box<dyn Read + Send>,
    id: SourceId,
    reads: Arc<Mutex<BTreeMap<u64, u64>>>,
}

impl Read for CountingReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(out)?;
        Counting::count(&self.reads, self.id, read);
        Ok(read)
    }
}

impl SourceAccess for Counting {
    fn snapshot(&self, source: SourceId) -> std::io::Result<Option<SourceSnapshot>> {
        self.inner.snapshot(source)
    }
    fn read_at(&self, source: SourceId, offset: u64, out: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read_at(source, offset, out)?;
        Counting::count(&self.reads, source, read);
        for &(id, at) in self.rot.lock().unwrap().iter() {
            if id == source.0 && (offset..offset + read as u64).contains(&at) {
                out[(at - offset) as usize] ^= 1;
            }
        }
        Ok(read)
    }
    fn next_available(&self, source: SourceId, offset: u64) -> std::io::Result<Option<Range<u64>>> {
        self.inner.next_available(source, offset)
    }
    fn open_sequential(&self, source: SourceId) -> std::io::Result<Option<Box<dyn Read + Send>>> {
        Ok(self.inner.open_sequential(source)?.map(|inner| {
            Box::new(CountingReader {
                inner,
                id: source,
                reads: Arc::clone(&self.reads),
            }) as Box<dyn Read + Send>
        }))
    }
    fn mount_kind(&self, _: SourceId) -> MountKind {
        MountKind::Local
    }
}

fn filler(seed: u64, len: usize) -> Vec<u8> {
    let mut bytes = vec![0; len];
    let mut hash = blake3::Hasher::new();
    hash.update(b"PAR3 read once");
    hash.update(&seed.to_le_bytes());
    hash.finalize_xof().fill(&mut bytes);
    bytes
}

const BLOCK: u64 = 256 << 10;

fn options(memory: usize) -> ExecutionOptions {
    let mut options = ExecutionOptions::default();
    options.workers = 1;
    options.memory = MemoryBudget::new(memory);
    options.retained_bytes = memory.min(64 << 20);
    options
}

fn creation(codec: CreationCodec, recovery: u64, retained: Option<usize>) -> CreationOptions {
    let mut config = CreationOptions {
        block_size: BLOCK,
        recovery_count: recovery,
        codec,
        ..CreationOptions::default()
    };
    config.execution = options(256 << 20);
    if let Some(retained) = retained {
        config.execution.retained_bytes = retained;
    }
    config
}

/// Two invented inputs, one with a described tail.
fn inputs() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("alpha.bin", filler(1, 12 * BLOCK as usize)),
        ("beta.dat", filler(2, 5 * BLOCK as usize + 777)),
    ]
}

struct Created {
    id: InputSetId,
    carriers: Vec<Vec<u8>>,
    /// Reads of each input during the plan and during execution.
    plan_reads: Vec<u64>,
    execute_reads: Vec<u64>,
}

/// Create a set from [`inputs`], with `retained` in place of the default
/// retained ceiling.
fn create(codec: CreationCodec, recovery: u64, retained: Option<usize>) -> Created {
    let mut access = Counting::default();
    let inputs = inputs();
    let mut sources = Vec::new();
    for (index, (name, bytes)) in inputs.iter().enumerate() {
        access.insert(index as u64 + 1, bytes.clone());
        sources.push(CreationSource {
            name: (*name).into(),
            source: SourceId(index as u64 + 1),
        });
    }
    let access = Arc::new(access);
    let plan = CreationPlan::build(
        access.clone(),
        &sources,
        creation(codec, recovery, retained),
    )
    .unwrap();
    let plan_reads = (1..=inputs.len() as u64)
        .map(|id| access.read(id))
        .collect();
    access.reset();
    let tree = common::TempTree::new("read-once-create");
    let paths = plan.execute(&tree.path().join("set"), tree.path()).unwrap();
    let execute_reads = (1..=inputs.len() as u64)
        .map(|id| access.read(id))
        .collect();
    Created {
        id: plan.input_set_id(),
        carriers: paths
            .iter()
            .map(|path| std::fs::read(path).unwrap())
            .collect(),
        plan_reads,
        execute_reads,
    }
}

const CODECS: [CreationCodec; 2] = [
    CreationCodec::Cauchy,
    CreationCodec::Fft {
        capacity_log2: 3,
        interleave: 0,
    },
];

#[test]
fn a_create_whose_sources_fit_reads_each_source_once() {
    let lens: Vec<u64> = inputs()
        .iter()
        .map(|(_, bytes)| bytes.len() as u64)
        .collect();
    for codec in CODECS {
        let once = create(codec, 4, None);
        // The hash pass keeps every source, and the encode reads from it.
        assert_eq!(once.plan_reads, lens, "{codec:?}");
        assert_eq!(once.execute_reads, [0, 0], "{codec:?}");
        // With room for the plan but not for the sources, the encode reads
        // every source again, and writes the same carriers.
        let twice = create(codec, 4, Some(2 << 20));
        assert_eq!(twice.plan_reads, lens, "{codec:?}");
        assert_eq!(twice.execute_reads, lens, "{codec:?}");
        assert_eq!(once.id, twice.id, "{codec:?}");
        assert_eq!(once.carriers, twice.carriers, "{codec:?}");
    }
}

/// Reads during one repair of [`inputs`] with blocks 3 and 8 of the first
/// damaged, under a `memory` budget.
struct Repaired {
    /// Reads of the damaged file during the assessment.
    assess: u64,
    /// Reads of every carrier during the repair.
    carriers: u64,
    /// The repaired first file.
    output: Vec<u8>,
}

const LOST: [usize; 2] = [3, 8];

fn repair(created: &Created, memory: usize) -> Option<Repaired> {
    let inputs = inputs();
    let mut access = Counting::default();
    let mut damaged = inputs[0].1.clone();
    for block in LOST {
        damaged[block * BLOCK as usize + 5] ^= 0x40;
    }
    access.insert(1, damaged);
    access.insert(2, inputs[1].1.clone());
    let carriers = 100..100 + created.carriers.len() as u64;
    for (id, carrier) in carriers.clone().zip(&created.carriers) {
        access.insert(id, carrier.clone());
    }
    let access = Arc::new(access);
    let options = options(memory);
    let mut session = Par3RepairSession::new(created.id, access.clone(), options.clone()).ok()?;
    for id in carriers.clone() {
        let mut scanner = PacketScanner::new(
            access.clone(),
            SourceId(id),
            options.clone(),
            ScanLimits::default(),
        )
        .ok()?;
        while let ScanEvent::Packet(packet) = scanner.poll().ok()? {
            session.merge(packet).ok()?;
        }
    }
    session.bind_file(inputs[0].0, SourceId(1)).ok()?;
    session.bind_file(inputs[1].0, SourceId(2)).ok()?;
    access.reset();
    if session.assess().ok()?.status != RepairStatus::Ready {
        return None;
    }
    let assess = access.read(1);
    access.reset();
    let output = common::TempTree::new("read-once-repair");
    let report = session.repair(output.path(), false).ok()?;
    assert_eq!(report.reconstructed_blocks, LOST.len() as u64);
    let repaired = Repaired {
        assess,
        carriers: carriers.map(|id| access.read(id)).sum(),
        output: std::fs::read(output.path().join(inputs[0].0)).unwrap(),
    };
    drop(session);
    assert_eq!(options.memory.used(), 0, "{memory}: the repair leaked");
    Some(repaired)
}

/// Budgets from a roomy 4 MiB down, a quarter block at a time, with what
/// each read, until one meets `until` or refuses the repair.
fn sweep(created: &Created, until: impl Fn(&Repaired) -> bool) -> Vec<(usize, Repaired)> {
    let mut rows = Vec::new();
    let mut memory = 4usize << 20;
    while let Some(run) = repair(created, memory) {
        let done = until(&run);
        rows.push((memory, run));
        if done {
            break;
        }
        let Some(next) = memory.checked_sub(BLOCK as usize / 4) else {
            break;
        };
        memory = next;
    }
    rows
}

#[test]
fn a_narrow_stripe_reads_each_held_recovery_row_once() {
    let created = create(CreationCodec::Cauchy, 6, None);
    let original = inputs().swap_remove(0).1;
    let once = LOST.len() as u64 * BLOCK;
    let packet = BLOCK + 64;
    let rows = sweep(&created, |run| {
        run.carriers == once + LOST.len() as u64 * packet
    });
    // The default stripe is a quarter of the block. A roomy repair reads each
    // row it uses whole once, authenticated by that read, and walks its
    // stripes from memory; it used to authenticate the row in a pass of its
    // own and then read it again a stripe at a time.
    assert_eq!(rows[0].1.carriers, once);
    // A budget with no room to hold a row authenticates it and reads it per
    // stripe, as before: its packet from the length field on, then its stripes.
    let mut held_none = false;
    for (memory, run) in &rows {
        assert!(
            run.output == original,
            "{memory}: the repair changed its bytes"
        );
        // Whole, then by block for its intact extents.
        assert_eq!(run.assess, 2 * original.len() as u64, "{memory}");
        let extra = run.carriers - once;
        assert_eq!(
            extra % packet,
            0,
            "{memory}: read {} of the rows",
            run.carriers
        );
        assert!(extra / packet <= LOST.len() as u64);
        held_none |= extra / packet == LOST.len() as u64;
    }
    assert!(held_none, "no budget was too tight to hold a row");
}

#[test]
fn a_held_recovery_row_that_rots_under_the_reader_refuses_the_repair() {
    let created = create(CreationCodec::Cauchy, 6, None);
    let inputs = inputs();
    let mut access = Counting::default();
    let mut damaged = inputs[0].1.clone();
    for block in LOST {
        damaged[block * BLOCK as usize + 5] ^= 0x40;
    }
    access.insert(1, damaged);
    access.insert(2, inputs[1].1.clone());
    for (id, carrier) in (100..).zip(&created.carriers) {
        access.insert(id, carrier.clone());
    }
    let access = Arc::new(access);
    let options = options(4 << 20);
    let mut session = Par3RepairSession::new(created.id, access.clone(), options.clone()).unwrap();
    let (mut rows, mut packet_length) = (Vec::new(), 0);
    for id in (100..).take(created.carriers.len()) {
        let mut scanner = PacketScanner::new(
            access.clone(),
            SourceId(id),
            options.clone(),
            ScanLimits::default(),
        )
        .unwrap();
        while let ScanEvent::Packet(packet) = scanner.poll().unwrap() {
            if let Some(payload) = packet.payload().filter(|payload| {
                matches!(
                    payload.kind(),
                    par3_rs::ingest::PayloadKind::Recovery { .. }
                )
            }) {
                let origin = packet.origin();
                packet_length = payload.packet_length();
                rows.push((origin.source.0, origin.offset + packet_length - 1));
            }
            session.merge(packet).unwrap();
        }
    }
    session.bind_file(inputs[0].0, SourceId(1)).unwrap();
    session.bind_file(inputs[1].0, SourceId(2)).unwrap();
    assert_eq!(session.assess().unwrap().status, RepairStatus::Ready);
    // Every row changes after it authenticated, so the one the narrow walk
    // holds first is the one that refuses.
    *access.rot.lock().unwrap() = rows;
    let output = common::TempTree::new("read-once-rot");
    let refused = session.repair(output.path(), false).unwrap_err();
    assert!(
        matches!(
            refused,
            par3_rs::runtime::EngineError::Format(par3_rs::Par3Error::PacketHashMismatch { .. })
        ),
        "{refused:?}"
    );
    assert_eq!(session.rejected_packets(), 1);
    assert_eq!(session.failed_hash_bytes(), packet_length);
    assert_eq!(
        std::fs::read_dir(output.path()).unwrap().count(),
        0,
        "a refused repair left staged output behind"
    );
    drop(session);
    assert_eq!(options.memory.used(), 0);
}
