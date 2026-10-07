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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// A local-mount provider that counts the bytes it hands out per source.
#[derive(Default)]
struct Counting {
    inner: MemorySourceAccess,
    reads: Arc<Mutex<BTreeMap<u64, u64>>>,
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

#[test]
fn measure_repair() {
    let created = create(CreationCodec::Cauchy, 6, None);
    let inputs = inputs();
    let mut access = Counting::default();
    let mut damaged = inputs[0].1.clone();
    for block in [3usize, 8] {
        damaged[block * BLOCK as usize + 5] ^= 0x40;
    }
    access.insert(1, damaged);
    access.insert(2, inputs[1].1.clone());
    for (index, carrier) in created.carriers.iter().enumerate() {
        access.insert(100 + index as u64, carrier.clone());
    }
    let access = Arc::new(access);
    let options = options(256 << 20);
    let mut session = Par3RepairSession::new(created.id, access.clone(), options.clone()).unwrap();
    for index in 0..created.carriers.len() {
        let mut scanner = PacketScanner::new(
            access.clone(),
            SourceId(100 + index as u64),
            options.clone(),
            ScanLimits::default(),
        )
        .unwrap();
        while let ScanEvent::Packet(packet) = scanner.poll().unwrap() {
            session.merge(packet).unwrap();
        }
    }
    let scan: u64 = (0..created.carriers.len() as u64)
        .map(|index| access.read(100 + index))
        .sum();
    access.reset();
    session.bind_file("alpha.bin", SourceId(1)).unwrap();
    session.bind_file("beta.dat", SourceId(2)).unwrap();
    assert_eq!(session.assess().unwrap().status, RepairStatus::Ready);
    let assess = (access.read(1), access.read(2));
    let assess_carriers: u64 = (0..created.carriers.len() as u64)
        .map(|index| access.read(100 + index))
        .sum();
    access.reset();
    let output = common::TempTree::new("read-once-repair");
    session.repair(output.path(), false).unwrap();
    let repair = (access.read(1), access.read(2));
    let repair_carriers: u64 = (0..created.carriers.len() as u64)
        .map(|index| access.read(100 + index))
        .sum();
    assert_eq!(
        std::fs::read(output.path().join("alpha.bin")).unwrap(),
        inputs[0].1
    );
    eprintln!(
        "file len {} scan carriers {scan} (total {}) assess {assess:?} carriers {assess_carriers} repair {repair:?} carriers {repair_carriers}",
        inputs[0].1.len(),
        created.carriers.iter().map(Vec::len).sum::<usize>()
    );
    let _ = AtomicU64::new(0).load(Ordering::Relaxed);
}
