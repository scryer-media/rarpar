//! Off-thread hashing for high-throughput extraction paths.
//!
//! Store-mode extraction and the solid decode apply phase are wall-clock bound
//! by hashing performed inline on the hot thread. This module moves checksum
//! work onto dedicated worker threads:
//!
//! - CRC32 runs on one worker, fed whole chunks in stream order (an mpsc
//!   channel preserves FIFO order, so a single sequential hasher suffices).
//! - BLAKE2sp is parallelized by construction: the format defines 8
//!   independent BLAKE2s leaf streams, interleaved in 64-byte blocks. Each
//!   incoming chunk is shared with the lane workers, and every worker walks
//!   only the bytes it owns straight out of that shared buffer (the same
//!   strided split unrar's `blake2sp.cpp` hands to its threads); the root node
//!   combines the leaf digests at finalize. The output is bit-identical to a
//!   serial BLAKE2sp (verified against `blake2s_simd::blake2sp` in tests).
//!
//!   How many leaves one worker owns is a policy choice — see
//!   [`LEAVES_PER_WORKER`]. Today it is one scalar leaf per worker on every
//!   arch; the 4-leaf NEON group arrangement exists (see
//!   `crate::crypto::Blake2spLeafGroup`) but is deliberately unwired pending
//!   group-kernel scaling work — the constant's comment carries the numbers.
//!
//! Pipelines spawn threads per instance, so callers should only use them for
//! members large enough to amortize spawn cost (see [`PIPELINE_MIN_BYTES`]).

use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, mpsc};
use std::thread::JoinHandle;

use blake2s_simd::Params as Blake2sParams;
use blake2s_simd::State as Blake2sState;

/// Chunk buffers cycled between the submitter and the hash workers.
const CHUNK_CAPACITY: usize = 4 * 1024 * 1024;
/// Bounded in-flight chunks: caps memory and applies backpressure when the
/// hash side falls behind the reader.
const MAX_IN_FLIGHT: usize = 4;
/// BLAKE2sp interleaves its leaves in 64-byte blocks.
const BLAKE_BLOCK: usize = 64;
/// Number of BLAKE2sp leaf lanes, fixed by the format.
const LANES: usize = 8;
/// Distance between two consecutive blocks owned by the same lane.
const LANE_STRIDE: u64 = (LANES * BLAKE_BLOCK) as u64;
/// Below this size the thread spawn + channel overhead outweighs the win;
/// callers should stay on the inline hashing path.
pub(crate) const PIPELINE_MIN_BYTES: u64 = 8 * 1024 * 1024;

pub(crate) struct HashPipelineOutputs {
    pub crc32: Option<u32>,
    pub blake2sp: Option<[u8; 32]>,
}

enum ChunkMsg {
    Data(Vec<u8>),
}

/// A stream chunk shared by every hash lane. The coordinator keeps the last
/// reference and returns the buffer to the submitter's free pool once all
/// lanes have dropped theirs.
type SharedChunk = Arc<Vec<u8>>;

enum LaneMsg {
    /// `stream_offset` is the absolute stream position of `chunk`'s first
    /// byte, which is all a lane needs to locate the blocks it owns.
    Data {
        chunk: SharedChunk,
        stream_offset: u64,
    },
}

/// Off-thread hasher accepting in-order stream chunks.
pub(crate) struct HashPipeline {
    chunk_tx: Option<mpsc::SyncSender<ChunkMsg>>,
    free_rx: mpsc::Receiver<Vec<u8>>,
    coordinator: Option<JoinHandle<CoordinatorResult>>,
    compute_crc: bool,
    compute_blake: bool,
}

struct CoordinatorResult {
    crc32: Option<u32>,
    blake2sp: Option<[u8; 32]>,
}

impl HashPipeline {
    pub(crate) fn new(compute_crc: bool, compute_blake: bool) -> Self {
        assert!(
            compute_crc || compute_blake,
            "hash pipeline needs at least one hash kind"
        );
        let (chunk_tx, chunk_rx) = mpsc::sync_channel::<ChunkMsg>(MAX_IN_FLIGHT);
        let (free_tx, free_rx) = mpsc::channel::<Vec<u8>>();

        let coordinator = std::thread::Builder::new()
            .name("weaver-rar-hash".into())
            .spawn(move || coordinator_loop(chunk_rx, free_tx, compute_crc, compute_blake))
            .expect("spawn hash pipeline coordinator");

        Self {
            chunk_tx: Some(chunk_tx),
            free_rx,
            coordinator: Some(coordinator),
            compute_crc,
            compute_blake,
        }
    }

    /// Fetch a recycled chunk buffer (or allocate one). The returned buffer is
    /// empty with at least [`CHUNK_CAPACITY`] capacity.
    pub(crate) fn take_buffer(&self) -> Vec<u8> {
        let mut buf = self.take_buffer_raw();
        buf.clear();
        buf
    }

    /// Fetch a recycled chunk buffer without clearing it (recycled contents
    /// are stale chunk data, useful when the caller overwrites in place).
    fn take_buffer_raw(&self) -> Vec<u8> {
        match self.free_rx.try_recv() {
            Ok(buf) => buf,
            Err(_) => Vec::with_capacity(CHUNK_CAPACITY),
        }
    }

    /// Submit the next chunk of the stream, in order.
    pub(crate) fn submit(&self, chunk: Vec<u8>) -> io::Result<()> {
        if chunk.is_empty() {
            return Ok(());
        }
        self.chunk_tx
            .as_ref()
            .expect("hash pipeline already finalized")
            .send(ChunkMsg::Data(chunk))
            .map_err(|_| io::Error::other("hash pipeline worker terminated early"))
    }

    /// Copy `data` into a pooled buffer and submit it. Convenience for
    /// writer-wrapper call sites that only have a borrowed slice.
    #[cfg(test)]
    pub(crate) fn update(&self, data: &[u8]) -> io::Result<()> {
        let mut offset = 0;
        while offset < data.len() {
            let take = (data.len() - offset).min(CHUNK_CAPACITY);
            let mut buf = self.take_buffer();
            buf.extend_from_slice(&data[offset..offset + take]);
            self.submit(buf)?;
            offset += take;
        }
        Ok(())
    }

    /// Signal end of stream and collect the digests.
    pub(crate) fn finalize(mut self) -> io::Result<HashPipelineOutputs> {
        drop(self.chunk_tx.take());
        let result = self
            .coordinator
            .take()
            .expect("hash pipeline already finalized")
            .join()
            .map_err(|_| io::Error::other("hash pipeline coordinator panicked"))?;
        debug_assert_eq!(result.crc32.is_some(), self.compute_crc);
        debug_assert_eq!(result.blake2sp.is_some(), self.compute_blake);
        Ok(HashPipelineOutputs {
            crc32: result.crc32,
            blake2sp: result.blake2sp,
        })
    }
}

impl Drop for HashPipeline {
    fn drop(&mut self) {
        drop(self.chunk_tx.take());
        if let Some(handle) = self.coordinator.take() {
            let _ = handle.join();
        }
    }
}

fn coordinator_loop(
    chunk_rx: mpsc::Receiver<ChunkMsg>,
    free_tx: mpsc::Sender<Vec<u8>>,
    compute_crc: bool,
    compute_blake: bool,
) -> CoordinatorResult {
    let mut crc_lanes = compute_crc.then(CrcLanes::spawn);
    let mut blake = compute_blake.then(BlakeLanes::spawn);
    // Chunks handed to the lanes, oldest first. Every lane reads the chunk in
    // place, so a buffer only becomes recyclable once they have all let go.
    let mut in_flight: VecDeque<SharedChunk> = VecDeque::new();

    while let Ok(ChunkMsg::Data(chunk)) = chunk_rx.recv() {
        let shared: SharedChunk = Arc::new(chunk);
        if let Some(ref mut lanes) = blake {
            lanes.dispatch(&shared);
        }
        if let Some(ref mut lanes) = crc_lanes {
            lanes.submit(Arc::clone(&shared));
        }
        in_flight.push_back(shared);
        recycle_spent_chunks(&mut in_flight, &free_tx);
    }

    let crc32 = crc_lanes.take().map(CrcLanes::finalize);
    let blake2sp = blake.take().map(BlakeLanes::finalize);
    CoordinatorResult { crc32, blake2sp }
}

/// Return buffers whose lanes have all finished to the submitter's free pool.
/// Chunks leave the lanes in roughly submission order, so popping from the
/// front until one is still referenced drains everything that is ready.
fn recycle_spent_chunks(in_flight: &mut VecDeque<SharedChunk>, free_tx: &mpsc::Sender<Vec<u8>>) {
    while in_flight
        .front()
        .is_some_and(|chunk| Arc::strong_count(chunk) == 1)
    {
        let chunk = in_flight.pop_front().expect("front was just observed");
        if let Ok(buf) = Arc::try_unwrap(chunk) {
            let _ = free_tx.send(buf);
        }
    }
}

/// CRC32 of a whole stream, computed as independent per-chunk CRCs on two
/// worker threads and folded back together in chunk order. Folding uses the
/// standard GF(2) length-shift operator: crc(A ++ B) =
/// shift(crc(A), len(B)) ^ crc(B). Two lanes keep CRC off the read loop's
/// critical path even when a single lane cannot match the read rate.
struct CrcLanes {
    txs: Vec<mpsc::SyncSender<(u64, SharedChunk)>>,
    handles: Vec<JoinHandle<Vec<ChunkCrc>>>,
    next_seq: u64,
}

struct ChunkCrc {
    seq: u64,
    crc: u32,
    len: u64,
}

const CRC_LANE_COUNT: usize = 2;

impl CrcLanes {
    fn spawn() -> Self {
        let mut txs = Vec::with_capacity(CRC_LANE_COUNT);
        let mut handles = Vec::with_capacity(CRC_LANE_COUNT);
        for lane in 0..CRC_LANE_COUNT {
            let (tx, rx) = mpsc::sync_channel::<(u64, SharedChunk)>(MAX_IN_FLIGHT);
            let handle = std::thread::Builder::new()
                .name(format!("weaver-rar-crc-{lane}"))
                .spawn(move || {
                    let mut results: Vec<ChunkCrc> = Vec::new();
                    while let Ok((seq, chunk)) = rx.recv() {
                        results.push(ChunkCrc {
                            seq,
                            crc: crc32fast::hash(&chunk),
                            len: chunk.len() as u64,
                        });
                    }
                    results
                })
                .expect("spawn CRC lane");
            txs.push(tx);
            handles.push(handle);
        }
        Self {
            txs,
            handles,
            next_seq: 0,
        }
    }

    fn submit(&mut self, chunk: SharedChunk) {
        let seq = self.next_seq;
        self.next_seq += 1;
        let lane = (seq as usize) % self.txs.len();
        let _ = self.txs[lane].send((seq, chunk));
    }

    fn finalize(mut self) -> u32 {
        self.txs.clear();
        let mut results: Vec<ChunkCrc> = Vec::new();
        for handle in self.handles.drain(..) {
            results.extend(handle.join().unwrap_or_default());
        }
        results.sort_unstable_by_key(|entry| entry.seq);

        let mut ops: Vec<(u64, CrcShiftOp)> = Vec::new();
        let mut crc = 0u32;
        for entry in results {
            let op = match ops.iter().find(|(len, _)| *len == entry.len) {
                Some((_, op)) => op,
                None => {
                    ops.push((entry.len, CrcShiftOp::new(entry.len)));
                    &ops.last().expect("just pushed").1
                }
            };
            crc = op.shift(crc) ^ entry.crc;
        }
        crc
    }
}

/// Operator that advances a finalized CRC32 past `len` zero bytes, so
/// per-chunk CRCs can be folded into the CRC of the concatenated stream.
struct CrcShiftOp {
    op: Option<[u32; 32]>,
}

impl CrcShiftOp {
    fn new(len: u64) -> Self {
        if len == 0 {
            return Self { op: None };
        }

        fn mat_vec(mat: &[u32; 32], mut vec: u32) -> u32 {
            let mut sum = 0u32;
            let mut idx = 0usize;
            while vec != 0 {
                if vec & 1 != 0 {
                    sum ^= mat[idx];
                }
                vec >>= 1;
                idx += 1;
            }
            sum
        }
        fn mat_square(dst: &mut [u32; 32], src: &[u32; 32]) {
            for n in 0..32 {
                dst[n] = mat_vec(src, src[n]);
            }
        }

        // One-bit shift operator over the reflected CRC32 polynomial; square
        // it up to the byte level, then square-and-multiply over `len`.
        let mut odd = [0u32; 32];
        odd[0] = 0xEDB8_8320;
        for (n, item) in odd.iter_mut().enumerate().skip(1) {
            *item = 1 << (n - 1);
        }
        let mut even = [0u32; 32];
        mat_square(&mut even, &odd); // 2 bits
        mat_square(&mut odd, &even); // 4 bits
        mat_square(&mut even, &odd); // 8 bits = 1 byte

        let mut combined = [0u32; 32];
        for (n, item) in combined.iter_mut().enumerate() {
            *item = 1 << n;
        }
        let mut per_step = even;
        let mut scratch = [0u32; 32];
        let mut remaining = len;
        loop {
            if remaining & 1 != 0 {
                let previous = combined;
                for n in 0..32 {
                    combined[n] = mat_vec(&per_step, previous[n]);
                }
            }
            remaining >>= 1;
            if remaining == 0 {
                break;
            }
            mat_square(&mut scratch, &per_step);
            per_step = scratch;
        }

        Self { op: Some(combined) }
    }

    fn shift(&self, crc: u32) -> u32 {
        let Some(ref op) = self.op else {
            return crc;
        };
        let mut sum = 0u32;
        let mut vec = crc;
        let mut idx = 0usize;
        while vec != 0 {
            if vec & 1 != 0 {
                sum ^= op[idx];
            }
            vec >>= 1;
            idx += 1;
        }
        sum
    }
}

/// How many BLAKE2sp leaves one worker thread owns.
///
/// The eight leaves are independent until the root combine, so any split of
/// them across threads is correct; the choice is vector width versus thread
/// count, and it is decided per target by which BLAKE2s implementation is
/// actually vectorized there.
///
/// * Off `aarch64`, the upstream `blake2s_simd` leaf state has real SSE4.1 /
///   AVX2 backends, so one leaf per thread is both wide and parallel: eight
///   workers, each walking its own 64-byte blocks.
/// * On `aarch64`, `blake2s_simd` ships **no** vector backend — every leaf
///   there runs its portable scalar path — while this crate's own
///   [`crate::crypto::Blake2spLeafGroup`] kernel is 4-wide NEON. So a worker
///   owns a whole 4-leaf group and drives that kernel over the group's
///   contiguous 256-byte half of each super-block: two vector workers instead
///   of eight scalar ones, for the same digest.
// One leaf per worker on EVERY arch for now — including aarch64, where the
// 4-leaf NEON group arrangement exists but is deliberately not wired: it
// saves 2.2x CPU (1.25 -> 0.56 cpu-s/GB) yet measures a 1.75x WALL
// regression on the hash lane (6.22 -> 3.56 GB/s, 256 MiB, min-of-9)
// because the group kernel reaches only ~55% of ideal 4-wide scaling, and
// two vector workers cannot match eight scalar ones. Wall is the
// user-visible metric on store-mode extraction, the dominant archive class.
// Re-wire the aarch64 arms to `crate::crypto::Blake2spLeafGroup` (see git
// history of this file for the exact shape) once the group kernel
// approaches ~4x scaling — two vector workers then win BOTH axes
// (~7.4 GB/s projected). The group kernel and its digest-equivalence tests
// stay live regardless.
const LEAVES_PER_WORKER: usize = 1;

/// Number of BLAKE2sp worker threads (8 leaf workers, or 2 group workers).
const BLAKE_WORKERS: usize = LANES / LEAVES_PER_WORKER;
/// Contiguous bytes a worker owns each time the round robin comes back to it.
/// The leaves a worker owns are adjacent, so its share of every `LANE_STRIDE`
/// cycle is one contiguous run.
const BLAKE_WORKER_SPAN: usize = LEAVES_PER_WORKER * BLAKE_BLOCK;

/// The hash state one worker drives: a single BLAKE2s leaf, or this crate's
/// 4-leaf NEON group. See [`LEAVES_PER_WORKER`].
type BlakeWorkerState = Blake2sState;

/// Build worker `worker`'s state, covering the `LEAVES_PER_WORKER` leaves that
/// start at `worker * LEAVES_PER_WORKER`.
fn new_worker_state(worker: usize) -> BlakeWorkerState {
    blake2sp_leaf_params(worker).to_state()
}

/// Worker `worker`'s finished leaf digests, in leaf order.
fn finish_worker_state(state: &BlakeWorkerState) -> [[u8; 32]; LEAVES_PER_WORKER] {
    let mut digest = [0u8; 32];
    digest.copy_from_slice(state.finalize().as_bytes());
    [digest]
}

struct BlakeLanes {
    lane_tx: Vec<mpsc::SyncSender<LaneMsg>>,
    lane_handles: Vec<JoinHandle<[[u8; 32]; LEAVES_PER_WORKER]>>,
    /// Absolute stream offset of the next incoming byte.
    stream_offset: u64,
}

impl BlakeLanes {
    fn spawn() -> Self {
        let mut lane_tx = Vec::with_capacity(BLAKE_WORKERS);
        let mut lane_handles = Vec::with_capacity(BLAKE_WORKERS);
        for worker in 0..BLAKE_WORKERS {
            let (tx, rx) = mpsc::sync_channel::<LaneMsg>(MAX_IN_FLIGHT);
            let handle = std::thread::Builder::new()
                .name(format!("weaver-rar-b2-{worker}"))
                .spawn(move || {
                    let mut state = new_worker_state(worker);
                    while let Ok(LaneMsg::Data {
                        chunk,
                        stream_offset,
                    }) = rx.recv()
                    {
                        walk_owned_spans(worker, stream_offset, &chunk, |bytes| {
                            state.update(bytes);
                        });
                    }
                    finish_worker_state(&state)
                })
                .expect("spawn BLAKE2sp lane worker");
            lane_tx.push(tx);
            lane_handles.push(handle);
        }
        Self {
            lane_tx,
            lane_handles,
            stream_offset: 0,
        }
    }

    /// Hand the chunk to every worker that owns bytes inside it. Nothing is
    /// deinterleaved here: each worker walks its own spans straight out of the
    /// shared buffer, exactly as unrar's blake2sp threads do.
    fn dispatch(&mut self, chunk: &SharedChunk) {
        if chunk.is_empty() {
            return;
        }
        let stream_offset = self.stream_offset;
        self.stream_offset += chunk.len() as u64;
        for (worker, tx) in self.lane_tx.iter().enumerate() {
            if owned_span_start(worker, BLAKE_WORKER_SPAN, stream_offset)
                >= stream_offset + chunk.len() as u64
            {
                // Short chunk that stops before this worker's next span.
                continue;
            }
            let _ = tx.send(LaneMsg::Data {
                chunk: Arc::clone(chunk),
                stream_offset,
            });
        }
    }

    fn finalize(self) -> [u8; 32] {
        drop(self.lane_tx);

        // Workers are ordered by first leaf, and each yields its leaves in
        // order, so joining in worker order visits leaves 0..8 in order.
        let mut root = blake2sp_root_params().to_state();
        for handle in self.lane_handles {
            let digests = handle.join().unwrap_or([[0u8; 32]; LEAVES_PER_WORKER]);
            for digest in digests {
                root.update(&digest);
            }
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(root.finalize().as_bytes());
        out
    }
}

/// First absolute offset at or after `from` that starts, or lies inside, the
/// `span`-byte run owned by `index` in the stream's `LANE_STRIDE`-periodic
/// round robin. With `span == BLAKE_BLOCK` this is the leaf schedule (BLAKE2sp
/// assigns block `b` to leaf `b % 8`); with `span == BLAKE_WORKER_SPAN` it is
/// the worker schedule, which is the same schedule coarsened to the run of
/// adjacent leaves a worker owns.
fn owned_span_start(index: usize, span: usize, from: u64) -> u64 {
    let cycle = from / LANE_STRIDE;
    let start = cycle * LANE_STRIDE + (index * span) as u64;
    if start + span as u64 <= from {
        // This index's run in the current cycle already went by.
        start + LANE_STRIDE
    } else {
        start
    }
}

/// Hand `consume` the parts of `chunk` that `worker` owns, in order. `chunk`
/// starts at absolute `stream_offset`; chunk edges may split a span, but the
/// pieces still arrive in order, so the worker's state sees exactly its
/// interleaved substream.
fn walk_owned_spans(
    worker: usize,
    stream_offset: u64,
    chunk: &[u8],
    mut consume: impl FnMut(&[u8]),
) {
    walk_spans(
        worker,
        BLAKE_WORKER_SPAN,
        stream_offset,
        chunk,
        &mut consume,
    );
}

/// [`walk_owned_spans`] with an explicit span, so the tests can drive the same
/// walker at leaf granularity as well as worker granularity.
fn walk_spans(
    index: usize,
    span: usize,
    stream_offset: u64,
    chunk: &[u8],
    consume: &mut impl FnMut(&[u8]),
) {
    let end = stream_offset + chunk.len() as u64;
    let mut span_start = owned_span_start(index, span, stream_offset);
    while span_start < end {
        let from = span_start.max(stream_offset);
        let to = (span_start + span as u64).min(end);
        consume(&chunk[(from - stream_offset) as usize..(to - stream_offset) as usize]);
        span_start += LANE_STRIDE;
    }
}

/// BLAKE2sp leaf parameters per the BLAKE2 tree spec (fanout 8, depth 2).
///
/// The leaf-per-worker arrangement builds its worker states from these. On
/// aarch64 the workers are 4-leaf NEON groups that carry the same parameters
/// internally, so there this is only the tests' independent statement of the
/// tree parameters.
fn blake2sp_leaf_params(lane: usize) -> Blake2sParams {
    let mut params = Blake2sParams::new();
    params
        .hash_length(32)
        .fanout(8)
        .max_depth(2)
        .max_leaf_length(0)
        .node_offset(lane as u64)
        .node_depth(0)
        .inner_hash_length(32);
    if lane == LANES - 1 {
        params.last_node(true);
    }
    params
}

/// BLAKE2sp root-node parameters.
fn blake2sp_root_params() -> Blake2sParams {
    let mut params = Blake2sParams::new();
    params
        .hash_length(32)
        .fanout(8)
        .max_depth(2)
        .max_leaf_length(0)
        .node_offset(0)
        .node_depth(1)
        .inner_hash_length(32)
        .last_node(true);
    params
}

/// Threshold at which accumulated writer-path bytes are flushed to the
/// pipeline (keeps channel traffic coarse when the producer writes small
/// spans, as the solid apply phase does).
const PENDING_FLUSH_BYTES: usize = 1024 * 1024;

/// Final digests from a [`SharedHashStream`]. Fields are `Some` iff the
/// corresponding hash was requested at construction.
pub(crate) struct StreamHashOutputs {
    pub crc32: Option<u32>,
    pub rar14: Option<u16>,
    pub blake2sp: Option<[u8; 32]>,
}

enum StreamState {
    /// Hash inline on the submitting thread (small members, or RAR 1.4
    /// checksums which are not worth threading). This is the ONLY member-data
    /// CRC path taken on wasm (the threaded `Pipelined` lane path is
    /// const-folded off there), so its CRC goes through the [`crate::crc::Crc32`]
    /// seam, which delegates to the host under `crc-host` and is byte-identical
    /// `crc32fast` everywhere else.
    Inline {
        crc: Option<Box<crate::crc::Crc32>>,
        rar14: Option<u16>,
        blake: Option<Box<crate::crypto::Blake2spHasher>>,
        pool: Vec<Vec<u8>>,
    },
    /// Hash on worker threads; `pending` coalesces small writer-path updates.
    Pipelined {
        pipeline: HashPipeline,
        pending: Vec<u8>,
    },
    Finished,
}

/// Shared, thread-safe hashing front-end for extraction output streams.
///
/// One instance tracks the checksums of a single member's output stream and
/// is safe to share across successive per-volume writers (`Arc`). Internally
/// it hashes inline for small members and spawns the off-thread
/// [`HashPipeline`] for large ones; `Nop` behavior (no hashes requested)
/// still serves recycled buffers so call sites need no branching.
pub(crate) struct SharedHashStream {
    state: std::sync::Mutex<StreamState>,
}

impl SharedHashStream {
    pub(crate) fn new(
        compute_crc: bool,
        compute_rar14: bool,
        compute_blake: bool,
        expected_len: u64,
    ) -> std::sync::Arc<Self> {
        // `!cfg!(target_family = "wasm")` const-folds to `true` on native (LLVM
        // drops it, leaving the native decision unchanged) and to `false` on
        // wasm, forcing the `StreamState::Inline` path so `HashPipeline::new`
        // (which spawns worker threads) is never constructed on wasm.
        let pipelined = !cfg!(target_family = "wasm")
            && !compute_rar14
            && (compute_crc || compute_blake)
            && expected_len >= PIPELINE_MIN_BYTES;
        let state = if pipelined {
            StreamState::Pipelined {
                pipeline: HashPipeline::new(compute_crc, compute_blake),
                pending: Vec::new(),
            }
        } else {
            StreamState::Inline {
                crc: compute_crc.then(|| Box::new(crate::crc::Crc32::new())),
                rar14: compute_rar14.then_some(0u16),
                blake: compute_blake.then(|| Box::new(crate::crypto::Blake2spHasher::new())),
                pool: Vec::new(),
            }
        };
        std::sync::Arc::new(Self {
            state: std::sync::Mutex::new(state),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, StreamState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Borrow-slice update (writer wrappers). May copy into an internal
    /// accumulation buffer in pipelined mode. Do not mix with
    /// [`Self::submit`] on the same stream.
    pub(crate) fn update(&self, data: &[u8]) -> io::Result<()> {
        let mut state = self.lock();
        match &mut *state {
            StreamState::Inline {
                crc, rar14, blake, ..
            } => {
                inline_update(crc, rar14, blake, data);
                Ok(())
            }
            StreamState::Pipelined { pipeline, pending } => {
                if pending.capacity() == 0 {
                    // Start from a pooled buffer rather than growing a fresh
                    // Vec from zero on the way to the flush threshold.
                    *pending = pipeline.take_buffer();
                }
                pending.extend_from_slice(data);
                if pending.len() >= PENDING_FLUSH_BYTES {
                    // Hand the filled buffer over and take a recycled one back,
                    // so successive chunks cycle pool memory instead of
                    // reallocating multiple MiB per chunk.
                    let chunk = std::mem::replace(pending, pipeline.take_buffer());
                    pipeline.submit(chunk)?;
                }
                Ok(())
            }
            StreamState::Finished => Err(io::Error::other("hash stream already finalized")),
        }
    }

    /// Fetch a recycled, cleared buffer for the zero-extra-copy submit path.
    #[cfg(test)]
    pub(crate) fn take_buffer(&self) -> Vec<u8> {
        let mut buf = self.take_buffer_len(0);
        buf.clear();
        buf
    }

    /// Fetch a recycled buffer resized to exactly `len` bytes. Only bytes
    /// beyond previously written data are zeroed: recycled bytes may hold
    /// stale chunk data, which callers overwrite via `Read` before use.
    pub(crate) fn take_buffer_len(&self, len: usize) -> Vec<u8> {
        let mut buf = {
            let mut state = self.lock();
            match &mut *state {
                StreamState::Inline { pool, .. } => pool.pop().unwrap_or_default(),
                StreamState::Pipelined { pipeline, .. } => pipeline.take_buffer_raw(),
                StreamState::Finished => Vec::new(),
            }
        };
        if buf.len() < len {
            buf.resize(len, 0);
        } else {
            buf.truncate(len);
        }
        buf
    }

    /// Submit an owned in-order chunk previously obtained from
    /// [`Self::take_buffer`]. Do not mix with [`Self::update`].
    pub(crate) fn submit(&self, chunk: Vec<u8>) -> io::Result<()> {
        let mut state = self.lock();
        match &mut *state {
            StreamState::Inline {
                crc,
                rar14,
                blake,
                pool,
            } => {
                inline_update(crc, rar14, blake, &chunk);
                if pool.len() < MAX_IN_FLIGHT {
                    pool.push(chunk);
                }
                Ok(())
            }
            StreamState::Pipelined { pipeline, .. } => pipeline.submit(chunk),
            StreamState::Finished => Err(io::Error::other("hash stream already finalized")),
        }
    }

    /// Finish the stream and return the digests.
    pub(crate) fn finalize(&self) -> io::Result<StreamHashOutputs> {
        let mut state = self.lock();
        match std::mem::replace(&mut *state, StreamState::Finished) {
            StreamState::Inline {
                crc, rar14, blake, ..
            } => Ok(StreamHashOutputs {
                crc32: crc.map(|hasher| hasher.finalize()),
                rar14,
                blake2sp: blake.map(|hasher| hasher.finalize()),
            }),
            StreamState::Pipelined { pipeline, pending } => {
                if !pending.is_empty() {
                    pipeline.submit(pending)?;
                }
                let outputs = pipeline.finalize()?;
                Ok(StreamHashOutputs {
                    crc32: outputs.crc32,
                    rar14: None,
                    blake2sp: outputs.blake2sp,
                })
            }
            StreamState::Finished => Err(io::Error::other("hash stream already finalized")),
        }
    }
}

fn inline_update(
    crc: &mut Option<Box<crate::crc::Crc32>>,
    rar14: &mut Option<u16>,
    blake: &mut Option<Box<crate::crypto::Blake2spHasher>>,
    data: &[u8],
) {
    if let Some(hasher) = crc {
        hasher.update(data);
    }
    if let Some(checksum) = rar14 {
        *checksum = crate::rar4::header::checksum14_update(*checksum, data);
    }
    if let Some(hasher) = blake {
        hasher.update(data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference_blake2sp(data: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(
            blake2s_simd::blake2sp::Params::new()
                .hash_length(32)
                .hash(data)
                .as_bytes(),
        );
        out
    }

    fn deterministic_bytes(len: usize, seed: u64) -> Vec<u8> {
        let mut state = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect()
    }

    fn run_pipeline(data: &[u8], chunk_sizes: &[usize]) -> HashPipelineOutputs {
        let pipeline = HashPipeline::new(true, true);
        let mut offset = 0;
        let mut size_index = 0;
        while offset < data.len() {
            let take = chunk_sizes[size_index % chunk_sizes.len()]
                .max(1)
                .min(data.len() - offset);
            pipeline.update(&data[offset..offset + take]).unwrap();
            offset += take;
            size_index += 1;
        }
        pipeline.finalize().unwrap()
    }

    #[test]
    fn pipeline_matches_reference_hashes_across_sizes() {
        for &len in &[
            0usize, 1, 63, 64, 65, 127, 128, 511, 512, 513, 1024, 4095, 4096, 4097, 65_535, 65_536,
            65_537, 1_000_000,
        ] {
            let data = deterministic_bytes(len, len as u64);
            let outputs = run_pipeline(&data, &[97, 64, 1, 511, 4096, 1 << 20]);
            assert_eq!(
                outputs.crc32.unwrap(),
                crc32fast::hash(&data),
                "crc mismatch at len {len}"
            );
            assert_eq!(
                outputs.blake2sp.unwrap(),
                reference_blake2sp(&data),
                "blake2sp mismatch at len {len}"
            );
        }
    }

    #[test]
    fn pipeline_matches_reference_on_large_streams() {
        let data = deterministic_bytes(23_456_789, 42);
        let outputs = run_pipeline(&data, &[CHUNK_CAPACITY]);
        assert_eq!(outputs.crc32.unwrap(), crc32fast::hash(&data));
        assert_eq!(outputs.blake2sp.unwrap(), reference_blake2sp(&data));
    }

    #[test]
    fn manual_lane_construction_matches_blake2sp_reference() {
        // Direct check of the tree parameters, independent of threading.
        for &len in &[0usize, 1, 64, 512, 5_000, 100_000] {
            let data = deterministic_bytes(len, 7 + len as u64);
            let mut leaves: Vec<_> = (0..LANES)
                .map(|lane| blake2sp_leaf_params(lane).to_state())
                .collect();
            for (index, block) in data.chunks(BLAKE_BLOCK).enumerate() {
                leaves[index % LANES].update(block);
            }
            let mut root = blake2sp_root_params().to_state();
            for leaf in &mut leaves {
                root.update(leaf.finalize().as_bytes());
            }
            let mut out = [0u8; 32];
            out.copy_from_slice(root.finalize().as_bytes());
            assert_eq!(out, reference_blake2sp(&data), "len {len}");
        }
    }

    #[test]
    fn owned_span_start_walks_the_interleave_schedule() {
        // Index I owns the `span`-byte run at I*span in every LANE_STRIDE
        // cycle. Starting inside one of its own runs must return that run, not
        // the next one. Checked at both granularities the walker is used at:
        // the leaf schedule (64) and the worker schedule.
        for &span in &[BLAKE_BLOCK, BLAKE_WORKER_SPAN] {
            for index in 0..(LANE_STRIDE as usize / span) {
                let own = (index * span) as u64;
                assert_eq!(owned_span_start(index, span, 0), own);
                assert_eq!(owned_span_start(index, span, own), own);
                assert_eq!(owned_span_start(index, span, own + 1), own);
                assert_eq!(owned_span_start(index, span, own + span as u64 - 1), own);
                assert_eq!(
                    owned_span_start(index, span, own + span as u64),
                    own + LANE_STRIDE
                );
                // Deep into the stream the schedule is still stride-periodic.
                let base = 97 * LANE_STRIDE;
                assert_eq!(owned_span_start(index, span, base), base + own);
            }
        }
    }

    #[test]
    fn strided_lane_walk_matches_deinterleaved_lanes() {
        // The strided walk must feed each leaf exactly the bytes a copying
        // deinterleave would have handed it, no matter where chunks split.
        for &chunk_len in &[1usize, 7, 63, 64, 65, 200, 512, 513, 4096, 100_000] {
            let data = deterministic_bytes(300_000, chunk_len as u64);
            let mut strided: Vec<_> = (0..LANES)
                .map(|lane| blake2sp_leaf_params(lane).to_state())
                .collect();
            let mut offset = 0u64;
            for chunk in data.chunks(chunk_len) {
                for (lane, state) in strided.iter_mut().enumerate() {
                    walk_spans(lane, BLAKE_BLOCK, offset, chunk, &mut |bytes: &[u8]| {
                        state.update(bytes);
                    });
                }
                offset += chunk.len() as u64;
            }

            let mut copied: Vec<_> = (0..LANES)
                .map(|lane| blake2sp_leaf_params(lane).to_state())
                .collect();
            for (index, block) in data.chunks(BLAKE_BLOCK).enumerate() {
                copied[index % LANES].update(block);
            }

            for lane in 0..LANES {
                assert_eq!(
                    strided[lane].finalize().as_bytes(),
                    copied[lane].finalize().as_bytes(),
                    "lane {lane} diverged at chunk length {chunk_len}"
                );
            }
        }
    }

    /// The worker walk must hand each worker exactly the bytes its leaves own:
    /// worker W's substream, concatenated in order, has to equal the
    /// concatenation of leaves `W*LEAVES_PER_WORKER..` blocks in leaf order.
    /// This is what lets a multi-leaf worker treat its input as one contiguous
    /// round-robin substream.
    #[test]
    fn worker_walk_delivers_exactly_its_leaves_bytes() {
        for &chunk_len in &[1usize, 7, 63, 64, 65, 200, 255, 256, 257, 512, 513, 4096] {
            let data = deterministic_bytes(300_000, 3 + chunk_len as u64);

            let mut walked: Vec<Vec<u8>> = vec![Vec::new(); BLAKE_WORKERS];
            let mut offset = 0u64;
            for chunk in data.chunks(chunk_len) {
                for (worker, sink) in walked.iter_mut().enumerate() {
                    walk_owned_spans(worker, offset, chunk, |bytes| {
                        sink.extend_from_slice(bytes);
                    });
                }
                offset += chunk.len() as u64;
            }

            // Independent construction straight from the BLAKE2sp schedule:
            // 64-byte block `b` belongs to leaf `b % 8`, hence to the worker
            // that owns that leaf. Blocks keep their stream order, which is the
            // round-robin order a multi-leaf worker's state expects.
            let mut expected: Vec<Vec<u8>> = vec![Vec::new(); BLAKE_WORKERS];
            for (index, block) in data.chunks(BLAKE_BLOCK).enumerate() {
                let leaf = index % LANES;
                expected[leaf / LEAVES_PER_WORKER].extend_from_slice(block);
            }
            for worker in 0..BLAKE_WORKERS {
                assert_eq!(
                    walked[worker], expected[worker],
                    "worker {worker} substream diverged at chunk length {chunk_len}"
                );
            }
        }
    }

    /// The in-crate 4-leaf NEON group must produce exactly the leaf digests the
    /// external `blake2s_simd` leaf states produce for the same leaves — the
    /// equality the aarch64 worker arrangement rests on. Driven directly, with
    /// no threads, over lengths that put 0, 1 and 2 blocks in each lane and
    /// straddle the group super-block boundary, and with randomized update
    /// splits so the group's buffering is exercised too.
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn neon_leaf_group_digests_match_external_leaf_states() {
        use crate::crypto::{Blake2spLeafGroup, GROUP_LEAVES};

        let lengths = [
            0usize, 1, 63, 64, 65, 127, 128, 192, 255, 256, 257, 448, 449, 511, 512, 513, 1024,
            4095, 4096, 65_537, 1_000_000,
        ];
        for &len in &lengths {
            let data = deterministic_bytes(len, 999 + len as u64);

            // Reference: the eight external leaf states, deinterleaved.
            let mut leaves: Vec<_> = (0..LANES)
                .map(|lane| blake2sp_leaf_params(lane).to_state())
                .collect();
            for (index, block) in data.chunks(BLAKE_BLOCK).enumerate() {
                leaves[index % LANES].update(block);
            }

            for group in 0..(LANES / GROUP_LEAVES) {
                // The group's own substream, in stream order.
                let mut substream = Vec::new();
                for (index, block) in data.chunks(BLAKE_BLOCK).enumerate() {
                    if (index % LANES) / GROUP_LEAVES == group {
                        substream.extend_from_slice(block);
                    }
                }

                // Feed it in one shot and in uneven splits; both must agree.
                for &split in &[usize::MAX, 1, 63, 64, 193, 256, 449, 1000] {
                    let mut state = Blake2spLeafGroup::new(group);
                    if split == usize::MAX {
                        state.update(&substream);
                    } else {
                        for piece in substream.chunks(split.max(1)) {
                            state.update(piece);
                        }
                    }
                    let digests = state.finalize_leaves();
                    // Idempotent, like the whole-tree state.
                    assert_eq!(digests, state.finalize_leaves(), "finalize not idempotent");

                    for (lane, digest) in digests.iter().enumerate() {
                        let leaf = group * GROUP_LEAVES + lane;
                        assert_eq!(
                            digest.as_slice(),
                            leaves[leaf].finalize().as_bytes(),
                            "leaf {leaf} diverged at len {len}, split {split}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn blake_lanes_share_chunks_without_deinterleaving() {
        // End-to-end through the shared-chunk dispatch, with chunk lengths that
        // are not block multiples so lanes see split blocks across messages.
        for &len in &[0usize, 63, 500, 4096, 5_000_000] {
            let data = deterministic_bytes(len, 11 + len as u64);
            let pipeline = HashPipeline::new(false, true);
            for chunk in data.chunks(333_331) {
                let mut buf = pipeline.take_buffer();
                buf.extend_from_slice(chunk);
                pipeline.submit(buf).unwrap();
            }
            let outputs = pipeline.finalize().unwrap();
            assert_eq!(
                outputs.blake2sp.unwrap(),
                reference_blake2sp(&data),
                "blake2sp mismatch at len {len}"
            );
            assert!(outputs.crc32.is_none());
        }
    }

    #[test]
    fn shared_stream_matches_reference_in_both_modes() {
        // Below the pipeline threshold (inline) and above it (pipelined),
        // via both the update() and take_buffer()/submit() interfaces.
        for &len in &[100_000usize, (PIPELINE_MIN_BYTES as usize) + 12_345] {
            let data = deterministic_bytes(len, len as u64);

            let via_update = SharedHashStream::new(true, false, true, len as u64);
            for chunk in data.chunks(70_001) {
                via_update.update(chunk).unwrap();
            }
            let outputs = via_update.finalize().unwrap();
            assert_eq!(outputs.crc32.unwrap(), crc32fast::hash(&data));
            assert_eq!(outputs.blake2sp.unwrap(), reference_blake2sp(&data));

            let via_submit = SharedHashStream::new(true, false, true, len as u64);
            for chunk in data.chunks(CHUNK_CAPACITY) {
                let mut buf = via_submit.take_buffer();
                buf.extend_from_slice(chunk);
                via_submit.submit(buf).unwrap();
            }
            let outputs = via_submit.finalize().unwrap();
            assert_eq!(outputs.crc32.unwrap(), crc32fast::hash(&data));
            assert_eq!(outputs.blake2sp.unwrap(), reference_blake2sp(&data));
        }
    }

    #[test]
    fn shared_stream_rar14_stays_inline_and_matches() {
        let data = deterministic_bytes(50_000_000, 3);
        let stream = SharedHashStream::new(false, true, false, data.len() as u64);
        stream.update(&data).unwrap();
        let outputs = stream.finalize().unwrap();
        let mut expected = 0u16;
        expected = crate::rar4::header::checksum14_update(expected, &data);
        assert_eq!(outputs.rar14.unwrap(), expected);
        assert!(outputs.crc32.is_none());
    }

    #[test]
    fn crc_only_pipeline_recycles_buffers() {
        let pipeline = HashPipeline::new(true, false);
        let data = deterministic_bytes(3 * CHUNK_CAPACITY + 17, 9);
        for chunk in data.chunks(CHUNK_CAPACITY) {
            let mut buf = pipeline.take_buffer();
            buf.extend_from_slice(chunk);
            pipeline.submit(buf).unwrap();
        }
        let outputs = pipeline.finalize().unwrap();
        assert_eq!(outputs.crc32.unwrap(), crc32fast::hash(&data));
        assert!(outputs.blake2sp.is_none());
    }

    #[test]
    fn crc_shift_op_folds_chunk_crcs() {
        let data: Vec<u8> = (0..1_000_003).map(|i| (i * 131 % 256) as u8).collect();
        let whole = crc32fast::hash(&data);
        for split in [0usize, 1, 63, 4096, 65_536, 999_999, 1_000_003] {
            let (a, b) = data.split_at(split);
            let folded =
                CrcShiftOp::new(b.len() as u64).shift(crc32fast::hash(a)) ^ crc32fast::hash(b);
            assert_eq!(folded, whole, "split at {split}");
        }
    }
}
