//! Read, verify, create, and repair PAR3 recovery sets.
//!
//! The convenience APIs handle default Cauchy sets on disk. The incremental
//! engine adds low-rate FFT, virtual sources, streaming integrity evidence,
//! and retained analysis as protected data and recovery packets arrive.
//! Matched native performance acceptance remains outstanding.
//!
//! # Choose an API
//!
//! - **Inspect or verify:** [`scan_packets_from_path`], [`Par3Set`], [`verify_set`].
//! - **Default Cauchy creation and repair:** [`mod@create`] and [`repair`].
//! - **Incremental or bounded execution:** [`ingest::PacketScanner`],
//!   [`Par3RepairSession`], and [`source::SourceAccess`].
//! - **Advanced creation:** [`creation::CreationPlan`].
//! - **Carrier reconstruction or PAR-inside:** [`carrier`] and [`inside`].
//!
//! All engine APIs are synchronous. The host supplies source identities and
//! generations, owns downloading and scheduling, and chooses repair outputs.
//! See the [streaming engine contract](https://github.com/scryer-media/rarpar/blob/main/crates/par3-rs/ENGINE.md)
//! for evidence replay, resource accounting, and host integration.
//!
//! # Verify a set on disk
//!
//! ```no_run
//! use par3_rs::{Par3Set, VerifyReport, scan_packets_from_path, verify_set};
//! use std::path::Path;
//!
//! # fn main() -> par3_rs::Result<()> {
//! let packets = scan_packets_from_path(Path::new("archive.par3"))?
//!     .into_iter()
//!     .map(|(_offset, packet)| packet)
//!     .collect();
//!
//! for set in Par3Set::from_packets(packets)? {
//!     println!("set {} — {} files", set.input_set_id(), set.files().len());
//!     let report: VerifyReport = verify_set(&set, Path::new("."))?;
//!     println!("{} complete, {} damaged, {} missing",
//!         report.complete_count(), report.damaged_count(), report.missing_count());
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Streaming evidence and repair
//!
//! [`evidence::StreamingVerifier`] accepts positioned decoded bytes and produces
//! sealed evidence tied to the set layout, source identity, and generation.
//! Admit it with [`Par3RepairSession::add_evidence`]. Unchanged assessments and
//! recovery-only merges retain it without rereading protected sources.
//! [`session::RecoveryRequirement`] exposes per-cohort deficits and admissible
//! recovery indices; surplus in one interleaved cohort cannot cover another.
//!
//! Unknown ranges remain unavailable, never implicit zeroes. A checkpoint's
//! digest must be retained in trusted host metadata separately from its bytes;
//! see [`evidence::EvidenceCheckpoint`] before implementing restart replay.
//!
//! # What is in scope
//!
//! - Packet framing, authenticated scanning, and core packet parsing, retaining
//!   unknown packet types verbatim ([`scan`], [`ingest`], [`packet`]).
//! - Set resolution, shared block layouts, packed/inline tails, Data packets,
//!   protected/unprotected extents, and verification ([`set`], [`layout`], [`evidence`]).
//! - Cauchy and low-rate FFT recovery over GF(2⁸) and GF(2¹⁶), including interleaved
//!   cohorts above 65,536 total blocks ([`cauchy`], [`fft`], [`Par3RepairSession`]).
//! - Aligned/sliding deduplication, Data packets, and configurable volume layouts
//!   during advanced creation ([`creation`]); [`mod@create`] preserves defaults.
//! - Explicit source candidates and CRC64 placement with BLAKE3 confirmation
//!   ([`placement`]). Packed tails use their own fingerprints, not an invented
//!   checksum for their shared block.
//! - Recovery-carrier reconstruction and staged Cauchy PAR-inside insertion or
//!   self-repair for supported ZIP, ZIP64, and 7z layouts ([`carrier`], [`inside`]).
//!
//! # What is not
//!
//! - Sparse/explicit matrix execution, high-rate FFT, and parent-set backups.
//! - Permission/link restoration, recursive PAR-inside, and automatic source
//!   directory discovery.
//! - Arbitrary unprotected creation layouts beyond supported container insertion.
//! - Inferring an unknown carrier's original byte order or missing metadata.
//!   Exact restoration requires a captured manifest; explicit replacement APIs
//!   report replacement separately from protected-data completeness.
//! - A supported CLI. The repository's `par3rs` example demonstrates convenience APIs.
//!
//! Ordinary repair does not silently strip embedded protection. Use [`inside`]
//! for those carriers. The convenience verifier reports unprotected chunks as
//! unverifiable, and the convenience repair API executes Cauchy only.
//!
//! # Format notes
//!
//! PAR3 has a published specification draft and a reference implementation that
//! disagree. Where they do, **this crate follows the reference implementation**,
//! because that is what produces the files in circulation. The differences that
//! affect parsing:
//!
//! - **Field size:** one byte, rather than the draft's two-byte field.
//! - **Start packet:** no leading random bytes. The older layout is detected by
//!   body length and preserved.
//! - **InputSetID:** an opaque grouping key; it cannot be recomputed from stored
//!   bytes as the draft describes.
//! - **File hash:** a 16-byte BLAKE3 hash, absent from the draft, over protected
//!   chunks concatenated in file order. Unprotected bytes are omitted.
//! - **Chunks:** no per-chunk fingerprint from the draft layout.
//! - **Cauchy matrix:** `x_I = I`, rather than interleaved `x` values.
//! - **External Data:** full-size blocks only; packed tail blocks are omitted.
//! - **FFT:** low-rate Cantor-field semantics follow the pinned appendix.
//!   GF16 uses `0x1002D`, distinct from Cauchy's `0x1100B`.
//! - **Trivial FFT:** field size zero represents one-input copy recovery or
//!   capacity-one XOR, without transform tables.
//! - **ZIP64 insertion:** the pinned reference requires ZIP size/offset sentinel
//!   fields too; member count alone is insufficient. Corpus recipes normalize
//!   those original ZIP fields before official insertion.
//!
//! Because the InputSetID cannot be recomputed, this crate never validates it —
//! it is only ever compared for equality.
//!
//! # Damage is not an error
//!
//! A `.par3` file exists to survive damage, so the scanner treats a packet whose
//! header hash does not match as noise: it is skipped and the scan resynchronises
//! on the next magic sequence. [`Par3Error`] describes inputs that cannot be
//! interpreted at all, or sets whose packets contradict each other — not bytes
//! that are merely corrupt.
//!
//! # Untrusted input
//!
//! [`runtime::ExecutionOptions`] defaults to 256 MiB shared allocation accounting
//! and 64 MiB retained state per session. Its memory, handle, and scan-work
//! budgets can be shared across operations. Provider storage and allocator
//! overhead remain outside accounting; it is not a process-RSS limit.
//! [`runtime::ExecutionDiagnostics`] and [`runtime::ProgressCallback`] expose
//! work, I/O, timings, and cooperative cancellation. Set worker limits explicitly
//! when the host runs several jobs. [`runtime::ExecutionOptions::fft_backend`]
//! selects automatic or scalar FFT butterflies.
//!
//! Convenience APIs instead use [`ScanLimits`], [`SetLimits`], [`CodecLimits`],
//! [`CreateLimits`], and [`RepairLimits`]. In particular,
//! [`scan_packets_from_path`] reads an entire carrier before applying packet
//! limits; use [`ingest::PacketScanner`] when that allocation must be bounded.
//!
//! The crate forbids unsafe Rust; shared arithmetic uses CPU-specific kernels.
//! Set construction bounds directory expansion and rejects cycles. Parsed path
//! components reject traversal names and separators. These are lexical checks,
//! not a filesystem sandbox: callers must control destination links and changes
//! to the tree during verification or repair.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod carrier;
pub mod cauchy;
pub mod create;
pub mod creation;
pub mod error;
pub mod evidence;
pub mod fft;
pub mod gf;
pub mod hash;
pub mod ingest;
pub mod inside;
pub mod layout;
pub mod placement;
pub mod runtime;
pub mod session;
pub mod session_repair;
pub mod source;

pub use session::Par3RepairSession;
pub mod packet;
pub mod repair;
pub mod scan;
pub mod set;
pub mod verify;

pub use cauchy::{CodecLimits, Decoder, Encoder, Geometry, RecoveredBlock, RecoveryRow};
pub use create::{
    CreateLimits, CreateOptions, CreateReport, InputSpec, RecoveryAmount, create,
    suggest_block_size,
};
pub use error::{Par3Error, Result};
pub use gf::{AnyField, Field, Gf8, Gf16};
pub use hash::{
    FINGERPRINT_LEN, Fingerprint, FingerprintHasher, QUICK_HASH_LEN, RollingHasher, TAIL_HASH_LEN,
    fingerprint, quick_rolling_hash, rolling_hash,
};
pub use packet::{
    BlockChecksum, ChunkDescription, ChunkTail, CommentPacket, CreatorPacket, DataPacket,
    DirectoryPacket, ExternalDataPacket, FilePacket, GaloisField, HEADER_SIZE, InputSetId, MAGIC,
    Packet, PacketBody, PacketHeader, PacketType, ParseContext, RecoveryDataPacket,
    RecoveryExternalDataPacket, RootPacket, StartPacket,
};
pub use repair::{
    RepairLimits, RepairOptions, RepairPlan, RepairReport, RepairedFile, plan_repair, repair_set,
};
pub use scan::{
    ScanLimits, scan_packets, scan_packets_from_path, scan_packets_from_path_with_limits,
    scan_packets_with_limits,
};
pub use set::{Par3Directory, Par3File, Par3Set, RecoveryBlock, SetLimits};
pub use verify::{
    FileReport, FileVerdict, VerifyReport, verify_file, verify_file_at_path, verify_set,
};
