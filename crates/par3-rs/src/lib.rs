//! Reading, creating and repairing PAR3 (Parity Volume Set 3.0) recovery files.
//!
//! This crate parses `.par3` packets, groups them into input sets, resolves the
//! directory tree a set describes, checks input files against it, computes the
//! Cauchy Reed-Solomon code PAR3 recovery data is built from, writes a complete
//! set — an index file and its recovery volumes — from a list of input files,
//! and puts damaged and missing files back from the recovery blocks a set
//! carries.
//!
//! It is a **work in progress**. The original convenience APIs retain their
//! default Cauchy behavior. The incremental [`Par3RepairSession`] adds virtual
//! sources, streaming evidence, shared block layouts, retained assessments,
//! bounded striped repair, and low-rate FFT recovery with interleaved cohorts.
//! FFT butterflies dispatch Cantor-derived shuffle maps on supported CPUs;
//! [`ExecutionOptions::fft_backend`] retains an explicit scalar comparison path.
//! FFT worker pools obey the worker and allocation ceilings and join their
//! threads before releasing stack reservations; small stripes run synchronously.
//! Data packets are checked against block and tail fingerprints once per layout
//! and source generation; recovery-only merges retain these results. Reconstruction
//! from available Data and aliases does not require a Galois field or matrix.
//! [`runtime::ScanWorkBudget`] bounds cumulative carrier read requests across
//! scanners, retries and seeks independently of the shared allocation budget.
//! Carrier generation changes invalidate recovery availability without rereading
//! protected sources. Verification resumes after honest sequential readers stop
//! at holes, omitting unprotected gaps from the whole protected-data fingerprint.
//! Performance acceptance and the remaining advanced capabilities are still
//! being developed; see [what is not in scope](#what-is-not).
//! The crate's `ENGINE.md` documents the Weaver integration contract, including
//! source identity, evidence, lifecycle, resource limits, and remaining acceptance.
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
//! # What is in scope
//!
//! - The two PAR3 hash functions: CRC-64/GO-ISO and 16-byte BLAKE3
//!   ([`hash`]).
//! - Packet framing, scanning a byte range for packets, and skipping damage
//!   ([`scan`]).
//! - Typed parsing *and* re-serialisation of the core packet types, with every
//!   other type retained verbatim ([`packet`]).
//! - Assembling packets into an input set and resolving its files and
//!   directories to paths, and taking inventory of the recovery blocks the set
//!   carries ([`set`]).
//! - Whole-file verification, with damage narrowed down to input blocks
//!   ([`verify`]).
//! - Arithmetic in the two Galois fields PAR3 uses, GF(2^8) and GF(2^16)
//!   ([`gf`]).
//! - The Cauchy Reed-Solomon codec: computing a set's recovery blocks from its
//!   input blocks, and solving for lost input blocks from the recovery blocks
//!   that survived ([`cauchy`]).
//! - Creating a set: planning the blocks, packing chunk tails, building the
//!   packets and writing the index file and recovery volumes ([`mod@create`]).
//! - Repairing a set: working out which input blocks were lost, solving for
//!   them, and writing every damaged or missing file back over a backup of the
//!   damaged one ([`repair`]).
//!
//! # What is not
//!
//! The following capabilities are not implemented:
//!
//! - Inferring an unknown recovery carrier's original layout. [`carrier`]
//!   reconstructs captured layouts exactly, or writes an explicitly requested
//!   replacement from verified input blocks and authenticated matrix metadata.
//! - Sparse and explicit matrix execution, and high-rate FFT. Low-rate FFT
//!   execution is available through [`fft`] and the retained session.
//! - Automatic directory discovery. [`placement`] accepts explicit candidates
//!   and locates moved extents using CRC64 followed by BLAKE3 confirmation.
//! - Checking a block of packed tails as a block. Each file's own tail is
//!   checked against the hashes in its chunk description; the block those tails
//!   share carries no checksum of its own — the reference implementation leaves
//!   tail blocks out of its External Data packets — and is never checked as a
//!   unit.
//! - Incremental backups: a Start packet's parent set is exposed, but parent
//!   packets are never followed.
//! - Permissions and link packets, beyond keeping their bytes.
//! - PAR-inside repair without a captured authenticated carrier manifest.
//!   [`inside::SelfRepairPlan`] stages protected-data reconstruction, preserves
//!   valid packets and regenerates missing packets from verified input blocks.
//!   Reference ZIP/ZIP64 and 7z fixtures restore byte for byte, including packet holes.
//!   [`inside::InsertionPlan`] supports staged Cauchy
//!   insertion into ZIP/ZIP64 and 7z, validated by the reference's self-verifier
//!   and self-repairer after protected-byte damage. The convenience
//!   verifier still reports unprotected chunks as unverifiable.
//! - Arbitrary unprotected creation layouts, permission or link packets, and parent sets.
//!   Advanced standalone creation in [`creation`] supports Cauchy or low-rate
//!   FFT, interleaving, aligned/sliding deduplication, Data packets, and variable,
//!   uniform, or size-limited volumes. [`mod@create`] keeps its original defaults.
//! - Any command-line interface. `examples/par3rs.rs` drives this API from a
//!   shell to demonstrate it; it is not a tool.
//!
//! # Format notes
//!
//! PAR3 has a published specification draft and a reference implementation that
//! disagree. Where they do, **this crate follows the reference implementation**,
//! because that is what produces the files in circulation. The differences that
//! affect parsing:
//!
//! | Area | Specification draft | What this crate reads |
//! | --- | --- | --- |
//! | Galois field size | 2-byte field | 1 byte |
//! | Start packet | Begins with 8 random bytes | No random bytes; the older layout is detected by body length and retained |
//! | InputSetID | First 8 bytes of the BLAKE3 of the Start body | Not derivable from anything stored; an opaque grouping key |
//! | File packet | No whole-file hash | 16-byte BLAKE3 of the file's protected data |
//! | Chunk descriptions | Per-chunk fingerprint | No per-chunk fingerprint |
//! | Cauchy matrix | Interleaved `x` values | `x_I = I` |
//! | External Data | Every input block | Full-size blocks only; blocks holding chunk tails are omitted |
//! | `PAR FFT\0` | Not specified | Low-rate Cantor-field execution follows the pinned reference appendix; GF16 uses polynomial `0x1002D`, distinct from Cauchy |
//! | Trivial FFT field | Not specified | Field size zero denotes copy recovery for one input, or XOR for recovery capacity one; byte stripes need no transform tables |
//! | ZIP64 insertion detection | ZIP64 can be required by member count alone | The pinned reference requires size/offset sentinels too; the corpus normalizes these original ZIP fields before insertion |
//! | Unprotected file hash | The draft does not define this File-packet hash | Concatenate protected chunks, omitting unprotected bytes; earlier crate docs incorrectly described zero substitution |
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
//! Every entry point is written to be safe on hostile bytes. There is no
//! `unsafe` code; allocations are bounded by [`ScanLimits`], [`SetLimits`],
//! [`CodecLimits`], [`CreateLimits`] and [`RepairLimits`] rather than by lengths
//! a packet or a caller claims; verifying and repairing read a bounded region at
//! a time rather than a whole file; the
//! directory walk is iterative and refuses cycles; and File and Directory names
//! that are empty, `.`, `..`, or contain a path separator are refused at parse
//! time, so a set cannot direct a read outside the directory it is verified
//! against.

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
