//! Reading PAR3 (Parity Volume Set 3.0) recovery files.
//!
//! This crate parses `.par3` packets, groups them into input sets, resolves the
//! directory tree a set describes, and checks input files against it. It is a
//! **work in progress**: it reads and inspects PAR3, and does not create or
//! repair anything.
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
//!   directories to paths ([`set`]).
//! - Whole-file verification, with damage narrowed down to input blocks
//!   ([`verify`]).
//!
//! # What is not
//!
//! None of the following is implemented, and none of it is planned for this
//! release:
//!
//! - Creating PAR3 files.
//! - Recovery or repair of damaged files, and the Galois-field arithmetic that
//!   would need. Matrix and Recovery Data packets are parsed and retained, but
//!   nothing is computed from them.
//! - The sliding rolling-hash search that finds blocks whose position in a file
//!   has moved. Verification compares bytes where the packets say they should
//!   be.
//! - Verifying tail packing beyond each file's own whole-file hash.
//! - Incremental backups: a Start packet's parent set is exposed, but parent
//!   packets are never followed.
//! - Permissions and link packets, beyond keeping their bytes.
//! - "Par inside", where PAR3 packets live within the file they protect. Files
//!   with unprotected chunks are reported as unverifiable.
//! - Any command-line interface.
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
//! | `PAR FFT\0` | Not specified | Written by the reference implementation; parsed here |
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
//! `unsafe` code; allocations are bounded by [`ScanLimits`] and
//! [`SetLimits`] rather than by lengths a packet claims; the
//! directory walk is iterative and refuses cycles; and File and Directory names
//! that are empty, `.`, `..`, or contain a path separator are refused at parse
//! time, so a set cannot direct a read outside the directory it is verified
//! against.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod hash;
pub mod packet;
pub mod scan;
pub mod set;
pub mod verify;

pub use error::{Par3Error, Result};
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
pub use scan::{
    ScanLimits, scan_packets, scan_packets_from_path, scan_packets_from_path_with_limits,
    scan_packets_with_limits,
};
pub use set::{Par3Directory, Par3File, Par3Set, SetLimits};
pub use verify::{
    FileReport, FileVerdict, VerifyReport, verify_file, verify_file_at_path, verify_set,
};
