//! `rarpar par3 create -`: a PAR3 set for one file read once from standard
//! input or a pipe.
//!
//! The file's length is unknown until the stream ends, so the operator fixes
//! everything the length would otherwise choose: the name the set records,
//! the block size and the recovery count. The bytes are fed to a
//! [`par3_stream::Lane`] as they arrive; it keeps the block checksums and the
//! recovery rows, never the file, so memory is the rows plus a few dozen bytes
//! per block whatever the stream's length. The set is laid out as
//! par3cmdline's `c` lays out a sibling set, as `par3 archive` writes one.

use std::io::{self, Read};
use std::path::{Path, PathBuf};

use par3_rs::packet::GaloisField;
use rarpar::cli::{Cli, Par3Codec, Par3CreateArgs, Par3Dedup};
use serde_json::{Value, json};

use crate::error::RarparError;
use crate::par3::reject_symlinks;
use crate::par3_stream::{
    self, Coding, FileDigest, LANE_BYTES_PER_BLOCK, Lane, RecoveryChoice, SetSpec, build_set,
    reference_field, sibling_geometry, sibling_paths, write_sibling,
};
use crate::streams::{IO_BUFFER, Input};

const MIB: u64 = 1 << 20;
/// GF(2^8) holds a set only while it has at most this many input blocks.
const GF8_MAX_BLOCKS: u64 = 128;
/// GF(2^16) gives every input block and recovery row its own value below this.
const GF16_ORDER: u64 = 1 << 16;

const GF8: GaloisField = GaloisField {
    size: 1,
    generator: 0x1d,
};
const GF16: GaloisField = GaloisField {
    size: 2,
    generator: 0x100b,
};

/// Refuses the options a set over a stream cannot honour, and names the
/// required ones that are missing.
fn check_options(args: &Par3CreateArgs) -> Result<(String, u64, u64), RarparError> {
    let mut missing = Vec::new();
    if args.name.is_none() {
        missing.push("--name");
    }
    if args.block_size.is_none() {
        missing.push("-s/--block-size");
    }
    if args.recovery_count.is_none() {
        missing.push("-c/--recovery-count");
    }
    if !missing.is_empty() {
        return Err(RarparError::Usage(format!(
            "a set over standard input needs {}: its length is unknown until it ends{}",
            missing.join(", "),
            if args.recovery_percent.is_some() {
                ", so -r/--recovery-percent cannot be used"
            } else {
                ""
            }
        )));
    }
    let unsupported = [
        (args.recovery_percent.is_some(), "-r/--recovery-percent"),
        (args.codec != Par3Codec::Cauchy, "--codec fft"),
        (args.capacity_log2.is_some(), "--capacity-log2"),
        (args.interleave != 0, "--interleave"),
        (args.first_recovery != 0, "-f/--first-recovery"),
        (args.dedup != Par3Dedup::None, "--dedup"),
        (args.data_packets, "--data-packets"),
        (args.volume_blocks.is_some(), "--volume-blocks"),
        (args.volume_bytes.is_some(), "--volume-bytes"),
        (args.base_path.is_some(), "--base-path"),
        (args.scratch_dir.is_some(), "--scratch-dir"),
    ];
    let refused: Vec<&str> = unsupported
        .iter()
        .filter(|(given, _)| *given)
        .map(|(_, flag)| *flag)
        .collect();
    if !refused.is_empty() {
        return Err(RarparError::Usage(format!(
            "{} cannot be used with standard input",
            refused.join(", ")
        )));
    }
    let name = args.name.clone().unwrap_or_default();
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
    {
        return Err(RarparError::Usage(format!(
            "--name must be a single file name, not {name:?}"
        )));
    }
    // A Cauchy set over GF(2^16) codes in two-byte symbols, as par3cmdline
    // rounds an odd block size up.
    let block_size = sibling_geometry(0, args.block_size, RecoveryChoice::Count(0)).block_size;
    let rows = args.recovery_count.unwrap_or_default();
    if rows >= GF16_ORDER {
        return Err(RarparError::Usage(format!(
            "-c/--recovery-count must be below {GF16_ORDER}"
        )));
    }
    Ok((name, block_size, rows))
}

/// Where the set goes: OUTPUT, or the recorded name inside OUTPUT when that is
/// an existing directory. (The global `-o/--output` shares OUTPUT's argument
/// id, so clap fills it with OUTPUT; it is not a second directory here.)
fn stem_for(output: &Path, name: &str) -> PathBuf {
    if output.is_dir() {
        output.join(name)
    } else {
        output.to_path_buf()
    }
}

pub fn create(
    cli: &Cli,
    input: &Path,
    args: &Par3CreateArgs,
) -> Result<(bool, Value), RarparError> {
    let (name, block_size, rows) = check_options(args)?;
    let stem = stem_for(&args.output, &name);
    reject_symlinks(&stem)?;
    // The volumes a full set would have are known now, so a name already
    // taken is refused before the stream is read.
    let (index, volumes) = sibling_paths(&stem, rows);
    let planned: Vec<PathBuf> = std::iter::once(index)
        .chain(volumes.into_iter().map(|(_, _, path)| path))
        .collect();
    for path in &planned {
        reject_symlinks(path)?;
        if !cli.overwrite && std::fs::symlink_metadata(path).is_ok() {
            return Err(RarparError::Unsafe(format!(
                "output exists; pass --overwrite to replace: {}",
                path.display()
            )));
        }
    }
    let fields: &[GaloisField] = if rows < 256 { &[GF8, GF16] } else { &[GF16] };
    let rows_bytes =
        par3_stream::coding_bytes(block_size, rows).saturating_mul(fields.len() as u64);
    // Blocks past the GF(2^16) limit fail the set, so they bound the per-block
    // state too.
    let memory_estimate = rows_bytes
        .saturating_add(GF16_ORDER.saturating_mul(LANE_BYTES_PER_BLOCK))
        .saturating_add(block_size)
        .saturating_add(IO_BUFFER as u64);
    let budget = (cli.par3_memory_mib as u64).saturating_mul(MIB);
    if memory_estimate > budget {
        return Err(RarparError::Resource(format!(
            "{rows} recovery block(s) of {block_size} bytes need about {} MiB, more than --par3-memory-mib allows ({} MiB)",
            memory_estimate.div_ceil(MIB),
            cli.par3_memory_mib
        )));
    }
    let mut report = json!({"operation":"par3_create","success":true,"dry_run":cli.dry_run,
        "input":"-","name":name,"block_size":block_size,"recovery_blocks":rows,
        "memory_estimate_bytes":memory_estimate,"cohorts":1,"scratch_bytes":0});
    if cli.dry_run {
        report["outputs"] = json!(planned);
        return Ok((true, report));
    }

    let mut lane = Lane::new(block_size, false, true);
    for &field in fields {
        lane.add_coding(Coding::new(field, 0, rows, block_size).map_err(RarparError::Data)?);
    }
    lane.begin_chunk();
    let mut digest = FileDigest::new();
    let mut source = Input::open(input)?.into_reader();
    let mut buffer = vec![0u8; IO_BUFFER];
    let mut size = 0u64;
    loop {
        let read = match source.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        };
        let data = &buffer[..read];
        lane.feed(data).map_err(RarparError::Data)?;
        digest.update(data, true);
        size += read as u64;
        // GF(2^8) stops being the set's field for good once the blocks pass
        // what it can hold; its rows are memory nothing will use.
        if lane.block_count() > GF8_MAX_BLOCKS || lane.block_count() + rows > 256 {
            lane.codings_mut().retain(|coding| coding.galois() != GF8);
        }
        if lane.codings().is_empty() {
            return Err(RarparError::Data(format!(
                "{} blocks of {block_size} bytes and {rows} recovery block(s) do not fit GF(2^16); use a larger block size",
                lane.block_count()
            )));
        }
    }
    if size > 0 {
        lane.end_chunk().map_err(RarparError::Data)?;
    }
    lane.finish().map_err(RarparError::Data)?;
    let geometry = sibling_geometry(size, Some(block_size), RecoveryChoice::Count(rows));
    if lane.block_count() != geometry.blocks {
        return Err(RarparError::Data(format!(
            "the stream filled {} blocks where its geometry expects {}",
            lane.block_count(),
            geometry.blocks
        )));
    }
    debug_assert_eq!(
        geometry.galois,
        reference_field(geometry.blocks, 0, geometry.recovery, 0)
    );
    let codings = lane.codings_mut();
    codings.retain(|coding| coding.galois() == geometry.galois);
    let Some(coding) = codings.first_mut() else {
        return Err(RarparError::Data(
            "the set's field cannot hold its input blocks".into(),
        ));
    };
    coding.truncate(geometry.recovery);
    let runs = lane.checksum_runs();
    let creator = par3_stream::creator_text();
    let spec = SetSpec {
        id_name: &name,
        name: &name,
        file_size: size,
        block_size,
        galois: geometry.galois,
        matrix_hint: Some(0),
        quick_hash: digest.quick_hash(),
        fingerprint: digest.fingerprint(),
        chunks: lane.chunks(),
        runs: &runs,
        block_count: lane.block_count(),
        creator: &creator,
    };
    let set = build_set(&spec);
    let rows = lane.codings()[0].rows();
    if let Some(directory) = stem
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(directory)?;
    }
    let outputs = write_sibling(&stem, &set, rows, cli.overwrite)
        .and_then(|staged| staged.install())
        .map_err(|error| match error.kind() {
            io::ErrorKind::AlreadyExists => RarparError::Unsafe(format!(
                "output exists; pass --overwrite to replace: {error}"
            )),
            _ => RarparError::Io(error),
        })?;
    let sizes = outputs
        .iter()
        .map(|path| std::fs::metadata(path).map(|meta| meta.len()))
        .collect::<io::Result<Vec<_>>>()?;
    report["set_id"] = json!(set.set_id.to_string());
    report["source_bytes"] = json!(size);
    report["blocks"] = json!(geometry.blocks);
    report["recovery_blocks"] = json!(geometry.recovery);
    report["field_bytes"] = json!(geometry.galois.size);
    report["outputs"] = json!(outputs);
    report["output_sizes"] = json!(sizes);
    Ok((true, report))
}
