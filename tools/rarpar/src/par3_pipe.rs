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

use rarpar::cli::{Cli, Par3Codec, Par3CreateArgs, Par3Dedup, SidecarFormat};
use serde_json::{Value, json};

use crate::error::RarparError;
use crate::par3::reject_symlinks;
use crate::sidecar::{GF16_ORDER, SidecarPlan, preflight};
use crate::streams::{IO_BUFFER, Input};

/// Refuses the options a set over a stream cannot honour, and names the
/// required ones that are missing.
fn check_options(args: &Par3CreateArgs) -> Result<(String, SidecarPlan), RarparError> {
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
    let rows = args.recovery_count.unwrap_or_default();
    if rows >= GF16_ORDER {
        return Err(RarparError::Usage(format!(
            "-c/--recovery-count must be below {GF16_ORDER}"
        )));
    }
    let plan = SidecarPlan::new(
        SidecarFormat::Par3,
        args.block_size.unwrap_or_default(),
        rows,
    )?;
    Ok((name, plan))
}

/// Where the set goes: OUTPUT (under the global `-o` directory when one is
/// given), or the recorded name inside it when that is an existing directory.
fn stem_for(cli: &Cli, output: &Path, name: &str) -> PathBuf {
    let output = cli.place_output(output);
    if output.is_dir() {
        output.join(name)
    } else {
        output
    }
}

pub fn create(
    cli: &Cli,
    input: &Path,
    args: &Par3CreateArgs,
) -> Result<(bool, Value), RarparError> {
    let (name, plan) = check_options(args)?;
    let (block_size, rows) = (plan.block_size, plan.rows);
    let stem = stem_for(cli, &args.output, &name);
    reject_symlinks(&stem)?;
    // The volumes a full set would have are known now, so a name already
    // taken is refused before the stream is read.
    let planned: Vec<PathBuf> = plan.paths(&stem);
    preflight(&planned, cli.overwrite)?;
    plan.check_budget(cli.par3_memory_mib)?;
    let memory_estimate = plan.memory_estimate().saturating_add(IO_BUFFER as u64);
    let mut report = json!({"operation":"par3_create","success":true,"dry_run":cli.dry_run,
        "input":"-","name":name,"block_size":block_size,"recovery_blocks":rows,
        "memory_estimate_bytes":memory_estimate,"cohorts":1,"scratch_bytes":0});
    if cli.dry_run {
        report["outputs"] = json!(planned);
        return Ok((true, report));
    }

    let mut sidecar = plan.start()?;
    let mut source = Input::open(input)?.into_reader();
    let mut buffer = vec![0u8; IO_BUFFER];
    loop {
        let read = match source.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        };
        sidecar.feed(&buffer[..read]).map_err(RarparError::Data)?;
    }
    if let Some(directory) = stem
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(directory)?;
    }
    let finished = sidecar.finish(&name, &stem, cli.overwrite)?;
    let set = finished.report.clone();
    let (outputs, sizes) = finished.install()?;
    for key in [
        "set_id",
        "source_bytes",
        "blocks",
        "recovery_blocks",
        "field_bytes",
    ] {
        report[key] = set[key].clone();
    }
    report["outputs"] = json!(outputs);
    report["output_sizes"] = json!(sizes);
    Ok((true, report))
}
