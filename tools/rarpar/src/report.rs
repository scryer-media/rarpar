use crate::discovery::DiscoveryReport;
use crate::error::RarparError;
use crate::rar::RarRestoreOutcome;
use par2_rs::{CreationBackend, Par2CreateOutcome, Par2CreatePlan};
use rarpar::cli::Cli;
use serde::Serialize;
use unrar_rs::{
    ArchiveFormat, DataVolumeStatus, RecoveryReport, RestorePlan, RevTestResult, RevTestStatus,
};

#[derive(Debug, Serialize)]
struct ParCreateReport {
    schema_version: u8,
    command: &'static str,
    status: &'static str,
    dry_run: bool,
    success: bool,
    plan: ParCreatePlanReport,
    outcome: Option<ParCreateOutcomeReport>,
}

#[derive(Debug, Serialize)]
struct ParCreatePlanReport {
    base_path: String,
    output_stem: String,
    main_path: String,
    output_paths: Vec<String>,
    volume_paths: Vec<String>,
    file_count: usize,
    volume_count: usize,
    volume_scheme: &'static str,
    volumes: Vec<ParCreateVolumeReport>,
    sources: Vec<ParCreateSourceReport>,
    slice_size: u64,
    source_slice_count: u32,
    recovery_count: u32,
    first_exponent: u32,
    recovery_exponents: Vec<u32>,
    recovery_set_id: String,
    backend_requested: &'static str,
    backend_selected: &'static str,
    memory: ParCreateMemoryReport,
    dry_run: bool,
    /// Inputs excluded from the set because they are zero-length. A PAR2 set
    /// cannot describe an empty file, so these get no packets and are invisible
    /// to verify/repair — consumers must not read the set as covering them.
    skipped_empty_files: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ParCreateSourceReport {
    path: String,
    par2_name: String,
    file_length: u64,
    slice_count: u32,
}

#[derive(Debug, Serialize)]
struct ParCreateVolumeReport {
    first_exponent: u32,
    recovery_count: u32,
    filename: String,
    path: String,
}

#[derive(Debug, Serialize)]
struct ParCreateMemoryReport {
    source_metadata_bytes: usize,
    source_hash_workspace_bytes: usize,
    critical_packet_bytes: usize,
    main_file_id_workspace_bytes: usize,
    packet_build_workspace_bytes: usize,
    transaction_workspace_bytes: usize,
    validation_workspace_bytes: usize,
    processing_buffer_limit_bytes: usize,
    processing_peak_bytes: usize,
    total_creation_peak_bytes: usize,
    factor_workspace_bytes: usize,
    jit_workspace_bytes: usize,
    stripe_buffer_bytes: usize,
    controller_overhead_blocks: usize,
}

#[derive(Debug, Serialize)]
struct ParCreateOutcomeReport {
    recovery_set_id: String,
    main_path: String,
    volume_paths: Vec<String>,
    output_paths: Vec<String>,
    source_slice_count: u32,
    recovery_count: u32,
    bytes_written: u64,
    dry_run: bool,
    backend_requested: &'static str,
    backend_selected: &'static str,
}

impl ParCreatePlanReport {
    fn from_plan(plan: &Par2CreatePlan, selected_backend: CreationBackend) -> Self {
        Self {
            base_path: plan.base_path.display().to_string(),
            output_stem: plan.output_stem.display().to_string(),
            main_path: plan.main_path.display().to_string(),
            output_paths: display_paths(&plan.output_paths),
            volume_paths: display_paths(&plan.volume_paths),
            file_count: plan.file_count(),
            volume_count: plan.volume_count(),
            volume_scheme: match plan.volume_scheme {
                par2_rs::VolumeScheme::Variable => "variable",
                par2_rs::VolumeScheme::Uniform => "uniform",
                par2_rs::VolumeScheme::Limited => "limited",
            },
            volumes: plan
                .volumes
                .iter()
                .zip(&plan.volume_paths)
                .map(|(volume, path)| ParCreateVolumeReport {
                    first_exponent: volume.first_exponent,
                    recovery_count: volume.recovery_count,
                    filename: volume.filename.clone(),
                    path: path.display().to_string(),
                })
                .collect(),
            sources: plan
                .sources
                .iter()
                .map(|source| ParCreateSourceReport {
                    path: source.path.display().to_string(),
                    par2_name: source.par2_name.clone(),
                    file_length: source.file_length,
                    slice_count: source.slice_count(),
                })
                .collect(),
            slice_size: plan.slice_size,
            source_slice_count: plan.source_slice_count,
            recovery_count: plan.recovery_count,
            first_exponent: plan.first_exponent,
            recovery_exponents: plan.recovery_exponents.clone(),
            recovery_set_id: plan.recovery_set_id.to_string(),
            backend_requested: backend_name(plan.backend),
            backend_selected: backend_name(selected_backend),
            memory: ParCreateMemoryReport {
                source_metadata_bytes: plan.memory.source_metadata_bytes,
                source_hash_workspace_bytes: plan.memory.source_hash_workspace_bytes,
                critical_packet_bytes: plan.memory.critical_packet_bytes,
                main_file_id_workspace_bytes: plan.memory.main_file_id_workspace_bytes,
                packet_build_workspace_bytes: plan.memory.packet_build_workspace_bytes,
                transaction_workspace_bytes: plan.memory.transaction_workspace_bytes,
                validation_workspace_bytes: plan.memory.validation_workspace_bytes,
                processing_buffer_limit_bytes: plan.memory.processing_buffer_limit_bytes,
                processing_peak_bytes: plan.memory.processing_peak_bytes,
                total_creation_peak_bytes: plan.memory.total_creation_peak_bytes,
                factor_workspace_bytes: plan.memory.factor_workspace_bytes,
                jit_workspace_bytes: plan.memory.jit_workspace_bytes,
                stripe_buffer_bytes: plan.memory.stripe_buffer_bytes,
                controller_overhead_blocks: plan.memory.controller_overhead_blocks,
            },
            dry_run: plan.dry_run,
            skipped_empty_files: display_paths(&plan.skipped_empty),
        }
    }
}

impl From<&Par2CreateOutcome> for ParCreateOutcomeReport {
    fn from(outcome: &Par2CreateOutcome) -> Self {
        Self {
            recovery_set_id: outcome.recovery_set_id.to_string(),
            main_path: outcome.main_path.display().to_string(),
            volume_paths: display_paths(&outcome.volume_paths),
            output_paths: display_paths(&outcome.output_paths),
            source_slice_count: outcome.source_slice_count,
            recovery_count: outcome.recovery_count,
            bytes_written: outcome.bytes_written,
            dry_run: outcome.dry_run,
            backend_requested: backend_name(outcome.requested_backend),
            backend_selected: backend_name(outcome.selected_backend),
        }
    }
}

/// `rar restore-volumes --json`: `plan` for a dry run, `outcome` for a real
/// run, never both.
#[derive(Debug, Serialize)]
struct RarRestoreReport {
    schema_version: u8,
    command: &'static str,
    dry_run: bool,
    success: bool,
    message: String,
    plan: Option<RarRestorePlanReport>,
    outcome: Option<RarRestoreOutcomeReport>,
}

#[derive(Debug, Serialize)]
struct RarRestorePlanReport {
    format: &'static str,
    data_count: usize,
    recovery_count: usize,
    needed: usize,
    usable_recovery_count: usize,
    sufficient: bool,
    output_dir: String,
    data_volumes: Vec<RarDataVolumeReport>,
    recovery_volumes: Vec<RarRecoveryVolumeReport>,
}

#[derive(Debug, Serialize)]
struct RarDataVolumeReport {
    /// Zero-based, as `missing_volume_numbers` counts volumes.
    index: usize,
    path: Option<String>,
    status: &'static str,
    /// Set for `wrong_size` only: the `.rev` table's length and the file's.
    expected_size: Option<u64>,
    actual_size: Option<u64>,
    output_path: String,
    set_aside_path: Option<String>,
}

#[derive(Debug, Serialize)]
struct RarRecoveryVolumeReport {
    slot: usize,
    /// Zero-based position in the whole set, data volumes first.
    volume_number: usize,
    path: String,
    status: &'static str,
    usable: bool,
}

#[derive(Debug, Serialize)]
struct RarRestoreOutcomeReport {
    restored_paths: Vec<String>,
    /// Every valid recovery volume the restore read, which can be more than
    /// it needed.
    used_recovery_paths: Vec<String>,
    missing_volume_numbers: Vec<usize>,
}

/// `rar test-volumes --json`: one result per path, in the order given.
#[derive(Debug, Serialize)]
struct RarTestVolumesReport {
    schema_version: u8,
    command: &'static str,
    success: bool,
    results: Vec<RarTestVolumeReport>,
}

#[derive(Debug, Serialize)]
struct RarTestVolumeReport {
    path: String,
    format: Option<&'static str>,
    /// `unreadable` for a file that could not be opened or read, with
    /// `message` naming the I/O error kind.
    status: &'static str,
    /// Set for `crc_mismatch` only.
    expected_crc32: Option<u32>,
    actual_crc32: Option<u32>,
    /// Set for `unreadable` only.
    message: Option<String>,
}

/// A discovery report as `--json` prints it, marked with whether the run was
/// a dry run: an `auto --dry-run` report records the steps it planned, none
/// of which ran, as `executed_actions`.
#[derive(Serialize)]
struct DiscoveryJson<'a> {
    dry_run: bool,
    #[serde(flatten)]
    report: &'a DiscoveryReport,
}

impl RarRestorePlanReport {
    fn from_plan(plan: &RestorePlan) -> Self {
        Self {
            format: rar_format_name(plan.format),
            data_count: plan.data_count,
            recovery_count: plan.recovery_count,
            needed: plan.needed(),
            usable_recovery_count: plan.usable_recovery_count(),
            sufficient: plan.is_sufficient(),
            output_dir: plan.output_dir.display().to_string(),
            data_volumes: plan
                .data_volumes
                .iter()
                .map(|volume| {
                    let (expected_size, actual_size) = match volume.status {
                        DataVolumeStatus::WrongSize { expected, actual } => {
                            (Some(expected), Some(actual))
                        }
                        _ => (None, None),
                    };
                    RarDataVolumeReport {
                        index: volume.index,
                        path: volume.path.as_ref().map(|path| path.display().to_string()),
                        status: data_volume_status_name(&volume.status),
                        expected_size,
                        actual_size,
                        output_path: volume.output_path.display().to_string(),
                        set_aside_path: volume
                            .set_aside_path
                            .as_ref()
                            .map(|path| path.display().to_string()),
                    }
                })
                .collect(),
            recovery_volumes: plan
                .recovery_volumes
                .iter()
                .map(|volume| RarRecoveryVolumeReport {
                    slot: volume.slot,
                    volume_number: volume.volume_number,
                    path: volume.path.display().to_string(),
                    status: rev_status_name(&volume.status),
                    usable: volume.usable,
                })
                .collect(),
        }
    }
}

impl RarRestoreOutcomeReport {
    fn from_report(report: &RecoveryReport) -> Self {
        Self {
            restored_paths: display_paths(&report.restored_paths),
            used_recovery_paths: display_paths(&report.used_recovery_paths),
            missing_volume_numbers: report.missing_volume_numbers.clone(),
        }
    }
}

impl RarTestVolumeReport {
    fn from_result(result: &RevTestResult) -> Self {
        let (expected_crc32, actual_crc32) = match result.status {
            RevTestStatus::CrcMismatch { expected, actual } => (Some(expected), Some(actual)),
            _ => (None, None),
        };
        let message = match result.status {
            RevTestStatus::Unreadable { kind } => Some(kind.to_string()),
            _ => None,
        };
        Self {
            path: result.path.display().to_string(),
            format: result.format.map(rar_format_name),
            status: rev_status_name(&result.status),
            expected_crc32,
            actual_crc32,
            message,
        }
    }
}

fn rar_format_name(format: ArchiveFormat) -> &'static str {
    match format {
        ArchiveFormat::Rar14 => "rar14",
        ArchiveFormat::Rar4 => "rar4",
        ArchiveFormat::Rar5 => "rar5",
    }
}

fn rev_status_name(status: &RevTestStatus) -> &'static str {
    match status {
        RevTestStatus::Ok => "ok",
        RevTestStatus::CrcMismatch { .. } => "crc_mismatch",
        RevTestStatus::InvalidHeader => "invalid_header",
        RevTestStatus::Unverifiable => "unverifiable",
        RevTestStatus::NotRecoveryVolume => "not_recovery_volume",
        RevTestStatus::Missing => "missing",
        RevTestStatus::Unreadable { .. } => "unreadable",
        _ => "unknown",
    }
}

fn data_volume_status_name(status: &DataVolumeStatus) -> &'static str {
    match status {
        DataVolumeStatus::Valid => "valid",
        DataVolumeStatus::Missing => "missing",
        DataVolumeStatus::WrongSize { .. } => "wrong_size",
        DataVolumeStatus::CrcMismatch => "crc_mismatch",
        DataVolumeStatus::InvalidHeaders => "invalid_headers",
        _ => "unknown",
    }
}

fn display_paths(paths: &[std::path::PathBuf]) -> Vec<String> {
    paths
        .iter()
        .map(|path| path.display().to_string())
        .collect()
}

pub fn emit_discovery(cli: &Cli, report: &DiscoveryReport) -> Result<(), RarparError> {
    if cli.json {
        let report = DiscoveryJson {
            dry_run: cli.dry_run,
            report,
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    if cli.quiet {
        return Ok(());
    }

    println!("rarpar discovery");
    println!("  roots: {}", report.roots.len());
    println!("  recursive: {}", report.recursive);
    println!("  files inspected: {}", report.files.len());
    for set in &report.sets {
        println!(
            "  set {}: rar={}, rev={}, par2={}",
            set.label, set.rar_volumes, set.rar_recovery_volumes, set.par2_files
        );
    }
    for set in &report.par3_sets {
        println!(
            "  PAR3 set {}: {} carrier(s), {} protected file(s), metadata complete={}",
            set.id,
            set.paths.len(),
            set.protected_files.len(),
            set.metadata_complete
        );
    }
    for action in &report.planned_actions {
        println!("  plan {}: {}", action.action, action.reason);
    }
    for cleanup in &report.cleanup_candidates {
        if !cleanup.candidates.is_empty() {
            println!("  cleanup candidates: {}", cleanup.candidates.len());
        }
    }
    // A dry run records the restores it planned, none of which it ran.
    let ran = if cli.dry_run { "dry-run" } else { "ran" };
    for action in &report.executed_actions {
        let status = if !action.success {
            "failed"
        } else if action.deferred_to.is_some() {
            "deferred"
        } else {
            "ok"
        };
        println!("  {ran} {} [{}]: {}", action.action, status, action.message);
    }
    for cleanup in &report.cleanup_results {
        let status = if cleanup.success { "ok" } else { "failed" };
        println!(
            "  cleanup [{}]: {} candidate(s), {}",
            status,
            cleanup.candidates.len(),
            cleanup.message
        );
    }
    Ok(())
}

pub fn emit_par_create_plan(cli: &Cli, plan: &Par2CreatePlan) -> Result<(), RarparError> {
    // Not gated on --quiet: an input the set will NOT protect is a warning,
    // not progress chrome, and the reference tool prints it on every noise
    // level for the same reason. JSON mode instead carries the list in the
    // report's `skipped_empty_files`, where a machine consumer will look.
    if !cli.json {
        for path in &plan.skipped_empty {
            eprintln!(
                "rarpar: skipping empty file (a PAR2 set cannot protect it): {}",
                path.display()
            );
        }
    }
    if !cli.json && !cli.quiet {
        print_plan_summary(plan);
    }
    Ok(())
}

pub fn emit_par_create_outcome(
    cli: &Cli,
    plan: &Par2CreatePlan,
    outcome: &Par2CreateOutcome,
) -> Result<(), RarparError> {
    if cli.json {
        let report = ParCreateReport {
            schema_version: 1,
            command: "create",
            status: if outcome.dry_run {
                "planned"
            } else {
                "created"
            },
            dry_run: outcome.dry_run,
            success: true,
            plan: ParCreatePlanReport::from_plan(plan, outcome.selected_backend),
            outcome: Some(outcome.into()),
        };
        println!("{}", serde_json::to_string(&report)?);
    } else if !cli.quiet {
        eprintln!(
            "  {}",
            if outcome.dry_run {
                "dry-run complete"
            } else {
                "creation complete"
            }
        );
        eprintln!(
            "  backend requested: {}",
            backend_name(outcome.requested_backend)
        );
        eprintln!(
            "  backend selected: {}",
            backend_name(outcome.selected_backend)
        );
        eprintln!(
            "  {}: {}",
            if outcome.dry_run {
                "outputs planned"
            } else {
                "created outputs"
            },
            outcome.output_paths.len()
        );
        eprintln!("  bytes written: {}", outcome.bytes_written);
    }
    Ok(())
}

pub fn emit_rar_restore(cli: &Cli, outcome: &RarRestoreOutcome) -> Result<(), RarparError> {
    if cli.json {
        let report = RarRestoreReport {
            schema_version: 1,
            command: "rar_restore_volumes",
            dry_run: outcome.dry_run,
            success: outcome.success,
            message: outcome.message.clone(),
            plan: outcome.plan.as_ref().map(RarRestorePlanReport::from_plan),
            outcome: outcome
                .report
                .as_ref()
                .map(RarRestoreOutcomeReport::from_report),
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else if !cli.quiet {
        println!("{}", outcome.message);
    }
    Ok(())
}

pub fn emit_rar_test_volumes(
    cli: &Cli,
    success: bool,
    results: &[RevTestResult],
) -> Result<(), RarparError> {
    if cli.json {
        let report = RarTestVolumesReport {
            schema_version: 1,
            command: "rar_test_volumes",
            success,
            results: results
                .iter()
                .map(RarTestVolumeReport::from_result)
                .collect(),
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else if !cli.quiet {
        for result in results {
            let status = match result.status {
                RevTestStatus::Ok => "OK".to_string(),
                RevTestStatus::CrcMismatch { expected, actual } => {
                    format!("CRC32 mismatch (expected {expected:08x}, actual {actual:08x})")
                }
                RevTestStatus::InvalidHeader => "invalid recovery volume header".to_string(),
                RevTestStatus::Unverifiable => {
                    "RAR 3.0 name-form recovery volume carries no checksum".to_string()
                }
                RevTestStatus::NotRecoveryVolume => "not a recovery volume".to_string(),
                RevTestStatus::Missing => "missing".to_string(),
                RevTestStatus::Unreadable { kind } => format!("unreadable ({kind})"),
                // A status this build does not know yet, named as the
                // library debug-prints it.
                ref status => format!("{status:?}"),
            };
            println!("{}: {status}", result.path.display());
        }
    }
    Ok(())
}

fn print_plan_summary(plan: &Par2CreatePlan) {
    eprintln!("rarpar par create");
    eprintln!("  output: {}", plan.main_path.display());
    eprintln!("  base path: {}", plan.base_path.display());
    eprintln!("  source files: {}", plan.file_count());
    eprintln!("  source slices: {}", plan.source_slice_count);
    eprintln!("  slice size: {} bytes", plan.slice_size);
    eprintln!("  recovery slices: {}", plan.recovery_count);
    eprintln!("  recovery volumes: {}", plan.volume_count());
    eprintln!("  backend requested: {}", backend_name(plan.backend));
    if plan.dry_run {
        eprintln!("  dry-run: no files written");
    }
}

fn backend_name(backend: par2_rs::CreationBackend) -> &'static str {
    match backend {
        par2_rs::CreationBackend::Cpu => "cpu",
        par2_rs::CreationBackend::Auto => "auto",
        par2_rs::CreationBackend::Metal => "metal",
    }
}
