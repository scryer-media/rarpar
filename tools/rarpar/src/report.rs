use crate::discovery::DiscoveryReport;
use crate::error::RarparError;
use par2_rs::{CreationBackend, Par2CreateOutcome, Par2CreatePlan};
use rarpar::cli::Cli;
use serde::Serialize;

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

fn display_paths(paths: &[std::path::PathBuf]) -> Vec<String> {
    paths
        .iter()
        .map(|path| path.display().to_string())
        .collect()
}

pub fn emit_discovery(cli: &Cli, report: &DiscoveryReport) -> Result<(), RarparError> {
    if cli.json {
        println!("{}", serde_json::to_string_pretty(report)?);
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
    for action in &report.planned_actions {
        println!("  plan {}: {}", action.action, action.reason);
    }
    for cleanup in &report.cleanup_candidates {
        if !cleanup.candidates.is_empty() {
            println!("  cleanup candidates: {}", cleanup.candidates.len());
        }
    }
    for action in &report.executed_actions {
        let status = if action.success { "ok" } else { "failed" };
        println!("  ran {} [{}]: {}", action.action, status, action.message);
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
