use crate::cli::Cli;
use crate::discovery::DiscoveryReport;
use crate::error::RarparError;

pub fn emit_discovery(cli: &Cli, report: &DiscoveryReport) -> Result<(), RarparError> {
    if cli.json {
        println!("{}", serde_json::to_string_pretty(report)?);
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
