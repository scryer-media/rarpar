use std::collections::{BTreeSet, HashSet};
use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::CommandFactory;
use clap_complete::shells::{Bash, Elvish, Fish, PowerShell, Zsh};
use clap_complete::{Generator, generate};
use clap_mangen::Man;
use rarpar::cli::Cli;
use serde::Deserialize;

mod test_corpus;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const BIN_NAME: &str = "rarpar";
const MAN_REL: &str = "share/man/man1/rarpar.1";
const BASH_REL: &str = "share/bash-completion/completions/rarpar";
const ZSH_REL: &str = "share/zsh/site-functions/_rarpar";
const FISH_REL: &str = "share/fish/vendor_completions.d/rarpar.fish";
const ELVISH_REL: &str = "share/elvish/lib/rarpar.elv";
const POWERSHELL_REL: &str = "share/powershell/Completions/rarpar.ps1";
const GENERATED_SENTINEL: &str = ".rarpar-xtask-generated";

fn main() {
    if let Err(error) = run() {
        eprintln!("xtask: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut args = env::args_os();
    let _program = args.next();
    match args
        .next()
        .and_then(|arg| arg.into_string().ok())
        .as_deref()
    {
        Some("docs") => run_docs(args.collect()),
        Some("package-root") => run_package_root(args.collect()),
        Some("feature-audit") => run_feature_audit(args.collect()),
        Some("bench") => run_bench(args.collect()),
        Some("test-corpus") => test_corpus::run(args.collect()),
        Some("-h" | "--help") | None => {
            print_usage();
            Ok(())
        }
        Some(command) => fail(format!("unknown xtask command {command:?}")),
    }
}

fn print_usage() {
    eprintln!(
        "\
Usage:
  cargo run -p xtask -- docs [--out DIR]
  cargo run -p xtask -- docs --check
  cargo run -p xtask -- package-root --binary PATH --out DIR [--docs DIR] [--target TRIPLE]
  cargo run -p xtask -- feature-audit --manifest PATH --target TRIPLE --features LIST
  cargo run -p xtask -- bench <toolchains|corpus|payload|plan|preflight|run|report|render> [OPTIONS]
  cargo run -p xtask -- bench all-hosts [--config PATH] [--jobs N]
  cargo run -p xtask -- test-corpus <generate|bench-pins|build|verify|fetch|hydrate|sign|publish> [OPTIONS]"
    );
}

fn run_bench(args: Vec<OsString>) -> Result<()> {
    if args.first().is_some_and(|arg| arg == "all-hosts") {
        return run_bench_all_hosts(args.into_iter().skip(1).collect());
    }

    let bench_root = workspace_root().join("bench/rarpar-bench");
    if !bench_root.join("go.mod").is_file() {
        return fail("benchmark harness is missing bench/rarpar-bench/go.mod");
    }
    let status = Command::new("go")
        .args(["run", "./cmd/rarpar-bench"])
        .args(args)
        .current_dir(&bench_root)
        .env("RARPAR_BENCH_WORKSPACE_ROOT", workspace_root())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        fail(format!("benchmark harness exited with {status}"))
    }
}

struct BenchAllHostsOptions {
    config: PathBuf,
    jobs: Option<usize>,
}

impl BenchAllHostsOptions {
    fn parse(args: Vec<OsString>) -> Result<Self> {
        let mut config = None;
        let mut jobs = None;
        let mut args = args.into_iter();
        while let Some(argument) = args.next() {
            match argument.to_str() {
                Some("--config") => config = Some(next_path(&mut args, "--config")?),
                Some("--jobs") => {
                    let value = next_string(&mut args, "--jobs")?;
                    let parsed = value
                        .parse::<usize>()
                        .map_err(|_| error("--jobs must be a positive integer"))?;
                    if parsed == 0 {
                        return fail("--jobs must be a positive integer");
                    }
                    jobs = Some(parsed);
                }
                _ => return fail(format!("unknown bench all-hosts option {argument:?}")),
            }
        }
        Ok(Self {
            config: config.unwrap_or_else(default_bench_hosts_config),
            jobs,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BenchHostsConfig {
    schema_version: u32,
    hosts: Vec<BenchHost>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BenchHost {
    label: String,
    host: String,
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    identity_file: Option<PathBuf>,
    #[serde(default)]
    ssh_options: Vec<String>,
    workspace_dir: String,
    corpus_dir: String,
    output_dir: String,
    candidate: String,
    reference_rar: String,
    reference_par2: String,
    source_target: String,
    #[serde(default = "default_bench_go_binary")]
    go_binary: String,
    #[serde(default)]
    path: Option<String>,
    #[serde(default = "default_bench_candidate_label")]
    candidate_label: String,
    #[serde(default = "default_bench_reference_label")]
    reference_label: String,
    #[serde(default = "default_bench_seed")]
    seed: String,
    #[serde(default = "default_bench_lane")]
    lane: String,
    #[serde(default)]
    family: Option<String>,
    #[serde(default = "default_bench_par2_placement")]
    par2_placement: String,
    #[serde(default = "default_bench_warmups")]
    warmups: usize,
    #[serde(default = "default_bench_repeats")]
    repeats: usize,
}

fn default_bench_hosts_config() -> PathBuf {
    workspace_root().join("bench/rarpar-bench/config/hosts.local.json")
}

fn default_bench_go_binary() -> String {
    "go".to_owned()
}

fn default_bench_candidate_label() -> String {
    "rarpar".to_owned()
}

fn default_bench_reference_label() -> String {
    "reference".to_owned()
}

fn default_bench_seed() -> String {
    "rarpar-benchmark-plan-v1".to_owned()
}

fn default_bench_lane() -> String {
    "cpu".to_owned()
}

fn default_bench_par2_placement() -> String {
    "canonical".to_owned()
}

fn default_bench_warmups() -> usize {
    1
}

fn default_bench_repeats() -> usize {
    5
}

fn run_bench_all_hosts(args: Vec<OsString>) -> Result<()> {
    if args.len() == 1 && matches!(args[0].to_str(), Some("-h" | "--help")) {
        eprintln!(
            "Usage: cargo run --locked -p xtask -- bench all-hosts [--config PATH] [--jobs N]"
        );
        return Ok(());
    }
    let options = BenchAllHostsOptions::parse(args)?;
    let config = load_bench_hosts_config(&options.config)?;
    let jobs = options
        .jobs
        .unwrap_or(config.hosts.len())
        .min(config.hosts.len());
    let next = AtomicUsize::new(0);
    let results = Mutex::new(Vec::with_capacity(config.hosts.len()));

    thread::scope(|scope| {
        for _ in 0..jobs {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    if index >= config.hosts.len() {
                        return;
                    }
                    let host = &config.hosts[index];
                    eprintln!("bench all-hosts [{}]: started", host.label);
                    let result = run_bench_host(host).map_err(|error| error.to_string());
                    match &result {
                        Ok(()) => eprintln!("bench all-hosts [{}]: completed", host.label),
                        Err(error) => {
                            eprintln!("bench all-hosts [{}]: failed: {error}", host.label)
                        }
                    }
                    results
                        .lock()
                        .expect("benchmark result lock must not be poisoned")
                        .push((host.label.as_str(), result));
                }
            });
        }
    });

    let mut failures = results
        .into_inner()
        .expect("benchmark result lock must not be poisoned")
        .into_iter()
        .filter_map(|(label, result)| result.err().map(|error| format!("{label}: {error}")))
        .collect::<Vec<_>>();
    if failures.is_empty() {
        return Ok(());
    }
    failures.sort();
    fail(format!("benchmark host failures:\n{}", failures.join("\n")))
}

fn load_bench_hosts_config(path: &Path) -> Result<BenchHostsConfig> {
    let data =
        fs::read(path).map_err(|source| error(format!("read {}: {source}", path.display())))?;
    let config: BenchHostsConfig = serde_json::from_slice(&data)
        .map_err(|source| error(format!("decode {}: {source}", path.display())))?;
    validate_bench_hosts_config(&config)?;
    Ok(config)
}

fn validate_bench_hosts_config(config: &BenchHostsConfig) -> Result<()> {
    if config.schema_version != 1 {
        return fail("benchmark hosts config schema_version must be 1");
    }
    if config.hosts.is_empty() {
        return fail("benchmark hosts config must declare at least one host");
    }
    let mut labels = HashSet::new();
    let mut outputs = HashSet::new();
    for host in &config.hosts {
        validate_bench_value("host label", &host.label)?;
        if !labels.insert(&host.label) {
            return fail(format!(
                "benchmark host label is duplicated: {}",
                host.label
            ));
        }
        validate_bench_value("host", &host.host)?;
        if host.host.starts_with('-') {
            return fail(format!(
                "benchmark host must not begin with '-': {}",
                host.host
            ));
        }
        let short_host = host.host.split('.').next().unwrap_or(&host.host);
        if host.label.eq_ignore_ascii_case(&host.host)
            || host.label.eq_ignore_ascii_case(short_host)
        {
            return fail(
                "benchmark host label must describe the machine without using its hostname",
            );
        }
        if let Some(user) = &host.user {
            validate_bench_value("SSH user", user)?;
            if user.contains('@') {
                return fail("SSH user must not contain '@'");
            }
        }
        for option in &host.ssh_options {
            validate_bench_value("SSH option", option)?;
        }
        for (name, path) in [
            ("workspace_dir", &host.workspace_dir),
            ("corpus_dir", &host.corpus_dir),
            ("output_dir", &host.output_dir),
            ("candidate", &host.candidate),
            ("reference_rar", &host.reference_rar),
            ("reference_par2", &host.reference_par2),
        ] {
            validate_remote_absolute_path(name, path)?;
        }
        let output_key = format!(
            "{}\0{}\0{}\0{}",
            host.user.as_deref().unwrap_or(""),
            host.host.to_ascii_lowercase(),
            host.port.unwrap_or(22),
            host.output_dir
        );
        if !outputs.insert(output_key) {
            return fail("benchmark hosts must not share an SSH endpoint and output directory");
        }
        for (name, value) in [
            ("source_target", &host.source_target),
            ("go_binary", &host.go_binary),
            ("candidate_label", &host.candidate_label),
            ("reference_label", &host.reference_label),
            ("seed", &host.seed),
            ("lane", &host.lane),
            ("par2_placement", &host.par2_placement),
        ] {
            validate_bench_value(name, value)?;
        }
        if let Some(path) = &host.path {
            validate_bench_value("PATH", path)?;
        }
        if let Some(family) = &host.family
            && family != "rar"
            && family != "par2"
        {
            return fail("benchmark family must be rar or par2");
        }
        if host.lane != "cpu" && host.lane != "metal" && host.lane != "docker-cpu" {
            return fail(format!("benchmark lane is unsupported: {}", host.lane));
        }
        if host.par2_placement != "canonical" && host.par2_placement != "smart" {
            return fail(format!(
                "benchmark PAR2 placement is unsupported: {}",
                host.par2_placement
            ));
        }
        if host.repeats == 0 {
            return fail("benchmark repeats must be positive");
        }
        if let Some(identity_file) = &host.identity_file {
            let identity_file = expand_home(identity_file)?;
            if !fs::metadata(&identity_file).is_ok_and(|metadata| metadata.is_file()) {
                return fail(format!(
                    "SSH identity file for {} does not exist or is not a file: {}",
                    host.label,
                    identity_file.display()
                ));
            }
        }
    }
    Ok(())
}

fn validate_bench_value(name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return fail(format!(
            "{name} must be non-empty and contain no control characters"
        ));
    }
    Ok(())
}

fn validate_remote_absolute_path(name: &str, path: &str) -> Result<()> {
    validate_bench_value(name, path)?;
    if !path.starts_with('/') {
        return fail(format!("{name} must be an absolute POSIX path: {path}"));
    }
    Ok(())
}

fn expand_home(path: &Path) -> Result<PathBuf> {
    let value = path
        .to_str()
        .ok_or_else(|| error("SSH identity file must be valid UTF-8"))?;
    if value == "~" {
        return env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| error("cannot expand ~ without HOME"));
    }
    if let Some(suffix) = value.strip_prefix("~/") {
        return env::var_os("HOME")
            .map(|home| PathBuf::from(home).join(suffix))
            .ok_or_else(|| error("cannot expand ~/ without HOME"));
    }
    Ok(path.to_owned())
}

fn run_bench_host(host: &BenchHost) -> Result<()> {
    let mut command = Command::new("ssh");
    command.arg("-o").arg("BatchMode=yes");
    if let Some(port) = host.port {
        command.arg("-p").arg(port.to_string());
    }
    if let Some(identity_file) = &host.identity_file {
        command.arg("-i").arg(expand_home(identity_file)?);
        command.arg("-o").arg("IdentitiesOnly=yes");
    }
    command.args(&host.ssh_options);
    let target = match &host.user {
        Some(user) => format!("{user}@{}", host.host),
        None => host.host.clone(),
    };
    let status = command.arg(target).arg(bench_host_script(host)).status()?;
    if status.success() {
        Ok(())
    } else {
        fail(format!("SSH benchmark command exited with {status}"))
    }
}

fn bench_host_script(host: &BenchHost) -> String {
    let harness_dir = remote_join(&host.workspace_dir, "bench/rarpar-bench");
    let plan = remote_join(&host.output_dir, "plan.json");
    let run_dir = remote_join(&host.output_dir, "run");
    let raw = remote_join(&run_dir, "raw.json");
    let report = remote_join(&host.output_dir, "report.json");
    let charts = remote_join(&host.output_dir, "charts");
    let source_manifest = remote_join(&host.workspace_dir, "tools/rarpar/Cargo.toml");
    let output_parent = Path::new(&host.output_dir)
        .parent()
        .and_then(Path::to_str)
        .unwrap_or("/");

    let mut plan_args = vec![
        "plan".to_owned(),
        "create".to_owned(),
        "--corpus".to_owned(),
        host.corpus_dir.clone(),
        "--out".to_owned(),
        plan,
        "--seed".to_owned(),
        host.seed.clone(),
        "--lane".to_owned(),
        host.lane.clone(),
        "--par2-placement".to_owned(),
        host.par2_placement.clone(),
        "--warmups".to_owned(),
        host.warmups.to_string(),
        "--repeats".to_owned(),
        host.repeats.to_string(),
    ];
    if let Some(family) = &host.family {
        plan_args.extend(["--family".to_owned(), family.clone()]);
    }

    let run_args = vec![
        "run".to_owned(),
        "--corpus".to_owned(),
        host.corpus_dir.clone(),
        "--plan".to_owned(),
        remote_join(&host.output_dir, "plan.json"),
        "--candidate".to_owned(),
        host.candidate.clone(),
        "--candidate-label".to_owned(),
        host.candidate_label.clone(),
        "--reference-rar".to_owned(),
        host.reference_rar.clone(),
        "--reference-par2".to_owned(),
        host.reference_par2.clone(),
        "--reference-label".to_owned(),
        host.reference_label.clone(),
        "--machine".to_owned(),
        host.label.clone(),
        "--out".to_owned(),
        run_dir,
        "--source-manifest".to_owned(),
        source_manifest,
        "--source-target".to_owned(),
        host.source_target.clone(),
    ];

    let mut lines = vec![
        "set -eu".to_owned(),
        format!("cd {}", shell_quote(&harness_dir)),
    ];
    if let Some(path) = &host.path {
        lines.push(format!("export PATH={}", shell_quote(path)));
    }
    lines.push(format!(
        "export RARPAR_BENCH_WORKSPACE_ROOT={}",
        shell_quote(&host.workspace_dir)
    ));
    lines.push(format!("mkdir -p {}", shell_quote(output_parent)));
    lines.push(format!(
        "if ! mkdir {}; then printf '%s\\n' {} >&2; exit 64; fi",
        shell_quote(&host.output_dir),
        shell_quote(&format!(
            "benchmark output already exists: {}",
            host.output_dir
        ))
    ));
    lines.push(format!("{} test ./...", shell_quote(&host.go_binary)));
    lines.push(bench_go_command(
        &host.go_binary,
        &[
            "corpus".to_owned(),
            "verify".to_owned(),
            "--root".to_owned(),
            host.corpus_dir.clone(),
        ],
    ));
    lines.push(bench_go_command(&host.go_binary, &plan_args));
    lines.push(bench_go_command(&host.go_binary, &run_args));
    lines.push(bench_go_command(
        &host.go_binary,
        &[
            "report".to_owned(),
            "--input".to_owned(),
            raw,
            "--out".to_owned(),
            report,
        ],
    ));
    lines.push(bench_go_command(
        &host.go_binary,
        &[
            "render".to_owned(),
            "--input".to_owned(),
            remote_join(&host.output_dir, "report.json"),
            "--out".to_owned(),
            charts,
        ],
    ));
    lines.join("\n")
}

fn remote_join(base: &str, child: &str) -> String {
    if base == "/" {
        format!("/{child}")
    } else {
        format!("{}/{}", base.trim_end_matches('/'), child)
    }
}

fn bench_go_command(go_binary: &str, args: &[String]) -> String {
    let mut words = vec![
        go_binary.to_owned(),
        "run".to_owned(),
        "./cmd/rarpar-bench".to_owned(),
    ];
    words.extend(args.iter().cloned());
    words
        .iter()
        .map(|word| shell_quote(word))
        .collect::<Vec<_>>()
        .join(" ")
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\\"'\\\"'"))
}

fn run_docs(args: Vec<OsString>) -> Result<()> {
    let options = DocsOptions::parse(args)?;
    if options.check {
        let temp = temp_docs_dir();
        generate_docs(&temp)?;
        validate_docs(&temp)?;
        let _ = fs::remove_dir_all(&temp);
        return Ok(());
    }

    let out = options.out.unwrap_or_else(default_docs_dir);
    generate_docs(&out)?;
    validate_docs(&out)
}

fn run_package_root(args: Vec<OsString>) -> Result<()> {
    let options = PackageRootOptions::parse(args)?;
    let docs = match options.docs {
        Some(path) => path,
        None => {
            let docs = default_docs_dir();
            generate_docs(&docs)?;
            validate_docs(&docs)?;
            docs
        }
    };
    stage_package_root(
        &options.binary,
        &docs,
        &options.out,
        options.target.as_deref(),
    )
}

fn run_feature_audit(args: Vec<OsString>) -> Result<()> {
    let options = FeatureAuditOptions::parse(args)?;
    reject_target_cpu_flags()?;
    let metadata = cargo_metadata(&options)?;
    audit_feature_metadata(&metadata, &options)?;
    println!("feature audit passed: target={}", options.target);
    Ok(())
}

struct DocsOptions {
    out: Option<PathBuf>,
    check: bool,
}

impl DocsOptions {
    fn parse(args: Vec<OsString>) -> Result<Self> {
        let mut out = None;
        let mut check = false;
        let mut iter = args.into_iter();
        while let Some(arg) = iter.next() {
            match arg.to_string_lossy().as_ref() {
                "--out" => out = Some(next_path(&mut iter, "--out")?),
                "--check" => check = true,
                "-h" | "--help" => {
                    print_usage();
                    std::process::exit(0);
                }
                other => return fail(format!("unknown docs option {other:?}")),
            }
        }
        Ok(Self { out, check })
    }
}

struct PackageRootOptions {
    binary: PathBuf,
    docs: Option<PathBuf>,
    out: PathBuf,
    target: Option<String>,
}

impl PackageRootOptions {
    fn parse(args: Vec<OsString>) -> Result<Self> {
        let mut binary = None;
        let mut docs = None;
        let mut out = None;
        let mut target = None;
        let mut iter = args.into_iter();
        while let Some(arg) = iter.next() {
            match arg.to_string_lossy().as_ref() {
                "--binary" => binary = Some(next_path(&mut iter, "--binary")?),
                "--docs" => docs = Some(next_path(&mut iter, "--docs")?),
                "--out" => out = Some(next_path(&mut iter, "--out")?),
                "--target" => target = Some(next_string(&mut iter, "--target")?),
                "-h" | "--help" => {
                    print_usage();
                    std::process::exit(0);
                }
                other => return fail(format!("unknown package-root option {other:?}")),
            }
        }
        Ok(Self {
            binary: binary.ok_or_else(|| error("--binary is required"))?,
            docs,
            out: out.ok_or_else(|| error("--out is required"))?,
            target,
        })
    }
}

struct FeatureAuditOptions {
    manifest: PathBuf,
    target: String,
    features: String,
}

impl FeatureAuditOptions {
    fn parse(args: Vec<OsString>) -> Result<Self> {
        let mut manifest = None;
        let mut target = None;
        let mut features = None;
        let mut iter = args.into_iter();
        while let Some(arg) = iter.next() {
            match arg.to_string_lossy().as_ref() {
                "--manifest" => manifest = Some(next_path(&mut iter, "--manifest")?),
                "--target" => target = Some(next_string(&mut iter, "--target")?),
                "--features" => features = Some(next_string(&mut iter, "--features")?),
                "-h" | "--help" => {
                    print_usage();
                    std::process::exit(0);
                }
                other => return fail(format!("unknown feature-audit option {other:?}")),
            }
        }
        Ok(Self {
            manifest: manifest.ok_or_else(|| error("--manifest is required"))?,
            target: target.ok_or_else(|| error("--target is required"))?,
            features: features.ok_or_else(|| error("--features is required"))?,
        })
    }
}

#[derive(Deserialize)]
struct CargoMetadata {
    packages: Vec<CargoPackage>,
    resolve: CargoResolve,
}

#[derive(Deserialize)]
struct CargoPackage {
    id: String,
    name: String,
    version: String,
}

#[derive(Deserialize)]
struct CargoResolve {
    nodes: Vec<CargoNode>,
}

#[derive(Deserialize)]
struct CargoNode {
    id: String,
    features: Vec<String>,
}

fn cargo_metadata(options: &FeatureAuditOptions) -> Result<CargoMetadata> {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let output = Command::new(cargo)
        .args([
            "metadata",
            "--locked",
            "--format-version",
            "1",
            "--manifest-path",
        ])
        .arg(&options.manifest)
        .args([
            "--filter-platform",
            &options.target,
            "--no-default-features",
            "--features",
            &options.features,
        ])
        .output()?;
    if !output.status.success() {
        return fail(format!(
            "cargo metadata failed for {}:\n{}",
            options.manifest.display(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}

fn audit_feature_metadata(metadata: &CargoMetadata, options: &FeatureAuditOptions) -> Result<()> {
    require_feature(metadata, "rarpar", "runtime")?;
    require_feature(metadata, "par2-rs", "native-crypto")?;
    require_feature(metadata, "unrar-rs", "crypto-aws-lc")?;

    let aws_lc_versions = resolved_package_versions(metadata, "aws-lc-sys");
    if aws_lc_versions.len() != 1 {
        return fail(format!(
            "expected one resolved aws-lc-sys version, found: {}",
            aws_lc_versions.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }

    if requested_feature(options, "metal") {
        assert_metal_only(metadata, &options.target)?;
    } else {
        assert_cpu_only(metadata)?;
    }
    Ok(())
}

fn requested_feature(options: &FeatureAuditOptions, feature: &str) -> bool {
    options
        .features
        .split([',', ' '])
        .any(|requested| requested == feature)
}

fn reject_target_cpu_flags() -> Result<()> {
    for key in ["RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"] {
        if let Some(value) = env::var_os(key)
            && value.to_string_lossy().contains("target-cpu")
        {
            return fail(format!(
                "{key} must not set target-cpu; use runtime dispatch"
            ));
        }
    }
    Ok(())
}

fn assert_cpu_only(metadata: &CargoMetadata) -> Result<()> {
    reject_gpu_features(metadata)?;
    reject_resolved_package(metadata, "wgpu")?;
    reject_resolved_package(metadata, "objc2-metal")
}

fn assert_metal_only(metadata: &CargoMetadata, target: &str) -> Result<()> {
    if target != "aarch64-apple-darwin" {
        return fail(format!(
            "Metal is supported only for aarch64-apple-darwin, not {target}"
        ));
    }
    for package in ["rarpar", "par2-rs", "reedsolomon-rs"] {
        require_feature(metadata, package, "metal")?;
        reject_feature(metadata, package, "wgpu")?;
    }
    reject_resolved_package(metadata, "wgpu")?;
    if resolved_package_versions(metadata, "objc2-metal").is_empty() {
        return fail("Metal build must resolve objc2-metal");
    }
    Ok(())
}

fn reject_gpu_features(metadata: &CargoMetadata) -> Result<()> {
    for package in ["rarpar", "par2-rs", "reedsolomon-rs"] {
        reject_feature(metadata, package, "metal")?;
        reject_feature(metadata, package, "wgpu")?;
    }
    Ok(())
}

fn require_feature(metadata: &CargoMetadata, package: &str, feature: &str) -> Result<()> {
    let (_, node) = resolved_package_node(metadata, package)?;
    if !node.features.iter().any(|enabled| enabled == feature) {
        return fail(format!("{package} must resolve feature {feature:?}"));
    }
    Ok(())
}

fn reject_feature(metadata: &CargoMetadata, package: &str, feature: &str) -> Result<()> {
    let (_, node) = resolved_package_node(metadata, package)?;
    if node.features.iter().any(|enabled| enabled == feature) {
        return fail(format!("{package} must not resolve feature {feature:?}"));
    }
    Ok(())
}

fn reject_resolved_package(metadata: &CargoMetadata, package: &str) -> Result<()> {
    if !resolved_package_versions(metadata, package).is_empty() {
        return fail(format!("package {package} must not resolve"));
    }
    Ok(())
}

fn resolved_package_node<'a>(
    metadata: &'a CargoMetadata,
    name: &str,
) -> Result<(&'a CargoPackage, &'a CargoNode)> {
    let candidates = metadata
        .packages
        .iter()
        .filter(|package| package.name == name)
        .filter_map(|package| {
            metadata
                .resolve
                .nodes
                .iter()
                .find(|node| node.id == package.id)
                .map(|node| (package, node))
        })
        .collect::<Vec<_>>();
    match candidates.as_slice() {
        [(package, node)] => Ok((package, node)),
        [] => fail(format!("resolved package {name} was not found")),
        _ => fail(format!("resolved package {name} is ambiguous")),
    }
}

fn resolved_package_versions(metadata: &CargoMetadata, name: &str) -> BTreeSet<String> {
    let resolved_ids = metadata
        .resolve
        .nodes
        .iter()
        .map(|node| node.id.as_str())
        .collect::<HashSet<_>>();
    metadata
        .packages
        .iter()
        .filter(|package| package.name == name && resolved_ids.contains(package.id.as_str()))
        .map(|package| package.version.clone())
        .collect()
}

fn next_path(iter: &mut impl Iterator<Item = OsString>, option: &str) -> Result<PathBuf> {
    iter.next()
        .map(PathBuf::from)
        .ok_or_else(|| error(format!("{option} requires a value")))
}

fn next_string(iter: &mut impl Iterator<Item = OsString>, option: &str) -> Result<String> {
    iter.next()
        .and_then(|value| value.into_string().ok())
        .ok_or_else(|| error(format!("{option} requires a UTF-8 value")))
}

fn generate_docs(out: &Path) -> Result<()> {
    reset_generated_dir(out, "docs", true)?;

    let man_path = out.join(MAN_REL);
    write_parented(&man_path, manpage_bytes()?)?;
    write_completion(Bash, &out.join(BASH_REL))?;
    write_completion(Zsh, &out.join(ZSH_REL))?;
    write_completion(Fish, &out.join(FISH_REL))?;
    write_completion(Elvish, &out.join(ELVISH_REL))?;
    write_completion(PowerShell, &out.join(POWERSHELL_REL))?;
    Ok(())
}

fn manpage_bytes() -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    Man::new(Cli::command()).render(&mut buffer)?;
    let mut manpage = String::from_utf8(buffer)?;
    manpage.push_str(CURATED_MANPAGE_SECTIONS);
    Ok(normalize_manpage(&manpage).into_bytes())
}

fn normalize_manpage(manpage: &str) -> String {
    let mut output = String::new();
    let mut in_example = false;
    let mut skip_generated_subcommands = false;
    for line in manpage.lines() {
        let mut line = line.trim_end().to_string();
        if line.starts_with(".TH ") {
            line = format!(
                ".TH RARPAR 1 \"2026-07-07\" \"rarpar {}\" \"User Commands\"",
                env!("CARGO_PKG_VERSION")
            );
        }

        if line == ".SH SUBCOMMANDS" {
            skip_generated_subcommands = true;
            continue;
        }
        if skip_generated_subcommands {
            if line.starts_with(".SH ") {
                skip_generated_subcommands = false;
            } else {
                continue;
            }
        }

        if line == ".EX" {
            in_example = true;
            output.push_str(&line);
            output.push('\n');
            continue;
        }
        if line == ".EE" {
            in_example = false;
            output.push_str(&line);
            output.push('\n');
            continue;
        }

        if !in_example && (line.is_empty() || line == ".br") && output.ends_with(".br\n") {
            continue;
        }

        if in_example || line.starts_with('.') {
            output.push_str(&line);
            output.push('\n');
            continue;
        }

        for wrapped in wrap_roff_text_line(&line, 78) {
            output.push_str(&wrapped);
            output.push('\n');
        }
    }
    output
}

fn wrap_roff_text_line(line: &str, width: usize) -> Vec<String> {
    if line.len() <= width {
        return vec![line.to_string()];
    }

    let mut remaining = line.trim_start();
    let mut wrapped = Vec::new();
    while remaining.len() > width {
        let split = remaining[..width]
            .rfind(' ')
            .filter(|index| *index > 0)
            .unwrap_or(width);
        let (head, tail) = remaining.split_at(split);
        wrapped.push(head.trim_end().to_string());
        remaining = tail.trim_start();
    }
    if !remaining.is_empty() {
        wrapped.push(remaining.to_string());
    }
    wrapped
}

fn write_completion<G: Generator>(generator: G, path: &Path) -> Result<()> {
    let mut command = Cli::command();
    let mut buffer = Vec::new();
    generate(generator, &mut command, BIN_NAME, &mut buffer);
    write_parented(path, buffer)
}

fn write_parented(path: &Path, bytes: Vec<u8>) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, bytes)?;
    set_file_mode(path, 0o644)
}

fn validate_docs(root: &Path) -> Result<()> {
    let expected = [
        MAN_REL,
        BASH_REL,
        ZSH_REL,
        FISH_REL,
        ELVISH_REL,
        POWERSHELL_REL,
    ];
    for relative in expected {
        let path = root.join(relative);
        if !path.is_file() {
            return fail(format!(
                "missing generated docs artifact: {}",
                path.display()
            ));
        }
    }

    let manpage = fs::read_to_string(root.join(MAN_REL))?;
    for section in [
        "NAME",
        "SYNOPSIS",
        "DESCRIPTION",
        "COMMANDS",
        "OPTIONS",
        "PASSWORD HANDLING",
        "CLEANUP SAFETY",
        "EXIT STATUS",
        "EXAMPLES",
        "FILES",
        "LICENSE",
    ] {
        if !manpage.contains(&format!(".SH {section}"))
            && !manpage.contains(&format!(".SH \"{section}\""))
        {
            return fail(format!("manpage missing {section} section"));
        }
    }

    for needle in [
        "rarpar ./release",
        "rarpar auto ./release",
        "rarpar inspect --json ./release",
        "rarpar cleanup --dry-run ./release",
        "rarpar --password-file passwords.txt ./release",
        "rarpar --password-env RAR_PASSWORD ./release",
        "rarpar --password-fd 3 ./release 3< passwords.txt",
        "rarpar rar list archive.part1.rar",
        "rarpar par repair release.par2",
        "trash/recycle bin",
        "values are never printed",
    ] {
        if !manpage.contains(needle) {
            return fail(format!("manpage missing required text: {needle}"));
        }
    }

    if manpage.contains("official UnRAR") && !manpage.contains("not an official UnRAR") {
        return fail("manpage appears to claim official UnRAR identity");
    }
    if manpage.contains("rarpar-auto(1)") {
        return fail("manpage references subcommand pages that are not shipped");
    }

    Ok(())
}

fn stage_package_root(binary: &Path, docs: &Path, out: &Path, target: Option<&str>) -> Result<()> {
    validate_binary(binary)?;
    validate_docs(docs)?;

    reset_generated_dir(out, "package-root", false)?;

    copy_into_root(out, Path::new("usr/bin/rarpar"), binary, 0o755)?;
    copy_into_root(
        out,
        Path::new("usr/share/man/man1/rarpar.1"),
        &docs.join(MAN_REL),
        0o644,
    )?;
    copy_into_root(
        out,
        Path::new("usr/share/bash-completion/completions/rarpar"),
        &docs.join(BASH_REL),
        0o644,
    )?;
    copy_into_root(
        out,
        Path::new("usr/share/zsh/site-functions/_rarpar"),
        &docs.join(ZSH_REL),
        0o644,
    )?;
    copy_into_root(
        out,
        Path::new("usr/share/fish/vendor_completions.d/rarpar.fish"),
        &docs.join(FISH_REL),
        0o644,
    )?;

    let root = workspace_root();
    copy_into_root(
        out,
        Path::new("usr/share/doc/rarpar/README.md"),
        &root.join("README.md"),
        0o644,
    )?;
    copy_into_root(
        out,
        Path::new("usr/share/licenses/rarpar/LICENSE"),
        &root.join("tools/rarpar/LICENSE"),
        0o644,
    )?;
    copy_into_root(
        out,
        Path::new("usr/share/licenses/rarpar/LICENSE.GPL-3.0-or-later"),
        &root.join("LICENSE"),
        0o644,
    )?;
    copy_into_root(
        out,
        Path::new("usr/share/licenses/rarpar/LICENSE.unrar-rs"),
        &root.join("crates/unrar-rs/LICENSE"),
        0o644,
    )?;

    validate_package_root(out)?;
    if let Some(target) = target {
        println!("staged package root for {target}: {}", out.display());
    } else {
        println!("staged package root: {}", out.display());
    }
    Ok(())
}

fn reset_generated_dir(out: &Path, expected_leaf: &str, write_sentinel: bool) -> Result<()> {
    if out.exists() {
        if !out.is_dir() {
            return fail(format!("output path is not a directory: {}", out.display()));
        }
        if !can_remove_generated_dir(out, expected_leaf) {
            return fail(format!(
                "refusing to remove output directory without xtask sentinel or safe target/dist path: {}",
                out.display()
            ));
        }
        fs::remove_dir_all(out)?;
    }

    fs::create_dir_all(out)?;
    set_file_mode(out, 0o755)?;
    if write_sentinel {
        let sentinel = out.join(GENERATED_SENTINEL);
        fs::write(&sentinel, b"generated by rarpar xtask\n")?;
        set_file_mode(&sentinel, 0o644)?;
    }
    Ok(())
}

fn can_remove_generated_dir(out: &Path, expected_leaf: &str) -> bool {
    if out.join(GENERATED_SENTINEL).is_file() {
        return true;
    }
    if out.file_name().and_then(|name| name.to_str()) != Some(expected_leaf) {
        return false;
    }
    let Ok(out) = out.canonicalize() else {
        return false;
    };
    let target_dist = workspace_root().join("target").join("dist");
    let Ok(target_dist) = target_dist.canonicalize() else {
        return false;
    };
    out.starts_with(target_dist)
}

fn validate_binary(binary: &Path) -> Result<()> {
    if !binary.is_file() {
        return fail(format!("binary is missing: {}", binary.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(binary)?.permissions().mode();
        if mode & 0o111 == 0 {
            return fail(format!("binary is not executable: {}", binary.display()));
        }
    }
    Ok(())
}

fn copy_into_root(root: &Path, relative: &Path, source: &Path, mode: u32) -> Result<()> {
    ensure_safe_relative(relative)?;
    if !source.is_file() {
        return fail(format!("missing source file: {}", source.display()));
    }
    let destination = root.join(relative);
    ensure_inside(root, &destination)?;
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
        set_file_mode(parent, 0o755)?;
    }
    fs::copy(source, &destination)?;
    set_file_mode(&destination, mode)
}

fn validate_package_root(root: &Path) -> Result<()> {
    for relative in [
        "usr/bin/rarpar",
        "usr/share/man/man1/rarpar.1",
        "usr/share/bash-completion/completions/rarpar",
        "usr/share/zsh/site-functions/_rarpar",
        "usr/share/fish/vendor_completions.d/rarpar.fish",
        "usr/share/doc/rarpar/README.md",
        "usr/share/licenses/rarpar/LICENSE",
        "usr/share/licenses/rarpar/LICENSE.GPL-3.0-or-later",
        "usr/share/licenses/rarpar/LICENSE.unrar-rs",
    ] {
        let path = root.join(relative);
        if !path.is_file() {
            return fail(format!("package root missing {}", path.display()));
        }
    }

    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_name() != "usr" {
            return fail(format!(
                "unexpected package root top-level path {}",
                entry.path().display()
            ));
        }
    }
    Ok(())
}

fn ensure_safe_relative(path: &Path) -> Result<()> {
    if path.is_absolute() {
        return fail(format!("package path must be relative: {}", path.display()));
    }
    for component in path.components() {
        if matches!(component, Component::ParentDir | Component::Prefix(_)) {
            return fail(format!("unsafe package path: {}", path.display()));
        }
    }
    Ok(())
}

fn ensure_inside(root: &Path, destination: &Path) -> Result<()> {
    let root = root.canonicalize().or_else(|_| {
        fs::create_dir_all(root)?;
        root.canonicalize()
    })?;
    let parent = destination
        .parent()
        .ok_or_else(|| error(format!("path has no parent: {}", destination.display())))?;
    fs::create_dir_all(parent)?;
    let parent = parent.canonicalize()?;
    if !parent.starts_with(&root) {
        return fail(format!(
            "path escapes package root: {}",
            destination.display()
        ));
    }
    Ok(())
}

fn set_file_mode(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
    Ok(())
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives under the workspace root")
        .to_path_buf()
}

fn default_docs_dir() -> PathBuf {
    workspace_root().join("target/dist/docs")
}

fn temp_docs_dir() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    env::temp_dir().join(format!("rarpar-docs-{}-{nanos}", std::process::id()))
}

fn error(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(io::Error::other(message.into()))
}

fn fail<T>(message: impl Into<String>) -> Result<T> {
    Err(error(message))
}

const CURATED_MANPAGE_SECTIONS: &str = r#"
.SH COMMANDS
.TP
\fBauto\fR \fIPATH...\fR
Discover, verify or repair, restore recovery volumes when possible, and extract
RAR sets with verification enabled. This is the default when paths are provided
without an explicit command.
.TP
\fBinspect\fR \fIPATH...\fR
Print the same discovered action graph that auto mode would execute. Use
\fB--json\fR for structured automation output.
.TP
\fBcleanup\fR \fIPATH...\fR
Validate expected extracted outputs and delete only positively identified
consumed source files.
.TP
\fBrar\fR \fBlist\fR|\fBtest\fR|\fBextract\fR|\fBrestore-volumes\fR
Run explicit RAR operations.
.TP
\fBpar\fR \fBverify\fR|\fBrepair\fR
Run explicit PAR2 verification or repair operations.
.SH PASSWORD HANDLING
\fBrarpar\fR never prints passwords and never includes them in JSON output.
Use \fB--password-file\fR for newline-separated candidate passwords,
\fB--password-env\fR for one candidate from an environment variable, or
\fB--password-fd\fR for newline-separated candidates from a file descriptor.
Password source values are never printed. If no non-interactive candidate works
and stdin/stderr are TTYs, \fBrarpar\fR prompts with hidden input only when an
archive actually needs a password.
.SH CLEANUP SAFETY
Cleanup is narrow by design. \fB--delete-sources\fR deletes consumed source
files only after verified successful extraction. By default cleanup moves files
to the OS trash/recycle bin. \fB--permanent-delete\fR bypasses the
trash/recycle bin and is irreversible. Use \fBcleanup --dry-run\fR to inspect
the manifest before deleting anything.
.SH EXIT STATUS
.TP
\fB0\fR
Success.
.TP
\fB1\fR
Data failure such as corrupt input, missing volumes, failed validation, or wrong
password.
.TP
\fB2\fR
Usage error, missing input, unsupported operation, or fatal compatibility-mode
abort.
.TP
\fB3\fR
Unsafe operation was refused, such as overwrite rejection or failed trash
cleanup.
.SH EXAMPLES
.EX
rarpar ./release
rarpar auto ./release
rarpar inspect --json ./release
rarpar auto --output ./out ./release
rarpar auto --delete-sources ./release
rarpar auto --delete-sources --permanent-delete ./release
rarpar cleanup --dry-run ./release
rarpar --password-file passwords.txt ./release
rarpar --password-env RAR_PASSWORD ./release
rarpar --password-fd 3 ./release 3< passwords.txt
rarpar rar list archive.part1.rar
rarpar rar test archive.part1.rar
rarpar rar extract archive.part1.rar ./out
rarpar par verify release.par2
rarpar par repair release.par2
.EE
.SH FILES
.TP
\fB/usr/bin/rarpar\fR
Installed executable path used by future Linux packages.
.TP
\fB/usr/share/man/man1/rarpar.1\fR
Manual page.
.TP
\fB/usr/share/bash-completion/completions/rarpar\fR
Bash completion script.
.TP
\fB/usr/share/zsh/site-functions/_rarpar\fR
Zsh completion script.
.TP
\fB/usr/share/fish/vendor_completions.d/rarpar.fish\fR
Fish completion script.
.SH LICENSE
\fBrarpar\fR source is GPL-3.0-or-later with a GPLv3 section 7 permission to
combine with \fBunrar-rs\fR. Normal binary builds link \fBunrar-rs\fR, so
distributed \fBrarpar\fR binaries contain UnRAR-derived RAR extraction and
recovery code that remains subject to the unRAR license restriction.
Binary archives include \fBLICENSE\fR, \fBLICENSE.GPL-3.0-or-later\fR, and
\fBLICENSE.unrar-rs\fR.
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bench_host_script_runs_the_complete_direct_harness_pipeline() {
        let host = bench_host_fixture();
        let script = bench_host_script(&host);

        for required in [
            "set -eu",
            "cd '/remote/rarpar/bench/rarpar-bench'",
            "export RARPAR_BENCH_WORKSPACE_ROOT='/remote/rarpar'",
            "'/opt/go/bin/go' test ./...",
            "corpus' 'verify' '--root' '/remote/corpus'",
            "plan' 'create'",
            "run' '--corpus' '/remote/corpus'",
            "--candidate' '/remote/bin/rarpar'",
            "report' '--input' '/remote/results/run/raw.json'",
            "render' '--input' '/remote/results/report.json'",
        ] {
            assert!(
                script.contains(required),
                "missing {required:?} in {script}"
            );
        }
        assert!(!script.contains("cargo run"));
    }

    #[test]
    fn bench_host_config_rejects_relative_paths_and_duplicate_labels() {
        let mut config = BenchHostsConfig {
            schema_version: 1,
            hosts: vec![bench_host_fixture()],
        };
        validate_bench_hosts_config(&config).expect("fixture must be valid");

        config.hosts[0].output_dir = "relative/results".to_owned();
        assert!(
            validate_bench_hosts_config(&config)
                .expect_err("relative path must fail")
                .to_string()
                .contains("absolute POSIX path")
        );

        config.hosts = vec![bench_host_fixture(), bench_host_fixture()];
        assert!(
            validate_bench_hosts_config(&config)
                .expect_err("duplicate host label must fail")
                .to_string()
                .contains("duplicated")
        );

        let mut second = bench_host_fixture();
        second.label = "Second Linux test machine".to_owned();
        config.hosts = vec![bench_host_fixture(), second];
        assert!(
            validate_bench_hosts_config(&config)
                .expect_err("duplicate endpoint output must fail")
                .to_string()
                .contains("output directory")
        );

        config.hosts = vec![bench_host_fixture()];
        config.hosts[0].label = "host-a".to_owned();
        assert!(
            validate_bench_hosts_config(&config)
                .expect_err("hostname label must fail")
                .to_string()
                .contains("without using its hostname")
        );
    }

    #[test]
    fn feature_audit_accepts_cpu_only_metadata() -> Result<()> {
        let options = FeatureAuditOptions {
            manifest: PathBuf::from("Cargo.toml"),
            target: "x86_64-apple-darwin".to_owned(),
            features: "runtime".to_owned(),
        };
        audit_feature_metadata(&feature_metadata(&["0.42.0"]), &options)
    }

    #[test]
    fn feature_audit_accepts_apple_silicon_metal_metadata() -> Result<()> {
        let options = FeatureAuditOptions {
            manifest: PathBuf::from("Cargo.toml"),
            target: "aarch64-apple-darwin".to_owned(),
            features: "runtime,metal".to_owned(),
        };
        audit_feature_metadata(&metal_feature_metadata(), &options)
    }

    #[test]
    fn feature_audit_rejects_metal_on_intel_macos() {
        let options = FeatureAuditOptions {
            manifest: PathBuf::from("Cargo.toml"),
            target: "x86_64-apple-darwin".to_owned(),
            features: "runtime,metal".to_owned(),
        };
        let error = audit_feature_metadata(&metal_feature_metadata(), &options)
            .expect_err("Intel macOS must not resolve Metal");
        assert!(error.to_string().contains("aarch64-apple-darwin"));
    }

    #[test]
    fn feature_audit_rejects_duplicate_aws_lc_bindings() {
        let options = FeatureAuditOptions {
            manifest: PathBuf::from("Cargo.toml"),
            target: "x86_64-apple-darwin".to_owned(),
            features: "runtime".to_owned(),
        };
        let error = audit_feature_metadata(&feature_metadata(&["0.41.0", "0.42.0"]), &options)
            .expect_err("duplicate aws-lc-sys versions must fail the audit");
        assert!(
            error
                .to_string()
                .contains("one resolved aws-lc-sys version")
        );
    }

    #[test]
    fn docs_generation_contains_required_artifacts() -> Result<()> {
        let root = temp_path("docs");
        generate_docs(&root)?;
        validate_docs(&root)?;

        assert!(root.join(MAN_REL).is_file());
        assert!(root.join(BASH_REL).is_file());
        assert_eq!(
            root.join(ZSH_REL)
                .file_name()
                .and_then(|name| name.to_str()),
            Some("_rarpar")
        );
        assert!(root.join(FISH_REL).is_file());
        assert!(root.join(ELVISH_REL).is_file());
        assert!(root.join(POWERSHELL_REL).is_file());

        let manpage = fs::read_to_string(root.join(MAN_REL))?;
        assert!(manpage.contains("rarpar ./release"));
        assert!(manpage.contains("trash/recycle bin"));
        assert!(manpage.contains("values are never printed"));
        assert!(!manpage.contains("UNRAR 6"));
        assert!(!manpage.contains("rarpar-auto(1)"));

        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn generated_dir_reset_refuses_arbitrary_existing_directory() -> Result<()> {
        let root = temp_path("arbitrary");
        fs::create_dir_all(&root)?;
        fs::write(root.join("keep.txt"), b"do not delete")?;

        let result = reset_generated_dir(&root, "docs", true);
        assert!(result.is_err());
        assert!(root.join("keep.txt").is_file());

        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn package_root_stages_future_linux_layout() -> Result<()> {
        let work = temp_path("package-root");
        let docs = work.join("docs");
        let out = work.join("root");
        let binary = work.join("rarpar");
        fs::create_dir_all(&work)?;
        fs::write(&binary, b"#!/bin/sh\nexit 0\n")?;
        set_file_mode(&binary, 0o755)?;

        generate_docs(&docs)?;
        stage_package_root(&binary, &docs, &out, Some("host"))?;

        for relative in [
            "usr/bin/rarpar",
            "usr/share/man/man1/rarpar.1",
            "usr/share/bash-completion/completions/rarpar",
            "usr/share/zsh/site-functions/_rarpar",
            "usr/share/fish/vendor_completions.d/rarpar.fish",
            "usr/share/doc/rarpar/README.md",
            "usr/share/licenses/rarpar/LICENSE",
            "usr/share/licenses/rarpar/LICENSE.GPL-3.0-or-later",
            "usr/share/licenses/rarpar/LICENSE.unrar-rs",
        ] {
            assert!(out.join(relative).is_file(), "missing {relative}");
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(out.join("usr/bin/rarpar"))?
                    .permissions()
                    .mode()
                    & 0o777,
                0o755
            );
            assert_eq!(
                fs::metadata(out.join("usr/share/man/man1/rarpar.1"))?
                    .permissions()
                    .mode()
                    & 0o777,
                0o644
            );
        }

        let _ = fs::remove_dir_all(work);
        Ok(())
    }

    fn feature_metadata(aws_lc_versions: &[&str]) -> CargoMetadata {
        let mut packages = vec![
            CargoPackage {
                id: "rarpar".to_owned(),
                name: "rarpar".to_owned(),
                version: "0.3.0".to_owned(),
            },
            CargoPackage {
                id: "par2-rs".to_owned(),
                name: "par2-rs".to_owned(),
                version: "0.3.0".to_owned(),
            },
            CargoPackage {
                id: "unrar-rs".to_owned(),
                name: "unrar-rs".to_owned(),
                version: "0.4.0".to_owned(),
            },
            CargoPackage {
                id: "reedsolomon-rs".to_owned(),
                name: "reedsolomon-rs".to_owned(),
                version: "0.3.0".to_owned(),
            },
        ];
        let mut nodes = vec![
            CargoNode {
                id: "rarpar".to_owned(),
                features: vec!["runtime".to_owned()],
            },
            CargoNode {
                id: "par2-rs".to_owned(),
                features: vec!["native-crypto".to_owned()],
            },
            CargoNode {
                id: "unrar-rs".to_owned(),
                features: vec!["crypto-aws-lc".to_owned()],
            },
            CargoNode {
                id: "reedsolomon-rs".to_owned(),
                features: Vec::new(),
            },
        ];

        for (index, version) in aws_lc_versions.iter().enumerate() {
            let id = format!("aws-lc-sys-{index}");
            packages.push(CargoPackage {
                id: id.clone(),
                name: "aws-lc-sys".to_owned(),
                version: (*version).to_owned(),
            });
            nodes.push(CargoNode {
                id,
                features: Vec::new(),
            });
        }

        CargoMetadata {
            packages,
            resolve: CargoResolve { nodes },
        }
    }

    fn metal_feature_metadata() -> CargoMetadata {
        let mut metadata = feature_metadata(&["0.42.0"]);
        for package in ["rarpar", "par2-rs", "reedsolomon-rs"] {
            metadata
                .resolve
                .nodes
                .iter_mut()
                .find(|node| node.id == package)
                .expect("test package node")
                .features
                .push("metal".to_owned());
        }
        metadata.packages.push(CargoPackage {
            id: "objc2-metal".to_owned(),
            name: "objc2-metal".to_owned(),
            version: "0.3.2".to_owned(),
        });
        metadata.resolve.nodes.push(CargoNode {
            id: "objc2-metal".to_owned(),
            features: Vec::new(),
        });
        metadata
    }

    fn temp_path(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        env::temp_dir().join(format!(
            "rarpar-xtask-test-{label}-{}-{nanos}",
            std::process::id()
        ))
    }

    fn bench_host_fixture() -> BenchHost {
        BenchHost {
            label: "Linux test machine".to_owned(),
            host: "host-a.example.net".to_owned(),
            user: Some("bench".to_owned()),
            port: Some(22),
            identity_file: None,
            ssh_options: vec!["-o".to_owned(), "ConnectTimeout=30".to_owned()],
            workspace_dir: "/remote/rarpar".to_owned(),
            corpus_dir: "/remote/corpus".to_owned(),
            output_dir: "/remote/results".to_owned(),
            candidate: "/remote/bin/rarpar".to_owned(),
            reference_rar: "/remote/bin/unrar".to_owned(),
            reference_par2: "/remote/bin/par2".to_owned(),
            source_target: "x86_64-unknown-linux-gnu".to_owned(),
            go_binary: "/opt/go/bin/go".to_owned(),
            path: Some("/remote/bin:/usr/bin:/bin".to_owned()),
            candidate_label: "rarpar".to_owned(),
            reference_label: "reference".to_owned(),
            seed: "seed".to_owned(),
            lane: "cpu".to_owned(),
            family: None,
            par2_placement: "canonical".to_owned(),
            warmups: 1,
            repeats: 5,
        }
    }
}
