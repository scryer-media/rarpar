use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use par3_rs::creation::{
    CreationCodec, CreationOptions, CreationPlan, CreationSource, Deduplication, VolumeLayout,
};
use par3_rs::ingest::{IncrementalSet, PacketScanner, ScanEvent};
use par3_rs::layout::{BlockLayout, ExtentKind};
use par3_rs::placement::{PlacementOptions, search_extent};
use par3_rs::runtime::{EngineError, ExecutionOptions, MemoryBudget};
use par3_rs::session::{Par3RepairSession, RepairStatus};
use par3_rs::source::{DiskSourceAccess, SourceAccess, SourceId};
use par3_rs::{InputSetId, ScanLimits};
use rarpar::cli::{Cli, Par3Args, Par3Codec, Par3Command, Par3CreateArgs, Par3Dedup, ParPlacement};
use serde::Serialize;
use serde_json::{Value, json};

use crate::discovery::ExecutedAction;
use crate::error::{EXIT_DATA_FAILURE, EXIT_SUCCESS, RarparError};

#[derive(Clone, Debug, Serialize)]
pub struct Par3Set {
    pub id: String,
    pub base_dir: PathBuf,
    pub paths: Vec<PathBuf>,
    pub protected_files: Vec<String>,
    pub metadata_complete: bool,
    #[serde(skip)]
    loaded: Option<Arc<LoadedSet>>,
}

impl Par3Set {
    pub fn member_paths(&self, working_dir: Option<&Path>) -> Result<Vec<PathBuf>, RarparError> {
        self.protected_files
            .iter()
            .map(|name| protected_path(working_dir.unwrap_or(&self.base_dir), name))
            .collect()
    }

    pub fn release_carriers(&mut self) {
        self.loaded = None;
    }
}

struct LoadedSet {
    id: InputSetId,
    packets: IncrementalSet,
    paths: Vec<PathBuf>,
    options: ExecutionOptions,
}

impl std::fmt::Debug for LoadedSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedSet")
            .field("id", &self.id)
            .field("paths", &self.paths)
            .finish_non_exhaustive()
    }
}

pub fn execution_options(
    memory_mib: usize,
    workers: Option<usize>,
    max_lost: u64,
) -> Result<ExecutionOptions, RarparError> {
    let bytes = memory_mib
        .checked_mul(1 << 20)
        .ok_or_else(|| RarparError::Resource("PAR3 allocation budget overflow".into()))?;
    let mut options = ExecutionOptions::default();
    options.memory = MemoryBudget::new(bytes);
    options.retained_bytes = bytes.min(64 << 20);
    if let Some(workers) = workers {
        if workers == 0 {
            return Err(RarparError::Usage("--par3-workers must be positive".into()));
        }
        options.workers = workers;
    }
    options.max_cauchy_lost_blocks = max_lost;
    if bytes == 0 {
        return Err(RarparError::Resource(
            "PAR3 allocation budget is zero".into(),
        ));
    }
    Ok(options)
}

fn options(cli: &Cli) -> Result<ExecutionOptions, RarparError> {
    execution_options(
        cli.par3_memory_mib,
        cli.par3_workers,
        cli.par3_max_lost_blocks,
    )
}

pub fn is_carrier(path: &Path) -> bool {
    path.extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("par3"))
}

pub fn is_carrier_candidate(path: &Path) -> bool {
    use std::io::Read;
    if is_carrier(path) {
        return true;
    }
    let mut prefix = [0; 8];
    std::fs::File::open(path)
        .and_then(|mut file| file.read_exact(&mut prefix))
        .is_ok()
        && &prefix == par3_rs::MAGIC
}

fn carrier_options(
    options: &ExecutionOptions,
    carriers: usize,
) -> Result<ExecutionOptions, RarparError> {
    let mut options = options.clone();
    // Windows keeps immutable carrier handles with lazy packet payloads. Size
    // one shared collection budget before scanning, preserving execution headroom.
    options.open_handles = options
        .open_handles
        .checked_add(carriers)
        .ok_or_else(|| RarparError::Resource("PAR3 handle budget overflow".into()))?;
    options.handles = par3_rs::runtime::HandleBudget::new(options.open_handles);
    Ok(options)
}

fn scan(paths: &[PathBuf], options: &ExecutionOptions) -> Result<Vec<LoadedSet>, RarparError> {
    let mut disk = DiskSourceAccess::with_options(options.clone());
    for (index, path) in paths.iter().enumerate() {
        reject_symlinks(path)?;
        disk.insert(SourceId(index as u64), path.clone());
    }
    let access: Arc<dyn SourceAccess> = Arc::new(disk);
    let mut sets: BTreeMap<(InputSetId, PathBuf), LoadedSet> = BTreeMap::new();
    for (index, path) in paths.iter().enumerate() {
        let directory = parent(path).canonicalize()?;
        let mut scanner = PacketScanner::new(
            access.clone(),
            SourceId(index as u64),
            options.clone(),
            ScanLimits::default(),
        )?;
        loop {
            match scanner.poll()? {
                ScanEvent::Packet(packet) => {
                    let id = packet.input_set_id();
                    let key = (id, directory.clone());
                    if let std::collections::btree_map::Entry::Vacant(entry) =
                        sets.entry(key.clone())
                    {
                        entry.insert(LoadedSet {
                            id,
                            packets: IncrementalSet::new(id, options.clone())?,
                            paths: Vec::new(),
                            options: options.clone(),
                        });
                    }
                    let set = sets.get_mut(&key).expect("inserted set");
                    set.packets.merge(packet)?;
                    if set.paths.last() != Some(path) {
                        set.paths.push(path.clone());
                    }
                }
                ScanEvent::End => break,
                ScanEvent::NeedData { offset } => {
                    return Err(EngineError::Unavailable {
                        source_id: SourceId(index as u64),
                        offset,
                    }
                    .into());
                }
            }
        }
    }
    Ok(sets.into_values().collect())
}

pub fn discover_sets(
    paths: &[PathBuf],
    options: &ExecutionOptions,
) -> Result<Vec<Par3Set>, RarparError> {
    let options = carrier_options(options, paths.len())?;
    let mut result = Vec::new();
    let mut directories: BTreeMap<PathBuf, Vec<PathBuf>> = BTreeMap::new();
    for path in paths {
        directories
            .entry(parent(path).canonicalize()?)
            .or_default()
            .push(path.clone());
    }
    // Identical sets in separate downloads still need independent repair.
    for paths in directories.into_values() {
        for set in scan(&paths, &options)? {
            let metadata = set.packets.metadata()?;
            let layout = metadata
                .as_ref()
                .map(|metadata| BlockLayout::new(metadata, &options))
                .transpose()?;
            result.push(Par3Set {
                id: set.id.to_string(),
                base_dir: parent(&set.paths[0]),
                paths: set.paths.clone(),
                protected_files: layout
                    .as_ref()
                    .map(|layout| {
                        layout
                            .files()
                            .iter()
                            .map(|file| file.path.clone())
                            .collect()
                    })
                    .unwrap_or_default(),
                metadata_complete: layout.is_some(),
                loaded: Some(Arc::new(set)),
            });
        }
    }
    Ok(result)
}

fn parent(path: &Path) -> PathBuf {
    path.parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .to_path_buf()
}

fn reject_symlinks(path: &Path) -> Result<(), RarparError> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(RarparError::Unsafe(format!(
                "symlink in PAR3 path: {}",
                path.display()
            )));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn protected_path(root: &Path, name: &str) -> Result<PathBuf, RarparError> {
    let path = Path::new(name);
    if name.is_empty()
        || name.contains('\\')
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(RarparError::Unsafe(format!(
            "unsafe PAR3 member path: {name}"
        )));
    }
    // The user chooses the root; every component supplied by PAR3 is untrusted.
    let mut joined = root.to_path_buf();
    for component in path.components() {
        joined.push(component);
        reject_symlinks(&joined)?;
    }
    Ok(joined)
}

fn validate_destinations(paths: &[PathBuf], probe_missing: bool) -> Result<(), RarparError> {
    let mut existing = BTreeSet::new();
    let mut probes: BTreeMap<PathBuf, tempfile::TempDir> = BTreeMap::new();
    for path in paths {
        let path = if path.is_absolute() {
            path.clone()
        } else {
            std::env::current_dir()?.join(path)
        };
        if path.exists() {
            if !existing.insert(path.canonicalize()?) {
                return Err(RarparError::Unsafe(format!(
                    "PAR3 member paths alias on the target filesystem: {}",
                    path.display()
                )));
            }
            continue;
        }
        let mut ancestor = parent(&path);
        while !ancestor.exists() {
            ancestor = parent(&ancestor);
        }
        if !ancestor.is_dir() {
            return Err(RarparError::Unsafe(format!(
                "PAR3 member is nested under a file: {}",
                path.display()
            )));
        }
        if !probe_missing {
            continue;
        }
        let relative = path.strip_prefix(&ancestor).expect("ancestor prefix");
        let key = ancestor.canonicalize()?;
        if !probes.contains_key(&key) {
            probes.insert(key.clone(), tempfile::tempdir_in(&ancestor)?);
        }
        // Mirror missing names on the destination filesystem, letting its own
        // case folding, Unicode normalization and name rules detect aliases.
        let probe = probes[&key].path().join(relative);
        let result = std::fs::create_dir_all(parent(&probe)).and_then(|()| {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&probe)
                .map(drop)
        });
        if let Err(error) = result {
            return Err(RarparError::Unsafe(format!(
                "PAR3 member paths alias or cannot be represented on the target filesystem: {}: {error}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn collect_files(
    root: &Path,
    cli: &Cli,
    depth: usize,
    files: &mut BTreeSet<PathBuf>,
) -> Result<(), RarparError> {
    reject_symlinks(root)?;
    let meta = std::fs::metadata(root)?;
    if meta.is_file() {
        files.insert(root.to_path_buf());
        if files.len() > cli.max_files {
            return Err(RarparError::Resource(
                "PAR3 discovery exceeded --max-files".into(),
            ));
        }
    } else if meta.is_dir() {
        for entry in std::fs::read_dir(root)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_file() || (kind.is_dir() && !cli.no_recursive && depth < cli.max_depth) {
                collect_files(&entry.path(), cli, depth + 1, files)?;
            }
        }
    } else {
        return Err(RarparError::Unsafe(format!(
            "not a regular file or directory: {}",
            root.display()
        )));
    }
    Ok(())
}

fn load_selected(
    cli: &Cli,
    args: &Par3Args,
    options: &ExecutionOptions,
) -> Result<LoadedSet, RarparError> {
    reject_symlinks(&args.input)?;
    let input = args.input.canonicalize()?;
    let mut files = BTreeSet::new();
    if input.is_dir() {
        collect_files(&input, cli, 0, &mut files)?;
    } else {
        files.insert(input.clone());
        // Siblings are candidates only; authenticated identities select the set.
        for entry in std::fs::read_dir(parent(&input))? {
            let entry = entry?;
            if entry.file_type()?.is_file() && is_carrier_candidate(&entry.path()) {
                files.insert(entry.path());
                if files.len() > cli.max_files {
                    return Err(RarparError::Resource(
                        "PAR3 discovery exceeded --max-files".into(),
                    ));
                }
            }
        }
    }
    let paths: Vec<_> = files
        .into_iter()
        .filter(|path| *path == input || is_carrier_candidate(path))
        .collect();
    let options = carrier_options(options, paths.len())?;
    let mut sets = scan(&paths, &options)?;
    sets.retain(|set| {
        args.set_id.as_ref().map_or_else(
            || input.is_dir() || set.paths.contains(&input),
            |id| set.id.to_string().eq_ignore_ascii_case(id),
        )
    });
    match sets.len() {
        0 => Err(RarparError::Data(
            "no authenticated PAR3 set matches the input and --set-id".into(),
        )),
        1 => Ok(sets.remove(0)),
        _ => Err(RarparError::Usage(format!(
            "multiple PAR3 sets or copies; select a carrier path or --set-id from: {}",
            sets.iter()
                .map(|set| set.id.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

pub fn run_command(cli: &Cli, command: Par3Command) -> Result<u8, RarparError> {
    let result = match command {
        Par3Command::Create(args) => create(cli, &args),
        Par3Command::Verify(args) => {
            verify_repair(cli, &args, false).map(|outcome| (outcome.success, outcome.report))
        }
        Par3Command::Repair(args) => {
            verify_repair(cli, &args, true).map(|outcome| (outcome.success, outcome.report))
        }
    };
    match result {
        Ok((success, report)) => {
            emit(cli, &report)?;
            Ok(if success {
                EXIT_SUCCESS
            } else {
                EXIT_DATA_FAILURE
            })
        }
        Err(error) => {
            if cli.json {
                let mut report = json!({"operation":"par3", "success":false, "error":error.to_string(), "exit_code":error.exit_code()});
                if let RarparError::Par3(EngineError::RepairInterrupted {
                    installed,
                    temporary,
                    ..
                }) = &error
                {
                    report["installed"] = json!(
                        installed
                            .iter()
                            .map(|file| json!({"path":file.path,"backup":file.backup}))
                            .collect::<Vec<_>>()
                    );
                    report["temporary"] = json!(temporary);
                }
                if let RarparError::Par3(EngineError::OutputInterrupted { installed, .. }) = &error
                {
                    report["installed"] = json!(installed);
                }
                emit(cli, &report)?;
            }
            Err(error)
        }
    }
}

fn emit(cli: &Cli, report: &Value) -> Result<(), RarparError> {
    if cli.json {
        println!("{}", serde_json::to_string_pretty(report)?);
    } else if !cli.quiet {
        println!(
            "{}: {}{}",
            report["operation"].as_str().unwrap_or("PAR3"),
            report["status"].as_str().unwrap_or("created"),
            if report["dry_run"] == true {
                " (dry run)"
            } else {
                ""
            }
        );
        if let Some(outputs) = report["outputs"].as_array() {
            println!(
                "  {} block(s), {} cohort(s), {} scratch bytes",
                report["blocks"], report["cohorts"], report["scratch_bytes"]
            );
            for (index, path) in outputs.iter().enumerate() {
                println!(
                    "  {}: {} bytes",
                    path.as_str().unwrap_or_default(),
                    report["output_sizes"][index]
                );
            }
        }
        if let Some(files) = report["files"].as_array() {
            for file in files {
                println!(
                    "  {}: {}, verified prefix {} bytes",
                    file["path"].as_str().unwrap_or_default(),
                    if file["complete"] == true {
                        "verified"
                    } else {
                        "damaged or unavailable"
                    },
                    file["verified_prefix"]
                );
            }
        }
        if let Some(needs) = report["requirements"].as_array() {
            for need in needs {
                println!(
                    "  cohort {}: {} additional recovery packet(s) needed",
                    need["cohort"], need["additional"]
                );
            }
        }
        if let Some(installed) = report["installed"].as_array() {
            for file in installed {
                println!("  installed {}", file["path"].as_str().unwrap_or_default());
            }
        }
    }
    Ok(())
}

pub struct RepairOutcome {
    pub success: bool,
    pub report: Value,
    pub protected_paths: Vec<PathBuf>,
}

pub fn repair_set(cli: &Cli, set: &Par3Set) -> Result<RepairOutcome, RarparError> {
    let args = Par3Args {
        input: set.paths[0].clone(),
        search_dirs: Vec::new(),
        set_id: Some(set.id.clone()),
        no_backup: false,
    };
    let loaded = set
        .loaded
        .as_ref()
        .ok_or(EngineError::InvalidState("PAR3 carriers already released"))?;
    verify_repair_loaded(cli, &args, true, loaded)
}

impl RepairOutcome {
    pub fn action(&self) -> ExecutedAction {
        ExecutedAction {
            set_id: self.report["set_id"].as_str().unwrap_or_default().into(),
            action: "par3_verify_repair".into(),
            success: self.success,
            message: self.report.to_string(),
        }
    }
}

fn verify_repair(cli: &Cli, args: &Par3Args, repair: bool) -> Result<RepairOutcome, RarparError> {
    let options = options(cli)?;
    let loaded = load_selected(cli, args, &options)?;
    verify_repair_loaded(cli, args, repair, &loaded)
}

fn verify_repair_loaded(
    cli: &Cli,
    args: &Par3Args,
    repair: bool,
    loaded: &LoadedSet,
) -> Result<RepairOutcome, RarparError> {
    // Discovery, every set, and any reassessment share cumulative budgets.
    let options = loaded.options.clone();
    let root = cli
        .working_dir
        .clone()
        .unwrap_or_else(|| parent(&loaded.paths[0]));
    reject_symlinks(&root)?;
    let mut disk = DiskSourceAccess::with_options(options.clone());
    let mut bindings = Vec::new();
    let mut protected_paths = Vec::new();
    let metadata = loaded.packets.metadata()?;
    let layout = metadata
        .as_ref()
        .map(|set| BlockLayout::new(set, &options))
        .transpose()?;
    if let Some(layout) = &layout {
        if layout.files().len() > cli.max_files {
            return Err(RarparError::Resource(
                "PAR3 layout exceeded --max-files".into(),
            ));
        }
        let destinations: Vec<_> = layout
            .files()
            .iter()
            .map(|file| protected_path(&root, &file.path))
            .collect::<Result<_, _>>()?;
        if repair {
            validate_destinations(&destinations, !cli.dry_run)?;
        }
        for (file, path) in layout.files().iter().zip(destinations) {
            let id = SourceId(bindings.len() as u64);
            disk.insert(id, path.clone());
            protected_paths.push(path);
            bindings.push((file.path.clone(), id));
        }
    }
    let mut candidates = Vec::new();
    if cli.par_placement == ParPlacement::Smart {
        let mut files = BTreeSet::new();
        if root.exists() {
            collect_files(&root, cli, 0, &mut files)?;
        }
        for directory in cli.search_dir.iter().chain(&args.search_dirs) {
            collect_files(directory, cli, 0, &mut files)?;
        }
        for path in files.into_iter().filter(|path| !is_carrier(path)) {
            let id = SourceId((bindings.len() + candidates.len()) as u64);
            disk.insert(id, path);
            candidates.push(id);
        }
    }
    drop(layout);
    drop(metadata);
    let access: Arc<dyn SourceAccess> = Arc::new(disk);
    let mut session = Par3RepairSession::new(loaded.id, access.clone(), options.clone())?;
    for packet in loaded.packets.packets() {
        session.merge(packet.clone())?;
    }
    for (name, id) in bindings {
        session.bind_file(&name, id)?;
    }
    let assessment = session.assess()?;
    let unresolved: Vec<_> = assessment
        .files
        .iter()
        .map(|file| file.unresolved.clone())
        .collect();
    if matches!(
        assessment.status,
        RepairStatus::NeedRecovery | RepairStatus::Unsupported
    ) && !candidates.is_empty()
    {
        let layout = session.layout()?.expect("assessed layout");
        let mut limits = PlacementOptions {
            max_candidates: cli.max_files,
            ..PlacementOptions::default()
        };
        for (file_index, file) in layout.files().iter().enumerate() {
            for (extent_index, extent) in file.extents.iter().enumerate() {
                if matches!(
                    extent.kind,
                    ExtentKind::Block {
                        fingerprint: Some(_),
                        rolling_hash: Some(_),
                        ..
                    }
                ) && unresolved[file_index]
                    .iter()
                    .any(|range| range.start < extent.range.end && extent.range.start < range.end)
                {
                    let found = search_extent(
                        &layout,
                        file_index,
                        extent_index,
                        access.as_ref(),
                        &candidates,
                        &limits,
                        &options,
                    )?;
                    limits.max_read_bytes = limits.max_read_bytes.saturating_sub(found.read_bytes);
                    if let Some(placement) = found.matches.into_iter().next() {
                        session.add_placement(placement)?;
                    }
                }
            }
        }
    }
    let assessment = session.assess()?;
    let mut success = assessment.status == RepairStatus::Complete;
    let ready = assessment.status == RepairStatus::Ready;
    let mut report = json!({
        "operation": if repair {"par3_repair"} else {"par3_verify"}, "set_id":loaded.id.to_string(),
        "status":format!("{:?}", assessment.status), "success":success, "dry_run":cli.dry_run,
        "files":assessment.files.iter().map(|file| json!({"path":file.path,"complete":file.complete,"verified_prefix":file.verified_prefix,"unresolved":file.unresolved})).collect::<Vec<_>>(),
        "lost_blocks":assessment.lost_blocks,
        "requirements":assessment.requirements.iter().map(|need| json!({"matrix":need.matrix.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),"cohort":need.cohort,"cohorts":need.cohorts,"recovery_indices":need.recovery_indices,"available":need.available,"additional":need.additional})).collect::<Vec<_>>(),
        "installed":[], "reconstructed_blocks":0
    });
    if repair && ready && !cli.dry_run {
        let result = session.repair(&root, !args.no_backup)?;
        success = true;
        report["success"] = json!(true);
        report["status"] = json!("Repaired");
        report["installed"] = json!(
            result
                .installed
                .iter()
                .map(|file| json!({"path":file.path,"backup":file.backup}))
                .collect::<Vec<_>>()
        );
        report["reconstructed_blocks"] = json!(result.reconstructed_blocks);
        report["initial_lost_blocks"] = report["lost_blocks"].take();
        report["initial_requirements"] = report["requirements"].take();
        report["lost_blocks"] = json!([]);
        report["requirements"] = json!([]);
        let layout = session.layout()?.expect("repaired layout");
        for (file, description) in report["files"]
            .as_array_mut()
            .expect("file report")
            .iter_mut()
            .zip(layout.files())
        {
            file["complete"] = json!(true);
            file["verified_prefix"] = json!(description.len);
            file["unresolved"] = json!([]);
        }
    }
    // A repair dry run succeeds when it can execute, while verify still reports damage.
    if repair && cli.dry_run && ready {
        session.validate_repair()?;
        success = true;
        report["success"] = json!(true);
    }
    Ok(RepairOutcome {
        success,
        report,
        protected_paths,
    })
}

fn reject_obsolete_carriers(
    cli: &Cli,
    stem: &Path,
    outputs: &[PathBuf],
    options: &ExecutionOptions,
) -> Result<(), RarparError> {
    let directory = parent(stem);
    if !directory.exists() {
        return Ok(());
    }
    let mut files = BTreeSet::new();
    let mut local = cli.clone();
    local.no_recursive = true;
    collect_files(&directory, &local, 0, &mut files)?;
    let candidates: Vec<_> = files
        .into_iter()
        .filter(|path| is_carrier_candidate(path))
        .collect();
    let stem_name = stem.file_name().unwrap_or_default().to_string_lossy();
    let intended: BTreeSet<_> = outputs
        .iter()
        .map(|path| {
            if path.exists() {
                path.canonicalize()
            } else {
                directory
                    .canonicalize()
                    .map(|root| root.join(path.file_name().unwrap_or_default()))
            }
        })
        .collect::<Result<_, _>>()?;
    let options = carrier_options(options, candidates.len())?;
    for set in scan(&candidates, &options)? {
        // Names select overwrite candidates only. Membership comes exclusively
        // from authenticated packets, including renamed copies of the old set.
        let selected = set.paths.iter().any(|path| {
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            path.canonicalize()
                .is_ok_and(|path| intended.contains(&path))
                || name == format!("{stem_name}.par3")
                || (name.starts_with(&format!("{stem_name}.vol")) && is_carrier(path))
                || (name.starts_with(&format!("{stem_name}.part")) && is_carrier(path))
        });
        if selected {
            for path in &set.paths {
                if !intended.contains(&path.canonicalize()?) {
                    return Err(RarparError::Unsafe(format!(
                        "overwrite would leave an obsolete authenticated PAR3 carrier: {}; move the previous set aside or choose a new output directory",
                        path.display()
                    )));
                }
            }
        }
    }
    Ok(())
}

fn create(cli: &Cli, args: &Par3CreateArgs) -> Result<(bool, Value), RarparError> {
    let execution = options(cli)?;
    if args.files.len() > cli.max_files {
        return Err(RarparError::Resource(
            "creation exceeded --max-files".into(),
        ));
    }
    let base = args.base_path.clone().unwrap_or(std::env::current_dir()?);
    reject_symlinks(&base)?;
    let base = base.canonicalize()?;
    let mut disk = DiskSourceAccess::with_options(execution.clone());
    let mut sources = Vec::new();
    let mut input_paths = BTreeSet::new();
    for path in &args.files {
        let path = if path.is_absolute() {
            path.clone()
        } else {
            base.join(path)
        };
        reject_symlinks(&path)?;
        let path = path.canonicalize()?;
        if !path.is_file() {
            return Err(RarparError::Usage(
                "creation inputs must be regular files".into(),
            ));
        }
        let relative = path.strip_prefix(&base).map_err(|_| {
            RarparError::Usage(format!(
                "input {} is outside --base-path {}",
                path.display(),
                base.display()
            ))
        })?;
        let name = relative
            .to_str()
            .ok_or_else(|| RarparError::Usage("PAR3 member names must be UTF-8".into()))?
            .replace(std::path::MAIN_SEPARATOR, "/");
        protected_path(&base, &name)?;
        let id = SourceId(sources.len() as u64);
        disk.insert(id, path.clone());
        input_paths.insert(path);
        sources.push(CreationSource { name, source: id });
    }
    let mut config = CreationOptions {
        execution: execution.clone(),
        block_size: args.block_size,
        codec: match args.codec {
            Par3Codec::Cauchy => {
                if args.capacity_log2.is_some() || args.interleave != 0 {
                    return Err(RarparError::Usage(
                        "--capacity-log2 and --interleave require --codec fft".into(),
                    ));
                }
                CreationCodec::Cauchy
            }
            Par3Codec::Fft => CreationCodec::Fft {
                capacity_log2: args.capacity_log2.ok_or_else(|| {
                    RarparError::Usage("--codec fft requires --capacity-log2".into())
                })?,
                interleave: args.interleave,
            },
        },
        first_recovery: args.first_recovery,
        recovery_count: if args.recovery_percent.is_some() {
            0
        } else {
            args.recovery_count.unwrap_or(1)
        },
        deduplication: match args.dedup {
            Par3Dedup::None => Deduplication::None,
            Par3Dedup::Aligned => Deduplication::Aligned,
            Par3Dedup::Sliding => Deduplication::Sliding,
        },
        store_data: args.data_packets,
        volumes: if let Some(blocks) = args.volume_blocks {
            VolumeLayout::Uniform(blocks)
        } else if let Some(bytes) = args.volume_bytes {
            VolumeLayout::SizeLimited(bytes)
        } else {
            VolumeLayout::Variable
        },
        ..CreationOptions::default()
    };
    let access: Arc<dyn SourceAccess> = Arc::new(disk);
    let mut plan = CreationPlan::build(access.clone(), &sources, config.clone())?;
    if let Some(percent) = args.recovery_percent {
        config.recovery_count = plan
            .requirements()
            .blocks
            .checked_mul(u64::from(percent))
            .ok_or_else(|| RarparError::Resource("recovery percentage overflow".into()))?
            .div_ceil(100);
        drop(plan);
        plan = CreationPlan::build(access, &sources, config)?;
    }
    let stem = if is_carrier(&args.output) {
        args.output.with_extension("")
    } else {
        args.output.clone()
    };
    reject_symlinks(&stem)?;
    let outputs: Vec<_> = plan.output_paths(&stem).collect();
    if cli.overwrite {
        reject_obsolete_carriers(cli, &stem, &outputs, &execution)?;
    }
    for output in &outputs {
        reject_symlinks(output)?;
        match std::fs::symlink_metadata(output) {
            Ok(meta) => {
                if !cli.overwrite
                    || !meta.is_file()
                    || input_paths.contains(&output.canonicalize()?)
                {
                    return Err(RarparError::Unsafe(format!(
                        "output exists or aliases an input: {}",
                        output.display()
                    )));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    let requirements = plan.requirements();
    let report = json!({"operation":"par3_create", "success":true,"dry_run":cli.dry_run,"set_id":plan.input_set_id().to_string(),"outputs":outputs,"output_sizes":requirements.output_sizes,"blocks":requirements.blocks,"source_bytes":requirements.source_bytes,"reused_blocks":requirements.reused_blocks,"scratch_bytes":requirements.scratch_bytes,"metadata_bytes":requirements.metadata_bytes,"cohorts":requirements.cohorts,"field_bytes":requirements.field.size,"buffered":args.buffered});
    if !cli.dry_run {
        let directory = parent(&stem);
        std::fs::create_dir_all(&directory)?;
        let stage = tempfile::tempdir_in(&directory)?;
        let stage_stem = stage.path().join(
            stem.file_name()
                .ok_or_else(|| RarparError::Usage("output must have a file name".into()))?,
        );
        let scratch = args.scratch_dir.as_deref().unwrap_or(stage.path());
        reject_symlinks(scratch)?;
        let durability = if args.buffered {
            par3_rs::creation::CreationDurability::Buffered
        } else {
            par3_rs::creation::CreationDurability::SyncFiles
        };
        let staged = plan.execute_with_durability(&stage_stem, scratch, durability)?;
        let mut installed = Vec::new();
        for (source, destination) in staged.iter().zip(&outputs) {
            let result = if cli.overwrite {
                std::fs::rename(source, destination)
            } else {
                std::fs::hard_link(source, destination)
            };
            if let Err(cause) = result {
                return Err(EngineError::OutputInterrupted {
                    installed,
                    cause: Box::new(cause.into()),
                }
                .into());
            }
            installed.push(destination.clone());
        }
    }
    Ok((true, report))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use par3_rs::runtime::ScanWorkBudget;
    use par3_rs::source::MemorySourceAccess;

    #[test]
    fn shared_carrier_sets_repair_and_rediscover_without_rescanning() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let mut carrier = Vec::new();
        for index in 0..16 {
            let mut access = MemorySourceAccess::default();
            access.insert(SourceId(0), 0, Arc::from(&b""[..]));
            let sources = [CreationSource {
                name: format!("empty{index}"),
                source: SourceId(0),
            }];
            let plan = CreationPlan::build(
                Arc::new(access),
                &sources,
                CreationOptions {
                    block_size: 256,
                    recovery_count: 0,
                    ..CreationOptions::default()
                },
            )
            .unwrap();
            for path in plan
                .execute(&root.join(format!("set{index}")), root)
                .unwrap()
            {
                // Concatenate complete carrier output, without modifying packets.
                carrier.extend(std::fs::read(&path).unwrap());
                std::fs::remove_file(path).unwrap();
            }
        }
        let path = root.join("collection.par3");
        std::fs::write(&path, &carrier).unwrap();
        let mut options = ExecutionOptions::default();
        options.scan_work = ScanWorkBudget::new(4 * carrier.len() as u64);
        let sets = discover_sets(std::slice::from_ref(&path), &options).unwrap();
        assert_eq!(sets.len(), 16);
        let scanned = options.scan_work.used();
        let read_bytes = options.diagnostics.file_io().read_bytes;
        let expected_reads = carrier.len() as u64 * if cfg!(windows) { 2 } else { 1 };
        assert_eq!(read_bytes, expected_reads);
        assert_eq!(scanned, expected_reads + u64::from(cfg!(windows)));
        let cli = Cli::try_parse_from(["rarpar", "auto", path.to_str().unwrap()]).unwrap();
        for set in &sets {
            assert_eq!(
                set.loaded.as_ref().unwrap().options.scan_work.used(),
                options.scan_work.used()
            );
            assert!(repair_set(&cli, set).unwrap().success);
        }
        assert_eq!(
            options.diagnostics.file_io().read_bytes,
            read_bytes,
            "repair must reuse discovery packets and budgets"
        );
        let report = crate::discovery::discover_reusing_par3(
            vec![path],
            &crate::discovery::DiscoveryOptions::from_cli(&cli),
            Some(sets),
        )
        .unwrap();
        assert_eq!(report.par3_sets.len(), 16);
        assert_eq!(options.diagnostics.file_io().read_bytes, read_bytes);
        #[cfg(unix)]
        assert_eq!(options.scan_work.used(), scanned);
        for index in 0..16 {
            assert!(root.join(format!("empty{index}")).is_file());
        }
        drop(report);
        assert_eq!(options.handles.used(), 0);
        assert_eq!(options.memory.used(), 0);
    }
}
