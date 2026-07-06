use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::cleanup::{CleanupManifest, CleanupResult};
use crate::cli::Cli;
use crate::error::RarparError;

const PAR2_MAGIC: &[u8] = b"PAR2\0PKT";
const RAR5_SIGNATURE: &[u8] = &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00];
const RAR4_SIGNATURE: &[u8] = &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00];
const RAR14_SIGNATURE: &[u8] = &[0x52, 0x45, 0x7E, 0x5E];

#[derive(Debug, Clone)]
pub struct DiscoveryOptions {
    pub recursive: bool,
    pub max_depth: usize,
    pub max_files: usize,
}

impl DiscoveryOptions {
    pub fn from_cli(cli: &Cli) -> Self {
        Self {
            recursive: !cli.no_recursive,
            max_depth: cli.max_depth,
            max_files: cli.max_files,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DiscoveryReport {
    pub roots: Vec<PathBuf>,
    pub recursive: bool,
    pub max_depth: usize,
    pub max_files: usize,
    pub files: Vec<DiscoveredFile>,
    pub sets: Vec<DiscoveredSet>,
    pub rar_sets: Vec<RarSet>,
    pub par2_sets: Vec<Par2Set>,
    pub planned_actions: Vec<PlannedAction>,
    pub cleanup_candidates: Vec<CleanupManifest>,
    pub executed_actions: Vec<ExecutedAction>,
    pub cleanup_results: Vec<CleanupResult>,
}

impl DiscoveryReport {
    pub fn record_action(&mut self, action: ExecutedAction) {
        self.executed_actions.push(action);
    }

    pub fn record_cleanup(&mut self, cleanup: CleanupResult) {
        self.cleanup_results.push(cleanup);
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DiscoveredFile {
    pub path: PathBuf,
    pub kind: DiscoveredKind,
    pub set_hint: Option<String>,
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveredKind {
    RarVolume(RarVolumeInfo),
    RarRecoveryVolume,
    Par2(Par2FileInfo),
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RarVolumeInfo {
    pub format: String,
    pub volume_number: Option<usize>,
    pub is_multi_volume: bool,
    pub has_next_volume: bool,
    pub is_header_encrypted: bool,
    pub has_encrypted_files: bool,
    pub is_solid: bool,
    pub is_first_volume: bool,
    pub files: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Par2FileInfo {
    pub recovery_set_id: Option<String>,
    pub packet_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiscoveredSet {
    pub label: String,
    pub base_dir: PathBuf,
    pub rar_volumes: usize,
    pub rar_recovery_volumes: usize,
    pub par2_files: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct RarSet {
    pub id: String,
    pub label: String,
    pub base_dir: PathBuf,
    pub volumes: Vec<RarVolume>,
    pub recovery_volumes: Vec<PathBuf>,
}

impl RarSet {
    pub fn source_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        paths.extend(self.volumes.iter().map(|volume| volume.path.clone()));
        paths.extend(self.recovery_volumes.clone());
        paths.sort();
        paths.dedup();
        paths
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RarVolume {
    pub path: PathBuf,
    pub volume_number: Option<usize>,
    pub sort_index: usize,
    pub is_first_volume: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Par2Set {
    pub id: String,
    pub base_dir: PathBuf,
    pub paths: Vec<PathBuf>,
    pub protected_files: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlannedAction {
    pub set_id: String,
    pub action: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExecutedAction {
    pub set_id: String,
    pub action: String,
    pub success: bool,
    pub message: String,
}

pub fn discover(
    paths: Vec<PathBuf>,
    options: &DiscoveryOptions,
) -> Result<DiscoveryReport, RarparError> {
    let roots = paths.clone();
    let mut files = Vec::new();
    let mut scan_count = 0usize;
    for path in paths {
        if !path.exists() {
            return Err(RarparError::MissingInput(path));
        }
        collect_path(&path, options, 0, &mut scan_count, &mut files)?;
    }

    files.sort_by(|a, b| a.path.cmp(&b.path));
    let par2_sets = build_par2_sets(&files);
    let rar_sets = build_rar_sets(&files);
    let sets = summarize_sets(&rar_sets, &par2_sets);
    let planned_actions = plan_actions(&rar_sets, &par2_sets);
    let cleanup_candidates = cleanup_candidates(&rar_sets, &par2_sets);

    Ok(DiscoveryReport {
        roots,
        recursive: options.recursive,
        max_depth: options.max_depth,
        max_files: options.max_files,
        files,
        sets,
        rar_sets,
        par2_sets,
        planned_actions,
        cleanup_candidates,
        executed_actions: Vec::new(),
        cleanup_results: Vec::new(),
    })
}

pub fn discover_rar_set_for_archive(
    archive: &Path,
    options: &DiscoveryOptions,
) -> Result<RarSet, RarparError> {
    if !archive.exists() {
        return Err(RarparError::MissingInput(archive.to_path_buf()));
    }
    let root = archive
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let report = discover(vec![root], options)?;
    report
        .rar_sets
        .into_iter()
        .find(|set| {
            set.volumes
                .iter()
                .any(|volume| same_path(&volume.path, archive))
        })
        .ok_or_else(|| RarparError::Data(format!("no RAR set found for {}", archive.display())))
}

pub fn output_dir_for_rar_set(cli: &Cli, set: &RarSet, total_sets: usize) -> PathBuf {
    match &cli.output {
        Some(output) if total_sets > 1 => output.join(safe_label(&set.label)),
        Some(output) => output.clone(),
        None => set.base_dir.clone(),
    }
}

fn collect_path(
    path: &Path,
    options: &DiscoveryOptions,
    depth: usize,
    scan_count: &mut usize,
    files: &mut Vec<DiscoveredFile>,
) -> Result<(), RarparError> {
    if *scan_count >= options.max_files {
        return Err(RarparError::Resource(format!(
            "discovery exceeded max files ({})",
            options.max_files
        )));
    }

    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.is_file() {
        *scan_count += 1;
        files.push(classify_path(path));
        return Ok(());
    }

    if !metadata.is_dir() {
        return Ok(());
    }
    if depth >= options.max_depth {
        return Ok(());
    }

    let mut entries = Vec::new();
    for entry in std::fs::read_dir(path)? {
        entries.push(entry?);
    }
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        let entry_path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_file() {
            *scan_count += 1;
            if *scan_count > options.max_files {
                return Err(RarparError::Resource(format!(
                    "discovery exceeded max files ({})",
                    options.max_files
                )));
            }
            files.push(classify_path(&entry_path));
        } else if options.recursive && file_type.is_dir() {
            collect_path(&entry_path, options, depth + 1, scan_count, files)?;
        }
    }
    Ok(())
}

fn classify_path(path: &Path) -> DiscoveredFile {
    let mut diagnostics = Vec::new();
    let prefix = read_prefix(path, 16).unwrap_or_default();

    if looks_like_par2(path, &prefix) {
        match weaver_par2::scan_packets_from_path_with_set_ids(path) {
            Ok(packets) if !packets.is_empty() => {
                let set_id = packets
                    .first()
                    .map(|packet| packet.recovery_set_id.to_string());
                return DiscoveredFile {
                    path: path.to_path_buf(),
                    kind: DiscoveredKind::Par2(Par2FileInfo {
                        recovery_set_id: set_id,
                        packet_count: packets.len(),
                    }),
                    set_hint: set_hint(path),
                    diagnostics,
                };
            }
            Ok(_) if is_ext(path, "par2") => {
                diagnostics.push("no valid PAR2 packets found".to_string());
                return DiscoveredFile {
                    path: path.to_path_buf(),
                    kind: DiscoveredKind::Par2(Par2FileInfo {
                        recovery_set_id: None,
                        packet_count: 0,
                    }),
                    set_hint: set_hint(path),
                    diagnostics,
                };
            }
            Ok(_) => {}
            Err(error) if is_ext(path, "par2") => {
                diagnostics.push(format!("PAR2 scan failed: {error}"));
                return DiscoveredFile {
                    path: path.to_path_buf(),
                    kind: DiscoveredKind::Par2(Par2FileInfo {
                        recovery_set_id: None,
                        packet_count: 0,
                    }),
                    set_hint: set_hint(path),
                    diagnostics,
                };
            }
            Err(_) => {}
        }
    }

    if is_ext(path, "rev") {
        return DiscoveredFile {
            path: path.to_path_buf(),
            kind: DiscoveredKind::RarRecoveryVolume,
            set_hint: set_hint(path),
            diagnostics,
        };
    }

    if looks_like_rar(path, &prefix) {
        match File::open(path).and_then(|mut file| {
            weaver_unrar::probe_volume(&mut file).map_err(std::io::Error::other)
        }) {
            Ok(probe) => {
                let files = probe
                    .files
                    .iter()
                    .map(|file| file.name.clone())
                    .collect::<Vec<_>>();
                let format = format!("{:?}", probe.format).to_ascii_lowercase();
                return DiscoveredFile {
                    path: path.to_path_buf(),
                    kind: DiscoveredKind::RarVolume(RarVolumeInfo {
                        format,
                        volume_number: probe.volume_number,
                        is_multi_volume: probe.is_multi_volume,
                        has_next_volume: probe.has_next_volume,
                        is_header_encrypted: probe.is_header_encrypted,
                        has_encrypted_files: probe.has_encrypted_files,
                        is_solid: probe.is_solid,
                        is_first_volume: probe.is_first_volume,
                        files,
                    }),
                    set_hint: set_hint(path),
                    diagnostics,
                };
            }
            Err(error) if looks_rarish_by_name(path) => {
                diagnostics.push(format!("RAR probe failed: {error}"));
            }
            Err(_) => {}
        }
    }

    DiscoveredFile {
        path: path.to_path_buf(),
        kind: DiscoveredKind::Other,
        set_hint: None,
        diagnostics,
    }
}

fn build_par2_sets(files: &[DiscoveredFile]) -> Vec<Par2Set> {
    let mut groups: BTreeMap<String, Vec<PathBuf>> = BTreeMap::new();
    for file in files {
        let DiscoveredKind::Par2(info) = &file.kind else {
            continue;
        };
        let key = info
            .recovery_set_id
            .clone()
            .unwrap_or_else(|| format!("par2:{}", fallback_set_key(&file.path)));
        groups.entry(key).or_default().push(file.path.clone());
    }

    groups
        .into_iter()
        .map(|(id, mut paths)| {
            paths.sort();
            paths.dedup();
            let base_dir = common_base_dir(&paths);
            let protected_files = weaver_par2::Par2FileSet::from_paths(&paths)
                .ok()
                .map(|set| {
                    set.files
                        .values()
                        .map(|desc| desc.filename.clone())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            Par2Set {
                id,
                base_dir,
                paths,
                protected_files,
            }
        })
        .collect()
}

fn build_rar_sets(files: &[DiscoveredFile]) -> Vec<RarSet> {
    let mut groups: BTreeMap<String, RarSetBuilder> = BTreeMap::new();

    for file in files {
        match &file.kind {
            DiscoveredKind::RarVolume(info) => {
                let key = rar_group_key(file, info);
                let entry = groups
                    .entry(key.clone())
                    .or_insert_with(|| RarSetBuilder::new(&key, file));
                entry.label = entry.label.clone().or_else(|| file.set_hint.clone());
                let volume_number = info.volume_number;
                entry.volumes.push(RarVolume {
                    path: file.path.clone(),
                    volume_number,
                    sort_index: volume_number.unwrap_or_else(|| filename_volume_index(&file.path)),
                    is_first_volume: info.is_first_volume,
                });
            }
            DiscoveredKind::RarRecoveryVolume => {
                let key = format!(
                    "{}:{}",
                    parent_key(&file.path),
                    file.set_hint
                        .clone()
                        .unwrap_or_else(|| fallback_set_key(&file.path))
                );
                let entry = groups
                    .entry(key.clone())
                    .or_insert_with(|| RarSetBuilder::new(&key, file));
                entry.label = entry.label.clone().or_else(|| file.set_hint.clone());
                entry.recovery_volumes.push(file.path.clone());
            }
            _ => {}
        }
    }

    let mut sets = groups
        .into_iter()
        .map(|(id, mut builder)| {
            builder.volumes.sort_by(|a, b| {
                a.sort_index
                    .cmp(&b.sort_index)
                    .then_with(|| a.path.cmp(&b.path))
            });
            builder.recovery_volumes.sort();
            builder.recovery_volumes.dedup();
            RarSet {
                id,
                label: builder.label.unwrap_or_else(|| builder.id.clone()),
                base_dir: builder.base_dir,
                volumes: builder.volumes,
                recovery_volumes: builder.recovery_volumes,
            }
        })
        .collect::<Vec<_>>();
    sets.sort_by(|a, b| a.id.cmp(&b.id));
    sets
}

#[derive(Debug)]
struct RarSetBuilder {
    id: String,
    label: Option<String>,
    base_dir: PathBuf,
    volumes: Vec<RarVolume>,
    recovery_volumes: Vec<PathBuf>,
}

impl RarSetBuilder {
    fn new(id: &str, file: &DiscoveredFile) -> Self {
        Self {
            id: id.to_string(),
            label: file.set_hint.clone(),
            base_dir: file
                .path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf(),
            volumes: Vec::new(),
            recovery_volumes: Vec::new(),
        }
    }
}

fn summarize_sets(rar_sets: &[RarSet], par2_sets: &[Par2Set]) -> Vec<DiscoveredSet> {
    let mut summaries = Vec::new();
    for set in rar_sets {
        summaries.push(DiscoveredSet {
            label: set.label.clone(),
            base_dir: set.base_dir.clone(),
            rar_volumes: set.volumes.len(),
            rar_recovery_volumes: set.recovery_volumes.len(),
            par2_files: related_par2_sets(set, par2_sets)
                .iter()
                .map(|par| par.paths.len())
                .sum(),
        });
    }
    for set in par2_sets {
        if !rar_sets.iter().any(|rar| par2_related_to_rar(rar, set)) {
            summaries.push(DiscoveredSet {
                label: set.id.clone(),
                base_dir: set.base_dir.clone(),
                rar_volumes: 0,
                rar_recovery_volumes: 0,
                par2_files: set.paths.len(),
            });
        }
    }
    summaries
}

fn plan_actions(rar_sets: &[RarSet], par2_sets: &[Par2Set]) -> Vec<PlannedAction> {
    let mut actions = Vec::new();
    for par in par2_sets {
        actions.push(PlannedAction {
            set_id: par.id.clone(),
            action: "par_verify_repair".to_string(),
            reason: format!("{} PAR2 file(s) found", par.paths.len()),
        });
    }
    for rar in rar_sets {
        if !rar.recovery_volumes.is_empty() {
            actions.push(PlannedAction {
                set_id: rar.id.clone(),
                action: "rar_restore_volumes".to_string(),
                reason: format!(
                    "{} RAR recovery volume(s) found",
                    rar.recovery_volumes.len()
                ),
            });
        }
        if !rar.volumes.is_empty() {
            actions.push(PlannedAction {
                set_id: rar.id.clone(),
                action: "rar_extract".to_string(),
                reason: format!("{} RAR volume(s) found", rar.volumes.len()),
            });
        }
    }
    actions
}

fn cleanup_candidates(rar_sets: &[RarSet], par2_sets: &[Par2Set]) -> Vec<CleanupManifest> {
    rar_sets
        .iter()
        .map(|rar| {
            let mut candidates = rar.source_paths();
            for par in related_par2_sets(rar, par2_sets) {
                candidates.extend(par.paths.clone());
            }
            candidates.sort();
            candidates.dedup();
            CleanupManifest { candidates }
        })
        .collect()
}

pub fn related_par2_sets<'a>(rar: &RarSet, par2_sets: &'a [Par2Set]) -> Vec<&'a Par2Set> {
    par2_sets
        .iter()
        .filter(|par| par2_related_to_rar(rar, par))
        .collect()
}

fn par2_related_to_rar(rar: &RarSet, par: &Par2Set) -> bool {
    if rar.base_dir != par.base_dir {
        return false;
    }
    if par.protected_files.is_empty() {
        return label_related(&rar.label, par.paths.first().map(PathBuf::as_path));
    }
    let rar_names = rar
        .volumes
        .iter()
        .filter_map(|volume| volume.path.file_name().and_then(OsStr::to_str))
        .collect::<BTreeSet<_>>();
    par.protected_files.iter().any(|name| {
        rar_names.contains(name.as_str()) || label_related(&rar.label, Some(Path::new(name)))
    })
}

fn rar_group_key(file: &DiscoveredFile, info: &RarVolumeInfo) -> String {
    let label = if looks_rarish_by_name(&file.path) {
        file.set_hint
            .clone()
            .unwrap_or_else(|| fallback_set_key(&file.path))
    } else {
        info.files
            .iter()
            .find(|name| !name.is_empty())
            .cloned()
            .or_else(|| file.set_hint.clone())
            .unwrap_or_else(|| fallback_set_key(&file.path))
    };
    format!("{}:{}", parent_key(&file.path), label)
}

fn label_related(label: &str, path: Option<&Path>) -> bool {
    let Some(path) = path else {
        return false;
    };
    let Some(name) = path.file_name().and_then(OsStr::to_str) else {
        return false;
    };
    let stem = set_hint(path).unwrap_or_else(|| name.to_string());
    stem == label || name.starts_with(label)
}

fn read_prefix(path: &Path, len: usize) -> std::io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut buf = vec![0u8; len];
    let read = file.read(&mut buf)?;
    buf.truncate(read);
    Ok(buf)
}

fn looks_like_par2(path: &Path, prefix: &[u8]) -> bool {
    prefix.starts_with(PAR2_MAGIC) || is_ext(path, "par2")
}

fn looks_like_rar(path: &Path, prefix: &[u8]) -> bool {
    prefix.starts_with(RAR5_SIGNATURE)
        || prefix.starts_with(RAR4_SIGNATURE)
        || prefix.starts_with(RAR14_SIGNATURE)
        || prefix.starts_with(b"MZ")
        || looks_rarish_by_name(path)
}

fn looks_rarish_by_name(path: &Path) -> bool {
    is_ext(path, "rar")
        || path.extension().and_then(OsStr::to_str).is_some_and(|ext| {
            ext.len() == 3 && ext.starts_with('r') && ext[1..].chars().all(|ch| ch.is_ascii_digit())
        })
}

fn set_hint(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_str()?.to_string();
    let lower = name.to_ascii_lowercase();
    for marker in [".part", ".vol", ".par2", ".rev", ".rar"] {
        if let Some(index) = lower.find(marker) {
            return Some(name[..index].trim_end_matches('.').to_string());
        }
    }
    path.file_stem()
        .and_then(OsStr::to_str)
        .map(|stem| stem.to_string())
}

fn filename_volume_index(path: &Path) -> usize {
    let Some(name) = path.file_name().and_then(OsStr::to_str) else {
        return usize::MAX;
    };
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".rar") && !lower.contains(".part") {
        return 0;
    }
    for marker in [".part", ".r", ".vol"] {
        if let Some(index) = lower.find(marker) {
            let number = lower[index + marker.len()..]
                .chars()
                .take_while(|ch| ch.is_ascii_digit())
                .collect::<String>();
            if let Ok(value) = number.parse::<usize>() {
                return value.saturating_sub(1);
            }
        }
    }
    usize::MAX
}

fn fallback_set_key(path: &Path) -> String {
    set_hint(path).unwrap_or_else(|| path.display().to_string())
}

fn parent_key(path: &Path) -> String {
    path.parent()
        .unwrap_or_else(|| Path::new("."))
        .display()
        .to_string()
}

fn common_base_dir(paths: &[PathBuf]) -> PathBuf {
    paths
        .first()
        .and_then(|path| path.parent())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf()
}

fn safe_label(label: &str) -> String {
    let converted = label
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    if converted.is_empty() {
        "rarpar-set".to_string()
    } else {
        converted
    }
}

fn same_path(left: &Path, right: &Path) -> bool {
    if left == right {
        return true;
    }
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

fn is_ext(path: &Path, expected: &str) -> bool {
    path.extension()
        .and_then(OsStr::to_str)
        .is_some_and(|ext| ext.eq_ignore_ascii_case(expected))
}
