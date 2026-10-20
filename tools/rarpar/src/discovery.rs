use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use par2_rs::FileStatFingerprint;
use serde::Serialize;

use crate::cleanup::{CleanupManifest, CleanupResult};
use crate::error::RarparError;
use crate::par3_inside::fold_case;
use rarpar::cli::Cli;

const PAR2_MAGIC: &[u8] = b"PAR2\0PKT";
const RAR5_SIGNATURE: &[u8] = &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00];
const RAR4_SIGNATURE: &[u8] = &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00];
const RAR14_SIGNATURE: &[u8] = &[0x52, 0x45, 0x7E, 0x5E];

#[derive(Debug, Clone)]
pub struct DiscoveryOptions {
    pub working_dir: Option<PathBuf>,
    pub recursive: bool,
    pub max_depth: usize,
    pub max_files: usize,
    pub par3_memory_mib: usize,
    pub par3_workers: Option<usize>,
    pub par3_max_lost_blocks: u64,
}

impl DiscoveryOptions {
    pub fn from_cli(cli: &Cli) -> Self {
        Self {
            recursive: !cli.no_recursive,
            working_dir: cli.working_dir.clone(),
            max_depth: cli.max_depth,
            max_files: cli.max_files,
            par3_memory_mib: cli.par3_memory_mib,
            par3_workers: cli.par3_workers,
            par3_max_lost_blocks: cli.par3_max_lost_blocks,
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
    pub par3_sets: Vec<crate::par3::Par3Set>,
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
    /// For a PAR2 file, the stat of the bytes its packet scan read, when that
    /// stat can vouch for them (see [`settled_scan`]). A later discovery in
    /// the same run reuses this classification while the stat still matches.
    #[serde(skip)]
    pub(crate) settled: Option<FileStatFingerprint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveredKind {
    RarVolume(RarVolumeInfo),
    RarRecoveryVolume,
    Par2(Par2FileInfo),
    Par3,
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
    /// The packet set discovery loaded from `paths`, kept so the repair and a
    /// later discovery in the same run do not read the volumes again.
    #[serde(skip)]
    pub(crate) loaded: Option<Arc<LoadedPar2Set>>,
}

/// A PAR2 packet set and the stat of each volume it was read from.
#[derive(Debug)]
pub(crate) struct LoadedPar2Set {
    set: par2_rs::Par2FileSet,
    fingerprints: Vec<FileStatFingerprint>,
}

impl Par2Set {
    /// The loaded packet set, while every volume still has the stat it had
    /// when it was read. `None` sends the caller back to the volumes.
    pub(crate) fn reusable_packets(&self) -> Option<par2_rs::Par2FileSet> {
        let loaded = self.loaded.as_ref()?;
        unchanged(&self.paths, &loaded.fingerprints).then(|| loaded.set.clone())
    }
}

/// How long before a scan a file's mtime must lie for its stat to vouch for
/// the bytes the scan read. A write inside the filesystem's timestamp
/// granularity can leave length, mtime and inode as they were; a file last
/// written at least this long before the scan started cannot have been.
const SCAN_SETTLE: Duration = Duration::from_secs(2);

/// Run `scan` over `path` and report the file's stat if it vouches for the
/// bytes the scan read: the same before and after, and last modified at
/// least [`SCAN_SETTLE`] before the scan started.
fn settled_scan<T>(path: &Path, scan: impl FnOnce() -> T) -> (T, Option<FileStatFingerprint>) {
    let (value, settled) = settled_scan_all(std::slice::from_ref(&path.to_path_buf()), scan);
    (value, settled.and_then(|mut all| all.pop()))
}

/// [`settled_scan`] over several files: their stats, in order, if every one
/// of them vouches for the bytes the scan read.
fn settled_scan_all<T>(
    paths: &[PathBuf],
    scan: impl FnOnce() -> T,
) -> (T, Option<Vec<FileStatFingerprint>>) {
    let started = SystemTime::now();
    let before: Option<Vec<_>> = paths
        .iter()
        .map(FileStatFingerprint::capture_path)
        .collect();
    let value = scan();
    let settled = before.filter(|before| {
        unchanged(paths, before)
            && before.iter().all(|fingerprint| {
                fingerprint
                    .modified()
                    .and_then(|modified| started.duration_since(modified).ok())
                    .is_some_and(|age| age >= SCAN_SETTLE)
            })
    });
    (value, settled)
}

fn unchanged(paths: &[PathBuf], fingerprints: &[FileStatFingerprint]) -> bool {
    paths.len() == fingerprints.len()
        && paths.iter().zip(fingerprints).all(|(path, fingerprint)| {
            FileStatFingerprint::capture_path(path).as_ref() == Some(fingerprint)
        })
}

/// PAR2 work an earlier discovery in the same run already did.
#[derive(Default)]
struct Par2Reuse {
    files: BTreeMap<PathBuf, DiscoveredFile>,
    sets: Vec<Par2Set>,
}

impl Par2Reuse {
    fn from_report(report: &DiscoveryReport) -> Self {
        Self {
            files: report
                .files
                .iter()
                .filter(|file| file.settled.is_some())
                .map(|file| (file.path.clone(), file.clone()))
                .collect(),
            sets: report
                .par2_sets
                .iter()
                .filter(|set| set.loaded.is_some())
                .cloned()
                .collect(),
        }
    }

    /// The earlier classification of `path`, if its stat has not changed.
    fn file(&self, path: &Path) -> Option<DiscoveredFile> {
        let file = self.files.get(path)?;
        let settled = file.settled.as_ref()?;
        (FileStatFingerprint::capture_path(path).as_ref() == Some(settled)).then(|| file.clone())
    }

    /// The earlier set over exactly `paths`, if no volume's stat has changed.
    fn set(&self, paths: &[PathBuf]) -> Option<&Par2Set> {
        self.sets.iter().find(|set| {
            set.paths == paths
                && set
                    .loaded
                    .as_ref()
                    .is_some_and(|loaded| unchanged(paths, &loaded.fingerprints))
        })
    }
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
    /// For an `auto --dry-run` restore that would fail by itself, the parity
    /// repair the real run makes first that covers the shortfall: `par2`,
    /// `par3` or `par2+par3`. Absent from the JSON otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deferred_to: Option<&'static str>,
}

pub fn selected_par3_set(set: &crate::par3::Par3Set, roots: &[PathBuf]) -> bool {
    roots
        .iter()
        .any(|root| root.is_dir() || set.paths.iter().any(|path| same_path(path, root)))
}

pub fn discover(
    paths: Vec<PathBuf>,
    options: &DiscoveryOptions,
) -> Result<DiscoveryReport, RarparError> {
    discover_reusing_par3(paths, options, None)
}

// Pipeline rediscovery refreshes archive volumes after repair. The authenticated
// PAR3 collection belongs to the operation and is not scanned again here.
pub(crate) fn discover_reusing_par3(
    paths: Vec<PathBuf>,
    options: &DiscoveryOptions,
    cached: Option<Vec<crate::par3::Par3Set>>,
) -> Result<DiscoveryReport, RarparError> {
    discover_with(paths, options, cached, &Par2Reuse::default())
}

/// Discover again after an action changed the tree. The PAR3 collection is
/// taken from `previous`, and PAR2 volumes whose stat has not changed since
/// `previous` read them are not read again.
pub(crate) fn rediscover(
    paths: Vec<PathBuf>,
    options: &DiscoveryOptions,
    previous: &mut DiscoveryReport,
) -> Result<DiscoveryReport, RarparError> {
    let reuse = Par2Reuse::from_report(previous);
    let par3_sets = std::mem::take(&mut previous.par3_sets);
    discover_with(paths, options, Some(par3_sets), &reuse)
}

fn discover_with(
    paths: Vec<PathBuf>,
    options: &DiscoveryOptions,
    cached: Option<Vec<crate::par3::Par3Set>>,
    reuse: &Par2Reuse,
) -> Result<DiscoveryReport, RarparError> {
    let roots = paths.clone();
    let mut sibling_directories = BTreeSet::new();
    let mut files = Vec::new();
    let mut scan_count = 0usize;
    let mut visited = BTreeSet::new();
    for path in paths {
        if !path.exists() {
            return Err(RarparError::MissingInput(path));
        }
        collect_path(
            &path,
            options,
            0,
            &mut scan_count,
            &mut files,
            &mut visited,
            reuse,
        )?;
        if path.is_file() && crate::par3::is_carrier_candidate(&path) {
            let directory = path
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            if !sibling_directories.insert(directory.canonicalize()?) {
                continue;
            }
            for entry in std::fs::read_dir(directory)? {
                let entry = entry?;
                if entry.file_type()?.is_file()
                    && !visited.contains(&entry.path().canonicalize()?)
                    && crate::par3::is_carrier_candidate(&entry.path())
                {
                    collect_path(
                        &entry.path(),
                        options,
                        0,
                        &mut scan_count,
                        &mut files,
                        &mut visited,
                        reuse,
                    )?;
                }
            }
        }
    }

    files.sort_by(|a, b| a.path.cmp(&b.path));
    files.dedup_by(|a, b| a.path == b.path);
    let par3_paths: Vec<_> = files
        .iter()
        .filter(|file| file.kind == DiscoveredKind::Par3)
        .map(|file| file.path.clone())
        .collect();
    let par3_sets = if let Some(cached) = cached {
        cached
    } else if par3_paths.is_empty() {
        Vec::new()
    } else {
        crate::par3::discover_sets(
            &par3_paths,
            &crate::par3::execution_options(
                options.par3_memory_mib,
                options.par3_workers,
                options.par3_max_lost_blocks,
            )?,
        )?
    };
    for file in files
        .iter_mut()
        .filter(|file| file.kind == DiscoveredKind::Par3)
    {
        if !par3_sets.iter().any(|set| set.paths.contains(&file.path)) {
            file.diagnostics
                .push("no authenticated PAR3 packets found".into());
        }
    }
    let par2_sets = build_par2_sets(&files, reuse);
    let rar_sets = build_rar_sets(&files);
    let sets = summarize_sets(&rar_sets, &par2_sets);
    let mut planned_actions: Vec<_> = par3_sets.iter().filter(|set| selected_par3_set(set, &roots)).map(|set| PlannedAction { set_id: set.id.clone(), action: "par3_verify_repair".into(), reason: "verify protected data and repair with authenticated PAR3 recovery before extraction".into() }).collect();
    planned_actions.extend(plan_actions(&rar_sets, &par2_sets));
    let mut cleanup_candidates = cleanup_candidates(&rar_sets, &par2_sets);
    for (manifest, rar) in cleanup_candidates.iter_mut().zip(&rar_sets) {
        crate::cleanup::add_par3_carriers(
            manifest,
            rar,
            &par3_sets,
            options.working_dir.as_deref(),
        );
    }

    Ok(DiscoveryReport {
        roots,
        recursive: options.recursive,
        max_depth: options.max_depth,
        max_files: options.max_files,
        files,
        sets,
        rar_sets,
        par2_sets,
        par3_sets,
        planned_actions,
        cleanup_candidates,
        executed_actions: Vec::new(),
        cleanup_results: Vec::new(),
    })
}

/// Resolve a protected archive member to the same complete volume family used
/// by explicit archive extraction before building an inferred cleanup manifest.
pub fn expand_inferred_member(
    path: &Path,
    options: &DiscoveryOptions,
) -> Result<Vec<PathBuf>, RarparError> {
    if matches!(classify_path(path).kind, DiscoveredKind::RarVolume(_)) {
        Ok(discover_rar_set_for_archive(path, options)?.source_paths())
    } else {
        Ok(vec![path.to_path_buf()])
    }
}

pub fn discover_rar_set_for_archive(
    archive: &Path,
    options: &DiscoveryOptions,
) -> Result<RarSet, RarparError> {
    if !archive.exists() {
        return Err(RarparError::MissingInput(archive.to_path_buf()));
    }

    if options.max_files == 0 {
        return Err(RarparError::Resource(
            "discovery exceeded max files (0)".to_string(),
        ));
    }

    let archive_file = classify_path(archive);
    if let DiscoveredKind::RarVolume(info) = &archive_file.kind {
        if !info.is_multi_volume && !info.is_header_encrypted {
            return selected_rar_set(vec![archive_file], archive);
        }

        if looks_rarish_by_name(archive)
            && let Some(label) = archive_file.set_hint.as_deref()
        {
            let family = discover_named_rar_family(archive, archive_file.clone(), label, options)?;
            return selected_rar_set(family, archive);
        }
    }

    let root = parent_directory(archive).to_path_buf();
    let report = discover(vec![root], options)?;
    selected_rar_set_from_sets(report.rar_sets, archive)
}

/// The directory a file lives in.
///
/// A bare file name's parent is the empty path, which no filesystem call
/// accepts and which would key the file apart from the `./`-prefixed
/// siblings a listing of the current directory yields, so it stands for the
/// current directory instead.
fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

fn discover_named_rar_family(
    archive: &Path,
    archive_file: DiscoveredFile,
    label: &str,
    options: &DiscoveryOptions,
) -> Result<Vec<DiscoveredFile>, RarparError> {
    let root = parent_directory(archive);
    let mut entries = std::fs::read_dir(root)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.path());

    let mut archive_identity = ArchiveIdentity::new(archive);
    let mut files = Vec::new();
    for entry in entries {
        let file_type = entry.file_type()?;
        if !file_type.is_file() {
            continue;
        }

        let path = entry.path();
        let is_archive = archive_identity.is(&path);
        let is_family_candidate = in_named_family(&path, label);
        if !is_archive && !is_family_candidate {
            continue;
        }
        if files.len() >= options.max_files {
            return Err(RarparError::Resource(format!(
                "discovery exceeded max files ({})",
                options.max_files
            )));
        }

        if is_archive {
            files.push(archive_file.clone());
        } else {
            // Under the archive's spelling of the label, so a volume whose
            // name spells it in another case groups into the archive's set.
            let mut file = classify_path(&path);
            file.set_hint = Some(label.to_owned());
            files.push(file);
        }
    }
    Ok(files)
}

/// Whether `path` names a volume of the family labelled `label`: a RAR
/// volume or `.rev` recovery volume by name whose label is `label` as the
/// filesystem holding it compares names. A label spelled in another case
/// joins when the name respelled with `label` opens the same file, so on a
/// volume that ignores case (macOS and Windows by default) `set.part2.rar`
/// is a volume of the family `SET.part1.rar` names, and on one that does not
/// `SET.*` and `set.*` stay two families.
fn in_named_family(path: &Path, label: &str) -> bool {
    in_named_family_with(path, label, same_file_on_disk)
}

/// [`in_named_family`] with `same_file` deciding whether two names open one
/// file, so tests can stand in for either kind of filesystem.
fn in_named_family_with(
    path: &Path,
    label: &str,
    same_file: impl Fn(&Path, &Path) -> bool,
) -> bool {
    if !(looks_rarish_by_name(path) || is_ext(path, "rev")) {
        return false;
    }
    let Some(hint) = set_hint(path) else {
        return false;
    };
    if hint == label {
        return true;
    }
    if fold_case(&hint) != fold_case(label) {
        return false;
    }
    // The hint is a prefix of the file name, so the respelling keeps the
    // rest of the name exactly.
    let Some(rest) = path
        .file_name()
        .and_then(OsStr::to_str)
        .and_then(|name| name.get(hint.len()..))
    else {
        return false;
    };
    same_file(path, &path.with_file_name(format!("{label}{rest}")))
}

/// Whether both names exist and open one file: the same device and inode on
/// Unix, the same final path elsewhere (which on Windows reports the name as
/// stored, whatever case it was opened in).
#[cfg(unix)]
fn same_file_on_disk(left: &Path, right: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (std::fs::metadata(left), std::fs::metadata(right)) {
        (Ok(left), Ok(right)) => left.dev() == right.dev() && left.ino() == right.ino(),
        _ => false,
    }
}

#[cfg(not(unix))]
fn same_file_on_disk(left: &Path, right: &Path) -> bool {
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

/// [`Path::canonicalize`], counted per thread under test so RAR set
/// discovery's path resolutions can be asserted.
fn real_path(path: &Path) -> std::io::Result<PathBuf> {
    #[cfg(test)]
    REAL_PATH_CALLS.with(|calls| calls.set(calls.get() + 1));
    path.canonicalize()
}

#[cfg(test)]
thread_local! {
    static REAL_PATH_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Whether a regular file listed in the archive's own directory is the archive,
/// as [`same_path`] decides, without resolving every entry's real path.
///
/// Such an entry is not a link (the listing's type does not follow one), so
/// its real path ends in its own name. It can be the archive only when that
/// name is the archive's real name, so only an entry whose name could be that
/// one is resolved, and the archive itself is resolved at most once. The
/// names are compared without case because a case-insensitive filesystem
/// accepts the archive in a spelling the listing does not use.
struct ArchiveIdentity<'a> {
    archive: &'a Path,
    is_link: bool,
    resolved: Option<Option<PathBuf>>,
}

impl<'a> ArchiveIdentity<'a> {
    fn new(archive: &'a Path) -> Self {
        // A link archive's real name is its target's, which only resolving it
        // tells; any other archive's real name is its own up to case.
        let is_link = std::fs::symlink_metadata(archive)
            .map(|metadata| metadata.file_type().is_symlink())
            .unwrap_or(true);
        Self {
            archive,
            is_link,
            resolved: None,
        }
    }

    fn resolved(&mut self) -> Option<&Path> {
        self.resolved
            .get_or_insert_with(|| real_path(self.archive).ok())
            .as_deref()
    }

    fn is(&mut self, entry: &Path) -> bool {
        if entry == self.archive {
            return true;
        }
        let names_match = |candidate: Option<&Path>| {
            candidate
                .and_then(Path::file_name)
                .zip(entry.file_name())
                .is_some_and(|(left, right)| {
                    left.to_string_lossy()
                        .eq_ignore_ascii_case(&right.to_string_lossy())
                })
        };
        let candidate = if self.is_link {
            names_match(self.resolved())
        } else {
            names_match(Some(self.archive))
        };
        if !candidate {
            return false;
        }
        let Ok(entry) = real_path(entry) else {
            return false;
        };
        self.resolved() == Some(entry.as_path())
    }
}

fn selected_rar_set(files: Vec<DiscoveredFile>, archive: &Path) -> Result<RarSet, RarparError> {
    selected_rar_set_from_sets(build_rar_sets(&files), archive)
}

fn selected_rar_set_from_sets(sets: Vec<RarSet>, archive: &Path) -> Result<RarSet, RarparError> {
    // Discovery lists the archive under the spelling it was given, so a
    // textual match finds it without resolving any path; only a set reached
    // some other way resolves the archive, once, against each volume.
    let position = sets
        .iter()
        .position(|set| set.volumes.iter().any(|volume| volume.path == archive))
        .or_else(|| {
            let archive = real_path(archive).ok()?;
            sets.iter().position(|set| {
                set.volumes
                    .iter()
                    .any(|volume| real_path(&volume.path).ok().as_ref() == Some(&archive))
            })
        });
    position
        .and_then(|index| sets.into_iter().nth(index))
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
    visited: &mut BTreeSet<PathBuf>,
    reuse: &Par2Reuse,
) -> Result<(), RarparError> {
    if !visited.insert(path.canonicalize()?) {
        return Ok(());
    }
    if *scan_count >= options.max_files {
        return Err(RarparError::Resource(format!(
            "discovery exceeded max files ({})",
            options.max_files
        )));
    }

    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.is_file() {
        *scan_count += 1;
        files.push(reuse.file(path).unwrap_or_else(|| classify_path(path)));
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
            if !visited.insert(entry_path.canonicalize()?) {
                continue;
            }
            *scan_count += 1;
            if *scan_count > options.max_files {
                return Err(RarparError::Resource(format!(
                    "discovery exceeded max files ({})",
                    options.max_files
                )));
            }
            files.push(
                reuse
                    .file(&entry_path)
                    .unwrap_or_else(|| classify_path(&entry_path)),
            );
        } else if options.recursive && file_type.is_dir() {
            collect_path(
                &entry_path,
                options,
                depth + 1,
                scan_count,
                files,
                visited,
                reuse,
            )?;
        }
    }
    Ok(())
}

fn classify_path(path: &Path) -> DiscoveredFile {
    let mut diagnostics = Vec::new();
    let prefix = read_prefix(path, 16).unwrap_or_default();

    if crate::par3::is_carrier(path) || prefix.starts_with(par3_rs::MAGIC) {
        return DiscoveredFile {
            path: path.to_path_buf(),
            kind: DiscoveredKind::Par3,
            set_hint: set_hint(path),
            diagnostics,
            settled: None,
        };
    }

    if looks_like_par2(path, &prefix) {
        let (scanned, settled) =
            settled_scan(path, || par2_rs::scan_packets_from_path_with_set_ids(path));
        match scanned {
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
                    settled,
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
                    settled: None,
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
                    settled: None,
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
            settled: None,
        };
    }

    if looks_like_rar(path, &prefix) {
        match File::open(path)
            .and_then(|mut file| unrar_rs::probe_volume(&mut file).map_err(std::io::Error::other))
        {
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
                    settled: None,
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
        settled: None,
    }
}

fn build_par2_sets(files: &[DiscoveredFile], reuse: &Par2Reuse) -> Vec<Par2Set> {
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
            if let Some(previous) = reuse.set(&paths) {
                return Par2Set {
                    id,
                    base_dir,
                    paths,
                    protected_files: previous.protected_files.clone(),
                    loaded: previous.loaded.clone(),
                };
            }
            let (set, settled) =
                settled_scan_all(&paths, || par2_rs::Par2FileSet::from_paths(&paths).ok());
            let protected_files = set
                .as_ref()
                .map(|set| {
                    set.files
                        .values()
                        .map(|desc| desc.filename.clone())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let loaded = set
                .zip(settled)
                .map(|(set, fingerprints)| Arc::new(LoadedPar2Set { set, fingerprints }));
            Par2Set {
                id,
                base_dir,
                paths,
                protected_files,
                loaded,
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
            base_dir: parent_directory(&file.path).to_path_buf(),
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

/// Read at most `len` bytes from the start of `path` for a format check.
///
/// The read is advised as random access, so it pulls in no read-ahead: a
/// cached prefix beyond the bytes asked for makes a later sequential read of
/// the file over NFS split each large request in two.
pub(crate) fn read_prefix(path: &Path, len: usize) -> std::io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    no_read_ahead(&file);
    let mut buf = vec![0u8; len];
    // A short `read` is not EOF; an under-filled prefix would make
    // magic-number checks miss real PAR2 files.
    let mut filled = 0;
    while filled < len {
        let read = file.read(&mut buf[filled..])?;
        if read == 0 {
            break;
        }
        filled += read;
    }
    buf.truncate(filled);
    Ok(buf)
}

/// Turn off read-ahead for `file`. Advice only: a refusal changes nothing
/// but the cache.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn no_read_ahead(file: &File) {
    use std::os::fd::AsRawFd;
    // SAFETY: the descriptor is open for the call; the advice reads no memory.
    unsafe {
        libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_RANDOM);
    }
}

/// Turn off read-ahead for `file`. Advice only: a refusal changes nothing
/// but the cache.
#[cfg(target_os = "macos")]
fn no_read_ahead(file: &File) {
    use std::os::fd::AsRawFd;
    // SAFETY: the descriptor is open for the call; F_RDAHEAD takes an int.
    unsafe {
        libc::fcntl(file.as_raw_fd(), libc::F_RDAHEAD, 0);
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
fn no_read_ahead(_file: &File) {}

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
    is_ext(path, "rar") || old_rar_volume_index(path).is_some()
}

fn old_rar_volume_index(path: &Path) -> Option<usize> {
    let ext = path.extension()?.to_string_lossy().to_ascii_lowercase();
    let bytes = ext.as_bytes();
    if bytes.len() != 3 {
        return None;
    }

    if bytes.iter().all(u8::is_ascii_digit) {
        let number = usize::from(bytes[0] - b'0') * 100
            + usize::from(bytes[1] - b'0') * 10
            + usize::from(bytes[2] - b'0');
        return number.checked_sub(1);
    }
    if !bytes[1].is_ascii_digit() || !bytes[2].is_ascii_digit() {
        return None;
    }

    let prefix = bytes[0];
    let number = usize::from(bytes[1] - b'0') * 10 + usize::from(bytes[2] - b'0');
    if (b'a'..b'r').contains(&prefix) {
        return Some(999 + usize::from(prefix - b'a') * 100 + number);
    }
    if !(b'r'..=b'z').contains(&prefix) {
        return None;
    }
    Some(usize::from(prefix - b'r') * 100 + number + 1)
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
    if let Some(index) = old_rar_volume_index(path) {
        return index;
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
    parent_directory(path).display().to_string()
}

fn common_base_dir(paths: &[PathBuf]) -> PathBuf {
    paths
        .first()
        .map_or(Path::new("."), |path| parent_directory(path))
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

pub(crate) fn same_path(left: &Path, right: &Path) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn rar4_fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../crates/unrar-rs/tests/fixtures/rar4")
            .join(name)
    }

    /// Existence is the wrong guard under partial Git LFS hydration: the
    /// no-fixture CI lane checks these fixtures out as pointer files, which
    /// exist and then fail to parse, so discovery reports a resource error
    /// instead of a volume set. A hydrated archive starts with `Rar!`; a
    /// pointer starts with `version https://git-lfs…`.
    fn fixture_is_hydrated(path: &Path) -> bool {
        std::fs::read(path)
            .ok()
            .is_some_and(|bytes| bytes.starts_with(b"Rar!"))
    }

    fn rar4_fixtures_hydrated(names: &[&str]) -> bool {
        names
            .iter()
            .all(|name| fixture_is_hydrated(&rar4_fixture(name)))
    }

    fn real_path_calls() -> usize {
        REAL_PATH_CALLS.with(std::cell::Cell::get)
    }

    /// Finding the named archive's volume family compared every regular file
    /// in the directory with the archive by resolving both real paths, so a
    /// directory of 13 files resolved the archive 13 times and each other file
    /// once, unrelated files included. The archive as listed is now matched by
    /// its spelling, and only an entry that could carry the archive's real
    /// name is resolved: none here, and for an archive named through a link,
    /// the link once and its target once.
    #[test]
    fn rar_family_discovery_resolves_only_what_could_be_the_archive() {
        let temp = tempfile::tempdir().unwrap();
        for name in [
            "glade.part1.rar",
            "glade.part2.rar",
            "glade.part3.rar",
            "notes-1.txt",
            "notes-2.txt",
            "notes-3.txt",
            "unrelated.part1.rar",
        ] {
            std::fs::write(temp.path().join(name), b"Rar!\x1a\x07\x01\x00").unwrap();
        }
        let options = DiscoveryOptions {
            working_dir: None,
            recursive: false,
            max_depth: 1,
            max_files: 100,
            par3_memory_mib: 256,
            par3_workers: None,
            par3_max_lost_blocks: 4096,
        };
        let names = |files: &[DiscoveredFile]| {
            let mut names: Vec<String> = files
                .iter()
                .map(|file| {
                    file.path
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .into_owned()
                })
                .collect();
            names.sort();
            names
        };

        let archive = temp.path().join("glade.part1.rar");
        let before = real_path_calls();
        let files = discover_named_rar_family(&archive, classify_path(&archive), "glade", &options)
            .unwrap();
        assert_eq!(real_path_calls() - before, 0);
        assert_eq!(
            names(&files),
            ["glade.part1.rar", "glade.part2.rar", "glade.part3.rar"]
        );

        #[cfg(unix)]
        {
            let alias = temp.path().join("alias.part1.rar");
            std::os::unix::fs::symlink(&archive, &alias).unwrap();
            let before = real_path_calls();
            let files = discover_named_rar_family(&alias, classify_path(&alias), "glade", &options)
                .unwrap();
            assert_eq!(real_path_calls() - before, 2);
            // The link's target is the archive, so it is listed once, as the
            // archive the caller named.
            let archive_entries: Vec<_> = files.iter().filter(|file| file.path == alias).collect();
            assert_eq!(archive_entries.len(), 1);
            assert_eq!(
                names(&files),
                ["alias.part1.rar", "glade.part2.rar", "glade.part3.rar"]
            );
        }
    }

    /// A volume joins the family the caller named when its label is the
    /// caller's exactly, or in another case when the filesystem opens the
    /// respelled name as the same file: `rar list SET.part1.rar` reaches
    /// `set.part2.rar` where names ignore case, and where they do not, a
    /// `set.*` family stays apart from `SET.*`. The probe stands in for
    /// both kinds of filesystem.
    #[test]
    fn a_named_family_compares_labels_as_the_filesystem_compares_names() {
        let probed = std::cell::RefCell::new(Vec::new());
        for folds in [true, false] {
            let probe = |left: &Path, right: &Path| {
                probed
                    .borrow_mut()
                    .push((left.to_path_buf(), right.to_path_buf()));
                folds
            };
            for (name, label, member) in [
                ("set.part2.rar", "set", true),
                ("set.part2.rar", "SET", folds),
                ("Set.R00", "sET", folds),
                ("SET.part1.rev", "set", folds),
                ("\u{e9}t\u{e9}.part2.rar", "\u{c9}T\u{c9}", folds),
                ("sets.part2.rar", "set", false),
                ("set.par2", "set", false),
            ] {
                let path = Path::new("dir").join(name);
                assert_eq!(
                    in_named_family_with(&path, label, probe),
                    member,
                    "{name} in {label}, folding {folds}"
                );
            }
        }
        // Only a name differing from the label by case is probed, under the
        // label's spelling.
        let probed = probed.into_inner();
        assert_eq!(probed.len(), 8);
        assert_eq!(
            probed[0],
            (
                Path::new("dir").join("set.part2.rar"),
                Path::new("dir").join("SET.part2.rar")
            )
        );
        assert_eq!(probed[1].1, Path::new("dir").join("sET.R00"));
    }

    /// The real probe on this machine's temporary directory: a sibling in
    /// another case joins exactly when the filesystem opens its respelling
    /// as the same file, and two files whose names differ only by case,
    /// possible only where names keep case apart, never merge.
    #[test]
    fn the_family_probe_follows_the_temporary_filesystem() {
        let temp = tempfile::tempdir().unwrap();
        let lower = temp.path().join("set.part2.rar");
        std::fs::write(&lower, b"lower").unwrap();
        let upper = temp.path().join("SET.part2.rar");
        let folds = std::fs::metadata(&upper).is_ok();
        assert_eq!(in_named_family(&lower, "SET"), folds);
        if !folds {
            std::fs::write(&upper, b"upper").unwrap();
            assert!(!in_named_family(&lower, "SET"));
            assert!(!in_named_family(&upper, "set"));
        }
        assert!(!in_named_family(&temp.path().join("set.part3.rar"), "SET"));
    }

    #[test]
    fn fixture_hydration_guard_separates_archives_from_lfs_pointers() {
        let temp = tempfile::tempdir().unwrap();

        let archive = temp.path().join("hydrated.rar");
        std::fs::write(&archive, b"Rar!\x1a\x07\x00").unwrap();
        assert!(fixture_is_hydrated(&archive));

        // Byte for byte what Git leaves behind under GIT_LFS_SKIP_SMUDGE=1.
        let pointer = temp.path().join("pointer.rar");
        std::fs::write(
            &pointer,
            b"version https://git-lfs.github.com/spec/v1\noid sha256:0\nsize 0\n",
        )
        .unwrap();
        assert!(!fixture_is_hydrated(&pointer));

        assert!(!fixture_is_hydrated(&temp.path().join("absent.rar")));
    }

    #[test]
    fn old_rar_volume_rollover_is_recognized_and_sorted() {
        for (name, index) in [
            ("movie.r00", 1),
            ("movie.r99", 100),
            ("movie.s00", 101),
            ("movie.z99", 900),
            ("movie.001", 0),
            ("movie.999", 998),
            ("movie.a00", 999),
        ] {
            let path = Path::new(name);
            assert!(looks_rarish_by_name(path), "{name}");
            assert_eq!(filename_volume_index(path), index, "{name}");
        }
    }

    #[test]
    fn explicit_single_volume_does_not_scan_unrelated_siblings() {
        if !rar4_fixtures_hydrated(&["rar4_store.rar"]) {
            eprintln!("skipping test: rar4_store.rar fixture not hydrated");
            return;
        }

        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("selected.rar");
        std::fs::copy(rar4_fixture("rar4_store.rar"), &archive).unwrap();
        std::fs::write(temp.path().join("unrelated.bin"), b"not an archive").unwrap();

        let set = discover_rar_set_for_archive(
            &archive,
            &DiscoveryOptions {
                recursive: true,
                max_depth: 8,
                max_files: 1,
                working_dir: None,
                par3_memory_mib: 256,
                par3_workers: None,
                par3_max_lost_blocks: 4096,
            },
        )
        .unwrap();

        assert_eq!(set.volumes.len(), 1);
        assert!(same_path(&set.volumes[0].path, &archive));
    }

    #[test]
    fn explicit_multi_volume_probes_only_name_compatible_siblings() {
        let volume_names: Vec<String> = (1..=5)
            .map(|part| format!("rar4_tiny_volumes.part{part}.rar"))
            .collect();
        let required: Vec<&str> = volume_names
            .iter()
            .map(String::as_str)
            .chain(std::iter::once("rar4_store.rar"))
            .collect();
        if !rar4_fixtures_hydrated(&required) {
            eprintln!("skipping test: rar4_tiny_volumes fixtures not hydrated");
            return;
        }

        let temp = tempfile::tempdir().unwrap();
        for name in &volume_names {
            std::fs::copy(rar4_fixture(name), temp.path().join(name)).unwrap();
        }
        for index in 0..8 {
            std::fs::copy(
                rar4_fixture("rar4_store.rar"),
                temp.path().join(format!("unrelated{index}.rar")),
            )
            .unwrap();
        }

        let first = temp.path().join("rar4_tiny_volumes.part1.rar");
        let set = discover_rar_set_for_archive(
            &first,
            &DiscoveryOptions {
                recursive: true,
                max_depth: 8,
                max_files: 5,
                working_dir: None,
                par3_memory_mib: 256,
                par3_workers: None,
                par3_max_lost_blocks: 4096,
            },
        )
        .unwrap();

        assert_eq!(set.volumes.len(), 5);
        assert!(set.volumes.iter().all(|volume| {
            volume
                .path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("rar4_tiny_volumes.part")
        }));
    }

    /// A small PAR2 set in `dir`, every file last modified `age` ago.
    fn par2_set_aged(dir: &Path, age: Duration) -> Vec<PathBuf> {
        let mut sources = Vec::new();
        for (index, name) in ["ledger.a.bin", "ledger.b.bin"].into_iter().enumerate() {
            let path = dir.join(name);
            std::fs::write(&path, vec![0x41 + index as u8; 3_000]).unwrap();
            sources.push(path);
        }
        let mut options = par2_rs::Par2CreatorOptions::with_output(
            dir.join("ledger.par2"),
            Some(dir.to_path_buf()),
            sources.clone(),
        );
        options.block_sizing = par2_rs::BlockSizing::Bytes(512);
        options.recovery_amount = par2_rs::RecoveryAmount::Count(4);
        let creator = par2_rs::Par2Creator::new(options);
        let plan = creator.plan().unwrap();
        let outcome = creator.create(&plan).unwrap();
        let mut volumes = vec![outcome.main_path.clone()];
        volumes.extend(outcome.volume_paths.iter().cloned());
        for path in sources.iter().chain(&volumes) {
            age_file(path, age);
        }
        volumes.sort();
        volumes
    }

    fn age_file(path: &Path, age: Duration) {
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(SystemTime::now() - age)
            .unwrap();
    }

    fn flat_options() -> DiscoveryOptions {
        DiscoveryOptions {
            working_dir: None,
            recursive: false,
            max_depth: 1,
            max_files: 100,
            par3_memory_mib: 256,
            par3_workers: None,
            par3_max_lost_blocks: 4096,
        }
    }

    /// Rediscovery after an action took every PAR2 volume through a full
    /// packet scan twice more: once to classify it, once to load its set.
    /// Volumes whose stat is unchanged now keep the earlier classification and
    /// set, so a rediscovery reads none of them: here they are unreadable by
    /// then, and it still reports the same set.
    #[cfg(unix)]
    #[test]
    fn rediscovery_does_not_read_unchanged_par2_volumes_again() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let volumes = par2_set_aged(&root, Duration::from_secs(60));
        let options = flat_options();
        let mut first = discover(vec![root.clone()], &options).unwrap();
        assert_eq!(first.par2_sets.len(), 1);
        assert_eq!(first.par2_sets[0].paths, volumes);
        let loaded = first.par2_sets[0]
            .loaded
            .clone()
            .expect("a settled set is kept");
        assert!(first.par2_sets[0].reusable_packets().is_some());
        let classified: Vec<_> = first.files.iter().map(|file| file.kind.clone()).collect();

        for volume in &volumes {
            std::fs::set_permissions(volume, std::fs::Permissions::from_mode(0o000)).unwrap();
        }
        if std::fs::File::open(&volumes[0]).is_ok() {
            return;
        }
        let second = rediscover(vec![root.clone()], &options, &mut first).unwrap();
        for volume in &volumes {
            std::fs::set_permissions(volume, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        assert_eq!(
            second
                .files
                .iter()
                .map(|file| file.kind.clone())
                .collect::<Vec<_>>(),
            classified
        );
        assert_eq!(second.par2_sets.len(), 1);
        assert!(Arc::ptr_eq(
            second.par2_sets[0].loaded.as_ref().unwrap(),
            &loaded
        ));
        assert_eq!(
            second.par2_sets[0].protected_files,
            first.par2_sets[0].protected_files
        );
    }

    /// A volume whose stat changed is read again, and a volume written too
    /// recently for its stat to vouch for its bytes is never reused.
    #[test]
    fn rediscovery_reads_a_changed_or_fresh_par2_volume_again() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let volumes = par2_set_aged(&root, Duration::from_secs(60));
        let options = flat_options();
        let mut first = discover(vec![root.clone()], &options).unwrap();
        let loaded = first.par2_sets[0]
            .loaded
            .clone()
            .expect("a settled set is kept");

        age_file(&volumes[1], Duration::from_secs(30));
        assert!(first.par2_sets[0].reusable_packets().is_none());
        let mut second = rediscover(vec![root.clone()], &options, &mut first).unwrap();
        let reloaded = second.par2_sets[0].loaded.clone().expect("still settled");
        assert!(!Arc::ptr_eq(&reloaded, &loaded));
        assert!(second.par2_sets[0].reusable_packets().is_some());

        age_file(&volumes[1], Duration::ZERO);
        let third = rediscover(vec![root.clone()], &options, &mut second).unwrap();
        assert_eq!(third.par2_sets.len(), 1);
        assert!(third.par2_sets[0].loaded.is_none());
        assert!(third.par2_sets[0].reusable_packets().is_none());
        assert!(!third.par2_sets[0].protected_files.is_empty());
        let fresh = third
            .files
            .iter()
            .find(|file| file.path == volumes[1])
            .unwrap();
        assert!(fresh.settled.is_none());
    }
}
