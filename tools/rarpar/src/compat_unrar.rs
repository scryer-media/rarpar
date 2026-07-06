use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::discovery::{self, DiscoveryOptions, RarSet};

const EXIT_SUCCESS: u8 = 0;
const EXIT_FATAL: u8 = 2;
const EXIT_CHECKSUM: u8 = 3;
const EXIT_WRITE: u8 = 5;
const EXIT_OPEN: u8 = 6;
const EXIT_COMMAND_LINE: u8 = 7;
const EXIT_CREATE: u8 = 9;
const EXIT_NO_FILES: u8 = 10;
const EXIT_WRONG_PASSWORD: u8 = 11;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    ExtractFull,
    ExtractFlat,
    Test,
    List,
    ListBare,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OverwriteMode {
    Overwrite,
    Skip,
    AutoRename,
}

#[derive(Debug, Clone)]
enum PasswordMode {
    Auto,
    Disabled,
    Candidate(String),
}

#[derive(Debug, Clone)]
struct Invocation {
    action: Action,
    overwrite: OverwriteMode,
    incremental: bool,
    password: PasswordMode,
    archive_specs: Vec<PathBuf>,
    output_dir: PathBuf,
}

#[derive(Debug)]
struct CompatFailure {
    code: u8,
    message: String,
    stderr: bool,
}

impl CompatFailure {
    fn stdout(code: u8, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            stderr: false,
        }
    }

    fn stderr(code: u8, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            stderr: true,
        }
    }

    fn emit(&self) {
        if self.stderr {
            eprintln!("{}", self.message);
        } else {
            println!("{}", self.message);
        }
    }
}

pub fn dispatch(args: &[OsString]) -> Option<u8> {
    let invocation = match Invocation::parse(args) {
        Ok(Some(invocation)) => invocation,
        Ok(None) => return None,
        Err(error) => {
            error.emit();
            return Some(error.code);
        }
    };

    match run(invocation) {
        Ok(()) => Some(EXIT_SUCCESS),
        Err(error) => {
            error.emit();
            Some(error.code)
        }
    }
}

impl Invocation {
    fn parse(args: &[OsString]) -> Result<Option<Self>, CompatFailure> {
        let Some(command) = args.first().and_then(|arg| arg.to_str()) else {
            return Ok(None);
        };
        let action = match command.to_ascii_lowercase().as_str() {
            "x" => Action::ExtractFull,
            "e" => Action::ExtractFlat,
            "t" => Action::Test,
            "l" => Action::List,
            "lb" => Action::ListBare,
            command if is_unsupported_unrar_command(command) => {
                return Err(CompatFailure::stderr(
                    EXIT_COMMAND_LINE,
                    format!("Unsupported command: {command}"),
                ));
            }
            _ => return Ok(None),
        };

        let mut overwrite = OverwriteMode::Overwrite;
        let mut incremental = false;
        let mut password = PasswordMode::Auto;
        let mut positional = Vec::new();

        for arg in args.iter().skip(1) {
            let text = arg.to_string_lossy();
            if text.starts_with('-') && text.len() > 1 {
                parse_switch(&text, &mut overwrite, &mut incremental, &mut password)?;
            } else {
                positional.push(PathBuf::from(arg));
            }
        }

        if positional.is_empty() {
            return Err(CompatFailure::stderr(
                EXIT_COMMAND_LINE,
                "No archive specified",
            ));
        }

        let output_dir = if matches!(action, Action::ExtractFull | Action::ExtractFlat) {
            if positional.len() >= 2 {
                positional.pop().unwrap_or_else(|| PathBuf::from("."))
            } else {
                PathBuf::from(".")
            }
        } else {
            PathBuf::from(".")
        };

        Ok(Some(Self {
            action,
            overwrite,
            incremental,
            password,
            archive_specs: positional,
            output_dir,
        }))
    }
}

fn parse_switch(
    switch: &str,
    overwrite: &mut OverwriteMode,
    incremental: &mut bool,
    password: &mut PasswordMode,
) -> Result<(), CompatFailure> {
    let lower = switch.to_ascii_lowercase();
    match lower.as_str() {
        "-y" | "-ai" | "-idp" | "-scf" | "-tsm-" | "-mlp" | "-om" | "-om1" | "-om-" => {}
        "-vp" => *incremental = true,
        "-o+" => *overwrite = OverwriteMode::Overwrite,
        "-o-" => *overwrite = OverwriteMode::Skip,
        "-or" => *overwrite = OverwriteMode::AutoRename,
        "-p-" => *password = PasswordMode::Disabled,
        "-p" => *password = PasswordMode::Auto,
        _ if lower.starts_with("-p") => {
            *password = PasswordMode::Candidate(switch[2..].to_string());
        }
        _ if lower.starts_with("-om=")
            || lower.starts_with("-om1=")
            || lower.starts_with("-om-=")
            || is_ri_switch(&lower) => {}
        _ => {
            return Err(CompatFailure::stderr(
                EXIT_COMMAND_LINE,
                format!("Unknown option: {switch}"),
            ));
        }
    }
    Ok(())
}

fn is_ri_switch(switch: &str) -> bool {
    let Some(rest) = switch.strip_prefix("-ri") else {
        return false;
    };
    let (priority, sleep) = rest.split_once(':').unwrap_or((rest, ""));
    if priority.is_empty() || priority.len() > 2 {
        return false;
    }
    let Ok(priority) = priority.parse::<u8>() else {
        return false;
    };
    if priority > 15 {
        return false;
    }
    sleep.is_empty() || sleep.parse::<u16>().is_ok_and(|value| value <= 1000)
}

fn is_unsupported_unrar_command(command: &str) -> bool {
    matches!(
        command,
        "a" | "c"
            | "cf"
            | "ch"
            | "cw"
            | "d"
            | "f"
            | "i"
            | "k"
            | "m"
            | "r"
            | "rc"
            | "rn"
            | "rr"
            | "rv"
            | "s"
            | "u"
            | "v"
    )
}

fn run(invocation: Invocation) -> Result<(), CompatFailure> {
    match invocation.action {
        Action::ExtractFull | Action::ExtractFlat => run_extract(&invocation),
        Action::Test => run_test(&invocation),
        Action::List | Action::ListBare => run_list(&invocation),
    }
}

fn run_extract(invocation: &Invocation) -> Result<(), CompatFailure> {
    let sets = resolve_sets(&invocation.archive_specs)?;
    if sets.is_empty() {
        return Err(CompatFailure::stdout(EXIT_NO_FILES, "No files to extract"));
    }

    std::fs::create_dir_all(&invocation.output_dir).map_err(|error| {
        CompatFailure::stdout(
            EXIT_CREATE,
            format!("Cannot create {}: {error}", invocation.output_dir.display()),
        )
    })?;

    for set in sets {
        if invocation.incremental {
            run_incremental_extract(invocation, &set)?;
        } else {
            let password = password_candidate(&invocation.password);
            let mut archive = open_set(&set, password.as_deref())?;
            for path in ordered_volume_paths(&set) {
                println!("Extracting from {}", path.display());
            }
            let mut extracted = BTreeSet::new();
            extract_all_ready(invocation, &mut archive, &mut extracted)?;
            ensure_all_members_done(&archive, &extracted)?;
            println!("All OK");
        }
    }
    Ok(())
}

fn run_incremental_extract(invocation: &Invocation, set: &RarSet) -> Result<(), CompatFailure> {
    let paths = ordered_volume_paths(set);
    let Some(first_path) = paths.first() else {
        return Err(CompatFailure::stdout(EXIT_NO_FILES, "No files to extract"));
    };

    let password = password_candidate(&invocation.password);
    let mut archive = open_first_volume(first_path, password.as_deref())?;
    println!("Extracting from {}", first_path.display());

    let mut extracted = BTreeSet::new();
    loop {
        extract_all_ready(invocation, &mut archive, &mut extracted)?;
        if all_members_done(&archive, &extracted) && !archive.more_volumes() {
            break;
        }
        if !archive.more_volumes() {
            return Err(missing_volume_failure(&archive));
        }

        let next_index = archive
            .present_volumes()
            .into_iter()
            .max()
            .map_or(1, |volume| volume + 1);
        let next_path = next_volume_path(first_path, next_index);
        print!(
            "Insert disk with {} [C]ontinue, [Q]uit ",
            next_path.display()
        );
        io::stdout()
            .flush()
            .map_err(|error| CompatFailure::stdout(EXIT_WRITE, format!("Write error: {error}")))?;

        let mut answer = String::new();
        io::stdin()
            .read_line(&mut answer)
            .map_err(|error| CompatFailure::stdout(EXIT_FATAL, format!("Read error: {error}")))?;
        println!();
        if answer.trim_start().starts_with(['q', 'Q']) {
            return Err(CompatFailure::stdout(EXIT_FATAL, "User break"));
        }

        let reader = File::open(&next_path).map_err(|_| {
            CompatFailure::stdout(
                EXIT_FATAL,
                format!("Cannot find volume {}", next_path.display()),
            )
        })?;
        archive
            .add_volume(
                next_index,
                Box::new(reader) as Box<dyn weaver_unrar::ReadSeek>,
            )
            .map_err(map_rar_error)?;
        if !archive.has_volume(next_index) {
            return Err(CompatFailure::stdout(
                EXIT_FATAL,
                format!("Cannot find volume {}", next_path.display()),
            ));
        }
        println!("Extracting from {}", next_path.display());
    }

    println!("All OK");
    Ok(())
}

fn run_test(invocation: &Invocation) -> Result<(), CompatFailure> {
    let sets = resolve_sets(&invocation.archive_specs)?;
    if sets.is_empty() {
        return Err(CompatFailure::stdout(EXIT_NO_FILES, "No files to test"));
    }
    let temp = tempfile::tempdir()
        .map_err(|error| CompatFailure::stdout(EXIT_CREATE, format!("Cannot create: {error}")))?;
    let test_invocation = Invocation {
        output_dir: temp.path().to_path_buf(),
        incremental: false,
        ..invocation.clone()
    };

    for set in sets {
        let password = password_candidate(&test_invocation.password);
        let mut archive = open_set(&set, password.as_deref())?;
        for path in ordered_volume_paths(&set) {
            println!("Testing from {}", path.display());
        }
        let mut extracted = BTreeSet::new();
        extract_all_ready(&test_invocation, &mut archive, &mut extracted)?;
        ensure_all_members_done(&archive, &extracted)?;
    }
    println!("All OK");
    Ok(())
}

fn run_list(invocation: &Invocation) -> Result<(), CompatFailure> {
    let sets = resolve_sets(&invocation.archive_specs)?;
    if sets.is_empty() {
        return Err(CompatFailure::stdout(EXIT_NO_FILES, "No files to list"));
    }

    for set in sets {
        let password = password_candidate(&invocation.password);
        let archive = open_set(&set, password.as_deref())?;
        for member in archive.indexed_member_infos() {
            println!("{}", member.info.name);
        }
    }
    Ok(())
}

fn extract_all_ready(
    invocation: &Invocation,
    archive: &mut weaver_unrar::RarArchive,
    extracted: &mut BTreeSet<usize>,
) -> Result<(), CompatFailure> {
    let members = archive.indexed_member_infos();
    if members.is_empty() {
        return Err(CompatFailure::stdout(EXIT_NO_FILES, "No files to extract"));
    }

    let password = password_candidate(&invocation.password);
    let options = weaver_unrar::ExtractOptions {
        verify: true,
        password,
        restore_owners: false,
    };

    for member in members {
        if extracted.contains(&member.index) {
            continue;
        }
        if !member.extractable {
            break;
        }
        let out_path = member_output_path(invocation, &member.info);
        let out_path = prepare_output_path(&out_path, &member.info, invocation.overwrite)?;
        if let Some(out_path) = out_path {
            archive
                .extract_member_to_file(member.index, &options, None, &out_path)
                .map_err(map_rar_error)?;
            print_member_ok(&member.info, &out_path);
        }
        extracted.insert(member.index);
    }
    Ok(())
}

fn prepare_output_path(
    out_path: &Path,
    member: &weaver_unrar::MemberInfo,
    overwrite: OverwriteMode,
) -> Result<Option<PathBuf>, CompatFailure> {
    if member.is_directory {
        if out_path.exists() && !out_path.is_dir() {
            return match overwrite {
                OverwriteMode::Skip => Ok(None),
                OverwriteMode::Overwrite => Err(CompatFailure::stdout(
                    EXIT_CREATE,
                    format!("Cannot create {}", out_path.display()),
                )),
                OverwriteMode::AutoRename => Ok(Some(auto_rename_path(out_path))),
            };
        }
        return Ok(Some(out_path.to_path_buf()));
    }

    if !out_path.exists() {
        return Ok(Some(out_path.to_path_buf()));
    }
    match overwrite {
        OverwriteMode::Overwrite => Ok(Some(out_path.to_path_buf())),
        OverwriteMode::Skip => Ok(None),
        OverwriteMode::AutoRename => Ok(Some(auto_rename_path(out_path))),
    }
}

fn print_member_ok(member: &weaver_unrar::MemberInfo, out_path: &Path) {
    let verb = if member.is_directory {
        "Creating"
    } else {
        "Extracting"
    };
    println!("{verb}  {} OK", out_path.display());
}

fn ensure_all_members_done(
    archive: &weaver_unrar::RarArchive,
    extracted: &BTreeSet<usize>,
) -> Result<(), CompatFailure> {
    if all_members_done(archive, extracted) {
        Ok(())
    } else {
        Err(missing_volume_failure(archive))
    }
}

fn all_members_done(archive: &weaver_unrar::RarArchive, extracted: &BTreeSet<usize>) -> bool {
    archive
        .indexed_member_infos()
        .into_iter()
        .all(|member| extracted.contains(&member.index))
}

fn missing_volume_failure(archive: &weaver_unrar::RarArchive) -> CompatFailure {
    let missing = archive
        .indexed_member_infos()
        .into_iter()
        .flat_map(|member| member.missing_volumes)
        .next()
        .unwrap_or_else(|| {
            archive
                .present_volumes()
                .into_iter()
                .max()
                .map_or(1, |v| v + 1)
        });
    CompatFailure::stdout(EXIT_FATAL, format!("Cannot find volume {missing}"))
}

fn resolve_sets(specs: &[PathBuf]) -> Result<Vec<RarSet>, CompatFailure> {
    let mut sets = BTreeMap::new();
    let paths = expand_archive_specs(specs)?;
    let options = DiscoveryOptions {
        recursive: false,
        max_depth: 1,
        max_files: 20_000,
    };
    for path in paths {
        let set = discovery::discover_rar_set_for_archive(&path, &options).map_err(|error| {
            CompatFailure::stdout(
                EXIT_OPEN,
                format!("Cannot open {}: {error}", path.display()),
            )
        })?;
        sets.entry(set.id.clone()).or_insert(set);
    }
    Ok(sets.into_values().collect())
}

fn expand_archive_specs(specs: &[PathBuf]) -> Result<Vec<PathBuf>, CompatFailure> {
    let mut paths = Vec::new();
    for spec in specs {
        if has_wildcard(spec) {
            let matches = expand_wildcard(spec)?;
            if matches.is_empty() {
                return Err(CompatFailure::stdout(
                    EXIT_OPEN,
                    format!("Cannot open {}", spec.display()),
                ));
            }
            paths.extend(matches);
        } else {
            paths.push(spec.clone());
        }
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}

fn has_wildcard(path: &Path) -> bool {
    path.as_os_str()
        .to_string_lossy()
        .chars()
        .any(|ch| matches!(ch, '*' | '?' | '['))
}

fn expand_wildcard(pattern: &Path) -> Result<Vec<PathBuf>, CompatFailure> {
    let parent = pattern.parent().unwrap_or_else(|| Path::new("."));
    let file_pattern = pattern
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| CompatFailure::stderr(EXIT_COMMAND_LINE, "Invalid archive pattern"))?;
    let mut matches = Vec::new();
    for entry in std::fs::read_dir(parent).map_err(|error| {
        CompatFailure::stdout(
            EXIT_OPEN,
            format!("Cannot open {}: {error}", parent.display()),
        )
    })? {
        let entry = entry.map_err(|error| {
            CompatFailure::stdout(
                EXIT_OPEN,
                format!("Cannot open {}: {error}", parent.display()),
            )
        })?;
        let name = entry.file_name();
        if wildcard_match(file_pattern, &name.to_string_lossy()) {
            matches.push(entry.path());
        }
    }
    matches.sort();
    Ok(matches)
}

fn wildcard_match(pattern: &str, text: &str) -> bool {
    fn inner(pattern: &[u8], text: &[u8]) -> bool {
        if pattern.is_empty() {
            return text.is_empty();
        }
        match pattern[0] {
            b'*' => inner(&pattern[1..], text) || (!text.is_empty() && inner(pattern, &text[1..])),
            b'?' => !text.is_empty() && inner(&pattern[1..], &text[1..]),
            byte => {
                !text.is_empty()
                    && byte.eq_ignore_ascii_case(&text[0])
                    && inner(&pattern[1..], &text[1..])
            }
        }
    }
    inner(pattern.as_bytes(), text.as_bytes())
}

fn ordered_volume_paths(set: &RarSet) -> Vec<PathBuf> {
    let mut volumes = set.volumes.clone();
    volumes.sort_by(|a, b| {
        a.sort_index
            .cmp(&b.sort_index)
            .then_with(|| a.path.cmp(&b.path))
    });
    volumes.into_iter().map(|volume| volume.path).collect()
}

fn open_set(
    set: &RarSet,
    password: Option<&str>,
) -> Result<weaver_unrar::RarArchive, CompatFailure> {
    let paths = ordered_volume_paths(set);
    let Some(first) = paths.first() else {
        return Err(CompatFailure::stdout(EXIT_NO_FILES, "No files to extract"));
    };
    let mut archive = open_first_volume(first, password)?;
    for (index, path) in paths.iter().enumerate().skip(1) {
        let file = File::open(path).map_err(|error| {
            CompatFailure::stdout(
                EXIT_OPEN,
                format!("Cannot open {}: {error}", path.display()),
            )
        })?;
        archive
            .add_volume(index, Box::new(file) as Box<dyn weaver_unrar::ReadSeek>)
            .map_err(map_rar_error)?;
    }
    Ok(archive)
}

fn open_first_volume(
    path: &Path,
    password: Option<&str>,
) -> Result<weaver_unrar::RarArchive, CompatFailure> {
    let file = File::open(path).map_err(|error| {
        CompatFailure::stdout(
            EXIT_OPEN,
            format!("Cannot open {}: {error}", path.display()),
        )
    })?;
    let mut archive = if let Some(password) = password {
        weaver_unrar::RarArchive::open_with_password(file, password).map_err(map_rar_error)?
    } else {
        weaver_unrar::RarArchive::open(file).map_err(map_rar_error)?
    };
    if let Some(password) = password {
        archive.set_password(password.to_string());
    }
    Ok(archive)
}

fn password_candidate(password: &PasswordMode) -> Option<String> {
    match password {
        PasswordMode::Candidate(password) => Some(password.clone()),
        PasswordMode::Auto | PasswordMode::Disabled => None,
    }
}

fn member_output_path(invocation: &Invocation, member: &weaver_unrar::MemberInfo) -> PathBuf {
    if matches!(invocation.action, Action::ExtractFlat) {
        let name = Path::new(&member.name)
            .file_name()
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| OsStr::new(&member.name));
        invocation.output_dir.join(name)
    } else {
        invocation.output_dir.join(&member.name)
    }
}

fn auto_rename_path(path: &Path) -> PathBuf {
    if !path.exists() {
        return path.to_path_buf();
    }
    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    let stem = path.file_stem().and_then(OsStr::to_str).unwrap_or("file");
    let extension = path.extension().and_then(OsStr::to_str);
    for index in 1..10_000 {
        let candidate_name = if let Some(extension) = extension {
            format!("{stem}({index}).{extension}")
        } else {
            format!("{stem}({index})")
        };
        let candidate = parent.join(candidate_name);
        if !candidate.exists() {
            return candidate;
        }
    }
    path.to_path_buf()
}

fn next_volume_path(first_path: &Path, next_index: usize) -> PathBuf {
    let Some(name) = first_path.file_name().and_then(OsStr::to_str) else {
        return first_path.to_path_buf();
    };
    let lower = name.to_ascii_lowercase();
    let next_name = if let Some(part_start) = lower.rfind(".part") {
        if lower.ends_with(".rar") {
            let digits_start = part_start + ".part".len();
            let digits_end = lower.len() - ".rar".len();
            let digits = &name[digits_start..digits_end];
            if !digits.is_empty() && digits.chars().all(|ch| ch.is_ascii_digit()) {
                let width = digits.len();
                let number = next_index + 1;
                let prefix = &name[..digits_start];
                let suffix = &name[digits_end..];
                format!("{prefix}{number:0width$}{suffix}")
            } else {
                old_style_next_name(name, next_index)
            }
        } else {
            old_style_next_name(name, next_index)
        }
    } else {
        old_style_next_name(name, next_index)
    };
    first_path.with_file_name(next_name)
}

fn old_style_next_name(name: &str, next_index: usize) -> String {
    let base = name
        .strip_suffix(".rar")
        .or_else(|| name.strip_suffix(".RAR"))
        .unwrap_or(name);
    let number = next_index.saturating_sub(1);
    format!("{base}.r{number:02}")
}

fn map_rar_error(error: weaver_unrar::RarError) -> CompatFailure {
    match error {
        weaver_unrar::RarError::Io(error) => {
            if error.kind() == io::ErrorKind::AlreadyExists {
                CompatFailure::stdout(EXIT_CREATE, format!("Cannot create: {error}"))
            } else {
                CompatFailure::stdout(EXIT_WRITE, format!("Write error: {error}"))
            }
        }
        weaver_unrar::RarError::InvalidSignature => {
            CompatFailure::stdout(EXIT_CHECKSUM, "is not RAR archive")
        }
        weaver_unrar::RarError::EncryptedArchive
        | weaver_unrar::RarError::EncryptedMember { .. }
        | weaver_unrar::RarError::InvalidPassword
        | weaver_unrar::RarError::WrongPassword { .. } => {
            CompatFailure::stdout(EXIT_WRONG_PASSWORD, "The specified password is incorrect.")
        }
        weaver_unrar::RarError::DataCrcMismatch { member, .. } => {
            CompatFailure::stdout(EXIT_CHECKSUM, format!("{member} - CRC failed"))
        }
        weaver_unrar::RarError::PackedDataCrcMismatch { member, volume, .. } => {
            CompatFailure::stdout(
                EXIT_CHECKSUM,
                format!("{member} : packed data CRC failed in volume {volume}"),
            )
        }
        weaver_unrar::RarError::Blake2Mismatch { member }
        | weaver_unrar::RarError::PackedDataBlake2Mismatch { member, .. } => {
            CompatFailure::stdout(EXIT_CHECKSUM, format!("{member} - checksum failed"))
        }
        weaver_unrar::RarError::MissingVolume { volume, .. } => {
            CompatFailure::stdout(EXIT_FATAL, format!("Cannot find volume {volume}"))
        }
        weaver_unrar::RarError::ResourceLimit { detail } => {
            CompatFailure::stdout(EXIT_FATAL, format!("ERROR: {detail}"))
        }
        error => CompatFailure::stdout(EXIT_FATAL, format!("ERROR: {error}")),
    }
}
