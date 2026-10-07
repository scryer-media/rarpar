//! A 7-Zip-compatible front end over sevenz-turbo, for tools that drive
//! `7z`/`7za`/`7zz` (SABnzbd, NZBGet). It decodes only: `x`, `e`, `t` and
//! `l`, with 7-Zip's switches, messages and exit codes for those commands.

mod censor;
mod extract;
mod format;
mod list;
mod switches;
mod volume;

pub(crate) use format::local_civil_at;

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use censor::{Censor, MarkMode, NameOption, Recursion, has_wildcard, wildcard_match};
use extract::{Ending, HashSums, Overwrite, Setup, Stats};
use format::{archive_method, smart_size};
use switches::{LineError, Parsed, raw_tail};
use volume::{OpenFailure, Opened, VolumeSet, open_archive, volume_set};

const EXIT_OK: u8 = 0;
const EXIT_FATAL: u8 = 2;
const EXIT_USER_ERROR: u8 = 7;
const EXIT_MEMORY: u8 = 8;
const EXIT_BREAK: u8 = 255;

/// Whether the program name is one 7-Zip ships under.
pub(crate) fn invoked_as_7z(program: &OsStr) -> bool {
    let Some(stem) = Path::new(program).file_name().and_then(OsStr::to_str) else {
        return false;
    };
    let lower = stem.to_ascii_lowercase();
    let stem = lower.strip_suffix(".exe").unwrap_or(&lower);
    matches!(stem, "7z" | "7za" | "7zz" | "7zr")
}

/// Run a 7-Zip command line; the arguments follow the program name.
pub(crate) fn dispatch(args: &[OsString]) -> u8 {
    let mut session = Session {
        out_target: 1,
        err_target: 2,
        log_level: 0,
        password: None,
    };
    run(&mut session, args)
}

/// Whether `path` ends in a path separator.
fn ends_with_separator(path: &OsStr) -> bool {
    path.to_string_lossy()
        .ends_with(['/', std::path::MAIN_SEPARATOR])
}

/// `path` split after its last separator: the folder prefix (ending in the
/// separator, or empty) and the file name, each exactly as given.
fn split_folder(path: &OsStr) -> (OsString, OsString) {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let bytes = path.as_bytes();
        match bytes.iter().rposition(|&byte| byte == b'/') {
            Some(at) => (
                OsStr::from_bytes(&bytes[..=at]).to_owned(),
                OsStr::from_bytes(&bytes[at + 1..]).to_owned(),
            ),
            None => (OsString::new(), path.to_owned()),
        }
    }
    #[cfg(not(unix))]
    {
        let text = path.to_string_lossy();
        match text.rfind(['/', std::path::MAIN_SEPARATOR]) {
            Some(at) => (text[..=at].into(), text[at + 1..].into()),
            None => (OsString::new(), path.to_owned()),
        }
    }
}

/// `text` with every `*` replaced by `with`, the rest kept as given.
fn replace_star(text: &OsStr, with: &OsStr) -> OsString {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};
        let mut out = Vec::with_capacity(text.len());
        for &byte in text.as_bytes() {
            if byte == b'*' {
                out.extend_from_slice(with.as_bytes());
            } else {
                out.push(byte);
            }
        }
        OsString::from_vec(out)
    }
    #[cfg(not(unix))]
    {
        text.to_string_lossy()
            .replace('*', &with.to_string_lossy())
            .into()
    }
}

/// `name` without its last `.extension`, as 7-Zip names the `*` folder.
fn strip_extension(name: &OsStr) -> OsString {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let bytes = name.as_bytes();
        match bytes.iter().rposition(|&byte| byte == b'.') {
            Some(dot) if dot > 0 => OsStr::from_bytes(&bytes[..dot]).to_owned(),
            _ => name.to_owned(),
        }
    }
    #[cfg(not(unix))]
    {
        let text = name.to_string_lossy();
        match text.rfind('.') {
            Some(dot) if dot > 0 => text[..dot].into(),
            _ => name.to_owned(),
        }
    }
}

/// Where messages go, and what the user has told us so far.
pub(super) struct Session {
    out_target: u8,
    err_target: u8,
    pub log_level: u32,
    pub password: Option<String>,
}

fn write_to(target: u8, text: &str) {
    match target {
        1 => {
            let mut stdout = io::stdout().lock();
            let _ = stdout.write_all(text.as_bytes());
            let _ = stdout.flush();
        }
        2 => {
            let _ = io::stdout().lock().flush();
            let mut stderr = io::stderr().lock();
            let _ = stderr.write_all(text.as_bytes());
            let _ = stderr.flush();
        }
        _ => {}
    }
}

impl Session {
    pub fn out(&mut self, text: &str) {
        write_to(self.out_target, text);
    }

    pub fn err(&mut self, text: &str) {
        write_to(self.err_target, text);
    }

    /// A line from standard input; `None` at the end of input with nothing
    /// read.
    pub fn read_line(&mut self) -> Option<String> {
        let mut line = String::new();
        match io::stdin().lock().read_line(&mut line) {
            Ok(0) | Err(_) => None,
            Ok(_) => {
                while line.ends_with(['\n', '\r']) {
                    line.pop();
                }
                Some(line)
            }
        }
    }

    /// The password, asked for once when the command line gave none.
    pub fn ask_password(&mut self) -> Option<String> {
        if let Some(password) = &self.password {
            return Some(password.clone());
        }
        let prompt = if cfg!(windows) {
            "\nEnter password (will not be echoed):"
        } else {
            "\nEnter password:"
        };
        // The prompt is shown even when messages are switched off.
        write_to(
            if self.out_target == 0 {
                2
            } else {
                self.out_target
            },
            prompt,
        );
        let line = self.read_line();
        write_to(
            if self.out_target == 0 {
                2
            } else {
                self.out_target
            },
            "\n",
        );
        let line = line?;
        self.password = Some(line.clone());
        Some(line)
    }
}

/// `errno=N : text`, as 7-Zip formats a system error.
pub(super) fn errno_text(error: &io::Error) -> String {
    let text = error.to_string();
    match error.raw_os_error() {
        Some(code) => {
            let suffix = format!(" (os error {code})");
            let text = text.strip_suffix(&suffix).unwrap_or(&text);
            format!("errno={code} : {text}")
        }
        None => text,
    }
}

/// A 7z time (100 ns ticks since 1601) as a file time.
pub(super) fn filetime_of(ticks: u64) -> filetime::FileTime {
    const EPOCH_GAP: i64 = 11_644_473_600;
    let secs = (ticks / 10_000_000) as i64 - EPOCH_GAP;
    let nanos = ((ticks % 10_000_000) * 100) as u32;
    filetime::FileTime::from_unix_time(secs, nanos)
}

fn banner() -> String {
    format!(
        "\nrarpar {} (7-Zip compatible decoder) : Copyright (c) the rarpar authors\n\n",
        env!("CARGO_PKG_VERSION")
    )
}

const HELP: &str = "\
Usage: 7z <command> [<switches>...] <archive_name> [<file_names>...] [@listfile]

<Commands>
  e : Extract files from archive (without using directory names)
  l : List contents of archive
  t : Test integrity of archive
  x : eXtract files with full paths

<Switches>
  -- : Stop switches and @listfile parsing
  -ai[r[-|0]][m[-|2]][w[-]]{@listfile|!wildcard} : Include archives
  -ao{a|s|t|u} : set Overwrite mode
  -an : disable archive_name field
  -bb[0-3] : set output log level
  -bd : disable progress indicator
  -bs{o|e|p}{0|1|2} : set output stream for output/error/progress line
  -i[r[-|0]][m[-|2]][w[-]]{@listfile|!wildcard} : Include filenames
  -mmt[N] : set number of decoding threads
  -o{Directory} : set Output directory
  -p{Password} : set Password
  -r[-|0] : Recurse subdirectories for name search
  -scrc[CRC32] : set hash function for x, e, h commands
  -sdel : delete files after extraction
  -slt : show technical information for l (List) command
  -so : write data to stdout
  -spd : disable wildcard matching for file names
  -ssc[-] : set sensitive case mode
  -t{Type} : Set type of archive (7z or Split)
  -x[r[-|0]][m[-|2]][w[-]]{@listfile|!wildcard} : eXclude filenames
  -y : assume Yes on all queries
";

fn line_error(session: &mut Session, error: &LineError) -> u8 {
    let mut text = format!("\n\nCommand Line Error:\n{}\n", error.message);
    if !error.argument.is_empty() {
        text.push_str(&error.argument);
        text.push('\n');
    }
    write_to(
        if session.err_target == 0 {
            2
        } else {
            session.err_target
        },
        &text,
    );
    EXIT_USER_ERROR
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Command {
    Extract,
    ExtractFlat,
    Test,
    List,
}

/// One `-i`/`-x`/`-ai` argument: its options and its names.
fn wildcard_switch(
    text: &str,
    raw: &OsStr,
    include: bool,
    default: Recursion,
    names: &mut Vec<(NameOption, OsString)>,
) -> Result<(), LineError> {
    let invalid = |message: &str| LineError::new(message, text.to_owned());
    let mut option = NameOption {
        include,
        recursion: default,
        ..NameOption::default()
    };
    let chars: Vec<char> = text.chars().collect();
    let mut at = 0;
    if chars.len() < 2 {
        return Err(invalid("Too short switch"));
    }
    loop {
        let Some(&c) = chars.get(at) else {
            return Err(invalid("Too short switch"));
        };
        match c.to_ascii_lowercase() {
            'r' => {
                at += 1;
                option.recursion = match chars.get(at) {
                    Some('-') => {
                        at += 1;
                        Recursion::None
                    }
                    Some('0') => {
                        at += 1;
                        Recursion::WildcardOnly
                    }
                    _ => Recursion::All,
                };
            }
            'm' => {
                at += 1;
                option.mark = match chars.get(at) {
                    Some('-') => {
                        at += 1;
                        MarkMode::FileOrDir
                    }
                    Some('2') => {
                        at += 1;
                        MarkMode::StrictFileIfWildcard
                    }
                    _ => MarkMode::StrictFile,
                };
            }
            'w' => {
                at += 1;
                option.wildcards = if chars.get(at) == Some(&'-') {
                    at += 1;
                    false
                } else {
                    true
                };
            }
            _ => break,
        }
    }
    // Every option character before `at` is ASCII: the marker is at byte
    // `at` of the raw argument too.
    match chars[at] {
        '!' => {
            names.push((option, raw_tail(raw, at + 1)));
            Ok(())
        }
        '@' => list_file(&raw_tail(raw, at + 1), &option, names),
        _ => Err(invalid("Incorrect wildcard type marker")),
    }
}

/// A list file's names, one a line, kept as the file's own bytes on Unix.
fn list_lines(data: &[u8]) -> Vec<OsString> {
    let data = data.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(data);
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        data.split(|&byte| byte == b'\n')
            .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
            .map(<[u8]>::trim_ascii)
            .filter(|line| !line.is_empty())
            .map(|line| OsStr::from_bytes(line).to_owned())
            .collect()
    }
    #[cfg(not(unix))]
    {
        String::from_utf8_lossy(data)
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(OsString::from)
            .collect()
    }
}

fn list_file(
    file: &OsStr,
    option: &NameOption,
    names: &mut Vec<(NameOption, OsString)>,
) -> Result<(), LineError> {
    let data = fs::read(file).map_err(|_| {
        LineError::new("Cannot open list file", file.to_string_lossy().into_owned())
    })?;
    names.extend(list_lines(&data).into_iter().map(|line| (*option, line)));
    Ok(())
}

/// Everything the command line decided.
struct Options {
    command: Command,
    forced_type: Option<String>,
    archives: Vec<(NameOption, OsString)>,
    /// `-ax`: archives that are never opened, so never deleted.
    archive_excludes: Censor,
    censor: Censor,
    names_case_sensitive: bool,
    setup: Setup,
    hash: bool,
    technical: bool,
    headers: bool,
    delete_after: bool,
}

/// `Parse2`: the command, the names and the switches that need them.
fn parse_options(parsed: &Parsed, session: &mut Session) -> Result<Options, LineError> {
    let mut words = parsed.non_switches.iter().zip(&parsed.raw_non_switches);
    let Some((command_word, _)) = words.next() else {
        return Err(LineError::new("Cannot find command", ""));
    };
    let command = match command_word.to_ascii_lowercase().as_str() {
        "x" => Command::Extract,
        "e" => Command::ExtractFlat,
        "t" => Command::Test,
        "l" => Command::List,
        _ => {
            return Err(LineError::new("Unsupported command:", command_word.clone()));
        }
    };
    if parsed.has("si") {
        return Err(LineError::new(
            "Reading an archive from standard input is not supported:",
            "-si",
        ));
    }
    // Any other type is one this decoder cannot open: every archive fails
    // to open as that type, as 7-Zip's would on a file of the wrong kind.
    let mut forced_type = None;
    for kind in &parsed.get("t").strings {
        let lower = kind.to_ascii_lowercase();
        if !matches!(lower.as_str(), "7z" | "split" | "*" | "#") {
            forced_type = Some(lower);
        }
    }
    let case_sensitive = if parsed.has("ssc") {
        !parsed.get("ssc").with_minus
    } else {
        !cfg!(windows)
    };
    let recursion = if parsed.has("r") {
        match parsed.get("r").post_char {
            None => Recursion::All,
            Some(0) => Recursion::WildcardOnly,
            _ => Recursion::None,
        }
    } else {
        Recursion::None
    };
    let mut default_option = NameOption {
        recursion,
        wildcards: !parsed.has("spd"),
        ..NameOption::default()
    };
    if parsed.has("spm") {
        default_option.mark = match parsed.get("spm").strings[0].as_str() {
            "" | "1" => MarkMode::StrictFile,
            "2" => MarkMode::StrictFileIfWildcard,
            "-" => MarkMode::FileOrDir,
            _ => return Err(LineError::new("Unsupported switch postfix -spm", "")),
        };
    }

    // The archive names: `-ai` and `-ax` keep their own recursion, and
    // nothing ever recurses for the archive name itself, `-r` included.
    let mut archive_names = Vec::new();
    if !parsed.has("an") {
        match words.next() {
            Some((_, name)) => archive_names.push((NameOption::default(), name.clone())),
            None => return Err(LineError::new("Cannot find archive name", "")),
        }
    }
    let ai = parsed.get("ai");
    for (text, raw) in ai.strings.iter().zip(&ai.raw) {
        wildcard_switch(text, raw, true, Recursion::None, &mut archive_names)?;
    }
    let mut archive_excluded = Vec::new();
    let ax = parsed.get("ax");
    for (text, raw) in ax.strings.iter().zip(&ax.raw) {
        wildcard_switch(text, raw, false, Recursion::None, &mut archive_excluded)?;
    }
    let mut archive_excludes = Censor::new(case_sensitive);
    archive_excludes.add_name(
        &NameOption {
            recursion: Recursion::All,
            ..NameOption::default()
        },
        "*",
    );
    for (option, name) in &archive_excluded {
        if name.is_empty() {
            return Err(LineError::new("Empty file path", ""));
        }
        archive_excludes.add_name(option, &name.to_string_lossy());
    }

    let mut names: Vec<(NameOption, OsString)> = Vec::new();
    let i = parsed.get("i");
    for (text, raw) in i.strings.iter().zip(&i.raw) {
        wildcard_switch(text, raw, true, recursion, &mut names)?;
    }
    let has_includes = !names.is_empty();
    let x = parsed.get("x");
    for (text, raw) in x.strings.iter().zip(&x.raw) {
        let rest = text.to_ascii_lowercase();
        if rest == "td" || rest == "tf" {
            continue;
        }
        wildcard_switch(text, raw, false, recursion, &mut names)?;
    }
    let mut positional = Vec::new();
    // `--` ends `@listfile` reading for every word after it: judge each
    // word by its own place among the non-switches.
    let first = parsed.non_switches.len() - words.len();
    for (index, (word, raw)) in (first..).zip(words) {
        if word.starts_with('@') && parsed.stop_index.is_none_or(|stop| index < stop) {
            list_file(&raw_tail(raw, 1), &default_option, &mut positional)?;
        } else {
            positional.push((default_option, raw.clone()));
        }
    }
    let mut censor = Censor::new(case_sensitive);
    for text in &parsed.get("x").strings {
        match text.to_ascii_lowercase().as_str() {
            "td" => censor.exclude_dirs = true,
            "tf" => censor.exclude_files = true,
            _ => {}
        }
    }
    if positional.is_empty() && !has_includes {
        censor.add_name(&default_option, "*");
    }
    for (option, name) in positional.iter().chain(names.iter()) {
        if name.is_empty() {
            return Err(LineError::new("Empty file path", ""));
        }
        censor.add_name(option, &name.to_string_lossy());
    }

    let mut out_dir = OsString::new();
    if parsed.has("o") {
        out_dir = parsed.get("o").raw[0].clone();
        if !out_dir.is_empty() && !ends_with_separator(&out_dir) {
            out_dir.push(std::path::MAIN_SEPARATOR_STR);
        }
    }
    let mut overwrite = if parsed.has("y") {
        Overwrite::Always
    } else {
        Overwrite::Ask
    };
    if parsed.has("ao") {
        overwrite = match parsed.get("ao").post_char {
            Some(0) => Overwrite::Always,
            Some(1) => Overwrite::Skip,
            Some(2) => Overwrite::Rename,
            _ => Overwrite::RenameExisting,
        };
    }
    let mut threads = std::thread::available_parallelism().map_or(1, |n| n.get() as u32);
    for method in &parsed.get("m").strings {
        let lower = method.to_ascii_lowercase();
        if let Some(value) = lower.strip_prefix("mt") {
            let value = value.strip_prefix('=').unwrap_or(value);
            threads = match value {
                "" | "on" | "+" => threads,
                "off" | "-" => 1,
                number => number
                    .parse::<u32>()
                    .map_err(|_| LineError::new("Unsupported switch postfix -m", method.clone()))?
                    .max(1),
            };
        }
    }
    if parsed.has("p") {
        session.password = Some(parsed.get("p").strings[0].clone());
    }
    let hash = if parsed.has("scrc") {
        for kind in &parsed.get("scrc").strings {
            if !matches!(kind.to_ascii_uppercase().as_str(), "" | "CRC32") {
                return Err(LineError::new("Unsupported hash method:", kind.clone()));
            }
        }
        true
    } else {
        false
    };
    Ok(Options {
        command,
        forced_type,
        archives: archive_names,
        archive_excludes,
        censor,
        names_case_sensitive: case_sensitive,
        setup: Setup {
            test: command == Command::Test,
            flat: command == Command::ExtractFlat,
            to_stdout: parsed.has("so") && command != Command::Test,
            out_dir,
            overwrite,
            threads,
        },
        hash,
        technical: parsed.has("slt"),
        headers: !parsed.has("ba"),
        delete_after: parsed.has("sdel"),
    })
}

fn stream_target(parsed: &Parsed, key: &str, default: u8) -> u8 {
    if parsed.has(key) {
        parsed
            .get(key)
            .post_char
            .map_or(default, |index| index as u8)
    } else {
        default
    }
}

fn run(session: &mut Session, args: &[OsString]) -> u8 {
    // Parse1: switch syntax, before anything is printed.
    let parsed = match switches::parse(args) {
        Ok(parsed) => parsed,
        Err(error) => return line_error(session, &error),
    };
    if parsed.has("bb") {
        let value = &parsed.get("bb").strings[0];
        session.log_level = if value.is_empty() {
            1
        } else {
            match value.parse::<u32>() {
                Ok(level) if value.len() == 1 => level,
                _ => {
                    return line_error(
                        session,
                        &LineError::new("Unsupported switch postfix -bb", value.clone()),
                    );
                }
            }
        };
    }
    let to_stdout = parsed.has("so");
    session.out_target = stream_target(&parsed, "bso", if to_stdout { 0 } else { 1 });
    session.err_target = stream_target(&parsed, "bse", 2);
    if to_stdout && session.out_target == 1 {
        session.out_target = 0;
    }
    let headers = !parsed.has("ba");
    if headers {
        session.out(&banner());
    }
    let help = parsed.has("?") || parsed.has("h") || parsed.has("-help");
    if help || parsed.non_switches.is_empty() {
        session.out(HELP);
        return EXIT_OK;
    }
    // Parse2: the command and its names.
    let options = match parse_options(&parsed, session) {
        Ok(options) => options,
        Err(error) => return line_error(session, &error),
    };
    if headers {
        session.out("Scanning the drive for archives:\n");
    }
    let (archives, folders) = match find_archives(session, &options) {
        Ok(found) => found,
        Err(code) => return code,
    };
    if headers {
        let total: u64 = archives.iter().map(|(_, size)| size).sum();
        let count = archives.len();
        let mut line = String::new();
        if folders != 0 {
            let noun = if folders == 1 { "folder" } else { "folders" };
            line.push_str(&format!("{folders} {noun}, "));
        }
        let noun = if count == 1 { "file" } else { "files" };
        line.push_str(&format!("{count} {noun}, {}\n", smart_size(total)));
        session.out(&line);
    }
    if options.command == Command::List {
        list::run(session, &options, archives)
    } else {
        run_extract(session, options, archives)
    }
}

/// The archive names, wildcards expanded, with their sizes.
fn find_archives(
    session: &mut Session,
    options: &Options,
) -> Result<(Vec<(PathBuf, u64)>, u64), u8> {
    let mut found = Vec::new();
    let mut folders = 0u64;
    let mut missing: Option<io::Error> = None;
    let mut wildcard_names = false;
    let case_sensitive = options.names_case_sensitive;
    for (option, name) in &options.archives {
        let (dir, file) = split_folder(name);
        let dir = Path::new(&dir);
        let file = file.to_string_lossy();
        let file = file.as_ref();
        let recursive = match option.recursion {
            Recursion::All => true,
            Recursion::WildcardOnly => has_wildcard(file),
            Recursion::None => false,
        };
        if recursive {
            // `-air`: the name is matched in its folder and every folder
            // under it.
            wildcard_names = true;
            let mut matches = Vec::new();
            folders += walk(dir, Some((file, case_sensitive)), &mut matches);
            sort_paths(&mut matches);
            found.extend(matches);
            continue;
        }
        if has_wildcard(file) {
            wildcard_names = true;
            let listing = fs::read_dir(if dir.as_os_str().is_empty() {
                Path::new(".")
            } else {
                dir
            });
            let mut matches = Vec::new();
            if let Ok(listing) = listing {
                for entry in listing.flatten() {
                    let Ok(meta) = fs::metadata(entry.path()) else {
                        continue;
                    };
                    let entry_name = entry.file_name();
                    if meta.is_file()
                        && wildcard_match(file, &entry_name.to_string_lossy(), case_sensitive)
                    {
                        matches.push((dir.join(entry_name), meta.len()));
                    }
                }
            }
            sort_paths(&mut matches);
            found.extend(matches);
            continue;
        }
        match fs::metadata(name) {
            Ok(meta) if meta.is_file() => found.push((PathBuf::from(name), meta.len())),
            Ok(_) => {
                // A folder stands for every file under it.
                folders += 1;
                let mut inside = Vec::new();
                folders += walk(Path::new(name), None, &mut inside);
                sort_paths(&mut inside);
                found.extend(inside);
            }
            Err(error) => {
                session.err(&format!(
                    "\nERROR: {}\n{}\n\n",
                    errno_text(&error),
                    name.to_string_lossy()
                ));
                missing = Some(error);
            }
        }
    }
    if let Some(error) = missing {
        session.err(&format!("\n\nSystem ERROR:\n{}\n", errno_text(&error)));
        return Err(EXIT_FATAL);
    }
    // `-ax`: an excluded archive is never opened, so never deleted.
    found.retain(|(path, _)| {
        options
            .archive_excludes
            .selects(&path.to_string_lossy(), false)
    });
    if found.is_empty() && (wildcard_names || options.archives.is_empty()) {
        return Err(line_error(
            session,
            &LineError::new("Cannot find archive", ""),
        ));
    }
    Ok((found, folders))
}

/// Every file under the folder `prefix` names (`""` is the current one)
/// whose name matches `mask`, returning how many folders it passed.
///
/// Links are never followed: a linked folder such as `loop -> .` would
/// recurse without end, and a link out of the folder would reach archives
/// outside the one that was named.
fn walk(prefix: &Path, mask: Option<(&str, bool)>, found: &mut Vec<(PathBuf, u64)>) -> u64 {
    let mut folders = 0;
    let listing = fs::read_dir(if prefix.as_os_str().is_empty() {
        Path::new(".")
    } else {
        prefix
    });
    let Ok(listing) = listing else {
        return 0;
    };
    for entry in listing.flatten() {
        let Ok(meta) = fs::symlink_metadata(entry.path()) else {
            continue;
        };
        let entry_name = entry.file_name();
        let path = prefix.join(&entry_name);
        if meta.is_dir() {
            folders += 1 + walk(&path, mask, found);
        } else if meta.is_file()
            && mask.is_none_or(|(mask, cs)| wildcard_match(mask, &entry_name.to_string_lossy(), cs))
        {
            found.push((path, meta.len()));
        }
    }
    folders
}

/// Archive paths in the order 7-Zip lists them: by their text, byte by
/// byte, not component by component.
fn sort_paths(paths: &mut [(PathBuf, u64)]) {
    paths.sort_by(|a, b| a.0.as_os_str().cmp(b.0.as_os_str()));
}

/// The name 7-Zip shows for the archive inside a path, and its default
/// output folder name.
fn inner_name(path: &str, set: &VolumeSet) -> String {
    match &set.split_name {
        Some(name) => name.clone(),
        None => path.to_owned(),
    }
}

fn is_7z_name(name: &str) -> bool {
    name.to_ascii_lowercase().ends_with(".7z")
}

/// The body 7-Zip prints after `ERROR: <path>` for an archive it could not
/// open.
fn open_error_body(
    path: &str,
    set: &VolumeSet,
    failure: &OpenFailure,
    forced_type: Option<&str>,
) -> String {
    let inner = inner_name(path, set);
    match (failure, forced_type) {
        (_, Some(kind)) => format!(
            "{inner}\nOpen ERROR: Cannot open the file as [{kind}] archive\n\n\nERRORS:\nIs not archive\n"
        ),
        (OpenFailure::WrongPassword, None) => {
            "Cannot open encrypted archive. Wrong password?\n\n".into()
        }
        (OpenFailure::Format(flag), None) if is_7z_name(&inner) => format!(
            "{inner}\nOpen ERROR: Cannot open the file as [7z] archive\n\n\nERRORS:\n{flag}\n"
        ),
        _ => "Cannot open the file as archive\n\n".into(),
    }
}

/// The `--` property block 7-Zip prints for an opened archive.
fn info_block(path: &str, set: &VolumeSet, opened: &Opened) -> String {
    let mut text = String::new();
    let mut shown = path.to_owned();
    if let Some(inner) = &set.split_name {
        let total: u64 = set.sizes.iter().sum();
        text.push_str(&format!(
            "--\nPath = {path}\nType = Split\nPhysical Size = {}\nVolumes = {}\nTotal Physical Size = {total}\n----\nPath = {inner}\nSize = {total}\n",
            set.sizes[0],
            set.sizes.len()
        ));
        shown = inner.clone();
    }
    let tail = opened.stream_len.saturating_sub(opened.physical_size);
    text.push_str(&format!("--\nPath = {shown}\nType = 7z\n"));
    if tail > 0 {
        text.push_str("WARNINGS:\nThere are data after the end of archive\n");
    }
    text.push_str(&format!("Physical Size = {}\n", opened.physical_size));
    if tail > 0 {
        text.push_str(&format!("Tail Size = {tail}\n"));
    }
    text.push_str(&format!("Headers Size = {}\n", opened.headers_size));
    let method = archive_method(&opened.archive);
    if !method.is_empty() {
        text.push_str(&format!("Method = {method}\n"));
    }
    let archive = &opened.archive;
    let mut per_block = vec![0usize; archive.blocks.len()];
    for (index, block) in archive.stream_map.file_block_index.iter().enumerate() {
        if let Some(block) = *block
            && archive.files[index].has_stream
            && let Some(count) = per_block.get_mut(block)
        {
            *count += 1;
        }
    }
    let solid = per_block.iter().any(|&count| count > 1);
    text.push_str(&format!(
        "Solid = {}\nBlocks = {}\n",
        if solid { '+' } else { '-' },
        archive.blocks.len()
    ));
    text
}

/// Open one archive path, asking for a header password if needed.
fn open_path(
    session: &mut Session,
    options: &Options,
    path: &Path,
    size: u64,
) -> (VolumeSet, Result<Opened, OpenFailure>) {
    if options.forced_type.is_some() {
        let set = VolumeSet {
            paths: vec![path.to_path_buf()],
            sizes: vec![size],
            split_name: None,
        };
        return (set, Err(OpenFailure::Format("Is not archive")));
    }
    let set = volume_set(path, size);
    let opened = open_archive(&set, &mut || session.ask_password());
    (set, opened)
}

/// Whether `path` is one of the volumes an earlier archive already read.
fn already_read(read: &[PathBuf], path: &Path) -> bool {
    read.iter().any(|seen| seen == path)
}

/// The user stopped the command at a prompt (7-Zip's E_ABORT).
fn break_signaled(session: &mut Session) -> u8 {
    let target = if session.err_target == 0 {
        2
    } else {
        session.err_target
    };
    write_to(target, "\n\nBreak signaled\n");
    EXIT_BREAK
}

fn run_extract(session: &mut Session, options: Options, archives: Vec<(PathBuf, u64)>) -> u8 {
    let command = options.command;
    let hash = options.hash;
    let delete_after = options.delete_after;
    let mut setup = options.setup.clone();
    let mut stats = Stats {
        hash: hash.then(HashSums::default),
        ..Stats::default()
    };
    let verb = if command == Command::Test {
        "Testing"
    } else {
        "Extracting"
    };
    let base_out = setup.out_dir.clone();
    let mut tried = 0u64;
    let mut ok = 0u64;
    let mut cant_open = 0u64;
    let mut with_errors = 0u64;
    let mut with_warnings = 0u64;
    let mut open_warnings = 0u64;
    let mut file_errors = 0u64;
    let mut compressed = 0u64;
    let mut read_volumes: Vec<PathBuf> = Vec::new();
    let mut failure: Option<io::Error> = None;
    let mut aborted = false;
    for (archive, size) in &archives {
        if already_read(&read_volumes, archive) {
            continue;
        }
        let shown = archive.to_string_lossy();
        let path = shown.as_ref();
        tried += 1;
        session.out(&format!("\n{verb} archive: {path}\n"));
        let (set, opened) = open_path(session, &options, archive, *size);
        let opened = match opened {
            Ok(opened) => opened,
            Err(OpenFailure::Aborted) => {
                aborted = true;
                break;
            }
            Err(OpenFailure::Io(error)) if error.kind() == io::ErrorKind::OutOfMemory => {
                return EXIT_MEMORY;
            }
            Err(failure) => {
                cant_open += 1;
                let body = open_error_body(path, &set, &failure, options.forced_type.as_deref());
                session.err(&format!("ERROR: {path}\n{body}"));
                continue;
            }
        };
        read_volumes.extend(set.paths.iter().skip(1).cloned());
        compressed += set.sizes.iter().sum::<u64>();
        let tail = opened.stream_len > opened.physical_size;
        if tail {
            session.out("\nWARNINGS:\nThere are data after the end of archive\n\n");
            with_warnings += 1;
            open_warnings += 1;
        }
        session.out(&info_block(path, &set, &opened));
        session.out("\n");
        let default_name = {
            let inner: &Path = match &set.split_name {
                Some(name) => Path::new(name),
                None => archive,
            };
            strip_extension(inner.file_name().unwrap_or(inner.as_os_str()))
        };
        setup.out_dir = replace_star(&base_out, &default_name);
        let selected = extract::selection(&opened.archive.files, &options.censor);
        // An archive is deleted only when something was extracted from it.
        let any_selected = selected.iter().any(|&wanted| wanted);
        match extract::extract(session, &setup, &mut stats, opened, selected) {
            Ending::Done(0) => {
                ok += 1;
                session.out("Everything is Ok\n");
                if delete_after && !setup.test && any_selected {
                    for volume in &set.paths {
                        let _ = fs::remove_file(volume);
                    }
                }
            }
            Ending::Done(errors) => {
                with_errors += 1;
                file_errors += errors;
                session.out(&format!("\nSub items Errors: {errors}\n"));
            }
            Ending::Abort => {
                aborted = true;
                break;
            }
            Ending::Failed(error) => {
                with_errors += 1;
                session.err(&format!("\nERROR: {}\n", errno_text(&error)));
                failure = Some(error);
                break;
            }
        }
    }
    if let Some(error) = failure {
        session.err(&format!("\n\nSystem ERROR:\n{}\n", errno_text(&error)));
        return EXIT_FATAL;
    }
    let mut text = String::from("\n");
    if tried > 1 {
        text.push_str(&format!("Archives: {tried}\nOK archives: {ok}\n"));
    }
    if cant_open != 0 {
        text.push_str(&format!("Can't open as archive: {cant_open}\n"));
    }
    if with_errors != 0 {
        text.push_str(&format!("Archives with Errors: {with_errors}\n"));
    }
    if with_warnings != 0 {
        text.push_str(&format!("Archives with Warnings: {with_warnings}\n"));
    }
    if open_warnings != 0 {
        text.push_str(&format!("\nWarnings: {open_warnings}\n"));
    }
    if with_errors != 0 || file_errors != 0 {
        text.push('\n');
        if file_errors != 0 {
            text.push_str(&format!("Sub items Errors: {file_errors}\n"));
        }
    } else if !aborted {
        if stats.folders != 0 {
            text.push_str(&format!("Folders: {}\n", stats.folders));
        }
        if stats.files != 1 || stats.folders != 0 {
            text.push_str(&format!("Files: {}\n", stats.files));
        }
        text.push_str(&format!(
            "Size:       {}\nCompressed: {compressed}\n",
            stats.size
        ));
        if let Some(hash) = &stats.hash {
            text.push('\n');
            text.push_str(&hash.report());
        }
    }
    session.out(&text);
    if aborted {
        return break_signaled(session);
    }
    if cant_open != 0 || with_errors != 0 || file_errors != 0 {
        EXIT_FATAL
    } else {
        EXIT_OK
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    fn raw(bytes: &[u8]) -> OsString {
        OsString::from_vec(bytes.to_vec())
    }

    #[test]
    fn path_arguments_keep_their_bytes() {
        let args = [
            OsString::from("x"),
            raw(b"-oout\xfe"),
            raw(b"-ai!shelf\xfd/more.7z"),
            raw(b"crate\xff.7z"),
        ];
        let parsed = switches::parse(&args).unwrap();
        let mut session = Session {
            out_target: 0,
            err_target: 0,
            log_level: 0,
            password: None,
        };
        let Ok(options) = parse_options(&parsed, &mut session) else {
            panic!("the command line parses");
        };
        let archives: Vec<&[u8]> = options
            .archives
            .iter()
            .map(|(_, name)| name.as_bytes())
            .collect();
        assert_eq!(archives, [&b"crate\xff.7z"[..], b"shelf\xfd/more.7z"]);
        assert_eq!(options.setup.out_dir.as_bytes(), b"out\xfe/");
    }

    #[test]
    fn folder_split_star_and_extension_work_on_bytes() {
        let (dir, file) = split_folder(&raw(b"a\xff/b\xfe.7z"));
        assert_eq!(
            (dir.as_bytes(), file.as_bytes()),
            (&b"a\xff/"[..], &b"b\xfe.7z"[..])
        );
        assert_eq!(strip_extension(&file).as_bytes(), b"b\xfe");
        assert_eq!(
            replace_star(&raw(b"o\xfd/*/"), &raw(b"b\xfe")).as_bytes(),
            b"o\xfd/b\xfe/"
        );
        assert!(ends_with_separator(&raw(b"o\xfd/")));
    }
}
