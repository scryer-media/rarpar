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

use censor::{Censor, MarkMode, NameOption, Recursion, has_wildcard, names_equal, wildcard_match};
use extract::{Ending, HashSums, Overwrite, Setup, Stats};
use format::{archive_method, smart_size};
use switches::{LineError, Parsed};
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
    // An argument that is not valid Unicode is refused, never read with
    // U+FFFD in place of its bytes: that would name a different archive,
    // output folder or member, which `-sdel` could then delete.
    let mut text = Vec::with_capacity(args.len());
    for arg in args {
        match arg.to_str() {
            Some(arg) => text.push(arg.to_owned()),
            None => {
                let shown = arg.to_string_lossy().into_owned();
                return line_error(
                    &mut session,
                    &LineError::new("Unsupported argument that is not valid Unicode:", shown),
                );
            }
        }
    }
    run(&mut session, &text)
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
        let line = {
            let _quiet = EchoOff::stdin();
            self.read_line()
        };
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

/// Terminal echo switched off while a password is typed, and restored when
/// this is dropped. 7-Zip does this on Windows; it is done on a Unix
/// terminal too, so a typed password is never shown. Input that is not a
/// terminal is left alone.
struct EchoOff {
    #[cfg(unix)]
    fd: i32,
    #[cfg(unix)]
    saved: libc::termios,
    #[cfg(windows)]
    console: *mut std::ffi::c_void,
    #[cfg(windows)]
    saved: u32,
}

impl EchoOff {
    fn stdin() -> Option<Self> {
        #[cfg(unix)]
        return Self::on(0);
        #[cfg(windows)]
        return Self::on_console();
        #[cfg(not(any(unix, windows)))]
        return None;
    }

    #[cfg(unix)]
    fn on(fd: i32) -> Option<Self> {
        // SAFETY: `termios` is plain data that `tcgetattr` fills; the calls
        // only read and set the terminal state of `fd`.
        unsafe {
            if libc::isatty(fd) != 1 {
                return None;
            }
            let mut saved: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(fd, &mut saved) != 0 {
                return None;
            }
            let mut quiet = saved;
            quiet.c_lflag &= !libc::ECHO;
            (libc::tcsetattr(fd, libc::TCSANOW, &quiet) == 0).then_some(Self { fd, saved })
        }
    }

    #[cfg(windows)]
    fn on_console() -> Option<Self> {
        const STD_INPUT_HANDLE: u32 = -10i32 as u32;
        const ENABLE_ECHO_INPUT: u32 = 0x0004;
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetStdHandle(which: u32) -> *mut std::ffi::c_void;
            fn GetConsoleMode(console: *mut std::ffi::c_void, mode: *mut u32) -> i32;
        }
        // SAFETY: the handle is the process's own standard input, checked
        // before use; the mode is a plain integer.
        unsafe {
            let console = GetStdHandle(STD_INPUT_HANDLE);
            if console.is_null() || console as isize == -1 {
                return None;
            }
            let mut saved = 0u32;
            if GetConsoleMode(console, &mut saved) == 0 {
                return None;
            }
            (set_console_mode(console, saved & !ENABLE_ECHO_INPUT) != 0)
                .then_some(Self { console, saved })
        }
    }
}

#[cfg(windows)]
unsafe fn set_console_mode(console: *mut std::ffi::c_void, mode: u32) -> i32 {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn SetConsoleMode(console: *mut std::ffi::c_void, mode: u32) -> i32;
    }
    // SAFETY: the caller passes a console handle it read the mode from.
    unsafe { SetConsoleMode(console, mode) }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        // SAFETY: restores the state read from the same terminal in `on`.
        #[cfg(unix)]
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.saved);
        }
        // SAFETY: restores the mode read from the same console handle.
        #[cfg(windows)]
        unsafe {
            set_console_mode(self.console, self.saved);
        }
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

/// One `-i`/`-x`/`-ai` argument: its options and its names. `base` carries
/// the defaults its own `r`, `m` and `w` modifiers override: the recursion,
/// and the `-spd`/`-spm` matching and mark mode.
fn wildcard_switch(
    text: &str,
    include: bool,
    base: NameOption,
    names: &mut Vec<(NameOption, String)>,
) -> Result<(), LineError> {
    let invalid = |message: &str| LineError::new(message, text.to_owned());
    let mut option = NameOption { include, ..base };
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
    let rest: String = chars[at..].iter().collect();
    if let Some(name) = rest.strip_prefix('!') {
        names.push((option, name.to_owned()));
        Ok(())
    } else if let Some(file) = rest.strip_prefix('@') {
        list_file(file, &option, names)
    } else {
        Err(invalid("Incorrect wildcard type marker"))
    }
}

fn list_file(
    file: &str,
    option: &NameOption,
    names: &mut Vec<(NameOption, String)>,
) -> Result<(), LineError> {
    let data =
        fs::read(file).map_err(|_| LineError::new("Cannot open list file", file.to_owned()))?;
    let text = match data.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        Some(rest) => String::from_utf8_lossy(rest).into_owned(),
        None => String::from_utf8_lossy(&data).into_owned(),
    };
    for line in text.lines() {
        let line = line.trim();
        if !line.is_empty() {
            names.push((*option, line.to_owned()));
        }
    }
    Ok(())
}

/// Everything the command line decided.
struct Options {
    command: Command,
    forced_type: Option<String>,
    archives: Vec<(NameOption, String)>,
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
    let mut words = parsed.non_switches.iter();
    let Some(command_word) = words.next() else {
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
    // `-spd` and `-spm` reach them all, as 7-Zip's `nopArc` takes them.
    let archive_option = NameOption {
        recursion: Recursion::None,
        ..default_option
    };
    let mut archive_names = Vec::new();
    if !parsed.has("an") {
        match words.next() {
            Some(name) => archive_names.push((archive_option, name.clone())),
            None => return Err(LineError::new("Cannot find archive name", "")),
        }
    }
    for text in &parsed.get("ai").strings {
        wildcard_switch(text, true, archive_option, &mut archive_names)?;
    }
    let mut archive_excluded = Vec::new();
    for text in &parsed.get("ax").strings {
        wildcard_switch(text, false, archive_option, &mut archive_excluded)?;
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
        archive_excludes.add_name(option, name);
    }

    let mut names: Vec<(NameOption, String)> = Vec::new();
    for text in &parsed.get("i").strings {
        wildcard_switch(text, true, default_option, &mut names)?;
    }
    let has_includes = !names.is_empty();
    for text in &parsed.get("x").strings {
        let rest = text.to_ascii_lowercase();
        if rest == "td" || rest == "tf" {
            continue;
        }
        wildcard_switch(text, false, default_option, &mut names)?;
    }
    let mut positional = Vec::new();
    // `--` ends `@listfile` reading for every word after it: judge each
    // word by its own place among the non-switches.
    let first = parsed.non_switches.len() - words.len();
    for (index, word) in (first..).zip(words) {
        if let Some(file) = word.strip_prefix('@')
            && parsed.stop_index.is_none_or(|stop| index < stop)
        {
            list_file(file, &default_option, &mut positional)?;
        } else {
            positional.push((default_option, word.clone()));
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
        // 7-Zip's universal wildcard takes the default options, so `-spd`
        // never turns it into a member literally named `*`.
        censor.add_name(&NameOption::default(), "*");
    }
    for (option, name) in positional.iter().chain(names.iter()) {
        if name.is_empty() {
            return Err(LineError::new("Empty file path", ""));
        }
        censor.add_name(option, name);
    }

    let mut out_dir = String::new();
    if parsed.has("o") {
        out_dir = parsed.get("o").strings[0].clone();
        if !out_dir.is_empty() && !out_dir.ends_with(['/', std::path::MAIN_SEPARATOR]) {
            out_dir.push(std::path::MAIN_SEPARATOR);
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

fn run(session: &mut Session, args: &[String]) -> u8 {
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
) -> Result<(Vec<(String, u64)>, u64), u8> {
    let mut found = Vec::new();
    let mut folders = 0u64;
    let mut missing: Option<io::Error> = None;
    let mut wildcard_names = false;
    let case_sensitive = options.names_case_sensitive;
    for (option, name) in &options.archives {
        let (dir, file) = match name.rfind(['/', std::path::MAIN_SEPARATOR]) {
            Some(at) => (&name[..=at], &name[at + 1..]),
            None => ("", name.as_str()),
        };
        let recursive = match option.recursion {
            Recursion::All => true,
            Recursion::WildcardOnly => has_wildcard(file),
            Recursion::None => false,
        };
        // `-spd` or `w-`: `*` and `?` are the name's own characters.
        let mask = Mask {
            name: file,
            wildcards: option.wildcards,
            case_sensitive,
        };
        if recursive {
            // `-air`: the name is matched in its folder and every folder
            // under it.
            wildcard_names = true;
            let mut matches = Vec::new();
            match walk(dir, Some(mask), &mut matches) {
                Ok(passed) => folders += passed,
                // A folder that is not there holds nothing to match.
                Err((path, error)) if error.kind() == io::ErrorKind::NotFound && path == dir => {}
                Err((path, error)) => {
                    scan_error(session, &path, &error);
                    missing = Some(error);
                    continue;
                }
            }
            matches.sort();
            found.extend(matches);
            continue;
        }
        if option.wildcards && has_wildcard(file) {
            wildcard_names = true;
            let listing = fs::read_dir(if dir.is_empty() { "." } else { dir });
            let mut matches = Vec::new();
            if let Ok(listing) = listing {
                for entry in listing.flatten() {
                    let Ok(meta) = fs::metadata(entry.path()) else {
                        continue;
                    };
                    let entry_name = entry.file_name().to_string_lossy().into_owned();
                    if meta.is_file() && wildcard_match(file, &entry_name, case_sensitive) {
                        matches.push((format!("{dir}{entry_name}"), meta.len()));
                    }
                }
            }
            matches.sort();
            found.extend(matches);
            continue;
        }
        match fs::metadata(name) {
            Ok(meta) if meta.is_file() => found.push((name.clone(), meta.len())),
            Ok(_) => {
                // A folder stands for every file under it.
                folders += 1;
                let mut inside = Vec::new();
                let prefix = if name.ends_with(['/', std::path::MAIN_SEPARATOR]) {
                    name.clone()
                } else {
                    format!("{name}{}", std::path::MAIN_SEPARATOR)
                };
                match walk(&prefix, None, &mut inside) {
                    Ok(passed) => folders += passed,
                    // A folder that cannot be read fails the scan, as
                    // 7-Zip's does: never an empty, successful one.
                    Err((path, error)) => {
                        scan_error(session, &path, &error);
                        missing = Some(error);
                        continue;
                    }
                }
                inside.sort();
                found.extend(inside);
            }
            Err(error) => {
                scan_error(session, name, &error);
                missing = Some(error);
            }
        }
    }
    if let Some(error) = missing {
        session.err(&format!("\n\nSystem ERROR:\n{}\n", errno_text(&error)));
        return Err(EXIT_FATAL);
    }
    // `-ax`: an excluded archive is never opened, so never deleted.
    found.retain(|(path, _)| options.archive_excludes.selects(path, false));
    if found.is_empty() && (wildcard_names || options.archives.is_empty()) {
        return Err(line_error(
            session,
            &LineError::new("Cannot find archive", ""),
        ));
    }
    Ok((found, folders))
}

/// A file name to look for while walking: a wildcard, or with wildcard
/// matching off, the literal name.
#[derive(Clone, Copy)]
struct Mask<'a> {
    name: &'a str,
    wildcards: bool,
    case_sensitive: bool,
}

impl Mask<'_> {
    fn matches(&self, name: &str) -> bool {
        if self.wildcards {
            wildcard_match(self.name, name, self.case_sensitive)
        } else {
            names_equal(self.name, name, self.case_sensitive)
        }
    }
}

/// Every file under the folder `prefix` names (`""` is the current one)
/// whose name matches `mask`, returning how many folders it passed.
///
/// Links are never followed: a linked folder such as `loop -> .` would
/// recurse without end, and a link out of the folder would reach archives
/// outside the one that was named.
///
/// A folder that cannot be read ends the walk with its path and the error.
fn walk(
    prefix: &str,
    mask: Option<Mask>,
    found: &mut Vec<(String, u64)>,
) -> Result<u64, (String, io::Error)> {
    let mut folders = 0;
    let fail = |error| Err((prefix.to_owned(), error));
    let listing = match fs::read_dir(if prefix.is_empty() { "." } else { prefix }) {
        Ok(listing) => listing,
        Err(error) => return fail(error),
    };
    for entry in listing {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => return fail(error),
        };
        let entry_name = entry.file_name().to_string_lossy().into_owned();
        let path = format!("{prefix}{entry_name}");
        let meta = match fs::symlink_metadata(entry.path()) {
            Ok(meta) => meta,
            // Gone since the folder was listed.
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err((path, error)),
        };
        if meta.is_dir() {
            let inner = format!("{path}{}", std::path::MAIN_SEPARATOR);
            folders += 1 + walk(&inner, mask, found)?;
        } else if meta.is_file() && mask.is_none_or(|mask| mask.matches(&entry_name)) {
            found.push((path, meta.len()));
        }
    }
    Ok(folders)
}

/// 7-Zip's scan error: the system message and the path it hit.
fn scan_error(session: &mut Session, path: &str, error: &io::Error) {
    session.err(&format!("\nERROR: {}\n{path}\n\n", errno_text(error)));
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
    path: &str,
    size: u64,
) -> (VolumeSet, Result<Opened, OpenFailure>) {
    if options.forced_type.is_some() {
        let set = VolumeSet {
            paths: vec![PathBuf::from(path)],
            sizes: vec![size],
            split_name: None,
        };
        return (set, Err(OpenFailure::Format("Is not archive")));
    }
    let set = volume_set(Path::new(path), size);
    let opened = open_archive(&set, &mut || session.ask_password());
    (set, opened)
}

/// Whether `path` is one of the volumes an earlier archive already read.
fn already_read(read: &[PathBuf], path: &str) -> bool {
    let path = Path::new(path);
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

fn run_extract(session: &mut Session, options: Options, archives: Vec<(String, u64)>) -> u8 {
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
    for (path, size) in &archives {
        if already_read(&read_volumes, path) {
            continue;
        }
        tried += 1;
        session.out(&format!("\n{verb} archive: {path}\n"));
        let (set, opened) = open_path(session, &options, path, *size);
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
            let inner = inner_name(path, &set);
            let file = Path::new(&inner)
                .file_name()
                .map_or(inner.clone(), |name| name.to_string_lossy().into_owned());
            match file.rfind('.') {
                Some(dot) if dot > 0 => file[..dot].to_owned(),
                _ => file,
            }
        };
        setup.out_dir = base_out.replace('*', &default_name);
        if setup.out_dir.is_empty() && !setup.test && !setup.to_stdout {
            setup.out_dir = String::new();
        }
        let selected = extract::selection(&opened.archive.files, &options.censor);
        match extract::extract(session, &setup, &mut stats, opened, selected) {
            Ending::Done { errors: 0, written } => {
                ok += 1;
                session.out("Everything is Ok\n");
                // An archive is deleted only when something was written from
                // it: not when the filters selected nothing, nor when the
                // overwrite policy skipped every destination.
                // A volume that cannot be deleted is an error of this archive:
                // it is named with the system's reason, and the archive is no
                // longer counted as OK, so the command does not exit 0.
                if delete_after && !setup.test && written > 0 {
                    let mut failed = 0u64;
                    for volume in &set.paths {
                        match fs::remove_file(volume) {
                            Err(error) if error.kind() != io::ErrorKind::NotFound => {
                                failed += 1;
                                session.err(&format!(
                                    "ERROR: Cannot delete file : {} : {}\n",
                                    errno_text(&error),
                                    volume.display()
                                ));
                            }
                            _ => {}
                        }
                    }
                    if failed != 0 {
                        ok -= 1;
                        with_errors += 1;
                        file_errors += failed;
                    }
                }
            }
            Ending::Done { errors, .. } => {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The echo flag of the terminal `fd`.
    #[cfg(unix)]
    fn echoes(fd: i32) -> bool {
        // SAFETY: reads the state of a terminal the test opened.
        unsafe {
            let mut state: libc::termios = std::mem::zeroed();
            assert_eq!(libc::tcgetattr(fd, &mut state), 0);
            state.c_lflag & libc::ECHO != 0
        }
    }

    /// A password typed at a terminal is not echoed, and the terminal's own
    /// state comes back afterwards; input that is not a terminal is left
    /// alone.
    #[cfg(unix)]
    #[test]
    fn echo_is_off_only_while_a_password_is_read() {
        // SAFETY: a pseudo-terminal pair the test owns and closes.
        unsafe {
            let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
            assert!(master >= 0);
            assert_eq!(libc::grantpt(master), 0);
            assert_eq!(libc::unlockpt(master), 0);
            let name = libc::ptsname(master);
            assert!(!name.is_null());
            let terminal = libc::open(name, libc::O_RDWR | libc::O_NOCTTY);
            assert!(terminal >= 0);
            assert!(echoes(terminal));
            {
                let _quiet = EchoOff::on(terminal).expect("a terminal");
                assert!(!echoes(terminal));
            }
            assert!(echoes(terminal));
            libc::close(terminal);
            libc::close(master);

            let mut pipe = [0i32; 2];
            assert_eq!(libc::pipe(pipe.as_mut_ptr()), 0);
            assert!(EchoOff::on(pipe[0]).is_none());
            libc::close(pipe[0]);
            libc::close(pipe[1]);
        }
    }
}
