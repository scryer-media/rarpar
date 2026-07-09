use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::CommandFactory;
use clap_complete::shells::{Bash, Elvish, Fish, PowerShell, Zsh};
use clap_complete::{Generator, generate};
use clap_mangen::Man;
use rarpar::cli::Cli;

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
  cargo run -p xtask -- package-root --binary PATH --out DIR [--docs DIR] [--target TRIPLE]"
    );
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
        Path::new("usr/share/licenses/rarpar/LICENSE.weaver-unrar"),
        &root.join("crates/weaver-unrar/LICENSE"),
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
        "usr/share/licenses/rarpar/LICENSE.weaver-unrar",
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
\fBrarpar\fR source is GPL-3.0-or-later. Normal binary builds link
\fBweaver-unrar\fR, so distributed \fBrarpar\fR binaries also carry the
additional UnRAR source-code restriction for RAR extraction and recovery code.
Binary archives include \fBLICENSE\fR, \fBLICENSE.GPL-3.0-or-later\fR, and
\fBLICENSE.weaver-unrar\fR.
"#;

#[cfg(test)]
mod tests {
    use super::*;

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
            "usr/share/licenses/rarpar/LICENSE.weaver-unrar",
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
}
