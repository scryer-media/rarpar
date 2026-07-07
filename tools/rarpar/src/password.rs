use std::fs::File;
use std::io::{self, BufRead, Read, Write};
use std::path::Path;

use crate::error::RarparError;
use rarpar::cli::Cli;

#[derive(Debug, Clone)]
pub struct PasswordResolver {
    candidates: Vec<String>,
    prompted: bool,
}

impl PasswordResolver {
    pub fn from_cli(cli: &Cli) -> Result<Self, RarparError> {
        let mut candidates = Vec::new();

        if let Some(name) = &cli.password_env {
            match std::env::var(name) {
                Ok(value) if !value.is_empty() => candidates.push(value),
                Ok(_) => {}
                Err(error) => {
                    return Err(RarparError::Usage(format!(
                        "password environment variable {name:?} is unavailable: {error}"
                    )));
                }
            }
        }

        if let Some(path) = &cli.password_file {
            read_password_lines_from_path(path, &mut candidates)?;
        }

        if let Some(fd) = cli.password_fd {
            read_password_lines_from_fd(fd, &mut candidates)?;
        }

        dedup_passwords(&mut candidates);
        Ok(Self {
            candidates,
            prompted: false,
        })
    }

    pub fn candidates_with_prompt(&mut self, prompt: &str) -> Result<Vec<String>, RarparError> {
        if !self.candidates.is_empty() {
            return Ok(self.candidates.clone());
        }
        if self.prompted {
            return Ok(Vec::new());
        }
        self.prompted = true;
        let Some(password) = prompt_password(prompt)? else {
            return Ok(Vec::new());
        };
        if password.is_empty() {
            return Ok(Vec::new());
        }
        self.candidates.push(password);
        Ok(self.candidates.clone())
    }
}

fn read_password_lines_from_path(
    path: &Path,
    candidates: &mut Vec<String>,
) -> Result<(), RarparError> {
    let file = File::open(path)?;
    read_password_lines(file, candidates)
}

fn read_password_lines<R: Read>(
    reader: R,
    candidates: &mut Vec<String>,
) -> Result<(), RarparError> {
    for line in io::BufReader::new(reader).lines() {
        let line = line?;
        let password = line.trim_end_matches(['\r', '\n']).to_string();
        if !password.is_empty() {
            candidates.push(password);
        }
    }
    Ok(())
}

#[cfg(unix)]
fn read_password_lines_from_fd(fd: i32, candidates: &mut Vec<String>) -> Result<(), RarparError> {
    if fd < 0 {
        return Err(RarparError::Usage(format!("invalid password fd {fd}")));
    }
    let proc_path = format!("/proc/self/fd/{fd}");
    let dev_path = format!("/dev/fd/{fd}");
    let file = File::open(&proc_path).or_else(|_| File::open(&dev_path))?;
    read_password_lines(file, candidates)
}

#[cfg(not(unix))]
fn read_password_lines_from_fd(_fd: i32, _candidates: &mut Vec<String>) -> Result<(), RarparError> {
    Err(RarparError::Usage(
        "--password-fd is not supported on this platform".to_string(),
    ))
}

fn dedup_passwords(candidates: &mut Vec<String>) {
    let mut seen = std::collections::BTreeSet::new();
    candidates.retain(|candidate| seen.insert(candidate.clone()));
}

#[cfg(unix)]
fn prompt_password(prompt: &str) -> Result<Option<String>, RarparError> {
    use std::io::IsTerminal;
    use std::process::Command;

    if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        return Ok(None);
    }

    eprint!("{prompt}");
    io::stderr().flush()?;
    let _ = Command::new("stty").arg("-echo").status();
    let mut line = String::new();
    let read_result = io::stdin().read_line(&mut line);
    let _ = Command::new("stty").arg("echo").status();
    eprintln!();
    read_result?;
    Ok(Some(line.trim_end_matches(['\r', '\n']).to_string()))
}

#[cfg(not(unix))]
fn prompt_password(_prompt: &str) -> Result<Option<String>, RarparError> {
    use std::io::IsTerminal;

    if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        return Ok(None);
    }
    Err(RarparError::Usage(
        "interactive hidden password prompts are not supported on this platform; use --password-file, --password-env, or --password-fd".to_string(),
    ))
}
