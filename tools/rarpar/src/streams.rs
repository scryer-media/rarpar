//! Standard input and output, pipes and staged outputs for the format
//! subcommands.
//!
//! A format subcommand names its input and output with paths, where `-` is
//! standard input or output, and an absent input is standard input when that
//! is not a terminal. An input is either a regular file, which may be sized
//! and seeked, or a forward-only stream (standard input, a pipe, a FIFO or a
//! device), which is read once, in order, with memory that does not depend
//! on its length. An output file is staged beside its destination and
//! installed whole, never over an existing file without `--overwrite`;
//! standard output is written as the data is produced, so a slow reader
//! holds the writer back instead of growing a buffer. A report never shares
//! standard output with data.

use std::cell::Cell;
use std::fs::{File, Metadata};
use std::io::{self, BufWriter, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use rarpar::cli::Cli;

use crate::error::RarparError;

/// Buffer size for reading inputs and writing outputs.
pub const IO_BUFFER: usize = 1 << 20;

/// Whether `path` names standard input or output.
pub fn is_stdio(path: &Path) -> bool {
    path.as_os_str() == "-"
}

/// INPUT, or `-` when INPUT is absent and standard input is not a terminal.
pub fn input_or_stdin(input: Option<&Path>) -> Result<PathBuf, RarparError> {
    match input {
        Some(path) => Ok(path.to_path_buf()),
        None if io::stdin().is_terminal() => Err(RarparError::Usage(
            "no INPUT given and standard input is a terminal; give INPUT or `-`".into(),
        )),
        None => Ok(PathBuf::from("-")),
    }
}

/// The metadata of `path` when it is a regular file, and `None` for standard
/// input and for anything that can only be read forward. Never opens the
/// path, so a FIFO is not consumed by asking.
pub fn regular_file_metadata(path: &Path) -> Result<Option<Metadata>, RarparError> {
    if is_stdio(path) {
        return Ok(None);
    }
    let meta = std::fs::metadata(path).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound => RarparError::MissingInput(path.to_path_buf()),
        _ => RarparError::Io(error),
    })?;
    if meta.is_dir() {
        return Err(RarparError::Usage(format!(
            "input is a directory: {}",
            path.display()
        )));
    }
    Ok(meta.is_file().then_some(meta))
}

/// An opened input.
pub enum Input {
    /// A regular file: sized, seekable, and the source of an output's
    /// permissions and times.
    File { file: File, meta: Metadata },
    /// Standard input, a pipe, a FIFO or a device: read forward only.
    Stream(Box<dyn Read>),
}

impl Input {
    pub fn open(path: &Path) -> Result<Self, RarparError> {
        if is_stdio(path) {
            return Ok(Self::Stream(Box::new(io::stdin().lock())));
        }
        let meta = regular_file_metadata(path)?;
        let file = File::open(path)?;
        Ok(match meta {
            Some(meta) => Self::File { file, meta },
            None => Self::Stream(Box::new(file)),
        })
    }

    /// The input as a plain reader, whatever it is.
    pub fn into_reader(self) -> Box<dyn Read> {
        match self {
            Self::File { file, .. } => Box::new(file),
            Self::Stream(reader) => reader,
        }
    }
}

/// A reader that counts what it reads into a counter its owner keeps after
/// handing the reader to a decoder.
pub struct Tally<R> {
    inner: R,
    count: Rc<Cell<u64>>,
}

impl<R: Read> Tally<R> {
    pub fn new(inner: R) -> (Self, Rc<Cell<u64>>) {
        let count = Rc::new(Cell::new(0));
        (
            Self {
                inner,
                count: Rc::clone(&count),
            },
            count,
        )
    }
}

impl<R: Read> Read for Tally<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.count.set(self.count.get() + n as u64);
        Ok(n)
    }
}

/// A writer that counts what passes through it.
pub struct CountingWriter<W> {
    pub inner: W,
    pub count: u64,
}

impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.count += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Where the output for `input` goes: `None` for standard output.
///
/// OUTPUT `-` is standard output, and an OUTPUT that is not an existing
/// directory is the output file. Otherwise the file is named by
/// `default_name` from INPUT, inside OUTPUT when that is a directory, else in
/// the global `--output` directory or beside INPUT. Standard input with no
/// OUTPUT goes to standard output.
pub fn resolve_output(
    cli: &Cli,
    input: &Path,
    output: Option<&Path>,
    default_name: impl FnOnce(&Path) -> Result<PathBuf, RarparError>,
) -> Result<Option<PathBuf>, RarparError> {
    let output = output.map(|path| cli.place_output(path));
    match output.as_deref() {
        Some(path) if is_stdio(path) => Ok(None),
        Some(path) if !path.is_dir() => Ok(Some(path.to_path_buf())),
        Some(directory) => {
            if is_stdio(input) {
                return Err(RarparError::Usage(
                    "standard input has no name; give OUTPUT as a file path".into(),
                ));
            }
            Ok(Some(directory.join(default_name(input)?)))
        }
        None if is_stdio(input) => Ok(None),
        None => {
            let name = default_name(input)?;
            let directory = match &cli.output {
                Some(directory) => directory.clone(),
                None => input.parent().map(Path::to_path_buf).unwrap_or_default(),
            };
            Ok(Some(directory.join(name)))
        }
    }
}

/// Refuses an output that exists (without `--overwrite`) or is the input.
pub fn preflight_output(cli: &Cli, input: &Path, output: &Path) -> Result<(), RarparError> {
    if !output.exists() {
        return Ok(());
    }
    if !is_stdio(input) && input.canonicalize()? == output.canonicalize()? {
        return Err(RarparError::Unsafe(format!(
            "output is the input: {}",
            output.display()
        )));
    }
    if !cli.overwrite {
        return Err(RarparError::Unsafe(format!(
            "output exists; pass --overwrite to replace: {}",
            output.display()
        )));
    }
    Ok(())
}

/// Refuses to write binary data to a terminal.
pub fn refuse_terminal_stdout(what: &str) -> Result<(), RarparError> {
    if io::stdout().is_terminal() {
        return Err(RarparError::Usage(format!(
            "{what} is not written to a terminal; give OUTPUT or redirect"
        )));
    }
    Ok(())
}

/// An output file staged beside its destination and installed whole.
pub struct Staged {
    file: tempfile::NamedTempFile,
    destination: PathBuf,
}

impl Staged {
    /// Stages `destination` as a hidden file whose name starts with `prefix`.
    pub fn create(destination: &Path, prefix: &str) -> Result<Self, RarparError> {
        let directory = match destination.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
            _ => PathBuf::from("."),
        };
        std::fs::create_dir_all(&directory)?;
        let mut builder = tempfile::Builder::new();
        builder.prefix(prefix);
        // The output is an ordinary file, not a private temporary.
        #[cfg(unix)]
        builder.permissions(std::os::unix::fs::PermissionsExt::from_mode(0o666));
        Ok(Self {
            file: builder.tempfile_in(&directory)?,
            destination: destination.to_path_buf(),
        })
    }

    pub fn file(&self) -> &File {
        self.file.as_file()
    }

    /// Copies `input`'s permissions and times, then installs the file, over
    /// an existing one only with `--overwrite`.
    pub fn install(self, cli: &Cli, input: Option<&Metadata>) -> Result<(), RarparError> {
        if let Some(meta) = input {
            self.file
                .as_file()
                .set_permissions(meta.permissions())
                .or_else(|error| match error.kind() {
                    io::ErrorKind::PermissionDenied => Ok(()),
                    _ => Err(error),
                })?;
            let modified = filetime::FileTime::from_last_modification_time(meta);
            let accessed = filetime::FileTime::from_last_access_time(meta);
            filetime::set_file_handle_times(self.file.as_file(), Some(accessed), Some(modified))?;
        }
        let destination = self.destination;
        if cli.overwrite {
            self.file.persist(&destination)
        } else {
            self.file.persist_noclobber(&destination)
        }
        .map_err(|error| match error.error.kind() {
            io::ErrorKind::AlreadyExists if !cli.overwrite => RarparError::Unsafe(format!(
                "output exists; pass --overwrite to replace: {}",
                destination.display()
            )),
            _ => RarparError::Io(error.error),
        })?;
        Ok(())
    }
}

/// Runs `write` against the output: standard output for `None`, otherwise a
/// file staged beside `output` and installed, with `input`'s permissions and
/// times, only once `write` has succeeded. Returns what `write` returns; a
/// failed write leaves no file behind.
pub fn write_output<T>(
    cli: &Cli,
    output: Option<&Path>,
    input: Option<&Metadata>,
    prefix: &str,
    write: impl FnOnce(&mut dyn Write) -> Result<T, RarparError>,
) -> Result<T, RarparError> {
    let (value, staged) = stage_output(output, prefix, write)?;
    if let Some(staged) = staged {
        staged.install(cli, input)?;
    }
    Ok(value)
}

/// [`write_output`] without the install: a file output comes back staged,
/// for the caller to install once whatever must accompany it is ready.
pub fn stage_output<T>(
    output: Option<&Path>,
    prefix: &str,
    write: impl FnOnce(&mut dyn Write) -> Result<T, RarparError>,
) -> Result<(T, Option<Staged>), RarparError> {
    match output {
        None => {
            let stdout = io::stdout();
            let mut sink = BufWriter::with_capacity(IO_BUFFER, stdout.lock());
            let value = write(&mut sink)?;
            sink.flush()?;
            Ok((value, None))
        }
        Some(path) => {
            let staged = Staged::create(path, prefix)?;
            let value = {
                let mut sink = BufWriter::with_capacity(IO_BUFFER, staged.file());
                let value = write(&mut sink)?;
                sink.flush()?;
                value
            };
            Ok((value, Some(staged)))
        }
    }
}

/// Where a report goes: standard error while data holds standard output.
pub fn report_writer(data_on_stdout: bool) -> Box<dyn Write> {
    if data_on_stdout {
        Box::new(io::stderr().lock())
    } else {
        Box::new(io::stdout().lock())
    }
}
