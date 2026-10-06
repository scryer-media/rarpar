//! `rarpar par3 archive`: write a 7z or ZIP archive and protect it with PAR3
//! in the same pass.
//!
//! sevenz-turbo or the zip crate writes the archive through [`Tee`], which
//! hands every byte to [`Protect`] in file order as it reaches the disk. The 7z
//! start header is the one exception: the writer leaves its 32 bytes for last,
//! so they are fed as zeros and patched in when the writer goes back for them.
//! The ZIP writer streams, with data descriptors, and never goes back.
//!
//! A ZIP set inside the archive follows par3cmdline: the end records (the
//! footer) form their own chunk, the packets follow them, and a copy of the
//! footer ends the file so that it is still a ZIP. The footer is only known at
//! the end, so with a set inside a ZIP the lanes trail the archive by the most
//! a footer can take.
//!
//! The set's geometry depends on the archive's final length, which is only
//! known once the end header is written. Small archives are held in memory
//! and computed exactly at the end. Larger ones start one lane per block size
//! the final length could still choose, each coding in every field it could
//! still need, and drop lanes as the remaining input narrows the length down.
//! If the final geometry was nonetheless not among them, the archive is read
//! back once; a bound that tight on the encoder's output makes that a
//! fallback, not a path.

use std::fs::File;
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use par3_rs::hash::QUICK_HASH_LEN;
use par3_rs::packet::{CreatorPacket, GaloisField};
use rarpar::cli::{ArchiveFilter, ArchiveFormat, Cli, Par3ArchiveArgs};
use serde_json::{Value, json};
use sevenz_turbo::encoder_options::{EncoderOptions, Lzma2Options};
use sevenz_turbo::{
    ArchiveEntry, ArchiveWriter, EncoderConfiguration, EncoderMethod, SourceReader,
};

use crate::compat_7z::local_civil;
use crate::error::RarparError;
use crate::par3::{parent, reject_symlinks};
use crate::par3_stream::{
    self, Coding, FileDigest, InsideParams, InsideShape, Lane, RecoveryChoice, SetSpec,
    block_count, build_set, inside_geometry, inside_size, reference_field, sibling_geometry,
    write_inside, write_sibling,
};

const MIB: u64 = 1 << 20;

/// How far back from the end par3cmdline looks for a ZIP's end records, and so
/// how far the lanes trail a ZIP that takes a set inside.
const ZIP_SEARCH: usize = 1024;

/// The end records the zip crate writes without a comment: the end of central
/// directory record, or that with the ZIP64 record and locator before it.
const ZIP_FOOTERS: [u64; 2] = [22, 98];

/// How the set is laid out.
#[derive(Clone, Copy)]
enum Plan {
    /// Beside the archive, as `par3 c -s<block> -c<n>|-r<n>` lays it out.
    Sibling {
        block_size: u64,
        choice: RecoveryChoice,
    },
    /// After the end header, as `par3 i -r<n>` lays it out, or before a
    /// ZIP's central directory in the strict layout. `footers` are the footer
    /// lengths the finished archive may end with (for the strict layout, the
    /// least and most its central directory and end records may take), until
    /// `params.footer` is set to the one it does.
    Inside {
        params: InsideParams,
        footers: [u64; 2],
    },
}

/// The geometry the finished archive settles on.
struct Geometry {
    block_size: u64,
    galois: GaloisField,
    rows: u64,
    blocks: u64,
    inside: Option<InsideShape>,
}

impl Plan {
    fn inside_params(params: &InsideParams, size: u64) -> InsideParams {
        InsideParams {
            file_size: size,
            footer: params.footer.min(size),
            ..*params
        }
    }

    fn with_footer(self, footer: u64) -> Plan {
        match self {
            Plan::Inside { params, footers } => Plan::Inside {
                params: InsideParams { footer, ..params },
                footers,
            },
            sibling => sibling,
        }
    }

    fn geometry(&self, size: u64) -> Geometry {
        match *self {
            Plan::Sibling { block_size, choice } => {
                let geometry = sibling_geometry(size, Some(block_size), choice);
                Geometry {
                    block_size: geometry.block_size,
                    galois: geometry.galois,
                    rows: geometry.recovery,
                    blocks: geometry.blocks,
                    inside: None,
                }
            }
            Plan::Inside { params, .. } => {
                let shape = inside_geometry(&Self::inside_params(&params, size));
                Geometry {
                    block_size: shape.block_size,
                    galois: reference_field(shape.blocks, 0, shape.recovery, shape.recovery),
                    rows: shape.recovery,
                    blocks: shape.blocks,
                    inside: Some(shape),
                }
            }
        }
    }

    /// Every block size a final length in `[low, high]` could choose, with
    /// the fields it could code in and the most rows it could need.
    fn candidates(&self, low: u64, high: u64) -> Vec<Candidate> {
        match *self {
            Plan::Sibling { block_size, choice } => {
                let block_size = sibling_geometry(0, Some(block_size), choice).block_size;
                let field = |size: u64| {
                    let blocks = block_count(size, block_size);
                    reference_field(blocks, 0, choice.rows(blocks), 0)
                };
                let mut fields = vec![field(low)];
                if field(high) != fields[0] {
                    fields.push(field(high));
                }
                vec![Candidate {
                    block_size,
                    fields,
                    rows: choice.rows(block_count(high, block_size)),
                }]
            }
            Plan::Inside { params, footers } => {
                let mut merged: Vec<Candidate> = Vec::new();
                let footers = if params.strict {
                    // The directory's length moves the block size the search
                    // picks, so sample its whole range, geometrically.
                    let [least, most] = footers;
                    let ratio = (most.max(least) as f64 / least.max(1) as f64).powf(1.0 / 16.0);
                    let mut at = least.max(1) as f64;
                    let mut sampled = Vec::with_capacity(18);
                    for _ in 0..=16 {
                        sampled.push((at as u64).clamp(least, most.max(least)));
                        at *= ratio;
                    }
                    sampled.push(most.max(least));
                    sampled.dedup();
                    sampled
                } else {
                    footers.to_vec()
                };
                for footer in footers {
                    let params = InsideParams { footer, ..params };
                    for mut candidate in Self::inside_candidates(&params, low, high) {
                        if params.strict {
                            // A directory length between the two can pack
                            // its tail differently from both: one more block.
                            candidate.rows += 1;
                        }
                        match merged
                            .iter_mut()
                            .find(|known| known.block_size == candidate.block_size)
                        {
                            Some(known) => {
                                for field in candidate.fields {
                                    if !known.fields.contains(&field) {
                                        known.fields.push(field);
                                    }
                                }
                                known.rows = known.rows.max(candidate.rows);
                            }
                            None => merged.push(candidate),
                        }
                    }
                }
                merged
            }
        }
    }

    fn inside_candidates(params: &InsideParams, low: u64, high: u64) -> Vec<Candidate> {
        let params = *params;
        let mut sizes: Vec<u64> = Vec::new();
        const POINTS: u64 = 4096;
        if high - low <= POINTS {
            sizes.extend(low..=high);
        } else {
            // Even steps and geometric steps, so that both a narrow
            // window and a wide one are sampled densely near `low`.
            let ratio = (high as f64 / low.max(1) as f64).powf(1.0 / POINTS as f64);
            let mut at = low.max(1) as f64;
            for step in 0..=POINTS {
                sizes.push(low + (high - low) / POINTS * step);
                sizes.push((at as u64).clamp(low, high));
                at *= ratio;
            }
            sizes.push(high);
        }
        let mut chosen: Vec<u64> = sizes
            .iter()
            .map(|&size| inside_geometry(&Self::inside_params(&params, size)).block_size)
            .collect();
        chosen.sort_unstable();
        chosen.dedup();
        // The ladder par3cmdline steps through: 40, 64, 128, 256, ...
        let below = |size: u64| match size {
            0..=40 => None,
            41..=64 => Some(40),
            _ => Some(size / 2),
        };
        let above = |size: u64| if size <= 40 { 64 } else { size * 2 };
        let mut block_sizes = Vec::new();
        for size in chosen {
            block_sizes.extend(below(size));
            block_sizes.push(size);
            block_sizes.push(above(size));
        }
        block_sizes.sort_unstable();
        block_sizes.dedup();
        block_sizes
            .into_iter()
            .map(|block_size| {
                let field = |size: u64| {
                    let shape = inside_size(&Self::inside_params(&params, size), block_size);
                    reference_field(shape.blocks, 0, shape.recovery, shape.recovery)
                };
                let mut fields = vec![field(low)];
                if field(high) != fields[0] {
                    fields.push(field(high));
                }
                Candidate {
                    block_size,
                    fields,
                    rows: inside_size(&Self::inside_params(&params, high), block_size).recovery,
                }
            })
            .collect()
    }
}

struct Candidate {
    block_size: u64,
    fields: Vec<GaloisField>,
    rows: u64,
}

impl Candidate {
    fn bytes(&self) -> u64 {
        self.block_size
            .saturating_mul(self.rows)
            .saturating_mul(self.fields.len() as u64)
    }
}

/// What the encoder still has to emit, for bounding the archive's length.
struct Outlook {
    /// Input bytes the encoder has taken.
    consumed: Arc<AtomicU64>,
    /// Input bytes it will take in all.
    total: u64,
    /// Input the encoder may hold without having written it out yet.
    in_flight: u64,
    /// The most the end header can take.
    header: u64,
    /// The most output one input byte can become, in thousandths.
    expansion: u64,
}

impl Outlook {
    fn high(&self, written: u64) -> u64 {
        let consumed = self.consumed.load(Ordering::Relaxed);
        let pending = self.total.saturating_sub(consumed) + consumed.min(self.in_flight);
        written
            .saturating_add(pending.saturating_mul(self.expansion).div_ceil(1000))
            .saturating_add(64 << 10)
            .saturating_add(self.header)
    }
}

/// PAR3 state fed with the archive's bytes in order.
struct Protect {
    plan: Plan,
    outlook: Outlook,
    budget: u64,
    head: Vec<u8>,
    head_cap: u64,
    buffering: bool,
    lanes: Vec<Lane>,
    /// How many of the latest bytes the lanes trail by.
    hold: usize,
    /// The bytes the lanes have not been fed yet: at most `hold`, or once
    /// `directory` is set, every byte from then on.
    held: Vec<u8>,
    /// Set by the strict ZIP layout as the writer starts on its central
    /// directory: the bytes after it are neither fed nor digested until the
    /// directory's start is known and its offsets are moved.
    directory: Arc<AtomicBool>,
    digest: FileDigest,
    len: u64,
    next_prune: u64,
    /// The reason a write was refused, for the report: the 7z writer that
    /// saw the refusal owns this state and drops it on error.
    failure: Arc<Mutex<Option<RarparError>>>,
}

impl Protect {
    fn fail(&mut self, error: RarparError) -> io::Error {
        let message = error.to_string();
        *self
            .failure
            .lock()
            .unwrap_or_else(|poison| poison.into_inner()) = Some(error);
        io::Error::other(message)
    }

    fn feed(&mut self, data: &[u8]) -> io::Result<()> {
        if self.directory.load(Ordering::Relaxed) {
            self.held.extend_from_slice(data);
            self.len += data.len() as u64;
            return Ok(());
        }
        self.digest.update(data, true);
        self.len += data.len() as u64;
        if self.buffering {
            self.head.extend_from_slice(data);
            if self.head.len() as u64 > self.head_cap {
                self.start_lanes()?;
            }
            return Ok(());
        }
        if self.hold == 0 {
            self.feed_lanes(data)?;
        } else {
            let total = self.held.len() + data.len();
            if total <= self.hold {
                self.held.extend_from_slice(data);
            } else {
                let release = total - self.hold;
                let mut held = std::mem::take(&mut self.held);
                let from_held = release.min(held.len());
                self.feed_lanes(&held[..from_held])?;
                self.feed_lanes(&data[..release - from_held])?;
                held.drain(..from_held);
                held.extend_from_slice(&data[release - from_held..]);
                self.held = held;
            }
        }
        if self.len >= self.next_prune {
            self.prune();
        }
        Ok(())
    }

    fn feed_lanes(&mut self, data: &[u8]) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        for lane in &mut self.lanes {
            if let Err(error) = lane.feed(data) {
                return Err(self.fail(RarparError::Data(error)));
            }
        }
        Ok(())
    }

    fn patch(&mut self, at: u64, bytes: &[u8]) -> io::Result<()> {
        self.digest.patch(at as usize, bytes);
        if self.buffering {
            let at = at as usize;
            self.head[at..at + bytes.len()].copy_from_slice(bytes);
            return Ok(());
        }
        for lane in &mut self.lanes {
            if let Err(error) = lane.patch(at, bytes) {
                return Err(self.fail(RarparError::Data(error)));
            }
        }
        Ok(())
    }

    fn start_lanes(&mut self) -> io::Result<()> {
        let low = self.len;
        let high = self.outlook.high(self.len).max(low);
        let candidates = self.plan.candidates(low, high);
        let needed: u64 = candidates.iter().map(Candidate::bytes).sum();
        if needed > self.budget {
            return Err(self.fail(memory_error(needed, self.budget)));
        }
        let fed = self.head.len() - self.hold.min(self.head.len());
        let mut lanes = Vec::with_capacity(candidates.len());
        for candidate in &candidates {
            let mut lane = Lane::new(candidate.block_size, true, true);
            for &field in &candidate.fields {
                match Coding::new(field, 0, candidate.rows, candidate.block_size) {
                    Ok(coding) => lane.add_coding(coding),
                    Err(error) => return Err(self.fail(RarparError::Data(error))),
                }
            }
            lane.begin_chunk();
            if let Err(error) = lane.feed(&self.head[..fed]) {
                return Err(self.fail(RarparError::Data(error)));
            }
            lanes.push(lane);
        }
        self.lanes = lanes;
        self.held = self.head[fed..].to_vec();
        self.head = Vec::new();
        self.buffering = false;
        self.schedule_prune();
        Ok(())
    }

    fn schedule_prune(&mut self) {
        self.next_prune = self.len + (16 * MIB).max(self.len / 64);
    }

    /// Drop the lanes, fields and rows the narrowed length range rules out.
    fn prune(&mut self) {
        let low = self.len;
        let high = self.outlook.high(self.len).max(low);
        let candidates = self.plan.candidates(low, high);
        self.lanes.retain_mut(|lane| {
            let Some(candidate) = candidates
                .iter()
                .find(|candidate| candidate.block_size == lane.block_size())
            else {
                return false;
            };
            let codings = lane.codings_mut();
            codings.retain(|coding| candidate.fields.contains(&coding.galois()));
            for coding in codings.iter_mut() {
                coding.truncate(candidate.rows);
            }
            !codings.is_empty()
        });
        self.schedule_prune();
    }

    /// Take the lane that matches `geometry`, with only the coding it needs.
    fn take_lane(&mut self, geometry: &Geometry) -> Option<Lane> {
        let position = self.lanes.iter().position(|lane| {
            lane.block_size() == geometry.block_size
                && lane.codings().iter().any(|coding| {
                    coding.galois() == geometry.galois
                        && coding.rows().len() as u64 >= geometry.rows
                })
        })?;
        let mut lane = self.lanes.swap_remove(position);
        let codings = lane.codings_mut();
        codings.retain(|coding| coding.galois() == geometry.galois);
        codings.truncate(1);
        codings[0].truncate(geometry.rows);
        Some(lane)
    }
}

fn memory_error(needed: u64, budget: u64) -> RarparError {
    RarparError::Resource(format!(
        "one-pass recovery data needs {} MiB of memory, more than --par3-memory-mib allows ({} MiB)",
        needed.div_ceil(MIB),
        budget / MIB
    ))
}

/// The archive file, seen by the 7z writer, with every byte also fed to
/// [`Protect`].
struct Tee {
    file: BufWriter<File>,
    position: u64,
    end: u64,
    protect: Protect,
}

impl Write for Tee {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        let written = self.file.write(data)?;
        let data = &data[..written];
        let overlap = (self.end - self.position).min(data.len() as u64) as usize;
        if overlap > 0 {
            self.protect.patch(self.position, &data[..overlap])?;
        }
        if overlap < data.len() {
            self.protect.feed(&data[overlap..])?;
        }
        self.position += written as u64;
        self.end = self.end.max(self.position);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl Seek for Tee {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let target = match to {
            SeekFrom::Start(offset) => offset,
            SeekFrom::Current(delta) => {
                self.position.checked_add_signed(delta).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "seek before the start")
                })?
            }
            SeekFrom::End(delta) => self.end.checked_add_signed(delta).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "seek before the start")
            })?,
        };
        if target == self.position {
            return Ok(target);
        }
        if target > self.end {
            // The writer reserves the start header by seeking past it; those
            // bytes are zeros until it comes back for them.
            self.file.seek(SeekFrom::Start(self.end))?;
            self.position = self.end;
            let zeros = vec![0u8; (target - self.end) as usize];
            self.write_all(&zeros)?;
            return Ok(target);
        }
        self.file.seek(SeekFrom::Start(target))?;
        self.position = target;
        Ok(target)
    }
}

/// An input file opened on first read, counting what the encoder takes.
struct Input {
    path: PathBuf,
    file: Option<File>,
    done: bool,
    consumed: Arc<AtomicU64>,
}

impl Read for Input {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.done {
            return Ok(0);
        }
        if self.file.is_none() {
            self.file = Some(File::open(&self.path)?);
        }
        let read = self.file.as_mut().expect("opened above").read(buf)?;
        if read == 0 {
            self.file = None;
            self.done = true;
        }
        self.consumed.fetch_add(read as u64, Ordering::Relaxed);
        Ok(read)
    }
}

/// One archive member.
struct Member {
    path: PathBuf,
    name: String,
    directory: bool,
    size: u64,
}

fn collect(base: &Path, inputs: &[PathBuf]) -> Result<Vec<Member>, RarparError> {
    let mut members = Vec::new();
    let mut pending: Vec<PathBuf> = inputs
        .iter()
        .map(|path| {
            if path.is_absolute() {
                path.clone()
            } else {
                base.join(path)
            }
        })
        .collect();
    pending.reverse();
    while let Some(path) = pending.pop() {
        reject_symlinks(&path)?;
        let meta = std::fs::metadata(&path).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                RarparError::MissingInput(path.clone())
            } else {
                error.into()
            }
        })?;
        let canonical = path.canonicalize()?;
        let relative = canonical.strip_prefix(base).map_err(|_| {
            RarparError::Usage(format!(
                "input {} is outside --base-path {}",
                path.display(),
                base.display()
            ))
        })?;
        let name = relative
            .to_str()
            .ok_or_else(|| RarparError::Usage("archive member names must be UTF-8".into()))?
            .replace(std::path::MAIN_SEPARATOR, "/");
        if name.is_empty() {
            return Err(RarparError::Usage(
                "an input names the base path itself; name its contents instead".into(),
            ));
        }
        if meta.is_dir() {
            let mut children: Vec<PathBuf> = std::fs::read_dir(&canonical)?
                .map(|entry| entry.map(|entry| entry.path()))
                .collect::<Result<_, _>>()?;
            children.sort();
            members.push(Member {
                path: canonical,
                name,
                directory: true,
                size: 0,
            });
            pending.extend(children.into_iter().rev());
        } else if meta.is_file() {
            members.push(Member {
                path: canonical,
                name,
                directory: false,
                size: meta.len(),
            });
        } else {
            return Err(RarparError::Usage(format!(
                "{} is neither a file nor a directory",
                path.display()
            )));
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    for member in &members {
        if !seen.insert(member.name.as_str()) {
            return Err(RarparError::Usage(format!(
                "{} is named more than once",
                member.name
            )));
        }
    }
    Ok(members)
}

fn filter_method(filter: ArchiveFilter) -> Option<EncoderMethod> {
    Some(match filter {
        ArchiveFilter::None => return None,
        ArchiveFilter::X86 => EncoderMethod::BCJ_X86_FILTER,
        ArchiveFilter::Arm => EncoderMethod::BCJ_ARM_FILTER,
        ArchiveFilter::ArmThumb => EncoderMethod::BCJ_ARM_THUMB_FILTER,
        ArchiveFilter::Arm64 => EncoderMethod::BCJ_ARM64_FILTER,
        ArchiveFilter::Ia64 => EncoderMethod::BCJ_IA64_FILTER,
        ArchiveFilter::Sparc => EncoderMethod::BCJ_SPARC_FILTER,
        ArchiveFilter::Ppc => EncoderMethod::BCJ_PPC_FILTER,
        ArchiveFilter::Riscv => EncoderMethod::BCJ_RISCV_FILTER,
    })
}

/// The coder chain, outermost first, and the input the coder may hold back.
fn methods(args: &Par3ArchiveArgs, threads: u32) -> (Vec<EncoderConfiguration>, u64) {
    let mut methods = Vec::new();
    let in_flight = if args.level == 0 {
        methods.push(EncoderConfiguration::new(EncoderMethod::COPY));
        MIB
    } else {
        let options = if threads > 1 {
            Lzma2Options::from_level_mt(args.level, threads, 0)
        } else {
            Lzma2Options::from_level(args.level)
        };
        let options = EncoderOptions::from(options);
        let dictionary = u64::from(options.get_lzma_dict_size());
        methods.push(EncoderConfiguration::new(EncoderMethod::LZMA2).with_options(options));
        (u64::from(threads) + 1) * dictionary.max(MIB) * 2 + 4 * MIB
    };
    methods.extend(filter_method(args.filter).map(EncoderConfiguration::new));
    (methods, in_flight)
}

pub fn run(cli: &Cli, args: &Par3ArchiveArgs) -> Result<(bool, Value), RarparError> {
    let base = args.base_path.clone().unwrap_or(std::env::current_dir()?);
    reject_symlinks(&base)?;
    let base = base.canonicalize()?;
    let members = collect(&base, &args.inputs)?;
    if members.len() > cli.max_files {
        return Err(RarparError::Resource(
            "archiving exceeded --max-files".into(),
        ));
    }

    let output = &args.output;
    reject_symlinks(output)?;
    let name = output
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| RarparError::Usage("the archive path must end in a UTF-8 file name".into()))?
        .to_owned();
    let directory = parent(output);
    let creator = par3_stream::creator_text();
    let zip = args.format == ArchiveFormat::Zip;
    if zip && (args.filter != ArchiveFilter::None || args.no_solid) {
        return Err(RarparError::Usage(
            "--filter and --no-solid are for 7z archives; a ZIP compresses each file on its own"
                .into(),
        ));
    }
    let plan = if args.inside {
        let redundancy = args.recovery_percent.unwrap_or(0);
        if redundancy > 250 {
            return Err(RarparError::Usage(
                "--inside takes a recovery percentage from 0 to 250".into(),
            ));
        }
        Plan::Inside {
            params: InsideParams {
                file_size: 0,
                footer: 0,
                name_len: name.len() as u64,
                creator_packet_size: 48 + CreatorPacket::new(&creator).to_body_bytes().len() as u64,
                redundancy: u64::from(redundancy),
                repetition_limit: 0,
                strict: args.strict_zip,
            },
            footers: if args.strict_zip {
                [22, 0]
            } else if zip {
                ZIP_FOOTERS
            } else {
                [0, 0]
            },
        }
    } else {
        Plan::Sibling {
            block_size: args.block_size,
            choice: match args.recovery_percent {
                Some(percent) => RecoveryChoice::Percent(u64::from(percent)),
                None => RecoveryChoice::Count(args.recovery_count.unwrap_or(1)),
            },
        }
    };
    let stem = output.with_extension("");
    let mut outputs = vec![output.clone()];
    if !args.inside {
        // The volume names depend on the row count, so list the index only.
        outputs.push(par3_stream::sibling_paths(&stem, 0).0);
    }
    for path in &outputs {
        reject_symlinks(path)?;
        if !cli.overwrite && path.try_exists()? {
            return Err(RarparError::Unsafe(format!(
                "output exists: {}",
                path.display()
            )));
        }
    }
    let input_bytes: u64 = members.iter().map(|member| member.size).sum();
    if cli.dry_run {
        return Ok((
            true,
            json!({"operation":"par3_archive","success":true,"dry_run":true,
                "archive":output,"format":format_name(args.format),"mode":if args.inside {"inside"} else {"sibling"},
                "members":members.len(),"input_bytes":input_bytes}),
        ));
    }

    let threads = cli
        .par3_workers
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, usize::from))
        .clamp(1, 64) as u32;
    let (methods, in_flight) = if zip {
        // The deflate stream holds back little more than its window.
        (Vec::new(), MIB)
    } else {
        methods(args, threads)
    };
    let header: u64 = if zip {
        // Local header, ZIP64 fields, data descriptor and central header.
        members
            .iter()
            .map(|member| member.name.len() as u64 * 2 + 200)
            .sum::<u64>()
            + 4096
    } else {
        members
            .iter()
            .map(|member| member.name.encode_utf16().count() as u64 * 2 + 128)
            .sum::<u64>()
            .saturating_mul(102)
            / 100
            + 4096
    };
    let plan = match plan {
        Plan::Inside { params, footers } if params.strict => Plan::Inside {
            params,
            footers: [footers[0], header.max(footers[0])],
        },
        plan => plan,
    };
    let consumed = Arc::new(AtomicU64::new(0));
    let at_directory = Arc::new(AtomicBool::new(false));
    let failure = Arc::new(Mutex::new(None));
    let budget = (cli.par3_memory_mib as u64).saturating_mul(MIB);
    let protect = Protect {
        plan,
        outlook: Outlook {
            consumed: consumed.clone(),
            total: input_bytes,
            in_flight,
            header,
            expansion: if args.level == 0 { 1000 } else { 1002 },
        },
        budget,
        head: Vec::new(),
        head_cap: budget / 2,
        buffering: true,
        lanes: Vec::new(),
        hold: if zip && args.inside && !args.strict_zip {
            ZIP_SEARCH
        } else {
            0
        },
        held: Vec::new(),
        directory: at_directory.clone(),
        digest: FileDigest::new(),
        len: 0,
        next_prune: 0,
        failure: failure.clone(),
    };

    std::fs::create_dir_all(&directory)?;
    let mut builder = tempfile::Builder::new();
    builder.prefix(".rarpar-archive-");
    // The archive is an ordinary output file, not a private temporary.
    #[cfg(unix)]
    builder.permissions(std::os::unix::fs::PermissionsExt::from_mode(0o666));
    let staged = builder.tempfile_in(&directory)?;
    let file = staged.reopen()?;
    let tee = Tee {
        file: BufWriter::with_capacity(MIB as usize, file),
        position: 0,
        end: 0,
        protect,
    };
    let written = if zip {
        let mark = args.strict_zip.then_some(&at_directory);
        write_zip(tee, &members, args.level, &consumed, mark)
    } else {
        write_archive(tee, &members, methods, args.no_solid, &consumed)
    };
    let tee = match written {
        Ok(tee) => tee,
        Err(error) => {
            let refused = failure
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .take();
            return Err(refused.unwrap_or(error));
        }
    };
    let Tee {
        file,
        mut protect,
        end: size,
        ..
    } = tee;
    let mut file = file.into_inner().map_err(|error| error.into_error())?;

    // The strict layout's central directory and end records, held back
    // from the point the writer started on them; the data before the
    // directory's start joins what the lanes and the digest were fed.
    let strict = zip && args.strict_zip;
    let (footer, plan) = if strict {
        let before = protect.len - protect.held.len() as u64;
        let start = zip_directory_start(&protect.held, size)
            .filter(|&start| start >= before)
            .ok_or_else(|| {
                RarparError::Data(
                    "the ZIP writer's central directory was not where its end records place it"
                        .into(),
                )
            })?;
        let directory = protect.held.split_off((start - before) as usize);
        protect.digest.update(&protect.held, true);
        if protect.buffering {
            let rest = std::mem::take(&mut protect.held);
            protect.head.extend_from_slice(&rest);
        }
        let length = directory.len() as u64;
        (directory, plan.with_footer(length))
    } else if zip && args.inside {
        // The footer of a ZIP that takes the set inside, found as
        // par3cmdline finds it, among the bytes the lanes have not been fed.
        let tail: &[u8] = if protect.buffering {
            &protect.head
        } else {
            &protect.held
        };
        let tail = &tail[tail.len().saturating_sub(ZIP_SEARCH)..];
        let footer = zip_footer(tail, size).ok_or_else(|| {
            RarparError::Data("the ZIP writer's end records were not where par3 looks".into())
        })?;
        (
            tail[tail.len() - footer as usize..].to_vec(),
            plan.with_footer(footer),
        )
    } else {
        (Vec::new(), plan)
    };
    let data_end = size - footer.len() as u64;
    let geometry = plan.geometry(size);
    if geometry.blocks == 0 {
        return Err(RarparError::Usage(
            "the archive is too small to hold an input block".into(),
        ));
    }
    let needed = geometry.block_size.saturating_mul(geometry.rows);
    let mut reread = false;
    let mut lane = if protect.buffering {
        if needed > budget {
            return Err(memory_error(needed, budget));
        }
        exact_lane(&geometry, |lane| {
            lane.feed(&protect.head[..data_end as usize])
        })?
    } else if let Some(mut lane) = protect.take_lane(&geometry) {
        protect.lanes.clear();
        // The default layout's footer is still among the held bytes.
        let trailing = if strict { 0 } else { footer.len() };
        let held = &protect.held[..protect.held.len() - trailing];
        lane.feed(held).map_err(RarparError::Data)?;
        lane
    } else {
        protect.lanes.clear();
        if needed > budget {
            return Err(memory_error(needed, budget));
        }
        reread = true;
        file.flush()?;
        let mut source = File::open(staged.path())?.take(data_end);
        let mut buffer = vec![0u8; MIB as usize];
        exact_lane(&geometry, |lane| {
            loop {
                let read = source
                    .read(&mut buffer)
                    .map_err(|error| error.to_string())?;
                if read == 0 {
                    return Ok(());
                }
                lane.feed(&buffer[..read])?;
            }
        })?
    };
    protect.head = Vec::new();
    protect.held = Vec::new();
    lane.end_chunk().map_err(RarparError::Data)?;
    // What follows the packets: the default layout's footer copy, or the
    // strict layout's central directory with its offsets moved past them.
    let mut trailer = footer;
    if strict {
        let shape = geometry.inside.expect("the strict layout is inside");
        trailer = move_directory(&trailer, data_end, shape.total_packet_size)?;
        lane.unprotected(shape.total_packet_size);
        lane.begin_chunk();
        lane.feed(&trailer).map_err(RarparError::Data)?;
        lane.end_chunk().map_err(RarparError::Data)?;
        protect.digest.update(&trailer, false);
    }
    let footer = if strict { Vec::new() } else { trailer.clone() };
    let footer_chunk = if footer.is_empty() {
        None
    } else {
        lane.begin_chunk();
        lane.feed(&footer).map_err(RarparError::Data)?;
        Some(lane.end_chunk().map_err(RarparError::Data)?)
    };
    if let Some(shape) = geometry.inside
        && !strict
    {
        lane.unprotected(shape.total_packet_size);
    }
    if let Some(chunk) = &footer_chunk {
        // The copy after the packets is protected too, by the same blocks.
        lane.repeat_chunk(chunk);
        protect.digest.update(&footer, false);
    }
    lane.finish().map_err(RarparError::Data)?;
    if lane.block_count() != geometry.blocks {
        return Err(RarparError::Data(format!(
            "the set has {} input blocks where its geometry expects {}",
            lane.block_count(),
            geometry.blocks
        )));
    }
    if lane.codings().len() != 1 {
        return Err(RarparError::Data(
            "the set's field cannot hold its input blocks".into(),
        ));
    }
    let runs = lane.checksum_runs();
    // par3cmdline leaves an inside set's quick hash out for a file shorter
    // than the hash covers; the strict layout's first bytes are the data.
    let hashed = if strict { data_end } else { size };
    let quick_hash = match geometry.inside {
        Some(_) if hashed < QUICK_HASH_LEN as u64 => 0,
        _ => protect.digest.quick_hash(),
    };
    let spec = SetSpec {
        id_name: &name,
        name: &name,
        file_size: size,
        block_size: geometry.block_size,
        galois: geometry.galois,
        matrix_hint: Some(if geometry.inside.is_some() {
            geometry.rows
        } else {
            0
        }),
        quick_hash,
        fingerprint: protect.digest.fingerprint(),
        chunks: lane.chunks(),
        runs: &runs,
        block_count: lane.block_count(),
        creator: &creator,
    };
    let set = build_set(&spec);
    let rows = lane.codings()[0].rows();

    let mut written = vec![output.clone()];
    if let Some(shape) = geometry.inside {
        file.seek(SeekFrom::Start(if strict { data_end } else { size }))?;
        let mut out = BufWriter::new(&mut file);
        let packets = write_inside(&mut out, &set, rows, 0, shape.repeat)?;
        if packets != shape.total_packet_size {
            // par3cmdline sizes the run before writing it; a run that
            // differs would leave the chunk lengths describing other bytes.
            return Err(RarparError::Data(format!(
                "the packets take {packets} bytes where par3 reserves {}",
                shape.total_packet_size
            )));
        }
        out.write_all(&trailer)?;
        out.flush()?;
        drop(out);
    }
    file.sync_all()?;
    drop(file);
    let archive_bytes = std::fs::metadata(staged.path())?.len();
    staged
        .persist(output)
        .map_err(|error| RarparError::Io(error.error))?;
    if geometry.inside.is_none() {
        written.extend(write_sibling(&stem, &set, rows, cli.overwrite)?);
    }
    Ok((
        true,
        json!({"operation":"par3_archive","success":true,"dry_run":false,
            "archive":output,"format":format_name(args.format),
            "mode":if args.inside {"inside"} else {"sibling"},
            "zip_layout":(zip && args.inside).then_some(if strict {"strict"} else {"par3cmdline"}),
            "outputs":written,"members":members.len(),"input_bytes":input_bytes,
            "archive_bytes":archive_bytes,"protected_bytes":size,
            "set_id":set.set_id.to_string(),"block_size":geometry.block_size,
            "blocks":geometry.blocks,"recovery_blocks":geometry.rows,
            "field_bytes":geometry.galois.size,"read_back":reread}),
    ))
}

fn format_name(format: ArchiveFormat) -> &'static str {
    match format {
        ArchiveFormat::SevenZ => "7z",
        ArchiveFormat::Zip => "zip",
    }
}

/// par3cmdline's `check_outside_format` for ZIP: the length of the end
/// records, found by scanning `tail`, the last bytes of a `size`-byte file,
/// backwards for an end of central directory record (or its ZIP64 form) that
/// accounts for the file's end.
fn zip_footer(tail: &[u8], size: u64) -> Option<u64> {
    let u32_at =
        |at: usize| u32::from_le_bytes([tail[at], tail[at + 1], tail[at + 2], tail[at + 3]]);
    let u64_at = |at: usize| {
        let bytes = tail.get(at..at + 8)?;
        Some(u64::from_le_bytes(bytes.try_into().ok()?))
    };
    let len = tail.len() as i64;
    let mut offset = len - 22;
    while offset >= 0 {
        let at = offset as usize;
        let records = (len - offset) as u64;
        match u32_at(at) {
            0x0605_4b50 => {
                let directory = u64::from(u32_at(at + 12));
                let start = u64::from(u32_at(at + 16));
                if start + directory + records == size {
                    return Some(records);
                } else if directory == 0xFFFF_FFFF || start == 0xFFFF_FFFF {
                    offset -= 19;
                } else if start + directory + records < size {
                    return None;
                }
            }
            0x0606_4b50 => {
                let end = u64_at(at + 40)
                    .zip(u64_at(at + 48))
                    .and_then(|(directory, start)| start.checked_add(directory))
                    .and_then(|end| end.checked_add(records));
                match end {
                    Some(end) if end == size => return Some(records),
                    Some(end) if end < size => return None,
                    _ => {}
                }
            }
            _ => {}
        }
        offset -= 1;
    }
    None
}

const EOCD: u32 = 0x0605_4b50;
const ZIP64_EOCD: u32 = 0x0606_4b50;
const ZIP64_LOCATOR: u32 = 0x0706_4b50;
/// End of central directory record, without a comment.
const EOCD_LEN: usize = 22;
const LOCATOR_LEN: usize = 20;

fn le_u32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn le_u64(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}

/// Where the ZIP64 end of central directory record sits in `tail`, the last
/// bytes of a `size`-byte ZIP that ends with a locator and an end record.
fn zip64_record(tail: &[u8], size: u64) -> Option<usize> {
    let locator = tail.len().checked_sub(EOCD_LEN + LOCATOR_LEN)?;
    if le_u32(tail, locator)? != ZIP64_LOCATOR {
        return None;
    }
    let record = le_u64(tail, locator + 8)?;
    let at = usize::try_from(record.checked_sub(size - tail.len() as u64)?).ok()?;
    (le_u32(tail, at)? == ZIP64_EOCD).then_some(at)
}

/// The start of the central directory of a `size`-byte ZIP whose last bytes
/// are `tail`, which hold the directory and its end records, as the end
/// records give it. The zip crate writes no archive comment, so the end of
/// central directory record is the file's last 22 bytes.
fn zip_directory_start(tail: &[u8], size: u64) -> Option<u64> {
    let end = tail.len().checked_sub(EOCD_LEN)?;
    if le_u32(tail, end)? != EOCD || tail[end + 20..] != [0, 0] {
        return None;
    }
    let (directory, start) = match zip64_record(tail, size) {
        Some(record) => (le_u64(tail, record + 40)?, le_u64(tail, record + 48)?),
        None => (
            u64::from(le_u32(tail, end + 12)?),
            u64::from(le_u32(tail, end + 16)?),
        ),
    };
    // The directory runs up to the first end record.
    let first = zip64_record(tail, size).unwrap_or(end);
    (start.checked_add(directory)? == size - tail.len() as u64 + first as u64).then_some(start)
}

/// The strict layout's central directory and end records, `records`, with
/// the directory moved from `start` to `start + shift`, past the packets put
/// before it. The members' own offsets do not change.
fn move_directory(records: &[u8], start: u64, shift: u64) -> Result<Vec<u8>, RarparError> {
    let malformed = || RarparError::Data("the ZIP writer's end records are malformed".into());
    let mut out = records.to_vec();
    let size = start + records.len() as u64;
    let end = out.len().checked_sub(EOCD_LEN).ok_or_else(malformed)?;
    let moved = start + shift;
    let put32 = |out: &mut [u8], at: usize, value: u32| {
        out[at..at + 4].copy_from_slice(&value.to_le_bytes());
    };
    let put64 = |out: &mut [u8], at: usize, value: u64| {
        out[at..at + 8].copy_from_slice(&value.to_le_bytes());
    };
    let short = le_u32(&out, end + 16).ok_or_else(malformed)?;
    match zip64_record(&out, size) {
        Some(record) => {
            if le_u64(&out, record + 48) != Some(start) {
                return Err(malformed());
            }
            put64(&mut out, record + 48, moved);
            let locator = end - LOCATOR_LEN;
            let at = le_u64(&out, locator + 8).ok_or_else(malformed)?;
            put64(&mut out, locator + 8, at + shift);
            if short != u32::MAX {
                // The short field holds the offset while it fits.
                put32(&mut out, end + 16, u32::try_from(moved).unwrap_or(u32::MAX));
            }
        }
        None => {
            if u64::from(short) != start {
                return Err(malformed());
            }
            let moved = u32::try_from(moved)
                .ok()
                .filter(|&moved| moved != u32::MAX)
                .ok_or_else(|| {
                    RarparError::Resource(
                        "with the set before it, this ZIP's central directory would start past \
                         4 GiB, which its end records cannot say without ZIP64; drop --strict-zip"
                            .into(),
                    )
                })?;
            put32(&mut out, end + 16, moved);
        }
    }
    Ok(out)
}

/// A lane for exactly `geometry`, fed by `feed`.
fn exact_lane(
    geometry: &Geometry,
    feed: impl FnOnce(&mut Lane) -> Result<(), String>,
) -> Result<Lane, RarparError> {
    let mut lane = Lane::new(geometry.block_size, false, true);
    lane.add_coding(
        Coding::new(geometry.galois, 0, geometry.rows, geometry.block_size)
            .map_err(RarparError::Data)?,
    );
    lane.begin_chunk();
    feed(&mut lane).map_err(RarparError::Data)?;
    Ok(lane)
}

fn write_archive(
    tee: Tee,
    members: &[Member],
    methods: Vec<EncoderConfiguration>,
    no_solid: bool,
    consumed: &Arc<AtomicU64>,
) -> Result<Tee, RarparError> {
    let mut writer = ArchiveWriter::new(tee).map_err(archive_error)?;
    writer.set_content_methods(methods);
    let entry = |member: &Member| {
        let mut entry = ArchiveEntry::from_path(&member.path, member.name.clone());
        entry.name = member.name.clone();
        // As 7-Zip stores by default: the modification time only. Reading
        // a file moves its access time, so storing that would make the
        // same inputs give a different archive every time.
        entry.has_access_date = false;
        entry.has_creation_date = false;
        entry
    };
    let input = |member: &Member| Input {
        path: member.path.clone(),
        file: None,
        done: false,
        consumed: consumed.clone(),
    };
    let mut result = Ok(());
    let mut solid_entries = Vec::new();
    let mut solid_readers = Vec::new();
    for member in members {
        if member.directory || member.size == 0 {
            result = writer
                .push_archive_entry::<Input>(entry(member), None)
                .map(|_| ());
        } else if no_solid {
            result = writer
                .push_archive_entry(entry(member), Some(input(member)))
                .map(|_| ());
        } else {
            solid_entries.push(entry(member));
            solid_readers.push(SourceReader::new(input(member)));
        }
        if result.is_err() {
            break;
        }
    }
    if result.is_ok() && !solid_entries.is_empty() {
        result = writer
            .push_archive_entries(solid_entries, solid_readers)
            .map(|_| ());
    }
    result.map_err(archive_error)?;
    let mut tee = writer.finish()?;
    tee.flush()?;
    Ok(tee)
}

/// Members this large get ZIP64 sizes from the start: the writer streams, so
/// the local header cannot be widened once the sizes are known, and deflate
/// can grow incompressible input a little.
const ZIP64_MEMBER: u64 = 0xFFFF_FFFF - (0xFFFF_FFFF >> 8);

fn write_zip(
    tee: Tee,
    members: &[Member],
    level: u32,
    consumed: &Arc<AtomicU64>,
    directory: Option<&Arc<AtomicBool>>,
) -> Result<Tee, RarparError> {
    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    let large = Arc::new(AtomicBool::new(false));
    let mut writer = ZipWriter::new_stream(LocalHeaders {
        inner: tee,
        large: large.clone(),
        held: Vec::new(),
    });
    let mut buffer = vec![0u8; 256 << 10];
    for member in members {
        let meta = std::fs::metadata(&member.path)?;
        let mut options = SimpleFileOptions::default()
            .last_modified_time(dos_time(&meta))
            .large_file(member.size >= ZIP64_MEMBER);
        options = if level == 0 || member.directory {
            options.compression_method(CompressionMethod::Stored)
        } else {
            options
                .compression_method(CompressionMethod::Deflated)
                .compression_level(Some(i64::from(level)))
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            options = options.unix_permissions(meta.permissions().mode() & 0o7777);
        }
        if member.directory {
            writer
                .add_directory(member.name.as_str(), options)
                .map_err(zip_error)?;
            continue;
        }
        large.store(member.size >= ZIP64_MEMBER, Ordering::Relaxed);
        writer
            .start_file(member.name.as_str(), options)
            .map_err(zip_error)?;
        let mut input = Input {
            path: member.path.clone(),
            file: None,
            done: false,
            consumed: consumed.clone(),
        };
        loop {
            let read = input.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            writer.write_all(&buffer[..read])?;
        }
    }
    if let Some(directory) = directory {
        // Everything written from here on, the last member's end, its
        // descriptor and the central directory, is held back whole.
        directory.store(true, Ordering::Relaxed);
    }
    let mut tee = writer.finish().map_err(zip_error)?.into_inner().inner;
    tee.flush()?;
    Ok(tee)
}

/// Passes the zip crate's output through, fixing one field on the way. A
/// streamed ZIP64 member's local header carries its sizes in a data
/// descriptor, with zero in the header's own size fields, but the zip crate
/// fills the header's ZIP64 sizes with all-ones placeholders it never goes
/// back to. APPNOTE 4.5.3 wants zeros there, and 7-Zip warns on the
/// mismatch. While `large` is set, the next local header is held until
/// complete and its placeholders are zeroed before anything sees them.
struct LocalHeaders<W> {
    inner: W,
    large: Arc<AtomicBool>,
    held: Vec<u8>,
}

impl<W: Write> Write for LocalHeaders<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if !self.large.load(Ordering::Relaxed) {
            return self.inner.write(buf);
        }
        self.held.extend_from_slice(buf);
        let header = &mut self.held;
        if header.len() >= 4 && header[..4] != *b"PK\x03\x04" {
            self.large.store(false, Ordering::Relaxed);
        } else if header.len() >= 30 {
            let name = usize::from(u16::from_le_bytes([header[26], header[27]]));
            let extra = usize::from(u16::from_le_bytes([header[28], header[29]]));
            if header.len() < 30 + name + extra {
                return Ok(buf.len());
            }
            self.large.store(false, Ordering::Relaxed);
            let descriptor = header[6] & 8 != 0 && header[18..26] == [0; 8];
            let mut at = 30 + name;
            while descriptor && at + 4 <= 30 + name + extra {
                let id = u16::from_le_bytes([header[at], header[at + 1]]);
                let len = usize::from(u16::from_le_bytes([header[at + 2], header[at + 3]]));
                let fields = at + 4..at + 4 + len;
                if fields.end > 30 + name + extra {
                    break;
                }
                if id == 1 && len == 16 && header[fields.clone()].iter().all(|&b| b == 0xFF) {
                    header[fields].fill(0);
                    break;
                }
                at += 4 + len;
            }
        } else {
            return Ok(buf.len());
        }
        let held = std::mem::take(&mut self.held);
        self.inner.write_all(&held)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// A file's modification time as a ZIP stores it: local time, clamped to the
/// years the format holds.
fn dos_time(meta: &std::fs::Metadata) -> zip::DateTime {
    let secs = meta
        .modified()
        .ok()
        .and_then(|time| {
            time.duration_since(std::time::UNIX_EPOCH)
                .map(|since| since.as_secs() as i64)
                .ok()
        })
        .unwrap_or(0);
    let [year, month, day, hour, minute, second] = local_civil(secs);
    if year < 1980 {
        return zip::DateTime::default();
    }
    if year > 2107 {
        return zip::DateTime::from_date_and_time(2107, 12, 31, 23, 59, 58).unwrap_or_default();
    }
    zip::DateTime::from_date_and_time(
        year as u16,
        month as u8,
        day as u8,
        hour as u8,
        minute as u8,
        second as u8,
    )
    .unwrap_or_default()
}

fn zip_error(error: zip::result::ZipError) -> RarparError {
    RarparError::Data(format!("ZIP writer: {error}"))
}

fn archive_error(error: sevenz_turbo::Error) -> RarparError {
    RarparError::Data(format!("7z writer: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_streamed_zip64_local_header_gets_zero_sizes() {
        let mut header = b"PK\x03\x04\x2d\x00\x08\x00".to_vec();
        header.extend_from_slice(&[0; 18]);
        header.extend_from_slice(&[4, 0, 20, 0]);
        header.extend_from_slice(b"vast");
        header.extend_from_slice(&[1, 0, 16, 0]);
        header.extend_from_slice(&[0xFF; 16]);
        let large = Arc::new(AtomicBool::new(true));
        let mut writer = LocalHeaders {
            inner: Vec::new(),
            large: large.clone(),
            held: Vec::new(),
        };
        for piece in header.chunks(7) {
            writer.write_all(piece).unwrap();
        }
        writer.write_all(&[0xFF; 3]).unwrap();
        let mut expected = header.clone();
        expected[38..54].fill(0);
        expected.extend_from_slice(&[0xFF; 3]);
        assert_eq!(writer.inner, expected);
        assert!(!large.load(Ordering::Relaxed));

        // Unarmed, the same bytes pass through untouched.
        let mut writer = LocalHeaders {
            inner: Vec::new(),
            large,
            held: Vec::new(),
        };
        writer.write_all(&header).unwrap();
        assert_eq!(writer.inner, header);
    }

    fn inside(redundancy: u64, footers: [u64; 2], strict: bool) -> Plan {
        Plan::Inside {
            params: InsideParams {
                file_size: 0,
                footer: 0,
                name_len: 9,
                creator_packet_size: 120,
                redundancy,
                repetition_limit: 0,
                strict,
            },
            footers,
        }
    }

    /// Every length in a window, including the block sizes where the
    /// geometry jumps back down, is covered by that window's candidates.
    #[test]
    fn candidates_cover_every_length_in_their_window() {
        let plans = [0, 1, 10, 40, 250]
            .map(|redundancy| (redundancy, [0u64, 0], false))
            .into_iter()
            .chain([0, 10, 250].map(|redundancy| (redundancy, ZIP_FOOTERS, false)))
            .chain([0, 10, 250].map(|redundancy| (redundancy, [22, 70_000], true)));
        for (redundancy, footers, strict) in plans {
            let plan = inside(redundancy, footers, strict);
            // The strict layout's directory may take any length in its range.
            let lengths: Vec<u64> = if strict {
                vec![
                    22, 23, 63, 64, 65, 1000, 4097, 33_333, 65_536, 69_999, 70_000,
                ]
            } else {
                footers.to_vec()
            };
            let mut low = 1u64 << 12;
            while low < 1 << 34 {
                for spread in [0u64, 1, 37, 4096, low / 100, low / 3, low] {
                    let high = low + spread;
                    let candidates = plan.candidates(low, high);
                    for size in [low, low + spread / 3, low + spread / 2, high] {
                        for &footer in &lengths {
                            let geometry = plan.with_footer(footer).geometry(size);
                            let candidate = candidates
                                .iter()
                                .find(|candidate| candidate.block_size == geometry.block_size)
                                .unwrap_or_else(|| {
                                    panic!(
                                        "-r{redundancy} footer {footer} [{low}, {high}] misses {size}"
                                    )
                                });
                            assert!(candidate.fields.contains(&geometry.galois));
                            assert!(candidate.rows >= geometry.rows);
                        }
                    }
                }
                low = low * 3 / 2 + 7;
            }
        }
        let sibling = Plan::Sibling {
            block_size: 4095,
            choice: RecoveryChoice::Percent(30),
        };
        for (low, high) in [(1000, 2000), (100_000, 2_000_000), (600_000, 40_000_000)] {
            let candidates = sibling.candidates(low, high);
            for size in [low, (low + high) / 2, high] {
                let geometry = sibling.geometry(size);
                let candidate = &candidates[0];
                assert_eq!(candidate.block_size, geometry.block_size);
                assert!(candidate.fields.contains(&geometry.galois));
                assert!(candidate.rows >= geometry.rows);
            }
        }
    }

    /// A length outside the window the lanes were started for finds no lane,
    /// which sends the archive to the read-back path instead of a wrong set.
    #[test]
    fn a_length_the_lanes_ruled_out_finds_no_lane() {
        let plan = Plan::Sibling {
            block_size: 4096,
            choice: RecoveryChoice::Percent(10),
        };
        let mut protect = Protect {
            plan,
            outlook: Outlook {
                consumed: Arc::new(AtomicU64::new(0)),
                // An encoder that writes far more than it promised.
                total: 0,
                in_flight: 0,
                header: 0,
                expansion: 1000,
            },
            budget: 64 * MIB,
            head: Vec::new(),
            head_cap: 4096,
            buffering: true,
            lanes: Vec::new(),
            hold: 0,
            held: Vec::new(),
            directory: Arc::new(AtomicBool::new(false)),
            digest: FileDigest::new(),
            len: 0,
            next_prune: 0,
            failure: Arc::new(Mutex::new(None)),
        };
        let data = vec![7u8; 1 << 20];
        protect.feed(&data[..8192]).unwrap();
        assert!(!protect.buffering);
        for _ in 0..4 {
            protect.feed(&data).unwrap();
        }
        let geometry = plan.geometry(protect.len);
        assert!(protect.take_lane(&geometry).is_none());
    }

    /// A central directory of one entry, then its end records: the plain end
    /// record, or the ZIP64 record, locator and plain record.
    fn records(start: u64, zip64: bool) -> Vec<u8> {
        let mut out = b"PK\x01\x02".to_vec();
        out.resize(46 + 4, b'n');
        let directory = out.len() as u64;
        if zip64 {
            out.extend_from_slice(&0x0606_4b50u32.to_le_bytes());
            out.extend_from_slice(&44u64.to_le_bytes());
            out.extend_from_slice(&[0; 28]);
            out.extend_from_slice(&directory.to_le_bytes());
            out.extend_from_slice(&start.to_le_bytes());
            out.extend_from_slice(&0x0706_4b50u32.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&(start + directory).to_le_bytes());
            out.extend_from_slice(&1u32.to_le_bytes());
        }
        out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        out.extend_from_slice(&[0; 8]);
        out.extend_from_slice(&(directory as u32).to_le_bytes());
        let short = if zip64 && start >= u64::from(u32::MAX) {
            u32::MAX
        } else {
            start as u32
        };
        out.extend_from_slice(&short.to_le_bytes());
        out.extend_from_slice(&[0; 2]);
        out
    }

    #[test]
    fn the_strict_layout_moves_the_directory_past_the_packets() {
        // Plain end record: the directory's offset moves by the packets.
        let plain = records(1000, false);
        let size = 1000 + plain.len() as u64;
        assert_eq!(zip_directory_start(&plain, size), Some(1000));
        let moved = move_directory(&plain, 1000, 777).unwrap();
        assert_eq!(zip_directory_start(&moved, size + 777), Some(1777));
        assert_eq!(moved[..50], plain[..50]);

        // ZIP64: the record's offset and the locator's move; the short field
        // takes the sentinel once the offset no longer fits it.
        let zip64 = records(5000, true);
        let size = 5000 + zip64.len() as u64;
        assert_eq!(zip_directory_start(&zip64, size), Some(5000));
        let moved = move_directory(&zip64, 5000, 300).unwrap();
        assert_eq!(zip_directory_start(&moved, size + 300), Some(5300));
        assert_eq!(le_u32(&moved, moved.len() - 6), Some(5300));
        let far = u64::from(u32::MAX) - 100;
        let moved = move_directory(&zip64, 5000, far).unwrap();
        assert_eq!(zip_directory_start(&moved, size + far), Some(5000 + far));
        assert_eq!(le_u32(&moved, moved.len() - 6), Some(u32::MAX));

        // Without ZIP64 records, an offset past 4 GiB is refused.
        assert!(matches!(
            move_directory(&plain, 1000, u64::from(u32::MAX) - 1000),
            Err(RarparError::Resource(_))
        ));
        assert!(move_directory(&plain, 1000, u64::from(u32::MAX) - 1001).is_ok());

        // End records that do not account for the directory are not taken.
        assert_eq!(zip_directory_start(&plain, size + 1), None);
        assert!(move_directory(&plain, 999, 10).is_err());
    }
}
