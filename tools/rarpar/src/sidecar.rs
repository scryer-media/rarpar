//! A conventional recovery set (`NAME.par2` or `NAME.par3` and their
//! volumes) for one file whose bytes are seen once, in order, as they are read
//! from a pipe or written to an output.
//!
//! The block size and recovery count are fixed before the first byte, because
//! the file's length is known only at its end. A PAR3 set is coded in GF(2^8)
//! and GF(2^16) until the block count rules GF(2^8) out, as par3cmdline would
//! choose for the final length; a PAR2 set has one field. Memory is the
//! recovery blocks, one block, and a few dozen bytes per input block.

use std::io::Write;
use std::path::{Path, PathBuf};

use par3_rs::packet::GaloisField;
use rarpar::cli::{SidecarArgs, SidecarFormat};
use serde_json::{Value, json};

use crate::error::RarparError;
use crate::par2_stream::{self, Par2Lane};
use crate::par3_stream::{
    self, Coding, FileDigest, LANE_BYTES_PER_BLOCK, Lane, RecoveryChoice, SetSpec, StagedSibling,
    build_set, reference_field, sibling_geometry, sibling_paths, write_sibling,
};

const MIB: u64 = 1 << 20;
/// GF(2^8) holds a set only while it has at most this many input blocks.
const GF8_MAX_BLOCKS: u64 = 128;
/// GF(2^16) gives every input block and recovery row its own value below this.
pub(crate) const GF16_ORDER: u64 = 1 << 16;

const GF8: GaloisField = GaloisField {
    size: 1,
    generator: 0x1d,
};
const GF16: GaloisField = GaloisField {
    size: 2,
    generator: 0x100b,
};

/// What a set will be, decided before its file's first byte.
#[derive(Clone, Copy)]
pub(crate) struct SidecarPlan {
    pub(crate) format: SidecarFormat,
    pub(crate) block_size: u64,
    pub(crate) rows: u64,
}

impl SidecarPlan {
    /// Round the block size as the format needs and check the recovery count.
    pub(crate) fn new(
        format: SidecarFormat,
        block_size: u64,
        rows: u64,
    ) -> Result<Self, RarparError> {
        let block_size = match format {
            // A Cauchy set over GF(2^16) codes in two-byte symbols, so
            // par3cmdline rounds an odd block size up.
            SidecarFormat::Par3 => {
                sibling_geometry(0, Some(block_size), RecoveryChoice::Count(0)).block_size
            }
            SidecarFormat::Par2 => par2_stream::slice_size(block_size),
        };
        let limit = match format {
            SidecarFormat::Par3 => GF16_ORDER,
            SidecarFormat::Par2 => par2_stream::MAX_ROWS,
        };
        if rows >= limit {
            return Err(RarparError::Usage(format!(
                "a {} set takes fewer than {limit} recovery blocks",
                format_name(format)
            )));
        }
        Ok(SidecarPlan {
            format,
            block_size,
            rows,
        })
    }

    /// Bytes the set holds while its file streams by, whatever its length.
    pub(crate) fn memory_estimate(&self) -> u64 {
        match self.format {
            SidecarFormat::Par3 => {
                let fields = if self.rows < 256 { 2 } else { 1 };
                par3_stream::coding_bytes(self.block_size, self.rows)
                    .saturating_mul(fields)
                    // Blocks past the GF(2^16) limit fail the set, so they
                    // bound the per-block state too.
                    .saturating_add(GF16_ORDER.saturating_mul(LANE_BYTES_PER_BLOCK))
                    .saturating_add(self.block_size)
            }
            SidecarFormat::Par2 => par2_stream::lane_bytes(self.block_size, self.rows)
                .saturating_add(par2_stream::MAX_SLICES * par2_stream::BYTES_PER_SLICE),
        }
    }

    /// Refuse a plan whose memory passes `--par3-memory-mib`.
    pub(crate) fn check_budget(&self, budget_mib: usize) -> Result<(), RarparError> {
        let needed = self.memory_estimate();
        let budget = (budget_mib as u64).saturating_mul(MIB);
        if needed > budget {
            return Err(RarparError::Resource(format!(
                "{} recovery block(s) of {} bytes need about {} MiB, more than --par3-memory-mib allows ({budget_mib} MiB)",
                self.rows,
                self.block_size,
                needed.div_ceil(MIB),
            )));
        }
        Ok(())
    }

    /// Every file the set will be written to, named by `stem`.
    pub(crate) fn paths(&self, stem: &Path) -> Vec<PathBuf> {
        let (index, volumes) = match self.format {
            SidecarFormat::Par3 => sibling_paths(stem, self.rows),
            SidecarFormat::Par2 => par2_stream::sidecar_paths(stem, self.rows),
        };
        std::iter::once(index)
            .chain(volumes.into_iter().map(|(_, _, path)| path))
            .collect()
    }

    pub(crate) fn start(&self) -> Result<Sidecar, RarparError> {
        let lane = match self.format {
            SidecarFormat::Par3 => {
                let mut lane = Lane::new(self.block_size, false, true);
                let fields: &[GaloisField] = if self.rows < 256 {
                    &[GF8, GF16]
                } else {
                    &[GF16]
                };
                for &field in fields {
                    lane.add_coding(
                        Coding::new(field, 0, self.rows, self.block_size)
                            .map_err(RarparError::Data)?,
                    );
                }
                lane.begin_chunk();
                Inner::Par3 {
                    lane,
                    digest: Box::new(FileDigest::new()),
                    size: 0,
                }
            }
            SidecarFormat::Par2 => {
                Inner::Par2(Par2Lane::new(self.block_size, self.rows).map_err(RarparError::Usage)?)
            }
        };
        Ok(Sidecar { plan: *self, lane })
    }
}

/// The plan `--sidecar`, `--sidecar-block-size` and `--sidecar-recovery-count`
/// ask for, or `None` without `--sidecar`. The output's length is unknown
/// until its last byte, so both numbers are required.
pub(crate) fn plan_from_args(args: &SidecarArgs) -> Result<Option<SidecarPlan>, RarparError> {
    let Some(format) = args.sidecar else {
        return Ok(None);
    };
    let missing: Vec<&str> = [
        (args.sidecar_block_size.is_none(), "--sidecar-block-size"),
        (
            args.sidecar_recovery_count.is_none(),
            "--sidecar-recovery-count",
        ),
    ]
    .iter()
    .filter(|(absent, _)| *absent)
    .map(|(_, flag)| *flag)
    .collect();
    if !missing.is_empty() {
        return Err(RarparError::Usage(format!(
            "--sidecar needs {}: the set is computed as the output is written, before its length is known",
            missing.join(", ")
        )));
    }
    SidecarPlan::new(
        format,
        args.sidecar_block_size.unwrap_or_default(),
        args.sidecar_recovery_count.unwrap_or_default(),
    )
    .map(Some)
}

pub(crate) fn format_name(format: SidecarFormat) -> &'static str {
    match format {
        SidecarFormat::Par2 => "par2",
        SidecarFormat::Par3 => "par3",
    }
}

enum Inner {
    Par3 {
        lane: Lane,
        /// Boxed: the BLAKE3 tree state dwarfs the PAR2 variant.
        digest: Box<FileDigest>,
        size: u64,
    },
    Par2(Par2Lane),
}

/// A set being computed from its file's bytes.
pub(crate) struct Sidecar {
    plan: SidecarPlan,
    lane: Inner,
}

/// A computed set, written beside its destinations but not installed.
pub(crate) struct FinishedSidecar {
    pub(crate) staged: StagedSibling,
    pub(crate) report: Value,
}

impl Sidecar {
    pub(crate) fn feed(&mut self, data: &[u8]) -> Result<(), String> {
        let rows = self.plan.rows;
        match &mut self.lane {
            Inner::Par2(lane) => lane.feed(data),
            Inner::Par3 { lane, digest, size } => {
                lane.feed(data)?;
                digest.update(data, true);
                *size += data.len() as u64;
                // GF(2^8) stops being the set's field for good once the blocks
                // pass what it can hold; its rows are memory nothing will use.
                if lane.block_count() > GF8_MAX_BLOCKS || lane.block_count() + rows > 256 {
                    lane.codings_mut().retain(|coding| coding.galois() != GF8);
                }
                if lane.codings().is_empty() {
                    return Err(format!(
                        "{} blocks of {} bytes and {rows} recovery block(s) do not fit GF(2^16); use a larger block size",
                        lane.block_count(),
                        self.plan.block_size
                    ));
                }
                Ok(())
            }
        }
    }

    /// Finish the set for a file recorded as `name`, and write it beside the
    /// paths `stem` names.
    pub(crate) fn finish(
        self,
        name: &str,
        stem: &Path,
        overwrite: bool,
    ) -> Result<FinishedSidecar, RarparError> {
        let creator = par3_stream::creator_text();
        let block_size = self.plan.block_size;
        let (staged, report) = match self.lane {
            Inner::Par2(lane) => {
                let set = lane.finish(name).map_err(RarparError::Data)?;
                let staged =
                    par2_stream::write_sidecar(stem, &set, overwrite).map_err(output_error)?;
                let set_id: String = set
                    .set_id
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect();
                (
                    staged,
                    json!({"format":"par2","set_id":set_id,"block_size":set.slice_size,
                        "blocks":set.blocks,"recovery_blocks":set.recovery_blocks(),
                        "source_bytes":set.len,"field_bytes":2}),
                )
            }
            Inner::Par3 {
                mut lane,
                digest,
                size,
            } => {
                if size > 0 {
                    lane.end_chunk().map_err(RarparError::Data)?;
                }
                lane.finish().map_err(RarparError::Data)?;
                let geometry = sibling_geometry(
                    size,
                    Some(block_size),
                    RecoveryChoice::Count(self.plan.rows),
                );
                if lane.block_count() != geometry.blocks {
                    return Err(RarparError::Data(format!(
                        "the stream filled {} blocks where its geometry expects {}",
                        lane.block_count(),
                        geometry.blocks
                    )));
                }
                debug_assert_eq!(
                    geometry.galois,
                    reference_field(geometry.blocks, 0, geometry.recovery, 0)
                );
                let codings = lane.codings_mut();
                codings.retain(|coding| coding.galois() == geometry.galois);
                let Some(coding) = codings.first_mut() else {
                    return Err(RarparError::Data(
                        "the set's field cannot hold its input blocks".into(),
                    ));
                };
                coding.truncate(geometry.recovery);
                let runs = lane.checksum_runs();
                let spec = SetSpec {
                    id_name: name,
                    name,
                    file_size: size,
                    block_size,
                    galois: geometry.galois,
                    matrix_hint: Some(0),
                    quick_hash: digest.quick_hash(),
                    fingerprint: digest.fingerprint(),
                    chunks: lane.chunks(),
                    runs: &runs,
                    block_count: lane.block_count(),
                    creator: &creator,
                };
                let set = build_set(&spec);
                let rows = lane.codings()[0].rows();
                let staged = write_sibling(stem, &set, rows, overwrite).map_err(output_error)?;
                (
                    staged,
                    json!({"format":"par3","set_id":set.set_id.to_string(),
                        "block_size":block_size,"blocks":geometry.blocks,
                        "recovery_blocks":geometry.recovery,"source_bytes":size,
                        "field_bytes":geometry.galois.size}),
                )
            }
        };
        Ok(FinishedSidecar { staged, report })
    }
}

impl FinishedSidecar {
    /// Rename the staged set onto its paths; returns them and their sizes.
    pub(crate) fn install(self) -> Result<(Vec<PathBuf>, Vec<u64>), RarparError> {
        let outputs = self.staged.install().map_err(output_error)?;
        let sizes = outputs
            .iter()
            .map(|path| std::fs::metadata(path).map(|meta| meta.len()))
            .collect::<std::io::Result<Vec<_>>>()?;
        Ok((outputs, sizes))
    }
}

/// A writer that passes every byte it writes on to a [`Sidecar`], so the set
/// is computed from exactly what reached the output, in the same pass.
pub(crate) struct SidecarWriter<'a, W> {
    pub(crate) inner: W,
    pub(crate) sidecar: &'a mut Sidecar,
}

impl<W: Write> Write for SidecarWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.sidecar
            .feed(&buf[..written])
            .map_err(std::io::Error::other)?;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn output_error(error: std::io::Error) -> RarparError {
    match error.kind() {
        std::io::ErrorKind::AlreadyExists => RarparError::Unsafe(format!(
            "output exists; pass --overwrite to replace: {error}"
        )),
        std::io::ErrorKind::InvalidInput => RarparError::Unsafe(error.to_string()),
        _ => RarparError::Io(error),
    }
}

/// Check every file `plan` will write under `stem` before any byte is read,
/// and return them. Beyond [`preflight`], a PAR3 set follows `par3 create`'s
/// overwrite rule: replacing a set whose authenticated carriers it would not
/// all overwrite (a previous set with more volumes) is refused.
pub(crate) fn preflight_set(
    cli: &rarpar::cli::Cli,
    plan: &SidecarPlan,
    stem: &Path,
) -> Result<Vec<PathBuf>, RarparError> {
    let paths = plan.paths(stem);
    preflight(&paths, cli.overwrite)?;
    if plan.format == SidecarFormat::Par3 {
        crate::par3::reject_obsolete_sibling_carriers(cli, stem, &paths)?;
    }
    Ok(paths)
}

/// Refuse a planned output that is a link, or that exists without
/// `--overwrite`, before any byte is read.
pub(crate) fn preflight(paths: &[PathBuf], overwrite: bool) -> Result<(), RarparError> {
    for path in paths {
        crate::par3::reject_symlinks(path)?;
        if !overwrite && std::fs::symlink_metadata(path).is_ok() {
            return Err(RarparError::Unsafe(format!(
                "output exists; pass --overwrite to replace: {}",
                path.display()
            )));
        }
    }
    Ok(())
}
