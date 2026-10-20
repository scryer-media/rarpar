# rarpar command reference

The full detail behind the examples in the [README](../README.md). `rarpar --help`
and `rarpar <command> --help` list every flag.

## RAR

```bash
rarpar rar list archive.part1.rar
rarpar rar test archive.part1.rar
rarpar rar extract archive.part1.rar ./out
rarpar rar restore-volumes archive.part1.rar archive.part1.rev
rarpar rar restore-volumes --dry-run archive.part1.rar
rarpar rar test-volumes archive.part1.rev archive.part2.rev
```

### Recovery volumes

`rar restore-volumes` rebuilds missing or damaged data volumes of a set from
its `.rev` files. Name any volume or `.rev` file of the set; the rest of the
set is found beside it by name. Every named path must be one of the set's
volumes by its name: a path named otherwise, or one that numbers a data
volume past the set's count, is an error naming it, as are two files for one
volume, and the command exits 1. A file found beside the named ones that does
not fit the set is passed over. A damaged volume is renamed to `<name>.bad`
and rebuilt under its own name. With `--output DIR` the volumes are rebuilt
into DIR and damaged ones are left where they are. Without `--overwrite`, a
`.bad` backup or rebuilt volume that already exists stops the restore: exit 3
for a `.bad` backup, exit 1 for a volume. The restore prints
`restored M volume(s) (<names>) from K recovery volume(s) read`, where K
counts every valid `.rev` file it read and can be more than M, or
`nothing to restore: all data volumes valid`.

`--dry-run` plans the restore and writes nothing. To judge each volume as the
restore would, it reads every data volume of the set in full. It prints
`would restore M volume(s) (<names>) using M of K usable recovery volume(s)`,
followed by `; would set aside N damaged volume(s) as .bad` when the restore
would rename damaged volumes. Where the restore would fail, the dry run fails
with the restore's exit code: `insufficient recovery volumes: need M, have K
for <names>` exits 1, and without `--overwrite` an existing `.bad` backup
(exit 3) or rebuilt volume (exit 1) is refused in the restore's own words. A
set the planner cannot read fails with the error the restore would raise.

`--json` prints a `rar_restore_volumes` report (schema version 1) with
`dry_run`, `success`, `message`, and the dry run's `plan` or the real run's
`outcome`. The plan lists each data volume (`index`, `path`, `status`, the
`expected_size` and `actual_size` of a `wrong_size` volume, `output_path`,
`set_aside_path`) and each recovery volume (`slot`, `volume_number`, `path`,
`status`, `usable`), with `needed`, `usable_recovery_count` and `sufficient`.
A recovery volume is `usable: false` when the restore passes it over, for a
failed CRC32 or a number outside the set's recovery slots. The outcome lists
`restored_paths`, `used_recovery_paths` and `missing_volume_numbers`. A data
volume's `index`, a recovery volume's `volume_number` and the
`missing_volume_numbers` are zero-based positions in the whole set, data
volumes first: the set's first volume is 0, and slot 0 of a set with ten data
volumes is volume 10.

`rar test-volumes <REV>...` tests each named `.rev` file as `rar t` does: its
header must parse and the CRC32 it records must match. It prints one line per
path, in order: `<path>: OK`, a CRC32 mismatch with the expected and actual
values, an invalid header, a RAR 3.0 name-form volume (which records no
CRC32), a file that is not a recovery volume, a missing file, or
`<path>: unreadable (<kind>)` for a file it cannot open or read, naming the
I/O error kind (`is a directory`, `permission denied`), which does not stop
the other paths being tested. Only the named paths are tested; see
[the compatibility notes](rarpar-compatibility.md#recovery-volumes) for how
that differs from `rar t`. It exits 1 unless every path tests OK. `--json`
prints a `rar_test_volumes` report (schema version 1) with each path's
`format`, `status`, `expected_crc32` and `actual_crc32` for a `crc_mismatch`,
and the I/O error kind as `message` for an `unreadable` file. A RAR3 `.rev`
file's `format` is `rar4`, a RAR 3.0 name-form one's included.

`--quiet` silences both commands; the exit code still gives the result.

`auto` restores each set with `.rev` files after its PAR2 and PAR3 repairs
and before extraction. `auto --dry-run` plans each of those restores beside
the set's volumes and lists it as a `dry-run rar_restore_volumes` step, in the
JSON report's `executed_actions`; that report carries `dry_run: true`. A
damaged or missing volume whose path appears among the protected files of a
PAR2 set related to the RAR set, or of a PAR3 set `auto` repairs, counts as
repaired by the time the restore runs, and a `.rev` file of the set they
list counts among its usable `.rev` files by then. A protected name is
compared as the volume's directory compares names: one differing by case
alone matches where that directory folds case, never where it keeps case
apart. A restore short of `.rev` files is then deferred, not failed, when the
volumes no parity names fit within the usable `.rev` files: the step passes,
shows `[deferred]` in place of `[ok]`, carries `deferred_to` (`par2`, `par3`
or `par2+par3`) in the JSON, and its message ends
`; PAR2 repair runs first for <names>`, naming the volumes and `.rev` files
the parity rebuilds. The dry run does not check that the parity holds enough
recovery data for those files, and it still needs one `.rev` file of the set
to read to plan at all. A set whose restore cannot be planned is a failed
step, `cannot plan restore: <error>`, and the sets after it are still
planned. `auto --dry-run` exits with the code of the first set that fails.

## PAR2

For a named PAR2 input, volume discovery reuses the seed scan and first reads
siblings matching `name.*.par2`. Other sibling names, including protected
files at their recorded length, are deferred. If metadata is missing or
verification finds an incomplete file, discovery checks the deferred siblings
for matching recovery headers before reporting repairability. Obfuscated
volumes remain usable, including a volume at a missing protected file's name
and length. Directory and explicit wildcard inputs retain their requested
scope.


```bash
rarpar par verify release.par2
rarpar par repair release.par2
rarpar par create ./release/release --block-size 1048576 \
  --recovery-percent 5 part01.rar part02.rar
```

`par create` takes one OUTPUT path or stem followed by one or more explicit
FILE inputs. Directories, recursion, and file-list expansion are rejected. If omitted,
`--base-path` defaults to OUTPUT's parent, and input names are recorded relative
to that directory. Use `--block-size` or `--block-count` to choose source-block
sizing, then select recovery with `--recovery-percent` or the exact, long-only
`--recovery-count`. Recovery blocks begin at `--first-exponent`; volumes use the
variable scheme by default and can be selected as `uniform` with
`--volume-scheme`, then split with `--volume-count`. `--memory-mib` sets the
creator's bounded planning/working budget.

With the global `-o DIR`, a relative OUTPUT is written under DIR (an absolute
OUTPUT wins), but `--base-path` still defaults to the parent of OUTPUT as typed,
so the inputs are found where they were and an explicit `--base-path` is used
as given. `rarpar -o sets par create set.par2 input.bin` writes
`sets/set.par2` protecting `./input.bin`; verify it with the data's directory
as a search directory (`rarpar par verify sets/set.par2 .`).

Creation honors the global safety/reporting flags:

```bash
rarpar --dry-run --json par create ./release/release \
  --block-count 256 --recovery-count 16 \
  part01.rar part02.rar
rarpar --overwrite par create ./release/release --recovery-percent 10 \
  part01.rar part02.rar
```

Dry-run produces a creation-specific plan report and does not write PAR2 files.
Human progress is rate-limited and goes to stderr; JSON mode emits one final
structured creation report on stdout. Add `--quiet` to suppress human output.

Automation that already emits a PAR2-command-shaped repair invocation can use
the compatibility form directly. This form accepts repair mode, `-B` as a
separate or joined base-directory option, the PAR2 file, and an optional data
wildcard:

```bash
rarpar r -B ./release ./release/release.par2 "*.rar"
```

The explicit `rarpar par ...` commands remain the general-purpose interface.

`par verify` can check one protected file as it streams in, without saving it
first: give the set as a path and name the file the stream is with `--name`.

```bash
curl -s "$URL" | rarpar par verify release.par2 --name part01.rar
```

The stream is hashed one slice at a time in memory that does not depend on its
length. That slice must fit `--par3-memory-mib` (default 256 MiB) and the file
may have at most 32768 slices; a set that declares more exits 1 before any
slice is allocated. The report names the damaged slices, how many are missing from a short
stream or trail a long one, and whether the set's recovery blocks could repair
it; an intact stream exits 0 and a damaged one 1. An unknown `--name` exits 2
and lists the names the set protects. `par repair` works on files on disk only
and exits 2 when given `-` or `--name`.

## PAR3


```bash
rarpar par3 create release.par3 part01.rar part02.rar -s 1048576 -r 5
rarpar par3 verify release.par3
rarpar par3 repair release.par3
rarpar auto release.par3
rarpar par3 create fft.par3 part01.rar --codec fft --capacity-log2 8 \
  --interleave 1 --recovery-count 32 --volume-blocks 8
```

PAR3 creation takes an output stem (or `.par3` path) and explicit files. Names
are recorded relative to `--base-path`, which defaults to the current directory.
The defaults are Cauchy, one recovery packet, 1 MiB blocks, no deduplication,
and power-of-two recovery volumes. Opt into `--dedup aligned|sliding`,
`--data-packets`, `--volume-blocks`, or `--volume-bytes` as needed. FFT requires
`--capacity-log2`; `--interleave` counts extra cohorts and `--first-recovery`
selects the first recovery index. An interleaved set is cut and named by row —
one recovery index in each cohort — so `--first-recovery` takes a multiple of
the cohort count and a recovery count or percentage is completed to the whole
rows that hold it. Percentage sizing uses the block count after deduplication
and requires a second planning pass over sources.

`par3 create OUTPUT -` (or an absent FILE when standard input is not a terminal)
makes a set for one file read from standard input:

```bash
tar -c ./release | rarpar par3 create release.tar.par3 - \
  --name release.tar -s 1048576 -c 16
```

The stream's length is unknown until it ends, so `--name` (the file name the set
records), `-s/--block-size` and `-c/--recovery-count` are required, and options
that depend on the length or on seeing the data twice (`-r`, FFT, interleave,
`--first-recovery`, deduplication, data packets, volume sizing, `--base-path`,
`--scratch-dir`) are refused. The data is read once as it arrives and never
buffered or staged to a temporary file; memory is the recovery blocks plus a few
dozen bytes per input block (twice the recovery blocks until the stream passes
128 blocks, while the set's field is still open). OUTPUT is a stem or `.par3`
path, or an existing directory that takes `--name` inside it. The set is laid out
as `par3 archive` lays out its sibling sets; verify it against the saved file.

Use `--dry-run --json par3 create ...` to obtain output paths, sizes, block counts,
and scratch requirements without writing. Existing carriers require `--overwrite`;
creation stages and authenticates every output before installation and refuses
to overwrite an input. par3-rs flushes every file it writes but never fsyncs,
so by default `par3 create`, `par3 repair` and `par3 inside` issue no storage
barrier. `--fsync` on `par3 create`, `par3 repair`, and
`par3 inside insert|repair|remove` opts in:
once the run has succeeded, each file it wrote is opened and synced (parent
directories are not), and the JSON report records `"fsync": true`.
Installation is per file, not atomic for the entire set.
An overwrite that would leave obsolete authenticated carriers is rejected before
writing. Move the old set aside or choose a new output directory when changing
volume layouts.

Verification and repair accept a carrier or directory, matching sibling `.par3`
files and magic-detected renamed carriers by authenticated set identity.
`--set-id` selects among multiple sets.
`-C DIR` chooses the protected-data working directory, defaulting to the selected
carrier's directory; `--output` controls RAR extraction only. Repair replaces
a damaged file without keeping it unless `--backup` is given, which keeps it
as a numbered backup (`NAME.1`, or the next free number), and does not rewrite
clean files. Smart placement searches explicit
`--search-dir` candidates by content when recovery is insufficient; canonical
placement uses recorded paths only. JSON reports include file-coordinate damage,
verified prefixes, cohort deficits, and installed paths and backups.
Repair checks destination aliases using temporary name probes on the target
filesystem before binding files; it rejects names that collapse to one path.
Dry runs check existing paths without creating probes; missing-name collisions
are checked again during execution. Damaged embedded layouts with unprotected
ranges require the explicit self-repair API, including during dry-run validation.
The CLI sizes its shared handle ceiling for the selected carrier collection plus
32 execution handles, so retained Windows carriers do not consume repair headroom.
Explicit carrier discovery counts admitted candidates against `--max-files`;
smart placement separately counts the source files it inspects. Inferred RAR
members expand to their volume family for automatic and standalone cleanup.
Dry-run repair also enforces the configured Cauchy loss ceiling. Cleanup uses
the same `-C` data root as repair. Auto mode retains discovery packets and tries
available PAR2 recovery before returning a deferred PAR3 deficit.

PAR3 commands use the bounded session engine, including FFT and Data-only
recovery. Global `--par3-memory-mib` (default 256), `--par3-workers`, and
`--par3-max-lost-blocks` (default 4096 for Cauchy) control resources. The memory
budget covers engine allocations; CLI path/report storage is bounded separately
by `--max-files` and metadata limits. `auto` repairs before rediscovering and
extracting RAR inputs.

`par3 inside` (EXPERIMENTAL: the on-disk layout may change before it is
stable, and output from this version may not verify with a later one) embeds
PAR3 recovery inside existing RAR5 archives made by RARLAB `rar`, verifies and
repairs them from it, and removes it again: `par3 inside insert|verify|repair|remove`.
`insert` writes a protected copy of each archive, or of every volume of a
`.partN.rar` set, into `-d DIR` or `--in-place`, with one `PAR3` service record
added before the end-of-archive header (`--layout service`, the only layout);
members and other headers are copied unchanged, and `remove` restores the
originals byte for byte. `--placement spread|last|independent` chooses one set
shared across the volumes with the recovery spread evenly or all on the last
volume, or a separate set per volume; `-s`, `-c` and `-r` (default 5%) size
it. Archives with encrypted headers (`-hp`) need their password and get their
record header encrypted like the others. `repair` rebuilds damaged or missing
volumes in place, into `-d DIR`, or with `--backup`. RAR archives are never
created or recompressed. Container self-repair for damaged embedded layouts
with unprotected ranges and recovery-carrier
reconstruction remain library APIs rather than CLI commands.

## xz


```bash
rarpar xz compress data.tar                    # writes data.tar.xz
rarpar xz compress --level 9 --extreme --threads 8 data.tar
rarpar xz decompress data.tar.xz ./out         # writes ./out/data.tar
rarpar xz test data.tar.xz
rarpar --json xz list data.tar.xz
tar -c ./release | rarpar xz compress > release.tar.xz
curl -s "$URL" | rarpar xz decompress --threads 4 | tar -x
```

`xz compress [INPUT] [OUTPUT]` and `xz decompress [INPUT] [OUTPUT]` take a file,
or `-` for standard input or output; an absent INPUT is standard input when that
is not a terminal. Pipes are read and written as the data flows, never staged
to a temporary file, in memory that does not depend on the stream's length, and
a slow reader holds rarpar back rather than growing a buffer. OUTPUT defaults to INPUT with `.xz` added
(compress) or removed (decompress, where `.txz` becomes `.tar`), beside INPUT or
in the global `--output` directory; an existing directory as OUTPUT takes that
name inside it, and standard input defaults to standard output. When both
`-o DIR` and OUTPUT are given, a relative OUTPUT is placed under DIR keeping its
own subdirectories (`-o out ... sub/a.xz` writes `out/sub/a.xz`), an absolute
OUTPUT wins and ignores `-o`, and `-` is always standard output; `par3 create`
and `par3 archive` place their OUTPUT the same way. Inputs are
always kept, so `--delete-sources` is refused. An existing output requires
`--overwrite`; the output is staged beside its destination, installed only once
complete, and keeps the input's permissions and modification time. Compressed
data is not written to a terminal.

`--level` 0-9 and `--extreme` select the xz preset of that number; the default
is 6 with a CRC-64 check, and `--check` selects `crc32`, `crc64`, `sha256` or
`none`. The stream is cut into blocks of `--block-size` bytes, by default three
times the preset's dictionary (at least 1 MiB) as xz's threaded mode does, and
up to `--threads` blocks (default: available CPUs) are compressed at once. The
output bytes do not depend on `--threads`. A dictionary larger than the largest
block is shrunk to fit it. `--memory-mib` caps the estimated encoder memory by
running fewer threads; there is no cap by default.

Decompression and `xz test` verify every block's check. A file with more than
one block is decoded on up to `--threads` threads within `--memory-mib` (default
1024), with fewer threads when the largest block needs it; single-block files
and files the parallel decoder cannot map are decoded in one pass, whose
dictionary must fit the same limit. A pipe is decoded as it arrives: on several
threads, blocks whose headers record their sizes (as rarpar's and xz's threaded
output do) go to workers, and other blocks are decoded in order.
Concatenated streams and stream padding decode as one output. `xz list` reads
the index of every stream from the end of a file and reports each stream's
offset, sizes, check, padding and blocks. A pipe has no end to seek to, so
`xz list -` decodes it once and reports the sizes, the stream and block counts,
each block's uncompressed size and the first stream's check, with `unknown`
naming what a single forward pass cannot give. With `--json`, every action prints one
report; when the data itself goes to standard output, reports go to standard
error. A damaged stream exits 1, an exceeded memory limit 4, and a refused
output 3.

## Recovery sets written with the archive


```bash
rarpar xz compress --sidecar par2 --sidecar-block-size 1048576 \
  --sidecar-recovery-count 16 data.tar         # data.tar.xz + data.tar.xz.par2 + volumes
tar -c ./release | rarpar xz compress --sidecar par3 --sidecar-block-size 1048576 \
  --sidecar-recovery-count 16 --sidecar-name release.tar.xz > release.tar.xz
rarpar par3 archive --format zip --sidecar par2 -s 1048576 -c 16 set.zip ./release
```

`xz compress --sidecar par2|par3` and `par3 archive --sidecar par2|par3` feed
the archive's bytes, as they are written, to a PAR2 or PAR3 creator and write a
conventional one-file set (an index plus power-of-two recovery volumes) beside
the archive. The archive is never read back and nothing is staged to a temporary
file; memory is the recovery blocks, one block, and a few dozen bytes per input
block, within `--par3-memory-mib` for either format. The archive's length is
unknown until its last byte, so the block size and recovery count are fixed up
front: `--sidecar-block-size` and `--sidecar-recovery-count` (both required for
`xz compress`; on `par3 archive` they are aliases of `-s` and `-c`, and `-c`
defaults to 1). A PAR2 sidecar records the same packets in the same layout as
`par create` over the finished archive with the same block size and recovery
count, byte for byte. Verify and repair with `par verify|repair` or
`par3 verify|repair` against the archive.

An xz file names its set after itself (`data.tar.xz.par2`); `par3 archive`
names it after the archive's stem (`set.par2`, as its PAR3 sibling sets are
named). The set follows the archive's placement under `-o`, is staged beside
its names and installed after the archive, and every name it will take is
checked, with the same `--overwrite` and symlink rules, before a byte is
read. An archive written to standard output has no name to record, so
`--sidecar` there needs `--sidecar-name NAME`, the name the output will be
saved under (placed under `-o` like an OUTPUT); otherwise it exits 2. Neither
command writes multi-volume archives, so one set covers the one archive.
`par3 archive --format 7z --sidecar par2` is refused (exit 2): the 7z writer
writes its start header last, over bytes PAR2's whole-file MD5 has already
taken, so use `--sidecar par3` or run `par create` over the finished 7z.

## Placement and discovery

PAR2 placement defaults to `smart`, which can locate renamed or moved data by
content. For a conventional expected-path-only verification or repair, use:

```bash
rarpar par verify --par-placement canonical release.par2
rarpar auto --par-placement canonical ./release
```

Explicit RAR selection recognizes modern `partNN` names and old-style `.r00`,
`.s00`, and numeric volume sequences. Discovery probes only name-compatible
siblings for an explicitly selected multi-volume archive. During `auto`, RAR
volumes restored from `.rev` files stay beside the source set; `--output`
controls extracted payload placement, not those intermediate volumes.

Discovery controls are global:

```bash
rarpar --no-recursive inspect ./release
rarpar --max-depth 4 --max-files 5000 ./downloads
```

Directory inputs recurse by default with a maximum depth of 8 and a maximum of
20,000 files. Symlink directories are not traversed.

## Passwords

`rarpar` never prints passwords and does not include them in JSON output.

Use one or more non-interactive password sources:

```bash
rarpar --password-file passwords.txt ./release
RAR_PASSWORD='correct horse battery staple' rarpar --password-env RAR_PASSWORD ./release
rarpar --password-fd 3 ./release 3< passwords.txt
```

`--password-file` and `--password-fd` read newline-separated candidates.
`--password-env` reads one candidate from the named environment variable. If no
non-interactive candidate works and stdin/stderr are TTYs, `rarpar` prompts with
hidden input only when a password is needed.

Use `-p-` in UnRAR-compatible mode to disable prompting.

## Cleanup Safety

Cleanup is intentionally narrow. Automatic cleanup only considers files
positively identified as consumed source files for an extracted set:

- RAR volumes used for extraction
- Restored or repaired RAR volumes used for extraction
- `.rev` recovery volumes for that set
- PAR2 files used for that set
- PAR3 carriers whose authenticated sets protect only volumes of that archive;
  carriers shared with other protected data are retained

It does not delete unrelated sidecar files such as `.nfo`, `.sfv`, samples,
subtitles, or PAR2-protected data files. Standalone `cleanup` validates expected
outputs before deleting anything for a set.

## UnRAR-Compatible Mode

Tools that expect an UnRAR-shaped command can call the `rarpar` binary directly.
`rarpar` accepts these command forms:

```bash
rarpar x archive.part1.rar /dest/
rarpar e archive.rar /dest/
rarpar t archive.rar
rarpar l archive.rar
rarpar lb archive.rar
```

Supported compatibility switches include `-y`, `-ai`, `-idp`, `-scf`, `-tsm-`,
`-mlp`, `-vp`, `-o+`, `-o-`, `-or`, `-p-`, `-pPASSWORD`, `-om`, `-om1`, `-om-`,
and `-riN[:S]`.

`-vp` keeps the archive open, waits for later volumes, and prints the
incremental prompt expected by UnRAR-compatible callers. `rarpar` intentionally
does not print an UnRAR banner and does not claim to be official UnRAR.

Normal `x` and `e` extraction uses sibling `.rev` recovery files to restore
missing volumes before extraction. The incremental `-vp` path does not mutate
the archive set; it waits for each later volume instead.
