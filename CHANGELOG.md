# Changelog

This file records user-visible `rarpar` CLI changes. Library API changes are
documented in each crate's own changelog so those notes ship with the crate.

## rarpar 0.6.1

### CLI Changes

- RAR3 PPMd members extract faster: `unrar-rs` 0.11.0 decodes them through
  the `ppmd-turbo` crate, 1.16-1.71x faster than 0.6.0 on the RAR4 PPMd
  fixtures (32 MiB order-16 member: 3.41 s wall, from 4.71 s). Output is
  unchanged, and a PPMd stream that overruns its packed data by more than 64
  bytes now fails at that symbol rather than at the next output flush. The
  `ppmd-debug` feature and `UNRAR_RS_RAR4_DEBUG_PPM` are gone.
- The libraries `rarpar` links changed license: `reedsolomon-rs` 0.4.11 and
  `par3-rs` 0.5.2 are Apache-2.0, and `unrar-rs` 0.11.0 is Apache-2.0 plus
  the unRAR license restriction. `par2-rs` stays GPL-3.0-or-later. The CLI
  itself is unchanged: GPL-3.0-or-later with its section 7 permission to
  combine with `unrar-rs`, and its binaries still carry the unRAR
  restriction.
- FFT-codec PAR3 repair needs less memory and runs faster: 1.2 to 1.9
  times faster on the measured hosts, and the 4096 × 16 KiB repair's charged
  peak falls from 137.9 MB to 15.8 MB. On AMD CPUs with AVX2 kernels, FFT
  create and repair also take a four-step transform where it measured
  faster. Output is unchanged.

### Library versions

- unrar-rs 0.11.0: RAR3 PPMd decoding through `ppmd-turbo` 0.1.1, a
  caller-set bound on the PPMd model arena (`Limits::max_ppmd_arena_size`,
  default the format's 256 MiB), and the move to Apache-2.0 plus the unRAR
  restriction.
- par3-rs 0.5.2 (pinned exactly): an FFT decode that keeps two banks of
  `capacity` rows (lower charged memory, faster repair), and the four-step
  transform on AMD CPUs with AVX2 kernels, on top of 0.5.1, the move to
  Apache-2.0.
- reedsolomon-rs 0.4.11: the four-step transform with its CPU gate, on top
  of 0.4.10, the move to Apache-2.0.
- par2-rs 0.10.8: unchanged.

## rarpar 0.6.0

### CLI Changes

- `par verify` and `par repair` read a damaged file once. The strict pass
  checks every slice's CRC32 and MD5 beside the whole-file hash and runs to
  the end of the file, so a damaged file no longer costs a second full read;
  verdicts are unchanged. Clean files pay more CPU for the slice hashes.
- `par repair` no longer re-reads and re-hashes the recovery packets the set
  scan already authenticated while their volumes are unchanged on disk.

- The format probes that read the first bytes of every file in a directory
  (PAR3 sibling discovery and `auto` classification) no longer pull in
  read-ahead (random-access advice on Linux, `F_RDAHEAD` off on macOS). A
  Linux NFS client that had cached a probed file's read-ahead split every
  later mebibyte read of that file into two requests; `par3 verify` now
  reads a file over NFS in whole-mebibyte requests.
- `par3 verify` and `par3 repair` verify a source on an NFS or SMB mount in
  one pass, hashing it whole and by block together, so a damaged file is not
  read over the network twice; files on a local disk are still hashed whole
  first.
- `par3 verify` and `par3 repair` read a source in whole-mebibyte requests
  instead of 64 KiB ones, and repair reads each recovery and data packet it
  uses once, authenticating it from the bytes it decodes.
- `rar restore-volumes`, and the extraction commands that restore a missing
  volume from RAR3 (RAR 2.9-4.x) `.rev` files, rebuild those volumes about
  eight times faster: the decoder is applied as a matrix to whole regions on
  every core instead of byte column by byte column. Restored volumes are
  byte-identical to before.
- Restoring several missing volumes from RAR5 `.rev` files multiplies on every
  core: about twice as fast with eight of 41 volumes missing.
- Restoring from `.rev` files reads and checks the volumes side by side,
  hashes restored volumes as they are written, and for RAR5 checks the intact
  data volumes during the decode instead of reading them twice. Restoring a
  2.1 GB set with one or eight of 41 volumes missing now takes about 0.25 to
  0.33 s for either RAR3 or RAR5, against 1 to 5.6 s for RARLAB unrar 7.20.
  Damaged volumes are renamed to `.bad` exactly as before.
- **Experimental:** `rarpar par3 inside insert|verify|repair|remove` embeds
  PAR3 recovery inside existing RAR5 archives and RAR5 volume sets made by
  RARLAB rar, verifies and repairs them from it, and takes it out again. The
  region layout is not part of the PAR3 specification yet: it may change
  before it is stable, and output from this version may not verify with a
  later one. Every run says so on stderr (silenced by `--quiet`), `--json`
  reports carry `"experimental": true`, and the help text starts with
  "EXPERIMENTAL:". No flag is needed to run it. The par3cmdline, unrar and
  7-Zip front ends do not read these regions.
- One PAR3 set covers a whole volume set, with one File packet per volume.
  Each File's chunks are the archive's bytes before the region, one
  unprotected chunk holding the region, and the bytes after it, so the File's
  hash is the hash of the original archive. Archive bytes are never changed,
  and no RAR archive is created or recompressed.
- `--layout trailing` (the default) appends the region after the
  end-of-archive header and any volume padding. It works on every RAR5
  archive, including ones with encrypted headers (`-hp`) and locked ones.
  `--layout service` instead places a stored `PAR3` service header with the
  skip-if-unknown flag before the end-of-archive header; it is refused for
  `-hp` and locked archives. `--layout block` uses an unassigned header type
  with the skip flag and is kept for comparison only.
- Reader behaviour after insertion, across 15 RARLAB-made fixtures (stored,
  compressed, solid, recovery record, quick open, comment, encrypted files,
  encrypted headers, locked, service headers, many files, SFX, and stored,
  recovery-record and solid volume sets) and one 4.6 GB archive, each listed,
  tested and extracted by RARLAB unrar 7.23, 7-Zip 7zz and unrar-rs and
  compared with the archive before insertion: trailing gives the same result
  in unrar and unrar-rs, and 7-Zip warns "data after end of archive"; service
  gives the same result in all three; block makes 7-Zip refuse the archive and
  unrar-rs warn about an unknown header.
- `--placement spread` (the default) gives every volume the set's metadata
  and an even share of the recovery packets, so any one volume, the first and
  last included, can be rebuilt. `last` puts all recovery in the last volume
  and cannot rebuild that volume; `independent` writes one set per volume and
  cannot rebuild any lost volume. Rebuilding a lost volume needs about one
  volume's worth of recovery: on a 1 GiB set of ten volumes it failed at 2%
  and 5% and succeeded at 11%, 12% and 15%.
- `insert` takes `-s`, `-c` and `-r` (5% by default) as `par3 create` does;
  the default block size is the smallest power of two from 4096 that keeps
  at most 2048 blocks. Output goes to `-d DIR` or, with `--in-place`, over the
  input. Insertion is deterministic: the same archive and options give the
  same bytes. RAR4 archives, unknown trailing data and archives that already
  hold PAR3 packets are refused.
- `verify` finds the other volumes of a set by the names recorded in the set
  and by `.partN.rar` numbering, follows renamed sets, and reports each
  volume's data and region separately. A missing volume that no set covers
  is reported and fails the run.
- `repair` rebuilds damaged and missing volumes in place, keeping numbered
  backups (`--no-backup` to drop them), or into `-d DIR`. It rebuilds the
  region as well as the data: the layout and packet count are solved from the
  region's checked length, and lost recovery packets are recomputed from the
  rebuilt data, so the output matches the protected file byte for byte.
- `remove` writes the archives without their regions, checked against the
  hash recorded in the set; the result is byte-identical to the original.
- On 1 GiB (one archive, stored random data) inserting took 0.72, 0.88 and
  1.5 s wall at 2%, 5% and 15%, for regions of 22, 55 and 162 MB, and
  repairing burst or scattered damage took 1.6 to 2.6 s. RARLAB `rar` adds a
  recovery record of about the same size in 1.0 to 1.7 s and repairs a burst
  in 4.4 to 8.8 s; at 2% it could not repair the scattered damage PAR3
  repaired. Neither recovers an archive whose end, with the region, is cut
  off.
- RARLAB `rar r` on an archive holding a region: with the archive intact, or
  with only the region damaged, it reports nothing to repair and writes
  nothing. With damaged data and a recovery record it writes `fixed.NAME`,
  repaired and byte-identical to the original archive, without the region,
  for all three layouts; inserting again under the original name reproduces
  the protected file byte for byte. Without a recovery record it writes
  `rebuilt.NAME`, also without the region, with the damaged data still
  damaged; `par3 inside repair` restores that archive exactly.
- New `sevenz` feature, on by default, brings in sevenz-turbo (7z reading
  and writing) and blake3. Builds without it behave as 0.6.0 did.
- `rarpar par3 archive OUTPUT.7z INPUTS...` writes a 7z archive and computes
  its PAR3 recovery data from the bytes as they reach the disk, in one pass,
  without reading the archive back. By default the set is written beside the
  archive as `OUTPUT.par3` and recovery volumes, laid out as
  `par3 c -s<size> -c<count>|-r<percent>` lays them out over the finished
  archive; with `--inside` it is appended after the 7z end header, laid out
  as `par3 i -r<percent>` appends it. 7z readers stop at the end header and
  ignore it. Options: `--base-path`, `--level 0..9` (0 stores), `--filter`
  (x86, arm, arm-thumb, arm64, ia64, sparc, ppc, riscv), `--no-solid`,
  `-s`/`-c`/`-r` for the sibling set, and `--inside` with `-r 0..250`.
  Archives that fit in half of `--par3-memory-mib` are held and coded at the
  end; larger ones are coded as they stream. A final layout no streaming lane
  covered falls back to one read of the finished archive, reported as
  `read_back` in `--json` output. Every non-Creator packet is byte-identical
  to par3cmdline 0.0.1's over the same archive.
- `rarpar par3 archive --format zip OUTPUT.zip INPUTS...` writes a ZIP
  instead, through the zip crate: each file stored (`--level 0`) or deflated
  on its own through flate2's zlib-rs backend at `--level 1..9`, with no
  encryption. Deflate runs as one stream per member, on one thread. The
  writer streams, with data descriptors, so no byte is rewritten; members
  larger than 4 GiB less 16 MiB get ZIP64 sizes from the start, and the archive gets the
  ZIP64 end records when it passes 4 GiB or 65,535 entries. Directories are
  stored with a trailing slash, and every entry keeps its modification time
  (local time, 1980 to 2107) and, on Unix, its permission bits. `--filter`
  and `--no-solid` are 7z only and refused with `--format zip`. The sibling
  set is laid out as for 7z. With `--inside` the set follows par3cmdline's
  ZIP layout: the end records (22 bytes, or 98 with the ZIP64 records) form
  their own protected chunk after the data chunk, the packets follow as an
  unprotected chunk, and a copy of the end records ends the file as a fourth
  chunk, protected by the same blocks as the original. Every non-Creator
  packet is byte-identical to par3cmdline 0.0.1's `i -r<percent>` over the
  same ZIP, and with the same Creator text so is the whole file. `--json` output now names the `format`.
- Where `--format zip --inside` differs from the request it was built to:
  - The copy of the end records after the packets is protected, as
    par3cmdline protects it, rather than only the original archive's bytes.
  - The central directory stays where the writer put it and only the end
    records are copied after the packets, as par3cmdline lays it out. The
    zip crate and par3cmdline read such a file, and 7-Zip reads it with a
    "data after the end of archive" warning and exit code 0; Info-ZIP `unzip` extracts it with a
    warning and exit code 2, and Python's `zipfile` refuses it.
  - A layout where par3cmdline's size estimate and the packets it writes
    would disagree (a data tail under 40 bytes ahead of whole footer
    blocks, which only a block size of 98 bytes or less can produce) is refused
    rather than written.
- The par3cmdline front end now runs `vs` and `rs` on ZIP and 7z files that
  carry their PAR3 packets inside them, where 0.6.0 refused them:
  - `vs` judges such a file by its protected chunks alone, as par3cmdline
    does: "protected data is complete" when every protected chunk verifies,
    otherwise "damaged" with par3cmdline's count of available bytes. It
    never reports on the appended packets themselves.
  - `rs` restores the protected bytes, then refills the packet region as
    par3cmdline's `copy_inside_data` does: every complete packet still found
    in the damaged file, in file order, then zeros. The damaged file is kept
    as `<name>.1`.
  - `i`, `ti` and `d` are still refused: they write recovery data, which is
    left to `rarpar par3 archive --inside`.
- Three par3cmdline front-end lines that `v` and `r` share with `vs` and
  `rs` now match par3cmdline:
  - without a Root packet, the Creator, Comment and Start header lines are
    printed;
  - with a Root packet but no File packet, the message is "File Packet or
    Directory Packet is missing.";
  - the recovery block count is printed only when both a Matrix packet and a
    Recovery Data packet are held, and a 16-bit Cauchy repair prints
    "Computing Reed Solomon matrix:".
- rarpar accepts 7-Zip's extract, test and list command lines. Started under
  the name `7z`, `7za`, `7zz` or `7zr` (a link or copy of the binary), or as
  `rarpar 7z ...`, it runs `x`, `e`, `t` and `l` on 7z archives (single
  files, `.001` split sets, solid and non-solid, encrypted data and
  encrypted headers, with trailing data such as an inside PAR3 set). It
  decodes LZMA, LZMA2, PPMd, BZip2, Deflate and Copy, with the BCJ, BCJ2 and
  ARM64 filters and AES-256. It parses 7-Zip's whole switch table, so an
  unknown or malformed switch gets 7-Zip's "Command Line Error" and exit
  code 7. Of the switches, it acts on `-o`, `-p`, `-y`, `-ao[a|s|t|u]`,
  `-i`, `-x`, `-r`, `-an`, `-ai`, `-t`, `-so`, `-bso`, `-bse`, `-bb`, `-ba`,
  `-slt`, `-scrc`, `-sdel`, `-ssc`, `-spd`, `-spm` and `-mmt`, with list
  files (`@file`) and wildcards in archive and member names. It prints
  7-Zip 26.01's lines on standard output and standard error, including the archive information block, `l` and `l -slt`
  listings, overwrite and password prompts on standard input, per-item
  errors ("CRC Failed", "Data Error", "Wrong password?", "Unexpected end of
  data", "Unsupported Method"), the closing summary and `-scrc` sums, and
  exits with 7-Zip's codes (0, 1, 2, 7, 8, 255). Extracted files are
  byte-identical to 7-Zip's, with the same names, modes and times. The
  command lines SABnzbd and NZBGet run work unchanged.
- Where the 7-Zip front end differs from 7-Zip:
  - Only 7z archives (and `.001` split sets of them) are read. `-t` with any
    other type fails to open the archive, as 7-Zip does for a 7z file opened
    as that type. ZIP, RAR and the other formats 7-Zip reads are not
    supported.
  - The commands `a`, `u`, `d`, `rn`, `h`, `b` and `i` fail with "Unsupported
    command" and exit code 7, the error 7-Zip gives for an unknown command.
    Creating archives is left to `rarpar par3 archive`.
  - The banner is one line, "rarpar VERSION (7-Zip compatible decoder) :
    Copyright (c) the rarpar authors", and the help text lists only the
    supported commands and switches.
  - No progress output is printed.
  - `-si` (archive from standard input) is a command-line error.
  - `-scrc` computes CRC32 only; other hash types are a command-line error.
  - The other switches are accepted and ignored. Names are always read and
    printed as UTF-8 whatever `-scc` and `-scs` say, `-spf` paths are
    sanitised as without it, `-ax` excludes no archive, and `-t#` and
    `-tsplit` open the archive as 7z.
  - A member whose data fails to decode keeps the bytes decoded before the
    fault, as in 7-Zip, but how many depends on the decoder's buffering. A
    damaged member may keep fewer bytes than 7-Zip keeps, or, when its block
    fails within its first 4 KiB or, for LZMA2, within the failing chunk,
    may not be created at all.
  - On Windows, symbolic links are written as regular files holding the link
    target, and times are shown in UTC.
  - When writing an output file fails, the per-item error and the closing
    "System ERROR" text approximate 7-Zip's.
- rarpar's compatibility front ends now cover the consumer side only:
  decoding, verifying, repairing and listing. Creating recovery data stays
  with rarpar's first-party commands, `rarpar par create` for PAR2 and
  `rarpar par3 create` for PAR3, which are unchanged. Each front end refuses
  the create side in its own tool's command-line style.
- rarpar accepts par3cmdline's verify, repair and list command lines. Started
  under the name `par3` (a link or copy of the binary), it runs `v`/`verify`,
  `r`/`repair` and `l`/`list` with the base path (`-B`), verbosity (`-v`,
  `-q`), memory (`-m`) and search (`-S`) options, `--`, extra input files and
  wildcards, and prints par3cmdline's verification, repair and listing
  reports and its exit codes (0, 3, 4, 6, 8). `-h`, `-V` and `-VV` work as
  in par3cmdline. Started as `rarpar`, it takes a command line whose first
  word is a par3cmdline command and whose PAR file argument ends in `.par3`
  (`.zip` or `.7z` for `i`, `ti`, `d`, `vs` and `rs`). Such command lines
  previously reached the unrar front end; all others are routed as before.
- The par3cmdline front end refuses, with exit code 3, after par3cmdline's
  own argument checks (so a malformed option still gets par3cmdline's
  message, and `vs` on a file that is not a ZIP still exits 6):
  - the create-side commands `c`/`create`, `tc`, `e`/`extend`, `te`,
    `i`/`insert`, `ti` and `d`/`delete`, with a message that points to
    `rarpar par3 create`;
  - `vs` and `rs`;
  - the create-only switches `-b`, `-s`, `-r`, `-rm`, `-c`, `-cf`, `-cm`,
    `-u`, `-l`, `-n`, `-R`, `-D`, `-d`, `-e`, `-i`, `-lp` and `-C`, with
    par3cmdline's own "Cannot specify ... unless creating." messages;
  - `-fu`, `-ff` and `-abs`, which par3cmdline accepts with any command but
    which only shape creation, with a rarpar message.
- Removed: the par2cmdline front end (`par2 r ... set.par2`, as SABnzbd runs
  it) used to ignore every switch except `-B`, including par2cmdline's
  create-only ones. It now rejects `-b`, `-s`, `-r`, `-c`, `-f`, `-u`, `-l`,
  `-n` and `-R` with par2cmdline's own messages and exit code 3, as
  par2cmdline does, so a command line that par2cmdline would refuse is no
  longer silently repaired. Repair options (`-B`, `-q`, `-v`, `-p`, `-N`,
  `-m`, `-t`, `-T`) are still accepted. `c`/`create` and `v`/`verify` with a
  `.par2` argument now exit 3 with a message that points to `rarpar par
  create` or `rarpar par verify`; they used to reach the unrar front end and
  exit 7 as an unsupported command. The unrar front end already accepted
  only `x`, `e`, `t`, `l` and `lb` and is unchanged.
- Where the par3cmdline front end differs from par3cmdline:
  - Repair is all or nothing: rarpar never repairs part of a set.
    "Repair is possible partially." is never printed; a repair that is not
    possible changes nothing.
  - A misnamed input found among the extra files is used as a source and the
    file is rebuilt under its own name; par3cmdline renames it. "files have
    the wrong name" is never printed.
  - `-m` sets the engine's memory budget, and a budget too small to read or
    repair the set fails with exit code 8; par3cmdline treats it as a hint.
    Without `-m` the budget is 256 MiB, as for `rarpar par3`.
  - `-S` is checked between the extents searched in extra files, not inside
    one.
  - Permissions and timestamps are not checked or restored.
  - Recovery files beside the named PAR file are loaded in name order, not
    directory order.
  - Of the timing lines only the repair's "done in ... seconds." is printed,
    and the `-v` packet statistics are not printed.
  - `-V` prints "par3cmdline version 0.0.1 (rarpar facade)", and `-VV`
    prints a rarpar notice instead of par3cmdline's copyright.

### Fixes

- 7-Zip facade extraction stays inside the output folder: a member is never
  written through a folder that an extracted link created ("Dangerous link
  via another link was ignored"), files are opened without following a link
  at their own name, a link is judged from the folder it is created in, and
  a link target over 4096 bytes is refused while it streams. A link member's
  recorded mode is never applied through the link, so a target reached
  through a link already in the output folder keeps its own mode. A member whose
  solid block failed is reported as failed even when its own CRC matched.
- 7-Zip facade: after `--`, words starting with `@` are member names, not
  list files, and `-sdel` deletes an archive only when something was written
  from it: not when the member filters selected nothing, nor when the
  overwrite policy (`-aos`) skipped every destination.
- 7-Zip facade archive discovery: `-ax` excludes archives, so an excluded
  archive is never opened and never deleted by `-sdel`; `-ai`/`-ax` keep
  their own `r` recursion, so `-air!*.7z` finds archives in every folder
  below; and a folder named as the archive is walked without following
  links, so a self-referential link ends the walk and a link out of the
  folder finds nothing outside it.
- 7-Zip facade name matching follows `-spd`, `-spm` and the `w-` modifier
  everywhere 7-Zip does: the archive name, `-ai`/`-ax` and `-i`/`-x` all take
  them, so `-aiw-!set*.7z` or `-spd set*.7z` opens (and under `-sdel`
  deletes) only the archive literally named `set*.7z`, and the implicit `*`
  that selects every member stays a wildcard under `-spd`.
- 7-Zip facade: a folder that cannot be read while scanning for archives
  (the folder named as the archive, anything below it, or an `-air` walk)
  fails the command with 7-Zip's scan error and exit code 2, instead of
  counting as empty and exiting 0 with nothing processed. A wildcard name or
  `-ai` rule in one folder fails the same way when that folder or one of its
  entries cannot be read, even when another selector already found an
  archive, so `-sdel` never runs after an incomplete scan.
- 7-Zip facade: a command-line argument that is not valid Unicode is a
  command-line error (exit code 7). It was read with U+FFFD in place of its
  bytes, so it could name a different archive, which `-sdel` then deleted.
- 7-Zip facade: a password typed at the prompt is no longer echoed. Echo is
  switched off on a Unix terminal and on the Windows console while the
  password is read, and restored after; the Windows prompt already said it
  would not be echoed. Input that is not a terminal is read as before.
- 7-Zip facade: a link member refused as dangerous leaves nothing at its
  name, as 7-Zip's does, instead of the empty placeholder opened when its
  data began.
- 7-Zip facade: a Unix link target that is not UTF-8 is created byte for
  byte, not rewritten with U+FFFD into a link to a different name.
- par3cmdline facade: the block-map report is counted from ranges, so a set
  with a huge block count no longer walks every block; non-UTF-8 arguments
  reach the files they name byte for byte on Unix; `\` separates path
  components on Windows; every `-fu` spelling is remembered; unsupported
  options are refused before any file is read; hidden entries are no longer
  skipped and an unreadable directory entry no longer stops the listing;
  only regular files are bound to protected names, so a directory at a
  protected name reports the file missing; empty directories a set records
  are created without following links; a moved-file search has no byte or
  candidate ceiling; directory-tree ordering is linear rather than
  quadratic; a PAR filename given in another case on a case-insensitive
  filesystem finds its recovery volumes by their on-disk spelling. Verify
  and list read through a protected name that is a link to a regular file,
  as par3cmdline does, while repair still refuses to write through one.
- par3cmdline facade, PAR-inside (`vs`/`rs`): complete packets are copied by
  par3cmdline's own window rule, archive reads go through a mebibyte cache
  and repeated self-repair replaces the previous `.1` backup instead of
  failing.
- `par3 archive` checks every recovery-volume name before installing the
  archive, refusing a symbolic link and, without overwrite, an existing file;
  a volume is never written through a link. An archive path that would also
  be its own PAR3 index or a recovery volume (`set.par3`, in any case) is
  refused before anything is written. `--max-files` stops the input
  walk as soon as the limit is passed, the streaming lanes' memory budget
  counts the state kept per block and the archive bytes still buffered
  when the lanes start, so `--par3-memory-mib` is no longer exceeded by
  about half once an archive outgrows the buffer, ZIP member times are local times (DOS
  time has no zone), and setuid, setgid and sticky bits are kept in ZIP
  external attributes. An odd `--block-size` too large to round up to an
  even size is refused as a usage error instead of aborting.
- `par3 inside repair` puts a lost host beside the surviving hosts of its
  own set when one command repairs sets from several directories, and a
  `--dry-run` repair reports `"status": "planned"` with `"dry_run": true`
  instead of `"repaired"`. A `--dry-run` removal refuses a missing or
  damaged host as a removal would, and reports `"status": "planned"` with
  `"dry_run": true` for an intact set. A `--dry-run` insertion no longer
  creates the `-d` output directory or in-place staging directories, and
  still refuses an existing output. In place, `insert`, `repair` and
  `remove` stage each output in its own volume's directory, so the final
  rename never crosses a filesystem.
- `par3 inside repair` and `remove` refuse a host name recorded in the set
  that is not one safe file name (absolute, `..`, or a separator) before
  writing anything, so an output never lands outside the chosen directory.
  Missing-volume gaps are enumerated only up to the volumes present plus the
  hosts the sets record, so a volume renamed to a huge `.partN.rar` suffix
  yields a report instead of unbounded work. Only regular files count as
  present volumes, so a directory named like a missing `.partN.rar` volume
  no longer masks it and lets verification report the set healthy.
- Release binaries are built with the `sevenz` feature, so `par3 archive`
  and the 7-Zip facade ship in them, and the `cargo xtask` feature audit
  refuses a release build without it.
- `par3 verify` and `repair` assess the set once unless a placement search
  ran, resolve each carrier directory once, sniff each sibling once, and take
  a directory entry's type from the listing; on a three-file set with 52
  recovery blocks, verify drops from 181 path stats to 60 and repair from 324
  to 111, with the same bytes read.
- `par verify` and `repair` read and hash the PAR2 volumes once instead of
  twice; on ten 3 MiB files with 10% recovery, verify reads 34.7 MB instead
  of 37.9 MB. Volume discovery no longer opens a file the set protects at its
  recorded length when no PAR2 volume can have that length (under 64 bytes
  or not a multiple of 4), as `par2_rs::identify_par2_files_for_set` does;
  any other protected file has only its 64-byte header read, so an
  obfuscated volume renamed onto a missing file's name and exact length is
  still found and the set repaired.
- `par verify` and `repair` of a set whose named `.par2` is its only file
  build the set from the parse volume discovery already made, so that file
  is parsed once instead of twice. With other volumes the whole list is
  parsed together, so one budget meters it and slice checksums described in
  another file are kept.
- RAR volume discovery for a named archive (the unrar facade and
  `rarpar rar`) no longer resolves the real path of every file in the
  directory: the archive is matched by the spelling it was given, and only a
  file that could carry its real name is resolved. A six-volume set beside
  eight unrelated files goes from 27 path resolutions (14 of the first
  volume) to 1.
- `par3 verify` and `repair` of a named carrier no longer sniff the files the
  set protects when looking for renamed carriers beside it: the `.par3`
  carriers are scanned first and only the other siblings are sniffed. Ten
  protected files beside the set: verify opens 14 files instead of 24.
- `par3 archive --overwrite` with the archive under an input directory no
  longer packs the previous archive, its PAR3 index or its recovery volumes
  into the new archive. On Windows and macOS the recovery volumes match
  without regard to case, as their default volumes name files, so `SET.7z`
  rebuilt beside `set.vol0+1.par3` no longer packs that stale volume.
- `par3 archive` counts each recovery row's own allocation against
  `--par3-memory-mib`, so many recovery blocks of a small block size are
  refused before they are allocated instead of overrunning the budget.
- `par3 archive` writes and syncs the sibling index and recovery volumes
  beside their names before it installs anything, so a failed write (a full
  disk, say) no longer leaves the archive replaced and the previous set
  truncated.
- par3cmdline facade: `vs` and `rs` given a ZIP or 7z with a directory
  (`par3 vs sub/archive.zip`, or an absolute path) find it in that
  directory instead of reporting it missing.
- par3cmdline facade: the verbose header and the partial-set report print
  the Galois field generator of a Start packet declaring an eight-byte (or
  larger) field with its leading 1 spelled out, instead of shifting a 64-bit
  value out of range and panicking in an overflow-checked build.
- par3cmdline facade: `-S<n>` also stops a candidate scan already under way
  when the time is up, instead of letting one large extra file be searched
  to its end first.
- `par3 inside verify` and `repair` scope a missing volume's coverage to its
  own directory: a set elsewhere that records a volume of the same name no
  longer hides it, so the run reports it and fails.
- `par3 inside` lists each volume family's directory once and opens each
  volume once, however many volumes of the family are named.
- 7-Zip facade extraction on Unix is anchored to an open handle on the
  output folder: every folder on a member's way is opened (or made) relative
  to the folder above it without following links, and the member's file,
  link, overwrite removal and rename, and metadata go through the handle of
  the folder it lands in. A folder swapped for a link while extraction runs
  can no longer redirect a member outside the output folder, and a new file
  is created exclusively, so a link or hard link planted at its name is
  refused rather than truncated. On Windows the folders are still checked
  and then opened by path, which keeps a member inside the output folder
  only while no untrusted party can write to that tree during extraction.
- 7-Zip facade: a volume `-sdel` cannot delete is reported with its path and
  the system's reason, and counts as an error of its archive, so the summary
  lists the archive with errors and the command exits 2 instead of 0.
- `par3 inside` on Windows and macOS matches a `.partN.rar` family's stem
  without regard to case, as their default volumes name files: naming
  `set.part1.rar` beside `SET.part2.rar` opens and verifies every volume, and
  a missing volume is reported in the directory's spelling, instead of
  verifying only the named volume and reporting the family healthy. On Linux
  stems still match exactly.
- 7-Zip facade: an archive two selectors both name (a positional name and an
  `-ai` rule, say) is processed once, so `-sdel` deletes it once and exits 0
  instead of failing on the second pass, and without `-sdel` it is no longer
  extracted or prompted for twice.
- 7-Zip facade: a member's time or mode that cannot be restored after
  extraction is an error of that member, named with its path and the
  system's reason, so the summary counts it under `Sub items Errors` and the
  command exits 2 instead of 0.
- `par3 archive` without `--overwrite` installs the archive with a
  no-clobber rename, so an archive that appears at the output name while
  the build runs is refused as "output exists" instead of replaced; the
  preflight only saw the name before the build began.
- rarpar requires unrar-rs 0.10.9, the version that carries the restore and
  decoder fixes it advertises, so a lockfile cannot resolve an older one.
- `par3 inside insert --placement independent -d DIR` removes the outputs of
  the sets it already inserted when a later volume's set fails, so a failed
  run no longer leaves earlier volumes behind for a retry to refuse. A
  shared set, `par3 inside repair` and a host bound across directories get
  the matching par3-rs fixes below.

### Library versions

- par3-rs 0.5.0 (pinned exactly): mebibyte source reads, the verification
  order by mount kind, single-read packet authentication during repair,
  `session_repair::create_directory`, and the RAR5 PAR-inside support and
  fixes.
- par2-rs 0.10.8: strict verify reads a damaged file once, repair planning
  trusts the scan's recovery packet authentication while a volume's stat is
  unchanged, and `identify_par2_files_for_set` skips the files a set
  protects that are present at recorded lengths no PAR2 volume can have.
- reedsolomon-rs 0.4.9 and unrar-rs 0.10.9: the RAR recovery-volume restore
  above.
- sevenz-turbo 0.26.1, zip 8.6 (with flate2's zlib-rs backend) and blake3
  for the `sevenz` feature; crc-fast, filetime and libc are now also used by
  rarpar itself.

## rarpar 0.5.4

### CLI Changes

- PAR2 inspection and repair retain valid recovery packets following a corrupt
  packet length and prefer valid copies over corrupt duplicate exponents.
- PAR2 repair analysis reports a source-changed error instead of panicking when
  a source file grows between parallel scan phases; shrinking files also reject
  the stale scan.
- PAR3 repair confines output to the opened destination tree, rejects unsafe
  destination links and filesystem aliases, and uses exclusively created private
  staging directories. Ordinary source-file verification keeps its existing link
  behavior.

### Library versions

- par2-rs 0.10.7: authenticate recovery packets during the bounded file scan
  and reject changed source extents during parallel repair analysis.
- par3-rs 0.4.4: confine repair reads and installs to the opened output tree.
  Other library versions are unchanged.

## rarpar 0.5.3

### CLI Changes

- `rar extract` decodes RAR5 LZ members about 3.5% faster on x86-64 machines
  with AVX2 and BMI2 (any Intel Haswell or AMD Zen part onward). The symbol
  decoder is now compiled a second time for that feature level and chosen at
  runtime; the output is byte-identical and `RARPAR_LZ_DECODE_V3=0` pins the
  baseline loop. Other machines are unchanged.

### Library versions

- unrar-rs 0.10.8: the x86-64-v3 symbol decoder above; a NEON BLAKE2sp load
  that was undefined behaviour as written (it never misbehaved); streaming
  BLAKE2sp on NEON no longer copies every byte twice; a test-isolation fix in
  the LZ decoder's adaptive-engine test.
- par2-rs 0.10.6: documentation only, naming the upstream `crc-fast` change
  the VPCLMULQDQ CRC stopgap is waiting on.

## rarpar 0.5.2

### CLI Changes

- `par repair` no longer slows to a crawl, or fails outright, on an AVX2 x86
  machine without GFNI when a large number of blocks is missing. The JIT
  arithmetic tier kept per-output state that grew with the missing-block count
  and was paid for out of the same repair memory budget as the data buffers,
  so past about a thousand missing blocks the repair read the source files over
  and over: at 2048 missing blocks in a 2 GiB set a 36 s repair took 22
  minutes, and past about 2100 missing blocks the repair aborted with an
  XOR-JIT capacity error. The tier is now chosen only when its state costs the
  data chunk nothing, and a shortfall picks the other kernel and logs why
  instead of failing.
- `par repair` also uses the whole of its memory budget for its data chunk. It
  previously halved the chunk until it fit, leaving up to half the budget
  unspent and reading the sources more times than the limit required.
- `par repair` now works in a 128 MiB budget instead of 64 MiB. The budget
  sets how much of a slice the repair holds at once, so on a badly damaged set
  the old figure was itself a large part of the runtime.
- `RARPAR_PAR2_XORJIT=0` pins the non-JIT repair kernel on x86, for comparing
  the two.

### Library Versions

- `par2-rs` 0.10.5, for the repair kernel selection and chunk sizing above.
  `reedsolomon-rs`, `unrar-rs` and `par3-rs` are unchanged.

## rarpar 0.5.1

### CLI Changes

- `par create` computes recovery slices with an output-pruned GF(2^16)
  transform when that beats folding every source into every recovery row. The
  choice is automatic and the `.par2` output is byte-identical either way; the
  existing `--memory-mib` limit still bounds the whole creation, and a job the
  transform cannot win, or cannot fit, takes the previous path unchanged. An
  eight-file 4 GiB set at `-s 768000` went from 8.8 s to 4.5 s at `-r 5`,
  10.3 s to 7.5 s at `-r 15`, and 23.1 s to 9.0 s at `-r 30`, using less peak
  memory than before at both the default limit and `--memory-mib 256`. Set
  `RARPAR_PAR2_TRANSFORM=0` to force the old path.

- `par repair` can now reconstruct a heavily damaged set through a syndrome
  transform instead of the dense Reed-Solomon product. On a set where thousands
  of blocks are missing the dense arithmetic folds every surviving block into
  every missing one; the transform reaches the same bytes in far fewer passes
  over memory. It is chosen automatically, only when it wins and only when it
  fits inside the repair memory budget already in force, and it checks itself
  against the dense arithmetic on every pass, so an ordinary repair of a few
  blocks behaves exactly as before. `RARPAR_PAR2_TRANSFORM=0` pins the old
  path; `=1` forces the new one wherever it is admissible.

- `par verify` and `par repair` under the default smart placement no longer
  read a set that is already in place twice. The placement scan hashed every
  matching file in full, serially, before verification read it all again; a
  file already at its recorded name is now left to verification, and the
  remaining confirmations run in parallel. A clean eight-file 4 GiB verify
  went from 5.6 s to 0.6 s, the same as `--par-placement canonical`.

### Build Changes

- The crypto backend is now selected by an explicit feature rather than riding
  along with `runtime`. `crypto-aws-lc` forwards the AWS-LC backend to
  `par2-rs` and `unrar-rs` and is on by default; `crypto-rust` forwards the
  portable RustCrypto backends instead, for a build that must carry no C or
  assembly dependency. `runtime` forwards neither, so
  `--no-default-features --features runtime` now fails to compile — naming
  both features — instead of quietly resolving a backend.
- Every shipped artifact is still built with AWS-LC. The release and CI
  feature matrices name `crypto-aws-lc` explicitly, the release feature audit
  now requires all three packages to resolve it, and a new step reads the
  dependency graph of the exact feature list that was built and fails if
  `aws-lc-sys` is not in it.

### Library Versions

- `unrar-rs` 0.10.7 and `par2-rs` 0.10.4, for the backend feature scheme above,
  the placement scan fix, and the transform arms for create and repair;
  `unrar-rs` 0.10.7 also stops hashing a split streaming member with BLAKE2sp
  when no header names one.
  `reedsolomon-rs` 0.4.6 adds the GF(2^16) transform and the closed-form
  consecutive-exponent solve those arms run on.
  `par3-rs` is unchanged; it has no AWS-LC code path at all and gains no crypto
  feature.

## rarpar 0.5.0

### CLI Changes

- `par3 create` completes a recovery count or percentage to the whole rows that
  hold it when `--interleave` is set, so a request that is not a multiple of the
  cohort count no longer fails. `--first-recovery` names a row rather than a
  global recovery index for the same reason: an interleaved set takes a multiple
  of the cohort count, and anything else is refused as a command-line error
  naming that count instead of as an engine-state failure.
- A PAR3 operation refused because a name in the set breaks a name-safety rule
  now exits 3 (unsafe operation rejected) rather than 1. Creation raises it
  before it writes a byte of the set and repair before it writes a byte of any
  output, so nothing on disk has changed when it does.
- Keep repair dry runs read-only and reject layouts requiring explicit
  self-repair. Size CLI handle budgets for retained carrier collections, count
  only admitted carrier siblings, and expand inferred RAR cleanup members to
  their complete volume family.
- Retain authenticated PAR3 discovery packets across automatic repair and
  rediscovery, including renamed carriers. Defer PAR3 deficits until available
  PAR2 recovery has run, then reassess the affected sets.
- Reject overwrite plans leaving authenticated obsolete carriers and repair
  destinations that alias on the target filesystem. Apply Cauchy loss limits
  to repair dry runs and resolve cleanup membership against `-C`.
- Add `par3 create`, `par3 verify`, and `par3 repair`, using the bounded engine
  in `par3-rs` 0.4. Support FFT/interleaving, deduplication, Data packets,
  content placement, configurable volumes, dry-run creation plans, and explicit
  memory, worker, and repair-loss limits.
- Discover and repair PAR3 sets in `auto` before archive extraction. Handle
  independent copies and multiple sets, and preserve shared protection carriers
  during cleanup. Existing `par` commands continue to handle PAR2.
- Report file-coordinate damage, verified prefixes, cohort deficits, installed
  outputs, backups, and partial repair failures in human and JSON output.
- Keep creation durable by default, with an explicit buffered-write option.
  Embedded-container self-repair remains a library API.

### Libraries

- `unrar-rs` moves from 0.9.2 to 0.10.5. `rev` restores of a RAR3/RAR4 set no
  longer fail with `Bad file descriptor` when the missing volume is the set's
  last data volume, and they cost a fraction of the CPU they did: restoring a
  missing 1 MiB volume of the recovery fixture falls from about 3.0 s to 0.26 s
  on one core, byte-identical. A volume whose reader cannot report its length
  parses again, which 0.9.2's scan guard had broken for RAR4. Extraction gains
  BLAKE2sp hashing through the upstream `blake2s_simd` streaming state with
  runtime SSE4.1/AVX2 detection, cheaper RAR5 parallel-decoder literal replay,
  and a literal-run fix that keeps bounded progress when a pending filter holds
  the flush border. The parse-provenance flag, the incremental header prefixes,
  the shared KDF cache and the `Adaptive`/`Serial` decode modes are library APIs
  for streaming embedders; the binary keeps the unchanged `Auto` default and
  exposes no new option for them. See its
  [changelog](crates/unrar-rs/CHANGELOG.md).
- `par2-rs` moves from 0.9.1 to 0.10.2. The deferred short-block relocation
  sweep now reads only the bytes the scan cannot account for instead of
  byte-stepping the whole candidate once per open short length, so a damaged
  volume tail costs its own length rather than seconds; and the ordered
  canonical scan sizes its rolling buffer against the repair memory limit, so a
  set declaring a multi-gigabyte slice is scanned through a mapped window
  instead of aborting the process on an allocation it never reserved. `verify`
  and `repair` can also be cancelled while a very large candidate is being
  scanned. The extra-scan controls added in 0.10.0 are for the repairer API the
  CLI does not use. No API or option change reaches the binary. See its
  [changelog](crates/par2-rs/CHANGELOG.md).
- `par3-rs` is required at 0.4.2, the version the new `par3` commands are built
  against. It cuts and names an interleaved set's recovery carriers by row,
  bounds every repair stage's resident working set against an explicit memory
  budget, verifies large sources in a small admitted worker pool, prunes an FFT
  decode to the rows the caller reads, and refuses a set naming a path this
  platform could never write with `UnsafePath` rather than a generic
  engine-state error. See its [changelog](crates/par3-rs/CHANGELOG.md).
- `reedsolomon-rs` moves from 0.4.3 to 0.4.5. It carries the GF(2^8) region
  arithmetic and Cantor-field FFT primitives the PAR3 engine runs on, and a RAR3
  decoder that no longer clears and reallocates its syndrome and error-evaluator
  scratch on every call — the order-of-magnitude part of the `rev` restore
  saving above. See its [changelog](crates/reedsolomon-rs/CHANGELOG.md).

Every library the binary needs is now on crates.io at the version the workspace
carries, so the `[patch.crates-io]` block that stood in for the unpublished PAR3
engine and its arithmetic is gone. The CLI now names `unrar-rs`, `par2-rs` and
`par3-rs` by workspace path alongside the 0.10.5, 0.10.2 and 0.4.2 floors, so a
tagged binary is built from the tree it was cut from and the floors can no
longer drift silently behind the libraries beside them.

## rarpar 0.4.1

The 0.4.0 tag never produced a release: its build refused to link two
`aws-lc-sys` versions, because the copies of `par2-rs` and `unrar-rs` on
crates.io asked for incompatible ranges. 0.4.1 carries everything listed
under 0.4.0 below, with that conflict resolved and the RAR4 hardening added.

### Libraries

- `unrar-rs` moves from 0.9.0 to 0.9.2. RAR4 archives whose headers declare
  data that cannot exist now fail fast with `CorruptArchive` instead of
  hanging, panicking, or trying to decode gigabytes from a kilobyte; every
  reproducer the nightly fuzzing lane has saved since 2026-08-16 is covered.
  The checks run at header time or on paths the decoder reaches only once its
  input is exhausted, so legitimate archives pay nothing and the decode
  benches are unchanged within noise. `restore_volumes_from_paths` also
  restores missing volumes of a RAR5 set written with encrypted headers
  (`-hp`), which previously refused with "insufficient RAR5 recovery
  volumes". See its [changelog](crates/unrar-rs/CHANGELOG.md).
- `par2-rs` moves from 0.9.0 to 0.9.1: its optional `native-crypto` backend
  requires `aws-lc-sys` 0.45 rather than 0.44, matching `unrar-rs`. No API or
  behaviour change. See its [changelog](crates/par2-rs/CHANGELOG.md).
- `reedsolomon-rs` stays at 0.4.3.

## rarpar 0.4.0

### CLI Changes

- GPU acceleration is disabled on every platform. The `metal` and `wgpu`
  features are gone from the tool, `par create --backend metal` is no longer
  accepted, and the Apple Silicon release archive is CPU-only like every other
  archive. `--backend auto` still parses and resolves to the CPU path. The
  release feature audit now refuses any GPU feature request instead of
  admitting Metal on Apple Silicon.
- The VPCLMULQDQ CRC tier override the binary honours is renamed from
  `WEAVER_CRC32_VPCLMUL` to `RARPAR_CRC32_VPCLMUL`; values and semantics are
  unchanged and there is no alias. The `unrar-rs` runtime override knobs the
  binary inherits move from `WEAVER_*` to `UNRAR_RS_*` at the same time. A
  deployment that set the old names must rename them, which is why this is a
  minor release rather than a patch.
- A password named on the command line is now asserted on the archive after
  it opens, so members encrypted behind readable headers extract with it.
- RAR extraction goes through the `unrar-rs` 0.9.0 entry API. Output files are
  no longer preallocated to the member's declared size before extraction.

### Libraries

- `unrar-rs` moves from 0.5.5 to 0.9.0: the entry-handle extraction API, solid
  archives that refuse further extraction after an interrupted member instead
  of decoding wrong bytes, `volume_number` reported as absent when the format
  states nothing, and the `WEAVER_*` to `UNRAR_RS_*` knob rename. See its
  [changelog](crates/unrar-rs/CHANGELOG.md).
- `par2-rs` moves from 0.6.0 to 0.9.0: verification carried into repair without
  re-reading the payload, proven-slice verification, seeded-evidence scan
  settlement, and the CRC knob rename. See its
  [changelog](crates/par2-rs/CHANGELOG.md).
- `reedsolomon-rs` stays at 0.4.3.

### Dependencies

- Third-party crates move to their latest releases: `aws-lc-rs` 1.18.1 on
  `aws-lc-sys` 0.45, `cap-std` 4.0.3, `wgpu` 30.0.1, and the `wasmtime` test
  harness on 48, whose conformance test adopts wasmtime-wasi's `FsPerms`
  preopen API.

## rarpar 0.3.4

### Libraries

- `reedsolomon-rs` moves to 0.4.3, including guarded AVX512BMM capability
  detection for future SIMD dispatch work. See its
  [changelog](crates/reedsolomon-rs/CHANGELOG.md).
- `par2-rs` moves to 0.6.0. Repair scans now merge candidates before relocating
  unresolved short blocks, avoiding repeated relocation re-reads; its new
  `ScanDiagnostics` counters make that work observable. See its
  [changelog](crates/par2-rs/CHANGELOG.md).

## rarpar 0.3.3

### CLI Changes

- `par create` now warns on stderr for every zero-length input it excludes
  from the set (`skipping empty file (a PAR2 set cannot protect it): …`), on
  every noise level including `--quiet` — the same unconditional report
  `par2cmdline` gives, because an input the set will not protect is a warning,
  not progress chrome. `--json` reports the same list as the plan's
  `skipped_empty_files`. The exclusion itself is unchanged and matches the
  reference tool; details in the `par2-rs` changelog.

### Performance

- PAR2 creation now beats `par2cmdline-turbo` on every ARM class in the bench
  fleet: 1.22× on Cortex-A72 (was 0.54×), 1.10× on Neoverse V2 (was 0.77×),
  1.01× on Neoverse N1 (was 0.74×), and extends Zen 4 to 1.16× (>1 =
  `rarpar` faster), byte-identical sets throughout. The levers are a
  de-aliased, block-interleaved staging layout feeding sixteen-source CLMUL
  passes, a stripe-major banded pipeline with source hashing fused onto the
  encode bands, and a create-side kernel ladder correction on Zen 2; details
  in the `par2-rs` and `reedsolomon-rs` changelogs.
- Solid RAR4 archives no longer decode their first member twice (up to −33%
  wall on small solid PPMd archives); details in the `unrar-rs` changelog.

### Libraries

- `reedsolomon-rs` moves to 0.4.2. See
  [its changelog](crates/reedsolomon-rs/CHANGELOG.md).
- `unrar-rs` moves to 0.5.4. See
  [its changelog](crates/unrar-rs/CHANGELOG.md).
- `par2-rs` moves to 0.5.0 — a compatibility break, because bounding the
  packet inventory changed `scan_packets`'s return type and added a field to
  `Par2RepairerOptions`. See [its changelog](crates/par2-rs/CHANGELOG.md).

## rarpar 0.3.1

### CLI Changes

- Fixed a hang at 100% CPU when extracting RAR4 archives whose compressed
  payloads carry stacked delta+x86 VM filters (typical of compressed ELF
  binaries). Pre-existing since 0.2.4; details in the `unrar-rs` changelog.
- RAR4/RAR5 members whose filtered output straddles the declared member size
  now extract byte-identically to reference UnRAR (previously clamped a
  different way at decode time).
- The portable Linux musl builds — including the container image — now ship
  with the mimalloc allocator. This erases the musl allocator tax on
  allocation-heavy paths: the musl channel moves from ~5% slower than the
  glibc build to at or slightly ahead of it on the same hardware.

### Performance

- Encrypted RAR3/RAR4 extraction on x86-64 CPUs without SHA extensions flips
  from losing to reference UnRAR to beating it: 0.67–0.73× → 1.28–1.34× on
  Haswell (>1 = `rarpar` faster), from a rebuilt SHA-1 key-derivation path
  with runtime-dispatched SSSE3/AVX2 kernels. Hosts with SHA extensions were
  already ahead and are unchanged.
- PAR2 creation now beats `par2cmdline-turbo` outright on Zen 4 (1.13×) and
  Haswell (1.05×), while keeping `rarpar`'s write-and-revalidate commit.
- The published benchmark tables and charts were remeasured across all
  eleven machines on one workspace commit; per-class numbers are in
  [docs/benchmark.md](docs/benchmark.md).

### Libraries

- `reedsolomon-rs` moves to 0.4.1. See
  [its changelog](crates/reedsolomon-rs/CHANGELOG.md).
- `unrar-rs` moves to 0.5.1. See
  [its changelog](crates/unrar-rs/CHANGELOG.md).
- `par2-rs` moves to 0.4.1. See
  [its changelog](crates/par2-rs/CHANGELOG.md).
- `aws-lc-rs`/`aws-lc-sys` and the rest of the dependency tree were swept to
  current; the full workspace test matrix (1840 tests plus the slow-test
  corpus lanes) ran green on the swept tree.

## rarpar 0.3.0

### CLI Changes

- Added global `--par-placement smart|canonical`. `smart` remains the default
  and locates renamed or moved protected files by content. `canonical` limits
  PAR2 work to recorded paths and explicitly supplied search locations.
- Added the direct repair-compatible form
  `rarpar r [-B DIR] PARFILE [WILDCARD]`. The documented `rarpar par verify`
  and `rarpar par repair` commands remain the general interface.
- Explicit RAR discovery now probes only the selected archive's
  name-compatible siblings and recognizes extended old-style `.rNN`, `.sNN`
  through `.zNN`, numeric, and post-numeric volume names.
- In `auto`, volumes restored from `.rev` files remain beside their archive
  set. `--output` affects extracted payloads, not restored intermediate
  volumes.
- Relative archive paths are canonicalized before compatibility-mode set
  discovery, avoiding accidental sibling selection when the working directory
  changes.
- Header-encrypted multi-volume archives use their validated filename family
  to assemble sibling volumes when encrypted headers hide volume topology.
- Normal compatibility `x` and `e` extraction restores missing volumes from
  discovered `.rev` recovery files before extraction. Incremental `-vp` mode
  remains non-mutating and waits for later volumes through its continue/quit
  protocol.

### Libraries

- `reedsolomon-rs` moves to 0.3.0. See
  [its changelog](crates/reedsolomon-rs/CHANGELOG.md).
- `unrar-rs` moves to 0.4.0. See
  [its changelog](crates/unrar-rs/CHANGELOG.md).
- `par2-rs` moves to 0.3.0. See
  [its changelog](crates/par2-rs/CHANGELOG.md).
