# `rarpar` Compatibility Notes

`rarpar` can be configured anywhere an UnRAR-shaped extraction command is
accepted. Official release artifacts use the single binary name `rarpar`; the
project does not ship binaries named `unrar`, `rar`, `par2`, or `par2repair`.

## UnRAR-Compatible Mode

When the first argument looks like an UnRAR command, `rarpar` enters
compatibility mode before parsing its native CLI.

Supported command shapes:

```text
rarpar x [switches] <archive-or-glob>... [dest]
rarpar e [switches] <archive-or-glob>... [dest]
rarpar t [switches] <archive-or-glob>...
rarpar l [switches] <archive-or-glob>...
rarpar lb [switches] <archive-or-glob>...
```

Supported compatibility switches:

```text
-y
-ai
-idp
-scf
-tsm-
-mlp
-vp
-o+
-o-
-or
-p
-p-
-pPASSWORD
-om
-om1
-om-
-riN[:S]
```

Unsupported modifying RAR commands, such as `a`, `d`, `rn`, `rr`, and `rv`,
return an UnRAR-style command-line error.

## Incremental Extraction

`-vp` enables incremental extraction. `rarpar` opens the first volume, keeps the
archive alive, waits for the next volume when needed, and prints:

```text
Insert disk with <path> [C]ontinue, [Q]uit 
```

Responding with `C` retries the expected next volume. Responding with `Q` exits
with a fatal error. Members are extracted in archive order so solid archives
remain correct.

## Output Contract

Compatibility mode intentionally prints only operational extraction messages,
such as:

```text
Extracting from <archive>
Extracting  <path> OK
Creating  <path> OK
All OK
```

It does not print an UnRAR startup banner and does not claim to be official
UnRAR.

## PAR2

Native PAR2 support is available through:

```text
rarpar par verify <par2-or-dir> [search-dir...]
rarpar par repair <par2-or-dir> [search-dir...]
```

Top-level PAR2 `v`/`r` command aliases are not currently implemented.

## Recovery Volumes

RAR recovery volumes (`.rev` files) are handled through:

```text
rarpar rar restore-volumes <rar-or-rev>...
rarpar rar test-volumes <rev>...
```

`rar restore-volumes` covers what `rar rc` does for a `.rev` set: it rebuilds
missing or damaged data volumes, renaming a damaged one to `<name>.bad` before
rebuilding it in place. With `--dry-run` it reports what it would rebuild and
writes nothing. `rar test-volumes` covers `rar t name.rev`: each named `.rev`
header must parse and the CRC32 it records must match. RAR 3.0 name-form
`.rev` files record no CRC32, so they report as unverifiable and fail the test.

`rar test-volumes` tests only the paths it is given. `rar t name.rev` goes on
to test every `.rev` file of the set that follows `name.rev`, and
`rar t archive.part1.rar` tests the set's `.rev` files along with its
volumes. To test a whole set's `.rev` files with `rarpar`, name each of them.

There are no top-level `rc` or `t` aliases for recovery volumes. `rarpar rc`
returns an unsupported-command error like the other modifying commands, and
`rarpar t` tests archives, not `.rev` files.
