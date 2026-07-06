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
