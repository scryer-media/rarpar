# par3-rs test fixtures

The PAR3 sets here are part of the repository's **test corpus**: every file has
an entry in `test-corpus/sources.json` (digest, size and provenance), and the
corpus is published as a signed, content-addressed object set hydrated by
`cargo run -p xtask -- test-corpus fetch --profile par3`. See
`docs/test-corpus.md`. The repository carries no fixture bytes; `Cargo.toml`
sets `exclude = ["tests/fixtures/**"]`, so none of this ships in the crate.

Until the first corpus revision that carries these sets is published, the
ledger entries are placeholders (size 0, zero digest) *pending first
publication*, and there are no tests that read them yet: the publication comes
first, the tests after it.

## Recipe

**Every set here is written by the reference implementation, and nothing else.**
`par3cmdline` is pinned as a commit archive in
`bench/rarpar-bench/config/toolchains.json` (the reference has no release) and
compiled into a container image; `par3_sets` in
`bench/rarpar-bench/internal/testcorpus/par3_sets.go` writes each case's inputs
from a deterministic byte stream and runs one `par3 create` per case with
`-B` pointing at that case's `in/` directory:

```sh
cargo run --locked -p xtask -- bench toolchains build --only-images-for par3_sets
cargo run --locked -p xtask -- test-corpus generate --only par3_sets
```

The image is `linux/amd64`; build and run it on an x86-64 host. Each case is
one directory: `in/` holds the inputs exactly as the reference read them, and
`set.par3` plus `set.vol*.par3` are exactly what it wrote. No PAR3 packet is
ever hand-assembled or bit-edited (`AGENTS.md`, PAR3 rules): tests that need
damage make it in memory, on copies of the inputs.

| Case | What it pins |
| --- | --- |
| `gf8_packed` | four files with tails of every kind and a subdirectory; 4 KiB blocks, 20 % recovery, GF(2^8), five volumes, a comment |
| `gf16_blocks` | more than 128 input blocks, which moves the reference to GF(2^16) on block count alone |
| `gf16_by_recovery` | 100 input blocks and 200 recovery blocks: GF(2^16) because input + recovery exceeds 256 |
| `index_only` | no recovery blocks: an index file, no volumes, no Matrix packet |
| `tree` | nested directories through `-R`, identical files in different directories, an empty file |
| `tiny_inline` | files around the 40-byte tail threshold, block size left to the reference |
| `auto_block` | mixed sizes, block size left to the reference |
| `large_stream` | a 16 MiB file at 64 KiB blocks |
