# unrar-rs

A pure-Rust RAR archive **reader** and extractor. No C bindings, no shelling out
to `unrar`.

This crate reads existing archives only. It deliberately exposes no writer,
builder, or archive-creation API — see the licence note at the bottom, which is
the reason.

```toml
[dependencies]
unrar-rs = "0.3"
```

```rust
use unrar_rs::RarArchive;

let mut archive = RarArchive::open(std::fs::File::open("release.part01.rar")?)?;
for member in &archive.metadata().members {
    println!("{} ({} bytes)", member.name, member.unpacked_size);
}
```

## What it handles

- **RAR5 and RAR4**, including legacy RAR 1.5 / 2.0 / 2.9 archives, and SFX
  (self-extracting) archives.
- **Every RAR5 header type** — main, file, service, encryption, end — with vint
  decoding and header CRC32 validation.
- **Decompression**: Store, LZ (methods 1–5) with Huffman decoding and a sliding
  window, and PPMd variant H, plus the post-decompression filters (Delta, E8,
  E8E9, ARM).
- **Encryption**: AES with RAR-compatible key derivation, for both file data
  (`-p`) and encrypted headers (`-hp`).
- **Multi-volume sets**, with topology tracking and cross-volume member layout.
- **Metadata-only mode**, so you can inspect an archive without extracting it.
- **Path sanitisation**, so a hostile archive cannot traverse out of its
  destination directory.

## Streaming extraction

Beyond the usual read-a-file-from-disk path, members can be extracted through a
`VolumeProvider` — you supply the volume bytes, from wherever they live. Volumes
are addressed in the **set's own numbering** throughout, so a member whose first
segment lives in volume 5 asks the provider for volume 5.

That makes it possible to extract a member while its volumes are still arriving,
or to extract from volumes that never exist as files at all. It is what powers
[Weaver](https://github.com/scryer-media/weaver)'s direct-store pipeline, where
a stored member's payload is written straight to its destination as articles
arrive off Usenet.

## Verification

Extraction verifies by default, and the checks match what the format actually
provides: the whole-member CRC32 or BLAKE2sp, and — for a member split across
volumes — the per-part packed checksum each non-final part carries, so damage is
caught at the part that carries it rather than at the end of the member.

## Related crates

- [`par2-rs`](https://crates.io/crates/par2-rs) — PAR2 verification and repair,
  for recovering damaged volumes before extraction.
- [`reedsolomon-rs`](https://crates.io/crates/reedsolomon-rs) — the GF(2¹⁶)
  kernels underneath both.

## Licence

GPL-3.0-or-later, **with the additional UnRAR source-code restriction**:

> UnRAR source code may be used in any software to handle RAR archives without
> limitations free of charge, but cannot be used to develop RAR (WinRAR)
> compatible archiver and to re-create RAR compression algorithm, which is
> proprietary. Distribution of modified UnRAR source code in separate form or as
> a part of other software is permitted, provided that full text of this
> paragraph, starting from "UnRAR source code" words, is included in license, or
> in documentation if license is not available, and in source code comments of
> resulting package.

This is why the crate ships no compression or archive-writing API, and why
anything that links it inherits the same restriction.
