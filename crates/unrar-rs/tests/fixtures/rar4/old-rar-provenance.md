Old RAR oracle fixtures
=======================

Fixture provenance:

- `rar15_lz.rar`: `src/test/resources/com/github/junrar/audio/BoatModernEnglish-regular-unpack15-dos.rar`
- `rar20_lz.rar`: `src/test/resources/com/github/junrar/audio/BoatModernEnglish-regular-unpack20.rar`
- `rar20_audio_text.rar`: `src/test/resources/com/github/junrar/audio/BoatModernEnglish-audio-text-unpack20.rar`
- Expected bytes: `src/test/resources/com/github/junrar/audio/BoatModernEnglish.wav`

Upstream repository: https://github.com/junrar/junrar
Upstream commit: 57091f9ccd43661cf8f12c389917cc24950df707 (v8.1.0)
Upstream license: the UnRAR license (junrar's `LICENSE` is RARLAB's "UnRAR -
free portable version" text and its POM declares "UnRar License"; there is no
SPDX identifier, so `test-corpus/sources.json` records it as `LicenseRef-UnRAR`).
An earlier revision of this note said Apache-2.0; that was wrong.

These RAR 1.5 / 2.0 archives are immutable imports: they predate every writer
in the shared toolchain lock and are never assigned a RARLAB writer.

BLAKE3 (the digest `test-corpus/sources.json` records; these replace the SHA-256
values this note carried before the corpus moved to BLAKE3, and describe exactly
the same bytes):

- `rar15_lz.rar`: `e1bde199511d2ba4bcd099dff28766fef1a008b3fb47a8aa6008fc967d8cfb6b`
- `rar20_lz.rar`: `41687f8e8d2800926fa4e1fe437f74c658ba34b43be31075e619126ce115a798`
- `rar20_audio_text.rar`: `6e3ae224c6b075b6ba170d6b7e2da02fd6db4978cc788526cf52a0ce7441bf54`
- `../originals/boat_modern_english.wav`: `a69aeb9dfaaf0abb93fe4cecb32a549f0faf237fe4a5bcb24c5e8a6ca0327ec1`
