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

SHA-256:

- `rar15_lz.rar`: `9c1deb8e11baa6fa1658c453b26a128a8437cefcbdeef3f4bcc499f6f7720a98`
- `rar20_lz.rar`: `3baa87e8e4f44628655d64954a03e79b28abf84261eba6b21e7244f27c104b79`
- `rar20_audio_text.rar`: `4144b4063f2f7c997b28b0bf42dc16cdb42ec913f271eecc47cd07b71335396e`
- `../originals/boat_modern_english.wav`: `0aeeb3c12f01d7089ca83eb321d5a54673ba0e6011231f5bc1fa10102ea3d797`
