//! Real-archive coverage for the cross-volume stored-layout assembler.
//!
//! The unit tests inside `stored_layout` build [`RarVolumeFacts`] by hand, which
//! keeps them total and fast but leaves one thing unproven: that the header
//! shapes a real RAR writer emits are the shapes those tests assume. These
//! tests drive the same builder from checked-in archives written by RARLAB
//! `rar`, so the classification rules are held against the format as produced
//! rather than as described.
//!
//! Every test soft-skips when its fixtures are absent, so a checkout without
//! Git LFS payloads still runs the rest of the suite.
//!
//! See `tests/fixtures/README.md` for each set's provenance and the exact
//! command that produced it.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use unrar_rs::{
    ArchiveFormat, EncryptedStore, IneligibilityReason, KdfCache, MappedSlice, MemberEligibility,
    MemberKeying, PasswordCheck, RarArchive, RarVolumeFacts, RarVolumeHeaderEncryption,
    StoredLayoutBuilder, StoredMember, check_member_password, convert_crc32_to_mac,
    decrypt_cipher_range, decrypt_cipher_range_rar4, derive_rar5_material,
};

/// The corpus-wide fixture password, as `generate_encrypted.sh` and
/// `generate_stored_layout.sh` both set it.
const TEST_PASSWORD: &str = "testpass123";

/// The password the `-hp` (header-encrypted) fixtures were written with, which
/// differs from the corpus-wide one — see `tests/fixtures/README.md`.
const HP_PASSWORD: &str = "secretpass";

// ---------------------------------------------------------------------------
// Fixture loading
// ---------------------------------------------------------------------------

/// One archive set: its volumes' parsed facts alongside their true byte
/// lengths, which is what a whole-volume mapping has to add up to.
struct Fixture {
    name: &'static str,
    facts: Vec<RarVolumeFacts>,
    lens: Vec<u64>,
    paths: Vec<PathBuf>,
}

impl Fixture {
    /// Parse every named volume under `tests/fixtures/<dir>`, or `None` when any
    /// of them is missing.
    ///
    /// Missing-means-skip is deliberate: the fixtures live in Git LFS, and a
    /// checkout without the payloads should not turn into a wall of failures.
    fn load(name: &'static str, dir: &str, files: &[String]) -> Option<Self> {
        let base = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(dir);
        let paths: Vec<PathBuf> = files.iter().map(|file| base.join(file)).collect();
        if paths.iter().any(|path| !path.exists()) {
            eprintln!("skipping test: {name} fixtures not present");
            return None;
        }

        let mut facts = Vec::with_capacity(paths.len());
        let mut lens = Vec::with_capacity(paths.len());
        for path in &paths {
            let file = std::fs::File::open(path).expect("fixture readable");
            facts.push(
                RarArchive::parse_volume_facts(file, None).expect("fixture volume facts parse"),
            );
            lens.push(std::fs::metadata(path).expect("fixture metadata").len());
        }
        Some(Self {
            name,
            facts,
            lens,
            paths,
        })
    }

    /// [`Self::load`] for a test that may not silently skip.
    ///
    /// Missing-means-skip is right for a fixture that adds coverage to
    /// something already pinned by synthetic tests. It is wrong for a fixture
    /// that is the *only* check of its kind, because a corpus regression would
    /// then delete the check rather than fail it — and this one is exactly
    /// that: `a_rar4_encrypted_chain_is_one_cbc_stream_keyed_by_its_file_salt`
    /// is the only place RAR4 key derivation is validated against an archive
    /// `rar` itself wrote. Every synthetic RAR4 fixture on either side of the
    /// crate boundary is built with the same derivation it is later checked
    /// with, so a wrong KDF would agree with itself everywhere else.
    fn require(name: &'static str, dir: &str, files: &[String]) -> Self {
        Self::load(name, dir, files).unwrap_or_else(|| {
            panic!(
                "{name} fixtures are required, not optional: this test is the only \
                 real-archive check of RAR4 key derivation, and skipping it would \
                 leave nothing validating the KDF against bytes `rar` wrote. Fetch \
                 the Git LFS payloads under tests/fixtures/{dir}."
            )
        })
    }

    fn count(&self) -> usize {
        self.facts.len()
    }

    /// Build a layout, adding the volumes in a shuffled order.
    ///
    /// Arrival order is the property the builder exists to be indifferent to,
    /// so no fixture test is allowed to feed it volumes in order.
    fn build(&self, format: ArchiveFormat) -> StoredLayoutBuilder {
        let mut builder = StoredLayoutBuilder::new(format);
        for index in shuffled_order(self.count()) {
            builder
                .add_volume(index as u32, &self.facts[index])
                .expect("fixture volume accepted");
        }
        builder
    }
}

/// A fixed permutation of `0..n` that is neither ascending nor a plain reversal.
///
/// `n < 7919` and 7919 prime make `i -> (i * 7919 + 13) % n` a bijection, so
/// sorting by it yields a genuine permutation for every set size used here.
fn shuffled_order(n: usize) -> Vec<usize> {
    assert!(n > 0 && n < 7919, "permutation is only a bijection here");
    let mut order: Vec<usize> = (0..n).collect();
    order.sort_by_key(|index| (index * 7919 + 13) % n);
    assert_ne!(
        order,
        (0..n).collect::<Vec<_>>(),
        "the arrival order must not be sorted, or the test proves nothing"
    );
    order
}

fn parts(prefix: &str, range: std::ops::RangeInclusive<u32>, width: usize) -> Vec<String> {
    range
        .map(|part| format!("{prefix}.part{part:0width$}.rar"))
        .collect()
}

// ---------------------------------------------------------------------------
// Shared assertions
// ---------------------------------------------------------------------------

fn slice_len(slice: &MappedSlice) -> u64 {
    match *slice {
        MappedSlice::Member { len, .. }
        | MappedSlice::EncryptedMember { len, .. }
        | MappedSlice::Envelope { len }
        | MappedSlice::Unroutable { len } => len,
    }
}

fn total_len(slices: &[MappedSlice]) -> u64 {
    slices.iter().map(slice_len).sum()
}

fn envelope_len(slices: &[MappedSlice]) -> u64 {
    slices
        .iter()
        .filter(|slice| matches!(slice, MappedSlice::Envelope { .. }))
        .map(slice_len)
        .sum()
}

fn member_len(slices: &[MappedSlice]) -> u64 {
    slices
        .iter()
        .filter(|slice| {
            matches!(
                slice,
                MappedSlice::Member { .. } | MappedSlice::EncryptedMember { .. }
            )
        })
        .map(slice_len)
        .sum()
}

/// How far a member's packed bytes reach: its declared size, or the padded
/// cipher length when the member is encrypted.
fn packed_extent(member: &StoredMember) -> Option<u64> {
    match member.eligibility.encrypted_store() {
        Some(encrypted) => encrypted.cipher_size,
        None => member.unpacked_size,
    }
}

/// The mapping is a partition of each volume, not a set of interesting
/// fragments: every byte of every file lands in exactly one slice.
fn assert_maps_every_volume_whole(builder: &StoredLayoutBuilder, fixture: &Fixture) {
    for (number, &len) in fixture.lens.iter().enumerate() {
        let slices = builder.map_physical_range(number as u32, 0, len);
        assert_eq!(
            total_len(&slices),
            len,
            "{}: volume {number} mapping must cover the whole file",
            fixture.name
        );
        assert!(
            slices
                .iter()
                .all(|slice| !matches!(slice, MappedSlice::Unroutable { .. })),
            "{}: volume {number} is fully known once every volume is added",
            fixture.name
        );
    }
}

/// A member's logical offsets are the prefix sums of its parts' packed sizes —
/// the one value no header states.
fn assert_logical_offsets_are_prefix_sums(member: &StoredMember) {
    assert!(member.chain_complete, "{}: chain complete", member.name);
    let mut running = 0u64;
    for (position, part) in member.parts.iter().enumerate() {
        assert_eq!(
            part.logical_offset,
            Some(running),
            "{}: part {position} starts at the sum of the earlier parts",
            member.name
        );
        running += part.data_size;
    }
    assert_eq!(
        Some(running),
        packed_extent(member),
        "{}: a stored chain's packed bytes sum to the member's extent",
        member.name
    );
}

/// Split-chain checksum placement: only a non-final part states a hash of its
/// own packed bytes, and only the final part states the whole-member hash.
fn assert_packed_hash_placement(member: &StoredMember, crc32_format: bool) {
    let last = member.parts.len() - 1;
    for (position, part) in member.parts.iter().enumerate() {
        let final_part = position == last;
        assert_eq!(
            part.split_after, !final_part,
            "{}: only a non-final part continues into the next volume",
            member.name
        );
        assert_eq!(
            part.split_before,
            position != 0,
            "{}: only a non-first part continues a previous volume",
            member.name
        );
        if crc32_format {
            assert_eq!(
                part.packed_crc32.is_some(),
                !final_part,
                "{}: part {position} states a packed CRC32 iff it is not the final part",
                member.name
            );
        } else {
            assert_eq!(
                part.packed_blake2_hash.is_some(),
                !final_part,
                "{}: part {position} states a packed BLAKE2sp iff it is not the final part",
                member.name
            );
            assert_eq!(
                part.packed_crc32, None,
                "{}: a BLAKE2 archive states no packed CRC32",
                member.name
            );
        }
    }
}

fn only_member(builder: &StoredLayoutBuilder) -> &StoredMember {
    let members = builder.members();
    assert_eq!(members.len(), 1, "fixture set holds exactly one member");
    &members[0]
}

// ---------------------------------------------------------------------------
// 1. RAR4 multi-volume store — the `compression.version >= 20` packed-CRC path
// ---------------------------------------------------------------------------

/// RAR4 has no separate packed-hash field: a split part reuses `FILE_CRC` to
/// state the CRC32 of the bytes *that volume* holds, and only the final part's
/// `FILE_CRC` is the whole member's. Every non-final part therefore looks like
/// it is announcing a whole-member checksum, and a builder that believed the
/// first one would verify the member against a quarter of its bytes.
#[test]
fn rar4_multi_volume_store_takes_the_whole_member_crc32_from_the_final_part() {
    let Some(fixture) = Fixture::load("rar4_mv_store", "rar4", &parts("rar4_mv_store", 1..=5, 1))
    else {
        return;
    };

    // The fixture is on the RAR4 packed-CRC path, not the older RAR 1.5/2.0
    // layout that predates it.
    for facts in &fixture.facts {
        assert_eq!(facts.format, 4);
        for member in &facts.members {
            assert!(
                member.compression_version >= 20,
                "the packed-CRC path needs a RAR 2.0-or-later compression version"
            );
        }
    }

    // Every non-final volume states a CRC32 in *both* fields, and they agree:
    // that single value is the packed CRC of this volume's bytes, and reading
    // it as a whole-member checksum is exactly the mistake to guard against.
    for facts in &fixture.facts[..4] {
        let member = &facts.members[0];
        assert_eq!(member.data_crc32, member.packed_crc32);
        assert!(member.packed_crc32.is_some());
    }

    let builder = fixture.build(ArchiveFormat::Rar4);
    assert_eq!(builder.header_frontier(), Some(4));

    let member = only_member(&builder);
    assert_eq!(member.name, "binary.bin");
    assert_eq!(member.parts.len(), 5);
    assert_eq!(member.eligibility, MemberEligibility::DirectEligible);
    assert_eq!(member.unpacked_size, Some(262_144));

    // The whole-member value is the final part's, not the first part's.
    assert_eq!(member.data_crc32, Some(3_348_152_310));
    assert_ne!(member.data_crc32, fixture.facts[0].members[0].data_crc32);

    assert_packed_hash_placement(member, true);
    assert_logical_offsets_are_prefix_sums(member);
    assert_maps_every_volume_whole(&builder, &fixture);
}

// ---------------------------------------------------------------------------
// 2. RAR5 long chain — real prefix sums over more than twenty volumes
// ---------------------------------------------------------------------------

/// Twenty-seven volumes of one member, with the first and last parts sized
/// differently from the middle. A prefix sum over these cannot be confused with
/// `index * part_size`, so an offset assertion here is asserting the real thing.
#[test]
fn rar5_long_volume_chain_resolves_true_prefix_sums() {
    let Some(fixture) = Fixture::load(
        "rar5_mv_store_long",
        "rar5",
        &parts("rar5_mv_store_long", 1..=27, 2),
    ) else {
        return;
    };
    assert!(
        fixture.count() >= 20,
        "the long-chain fixture must exceed twenty volumes"
    );

    let builder = fixture.build(ArchiveFormat::Rar5);
    assert_eq!(builder.header_frontier(), Some(26));

    let member = only_member(&builder);
    assert_eq!(member.name, "Silver.Horizon.S01E04.mkv");
    assert_eq!(member.parts.len(), 27);
    assert_eq!(member.eligibility, MemberEligibility::DirectEligible);
    assert_eq!(member.unpacked_size, Some(49_152));

    // Non-vacuity: uniform part sizes would make every prefix sum a multiple of
    // one number, and the assertion below would hold for the wrong reason.
    let sizes: BTreeSet<u64> = member.parts.iter().map(|part| part.data_size).collect();
    assert!(
        sizes.len() >= 3,
        "part sizes must vary for a prefix-sum test to mean anything, got {sizes:?}"
    );

    assert_packed_hash_placement(member, true);
    assert_logical_offsets_are_prefix_sums(member);

    // Each part's own packed range maps back to that part's logical span.
    for (position, part) in member.parts.iter().enumerate() {
        assert_eq!(
            builder.map_physical_range(part.volume, part.data_offset, part.data_size),
            vec![MappedSlice::Member {
                member_index: 0,
                logical_offset: part.logical_offset.expect("resolved"),
                len: part.data_size,
            }],
            "part {position} maps to its own logical span"
        );
    }

    assert_maps_every_volume_whole(&builder, &fixture);
}

// ---------------------------------------------------------------------------
// 3. RAR5 quick-open service data
// ---------------------------------------------------------------------------

/// A quick-open block is a service header carrying a cached copy of the set's
/// file headers. It sits inside the volume but belongs to no member, so it must
/// fall to the envelope and leave the member mapping untouched.
#[test]
fn rar5_quick_open_service_data_falls_to_the_envelope() {
    let Some(fixture) = Fixture::load(
        "generated_matrix_rar5_store_plain",
        "rar5",
        &parts("generated_matrix_rar5_store_plain", 1..=7, 1),
    ) else {
        return;
    };

    // Non-vacuity: the point of the fixture is that quick-open data is present.
    for (number, facts) in fixture.facts.iter().enumerate() {
        assert!(
            facts.quick_open_offset.is_some(),
            "volume {number} carries quick-open data"
        );
        assert!(
            facts.services.iter().any(|service| service.name == "QO"),
            "volume {number} carries a QO service header"
        );
    }

    let builder = fixture.build(ArchiveFormat::Rar5);
    let member = only_member(&builder);
    assert_eq!(member.name, "generated_matrix_clip.mkv");
    assert_eq!(member.parts.len(), 7);
    assert_eq!(member.eligibility, MemberEligibility::DirectEligible);
    assert_packed_hash_placement(member, true);
    assert_logical_offsets_are_prefix_sums(member);
    assert_maps_every_volume_whole(&builder, &fixture);

    // Per volume: member bytes are exactly that volume's part, and everything
    // else — headers and the quick-open block — is envelope.
    for (number, &len) in fixture.lens.iter().enumerate() {
        let slices = builder.map_physical_range(number as u32, 0, len);
        let part = &member.parts[number];
        assert_eq!(member_len(&slices), part.data_size);
        assert_eq!(envelope_len(&slices), len - part.data_size);

        let quick_open = fixture.facts[number]
            .services
            .iter()
            .find(|service| service.name == "QO")
            .expect("QO service");
        assert_eq!(
            builder.map_physical_range(number as u32, quick_open.data_offset, quick_open.data_size),
            vec![MappedSlice::Envelope {
                len: quick_open.data_size
            }],
            "volume {number}: quick-open bytes are envelope"
        );
    }
}

// ---------------------------------------------------------------------------
// 4. RAR5 recovery records
// ---------------------------------------------------------------------------

/// A recovery record is service data appended to every volume. Like quick-open
/// data it is envelope, but it is far larger, so a per-volume sum that ignored
/// it would be visibly wrong rather than off by a rounding error.
#[test]
fn rar5_recovery_record_service_data_falls_to_the_envelope() {
    let Some(fixture) = Fixture::load(
        "rar5_mv_store_rr",
        "rar5",
        &parts("rar5_mv_store_rr", 1..=6, 1),
    ) else {
        return;
    };

    for (number, facts) in fixture.facts.iter().enumerate() {
        assert!(
            facts.has_recovery_record,
            "volume {number} carries a recovery record"
        );
        assert!(facts.recovery_record_offset.is_some());
        assert!(
            facts.services.iter().any(|service| service.name == "RR"),
            "volume {number} carries an RR service header"
        );
    }

    let builder = fixture.build(ArchiveFormat::Rar5);
    let member = only_member(&builder);
    assert_eq!(member.name, "Silver.Horizon.S01E05.mkv");
    assert_eq!(member.parts.len(), 6);
    assert_eq!(member.eligibility, MemberEligibility::DirectEligible);
    assert_eq!(member.unpacked_size, Some(16_384));
    assert_packed_hash_placement(member, true);
    assert_logical_offsets_are_prefix_sums(member);
    assert_maps_every_volume_whole(&builder, &fixture);

    for (number, &len) in fixture.lens.iter().enumerate() {
        let slices = builder.map_physical_range(number as u32, 0, len);
        let part = &member.parts[number];
        assert_eq!(member_len(&slices), part.data_size);
        assert_eq!(envelope_len(&slices), len - part.data_size);

        let recovery = fixture.facts[number]
            .services
            .iter()
            .find(|service| service.name == "RR")
            .expect("RR service");
        assert!(recovery.data_size > 0);
        assert_eq!(
            builder.map_physical_range(number as u32, recovery.data_offset, recovery.data_size),
            vec![MappedSlice::Envelope {
                len: recovery.data_size
            }],
            "volume {number}: recovery-record bytes are envelope"
        );
    }
}

// ---------------------------------------------------------------------------
// 5. RAR5 mixed store and compressed members
// ---------------------------------------------------------------------------

/// `rar -m3` still stores whatever it cannot shrink, so a single archive can
/// hold both stored and compressed members. The stored ones stay routable; the
/// compressed one is demoted and its packed bytes join the envelope.
#[test]
fn rar5_mixed_store_and_compressed_members_split_along_the_compression_flag() {
    let Some(fixture) = Fixture::load(
        "rar5_multifile_lz",
        "rar5",
        &["rar5_multifile_lz.rar".to_string()],
    ) else {
        return;
    };

    let mut builder = StoredLayoutBuilder::new(ArchiveFormat::Rar5);
    builder
        .add_volume(0, &fixture.facts[0])
        .expect("fixture volume accepted");

    let members = builder.members();
    assert_eq!(members.len(), 3);

    let stored: Vec<&StoredMember> = members
        .iter()
        .filter(|member| member.eligibility == MemberEligibility::DirectEligible)
        .collect();
    assert_eq!(
        stored
            .iter()
            .map(|member| member.name.as_str())
            .collect::<Vec<_>>(),
        vec!["hello.txt", "second.txt"],
        "the stored members stay direct-eligible"
    );
    for member in &stored {
        assert_eq!(member.parts.len(), 1);
        assert_eq!(member.parts[0].logical_offset, Some(0));
        assert!(member.data_crc32.is_some());
    }

    let compressed = members
        .iter()
        .find(|member| member.name == "zeros_64k.bin")
        .expect("the compressed member");
    assert_eq!(
        compressed.eligibility,
        MemberEligibility::Ineligible(IneligibilityReason::Compressed {
            packed_bytes: Some(44),
            unpacked_bytes: Some(65_536),
            totals_final: true,
        }),
        "a closed compressed chain reports both totals as final"
    );

    // Envelope bytes are the volume minus the direct members' packed bytes —
    // which means the compressed member's 44 packed bytes are in there.
    let len = fixture.lens[0];
    let slices = builder.map_physical_range(0, 0, len);
    let eligible_bytes: u64 = stored.iter().map(|member| member.parts[0].data_size).sum();
    assert_eq!(total_len(&slices), len);
    assert_eq!(member_len(&slices), eligible_bytes);
    assert_eq!(envelope_len(&slices), len - eligible_bytes);

    let packed = &fixture.facts[0].members[2];
    assert_eq!(packed.name, "zeros_64k.bin");
    assert_eq!(
        builder.map_physical_range(0, packed.data_offset, packed.data_size),
        vec![MappedSlice::Envelope {
            len: packed.data_size
        }],
        "a compressed member's packed bytes take the envelope path"
    );
}

// ---------------------------------------------------------------------------
// 6. RAR5 `-htb` BLAKE2
// ---------------------------------------------------------------------------

/// Empirical finding, fixed by `rar5_store_blake2.rar` against its CRC32 twin:
/// `-htb` *replaces* the CRC32, it does not add to it. RARLAB `rar` 7.20 writes
/// a BLAKE2sp digest and no `Data-CRC32` at all, so `Blake2OnlyNoCrc32` is a
/// state real archives reach, not a defensive branch.
#[test]
fn rar5_blake2_hash_type_replaces_the_crc32_and_demotes_the_member() {
    let Some(blake2) = Fixture::load(
        "rar5_store_blake2",
        "rar5",
        &["rar5_store_blake2.rar".to_string()],
    ) else {
        return;
    };
    let Some(control) = Fixture::load(
        "rar5_store_crc32_control",
        "rar5",
        &["rar5_store_crc32_control.rar".to_string()],
    ) else {
        return;
    };

    // The two archives hold the same members; only the hash switch differs.
    let names: Vec<&str> = blake2.facts[0]
        .members
        .iter()
        .map(|member| member.name.as_str())
        .collect();
    assert_eq!(
        names,
        control.facts[0]
            .members
            .iter()
            .map(|member| member.name.as_str())
            .collect::<Vec<_>>()
    );

    // The finding itself: BLAKE2 only, never both.
    for member in &blake2.facts[0].members {
        assert!(
            member.data_blake2_hash.is_some(),
            "{}: -htb writes a BLAKE2sp digest",
            member.name
        );
        assert_eq!(
            member.data_crc32, None,
            "{}: -htb writes no Data-CRC32 alongside it",
            member.name
        );
    }
    for member in &control.facts[0].members {
        assert!(member.data_crc32.is_some());
        assert!(member.data_blake2_hash.is_none());
    }

    let mut builder = StoredLayoutBuilder::new(ArchiveFormat::Rar5);
    builder
        .add_volume(0, &blake2.facts[0])
        .expect("fixture volume accepted");
    for member in builder.members() {
        assert_eq!(
            member.eligibility,
            MemberEligibility::Ineligible(IneligibilityReason::Blake2OnlyNoCrc32),
            "{}: BLAKE2sp cannot verify out-of-order writes",
            member.name
        );
    }

    // Same bytes, same layout, CRC32 instead: the members route.
    let mut control_builder = StoredLayoutBuilder::new(ArchiveFormat::Rar5);
    control_builder
        .add_volume(0, &control.facts[0])
        .expect("fixture volume accepted");
    for member in control_builder.members() {
        assert_eq!(
            member.eligibility,
            MemberEligibility::DirectEligible,
            "{}: the CRC32 twin is the same archive minus the demotion",
            member.name
        );
    }

    // A demoted member still maps: its bytes are envelope, and the volume is
    // covered exactly once.
    let len = blake2.lens[0];
    let slices = builder.map_physical_range(0, 0, len);
    assert_eq!(total_len(&slices), len);
    assert_eq!(member_len(&slices), 0);
    assert_eq!(envelope_len(&slices), len);
}

/// The split-chain half of the same finding: with `-htb` a non-final part
/// states a packed BLAKE2sp and no packed CRC32, so nothing in the chain can
/// supply the whole-member CRC32 the direct path needs.
#[test]
fn rar5_blake2_split_chain_carries_packed_blake2_and_no_crc32() {
    let Some(fixture) = Fixture::load(
        "rar5_mv_store_blake2",
        "rar5",
        &parts("rar5_mv_store_blake2", 1..=6, 1),
    ) else {
        return;
    };

    let builder = fixture.build(ArchiveFormat::Rar5);
    assert_eq!(builder.header_frontier(), Some(5));

    let member = only_member(&builder);
    assert_eq!(member.name, "Silver.Horizon.S01E06.mkv");
    assert_eq!(member.parts.len(), 6);
    assert_eq!(member.unpacked_size, Some(4_096));
    assert!(member.data_blake2_hash.is_some());
    assert_eq!(member.data_crc32, None);
    assert_eq!(
        member.eligibility,
        MemberEligibility::Ineligible(IneligibilityReason::Blake2OnlyNoCrc32)
    );

    assert_packed_hash_placement(member, false);

    // Demotion does not cost the chain its structure: the offsets still resolve
    // and every volume is still fully accounted for, as envelope.
    assert_logical_offsets_are_prefix_sums(member);
    assert_maps_every_volume_whole(&builder, &fixture);
    for (number, &len) in fixture.lens.iter().enumerate() {
        let slices = builder.map_physical_range(number as u32, 0, len);
        assert_eq!(
            envelope_len(&slices),
            len,
            "volume {number} is all envelope"
        );
    }
}

// ---------------------------------------------------------------------------
// 7. Volume number as stated versus volume number as named
// ---------------------------------------------------------------------------

/// The header's volume number and the filename's part number are independent
/// signals, and they do not agree: RAR numbers volumes from zero in the header
/// and from one in the name. A reconciler that matched them literally would
/// misplace every volume by one, which is why weaver reconciles on the modal
/// delta between the two rather than on either alone.
#[test]
fn header_volume_number_and_filename_part_number_disagree_by_a_constant() {
    for (name, dir, files) in [
        (
            "rar5_recovery_volumes",
            "rar5",
            parts("rar5_recovery_volumes", 1..=10, 2),
        ),
        ("rar4_mv_store", "rar4", parts("rar4_mv_store", 1..=5, 1)),
        (
            "rar5_mv_store_long",
            "rar5",
            parts("rar5_mv_store_long", 1..=27, 2),
        ),
    ] {
        let Some(fixture) = Fixture::load(name, dir, &files) else {
            continue;
        };

        let deltas: BTreeSet<i64> = fixture
            .facts
            .iter()
            .zip(&files)
            .map(|(facts, file)| {
                let named: i64 = file
                    .rsplit_once(".part")
                    .and_then(|(_, tail)| tail.split('.').next())
                    .expect("fixture names carry a part number")
                    .parse()
                    .expect("part number parses");
                named - i64::from(facts.volume_number)
            })
            .collect();

        // Both signals are present, they disagree, and they disagree the same
        // way on every volume — which is exactly what makes a modal delta the
        // right reconciliation and a literal match the wrong one.
        assert_eq!(
            deltas,
            BTreeSet::from([1]),
            "{name}: filename part numbers run one ahead of header volume numbers"
        );
        assert_eq!(
            fixture.facts[0].volume_number, 0,
            "{name}: headers number volumes from zero"
        );
    }
}

// ---------------------------------------------------------------------------
// 8. RAR5 encrypted store
// ---------------------------------------------------------------------------

/// An encrypted `Store` member's cipher bytes sit at the member's own offsets,
/// so the layout maps them to the member — as [`MappedSlice::EncryptedMember`],
/// which is the same coordinates plus "decrypt these first". Its packed bytes
/// are the plaintext CBC-encrypted, so the chain sums to `align16` of the
/// declared size rather than to the size itself.
#[test]
fn rar5_encrypted_multi_volume_store_classifies_as_encrypted_store() {
    let Some(fixture) = Fixture::load(
        "rar5_enc_mv_store",
        "rar5",
        &parts("rar5_enc_mv_store", 1..=5, 1),
    ) else {
        return;
    };

    for facts in &fixture.facts {
        assert!(
            facts.members.iter().all(|member| member.is_encrypted),
            "every member of the encrypted fixture is encrypted"
        );
        assert!(
            !facts.is_encrypted,
            "`-p` encrypts file data only; the headers parse without a password"
        );
    }

    let builder = fixture.build(ArchiveFormat::Rar5);
    let member = only_member(&builder);
    assert_eq!(member.name, "binary.bin");
    assert_eq!(member.parts.len(), 5);
    assert!(member.chain_complete);

    let store = member
        .eligibility
        .encrypted_store()
        .expect("an encrypted stored member");
    assert!(store.resolved);
    // This member's plaintext is already a whole number of blocks, so the
    // padded length and the declared one coincide — the case where an exact
    // equality check would have passed by luck.
    assert_eq!(member.unpacked_size, Some(262_144));
    assert_eq!(store.cipher_size, Some(262_144));
    assert_eq!(store.tail_padding, Some(0));
    assert!(store.claims_password_check());
    assert!(store.password_check().is_some());

    assert_logical_offsets_are_prefix_sums(member);
    assert_maps_every_volume_whole(&builder, &fixture);

    // Split parts are not individually block-aligned: only the member's total
    // is. That is what makes the preceding cipher block cross volumes.
    let unaligned = member
        .parts
        .iter()
        .filter(|part| !part.data_size.is_multiple_of(16))
        .count();
    assert!(
        unaligned > 0,
        "the writer splits mid-block, which is the whole boundary problem"
    );

    for (number, &len) in fixture.lens.iter().enumerate() {
        let slices = builder.map_physical_range(number as u32, 0, len);
        let part = &member.parts[number];
        assert_eq!(
            slices
                .iter()
                .filter(|slice| matches!(slice, MappedSlice::Member { .. }))
                .count(),
            0,
            "volume {number}: cipher bytes never present as writable member bytes"
        );
        assert_eq!(
            builder.map_physical_range(number as u32, part.data_offset, part.data_size),
            vec![MappedSlice::EncryptedMember {
                member_index: 0,
                logical_offset: part.logical_offset.expect("resolved"),
                len: part.data_size,
            }],
            "volume {number}: the part maps to its own cipher span"
        );
        assert_eq!(envelope_len(&slices), len - part.data_size);
    }
}

/// Two encrypted members in one chain: RAR gives each its own CBC stream, so
/// each has its own IV and its own padding, while the KDF tuple and password
/// check are the archive's. The volume where one member ends and the next
/// begins is the case a single-member fixture cannot reach.
#[test]
fn rar5_encrypted_multi_member_store_gives_each_member_its_own_cipher_stream() {
    let Some(fixture) = Fixture::load(
        "rar5_enc_mv_store_pair",
        "rar5",
        &parts("rar5_enc_mv_store_pair", 1..=9, 2),
    ) else {
        return;
    };

    let builder = fixture.build(ArchiveFormat::Rar5);
    let members = builder.members();
    assert_eq!(members.len(), 2);
    assert_eq!(members[0].name, "Silver.Horizon.S02E01.mkv");
    assert_eq!(members[1].name, "Silver.Horizon.S02E02.mkv");

    let stores: Vec<EncryptedStore> = members
        .iter()
        .map(|member| {
            member
                .eligibility
                .encrypted_store()
                .unwrap_or_else(|| panic!("{}: encrypted store", member.name))
        })
        .collect();
    assert!(stores.iter().all(|store| store.resolved));

    // Opposite sides of the padding rule, in one archive: 20001 bytes need a
    // 15-byte tail, 12288 need none.
    assert_eq!(members[0].unpacked_size, Some(20_001));
    assert_eq!(stores[0].cipher_size, Some(20_016));
    assert_eq!(stores[0].tail_padding, Some(15));
    assert_eq!(members[1].unpacked_size, Some(12_288));
    assert_eq!(stores[1].cipher_size, Some(12_288));
    assert_eq!(stores[1].tail_padding, Some(0));

    let first = stores[0].crypt.expect("RAR5 crypt record");
    let second = stores[1].crypt.expect("RAR5 crypt record");
    assert_eq!(first.salt, second.salt, "one KDF tuple for the archive");
    assert_eq!(first.kdf_count_lg2, second.kdf_count_lg2);
    assert_eq!(first.psw_check, second.psw_check);
    assert_ne!(first.iv, second.iv, "one CBC stream per member");

    for member in members {
        assert!(member.chain_complete);
        assert_logical_offsets_are_prefix_sums(member);
        // The keyed-checksum finding: `rar` sets the hash-MAC flag on the
        // final part only, so the whole-member checksum is keyed while the
        // non-final parts' packed checksums are not.
        assert!(
            member.data_hash_uses_mac,
            "{}: the whole-member checksum is a keyed fold",
            member.name
        );
        for (position, part) in member.parts.iter().enumerate() {
            if part.split_after {
                assert!(part.packed_crc32.is_some());
                assert!(
                    !part.packed_hash_uses_mac,
                    "{}: part {position}'s packed CRC32 is a plain one",
                    member.name
                );
            }
        }
    }

    // The straddle volume: member 0's last part and member 1's first part.
    let straddle = members[0].parts.last().expect("parts").volume;
    assert_eq!(straddle, members[1].parts[0].volume);
    assert_eq!(fixture.facts[straddle as usize].members.len(), 2);

    assert_maps_every_volume_whole(&builder, &fixture);
    let slices = builder.map_physical_range(straddle, 0, fixture.lens[straddle as usize]);
    let indices: Vec<usize> = slices
        .iter()
        .filter_map(|slice| match slice {
            MappedSlice::EncryptedMember { member_index, .. } => Some(*member_index),
            _ => None,
        })
        .collect();
    assert_eq!(
        indices,
        vec![0, 1],
        "the straddle volume hands its bytes to both members in physical order"
    );
}

/// The single-volume case, and the only place the tail padding is directly
/// visible: a 20 001-byte member occupies 20 016 packed bytes, and all 20 016
/// map to the member because the last block cannot be decrypted without them.
#[test]
fn rar5_single_volume_encrypted_store_maps_its_tail_padding_as_member_bytes() {
    let Some(fixture) = Fixture::load(
        "rar5_enc_store_pair",
        "rar5",
        &["rar5_enc_store_pair.rar".to_string()],
    ) else {
        return;
    };

    let mut builder = StoredLayoutBuilder::new(ArchiveFormat::Rar5);
    builder
        .add_volume(0, &fixture.facts[0])
        .expect("fixture volume accepted");

    let members = builder.members();
    assert_eq!(members.len(), 2);
    let padded = &members[0];
    let store = padded.eligibility.encrypted_store().expect("encrypted");
    assert_eq!(padded.unpacked_size, Some(20_001));
    assert_eq!(store.cipher_size, Some(20_016));
    assert_eq!(store.tail_padding, Some(15));

    let part = &padded.parts[0];
    assert_eq!(part.data_size, 20_016);
    assert_eq!(
        builder.map_physical_range(0, part.data_offset, part.data_size),
        vec![MappedSlice::EncryptedMember {
            member_index: 0,
            logical_offset: 0,
            len: 20_016,
        }],
        "the padding bytes are member bytes on the wire, not envelope"
    );

    assert_maps_every_volume_whole(&builder, &fixture);
}

/// RAR4 states no per-file crypt record — key and IV come from the password
/// and this 8-byte salt — so the salt is the whole of the facts, and the
/// `align16` rule is the same one.
#[test]
fn rar4_encrypted_multi_volume_store_carries_its_file_salt() {
    let Some(fixture) = Fixture::load(
        "rar4_enc_mv_store",
        "rar4",
        &parts("rar4_enc_mv_store", 1..=5, 1),
    ) else {
        return;
    };

    for (number, facts) in fixture.facts.iter().enumerate() {
        assert_eq!(facts.format, 4);
        let member = &facts.members[0];
        assert!(member.is_encrypted);
        assert_eq!(member.encryption, None, "RAR4 has no FHEXTRA_CRYPT record");
        assert!(
            member.rar4_salt.is_some(),
            "volume {number}: RAR4 `-p` writes a per-file salt"
        );
    }

    let builder = fixture.build(ArchiveFormat::Rar4);
    let member = only_member(&builder);
    let store = member.eligibility.encrypted_store().expect("encrypted");
    assert!(store.resolved);
    assert_eq!(store.crypt, None);
    assert_eq!(store.rar4_salt, fixture.facts[0].members[0].rar4_salt);
    assert!(
        !store.claims_password_check(),
        "RAR4 carries no check value"
    );
    assert_eq!(store.cipher_size, Some(262_144));

    assert_logical_offsets_are_prefix_sums(member);
    assert_maps_every_volume_whole(&builder, &fixture);
}

// ---------------------------------------------------------------------------
// 9. The encrypted-member surface a decrypting router calls
// ---------------------------------------------------------------------------

/// Admission (E-D1): the password is decided from the header's check value,
/// before a byte is decrypted, and a wrong one is refuted rather than merely
/// unconfirmed.
#[test]
fn deriving_a_members_key_reproduces_the_password_check_its_header_states() {
    let sets: [(&'static str, &str, Vec<String>); 2] = [
        (
            "rar5_enc_mv_store_pair",
            "rar5",
            parts("rar5_enc_mv_store_pair", 1..=9, 2),
        ),
        (
            "rar5_enc_mv_store",
            "rar5",
            parts("rar5_enc_mv_store", 1..=5, 1),
        ),
    ];

    let cache = KdfCache::new();
    let mut checked = 0usize;
    for (name, dir, files) in sets {
        let Some(fixture) = Fixture::load(name, dir, &files) else {
            continue;
        };
        let builder = fixture.build(ArchiveFormat::Rar5);
        for member in builder.members() {
            let store = member.eligibility.encrypted_store().expect("encrypted");
            let crypt = store.crypt.expect("RAR5 crypt record");
            let check = store.password_check().expect("the writer states one");

            assert_eq!(
                check_member_password(
                    &cache,
                    TEST_PASSWORD,
                    &crypt.salt,
                    crypt.kdf_count_lg2,
                    Some(&check)
                ),
                PasswordCheck::Verified,
                "{name}/{}: the fixture password verifies",
                member.name
            );
            assert_eq!(
                check_member_password(
                    &cache,
                    "not-the-password",
                    &crypt.salt,
                    crypt.kdf_count_lg2,
                    Some(&check)
                ),
                PasswordCheck::Wrong,
                "{name}/{}: a wrong password is refuted, not merely unconfirmed",
                member.name
            );
            checked += 1;
        }
    }
    assert!(checked > 0, "no encrypted fixture was reachable");
}

/// The hostile case that says what [`PasswordCheck::Verified`] is worth: the
/// header's password check is unauthenticated data a writer chooses.
///
/// Forge those 8 bytes to the value a *wrong* password derives and
/// `check_member_password` answers `Verified` for that password — correctly,
/// since it is reporting what the header states, and the header lied. Every
/// byte then decrypted is garbage.
///
/// What still catches it is the member's own checksum, folded with the same
/// wrong password's hash key exactly as [`RarArchive`]'s conventional
/// extractor folds it: the keyed whole-member gate is the real backstop, and
/// it fires whether the check value was forged or simply absent. Any consumer
/// that treats `Verified` as licence to keep decrypted bytes without running
/// that gate is admitting this archive.
#[test]
fn forged_password_check_admits_a_wrong_password_and_the_keyed_member_gate_still_catches_it() {
    /// A password that is not [`TEST_PASSWORD`], and never becomes one.
    const WRONG_PASSWORD: &str = "testpass124";

    let Some(fixture) = Fixture::load(
        "rar5_enc_store_pair",
        "rar5",
        &["rar5_enc_store_pair.rar".to_string()],
    ) else {
        return;
    };

    let mut builder = StoredLayoutBuilder::new(ArchiveFormat::Rar5);
    builder
        .add_volume(0, &fixture.facts[0])
        .expect("fixture volume accepted");
    let volume = std::fs::read(&fixture.paths[0]).expect("volume");
    let cache = KdfCache::new();

    let mut checked = 0usize;
    for member in builder.members() {
        let store = member.eligibility.encrypted_store().expect("encrypted");
        let crypt = store.crypt.expect("RAR5 crypt record");
        let stated = store.password_check().expect("the writer states one");
        let unpacked_size = member.unpacked_size.expect("resolved") as usize;
        let stored_checksum = member.data_crc32.expect("whole-member CRC32");
        assert!(
            member.data_hash_uses_mac,
            "{}: this fixture's whole-member checksum is a keyed fold, which is \
             the gate under test",
            member.name
        );

        let wrong = derive_rar5_material(WRONG_PASSWORD, &crypt.salt, crypt.kdf_count_lg2)
            .expect("the wrong password still derives material");

        // Against the header as written, the wrong password is refuted. This
        // is the control: the forgery below is what changes the answer, not
        // some accident of the fixture.
        assert_eq!(
            check_member_password(
                &cache,
                WRONG_PASSWORD,
                &crypt.salt,
                crypt.kdf_count_lg2,
                Some(&stated)
            ),
            PasswordCheck::Wrong,
            "{}: control",
            member.name
        );

        // Forge the check field to what the wrong password derives. Only the 8
        // check bytes are forged here: the trailing 4-byte SHA-256 tag is the
        // parser's business — it drops a field whose tag fails, and a writer
        // forging the check would recompute the tag over its own bytes — and
        // `check_member_password` compares the 8 alone.
        let mut forged = stated;
        forged[..8].copy_from_slice(&wrong.psw_check);
        assert_ne!(
            forged, stated,
            "{}: the forgery must actually change the header's claim",
            member.name
        );
        assert_eq!(
            check_member_password(
                &cache,
                WRONG_PASSWORD,
                &crypt.salt,
                crypt.kdf_count_lg2,
                Some(&forged)
            ),
            PasswordCheck::Verified,
            "{}: admission believes the header, and the header lied",
            member.name
        );

        // The cipher bytes exactly as the layout maps them: one part, whole
        // member, so the preceding block of its first block is the header IV.
        let part = &member.parts[0];
        let start = part.data_offset as usize;
        let cipher = volume[start..start + part.data_size as usize].to_vec();

        // Decrypt with the admitted-but-wrong key and fold the result the way
        // the header says its checksum was folded. Garbage in, and the keyed
        // gate says so.
        let mut garbage = cipher.clone();
        decrypt_cipher_range(&wrong.key, &crypt.iv, &mut garbage).expect("block-aligned");
        garbage.truncate(unpacked_size);
        assert_ne!(
            convert_crc32_to_mac(crc32(&garbage), &wrong.hash_key),
            stored_checksum,
            "{}: the keyed whole-member checksum must reject the forged \
             admission — this assertion is the backstop the router may not skip",
            member.name
        );

        // Non-vacuity: the same composition over the *right* password
        // reproduces the header's stored value, so the mismatch above is the
        // gate discriminating rather than the arithmetic simply never matching.
        let right = derive_rar5_material(TEST_PASSWORD, &crypt.salt, crypt.kdf_count_lg2)
            .expect("the fixture password derives");
        let mut plaintext = cipher;
        decrypt_cipher_range(&right.key, &crypt.iv, &mut plaintext).expect("block-aligned");
        plaintext.truncate(unpacked_size);
        assert_eq!(
            convert_crc32_to_mac(crc32(&plaintext), &right.hash_key),
            stored_checksum,
            "{}: the gate accepts the real password",
            member.name
        );

        checked += 1;
    }
    assert_eq!(checked, 2, "both members of the pair fixture were checked");
}

/// CRC-32/ISO-HDLC, computed here rather than taken from the crate under test:
/// a hostile test that borrows its checksum from the code it is checking
/// proves less. Bitwise and slow, over ≤32 KiB.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xEDB8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

/// The standard check value, so a broken local helper cannot quietly make the
/// forged-check test's inequality pass.
#[test]
fn crc32_helper_matches_the_standard_check_value() {
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    assert_eq!(crc32(b""), 0);
}

/// The write transform (E-D2): any 16-aligned range of a member's cipher
/// stream decrypts from its own bytes plus the 16 immediately before them, and
/// the result is what the conventional extractor produces with the same
/// password. Every part boundary is exercised, so the case where the preceding
/// block lives in — or straddles — the previous volume is covered by
/// construction.
#[test]
fn decrypting_any_cipher_range_from_its_preceding_block_matches_the_extractor() {
    let files = parts("rar5_enc_mv_store_pair", 1..=9, 2);
    let Some(fixture) = Fixture::load("rar5_enc_mv_store_pair", "rar5", &files) else {
        return;
    };

    let builder = fixture.build(ArchiveFormat::Rar5);
    let cache = KdfCache::new();
    let mut boundary_cases = 0usize;

    for (member_index, member) in builder.members().iter().enumerate() {
        let store = member.eligibility.encrypted_store().expect("encrypted");
        let crypt = store.crypt.expect("RAR5 crypt record");
        let cipher_size = store.cipher_size.expect("resolved");
        let unpacked_size = member.unpacked_size.expect("resolved");

        // The member's cipher stream, read straight off the volumes at the
        // offsets the layout maps — this is exactly the byte sequence a router
        // sees on the wire.
        let mut cipher = Vec::with_capacity(cipher_size as usize);
        for part in &member.parts {
            assert_eq!(
                builder.map_physical_range(part.volume, part.data_offset, part.data_size),
                vec![MappedSlice::EncryptedMember {
                    member_index,
                    logical_offset: part.logical_offset.expect("resolved"),
                    len: part.data_size,
                }]
            );
            let volume = std::fs::read(&fixture.paths[part.volume as usize]).expect("volume");
            let start = part.data_offset as usize;
            cipher.extend_from_slice(&volume[start..start + part.data_size as usize]);
        }
        assert_eq!(cipher.len() as u64, cipher_size);

        let plaintext = extract_member(&fixture.paths, &member.name);
        assert_eq!(plaintext.len() as u64, unpacked_size);

        let key = cache
            .derive_key_rar5(TEST_PASSWORD, &crypt.salt, crypt.kdf_count_lg2)
            .expect("key derives");

        // Offsets worth testing: the stream's start (the IV case), the first
        // block boundary at or after every part boundary (where the preceding
        // block comes from another volume), and the final block (whose tail is
        // padding rather than member bytes).
        let mut offsets = vec![0u64, cipher_size - 16];
        let mut running = 0u64;
        for part in &member.parts {
            running += part.data_size;
            let aligned = running.next_multiple_of(16);
            if aligned > 0 && aligned < cipher_size {
                offsets.push(aligned);
            }
        }
        offsets.sort_unstable();
        offsets.dedup();

        for offset in offsets {
            let preceding: [u8; 16] = if offset == 0 {
                crypt.iv
            } else {
                cipher[(offset - 16) as usize..offset as usize]
                    .try_into()
                    .expect("one block")
            };
            let len = (cipher_size - offset).min(32);
            let mut range = cipher[offset as usize..(offset + len) as usize].to_vec();
            decrypt_cipher_range(&key, &preceding, &mut range).expect("block-aligned range");

            // Compare against the extractor's plaintext, stopping at the
            // member's declared end: anything past it is the tail padding,
            // which is not the member's data.
            let compare = (unpacked_size.saturating_sub(offset)).min(len) as usize;
            assert_eq!(
                &range[..compare],
                &plaintext[offset as usize..offset as usize + compare],
                "{}: range {offset}+{len}",
                member.name
            );

            if offset > 0 && offset < cipher_size {
                let owner = |position: u64| {
                    member
                        .parts
                        .iter()
                        .position(|part| {
                            let start = part.logical_offset.expect("resolved");
                            position >= start && position < start + part.data_size
                        })
                        .expect("inside the member")
                };
                if owner(offset - 16) != owner(offset) {
                    boundary_cases += 1;
                }
            }
        }
    }

    assert!(
        boundary_cases > 0,
        "the preceding block must come from an earlier volume somewhere, or \
         this test never exercises the boundary case it exists for"
    );
}

/// The RAR4 twin of the test above (plan 136, E3), and the one that proves the
/// premise the whole RAR4 half rests on: **RAR4 encrypts a split member's whole
/// plaintext as one AES-128-CBC stream running unbroken across the volume
/// boundaries**, seeded by the IV the KDF produces beside the key.
///
/// That is not a formality. If RAR restarted the cipher at each part — which the
/// format would allow, since each part's header carries its own salt copy — then
/// a part's first block would chain from the derived IV rather than from the
/// previous volume's last cipher block, every cross-volume decrypt would be
/// wrong by one block, and the `align16` rule would have to hold per part rather
/// than per member. The assertions below fail loudly in that world: the whole
/// chain is decrypted with one CBC stream and compared byte for byte against the
/// conventional extractor's output, and every part boundary is decrypted again
/// as a bare range from its own preceding block alone.
///
/// It loads through [`Fixture::require`] rather than [`Fixture::load`]: this is
/// also the only test anywhere that checks RAR4 key derivation against an
/// archive `rar` wrote, so a missing corpus must fail here rather than quietly
/// remove the check.
#[test]
fn a_rar4_encrypted_chain_is_one_cbc_stream_keyed_by_its_file_salt() {
    let files = parts("rar4_enc_mv_store", 1..=5, 1);
    let fixture = Fixture::require("rar4_enc_mv_store", "rar4", &files);

    let builder = fixture.build(ArchiveFormat::Rar4);
    let member = only_member(&builder);
    let store = member.eligibility.encrypted_store().expect("encrypted");
    assert_eq!(
        store.keying(),
        MemberKeying::Rar4 {
            salt: store.rar4_salt
        },
        "a RAR4 member keys off its file salt and nothing else"
    );
    let MemberKeying::Rar4 { salt } = store.keying() else {
        panic!("a RAR4 fixture must key as RAR4");
    };
    let cipher_size = store.cipher_size.expect("resolved");
    let unpacked_size = member.unpacked_size.expect("resolved");

    // The member's cipher stream read straight off the volumes at the offsets
    // the layout maps: exactly the byte sequence a router sees on the wire.
    let mut cipher = Vec::with_capacity(cipher_size as usize);
    for (index, part) in member.parts.iter().enumerate() {
        assert_eq!(
            builder.map_physical_range(part.volume, part.data_offset, part.data_size),
            vec![MappedSlice::EncryptedMember {
                member_index: 0,
                logical_offset: part.logical_offset.expect("resolved"),
                len: part.data_size,
            }],
            "part {index} maps to its own cipher span"
        );
        let volume = std::fs::read(&fixture.paths[part.volume as usize]).expect("volume");
        let start = part.data_offset as usize;
        cipher.extend_from_slice(&volume[start..start + part.data_size as usize]);
    }
    assert_eq!(cipher.len() as u64, cipher_size);

    // The key and the IV come out of the same derivation — no header states
    // either — and the KDF cache is the surface a router calls.
    let cache = KdfCache::new();
    let (key, iv) = cache.derive_key_rar4(TEST_PASSWORD, salt.as_ref());

    let plaintext = extract_member(&fixture.paths, &member.name);
    assert_eq!(plaintext.len() as u64, unpacked_size);

    // (1) One stream, from the derived IV, across every volume boundary.
    let mut whole = cipher.clone();
    decrypt_cipher_range_rar4(&key, &iv, &mut whole).expect("block-aligned");
    assert_eq!(
        &whole[..unpacked_size as usize],
        plaintext.as_slice(),
        "the chain is one CBC stream: a per-part restart would diverge at the \
         first volume boundary"
    );

    // (2) And every part boundary decrypts as a bare range from its own
    // preceding 16 cipher bytes, which for a boundary live in the previous
    // volume — the CBC random-access property E-D2 rests on, over RAR4.
    let mut offsets = vec![0u64, cipher_size - 16];
    let mut running = 0u64;
    for part in &member.parts {
        running += part.data_size;
        let aligned = running.next_multiple_of(16);
        if aligned > 0 && aligned < cipher_size {
            offsets.push(aligned);
        }
    }
    offsets.sort_unstable();
    offsets.dedup();
    let mut boundary_cases = 0usize;
    for offset in offsets {
        let preceding: [u8; 16] = if offset == 0 {
            iv
        } else {
            cipher[(offset - 16) as usize..offset as usize]
                .try_into()
                .expect("one block")
        };
        let len = (cipher_size - offset).min(32);
        let mut range = cipher[offset as usize..(offset + len) as usize].to_vec();
        decrypt_cipher_range_rar4(&key, &preceding, &mut range).expect("block-aligned range");
        let compare = (unpacked_size.saturating_sub(offset)).min(len) as usize;
        assert_eq!(
            &range[..compare],
            &plaintext[offset as usize..offset as usize + compare],
            "range {offset}+{len}"
        );

        if offset > 0 && offset < cipher_size {
            let owner = |position: u64| {
                member
                    .parts
                    .iter()
                    .position(|part| {
                        let start = part.logical_offset.expect("resolved");
                        position >= start && position < start + part.data_size
                    })
                    .expect("inside the member")
            };
            if owner(offset - 16) != owner(offset) {
                boundary_cases += 1;
            }
        }
    }
    assert!(
        boundary_cases > 0,
        "the preceding block must come from an earlier volume somewhere, or this \
         test never exercises the boundary case it exists for"
    );

    // (3) The wrong password produces garbage and nothing refutes it earlier:
    // RAR4 has no password-check value, so the member's plain CRC32 is the only
    // detector there is — and it is a *plain* one, never a keyed fold, because
    // no RAR4 header can set the hash-MAC flag.
    assert!(
        !member.data_hash_uses_mac,
        "RAR4 has no tweaked-checksum flag: the whole-member CRC32 is the bare one"
    );
    let (wrong_key, wrong_iv) = cache.derive_key_rar4("not-the-password", salt.as_ref());
    let mut garbage = cipher;
    decrypt_cipher_range_rar4(&wrong_key, &wrong_iv, &mut garbage).expect("block-aligned");
    garbage.truncate(unpacked_size as usize);
    assert_ne!(
        crc32(&garbage),
        member.data_crc32.expect("whole-member CRC32"),
        "the plain whole-member CRC32 is RAR4's only wrong-password gate, and it \
         must reject"
    );
    assert_eq!(
        crc32(&plaintext),
        member.data_crc32.expect("whole-member CRC32"),
        "and it accepts the real password, so the rejection above discriminates"
    );
}

/// The RAR4 `align16` slack, on a real archive: a 290-byte member occupies 304
/// packed bytes, all of which are member bytes on the wire.
///
/// The multi-volume RAR4 fixture cannot show this — its payload is exactly
/// 256 KiB, so `align16` is a no-op there and a chain that summed to the
/// unpadded size would pass it just as happily.
#[test]
fn a_single_volume_rar4_encrypted_store_maps_its_tail_padding_as_member_bytes() {
    let Some(fixture) = Fixture::load(
        "rar4_enc_store",
        "rar4",
        &["rar4_enc_store.rar".to_string()],
    ) else {
        return;
    };

    let mut builder = StoredLayoutBuilder::new(ArchiveFormat::Rar4);
    builder
        .add_volume(0, &fixture.facts[0])
        .expect("fixture volume accepted");

    let member = only_member(&builder);
    let store = member.eligibility.encrypted_store().expect("encrypted");
    assert_eq!(member.unpacked_size, Some(290));
    assert_eq!(store.cipher_size, Some(304));
    assert_eq!(store.tail_padding, Some(14));
    assert!(store.resolved);

    let part = &member.parts[0];
    assert_eq!(
        part.data_size, 304,
        "the packed bytes are the padded cipher length, not the declared size"
    );
    assert_eq!(
        builder.map_physical_range(0, part.data_offset, part.data_size),
        vec![MappedSlice::EncryptedMember {
            member_index: 0,
            logical_offset: 0,
            len: 304,
        }],
        "the padding bytes are member bytes on the wire, not envelope"
    );

    // And the padding really is what the final block decrypts to past the end:
    // 14 bytes that exist only in the cipher, which is why they are retained.
    let MemberKeying::Rar4 { salt } = store.keying() else {
        panic!("a RAR4 fixture must key as RAR4");
    };
    let (key, iv) = KdfCache::new().derive_key_rar4(TEST_PASSWORD, salt.as_ref());
    let volume = std::fs::read(&fixture.paths[0]).expect("volume");
    let start = part.data_offset as usize;
    let mut plain = volume[start..start + part.data_size as usize].to_vec();
    decrypt_cipher_range_rar4(&key, &iv, &mut plain).expect("block-aligned");
    assert_eq!(
        &plain[..290],
        extract_member(&fixture.paths, &member.name).as_slice()
    );
    assert_eq!(plain.len(), 304);

    assert_maps_every_volume_whole(&builder, &fixture);
}

/// What `-hp` (header encryption) actually costs a one-pass router, measured
/// rather than assumed — the evidence behind plan 136 E3's scoping of it.
///
/// Three facts, and they do not all point the same way:
///
/// 1. **The keying facts are in the clear.** RAR5's type-4 encryption header is
///    itself plaintext, and `header::parse_all_headers` parses it *before* it
///    looks at the password: salt, lg2 count and the 12-byte password check all
///    come out of the first article of the first volume, at exactly the place
///    D2's header walk already reads. `-hp` withholds **layout** facts, not
///    **keying** facts.
/// 2. **And `parse_volume_header_encryption` surfaces them** (E4). The walk
///    used to return `EncryptedArchive` and drop the whole result, so there was
///    no way to obtain the record without a password; the walk now hands it
///    back and `RarArchive::parse_volume_header_encryption` is the accessor.
///    `parse_all_headers` still refuses exactly as it did.
/// 3. **The layout half needs the password and is otherwise unchanged.** Given
///    one, `parse_volume_facts` returns ordinary facts and the stored layout
///    classifies the set exactly as a `-p` set: same eligibility, same
///    `align16`, same member keying. Nothing downstream of the parse is
///    `-hp`-shaped.
#[test]
fn header_encryption_withholds_the_layout_but_not_the_keying_facts() {
    for (dir, file) in [("rar5", "rar5_hp_store.rar"), ("rar4", "rar4_hp_store.rar")] {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(dir)
            .join(file);
        if !path.exists() {
            eprintln!("skipping: {file} not present");
            continue;
        }

        // (a) Without a password there are no facts at all — so a router that
        // learns its layout from the volume's own first article learns nothing,
        // which is the premise `-hp` really does break.
        let refused = RarArchive::parse_volume_facts(
            std::fs::File::open(&path).expect("fixture readable"),
            None,
        );
        assert!(
            refused.is_err(),
            "{file}: a header-encrypted volume must yield no facts without a password"
        );

        // (b) With one, the facts are ordinary and the layout classifies the set
        // with no `-hp`-specific handling anywhere.
        let facts = RarArchive::parse_volume_facts(
            std::fs::File::open(&path).expect("fixture readable"),
            Some(HP_PASSWORD),
        )
        .expect("a header-encrypted volume parses with its password");
        assert!(
            !facts.members.is_empty(),
            "{file}: the password must yield the member list"
        );
        let format = facts.archive_format();
        let mut builder = StoredLayoutBuilder::new(format);
        builder.add_volume(0, &facts).expect("volume accepted");
        assert_eq!(builder.members().len(), facts.members.len());
    }

    // (c) And the keying facts really are readable with no password: the type-4
    // block is plaintext, and the walk parses it before it consults the
    // password. It is only the *return* that throws them away.
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rar5/rar5_hp_store.rar");
    if !path.exists() {
        return;
    }
    let mut image = std::io::Cursor::new(std::fs::read(&path).expect("fixture readable"));
    assert_eq!(
        unrar_rs::signature::read_signature(&mut image).expect("a RAR5 signature"),
        ArchiveFormat::Rar5
    );
    let error =
        unrar_rs::header::parse_all_headers(&mut image, None).expect_err("no password, no headers");
    assert!(
        matches!(error, unrar_rs::RarError::EncryptedArchive),
        "the refusal must name header encryption rather than corruption, got {error:?}"
    );

    // The same walk with the password reaches the same type-4 record it had
    // already parsed a moment before refusing — which is the measurement: the
    // salt and the KDF count are the archive's, stated in the clear, and a
    // password-candidate loop could be proved against them before a byte of
    // anyone's data is decrypted.
    let mut image = std::io::Cursor::new(std::fs::read(&path).expect("fixture readable"));
    unrar_rs::signature::read_signature(&mut image).expect("a RAR5 signature");
    let parsed = unrar_rs::header::parse_all_headers(&mut image, Some(HP_PASSWORD))
        .expect("the password opens the headers");
    let encryption = parsed
        .encryption
        .expect("a `-hp` archive states its type-4 record");
    let cache = KdfCache::new();
    assert_eq!(
        check_member_password(
            &cache,
            HP_PASSWORD,
            &encryption.salt,
            encryption.kdf_count,
            encryption.check_data.as_ref(),
        ),
        PasswordCheck::Verified,
        "the archive-level check proves the right password"
    );
    assert_eq!(
        check_member_password(
            &cache,
            "not-the-password",
            &encryption.salt,
            encryption.kdf_count,
            encryption.check_data.as_ref(),
        ),
        PasswordCheck::Wrong,
        "and refutes a wrong one — the gate a candidate loop would need already exists"
    );
    // The third outcome, which is the one that must never be mistaken for the
    // first: a check the parser could not validate refutes nothing, for any
    // password. `parse` degrades such a field to `None` (pinned in
    // `header::encryption`'s own tests), and `None` reads as `Unverifiable`.
    assert_eq!(
        check_member_password(
            &cache,
            "not-the-password",
            &encryption.salt,
            encryption.kdf_count,
            None,
        ),
        PasswordCheck::Unverifiable,
        "an unusable check must be exactly as informative as no check at all — never a \
         verification"
    );
}

/// The E4 surfacing itself: the same keying facts, obtained with **no
/// password**, and provably the same ones the password-bearing walk reaches.
///
/// The failure this is shaped against is the one that would make E4 silently
/// useless *and* silently wrong: a `parse_volume_header_encryption` that
/// answered `None`, or answered with a zeroed/defaulted record, would still let
/// a caller "verify" nothing and route. So every assertion below is against the
/// **no-password** value, and the record it returns is compared field by field
/// with the one `parse_all_headers(.., Some(password))` produces — a stub could
/// not pass that, and a candidate loop proved against a stub would admit the
/// first password it tried.
#[test]
fn header_encryption_keying_facts_come_out_with_no_password() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");

    // (a) RAR5 `-hp`: the whole type-4 record, from a reader that was never
    //     given a password.
    let path = fixtures.join("rar5/rar5_hp_store.rar");
    if !path.exists() {
        eprintln!("skipping: rar5_hp_store.rar not present");
        return;
    }
    let surfaced =
        RarArchive::parse_volume_header_encryption(std::fs::File::open(&path).expect("fixture"))
            .expect("the type-4 record is plaintext");
    let RarVolumeHeaderEncryption::Rar5(facts) = surfaced else {
        panic!("a RAR5 `-hp` volume must report its archive encryption, got {surfaced:?}");
    };

    // It is the archive's record, not a default: compared against the one the
    // password-bearing walk reaches, field by field.
    let mut image = std::io::Cursor::new(std::fs::read(&path).expect("fixture readable"));
    unrar_rs::signature::read_signature(&mut image).expect("a RAR5 signature");
    let keyed = unrar_rs::header::parse_all_headers(&mut image, Some(HP_PASSWORD))
        .expect("the password opens the headers")
        .encryption
        .expect("a `-hp` archive states its type-4 record");
    assert_eq!(facts.version, keyed.version);
    assert_eq!(facts.kdf_count_lg2, keyed.kdf_count);
    assert_eq!(facts.salt, keyed.salt);
    assert_eq!(facts.psw_check_present, keyed.has_password_check);
    assert_eq!(facts.psw_check, keyed.check_data);

    // And they are load-bearing: the right password verifies against the
    // no-password facts and the wrong one is refuted, which is the entire gate
    // an `-hp` admission decision rests on.
    let cache = KdfCache::new();
    assert!(
        facts.psw_check_present && facts.psw_check.is_some(),
        "WinRAR writes a check by default; without one this fixture proves nothing"
    );
    assert_eq!(
        check_member_password(
            &cache,
            HP_PASSWORD,
            &facts.salt,
            facts.kdf_count_lg2,
            facts.psw_check.as_ref(),
        ),
        PasswordCheck::Verified,
    );
    assert_eq!(
        check_member_password(
            &cache,
            "not-the-password",
            &facts.salt,
            facts.kdf_count_lg2,
            facts.psw_check.as_ref(),
        ),
        PasswordCheck::Wrong,
    );

    // (b) RAR4 `-hp` reports *that* it is header-encrypted and nothing more.
    //     The format has no password-check value anywhere, so there is nothing
    //     a candidate could be proved against — which is why this variant
    //     carries no facts rather than carrying empty ones.
    let path = fixtures.join("rar4/rar4_hp_store.rar");
    if path.exists() {
        assert_eq!(
            RarArchive::parse_volume_header_encryption(
                std::fs::File::open(&path).expect("fixture")
            )
            .expect("the RAR4 archive header flag is in the clear"),
            RarVolumeHeaderEncryption::Rar4,
        );
    }

    // (c) Non-vacuity, both formats: a `-p` archive — file data encrypted,
    //     headers readable — is **not** header-encrypted. Without this the
    //     function could be `Rar5(..)`-for-everything and (a) would still pass.
    for (dir, file) in [
        ("rar5", "rar5_enc_store.rar"),
        ("rar5", "rar5_store.rar"),
        ("rar4", "rar4_enc_store.rar"),
        ("rar4", "rar4_store.rar"),
    ] {
        let path = fixtures.join(dir).join(file);
        if !path.exists() {
            continue;
        }
        assert_eq!(
            RarArchive::parse_volume_header_encryption(
                std::fs::File::open(&path).expect("fixture")
            )
            .expect("a readable-header volume walks without a password"),
            RarVolumeHeaderEncryption::None,
            "{file}: `-p` encrypts file data, not headers"
        );
    }
}

/// Extract one member conventionally, with the password, as the reference
/// every decrypt above is compared against.
///
/// The batch path, because this test is about the write transform and not about
/// streaming. The streaming path reads the same bytes:
/// `test_rar5_encrypted_multivolume_store_pair_second_member_streams_from_its_own_volumes`
/// in `tests/integration.rs` holds it against this same fixture's second
/// member, which is the one that starts past the set's first volume.
fn extract_member(paths: &[PathBuf], name: &str) -> Vec<u8> {
    let readers: Vec<Box<dyn unrar_rs::ReadSeek>> = paths
        .iter()
        .map(|path| {
            Box::new(std::io::Cursor::new(std::fs::read(path).expect("volume")))
                as Box<dyn unrar_rs::ReadSeek>
        })
        .collect();
    let mut archive = RarArchive::open_volumes(readers).expect("volumes open");
    archive.set_password(TEST_PASSWORD);
    let index = archive.find_member(name).expect("member present");
    let options = unrar_rs::ExtractOptions {
        verify: true,
        password: Some(TEST_PASSWORD.into()),
        restore_owners: false,
    };
    archive
        .extract_member(index, &options, None)
        .and_then(|member| member.into_bytes())
        .expect("member extracts")
}
