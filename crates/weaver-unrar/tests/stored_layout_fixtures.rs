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

use weaver_unrar::{
    ArchiveFormat, IneligibilityReason, MappedSlice, MemberEligibility, RarArchive, RarVolumeFacts,
    StoredLayoutBuilder, StoredMember,
};

// ---------------------------------------------------------------------------
// Fixture loading
// ---------------------------------------------------------------------------

/// One archive set: its volumes' parsed facts alongside their true byte
/// lengths, which is what a whole-volume mapping has to add up to.
struct Fixture {
    name: &'static str,
    facts: Vec<RarVolumeFacts>,
    lens: Vec<u64>,
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
        Some(Self { name, facts, lens })
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
        .filter(|slice| matches!(slice, MappedSlice::Member { .. }))
        .map(slice_len)
        .sum()
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
        member.unpacked_size,
        "{}: a stored chain's packed bytes sum to the member's size",
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

/// Encrypted members are ineligible whatever their compression: the packed
/// bytes on the wire are ciphertext, so routing them to a destination would
/// write ciphertext. The facts still describe the chain, which is what a future
/// decrypt-then-route path would need.
#[test]
fn rar5_encrypted_multi_volume_store_is_ineligible_but_still_mapped() {
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
    }

    let builder = fixture.build(ArchiveFormat::Rar5);
    let member = only_member(&builder);
    assert_eq!(member.name, "binary.bin");
    assert_eq!(member.parts.len(), 5);
    assert_eq!(
        member.eligibility,
        MemberEligibility::Ineligible(IneligibilityReason::Encrypted)
    );

    // The chain is intact underneath the demotion, so the facts a later
    // decrypting router would consume are all present.
    assert!(member.chain_complete);
    assert_logical_offsets_are_prefix_sums(member);

    assert_maps_every_volume_whole(&builder, &fixture);
    for (number, &len) in fixture.lens.iter().enumerate() {
        let slices = builder.map_physical_range(number as u32, 0, len);
        assert_eq!(
            envelope_len(&slices),
            len,
            "volume {number}: ciphertext never routes"
        );
    }
}
