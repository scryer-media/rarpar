//! Cross-volume stored-layout assembly over per-volume header facts.
//!
//! [`StoredLayoutBuilder`] learns a multi-volume set's layout one volume at a
//! time from [`RarVolumeFacts`], in any order, and answers the question a
//! one-pass router asks: for a physical byte range inside a volume, which
//! member owns each byte and at what offset inside that member.
//!
//! The whole design turns on one property of the format: **no RAR header field
//! carries a part's logical offset within its member**. A split part header
//! states the member's *total* unpacked size only, so part *N* begins at
//! `sum(data_size)` over parts `0..N` — a value that exists only once every
//! earlier part's header has been parsed. [`StoredLayoutBuilder::header_frontier`]
//! reports how far that knowledge reaches for the set as a whole, and
//! [`StoredMemberPart::logical_offset`] is `None` until the part's own chain
//! prefix is complete.
//!
//! **Encrypted store members** ride the same machinery with one difference.
//! Their packed bytes are the member's plaintext as a single AES-CBC stream,
//! so cipher offset and member-logical offset coincide and every range answer
//! above is unchanged — but a chain's packed sizes sum to
//! `align16(unpacked_size)` rather than to the size itself, and the bytes must
//! be decrypted before they are anyone's data. The layout says so in the type
//! system: [`MemberEligibility::EncryptedStore`] carries the key material the
//! headers state, and the bytes map as [`MappedSlice::EncryptedMember`], never
//! as [`MappedSlice::Member`]. RAR5 (AES-256, IV in the header) and RAR4
//! (AES-128, IV out of the KDF) are both classified, and [`MemberKeying`] is
//! which — the pre-AES RAR4 ciphers are not, because their streams obey neither
//! the CBC random-access rule nor the `align16` one.
//!
//! This module classifies facts and nothing else. Budgets, tolerances, group
//! merging, password handling and the decision to route or demote belong to the
//! caller; the layout only reports what the headers say. In particular it holds
//! no password, derives no key and decrypts nothing — see
//! [`crate::crypto::check_member_password`] and
//! [`crate::crypto::decrypt_cipher_range`] for the surfaces that do.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::archive::{RarVolumeFacts, RarVolumeMemberEncryptionFacts, RarVolumeMemberFacts};
use crate::types::{ArchiveFormat, CompressionMethod};

/// AES block size. An encrypted member's packed bytes are its plaintext
/// CBC-encrypted, so they run to a whole number of these — see
/// [`EncryptedStore`].
const AES_BLOCK: u64 = 16;

/// The cipher length of a member whose plaintext is `unpacked_size` bytes:
/// `unpacked_size` rounded up to a whole AES block.
///
/// `None` only when that value is past `u64::MAX`, which no chain's packed
/// sizes can reach — so a `None` limit fails every comparison below, which is
/// the fail-closed answer such a header deserves.
fn align16(unpacked_size: u64) -> Option<u64> {
    unpacked_size.checked_next_multiple_of(AES_BLOCK)
}

/// Whether a RAR4-family part encrypts with AES-128-CBC ("RAR 3.0"
/// encryption) rather than with one of the three legacy ciphers.
///
/// The selection rule is the format's, and this **delegates** to the same call
/// the extraction path makes — [`crate::rar4::types::Rar4EncryptionMethod::for_unpack_version`],
/// which [`crate::archive`]'s RAR4 decryptor selection also uses — rather than
/// restating the table. That is deliberate and load-bearing: a second copy of
/// the version table could drift, and a classification that said AES where the
/// extractor reached for a legacy cipher (or the reverse) is precisely the
/// wrong-bytes hazard this predicate exists to close. The only thing stated
/// here is the RAR 1.4 exception, which is not a version question at all: RAR
/// 1.4 encryption is always the RAR 1.3 cipher whatever its version byte says.
fn rar4_uses_aes(format: ArchiveFormat, unpack_version: u8) -> bool {
    format != ArchiveFormat::Rar14
        && matches!(
            crate::rar4::types::Rar4EncryptionMethod::for_unpack_version(unpack_version),
            crate::rar4::types::Rar4EncryptionMethod::Rar30
        )
}

/// Why a member's split chain cannot be trusted.
///
/// A malformed chain never panics and never routes: the member's packed bytes
/// take the envelope path like any other ineligible member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MalformedReason {
    /// Two headers in one volume claim the same member name.
    DuplicatePartInVolume { volume: u32 },
    /// Two members' packed ranges overlap inside one volume.
    OverlappingParts { volume: u32 },
    /// The set's first volume carries a continuation part, so the chain claims
    /// a predecessor volume that cannot exist.
    ContinuationInFirstVolume,
    /// A part that is not the member's first claims to start it
    /// (`split_before` clear).
    UnexpectedChainStart { volume: u32 },
    /// A part that is not the member's last claims to end it (`split_after`
    /// clear).
    UnexpectedChainEnd { volume: u32 },
    /// A volume inside the member's span was added but carries no part of it.
    MissingPartInAddedVolume { volume: u32 },
    /// The header declares the unpacked size unknown, so neither the chain sum
    /// nor a destination size can be established.
    MissingUnpackedSize,
    /// Two parts declare different whole-member unpacked sizes. Reported in
    /// volume order — the lowest volume's declaration first — so the reason is
    /// the same whatever order the volumes arrive in.
    InconsistentUnpackedSize { first: u64, second: u64 },
    /// The member's parts do not agree about encryption: some are encrypted
    /// and some are not, or their `FHEXTRA_CRYPT` records state different key
    /// material. Either way no single key decrypts the chain, and a chain that
    /// is ciphertext in places and plaintext in others has no coherent length
    /// rule.
    ///
    /// `volume` is the lowest volume disagreeing with the member's first part,
    /// read in volume order rather than arrival order.
    ///
    /// The hash-MAC flag is deliberately not part of "agree": RARLAB `rar`
    /// 7.20 sets it on a split member's final part only, so requiring it to
    /// match would malform every real encrypted split chain.
    MixedEncryption { volume: u32 },
    /// A complete stored chain's packed bytes do not sum to the member's
    /// unpacked size. Checked over the whole chain, never per part.
    ///
    /// For an **encrypted** member the sum is compared against
    /// `align16(unpacked_size)` instead, because its packed bytes are the
    /// plaintext CBC-encrypted; the fields still report the declared unpacked
    /// size, not the derived cipher length. A chain carrying one whole block
    /// too many is a mismatch even though its slack is "only" 16 bytes.
    SizeMismatch {
        packed_total: u64,
        unpacked_size: u64,
    },
    /// The parts seen so far already carry more stored bytes than the declared
    /// unpacked size — `align16` of it for an encrypted member — so the chain
    /// is wrong before it even closes. Stored bytes are the member's bytes, so
    /// no such part can have a destination.
    ///
    /// `packed_total` is saturated to `u64::MAX` in the one case the true sum
    /// cannot be represented: headers claiming more than `u64::MAX` bytes.
    ExceedsDeclaredSize {
        packed_total: u64,
        unpacked_size: u64,
    },
}

/// Why a member's bytes cannot be routed straight to a destination.
///
/// The variants carry what a caller needs to apply its own policy — notably
/// the byte counts a compressed member would cost if it were tolerated. Those
/// counts are the member's totals only when the variant says so: a chain that
/// is still open has more parts to come, and a size no header states is not a
/// zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IneligibilityReason {
    /// At least one part uses a compression method other than `Store`.
    Compressed {
        /// Packed bytes summed over the parts seen so far — the member's total
        /// only when `totals_final`, a lower bound otherwise. `None` when the
        /// sum overflows `u64`, which only a hostile header can claim.
        packed_bytes: Option<u64>,
        /// The whole-member unpacked size the headers declare, or `None` when
        /// no header states one. Never a substituted zero.
        unpacked_bytes: Option<u64>,
        /// Whether the chain is closed, so both counts are the member's totals
        /// rather than a running lower bound over the parts seen so far.
        totals_final: bool,
    },
    /// At least one part is encrypted, and the member is not a plain encrypted
    /// `Store` chain — it is also compressed or solid, or nothing can key it:
    /// a RAR5 part claimed encryption while stating no `FHEXTRA_CRYPT` record,
    /// or a RAR4 part selected one of the pre-AES ciphers (RAR 1.3, 1.5, 2.0),
    /// whose streams are neither AES-CBC nor block-padded. An encrypted `Store`
    /// member whose parts agree and whose cipher is AES classifies as
    /// [`MemberEligibility::EncryptedStore`] instead.
    Encrypted,
    /// At least one part sets the per-member solid flag. This is the member's
    /// own flag, not the archive-level solid flag.
    Solid,
    /// The member is a directory entry.
    Directory,
    /// The member is a redirection (symlink, hardlink, junction, file copy).
    Redirection,
    /// The member carries a BLAKE2sp digest but no whole-member CRC32. BLAKE2sp
    /// only accepts bytes in order, so out-of-order routing cannot verify it.
    Blake2OnlyNoCrc32,
    /// The member carries no whole-member checksum at all.
    NoChecksum,
    /// The member's split chain is inconsistent.
    MalformedChain(MalformedReason),
}

/// An encrypted `Store` member's key material and cipher extent.
///
/// Every part of the member is encrypted, uses method `Store`, and states the
/// same key material. The library states these facts and derives nothing: no
/// password is involved, no key exists here, and whether such a member routes
/// is the caller's decision.
///
/// **What the cipher bytes are.** RAR encrypts a member's whole plaintext as
/// one CBC stream — one IV per member, with the chain running unbroken across
/// volume boundaries — so cipher offset and member-logical offset are the same
/// number. Split parts are *not* individually block-aligned; only the member's
/// total is. Decrypting cipher block *N* therefore needs only cipher block
/// *N−1*, which for the first block of a part is the tail of the previous
/// volume's part.
///
/// Both formats work this way and the `align16` rule is the same for both. What
/// differs is the key: RAR5 is AES-256 with the IV in the header, RAR4 is
/// AES-128 with the IV coming out of the KDF beside the key. [`Self::keying`]
/// is the discriminant, and it is total — a member that cannot be keyed at all
/// never reaches this state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptedStore {
    /// The set's archive format, and the discriminant [`Self::keying`] reads:
    /// it is what says whether this member's cipher stream is RAR5's AES-256 or
    /// RAR4's AES-128, which are keyed by different derivations from different
    /// header material.
    pub format: ArchiveFormat,
    /// The RAR5 `FHEXTRA_CRYPT` record every part states. `None` for a RAR4
    /// member, which carries only `rar4_salt`; a RAR5 member that stated no
    /// record never reaches this state (it is
    /// [`IneligibilityReason::Encrypted`], since nothing could key it).
    ///
    /// Prefer [`Self::keying`] over testing this field: it says the same thing
    /// exhaustively and names what each answer means.
    pub crypt: Option<RarVolumeMemberEncryptionFacts>,
    /// RAR4's per-file KDF salt, where the headers state one. RAR4 derives
    /// both key and IV from password plus this salt, and a header with no salt
    /// is valid — the key then comes from the password alone.
    pub rar4_salt: Option<[u8; 8]>,
    /// The member's cipher length, `align16(unpacked_size)`: what a complete
    /// chain's packed sizes must sum to. `None` while no header declares a
    /// size, never a substituted zero.
    pub cipher_size: Option<u64>,
    /// `cipher_size - unpacked_size`, always `0..16`: the plaintext bytes of
    /// the final cipher block that lie past the member's end.
    ///
    /// They are never destination bytes, but they are real cipher bytes that
    /// arrive on the wire, and byte-exact re-encryption of the last block
    /// needs the plaintext they decrypt to. `None` together with
    /// `cipher_size`.
    pub tail_padding: Option<u8>,
    /// Whether the chain has closed with every requirement
    /// [`MemberEligibility::DirectEligible`] states also met — the align16 sum
    /// exact and a whole-member CRC32 seen. `false` is the encrypted twin of
    /// [`MemberEligibility::ProvisionallyDirect`]: the member's bytes map, and
    /// the chain closing is what decides whether it stays eligible.
    pub resolved: bool,
}

/// How a member's cipher stream is keyed, as its headers state it.
///
/// The two formats state key material in completely different shapes, and a
/// caller that has to derive a key needs to know which one it is holding —
/// exhaustively, so that a third never slips past as a default. This is that
/// discriminant, and [`EncryptedStore::keying`] is the only way to obtain one:
/// a member reaches [`MemberEligibility::EncryptedStore`] **only** when it is
/// keyable, so there is no "neither" variant to handle.
///
/// It carries no password, derives nothing and holds no secret — every field is
/// what the archive says in the clear. The derivations it names are
/// [`crate::KdfCache::derive_key_rar5`] and [`crate::KdfCache::derive_key_rar4`],
/// and the cipher it selects is [`crate::crypto::MemberCipherKey`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberKeying {
    /// RAR5 file encryption: AES-256-CBC. The record carries the KDF salt and
    /// iteration count, the member's IV, and an optional password-check value —
    /// so a wrong password is refutable before a byte is decrypted.
    Rar5(RarVolumeMemberEncryptionFacts),
    /// RAR4/RAR3 "RAR 3.0" file encryption: AES-128-CBC. The header carries at
    /// most this 8-byte per-file salt; **key and IV are both KDF outputs**, and
    /// there is no password-check value at all, so a wrong password is only ever
    /// caught by the member's checksum. A header with no salt is valid — the key
    /// then comes from the password alone.
    Rar4 { salt: Option<[u8; 8]> },
}

impl EncryptedStore {
    /// How this member is keyed, and therefore which derivation and which
    /// cipher width a caller must use for it.
    ///
    /// The discriminant is the **format**, not the presence of a
    /// `FHEXTRA_CRYPT` record. A record reaches this type only from a RAR5
    /// header, so the two agree today — but they are not the same statement,
    /// and only one of them is safe to be wrong about: a RAR4 part that somehow
    /// carried a record would key as `Rar5` under a record test, and a caller
    /// would then run AES-256 with a header IV over an AES-128 stream. That is
    /// wrong bytes, caught only by the member's CRC32 after the whole member has
    /// been written. Reading the format instead makes a RAR4 member key as RAR4
    /// whatever else a header carried, which is the format's own answer.
    ///
    /// Total by construction: a RAR5 member with no `FHEXTRA_CRYPT` record and a
    /// RAR4 member using one of the pre-AES ciphers are both
    /// [`IneligibilityReason::Encrypted`], so neither can reach this type — the
    /// RAR5 half of that is decided where the builder reads member encryption,
    /// and is itself format-discriminated.
    pub fn keying(&self) -> MemberKeying {
        match self.crypt {
            Some(crypt) if self.format == ArchiveFormat::Rar5 => MemberKeying::Rar5(crypt),
            _ => MemberKeying::Rar4 {
                salt: self.rar4_salt,
            },
        }
    }

    /// Whether the header claims a password-check value, whether or not that
    /// value survived its own checksum.
    ///
    /// Always `false` for a RAR4 member: the format has no such field, so the
    /// member's checksum gate is the only wrong-password detector there is.
    pub fn claims_password_check(&self) -> bool {
        self.crypt.is_some_and(|crypt| crypt.psw_check_present)
    }

    /// The usable 12-byte password-check field, when the header carries one
    /// that validated.
    ///
    /// `Some` means a wrong password is detectable before a single byte is
    /// decrypted — see [`crate::crypto::check_member_password`]. `None` means
    /// it is not, and the member's checksum gates are the earliest detector.
    pub fn password_check(&self) -> Option<[u8; 12]> {
        self.crypt.and_then(|crypt| crypt.psw_check)
    }
}

/// Whether a member's packed bytes can be routed to their final destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberEligibility {
    /// The chain is complete and every direct-store requirement holds,
    /// including a whole-member CRC32.
    DirectEligible,
    /// Nothing observed so far disqualifies the member, but its chain is still
    /// open, so the authoritative whole-member CRC32 — which lives in the final
    /// part's header — has not been seen yet. Resolves to [`Self::DirectEligible`]
    /// or [`Self::Ineligible`] once the chain closes.
    ProvisionallyDirect,
    /// An encrypted `Store` member: the same classification work as the two
    /// states above, over cipher bytes instead of plaintext.
    ///
    /// The member's bytes map to the member, but they map as
    /// [`MappedSlice::EncryptedMember`] — they are ciphertext, and writing
    /// them to a destination unchanged would write ciphertext. The payload
    /// carries what a decrypting caller needs; deciding whether to route it at
    /// all (has a password arrived? does its check pass?) is the caller's.
    EncryptedStore(EncryptedStore),
    /// A fact disqualifies the member.
    Ineligible(IneligibilityReason),
}

impl MemberEligibility {
    /// Whether the layout maps this member's packed bytes to the member rather
    /// than to the envelope.
    ///
    /// True for every non-ineligible state: a set is routed while its chains
    /// are still open, and a member that later fails to close cleanly is the
    /// caller's demotion decision, not a mapping error.
    ///
    /// True does **not** mean the mapped bytes may be written unchanged: for
    /// [`Self::EncryptedStore`] they are ciphertext, which is why they map to
    /// their own [`MappedSlice`] variant rather than to
    /// [`MappedSlice::Member`].
    pub fn routes_direct(self) -> bool {
        matches!(
            self,
            Self::DirectEligible | Self::ProvisionallyDirect | Self::EncryptedStore(_)
        )
    }

    /// The encrypted-store facts, for the one state that has them.
    pub fn encrypted_store(self) -> Option<EncryptedStore> {
        match self {
            Self::EncryptedStore(facts) => Some(facts),
            _ => None,
        }
    }
}

/// One volume's slice of a member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMemberPart {
    /// Volume number this part lives in.
    pub volume: u32,
    /// Physical offset of the packed bytes within that volume.
    pub data_offset: u64,
    /// Packed byte count in that volume.
    pub data_size: u64,
    /// Offset of this part inside the member, or `None` while any earlier part
    /// of the chain is still unknown. No header states this value; it is the
    /// prefix sum of the earlier parts' `data_size`.
    ///
    /// Stable while the member is not [`MemberEligibility::Ineligible`]: for a
    /// well-formed set a later volume only ever resolves a `None`, never moves
    /// an offset it already reported. A malformation is the exception — an
    /// earlier part arriving late can renumber the chain or unresolve it
    /// ([`MalformedReason::UnexpectedChainStart`],
    /// [`MalformedReason::ContinuationInFirstVolume`]) — but it does so in the
    /// same [`StoredLayoutBuilder::add_volume`] call that turns the member
    /// ineligible, so no offset ever moves while the member still routes.
    ///
    /// A caller that has already written bytes therefore holds the only record
    /// of where they went; this field describes the current layout, not the
    /// history of what was emitted.
    pub logical_offset: Option<u64>,
    /// CRC32 of this part's packed bytes, from a non-final split header.
    pub packed_crc32: Option<u32>,
    /// BLAKE2sp of this part's packed bytes, from a non-final split header.
    pub packed_blake2_hash: Option<[u8; 32]>,
    /// Whether this part's packed checksums are keyed folds rather than plain
    /// checksums (RAR5 `FHEXTRA_CRYPT` hash-MAC), so comparing against them
    /// needs the KDF's hash key.
    ///
    /// Per part, not per member: RARLAB `rar` 7.20 keys a split member's
    /// whole-member checksum but leaves the non-final parts' packed checksums
    /// plain, so a caller checking part completions and a caller checking the
    /// member both need their own answer.
    pub packed_hash_uses_mac: bool,
    /// The part continues a member started in an earlier volume.
    pub split_before: bool,
    /// The member continues into a later volume.
    pub split_after: bool,
}

/// A member assembled from every volume that carries part of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMember {
    /// Name exactly as the headers state it. Not sanitized: destination path
    /// policy belongs to the caller, and the raw name is what links parts
    /// across volumes.
    pub name: String,
    /// Lowest volume number carrying a part of this member.
    pub first_volume: u32,
    /// Total unpacked size the headers declare.
    pub unpacked_size: Option<u64>,
    /// Whole-member CRC32: the final part's header for a split member, the
    /// member's own header when unsplit. `None` until that header arrives.
    pub data_crc32: Option<u32>,
    /// Whole-member BLAKE2sp, from the same header as `data_crc32`.
    pub data_blake2_hash: Option<[u8; 32]>,
    /// Whether `data_crc32` and `data_blake2_hash` are keyed folds rather than
    /// plain checksums (RAR5 `FHEXTRA_CRYPT` hash-MAC). Read from the same
    /// header as those values, so `false` until that header arrives.
    pub data_hash_uses_mac: bool,
    /// Parts in volume order.
    pub parts: Vec<StoredMemberPart>,
    /// Whether the chain runs from a known first part to a known last part with
    /// no unseen volume in between.
    pub chain_complete: bool,
    /// Classification of this member from the facts seen so far.
    pub eligibility: MemberEligibility,
}

impl StoredMember {
    /// How far the member's packed bytes may reach: the declared unpacked size
    /// for a plaintext member, its `align16` for an encrypted one — whose
    /// packed bytes are the plaintext CBC-encrypted and so run one part-block
    /// further.
    ///
    /// `None` when no header declares a size, and when an encrypted member's
    /// declared size rounds past `u64::MAX`.
    fn packed_extent(&self) -> Option<u64> {
        match self.eligibility.encrypted_store() {
            Some(encrypted) => encrypted.cipher_size,
            None => self.unpacked_size,
        }
    }
}

/// The member names one volume's headers link to its neighbours.
///
/// Split flags are the only evidence that two archive identities are the same
/// set, so a caller merging candidate sets should merge on these names alone.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VolumeSplitEvidence {
    /// Names continuing from the previous volume (`split_before`).
    pub continued_from_previous: Vec<String>,
    /// Names continuing into the next volume (`split_after`).
    pub continues_into_next: Vec<String>,
}

/// Where one run of physical volume bytes belongs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappedSlice {
    /// Bytes of a direct-routed member, at `logical_offset` inside it.
    Member {
        member_index: usize,
        logical_offset: u64,
        len: u64,
    },
    /// Cipher bytes of a [`MemberEligibility::EncryptedStore`] member, at
    /// `logical_offset` inside its cipher stream.
    ///
    /// The coordinates are exactly [`Self::Member`]'s — cipher offset and
    /// member-logical offset coincide for a stored member — and the variant
    /// differs solely so that no caller can write these bytes to a destination
    /// by mistake. Decrypting them needs the member's key and the 16 cipher
    /// bytes immediately before `logical_offset` (the member's IV when
    /// `logical_offset` is 0).
    ///
    /// A run may reach up to `align16(unpacked_size)`, so its last ≤15
    /// plaintext bytes can lie past the member's declared end; those are the
    /// [`EncryptedStore::tail_padding`] bytes and are not destination bytes.
    EncryptedMember {
        member_index: usize,
        logical_offset: u64,
        len: u64,
    },
    /// Bytes that are not inside a direct-routed member's packed range:
    /// headers, service blocks, recovery records and ineligible members' data.
    Envelope { len: u64 },
    /// Bytes whose destination is not known yet, because the volume has not
    /// been added or because the owning member's logical offset is still
    /// unresolved.
    Unroutable { len: u64 },
}

/// Rejections from [`StoredLayoutBuilder::add_volume`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StoredLayoutError {
    /// The volume was already added with different header facts.
    #[error("volume {volume} was already added with different header facts")]
    ConflictingVolume { volume: u32 },
    /// The volume belongs to a different archive format than the layout.
    #[error("volume format {found:?} does not match layout format {expected:?}")]
    FormatMismatch {
        expected: ArchiveFormat,
        found: ArchiveFormat,
    },
}

/// The header facts one volume states about one member.
///
/// Only the fields the layout consumes are kept, which is exactly the
/// comparison a re-add must survive.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MemberSnapshot {
    name: String,
    data_offset: u64,
    data_size: u64,
    unpacked_size: Option<u64>,
    data_crc32: Option<u32>,
    data_blake2_hash: Option<[u8; 32]>,
    data_hash_uses_mac: bool,
    packed_crc32: Option<u32>,
    packed_blake2_hash: Option<[u8; 32]>,
    packed_hash_uses_mac: bool,
    split_before: bool,
    split_after: bool,
    is_directory: bool,
    is_encrypted: bool,
    is_redirection: bool,
    is_store: bool,
    is_solid: bool,
    encryption: PartEncryption,
}

impl MemberSnapshot {
    /// `format` is the volume's, checked equal to the layout's before any
    /// snapshot is taken. It is here for one field: the RAR4 unpack version,
    /// which is only a cipher selector in the RAR4 family and is not one at all
    /// under RAR5.
    fn from_facts(facts: &RarVolumeMemberFacts, format: ArchiveFormat) -> Self {
        Self {
            name: facts.name.clone(),
            data_offset: facts.data_offset,
            data_size: facts.data_size,
            unpacked_size: facts.unpacked_size,
            data_crc32: facts.data_crc32,
            data_blake2_hash: facts.data_blake2_hash,
            data_hash_uses_mac: facts.use_hash_mac,
            packed_crc32: facts.packed_crc32,
            packed_blake2_hash: facts.packed_blake2_hash,
            packed_hash_uses_mac: facts.packed_hash_uses_mac,
            split_before: facts.split_before,
            split_after: facts.split_after,
            is_directory: facts.is_directory,
            is_encrypted: facts.is_encrypted,
            is_redirection: facts.redirection_type.is_some(),
            is_store: facts.compression_method == CompressionMethod::Store.code(),
            is_solid: facts.compression_solid,
            encryption: PartEncryption {
                encrypted: facts.is_encrypted,
                crypt: facts.encryption,
                rar4_salt: facts.rar4_salt,
                // The field means what it is named: the RAR4 unpack version,
                // recorded only where it selects a cipher — an encrypted part
                // of a RAR4-family volume.
                //
                // Both halves of that condition are load-bearing, because this
                // struct is compared for equality across a member's parts.
                // Recording it for *plaintext* parts would make two parts
                // stating different unpack versions `Mixed`, where before RAR4
                // was keyable they simply agreed. Recording it under **RAR5**,
                // where `compression_version` is not a cipher selector at all,
                // would do the same to two encrypted RAR5 parts — demoting a
                // member that RAR5 keys perfectly well off its `FHEXTRA_CRYPT`
                // record.
                rar4_version: (facts.is_encrypted && format.is_rar4_family())
                    .then_some(facts.compression_version),
            },
        }
    }
}

/// What one header states about its part's encryption.
///
/// Compared for equality across a member's parts: two parts that disagree
/// cannot be one cipher stream. The hash-MAC flag is deliberately outside this
/// struct — it lives on the snapshot, because it legitimately differs per part.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PartEncryption {
    encrypted: bool,
    crypt: Option<RarVolumeMemberEncryptionFacts>,
    rar4_salt: Option<[u8; 8]>,
    /// The RAR4 unpack version, which is what selects the cipher — `Some` only
    /// on an encrypted part **of a RAR4-family volume**. RAR4 has carried four
    /// different encryptions over its life and only the newest is AES-128-CBC;
    /// see [`StoredLayoutBuilder::member_encryption`]. RAR5 keys off its
    /// `FHEXTRA_CRYPT` record instead, and its version byte says nothing about
    /// a cipher, so recording one there would only be a way for two parts of
    /// one member to disagree.
    rar4_version: Option<u8>,
}

/// What a member's parts agree on about encryption, read in volume order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MemberEncryption {
    /// No part is encrypted.
    Plain,
    /// Every part is encrypted and they state the same key material.
    Uniform {
        crypt: Option<RarVolumeMemberEncryptionFacts>,
        rar4_salt: Option<[u8; 8]>,
    },
    /// Parts disagree: some encrypted and some not, or different key material.
    Mixed { volume: u32 },
    /// Every part is encrypted and they agree, but nothing here can key them:
    /// a RAR5 header claimed encryption while stating no `FHEXTRA_CRYPT`
    /// record, or a RAR4 header selected one of the three pre-AES ciphers
    /// (RAR 1.3, 1.5 and 2.0 each had their own), which are not AES-CBC, have
    /// no `align16` rule, and cannot be handed to a router as a key plus an IV.
    Unkeyable,
}

/// A member's packed range inside one volume, used by the physical mapping.
#[derive(Debug, Clone, Copy)]
struct VolumeExtent {
    member_index: usize,
    data_offset: u64,
    data_size: u64,
}

/// Everything one added volume contributes.
struct VolumeRecord {
    snapshots: Vec<MemberSnapshot>,
    /// Member extents sorted by physical offset.
    extents: Vec<VolumeExtent>,
    evidence: VolumeSplitEvidence,
}

/// Facts about a member that only ever accumulate as volumes arrive.
#[derive(Debug, Clone, Copy, Default)]
struct MemberTraits {
    /// Set by a violation a single volume proves on its own; structural chain
    /// violations are re-derived from the chain instead.
    malformed: Option<MalformedReason>,
    encrypted: bool,
    solid: bool,
    directory: bool,
    redirection: bool,
    compressed: bool,
}

/// Incremental cross-volume stored layout for one archive set.
///
/// Volumes may be added in any order and any number of times; re-adding a
/// volume with the same header facts is a no-op. See the module docs for the
/// logical-offset precondition the whole layout rests on.
pub struct StoredLayoutBuilder {
    format: ArchiveFormat,
    volumes: BTreeMap<u32, VolumeRecord>,
    members: Vec<StoredMember>,
    traits: Vec<MemberTraits>,
    /// Per member, the whole-member unpacked size each volume's header states,
    /// keyed by volume. Kept apart from the member so the size and any
    /// disagreement between parts are read in volume order rather than in the
    /// order the volumes happened to arrive. Headers stating no size at all are
    /// absent rather than recorded.
    declarations: Vec<BTreeMap<u32, u64>>,
    /// Per member, what each volume's header stated about encryption, keyed by
    /// volume. Kept apart from the member for the same reason as
    /// `declarations`: which record the member ends up with, and which volume
    /// is named when the parts disagree, must not depend on arrival order.
    encryptions: Vec<BTreeMap<u32, PartEncryption>>,
    index: HashMap<String, usize>,
    frontier: Option<u32>,
}

impl StoredLayoutBuilder {
    /// Start an empty layout for a set of the given format.
    pub fn new(format: ArchiveFormat) -> Self {
        Self {
            format,
            volumes: BTreeMap::new(),
            members: Vec::new(),
            traits: Vec::new(),
            declarations: Vec::new(),
            encryptions: Vec::new(),
            index: HashMap::new(),
            frontier: None,
        }
    }

    /// The format this layout was opened for.
    pub fn format(&self) -> ArchiveFormat {
        self.format
    }

    /// Learn one volume's headers.
    ///
    /// `volume` is the caller's 0-based index within the set, which is
    /// authoritative: RAR4 volumes do not reliably state their own number.
    ///
    /// Re-adding a volume whose facts are unchanged succeeds and changes
    /// nothing; re-adding it with different facts is rejected rather than
    /// silently rewriting a layout other volumes were already resolved against.
    pub fn add_volume(
        &mut self,
        volume: u32,
        facts: &RarVolumeFacts,
    ) -> Result<(), StoredLayoutError> {
        let found = facts.archive_format();
        if found != self.format {
            return Err(StoredLayoutError::FormatMismatch {
                expected: self.format,
                found,
            });
        }

        let snapshots: Vec<MemberSnapshot> = facts
            .members
            .iter()
            .map(|member| MemberSnapshot::from_facts(member, found))
            .collect();
        if let Some(existing) = self.volumes.get(&volume) {
            return if existing.snapshots == snapshots {
                Ok(())
            } else {
                Err(StoredLayoutError::ConflictingVolume { volume })
            };
        }

        let mut extents: Vec<VolumeExtent> = Vec::with_capacity(snapshots.len());
        let mut evidence = VolumeSplitEvidence::default();
        let mut names_here: HashSet<&str> = HashSet::with_capacity(snapshots.len());

        for snapshot in &snapshots {
            if snapshot.split_before {
                evidence.continued_from_previous.push(snapshot.name.clone());
            }
            if snapshot.split_after {
                evidence.continues_into_next.push(snapshot.name.clone());
            }

            let member_index = self.member_index_for(snapshot, volume);
            self.absorb_traits(member_index, snapshot);

            if !names_here.insert(snapshot.name.as_str()) {
                // Keep the first header and record the conflict; either way the
                // member can no longer be trusted.
                self.traits[member_index]
                    .malformed
                    .get_or_insert(MalformedReason::DuplicatePartInVolume { volume });
                continue;
            }

            if let Some(unpacked_size) = snapshot.unpacked_size {
                self.declarations[member_index].insert(volume, unpacked_size);
            }
            self.encryptions[member_index].insert(volume, snapshot.encryption);

            let member = &mut self.members[member_index];
            member.first_volume = member.first_volume.min(volume);
            // Only a final part states the whole-member checksums; every
            // earlier part's fields describe that volume's packed bytes. The
            // hash-MAC flag qualifies those checksums, so it comes from the
            // same header rather than from whichever part arrived last.
            if !snapshot.split_after {
                member.data_crc32 = snapshot.data_crc32;
                member.data_blake2_hash = snapshot.data_blake2_hash;
                member.data_hash_uses_mac = snapshot.data_hash_uses_mac;
            }

            let part = StoredMemberPart {
                volume,
                data_offset: snapshot.data_offset,
                data_size: snapshot.data_size,
                logical_offset: None,
                packed_crc32: snapshot.packed_crc32,
                packed_blake2_hash: snapshot.packed_blake2_hash,
                packed_hash_uses_mac: snapshot.packed_hash_uses_mac,
                split_before: snapshot.split_before,
                split_after: snapshot.split_after,
            };
            let position = member
                .parts
                .partition_point(|existing| existing.volume < volume);
            member.parts.insert(position, part);

            extents.push(VolumeExtent {
                member_index,
                data_offset: snapshot.data_offset,
                data_size: snapshot.data_size,
            });
        }

        extents.sort_by_key(|extent| extent.data_offset);
        // A sweep, not a walk over adjacent pairs: a member whose range sits
        // wholly inside an earlier member's range is not its neighbour once the
        // extents are sorted, yet it still overlaps it. Carrying the furthest
        // end seen so far catches every such extent, and marks both parties as
        // the pairwise check did. Zero-length extents claim no bytes and so
        // overlap nothing.
        let mut covered: Option<(u64, usize)> = None;
        for extent in &extents {
            if extent.data_size == 0 {
                continue;
            }
            let extent_end = extent.data_offset.saturating_add(extent.data_size);
            match covered {
                Some((end, owner)) if extent.data_offset < end => {
                    for member_index in [owner, extent.member_index] {
                        self.traits[member_index]
                            .malformed
                            .get_or_insert(MalformedReason::OverlappingParts { volume });
                    }
                    if extent_end > end {
                        covered = Some((extent_end, extent.member_index));
                    }
                }
                _ => covered = Some((extent_end, extent.member_index)),
            }
        }

        self.volumes.insert(
            volume,
            VolumeRecord {
                snapshots,
                extents,
                evidence,
            },
        );
        self.advance_frontier();

        // A volume also changes members it carries no part of: one added inside
        // a member's span proves a hole in that member's chain.
        let affected: Vec<usize> = (0..self.members.len())
            .filter(|index| self.member_spans(*index, volume))
            .collect();
        for index in affected {
            self.resolve_member(index);
        }

        Ok(())
    }

    /// Whether this volume's headers have been learned.
    pub fn has_volume(&self, volume: u32) -> bool {
        self.volumes.contains_key(&volume)
    }

    /// The largest `N` for which volumes `0..=N` have all been added, or `None`
    /// while volume 0 is missing.
    ///
    /// A *split continuation* arriving for a volume past the frontier cannot be
    /// placed: its logical offset is the prefix sum of the earlier parts, so it
    /// needs every earlier part's header. The frontier bounds how far ahead of
    /// the header chain such a part can be routed. It says nothing about a
    /// member that begins and ends inside one volume: that part starts at
    /// logical 0 and routes as soon as its own volume is added, however far
    /// ahead of the frontier the volume is.
    pub fn header_frontier(&self) -> Option<u32> {
        self.frontier
    }

    /// Members in the order they were first seen, which is the order
    /// [`MappedSlice::Member`] indexes them by.
    pub fn members(&self) -> &[StoredMember] {
        &self.members
    }

    /// The split flags one volume's headers carry, once that volume is added.
    pub fn split_evidence(&self, volume: u32) -> Option<&VolumeSplitEvidence> {
        self.volumes.get(&volume).map(|record| &record.evidence)
    }

    /// Split `[offset, offset + len)` of one volume into destination runs.
    ///
    /// Slices come back in physical order and cover the requested range
    /// exactly; adjacent runs of the same non-member kind are coalesced. An
    /// empty range maps to no slices.
    ///
    /// A range running past `u64::MAX` is clamped to end there before anything
    /// else — no volume byte can live at such an offset — and every branch
    /// reports the same clamped length, so the returned slices always sum to
    /// `min(len, u64::MAX - offset)`.
    pub fn map_physical_range(&self, volume: u32, offset: u64, len: u64) -> Vec<MappedSlice> {
        let mut slices = Vec::new();
        let end = offset.saturating_add(len);
        let len = end - offset;
        if len == 0 {
            return slices;
        }

        let Some(record) = self.volumes.get(&volume) else {
            slices.push(MappedSlice::Unroutable { len });
            return slices;
        };

        let mut cursor = offset;
        for extent in &record.extents {
            if cursor >= end {
                break;
            }
            if extent.data_size == 0 {
                continue;
            }
            let extent_end = extent.data_offset.saturating_add(extent.data_size);
            if extent_end <= cursor {
                continue;
            }
            if extent.data_offset >= end {
                break;
            }

            if extent.data_offset > cursor {
                push_slice(
                    &mut slices,
                    MappedSlice::Envelope {
                        len: extent.data_offset - cursor,
                    },
                );
                cursor = extent.data_offset;
            }

            let run_end = extent_end.min(end);
            let run_len = run_end - cursor;
            let member = &self.members[extent.member_index];
            if member.eligibility.routes_direct() {
                // `None` for a part whose prefix sum is still unknown, and for
                // the offset a hostile chain pushes past `u64::MAX`; both mean
                // the same thing here — these bytes have no known destination.
                let logical_offset = member
                    .parts
                    .binary_search_by_key(&volume, |part| part.volume)
                    .ok()
                    .and_then(|position| member.parts[position].logical_offset)
                    .and_then(|base| base.checked_add(cursor - extent.data_offset));
                push_member_run(
                    &mut slices,
                    extent.member_index,
                    member.packed_extent(),
                    member.eligibility.encrypted_store().is_some(),
                    logical_offset,
                    run_len,
                );
            } else {
                push_slice(&mut slices, MappedSlice::Envelope { len: run_len });
            }
            cursor = run_end;
        }

        if cursor < end {
            push_slice(&mut slices, MappedSlice::Envelope { len: end - cursor });
        }
        debug_assert_eq!(
            slices.iter().map(slice_len).sum::<u64>(),
            len,
            "mapped slices must cover the clamped request exactly"
        );
        slices
    }

    /// Find or create the member a header belongs to, keyed by header name.
    fn member_index_for(&mut self, snapshot: &MemberSnapshot, volume: u32) -> usize {
        if let Some(index) = self.index.get(&snapshot.name) {
            return *index;
        }
        let index = self.members.len();
        self.members.push(StoredMember {
            name: snapshot.name.clone(),
            first_volume: volume,
            unpacked_size: None,
            data_crc32: None,
            data_blake2_hash: None,
            data_hash_uses_mac: false,
            parts: Vec::new(),
            chain_complete: false,
            eligibility: MemberEligibility::ProvisionallyDirect,
        });
        self.traits.push(MemberTraits::default());
        self.declarations.push(BTreeMap::new());
        self.encryptions.push(BTreeMap::new());
        self.index.insert(snapshot.name.clone(), index);
        index
    }

    /// Fold one header's disqualifying facts into the member's running traits.
    fn absorb_traits(&mut self, member_index: usize, snapshot: &MemberSnapshot) {
        let traits = &mut self.traits[member_index];
        traits.encrypted |= snapshot.is_encrypted;
        traits.solid |= snapshot.is_solid;
        traits.directory |= snapshot.is_directory;
        traits.redirection |= snapshot.is_redirection;
        traits.compressed |= !snapshot.is_store;
    }

    fn member_spans(&self, member_index: usize, volume: u32) -> bool {
        let parts = &self.members[member_index].parts;
        match (parts.first(), parts.last()) {
            (Some(first), Some(last)) => first.volume <= volume && volume <= last.volume,
            _ => false,
        }
    }

    fn advance_frontier(&mut self) {
        if !self.volumes.contains_key(&0) {
            return;
        }
        let mut frontier = self.frontier.unwrap_or(0);
        while let Some(next) = frontier.checked_add(1) {
            if !self.volumes.contains_key(&next) {
                break;
            }
            frontier = next;
        }
        self.frontier = Some(frontier);
    }

    /// Re-derive one member's logical offsets, completeness and classification.
    fn resolve_member(&mut self, member_index: usize) {
        let mut parts = std::mem::take(&mut self.members[member_index].parts);

        // A logical offset is the prefix sum of the earlier parts, so it exists
        // only from a known first part and only across an unbroken run. Sums
        // are checked, never saturated: a saturated offset is a plausible-
        // looking lie, and headers claiming petabyte-scale parts are free.
        let head_known = parts.first().is_some_and(|part| !part.split_before);
        let mut running = head_known.then_some(0u64);
        let mut expected_volume = parts.first().map_or(0, |part| part.volume);
        let mut packed_total = Some(0u64);
        for part in &mut parts {
            if part.volume != expected_volume {
                running = None;
            }
            part.logical_offset = running;
            running = running.and_then(|value| value.checked_add(part.data_size));
            expected_volume = part.volume.saturating_add(1);
            packed_total = packed_total.and_then(|value| value.checked_add(part.data_size));
        }

        let chain_complete =
            running.is_some() && parts.last().is_some_and(|part| !part.split_after);

        // Read in volume order rather than arrival order, so which size the
        // member ends up with — and whether its parts disagree at all — does
        // not depend on which volume happened to arrive first.
        let mut declared = self.declarations[member_index].values().copied();
        let unpacked_size = declared.next();
        let inconsistent = unpacked_size.and_then(|first| {
            declared
                .find(|other| *other != first)
                .map(|second| MalformedReason::InconsistentUnpackedSize { first, second })
        });

        let traits = self.traits[member_index];
        let encryption = self.member_encryption(member_index);
        // Appended last so a chain that is both size-inconsistent and
        // encryption-inconsistent keeps reporting the size disagreement, as it
        // did before encrypted members were classified at all.
        let mixed_encryption = match encryption {
            MemberEncryption::Mixed { volume } => Some(MalformedReason::MixedEncryption { volume }),
            _ => None,
        };
        let malformed = traits
            .malformed
            .or_else(|| self.chain_malformation(&parts))
            .or(inconsistent)
            .or(mixed_encryption);

        let format = self.format;
        let member = &mut self.members[member_index];
        member.unpacked_size = unpacked_size;
        let eligibility = classify(
            traits,
            ChainFacts {
                format,
                malformed,
                complete: chain_complete,
                packed_total,
                unpacked_size,
                data_crc32: member.data_crc32,
                data_blake2_hash: member.data_blake2_hash,
            },
            encryption,
        );
        member.eligibility = eligibility;
        member.chain_complete = chain_complete;
        member.parts = parts;
    }

    /// Fold one member's per-volume encryption records into what its parts
    /// agree on, read in volume order.
    fn member_encryption(&self, member_index: usize) -> MemberEncryption {
        let mut records = self.encryptions[member_index].iter();
        let Some((_, first)) = records.next() else {
            return MemberEncryption::Plain;
        };
        if let Some((volume, _)) = records.find(|(_, record)| *record != first) {
            return MemberEncryption::Mixed { volume: *volume };
        }
        if !first.encrypted {
            return MemberEncryption::Plain;
        }
        // Keyability is a per-format question, so the format asks it — the same
        // discriminant [`EncryptedStore::keying`] answers with. Deciding it from
        // the presence of a `FHEXTRA_CRYPT` record instead would let one
        // format's evidence settle the other format's question.
        match self.format {
            // RAR5 states its key material in the record, so a header claiming
            // encryption without one leaves nothing to key.
            ArchiveFormat::Rar5 => {
                if first.crypt.is_none() {
                    return MemberEncryption::Unkeyable;
                }
            }
            // RAR4 states no per-file record at all — its key comes from the
            // password and the optional salt — and its *cipher* is chosen by
            // the unpack version. Only the newest one, "RAR 3.0" encryption
            // (AES-128-CBC), is the shape this whole classification assumes:
            // one CBC stream over the member's plaintext, padded once to a
            // whole block. RAR 1.3 and 1.5 are stream ciphers with no padding
            // at all and RAR 2.0 is its own block cipher, so an `align16` sum
            // would be meaningless for them and decrypting them as AES would
            // silently produce garbage that only the member checksum could
            // catch. They stay ineligible — and so does a RAR4 header that
            // somehow carried a RAR5 record, because the version is still what
            // says which cipher wrote the bytes.
            ArchiveFormat::Rar4 | ArchiveFormat::Rar14 => {
                if !first
                    .rar4_version
                    .is_some_and(|version| rar4_uses_aes(self.format, version))
                {
                    return MemberEncryption::Unkeyable;
                }
            }
        }
        MemberEncryption::Uniform {
            crypt: first.crypt,
            rar4_salt: first.rar4_salt,
        }
    }

    /// Structural violations a chain proves once enough volumes are present.
    fn chain_malformation(&self, parts: &[StoredMemberPart]) -> Option<MalformedReason> {
        let last_position = parts.len().checked_sub(1)?;
        for (position, part) in parts.iter().enumerate() {
            if !part.split_before && position != 0 {
                return Some(MalformedReason::UnexpectedChainStart {
                    volume: part.volume,
                });
            }
            if !part.split_after && position != last_position {
                return Some(MalformedReason::UnexpectedChainEnd {
                    volume: part.volume,
                });
            }
        }

        let first = parts.first()?;
        if first.split_before && first.volume == 0 {
            return Some(MalformedReason::ContinuationInFirstVolume);
        }

        // A hole is only provably wrong once the volume that should have filled
        // it has been added and turned out to carry nothing for this member.
        let mut expected_volume = first.volume;
        for part in parts {
            while expected_volume < part.volume {
                if self.volumes.contains_key(&expected_volume) {
                    return Some(MalformedReason::MissingPartInAddedVolume {
                        volume: expected_volume,
                    });
                }
                expected_volume += 1;
            }
            expected_volume = part.volume.saturating_add(1);
        }

        None
    }
}

/// Append a slice, merging it into a same-kind run where that is meaningful.
fn push_slice(slices: &mut Vec<MappedSlice>, slice: MappedSlice) {
    match (slices.last_mut(), slice) {
        (Some(MappedSlice::Envelope { len }), MappedSlice::Envelope { len: extra })
        | (Some(MappedSlice::Unroutable { len }), MappedSlice::Unroutable { len: extra }) => {
            *len = len.saturating_add(extra);
        }
        _ => slices.push(slice),
    }
}

/// How many bytes one slice accounts for.
fn slice_len(slice: &MappedSlice) -> u64 {
    match *slice {
        MappedSlice::Member { len, .. }
        | MappedSlice::EncryptedMember { len, .. }
        | MappedSlice::Envelope { len }
        | MappedSlice::Unroutable { len } => len,
    }
}

/// Append one extent run belonging to a member the layout routes.
///
/// A run is the member's bytes only as far as `packed_extent` reaches — the
/// declared unpacked size, or its `align16` for an encrypted member. An open
/// chain is routed before anything has checked its totals, so a part can claim
/// packed bytes that run past that end; those bytes have no destination — the
/// chain closing is what will demote the member — and are reported unroutable
/// rather than written past the file's length. An unknown offset (unresolved
/// prefix sum, or one pushed past `u64::MAX`) makes the whole run unroutable
/// the same way.
fn push_member_run(
    slices: &mut Vec<MappedSlice>,
    member_index: usize,
    packed_extent: Option<u64>,
    encrypted: bool,
    logical_offset: Option<u64>,
    run_len: u64,
) {
    let routed = logical_offset
        .map(|logical_offset| {
            let limit = packed_extent.unwrap_or(u64::MAX);
            let room = limit.saturating_sub(logical_offset);
            (logical_offset, run_len.min(room))
        })
        .filter(|(_, len)| *len > 0);

    let Some((logical_offset, len)) = routed else {
        push_slice(slices, MappedSlice::Unroutable { len: run_len });
        return;
    };
    push_slice(
        slices,
        if encrypted {
            MappedSlice::EncryptedMember {
                member_index,
                logical_offset,
                len,
            }
        } else {
            MappedSlice::Member {
                member_index,
                logical_offset,
                len,
            }
        },
    );
    if len < run_len {
        push_slice(slices, MappedSlice::Unroutable { len: run_len - len });
    }
}

/// What one resolved chain states about itself, as [`classify`] reads it.
#[derive(Debug, Clone, Copy)]
struct ChainFacts {
    /// The set's format, checked equal to every volume's before a fact from it
    /// was recorded. It is what an encrypted member is keyed *as*, so it
    /// travels with the facts rather than being re-inferred from them.
    format: ArchiveFormat,
    malformed: Option<MalformedReason>,
    /// The chain runs from a known first part to a known last part with no
    /// unseen volume in between.
    complete: bool,
    /// The parts' packed sizes summed, or `None` when that sum runs past
    /// `u64::MAX` — impossible for real bytes, free for a header to claim.
    packed_total: Option<u64>,
    unpacked_size: Option<u64>,
    data_crc32: Option<u32>,
    data_blake2_hash: Option<[u8; 32]>,
}

/// Classify a member from its accumulated facts.
///
/// The order is deliberate: a fact that rules out any handling is reported
/// ahead of one a caller might tolerate, so an encrypted or solid member never
/// presents itself as merely compressed.
fn classify(
    traits: MemberTraits,
    chain: ChainFacts,
    encryption: MemberEncryption,
) -> MemberEligibility {
    use IneligibilityReason as Reason;

    if let Some(reason) = chain.malformed {
        return MemberEligibility::Ineligible(Reason::MalformedChain(reason));
    }
    if traits.directory {
        return MemberEligibility::Ineligible(Reason::Directory);
    }
    if traits.redirection {
        return MemberEligibility::Ineligible(Reason::Redirection);
    }
    if traits.encrypted {
        // Only a stored member's cipher bytes are the member's own bytes at
        // the member's own offsets. Compressed or solid, the cipher stream
        // decrypts to packed data that still has to go through a codec, so the
        // member stays exactly as ineligible as it was before encrypted store
        // was classified at all — including staying `Encrypted` rather than
        // `Solid` or `Compressed`, which is the answer this order has always
        // given for an encrypted member.
        let MemberEncryption::Uniform { crypt, rar4_salt } = encryption else {
            return MemberEligibility::Ineligible(Reason::Encrypted);
        };
        if traits.solid || traits.compressed {
            return MemberEligibility::Ineligible(Reason::Encrypted);
        }
        return classify_stored_chain(chain, Some((crypt, rar4_salt)));
    }
    if traits.solid {
        return MemberEligibility::Ineligible(Reason::Solid);
    }
    if traits.compressed {
        return MemberEligibility::Ineligible(Reason::Compressed {
            packed_bytes: chain.packed_total,
            unpacked_bytes: chain.unpacked_size,
            totals_final: chain.complete,
        });
    }

    classify_stored_chain(chain, None)
}

/// Classify a `Store` chain that nothing else has disqualified.
///
/// `encrypted` carries the member's key material when its parts are encrypted,
/// and is the only difference between the two paths: an encrypted chain's
/// packed bytes are its plaintext CBC-encrypted, so they sum to
/// `align16(unpacked_size)` rather than to `unpacked_size` itself. Everything
/// else — when the totals may be checked, which checksums are required — is
/// the same question over the same facts.
fn classify_stored_chain(
    chain: ChainFacts,
    encrypted: Option<(Option<RarVolumeMemberEncryptionFacts>, Option<[u8; 8]>)>,
) -> MemberEligibility {
    use IneligibilityReason as Reason;

    // A sum past `u64::MAX` exceeds every size a header can declare, so it is
    // read at its saturated value from here down.
    let packed_total = chain.packed_total.unwrap_or(u64::MAX);
    // How far the chain's packed bytes may legitimately reach. `None` means
    // either that no header declared a size, or — for an encrypted member
    // whose declared size rounds past `u64::MAX` — that the true limit is not
    // representable; the two are told apart by `chain.unpacked_size` below.
    let extent = match encrypted {
        Some(_) => chain.unpacked_size.and_then(align16),
        None => chain.unpacked_size,
    };
    let encrypted_state = |resolved: bool| {
        let (crypt, rar4_salt) = encrypted.expect("only called on the encrypted path");
        MemberEligibility::EncryptedStore(EncryptedStore {
            format: chain.format,
            crypt,
            rar4_salt,
            cipher_size: extent,
            // Both `Some` or both `None`: the padding is `extent - declared`,
            // so it exists exactly when the extent does.
            tail_padding: extent.zip(chain.unpacked_size).map(|(cipher, unpacked)| {
                debug_assert!(cipher - unpacked < AES_BLOCK);
                (cipher - unpacked) as u8
            }),
            resolved,
        })
    };

    // Stored bytes are the member's bytes, so the chain can never carry more of
    // them than the member declares. Checked before the chain closes as well:
    // an open chain routes, and a part reaching past the declared end would
    // otherwise hand the caller a destination the file does not have.
    if let Some(unpacked_size) = chain.unpacked_size
        && packed_total > extent.unwrap_or(u64::MAX)
    {
        return MemberEligibility::Ineligible(Reason::MalformedChain(
            MalformedReason::ExceedsDeclaredSize {
                packed_total,
                unpacked_size,
            },
        ));
    }
    if !chain.complete {
        return match encrypted {
            Some(_) => encrypted_state(false),
            None => MemberEligibility::ProvisionallyDirect,
        };
    }

    let Some(unpacked_size) = chain.unpacked_size else {
        return MemberEligibility::Ineligible(Reason::MalformedChain(
            MalformedReason::MissingUnpackedSize,
        ));
    };
    // A complete chain must sum to exactly the extent — the check above has
    // already ruled out overshooting. Never checked per part: only the sum is
    // meaningful, and an encrypted member's parts are not individually
    // block-aligned. An unrepresentable extent can equal no sum, so it lands
    // here as a mismatch rather than passing by default.
    if extent != Some(packed_total) {
        return MemberEligibility::Ineligible(Reason::MalformedChain(
            MalformedReason::SizeMismatch {
                packed_total,
                unpacked_size,
            },
        ));
    }

    match (chain.data_crc32, chain.data_blake2_hash) {
        (Some(_), _) => match encrypted {
            Some(_) => encrypted_state(true),
            None => MemberEligibility::DirectEligible,
        },
        (None, Some(_)) => MemberEligibility::Ineligible(Reason::Blake2OnlyNoCrc32),
        (None, None) => MemberEligibility::Ineligible(Reason::NoChecksum),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::RarArchive;

    const EPISODE: &str = "Silver.Horizon.S01E01.mkv";
    const EXTRA: &str = "Silver.Horizon.S01E01.nfo";
    const NEIGHBOUR: &str = "Silver.Horizon.S01E02.mkv";
    const DISTANT: &str = "Silver.Horizon.S01E03.mkv";

    /// A stored, unsplit, unencrypted member with no checksum yet.
    fn member(name: &str, data_offset: u64, data_size: u64) -> RarVolumeMemberFacts {
        RarVolumeMemberFacts {
            order: 0,
            name: name.to_string(),
            name_raw: None,
            unpacked_size: Some(data_size),
            data_crc32: None,
            data_blake2_hash: None,
            version: None,
            packed_crc32: None,
            packed_blake2_hash: None,
            packed_hash_uses_mac: false,
            split_before: false,
            split_after: false,
            is_directory: false,
            is_encrypted: false,
            encryption: None,
            rar4_salt: None,
            host_os: None,
            attributes: None,
            owner: None,
            mtime_ns: None,
            ctime_ns: None,
            atime_ns: None,
            data_offset,
            data_size,
            compression_method: CompressionMethod::Store.code(),
            compression_version: 5,
            compression_solid: false,
            dict_size: 0,
            use_hash_mac: false,
            redirection_type: None,
            redirection_target: None,
            redirection_target_raw: None,
            redirection_target_is_directory: false,
        }
    }

    /// One part of a member split across volumes. `unpacked_size` is the whole
    /// member's size, exactly as every split header states it.
    fn split_part(
        name: &str,
        data_offset: u64,
        data_size: u64,
        unpacked_size: u64,
        split_before: bool,
        split_after: bool,
    ) -> RarVolumeMemberFacts {
        let mut facts = member(name, data_offset, data_size);
        facts.unpacked_size = Some(unpacked_size);
        facts.split_before = split_before;
        facts.split_after = split_after;
        if split_after {
            facts.packed_crc32 = Some(0xC0DE_0000_u32.wrapping_add(data_size as u32));
        }
        facts
    }

    /// Deterministic, non-uniform part sizes. A prefix sum over these cannot be
    /// mistaken for `index * size`, so a test asserting one is asserting the
    /// real thing.
    fn part_size(number: u32) -> u64 {
        512 + u64::from((number * 37) % 89) * 8
    }

    /// The RAR5 crypt record every part of an encrypted fixture member states.
    /// Distinct byte fills so a test cannot pass by confusing salt with IV.
    fn crypt_record() -> RarVolumeMemberEncryptionFacts {
        RarVolumeMemberEncryptionFacts {
            version: 0,
            kdf_count_lg2: 15,
            salt: [0x5A; 16],
            iv: [0x1F; 16],
            psw_check_present: true,
            psw_check: Some([0xC4; 12]),
        }
    }

    /// Mark a header encrypted, carrying `crypt`.
    fn encrypted(
        mut facts: RarVolumeMemberFacts,
        crypt: RarVolumeMemberEncryptionFacts,
    ) -> RarVolumeMemberFacts {
        facts.is_encrypted = true;
        facts.encryption = Some(crypt);
        facts
    }

    /// One encrypted, unsplit `Store` member whose packed bytes are the
    /// `align16` of `unpacked_size`, as RAR writes them.
    fn encrypted_member(name: &str, data_offset: u64, unpacked_size: u64) -> RarVolumeMemberFacts {
        let cipher_size = align16(unpacked_size).expect("test sizes are small");
        let mut facts = encrypted(member(name, data_offset, cipher_size), crypt_record());
        facts.unpacked_size = Some(unpacked_size);
        facts.data_crc32 = Some(0x1234_5678);
        facts
    }

    /// The encrypted-store facts of a member the layout classified that way.
    fn encrypted_store(builder: &StoredLayoutBuilder, index: usize) -> EncryptedStore {
        match builder.members()[index].eligibility {
            MemberEligibility::EncryptedStore(facts) => facts,
            other => panic!("expected an encrypted-store member, got {other:?}"),
        }
    }

    /// Every part's currently reported offset, keyed by the part's identity
    /// rather than its position, so a newly inserted part cannot look like a
    /// moved one.
    fn reported_offsets(builder: &StoredLayoutBuilder) -> BTreeMap<(String, u32), Option<u64>> {
        builder
            .members()
            .iter()
            .flat_map(|member| {
                member
                    .parts
                    .iter()
                    .map(|part| ((member.name.clone(), part.volume), part.logical_offset))
            })
            .collect()
    }

    /// Add a volume and hold the layout to its one stability promise: a part
    /// that has already reported an offset never reports a different one, and
    /// never withdraws it, unless that same call turns its member ineligible.
    fn add_stably(builder: &mut StoredLayoutBuilder, number: u32, facts: &RarVolumeFacts) {
        let before = reported_offsets(builder);
        add(builder, number, facts);
        let after = reported_offsets(builder);

        for ((name, volume), old) in before {
            // An unresolved part resolving is the whole point of the layout.
            let Some(old) = old else { continue };
            let new = after[&(name.clone(), volume)];
            if new == Some(old) {
                continue;
            }
            let member = builder
                .members()
                .iter()
                .find(|member| member.name == name)
                .expect("members are never dropped");
            assert!(
                matches!(
                    member.eligibility,
                    MemberEligibility::Ineligible(IneligibilityReason::MalformedChain(_))
                ),
                "volume {volume} of {name} moved from {old} to {new:?} while the member was \
                 still {:?}",
                member.eligibility
            );
        }
    }

    fn with_crc32(mut facts: RarVolumeMemberFacts, crc32: u32) -> RarVolumeMemberFacts {
        facts.data_crc32 = Some(crc32);
        facts
    }

    fn volume(members: Vec<RarVolumeMemberFacts>) -> RarVolumeFacts {
        RarVolumeFacts {
            format: 5,
            volume_number: 0,
            more_volumes: false,
            is_solid: false,
            is_encrypted: false,
            is_volume: true,
            has_recovery_record: false,
            is_locked: false,
            has_authenticity_verification: false,
            has_locator: false,
            quick_open_offset: None,
            recovery_record_offset: None,
            original_name: None,
            original_name_raw: None,
            original_creation_time_ns: None,
            members,
            services: Vec::new(),
        }
    }

    fn layout() -> StoredLayoutBuilder {
        StoredLayoutBuilder::new(ArchiveFormat::Rar5)
    }

    fn add(builder: &mut StoredLayoutBuilder, number: u32, facts: &RarVolumeFacts) {
        builder.add_volume(number, facts).expect("volume accepted");
    }

    fn ineligible(builder: &StoredLayoutBuilder, index: usize) -> IneligibilityReason {
        match builder.members()[index].eligibility {
            MemberEligibility::Ineligible(reason) => reason,
            other => panic!("expected an ineligible member, got {other:?}"),
        }
    }

    #[test]
    fn unsplit_store_member_is_direct_eligible_and_maps_around_the_envelope() {
        let mut builder = layout();
        add(
            &mut builder,
            0,
            &volume(vec![with_crc32(member(EPISODE, 100, 64), 0x1234_5678)]),
        );

        let member = &builder.members()[0];
        assert_eq!(member.name, EPISODE);
        assert_eq!(member.first_volume, 0);
        assert!(member.chain_complete);
        assert_eq!(member.eligibility, MemberEligibility::DirectEligible);
        assert_eq!(member.parts[0].logical_offset, Some(0));
        assert_eq!(member.data_crc32, Some(0x1234_5678));
        assert_eq!(builder.header_frontier(), Some(0));

        assert_eq!(
            builder.map_physical_range(0, 0, 200),
            vec![
                MappedSlice::Envelope { len: 100 },
                MappedSlice::Member {
                    member_index: 0,
                    logical_offset: 0,
                    len: 64,
                },
                MappedSlice::Envelope { len: 36 },
            ]
        );
        assert!(builder.map_physical_range(0, 0, 0).is_empty());
    }

    #[test]
    fn member_split_across_three_volumes_resolves_prefix_sums() {
        let mut builder = layout();
        add(
            &mut builder,
            0,
            &volume(vec![split_part(EPISODE, 40, 10, 60, false, true)]),
        );
        add(
            &mut builder,
            1,
            &volume(vec![split_part(EPISODE, 44, 20, 60, true, true)]),
        );
        add(
            &mut builder,
            2,
            &volume(vec![with_crc32(
                split_part(EPISODE, 48, 30, 60, true, false),
                0xFEED_BEEF,
            )]),
        );

        let member = &builder.members()[0];
        assert_eq!(member.parts.len(), 3);
        assert_eq!(
            member
                .parts
                .iter()
                .map(|part| part.logical_offset)
                .collect::<Vec<_>>(),
            vec![Some(0), Some(10), Some(30)]
        );
        assert!(member.chain_complete);
        assert_eq!(member.eligibility, MemberEligibility::DirectEligible);
        // Whole-member checksums come from the final part only.
        assert_eq!(member.data_crc32, Some(0xFEED_BEEF));
        assert!(member.parts[0].packed_crc32.is_some());
        assert!(member.parts[1].packed_crc32.is_some());
        assert_eq!(member.parts[2].packed_crc32, None);

        assert_eq!(
            builder.map_physical_range(1, 44, 20),
            vec![MappedSlice::Member {
                member_index: 0,
                logical_offset: 10,
                len: 20,
            }]
        );
        // A range starting mid-part keeps the logical offset in step.
        assert_eq!(
            builder.map_physical_range(2, 60, 30),
            vec![
                MappedSlice::Member {
                    member_index: 0,
                    logical_offset: 42,
                    len: 18,
                },
                MappedSlice::Envelope { len: 12 },
            ]
        );
    }

    #[test]
    fn split_member_stays_provisional_until_its_final_header_arrives() {
        let mut builder = layout();
        add(
            &mut builder,
            0,
            &volume(vec![split_part(EPISODE, 40, 10, 60, false, true)]),
        );

        assert_eq!(
            builder.members()[0].eligibility,
            MemberEligibility::ProvisionallyDirect
        );
        assert!(!builder.members()[0].chain_complete);
        // Provisional members still route: the chain closing is what decides
        // whether they stay direct.
        assert_eq!(
            builder.map_physical_range(0, 40, 10),
            vec![MappedSlice::Member {
                member_index: 0,
                logical_offset: 0,
                len: 10,
            }]
        );
    }

    #[test]
    fn a_long_chain_resolves_each_prefix_sum_as_its_volume_arrives() {
        const VOLUMES: u32 = 64;
        const HEADER: u64 = 96;

        let total: u64 = (0..VOLUMES).map(part_size).sum();
        let mut builder = layout();
        let mut expected_offset = 0u64;
        for number in 0..VOLUMES {
            let size = part_size(number);
            let part = split_part(
                EPISODE,
                HEADER,
                size,
                total,
                number > 0,
                number + 1 < VOLUMES,
            );
            let facts = volume(vec![if number + 1 == VOLUMES {
                with_crc32(part, 0x0BAD_F00D)
            } else {
                part
            }]);
            // Payload for a volume not yet added is not placeable at all.
            assert_eq!(
                builder.map_physical_range(number, HEADER, size),
                vec![MappedSlice::Unroutable { len: size }]
            );

            add_stably(&mut builder, number, &facts);

            assert_eq!(builder.header_frontier(), Some(number));
            assert_eq!(
                builder.map_physical_range(number, HEADER, size),
                vec![MappedSlice::Member {
                    member_index: 0,
                    logical_offset: expected_offset,
                    len: size,
                }]
            );
            expected_offset += size;
        }
        assert_eq!(expected_offset, total);

        let member = &builder.members()[0];
        assert_eq!(member.parts.len(), VOLUMES as usize);
        let mut running = 0u64;
        for (position, part) in member.parts.iter().enumerate() {
            assert_eq!(part.data_size, part_size(position as u32));
            assert_eq!(part.logical_offset, Some(running));
            running += part.data_size;
        }
        assert_eq!(member.eligibility, MemberEligibility::DirectEligible);
    }

    #[test]
    fn an_unsplit_member_routes_ahead_of_the_header_frontier() {
        // The frontier bounds split continuations, which need every earlier
        // part's header. A member that starts and ends in one volume starts at
        // logical 0 whatever the frontier says.
        let mut builder = layout();
        add(
            &mut builder,
            7,
            &volume(vec![with_crc32(member(EXTRA, 40, 10), 0x1111_1111)]),
        );

        assert_eq!(builder.header_frontier(), None);
        assert_eq!(
            builder.map_physical_range(7, 40, 10),
            vec![MappedSlice::Member {
                member_index: 0,
                logical_offset: 0,
                len: 10,
            }]
        );
    }

    #[test]
    fn long_chain_added_out_of_order_resolves_when_the_gap_closes() {
        const VOLUMES: u32 = 52;
        const HEADER: u64 = 64;

        let total: u64 = (0..VOLUMES).map(part_size).sum();
        let offset_of = |number: u32| -> u64 { (0..number).map(part_size).sum() };
        let facts_for = |number: u32| {
            let part = split_part(
                EPISODE,
                HEADER,
                part_size(number),
                total,
                number > 0,
                number + 1 < VOLUMES,
            );
            let part = if number + 1 == VOLUMES {
                with_crc32(part, 0x0BAD_F00D)
            } else {
                part
            };
            volume(vec![part])
        };

        // Everything except volume 1, newest first.
        let mut builder = layout();
        for number in (0..VOLUMES).rev() {
            if number == 1 {
                continue;
            }
            add_stably(&mut builder, number, &facts_for(number));
        }

        assert_eq!(builder.header_frontier(), Some(0));
        assert_eq!(builder.members()[0].parts[0].logical_offset, Some(0));
        assert!(
            builder.members()[0].parts[1..]
                .iter()
                .all(|part| part.logical_offset.is_none()),
            "no part past the hole can know where it starts"
        );
        assert_eq!(
            builder.map_physical_range(2, HEADER, part_size(2)),
            vec![MappedSlice::Unroutable { len: part_size(2) }]
        );

        add_stably(&mut builder, 1, &facts_for(1));

        assert_eq!(builder.header_frontier(), Some(VOLUMES - 1));
        let member = &builder.members()[0];
        let mut running = 0u64;
        for (position, part) in member.parts.iter().enumerate() {
            assert_eq!(part.data_size, part_size(position as u32));
            assert_eq!(part.logical_offset, Some(running));
            running += part.data_size;
        }
        assert_eq!(running, total);
        assert_eq!(member.eligibility, MemberEligibility::DirectEligible);
        assert_eq!(
            builder.map_physical_range(2, HEADER, part_size(2)),
            vec![MappedSlice::Member {
                member_index: 0,
                logical_offset: offset_of(2),
                len: part_size(2),
            }]
        );
    }

    #[test]
    fn multiple_members_in_one_volume_map_across_their_boundaries() {
        let mut builder = layout();
        add(
            &mut builder,
            0,
            &volume(vec![
                with_crc32(member(EPISODE, 50, 100), 0x1111_1111),
                with_crc32(member(EXTRA, 170, 30), 0x2222_2222),
            ]),
        );

        // A span straddling the first member's tail, the header gap and the
        // second member's head.
        assert_eq!(
            builder.map_physical_range(0, 120, 70),
            vec![
                MappedSlice::Member {
                    member_index: 0,
                    logical_offset: 70,
                    len: 30,
                },
                MappedSlice::Envelope { len: 20 },
                MappedSlice::Member {
                    member_index: 1,
                    logical_offset: 0,
                    len: 20,
                },
            ]
        );
        // A whole-volume span covers both members and every envelope run.
        assert_eq!(
            builder.map_physical_range(0, 0, 220),
            vec![
                MappedSlice::Envelope { len: 50 },
                MappedSlice::Member {
                    member_index: 0,
                    logical_offset: 0,
                    len: 100,
                },
                MappedSlice::Envelope { len: 20 },
                MappedSlice::Member {
                    member_index: 1,
                    logical_offset: 0,
                    len: 30,
                },
                MappedSlice::Envelope { len: 20 },
            ]
        );
        // A span wholly inside one member stays one slice.
        assert_eq!(
            builder.map_physical_range(0, 60, 10),
            vec![MappedSlice::Member {
                member_index: 0,
                logical_offset: 10,
                len: 10,
            }]
        );
    }

    #[test]
    fn an_ineligible_member_routes_its_packed_bytes_into_the_envelope() {
        let mut compressed = member(EXTRA, 170, 30);
        compressed.compression_method = CompressionMethod::Normal.code();
        compressed.unpacked_size = Some(90);

        let mut builder = layout();
        add(
            &mut builder,
            0,
            &volume(vec![
                with_crc32(member(EPISODE, 50, 100), 0x1111_1111),
                with_crc32(compressed, 0x2222_2222),
            ]),
        );

        assert_eq!(
            ineligible(&builder, 1),
            IneligibilityReason::Compressed {
                packed_bytes: Some(30),
                unpacked_bytes: Some(90),
                totals_final: true,
            }
        );
        // The gap, the compressed member's packed bytes and the trailing gap
        // are one envelope run.
        assert_eq!(
            builder.map_physical_range(0, 150, 60),
            vec![MappedSlice::Envelope { len: 60 }]
        );
    }

    #[test]
    fn a_compressed_members_byte_counts_say_whether_they_are_totals() {
        // A caller budgeting the cost of tolerating a compressed member must be
        // able to tell a total from a running lower bound, and an undeclared
        // size from a zero-byte member.
        let compressed = |facts: RarVolumeMemberFacts| {
            let mut facts = facts;
            facts.compression_method = CompressionMethod::Normal.code();
            facts
        };

        let mut builder = layout();
        add(
            &mut builder,
            0,
            &volume(vec![compressed(split_part(EXTRA, 40, 30, 90, false, true))]),
        );
        assert_eq!(
            ineligible(&builder, 0),
            IneligibilityReason::Compressed {
                packed_bytes: Some(30),
                unpacked_bytes: Some(90),
                totals_final: false,
            },
            "an open chain has more parts to come"
        );

        add(
            &mut builder,
            1,
            &volume(vec![with_crc32(
                compressed(split_part(EXTRA, 40, 25, 90, true, false)),
                0x2222_2222,
            )]),
        );
        assert_eq!(
            ineligible(&builder, 0),
            IneligibilityReason::Compressed {
                packed_bytes: Some(55),
                unpacked_bytes: Some(90),
                totals_final: true,
            }
        );

        // A member whose header states no unpacked size reports none, not zero.
        let mut sizeless = compressed(member(EPISODE, 40, 10));
        sizeless.unpacked_size = None;
        let mut builder = layout();
        add(&mut builder, 0, &volume(vec![sizeless]));
        assert_eq!(
            ineligible(&builder, 0),
            IneligibilityReason::Compressed {
                packed_bytes: Some(10),
                unpacked_bytes: None,
                totals_final: true,
            }
        );
    }

    #[test]
    fn missing_middle_volume_is_malformed_once_that_volume_arrives() {
        let mut builder = layout();
        add(
            &mut builder,
            0,
            &volume(vec![split_part(EPISODE, 40, 10, 60, false, true)]),
        );
        add(
            &mut builder,
            2,
            &volume(vec![with_crc32(
                split_part(EPISODE, 40, 30, 60, true, false),
                0xFEED_BEEF,
            )]),
        );
        // A hole is not yet a fault: volume 1 simply has not been seen.
        assert_eq!(
            builder.members()[0].eligibility,
            MemberEligibility::ProvisionallyDirect
        );

        add(&mut builder, 1, &volume(vec![member(EXTRA, 40, 20)]));

        assert_eq!(
            ineligible(&builder, 0),
            IneligibilityReason::MalformedChain(MalformedReason::MissingPartInAddedVolume {
                volume: 1,
            })
        );
        // Malformed members take the envelope path rather than panicking.
        assert_eq!(
            builder.map_physical_range(0, 40, 10),
            vec![MappedSlice::Envelope { len: 10 }]
        );
    }

    #[test]
    fn continuation_in_the_first_volume_is_malformed() {
        let mut builder = layout();
        add(
            &mut builder,
            0,
            &volume(vec![split_part(EPISODE, 40, 10, 60, true, true)]),
        );

        assert_eq!(
            ineligible(&builder, 0),
            IneligibilityReason::MalformedChain(MalformedReason::ContinuationInFirstVolume)
        );
    }

    #[test]
    fn a_second_chain_start_inside_a_member_is_malformed() {
        let mut builder = layout();
        add(
            &mut builder,
            0,
            &volume(vec![split_part(EPISODE, 40, 10, 60, false, true)]),
        );
        add(
            &mut builder,
            1,
            &volume(vec![split_part(EPISODE, 40, 50, 60, false, false)]),
        );

        assert_eq!(
            ineligible(&builder, 0),
            IneligibilityReason::MalformedChain(MalformedReason::UnexpectedChainStart {
                volume: 1,
            })
        );
    }

    #[test]
    fn a_completed_chain_whose_parts_do_not_sum_to_the_member_is_malformed() {
        let mut builder = layout();
        add(
            &mut builder,
            0,
            &volume(vec![split_part(EPISODE, 40, 10, 60, false, true)]),
        );
        add(
            &mut builder,
            1,
            &volume(vec![with_crc32(
                split_part(EPISODE, 40, 20, 60, true, false),
                0xFEED_BEEF,
            )]),
        );

        assert_eq!(
            ineligible(&builder, 0),
            IneligibilityReason::MalformedChain(MalformedReason::SizeMismatch {
                packed_total: 30,
                unpacked_size: 60,
            })
        );
    }

    #[test]
    fn a_member_swallowed_by_another_members_range_is_overlapping() {
        // Sorted by offset, a contained member is not the neighbour of the
        // member that swallows it, so a walk over adjacent pairs goes straight
        // past the overlap. Both shapes here escaped that walk: a member ending
        // inside the swallowing range, and one wholly inside it.
        for inner in [(190u64, 50u64), (140u64, 10u64)] {
            let mut builder = layout();
            add(
                &mut builder,
                0,
                &volume(vec![
                    with_crc32(member(EPISODE, 100, 100), 0x1111_1111),
                    with_crc32(member(EXTRA, 120, 10), 0x2222_2222),
                    with_crc32(member(NEIGHBOUR, inner.0, inner.1), 0x3333_3333),
                    with_crc32(member(DISTANT, 300, 10), 0x4444_4444),
                ]),
            );

            let overlapping =
                IneligibilityReason::MalformedChain(MalformedReason::OverlappingParts {
                    volume: 0,
                });
            for index in 0..3 {
                assert_eq!(
                    ineligible(&builder, index),
                    overlapping,
                    "member {index} with inner extent {inner:?}"
                );
            }
            // The member clear of every overlap keeps its own verdict, and the
            // overlapping members' bytes take the envelope path.
            assert_eq!(
                builder.members()[3].eligibility,
                MemberEligibility::DirectEligible
            );
            assert_eq!(
                builder.map_physical_range(0, 100, 150),
                vec![MappedSlice::Envelope { len: 150 }]
            );
        }
    }

    #[test]
    fn parts_declaring_different_unpacked_sizes_are_malformed_in_either_order() {
        // Which size a member ends up with cannot depend on which volume the
        // router happened to see first.
        let head = || split_part(EPISODE, 40, 10, 30, false, true);
        let tail = || with_crc32(split_part(EPISODE, 40, 20, 999, true, false), 0xFEED_BEEF);
        let expected =
            IneligibilityReason::MalformedChain(MalformedReason::InconsistentUnpackedSize {
                first: 30,
                second: 999,
            });

        let mut forward = layout();
        add(&mut forward, 0, &volume(vec![head()]));
        add(&mut forward, 1, &volume(vec![tail()]));

        let mut backward = layout();
        add(&mut backward, 1, &volume(vec![tail()]));
        add(&mut backward, 0, &volume(vec![head()]));

        for builder in [&forward, &backward] {
            assert_eq!(ineligible(builder, 0), expected);
            // The lowest volume's declaration is the one that stands, whichever
            // volume arrived first.
            assert_eq!(builder.members()[0].unpacked_size, Some(30));
        }
    }

    #[test]
    fn an_open_chain_carrying_more_than_the_declared_size_is_malformed_before_it_closes() {
        // A stored part is the member's own bytes, so a part already past the
        // declared end has bytes with nowhere to go. Waiting for the chain to
        // close would route them in the meantime.
        let mut builder = layout();
        add(
            &mut builder,
            0,
            &volume(vec![split_part(EPISODE, 40, 500, 100, false, true)]),
        );

        assert!(!builder.members()[0].chain_complete);
        assert_eq!(
            ineligible(&builder, 0),
            IneligibilityReason::MalformedChain(MalformedReason::ExceedsDeclaredSize {
                packed_total: 500,
                unpacked_size: 100,
            })
        );
        assert_eq!(
            builder.map_physical_range(0, 40, 500),
            vec![MappedSlice::Envelope { len: 500 }]
        );
    }

    #[test]
    fn a_routed_run_is_clamped_to_the_members_declared_end() {
        // The check above catches every representable overshoot before a member
        // is routed, so the only way a routed part can still reach past the
        // declared end is a chain whose sums run past `u64::MAX`.
        const HUGE: u64 = u64::MAX - 100;

        let mut builder = layout();
        add(
            &mut builder,
            0,
            &volume(vec![split_part(EPISODE, 40, HUGE, u64::MAX, false, true)]),
        );
        add(
            &mut builder,
            1,
            &volume(vec![split_part(EPISODE, 40, 1000, u64::MAX, true, true)]),
        );

        assert_eq!(
            builder.members()[0].eligibility,
            MemberEligibility::ProvisionallyDirect
        );
        // Only 100 of that part's 1000 packed bytes are inside the member.
        assert_eq!(
            builder.map_physical_range(1, 40, 1000),
            vec![
                MappedSlice::Member {
                    member_index: 0,
                    logical_offset: HUGE,
                    len: 100,
                },
                MappedSlice::Unroutable { len: 900 },
            ]
        );
    }

    #[test]
    fn hostile_part_sizes_never_saturate_an_offset_or_panic() {
        const HUGE: u64 = u64::MAX - 100;

        let mut builder = layout();
        add(
            &mut builder,
            0,
            &volume(vec![split_part(EPISODE, 40, HUGE, u64::MAX, false, true)]),
        );
        add(
            &mut builder,
            1,
            &volume(vec![split_part(EPISODE, 40, 1000, u64::MAX, true, true)]),
        );
        add(
            &mut builder,
            2,
            &volume(vec![split_part(EPISODE, 40, 1000, u64::MAX, true, true)]),
        );

        let member = &builder.members()[0];
        assert_eq!(member.parts[0].logical_offset, Some(0));
        assert_eq!(member.parts[1].logical_offset, Some(HUGE));
        // The prefix sum runs past `u64::MAX` here: unresolved, never saturated
        // into an offset that looks like an answer.
        assert_eq!(member.parts[2].logical_offset, None);
        assert_eq!(
            builder.map_physical_range(2, 40, 1000),
            vec![MappedSlice::Unroutable { len: 1000 }]
        );
        // Nor does the mapping saturate one: an offset that only overflows
        // part-way into a part is just as unplaceable.
        assert_eq!(
            builder.map_physical_range(1, 240, 100),
            vec![MappedSlice::Unroutable { len: 100 }]
        );

        // Declaring a size those parts blow past demotes the member outright.
        let mut demoted = layout();
        add(
            &mut demoted,
            0,
            &volume(vec![split_part(EPISODE, 40, 1 << 62, 1 << 20, false, true)]),
        );
        add(
            &mut demoted,
            1,
            &volume(vec![split_part(EPISODE, 40, 1 << 62, 1 << 20, true, true)]),
        );
        assert_eq!(
            ineligible(&demoted, 0),
            IneligibilityReason::MalformedChain(MalformedReason::ExceedsDeclaredSize {
                packed_total: 1 << 63,
                unpacked_size: 1 << 20,
            })
        );
        assert_eq!(
            demoted.map_physical_range(0, 40, 1 << 62),
            vec![MappedSlice::Envelope { len: 1 << 62 }]
        );
    }

    #[test]
    fn a_range_running_past_the_addressable_end_is_clamped_in_every_branch() {
        let mut builder = layout();
        add(
            &mut builder,
            0,
            &volume(vec![with_crc32(member(EPISODE, 100, 64), 0x1234_5678)]),
        );

        // Present volume and missing volume clamp the same way, so a caller
        // cannot tell the two apart by how many bytes came back.
        assert_eq!(
            builder.map_physical_range(0, u64::MAX - 10, 100),
            vec![MappedSlice::Envelope { len: 10 }]
        );
        assert_eq!(
            builder.map_physical_range(1, u64::MAX - 10, 100),
            vec![MappedSlice::Unroutable { len: 10 }]
        );
        // A range starting at the addressable end covers nothing at all.
        assert!(builder.map_physical_range(0, u64::MAX, 100).is_empty());
        assert!(builder.map_physical_range(1, u64::MAX, 100).is_empty());
    }

    #[test]
    fn offsets_only_move_when_the_same_volume_makes_the_member_ineligible() {
        // A chain whose first part sits in volume 1 — nothing yet says an
        // earlier volume carries any of it.
        let head = || split_part(EPISODE, 40, 10, 30, false, true);
        let tail = || with_crc32(split_part(EPISODE, 40, 20, 30, true, false), 0xFEED_BEEF);
        let offsets = |builder: &StoredLayoutBuilder| {
            builder.members()[0]
                .parts
                .iter()
                .map(|part| part.logical_offset)
                .collect::<Vec<_>>()
        };

        let mut renumbered = layout();
        add_stably(&mut renumbered, 1, &volume(vec![head()]));
        add_stably(&mut renumbered, 2, &volume(vec![tail()]));
        assert_eq!(offsets(&renumbered), vec![Some(0), Some(10)]);
        assert_eq!(
            renumbered.members()[0].eligibility,
            MemberEligibility::DirectEligible
        );

        // An earlier part arriving late renumbers the chain. `add_stably` is
        // the assertion that it can only do so in the call that demotes the
        // member, which is what lets a caller trust an offset it acted on.
        add_stably(
            &mut renumbered,
            0,
            &volume(vec![split_part(EPISODE, 40, 5, 30, false, true)]),
        );
        assert_eq!(offsets(&renumbered), vec![Some(0), Some(5), Some(15)]);
        assert_eq!(
            ineligible(&renumbered, 0),
            IneligibilityReason::MalformedChain(MalformedReason::UnexpectedChainStart {
                volume: 1,
            })
        );

        // The same arrival flagged as a continuation withdraws the offsets
        // instead of moving them — again only alongside the demotion.
        let mut unresolved = layout();
        add_stably(&mut unresolved, 1, &volume(vec![head()]));
        add_stably(&mut unresolved, 2, &volume(vec![tail()]));
        add_stably(
            &mut unresolved,
            0,
            &volume(vec![split_part(EPISODE, 40, 5, 30, true, true)]),
        );
        assert_eq!(offsets(&unresolved), vec![None, None, None]);
        assert!(matches!(
            ineligible(&unresolved, 0),
            IneligibilityReason::MalformedChain(_)
        ));
    }

    #[test]
    fn duplicate_member_name_in_one_volume_is_malformed() {
        let mut builder = layout();
        add(
            &mut builder,
            0,
            &volume(vec![
                with_crc32(member(EPISODE, 40, 10), 0x1111_1111),
                with_crc32(member(EPISODE, 60, 10), 0x2222_2222),
            ]),
        );

        assert_eq!(builder.members().len(), 1);
        assert_eq!(
            ineligible(&builder, 0),
            IneligibilityReason::MalformedChain(MalformedReason::DuplicatePartInVolume {
                volume: 0,
            })
        );
    }

    #[test]
    fn re_adding_a_volume_is_idempotent_but_conflicting_facts_are_rejected() {
        let facts = volume(vec![with_crc32(member(EPISODE, 100, 64), 0x1234_5678)]);
        let mut builder = layout();
        add(&mut builder, 0, &facts);
        add(&mut builder, 0, &facts);

        assert_eq!(builder.members().len(), 1);
        assert_eq!(builder.members()[0].parts.len(), 1);

        let conflicting = volume(vec![with_crc32(member(EPISODE, 100, 65), 0x1234_5678)]);
        assert_eq!(
            builder.add_volume(0, &conflicting),
            Err(StoredLayoutError::ConflictingVolume { volume: 0 })
        );
        assert_eq!(builder.members()[0].parts[0].data_size, 64);
    }

    #[test]
    fn a_volume_from_another_format_is_rejected() {
        let mut facts = volume(vec![member(EPISODE, 100, 64)]);
        facts.format = 4;

        let mut builder = layout();
        assert_eq!(
            builder.add_volume(0, &facts),
            Err(StoredLayoutError::FormatMismatch {
                expected: ArchiveFormat::Rar5,
                found: ArchiveFormat::Rar4,
            })
        );
        assert!(!builder.has_volume(0));
    }

    #[test]
    fn a_split_part_keeps_both_packed_checksums() {
        let mut head = split_part(EPISODE, 40, 10, 30, false, true);
        head.packed_crc32 = Some(0xAAAA_BBBB);
        head.packed_blake2_hash = Some([0x5A; 32]);

        let mut builder = layout();
        add(&mut builder, 0, &volume(vec![head]));

        let part = &builder.members()[0].parts[0];
        assert_eq!(part.packed_crc32, Some(0xAAAA_BBBB));
        assert_eq!(part.packed_blake2_hash, Some([0x5A; 32]));
    }

    #[test]
    fn a_blake2_only_stored_member_is_not_direct_eligible() {
        let mut blake2_only = member(EPISODE, 40, 10);
        blake2_only.data_blake2_hash = Some([0x11; 32]);

        let mut builder = layout();
        add(&mut builder, 0, &volume(vec![blake2_only]));

        assert_eq!(
            ineligible(&builder, 0),
            IneligibilityReason::Blake2OnlyNoCrc32
        );
    }

    #[test]
    fn a_stored_member_with_no_checksum_is_not_direct_eligible() {
        let mut builder = layout();
        add(&mut builder, 0, &volume(vec![member(EPISODE, 40, 10)]));

        assert_eq!(ineligible(&builder, 0), IneligibilityReason::NoChecksum);
    }

    #[test]
    fn per_member_solid_rejects_while_an_archive_solid_store_set_passes() {
        let mut solid_member = with_crc32(member(EPISODE, 40, 10), 0x1111_1111);
        solid_member.compression_solid = true;
        let mut builder = layout();
        add(&mut builder, 0, &volume(vec![solid_member]));
        assert_eq!(ineligible(&builder, 0), IneligibilityReason::Solid);

        // The archive-level solid flag does not disqualify store members.
        let mut archive_solid = volume(vec![with_crc32(member(EPISODE, 40, 10), 0x1111_1111)]);
        archive_solid.is_solid = true;
        let mut builder = layout();
        add(&mut builder, 0, &archive_solid);
        assert_eq!(
            builder.members()[0].eligibility,
            MemberEligibility::DirectEligible
        );
    }

    #[test]
    fn directory_redirection_and_encrypted_members_are_rejected() {
        let mut directory = with_crc32(member("Silver.Horizon.S01", 40, 0), 0);
        directory.is_directory = true;

        let mut redirection = with_crc32(member("Silver.Horizon.S01E01.link", 40, 12), 0x3333);
        redirection.redirection_type = Some(1);
        redirection.redirection_target = Some(EPISODE.to_string());

        let mut encrypted = with_crc32(member(EPISODE, 60, 10), 0x4444);
        encrypted.is_encrypted = true;

        let mut builder = layout();
        add(
            &mut builder,
            0,
            &volume(vec![directory, redirection, encrypted]),
        );

        assert_eq!(ineligible(&builder, 0), IneligibilityReason::Directory);
        assert_eq!(ineligible(&builder, 1), IneligibilityReason::Redirection);
        assert_eq!(ineligible(&builder, 2), IneligibilityReason::Encrypted);
    }

    #[test]
    fn split_evidence_lists_only_the_names_that_link_volumes() {
        let mut builder = layout();
        add(
            &mut builder,
            0,
            &volume(vec![
                with_crc32(member(EXTRA, 40, 10), 0x1111_1111),
                split_part(EPISODE, 60, 10, 30, false, true),
            ]),
        );
        add(
            &mut builder,
            1,
            &volume(vec![with_crc32(
                split_part(EPISODE, 40, 20, 30, true, false),
                0x2222_2222,
            )]),
        );

        let first = builder.split_evidence(0).expect("volume 0 evidence");
        assert!(first.continued_from_previous.is_empty());
        assert_eq!(first.continues_into_next, vec![EPISODE.to_string()]);

        let second = builder.split_evidence(1).expect("volume 1 evidence");
        assert_eq!(second.continued_from_previous, vec![EPISODE.to_string()]);
        assert!(second.continues_into_next.is_empty());

        assert!(builder.split_evidence(2).is_none());
    }

    #[test]
    fn rar5_multi_volume_store_fixture_builds_a_direct_layout() {
        let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rar5");
        let volumes: Vec<std::path::PathBuf> = (1..=5)
            .map(|part| fixtures.join(format!("rar5_mv_store.part{part}.rar")))
            .collect();
        // Existence is the wrong guard under partial Git LFS hydration: the
        // no-fixture CI lane checks these out as pointer files, which exist and
        // then fail the signature parse. A hydrated fixture starts with `Rar!`;
        // a pointer starts with `version https://git-lfs…`.
        let hydrated = |path: &std::path::Path| {
            std::fs::read(path)
                .ok()
                .is_some_and(|bytes| bytes.starts_with(b"Rar!"))
        };
        if !volumes.iter().all(|path| hydrated(path)) {
            eprintln!("skipping test: rar5_mv_store fixtures not hydrated");
            return;
        }

        let mut builder = layout();
        for (number, path) in volumes.iter().enumerate() {
            let facts = RarArchive::parse_volume_facts(std::fs::File::open(path).unwrap(), None)
                .expect("fixture volume facts");
            builder
                .add_volume(number as u32, &facts)
                .expect("fixture volume accepted");
        }

        assert_eq!(builder.header_frontier(), Some(4));

        // Every byte of every volume is accounted for: the mapping is a
        // partition of the file, not a set of interesting fragments.
        for (number, path) in volumes.iter().enumerate() {
            let file_len = std::fs::metadata(path).unwrap().len();
            let slices = builder.map_physical_range(number as u32, 0, file_len);
            assert_eq!(
                slices.iter().map(slice_len).sum::<u64>(),
                file_len,
                "volume {number} mapping must cover the whole file"
            );
            assert!(
                slices
                    .iter()
                    .any(|slice| matches!(slice, MappedSlice::Member { .. })),
                "volume {number} carries member bytes"
            );
        }

        // The fixture's member spans all five volumes: the four non-final parts
        // state the CRC32 of their own packed bytes, and only the final part's
        // header states the whole-member CRC32.
        const PACKED_CRC32: [u32; 4] = [2_728_221_531, 183_482_895, 1_141_563_331, 2_959_284_075];
        let split = builder
            .members()
            .iter()
            .find(|member| member.parts.len() > 1)
            .expect("the fixture set splits a member across volumes");
        assert_eq!(split.parts.len(), 5);
        for (position, expected) in PACKED_CRC32.iter().enumerate() {
            let part = &split.parts[position];
            assert!(
                part.split_after,
                "part {position} continues into the next volume"
            );
            assert_eq!(
                part.packed_crc32,
                Some(*expected),
                "part {position} states its own packed CRC32"
            );
        }
        let final_part = &split.parts[4];
        assert!(!final_part.split_after);
        assert_eq!(
            final_part.packed_crc32, None,
            "a final part has no packed-only CRC32 to state"
        );
        assert_eq!(split.data_crc32, Some(3_348_152_310));
        let direct: Vec<&StoredMember> = builder
            .members()
            .iter()
            .filter(|member| member.eligibility == MemberEligibility::DirectEligible)
            .collect();
        assert!(
            !direct.is_empty(),
            "a plain multi-volume store set should yield direct members"
        );
        assert!(
            direct.iter().any(|member| member.parts.len() > 1),
            "the fixture set should exercise a member split across volumes"
        );

        for member in direct {
            assert!(member.chain_complete);
            assert_eq!(member.parts[0].logical_offset, Some(0));
            let mut running = 0u64;
            for part in &member.parts {
                assert_eq!(part.logical_offset, Some(running));
                running += part.data_size;
            }
            assert_eq!(Some(running), member.unpacked_size);
            assert!(member.data_crc32.is_some());

            // Every part's packed range maps back to that part's logical span.
            for (position, part) in member.parts.iter().enumerate() {
                if part.data_size == 0 {
                    continue;
                }
                let index = builder
                    .members()
                    .iter()
                    .position(|candidate| candidate.name == member.name)
                    .unwrap();
                assert_eq!(
                    builder.map_physical_range(part.volume, part.data_offset, part.data_size),
                    vec![MappedSlice::Member {
                        member_index: index,
                        logical_offset: part.logical_offset.unwrap(),
                        len: part.data_size,
                    }],
                    "part {position} of {}",
                    member.name
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // Encrypted `Store` members
    // -----------------------------------------------------------------------

    /// Re-label an encrypted run as a plaintext one, so two mappings can be
    /// compared on the only thing that is supposed to match: the coordinates.
    fn as_plain(slice: MappedSlice) -> MappedSlice {
        match slice {
            MappedSlice::EncryptedMember {
                member_index,
                logical_offset,
                len,
            } => MappedSlice::Member {
                member_index,
                logical_offset,
                len,
            },
            other => other,
        }
    }

    fn rar4_volume(members: Vec<RarVolumeMemberFacts>) -> RarVolumeFacts {
        let mut facts = volume(members);
        facts.format = 4;
        facts
    }

    #[test]
    fn an_encrypted_store_member_carries_its_crypt_record_and_cipher_extent() {
        let mut builder = layout();
        add(
            &mut builder,
            0,
            &volume(vec![encrypted_member(EPISODE, 100, 290)]),
        );

        let member = &builder.members()[0];
        assert!(member.chain_complete);
        assert_eq!(member.unpacked_size, Some(290));
        assert!(
            member.eligibility.routes_direct(),
            "an encrypted store member's bytes map to the member"
        );

        let facts = encrypted_store(&builder, 0);
        assert_eq!(facts.crypt, Some(crypt_record()));
        assert_eq!(facts.rar4_salt, None);
        // 290 -> 304: the cipher stream is the plaintext rounded up one block.
        assert_eq!(facts.cipher_size, Some(304));
        assert_eq!(facts.tail_padding, Some(14));
        assert!(facts.resolved);
        assert!(facts.claims_password_check());
        assert_eq!(facts.password_check(), Some([0xC4; 12]));

        // The mapped run is the whole cipher stream — including the 14 padding
        // bytes past the member's declared end, which are real wire bytes.
        assert_eq!(
            builder.map_physical_range(0, 100, 304),
            vec![MappedSlice::EncryptedMember {
                member_index: 0,
                logical_offset: 0,
                len: 304,
            }]
        );
    }

    #[test]
    fn an_encrypted_member_without_a_password_check_still_classifies() {
        let mut crypt = crypt_record();
        crypt.psw_check_present = false;
        crypt.psw_check = None;

        let mut builder = layout();
        let mut facts = encrypted_member(EPISODE, 100, 290);
        facts.encryption = Some(crypt);
        add(&mut builder, 0, &volume(vec![facts]));

        let facts = encrypted_store(&builder, 0);
        assert!(facts.resolved, "an absent check disqualifies nothing here");
        assert!(!facts.claims_password_check());
        assert_eq!(facts.password_check(), None);
    }

    #[test]
    fn an_encrypted_member_reports_a_claimed_check_it_cannot_use() {
        // The parser drops a check value whose SHA-256 tag failed, leaving the
        // claim and no value. A caller must not read that as "the writer
        // omitted it": it is a corrupt header, and the two deserve different
        // words even though both mean the password cannot be pre-verified.
        let mut crypt = crypt_record();
        crypt.psw_check = None;

        let mut builder = layout();
        let mut facts = encrypted_member(EPISODE, 100, 290);
        facts.encryption = Some(crypt);
        add(&mut builder, 0, &volume(vec![facts]));

        let facts = encrypted_store(&builder, 0);
        assert!(facts.claims_password_check());
        assert_eq!(facts.password_check(), None);
    }

    #[test]
    fn rar5_parts_disagreeing_about_the_unpack_version_are_still_one_encrypted_member() {
        // `compression_version` selects the cipher in the RAR4 family and
        // nothing at all under RAR5, which keys off its `FHEXTRA_CRYPT` record.
        // Recording it as part of a RAR5 part's encryption record would make
        // two parts that disagree about it `Mixed` — demoting a member both
        // parts describe identically everywhere it matters.
        let mut builder = layout();
        let unpacked_size = 4096u64;
        for (number, version, split_before, split_after) in
            [(0u32, 29u8, false, true), (1, 50, true, false)]
        {
            let mut facts = split_part(
                EPISODE,
                64,
                unpacked_size / 2,
                unpacked_size,
                split_before,
                split_after,
            );
            facts = encrypted(facts, crypt_record());
            facts.compression_version = version;
            if !split_after {
                facts.data_crc32 = Some(0xFEED_BEEF);
            }
            add(&mut builder, number, &volume(vec![facts]));
        }

        let store = encrypted_store(&builder, 0);
        assert!(store.resolved, "the chain is complete and sums to align16");
        assert_eq!(store.keying(), MemberKeying::Rar5(crypt_record()));
    }

    /// Build a three-part encrypted chain summing to exactly `packed_total`.
    fn encrypted_chain(unpacked_size: u64, packed_total: u64) -> StoredLayoutBuilder {
        let head = packed_total / 3;
        let middle = packed_total / 3;
        let tail = packed_total - head - middle;

        let mut builder = layout();
        for (number, size, split_before, split_after) in [
            (0u32, head, false, true),
            (1, middle, true, true),
            (2, tail, true, false),
        ] {
            let mut facts = split_part(EPISODE, 64, size, unpacked_size, split_before, split_after);
            facts = encrypted(facts, crypt_record());
            if !split_after {
                facts.data_crc32 = Some(0xFEED_BEEF);
            }
            add(&mut builder, number, &volume(vec![facts]));
        }
        builder
    }

    #[test]
    fn an_encrypted_chain_sums_to_align16_at_every_slack() {
        // Slack 0, 1 and 15: the whole range the final block can absorb.
        for (unpacked_size, slack) in [(4096u64, 0u64), (4095, 1), (4081, 15)] {
            let cipher_size = unpacked_size + slack;
            assert_eq!(align16(unpacked_size), Some(cipher_size), "test arithmetic");

            let builder = encrypted_chain(unpacked_size, cipher_size);
            let facts = encrypted_store(&builder, 0);
            assert!(
                facts.resolved,
                "unpacked {unpacked_size} padded to {cipher_size} is a complete chain"
            );
            assert_eq!(facts.cipher_size, Some(cipher_size));
            assert_eq!(facts.tail_padding, Some(slack as u8));
        }
    }

    #[test]
    fn an_encrypted_chain_carrying_a_whole_extra_block_is_rejected() {
        // The case a naive "within 16 bytes" tolerance gets wrong: the member
        // is already block-aligned, so `align16` adds nothing and a chain one
        // block longer is one block of bytes that belong to nobody.
        let builder = encrypted_chain(4096, 4096 + 16);
        assert_eq!(
            ineligible(&builder, 0),
            IneligibilityReason::MalformedChain(MalformedReason::ExceedsDeclaredSize {
                packed_total: 4112,
                unpacked_size: 4096,
            })
        );

        // And one byte past that, for good measure.
        let builder = encrypted_chain(4096, 4096 + 17);
        assert_eq!(
            ineligible(&builder, 0),
            IneligibilityReason::MalformedChain(MalformedReason::ExceedsDeclaredSize {
                packed_total: 4113,
                unpacked_size: 4096,
            })
        );
    }

    #[test]
    fn an_encrypted_chain_short_of_align16_is_a_size_mismatch() {
        // One block short.
        let builder = encrypted_chain(4095, 4080);
        assert_eq!(
            ineligible(&builder, 0),
            IneligibilityReason::MalformedChain(MalformedReason::SizeMismatch {
                packed_total: 4080,
                unpacked_size: 4095,
            })
        );

        // And the plaintext rule applied to ciphertext: an unpadded sum. This
        // is what the unencrypted equality check would have accepted, and it
        // is a length no AES-CBC stream can have.
        let builder = encrypted_chain(4095, 4095);
        assert_eq!(
            ineligible(&builder, 0),
            IneligibilityReason::MalformedChain(MalformedReason::SizeMismatch {
                packed_total: 4095,
                unpacked_size: 4095,
            })
        );
    }

    #[test]
    fn an_unencrypted_chain_still_needs_an_exact_sum() {
        // The regression floor for the change above: padding is an encrypted
        // member's rule and nobody else's.
        let mut builder = layout();
        for (number, size, split_before, split_after) in
            [(0u32, 2048u64, false, true), (1, 2048, true, false)]
        {
            let mut facts = split_part(EPISODE, 64, size, 4090, split_before, split_after);
            if !split_after {
                facts.data_crc32 = Some(0xFEED_BEEF);
            }
            add(&mut builder, number, &volume(vec![facts]));
        }
        assert_eq!(
            ineligible(&builder, 0),
            IneligibilityReason::MalformedChain(MalformedReason::ExceedsDeclaredSize {
                packed_total: 4096,
                unpacked_size: 4090,
            }),
            "a plaintext chain gets no block-padding tolerance"
        );
    }

    #[test]
    fn an_open_encrypted_chain_is_unresolved_and_its_bytes_still_map() {
        let mut builder = layout();
        add(
            &mut builder,
            0,
            &volume(vec![encrypted(
                split_part(EPISODE, 40, 1024, 4095, false, true),
                crypt_record(),
            )]),
        );

        let facts = encrypted_store(&builder, 0);
        assert!(!facts.resolved, "the whole-member CRC32 is still to come");
        assert_eq!(facts.cipher_size, Some(4096));
        assert_eq!(facts.tail_padding, Some(1));
        assert!(!builder.members()[0].chain_complete);
        assert_eq!(
            builder.map_physical_range(0, 40, 1024),
            vec![MappedSlice::EncryptedMember {
                member_index: 0,
                logical_offset: 0,
                len: 1024,
            }]
        );
    }

    #[test]
    fn an_encrypted_part_reaching_past_align16_demotes_before_the_chain_closes() {
        let mut builder = layout();
        add(
            &mut builder,
            0,
            &volume(vec![encrypted(
                split_part(EPISODE, 40, 4097, 4095, false, true),
                crypt_record(),
            )]),
        );

        assert_eq!(
            ineligible(&builder, 0),
            IneligibilityReason::MalformedChain(MalformedReason::ExceedsDeclaredSize {
                packed_total: 4097,
                unpacked_size: 4095,
            }),
            "4095 pads to 4096, so 4097 packed bytes are already too many"
        );
        assert_eq!(
            builder.map_physical_range(0, 40, 4097),
            vec![MappedSlice::Envelope { len: 4097 }],
            "a demoted member's bytes take the envelope path"
        );
    }

    #[test]
    fn mixed_encrypted_and_plain_parts_demote_the_chain() {
        let mut builder = layout();
        add(
            &mut builder,
            0,
            &volume(vec![encrypted(
                split_part(EPISODE, 40, 2048, 4096, false, true),
                crypt_record(),
            )]),
        );
        add(
            &mut builder,
            1,
            &volume(vec![with_crc32(
                split_part(EPISODE, 40, 2048, 4096, true, false),
                0xFEED_BEEF,
            )]),
        );

        assert_eq!(
            ineligible(&builder, 0),
            IneligibilityReason::MalformedChain(MalformedReason::MixedEncryption { volume: 1 })
        );
    }

    #[test]
    fn parts_disagreeing_on_key_material_demote_the_chain_in_volume_order() {
        let mut rotated = crypt_record();
        rotated.iv = [0x2E; 16];

        // Added newest first: the reason must still name volume 2, which is
        // the lowest volume that disagrees with the member's first part.
        let mut builder = layout();
        for number in (0..4u32).rev() {
            let crypt = if number >= 2 { rotated } else { crypt_record() };
            let mut facts = split_part(EPISODE, 40, 1024, 4096, number > 0, number + 1 < 4);
            facts = encrypted(facts, crypt);
            if number + 1 == 4 {
                facts.data_crc32 = Some(0xFEED_BEEF);
            }
            add(&mut builder, number, &volume(vec![facts]));
        }

        assert_eq!(
            ineligible(&builder, 0),
            IneligibilityReason::MalformedChain(MalformedReason::MixedEncryption { volume: 2 })
        );
    }

    #[test]
    fn the_hash_mac_flag_differing_across_parts_does_not_demote_the_chain() {
        // The shape RARLAB `rar` 7.20 actually writes: one crypt record on
        // every part, and the keyed-checksum flag set on the final part alone,
        // because only that part's checksum is the whole member's. Folding the
        // flag into "the parts agree" would malform every real encrypted split
        // chain.
        let mut builder = layout();
        for (number, split_before, split_after) in [(0u32, false, true), (1, true, false)] {
            let mut facts = split_part(EPISODE, 40, 2048, 4096, split_before, split_after);
            facts = encrypted(facts, crypt_record());
            facts.packed_hash_uses_mac = false;
            if !split_after {
                facts.data_crc32 = Some(0xFEED_BEEF);
                facts.use_hash_mac = true;
            }
            add(&mut builder, number, &volume(vec![facts]));
        }

        let facts = encrypted_store(&builder, 0);
        assert!(facts.resolved);
        let member = &builder.members()[0];
        assert!(
            member.data_hash_uses_mac,
            "the whole-member checksum is keyed, from the final part's header"
        );
        assert!(
            !member.parts[0].packed_hash_uses_mac,
            "the non-final part's packed checksum is not"
        );
    }

    #[test]
    fn encrypted_members_that_are_not_plain_stores_keep_reporting_encrypted() {
        // Compressed, solid, and a RAR5 header claiming encryption while
        // stating no crypt record — nothing can key that last one, so it is as
        // unroutable as it was before encrypted store existed.
        let compressed = {
            let mut facts = encrypted_member(EPISODE, 100, 4096);
            facts.compression_method = CompressionMethod::Normal.code();
            facts
        };
        let solid = {
            let mut facts = encrypted_member(EPISODE, 100, 4096);
            facts.compression_solid = true;
            facts
        };
        let recordless = {
            let mut facts = encrypted_member(EPISODE, 100, 4096);
            facts.encryption = None;
            facts
        };

        for facts in [compressed, solid, recordless] {
            let mut builder = layout();
            add(&mut builder, 0, &volume(vec![facts]));
            assert_eq!(ineligible(&builder, 0), IneligibilityReason::Encrypted);
        }
    }

    #[test]
    fn an_encrypted_member_still_needs_a_whole_member_crc32() {
        let mut blake2_only = encrypted_member(EPISODE, 100, 4096);
        blake2_only.data_crc32 = None;
        blake2_only.data_blake2_hash = Some([0x11; 32]);
        let mut none = encrypted_member(EPISODE, 100, 4096);
        none.data_crc32 = None;

        for (facts, expected) in [
            (blake2_only, IneligibilityReason::Blake2OnlyNoCrc32),
            (none, IneligibilityReason::NoChecksum),
        ] {
            let mut builder = layout();
            add(&mut builder, 0, &volume(vec![facts]));
            assert_eq!(ineligible(&builder, 0), expected);
        }
    }

    #[test]
    fn an_encrypted_directory_or_redirection_keeps_its_own_reason() {
        let mut directory = encrypted_member(EPISODE, 100, 4096);
        directory.is_directory = true;
        let mut redirection = encrypted_member(EPISODE, 100, 4096);
        redirection.redirection_type = Some(1);

        for (facts, expected) in [
            (directory, IneligibilityReason::Directory),
            (redirection, IneligibilityReason::Redirection),
        ] {
            let mut builder = layout();
            add(&mut builder, 0, &volume(vec![facts]));
            assert_eq!(ineligible(&builder, 0), expected);
        }
    }

    #[test]
    fn an_encrypted_member_maps_exactly_where_its_unencrypted_twin_does() {
        // Cipher offset and member-logical offset are the same number for a
        // stored member, so with an already-aligned size the two layouts must
        // produce identical runs — same indices, offsets and lengths, differing
        // only in the variant that says "decrypt these first".
        const SIZE: u64 = 4096;
        let plain = with_crc32(member(EPISODE, 100, SIZE), 0x1234_5678);
        let cipher = encrypted_member(EPISODE, 100, SIZE);
        assert_eq!(plain.data_size, cipher.data_size, "aligned twin");

        let mut plain_builder = layout();
        add(&mut plain_builder, 0, &volume(vec![plain]));
        let mut cipher_builder = layout();
        add(&mut cipher_builder, 0, &volume(vec![cipher]));

        for (offset, len) in [(0, 5000), (100, SIZE), (150, 64), (4000, 500)] {
            let expected = plain_builder.map_physical_range(0, offset, len);
            let actual: Vec<MappedSlice> = cipher_builder
                .map_physical_range(0, offset, len)
                .into_iter()
                .map(as_plain)
                .collect();
            assert_eq!(actual, expected, "range {offset}+{len}");
            assert!(
                expected
                    .iter()
                    .any(|slice| matches!(slice, MappedSlice::Member { .. })),
                "range {offset}+{len} must cover member bytes, or it proves nothing"
            );
        }
    }

    #[test]
    fn an_encrypted_split_chain_maps_each_part_to_its_cipher_offset() {
        // Real writers do not align split parts individually — only the
        // member's total — so the second part starts mid-block, and its
        // logical offset must be the plain prefix sum all the same.
        let sizes = [1001u64, 1001, 2094];
        let unpacked_size = 4090;
        assert_eq!(sizes.iter().sum::<u64>(), 4096);
        assert_eq!(align16(unpacked_size), Some(4096), "test arithmetic");

        let mut builder = layout();
        for (number, size) in sizes.iter().copied().enumerate() {
            let number = number as u32;
            let mut facts = split_part(
                EPISODE,
                64,
                size,
                unpacked_size,
                number > 0,
                number + 1 < sizes.len() as u32,
            );
            facts = encrypted(facts, crypt_record());
            if number + 1 == sizes.len() as u32 {
                facts.data_crc32 = Some(0xFEED_BEEF);
            }
            add(&mut builder, number, &volume(vec![facts]));
        }

        let facts = encrypted_store(&builder, 0);
        assert!(facts.resolved);
        assert_eq!(facts.tail_padding, Some(6));

        let mut running = 0u64;
        for (position, size) in sizes.iter().copied().enumerate() {
            assert_eq!(
                builder.map_physical_range(position as u32, 64, size),
                vec![MappedSlice::EncryptedMember {
                    member_index: 0,
                    logical_offset: running,
                    len: size,
                }],
                "part {position}"
            );
            if position == 1 {
                assert_ne!(
                    running % AES_BLOCK,
                    0,
                    "a part starting mid-block is what this test is about"
                );
            }
            running += size;
        }
    }

    #[test]
    fn a_rar4_encrypted_store_member_carries_its_file_salt() {
        // RAR4 states no per-file crypt record: its key and IV come from the
        // password plus this salt, so the salt is the whole of the facts.
        let mut facts = member(EPISODE, 100, 304);
        facts.unpacked_size = Some(290);
        facts.is_encrypted = true;
        facts.rar4_salt = Some([0x9B; 8]);
        facts.data_crc32 = Some(0x1234_5678);
        facts.compression_version = 29;

        let mut builder = StoredLayoutBuilder::new(ArchiveFormat::Rar4);
        builder
            .add_volume(0, &rar4_volume(vec![facts]))
            .expect("volume accepted");

        let store = encrypted_store(&builder, 0);
        assert_eq!(store.crypt, None);
        assert_eq!(store.rar4_salt, Some([0x9B; 8]));
        assert_eq!(store.cipher_size, Some(304));
        assert_eq!(store.tail_padding, Some(14));
        assert!(store.resolved);
        assert!(!store.claims_password_check());
    }

    #[test]
    fn a_rar4_encrypted_member_without_a_salt_is_still_keyable() {
        // RAR3 archives written without a salt derive the key from the password
        // alone. That is a complete description, not a missing record.
        let mut facts = member(EPISODE, 100, 304);
        facts.unpacked_size = Some(290);
        facts.is_encrypted = true;
        facts.data_crc32 = Some(0x1234_5678);
        facts.compression_version = 29;

        let mut builder = StoredLayoutBuilder::new(ArchiveFormat::Rar4);
        builder
            .add_volume(0, &rar4_volume(vec![facts]))
            .expect("volume accepted");

        let store = encrypted_store(&builder, 0);
        assert_eq!(store.crypt, None);
        assert_eq!(store.rar4_salt, None);
        assert!(store.resolved);
        assert_eq!(store.keying(), MemberKeying::Rar4 { salt: None });
    }

    /// One RAR4 encrypted `Store` member at `unpack_version`, sized so that the
    /// chain sums to `align16(unpacked_size)`.
    fn rar4_encrypted_member(unpacked_size: u64, unpack_version: u8) -> RarVolumeMemberFacts {
        let cipher_size = align16(unpacked_size).expect("test sizes are small");
        let mut facts = member(EPISODE, 100, cipher_size);
        facts.unpacked_size = Some(unpacked_size);
        facts.is_encrypted = true;
        facts.rar4_salt = Some([0x9B; 8]);
        facts.data_crc32 = Some(0x1234_5678);
        facts.compression_version = unpack_version;
        facts
    }

    #[test]
    fn the_pre_aes_rar4_ciphers_stay_ineligible_rather_than_being_decrypted_as_aes() {
        // Plan 136 E3. RAR4 has carried four encryptions and only "RAR 3.0" is
        // AES-128-CBC. The older three obey neither of the two rules the whole
        // encrypted-store classification rests on — a CBC chain whose block N
        // needs only block N−1, and a total padded once to `align16` — so a
        // router must never be handed a key for one. RAR 2.0 is the dangerous
        // case and the reason this is a version test rather than a size test:
        // its stream *is* block-padded, so the `align16` sum passes and nothing
        // downstream but the member checksum would notice.
        for version in [13u8, 15, 20, 26] {
            let mut builder = StoredLayoutBuilder::new(ArchiveFormat::Rar4);
            builder
                .add_volume(0, &rar4_volume(vec![rar4_encrypted_member(290, version)]))
                .expect("volume accepted");
            assert_eq!(
                builder.members()[0].eligibility,
                MemberEligibility::Ineligible(IneligibilityReason::Encrypted),
                "unpack version {version} is not AES and must not classify as an encrypted store"
            );
            assert!(!builder.members()[0].eligibility.routes_direct());
        }

        // And the versions that *are* AES still classify, so the gate is a gate
        // and not a blanket refusal.
        for version in [29u8, 36, 50] {
            let mut builder = StoredLayoutBuilder::new(ArchiveFormat::Rar4);
            builder
                .add_volume(0, &rar4_volume(vec![rar4_encrypted_member(290, version)]))
                .expect("volume accepted");
            assert!(
                builder.members()[0].eligibility.encrypted_store().is_some(),
                "unpack version {version} is AES-128 and must classify"
            );
        }
    }

    #[test]
    fn a_rar14_encrypted_member_is_never_keyable_whatever_its_version_says() {
        // RAR 1.4 predates every version-selected cipher: its encryption is
        // always the RAR 1.3 one, so the unpack-version byte cannot be trusted
        // to say otherwise.
        let mut facts = rar4_encrypted_member(290, 29);
        facts.compression_version = 29;
        let mut volume_facts = rar4_volume(vec![facts]);
        volume_facts.format = 14;

        let mut builder = StoredLayoutBuilder::new(ArchiveFormat::Rar14);
        builder
            .add_volume(0, &volume_facts)
            .expect("volume accepted");
        assert_eq!(
            builder.members()[0].eligibility,
            MemberEligibility::Ineligible(IneligibilityReason::Encrypted)
        );
    }

    /// The RAR4 twin of [`encrypted_chain`]: a three-part encrypted chain
    /// summing to exactly `packed_total`, keyed by a file salt rather than by a
    /// `FHEXTRA_CRYPT` record.
    fn rar4_encrypted_chain(unpacked_size: u64, packed_total: u64) -> StoredLayoutBuilder {
        let head = packed_total / 3;
        let middle = packed_total / 3;
        let tail = packed_total - head - middle;

        let mut builder = StoredLayoutBuilder::new(ArchiveFormat::Rar4);
        for (number, size, split_before, split_after) in [
            (0u32, head, false, true),
            (1, middle, true, true),
            (2, tail, true, false),
        ] {
            let mut facts = split_part(EPISODE, 64, size, unpacked_size, split_before, split_after);
            facts.is_encrypted = true;
            facts.rar4_salt = Some([0x9B; 8]);
            facts.compression_version = 29;
            if !split_after {
                facts.data_crc32 = Some(0xFEED_BEEF);
            }
            builder
                .add_volume(number, &rar4_volume(vec![facts]))
                .expect("volume accepted");
        }
        builder
    }

    #[test]
    fn a_rar4_encrypted_chain_sums_to_align16_exactly_as_a_rar5_one_does() {
        // The completeness rule is the format's, not RAR5's: RAR4 encrypts a
        // member's whole plaintext as one CBC stream too, padded once at the
        // end, so the same three slacks are the same three answers.
        for (unpacked_size, slack) in [(4096u64, 0u64), (4095, 1), (4081, 15)] {
            let cipher_size = unpacked_size + slack;
            assert_eq!(align16(unpacked_size), Some(cipher_size), "test arithmetic");

            let builder = rar4_encrypted_chain(unpacked_size, cipher_size);
            let store = encrypted_store(&builder, 0);
            assert!(
                store.resolved,
                "unpacked {unpacked_size} padded to {cipher_size} is a complete RAR4 chain"
            );
            assert_eq!(store.cipher_size, Some(cipher_size));
            assert_eq!(store.tail_padding, Some(slack as u8));
            assert_eq!(
                store.keying(),
                MemberKeying::Rar4 {
                    salt: Some([0x9B; 8])
                }
            );
        }
    }

    #[test]
    fn a_rar4_encrypted_chain_carrying_a_whole_extra_block_is_rejected() {
        // The other half of the same rule, and the half a "within one block"
        // tolerance gets wrong: `align16` of an already-aligned member adds
        // nothing, so a chain one block longer is one block of bytes that
        // belong to nobody. The RAR5 twin is
        // `an_encrypted_chain_carrying_a_whole_extra_block_is_rejected`; the
        // logic is shared, and this states that RAR4 really does reach it.
        for (unpacked_size, cipher_size) in [(4096u64, 4096u64), (4095, 4096), (4081, 4096)] {
            assert_eq!(align16(unpacked_size), Some(cipher_size), "test arithmetic");

            let builder = rar4_encrypted_chain(unpacked_size, cipher_size + 16);
            assert_eq!(
                ineligible(&builder, 0),
                IneligibilityReason::MalformedChain(MalformedReason::ExceedsDeclaredSize {
                    packed_total: cipher_size + 16,
                    unpacked_size,
                }),
                "a whole block past align16({unpacked_size}) is a mismatch even though the \
                 slack is only 16 bytes"
            );
        }

        // And one byte short of the padded length, which the plaintext rule
        // would have accepted for an unencrypted member.
        let builder = rar4_encrypted_chain(4095, 4095);
        assert_eq!(
            ineligible(&builder, 0),
            IneligibilityReason::MalformedChain(MalformedReason::SizeMismatch {
                packed_total: 4095,
                unpacked_size: 4095,
            })
        );
    }

    #[test]
    fn keying_is_the_discriminant_for_both_formats() {
        // The surface a router dispatches on: one exhaustive answer per member,
        // and never a `None` to fall through — a member nothing can key is
        // `Ineligible` and cannot reach this call at all.
        let mut rar5 = layout();
        add(
            &mut rar5,
            0,
            &volume(vec![encrypted_member(EPISODE, 100, 290)]),
        );
        assert_eq!(
            encrypted_store(&rar5, 0).keying(),
            MemberKeying::Rar5(crypt_record())
        );

        let mut rar4 = StoredLayoutBuilder::new(ArchiveFormat::Rar4);
        rar4.add_volume(0, &rar4_volume(vec![rar4_encrypted_member(290, 29)]))
            .expect("volume accepted");
        assert_eq!(
            encrypted_store(&rar4, 0).keying(),
            MemberKeying::Rar4 {
                salt: Some([0x9B; 8])
            }
        );
        assert!(
            !encrypted_store(&rar4, 0).claims_password_check(),
            "RAR4 has no password-check value, so admission can never refute a password"
        );
    }

    #[test]
    fn unencrypted_members_keep_every_classification_they_had() {
        // The regression floor, stated once as a table rather than trusted to
        // the tests above: nothing on the plaintext path changed.
        let store = with_crc32(member(EPISODE, 100, 64), 0x1234_5678);
        let mut compressed = with_crc32(member(EXTRA, 200, 44), 0x2222_2222);
        compressed.compression_method = CompressionMethod::Normal.code();
        compressed.unpacked_size = Some(65_536);
        let mut solid = with_crc32(member(NEIGHBOUR, 300, 64), 0x3333_3333);
        solid.compression_solid = true;
        let mut blake2 = member(DISTANT, 400, 64);
        blake2.data_blake2_hash = Some([0x11; 32]);

        let mut builder = layout();
        add(
            &mut builder,
            0,
            &volume(vec![store, compressed, solid, blake2]),
        );

        assert_eq!(
            builder.members()[0].eligibility,
            MemberEligibility::DirectEligible
        );
        assert_eq!(
            ineligible(&builder, 1),
            IneligibilityReason::Compressed {
                packed_bytes: Some(44),
                unpacked_bytes: Some(65_536),
                totals_final: true,
            }
        );
        assert_eq!(ineligible(&builder, 2), IneligibilityReason::Solid);
        assert_eq!(
            ineligible(&builder, 3),
            IneligibilityReason::Blake2OnlyNoCrc32
        );
    }
}
