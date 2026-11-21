use super::*;

impl RarArchive {
    /// Open a multi-volume archive from multiple readers.
    ///
    /// The readers should be provided in volume order (index 0 is the first volume).
    /// All volumes are parsed and the unified member list is built.
    pub fn open_volumes(readers: Vec<Box<dyn ReadSeek>>) -> RarResult<Self> {
        if readers.is_empty() {
            return Err(RarError::CorruptArchive {
                detail: "no volumes provided".into(),
            });
        }

        let mut readers = readers.into_iter();
        let first = readers.next().ok_or_else(|| RarError::CorruptArchive {
            detail: "no volumes provided".into(),
        })?;
        let mut archive = Self::open_boxed_inner(
            first,
            None,
            std::sync::Arc::new(crate::crypto::KdfCache::new()),
        )?;

        for (i, reader) in readers.enumerate() {
            archive.add_volume(i + 1, reader)?;
        }

        Ok(archive)
    }

    /// Add a volume to the archive incrementally.
    ///
    /// `index` is the volume number (0-based). The reader should be positioned
    /// at the start of the volume.
    ///
    /// This parses the volume's headers and integrates its file entries into
    /// the unified member list. Supports both RAR5 and RAR4 volumes.
    pub fn add_volume(&mut self, index: usize, reader: Box<dyn ReadSeek>) -> RarResult<()> {
        // The index is the volume's place when its headers state no number,
        // and the volume table grows to hold it, so it meets the same limit
        // as a number read from a header.
        crate::limits::checked_volume_number(index as u64)?;
        let mut reader = reader;

        // Seek to start and read signature.
        reader.seek(SeekFrom::Start(0)).map_err(RarError::from)?;
        let format = signature::read_signature(&mut reader)?;

        if format == ArchiveFormat::Rar14 {
            return self.add_volume_rar14(index, reader);
        }
        if format == ArchiveFormat::Rar4 {
            return self.add_volume_rar4(index, reader);
        }

        // Parse headers (RAR5).
        let parsed = header::parse_all_headers_with_kdf_cache(
            &mut reader,
            self.password.as_deref(),
            &self.kdf_cache,
        )?;

        let vol_num = match parsed.main.as_ref().and_then(|m| m.volume_number) {
            Some(declared) => crate::limits::checked_volume_number(declared)?,
            None => index,
        };
        self.ensure_volume_header_encryption_matches(vol_num, parsed.is_encrypted)?;

        // Register this volume.
        self.volume_set.add_volume(vol_num);

        let more_volumes = parsed.end.as_ref().is_some_and(|e| e.more_volumes);

        if !more_volumes {
            self.volume_set.set_last_volume_seen();
            self.more_volumes = false;
        }

        // Process file headers from this volume.
        let entries: Vec<MemberEntry> = parsed
            .files
            .into_iter()
            .map(|pf| Self::rar5_member_entry(vol_num, pf))
            .collect();
        self.integrate_members(vol_num, entries);

        let mut services = Vec::with_capacity(parsed.services.len());
        for service in parsed.services {
            let packed_hashes =
                Self::packed_hashes_for_split_segment(&service.header.inner, service.hash.as_ref());
            let packed_hash_uses_mac = service
                .file_encryption
                .as_ref()
                .is_some_and(|enc| enc.use_hash_mac);
            let segment = DataSegment::with_packed_hashes(
                vol_num,
                service.header.inner.data_offset,
                service.header.inner.data_size,
                packed_hashes,
                packed_hash_uses_mac,
            );
            let mut file_header = service.header.inner;
            file_header.is_encrypted = service.is_encrypted;
            let ntfs_stream_name = (file_header.name == "STM")
                .then(|| {
                    file_header
                        .service_subdata
                        .as_deref()
                        .map(crate::header::common::decode_utf8_prefix_until_nul)
                })
                .flatten();
            let entry = ServiceEntry {
                header_offset: service.header.header_offset,
                is_child: service.header.is_child,
                is_inherited: service.header.is_inherited,
                file_header,
                is_encrypted: service.is_encrypted,
                file_encryption: service.file_encryption.map(Self::file_encryption_info),
                rar4_salt: None,
                hash: service.hash,
                comment_crc16: None,
                ntfs_stream_name,
                segments: vec![segment],
            };
            services.push(entry);
        }
        self.integrate_services(vol_num, services);
        self.refresh_rar5_recovery_records_from_services();

        // Store the reader.
        self.store_volume_reader(vol_num, reader);

        Ok(())
    }

    /// Extend a physical header prefix while retaining the decoder's solid
    /// state. Returns the number of file headers found in this volume; fewer
    /// than requested means the physical walk reached its end.
    ///
    /// Call in volume order, increasing `file_headers` within each volume.
    /// Header traversal resumes after the last accepted data range, including
    /// encrypted headers. Existing segments are not inserted twice. The input must be unchanged
    /// since earlier calls; replacing consumed bytes requires a new archive.
    /// As with `open_prefix`, the reader must wait at temporary input gaps.
    pub fn extend_volume_prefix(
        &mut self,
        index: usize,
        reader: Box<dyn ReadSeek>,
        file_headers: std::num::NonZeroUsize,
    ) -> RarResult<usize> {
        let previous = self
            .prefix_cursor
            .as_ref()
            .ok_or_else(|| RarError::CorruptArchive {
                detail: "prefix extension requires an archive opened with open_prefix".into(),
            })?;
        let resume = if index == previous.volume {
            if file_headers.get() < previous.file_headers {
                return Err(RarError::CorruptArchive {
                    detail: "RAR prefix cannot rewind its header count".into(),
                });
            }
            if previous.finished || file_headers.get() == previous.file_headers {
                return Ok(previous.file_headers);
            }
            Some(previous.clone())
        } else if previous.finished && previous.volume.checked_add(1) == Some(index) {
            None
        } else {
            return Err(RarError::CorruptArchive {
                detail: "RAR prefixes must finish each volume in order".into(),
            });
        };
        let additional = std::num::NonZeroUsize::new(
            file_headers.get() - resume.as_ref().map_or(0, |cursor| cursor.file_headers),
        )
        .expect("an unchanged prefix returned above");
        let mut prefix = Self::open_boxed_at_prefix(
            reader,
            self.password.as_deref(),
            Arc::clone(&self.kdf_cache),
            crate::short_read::HeaderScan::ThroughFile(additional),
            resume,
        )?;
        if prefix.format != self.format || prefix.is_solid != self.is_solid {
            return Err(RarError::CorruptArchive {
                detail: "RAR prefix changed archive format or solid mode".into(),
            });
        }
        self.ensure_volume_header_encryption_matches(index, prefix.is_encrypted)?;
        let mut cursor = prefix
            .prefix_cursor
            .take()
            .expect("prefix scan creates a cursor");
        cursor.volume = index;
        let count = cursor.file_headers;
        let mut members = prefix.members;
        if self.format.is_rar4_family() {
            for entry in &mut members {
                entry.segments[0].volume_index = index;
            }
        }
        members.retain(|entry| !self.holds_member_segment(&entry.segments[0]));
        // Validate the complete delta before mutating the live catalog. A bad
        // later header in a multi-header extension must leave retry idempotent.
        for (position, entry) in members.iter().enumerate() {
            if !self.format.is_rar4_family() && entry.segments[0].volume_index != index {
                return Err(RarError::CorruptArchive {
                    detail: "RAR prefix declared an unexpected volume number".into(),
                });
            }
            if entry.file_header.split_before
                && (position != 0
                    || !self.members.last().is_some_and(|previous| {
                        previous.file_header.split_after
                            && previous
                                .segments
                                .last()
                                .is_some_and(|old| old.volume_index.checked_add(1) == Some(index))
                            && (entry.file_header.name.is_empty()
                                || previous.file_header.name == entry.file_header.name)
                    }))
            {
                return Err(RarError::CorruptArchive {
                    detail: "RAR prefix has an unmatched continuation".into(),
                });
            }
        }
        for entry in members {
            // Prefixes are ordered. Only the last logical member can continue
            // into the next volume; no catalog-wide reconciliation is needed.
            if entry.file_header.split_before {
                let previous = self
                    .members
                    .last_mut()
                    .expect("continuation validated above");
                Self::merge_continuation(previous, &entry, entry.segments[0].clone());
                self.hold(&entry.segments[0]);
            } else {
                for segment in &entry.segments {
                    self.hold(segment);
                }
                self.members.push(entry);
            }
        }
        self.catalog_changed();
        self.volume_set.add_volume(index);
        self.prefix_cursor = Some(cursor);
        Ok(count)
    }

    /// Re-parse and replace the cached topology contribution for a volume.
    ///
    /// This is used after external placement correction swaps volume contents
    /// while keeping the same filenames. Reader attachment is not enough in
    /// that case because the cached member segments still describe the old
    /// content at this volume index.
    pub fn refresh_volume(&mut self, index: usize, reader: Box<dyn ReadSeek>) -> RarResult<()> {
        self.remove_volume_segments(index);
        self.add_volume(index, reader)
    }

    fn remove_volume_segments(&mut self, index: usize) {
        self.held_segments = None;
        for member in &mut self.members {
            member
                .segments
                .retain(|segment| segment.volume_index != index);
        }
        self.members.retain(|member| !member.segments.is_empty());
        for service in &mut self.services {
            service
                .segments
                .retain(|segment| segment.volume_index != index);
        }
        self.services.retain(|service| !service.segments.is_empty());
        self.reconcile_member_chains();
        Self::reconcile_service_chains(&mut self.services);
        self.catalog_changed();
        self.refresh_rar5_recovery_records_from_services();
    }

    /// Add a RAR4 volume incrementally.
    pub(super) fn add_volume_rar4(
        &mut self,
        index: usize,
        mut reader: Box<dyn ReadSeek>,
    ) -> RarResult<()> {
        let parsed = crate::rar4::parse_rar4_headers_with_kdf_cache(
            &mut reader,
            self.password.as_deref(),
            &self.kdf_cache,
        )?;
        self.add_volume_rar4_parsed(index, reader, parsed)
    }

    /// Add a RAR 1.4 volume incrementally.
    pub(super) fn add_volume_rar14(
        &mut self,
        index: usize,
        mut reader: Box<dyn ReadSeek>,
    ) -> RarResult<()> {
        let parsed = crate::rar4::parse_rar14_headers(&mut reader)?;
        self.add_volume_rar4_parsed(index, reader, parsed)
    }

    fn add_volume_rar4_parsed(
        &mut self,
        index: usize,
        reader: Box<dyn ReadSeek>,
        parsed: crate::rar4::Rar4ParsedVolume,
    ) -> RarResult<()> {
        // Use volume number from ENDARC header if available, otherwise fall back to index.
        let vol_num = match parsed.end.as_ref().and_then(|e| e.volume_number) {
            Some(declared) => crate::limits::checked_volume_number(u64::from(declared))?,
            None => index,
        };
        self.ensure_volume_header_encryption_matches(vol_num, parsed.archive_header.is_encrypted)?;
        self.volume_set.add_volume(vol_num);

        let more_volumes = parsed.end.as_ref().is_some_and(|e| e.more_volumes);
        if !more_volumes {
            self.volume_set.set_last_volume_seen();
            self.more_volumes = false;
        }
        let entries: Vec<MemberEntry> = parsed
            .files
            .iter()
            .map(|fh| Self::rar4_member_entry(vol_num, fh, parsed.archive_header.is_solid))
            .collect();
        self.integrate_members(vol_num, entries);

        let mut services = Vec::new();
        for fh in &parsed.services {
            let file_header = Self::rar4_to_file_header(fh, parsed.archive_header.is_solid);
            let entry = ServiceEntry {
                header_offset: fh.data_offset,
                is_child: false,
                is_inherited: false,
                file_header: file_header.clone(),
                is_encrypted: fh.is_encrypted,
                file_encryption: None,
                rar4_salt: fh.salt,
                hash: None,
                comment_crc16: None,
                ntfs_stream_name: None,
                segments: vec![DataSegment::with_packed_hashes(
                    vol_num,
                    fh.data_offset,
                    fh.packed_size,
                    Self::packed_hashes_for_split_segment(&file_header, None),
                    false,
                )],
            };
            services.push(entry);
        }
        for old_service in &parsed.old_services {
            if let Some(entry) =
                Self::rar4_old_service_to_service_entry(old_service, vol_num, self.format)
            {
                services.push(entry);
            }
        }
        for comment in &parsed.comments {
            services.push(Self::rar4_comment_to_service_entry(
                comment,
                vol_num,
                self.format,
            ));
        }
        self.integrate_services(vol_num, services);

        self.store_volume_reader(vol_num, reader);
        self.hydrate_rar4_uowner_payloads();
        Ok(())
    }

    /// The member record a RAR5 file header in volume `vol_num` describes:
    /// the header's own fields and the one data segment it names.
    pub(super) fn rar5_member_entry(vol_num: usize, pf: header::ParsedFile) -> MemberEntry {
        let packed_hashes = Self::packed_hashes_for_split_segment(&pf.header, pf.hash.as_ref());
        let packed_hash_uses_mac = pf
            .file_encryption
            .as_ref()
            .is_some_and(|enc| enc.use_hash_mac);
        let segment = DataSegment::with_packed_hashes(
            vol_num,
            pf.header.data_offset,
            pf.header.data_size,
            packed_hashes,
            packed_hash_uses_mac,
        );

        let mut file_header = pf.header;
        file_header.is_encrypted = pf.is_encrypted;
        MemberEntry {
            file_header,
            is_encrypted: pf.is_encrypted,
            file_encryption: pf.file_encryption.map(Self::file_encryption_info),
            rar4_salt: None,
            hash: pf.hash,
            redirection: pf.redirection,
            owner: pf.owner,
            segments: vec![segment],
        }
    }

    /// The member record a RAR4 file header in volume `vol_num` describes:
    /// the header's own fields and the one data segment it names.
    pub(super) fn rar4_member_entry(
        vol_num: usize,
        fh: &crate::rar4::types::Rar4FileHeader,
        archive_solid: bool,
    ) -> MemberEntry {
        let file_header = Self::rar4_to_file_header(fh, archive_solid);
        let segment = DataSegment::with_packed_hashes(
            vol_num,
            fh.data_offset,
            fh.packed_size,
            Self::packed_hashes_for_split_segment(&file_header, None),
            false,
        );
        MemberEntry {
            file_header,
            is_encrypted: fh.is_encrypted,
            file_encryption: None,
            rar4_salt: fh.salt,
            hash: None,
            redirection: None,
            owner: fh.owner.clone(),
            segments: vec![segment],
        }
    }

    /// Whether a member record already holds the data segment `segment`
    /// names: the header naming it was integrated before, by an earlier
    /// volume add or by an extraction that read it through a provider.
    ///
    /// Answered from `held_segments`, which is built from `members` in one
    /// pass when it is not held.
    fn holds_member_segment(&mut self, segment: &DataSegment) -> bool {
        let members = &self.members;
        let held = self.held_segments.get_or_insert_with(|| {
            members
                .iter()
                .flat_map(|member| &member.segments)
                .map(|held| {
                    #[cfg(test)]
                    held_segment_visits::add();
                    (held.volume_index, held.data_offset)
                })
                .collect()
        });
        let holds = held.contains(&(segment.volume_index, segment.data_offset));
        #[cfg(test)]
        assert_eq!(holds, self.scan_member_segments(segment));
        holds
    }

    /// The same answer as `holds_member_segment`, read from every segment of
    /// every member. Tests check the set against it; it costs a walk of the
    /// whole catalog per call, so release and debug builds do not run it.
    #[cfg(test)]
    fn scan_member_segments(&self, segment: &DataSegment) -> bool {
        self.members.iter().any(|member| {
            member.segments.iter().any(|held| {
                held.volume_index == segment.volume_index && held.data_offset == segment.data_offset
            })
        })
    }

    /// Record that a member now holds `segment`.
    fn hold(&mut self, segment: &DataSegment) {
        if let Some(held) = &mut self.held_segments {
            held.insert((segment.volume_index, segment.data_offset));
        }
    }

    /// Record continuation parts of member `index` that extraction read from
    /// a volume provider.
    ///
    /// Each part is merged exactly as `add_volume` merges a continuation, so
    /// once the final part has been read the member's record carries the
    /// whole-member checksum, size and segment chain that header states.
    /// Discovery starts past the record's last known volume, so every part
    /// is one the record does not hold yet.
    pub(super) fn learn_continuations(&mut self, index: usize, parts: Vec<MemberEntry>) {
        let Some(existing) = self.members.get_mut(index) else {
            return;
        };
        let mut learned = Vec::with_capacity(parts.len());
        for part in parts {
            let segment = part.segments[0].clone();
            learned.push(segment.clone());
            Self::merge_continuation(existing, &part, segment);
        }
        for segment in &learned {
            self.hold(segment);
        }
        self.catalog_changed();
    }

    /// Drop the name and service-parent lookups after a change to the member
    /// or service lists.
    pub(super) fn catalog_changed(&mut self) {
        self.catalog = super::chains::CatalogIndex::default();
    }

    /// Integrate one member entry from a new volume.
    #[cfg(test)]
    pub(super) fn integrate_member(&mut self, vol_num: usize, entry: MemberEntry) {
        self.integrate_members(vol_num, [entry]);
    }

    /// Integrate the member entries of a new volume, in header order, into
    /// the unified member list.
    ///
    /// Handles split_before/split_after reconciliation for files spanning volumes.
    /// Continuation headers (split_before) in real RAR archives often have empty
    /// names, so we match by split state and volume adjacency, not by name.
    ///
    /// The result is the one integrating each entry alone gave, when each
    /// ended with a reconcile of every pair and a sort: the entries are
    /// matched through a [`Linker`](super::chains::Linker) that ranks records
    /// in the order those sorts left them, and the list is sorted once.
    pub(super) fn integrate_members(
        &mut self,
        vol_num: usize,
        entries: impl IntoIterator<Item = MemberEntry>,
    ) {
        let mut linker = None;
        for entry in entries {
            let segment = entry.segments[0].clone();
            if self.holds_member_segment(&segment) {
                continue;
            }
            let linker = linker.get_or_insert_with(|| {
                super::chains::Linker::new(&self.members, self.solid_next_index == 0)
            });
            self.integrate_member_with(linker, vol_num, entry, segment);
        }
        if let Some(linker) = linker {
            if linker.sorted() {
                self.members.sort_by_key(Self::member_physical_order_key);
            }
            self.catalog_changed();
        }
    }

    fn integrate_member_with(
        &mut self,
        linker: &mut super::chains::Linker,
        vol_num: usize,
        entry: MemberEntry,
        segment: DataSegment,
    ) {
        linker.begin(self.members.len());
        if entry.file_header.split_before {
            // Continuation segment — find the existing member that expects a
            // continuation in the immediately preceding volume.
            if let Some(at) = linker.continued_into(&self.members, vol_num, |_| true) {
                linker.update(&mut self.members, at, |existing| {
                    Self::merge_continuation(existing, &entry, segment.clone());
                });
                self.hold(&segment);
            } else {
                // No prior entry — volumes arrived out of order.
                for segment in &entry.segments {
                    self.hold(segment);
                }
                linker.push(&mut self.members, entry);
            }
        } else if let Some(at) =
            // New member starting in this volume. Check if we already have a
            // continuation-only entry from a later volume (out-of-order arrival).
            linker.named_after(&self.members, &entry.file_header.name, vol_num)
        {
            linker.moving(&self.members, at);
            linker.update(&mut self.members, at, |existing| {
                Self::insert_member_head(existing, entry, segment.clone());
            });
            self.hold(&segment);
        } else {
            for segment in &entry.segments {
                self.hold(segment);
            }
            linker.push(&mut self.members, entry);
        }
        linker.relink(&mut self.members, Self::merge_member_chain);
    }

    /// Put the first part of a member in front of the later parts already
    /// held.
    fn insert_member_head(existing: &mut MemberEntry, entry: MemberEntry, segment: DataSegment) {
        let authoritative_data_crc32 =
            (!existing.file_header.split_after).then_some(existing.file_header.data_crc32);
        let authoritative_data_hash =
            (!existing.file_header.split_after).then_some(existing.file_header.data_hash);
        let authoritative_hash = (!existing.file_header.split_after).then(|| existing.hash.clone());
        let authoritative_encryption =
            (!existing.file_header.split_after).then(|| existing.file_encryption.clone());
        // The new segment goes in front, so the chain still ends
        // where the later part said it does.
        let tail_split_after = existing.file_header.split_after;
        existing.segments.insert(0, segment.clone());
        existing.file_header = entry.file_header;
        existing.file_header.split_after = tail_split_after;
        existing.is_encrypted = entry.is_encrypted;
        existing.file_encryption = entry.file_encryption;
        existing.rar4_salt = entry.rar4_salt;
        if let Some(data_crc32) = authoritative_data_crc32 {
            existing.file_header.data_crc32 = data_crc32;
        }
        if let Some(data_hash) = authoritative_data_hash {
            existing.file_header.data_hash = data_hash;
        }
        if let Some(hash) = authoritative_hash {
            existing.hash = hash;
        } else if entry.hash.is_some() {
            existing.hash = entry.hash;
        }
        if let Some(Some(final_encryption)) = authoritative_encryption {
            if existing.file_encryption.is_none() {
                existing.file_encryption = Some(final_encryption);
            } else if final_encryption.use_hash_mac
                && let Some(existing_encryption) = existing.file_encryption.as_mut()
            {
                existing_encryption.use_hash_mac = true;
            }
        }
        if entry.redirection.is_some() {
            existing.redirection = entry.redirection;
        }
    }

    pub(crate) fn sort_members_by_physical_order(&mut self) {
        self.members.sort_by_key(Self::member_physical_order_key);
        self.catalog_changed();
    }

    fn member_physical_order_key(member: &MemberEntry) -> (usize, u64) {
        member
            .segments
            .iter()
            .map(|segment| (segment.volume_index, segment.data_offset))
            .min()
            .unwrap_or((usize::MAX, member.file_header.data_offset))
    }

    /// Join every pair of member parts that continue one another: the first
    /// part in list order that has a continuation takes its first one, until
    /// none is left. Then sort, when the catalog keeps physical order.
    fn reconcile_member_chains(&mut self) {
        let sorts = self.solid_next_index == 0;
        let mut linker = super::chains::Linker::new(&self.members, sorts);
        linker.begin(self.members.len());
        linker.relink(&mut self.members, Self::merge_member_chain);
        if sorts {
            self.members.sort_by_key(Self::member_physical_order_key);
        }
        self.catalog_changed();
    }

    fn merge_member_chain(existing: &mut MemberEntry, mut continuation: MemberEntry) {
        existing.segments.append(&mut continuation.segments);
        existing
            .segments
            .sort_by_key(|segment| segment.volume_index);
        Self::merge_member_metadata(existing, &continuation.file_header, &continuation);
    }

    /// Merge a continuation entry's metadata into an existing member.
    fn merge_continuation(existing: &mut MemberEntry, entry: &MemberEntry, segment: DataSegment) {
        existing.segments.push(segment);
        existing
            .segments
            .sort_by_key(|existing_segment| existing_segment.volume_index);
        Self::merge_member_metadata(existing, &entry.file_header, entry);
    }

    fn merge_member_metadata(
        existing: &mut MemberEntry,
        incoming_header: &crate::header::file::FileHeader,
        incoming_entry: &MemberEntry,
    ) {
        if !incoming_header.split_after {
            existing.file_header.split_after = false;
        }
        if incoming_header.unpacked_size.is_some() {
            existing.file_header.unpacked_size = incoming_header.unpacked_size;
        }
        // In multi-volume archives, each volume's file header stores the CRC of
        // that volume's data segment. Only the LAST continuation (split_after=false)
        // has the whole-file CRC. Always prefer the final segment's CRC.
        if (!incoming_header.split_after && incoming_header.data_crc32.is_some())
            || existing.file_header.data_crc32.is_none()
        {
            existing.file_header.data_crc32 = incoming_header.data_crc32;
            // When we adopt the CRC from a different segment, also update
            // use_hash_mac from that segment's encryption info. RAR7 sets
            // HASHMAC (enc_flags & 0x0002) only on the final segment of
            // encrypted multi-volume files, meaning the CRC there is
            // HMAC-transformed. We must know this to skip verification.
            if let Some(ref entry_enc) = incoming_entry.file_encryption
                && entry_enc.use_hash_mac
                && let Some(ref mut existing_enc) = existing.file_encryption
            {
                existing_enc.use_hash_mac = true;
            }
        }
        // Carry over the name if the existing entry still has an empty name
        // (can happen with out-of-order volume arrival).
        if existing.file_header.name.is_empty() && !incoming_header.name.is_empty() {
            existing.file_header.name = incoming_header.name.clone();
        }
        if !existing.is_encrypted && incoming_entry.is_encrypted {
            existing.is_encrypted = true;
        }
        if existing.file_encryption.is_none() && incoming_entry.file_encryption.is_some() {
            existing.file_encryption = incoming_entry.file_encryption.clone();
        }
        if existing.rar4_salt.is_none() && incoming_entry.rar4_salt.is_some() {
            existing.rar4_salt = incoming_entry.rar4_salt;
        }
        if !incoming_header.split_after
            || (existing.hash.is_none() && incoming_entry.hash.is_some())
        {
            existing.hash = incoming_entry.hash.clone();
        }
        if existing.redirection.is_none() && incoming_entry.redirection.is_some() {
            existing.redirection = incoming_entry.redirection.clone();
        }
    }

    /// Integrate one service entry from volume `vol_num`.
    #[cfg(test)]
    pub(super) fn integrate_service_entry(
        services: &mut Vec<ServiceEntry>,
        vol_num: usize,
        entry: ServiceEntry,
    ) {
        Self::integrate_service_entries(services, vol_num, [entry]);
    }

    /// Integrate the service entries of volume `vol_num` into this archive's
    /// service list, and drop the lookups built over the old list.
    pub(super) fn integrate_services(
        &mut self,
        vol_num: usize,
        entries: impl IntoIterator<Item = ServiceEntry>,
    ) {
        Self::integrate_service_entries(&mut self.services, vol_num, entries);
        self.catalog_changed();
    }

    /// Integrate service entries, in header order, the way member entries
    /// are: continuations join the part before them, out-of-order heads go in
    /// front of their later parts, and the list ends in physical order. As
    /// with [`integrate_members`](Self::integrate_members), the list is
    /// sorted once and matched in the order per-entry sorts left it.
    pub(super) fn integrate_service_entries(
        services: &mut Vec<ServiceEntry>,
        vol_num: usize,
        entries: impl IntoIterator<Item = ServiceEntry>,
    ) {
        let mut linker = None;
        for entry in entries {
            let linker = linker.get_or_insert_with(|| super::chains::Linker::new(services, true));
            linker.begin(services.len());
            let segment = entry.segments[0].clone();
            if entry.file_header.split_before {
                let at = linker.continued_into(services, vol_num, |service| {
                    Self::service_names_compatible(service, &entry)
                });
                if let Some(at) = at {
                    linker.update(services, at, |existing| {
                        Self::merge_service_continuation(existing, &entry, segment);
                    });
                } else {
                    linker.push(services, entry);
                }
            } else if let Some(at) = linker.named_after(services, &entry.file_header.name, vol_num)
            {
                linker.moving(services, at);
                linker.update(services, at, |existing| {
                    Self::insert_service_head(existing, entry, segment);
                });
            } else {
                linker.push(services, entry);
            }
            linker.relink(services, Self::merge_service_chain);
        }
        if linker.is_some_and(|linker| linker.sorted()) {
            services.sort_by_key(Self::service_physical_order_key);
        }
    }

    /// Put the first part of a service in front of the later parts already
    /// held.
    fn insert_service_head(existing: &mut ServiceEntry, entry: ServiceEntry, segment: DataSegment) {
        let authoritative_data_crc32 =
            (!existing.file_header.split_after).then_some(existing.file_header.data_crc32);
        let authoritative_data_hash =
            (!existing.file_header.split_after).then_some(existing.file_header.data_hash);
        let authoritative_hash = (!existing.file_header.split_after).then(|| existing.hash.clone());
        let authoritative_comment_crc16 =
            (!existing.file_header.split_after).then_some(existing.comment_crc16);
        let authoritative_encryption =
            (!existing.file_header.split_after).then(|| existing.file_encryption.clone());
        existing.segments.insert(0, segment);
        existing.file_header = entry.file_header;
        existing.is_encrypted = entry.is_encrypted;
        existing.file_encryption = entry.file_encryption;
        if let Some(data_crc32) = authoritative_data_crc32 {
            existing.file_header.data_crc32 = data_crc32;
        }
        if let Some(data_hash) = authoritative_data_hash {
            existing.file_header.data_hash = data_hash;
        }
        if let Some(hash) = authoritative_hash {
            existing.hash = hash;
        } else if entry.hash.is_some() {
            existing.hash = entry.hash;
        }
        if let Some(comment_crc16) = authoritative_comment_crc16 {
            existing.comment_crc16 = comment_crc16;
        } else if entry.comment_crc16.is_some() {
            existing.comment_crc16 = entry.comment_crc16;
        }
        if let Some(Some(final_encryption)) = authoritative_encryption {
            if existing.file_encryption.is_none() {
                existing.file_encryption = Some(final_encryption);
            } else if final_encryption.use_hash_mac
                && let Some(existing_encryption) = existing.file_encryption.as_mut()
            {
                existing_encryption.use_hash_mac = true;
            }
        }
    }

    /// Join every pair of service parts that continue one another, as
    /// [`reconcile_member_chains`](Self::reconcile_member_chains) does, then
    /// sort.
    fn reconcile_service_chains(services: &mut Vec<ServiceEntry>) {
        let mut linker = super::chains::Linker::new(services, true);
        linker.begin(services.len());
        linker.relink(services, Self::merge_service_chain);
        services.sort_by_key(Self::service_physical_order_key);
    }

    fn merge_service_chain(existing: &mut ServiceEntry, mut continuation: ServiceEntry) {
        existing.segments.append(&mut continuation.segments);
        existing
            .segments
            .sort_by_key(|segment| segment.volume_index);
        Self::merge_service_metadata(existing, &continuation);
    }

    fn service_physical_order_key(service: &ServiceEntry) -> (usize, u64) {
        service
            .segments
            .iter()
            .map(|segment| (segment.volume_index, segment.data_offset))
            .min()
            .unwrap_or((usize::MAX, service.file_header.data_offset))
    }

    fn service_names_compatible(left: &ServiceEntry, right: &ServiceEntry) -> bool {
        left.file_header.name.is_empty()
            || right.file_header.name.is_empty()
            || left.file_header.name == right.file_header.name
    }

    fn merge_service_continuation(
        existing: &mut ServiceEntry,
        incoming: &ServiceEntry,
        segment: DataSegment,
    ) {
        existing.segments.push(segment);
        existing
            .segments
            .sort_by_key(|existing_segment| existing_segment.volume_index);
        Self::merge_service_metadata(existing, incoming);
    }

    fn merge_service_metadata(existing: &mut ServiceEntry, incoming: &ServiceEntry) {
        let incoming_header = &incoming.file_header;

        if !incoming_header.split_after {
            existing.file_header.split_after = false;
        }
        if incoming_header.unpacked_size.is_some() {
            existing.file_header.unpacked_size = incoming_header.unpacked_size;
        }
        if (!incoming_header.split_after && incoming_header.data_crc32.is_some())
            || existing.file_header.data_crc32.is_none()
        {
            existing.file_header.data_crc32 = incoming_header.data_crc32;
            if let Some(ref incoming_enc) = incoming.file_encryption
                && incoming_enc.use_hash_mac
                && let Some(ref mut existing_enc) = existing.file_encryption
            {
                existing_enc.use_hash_mac = true;
            }
        }
        if existing.file_header.name.is_empty() && !incoming_header.name.is_empty() {
            existing.file_header.name = incoming_header.name.clone();
        }
        if !existing.is_encrypted && incoming.is_encrypted {
            existing.is_encrypted = true;
        }
        if existing.file_encryption.is_none() && incoming.file_encryption.is_some() {
            existing.file_encryption = incoming.file_encryption.clone();
        }
        if !incoming_header.split_after || (existing.hash.is_none() && incoming.hash.is_some()) {
            existing.hash = incoming.hash.clone();
        }
        if !incoming_header.split_after
            || (existing.comment_crc16.is_none() && incoming.comment_crc16.is_some())
        {
            existing.comment_crc16 = incoming.comment_crc16;
        }
        if !incoming_header.split_after
            || (existing.ntfs_stream_name.is_none() && incoming.ntfs_stream_name.is_some())
        {
            existing.ntfs_stream_name = incoming.ntfs_stream_name.clone();
        }
    }

    fn ensure_volume_header_encryption_matches(
        &self,
        vol_num: usize,
        next_is_encrypted: bool,
    ) -> RarResult<()> {
        if self.is_encrypted != next_is_encrypted {
            return Err(RarError::CorruptArchive {
                detail: format!(
                    "volume {vol_num} changed header encryption state from {} to {}",
                    self.is_encrypted, next_is_encrypted
                ),
            });
        }
        Ok(())
    }

    /// Store a volume reader at the given index.
    pub(super) fn store_volume_reader(&mut self, vol_num: usize, reader: Box<dyn ReadSeek>) {
        while self.volumes.len() <= vol_num {
            self.volumes.push(None);
        }
        self.volumes[vol_num] = Some(VolumeData { reader });
    }
}

/// How many member segments this thread's archives visited to build their
/// held-segment sets.
#[cfg(test)]
pub(super) mod held_segment_visits {
    use std::cell::Cell;

    thread_local! {
        static VISITS: Cell<usize> = const { Cell::new(0) };
    }

    pub(in crate::archive) fn add() {
        VISITS.with(|visits| visits.set(visits.get() + 1));
    }

    /// The visits since the last call, which resets the count.
    pub(in crate::archive) fn take() -> usize {
        VISITS.with(|visits| visits.replace(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::header::file::FileHeader;
    use crate::limits::Limits;
    use crate::types::{
        ArchiveFormat, CompressionInfo, CompressionMethod, FileAttributes, FileHash, HostOs,
        RecoveryRecordKind,
    };

    pub(super) fn test_file_header(
        name: &str,
        split_before: bool,
        split_after: bool,
        data_crc32: Option<u32>,
    ) -> FileHeader {
        FileHeader {
            name: name.to_string(),
            name_raw: Some(name.as_bytes().to_vec()),
            unpacked_size: Some(16),
            attributes: FileAttributes(0),
            mtime: None,
            ctime: None,
            atime: None,
            data_crc32,
            data_hash: data_crc32.map(crate::types::DataHash::Crc32),
            compression: CompressionInfo {
                format: ArchiveFormat::Rar5,
                version: 0,
                solid: false,
                method: CompressionMethod::Store,
                dict_size: 0,
            },
            host_os: HostOs::Unix,
            is_directory: false,
            file_flags: 0,
            data_size: 8,
            split_before,
            split_after,
            data_offset: 0,
            is_encrypted: false,
            version: None,
            service_subdata: None,
        }
    }

    fn test_member(
        name: &str,
        first_volume: usize,
        split_before: bool,
        split_after: bool,
        data_crc32: Option<u32>,
    ) -> MemberEntry {
        MemberEntry {
            file_header: test_file_header(name, split_before, split_after, data_crc32),
            is_encrypted: false,
            file_encryption: None,
            rar4_salt: None,
            hash: None,
            redirection: None,
            owner: None,
            segments: vec![DataSegment::new(first_volume, 0, 8)],
        }
    }

    fn test_service(
        name: &str,
        first_volume: usize,
        split_before: bool,
        split_after: bool,
    ) -> ServiceEntry {
        ServiceEntry {
            header_offset: 100 + first_volume as u64,
            is_child: false,
            is_inherited: false,
            file_header: test_file_header(name, split_before, split_after, Some(0xAABB_CCDD)),
            is_encrypted: false,
            file_encryption: None,
            rar4_salt: None,
            hash: None,
            comment_crc16: Some(0xCCDD),
            ntfs_stream_name: None,
            segments: vec![DataSegment::new(first_volume, 16, 8)],
        }
    }

    fn test_member_with_offset(
        name: &str,
        first_volume: usize,
        split_before: bool,
        split_after: bool,
        data_crc32: Option<u32>,
        data_offset: u64,
    ) -> MemberEntry {
        let mut member = test_member(name, first_volume, split_before, split_after, data_crc32);
        member.file_header.data_offset = data_offset;
        member.segments[0].data_offset = data_offset;
        member
    }

    pub(super) fn empty_archive(members: Vec<MemberEntry>) -> RarArchive {
        RarArchive {
            format: ArchiveFormat::Rar5,
            is_solid: false,
            is_encrypted: false,
            has_recovery_record: false,
            recovery_records: Vec::new(),
            is_locked: false,
            has_authenticity_verification: false,
            has_locator: false,
            quick_open_offset: None,
            recovery_record_offset: None,
            original_name: None,
            original_name_raw: None,
            original_creation_time: None,
            volume_set: VolumeSet::new(),
            members,
            services: Vec::new(),
            more_volumes: true,
            volumes: Vec::new(),
            solid_decoder: None,
            solid_decoder_rar4: None,
            solid_next_index: 0,
            solid_poison: None,
            verify: true,
            restore_owners: false,
            decode_mode: crate::DecodeMode::Auto,
            limits: Limits::default(),
            password: None,
            kdf_cache: std::sync::Arc::new(crate::crypto::KdfCache::new()),
            prefix_cursor: None,
            held_segments: None,
            catalog: super::chains::CatalogIndex::default(),
        }
    }

    #[test]
    fn volume_header_encryption_state_must_match_rar_behavior_merge_guard() {
        let mut archive = empty_archive(Vec::new());
        assert!(
            archive
                .ensure_volume_header_encryption_matches(1, false)
                .is_ok()
        );
        let err = archive
            .ensure_volume_header_encryption_matches(1, true)
            .unwrap_err();
        assert!(
            matches!(err, RarError::CorruptArchive { ref detail } if detail.contains("changed header encryption state")),
            "expected header encryption mismatch, got {err:?}"
        );

        archive.is_encrypted = true;
        assert!(
            archive
                .ensure_volume_header_encryption_matches(2, true)
                .is_ok()
        );
        let err = archive
            .ensure_volume_header_encryption_matches(2, false)
            .unwrap_err();
        assert!(
            matches!(err, RarError::CorruptArchive { ref detail } if detail.contains("volume 2")),
            "expected volume-specific mismatch, got {err:?}"
        );
    }

    #[test]
    fn a_volume_index_above_the_volume_limit_is_refused_before_the_table_grows() {
        let mut archive = empty_archive(Vec::new());
        let index = crate::limits::RAR_MAX_VOLUME_NUMBER as usize + 1;
        // The index is refused before the reader is touched.
        let err = archive
            .add_volume(index, Box::new(std::io::Cursor::new(Vec::new())))
            .unwrap_err();
        assert!(
            matches!(
                err,
                RarError::ResourceLimit {
                    kind: crate::error::LimitKind::VolumeNumber,
                    ..
                }
            ),
            "expected the volume number limit, got {err:?}"
        );
        assert!(archive.volumes.is_empty());
    }

    #[test]
    fn refresh_volume_removes_stale_service_segments() {
        let mut archive = empty_archive(Vec::new());
        archive.services = vec![
            test_service("CMT", 0, false, false),
            test_service("RR", 1, false, false),
        ];

        archive.remove_volume_segments(1);

        assert_eq!(archive.services.len(), 1);
        assert_eq!(archive.services[0].file_header.name, "CMT");
        assert_eq!(archive.services[0].segments[0].volume_index, 0);
    }

    #[test]
    fn rar5_recovery_records_refresh_from_integrated_services() {
        let mut archive = empty_archive(Vec::new());
        let mut rr = test_service("RR", 2, false, false);
        rr.header_offset = 0x1234;
        rr.file_header.data_offset = 0x1300;
        rr.file_header.data_size = 0x2000;
        rr.file_header.service_subdata = Some(crate::vint::encode_vint(375));
        archive.services = vec![rr];

        archive.refresh_rar5_recovery_records_from_services();

        assert!(archive.has_recovery_record);
        assert_eq!(archive.recovery_records.len(), 1);
        let record = &archive.recovery_records[0];
        assert_eq!(record.format, ArchiveFormat::Rar5);
        assert_eq!(record.kind, RecoveryRecordKind::Rar5Service);
        assert_eq!(record.offset, 0x1234);
        assert_eq!(record.data_offset, 0x1300);
        assert_eq!(record.data_size, 0x2000);
        assert_eq!(record.protected_size, Some(0x1234));
        assert_eq!(record.recovery_percent, Some(375));
    }

    #[test]
    fn removing_rr_service_drops_stale_rar5_recovery_records() {
        let mut archive = empty_archive(Vec::new());
        archive.services = vec![test_service("RR", 1, false, false)];
        archive.refresh_rar5_recovery_records_from_services();
        assert_eq!(archive.recovery_records.len(), 1);

        archive.remove_volume_segments(1);

        assert!(archive.recovery_records.is_empty());
    }

    #[test]
    fn reconcile_service_chains_handles_right_index_before_left_index() {
        let mut archive = empty_archive(Vec::new());
        archive.services = vec![
            test_service("", 2, true, false),
            test_service("RR", 1, false, true),
        ];
        archive.services[0].file_header.data_crc32 = Some(0x2222_2222);
        archive.services[0].comment_crc16 = Some(0x2222);
        archive.services[1].file_header.data_crc32 = None;
        archive.services[1].comment_crc16 = None;

        RarArchive::reconcile_service_chains(&mut archive.services);

        assert_eq!(archive.services.len(), 1);
        let merged = &archive.services[0];
        assert_eq!(merged.file_header.name, "RR");
        assert!(!merged.file_header.split_after);
        assert_eq!(merged.file_header.data_crc32, Some(0x2222_2222));
        assert_eq!(merged.comment_crc16, Some(0x2222));
        assert_eq!(
            merged
                .segments
                .iter()
                .map(|segment| segment.volume_index)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
    }

    #[test]
    fn integrate_service_preserves_out_of_order_final_hash_and_crc() {
        let first_hash = [0x11; 32];
        let final_hash = [0x22; 32];
        let mut continuation = test_service("CMT", 2, true, false);
        continuation.file_header.data_crc32 = Some(0x2222_2222);
        continuation.hash = Some(FileHash::Blake2sp(final_hash));
        continuation.comment_crc16 = Some(0x2222);
        let mut services = vec![continuation];

        let mut first = test_service("CMT", 1, false, true);
        first.file_header.data_crc32 = Some(0x1111_1111);
        first.hash = Some(FileHash::Blake2sp(first_hash));
        first.comment_crc16 = Some(0x1111);
        RarArchive::integrate_service_entry(&mut services, 1, first);

        assert_eq!(services.len(), 1);
        assert_eq!(services[0].file_header.data_crc32, Some(0x2222_2222));
        assert_eq!(services[0].hash, Some(FileHash::Blake2sp(final_hash)));
        assert_eq!(services[0].comment_crc16, Some(0x2222));
        assert_eq!(
            services[0]
                .segments
                .iter()
                .map(|segment| segment.volume_index)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
    }

    #[test]
    fn reconcile_member_chains_handles_right_index_before_left_index() {
        let mut archive = empty_archive(vec![
            test_member("", 2, true, false, Some(0x2222_2222)),
            test_member("episode.mkv", 1, false, true, None),
        ]);

        archive.reconcile_member_chains();

        assert_eq!(archive.members.len(), 1);
        let merged = &archive.members[0];
        assert_eq!(merged.file_header.name, "episode.mkv");
        assert!(!merged.file_header.split_after);
        assert_eq!(merged.file_header.data_crc32, Some(0x2222_2222));
        assert_eq!(
            merged
                .segments
                .iter()
                .map(|segment| segment.volume_index)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
    }

    #[test]
    fn merge_member_metadata_prefers_final_continuation_blake2_hash() {
        let first_hash = [0x11; 32];
        let final_hash = [0x22; 32];
        let mut archive = empty_archive(vec![test_member(
            "episode.mkv",
            1,
            false,
            true,
            Some(0x1111_1111),
        )]);
        archive.members[0].hash = Some(FileHash::Blake2sp(first_hash));
        let mut continuation = test_member("", 2, true, false, Some(0x2222_2222));
        continuation.hash = Some(FileHash::Blake2sp(final_hash));

        archive.integrate_member(2, continuation);

        assert_eq!(
            archive.members[0].hash,
            Some(FileHash::Blake2sp(final_hash))
        );
    }

    #[test]
    fn integrate_member_preserves_out_of_order_final_blake2_hash() {
        let first_hash = [0x11; 32];
        let final_hash = [0x22; 32];
        let mut continuation = test_member("episode.mkv", 2, true, false, Some(0x2222_2222));
        continuation.hash = Some(FileHash::Blake2sp(final_hash));
        let mut archive = empty_archive(vec![continuation]);
        let mut first = test_member("episode.mkv", 1, false, true, Some(0x1111_1111));
        first.hash = Some(FileHash::Blake2sp(first_hash));

        archive.integrate_member(1, first);

        assert!(!archive.members[0].file_header.split_after);
        assert_eq!(archive.members[0].file_header.data_crc32, Some(0x2222_2222));
        assert_eq!(
            archive.members[0].file_header.data_hash,
            Some(crate::types::DataHash::Crc32(0x2222_2222))
        );
        assert_eq!(
            archive.members[0].hash,
            Some(FileHash::Blake2sp(final_hash))
        );
        let info = archive.member_info(0).unwrap();
        assert_eq!(info.crc32, Some(0x2222_2222));
        assert_eq!(info.hash, Some(FileHash::Blake2sp(final_hash)));
    }

    #[test]
    fn cached_solid_multivolume_keeps_prior_member_before_split_member() {
        let archive = empty_archive(vec![
            test_member_with_offset("sample.mkv", 0, false, true, Some(0x1111_1111), 200),
            test_member_with_offset("ep1.mkv", 0, false, false, Some(0x2222_2222), 100),
        ]);

        let headers = archive.serialize_headers();
        let mut restored = RarArchive::deserialize_headers(&headers).unwrap();

        assert_eq!(restored.member_names(), vec!["ep1.mkv", "sample.mkv"]);
        assert_eq!(restored.find_member_sanitized("sample.mkv"), Some(1));

        restored.integrate_member(
            1,
            test_member_with_offset("sample.mkv", 1, true, true, Some(0x3333_3333), 0),
        );
        restored.integrate_member(
            2,
            test_member_with_offset("sample.mkv", 2, true, false, Some(0x4444_4444), 0),
        );

        assert_eq!(restored.member_names(), vec!["ep1.mkv", "sample.mkv"]);
        assert_eq!(restored.find_member_sanitized("sample.mkv"), Some(1));
    }
}

#[cfg(test)]
mod held_segment_tests {
    use std::collections::HashSet;
    use std::fs::File;
    use std::io::Cursor;
    use std::num::NonZeroUsize;
    use std::path::PathBuf;

    use super::*;
    use crate::volume::StaticVolumeProvider;

    const PASSWORD: &str = "testpass123";

    fn fixture_dir(dir: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(dir)
    }

    /// The volumes of a corpus set in order, or `None` (and a skip line) when
    /// the corpus is not hydrated.
    fn volumes(dir: &str, names: &[&str]) -> Option<Vec<PathBuf>> {
        let paths: Vec<PathBuf> = names
            .iter()
            .map(|name| fixture_dir(dir).join(name))
            .collect();
        let hydrated = paths
            .iter()
            .all(|path| std::fs::read(path).is_ok_and(|bytes| bytes.starts_with(b"Rar!")));
        if !hydrated {
            eprintln!("skipping test: {dir} fixtures not present ({})", names[0]);
            return None;
        }
        Some(paths)
    }

    fn numbered(stem: &str, count: usize, width: usize) -> Vec<String> {
        (1..=count)
            .map(|part| format!("{stem}.part{part:0width$}.rar"))
            .collect()
    }

    fn reader(path: &PathBuf) -> Box<dyn ReadSeek> {
        Box::new(File::open(path).unwrap())
    }

    fn scanned(archive: &RarArchive) -> HashSet<(usize, u64)> {
        archive
            .members
            .iter()
            .flat_map(|member| &member.segments)
            .map(|segment| (segment.volume_index, segment.data_offset))
            .collect()
    }

    /// The held set, once built, is exactly what a scan of the members
    /// finds; and a lookup through it agrees with the scan.
    fn assert_held(archive: &mut RarArchive, what: &str) {
        let probe =
            DataSegment::with_packed_hashes(usize::MAX - 1, 0, 0, Default::default(), false);
        assert!(!archive.holds_member_segment(&probe), "{what}");
        assert_eq!(
            archive.held_segments.as_ref(),
            Some(&scanned(archive)),
            "{what}"
        );
    }

    fn multi_volume_sets() -> Vec<(&'static str, Vec<PathBuf>)> {
        let mut sets = Vec::new();
        let named = [
            ("rar5", numbered("rar5_mv_store_pair", 9, 2)),
            ("rar5", numbered("rar5_mv_video", 5, 1)),
            ("rar5", numbered("rar5_tiny_volumes", 5, 1)),
            ("rar4", numbered("rar4_mv_store", 5, 1)),
            ("rar4", numbered("rar4_tiny_volumes", 5, 1)),
        ];
        for (dir, names) in named {
            let names: Vec<&str> = names.iter().map(String::as_str).collect();
            if let Some(paths) = volumes(dir, &names) {
                sets.push((dir, paths));
            }
        }
        sets
    }

    #[test]
    fn held_set_matches_the_scan_through_prefix_walks() {
        for (dir, paths) in multi_volume_sets() {
            for step in [1, 2, 5] {
                let what = format!("{dir} {} step {step}", paths[0].display());
                let mut archive = RarArchive::open_prefix(
                    File::open(&paths[0]).unwrap(),
                    None,
                    NonZeroUsize::MIN,
                )
                .unwrap();
                let mut headers = 1;
                for (volume, path) in paths.iter().enumerate() {
                    if volume > 0 {
                        headers = 0;
                    }
                    loop {
                        let wanted = NonZeroUsize::new(headers + step).unwrap();
                        let found = archive
                            .extend_volume_prefix(volume, reader(path), wanted)
                            .unwrap();
                        assert_held(&mut archive, &what);
                        headers = found;
                        if found < wanted.get() {
                            break;
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn held_set_matches_the_scan_through_volume_adds_in_any_order() {
        for (dir, paths) in multi_volume_sets() {
            let last = paths.len() - 1;
            let orders: [Vec<usize>; 3] = [
                (1..=last).collect(),
                (1..=last).rev().collect(),
                (1..=last)
                    .filter(|v| v % 2 == 0)
                    .chain((1..=last).filter(|v| v % 2 == 1))
                    .collect(),
            ];
            for order in orders {
                let what = format!("{dir} {} order {order:?}", paths[0].display());
                let mut archive = RarArchive::open(File::open(&paths[0]).unwrap()).unwrap();
                assert_held(&mut archive, &what);
                for &volume in &order {
                    archive.add_volume(volume, reader(&paths[volume])).unwrap();
                    assert_held(&mut archive, &what);
                }
                // A volume refreshed drops its segments and takes them again.
                archive.refresh_volume(1, reader(&paths[1])).unwrap();
                assert_held(&mut archive, &what);
                // Adding a volume already held integrates nothing twice.
                let before = archive.members.len();
                archive.add_volume(last, reader(&paths[last])).unwrap();
                assert_eq!(archive.members.len(), before, "{what}");
                assert_held(&mut archive, &what);
            }
        }
    }

    #[test]
    fn held_set_takes_the_continuations_a_decode_learns() {
        for (dir, paths) in multi_volume_sets() {
            let what = format!("{dir} {}", paths[0].display());
            let mut archive =
                RarArchive::open_prefix(File::open(&paths[0]).unwrap(), None, NonZeroUsize::MIN)
                    .unwrap();
            assert_held(&mut archive, &what);
            let provider = StaticVolumeProvider::from_ordered(paths.clone());
            let mut out = Vec::new();
            archive
                .by_index_via(0, &provider)
                .and_then(|entry| entry.copy_to(&mut out))
                .unwrap();
            assert_held(&mut archive, &what);
            // The walk reads on over the volumes the decode already learned.
            let mut headers = 1;
            for (volume, path) in paths.iter().enumerate() {
                if volume > 0 {
                    headers = 0;
                }
                let wanted = NonZeroUsize::new(headers + 1000).unwrap();
                headers = archive
                    .extend_volume_prefix(volume, reader(path), wanted)
                    .unwrap();
                assert_held(&mut archive, &what);
            }
            let fresh = RarArchive::open_volumes(paths.iter().map(reader).collect()).unwrap();
            assert_eq!(archive.members.len(), fresh.members.len(), "{what}");
        }
    }

    fn rar5_block(header_type: u64, header_flags: u64, sizes: &[u64], body: &[u8]) -> Vec<u8> {
        let mut full = crate::vint::encode_vint(header_type);
        full.extend_from_slice(&crate::vint::encode_vint(header_flags));
        for size in sizes {
            full.extend_from_slice(&crate::vint::encode_vint(*size));
        }
        full.extend_from_slice(body);
        let size = crate::vint::encode_vint(full.len() as u64);
        let mut hasher = crate::crc::Crc32::new();
        hasher.update(&size);
        hasher.update(&full);
        let mut raw = hasher.finalize().to_le_bytes().to_vec();
        raw.extend_from_slice(&size);
        raw.extend_from_slice(&full);
        raw
    }

    /// One RAR5 volume of `files` stored members of a few bytes each.
    fn stored_rar5(files: usize) -> Vec<u8> {
        let mut bytes = crate::signature::RAR5_SIGNATURE.to_vec();
        bytes.extend_from_slice(&rar5_block(1, 0, &[], &crate::vint::encode_vint(0)));
        for index in 0..files {
            let name = format!("file{index:05}.txt");
            let data = name.as_bytes();
            let mut body = crate::vint::encode_vint(0);
            body.extend_from_slice(&crate::vint::encode_vint(data.len() as u64));
            body.extend_from_slice(&crate::vint::encode_vint(0o644));
            body.extend_from_slice(&crate::vint::encode_vint(0));
            body.extend_from_slice(&crate::vint::encode_vint(1));
            body.extend_from_slice(&crate::vint::encode_vint(name.len() as u64));
            body.extend_from_slice(name.as_bytes());
            bytes.extend_from_slice(&rar5_block(
                2,
                crate::header::common::flags::DATA_AREA,
                &[data.len() as u64],
                &body,
            ));
            bytes.extend_from_slice(data);
        }
        bytes.extend_from_slice(&rar5_block(5, 0, &[], &crate::vint::encode_vint(0)));
        bytes
    }

    /// A prefix walk builds the held set once, from the members it holds
    /// then, and answers every later header by lookup: the segments visited
    /// do not grow with the headers walked.
    #[test]
    fn prefix_walk_builds_the_held_set_once() {
        for files in [64, 512] {
            let bytes = stored_rar5(files);
            held_segment_visits::take();
            let mut archive =
                RarArchive::open_prefix(Cursor::new(bytes.clone()), None, NonZeroUsize::MIN)
                    .unwrap();
            let mut headers = 1;
            loop {
                let wanted = NonZeroUsize::new(headers + 1).unwrap();
                let found = archive
                    .extend_volume_prefix(0, Box::new(Cursor::new(bytes.clone())), wanted)
                    .unwrap();
                headers = found;
                if found < wanted.get() {
                    break;
                }
            }
            assert_eq!(archive.len(), files);
            assert_eq!(held_segment_visits::take(), 1, "{files} files");
            assert_held(&mut archive, &format!("{files} files"));
        }
    }

    /// Decode member `index` of an archive opened from `paths[0]` through a
    /// provider over all of `paths`: its bytes, and its info afterwards.
    fn decoded(
        archive: &mut RarArchive,
        index: usize,
        provider: &StaticVolumeProvider,
    ) -> (Vec<u8>, String) {
        let mut out = Vec::new();
        archive
            .by_index_via(index, provider)
            .and_then(|entry| entry.copy_to(&mut out))
            .unwrap();
        (out, format!("{:?}", archive.member_info(index)))
    }

    #[test]
    fn member_archive_decodes_as_the_whole_archive_does() {
        let cases: Vec<(&str, Vec<String>, bool)> = vec![
            ("rar5", vec!["rar5_store.rar".into()], false),
            ("rar5", vec!["rar5_lz.rar".into()], false),
            ("rar5", vec!["rar5_multifile_lz.rar".into()], false),
            ("rar5", vec!["rar5_enc_lz.rar".into()], true),
            ("rar5", vec!["rar5_enc_store.rar".into()], true),
            (
                "rar5",
                numbered("generated_matrix_rar5_lz_plain", 7, 1),
                false,
            ),
            ("rar5", numbered("generated_matrix_rar5_lz_enc", 7, 1), true),
            ("rar5", numbered("rar5_mv_store_pair", 9, 2), false),
            ("rar4", vec!["rar4_store.rar".into()], false),
            ("rar4", vec!["rar4_lz.rar".into()], false),
            ("rar4", vec!["rar4_multifile_lz.rar".into()], false),
            ("rar4", vec!["rar4_enc_lz.rar".into()], true),
            (
                "rar4",
                numbered("generated_matrix_rar4_lz_plain", 7, 1),
                false,
            ),
            (
                "rar4",
                numbered("generated_matrix_rar4_store_enc", 7, 1),
                true,
            ),
        ];
        let mut checked = 0;
        for (dir, names, encrypted) in cases {
            let names: Vec<&str> = names.iter().map(String::as_str).collect();
            let Some(paths) = volumes(dir, &names) else {
                continue;
            };
            let open = || {
                let mut archive = RarArchive::open(File::open(&paths[0]).unwrap()).unwrap();
                if encrypted {
                    archive.set_password(PASSWORD);
                }
                archive
            };
            let provider = StaticVolumeProvider::from_ordered(paths.clone());
            let walk = open();
            let mut whole = open();
            assert!(walk.member_archive(walk.len()).is_none());
            for index in 0..walk.len() {
                let info = walk.member_info(index).unwrap();
                if info.is_directory {
                    continue;
                }
                let what = format!("{dir} {} member {index}", names[0]);
                let mut own = walk.member_archive(index).unwrap();
                assert_eq!(own.len(), 1, "{what}");
                let (copy_bytes, copy_info) = decoded(&mut own, 0, &provider);
                let (whole_bytes, whole_info) = decoded(&mut whole, index, &provider);
                assert_eq!(copy_bytes, whole_bytes, "{what}");
                assert_eq!(copy_info, whole_info, "{what}");
                checked += 1;
            }
        }
        eprintln!("member_archive: {checked} members checked");
    }
}

/// The chain linker against the per-entry upkeep it replaced, kept here as
/// the reference: every entry integrated alone, each followed by a reconcile
/// of every pair and, when the catalog keeps physical order, a sort.
#[cfg(test)]
mod chain_tests {
    use std::collections::HashSet;

    use super::tests::{empty_archive, test_file_header};
    use super::*;

    /// The old upkeep over one member list and one service list.
    struct Reference {
        members: Vec<MemberEntry>,
        services: Vec<ServiceEntry>,
        held: HashSet<(usize, u64)>,
        sorts: bool,
    }

    impl Reference {
        fn new(members: Vec<MemberEntry>, sorts: bool) -> Self {
            let held = members
                .iter()
                .flat_map(|member| &member.segments)
                .map(|segment| (segment.volume_index, segment.data_offset))
                .collect();
            Self {
                members,
                services: Vec::new(),
                held,
                sorts,
            }
        }

        fn hold(&mut self, segment: &DataSegment) {
            self.held
                .insert((segment.volume_index, segment.data_offset));
        }

        fn integrate_member(&mut self, vol_num: usize, entry: MemberEntry) {
            let segment = entry.segments[0].clone();
            if self
                .held
                .contains(&(segment.volume_index, segment.data_offset))
            {
                return;
            }
            if entry.file_header.split_before {
                let existing = self.members.iter_mut().find(|m| {
                    m.file_header.split_after
                        && m.segments.last().map(|s| s.volume_index)
                            == Some(vol_num.wrapping_sub(1))
                });
                if let Some(existing) = existing {
                    RarArchive::merge_continuation(existing, &entry, segment.clone());
                    self.hold(&segment);
                } else {
                    for segment in &entry.segments {
                        self.hold(segment);
                    }
                    self.members.push(entry);
                }
            } else {
                let existing = self.members.iter_mut().find(|m| {
                    !entry.file_header.name.is_empty()
                        && m.file_header.name == entry.file_header.name
                        && m.segments[0].volume_index > vol_num
                });
                if let Some(existing) = existing {
                    RarArchive::insert_member_head(existing, entry, segment.clone());
                    self.hold(&segment);
                } else {
                    for segment in &entry.segments {
                        self.hold(segment);
                    }
                    self.members.push(entry);
                }
            }
            self.reconcile_members();
        }

        fn reconcile_members(&mut self) {
            while let Some((left_idx, right_idx)) = Self::pair(&self.members) {
                let right = self.members.remove(right_idx);
                let left_idx = if right_idx < left_idx {
                    left_idx - 1
                } else {
                    left_idx
                };
                RarArchive::merge_member_chain(&mut self.members[left_idx], right);
            }
            if self.sorts {
                self.members
                    .sort_by_key(RarArchive::member_physical_order_key);
            }
        }

        fn integrate_service(&mut self, vol_num: usize, entry: ServiceEntry) {
            let segment = entry.segments[0].clone();
            if entry.file_header.split_before {
                let existing = self.services.iter_mut().find(|service| {
                    service.file_header.split_after
                        && service.segments.last().map(|s| s.volume_index)
                            == Some(vol_num.wrapping_sub(1))
                        && RarArchive::service_names_compatible(service, &entry)
                });
                if let Some(existing) = existing {
                    RarArchive::merge_service_continuation(existing, &entry, segment);
                } else {
                    self.services.push(entry);
                }
            } else {
                let existing = self.services.iter_mut().find(|service| {
                    !entry.file_header.name.is_empty()
                        && service.file_header.name == entry.file_header.name
                        && service.segments[0].volume_index > vol_num
                });
                if let Some(existing) = existing {
                    RarArchive::insert_service_head(existing, entry, segment);
                } else {
                    self.services.push(entry);
                }
            }
            self.reconcile_services();
        }

        fn reconcile_services(&mut self) {
            while let Some((left_idx, right_idx)) = Self::pair(&self.services) {
                let right = self.services.remove(right_idx);
                let left_idx = if right_idx < left_idx {
                    left_idx - 1
                } else {
                    left_idx
                };
                RarArchive::merge_service_chain(&mut self.services[left_idx], right);
            }
            self.services
                .sort_by_key(RarArchive::service_physical_order_key);
        }

        /// The all-pairs search both old reconciles ran.
        fn pair<E: super::super::chains::ChainEntry>(entries: &[E]) -> Option<(usize, usize)> {
            for (left_idx, left) in entries.iter().enumerate() {
                if !left.split_after() {
                    continue;
                }
                let Some(last_vol) = left.last_volume() else {
                    continue;
                };
                for (right_idx, right) in entries.iter().enumerate() {
                    if left_idx == right_idx {
                        continue;
                    }
                    let Some(first_vol) = right.first_volume() else {
                        continue;
                    };
                    if right.split_before()
                        && first_vol == last_vol + 1
                        && super::super::chains::names_compatible(left, right)
                    {
                        return Some((left_idx, right_idx));
                    }
                }
            }
            None
        }

        fn remove_volume(&mut self, index: usize) {
            for member in &mut self.members {
                member
                    .segments
                    .retain(|segment| segment.volume_index != index);
            }
            self.members.retain(|member| !member.segments.is_empty());
            for service in &mut self.services {
                service
                    .segments
                    .retain(|segment| segment.volume_index != index);
            }
            self.services.retain(|service| !service.segments.is_empty());
            self.held = self
                .members
                .iter()
                .flat_map(|member| &member.segments)
                .map(|segment| (segment.volume_index, segment.data_offset))
                .collect();
            self.reconcile_members();
            self.reconcile_services();
        }
    }

    struct Rng(u64);

    impl Rng {
        fn below(&mut self, bound: usize) -> usize {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            (self.0 % bound as u64) as usize
        }

        fn chance(&mut self, one_in: usize) -> bool {
            self.below(one_in) == 0
        }
    }

    fn part_header(name: &str, split_before: bool, split_after: bool, offset: u64) -> FileHeader {
        let mut header = test_file_header(name, split_before, split_after, Some(offset as u32));
        header.data_offset = offset;
        header.split_before = split_before;
        header.split_after = split_after;
        header
    }

    fn member(vol: usize, offset: u64, name: &str, before: bool, after: bool) -> MemberEntry {
        MemberEntry {
            file_header: part_header(name, before, after, offset),
            is_encrypted: false,
            file_encryption: None,
            rar4_salt: None,
            hash: None,
            redirection: None,
            owner: None,
            segments: vec![DataSegment::new(vol, offset, 8)],
        }
    }

    fn service(vol: usize, offset: u64, name: &str, before: bool, after: bool) -> ServiceEntry {
        ServiceEntry {
            header_offset: offset,
            is_child: false,
            is_inherited: false,
            file_header: part_header(name, before, after, offset),
            is_encrypted: false,
            file_encryption: None,
            rar4_salt: None,
            hash: None,
            comment_crc16: None,
            ntfs_stream_name: None,
            segments: vec![DataSegment::new(vol, offset, 8)],
        }
    }

    type Volume = (Vec<MemberEntry>, Vec<ServiceEntry>);

    /// A set of volumes with members and services split across them,
    /// duplicate names, nameless continuations and stray continuations
    /// that continue nothing.
    fn layout(rng: &mut Rng, count: usize) -> Vec<Volume> {
        const NAMES: [&str; 4] = ["a.bin", "b.bin", "a.bin", "c.bin"];
        const SERVICES: [&str; 4] = ["STM", "ACL", "UOW", "CMT"];
        let mut volumes = Vec::new();
        let mut open_member: Option<String> = None;
        let mut open_service: Option<String> = None;
        let mut unique = 0;
        for vol in 0..count {
            let mut members = Vec::new();
            let mut services = Vec::new();
            let mut offset = 10;
            let last = vol + 1 == count;
            let name_of = |rng: &mut Rng, kept: &str| {
                if rng.chance(2) {
                    String::new()
                } else {
                    kept.to_string()
                }
            };
            if let Some(name) = open_member.take() {
                let after = !last && rng.chance(3);
                members.push(member(vol, offset, &name_of(rng, &name), true, after));
                offset += 100;
                if after {
                    open_member = Some(name);
                }
            } else if vol > 0 && rng.chance(6) {
                members.push(member(vol, offset, &name_of(rng, "stray"), true, false));
                offset += 100;
            }
            if let Some(name) = open_service.take() {
                let after = !last && rng.chance(3);
                services.push(service(vol, offset, &name_of(rng, &name), true, after));
                offset += 100;
                if after {
                    open_service = Some(name);
                }
            }
            if open_member.is_none() {
                for position in 0..rng.below(4) {
                    let name = if rng.chance(2) {
                        NAMES[rng.below(NAMES.len())].to_string()
                    } else {
                        unique += 1;
                        format!("f{unique}.bin")
                    };
                    let tail = position > 0 || members.is_empty();
                    let after = !last && tail && rng.chance(3);
                    members.push(member(vol, offset, &name, false, after));
                    offset += 50;
                    if rng.chance(2) {
                        let service_name = SERVICES[rng.below(SERVICES.len())];
                        services.push(service(vol, offset, service_name, false, false));
                    }
                    offset += 50;
                    if after {
                        open_member = Some(name);
                        break;
                    }
                }
            }
            if open_service.is_none() && !last && rng.chance(3) {
                let name = SERVICES[rng.below(SERVICES.len())].to_string();
                services.push(service(vol, offset, &name, false, true));
                open_service = Some(name);
            }
            volumes.push((members, services));
        }
        volumes
    }

    /// Volumes no archiver writes: several parts per volume that continue
    /// from or into a neighbour, with names drawn from a pool of two and the
    /// empty name, in a header order unrelated to their data offsets. Every
    /// choice the upkeep makes between candidates is exercised here.
    fn chaos(rng: &mut Rng, count: usize) -> Vec<Volume> {
        const NAMES: [&str; 3] = ["", "a.bin", "b.bin"];
        const SERVICES: [&str; 3] = ["", "STM", "ACL"];
        (0..count)
            .map(|vol| {
                let mut offsets: Vec<u64> = (0..8).map(|at| 10 + 10 * at).collect();
                for at in (1..offsets.len()).rev() {
                    offsets.swap(at, rng.below(at + 1));
                }
                let mut offsets = offsets.into_iter();
                let members = (0..rng.below(5))
                    .map(|_| {
                        let name = NAMES[rng.below(NAMES.len())];
                        let before = vol > 0 && rng.chance(2);
                        let after = vol + 1 < count && rng.chance(2);
                        member(vol, offsets.next().unwrap(), name, before, after)
                    })
                    .collect();
                let services = (0..rng.below(4))
                    .map(|_| {
                        let name = SERVICES[rng.below(SERVICES.len())];
                        let before = vol > 0 && rng.chance(2);
                        let after = vol + 1 < count && rng.chance(2);
                        service(vol, offsets.next().unwrap(), name, before, after)
                    })
                    .collect();
                (members, services)
            })
            .collect()
    }

    fn orders(rng: &mut Rng, count: usize) -> Vec<Vec<usize>> {
        let mut orders = vec![(0..count).collect::<Vec<_>>(), (0..count).rev().collect()];
        for _ in 0..6 {
            let mut order: Vec<usize> = (0..count).collect();
            for at in (1..count).rev() {
                order.swap(at, rng.below(at + 1));
            }
            orders.push(order);
        }
        orders
    }

    fn same(what: &str, archive: &RarArchive, reference: &Reference) {
        assert_eq!(
            format!("{:?}", archive.members),
            format!("{:?}", reference.members),
            "{what}: members"
        );
        assert_eq!(
            format!("{:?}", archive.services),
            format!("{:?}", reference.services),
            "{what}: services"
        );
    }

    /// Every arrival order of every seeded set ends each add with the
    /// members, services, order and chains the per-entry upkeep produced;
    /// so does dropping a volume's segments and adding it again.
    #[test]
    fn batch_integrate_matches_per_entry_upkeep() {
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        let mut adds = 0;
        let mut merges = 0;
        for seed in 0..240 {
            let count = 2 + seed % 7;
            let odd = seed % 2 == 1;
            let volumes = if odd {
                chaos(&mut rng, count)
            } else {
                layout(&mut rng, count)
            };
            for order in orders(&mut rng, count) {
                for solid in [false, true] {
                    let what = format!("seed {seed}, chaos {odd}, order {order:?}, solid {solid}");
                    let (first_members, first_services) = volumes[order[0]].clone();
                    let mut archive = empty_archive(first_members.clone());
                    archive.solid_next_index = usize::from(solid);
                    archive.integrate_services(order[0], first_services.clone());
                    let mut reference = Reference::new(first_members, !solid);
                    for entry in first_services {
                        reference.integrate_service(order[0], entry);
                    }
                    same(&what, &archive, &reference);
                    for &vol in &order[1..] {
                        let (members, services) = volumes[vol].clone();
                        archive.integrate_members(vol, members.clone());
                        archive.integrate_services(vol, services.clone());
                        for entry in members {
                            reference.integrate_member(vol, entry);
                        }
                        for entry in services {
                            reference.integrate_service(vol, entry);
                        }
                        same(&format!("{what}, after volume {vol}"), &archive, &reference);
                        adds += 1;
                    }
                    merges +=
                        volumes.iter().map(|(m, _)| m.len()).sum::<usize>() - archive.members.len();
                    let dropped = order[rng.below(count)];
                    archive.remove_volume_segments(dropped);
                    reference.remove_volume(dropped);
                    same(
                        &format!("{what}, without volume {dropped}"),
                        &archive,
                        &reference,
                    );
                    let (members, services) = volumes[dropped].clone();
                    archive.integrate_members(dropped, members.clone());
                    archive.integrate_services(dropped, services.clone());
                    for entry in members {
                        reference.integrate_member(dropped, entry);
                    }
                    for entry in services {
                        reference.integrate_service(dropped, entry);
                    }
                    same(
                        &format!("{what}, volume {dropped} again"),
                        &archive,
                        &reference,
                    );
                }
            }
        }
        assert!(
            adds > 1000 && merges > 1000,
            "non-vacuity: {adds} adds, {merges} merges"
        );
    }

    /// Integrating a volume indexes the catalog once, however many entries
    /// the volume holds, where the old upkeep searched every pair of records
    /// after each entry.
    #[test]
    fn each_add_indexes_the_catalog_once() {
        let per_volume = 64;
        let volumes = 32;
        let mut archive = empty_archive(Vec::new());
        super::super::chains::linker_builds::take();
        let mut expected = 0;
        for vol in 0..volumes {
            expected += archive.members.len() + archive.services.len();
            let members: Vec<MemberEntry> = (0..per_volume)
                .map(|at| {
                    let after = at + 1 == per_volume && vol + 1 < volumes;
                    let before = at == 0 && vol > 0;
                    member(
                        vol,
                        10 + 100 * at as u64,
                        &format!("f{vol}-{at}"),
                        before,
                        after,
                    )
                })
                .collect();
            let services: Vec<ServiceEntry> = (0..per_volume)
                .map(|at| service(vol, 60 + 100 * at as u64, "STM", false, false))
                .collect();
            archive.integrate_members(vol, members);
            archive.integrate_services(vol, services);
        }
        assert_eq!(super::super::chains::linker_builds::take(), expected);
        assert_eq!(archive.members.len(), volumes * (per_volume - 1) + 1);
        assert_eq!(archive.services.len(), volumes * per_volume);
    }

    /// Every service's parent, and every member's services by name, read
    /// from the index after each add, equal what the old walk over every
    /// member's segments found (`service_parent` and `member_services_named`
    /// also assert this on every call under test).
    #[test]
    fn service_parents_match_the_catalog_walk() {
        let mut rng = Rng(0xD1B5_4A32_D192_ED03);
        let mut parented = 0;
        for seed in 0..120 {
            let count = 2 + seed % 6;
            let volumes = if seed % 2 == 1 {
                chaos(&mut rng, count)
            } else {
                layout(&mut rng, count)
            };
            for order in orders(&mut rng, count) {
                let mut archive = empty_archive(Vec::new());
                for &vol in &order {
                    let (members, services) = volumes[vol].clone();
                    archive.integrate_members(vol, members);
                    archive.integrate_services(vol, services);
                    for service in 0..archive.services.len() {
                        let old =
                            archive.rar4_service_parent_member_index(&archive.services[service]);
                        assert_eq!(archive.service_parent(service), old, "seed {seed}");
                        parented += usize::from(old.is_some());
                    }
                    for member in 0..archive.members.len() {
                        for name in ["STM", "ACL", "UOW", ""] {
                            archive.member_services_named(member, name);
                        }
                    }
                }
            }
        }
        assert!(
            parented > 1000,
            "non-vacuity: {parented} services had a parent"
        );
    }

    /// Asking every member for its services reads the catalog once, where
    /// the old walk read every member's segments for every service of every
    /// member asked about.
    #[test]
    fn parent_lookups_read_the_catalog_once() {
        let count = 400;
        let mut archive = empty_archive(Vec::new());
        let members: Vec<MemberEntry> = (0..count)
            .map(|at| member(0, 10 + 100 * at as u64, &format!("f{at}"), false, false))
            .collect();
        let services: Vec<ServiceEntry> = (0..count)
            .map(|at| service(0, 60 + 100 * at as u64, "STM", false, false))
            .collect();
        archive.integrate_members(0, members);
        archive.integrate_services(0, services);
        super::super::chains::parent_builds::take();
        let index = archive.catalog.parents(&archive.members, &archive.services);
        for member in 0..count {
            assert_eq!(index.children(member).collect::<Vec<_>>(), vec![member]);
        }
        for service in 0..count {
            assert_eq!(index.parent(service), Some(service));
        }
        assert_eq!(super::super::chains::parent_builds::take(), 2 * count);
        archive.integrate_services(1, [service(1, 10, "ACL", false, false)]);
        let index = archive.catalog.parents(&archive.members, &archive.services);
        assert_eq!(
            index.parent(count),
            Some(count - 1),
            "rebuilt after the add"
        );
        assert_eq!(super::super::chains::parent_builds::take(), 2 * count + 1);
    }

    /// Name lookups, raw and sanitized, answer the first member with the
    /// name, as the old scans did, and read each member's name once per
    /// change to the catalog rather than once per lookup.
    #[test]
    fn name_lookups_read_the_catalog_once() {
        let names: Vec<String> = (0..300)
            .map(|at| match at % 3 {
                0 => format!("dir/f{at}.bin"),
                1 => format!("dir/../f{}.bin", at - 1),
                _ => "dup.bin".to_string(),
            })
            .collect();
        let members: Vec<MemberEntry> = names
            .iter()
            .enumerate()
            .map(|(at, name)| member(0, 10 + 10 * at as u64, name, false, false))
            .collect();
        let mut archive = empty_archive(members);
        super::super::chains::name_builds::take();
        for name in &names {
            let old = archive
                .members
                .iter()
                .position(|m| m.file_header.name == *name);
            assert_eq!(archive.find_member(name), old);
            assert_eq!(archive.index_for_name(name), old);
            let sanitized =
                crate::path::sanitize_member_path(archive.format, crate::types::HostOs::Unix, name);
            let old = archive.members.iter().position(|m| {
                crate::path::sanitize_member_path(
                    archive.format,
                    m.file_header.host_os,
                    &m.file_header.name,
                ) == sanitized
            });
            assert_eq!(archive.find_member_sanitized(&sanitized), old);
        }
        assert_eq!(archive.find_member("dup.bin"), Some(2));
        assert_eq!(archive.find_member("absent"), None);
        assert_eq!(
            super::super::chains::name_builds::take(),
            2 * names.len(),
            "one raw and one sanitized pass"
        );
        archive.integrate_members(1, [member(1, 10, "late.bin", false, false)]);
        assert_eq!(archive.find_member("late.bin"), Some(names.len()));
        assert!(
            !archive.is_extractable("late.bin"),
            "no reader for volume 1"
        );
        assert_eq!(archive.missing_volumes("late.bin"), vec![1]);
        assert_eq!(super::super::chains::name_builds::take(), names.len() + 1);
    }
}
