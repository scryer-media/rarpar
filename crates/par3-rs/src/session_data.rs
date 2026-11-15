//! Retained Data-packet admission against authenticated extent fingerprints.

use std::collections::BTreeMap;

use super::Par3RepairSession;
use crate::FingerprintHasher;
use crate::ingest::{PayloadKind, PayloadRef};
use crate::layout::{BlockLayout, ExtentKind};
use crate::runtime::{EngineError, EngineResult, ExecutionOptions, MemoryCategory, Reservation};

pub(super) const ADMISSION_BYTES: usize = 1024;

pub(super) struct DataAdmission {
    payload: PayloadRef,
    _reservation: Reservation,
}

impl Par3RepairSession {
    pub(super) fn refresh_data(&mut self) -> EngineResult<()> {
        if !self.data_dirty {
            return Ok(());
        }
        let Some(layout) = &self.layout else {
            return Ok(());
        };
        self.data_blocks.clear();
        self.data_checked.retain(|hash, checked| {
            self.input
                .packet(hash)
                .and_then(|packet| packet.payload())
                .is_some_and(|payload| payload.same_binding(&checked.payload))
        });
        for checked in self.data_checked.values() {
            let PayloadKind::Data { index } = checked.payload.kind() else {
                unreachable!("Data admission")
            };
            self.data_blocks
                .entry(index)
                .or_insert_with(|| checked.payload.clone());
        }
        for payload in self.input.payloads() {
            let PayloadKind::Data { index } = payload.kind() else {
                continue;
            };
            if self.data_checked.contains_key(&payload.packet_hash()) {
                continue;
            }
            self.options.cancel.check()?;
            if index >= layout.block_count || payload.len() > layout.block_size {
                return Err(EngineError::InvalidState(
                    "Data packet exceeds authenticated block layout",
                ));
            }
            self.admit_retained(ADMISSION_BYTES)?;
            let reservation = self
                .options
                .memory
                .reserve_as(MemoryCategory::Caches, ADMISSION_BYTES)?;
            if !validate_extents(&self.input, layout, index, payload, &self.options)? {
                // Keep the payload pending until checksum metadata arrives.
                continue;
            }
            if let Some(existing) = self.data_blocks.get(&index) {
                compare_aliases(existing, payload, layout.block_size, &self.options)?;
            }
            self.data_blocks
                .entry(index)
                .or_insert_with(|| payload.clone());
            self.data_checked.insert(
                payload.packet_hash(),
                DataAdmission {
                    payload: payload.clone(),
                    _reservation: reservation,
                },
            );
            self.diagnostics.data_validations += 1;
        }
        self.report_cache(self.data_checked.len());
        self.data_dirty = false;
        Ok(())
    }
}

fn validate_extents(
    set: &crate::ingest::IncrementalSet,
    layout: &BlockLayout,
    index: u64,
    payload: &PayloadRef,
    options: &ExecutionOptions,
) -> EngineResult<bool> {
    set.validate_payload(payload, options)?;
    let Some(locations) = layout.locations(index) else {
        return Err(EngineError::InvalidState(
            "Data packet has no protected extents",
        ));
    };
    let size = options.stripe_bytes.min(64 << 10);
    let bookkeeping = locations
        .len()
        .checked_mul(256)
        .and_then(|n| n.checked_add(size))
        .ok_or(EngineError::resource_limit("Data extent validation"))?;
    let _memory = options
        .memory
        .reserve_as(MemoryCategory::SourceScratch, bookkeeping)?;
    let mut expected = BTreeMap::new();
    for location in locations.iter() {
        let extent = layout.files[location.file]
            .extents
            .get(location.extent)
            .ok_or(EngineError::InvalidState("unknown Data extent"))?;
        if let ExtentKind::Block {
            offset,
            fingerprint: Some(hash),
            ..
        } = extent.kind
        {
            let length = extent.range.end - extent.range.start;
            if expected
                .insert((offset, length), hash)
                .is_some_and(|previous| previous != hash)
            {
                return Err(EngineError::InvalidState(
                    "contradictory Data extent fingerprints",
                ));
            }
        }
    }
    let authenticated = super::union(
        expected
            .keys()
            .map(|&(offset, length)| offset..offset + length)
            .collect(),
    );
    for location in locations.iter() {
        let extents = &layout.files[location.file].extents;
        let Some(extent) = extents.range(location.extent) else {
            continue;
        };
        if let Some((_, offset)) = extents.block_at(location.extent) {
            let end = offset + extent.end - extent.start;
            if !authenticated
                .iter()
                .any(|range| range.start <= offset && range.end >= end)
            {
                return Ok(false);
            }
        }
    }
    let mut buffer = vec![0; size];
    for ((offset, length), expected) in expected {
        let mut hash = FingerprintHasher::new();
        // Only the stored bytes are read. What a trimmed payload leaves out is
        // zeros, and how many is the layout's word, not the carrier's: a Start
        // packet may declare a block near `u64::MAX` over an empty Data
        // packet. That padding is bounded as `DataPacket::matches_checksum`
        // bounds it, and charged as scanning work, since no carrier byte
        // stands behind it.
        let stored = payload.len().saturating_sub(offset).min(length);
        let mut at = 0;
        while at < stored {
            options.cancel.check()?;
            let take = (stored - at).min(size as u64) as usize;
            if payload.read_at(offset + at, &mut buffer[..take])? != take {
                return Err(EngineError::InvalidState(
                    "Data packet read came back short",
                ));
            }
            hash.update(&buffer[..take]);
            at += take as u64;
        }
        let mut padding = length - stored;
        if padding > crate::ScanLimits::DEFAULT_MAX_PACKET_LEN {
            return Err(EngineError::resource_limit("Data extent padding"));
        }
        while padding > 0 {
            options.cancel.check()?;
            let take = padding.min(size as u64);
            options.scan_work.charge(take as usize)?;
            hash.update_zeros(take);
            padding -= take;
        }
        if hash.finalize() != expected {
            return Err(EngineError::InvalidState(
                "Data packet contradicts authenticated extent fingerprint",
            ));
        }
    }
    Ok(true)
}

// Compare logical bytes directly. Packed tail blocks acquire no invented
// verification checksum; only their individual authenticated tails are hashed.
fn compare_aliases(
    first: &PayloadRef,
    second: &PayloadRef,
    block_size: u64,
    options: &ExecutionOptions,
) -> EngineResult<()> {
    let size = options.stripe_bytes.min(64 << 10);
    let _memory = options
        .memory
        .reserve_as(MemoryCategory::SourceScratch, size * 2)?;
    let mut a = vec![0; size];
    let mut b = vec![0; size];
    // Past the longer payload both blocks are zero padding, so there is
    // nothing left that could differ. The walk follows the stored bytes, not
    // the declared block size.
    let end = first.len().max(second.len()).min(block_size);
    let mut at = 0;
    while at < end {
        options.cancel.check()?;
        let take = (end - at).min(size as u64) as usize;
        a[..take].fill(0);
        b[..take].fill(0);
        first.read_at(at, &mut a[..take])?;
        second.read_at(at, &mut b[..take])?;
        if a[..take] != b[..take] {
            return Err(EngineError::InvalidState(
                "contradictory authenticated Data packets",
            ));
        }
        at += take as u64;
    }
    Ok(())
}
