//! Retained Data-packet admission against authenticated extent fingerprints.

use std::collections::BTreeMap;

use super::Par3RepairSession;
use crate::FingerprintHasher;
use crate::ingest::{PayloadKind, PayloadRef};
use crate::layout::{BlockLayout, ExtentKind};
use crate::runtime::{EngineError, EngineResult, ExecutionOptions, Reservation};

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
            let reservation = self.options.memory.reserve(ADMISSION_BYTES)?;
            validate_extents(layout, index, payload, &self.options)?;
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
        self.data_dirty = false;
        Ok(())
    }
}

fn validate_extents(
    layout: &BlockLayout,
    index: u64,
    payload: &PayloadRef,
    options: &ExecutionOptions,
) -> EngineResult<()> {
    payload.validate(options)?;
    let Some(locations) = layout.blocks.get(&index) else {
        return Err(EngineError::InvalidState(
            "Data packet has no protected extents",
        ));
    };
    let size = options.stripe_bytes.min(64 << 10);
    let bookkeeping = locations
        .len()
        .checked_mul(128)
        .and_then(|n| n.checked_add(size))
        .ok_or(EngineError::ResourceLimit("Data extent validation"))?;
    let _memory = options.memory.reserve(bookkeeping)?;
    let mut expected = BTreeMap::new();
    for location in locations {
        let extent = &layout.files[location.file].extents[location.extent];
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
    let mut buffer = vec![0; size];
    for ((offset, length), expected) in expected {
        let mut hash = FingerprintHasher::new();
        let mut at = 0;
        while at < length {
            options.cancel.check()?;
            let take = (length - at).min(size as u64) as usize;
            buffer[..take].fill(0);
            payload.read_at(offset + at, &mut buffer[..take])?;
            hash.update(&buffer[..take]);
            at += take as u64;
        }
        if hash.finalize() != expected {
            return Err(EngineError::InvalidState(
                "Data packet contradicts authenticated extent fingerprint",
            ));
        }
    }
    Ok(())
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
    let _memory = options.memory.reserve(size * 2)?;
    let mut a = vec![0; size];
    let mut b = vec![0; size];
    let mut at = 0;
    while at < block_size {
        options.cancel.check()?;
        let take = (block_size - at).min(size as u64) as usize;
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
