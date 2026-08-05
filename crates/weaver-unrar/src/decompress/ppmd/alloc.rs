//! Sub-allocator for PPMd context model nodes.
//!
//! PPMd uses a custom memory allocator (sub-allocator) for its context trie.
//! The arena is split into two regions:
//! - **Text region** (lower ~1/8): stores raw decoded symbols for model building
//! - **Unit region** (upper ~7/8): stores context nodes and state arrays
//!
//! Within the unit region, two allocation stacks grow toward each other:
//! - `lo_unit` grows upward (for state arrays via `alloc_units`)
//! - `hi_unit` grows downward (for contexts via `alloc_context`)
//!
//! Reference: 7-zip Ppmd7.c (public domain), Shkarin's original PPMd code.

use std::cell::Cell;
use std::num::NonZeroU32;

/// Size of one allocation unit in bytes.
pub const UNIT_SIZE: usize = 12;

/// Index-to-units mapping for the free list bins.
static INDEX_TO_UNITS: [u8; 38] = [
    1, 2, 3, 4, 6, 8, 10, 12, 15, 18, 21, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60, 64, 68, 72, 76,
    80, 84, 88, 92, 96, 100, 104, 108, 112, 116, 120, 124, 128,
];

/// Number of distinct free-list bin sizes.
const NUM_INDEXES: usize = 38;

/// Units-to-bin lookup: entry `u - 1` is the first bin whose size is >= `u`.
static UNITS_TO_INDEX: [u8; 128] = {
    let mut table = [0u8; 128];
    let mut i = 0usize;
    let mut k = 0usize;
    while k < 128 {
        if (INDEX_TO_UNITS[i] as usize) < k + 1 {
            i += 1;
        }
        table[k] = i as u8;
        k += 1;
    }
    table
};

const GLUE_COUNT_RESET: u8 = 255;
const HEAP_BASE_BYTES: usize = UNIT_SIZE;

// Temporary intrusive RARPPM_MEM_BLK layout used only while gluing free
// blocks. `insert_node` later overwrites the first four bytes with the normal
// free-list link.
const GLUE_STAMP: usize = 0;
const GLUE_UNITS: usize = 2;
const GLUE_NEXT: usize = 4;
const GLUE_PREV: usize = 8;
const GLUE_FREE_STAMP: u16 = 0xffff;

/// A reference to an allocated unit block in the arena.
/// Stored as a unit index (byte offset = index * UNIT_SIZE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeRef(pub u32);

impl NodeRef {
    pub const NULL: NodeRef = NodeRef(0);

    #[inline]
    pub fn is_null(self) -> bool {
        self.0 == 0
    }

    /// Byte offset into the arena.
    #[inline]
    pub fn offset(self) -> usize {
        (self.0 as usize).saturating_mul(UNIT_SIZE)
    }
}

/// A model-arena range checked against the current text/heap boundaries.
///
/// Tokens are crate-private, contain no pointer or reference, and are used
/// only as short-lived capabilities by the PPMd model. All unchecked memory
/// operations remain confined to `SubAllocator`.
#[derive(Clone, Copy)]
pub(super) struct ValidatedArenaSpan {
    offset: NonZeroU32,
    len: u16,
}

/// Compact form of an already validated arena span when the caller knows its
/// fixed record width. This keeps hot fixed-capacity stacks at one word per
/// entry without weakening the original range validation.
#[derive(Clone, Copy)]
pub(super) struct ValidatedArenaOffset(NonZeroU32);

impl ValidatedArenaSpan {
    #[inline(always)]
    pub(super) const fn offset(self) -> usize {
        self.offset.get() as usize
    }

    #[inline(always)]
    pub(super) const fn len(self) -> usize {
        self.len as usize
    }

    #[inline(always)]
    pub(super) const fn compact(self) -> ValidatedArenaOffset {
        ValidatedArenaOffset(self.offset)
    }

    #[inline(always)]
    pub(super) fn subspan(self, relative: usize, len: usize) -> Self {
        debug_assert!(
            relative
                .checked_add(len)
                .is_some_and(|end| end <= self.len())
        );
        Self {
            offset: NonZeroU32::new(self.offset.get() + relative as u32)
                .expect("validated arena subspan offset is non-zero"),
            len: u16::try_from(len).expect("validated PPMd span length fits u16"),
        }
    }
}

impl ValidatedArenaOffset {
    #[inline(always)]
    pub(super) fn span(self, len: usize) -> ValidatedArenaSpan {
        debug_assert!(len != 0 && u16::try_from(len).is_ok());
        ValidatedArenaSpan {
            offset: self.0,
            len: len as u16,
        }
    }
}

/// A free-list node stored in-place in unused arena blocks.
#[derive(Clone, Copy)]
struct FreeNode {
    next: NodeRef,
}

#[derive(Debug, Clone, Copy)]
struct AllocatorLayout {
    allocated_size: usize,
    units_start_bytes: usize,
    fake_units_start_bytes: usize,
    lo_unit: u32,
    hi_unit: u32,
    total_units: u32,
}

/// Sub-allocator for PPMd.
#[cfg_attr(test, derive(Clone))]
pub struct SubAllocator {
    /// The memory arena.
    arena: Vec<u8>,
    /// Original sub-allocator size requested by the stream.
    sub_allocator_size: usize,
    /// Set when a checked arena access would have gone out of bounds.
    arena_fault: Cell<bool>,
    /// Free lists indexed by bin size.
    free_lists: [NodeRef; NUM_INDEXES],

    // --- Text region (grows upward from byte UNIT_SIZE) ---
    /// Current text write position (byte offset in arena).
    p_text: usize,
    /// Byte offset where the real unit allocation region starts.
    units_start_bytes: usize,
    /// Byte offset where the original algorithm expects unit space to begin.
    /// Text exhaustion is checked against this boundary.
    fake_units_start_bytes: usize,

    // --- Unit allocation region ---
    /// Next available unit from the low end (unit index, grows up).
    lo_unit: u32,
    /// Next available unit from the high end (unit index, grows down).
    hi_unit: u32,
    /// Total number of units in the arena.
    total_units: u32,
    /// Rare-allocation glue countdown.
    glue_count: u8,
}

impl SubAllocator {
    fn layout_for(requested_size: usize) -> AllocatorLayout {
        let requested_size = requested_size.max(UNIT_SIZE * 8);
        let rar_allocated_size = (requested_size / UNIT_SIZE) * UNIT_SIZE + 2 * UNIT_SIZE;
        let allocated_size = HEAP_BASE_BYTES + rar_allocated_size;

        let size2 = UNIT_SIZE * ((requested_size / 8 / UNIT_SIZE) * 7);
        let real_size2 = (size2 / UNIT_SIZE) * UNIT_SIZE;
        let size1 = requested_size.saturating_sub(size2);
        let real_size1 = (size1 / UNIT_SIZE) * UNIT_SIZE + UNIT_SIZE;

        let units_start_bytes = HEAP_BASE_BYTES + real_size1;
        let fake_units_start_bytes = HEAP_BASE_BYTES + size1;
        let lo_unit = (units_start_bytes / UNIT_SIZE) as u32;
        let hi_unit = ((units_start_bytes + real_size2) / UNIT_SIZE) as u32;
        let total_units = (allocated_size / UNIT_SIZE) as u32;

        AllocatorLayout {
            allocated_size,
            units_start_bytes,
            fake_units_start_bytes,
            lo_unit,
            hi_unit,
            total_units,
        }
    }

    /// Create a new sub-allocator with the given arena size in bytes.
    pub fn new(arena_size: usize) -> Self {
        let layout = Self::layout_for(arena_size);

        Self {
            arena: vec![0u8; layout.allocated_size],
            sub_allocator_size: arena_size.max(UNIT_SIZE * 8),
            arena_fault: Cell::new(false),
            free_lists: [NodeRef::NULL; NUM_INDEXES],
            p_text: HEAP_BASE_BYTES,
            units_start_bytes: layout.units_start_bytes,
            fake_units_start_bytes: layout.fake_units_start_bytes,
            lo_unit: layout.lo_unit,
            hi_unit: layout.hi_unit,
            total_units: layout.total_units,
            glue_count: 0,
        }
    }

    /// Reset the allocator, freeing all allocations.
    pub fn reset(&mut self) {
        self.free_lists = [NodeRef::NULL; NUM_INDEXES];
        self.clear_arena_fault();

        let layout = Self::layout_for(self.sub_allocator_size);
        debug_assert_eq!(layout.allocated_size, self.arena.len());
        self.lo_unit = layout.lo_unit;
        self.units_start_bytes = layout.units_start_bytes;
        self.fake_units_start_bytes = layout.fake_units_start_bytes;
        self.hi_unit = layout.hi_unit;
        self.total_units = layout.total_units;
        self.p_text = HEAP_BASE_BYTES;
        self.glue_count = 0;
    }

    #[inline]
    pub fn allocated_size(&self) -> usize {
        self.sub_allocator_size
    }

    // ---- Text region methods ----

    /// Write a byte to the text region and advance the text pointer.
    /// Returns the byte offset where the byte was stored.
    pub fn write_text_byte(&mut self, b: u8) -> usize {
        let pos = self.p_text;
        if pos < self.fake_units_start_bytes {
            self.arena[pos] = b;
            self.p_text += 1;
        }
        pos
    }

    /// Current text write position (byte offset in arena).
    #[inline]
    pub fn text_position(&self) -> usize {
        self.p_text
    }

    /// Decrement text position (undo a write).
    pub fn text_dec(&mut self) {
        if self.p_text > HEAP_BASE_BYTES {
            self.p_text -= 1;
        }
    }

    /// Check if the text region is exhausted.
    #[inline]
    pub fn text_exhausted(&self) -> bool {
        self.p_text >= self.fake_units_start_bytes
    }

    /// The byte offset where the unit region starts.
    /// Successor values below this are text pointers.
    #[inline]
    pub fn units_start_bytes(&self) -> usize {
        self.units_start_bytes
    }

    /// Highest byte offset that can begin an arena object.
    #[inline]
    pub fn heap_end_bytes(&self) -> usize {
        self.total_units.saturating_sub(1) as usize * UNIT_SIZE
    }

    /// Validate a semantic model pointer against pText/HeapEnd guards.
    #[inline(always)]
    pub fn model_offset_valid(&self, off: u32) -> bool {
        let off = off as usize;
        off > self.p_text && off <= self.arena.len().saturating_sub(UNIT_SIZE)
    }

    #[inline(always)]
    pub fn model_range_valid(&self, off: u32, len: usize) -> bool {
        debug_assert!(len >= UNIT_SIZE);
        let off = off as usize;
        let arena_len = self.arena.len();
        off > self.p_text && off <= arena_len.saturating_sub(len)
    }

    #[inline(always)]
    pub(super) fn validated_model_span(&self, off: u32, len: usize) -> Option<ValidatedArenaSpan> {
        if !self.model_range_valid(off, len) {
            return None;
        }
        Some(ValidatedArenaSpan {
            offset: NonZeroU32::new(off)?,
            len: u16::try_from(len).ok()?,
        })
    }

    #[inline(always)]
    pub(super) fn validated_tail_span(&self, off: u32, len: usize) -> Option<ValidatedArenaSpan> {
        let start = off as usize;
        let end = start.checked_add(len)?;
        if start <= self.p_text || end > self.arena.len() {
            return None;
        }
        Some(ValidatedArenaSpan {
            offset: NonZeroU32::new(off)?,
            len: u16::try_from(len).ok()?,
        })
    }

    #[inline(always)]
    pub(super) fn span_read_u8(&self, span: ValidatedArenaSpan, relative: usize) -> u8 {
        debug_assert!(relative < span.len());
        // SAFETY: `validated_model_span` proves the entire span is inside the
        // fixed-size arena. The debug assertion documents the field bound, and
        // no pointer or reference escapes this expression.
        unsafe { *self.arena.as_ptr().add(span.offset() + relative) }
    }

    #[inline(always)]
    pub(super) fn span_read_u16(&self, span: ValidatedArenaSpan, relative: usize) -> u16 {
        debug_assert!(relative.checked_add(2).is_some_and(|end| end <= span.len()));
        // SAFETY: the checked token covers both bytes. PPMd records are packed,
        // so the load is explicitly unaligned and the raw pointer stays local.
        let value = unsafe {
            self.arena
                .as_ptr()
                .add(span.offset() + relative)
                .cast::<u16>()
                .read_unaligned()
        };
        u16::from_le(value)
    }

    #[inline(always)]
    pub(super) fn span_read_u32(&self, span: ValidatedArenaSpan, relative: usize) -> u32 {
        debug_assert!(relative.checked_add(4).is_some_and(|end| end <= span.len()));
        // SAFETY: the checked token covers all four bytes. The unaligned value
        // is copied out immediately; no reference into the arena is produced.
        let value = unsafe {
            self.arena
                .as_ptr()
                .add(span.offset() + relative)
                .cast::<u32>()
                .read_unaligned()
        };
        u32::from_le(value)
    }

    #[inline(always)]
    pub(super) fn span_read_u64(&self, span: ValidatedArenaSpan, relative: usize) -> u64 {
        debug_assert!(relative.checked_add(8).is_some_and(|end| end <= span.len()));
        // SAFETY: the validated token covers all eight bytes. Context records
        // are packed, so the value is copied with an unaligned load and no
        // pointer or reference escapes.
        let value = unsafe {
            self.arena
                .as_ptr()
                .add(span.offset() + relative)
                .cast::<u64>()
                .read_unaligned()
        };
        u64::from_le(value)
    }

    #[inline(always)]
    pub(super) fn span_write_u8(&mut self, span: ValidatedArenaSpan, relative: usize, value: u8) {
        debug_assert!(relative < span.len());
        // SAFETY: the checked token covers this byte and `&mut self` provides
        // exclusive access for the duration of the write.
        unsafe { *self.arena.as_mut_ptr().add(span.offset() + relative) = value };
    }

    #[inline(always)]
    pub(super) fn span_write_u16(&mut self, span: ValidatedArenaSpan, relative: usize, value: u16) {
        debug_assert!(relative.checked_add(2).is_some_and(|end| end <= span.len()));
        // SAFETY: the checked token covers both bytes and the packed field is
        // written unaligned without constructing a reference.
        unsafe {
            self.arena
                .as_mut_ptr()
                .add(span.offset() + relative)
                .cast::<u16>()
                .write_unaligned(value.to_le());
        }
    }

    #[inline(always)]
    pub(super) fn span_write_u32(&mut self, span: ValidatedArenaSpan, relative: usize, value: u32) {
        debug_assert!(relative.checked_add(4).is_some_and(|end| end <= span.len()));
        // SAFETY: the checked token covers all four bytes and the packed field
        // is written unaligned without constructing a reference.
        unsafe {
            self.arena
                .as_mut_ptr()
                .add(span.offset() + relative)
                .cast::<u32>()
                .write_unaligned(value.to_le());
        }
    }

    // ---- Unit allocation ----

    /// Map a requested number of units to a free-list bin index.
    #[inline(always)]
    fn units_to_index(units: usize) -> usize {
        debug_assert!((1..=128).contains(&units));
        UNITS_TO_INDEX[units - 1] as usize
    }

    #[inline]
    fn insert_node(&mut self, node: NodeRef, idx: usize) {
        self.write_free_node(
            node,
            FreeNode {
                next: self.free_lists[idx],
            },
        );
        self.free_lists[idx] = node;
    }

    #[inline]
    fn remove_node(&mut self, idx: usize) -> NodeRef {
        let node = self.free_lists[idx];
        let free_node = self.read_free_node(node);
        self.free_lists[idx] = free_node.next;
        node
    }

    fn split_block(&mut self, node: NodeRef, old_idx: usize, new_idx: usize) {
        let old_units = INDEX_TO_UNITS[old_idx] as usize;
        let new_units = INDEX_TO_UNITS[new_idx] as usize;
        let mut u_diff = old_units.saturating_sub(new_units);
        let mut p = NodeRef(node.0 + new_units as u32);

        let mut rem_idx = Self::units_to_index(u_diff);
        if INDEX_TO_UNITS[rem_idx] as usize != u_diff {
            rem_idx -= 1;
            self.insert_node(p, rem_idx);
            let rem_units = INDEX_TO_UNITS[rem_idx] as usize;
            p = NodeRef(p.0 + rem_units as u32);
            u_diff -= rem_units;
        }

        let tail_idx = Self::units_to_index(u_diff);
        self.insert_node(p, tail_idx);
    }

    #[inline]
    fn glue_next(&self, node: NodeRef) -> NodeRef {
        NodeRef(self.read_u32(node, GLUE_NEXT))
    }

    #[inline]
    fn glue_prev(&self, node: NodeRef) -> NodeRef {
        NodeRef(self.read_u32(node, GLUE_PREV))
    }

    #[inline]
    fn glue_insert_head(&mut self, node: NodeRef, head: &mut NodeRef, tail: &mut NodeRef) {
        let old_head = *head;
        self.write_u32(node, GLUE_NEXT, old_head.0);
        self.write_u32(node, GLUE_PREV, NodeRef::NULL.0);
        if old_head.is_null() {
            *tail = node;
        } else {
            self.write_u32(old_head, GLUE_PREV, node.0);
        }
        *head = node;
    }

    #[inline]
    fn glue_remove(&mut self, node: NodeRef, head: &mut NodeRef, tail: &mut NodeRef) {
        let prev = self.glue_prev(node);
        let next = self.glue_next(node);
        if prev.is_null() {
            *head = next;
        } else {
            self.write_u32(prev, GLUE_NEXT, next.0);
        }
        if next.is_null() {
            *tail = prev;
        } else {
            self.write_u32(next, GLUE_PREV, prev.0);
        }
    }

    /// Merge physically adjacent free blocks. Free lists are LIFO stacks, so
    /// the collection order, merge order, and reinsertion order all determine
    /// which block a later allocation returns — and through that the
    /// fragmentation pattern and the model-restart point, which must stay in
    /// lockstep with the encoder.
    fn glue_free_blocks(&mut self) {
        // Prevent a block ending at LoUnit from seeing a stale free stamp.
        if self.lo_unit != self.hi_unit {
            self.write_byte_at(NodeRef(self.lo_unit).offset(), 0);
        }

        // Overlay a 12-byte doubly linked block on every free block and insert
        // each removal at the sentinel head. A null link represents the
        // sentinel in the offset-based arena.
        let mut head = NodeRef::NULL;
        let mut tail = NodeRef::NULL;
        for idx in 0..NUM_INDEXES {
            let units = INDEX_TO_UNITS[idx] as u16;
            while !self.free_lists[idx].is_null() {
                let node = self.remove_node(idx);
                self.glue_insert_head(node, &mut head, &mut tail);
                self.write_u16(node, GLUE_STAMP, GLUE_FREE_STAMP);
                self.write_u16(node, GLUE_UNITS, units);
            }
        }

        // Walk in reverse collection order and absorb the physical successor
        // whenever it is another member of the temporary free chain.
        let mut node = head;
        while !node.is_null() {
            loop {
                let units = self.read_u16(node, GLUE_UNITS);
                let successor = NodeRef(node.0 + units as u32);
                if self.read_u16(successor, GLUE_STAMP) != GLUE_FREE_STAMP {
                    break;
                }
                let successor_units = self.read_u16(successor, GLUE_UNITS);
                let merged_units = units as u32 + successor_units as u32;
                if merged_units >= 0x10000 {
                    break;
                }
                self.glue_remove(successor, &mut head, &mut tail);
                self.write_u16(node, GLUE_UNITS, merged_units as u16);
            }
            node = self.glue_next(node);
        }

        // Reinsert from the temporary head. Leading 128-unit blocks and the
        // tail-before-head split preserve canonical LIFO allocation order.
        while !head.is_null() {
            let mut node = head;
            self.glue_remove(node, &mut head, &mut tail);
            let mut sz = self.read_u16(node, GLUE_UNITS) as u32;
            while sz > 128 {
                self.insert_node(node, NUM_INDEXES - 1);
                node = NodeRef(node.0 + 128);
                sz -= 128;
            }
            let mut idx = Self::units_to_index(sz as usize);
            if INDEX_TO_UNITS[idx] as u32 != sz {
                idx -= 1;
                let tail = sz - INDEX_TO_UNITS[idx] as u32;
                self.insert_node(NodeRef(node.0 + (sz - tail)), (tail - 1) as usize);
            }
            self.insert_node(node, idx);
        }
    }

    /// Previous allocation/sort implementation retained only as an ordering
    /// oracle for the intrusive glue tests.
    #[cfg(test)]
    fn glue_free_blocks_reference(&mut self) {
        let mut chain: Vec<(NodeRef, u32)> = Vec::new();
        let mut removed: Vec<bool> = Vec::new();
        for (idx, &bin_units) in INDEX_TO_UNITS.iter().enumerate().take(NUM_INDEXES) {
            let units = bin_units as u32;
            while !self.free_lists[idx].is_null() {
                let node = self.remove_node(idx);
                chain.push((node, units));
                removed.push(false);
            }
        }

        let mut by_start: Vec<(u32, usize)> =
            chain.iter().enumerate().map(|(i, e)| (e.0.0, i)).collect();
        by_start.sort_unstable_by_key(|&(start, _)| start);
        for i in (0..chain.len()).rev() {
            if removed[i] {
                continue;
            }
            loop {
                let (node, units) = chain[i];
                let Ok(pos) = by_start.binary_search_by_key(&(node.0 + units), |&(start, _)| start)
                else {
                    break;
                };
                let successor = by_start[pos].1;
                if removed[successor] || units + chain[successor].1 >= 0x10000 {
                    break;
                }
                chain[i].1 += chain[successor].1;
                removed[successor] = true;
            }
        }

        for i in (0..chain.len()).rev() {
            if removed[i] {
                continue;
            }
            let (mut node, mut sz) = chain[i];
            while sz > 128 {
                self.insert_node(node, NUM_INDEXES - 1);
                node = NodeRef(node.0 + 128);
                sz -= 128;
            }
            let mut idx = Self::units_to_index(sz as usize);
            if INDEX_TO_UNITS[idx] as u32 != sz {
                idx -= 1;
                let tail = sz - INDEX_TO_UNITS[idx] as u32;
                self.insert_node(NodeRef(node.0 + (sz - tail)), (tail - 1) as usize);
            }
            self.insert_node(node, idx);
        }
    }

    fn alloc_units_rare(&mut self, idx: usize) -> NodeRef {
        if self.glue_count == 0 {
            self.glue_count = GLUE_COUNT_RESET;
            self.glue_free_blocks();
            if !self.free_lists[idx].is_null() {
                return self.remove_node(idx);
            }
        }

        #[allow(clippy::needless_range_loop)]
        for i in idx + 1..NUM_INDEXES {
            if !self.free_lists[i].is_null() {
                let node = self.remove_node(i);
                self.split_block(node, i, idx);
                return node;
            }
        }

        self.glue_count = self.glue_count.saturating_sub(1);
        self.steal_from_text_region(idx)
    }

    fn steal_from_text_region(&mut self, idx: usize) -> NodeRef {
        let units = INDEX_TO_UNITS[idx] as usize;
        let bytes = units * UNIT_SIZE;
        if self.fake_units_start_bytes.saturating_sub(self.p_text) <= bytes {
            return NodeRef::NULL;
        }

        let Some(fake_start) = self.fake_units_start_bytes.checked_sub(bytes) else {
            return NodeRef::NULL;
        };
        let Some(units_start) = self.units_start_bytes.checked_sub(bytes) else {
            return NodeRef::NULL;
        };
        self.fake_units_start_bytes = fake_start;
        self.units_start_bytes = units_start;
        NodeRef((units_start / UNIT_SIZE) as u32)
    }

    /// Allocate a block of `units` contiguous units from lo_unit or free lists.
    /// Used for state arrays.
    pub fn alloc_units(&mut self, units: usize) -> NodeRef {
        let idx = Self::units_to_index(units);
        let bin_units = INDEX_TO_UNITS[idx] as usize;

        if !self.free_lists[idx].is_null() {
            return self.remove_node(idx);
        }

        if self.lo_unit + bin_units as u32 <= self.hi_unit {
            let node = NodeRef(self.lo_unit);
            self.lo_unit += bin_units as u32;
            return node;
        }

        self.alloc_units_rare(idx)
    }

    /// Allocate exactly 1 unit from lo_unit or free lists.
    pub fn alloc_one(&mut self) -> NodeRef {
        self.alloc_units(1)
    }

    /// Allocate a context node from hi_unit (growing downward).
    pub fn alloc_context(&mut self) -> NodeRef {
        if self.hi_unit > self.lo_unit {
            self.hi_unit -= 1;
            return NodeRef(self.hi_unit);
        }
        // Fallback to free list.
        if !self.free_lists[0].is_null() {
            let node = self.free_lists[0];
            let free_node = self.read_free_node(node);
            self.free_lists[0] = free_node.next;
            return node;
        }
        self.alloc_units_rare(0)
    }

    /// Expand a block from `old_nu` to `old_nu + 1` units.
    /// Returns the (possibly relocated) NodeRef, or NULL if out of memory.
    pub fn expand_units(&mut self, node: NodeRef, old_nu: usize) -> NodeRef {
        let old_idx = Self::units_to_index(old_nu);
        let new_idx = Self::units_to_index(old_nu + 1);
        if old_idx == new_idx {
            return node; // already fits in the same bin
        }
        let new_node = self.alloc_units(old_nu + 1);
        if new_node.is_null() {
            return NodeRef::NULL;
        }
        // Copy data.
        let src = node.offset();
        let dst = new_node.offset();
        let len = old_nu * UNIT_SIZE;
        self.copy_checked(src, dst, len);
        self.insert_node(node, old_idx);
        new_node
    }

    /// Shrink a block from `old_nu` to `new_nu` units.
    /// Returns the (possibly relocated) NodeRef.
    pub fn shrink_units(&mut self, node: NodeRef, old_nu: usize, new_nu: usize) -> NodeRef {
        let old_idx = Self::units_to_index(old_nu);
        let new_idx = Self::units_to_index(new_nu);
        if old_idx == new_idx {
            return node;
        }
        if !self.free_lists[new_idx].is_null() {
            let new_node = self.remove_node(new_idx);
            let src = node.offset();
            let dst = new_node.offset();
            let len = new_nu * UNIT_SIZE;
            self.copy_checked(src, dst, len);
            self.insert_node(node, old_idx);
            return new_node;
        }
        self.split_block(node, old_idx, new_idx);
        node
    }

    /// Free a block of `units` contiguous units back to the appropriate free list.
    pub fn free_units(&mut self, node: NodeRef, units: usize) {
        let idx = Self::units_to_index(units);
        self.insert_node(node, idx);
    }

    /// Free exactly 1 unit.
    pub fn free_one(&mut self, node: NodeRef) {
        self.insert_node(node, 0);
    }

    // ---- Arena access via NodeRef (unit-aligned) ----

    /// Read a u8 at a specific byte offset within a node.
    #[inline]
    pub fn read_u8(&self, node: NodeRef, field_offset: usize) -> u8 {
        self.node_field_offset(node, field_offset, 1)
            .and_then(|off| self.arena.get(off).copied())
            .unwrap_or_else(|| {
                self.mark_arena_fault();
                0
            })
    }

    /// Write a u8 at a specific byte offset within a node.
    #[inline]
    pub fn write_u8(&mut self, node: NodeRef, field_offset: usize, val: u8) {
        let Some(off) = self.node_field_offset(node, field_offset, 1) else {
            self.mark_arena_fault();
            return;
        };
        self.arena[off] = val;
    }

    /// Read a u16 LE at a specific byte offset within a node.
    #[inline]
    pub fn read_u16(&self, node: NodeRef, field_offset: usize) -> u16 {
        let Some(off) = self.node_field_offset(node, field_offset, 2) else {
            self.mark_arena_fault();
            return 0;
        };
        u16::from_le_bytes([self.arena[off], self.arena[off + 1]])
    }

    /// Write a u16 LE at a specific byte offset within a node.
    #[inline]
    pub fn write_u16(&mut self, node: NodeRef, field_offset: usize, val: u16) {
        let Some(off) = self.node_field_offset(node, field_offset, 2) else {
            self.mark_arena_fault();
            return;
        };
        let bytes = val.to_le_bytes();
        self.arena[off] = bytes[0];
        self.arena[off + 1] = bytes[1];
    }

    /// Read a u32 LE at a specific byte offset within a node.
    #[inline]
    pub fn read_u32(&self, node: NodeRef, field_offset: usize) -> u32 {
        let Some(off) = self.node_field_offset(node, field_offset, 4) else {
            self.mark_arena_fault();
            return 0;
        };
        u32::from_le_bytes([
            self.arena[off],
            self.arena[off + 1],
            self.arena[off + 2],
            self.arena[off + 3],
        ])
    }

    /// Write a u32 LE at a specific byte offset within a node.
    #[inline]
    pub fn write_u32(&mut self, node: NodeRef, field_offset: usize, val: u32) {
        let Some(off) = self.node_field_offset(node, field_offset, 4) else {
            self.mark_arena_fault();
            return;
        };
        let bytes = val.to_le_bytes();
        self.arena[off..off + 4].copy_from_slice(&bytes);
    }

    // ---- Direct byte-offset arena access (for state records) ----

    /// Read a byte at an arbitrary byte offset in the arena.
    #[inline]
    pub fn read_byte_at(&self, off: usize) -> u8 {
        self.checked_offset(off, 1)
            .and_then(|off| self.arena.get(off).copied())
            .unwrap_or_else(|| {
                self.mark_arena_fault();
                0
            })
    }

    /// Write a byte at an arbitrary byte offset.
    #[inline]
    pub fn write_byte_at(&mut self, off: usize, val: u8) {
        let Some(off) = self.checked_offset(off, 1) else {
            self.mark_arena_fault();
            return;
        };
        self.arena[off] = val;
    }

    /// Read u16 LE at an arbitrary byte offset.
    #[inline]
    pub fn read_u16_at(&self, off: usize) -> u16 {
        let Some(off) = self.checked_offset(off, 2) else {
            self.mark_arena_fault();
            return 0;
        };
        u16::from_le_bytes([self.arena[off], self.arena[off + 1]])
    }

    /// Write u16 LE at an arbitrary byte offset.
    #[inline]
    pub fn write_u16_at(&mut self, off: usize, val: u16) {
        let Some(off) = self.checked_offset(off, 2) else {
            self.mark_arena_fault();
            return;
        };
        let bytes = val.to_le_bytes();
        self.arena[off] = bytes[0];
        self.arena[off + 1] = bytes[1];
    }

    /// Read u32 LE at an arbitrary byte offset.
    #[inline]
    pub fn read_u32_at(&self, off: usize) -> u32 {
        let Some(off) = self.checked_offset(off, 4) else {
            self.mark_arena_fault();
            return 0;
        };
        u32::from_le_bytes([
            self.arena[off],
            self.arena[off + 1],
            self.arena[off + 2],
            self.arena[off + 3],
        ])
    }

    /// Write u32 LE at an arbitrary byte offset.
    #[inline]
    pub fn write_u32_at(&mut self, off: usize, val: u32) {
        let Some(off) = self.checked_offset(off, 4) else {
            self.mark_arena_fault();
            return;
        };
        self.arena[off..off + 4].copy_from_slice(&val.to_le_bytes());
    }

    /// Copy bytes within the arena.
    pub fn copy_within(&mut self, src: usize, dst: usize, len: usize) {
        self.copy_checked(src, dst, len);
    }

    /// Clear the recorded arena fault.
    pub fn clear_arena_fault(&self) {
        self.arena_fault.set(false);
    }

    /// Return and clear the recorded arena fault.
    pub fn take_arena_fault(&self) -> bool {
        let faulted = self.arena_fault.get();
        self.arena_fault.set(false);
        faulted
    }

    // ---- Internal ----

    fn mark_arena_fault(&self) {
        self.arena_fault.set(true);
    }

    fn checked_offset(&self, off: usize, len: usize) -> Option<usize> {
        off.checked_add(len)
            .filter(|end| *end <= self.arena.len())
            .map(|_| off)
    }

    fn node_field_offset(&self, node: NodeRef, field_offset: usize, len: usize) -> Option<usize> {
        node.offset()
            .checked_add(field_offset)
            .and_then(|off| self.checked_offset(off, len))
    }

    fn copy_checked(&mut self, src: usize, dst: usize, len: usize) {
        if self.checked_offset(src, len).is_none() || self.checked_offset(dst, len).is_none() {
            self.mark_arena_fault();
            return;
        }
        self.arena.copy_within(src..src + len, dst);
    }

    fn read_free_node(&self, node: NodeRef) -> FreeNode {
        FreeNode {
            next: NodeRef(self.read_u32(node, 0)),
        }
    }

    fn write_free_node(&mut self, node: NodeRef, free_node: FreeNode) {
        self.write_u32(node, 0, free_node.next.0);
    }

    /// Check if the allocator has available memory.
    pub fn has_memory(&self) -> bool {
        self.lo_unit < self.hi_unit
            || self.free_lists.iter().any(|n| !n.is_null())
            || self.fake_units_start_bytes.saturating_sub(self.p_text) > UNIT_SIZE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rar_layout_values(requested_size: usize) -> (usize, usize, usize, usize) {
        let allocated_size = (requested_size / UNIT_SIZE) * UNIT_SIZE + 2 * UNIT_SIZE;
        let size2 = UNIT_SIZE * ((requested_size / 8 / UNIT_SIZE) * 7);
        let size1 = requested_size - size2;
        let real_size1 = (size1 / UNIT_SIZE) * UNIT_SIZE + UNIT_SIZE;
        let real_size2 = (size2 / UNIT_SIZE) * UNIT_SIZE;
        (allocated_size, size1, real_size1, real_size2)
    }

    #[test]
    fn allocator_layout_matches_rar_suballocator_formula() {
        for mib in [1usize, 2, 4, 8, 17] {
            let requested_size = mib * 1024 * 1024;
            let layout = SubAllocator::layout_for(requested_size);
            let (allocated_size, size1, real_size1, real_size2) = rar_layout_values(requested_size);

            assert_eq!(layout.allocated_size, HEAP_BASE_BYTES + allocated_size);
            assert_eq!(layout.fake_units_start_bytes, HEAP_BASE_BYTES + size1);
            assert_eq!(layout.units_start_bytes, HEAP_BASE_BYTES + real_size1);
            assert_eq!(
                layout.lo_unit as usize * UNIT_SIZE,
                HEAP_BASE_BYTES + real_size1
            );
            assert_eq!(
                layout.hi_unit as usize * UNIT_SIZE,
                HEAP_BASE_BYTES + real_size1 + real_size2
            );
            assert_eq!(
                layout.total_units as usize * UNIT_SIZE,
                HEAP_BASE_BYTES + allocated_size
            );
            assert_eq!(layout.fake_units_start_bytes - HEAP_BASE_BYTES, size1);
            assert!(layout.fake_units_start_bytes < layout.units_start_bytes);
        }
    }

    #[test]
    fn text_region_preserves_full_rar_size1_capacity() {
        let requested_size = 4 * 1024 * 1024;
        let (_, size1, _, _) = rar_layout_values(requested_size);
        let alloc = SubAllocator::new(requested_size);

        assert_eq!(alloc.text_position(), HEAP_BASE_BYTES);
        assert_eq!(alloc.fake_units_start_bytes - alloc.text_position(), size1);
    }

    #[test]
    fn text_exhaustion_occurs_after_full_rar_text_capacity() {
        let requested_size = 96;
        let (_, size1, _, _) = rar_layout_values(requested_size);
        let mut alloc = SubAllocator::new(requested_size);

        for _ in 0..size1 {
            assert!(!alloc.text_exhausted());
            alloc.write_text_byte(0x41);
        }

        assert_eq!(alloc.text_position(), HEAP_BASE_BYTES + size1);
        assert!(alloc.text_exhausted());
    }

    #[test]
    fn reset_restores_rar_layout_boundaries() {
        let requested_size = 4 * 1024 * 1024;
        let mut alloc = SubAllocator::new(requested_size);
        let original_fake_start = alloc.fake_units_start_bytes;
        let original_units_start = alloc.units_start_bytes;

        alloc.lo_unit = alloc.hi_unit;
        alloc.fake_units_start_bytes -= UNIT_SIZE;
        alloc.units_start_bytes -= UNIT_SIZE;
        alloc.reset();

        assert_eq!(alloc.fake_units_start_bytes, original_fake_start);
        assert_eq!(alloc.units_start_bytes, original_units_start);
        assert!(alloc.fake_units_start_bytes < alloc.units_start_bytes);
    }

    #[test]
    fn test_alloc_one() {
        let mut alloc = SubAllocator::new(4096);
        let n = alloc.alloc_one();
        assert!(!n.is_null());
    }

    #[test]
    fn test_alloc_free_reuse() {
        let mut alloc = SubAllocator::new(4096);
        let n1 = alloc.alloc_one();
        alloc.free_one(n1);
        let n2 = alloc.alloc_one();
        assert_eq!(n1, n2);
    }

    #[test]
    fn test_alloc_multiple_units() {
        let mut alloc = SubAllocator::new(4096);
        let n = alloc.alloc_units(4);
        assert!(!n.is_null());
    }

    #[test]
    fn test_alloc_context() {
        let mut alloc = SubAllocator::new(4096);
        let c1 = alloc.alloc_context();
        let c2 = alloc.alloc_context();
        assert!(!c1.is_null());
        assert!(!c2.is_null());
        // Contexts are allocated from hi_unit (descending).
        assert!(c1.0 > c2.0);
    }

    #[test]
    fn test_read_write() {
        let mut alloc = SubAllocator::new(4096);
        let n = alloc.alloc_one();
        alloc.write_u8(n, 0, 0xAA);
        alloc.write_u16(n, 2, 0xBBCC);
        alloc.write_u32(n, 4, 0xDDEEFF00);
        assert_eq!(alloc.read_u8(n, 0), 0xAA);
        assert_eq!(alloc.read_u16(n, 2), 0xBBCC);
        assert_eq!(alloc.read_u32(n, 4), 0xDDEEFF00);
    }

    #[test]
    fn test_text_region() {
        let mut alloc = SubAllocator::new(4096);
        let pos = alloc.write_text_byte(0x42);
        assert_eq!(pos, HEAP_BASE_BYTES); // first text byte after NULL unit
        assert_eq!(alloc.read_byte_at(pos), 0x42);
        assert_eq!(alloc.text_position(), HEAP_BASE_BYTES + 1);
    }

    #[test]
    fn test_expand_units() {
        let mut alloc = SubAllocator::new(4096);
        let n = alloc.alloc_units(1);
        alloc.write_u32(n, 0, 0xDEADBEEF);
        let expanded = alloc.expand_units(n, 1);
        assert!(!expanded.is_null());
        // Data should be preserved.
        assert_eq!(alloc.read_u32(expanded, 0), 0xDEADBEEF);
    }

    #[test]
    fn test_shrink_units() {
        let mut alloc = SubAllocator::new(4096);
        let n = alloc.alloc_units(4);
        alloc.write_u32(n, 0, 0xCAFEBABE);
        let shrunk = alloc.shrink_units(n, 4, 1);
        assert!(!shrunk.is_null());
        assert_eq!(alloc.read_u32(shrunk, 0), 0xCAFEBABE);
    }

    #[test]
    fn test_reset() {
        let mut alloc = SubAllocator::new(4096);
        let _n1 = alloc.alloc_one();
        let _n2 = alloc.alloc_one();
        alloc.reset();
        assert!(alloc.has_memory());
    }

    #[test]
    fn reset_reuses_arena_without_clearing_payload_bytes() {
        let mut alloc = SubAllocator::new(4096);
        let node = alloc.alloc_one();
        alloc.write_u32(node, 0, 0xDEAD_BEEF);

        alloc.reset();
        let reused = alloc.alloc_one();

        assert_eq!(reused, node);
        assert_eq!(alloc.read_u32(reused, 0), 0xDEAD_BEEF);
    }

    #[test]
    fn test_direct_byte_access() {
        let mut alloc = SubAllocator::new(4096);
        let n = alloc.alloc_one();
        let off = n.offset();
        alloc.write_byte_at(off + 3, 0x77);
        assert_eq!(alloc.read_byte_at(off + 3), 0x77);
        alloc.write_u32_at(off + 4, 0x12345678);
        assert_eq!(alloc.read_u32_at(off + 4), 0x12345678);
    }

    #[test]
    fn adjacent_freed_blocks_are_glued_for_larger_allocation() {
        let mut alloc = SubAllocator::new(4096);
        let first = alloc.alloc_units(1);
        let second = alloc.alloc_units(1);
        assert_eq!(second.0, first.0 + 1);

        alloc.free_units(first, 1);
        alloc.free_units(second, 1);
        alloc.lo_unit = alloc.hi_unit;
        alloc.glue_count = 0;

        let merged = alloc.alloc_units(2);

        assert_eq!(merged, first);
    }

    fn free_list_snapshot(alloc: &SubAllocator) -> Vec<Vec<u32>> {
        alloc
            .free_lists
            .iter()
            .map(|&head| {
                let mut nodes = Vec::new();
                let mut node = head;
                while !node.is_null() {
                    assert!(nodes.len() < 4096, "free-list cycle at bin head {head:?}");
                    nodes.push(node.0);
                    node = alloc.read_free_node(node).next;
                }
                nodes
            })
            .collect()
    }

    #[test]
    fn intrusive_glue_matches_reference_order_for_every_size_class() {
        for seed in [1u64, 0x5eed, 0xdead_beef, u32::MAX as u64] {
            let mut alloc = SubAllocator::new(256 * 1024);
            let blocks = INDEX_TO_UNITS
                .iter()
                .map(|&units| (alloc.alloc_units(units as usize), units as usize))
                .collect::<Vec<_>>();
            assert!(blocks.iter().all(|(node, _)| !node.is_null()));

            let mut order = (0..blocks.len()).collect::<Vec<_>>();
            let mut state = seed;
            for index in (1..order.len()).rev() {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                order.swap(index, state as usize % (index + 1));
            }
            for index in order {
                let (node, units) = blocks[index];
                alloc.free_units(node, units);
            }

            let mut reference = alloc.clone();
            alloc.glue_free_blocks();
            reference.glue_free_blocks_reference();

            assert_eq!(
                free_list_snapshot(&alloc),
                free_list_snapshot(&reference),
                "free-list ordering diverged for seed {seed:#x}"
            );
            assert!(!alloc.take_arena_fault());
        }
    }

    #[test]
    fn rare_allocation_escalates_to_larger_bin_and_splits() {
        let mut alloc = SubAllocator::new(4096);
        let block = alloc.alloc_units(4);
        alloc.free_units(block, 4);
        alloc.lo_unit = alloc.hi_unit;
        alloc.glue_count = 1;

        let head = alloc.alloc_units(1);
        let tail = alloc.alloc_units(3);

        assert_eq!(head, block);
        assert_eq!(tail.0, block.0 + 1);
    }

    #[test]
    fn rare_allocation_steals_from_text_region_before_null() {
        let mut alloc = SubAllocator::new(4096);
        let old_units_start = alloc.units_start_bytes;
        let old_fake_start = alloc.fake_units_start_bytes;
        alloc.lo_unit = alloc.hi_unit;
        alloc.glue_count = 1;

        let stolen = alloc.alloc_units(1);

        assert!(!stolen.is_null());
        assert_eq!(stolen.offset(), old_units_start - UNIT_SIZE);
        assert_eq!(alloc.units_start_bytes, old_units_start - UNIT_SIZE);
        assert_eq!(alloc.fake_units_start_bytes, old_fake_start - UNIT_SIZE);
    }

    #[test]
    fn rare_allocation_returns_null_after_glue_escalation_and_steal_fail() {
        let mut alloc = SubAllocator::new(4096);
        alloc.lo_unit = alloc.hi_unit;
        alloc.glue_count = 1;
        alloc.p_text = alloc.fake_units_start_bytes - UNIT_SIZE;

        let node = alloc.alloc_units(1);

        assert!(node.is_null());
    }

    #[test]
    fn out_of_bounds_arena_access_records_fault_instead_of_panicking() {
        let mut alloc = SubAllocator::new(96);
        let past_end = 10_000;

        assert_eq!(alloc.read_byte_at(past_end), 0);
        assert!(alloc.take_arena_fault());

        alloc.write_u32_at(past_end, 0x12345678);
        assert!(alloc.take_arena_fault());

        alloc.copy_within(past_end, 0, 4);
        assert!(alloc.take_arena_fault());

        let bogus_node = NodeRef(u32::MAX);
        assert_eq!(alloc.read_u32(bogus_node, 0), 0);
        assert!(alloc.take_arena_fault());
    }
}
