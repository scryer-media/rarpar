//! PPMd variant H context model.
//!
//! Full implementation of the PPMd variant H algorithm including proper context
//! model updates (UpdateModel, CreateSuccessors, rescale).
//!
//! Reference: 7-zip Ppmd7.c (public domain), Shkarin's original PPMd (public domain).

use super::alloc::{NodeRef, SubAllocator, UNIT_SIZE, ValidatedArenaSpan};
use super::range::RangeCode;
#[cfg(test)]
use super::range::RangeDecoder;
use super::see::SeeTable;
use crate::error::{RarError, RarResult};
#[cfg(feature = "ppmd-debug")]
use std::sync::OnceLock;

#[cfg(feature = "ppmd-debug")]
fn ppmd_debug_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("WEAVER_RAR4_DEBUG_PPM").is_some())
}

// --- Constants ---

const MAX_ORDER: usize = 64;
const MAX_FREQ: u8 = 124;
const BIN_SCALE: u32 = 1 << 14; // 16384
const INTERVAL: u16 = 1 << 7; // 128

const INIT_BIN_ESC: [u16; 8] = [
    0x3CDD, 0x1F3F, 0x59BF, 0x48F3, 0x64A1, 0x5ABC, 0x6632, 0x6051,
];

const EXP_ESCAPE: [u8; 16] = [25, 14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2];

// --- Context layout (12 bytes per context node) ---
// Contexts are allocated as single units from the arena.

/// Byte offset of suffix context ref (u32, stored as byte offset in arena).
const CTX_SUFFIX: usize = 0;
/// Byte offset of NumStats (u16). NumStats = number of symbols (1 = binary).
const CTX_NUM_STATS: usize = 4;
// Union at offset 6 (6 bytes):
//   NumStats == 1: OneState inline — symbol(1) + freq(1) + successor(4)
//   NumStats > 1: SummFreq(2) + Stats pointer(4)
const CTX_SUMM_FREQ: usize = 6;
const CTX_STATS: usize = 8;
// OneState aliases (same offsets, different interpretation):
const CTX_ONE_SYM: usize = 6;
const CTX_ONE_FREQ: usize = 7;
const CTX_ONE_SUCC: usize = 8;

// --- State layout (6 bytes, packed 2 per 12-byte unit) ---
const STATE_SIZE: usize = 6;
const STATE_SYM: usize = 0;
const STATE_FREQ: usize = 1;
const STATE_SUCC: usize = 2;

#[inline(always)]
const fn pack_unmasked_state(index: usize, head: u16) -> u32 {
    debug_assert!(index <= u8::MAX as usize);
    index as u32 | ((head as u32) << 8)
}

#[inline(always)]
const fn unmasked_state_index(packed: u32) -> usize {
    (packed as u8) as usize
}

#[inline(always)]
const fn unmasked_state_symbol(packed: u32) -> u8 {
    (packed >> 8) as u8
}

#[inline(always)]
const fn unmasked_state_frequency(packed: u32) -> u8 {
    (packed >> 16) as u8
}

/// PPMd variant H model.
pub struct Model {
    alloc: SubAllocator,
    see: SeeTable,
    max_order: usize,

    // Context tracking (all stored as byte offsets in arena, 0 = NULL).
    min_context: u32,
    max_context: u32,

    // Found state (byte offset of the matched state, 0 = not found).
    found_state: u32,
    // Symbol from the last matched state. This avoids revalidating and
    // rereading FoundState on the next binary or escape decision.
    found_symbol: u8,

    order_fall: i32,

    // Binary summation table [freq-1][combined_index].
    bin_summ: [[u16; 64]; 128],

    // Lookup tables.
    ns2_indx: [u8; 256],
    ns2_bs_indx: [u8; 256],
    hb2_flag: [u8; 256],

    // Mask and counters.
    char_mask: [u8; 256],
    esc_count: u8,
    num_masked: usize,

    // State.
    prev_success: u8,
    hi_bits_flag: u8,
    init_esc: u8,
    run_length: i32,
    init_rl: i32,
    // Reused packed escape-decode state index/head values. Keeping this on the model avoids
    // clearing a padded 2 KiB `(u32, u8)` array on every masked-context walk.
    unmasked_scratch: [u32; 256],
    #[cfg(feature = "ppmd-debug")]
    debug_output_index: u64,
    model_fault: bool,
    // Cached WEAVER_RAR4_DEBUG_PPM flag; the OnceLock lookup is too hot for
    // the per-symbol decode paths.
    #[cfg(feature = "ppmd-debug")]
    debug: bool,
}

// --- Helpers for converting between NodeRef and byte offsets ---

#[inline]
fn ref_to_off(node: NodeRef) -> u32 {
    node.offset() as u32
}

#[inline]
fn off_to_ref(off: u32) -> NodeRef {
    NodeRef(off / UNIT_SIZE as u32)
}

impl Model {
    #[inline(always)]
    fn debug_enabled(&self) -> bool {
        #[cfg(feature = "ppmd-debug")]
        {
            return self.debug;
        }
        #[cfg(not(feature = "ppmd-debug"))]
        {
            false
        }
    }

    #[inline(always)]
    fn debug_index(&self) -> u64 {
        #[cfg(feature = "ppmd-debug")]
        {
            return self.debug_output_index;
        }
        #[cfg(not(feature = "ppmd-debug"))]
        {
            0
        }
    }

    #[inline(always)]
    fn advance_debug_index(&mut self) {
        #[cfg(feature = "ppmd-debug")]
        {
            self.debug_output_index += 1;
        }
    }

    /// Create a new PPMd model.
    pub fn new(max_order: usize, alloc_size: usize) -> Self {
        let max_order = max_order.clamp(2, MAX_ORDER);
        let mut model = Self {
            alloc: SubAllocator::new(alloc_size),
            see: SeeTable::new(),
            max_order,
            min_context: 0,
            max_context: 0,
            found_state: 0,
            found_symbol: 0,
            order_fall: 0,
            bin_summ: [[0u16; 64]; 128],
            ns2_indx: [0u8; 256],
            ns2_bs_indx: [0u8; 256],
            hb2_flag: [0u8; 256],
            char_mask: [0u8; 256],
            esc_count: 0,
            num_masked: 0,
            prev_success: 0,
            hi_bits_flag: 0,
            init_esc: 0,
            run_length: 0,
            init_rl: -(max_order.min(12) as i32) - 1,
            unmasked_scratch: [0; 256],
            #[cfg(feature = "ppmd-debug")]
            debug_output_index: 0,
            model_fault: false,
            #[cfg(feature = "ppmd-debug")]
            debug: ppmd_debug_enabled(),
        };
        model.build_lookup_tables();
        model.restart();
        model
    }

    fn build_lookup_tables(&mut self) {
        // NS2BSIndx
        self.ns2_bs_indx[0] = 0;
        self.ns2_bs_indx[1] = 2;
        for i in 2..11 {
            self.ns2_bs_indx[i] = 4;
        }
        for i in 11..256 {
            self.ns2_bs_indx[i] = 6;
        }

        // NS2Indx: 0,1,2 then groups of increasing size
        self.ns2_indx[0] = 0;
        self.ns2_indx[1] = 1;
        self.ns2_indx[2] = 2;
        let mut m = 3u8;
        let mut step = 1usize;
        let mut k = step;
        for i in 3..256 {
            self.ns2_indx[i] = m;
            k -= 1;
            if k == 0 {
                step += 1;
                k = step;
                m = m.saturating_add(1);
            }
        }

        // HB2Flag
        for i in 0..0x40 {
            self.hb2_flag[i] = 0;
        }
        for i in 0x40..256 {
            self.hb2_flag[i] = 0x08;
        }
    }

    /// Reset the model to initial state.
    pub fn restart(&mut self) {
        self.alloc.reset();
        self.see = SeeTable::new();
        self.char_mask = [0; 256];
        self.esc_count = 1;
        self.prev_success = 0;
        self.run_length = self.init_rl;
        self.order_fall = self.max_order as i32;
        #[cfg(feature = "ppmd-debug")]
        {
            self.debug_output_index = 0;
        }

        // Initialize BinSumm.
        for i in 0..128u16 {
            for (k, &esc) in INIT_BIN_ESC.iter().enumerate() {
                let val = BIN_SCALE as u16 - esc / (i + 2);
                for m in (0..64).step_by(8) {
                    self.bin_summ[i as usize][k + m] = val;
                }
            }
        }

        // Allocate root context.
        let root = self.alloc.alloc_context();
        if root.is_null() {
            return;
        }
        let root_off = ref_to_off(root);
        self.min_context = root_off;
        self.max_context = root_off;

        // Root has 256 symbols.
        self.alloc.write_u32(root, CTX_SUFFIX, 0); // no suffix
        self.alloc.write_u16(root, CTX_NUM_STATS, 256);
        self.alloc.write_u16(root, CTX_SUMM_FREQ, 257); // 256 + 1

        // Allocate states array (256 states, 2 per unit = 128 units).
        let states = self.alloc.alloc_units(128);
        if states.is_null() {
            return;
        }
        let states_off = ref_to_off(states);
        self.alloc.write_u32(root, CTX_STATS, states_off);

        // Initialize 256 states: symbol=i, freq=1, successor=0.
        for i in 0..256u32 {
            let off = states_off as usize + i as usize * STATE_SIZE;
            self.alloc.write_byte_at(off + STATE_SYM, i as u8);
            self.alloc.write_byte_at(off + STATE_FREQ, 1);
            self.alloc.write_u32_at(off + STATE_SUCC, 0);
        }

        // Set FoundState to first state (so found_state_symbol works).
        self.found_state = states_off;
        self.found_symbol = 0;
    }

    // --- Context field accessors ---

    #[inline(always)]
    fn validated_context(&self, ctx: u32) -> Option<ValidatedArenaSpan> {
        self.alloc.validated_model_span(ctx, UNIT_SIZE)
    }

    #[inline(always)]
    fn validated_states(&self, stats: u32, count: usize) -> Option<ValidatedArenaSpan> {
        if !(1..=256).contains(&count) {
            return None;
        }
        self.alloc.validated_model_span(stats, count * STATE_SIZE)
    }

    #[inline(always)]
    fn validated_state(&self, state: u32) -> Option<ValidatedArenaSpan> {
        self.alloc.validated_model_span(state, STATE_SIZE)
    }

    /// Packed context bytes 0..8: suffix, NumStats, and the first two union
    /// bytes (SummFreq or OneState symbol/frequency).
    #[inline(always)]
    fn span_context_head(&self, span: ValidatedArenaSpan) -> u64 {
        self.alloc.span_read_u64(span, 0)
    }

    #[inline(always)]
    fn span_ctx_suffix(&self, span: ValidatedArenaSpan) -> u32 {
        self.alloc.span_read_u32(span, CTX_SUFFIX)
    }

    #[inline(always)]
    fn span_ctx_num_stats(&self, span: ValidatedArenaSpan) -> u16 {
        self.alloc.span_read_u16(span, CTX_NUM_STATS)
    }

    #[inline(always)]
    fn span_ctx_summ_freq(&self, span: ValidatedArenaSpan) -> u16 {
        self.alloc.span_read_u16(span, CTX_SUMM_FREQ)
    }

    #[inline(always)]
    fn span_ctx_stats(&self, span: ValidatedArenaSpan) -> u32 {
        self.alloc.span_read_u32(span, CTX_STATS)
    }

    #[inline(always)]
    fn span_one_sym(&self, span: ValidatedArenaSpan) -> u8 {
        self.alloc.span_read_u8(span, CTX_ONE_SYM)
    }

    #[inline(always)]
    fn span_one_freq(&self, span: ValidatedArenaSpan) -> u8 {
        self.alloc.span_read_u8(span, CTX_ONE_FREQ)
    }

    #[inline(always)]
    fn span_one_succ(&self, span: ValidatedArenaSpan) -> u32 {
        self.alloc.span_read_u32(span, CTX_ONE_SUCC)
    }

    #[inline(always)]
    fn span_set_one_freq(&mut self, span: ValidatedArenaSpan, value: u8) {
        self.alloc.span_write_u8(span, CTX_ONE_FREQ, value);
    }

    #[inline(always)]
    fn span_state_head(&self, span: ValidatedArenaSpan, index: usize) -> u16 {
        self.alloc.span_read_u16(span, index * STATE_SIZE)
    }

    #[inline(always)]
    fn span_state_sym(&self, span: ValidatedArenaSpan, index: usize) -> u8 {
        self.alloc
            .span_read_u8(span, index * STATE_SIZE + STATE_SYM)
    }

    #[inline(always)]
    fn span_state_freq(&self, span: ValidatedArenaSpan, index: usize) -> u8 {
        self.alloc
            .span_read_u8(span, index * STATE_SIZE + STATE_FREQ)
    }

    #[inline(always)]
    fn span_state_succ(&self, span: ValidatedArenaSpan, index: usize) -> u32 {
        self.alloc
            .span_read_u32(span, index * STATE_SIZE + STATE_SUCC)
    }

    #[inline(always)]
    fn span_set_state_freq(&mut self, span: ValidatedArenaSpan, index: usize, value: u8) {
        self.alloc
            .span_write_u8(span, index * STATE_SIZE + STATE_FREQ, value);
    }

    #[inline(always)]
    fn span_set_state_sym(&mut self, span: ValidatedArenaSpan, index: usize, value: u8) {
        self.alloc
            .span_write_u8(span, index * STATE_SIZE + STATE_SYM, value);
    }

    #[inline(always)]
    fn span_set_state_succ(&mut self, span: ValidatedArenaSpan, index: usize, value: u32) {
        self.alloc
            .span_write_u32(span, index * STATE_SIZE + STATE_SUCC, value);
    }

    #[inline(always)]
    fn span_copy_state(&mut self, span: ValidatedArenaSpan, dst: usize, src: usize) {
        let head = self.alloc.span_read_u16(span, src * STATE_SIZE);
        let successor = self
            .alloc
            .span_read_u32(span, src * STATE_SIZE + STATE_SUCC);
        self.alloc.span_write_u16(span, dst * STATE_SIZE, head);
        self.alloc
            .span_write_u32(span, dst * STATE_SIZE + STATE_SUCC, successor);
    }

    #[inline(always)]
    fn span_swap_states(&mut self, span: ValidatedArenaSpan, a: usize, b: usize) {
        let a_head = self.alloc.span_read_u16(span, a * STATE_SIZE);
        let a_successor = self.alloc.span_read_u32(span, a * STATE_SIZE + STATE_SUCC);
        let b_head = self.alloc.span_read_u16(span, b * STATE_SIZE);
        let b_successor = self.alloc.span_read_u32(span, b * STATE_SIZE + STATE_SUCC);
        self.alloc.span_write_u16(span, a * STATE_SIZE, b_head);
        self.alloc
            .span_write_u32(span, a * STATE_SIZE + STATE_SUCC, b_successor);
        self.alloc.span_write_u16(span, b * STATE_SIZE, a_head);
        self.alloc
            .span_write_u32(span, b * STATE_SIZE + STATE_SUCC, a_successor);
    }

    #[inline(always)]
    fn span_set_ctx_num_stats(&mut self, span: ValidatedArenaSpan, value: u16) {
        self.alloc.span_write_u16(span, CTX_NUM_STATS, value);
    }

    #[inline(always)]
    fn span_set_ctx_summ_freq(&mut self, span: ValidatedArenaSpan, value: u16) {
        self.alloc.span_write_u16(span, CTX_SUMM_FREQ, value);
    }

    #[inline(always)]
    fn span_set_ctx_stats(&mut self, span: ValidatedArenaSpan, value: u32) {
        self.alloc.span_write_u32(span, CTX_STATS, value);
    }

    #[inline(always)]
    fn span_set_ctx_suffix(&mut self, span: ValidatedArenaSpan, value: u32) {
        self.alloc.span_write_u32(span, CTX_SUFFIX, value);
    }

    #[inline(always)]
    fn span_set_one_sym(&mut self, span: ValidatedArenaSpan, value: u8) {
        self.alloc.span_write_u8(span, CTX_ONE_SYM, value);
    }

    #[inline(always)]
    fn span_set_one_succ(&mut self, span: ValidatedArenaSpan, value: u32) {
        self.alloc.span_write_u32(span, CTX_ONE_SUCC, value);
    }

    #[inline]
    fn ctx_suffix(&self, ctx: u32) -> u32 {
        self.alloc.read_u32_at(ctx as usize + CTX_SUFFIX)
    }

    #[inline]
    fn ctx_num_stats(&self, ctx: u32) -> u16 {
        self.alloc.read_u16_at(ctx as usize + CTX_NUM_STATS)
    }

    #[cfg(test)]
    #[inline]
    fn ctx_summ_freq(&self, ctx: u32) -> u16 {
        self.alloc.read_u16_at(ctx as usize + CTX_SUMM_FREQ)
    }

    #[inline]
    fn ctx_stats(&self, ctx: u32) -> u32 {
        self.alloc.read_u32_at(ctx as usize + CTX_STATS)
    }

    #[cfg(test)]
    #[inline]
    fn set_ctx_stats(&mut self, ctx: u32, val: u32) {
        self.alloc.write_u32_at(ctx as usize + CTX_STATS, val);
    }

    // OneState accessors (when NumStats == 1).
    #[inline]
    fn one_sym(&self, ctx: u32) -> u8 {
        self.alloc.read_byte_at(ctx as usize + CTX_ONE_SYM)
    }
    #[inline]
    fn one_freq(&self, ctx: u32) -> u8 {
        self.alloc.read_byte_at(ctx as usize + CTX_ONE_FREQ)
    }
    // State accessors at arbitrary byte offset.
    #[inline]
    fn st_sym(&self, off: u32) -> u8 {
        self.alloc.read_byte_at(off as usize + STATE_SYM)
    }
    #[inline]
    fn st_freq(&self, off: u32) -> u8 {
        self.alloc.read_byte_at(off as usize + STATE_FREQ)
    }
    /// Check if a successor value is a text pointer.
    fn is_text_succ(&self, succ: u32) -> bool {
        succ != 0 && (succ as usize) <= self.alloc.text_position()
    }

    #[cold]
    #[inline(never)]
    fn fail_model(&mut self) -> i32 {
        self.model_fault = true;
        -1
    }

    #[cold]
    #[inline(never)]
    fn corrupt_model<T>() -> RarResult<T> {
        Err(RarError::CorruptArchive {
            detail: "RAR PPMd model pointer out of bounds".into(),
        })
    }

    // =======================================================================
    // Decode entry point
    // =======================================================================

    /// Decode one character. Returns 0-255 on success, -1 on error/restart.
    pub fn decode_char<R: RangeCode>(&mut self, rc: &mut R) -> i32 {
        let debug_output_index = self.debug_index();
        if self.debug_enabled() && (40272340..=40272346).contains(&debug_output_index) {
            let ns = self.ctx_num_stats(self.min_context);
            eprintln!(
                "PPMD decode_char start: index=117 min_context={} ns={} order_fall={} found_state={}",
                self.min_context, ns, self.order_fall, self.found_state
            );
        }
        if self.min_context == 0 || self.alloc.text_exhausted() {
            if self.debug_enabled() {
                eprintln!(
                    "PPMD decode_char early fail: min_context={} text_exhausted={} heap_end={}",
                    self.min_context,
                    self.alloc.text_exhausted(),
                    self.alloc.heap_end_bytes()
                );
            }
            return self.fail_model();
        }
        let Some(context_span) = self.validated_context(self.min_context) else {
            return self.fail_model();
        };
        let mut active_context_span = context_span;
        let context_head = self.span_context_head(context_span);
        let mut active_context_head = context_head;
        let mut found_span = None;

        let ns = (context_head >> 32) as u16;
        if ns == 0 || ns > 256 {
            return self.fail_model();
        }

        if ns != 1 {
            let stats = self.span_ctx_stats(context_span);
            let Some(states_span) = self.validated_states(stats, ns as usize) else {
                return self.fail_model();
            };
            // Multi-symbol context.
            if !self.decode_symbol1(rc, context_span, states_span, context_head, &mut found_span) {
                if self.debug_enabled() {
                    eprintln!(
                        "PPMD decode_symbol1 failed: min_context={}",
                        self.min_context
                    );
                }
                return -1;
            }
        } else {
            // Binary context.
            if !self.decode_bin_symbol(rc, context_span, context_head, &mut found_span) {
                return -1;
            }
        }

        // Escape loop: walk suffix chain until a symbol is found.
        let mut validated_suffix: Option<(ValidatedArenaSpan, u64)> = None;
        while found_span.is_none() {
            rc.normalize();
            let (decode_context_span, decode_context_head) = loop {
                self.order_fall += 1;
                let prev_ctx = self.min_context;
                debug_assert_eq!(active_context_span.offset(), prev_ctx as usize);
                let prev_ns = (active_context_head >> 32) as u16;
                let suffix = active_context_head as u32;
                self.min_context = suffix;
                if self.min_context == 0 {
                    if self.debug_enabled() {
                        eprintln!(
                            "PPMD suffix chain hit null: prev_ctx={} prev_ns={} num_masked={} max_context={} order_fall={}",
                            prev_ctx, prev_ns, self.num_masked, self.max_context, self.order_fall
                        );
                        let mut chain = self.max_context;
                        for depth in 0..8 {
                            if chain == 0 {
                                break;
                            }
                            let ns_chain = self.ctx_num_stats(chain) as usize;
                            if ns_chain == 1 {
                                eprintln!(
                                    "PPMD null max one-state[{depth}]: ctx={} sym={} freq={} suffix={}",
                                    chain,
                                    self.one_sym(chain),
                                    self.one_freq(chain),
                                    self.ctx_suffix(chain)
                                );
                            } else {
                                let stats = self.ctx_stats(chain);
                                let mut syms = Vec::new();
                                let mut p = stats;
                                for _ in 0..ns_chain.min(8) {
                                    syms.push((self.st_sym(p), self.st_freq(p)));
                                    p += STATE_SIZE as u32;
                                }
                                eprintln!(
                                    "PPMD null max states[{depth}]: ctx={} ns={} suffix={} states={:?}",
                                    chain,
                                    ns_chain,
                                    self.ctx_suffix(chain),
                                    syms
                                );
                            }
                            chain = self.ctx_suffix(chain);
                        }
                    }
                    return -1;
                }
                let (suffix_span, suffix_head) = if let Some((span, head)) = validated_suffix.take()
                {
                    if span.offset() != self.min_context as usize {
                        return self.fail_model();
                    }
                    (span, head)
                } else {
                    // Validate context pointer.
                    let Some(span) = self.validated_context(self.min_context) else {
                        if self.debug_enabled() {
                            eprintln!(
                                "PPMD suffix context invalid: ctx={} p_text={} heap_end={}",
                                self.min_context,
                                self.alloc.text_position(),
                                self.alloc.heap_end_bytes()
                            );
                        }
                        return self.fail_model();
                    };
                    (span, self.span_context_head(span))
                };
                active_context_span = suffix_span;
                active_context_head = suffix_head;
                let ns2 = (suffix_head >> 32) as u16 as usize;
                if ns2 != self.num_masked {
                    break (suffix_span, suffix_head);
                }
            };
            if !self.decode_symbol2(
                rc,
                decode_context_span,
                decode_context_head,
                &mut found_span,
                &mut validated_suffix,
            ) {
                if self.debug_enabled() {
                    eprintln!(
                        "PPMD decode_symbol2 failed: min_context={}",
                        self.min_context
                    );
                }
                return -1;
            }
        }

        let Some(found_span) = found_span else {
            return self.fail_model();
        };
        let symbol = self.span_state_sym(found_span, 0);
        self.found_symbol = symbol;

        if self.order_fall == 0 {
            let succ = self.span_state_succ(found_span, 0);
            if succ != 0 && !self.is_text_succ(succ) {
                // Deterministic context jump.
                // The successor is range-checked before dereference at the
                // next decode entry, avoiding the same check twice.
                self.min_context = succ;
                self.max_context = succ;
            } else {
                if !self.update_model(found_span, active_context_span, active_context_head) {
                    return -1;
                }
                if self.esc_count == 0 {
                    self.clear_mask();
                }
            }
        } else {
            if !self.update_model(found_span, active_context_span, active_context_head) {
                return -1;
            }
            if self.esc_count == 0 {
                self.clear_mask();
            }
        }

        if self.debug_enabled() {
            eprintln!(
                "PPMD decode_char ok: index={} symbol={} found_state={} order_fall={} min_context={}",
                debug_output_index, symbol, self.found_state, self.order_fall, self.min_context
            );
        }
        rc.normalize();
        self.advance_debug_index();
        symbol as i32
    }

    /// Decode one character with checked arena access.
    #[inline(always)]
    pub fn decode_char_result<R: RangeCode>(&mut self, rc: &mut R) -> RarResult<Option<u8>> {
        let ch = self.decode_char(rc);
        if ch < 0 {
            if std::mem::take(&mut self.model_fault) {
                return Self::corrupt_model();
            }
            Ok(None)
        } else {
            Ok(Some(ch as u8))
        }
    }

    // =======================================================================
    // decode_bin_symbol (NumStats == 1)
    // =======================================================================

    fn decode_bin_symbol<R: RangeCode>(
        &mut self,
        rc: &mut R,
        context_span: ValidatedArenaSpan,
        context_head: u64,
        found_span: &mut Option<ValidatedArenaSpan>,
    ) -> bool {
        let ctx = self.min_context;
        debug_assert_eq!(context_span.offset(), ctx as usize);
        let symbol = (context_head >> 48) as u8;
        let freq = (context_head >> 56) as u8;

        // BinSumm index. `found_symbol` was copied from the last fully
        // validated matched state and is reset with the model.
        self.hi_bits_flag = self.hb2_flag[self.found_symbol as usize];
        let suffix = context_head as u32;
        let suffix_ns = if suffix != 0 {
            let Some(suffix_span) = self.validated_context(suffix) else {
                self.model_fault = true;
                return false;
            };
            (self.span_context_head(suffix_span) >> 32) as u16
        } else {
            1 // Avoid underflow; won't be used if suffix is null.
        };
        let idx1 = self.prev_success as usize
            + self.ns2_bs_indx[suffix_ns.wrapping_sub(1).min(255) as usize] as usize
            + self.hi_bits_flag as usize
            + 2 * self.hb2_flag[symbol as usize] as usize
            + ((self.run_length >> 26) as usize & 0x20);
        let idx0 = (freq as usize).saturating_sub(1).min(127);
        let idx1 = idx1.min(63);
        let bs = self.bin_summ[idx0][idx1];
        if self.debug_enabled() && (40272340..=40272346).contains(&self.debug_index()) {
            eprintln!(
                "PPMD decode_bin_symbol: ctx={} symbol={} freq={} prev={} suffix={} suffix_ns={} hi={} sym_hi={} run={} idx0={} idx1={} bs={}",
                ctx,
                symbol,
                freq,
                self.prev_success,
                suffix,
                suffix_ns,
                self.hi_bits_flag,
                self.hb2_flag[symbol as usize],
                self.run_length,
                idx0,
                idx1,
                bs
            );
        }

        if bs as u32 > BIN_SCALE {
            return false;
        }
        let threshold = rc.get_binary_threshold();
        if self.debug_enabled() && (40272340..=40272346).contains(&self.debug_index()) {
            eprintln!(
                "PPMD decode_bin_symbol threshold: ctx={} threshold={} bs={}",
                ctx, threshold, bs
            );
        }
        if threshold < bs as u32 {
            rc.decode(0, bs as u32, BIN_SCALE);
            // Symbol found.
            self.found_state = ctx + CTX_ONE_SYM as u32;
            *found_span = Some(context_span.subspan(CTX_ONE_SYM, STATE_SIZE));
            let new_freq = if freq < 128 { freq + 1 } else { freq };
            self.span_set_one_freq(context_span, new_freq);

            // Update BinSumm: increase probability.
            let mean = ((bs as u32 + 32) >> 7) as u16;
            self.bin_summ[idx0][idx1] = bs.wrapping_add(INTERVAL).wrapping_sub(mean);

            self.prev_success = 1;
            self.run_length += 1;
        } else {
            // Escape.
            rc.decode(bs as u32, BIN_SCALE - bs as u32, BIN_SCALE);
            let mean = ((bs as u32 + 32) >> 7) as u16;
            let new_bs = bs.wrapping_sub(mean);
            let Some(&init_esc) = EXP_ESCAPE.get((new_bs >> 10) as usize) else {
                return false;
            };
            if self.debug_enabled() && (40272340..=40272346).contains(&self.debug_index()) {
                eprintln!(
                    "PPMD decode_bin_symbol escaped: ctx={} symbol={} new_bs={} init_esc={}",
                    ctx, symbol, new_bs, init_esc
                );
            }
            self.bin_summ[idx0][idx1] = new_bs;

            self.init_esc = init_esc;
            self.num_masked = 1;
            self.char_mask[symbol as usize] = self.esc_count;
            self.prev_success = 0;
            self.found_state = 0;
            *found_span = None;
        }
        true
    }

    // =======================================================================
    // decode_symbol1 (NumStats > 1)
    // =======================================================================

    fn decode_symbol1<R: RangeCode>(
        &mut self,
        rc: &mut R,
        context_span: ValidatedArenaSpan,
        states_span: ValidatedArenaSpan,
        context_head: u64,
        found_span: &mut Option<ValidatedArenaSpan>,
    ) -> bool {
        let ctx = self.min_context;
        debug_assert_eq!(context_span.offset(), ctx as usize);
        let ns = (context_head >> 32) as u16 as usize;
        let sum_freq = (context_head >> 48) as u16 as u32;
        let stats = self.span_ctx_stats(context_span);
        debug_assert_eq!(states_span.offset(), stats as usize);
        debug_assert_eq!(states_span.len(), ns * STATE_SIZE);

        let count = rc.get_current_count(sum_freq);
        if self.debug_enabled() && (40272340..=40272346).contains(&self.debug_index()) {
            eprintln!(
                "PPMD decode_symbol1: ctx={} ns={} sum_freq={} count={}",
                ctx, ns, sum_freq, count
            );
        }
        if count >= sum_freq {
            if self.debug_enabled() {
                eprintln!(
                    "PPMD decode_symbol1 count overflow: count={} sum_freq={} ctx={} found_state={}",
                    count, sum_freq, ctx, self.found_state
                );
            }
            return false;
        }

        // Check first symbol.
        let p0_freq = self.span_state_freq(states_span, 0) as u32;
        if count < p0_freq {
            // First symbol matched.
            self.prev_success = if 2 * p0_freq > sum_freq { 1 } else { 0 };
            self.run_length += self.prev_success as i32;
            self.found_state = stats;
            *found_span = Some(states_span.subspan(0, STATE_SIZE));

            let new_freq = (p0_freq + 4) as u8;
            self.span_set_state_freq(states_span, 0, new_freq);
            self.span_set_ctx_summ_freq(context_span, (sum_freq + 4) as u16);

            let model_valid = new_freq <= MAX_FREQ || self.rescale(ctx);
            if new_freq > MAX_FREQ {
                *found_span = self.validated_state(self.found_state);
            }
            rc.decode(0, p0_freq, sum_freq);
            return model_valid;
        }

        if self.found_state == 0 {
            if self.debug_enabled() {
                eprintln!("PPMD decode_symbol1 found_state=0");
            }
            return false;
        }

        self.prev_success = 0;
        let mut hi_cnt = p0_freq;
        let mut remaining = ns - 1;
        let mut state_index = 1usize;

        loop {
            let p_freq = self.span_state_freq(states_span, state_index) as u32;
            hi_cnt += p_freq;
            if hi_cnt > count {
                // Found a symbol.
                let low = hi_cnt - p_freq;
                rc.decode(low, p_freq, sum_freq);
                return self.update1(ctx, context_span, states_span, state_index, found_span);
            }
            remaining -= 1;
            if remaining == 0 {
                // Escape.
                self.hi_bits_flag = self.hb2_flag[self.found_symbol as usize];
                self.num_masked = ns;
                self.found_state = 0;
                *found_span = None;

                for index in 0..ns {
                    let sym = self.span_state_sym(states_span, index);
                    self.char_mask[sym as usize] = self.esc_count;
                }

                let escape_freq = sum_freq - hi_cnt;
                rc.decode(hi_cnt, escape_freq, sum_freq);
                return true;
            }
            state_index += 1;
        }
    }

    /// update1: increase freq, maintain sorted order, rescale if needed.
    #[inline(always)]
    fn update1(
        &mut self,
        ctx: u32,
        context_span: ValidatedArenaSpan,
        states_span: ValidatedArenaSpan,
        state_index: usize,
        found_span: &mut Option<ValidatedArenaSpan>,
    ) -> bool {
        debug_assert!(state_index < self.span_ctx_num_stats(context_span) as usize);
        let p = self.span_ctx_stats(context_span) + state_index as u32 * STATE_SIZE as u32;
        self.found_state = p;
        let freq = self.span_state_freq(states_span, state_index);
        let new_freq = freq.saturating_add(4);
        self.span_set_state_freq(states_span, state_index, new_freq);

        let sf = self.span_ctx_summ_freq(context_span);
        self.span_set_ctx_summ_freq(context_span, sf.wrapping_add(4));

        let mut found_index = state_index;
        if state_index > 0 {
            let prev = p - STATE_SIZE as u32;
            if new_freq > self.span_state_freq(states_span, state_index - 1) {
                self.span_swap_states(states_span, state_index, state_index - 1);
                self.found_state = prev;
                found_index -= 1;
                if self.span_state_freq(states_span, state_index - 1) > MAX_FREQ {
                    let model_valid = self.rescale(ctx);
                    *found_span = self.validated_state(self.found_state);
                    return model_valid && found_span.is_some();
                }
            }
        }
        *found_span = Some(states_span.subspan(found_index * STATE_SIZE, STATE_SIZE));
        true
    }

    // =======================================================================
    // decode_symbol2 (masked context decode during escape)
    // =======================================================================

    fn decode_symbol2<R: RangeCode>(
        &mut self,
        rc: &mut R,
        context_span: ValidatedArenaSpan,
        context_head: u64,
        found_span: &mut Option<ValidatedArenaSpan>,
        validated_suffix: &mut Option<(ValidatedArenaSpan, u64)>,
    ) -> bool {
        *validated_suffix = None;
        let ctx = self.min_context;
        debug_assert_eq!(context_span.offset(), ctx as usize);
        let ns = (context_head >> 32) as u16 as usize;
        let stats = self.span_ctx_stats(context_span);
        let Some(states_span) = self.validated_states(stats, ns) else {
            self.model_fault = true;
            return false;
        };
        let suffix = context_head as u32;
        let suffix_data = if ns != 256 {
            if suffix == 0 {
                self.model_fault = true;
                return false;
            }
            let Some(span) = self.validated_context(suffix) else {
                self.model_fault = true;
                return false;
            };
            Some((span, self.span_context_head(span)))
        } else {
            None
        };
        let Some(diff) = ns.checked_sub(self.num_masked) else {
            if self.debug_enabled() {
                eprintln!(
                    "PPMD decode_symbol2 masked overflow: ctx={} ns={} num_masked={} max_context={} order_fall={}",
                    ctx, ns, self.num_masked, self.max_context, self.order_fall
                );
                if self.max_context != 0 {
                    let ns_max = self.ctx_num_stats(self.max_context) as usize;
                    if ns_max == 1 {
                        eprintln!(
                            "PPMD overflow max one-state: sym={} freq={}",
                            self.one_sym(self.max_context),
                            self.one_freq(self.max_context)
                        );
                    } else {
                        let stats = self.ctx_stats(self.max_context);
                        let mut syms = Vec::new();
                        let mut p = stats;
                        for _ in 0..ns_max.min(8) {
                            syms.push((self.st_sym(p), self.st_freq(p)));
                            p += STATE_SIZE as u32;
                        }
                        eprintln!(
                            "PPMD overflow max_context: ctx={} ns={} suffix={} states={:?}",
                            self.max_context,
                            ns_max,
                            self.ctx_suffix(self.max_context),
                            syms
                        );
                    }
                }
                let mut chain = ctx;
                for depth in 0..6 {
                    if chain == 0 {
                        break;
                    }
                    let ns_chain = self.ctx_num_stats(chain) as usize;
                    if ns_chain == 1 {
                        eprintln!(
                            "PPMD overflow one-state[{depth}]: sym={} freq={}",
                            self.one_sym(chain),
                            self.one_freq(chain)
                        );
                    } else {
                        let stats = self.ctx_stats(chain);
                        let mut syms = Vec::new();
                        let mut p = stats;
                        for _ in 0..ns_chain.min(8) {
                            syms.push((self.st_sym(p), self.st_freq(p)));
                            p += STATE_SIZE as u32;
                        }
                        eprintln!("PPMD overflow states[{depth}]: {:?}", syms);
                    }
                    eprintln!(
                        "PPMD overflow chain[{depth}]: ctx={} ns={} suffix={}",
                        chain,
                        ns_chain,
                        self.ctx_suffix(chain)
                    );
                    chain = self.ctx_suffix(chain);
                }
            }
            return false;
        };
        if diff == 0 {
            if self.debug_enabled() {
                eprintln!(
                    "PPMD decode_symbol2 diff=0: ctx={} ns={} num_masked={}",
                    ctx, ns, self.num_masked
                );
            }
            return false;
        }

        // makeEscFreq2
        let suffix_ns = suffix_data.map_or(0, |(_, head)| (head >> 32) as u16 as usize);
        let (esc_freq, see_index) = self.make_esc_freq2(context_head, suffix_ns, diff);

        // Collect only the live state indices. The frequencies are already in
        // the arena and are cheap to reload on the selection pass. Reusing the
        // model-owned array avoids zeroing a padded 2 KiB stack allocation on
        // every escape decode.
        let mut hi_cnt = 0u32;
        let mut state_index = 0usize;
        for scratch_index in 0..diff {
            let head = loop {
                if state_index >= ns {
                    return false;
                }
                let head = self.span_state_head(states_span, state_index);
                let sym = head as u8;
                if self.char_mask[sym as usize] != self.esc_count {
                    break head;
                }
                state_index += 1;
            };

            hi_cnt += (head >> 8) as u32;
            self.unmasked_scratch[scratch_index] = pack_unmasked_state(state_index, head);
            state_index += 1;
        }
        let n = diff;

        let scale = esc_freq + hi_cnt;
        let count = rc.get_current_count(scale);
        if self.debug_enabled() && (40272340..=40272346).contains(&self.debug_index()) {
            let mut preview = Vec::new();
            for index in 0..n.min(8) {
                preview.push((
                    unmasked_state_symbol(self.unmasked_scratch[index]),
                    unmasked_state_frequency(self.unmasked_scratch[index]),
                ));
            }
            eprintln!(
                "PPMD decode_symbol2: ctx={} ns={} diff={} num_masked={} esc_freq={} hi_cnt={} scale={} count={} preview={:?}",
                ctx, ns, diff, self.num_masked, esc_freq, hi_cnt, scale, count, preview
            );
        }
        if count >= scale {
            if self.debug_enabled() {
                eprintln!(
                    "PPMD decode_symbol2 count overflow: ctx={} ns={} diff={} num_masked={} esc_count={} esc_freq={} hi_cnt={} scale={} count={}",
                    ctx, ns, diff, self.num_masked, self.esc_count, esc_freq, hi_cnt, scale, count
                );
                let stats = self.ctx_stats(ctx);
                let mut syms = Vec::new();
                let mut p = stats;
                for _ in 0..ns.min(16) {
                    syms.push((
                        self.st_sym(p),
                        self.st_freq(p),
                        self.char_mask[self.st_sym(p) as usize],
                    ));
                    p += STATE_SIZE as u32;
                }
                eprintln!("PPMD decode_symbol2 ctx states: {:?}", syms);
            }
            return false;
        }

        if count < hi_cnt {
            // Symbol found among unmasked.
            let mut cum = 0u32;
            for index in 0..n {
                let packed = self.unmasked_scratch[index];
                let state_index = unmasked_state_index(packed);
                let state_freq = unmasked_state_frequency(packed);
                let freq = state_freq as u32;
                cum += freq;
                if cum > count {
                    let low = cum - freq;
                    rc.decode(low, freq, scale);
                    // SEE update (success).
                    self.see_update_success(see_index);
                    return self.update2(
                        ctx,
                        context_span,
                        states_span,
                        state_index,
                        state_freq,
                        found_span,
                    );
                }
            }
        }

        // Escape again.
        rc.decode(hi_cnt, esc_freq, scale);

        // SEE update (escape): add scale to summ.
        self.see_update_escape(see_index, scale);

        // Mask remaining unmasked symbols.
        for index in 0..n {
            let sym = unmasked_state_symbol(self.unmasked_scratch[index]);
            self.char_mask[sym as usize] = self.esc_count;
        }
        self.num_masked = ns;
        *validated_suffix = suffix_data;

        true // escape — FoundState stays NULL and decode_char continues down the suffix chain
    }

    #[inline(always)]
    fn make_esc_freq2(
        &mut self,
        context_head: u64,
        suffix_ns: usize,
        diff: usize,
    ) -> (u32, Option<(usize, usize)>) {
        let ns = (context_head >> 32) as u16;
        if ns != 256 {
            let sf = (context_head >> 48) as u16;
            let idx0 = self.ns2_indx[diff.saturating_sub(1).min(255)] as usize;
            let idx1 = (if diff < suffix_ns.saturating_sub(ns as usize) {
                1
            } else {
                0
            }) + (if (sf as usize) < 11 * ns as usize {
                2
            } else {
                0
            }) + (if self.num_masked > diff { 4 } else { 0 })
                + self.hi_bits_flag as usize;
            let see_ctx = self.see.get(idx0, idx1);
            (see_ctx.get_mean(), Some((idx0, idx1)))
        } else {
            (1, None)
        }
    }

    #[inline(always)]
    fn see_update_success(&mut self, see_index: Option<(usize, usize)>) {
        if let Some((idx0, idx1)) = see_index {
            self.see.get(idx0, idx1).update();
        }
    }

    #[inline(always)]
    fn see_update_escape(&mut self, see_index: Option<(usize, usize)>, scale: u32) {
        if let Some((idx0, idx1)) = see_index {
            let see = self.see.get(idx0, idx1);
            see.summ = see.summ.wrapping_add(scale as u16);
        } else {
            let dummy = self.see.get_dummy();
            dummy.summ = dummy.summ.wrapping_add(scale as u16);
        }
    }

    /// update2: set FoundState, increase freq, maybe rescale.
    #[inline(always)]
    fn update2(
        &mut self,
        ctx: u32,
        context_span: ValidatedArenaSpan,
        states_span: ValidatedArenaSpan,
        state_index: usize,
        freq: u8,
        found_span: &mut Option<ValidatedArenaSpan>,
    ) -> bool {
        debug_assert!(state_index < self.span_ctx_num_stats(context_span) as usize);
        let p = self.span_ctx_stats(context_span) + state_index as u32 * STATE_SIZE as u32;
        self.found_state = p;
        let new_freq = freq.saturating_add(4);
        self.span_set_state_freq(states_span, state_index, new_freq);

        let sf = self.span_ctx_summ_freq(context_span);
        self.span_set_ctx_summ_freq(context_span, sf.wrapping_add(4));
        if new_freq > MAX_FREQ {
            if !self.rescale(ctx) {
                return false;
            }
            *found_span = self.validated_state(self.found_state);
            if found_span.is_none() {
                self.model_fault = true;
                return false;
            }
        } else {
            *found_span = Some(states_span.subspan(state_index * STATE_SIZE, STATE_SIZE));
        }
        self.esc_count = self.esc_count.wrapping_add(1);
        self.run_length = self.init_rl;
        true
    }

    // =======================================================================
    // rescale
    // =======================================================================

    fn rescale(&mut self, ctx: u32) -> bool {
        let Some(context_span) = self.validated_context(ctx) else {
            self.model_fault = true;
            return false;
        };
        let old_ns = self.span_ctx_num_stats(context_span) as usize;
        let stats = self.span_ctx_stats(context_span);
        let Some(states_span) = self.validated_states(stats, old_ns) else {
            self.model_fault = true;
            return false;
        };
        let adder: u8 = if self.order_fall != 0 { 1 } else { 0 };

        // Move FoundState to front.
        let Some(found_delta) = self.found_state.checked_sub(stats) else {
            self.model_fault = true;
            return false;
        };
        if found_delta as usize % STATE_SIZE != 0 {
            self.model_fault = true;
            return false;
        }
        let mut found_index = found_delta as usize / STATE_SIZE;
        if found_index >= old_ns {
            self.model_fault = true;
            return false;
        }
        while found_index != 0 {
            self.span_swap_states(states_span, found_index, found_index - 1);
            found_index -= 1;
        }

        // Boost first state.
        let f0 = self.span_state_freq(states_span, 0);
        let new_f0 = f0.saturating_add(4);
        self.span_set_state_freq(states_span, 0, new_f0);
        let sf0 = self.span_ctx_summ_freq(context_span);
        self.span_set_ctx_summ_freq(context_span, sf0.wrapping_add(4));

        // Halve frequencies, accumulate escape frequency.
        let mut esc_freq = self.span_ctx_summ_freq(context_span) as i32
            - self.span_state_freq(states_span, 0) as i32;
        let first_freq = ((self.span_state_freq(states_span, 0) as u16 + adder as u16) >> 1) as u8;
        self.span_set_state_freq(states_span, 0, first_freq);
        let mut new_summ = first_freq as u16;

        for state_index in 1..old_ns {
            esc_freq -= self.span_state_freq(states_span, state_index) as i32;
            let halved =
                ((self.span_state_freq(states_span, state_index) as u16 + adder as u16) >> 1) as u8;
            self.span_set_state_freq(states_span, state_index, halved);
            new_summ += halved as u16;

            // Maintain sorted order.
            if halved > self.span_state_freq(states_span, state_index - 1) {
                // Bubble up.
                let tmp_sym = self.span_state_sym(states_span, state_index);
                let tmp_freq = halved;
                let tmp_succ = self.span_state_succ(states_span, state_index);
                let mut dst = state_index;
                loop {
                    self.span_copy_state(states_span, dst, dst - 1);
                    dst -= 1;
                    if dst == 0 || tmp_freq <= self.span_state_freq(states_span, dst - 1) {
                        break;
                    }
                }
                self.span_set_state_sym(states_span, dst, tmp_sym);
                self.span_set_state_freq(states_span, dst, tmp_freq);
                self.span_set_state_succ(states_span, dst, tmp_succ);
            }
        }

        // Remove zero-frequency states.
        let mut last_index = old_ns - 1;
        if self.span_state_freq(states_span, last_index) == 0 {
            let mut zero_count = 0usize;
            while self.span_state_freq(states_span, last_index) == 0 && last_index > 0 {
                zero_count += 1;
                last_index -= 1;
            }
            if self.span_state_freq(states_span, last_index) == 0 {
                zero_count += 1;
            }
            esc_freq += zero_count as i32;
            let new_ns = (old_ns - zero_count) as u16;
            self.span_set_ctx_num_stats(context_span, new_ns);

            if new_ns == 1 {
                // Collapse to single-state (OneState) context.
                let tmp_sym = self.span_state_sym(states_span, 0);
                let tmp_freq = self.span_state_freq(states_span, 0);
                let tmp_succ = self.span_state_succ(states_span, 0);

                // Halve freq until escape is small.
                let mut tf = tmp_freq;
                let mut ef = esc_freq;
                while ef > 1 {
                    tf = tf.saturating_sub(tf >> 1);
                    ef >>= 1;
                }

                // Free the stats array.
                self.alloc.free_units(off_to_ref(stats), (old_ns + 1) >> 1);

                // Write OneState inline.
                self.span_set_one_sym(context_span, tmp_sym);
                self.span_set_one_freq(context_span, tf);
                self.span_set_one_succ(context_span, tmp_succ);
                self.found_state = ctx + CTX_ONE_SYM as u32;
                return true;
            }
        }

        // Update SummFreq with halved escape.
        new_summ += (esc_freq as u16).wrapping_sub((esc_freq as u16) >> 1);
        self.span_set_ctx_summ_freq(context_span, new_summ);

        // Shrink stats array if needed.
        let n0 = (old_ns + 1) >> 1;
        let new_ns = self.span_ctx_num_stats(context_span) as usize;
        let n1 = (new_ns + 1) >> 1;
        let mut new_stats = stats;
        if n0 != n1 {
            new_stats = ref_to_off(self.alloc.shrink_units(off_to_ref(stats), n0, n1));
            self.span_set_ctx_stats(context_span, new_stats);
        }
        self.found_state = new_stats;
        if self.validated_state(new_stats).is_none() {
            self.model_fault = true;
            return false;
        }
        true
    }

    // =======================================================================
    // UpdateModel
    // =======================================================================

    #[inline(never)]
    fn update_model(
        &mut self,
        found_span: ValidatedArenaSpan,
        min_context_span: ValidatedArenaSpan,
        min_context_head: u64,
    ) -> bool {
        debug_assert_eq!(min_context_span.offset(), self.min_context as usize);
        let fs_sym = self.span_state_sym(found_span, 0);
        let fs_freq = self.span_state_freq(found_span, 0);
        let fs_succ = self.span_state_succ(found_span, 0);

        if self.debug_enabled() && (110..=120).contains(&self.debug_index()) {
            eprintln!(
                "PPMD update_model: index={} fs_sym={} fs_freq={} fs_succ={} order_fall={} min_context={} max_context={}",
                self.debug_index(),
                fs_sym,
                fs_freq,
                fs_succ,
                self.order_fall,
                self.min_context,
                self.max_context
            );
        }

        // Update suffix context frequencies.
        let suffix = min_context_head as u32;
        if fs_freq < MAX_FREQ / 4 && suffix != 0 {
            let Some(suffix_span) = self.validated_context(suffix) else {
                self.model_fault = true;
                return false;
            };
            let sns = self.span_ctx_num_stats(suffix_span);
            if sns != 1 {
                // Find fs_sym in suffix stats.
                let s_stats = self.span_ctx_stats(suffix_span);
                let Some(suffix_states) = self.validated_states(s_stats, sns as usize) else {
                    self.model_fault = true;
                    return false;
                };
                let mut state_index = 0usize;
                if self.span_state_sym(suffix_states, state_index) != fs_sym {
                    state_index = 1;
                    while state_index < sns as usize
                        && self.span_state_sym(suffix_states, state_index) != fs_sym
                    {
                        state_index += 1;
                    }
                    if state_index >= sns as usize {
                        if self.debug_enabled() {
                            eprintln!(
                                "PPMD update_model missing suffix symbol: fs_sym={} min_context={} suffix={} suffix_ns={}",
                                fs_sym, self.min_context, suffix, sns
                            );
                        }
                        // Symbol not found in suffix — skip update.
                        return self.do_update_model_core(
                            found_span,
                            min_context_span,
                            fs_sym,
                            fs_freq,
                            fs_succ,
                            0,
                        );
                    }
                    // Swap with predecessor if freq is higher.
                    if self.span_state_freq(suffix_states, state_index)
                        >= self.span_state_freq(suffix_states, state_index - 1)
                    {
                        self.span_swap_states(suffix_states, state_index, state_index - 1);
                        state_index -= 1;
                    }
                }
                if self.span_state_freq(suffix_states, state_index) < MAX_FREQ - 9 {
                    let f = self.span_state_freq(suffix_states, state_index) + 2;
                    self.span_set_state_freq(suffix_states, state_index, f);
                    let sf = self.span_ctx_summ_freq(suffix_span);
                    self.span_set_ctx_summ_freq(suffix_span, sf.wrapping_add(2));
                }
                let p = s_stats + state_index as u32 * STATE_SIZE as u32;
                self.do_update_model_core(found_span, min_context_span, fs_sym, fs_freq, fs_succ, p)
            } else {
                // Suffix is binary context.
                let f = self.span_one_freq(suffix_span);
                if f < 32 {
                    self.span_set_one_freq(suffix_span, f + 1);
                }
                self.do_update_model_core(
                    found_span,
                    min_context_span,
                    fs_sym,
                    fs_freq,
                    fs_succ,
                    suffix + CTX_ONE_SYM as u32,
                )
            }
        } else {
            self.do_update_model_core(found_span, min_context_span, fs_sym, fs_freq, fs_succ, 0)
        }
    }

    /// Core of UpdateModel after suffix freq update.
    /// `p1` is the state offset in the suffix context (0 if none).
    #[inline(never)]
    fn do_update_model_core(
        &mut self,
        found_span: ValidatedArenaSpan,
        min_context_span: ValidatedArenaSpan,
        fs_sym: u8,
        fs_freq: u8,
        fs_succ: u32,
        p1: u32,
    ) -> bool {
        let mut next_min_context = fs_succ;

        if self.order_fall == 0 {
            // No escape: create successors.
            let new_ctx = self.create_successors(found_span, min_context_span, true, p1);
            if self.debug_enabled() && self.is_text_succ(new_ctx) {
                eprintln!(
                    "PPMD order_fall=0 create_successors returned text: new_ctx={} p1={} found_state={} min_context={} max_context={}",
                    new_ctx, p1, self.found_state, self.min_context, self.max_context
                );
            }
            if new_ctx == 0 {
                if self.model_fault {
                    return false;
                }
                self.restart();
                self.esc_count = 0;
                return true;
            }
            self.min_context = new_ctx;
            self.max_context = new_ctx;
            // Update found state's successor.
            self.span_set_state_succ(found_span, 0, new_ctx);
            return true;
        }

        // OrderFall > 0: store symbol in text region and propagate.
        self.alloc.write_text_byte(fs_sym);
        let successor = self.alloc.text_position() as u32;
        if self.alloc.text_exhausted() {
            self.restart();
            self.esc_count = 0;
            return true;
        }

        let final_succ;
        if fs_succ != 0 {
            // Existing successor — may need to create real contexts from text chain.
            if self.is_text_succ(fs_succ) {
                let new_succ = self.create_successors(found_span, min_context_span, false, p1);
                if new_succ == 0 {
                    if self.model_fault {
                        return false;
                    }
                    self.restart();
                    self.esc_count = 0;
                    return true;
                }
                self.span_set_state_succ(found_span, 0, new_succ);
                next_min_context = new_succ;
            }
            self.order_fall -= 1;
            if self.order_fall == 0 {
                final_succ = self.span_state_succ(found_span, 0);
                if self.max_context != self.min_context {
                    self.alloc.text_dec();
                }
            } else {
                final_succ = successor;
            }
        } else {
            // No successor yet: set text pointer as successor.
            self.span_set_state_succ(found_span, 0, successor);
            final_succ = successor;
            // fs.Successor becomes the current MinContext even though the live
            // FoundState successor now points into the text buffer.
            next_min_context = self.min_context;
        }

        let min_ctx = self.min_context;
        debug_assert_eq!(min_context_span.offset(), min_ctx as usize);
        let ns = self.span_ctx_num_stats(min_context_span) as u32;
        let s0 = (self.span_ctx_summ_freq(min_context_span) as u32)
            .wrapping_sub(ns)
            .wrapping_sub(fs_freq as u32)
            .wrapping_add(1);

        let mut pc = self.max_context;
        while pc != min_ctx {
            let Some(context_span) = self.validated_context(pc) else {
                self.model_fault = true;
                return false;
            };
            let ns1 = self.span_ctx_num_stats(context_span) as u32;
            if ns1 == 0 || ns1 > 256 {
                self.model_fault = true;
                return false;
            }

            let states_span = if ns1 != 1 {
                // Multi-symbol context: expand stats array if needed.
                let old_stats = self.span_ctx_stats(context_span);
                let stats = if (ns1 & 1) == 0 {
                    let new_stats = self
                        .alloc
                        .expand_units(off_to_ref(old_stats), (ns1 >> 1) as usize);
                    if new_stats.is_null() {
                        self.restart();
                        self.esc_count = 0;
                        return true;
                    }
                    let stats = ref_to_off(new_stats);
                    self.span_set_ctx_stats(context_span, stats);
                    stats
                } else {
                    old_stats
                };
                let Some(states_span) = self.validated_states(stats, ns1 as usize + 1) else {
                    self.model_fault = true;
                    return false;
                };
                // Adjust SummFreq.
                let sf = self.span_ctx_summ_freq(context_span) as u32;
                let adj = (if 2 * ns1 < ns { 1u32 } else { 0 })
                    + 2 * (if 4 * ns1 <= ns && sf <= 8 * ns1 { 1 } else { 0 });
                self.span_set_ctx_summ_freq(context_span, (sf + adj) as u16);
                states_span
            } else {
                // Single-state: promote to multi-state.
                let os_sym = self.span_one_sym(context_span);
                let os_freq = self.span_one_freq(context_span);
                let os_succ = self.span_one_succ(context_span);
                let new_stats_ref = self.alloc.alloc_units(1);
                if new_stats_ref.is_null() {
                    self.restart();
                    self.esc_count = 0;
                    return true;
                }
                let new_stats = ref_to_off(new_stats_ref);
                // Copy OneState to the new stats array.
                let Some(new_states_span) = self.validated_states(new_stats, 2) else {
                    self.model_fault = true;
                    return false;
                };
                self.span_set_state_sym(new_states_span, 0, os_sym);
                let adj_freq = if os_freq < MAX_FREQ / 4 - 1 {
                    os_freq * 2
                } else {
                    MAX_FREQ - 4
                };
                self.span_set_state_freq(new_states_span, 0, adj_freq);
                self.span_set_state_succ(new_states_span, 0, os_succ);
                self.span_set_ctx_stats(context_span, new_stats);
                self.span_set_ctx_summ_freq(
                    context_span,
                    adj_freq as u16 + self.init_esc as u16 + if ns > 3 { 1 } else { 0 },
                );
                new_states_span
            };

            // Compute new state's frequency.
            let sf_pc = self.span_ctx_summ_freq(context_span) as u32;
            let cf = 2 * fs_freq as u32 * (sf_pc + 6);
            let sf = s0 + sf_pc;
            let new_freq;
            if cf < 6 * sf {
                new_freq = 1 + (if cf > sf { 1 } else { 0 }) + (if cf >= 4 * sf { 1 } else { 0 });
                let new_sf = sf_pc + 3;
                self.span_set_ctx_summ_freq(context_span, new_sf as u16);
            } else {
                new_freq = 4
                    + (if cf >= 9 * sf { 1 } else { 0 })
                    + (if cf >= 12 * sf { 1 } else { 0 })
                    + (if cf >= 15 * sf { 1 } else { 0 });
                let new_sf = sf_pc + new_freq;
                self.span_set_ctx_summ_freq(context_span, new_sf as u16);
            }

            // Append new state at the end.
            self.span_set_state_succ(states_span, ns1 as usize, final_succ);
            self.span_set_state_sym(states_span, ns1 as usize, fs_sym);
            self.span_set_state_freq(states_span, ns1 as usize, new_freq as u8);
            self.span_set_ctx_num_stats(context_span, (ns1 + 1) as u16);

            pc = self.span_ctx_suffix(context_span);
        }

        if self.debug_enabled() && self.is_text_succ(next_min_context) {
            eprintln!(
                "PPMD next_min_context still text: next={} final_succ={} fs_succ={} found_state={} min_ctx={} max_ctx={} order_fall={}",
                next_min_context,
                final_succ,
                fs_succ,
                self.found_state,
                min_ctx,
                self.max_context,
                self.order_fall
            );
        }
        self.max_context = next_min_context;
        self.min_context = next_min_context;
        true
    }

    // =======================================================================
    // CreateSuccessors
    // =======================================================================

    #[inline(never)]
    fn create_successors(
        &mut self,
        found_span: ValidatedArenaSpan,
        min_context_span: ValidatedArenaSpan,
        skip: bool,
        p1: u32,
    ) -> u32 {
        debug_assert_eq!(min_context_span.offset(), self.min_context as usize);
        let up_branch = self.span_state_succ(found_span, 0);
        let found_sym = self.span_state_sym(found_span, 0);
        let min_suffix = self.span_ctx_suffix(min_context_span);

        if self.debug_enabled() && (40272337..=40272346).contains(&self.debug_index()) {
            eprintln!(
                "PPMD create_successors: index={} skip={} p1={} up_branch={} found_sym={} min_context={} max_context={}",
                self.debug_index(),
                skip,
                p1,
                up_branch,
                found_sym,
                self.min_context,
                self.max_context
            );
        }

        let mut pc = self.min_context;
        let mut ps = [found_span; MAX_ORDER + 1];
        let mut ps_len = 0usize;

        if !skip {
            ps[ps_len] = found_span;
            ps_len += 1;
            if min_suffix == 0 {
                // NO_LOOP
                return self.finish_create_successors(&ps[..ps_len], pc, up_branch, found_sym);
            }
        }

        if p1 != 0 {
            // p1 provided: use it and start from suffix.
            pc = min_suffix;
            let Some(p1_span) = self.validated_state(p1) else {
                self.model_fault = true;
                return 0;
            };
            let p1_succ = self.span_state_succ(p1_span, 0);
            // Check if p1's successor matches up_branch.
            if p1_succ != up_branch {
                pc = p1_succ;
                return self.finish_create_successors(&ps[..ps_len], pc, up_branch, found_sym);
            }
            if ps_len < MAX_ORDER + 1 {
                ps[ps_len] = p1_span;
                ps_len += 1;
            }
            // Fall through to suffix walk.
            let Some(context_span) = self.validated_context(pc) else {
                self.model_fault = true;
                return 0;
            };
            let suffix = self.span_ctx_suffix(context_span);
            if suffix == 0 {
                // No more suffix to walk.
                return self.finish_create_successors(&ps[..ps_len], pc, up_branch, found_sym);
            }
            pc = suffix;
        } else {
            if min_suffix == 0 {
                return self.finish_create_successors(&ps[..ps_len], pc, up_branch, found_sym);
            }
            pc = min_suffix;
        }

        // Walk suffix chain.
        loop {
            let Some(context_span) = self.validated_context(pc) else {
                self.model_fault = true;
                return 0;
            };
            let ns = self.span_ctx_num_stats(context_span);
            let (p_span, p_succ, p_sym);
            if ns != 1 {
                // Multi-symbol: find our symbol.
                let stats = self.span_ctx_stats(context_span);
                let Some(states_span) = self.validated_states(stats, ns as usize) else {
                    self.model_fault = true;
                    return 0;
                };
                let Some(state_index) = self.span_find_state(states_span, ns as usize, found_sym)
                else {
                    break; // Not found — shouldn't happen in valid data.
                };
                p_span = states_span.subspan(state_index * STATE_SIZE, STATE_SIZE);
                p_succ = self.span_state_succ(states_span, state_index);
                p_sym = self.span_state_sym(states_span, state_index);
            } else {
                // Binary context.
                p_span = context_span.subspan(CTX_ONE_SYM, STATE_SIZE);
                p_succ = self.span_one_succ(context_span);
                p_sym = self.span_one_sym(context_span);
            }
            if self.debug_enabled() && (40272337..=40272346).contains(&self.debug_index()) {
                eprintln!(
                    "PPMD create_successors loop: index={} pc={} ns={} p={} p_succ={} p_sym={} ps_len={}",
                    self.debug_index(),
                    pc,
                    ns,
                    p_span.offset(),
                    p_succ,
                    p_sym,
                    ps_len
                );
            }

            if p_succ != up_branch {
                pc = p_succ;
                break;
            }
            if ps_len > MAX_ORDER {
                return 0; // Safety limit.
            }
            ps[ps_len] = p_span;
            ps_len += 1;

            let suffix = self.span_ctx_suffix(context_span);
            if suffix == 0 {
                break;
            }
            pc = suffix;
        }

        self.finish_create_successors(&ps[..ps_len], pc, up_branch, found_sym)
    }

    #[inline(always)]
    fn finish_create_successors(
        &mut self,
        ps: &[ValidatedArenaSpan],
        mut pc: u32,
        up_branch: u32,
        found_sym: u8,
    ) -> u32 {
        if ps.is_empty() {
            if self.debug_enabled() && self.is_text_succ(pc) {
                eprintln!(
                    "PPMD finish_create_successors returning text pc={} up_branch={} found_sym={}",
                    pc, up_branch, found_sym
                );
            }
            return pc;
        }

        // Read the symbol and successor from the text chain (UpBranch).
        let up_sym;
        let up_succ;
        if up_branch != 0 && self.is_text_succ(up_branch) {
            up_sym = self.alloc.read_byte_at(up_branch as usize);
            up_succ = up_branch + 1;
        } else {
            up_sym = found_sym;
            up_succ = up_branch;
        }

        // Determine the frequency for the new state.
        let Some(context_span) = self.validated_context(pc) else {
            self.model_fault = true;
            return 0;
        };
        let up_freq;
        let ns_pc = self.span_ctx_num_stats(context_span);
        if ns_pc != 1 {
            let stats = self.span_ctx_stats(context_span);
            let Some(states_span) = self.validated_states(stats, ns_pc as usize) else {
                self.model_fault = true;
                return 0;
            };
            if let Some(state_index) = self.span_find_state(states_span, ns_pc as usize, up_sym) {
                let Some(cf) = self
                    .span_state_freq(states_span, state_index)
                    .checked_sub(1)
                    .map(u32::from)
                else {
                    self.model_fault = true;
                    return 0;
                };
                let s0 = (self.span_ctx_summ_freq(context_span) as u32)
                    .wrapping_sub(ns_pc as u32)
                    .wrapping_sub(cf);
                up_freq = if 2 * cf <= s0 {
                    1 + (if 5 * cf > s0 { 1 } else { 0 })
                } else {
                    (1 + ((2 * cf + 3 * s0 - 1) / (2 * s0))).min(255) as u8
                };
            } else {
                up_freq = 1;
            }
        } else {
            up_freq = self.span_one_freq(context_span);
        }

        // Create child contexts from ps (in reverse order).
        if self.debug_enabled() && (40272337..=40272346).contains(&self.debug_index()) {
            eprintln!(
                "PPMD finish_create_successors: index={} ps_len={} base_pc={} up_sym={} up_succ={} up_freq={}",
                self.debug_index(),
                ps.len(),
                pc,
                up_sym,
                up_succ,
                up_freq
            );
        }
        for &state_span in ps.iter().rev() {
            let child_ref = self.alloc.alloc_context();
            if child_ref.is_null() {
                return 0;
            }
            let child = ref_to_off(child_ref);
            let Some(child_span) = self.validated_context(child) else {
                self.model_fault = true;
                return 0;
            };

            // Initialize as single-state context.
            self.span_set_ctx_num_stats(child_span, 1);
            self.span_set_one_sym(child_span, up_sym);
            self.span_set_one_freq(child_span, up_freq);
            self.span_set_one_succ(child_span, up_succ);
            self.span_set_ctx_suffix(child_span, pc);

            // Update the state's successor to point to this new child.
            self.span_set_state_succ(state_span, 0, child);

            pc = child;
        }

        if self.debug_enabled() && (40272337..=40272346).contains(&self.debug_index()) {
            eprintln!(
                "PPMD finish_create_successors result: index={} new_pc={}",
                self.debug_index(),
                pc
            );
        }

        pc
    }

    /// Find a state with the given symbol in a stats array.
    #[inline(always)]
    fn span_find_state(
        &self,
        states_span: ValidatedArenaSpan,
        ns: usize,
        sym: u8,
    ) -> Option<usize> {
        (0..ns).find(|&index| self.span_state_sym(states_span, index) == sym)
    }

    fn clear_mask(&mut self) {
        self.esc_count = 1;
        self.char_mask = [0; 256];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_creation() {
        let model = Model::new(6, 1024 * 1024);
        assert_ne!(model.min_context, 0);
        assert_ne!(model.max_context, 0);
    }

    #[test]
    fn test_model_restart() {
        let mut model = Model::new(6, 1024 * 1024);
        model.restart();
        assert_ne!(model.min_context, 0);
    }

    #[test]
    fn test_root_has_256_symbols() {
        let model = Model::new(6, 1024 * 1024);
        let ns = model.ctx_num_stats(model.min_context);
        assert_eq!(ns, 256);
    }

    #[test]
    fn test_root_summary_freq() {
        let model = Model::new(6, 1024 * 1024);
        let sf = model.ctx_summ_freq(model.min_context);
        assert_eq!(sf, 257);
    }

    #[test]
    fn test_root_states() {
        let model = Model::new(6, 1024 * 1024);
        let stats = model.ctx_stats(model.min_context);
        // First state: symbol=0, freq=1.
        assert_eq!(model.st_sym(stats), 0);
        assert_eq!(model.st_freq(stats), 1);
        // Last state: symbol=255, freq=1.
        let last = stats + 255 * STATE_SIZE as u32;
        assert_eq!(model.st_sym(last), 255);
        assert_eq!(model.st_freq(last), 1);
    }

    #[test]
    fn test_decode_from_zeros() {
        let mut model = Model::new(6, 1024 * 1024);
        let data = vec![0u8; 256];
        let mut rc = RangeDecoder::new(&data).unwrap();
        // Should decode symbols without crashing. None is valid (escape/end).
        for _ in 0..5 {
            let _ = model.decode_char_result(&mut rc).unwrap();
        }
    }

    #[test]
    fn decode_rejects_context_offset_in_text_region() {
        let mut model = Model::new(6, 1024 * 1024);
        model.min_context = UNIT_SIZE as u32;
        let data = vec![0u8; 256];
        let mut rc = RangeDecoder::new(&data).unwrap();

        let result = model.decode_char_result(&mut rc);

        assert!(matches!(result, Err(RarError::CorruptArchive { .. })));
    }

    #[test]
    fn decode_rejects_stats_offset_in_text_region() {
        let mut model = Model::new(6, 1024 * 1024);
        model.set_ctx_stats(model.min_context, UNIT_SIZE as u32);
        let data = vec![0u8; 256];
        let mut rc = RangeDecoder::new(&data).unwrap();

        let result = model.decode_char_result(&mut rc);

        assert!(matches!(result, Err(RarError::CorruptArchive { .. })));
    }

    #[test]
    fn unmasked_scratch_packing_covers_one_and_256_states() {
        let one = pack_unmasked_state(0, u16::from_le_bytes([17, 23]));
        assert_eq!(unmasked_state_index(one), 0);
        assert_eq!(unmasked_state_symbol(one), 17);
        assert_eq!(unmasked_state_frequency(one), 23);

        let mut scratch = [0u32; 256];
        for (index, slot) in scratch.iter_mut().enumerate() {
            *slot = pack_unmasked_state(index, u16::from_le_bytes([index as u8, 1]));
        }
        let last = scratch[255];
        assert_eq!(unmasked_state_index(last), 255);
        assert_eq!(unmasked_state_symbol(last), 255);
        assert_eq!(unmasked_state_frequency(last), 1);
    }

    #[test]
    fn decode_rejects_zero_state_context() {
        let mut model = Model::new(6, 1024 * 1024);
        let context_span = model.validated_context(model.min_context).unwrap();
        model.span_set_ctx_num_stats(context_span, 0);
        let mut rc = RangeDecoder::new(&[0u8; 256]).unwrap();

        let result = model.decode_char_result(&mut rc);

        assert!(matches!(result, Err(RarError::CorruptArchive { .. })));
    }

    #[test]
    fn decode_rejects_truncated_state_span() {
        let mut model = Model::new(6, 1024 * 1024);
        model.set_ctx_stats(model.min_context, model.alloc.heap_end_bytes() as u32);
        let mut rc = RangeDecoder::new(&[0u8; 256]).unwrap();

        let result = model.decode_char_result(&mut rc);

        assert!(matches!(result, Err(RarError::CorruptArchive { .. })));
    }

    #[test]
    fn decode_rejects_suffix_in_text_region() {
        let mut model = Model::new(6, 1024 * 1024);
        let context_span = model.validated_context(model.min_context).unwrap();
        model.span_set_ctx_num_stats(context_span, 2);
        model.span_set_ctx_summ_freq(context_span, 3);
        model.span_set_ctx_suffix(context_span, UNIT_SIZE as u32);
        let mut rc = RangeDecoder::new(&[0u8; 256]).unwrap();

        let result = model.decode_char_result(&mut rc);

        assert!(matches!(result, Err(RarError::CorruptArchive { .. })));
    }

    #[test]
    fn decode_rejects_invalid_successor_before_dereference() {
        let mut model = Model::new(6, 1024 * 1024);
        let context_span = model.validated_context(model.min_context).unwrap();
        let stats = model.span_ctx_stats(context_span);
        let states_span = model.validated_states(stats, 256).unwrap();
        model.span_set_state_succ(states_span, 0, u32::MAX);
        model.order_fall = 0;
        let mut rc = RangeDecoder::new(&[0u8; 256]).unwrap();

        assert_eq!(model.decode_char_result(&mut rc).unwrap(), Some(0));
        let result = model.decode_char_result(&mut rc);

        assert!(matches!(result, Err(RarError::CorruptArchive { .. })));
    }
}
