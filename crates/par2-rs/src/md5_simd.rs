//! Multi-buffer MD5: compute several *independent* MD5 digests at once by
//! putting one message per SIMD lane.
//!
//! A single MD5 stream is a serial dependency chain — every round feeds the
//! next, so no amount of SIMD widens one message. Multi-buffer sidesteps that:
//! each 32-bit lane of a vector register holds a different message's `a/b/c/d`,
//! and one vector round instruction advances *N* messages at once. PAR2 is a
//! natural fit because a file's per-slice checksums are N independent messages
//! over consecutive, already-resident bytes.
//!
//! Lane widths, selected by ISA only (no per-uarch tuning, no `target-cpu`):
//!
//! | ISA                    | lanes | vector             |
//! |------------------------|-------|--------------------|
//! | x86_64/x86 + AVX2      | 8     | `__m256i`          |
//! | x86_64 (SSE2 baseline) | 4     | `__m128i`          |
//! | aarch64 (NEON baseline)| 4     | `uint32x4_t`       |
//! | wasm32 + simd128       | 4     | `v128`             |
//! | anything else          | 1     | `u32` (scalar)     |
//!
//! Every kernel shares one round schedule (the `md5_block_rounds!` macro), so
//! the scalar fallback is the same arithmetic with a lane count of one rather
//! than a separate implementation that could drift.
//!
//! ## No padded copies
//!
//! The kernel never materializes a padded copy of a message. [`LanePlan`]
//! resolves each 64-byte block to one of four sources:
//!
//! 1. a pointer straight into the caller's buffer (the overwhelming majority),
//! 2. a 64-byte scratch block straddling the end of the real data,
//! 3. a 128-byte scratch holding the final one or two blocks (`0x80`, the
//!    zero run, and the little-endian bit length),
//! 4. a shared all-zero block for PAR2 tail padding and for lanes that have
//!    already finished.
//!
//! Peak scratch is 192 bytes per lane regardless of message size, so hashing a
//! 4 MiB slice costs no allocation and no `memcpy` of the payload.
//!
//! ## Ragged batches
//!
//! Messages in one batch may have different lengths. Lanes run to the longest
//! message's block count; a lane's digest is extracted at the block where that
//! lane finishes and the lane is fed zero blocks afterwards (its state is no
//! longer read). PAR2's own batches are uniform — `pad_to` lifts a short final
//! slice to the full slice size — so the ragged path costs the common case
//! nothing.

#[cfg(test)]
use md5::{Digest, Md5};

// MD5 initial state.
const MD5_A0: u32 = 0x6745_2301;
const MD5_B0: u32 = 0xEFCD_AB89;
const MD5_C0: u32 = 0x98BA_DCFE;
const MD5_D0: u32 = 0x1032_5476;

/// Bytes per MD5 block.
const BLOCK: usize = 64;

/// Blocks held in a lane's tail scratch. The `0x80` terminator sits at byte
/// `effective_len` and the 8-byte length occupies the very end of the final
/// block; those are always within the last two blocks, so two is sufficient.
const TAIL_BLOCKS: usize = 2;

/// Shared source for all-zero blocks: PAR2 tail padding, the zero run inside
/// MD5 padding, and the filler fed to lanes that have already finished.
static ZERO_BLOCK: [u8; BLOCK] = [0u8; BLOCK];

// ---------------------------------------------------------------------------
// Block planning
// ---------------------------------------------------------------------------

/// Where each 64-byte block of one lane's message comes from.
///
/// Built once per message; costs no allocation and copies at most 192 bytes
/// regardless of how long the message is.
struct LanePlan<'a> {
    /// The caller's buffer. Blocks below `data_full_blocks` are read from here
    /// in place.
    data: &'a [u8],
    /// Number of leading blocks that lie entirely inside `data`.
    data_full_blocks: u64,
    /// Block index served by `straddle`, or `u64::MAX` when unused.
    straddle_index: u64,
    /// The block spanning the end of `data`: real bytes then zeros.
    straddle: [u8; BLOCK],
    /// First block index served by `tail`.
    tail_start: u64,
    /// The final one or two blocks, holding `0x80` and the bit length.
    tail: [u8; TAIL_BLOCKS * BLOCK],
    /// Total blocks in the padded message. Blocks at or above this index are
    /// zero filler for a finished lane.
    total_blocks: u64,
}

impl<'a> LanePlan<'a> {
    /// Plan `data`, logically zero-extended to `pad_to` bytes when that is
    /// longer (PAR2 short-final-slice semantics).
    fn new(data: &'a [u8], pad_to: Option<u64>) -> Self {
        let raw = data.len() as u64;
        let effective_len = match pad_to {
            Some(target) if target > raw => target,
            _ => raw,
        };

        // Padded length is `effective_len` + 0x80 + zeros + 8 length bytes,
        // rounded up to a block. `+ 9` covers the terminator and the length.
        let total_blocks = (effective_len + 9).div_ceil(BLOCK as u64);
        let tail_start = total_blocks.saturating_sub(TAIL_BLOCKS as u64);
        let data_full_blocks = raw / BLOCK as u64;

        let mut plan = Self {
            data,
            data_full_blocks,
            straddle_index: u64::MAX,
            straddle: [0u8; BLOCK],
            tail_start,
            tail: [0u8; TAIL_BLOCKS * BLOCK],
            total_blocks,
        };

        // Tail scratch: real bytes that reach into the tail region, then the
        // MD5 terminator and length. Zeros between them are already in place.
        let tail_start_byte = tail_start * BLOCK as u64;
        if raw > tail_start_byte {
            // `raw <= effective_len < total_blocks * BLOCK`, so this copy is
            // bounded by the scratch.
            let from = tail_start_byte as usize;
            let len = data.len() - from;
            plan.tail[..len].copy_from_slice(&data[from..]);
        }
        // `tail_start * BLOCK <= effective_len < total_blocks * BLOCK` holds
        // for every message length, so the terminator lands inside the tail.
        plan.tail[(effective_len - tail_start_byte) as usize] = 0x80;
        let tail_len_blocks = (total_blocks - tail_start) as usize;
        let length_at = tail_len_blocks * BLOCK - 8;
        plan.tail[length_at..length_at + 8].copy_from_slice(&(effective_len * 8).to_le_bytes());

        // Straddle scratch: only needed when the end of the real data falls in
        // a block the tail scratch does not already cover.
        if !raw.is_multiple_of(BLOCK as u64) && data_full_blocks < tail_start {
            let from = (data_full_blocks * BLOCK as u64) as usize;
            let len = data.len() - from;
            plan.straddle[..len].copy_from_slice(&data[from..]);
            plan.straddle_index = data_full_blocks;
        }

        plan
    }

    /// Pointer to the 64 bytes making up block `index`.
    ///
    /// Ordered so the finished/inactive check comes first and the in-place
    /// data read — the case that covers all but a handful of blocks — is next.
    #[inline(always)]
    fn block_ptr(&self, index: u64) -> *const u8 {
        if index >= self.total_blocks {
            return ZERO_BLOCK.as_ptr();
        }
        if index >= self.tail_start {
            let offset = (index - self.tail_start) as usize * BLOCK;
            // In range: `index < total_blocks` and `total_blocks -
            // tail_start <= TAIL_BLOCKS`.
            return unsafe { self.tail.as_ptr().add(offset) };
        }
        if index < self.data_full_blocks {
            // In range: the block lies entirely inside `data`.
            return unsafe { self.data.as_ptr().add(index as usize * BLOCK) };
        }
        if index == self.straddle_index {
            return self.straddle.as_ptr();
        }
        ZERO_BLOCK.as_ptr()
    }

    /// Highest block index below which *every* block of this lane is read
    /// straight out of `data`. Used to hoist pointer resolution out of the
    /// hot loop.
    #[inline(always)]
    fn in_place_blocks(&self) -> u64 {
        self.data_full_blocks.min(self.tail_start)
    }
}

// ---------------------------------------------------------------------------
// Round schedule (shared by every kernel)
// ---------------------------------------------------------------------------

// The four MD5 auxiliary functions, each written as one step of the classic
// unrolled form:
//
//     a = b + rotl(a + F(b, c, d) + K + M, s)
//
// with `(a, b, c, d)` rotated by the caller each round.
//
// Two scheduling rules, both taken from ParPar's `md5-base.h`:
//
// 1. The `K + M` add does not depend on this round's mixing function, so it is
//    issued first. The chain through the state is then
//    `mix -> accumulate -> rotl -> add` rather than carrying an extra add.
// 2. The mixing function and its accumulate into `a` are one ISA-level
//    operation (`acc_f` .. `acc_i`, ParPar's `ADDF`) rather than a fixed
//    `add(a, mix(b, c, d))`. That lets an ISA reassociate the two so the
//    dependency on `b` — the newest and therefore latest-arriving input — is
//    deferred as far as possible, which is the whole game in a
//    latency-bound kernel. See the per-ISA macros for what each one picks.
//
// `splat_i` exists for the same reason: an ISA that computes the I round via
// the `~x = -x - 1` identity folds the resulting `-1` into the round constant.

macro_rules! md5_step_f {
    ($op:ident, $a:ident, $b:ident, $c:ident, $d:ident, $m:expr, $k:expr, $s:literal, $rs:literal) => {
        $a = $op!(add, $a, $op!(add, $op!(splat, $k), $m));
        $a = $op!(acc_f, $a, $b, $c, $d);
        $a = $op!(add, $b, $op!(rotl, $a, $s, $rs));
    };
}

macro_rules! md5_step_g {
    ($op:ident, $a:ident, $b:ident, $c:ident, $d:ident, $m:expr, $k:expr, $s:literal, $rs:literal) => {
        $a = $op!(add, $a, $op!(add, $op!(splat, $k), $m));
        $a = $op!(acc_g, $a, $b, $c, $d);
        $a = $op!(add, $b, $op!(rotl, $a, $s, $rs));
    };
}

macro_rules! md5_step_h {
    ($op:ident, $a:ident, $b:ident, $c:ident, $d:ident, $m:expr, $k:expr, $s:literal, $rs:literal) => {
        $a = $op!(add, $a, $op!(add, $op!(splat, $k), $m));
        $a = $op!(acc_h, $a, $b, $c, $d);
        $a = $op!(add, $b, $op!(rotl, $a, $s, $rs));
    };
}

macro_rules! md5_step_i {
    ($op:ident, $a:ident, $b:ident, $c:ident, $d:ident, $m:expr, $k:expr, $s:literal, $rs:literal) => {
        $a = $op!(add, $a, $op!(add, $op!(splat_i, $k), $m));
        $a = $op!(acc_i, $a, $b, $c, $d);
        $a = $op!(add, $b, $op!(rotl, $a, $s, $rs));
    };
}

/// The 64 MD5 rounds, fully unrolled so every rotate amount and round constant
/// is a compile-time literal. `$op` names an ISA primitive macro; `$m` is a
/// 16-element array of transposed message words.
macro_rules! md5_block_rounds {
    ($op:ident, $a:ident, $b:ident, $c:ident, $d:ident, $m:ident) => {
        md5_step_f!($op, $a, $b, $c, $d, $m[0], 0xd76a_a478u32, 7, 25);
        md5_step_f!($op, $d, $a, $b, $c, $m[1], 0xe8c7_b756u32, 12, 20);
        md5_step_f!($op, $c, $d, $a, $b, $m[2], 0x2420_70dbu32, 17, 15);
        md5_step_f!($op, $b, $c, $d, $a, $m[3], 0xc1bd_ceeeu32, 22, 10);
        md5_step_f!($op, $a, $b, $c, $d, $m[4], 0xf57c_0fafu32, 7, 25);
        md5_step_f!($op, $d, $a, $b, $c, $m[5], 0x4787_c62au32, 12, 20);
        md5_step_f!($op, $c, $d, $a, $b, $m[6], 0xa830_4613u32, 17, 15);
        md5_step_f!($op, $b, $c, $d, $a, $m[7], 0xfd46_9501u32, 22, 10);
        md5_step_f!($op, $a, $b, $c, $d, $m[8], 0x6980_98d8u32, 7, 25);
        md5_step_f!($op, $d, $a, $b, $c, $m[9], 0x8b44_f7afu32, 12, 20);
        md5_step_f!($op, $c, $d, $a, $b, $m[10], 0xffff_5bb1u32, 17, 15);
        md5_step_f!($op, $b, $c, $d, $a, $m[11], 0x895c_d7beu32, 22, 10);
        md5_step_f!($op, $a, $b, $c, $d, $m[12], 0x6b90_1122u32, 7, 25);
        md5_step_f!($op, $d, $a, $b, $c, $m[13], 0xfd98_7193u32, 12, 20);
        md5_step_f!($op, $c, $d, $a, $b, $m[14], 0xa679_438eu32, 17, 15);
        md5_step_f!($op, $b, $c, $d, $a, $m[15], 0x49b4_0821u32, 22, 10);

        md5_step_g!($op, $a, $b, $c, $d, $m[1], 0xf61e_2562u32, 5, 27);
        md5_step_g!($op, $d, $a, $b, $c, $m[6], 0xc040_b340u32, 9, 23);
        md5_step_g!($op, $c, $d, $a, $b, $m[11], 0x265e_5a51u32, 14, 18);
        md5_step_g!($op, $b, $c, $d, $a, $m[0], 0xe9b6_c7aau32, 20, 12);
        md5_step_g!($op, $a, $b, $c, $d, $m[5], 0xd62f_105du32, 5, 27);
        md5_step_g!($op, $d, $a, $b, $c, $m[10], 0x0244_1453u32, 9, 23);
        md5_step_g!($op, $c, $d, $a, $b, $m[15], 0xd8a1_e681u32, 14, 18);
        md5_step_g!($op, $b, $c, $d, $a, $m[4], 0xe7d3_fbc8u32, 20, 12);
        md5_step_g!($op, $a, $b, $c, $d, $m[9], 0x21e1_cde6u32, 5, 27);
        md5_step_g!($op, $d, $a, $b, $c, $m[14], 0xc337_07d6u32, 9, 23);
        md5_step_g!($op, $c, $d, $a, $b, $m[3], 0xf4d5_0d87u32, 14, 18);
        md5_step_g!($op, $b, $c, $d, $a, $m[8], 0x455a_14edu32, 20, 12);
        md5_step_g!($op, $a, $b, $c, $d, $m[13], 0xa9e3_e905u32, 5, 27);
        md5_step_g!($op, $d, $a, $b, $c, $m[2], 0xfcef_a3f8u32, 9, 23);
        md5_step_g!($op, $c, $d, $a, $b, $m[7], 0x676f_02d9u32, 14, 18);
        md5_step_g!($op, $b, $c, $d, $a, $m[12], 0x8d2a_4c8au32, 20, 12);

        md5_step_h!($op, $a, $b, $c, $d, $m[5], 0xfffa_3942u32, 4, 28);
        md5_step_h!($op, $d, $a, $b, $c, $m[8], 0x8771_f681u32, 11, 21);
        md5_step_h!($op, $c, $d, $a, $b, $m[11], 0x6d9d_6122u32, 16, 16);
        md5_step_h!($op, $b, $c, $d, $a, $m[14], 0xfde5_380cu32, 23, 9);
        md5_step_h!($op, $a, $b, $c, $d, $m[1], 0xa4be_ea44u32, 4, 28);
        md5_step_h!($op, $d, $a, $b, $c, $m[4], 0x4bde_cfa9u32, 11, 21);
        md5_step_h!($op, $c, $d, $a, $b, $m[7], 0xf6bb_4b60u32, 16, 16);
        md5_step_h!($op, $b, $c, $d, $a, $m[10], 0xbebf_bc70u32, 23, 9);
        md5_step_h!($op, $a, $b, $c, $d, $m[13], 0x289b_7ec6u32, 4, 28);
        md5_step_h!($op, $d, $a, $b, $c, $m[0], 0xeaa1_27fau32, 11, 21);
        md5_step_h!($op, $c, $d, $a, $b, $m[3], 0xd4ef_3085u32, 16, 16);
        md5_step_h!($op, $b, $c, $d, $a, $m[6], 0x0488_1d05u32, 23, 9);
        md5_step_h!($op, $a, $b, $c, $d, $m[9], 0xd9d4_d039u32, 4, 28);
        md5_step_h!($op, $d, $a, $b, $c, $m[12], 0xe6db_99e5u32, 11, 21);
        md5_step_h!($op, $c, $d, $a, $b, $m[15], 0x1fa2_7cf8u32, 16, 16);
        md5_step_h!($op, $b, $c, $d, $a, $m[2], 0xc4ac_5665u32, 23, 9);

        md5_step_i!($op, $a, $b, $c, $d, $m[0], 0xf429_2244u32, 6, 26);
        md5_step_i!($op, $d, $a, $b, $c, $m[7], 0x432a_ff97u32, 10, 22);
        md5_step_i!($op, $c, $d, $a, $b, $m[14], 0xab94_23a7u32, 15, 17);
        md5_step_i!($op, $b, $c, $d, $a, $m[5], 0xfc93_a039u32, 21, 11);
        md5_step_i!($op, $a, $b, $c, $d, $m[12], 0x655b_59c3u32, 6, 26);
        md5_step_i!($op, $d, $a, $b, $c, $m[3], 0x8f0c_cc92u32, 10, 22);
        md5_step_i!($op, $c, $d, $a, $b, $m[10], 0xffef_f47du32, 15, 17);
        md5_step_i!($op, $b, $c, $d, $a, $m[1], 0x8584_5dd1u32, 21, 11);
        md5_step_i!($op, $a, $b, $c, $d, $m[8], 0x6fa8_7e4fu32, 6, 26);
        md5_step_i!($op, $d, $a, $b, $c, $m[15], 0xfe2c_e6e0u32, 10, 22);
        md5_step_i!($op, $c, $d, $a, $b, $m[6], 0xa301_4314u32, 15, 17);
        md5_step_i!($op, $b, $c, $d, $a, $m[13], 0x4e08_11a1u32, 21, 11);
        md5_step_i!($op, $a, $b, $c, $d, $m[4], 0xf753_7e82u32, 6, 26);
        md5_step_i!($op, $d, $a, $b, $c, $m[11], 0xbd3a_f235u32, 10, 22);
        md5_step_i!($op, $c, $d, $a, $b, $m[2], 0x2ad7_d2bbu32, 15, 17);
        md5_step_i!($op, $b, $c, $d, $a, $m[9], 0xeb86_d391u32, 21, 11);
    };
}

// ---------------------------------------------------------------------------
// Kernel driver (shared by every kernel)
// ---------------------------------------------------------------------------

/// Generates a multi-buffer kernel for one ISA.
///
/// `$op` names the primitive macro (`add`/`splat`/`f`/`g`/`h`/`i`/`rotl`/
/// `zero`/`store`), `$load` the block-load-and-transpose macro, and `$lanes`
/// the lane count. Everything else — block planning, the ragged-tail
/// bookkeeping, digest extraction — is identical across ISAs and lives here.
macro_rules! md5_multi_kernel {
    ($name:ident, $vec:ty, $lanes:expr, $op:ident, $load:ident $(, $feature:literal)?) => {
        $(#[target_feature(enable = $feature)])?
        unsafe fn $name(plans: &[LanePlan<'_>], out: &mut [[u8; 16]]) {
            const LANES: usize = $lanes;
            debug_assert!(plans.len() <= LANES);
            debug_assert_eq!(plans.len(), out.len());

            if plans.is_empty() {
                return;
            }

            let max_blocks = plans
                .iter()
                .map(|plan| plan.total_blocks)
                .max()
                .unwrap_or(0);
            let min_blocks = plans
                .iter()
                .map(|plan| plan.total_blocks)
                .min()
                .unwrap_or(0);
            // Below this index every lane reads in place, so the pointer
            // resolution collapses to a single add per lane.
            let in_place_blocks = plans
                .iter()
                .map(|plan| plan.in_place_blocks())
                .min()
                .unwrap_or(0);

            unsafe {
                let mut a = $op!(splat, MD5_A0);
                let mut b = $op!(splat, MD5_B0);
                let mut c = $op!(splat, MD5_C0);
                let mut d = $op!(splat, MD5_D0);

                // A batch narrower than the vector leaves the spare slots
                // pointing at the shared zero block for the whole run: they
                // are hashed alongside the rest but never extracted.
                let mut ptrs: [*const u8; LANES] = [ZERO_BLOCK.as_ptr(); LANES];

                for index in 0..max_blocks {
                    if index < in_place_blocks {
                        let offset = index as usize * BLOCK;
                        for (slot, plan) in ptrs.iter_mut().zip(plans) {
                            *slot = plan.data.as_ptr().add(offset);
                        }
                    } else {
                        for (slot, plan) in ptrs.iter_mut().zip(plans) {
                            *slot = plan.block_ptr(index);
                        }
                    }

                    let m: [$vec; 16] = $load!(ptrs);

                    let (oa, ob, oc, od) = (a, b, c, d);
                    md5_block_rounds!($op, a, b, c, d, m);
                    a = $op!(add, a, oa);
                    b = $op!(add, b, ob);
                    c = $op!(add, c, oc);
                    d = $op!(add, d, od);

                    // No lane can finish before `min_blocks`, so the common
                    // case is one predictable branch per block.
                    if index + 1 >= min_blocks {
                        let mut aw = [0u32; LANES];
                        let mut bw = [0u32; LANES];
                        let mut cw = [0u32; LANES];
                        let mut dw = [0u32; LANES];
                        let mut extracted = false;
                        for (lane, plan) in plans.iter().enumerate() {
                            if plan.total_blocks != index + 1 {
                                continue;
                            }
                            if !extracted {
                                $op!(store, a, aw);
                                $op!(store, b, bw);
                                $op!(store, c, cw);
                                $op!(store, d, dw);
                                extracted = true;
                            }
                            out[lane][0..4].copy_from_slice(&aw[lane].to_le_bytes());
                            out[lane][4..8].copy_from_slice(&bw[lane].to_le_bytes());
                            out[lane][8..12].copy_from_slice(&cw[lane].to_le_bytes());
                            out[lane][12..16].copy_from_slice(&dw[lane].to_le_bytes());
                        }
                    }
                }
            }
        }
    };
}

// ---------------------------------------------------------------------------
// Scalar kernel (also the wasm baseline and the differential-test oracle)
// ---------------------------------------------------------------------------

macro_rules! scalar_op {
    (add, $x:expr, $y:expr) => {
        $x.wrapping_add($y)
    };
    (splat, $k:expr) => {
        $k as u32
    };
    (splat_i, $k:expr) => {
        $k as u32
    };
    // Textbook forms: a scalar core has no bit-select and reassociating buys
    // nothing against a 1-cycle ALU, so this arm stays the plain definition
    // and doubles as the differential oracle for the vector rewrites.
    (acc_f, $a:expr, $b:expr, $c:expr, $d:expr) => {
        $a.wrapping_add(($b & $c) | (!$b & $d))
    };
    (acc_g, $a:expr, $b:expr, $c:expr, $d:expr) => {
        $a.wrapping_add(($d & $b) | (!$d & $c))
    };
    (acc_h, $a:expr, $b:expr, $c:expr, $d:expr) => {
        $a.wrapping_add($b ^ $c ^ $d)
    };
    (acc_i, $a:expr, $b:expr, $c:expr, $d:expr) => {
        $a.wrapping_add($c ^ ($b | !$d))
    };
    (rotl, $v:expr, $s:literal, $rs:literal) => {
        $v.rotate_left($s)
    };
    (store, $v:expr, $dst:expr) => {
        $dst[0] = $v
    };
}

macro_rules! scalar_load {
    ($ptrs:expr) => {{
        let mut words = [0u32; 16];
        let base = $ptrs[0];
        for (word, slot) in words.iter_mut().enumerate() {
            let mut bytes = [0u8; 4];
            std::ptr::copy_nonoverlapping(base.add(word * 4), bytes.as_mut_ptr(), 4);
            *slot = u32::from_le_bytes(bytes);
        }
        words
    }};
}

md5_multi_kernel!(md5_multi_scalar_kernel, u32, 1, scalar_op, scalar_load);

// ---------------------------------------------------------------------------
// aarch64 NEON kernel: 4 lanes in uint32x4_t
// ---------------------------------------------------------------------------

#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
macro_rules! neon_op {
    (add, $x:expr, $y:expr) => {
        std::arch::aarch64::vaddq_u32($x, $y)
    };
    (splat, $k:expr) => {
        std::arch::aarch64::vdupq_n_u32($k as u32)
    };
    (splat_i, $k:expr) => {
        std::arch::aarch64::vdupq_n_u32($k as u32)
    };
    // NEON has a real bit-select, so F and G are one instruction each and no
    // reassociation is worth doing. BSL selects on its first operand:
    // `vbslq_u32(m, x, y)` is `(m & x) | (~m & y)`. F is that with `m = b`;
    // G is the same function with the arguments rotated (`m = d`).
    (acc_f, $a:expr, $b:expr, $c:expr, $d:expr) => {
        std::arch::aarch64::vaddq_u32($a, std::arch::aarch64::vbslq_u32($b, $c, $d))
    };
    (acc_g, $a:expr, $b:expr, $c:expr, $d:expr) => {
        std::arch::aarch64::vaddq_u32($a, std::arch::aarch64::vbslq_u32($d, $b, $c))
    };
    (acc_h, $a:expr, $b:expr, $c:expr, $d:expr) => {
        std::arch::aarch64::vaddq_u32(
            $a,
            std::arch::aarch64::veorq_u32(std::arch::aarch64::veorq_u32($c, $d), $b),
        )
    };
    // ORN gives `b | ~d` in one instruction, so I costs two. ParPar carries a
    // `-1`/BSL variant here but has it commented out as measuring worse than
    // ORN on NEON, so this follows their shipped choice.
    (acc_i, $a:expr, $b:expr, $c:expr, $d:expr) => {
        std::arch::aarch64::vaddq_u32(
            $a,
            std::arch::aarch64::veorq_u32($c, std::arch::aarch64::vornq_u32($b, $d)),
        )
    };
    // A 16-bit rotate of a 32-bit lane is a halfword reverse: one instruction
    // instead of two. MD5 uses s=16 four times per block.
    (rotl, $v:expr, 16, 16) => {
        std::arch::aarch64::vreinterpretq_u32_u16(std::arch::aarch64::vrev32q_u16(
            std::arch::aarch64::vreinterpretq_u16_u32($v),
        ))
    };
    // SHL then SRI (shift-right-and-insert) rotates in two instructions
    // instead of the three a shift/shift/or triple would need.
    (rotl, $v:expr, $s:literal, $rs:literal) => {
        std::arch::aarch64::vsriq_n_u32::<$rs>(std::arch::aarch64::vshlq_n_u32::<$s>($v), $v)
    };
    (store, $v:expr, $dst:expr) => {
        std::arch::aarch64::vst1q_u32($dst.as_mut_ptr(), $v)
    };
}

/// Load one block from each of four lanes and transpose 4x4 word groups so
/// lane `l`'s word `w` lands in element `l` of `m[w]`.
#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
macro_rules! neon_load {
    ($ptrs:expr) => {{
        use std::arch::aarch64::*;
        let mut m = [vdupq_n_u32(0); 16];
        for group in 0..4 {
            let offset = group * 16;
            let r0 = vld1q_u32($ptrs[0].add(offset) as *const u32);
            let r1 = vld1q_u32($ptrs[1].add(offset) as *const u32);
            let r2 = vld1q_u32($ptrs[2].add(offset) as *const u32);
            let r3 = vld1q_u32($ptrs[3].add(offset) as *const u32);

            let t0 = vreinterpretq_u64_u32(vzip1q_u32(r0, r1));
            let t1 = vreinterpretq_u64_u32(vzip2q_u32(r0, r1));
            let t2 = vreinterpretq_u64_u32(vzip1q_u32(r2, r3));
            let t3 = vreinterpretq_u64_u32(vzip2q_u32(r2, r3));

            m[group * 4] = vreinterpretq_u32_u64(vzip1q_u64(t0, t2));
            m[group * 4 + 1] = vreinterpretq_u32_u64(vzip2q_u64(t0, t2));
            m[group * 4 + 2] = vreinterpretq_u32_u64(vzip1q_u64(t1, t3));
            m[group * 4 + 3] = vreinterpretq_u32_u64(vzip2q_u64(t1, t3));
        }
        m
    }};
}

#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
md5_multi_kernel!(
    md5_multi_neon,
    std::arch::aarch64::uint32x4_t,
    4,
    neon_op,
    neon_load,
    "neon"
);

// ---------------------------------------------------------------------------
// x86 SSE2 kernel: 4 lanes in __m128i
// ---------------------------------------------------------------------------

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_endian = "little"
))]
macro_rules! sse2_op {
    (add, $x:expr, $y:expr) => {
        crate::md5_simd::x86_arch::_mm_add_epi32($x, $y)
    };
    (splat, $k:expr) => {
        crate::md5_simd::x86_arch::_mm_set1_epi32($k as u32 as i32)
    };
    (splat_i, $k:expr) => {
        crate::md5_simd::x86_arch::_mm_set1_epi32($k as u32 as i32)
    };
    // F as `((c ^ d) & b) ^ d`. Same three operations as the OR form, but
    // `c ^ d` does not involve `b`, so only two of them sit on the chain from
    // `b` instead of the OR form's `and`/`andnot` pair plus `or`.
    (acc_f, $a:expr, $b:expr, $c:expr, $d:expr) => {
        crate::md5_simd::x86_arch::_mm_add_epi32(
            $a,
            crate::md5_simd::x86_arch::_mm_xor_si128(
                crate::md5_simd::x86_arch::_mm_and_si128(
                    crate::md5_simd::x86_arch::_mm_xor_si128($c, $d),
                    $b,
                ),
                $d,
            ),
        )
    };
    // G's two terms `(~d & c)` and `(d & b)` are disjoint, so the OR is an
    // ADD, which lets the accumulate be split: fold `~d & c` into `a` first
    // and add the `b`-dependent term last. Two operations from `b`.
    (acc_g, $a:expr, $b:expr, $c:expr, $d:expr) => {
        crate::md5_simd::x86_arch::_mm_add_epi32(
            crate::md5_simd::x86_arch::_mm_add_epi32(
                $a,
                crate::md5_simd::x86_arch::_mm_andnot_si128($d, $c),
            ),
            crate::md5_simd::x86_arch::_mm_and_si128($d, $b),
        )
    };
    (acc_h, $a:expr, $b:expr, $c:expr, $d:expr) => {
        crate::md5_simd::x86_arch::_mm_add_epi32(
            $a,
            crate::md5_simd::x86_arch::_mm_xor_si128(
                crate::md5_simd::x86_arch::_mm_xor_si128($c, $d),
                $b,
            ),
        )
    };
    // `andnot(d, ones)` is `~d`; SSE2 has no ORN. The `~x = -x - 1` identity
    // the AVX2 arm uses is deliberately not applied here: without VEX's
    // three-operand encoding, its PANDN forces `b` to be copied, which
    // lengthens exactly the chain the rewrite is meant to shorten.
    (acc_i, $a:expr, $b:expr, $c:expr, $d:expr) => {
        crate::md5_simd::x86_arch::_mm_add_epi32(
            $a,
            crate::md5_simd::x86_arch::_mm_xor_si128(
                $c,
                crate::md5_simd::x86_arch::_mm_or_si128(
                    $b,
                    crate::md5_simd::x86_arch::_mm_andnot_si128(
                        $d,
                        crate::md5_simd::x86_arch::_mm_set1_epi32(-1),
                    ),
                ),
            ),
        )
    };
    // Rotating a 32-bit lane by 16 is a halfword swap: two shuffles, no
    // shift/shift/or triple and no extra temporary.
    (rotl, $v:expr, 16, 16) => {
        crate::md5_simd::x86_arch::_mm_shufflehi_epi16::<0b10_11_00_01>(
            crate::md5_simd::x86_arch::_mm_shufflelo_epi16::<0b10_11_00_01>($v),
        )
    };
    (rotl, $v:expr, $s:literal, $rs:literal) => {
        crate::md5_simd::x86_arch::_mm_or_si128(
            crate::md5_simd::x86_arch::_mm_slli_epi32::<$s>($v),
            crate::md5_simd::x86_arch::_mm_srli_epi32::<$rs>($v),
        )
    };
    (store, $v:expr, $dst:expr) => {
        crate::md5_simd::x86_arch::_mm_storeu_si128($dst.as_mut_ptr().cast(), $v)
    };
}

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_endian = "little"
))]
macro_rules! sse2_load {
    ($ptrs:expr) => {{
        use crate::md5_simd::x86_arch::*;
        let mut m = [_mm_setzero_si128(); 16];
        for group in 0..4 {
            let offset = group * 16;
            let r0 = _mm_loadu_si128($ptrs[0].add(offset).cast());
            let r1 = _mm_loadu_si128($ptrs[1].add(offset).cast());
            let r2 = _mm_loadu_si128($ptrs[2].add(offset).cast());
            let r3 = _mm_loadu_si128($ptrs[3].add(offset).cast());

            let t0 = _mm_unpacklo_epi32(r0, r1);
            let t1 = _mm_unpackhi_epi32(r0, r1);
            let t2 = _mm_unpacklo_epi32(r2, r3);
            let t3 = _mm_unpackhi_epi32(r2, r3);

            m[group * 4] = _mm_unpacklo_epi64(t0, t2);
            m[group * 4 + 1] = _mm_unpackhi_epi64(t0, t2);
            m[group * 4 + 2] = _mm_unpacklo_epi64(t1, t3);
            m[group * 4 + 3] = _mm_unpackhi_epi64(t1, t3);
        }
        m
    }};
}

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_endian = "little"
))]
md5_multi_kernel!(
    md5_multi_sse2,
    crate::md5_simd::x86_arch::__m128i,
    4,
    sse2_op,
    sse2_load,
    "sse2"
);

// ---------------------------------------------------------------------------
// x86 AVX2 kernel: 8 lanes in __m256i
// ---------------------------------------------------------------------------

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_endian = "little"
))]
macro_rules! avx2_op {
    (add, $x:expr, $y:expr) => {
        crate::md5_simd::x86_arch::_mm256_add_epi32($x, $y)
    };
    (splat, $k:expr) => {
        crate::md5_simd::x86_arch::_mm256_set1_epi32($k as u32 as i32)
    };
    // The I rounds below compute `~(c ^ (~b & d))` as `-(c ^ (~b & d)) - 1`
    // and subtract instead of adding, so the `-1` is folded into the round
    // constant here and costs nothing at run time.
    (splat_i, $k:expr) => {
        crate::md5_simd::x86_arch::_mm256_set1_epi32(($k as u32).wrapping_sub(1) as i32)
    };
    // Same rewrites as the SSE2 arm; see there for why each form is chosen.
    (acc_f, $a:expr, $b:expr, $c:expr, $d:expr) => {
        crate::md5_simd::x86_arch::_mm256_add_epi32(
            $a,
            crate::md5_simd::x86_arch::_mm256_xor_si256(
                crate::md5_simd::x86_arch::_mm256_and_si256(
                    crate::md5_simd::x86_arch::_mm256_xor_si256($c, $d),
                    $b,
                ),
                $d,
            ),
        )
    };
    (acc_g, $a:expr, $b:expr, $c:expr, $d:expr) => {
        crate::md5_simd::x86_arch::_mm256_add_epi32(
            crate::md5_simd::x86_arch::_mm256_add_epi32(
                $a,
                crate::md5_simd::x86_arch::_mm256_andnot_si256($d, $c),
            ),
            crate::md5_simd::x86_arch::_mm256_and_si256($d, $b),
        )
    };
    (acc_h, $a:expr, $b:expr, $c:expr, $d:expr) => {
        crate::md5_simd::x86_arch::_mm256_add_epi32(
            $a,
            crate::md5_simd::x86_arch::_mm256_xor_si256(
                crate::md5_simd::x86_arch::_mm256_xor_si256($c, $d),
                $b,
            ),
        )
    };
    // `c ^ (b | ~d)` is `~(c ^ (~b & d))`, and `~x` is `-x - 1`. VEX's
    // three-operand encoding means the VPANDN needs no copy of `b`, so unlike
    // SSE2 this form is a straight win: it drops the all-ones register and one
    // operation, with the `-1` already folded into `splat_i`.
    (acc_i, $a:expr, $b:expr, $c:expr, $d:expr) => {
        crate::md5_simd::x86_arch::_mm256_sub_epi32(
            $a,
            crate::md5_simd::x86_arch::_mm256_xor_si256(
                $c,
                crate::md5_simd::x86_arch::_mm256_andnot_si256($b, $d),
            ),
        )
    };
    // A 16-bit rotate is a halfword swap, which VPSHUFB does in one
    // instruction (the control repeats across both 128-bit halves).
    (rotl, $v:expr, 16, 16) => {
        crate::md5_simd::x86_arch::_mm256_shuffle_epi8(
            $v,
            crate::md5_simd::x86_arch::_mm256_setr_epi8(
                2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13, 2, 3, 0, 1, 6, 7, 4, 5, 10,
                11, 8, 9, 14, 15, 12, 13,
            ),
        )
    };
    (rotl, $v:expr, $s:literal, $rs:literal) => {
        crate::md5_simd::x86_arch::_mm256_or_si256(
            crate::md5_simd::x86_arch::_mm256_slli_epi32::<$s>($v),
            crate::md5_simd::x86_arch::_mm256_srli_epi32::<$rs>($v),
        )
    };
    (store, $v:expr, $dst:expr) => {
        crate::md5_simd::x86_arch::_mm256_storeu_si256($dst.as_mut_ptr().cast(), $v)
    };
}

/// Load one block from each of eight lanes and transpose two 8x8 word groups.
#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_endian = "little"
))]
macro_rules! avx2_load {
    ($ptrs:expr) => {{
        use crate::md5_simd::x86_arch::*;
        let mut m = [_mm256_setzero_si256(); 16];
        for group in 0..2 {
            let offset = group * 32;
            let r0 = _mm256_loadu_si256($ptrs[0].add(offset).cast());
            let r1 = _mm256_loadu_si256($ptrs[1].add(offset).cast());
            let r2 = _mm256_loadu_si256($ptrs[2].add(offset).cast());
            let r3 = _mm256_loadu_si256($ptrs[3].add(offset).cast());
            let r4 = _mm256_loadu_si256($ptrs[4].add(offset).cast());
            let r5 = _mm256_loadu_si256($ptrs[5].add(offset).cast());
            let r6 = _mm256_loadu_si256($ptrs[6].add(offset).cast());
            let r7 = _mm256_loadu_si256($ptrs[7].add(offset).cast());

            let t0 = _mm256_unpacklo_epi32(r0, r1);
            let t1 = _mm256_unpackhi_epi32(r0, r1);
            let t2 = _mm256_unpacklo_epi32(r2, r3);
            let t3 = _mm256_unpackhi_epi32(r2, r3);
            let t4 = _mm256_unpacklo_epi32(r4, r5);
            let t5 = _mm256_unpackhi_epi32(r4, r5);
            let t6 = _mm256_unpacklo_epi32(r6, r7);
            let t7 = _mm256_unpackhi_epi32(r6, r7);

            let s0 = _mm256_unpacklo_epi64(t0, t2);
            let s1 = _mm256_unpackhi_epi64(t0, t2);
            let s2 = _mm256_unpacklo_epi64(t1, t3);
            let s3 = _mm256_unpackhi_epi64(t1, t3);
            let s4 = _mm256_unpacklo_epi64(t4, t6);
            let s5 = _mm256_unpackhi_epi64(t4, t6);
            let s6 = _mm256_unpacklo_epi64(t5, t7);
            let s7 = _mm256_unpackhi_epi64(t5, t7);

            let base = group * 8;
            m[base] = _mm256_permute2x128_si256::<0x20>(s0, s4);
            m[base + 1] = _mm256_permute2x128_si256::<0x20>(s1, s5);
            m[base + 2] = _mm256_permute2x128_si256::<0x20>(s2, s6);
            m[base + 3] = _mm256_permute2x128_si256::<0x20>(s3, s7);
            m[base + 4] = _mm256_permute2x128_si256::<0x31>(s0, s4);
            m[base + 5] = _mm256_permute2x128_si256::<0x31>(s1, s5);
            m[base + 6] = _mm256_permute2x128_si256::<0x31>(s2, s6);
            m[base + 7] = _mm256_permute2x128_si256::<0x31>(s3, s7);
        }
        m
    }};
}

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_endian = "little"
))]
md5_multi_kernel!(
    md5_multi_avx2,
    crate::md5_simd::x86_arch::__m256i,
    8,
    avx2_op,
    avx2_load,
    "avx2"
);

/// One import path for both x86 widths so the kernel macros do not need to
/// repeat the `x86` / `x86_64` split at every intrinsic.
#[cfg(all(target_arch = "x86", target_endian = "little"))]
pub(crate) use std::arch::x86 as x86_arch;
#[cfg(all(target_arch = "x86_64", target_endian = "little"))]
pub(crate) use std::arch::x86_64 as x86_arch;

// ---------------------------------------------------------------------------
// wasm32 simd128 kernel: 4 lanes in v128
// ---------------------------------------------------------------------------
//
// wasm has no runtime feature detection, so this arm is selected at compile
// time by `target_feature = "simd128"` exactly as the GF(2^16) kernels are.
// The portable wasm build keeps the scalar kernel.

#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
macro_rules! simd128_op {
    (add, $x:expr, $y:expr) => {
        std::arch::wasm32::u32x4_add($x, $y)
    };
    (splat, $k:expr) => {
        std::arch::wasm32::u32x4_splat($k as u32)
    };
    (splat_i, $k:expr) => {
        std::arch::wasm32::u32x4_splat($k as u32)
    };
    // simd128 has a bit-select, so F and G cost one operation each, as on
    // NEON. `v128_bitselect(x, y, m)` is `(m & x) | (~m & y)`.
    (acc_f, $a:expr, $b:expr, $c:expr, $d:expr) => {
        std::arch::wasm32::u32x4_add($a, std::arch::wasm32::v128_bitselect($c, $d, $b))
    };
    (acc_g, $a:expr, $b:expr, $c:expr, $d:expr) => {
        std::arch::wasm32::u32x4_add($a, std::arch::wasm32::v128_bitselect($b, $c, $d))
    };
    (acc_h, $a:expr, $b:expr, $c:expr, $d:expr) => {
        std::arch::wasm32::u32x4_add(
            $a,
            std::arch::wasm32::v128_xor(std::arch::wasm32::v128_xor($c, $d), $b),
        )
    };
    (acc_i, $a:expr, $b:expr, $c:expr, $d:expr) => {
        std::arch::wasm32::u32x4_add(
            $a,
            std::arch::wasm32::v128_xor(
                $c,
                std::arch::wasm32::v128_or($b, std::arch::wasm32::v128_not($d)),
            ),
        )
    };
    (rotl, $v:expr, $s:literal, $rs:literal) => {
        std::arch::wasm32::v128_or(
            std::arch::wasm32::u32x4_shl($v, $s),
            std::arch::wasm32::u32x4_shr($v, $rs),
        )
    };
    (store, $v:expr, $dst:expr) => {
        std::arch::wasm32::v128_store($dst.as_mut_ptr().cast(), $v)
    };
}

#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
macro_rules! simd128_load {
    ($ptrs:expr) => {{
        use std::arch::wasm32::*;
        let mut m = [u32x4_splat(0); 16];
        for group in 0..4 {
            let offset = group * 16;
            let r0 = v128_load($ptrs[0].add(offset).cast());
            let r1 = v128_load($ptrs[1].add(offset).cast());
            let r2 = v128_load($ptrs[2].add(offset).cast());
            let r3 = v128_load($ptrs[3].add(offset).cast());

            let t0 = u32x4_shuffle::<0, 4, 1, 5>(r0, r1);
            let t1 = u32x4_shuffle::<2, 6, 3, 7>(r0, r1);
            let t2 = u32x4_shuffle::<0, 4, 1, 5>(r2, r3);
            let t3 = u32x4_shuffle::<2, 6, 3, 7>(r2, r3);

            m[group * 4] = u32x4_shuffle::<0, 1, 4, 5>(t0, t2);
            m[group * 4 + 1] = u32x4_shuffle::<2, 3, 6, 7>(t0, t2);
            m[group * 4 + 2] = u32x4_shuffle::<0, 1, 4, 5>(t1, t3);
            m[group * 4 + 3] = u32x4_shuffle::<2, 3, 6, 7>(t1, t3);
        }
        m
    }};
}

#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
md5_multi_kernel!(
    md5_multi_simd128,
    std::arch::wasm32::v128,
    4,
    simd128_op,
    simd128_load,
    "simd128"
);

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// How many independent messages the active kernel hashes per pass.
///
/// Callers should size their batches by this so a wider host is used fully.
/// Detection is per-ISA only and is cached after the first call.
pub fn max_lanes() -> usize {
    #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_endian = "little"
    ))]
    {
        if avx2_available() {
            return 8;
        }
        #[cfg(target_arch = "x86_64")]
        {
            // SSE2 is part of the x86_64 baseline.
            return 4;
        }
        #[cfg(target_arch = "x86")]
        {
            if std::is_x86_feature_detected!("sse2") {
                return 4;
            }
        }
    }

    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
    {
        // NEON is part of the aarch64 baseline.
        return 4;
    }

    #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
    {
        return 4;
    }

    #[allow(unreachable_code)]
    1
}

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_endian = "little"
))]
fn avx2_available() -> bool {
    static AVX2: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *AVX2.get_or_init(|| std::is_x86_feature_detected!("avx2"))
}

/// Hash one batch of at most [`max_lanes`] messages.
fn md5_batch(plans: &[LanePlan<'_>], out: &mut [[u8; 16]]) {
    #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_endian = "little"
    ))]
    {
        if plans.len() > 4 {
            if avx2_available() {
                unsafe { md5_multi_avx2(plans, out) };
                return;
            }
            // Wider batch than the SSE2 kernel takes: split it.
            let (head_plans, tail_plans) = plans.split_at(4);
            let (head_out, tail_out) = out.split_at_mut(4);
            md5_batch(head_plans, head_out);
            md5_batch(tail_plans, tail_out);
            return;
        }
        #[cfg(target_arch = "x86_64")]
        {
            unsafe { md5_multi_sse2(plans, out) };
            return;
        }
        #[cfg(target_arch = "x86")]
        {
            if std::is_x86_feature_detected!("sse2") {
                unsafe { md5_multi_sse2(plans, out) };
                return;
            }
        }
    }

    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
    {
        unsafe { md5_multi_neon(plans, out) };
        return;
    }

    #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
    {
        unsafe { md5_multi_simd128(plans, out) };
        return;
    }

    #[allow(unreachable_code)]
    md5_batch_scalar(plans, out);
}

/// One message per pass through the shared round schedule.
#[cfg_attr(
    any(
        all(
            any(target_arch = "x86", target_arch = "x86_64"),
            target_endian = "little"
        ),
        all(target_arch = "aarch64", target_endian = "little"),
        all(target_arch = "wasm32", target_feature = "simd128"),
    ),
    allow(dead_code)
)]
fn md5_batch_scalar(plans: &[LanePlan<'_>], out: &mut [[u8; 16]]) {
    for (plan, digest) in plans.iter().zip(out.iter_mut()) {
        unsafe {
            md5_multi_scalar_kernel(std::slice::from_ref(plan), std::slice::from_mut(digest));
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Compute the MD5 of every input, hashing [`max_lanes`] of them at a time.
///
/// Each input is an independent message. When `pad_to` is `Some(n)`, every
/// input shorter than `n` is logically zero-extended to `n` bytes before
/// finalizing — PAR2's short-final-slice rule — without materializing the
/// padding. Inputs may have different lengths.
///
/// Returns one digest per input, in order.
pub fn md5_multi(inputs: &[&[u8]], pad_to: Option<u64>) -> Vec<[u8; 16]> {
    let mut out = vec![[0u8; 16]; inputs.len()];
    md5_multi_into(inputs, pad_to, &mut out);
    out
}

/// [`md5_multi`] writing into a caller-owned slice, for hot loops that would
/// otherwise allocate a `Vec` per batch.
///
/// # Panics
///
/// Panics when `out` is not exactly as long as `inputs`.
pub fn md5_multi_into(inputs: &[&[u8]], pad_to: Option<u64>, out: &mut [[u8; 16]]) {
    assert_eq!(
        inputs.len(),
        out.len(),
        "md5_multi_into requires one output slot per input"
    );
    if inputs.is_empty() {
        return;
    }

    let lanes = max_lanes();
    let mut plans: Vec<LanePlan<'_>> = Vec::with_capacity(lanes.min(inputs.len()));
    for (chunk, digests) in inputs.chunks(lanes).zip(out.chunks_mut(lanes)) {
        plans.clear();
        plans.extend(chunk.iter().map(|input| LanePlan::new(input, pad_to)));
        md5_batch(&plans, digests);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference_md5(data: &[u8]) -> [u8; 16] {
        Md5::digest(data).into()
    }

    fn reference_md5_padded(data: &[u8], pad_to: u64) -> [u8; 16] {
        let mut padded = data.to_vec();
        if (padded.len() as u64) < pad_to {
            padded.resize(pad_to as usize, 0);
        }
        Md5::digest(&padded).into()
    }

    /// Force the scalar kernel regardless of host ISA, so its arithmetic is
    /// checked on every platform rather than only on the fallback ones.
    fn scalar_md5_multi(inputs: &[&[u8]], pad_to: Option<u64>) -> Vec<[u8; 16]> {
        let plans: Vec<LanePlan<'_>> = inputs
            .iter()
            .map(|input| LanePlan::new(input, pad_to))
            .collect();
        let mut out = vec![[0u8; 16]; inputs.len()];
        md5_batch_scalar(&plans, &mut out);
        out
    }

    struct Xorshift(u64);

    impl Xorshift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn bytes(&mut self, len: usize) -> Vec<u8> {
            (0..len).map(|_| self.next() as u8).collect()
        }
    }

    #[test]
    fn max_lanes_is_a_supported_width() {
        assert!(matches!(max_lanes(), 1 | 4 | 8));
    }

    #[test]
    fn single_input_matches_reference() {
        let data = b"hello world";
        let result = md5_multi(&[data], None);
        assert_eq!(result[0], reference_md5(data));
    }

    #[test]
    fn empty_input() {
        let data: &[u8] = b"";
        let result = md5_multi(&[data], None);
        assert_eq!(result[0], reference_md5(data));
    }

    /// The exhaustive length sweep: every length from empty through more than
    /// three blocks, which covers every offset mod 64 and both padding shapes
    /// (terminator with room for the length, and terminator spilling into an
    /// extra block).
    #[test]
    fn every_length_through_three_blocks_matches_reference() {
        let mut rng = Xorshift(0x0BAD_F00D_DEAD_BEEF);
        let data = rng.bytes(256);
        for len in 0..=224usize {
            let input = &data[..len];
            let dispatched = md5_multi(&[input], None);
            let scalar = scalar_md5_multi(&[input], None);
            let expected = reference_md5(input);
            assert_eq!(dispatched[0], expected, "dispatched mismatch at len={len}");
            assert_eq!(scalar[0], expected, "scalar mismatch at len={len}");
        }
    }

    /// The same sweep under PAR2 padding: a short message zero-extended to a
    /// fixed slice size must equal hashing the materialized zero-padded copy.
    #[test]
    fn every_length_with_padding_matches_reference() {
        let mut rng = Xorshift(0xFEED_FACE_C0FF_EE01);
        let data = rng.bytes(200);
        for pad_to in [1u64, 55, 56, 63, 64, 65, 119, 120, 128, 200, 257] {
            for len in 0..=(pad_to as usize).min(data.len()) {
                let input = &data[..len];
                let dispatched = md5_multi(&[input], Some(pad_to));
                let scalar = scalar_md5_multi(&[input], Some(pad_to));
                let expected = reference_md5_padded(input, pad_to);
                assert_eq!(
                    dispatched[0], expected,
                    "dispatched mismatch at len={len} pad_to={pad_to}"
                );
                assert_eq!(
                    scalar[0], expected,
                    "scalar mismatch at len={len} pad_to={pad_to}"
                );
            }
        }
    }

    /// Lane-count x message-length matrix with every batch size from one lane
    /// up past the widest kernel, so partially filled vectors and multi-batch
    /// chunking are both exercised.
    #[test]
    fn lane_count_by_length_matrix() {
        let mut rng = Xorshift(0x1234_5678_9ABC_DEF0);
        for count in 1..=17usize {
            for len in [0usize, 1, 55, 56, 63, 64, 65, 127, 128, 129, 1000] {
                let inputs: Vec<Vec<u8>> = (0..count).map(|_| rng.bytes(len)).collect();
                let refs: Vec<&[u8]> = inputs.iter().map(|v| v.as_slice()).collect();
                let results = md5_multi(&refs, None);
                assert_eq!(results.len(), count);
                for (lane, input) in inputs.iter().enumerate() {
                    assert_eq!(
                        results[lane],
                        reference_md5(input),
                        "mismatch at count={count} len={len} lane={lane}"
                    );
                }
            }
        }
    }

    /// The hard case: messages of *different* lengths batched together, so
    /// lanes retire at different block indices and the per-lane freeze path
    /// runs. Includes ragged batches that straddle the widest kernel.
    #[test]
    fn ragged_batches_match_reference() {
        let mut rng = Xorshift(0xC0DE_1234_5678_9ABC);
        for count in 1..=16usize {
            for round in 0..8usize {
                let inputs: Vec<Vec<u8>> = (0..count)
                    .map(|lane| {
                        let len = (rng.next() as usize % 600) + lane + round;
                        rng.bytes(len)
                    })
                    .collect();
                let refs: Vec<&[u8]> = inputs.iter().map(|v| v.as_slice()).collect();
                let results = md5_multi(&refs, None);
                let scalar = scalar_md5_multi(&refs, None);
                for (lane, input) in inputs.iter().enumerate() {
                    let expected = reference_md5(input);
                    assert_eq!(
                        results[lane],
                        expected,
                        "dispatched ragged mismatch count={count} round={round} lane={lane} len={}",
                        input.len()
                    );
                    assert_eq!(
                        scalar[lane], expected,
                        "scalar ragged mismatch count={count} round={round} lane={lane}"
                    );
                }
            }
        }
    }

    /// Ragged *and* padded: the PAR2 shape where a file's final slice is short
    /// but every slice pads to the same size, mixed with genuinely ragged
    /// batches that cannot be uniformized.
    #[test]
    fn ragged_batches_with_padding_match_reference() {
        let mut rng = Xorshift(0xABCD_0123_4567_89EF);
        let pad_to = 512u64;
        for count in 1..=16usize {
            let inputs: Vec<Vec<u8>> = (0..count)
                .map(|lane| {
                    let len = if lane % 3 == 0 {
                        rng.next() as usize % 512
                    } else {
                        512
                    };
                    rng.bytes(len)
                })
                .collect();
            let refs: Vec<&[u8]> = inputs.iter().map(|v| v.as_slice()).collect();
            let results = md5_multi(&refs, Some(pad_to));
            for (lane, input) in inputs.iter().enumerate() {
                assert_eq!(
                    results[lane],
                    reference_md5_padded(input, pad_to),
                    "mismatch count={count} lane={lane} len={}",
                    input.len()
                );
            }
        }
    }

    /// Randomized property sweep over lengths and contents.
    #[test]
    fn random_property_sweep() {
        let mut rng = Xorshift(0x5EED_0000_1111_2222);
        for case in 0..400usize {
            let count = 1 + (rng.next() as usize % 9);
            let inputs: Vec<Vec<u8>> = (0..count)
                .map(|_| {
                    let len = rng.next() as usize % 4096;
                    rng.bytes(len)
                })
                .collect();
            let refs: Vec<&[u8]> = inputs.iter().map(|v| v.as_slice()).collect();
            let pad_to = if case % 2 == 0 { None } else { Some(4096) };
            let results = md5_multi(&refs, pad_to);
            let scalar = scalar_md5_multi(&refs, pad_to);
            for (lane, input) in inputs.iter().enumerate() {
                let expected = match pad_to {
                    Some(target) => reference_md5_padded(input, target),
                    None => reference_md5(input),
                };
                assert_eq!(
                    results[lane],
                    expected,
                    "dispatched mismatch case={case} lane={lane} len={}",
                    input.len()
                );
                assert_eq!(
                    scalar[lane],
                    expected,
                    "scalar mismatch case={case} lane={lane} len={}",
                    input.len()
                );
            }
        }
    }

    /// Padding much larger than the payload: the plan must resolve the long
    /// zero run to the shared zero block rather than materializing it.
    #[test]
    fn tiny_payload_with_large_padding() {
        for len in [0usize, 1, 63, 64, 65] {
            let data = vec![0xA5u8; len];
            let pad_to = 64 * 1024u64;
            let result = md5_multi(&[&data], Some(pad_to));
            assert_eq!(
                result[0],
                reference_md5_padded(&data, pad_to),
                "mismatch at len={len}"
            );
        }
    }

    #[test]
    fn pad_to_with_exact_length_is_noop() {
        let data = vec![0xABu8; 256];
        assert_eq!(
            md5_multi(&[&data], None)[0],
            md5_multi(&[&data], Some(256))[0]
        );
    }

    #[test]
    fn pad_to_shorter_than_data_is_ignored() {
        let data = vec![0x5Au8; 300];
        assert_eq!(
            md5_multi(&[&data], Some(64))[0],
            reference_md5(&data),
            "pad_to below the data length must not truncate"
        );
    }

    #[test]
    fn large_inputs_match_reference() {
        let mut rng = Xorshift(0x9999_8888_7777_6666);
        let inputs: Vec<Vec<u8>> = (0..8).map(|_| rng.bytes(65_536 + 17)).collect();
        let refs: Vec<&[u8]> = inputs.iter().map(|v| v.as_slice()).collect();
        let results = md5_multi(&refs, None);
        for (lane, input) in inputs.iter().enumerate() {
            assert_eq!(results[lane], reference_md5(input), "mismatch lane={lane}");
        }
    }

    #[test]
    fn md5_multi_into_matches_md5_multi() {
        let mut rng = Xorshift(0x0F0F_0F0F_1E1E_1E1E);
        let inputs: Vec<Vec<u8>> = (0..11).map(|lane| rng.bytes(100 + lane * 37)).collect();
        let refs: Vec<&[u8]> = inputs.iter().map(|v| v.as_slice()).collect();
        let expected = md5_multi(&refs, None);
        let mut out = vec![[0u8; 16]; refs.len()];
        md5_multi_into(&refs, None, &mut out);
        assert_eq!(out, expected);
    }

    #[test]
    fn empty_batch_is_a_noop() {
        assert!(md5_multi(&[], None).is_empty());
        md5_multi_into(&[], None, &mut []);
    }

    /// Every kernel the host can reach must agree with the scalar reference,
    /// not merely the one runtime dispatch happens to select.
    #[test]
    fn every_available_kernel_matches_scalar() {
        let mut rng = Xorshift(0x7777_1111_2222_3333);
        let inputs: Vec<Vec<u8>> = (0..8)
            .map(|lane| rng.bytes(64 * (lane + 1) + lane * 7))
            .collect();
        let refs: Vec<&[u8]> = inputs.iter().map(|v| v.as_slice()).collect();

        let check = |name: &str, count: usize, digests: &[[u8; 16]]| {
            for (lane, input) in inputs[..count].iter().enumerate() {
                assert_eq!(
                    digests[lane],
                    reference_md5(input),
                    "{name} mismatch lane={lane}"
                );
            }
        };

        for count in 1..=4usize {
            let plans: Vec<LanePlan<'_>> = refs[..count]
                .iter()
                .map(|input| LanePlan::new(input, None))
                .collect();
            let mut out = vec![[0u8; 16]; count];

            #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
            {
                unsafe { md5_multi_neon(&plans, &mut out) };
                check("neon", count, &out);
            }
            #[cfg(all(
                any(target_arch = "x86", target_arch = "x86_64"),
                target_endian = "little"
            ))]
            {
                unsafe { md5_multi_sse2(&plans, &mut out) };
                check("sse2", count, &out);
            }
            #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
            {
                unsafe { md5_multi_simd128(&plans, &mut out) };
                check("simd128", count, &out);
            }
            md5_batch_scalar(&plans, &mut out);
            check("scalar", count, &out);
        }

        #[cfg(all(
            any(target_arch = "x86", target_arch = "x86_64"),
            target_endian = "little"
        ))]
        if avx2_available() {
            for count in 1..=8usize {
                let plans: Vec<LanePlan<'_>> = refs[..count]
                    .iter()
                    .map(|input| LanePlan::new(input, None))
                    .collect();
                let mut out = vec![[0u8; 16]; count];
                unsafe { md5_multi_avx2(&plans, &mut out) };
                check("avx2", count, &out);
            }
        }
    }
}
