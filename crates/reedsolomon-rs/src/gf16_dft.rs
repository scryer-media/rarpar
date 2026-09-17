//! Output-pruned multiplicative DFT over GF(2^16) for PAR2 recovery rows.
//!
//! A PAR2 recovery block is a weighted sum of every input slice:
//!
//! ```text
//! R_e = sum_i D_i * g_i^e        g_i = 2^(L_i)
//! ```
//!
//! where `L_i` is the exponent PAR2 assigns to input slice `i` — the `i`-th
//! positive integer coprime to 65535 — and `e` is the recovery exponent. Done
//! literally that is an `n * r` product: one region fold (`dst ^= c * src` over
//! a stripe) for every (slice, recovery block) pair. At PAR2's ceiling — 32768
//! slices, 6553 recovery blocks — that is 215 million folds per stripe.
//!
//! # The transform
//!
//! Write the slices into a length-65535 sequence `a` with `a[L_i] = D_i` and
//! zero elsewhere. Because 2 is primitive in this field, `2^(L*e)` is exactly
//! the kernel of a cyclic DFT, and
//!
//! ```text
//! R_e = sum_k a[k] * w^(k*e)     w = 2, order 65535
//! ```
//!
//! is output `e` of the 65535-point DFT. The order factors into pairwise
//! coprime parts, `65535 = 3 * 5 * 17 * 257`, so by the Chinese remainder
//! theorem `Z_65535` splits as `Z_3 x Z_5 x Z_17 x Z_257` and the transform
//! factors the Good–Thomas way: a tensor product of four short DFTs with **no**
//! twiddle factors between the stages, only index relabelling.
//!
//! Concretely, with `w_d = w^(65535/d)` (an element of order `d`), an input
//! exponent `L` split as `k_d = L mod d` and an output exponent `e` split as
//! `f_d = (N_d^-1 mod d) * (e mod d) mod d` where `N_d = 65535/d`:
//!
//! ```text
//! 2^(L*e) = w_3^(f_3 k_3) * w_5^(f_5 k_5) * w_17^(f_17 k_17) * w_257^(f_257 k_257)
//! ```
//!
//! The identity is checked exhaustively enough in this module's tests; the
//! short proof is that `sum_d N_d f_d` reduces to `e` modulo every `d`, hence
//! equals `e`, and `d | (L - k_d)` makes each `N_d f_d k_d` congruent to
//! `N_d f_d L` modulo 65535.
//!
//! This module works with the coarser two-factor split `65535 = 255 * 257`,
//! since 255 and 257 are the only two parts whose sizes matter:
//!
//! ```text
//! p = 128 * (e mod 255) mod 255        u = L mod 255
//! q = 128 * (e mod 257) mod 257        v = L mod 257
//! ```
//!
//! (128 is the inverse of 257 modulo 255 and, coincidentally, of 255 modulo
//! 257.) Then `2^(L*e) = w_255^(p*u) * w_257^(q*v)`, and the 255-part factors
//! again into 17, 5 and 3.
//!
//! # Why this ordering, and why it fits in memory
//!
//! An addition and a multiplication both cost one pass over the stripe here, so
//! the figure of merit is region folds, not multiplications. For a pruned
//! Good–Thomas schedule with stage order `j1..j4`, the cost of stage `k` is
//!
//! ```text
//! |P_k| * product over m >= k of I_(j_m)
//! ```
//!
//! where `I_j` is the number of live input residues in dimension `j` and `P_k`
//! is the set of distinct *output* coordinate prefixes still needed after stage
//! `k`. Both factors matter: a range of recovery exponents is contiguous in
//! `e`, but its image in CRT coordinates is not, so the schedule has to plan
//! which intermediate rows are wanted and compute nothing else.
//!
//! Two structural facts shape the answer. The exponents `L_i` are coprime to
//! 65535, so residue 0 never occurs in any coordinate: a whole residue class is
//! structurally absent from the input (only 128 of the 255 `u` values and 256
//! of the 257 `v` values can carry a slice). And the caller wants a contiguous
//! window of `e`, which — once the window is longer than 257 — covers every
//! residue in every coordinate, so the pruning bites hardest at the small end.
//!
//! Minimising the cost formula over the six orderings of (3, 5, 17) puts the
//! largest radix first: **17, then 5, then 3**, with the 257-dimension handled
//! last. The 257-dimension is not run as a stage over a materialised array at
//! all — that array would be 65280 rows — but as a *streamed accumulation*:
//!
//! ```text
//! for each bucket v (slices whose L = v mod 257):
//!     B[p] = 255-point pruned transform of that bucket        # 255 scratch rows
//!     for each wanted output o:
//!         out[o] ^= w_257^(q_o * v) * B[p_o]
//! ```
//!
//! This is a loop interchange, not an approximation: the fold count is
//! identical to running the 257-dimension as a final stage, but the live row
//! count collapses from 65280 to 255. That is the whole memory argument —
//! scratch is proportional to the *transform's* row count (255 per in-flight
//! bucket), never to the slice count or the slice size.
//!
//! At the ceiling (32768 slices, 6553 outputs) the schedule costs 2,539,264
//! folds against 214,728,704 for the dense product: 84.6x fewer passes over
//! memory. It degrades gracefully — a single recovery block prunes all the way
//! back to the dense `n` folds, never worse.
//!
//! # Batching buckets
//!
//! The accumulation is the dominant stage (256 * `count` folds). Run one bucket
//! at a time, each output row is read and written once per bucket. Holding `G`
//! buckets' results at once turns that into a `G`-source batch into one
//! destination — one destination read and write for `G` source reads — which is
//! what [`crate::gf_simd::mul_acc_input_batch`] is built for. `G` trades scratch for
//! bandwidth and is a plan parameter ([`DftPlan::build_tuned`]).
//!
//! # What this module does not do
//!
//! It computes rows; it knows nothing about PAR2 packets, slice geometry, or
//! memory admission. Parallelism is the caller's job — plans are `Send + Sync`
//! and stripes are independent, so the natural axis is one worker per stripe.
//!
//! The length-257 leaf is a dense (live inputs) x (needed outputs) fold. Rader's
//! algorithm would turn it into a 256-point cyclic convolution, but in
//! characteristic 2 `x^256 - 1 = (x - 1)^256` has no coprime factorisation, so
//! there is no convolution theorem to exploit and the sub-quadratic routes cost
//! more than the rectangular product the pruning already leaves behind.

use std::ops::Range;

use crate::fft::TransformError;
use crate::gf;
use crate::gf_simd::{FactorSrc, mul_acc_input_batch};

/// Order of the multiplicative group, and the transform length.
const ORDER: u32 = 65535;

/// `log_2` of the order-257 root `w_257 = 2^255`.
const LOG_W257: u16 = 255;
/// `log_2` of the order-17 root `w_17 = 2^3855`.
const LOG_W17: u16 = 3855;
/// `log_2` of the order-5 root `w_5 = 2^13107`.
const LOG_W5: u16 = 13107;
/// `log_2` of the order-3 root `w_3 = 2^21845`.
const LOG_W3: u16 = 21845;

/// Rows of one 255-point sub-transform: 17 * 5 * 3.
const P_ORDER: usize = 255;
/// Cells in one `(g5, g3)` plane of the row layout: 5 * 3.
const PLANE: usize = 15;

/// Largest bucket batch [`DftPlan::build_tuned`] accepts.
pub const MAX_BUCKET_BATCH: usize = 8;

/// Bucket batch [`DftPlan::build`] selects.
///
/// Measured on aarch64 at a 64 KiB stripe (n=14000, r=2098): 1 -> 4 is a ~45%
/// gain as the accumulation stops re-reading each output row per bucket, and
/// the curve is flat past 4 — 8 buys a few percent for twice the scratch.
pub const DEFAULT_BUCKET_BATCH: usize = 4;

/// Sources folded into one destination in a single kernel call.
///
/// A line `(v, u5, u3)` can hold at most 17 distinct exponents, because
/// `L <-> (L mod 257, L mod 5, L mod 3, L mod 17)` is a bijection. Duplicate
/// exponents are legal input, though, so the scatter stage chunks rather than
/// assuming the bound.
const LINE_BATCH: usize = 16;

/// An immutable, precomputed schedule for one (slice set, exponent range) pair.
///
/// Build it once and share it across every stripe and every worker: it holds no
/// stripe-sized state, only index and coefficient tables whose size is
/// `O(slices + outputs)`.
#[derive(Debug)]
pub struct DftPlan {
    source_count: usize,
    first_exponent: u32,
    output_count: usize,
    bucket_batch: usize,

    /// Sources sorted by `(v, u5 * 3 + u3)`; values index the caller's slice.
    src_index: Vec<u32>,
    /// `L mod 17` for the correspondingly sorted source.
    src_u17: Vec<u8>,
    /// Start offset of cell `v * 15 + u5 * 3 + u3` in `src_index`, plus a tail.
    cell_start: Vec<u32>,
    /// The `v` values that carry at least one source, ascending.
    live_buckets: Vec<u16>,
    /// Bit `u5 * 3 + u3` set when bucket `live_buckets[i]` has that line.
    live_lines: Vec<u16>,

    /// Distinct `g17` coordinates the wanted outputs need, ascending.
    need_g17: Vec<u8>,
    /// Distinct `(g17 rank, g5)` pairs needed, ascending.
    need_pairs: Vec<[u8; 2]>,
    /// `g17 rank * 5 + g5 -> rank in need_pairs`, or `u16::MAX`.
    pair_rank: Vec<u16>,
    /// `(g17 rank, g5, g3)` triples needed — one per wanted `p`.
    need_triples: Vec<[u8; 3]>,

    /// Result-buffer row holding `B[p_o]` for output `o`.
    out_row: Vec<u16>,
    /// `q` coordinate of output `o`.
    out_q: Vec<u16>,

    /// `tab17[f * 17 + k] = w_17^(f * k)`, and likewise for 5 and 3.
    tab17: [u16; 17 * 17],
    tab5: [u16; 5 * 5],
    tab3: [u16; 3 * 3],

    /// Rows in one bucket result buffer.
    result_rows: usize,
    /// Rows in the shared stage buffer.
    stage_rows: usize,
    /// Exact region folds one [`DftPlan::transform_stripe`] performs.
    region_folds: u64,
}

/// Per-worker working memory. Sized for one plan at one stripe length.
#[derive(Debug)]
pub struct DftScratch {
    buf: Vec<u8>,
    stripe_len: usize,
}

impl DftScratch {
    /// Allocate exactly [`DftPlan::scratch_bytes`] for this stripe length.
    ///
    /// `stripe_len` must be even; zero is accepted and allocates nothing.
    pub fn new(plan: &DftPlan, stripe_len: usize) -> Self {
        Self {
            buf: vec![0u8; plan.scratch_bytes(stripe_len)],
            stripe_len,
        }
    }

    /// The stripe length this scratch was built for.
    pub fn stripe_len(&self) -> usize {
        self.stripe_len
    }
}

impl DftPlan {
    /// Plan the transform for `slots` (one PAR2 exponent `L_i` per source, in
    /// source order) and the recovery exponents in `outputs`.
    ///
    /// `slots` carries exponents, not the constants themselves: a source whose
    /// PAR2 constant is `c` has `L = gf::log(c)`. Exponents are taken modulo
    /// 65535, so 65535 and 0 name the same slot. Nothing requires them to be
    /// coprime to 65535 or distinct — that is what the PAR2 sequence supplies
    /// and what the schedule is tuned for, but arbitrary multisets are correct.
    ///
    /// # Errors
    ///
    /// [`TransformError::Geometry`] if `outputs` runs past exponent 65534.
    pub fn build(slots: &[u16], outputs: Range<u32>) -> Result<Self, TransformError> {
        Self::build_tuned(slots, outputs, DEFAULT_BUCKET_BATCH)
    }

    /// [`DftPlan::build`] with an explicit bucket batch in `1..=MAX_BUCKET_BATCH`.
    ///
    /// The batch is the number of 257-buckets held in flight. It multiplies the
    /// result scratch and divides the destination traffic of the dominant
    /// accumulation stage; it changes no result.
    ///
    /// # Errors
    ///
    /// [`TransformError::Geometry`] for an out-of-range batch or exponent.
    pub fn build_tuned(
        slots: &[u16],
        outputs: Range<u32>,
        bucket_batch: usize,
    ) -> Result<Self, TransformError> {
        if bucket_batch == 0 || bucket_batch > MAX_BUCKET_BATCH {
            return Err(TransformError::Geometry);
        }
        if outputs.end > ORDER {
            return Err(TransformError::Geometry);
        }
        let first_exponent = outputs.start;
        let output_count = outputs.len();

        // --- input side: bucket by v, then by the (u5, u3) line within it ----
        let cells = 257 * PLANE;
        let mut cell_start = vec![0u32; cells + 1];
        for &slot in slots {
            let exponent = slot as u32 % ORDER;
            cell_start[cell_of(exponent) + 1] += 1;
        }
        for at in 0..cells {
            cell_start[at + 1] += cell_start[at];
        }
        let mut cursor = cell_start.clone();
        let mut src_index = vec![0u32; slots.len()];
        let mut src_u17 = vec![0u8; slots.len()];
        for (source, &slot) in slots.iter().enumerate() {
            let exponent = slot as u32 % ORDER;
            let at = &mut cursor[cell_of(exponent)];
            src_index[*at as usize] = source as u32;
            src_u17[*at as usize] = (exponent % 17) as u8;
            *at += 1;
        }
        let mut live_buckets = Vec::new();
        let mut live_lines = Vec::new();
        for v in 0..257u16 {
            let base = v as usize * PLANE;
            let mut mask = 0u16;
            for line in 0..PLANE {
                if cell_start[base + line + 1] > cell_start[base + line] {
                    mask |= 1 << line;
                }
            }
            if mask != 0 {
                live_buckets.push(v);
                live_lines.push(mask);
            }
        }

        // --- output side: which p, and therefore which rows, are wanted ------
        let mut wanted_p = [false; P_ORDER];
        let mut out_p = Vec::with_capacity(output_count);
        let mut out_q = Vec::with_capacity(output_count);
        for exponent in outputs {
            let p = (128 * (exponent % 255) % 255) as usize;
            let q = (128 * (exponent % 257) % 257) as u16;
            wanted_p[p] = true;
            out_p.push(p);
            out_q.push(q);
        }

        // Prune backwards: the triples the last stage must produce fix the
        // pairs the middle stage must produce, which fix the g17 coordinates
        // the scatter must produce. Everything else is never computed.
        let mut need_g17 = Vec::new();
        let mut g17_rank = [u8::MAX; 17];
        for p in 0..P_ORDER {
            if !wanted_p[p] {
                continue;
            }
            let g17 = g17_of(p);
            if g17_rank[g17 as usize] == u8::MAX {
                g17_rank[g17 as usize] = 0;
                need_g17.push(g17);
            }
        }
        need_g17.sort_unstable();
        for (rank, &g17) in need_g17.iter().enumerate() {
            g17_rank[g17 as usize] = rank as u8;
        }

        let mut pair_rank = vec![u16::MAX; need_g17.len() * 5];
        let mut need_pairs: Vec<[u8; 2]> = Vec::new();
        let mut need_triples: Vec<[u8; 3]> = Vec::new();
        let mut row_of_p = vec![0u16; P_ORDER];
        for p in 0..P_ORDER {
            if !wanted_p[p] {
                continue;
            }
            let rank = g17_rank[g17_of(p) as usize];
            let g5 = (p % 5) as u8;
            let g3 = (p % 3) as u8;
            let slot = rank as usize * 5 + g5 as usize;
            if pair_rank[slot] == u16::MAX {
                pair_rank[slot] = 0;
                need_pairs.push([rank, g5]);
            }
            need_triples.push([rank, g5, g3]);
            row_of_p[p] = (rank as usize * PLANE + g5 as usize * 3 + g3 as usize) as u16;
        }
        need_pairs.sort_unstable();
        for (rank, pair) in need_pairs.iter().enumerate() {
            pair_rank[pair[0] as usize * 5 + pair[1] as usize] = rank as u16;
        }
        need_triples.sort_unstable();

        let out_row = out_p.iter().map(|&p| row_of_p[p]).collect();
        let result_rows = need_g17.len() * PLANE;
        let stage_rows = need_pairs.len() * 3;

        let mut plan = Self {
            source_count: slots.len(),
            first_exponent,
            output_count,
            bucket_batch,
            src_index,
            src_u17,
            cell_start,
            live_buckets,
            live_lines,
            need_g17,
            need_pairs,
            pair_rank,
            need_triples,
            out_row,
            out_q,
            tab17: root_table::<{ 17 * 17 }>(LOG_W17, 17),
            tab5: root_table::<{ 5 * 5 }>(LOG_W5, 5),
            tab3: root_table::<{ 3 * 3 }>(LOG_W3, 3),
            result_rows,
            stage_rows,
            region_folds: 0,
        };
        plan.region_folds = plan.count_region_folds();
        Ok(plan)
    }

    /// Slices this plan folds, i.e. the required `sources.len()`.
    pub fn source_count(&self) -> usize {
        self.source_count
    }

    /// Recovery rows this plan produces.
    pub fn output_count(&self) -> usize {
        self.output_count
    }

    /// The exponent range this plan was built for.
    pub fn outputs(&self) -> Range<u32> {
        self.first_exponent..self.first_exponent + self.output_count as u32
    }

    /// Working bytes one worker needs at this stripe length.
    ///
    /// Charge this against a memory budget *before* allocating a
    /// [`DftScratch`]. It depends only on the plan's row count and the stripe —
    /// never on the slice count or the slice size.
    pub fn scratch_bytes(&self, stripe_len: usize) -> usize {
        (self.bucket_batch * self.result_rows + self.stage_rows) * stripe_len
    }

    /// Heap bytes the plan's own tables occupy.
    pub fn plan_bytes(&self) -> usize {
        self.src_index.len() * 4
            + self.src_u17.len()
            + self.cell_start.len() * 4
            + self.live_buckets.len() * 2
            + self.live_lines.len() * 2
            + self.need_g17.len()
            + self.need_pairs.len() * 2
            + self.pair_rank.len() * 2
            + self.need_triples.len() * 3
            + self.out_row.len() * 2
            + self.out_q.len() * 2
    }

    /// Region folds one [`DftPlan::transform_stripe`] performs.
    ///
    /// Compare against [`DftPlan::dense_region_folds`] to decide whether the
    /// transform is worth its scratch for a given shape.
    pub fn region_folds(&self) -> u64 {
        self.region_folds
    }

    /// Region folds the dense definition would perform: `slices * outputs`.
    pub fn dense_region_folds(&self) -> u64 {
        self.source_count as u64 * self.output_count as u64
    }

    /// Compute the wanted recovery rows for one stripe of every slice.
    ///
    /// `sources[i]` is slice `i`'s stripe — read in place, never copied into a
    /// scattered array. `outputs` is row-major: output `o` occupies
    /// `outputs[o * stripe_len..][..stripe_len]`, in ascending exponent order
    /// from the plan's range.
    ///
    /// Results are **XOR-accumulated** into `outputs`; zero the buffer for a
    /// fresh computation. Accumulating lets a caller split an oversized slice
    /// set across several plans and sum the parts.
    ///
    /// `stripe_len` is taken from the sources and must be even — the kernels
    /// work in 16-bit words. Nothing is allocated here.
    ///
    /// # Errors
    ///
    /// [`TransformError::Geometry`] if the slice count, a stripe length, the
    /// output buffer or the scratch does not match the plan.
    /// [`TransformError::Cancelled`] if `cancelled` returns true; `outputs` is
    /// then partially written.
    pub fn transform_stripe(
        &self,
        sources: &[&[u8]],
        outputs: &mut [u8],
        scratch: &mut DftScratch,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), TransformError> {
        if sources.len() != self.source_count {
            return Err(TransformError::Geometry);
        }
        let stripe_len = sources.first().map_or(0, |s| s.len());
        if !stripe_len.is_multiple_of(2) || sources.iter().any(|s| s.len() != stripe_len) {
            return Err(TransformError::Geometry);
        }
        if outputs.len() != self.output_count * stripe_len {
            return Err(TransformError::Geometry);
        }
        if scratch.stripe_len != stripe_len || scratch.buf.len() != self.scratch_bytes(stripe_len) {
            return Err(TransformError::Geometry);
        }
        if stripe_len == 0 || self.output_count == 0 || self.live_buckets.is_empty() {
            return Ok(());
        }

        let result_span = self.result_rows * stripe_len;
        let (results, stage) = scratch.buf.split_at_mut(self.bucket_batch * result_span);

        for batch in 0..self.live_buckets.len().div_ceil(self.bucket_batch) {
            if cancelled() {
                return Err(TransformError::Cancelled);
            }
            let from = batch * self.bucket_batch;
            let upto = (from + self.bucket_batch).min(self.live_buckets.len());
            for at in from..upto {
                let slot = at - from;
                let result = &mut results[slot * result_span..][..result_span];
                self.bucket_transform(at, sources, result, stage, stripe_len);
            }
            self.accumulate(from..upto, results, outputs, stripe_len);
        }
        Ok(())
    }

    /// The 255-point pruned sub-transform of one 257-bucket.
    ///
    /// Leaves `B[p]` in `result` at row `out_row`'s indexing, for every wanted
    /// `p`. Rows outside the wanted set hold intermediate debris.
    fn bucket_transform(
        &self,
        bucket: usize,
        sources: &[&[u8]],
        result: &mut [u8],
        stage: &mut [u8],
        stripe_len: usize,
    ) {
        let base = self.live_buckets[bucket] as usize * PLANE;
        let lines = self.live_lines[bucket];

        // Stage 1 of 3 — the length-17 leaf, which also scatters. Each live
        // line folds its slices straight out of caller memory into the 17
        // destinations (fewer, when the outputs do not need them all), so the
        // sources are never gathered into a length-65535 array.
        let mut batch: [FactorSrc<'_>; LINE_BATCH] = std::array::from_fn(|_| FactorSrc {
            factor: 0,
            src: &[],
        });
        for line in 0..PLANE {
            if lines & (1 << line) == 0 {
                continue;
            }
            let start = self.cell_start[base + line] as usize;
            let end = self.cell_start[base + line + 1] as usize;
            for (rank, &g17) in self.need_g17.iter().enumerate() {
                let dst = &mut result[(rank * PLANE + line) * stripe_len..][..stripe_len];
                dst.fill(0);
                for chunk in (start..end).step_by(LINE_BATCH) {
                    let upto = (chunk + LINE_BATCH).min(end);
                    for (at, entry) in (chunk..upto).enumerate() {
                        batch[at] = FactorSrc {
                            factor: self.tab17[g17 as usize * 17 + self.src_u17[entry] as usize],
                            src: sources[self.src_index[entry] as usize],
                        };
                    }
                    mul_acc_input_batch(dst, &batch[..upto - chunk]);
                }
            }
        }

        // Stage 2 of 3 — length 5, along the middle axis, result -> stage.
        let mut batch: [FactorSrc<'_>; 5] = std::array::from_fn(|_| FactorSrc {
            factor: 0,
            src: &[],
        });
        for (pair_at, pair) in self.need_pairs.iter().enumerate() {
            let [rank, g5] = *pair;
            for u3 in 0..3 {
                if lines & line_mask_for_u3(u3) == 0 {
                    continue;
                }
                let dst = &mut stage[(pair_at * 3 + u3) * stripe_len..][..stripe_len];
                dst.fill(0);
                let mut live = 0;
                for u5 in 0..5 {
                    if lines & (1 << (u5 * 3 + u3)) == 0 {
                        continue;
                    }
                    batch[live] = FactorSrc {
                        factor: self.tab5[g5 as usize * 5 + u5],
                        src: &result[(rank as usize * PLANE + u5 * 3 + u3) * stripe_len..]
                            [..stripe_len],
                    };
                    live += 1;
                }
                mul_acc_input_batch(dst, &batch[..live]);
            }
        }

        // Stage 3 of 3 — length 3, stage -> result. Writing back into `result`
        // is safe because stage 2 consumed every row stage 1 wrote.
        let mut batch: [FactorSrc<'_>; 3] = std::array::from_fn(|_| FactorSrc {
            factor: 0,
            src: &[],
        });
        for triple in &self.need_triples {
            let [rank, g5, g3] = *triple;
            let pair_at = self.pair_rank[rank as usize * 5 + g5 as usize] as usize;
            let mut live = 0;
            for u3 in 0..3 {
                if lines & line_mask_for_u3(u3) == 0 {
                    continue;
                }
                batch[live] = FactorSrc {
                    factor: self.tab3[g3 as usize * 3 + u3],
                    src: &stage[(pair_at * 3 + u3) * stripe_len..][..stripe_len],
                };
                live += 1;
            }
            let dst = &mut result
                [(rank as usize * PLANE + g5 as usize * 3 + g3 as usize) * stripe_len..]
                [..stripe_len];
            dst.fill(0);
            mul_acc_input_batch(dst, &batch[..live]);
        }
    }

    /// The streamed length-257 dimension: fold a batch of finished buckets into
    /// every wanted output row.
    fn accumulate(
        &self,
        buckets: Range<usize>,
        results: &[u8],
        outputs: &mut [u8],
        stripe_len: usize,
    ) {
        let result_span = self.result_rows * stripe_len;
        let mut batch: [FactorSrc<'_>; MAX_BUCKET_BATCH] = std::array::from_fn(|_| FactorSrc {
            factor: 0,
            src: &[],
        });
        for (out, dst) in outputs.chunks_mut(stripe_len).enumerate() {
            let row = self.out_row[out] as usize * stripe_len;
            let q = self.out_q[out] as u32;
            for (slot, at) in buckets.clone().enumerate() {
                let v = self.live_buckets[at] as u32;
                batch[slot] = FactorSrc {
                    factor: gf::pow_from_log(LOG_W257, q * v),
                    src: &results[slot * result_span + row..][..stripe_len],
                };
            }
            mul_acc_input_batch(dst, &batch[..buckets.len()]);
        }
    }

    /// Exact fold count, walking the same schedule without touching stripes.
    fn count_region_folds(&self) -> u64 {
        if self.output_count == 0 {
            return 0;
        }
        let mut folds = 0u64;
        for bucket in 0..self.live_buckets.len() {
            let base = self.live_buckets[bucket] as usize * PLANE;
            let lines = self.live_lines[bucket];
            for line in 0..PLANE {
                if lines & (1 << line) == 0 {
                    continue;
                }
                let span = self.cell_start[base + line + 1] - self.cell_start[base + line];
                folds += span as u64 * self.need_g17.len() as u64;
            }
            for _ in &self.need_pairs {
                for u3 in 0..3 {
                    if lines & line_mask_for_u3(u3) == 0 {
                        continue;
                    }
                    folds += (0..5)
                        .filter(|u5| lines & (1 << (u5 * 3 + u3)) != 0)
                        .count() as u64;
                }
            }
            let live_u3 = (0..3)
                .filter(|&u3| lines & line_mask_for_u3(u3) != 0)
                .count() as u64;
            folds += self.need_triples.len() as u64 * live_u3;
        }
        folds + self.live_buckets.len() as u64 * self.output_count as u64
    }
}

/// `L`'s cell in the source ordering: `(L mod 257, L mod 5, L mod 3)`.
#[inline]
fn cell_of(exponent: u32) -> usize {
    (exponent % 257) as usize * PLANE + (exponent % 5) as usize * 3 + (exponent % 3) as usize
}

/// The order-17 output coordinate of `p`: `15^-1 = 8` times `p mod 17`.
#[inline]
fn g17_of(p: usize) -> u8 {
    ((8 * (p % 17)) % 17) as u8
}

/// Line bits of the layout that share one `u3`: `u5 * 3 + u3` for every `u5`.
#[inline]
fn line_mask_for_u3(u3: usize) -> u16 {
    const MASKS: [u16; 3] = [
        1 | 1 << 3 | 1 << 6 | 1 << 9 | 1 << 12,
        1 << 1 | 1 << 4 | 1 << 7 | 1 << 10 | 1 << 13,
        1 << 2 | 1 << 5 | 1 << 8 | 1 << 11 | 1 << 14,
    ];
    MASKS[u3]
}

/// `table[f * d + k] = (2^log_root)^(f * k)` for a root of order `d`.
fn root_table<const N: usize>(log_root: u16, d: usize) -> [u16; N] {
    let mut table = [0u16; N];
    for f in 0..d {
        for k in 0..d {
            table[f * d + k] = gf::pow_from_log(log_root, (f * k) as u32);
        }
    }
    table
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The dense definition, straight from the PAR2 statement of the problem.
    fn dense(
        slots: &[u16],
        outputs: Range<u32>,
        sources: &[Vec<u8>],
        stripe_len: usize,
    ) -> Vec<u8> {
        let mut out = vec![0u8; outputs.len() * stripe_len];
        for (at, exponent) in outputs.enumerate() {
            let dst = &mut out[at * stripe_len..][..stripe_len];
            for (source, &slot) in sources.iter().zip(slots) {
                let factor = gf::pow_from_log(slot, exponent);
                for word in 0..stripe_len / 2 {
                    let s = u16::from_le_bytes([source[word * 2], source[word * 2 + 1]]);
                    let d = u16::from_le_bytes([dst[word * 2], dst[word * 2 + 1]]);
                    let mixed = gf::add(d, gf::mul(s, factor)).to_le_bytes();
                    dst[word * 2] = mixed[0];
                    dst[word * 2 + 1] = mixed[1];
                }
            }
        }
        out
    }

    /// Deterministic pseudo-random bytes; no dev-dependency needed.
    fn noise(seed: u64, len: usize) -> Vec<u8> {
        let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect()
    }

    fn par2_slots(count: usize) -> Vec<u16> {
        let mut slots = Vec::with_capacity(count);
        let mut exponent = 1u32;
        while slots.len() < count {
            if !(exponent.is_multiple_of(3)
                || exponent.is_multiple_of(5)
                || exponent.is_multiple_of(17)
                || exponent.is_multiple_of(257))
            {
                slots.push(exponent as u16);
            }
            exponent += 1;
        }
        slots
    }

    /// Pick `take` of the first `pool` PAR2 slots — what repair sees when only
    /// some slices are present.
    fn subset(pool: usize, take: usize, seed: u64) -> Vec<u16> {
        let all = par2_slots(pool);
        let mut picked: Vec<u16> = Vec::with_capacity(take);
        let mut state = seed | 1;
        let mut used = vec![false; pool];
        while picked.len() < take {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let at = (state % pool as u64) as usize;
            if !used[at] {
                used[at] = true;
                picked.push(all[at]);
            }
        }
        picked
    }

    fn check(slots: &[u16], outputs: Range<u32>, stripe_len: usize, seed: u64) {
        let sources: Vec<Vec<u8>> = (0..slots.len())
            .map(|i| noise(seed ^ (i as u64 + 1), stripe_len))
            .collect();
        let refs: Vec<&[u8]> = sources.iter().map(|s| s.as_slice()).collect();
        let plan = DftPlan::build(slots, outputs.clone()).unwrap();
        let mut scratch = DftScratch::new(&plan, stripe_len);
        let mut got = vec![0u8; outputs.len() * stripe_len];
        plan.transform_stripe(&refs, &mut got, &mut scratch, &|| false)
            .unwrap();
        assert_eq!(
            got,
            dense(slots, outputs.clone(), &sources, stripe_len),
            "n={} outputs={:?} stripe={stripe_len}",
            slots.len(),
            outputs
        );
    }

    #[test]
    fn crt_factorisation_holds() {
        // The identity the whole module rests on, over a spread of exponents.
        for l in [1u32, 2, 4, 7, 11, 256, 257, 4096, 32768, 65534] {
            for e in [0u32, 1, 2, 255, 256, 257, 4369, 6553, 32767, 65534] {
                let (v, u3, u5, u17) = (l % 257, l % 3, l % 5, l % 17);
                let p = (128 * (e % 255) % 255) as usize;
                let q = 128 * (e % 257) % 257;
                let expect = gf::pow_from_log(l as u16, e);
                let got = gf::mul(
                    gf::mul(
                        gf::pow_from_log(LOG_W257, q * v),
                        gf::pow_from_log(LOG_W17, g17_of(p) as u32 * u17),
                    ),
                    gf::mul(
                        gf::pow_from_log(LOG_W5, (p % 5) as u32 * u5),
                        gf::pow_from_log(LOG_W3, (p % 3) as u32 * u3),
                    ),
                );
                assert_eq!(got, expect, "L={l} e={e}");
            }
        }
    }

    #[test]
    fn matches_dense_across_set_sizes() {
        for (at, n) in [1usize, 2, 5, 127, 128, 129, 1000, 4000]
            .into_iter()
            .enumerate()
        {
            check(&par2_slots(n), 0..9, 64, 0x51 + at as u64);
        }
    }

    #[test]
    fn matches_dense_on_stripe_tails() {
        // 2 is the kernel granule; the rest straddle the 32- and 64-byte block
        // widths the wide tiers consume, so each exercises a different tail.
        let slots = par2_slots(40);
        for stripe in [2usize, 6, 30, 32, 34, 62, 64, 66, 126, 130] {
            check(&slots, 3..11, stripe, 0x1234 + stripe as u64);
        }
    }

    #[test]
    fn matches_dense_on_output_ranges() {
        let slots = par2_slots(200);
        for outputs in [
            0..1,
            0..2,
            5..6,
            0..17,
            0..255,
            0..257,
            100..357,
            65000..65100,
        ] {
            check(&slots, outputs, 96, 0x99);
        }
    }

    #[test]
    fn matches_dense_on_high_exponents() {
        // Repair reaches the far end of the exponent space; 65535 is the order,
        // so the last legal exponent is 65534.
        check(&par2_slots(64), 32760..32780, 64, 0xA1);
        check(&par2_slots(64), 65500..65535, 64, 0xA2);
        check(&par2_slots(1000), 32767..32800, 64, 0xA3);
        check(&subset(9000, 900, 0xFACE), 40000..40030, 64, 0xA4);
    }

    #[test]
    fn matches_dense_on_present_slice_subsets() {
        // Repair folds only the slices that are present, which is an arbitrary
        // subset of the coprime sequence rather than a prefix of it.
        for (at, (pool, take)) in [(300usize, 7usize), (2000, 64), (4000, 300)]
            .into_iter()
            .enumerate()
        {
            check(
                &subset(pool, take, 0xC0DE + at as u64),
                0..23,
                64,
                0xB0 + at as u64,
            );
        }
    }

    #[test]
    fn matches_dense_on_degenerate_slots() {
        // Nothing in the schedule assumes coprimality or distinctness; slots
        // sitting on a residue-0 class or repeating must still be exact.
        check(&[0, 3, 5, 17, 257, 255, 65534, 3, 3], 0..13, 64, 0xD1);
        check(&[7, 7, 7, 7], 2..9, 64, 0xD2);
    }

    #[test]
    fn bucket_batch_does_not_change_results() {
        let slots = par2_slots(300);
        let sources: Vec<Vec<u8>> = (0..slots.len()).map(|i| noise(i as u64 + 1, 64)).collect();
        let refs: Vec<&[u8]> = sources.iter().map(|s| s.as_slice()).collect();
        let expect = dense(&slots, 0..40, &sources, 64);
        for batch in 1..=MAX_BUCKET_BATCH {
            let plan = DftPlan::build_tuned(&slots, 0..40, batch).unwrap();
            let mut scratch = DftScratch::new(&plan, 64);
            let mut got = vec![0u8; 40 * 64];
            plan.transform_stripe(&refs, &mut got, &mut scratch, &|| false)
                .unwrap();
            assert_eq!(got, expect, "batch={batch}");
        }
    }

    #[test]
    fn outputs_are_xor_accumulated() {
        // Splitting a slice set across two plans and summing the parts must
        // reproduce the whole, which is the contract callers rely on.
        let slots = par2_slots(60);
        let sources: Vec<Vec<u8>> = (0..60).map(|i| noise(i as u64 + 7, 64)).collect();
        let refs: Vec<&[u8]> = sources.iter().map(|s| s.as_slice()).collect();
        let mut got = vec![0u8; 12 * 64];
        for half in [0..25, 25..60] {
            let plan = DftPlan::build(&slots[half.clone()], 0..12).unwrap();
            let mut scratch = DftScratch::new(&plan, 64);
            plan.transform_stripe(&refs[half], &mut got, &mut scratch, &|| false)
                .unwrap();
        }
        assert_eq!(got, dense(&slots, 0..12, &sources, 64));
    }

    #[test]
    fn cancellation_is_observed() {
        let slots = par2_slots(64);
        let sources: Vec<Vec<u8>> = (0..64).map(|i| noise(i as u64, 64)).collect();
        let refs: Vec<&[u8]> = sources.iter().map(|s| s.as_slice()).collect();
        let plan = DftPlan::build(&slots, 0..8).unwrap();
        let mut scratch = DftScratch::new(&plan, 64);
        let mut got = vec![0u8; 8 * 64];
        assert_eq!(
            plan.transform_stripe(&refs, &mut got, &mut scratch, &|| true),
            Err(TransformError::Cancelled)
        );
    }

    #[test]
    fn geometry_is_validated() {
        let slots = par2_slots(4);
        assert_eq!(
            DftPlan::build(&slots, 0..65536).unwrap_err(),
            TransformError::Geometry
        );
        assert_eq!(
            DftPlan::build_tuned(&slots, 0..4, 0).unwrap_err(),
            TransformError::Geometry
        );
        assert_eq!(
            DftPlan::build_tuned(&slots, 0..4, MAX_BUCKET_BATCH + 1).unwrap_err(),
            TransformError::Geometry
        );

        let plan = DftPlan::build(&slots, 0..4).unwrap();
        let mut scratch = DftScratch::new(&plan, 64);
        let sources: Vec<Vec<u8>> = (0..4).map(|i| noise(i as u64, 64)).collect();
        let refs: Vec<&[u8]> = sources.iter().map(|s| s.as_slice()).collect();
        let mut got = vec![0u8; 4 * 64];
        assert_eq!(
            plan.transform_stripe(&refs[..3], &mut got, &mut scratch, &|| false),
            Err(TransformError::Geometry)
        );
        assert_eq!(
            plan.transform_stripe(&refs, &mut got[..64], &mut scratch, &|| false),
            Err(TransformError::Geometry)
        );
        let odd: Vec<Vec<u8>> = (0..4).map(|i| noise(i as u64, 63)).collect();
        let odd_refs: Vec<&[u8]> = odd.iter().map(|s| s.as_slice()).collect();
        let mut odd_out = vec![0u8; 4 * 63];
        let mut odd_scratch = DftScratch::new(&plan, 63);
        assert_eq!(
            plan.transform_stripe(&odd_refs, &mut odd_out, &mut odd_scratch, &|| false),
            Err(TransformError::Geometry)
        );
    }

    #[test]
    fn fold_count_matches_the_schedule() {
        // Independently derived from the cost model in the module docs.
        let plan = DftPlan::build(&par2_slots(32768), 0..6553).unwrap();
        assert_eq!(plan.region_folds(), 2_539_264);
        assert_eq!(plan.dense_region_folds(), 214_728_704);

        for (n, r, expect) in [
            (2000usize, 200u32, 351_820u64),
            (14000, 256, 608_176),
            (14000, 2098, 1_079_728),
            (14000, 4096, 1_591_216),
        ] {
            let plan = DftPlan::build(&par2_slots(n), 0..r).unwrap();
            assert_eq!(plan.region_folds(), expect, "n={n} r={r}");
        }
    }

    #[test]
    fn scratch_is_independent_of_the_slice_set() {
        // The memory rule: rows, not slices. Growing the set 32x must not move
        // the scratch by a byte.
        let small = DftPlan::build(&par2_slots(1000), 0..6553).unwrap();
        let large = DftPlan::build(&par2_slots(32000), 0..6553).unwrap();
        assert_eq!(small.scratch_bytes(65536), large.scratch_bytes(65536));
        assert_eq!(
            small.scratch_bytes(65536),
            (DEFAULT_BUCKET_BATCH * 255 + 255) * 65536
        );
        // A single output prunes almost the whole tree away.
        let one = DftPlan::build(&par2_slots(32000), 0..1).unwrap();
        assert_eq!(
            one.scratch_bytes(65536),
            (DEFAULT_BUCKET_BATCH * 15 + 3) * 65536
        );
    }

    #[test]
    fn plan_is_send_and_sync() {
        fn assert_shared<T: Send + Sync>() {}
        assert_shared::<DftPlan>();
    }
}
