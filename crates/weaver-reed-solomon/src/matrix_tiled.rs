//! Rank-k tiled Gauss-Jordan inversion for PAR2 repair-matrix solves.
//!
//! Ports the grouped (register-blocked) elimination from par2cmdline-turbo's
//! ParPar `gf16/gfmat_inv.cpp` — `Galois16RecMatrix::scaleRows`/`invertLoop`
//! (the in-group pivot reduction over up to 6 rows) and the `Compute` driver's
//! `INVERT_GROUP` ladder (`gfmat_inv.cpp:654-670`, max group of 6) — adapted to
//! rarpar's natural row-major `u16` layout. Upstream's prepare/finish/
//! replace_word/stripe machinery is intentionally dropped: rarpar's kernels
//! consume the natural layout directly, so no per-word marshalling is needed.
//!
//! # Algorithm
//!
//! Process the `n` pivot columns in groups of [`TILE_GROUP`]. For each group
//! `[g, g+k)`:
//!
//! 1. In-group reduction (serial, scalar): reduce the `k` group rows against
//!    each other so the `k*k` block ends as an exact identity, mirroring
//!    ParPar's `scaleRows` (`SCALE_ROW`/`MULADD_ROW`). Diagonals are read in
//!    the same sequential column order as the rank-1 path, so a zero pivot
//!    surfaces the same `Err(col)`.
//! 2. Rank-k apply (batched, parallel): for every row outside the group, read
//!    the `k` group-column coefficients up front (valid because the block is
//!    identity, so each pivot touches only its own group column in that row),
//!    then XOR-accumulate all `k` reduced pivot rows in a single
//!    [`gf_simd::mul_acc_input_batch`] pass over the row tail. The group columns
//!    zero themselves. This is one pass over each outside row per group of `k`
//!    columns instead of the rank-1 path's `k` passes.
//!
//! # Correctness
//!
//! GF(2^16) arithmetic is exact and the reduced result `[inv(sub)*aug]` is
//! unique, so any elimination order yields byte-identical output to the rank-1
//! path. `bad_row` equivalence holds because step 1 reads each diagonal in the
//! same sequential order after the same preceding column eliminations have been
//! applied to that row (columns of prior groups were eliminated by their step 2,
//! columns earlier in this group by this step's forward reduction).

use crate::gf;
use crate::gf_simd::{self, FactorSrc};
use rayon::prelude::*;

/// Pivot columns processed per group (rank-k width).
///
/// ParPar caps its groups at 6 because it register-blocks the pivot rows in C
/// (`gfmat_inv.cpp:268`, "max out at 6 groups (registers + cache assoc?)").
/// rarpar's apply kernel ([`gf_simd::mul_acc_input_batch`]) loops over the
/// group internally rather than holding each pivot row in a named register, so
/// the register-pressure ceiling does not apply and a wider group amortises the
/// per-row tail traversal further. This value is tuned on the `matrix_solve`
/// bench (Apple Silicon); a divergence from upstream's <=6 is deliberate.
pub const TILE_GROUP: usize = 8;

// Row-batching / parallelism thresholds mirror `weaver-par2`'s rank-1 path
// (`crates/weaver-par2/src/matrix.rs`) so both elimination strategies schedule
// identically.
const SIMD_ELIMINATION_ROWS: usize = 16;
const PARALLEL_ELIMINATION_ROWS: usize = 128;
const PARALLEL_ELIMINATION_THRESHOLD: usize = 256;

/// Invert `submatrix` (`n*n`, row-major) in place while applying the same row
/// operations to `augmented` (`n*aug_cols`, row-major), via rank-k tiled
/// Gauss-Jordan.
///
/// On success `submatrix` is the identity and `augmented` holds
/// `inv(submatrix_in) * augmented_in`. Returns `Err(col)` for the first pivot
/// column (sequential order) whose diagonal is zero, matching the rank-1
/// path's `DecodeMatrixError::singular(col)` semantics exactly.
pub fn invert_augmented_tiled(
    submatrix: &mut [u16],
    augmented: &mut [u16],
    n: usize,
    aug_cols: usize,
) -> Result<(), usize> {
    debug_assert_eq!(submatrix.len(), n * n, "submatrix must be n*n");
    debug_assert_eq!(
        augmented.len(),
        n * aug_cols,
        "augmented must be n*aug_cols"
    );
    if n == 0 {
        return Ok(());
    }

    let mut g = 0usize;
    while g < n {
        let k = TILE_GROUP.min(n - g);

        // Step 1: reduce the k group rows to an exact identity block.
        in_group_reduce(submatrix, augmented, n, aug_cols, g, k)?;

        // Snapshot the reduced pivot rows so step 2 has alias-free sources
        // (same `.to_vec()` discipline as the rank-1 path's pivot snapshot).
        let mut piv_mat: Vec<Vec<u16>> = Vec::with_capacity(k);
        let mut piv_aug: Vec<Vec<u16>> = Vec::with_capacity(k);
        for j in 0..k {
            let rj = g + j;
            piv_mat.push(submatrix[rj * n + g..rj * n + n].to_vec());
            piv_aug.push(augmented[rj * aug_cols..(rj + 1) * aug_cols].to_vec());
        }

        // Step 2: rank-k eliminate the group columns from every other row.
        apply_rank_k(submatrix, augmented, n, aug_cols, g, k, &piv_mat, &piv_aug);

        g += k;
    }
    Ok(())
}

/// Reduce the `k` group rows `[g, g+k)` so the `k*k` block over columns
/// `[g, g+k)` ends as an exact identity, tracking the same operations in
/// `augmented`. Mirrors ParPar `scaleRows` (`gfmat_inv.cpp:140-278`): forward-
/// eliminate against already-reduced pivots, scale the diagonal to 1, then
/// back-eliminate the new pivot column from the earlier group rows.
fn in_group_reduce(
    submatrix: &mut [u16],
    augmented: &mut [u16],
    n: usize,
    aug_cols: usize,
    g: usize,
    k: usize,
) -> Result<(), usize> {
    for j in 0..k {
        let rj = g + j;

        // Forward: apply reduced pivots 0..j so row rj has columns 0..g+j
        // eliminated before its diagonal is read (matches the rank-1 read state
        // at column g+j).
        for i in 0..j {
            let ri = g + i;
            let factor = submatrix[rj * n + g + i];
            if factor == 0 {
                continue;
            }
            for col in g..n {
                let p = submatrix[ri * n + col];
                if p != 0 {
                    submatrix[rj * n + col] ^= gf::mul(factor, p);
                }
            }
            for col in 0..aug_cols {
                let p = augmented[ri * aug_cols + col];
                if p != 0 {
                    augmented[rj * aug_cols + col] ^= gf::mul(factor, p);
                }
            }
        }

        let pivot = submatrix[rj * n + g + j];
        if pivot == 0 {
            return Err(g + j);
        }

        // Scale row rj: matrix tail from the diagonal, full augmented row.
        if pivot != 1 {
            let pinv = gf::inv(pivot);
            for col in (g + j)..n {
                submatrix[rj * n + col] = gf::mul(submatrix[rj * n + col], pinv);
            }
            for col in 0..aug_cols {
                augmented[rj * aug_cols + col] = gf::mul(augmented[rj * aug_cols + col], pinv);
            }
        }

        // Backward: clear column g+j from the earlier group rows so the block
        // is fully diagonalised (not merely triangular).
        for i in 0..j {
            let ri = g + i;
            let factor = submatrix[ri * n + g + j];
            if factor == 0 {
                continue;
            }
            for col in (g + j)..n {
                let p = submatrix[rj * n + col];
                if p != 0 {
                    submatrix[ri * n + col] ^= gf::mul(factor, p);
                }
            }
            for col in 0..aug_cols {
                let p = augmented[rj * aug_cols + col];
                if p != 0 {
                    augmented[ri * aug_cols + col] ^= gf::mul(factor, p);
                }
            }
        }
    }
    Ok(())
}

/// Eliminate the group columns `[g, g+k)` from every row outside the group in a
/// single [`gf_simd::mul_acc_input_batch`] pass per row, batched serially or
/// across rayon workers exactly like `weaver-par2`'s rank-1 path. Disjoint rows
/// are mutated through raw pointers reconstructed per row (`from_raw_parts_mut`),
/// the same idiom the rank-1 path uses for parallel row mutation.
#[allow(clippy::too_many_arguments)]
fn apply_rank_k(
    submatrix: &mut [u16],
    augmented: &mut [u16],
    n: usize,
    aug_cols: usize,
    g: usize,
    k: usize,
    piv_mat: &[Vec<u16>],
    piv_aug: &[Vec<u16>],
) {
    let submat_ptr = submatrix.as_mut_ptr() as usize;
    let aug_ptr = augmented.as_mut_ptr() as usize;
    let group_end = g + k;

    let apply_batch = |batch_start: usize, batch_end: usize| unsafe {
        let mut mat_srcs: Vec<FactorSrc<'_>> = Vec::with_capacity(k);
        let mut aug_srcs: Vec<FactorSrc<'_>> = Vec::with_capacity(k);
        for t in batch_start..batch_end {
            if t >= g && t < group_end {
                continue;
            }

            // Read the k group-column coefficients before any update; the
            // identity block guarantees these reads are independent.
            mat_srcs.clear();
            aug_srcs.clear();
            for j in 0..k {
                let cj = *(submat_ptr as *const u16).add(t * n + g + j);
                if cj != 0 {
                    mat_srcs.push(FactorSrc {
                        factor: cj,
                        src: words_as_bytes(&piv_mat[j]),
                    });
                    aug_srcs.push(FactorSrc {
                        factor: cj,
                        src: words_as_bytes(&piv_aug[j]),
                    });
                }
            }

            if mat_srcs.is_empty() {
                continue;
            }

            let mat_row =
                std::slice::from_raw_parts_mut((submat_ptr as *mut u16).add(t * n + g), n - g);
            gf_simd::mul_acc_input_batch(words_as_bytes_mut(mat_row), &mat_srcs);

            let aug_row =
                std::slice::from_raw_parts_mut((aug_ptr as *mut u16).add(t * aug_cols), aug_cols);
            gf_simd::mul_acc_input_batch(words_as_bytes_mut(aug_row), &aug_srcs);
        }
    };

    // `!cfg!(target_family = "wasm")` const-folds to `true` natively and
    // `false` on wasm, so wasm always takes the serial branch and never
    // evaluates `rayon::current_num_threads` (wasip1 has no worker pool).
    let row_group = if !cfg!(target_family = "wasm")
        && n >= PARALLEL_ELIMINATION_THRESHOLD
        && rayon::current_num_threads() > 1
    {
        PARALLEL_ELIMINATION_ROWS
    } else {
        SIMD_ELIMINATION_ROWS
    };

    if row_group == SIMD_ELIMINATION_ROWS {
        for batch_start in (0..n).step_by(row_group) {
            apply_batch(batch_start, (batch_start + row_group).min(n));
        }
    } else {
        let batch_starts: Vec<usize> = (0..n).step_by(row_group).collect();
        batch_starts.into_par_iter().for_each(|batch_start| {
            apply_batch(batch_start, (batch_start + row_group).min(n));
        });
    }
}

#[inline]
fn words_as_bytes(words: &[u16]) -> &[u8] {
    unsafe { std::slice::from_raw_parts(words.as_ptr().cast::<u8>(), words.len() * 2) }
}

#[inline]
fn words_as_bytes_mut(words: &mut [u16]) -> &mut [u8] {
    unsafe { std::slice::from_raw_parts_mut(words.as_mut_ptr().cast::<u8>(), words.len() * 2) }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic LCG (no `rand` dependency, matching the repo's test style)
    /// producing a stream of `u16` field elements.
    struct Lcg(u64);
    impl Lcg {
        fn new(seed: u64) -> Self {
            Lcg(seed)
        }
        fn next_u16(&mut self) -> u16 {
            // Numerical Recipes LCG constants.
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (self.0 >> 33) as u16
        }
    }

    /// Textbook no-pivot Gauss-Jordan, identical in structure and diagonal-read
    /// order to `weaver-par2`'s rank-1 path. The tiled inverter must produce
    /// byte-identical results and the same `Err(col)`.
    fn naive_solve(
        sub: &mut [u16],
        aug: &mut [u16],
        n: usize,
        aug_cols: usize,
    ) -> Result<(), usize> {
        for col in 0..n {
            let pivot = sub[col * n + col];
            if pivot == 0 {
                return Err(col);
            }
            if pivot != 1 {
                let pinv = gf::inv(pivot);
                for c in col..n {
                    sub[col * n + c] = gf::mul(sub[col * n + c], pinv);
                }
                for c in 0..aug_cols {
                    aug[col * aug_cols + c] = gf::mul(aug[col * aug_cols + c], pinv);
                }
            }
            for row in 0..n {
                if row == col {
                    continue;
                }
                let f = sub[row * n + col];
                if f == 0 {
                    continue;
                }
                for c in col..n {
                    let p = sub[col * n + c];
                    if p != 0 {
                        sub[row * n + c] ^= gf::mul(f, p);
                    }
                }
                for c in 0..aug_cols {
                    let p = aug[col * aug_cols + c];
                    if p != 0 {
                        aug[row * aug_cols + c] ^= gf::mul(f, p);
                    }
                }
            }
        }
        Ok(())
    }

    /// Build an `n*n` Vandermonde matrix from `n` distinct nonzero nodes
    /// (`node_j^i`). Distinct nodes make every leading principal minor nonzero,
    /// so no-pivot elimination never hits a zero diagonal.
    fn vandermonde(nodes: &[u16], n: usize) -> Vec<u16> {
        let mut m = vec![0u16; n * n];
        for (i, row) in m.chunks_mut(n).enumerate() {
            for (j, slot) in row.iter_mut().enumerate() {
                *slot = gf::pow(nodes[j], i as u32);
            }
        }
        m
    }

    fn distinct_nodes(count: usize, seed: u64) -> Vec<u16> {
        let mut rng = Lcg::new(seed);
        let mut seen = std::collections::HashSet::new();
        let mut nodes = Vec::with_capacity(count);
        while nodes.len() < count {
            let v = rng.next_u16();
            if v != 0 && seen.insert(v) {
                nodes.push(v);
            }
        }
        nodes
    }

    /// GF(2^16) matmul for the `orig * inv == I` correctness check.
    fn gf_matmul(a: &[u16], b: &[u16], n: usize) -> Vec<u16> {
        let mut out = vec![0u16; n * n];
        for i in 0..n {
            for x in 0..n {
                let av = a[i * n + x];
                if av == 0 {
                    continue;
                }
                for j in 0..n {
                    out[i * n + j] ^= gf::mul(av, b[x * n + j]);
                }
            }
        }
        out
    }

    fn identity(n: usize) -> Vec<u16> {
        let mut m = vec![0u16; n * n];
        for i in 0..n {
            m[i * n + i] = 1;
        }
        m
    }

    #[test]
    fn tiled_inverts_vandermonde_across_group_shapes() {
        // Straddle TILE_GROUP: below (3,5), exactly (=TILE_GROUP), k-tail
        // (not a multiple), and larger sizes.
        for &n in &[
            1usize,
            2,
            3,
            5,
            TILE_GROUP,
            TILE_GROUP + 1,
            15,
            40,
            41,
            47,
            63,
            64,
            97,
        ] {
            let nodes = distinct_nodes(n, 0x1234_5678 ^ n as u64);
            let orig = vandermonde(&nodes, n);
            let mut sub = orig.clone();
            let mut inv = identity(n);
            invert_augmented_tiled(&mut sub, &mut inv, n, n)
                .unwrap_or_else(|c| panic!("n={n} unexpected singular at {c}"));
            assert_eq!(sub, identity(n), "n={n}: submatrix must reduce to identity");
            assert_eq!(
                gf_matmul(&orig, &inv, n),
                identity(n),
                "n={n}: orig * inv must be identity"
            );
        }
    }

    #[test]
    fn tiled_matches_naive_reference_random() {
        // Arbitrary dense systems (may or may not be no-pivot solvable). The
        // tiled path must return the identical Result and, on success, the
        // identical augmented bytes as the textbook rank-1-style reference.
        for &n in &[
            1usize,
            3,
            5,
            TILE_GROUP,
            TILE_GROUP + 1,
            17,
            40,
            41,
            64,
            65,
            100,
        ] {
            let aug_cols = n + 3; // n unit columns worth + a few extra
            let mut rng = Lcg::new(0xDEAD_BEEF ^ (n as u64) << 20);
            let sub0: Vec<u16> = (0..n * n).map(|_| rng.next_u16()).collect();
            let aug0: Vec<u16> = (0..n * aug_cols).map(|_| rng.next_u16()).collect();

            let mut sub_ref = sub0.clone();
            let mut aug_ref = aug0.clone();
            let ref_res = naive_solve(&mut sub_ref, &mut aug_ref, n, aug_cols);

            let mut sub_t = sub0.clone();
            let mut aug_t = aug0.clone();
            let tiled_res = invert_augmented_tiled(&mut sub_t, &mut aug_t, n, aug_cols);

            assert_eq!(ref_res, tiled_res, "n={n}: Result must match reference");
            if ref_res.is_ok() {
                assert_eq!(sub_ref, sub_t, "n={n}: submatrix must match reference");
                assert_eq!(aug_ref, aug_t, "n={n}: augmented must match reference");
            }
        }
    }

    #[test]
    fn tiled_reports_singular_col() {
        // n < TILE_GROUP: duplicate rows 0 and 1 -> zero diagonal at column 1.
        let n = 4usize;
        let mut sub = vandermonde(&distinct_nodes(n, 7), n);
        for c in 0..n {
            sub[n + c] = sub[c];
        }
        let mut aug = identity(n);
        assert_eq!(invert_augmented_tiled(&mut sub, &mut aug, n, n), Err(1));

        // Duplicate a mid-group column so the zero diagonal falls inside a
        // later group (exercises the tail-group path). n=20, dup at row 13.
        let n = 20usize;
        let bad = 13usize;
        let mut sub = vandermonde(&distinct_nodes(n, 99), n);
        for c in 0..n {
            sub[bad * n + c] = sub[(bad - 1) * n + c];
        }
        let mut aug = identity(n);
        assert_eq!(invert_augmented_tiled(&mut sub, &mut aug, n, n), Err(bad));
    }

    #[test]
    fn tiled_singular_matches_reference_col() {
        // The reported column must equal the no-pivot reference's.
        let n = 30usize;
        for bad in [1usize, TILE_GROUP, TILE_GROUP + 2, 17, 29] {
            let mut sub = vandermonde(&distinct_nodes(n, 0xABCD ^ bad as u64), n);
            for c in 0..n {
                sub[bad * n + c] = sub[(bad - 1) * n + c];
            }
            let mut sub_ref = sub.clone();
            let mut aug_ref = identity(n);
            let ref_res = naive_solve(&mut sub_ref, &mut aug_ref, n, n);
            let mut aug_t = identity(n);
            let tiled_res = invert_augmented_tiled(&mut sub, &mut aug_t, n, n);
            assert_eq!(ref_res, tiled_res);
            assert_eq!(tiled_res, Err(bad));
        }
    }
}
