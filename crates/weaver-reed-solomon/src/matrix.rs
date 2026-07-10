//! Portable GF(2^16) repair-coefficient-matrix construction.
//!
//! This is the host-agnostic, dependency-light half of a PAR2 Reed-Solomon
//! *repair* solve: given which input slices are missing, which are available,
//! and which recovery exponents will be used, it builds the coefficient matrix
//! (`input_factors`) that reconstructs the missing slices as
//!
//! ```text
//! out[j] = XOR over sources s of gf::mul(coeff[j][s], src[s])
//! ```
//!
//! where the `sources` are ordered `available inputs` (in `available_indices`
//! order) followed by the selected `recovery blocks` (in `recovery_exponents`
//! order) — exactly the column layout of `weaver-par2`'s repair matrix.
//!
//! It exists so an embedding host (e.g. a wasmtime host application) can run
//! the whole RS solve natively — Gaussian elimination on a large native stack
//! plus the parallel GF matmul — on behalf of a single-threaded `wasm32-wasip1`
//! guest that can neither spawn a rayon pool nor provision the large stack the
//! elimination needs. `weaver-par2` keeps its own performance-tuned matrix path
//! for native, in-process repair; the two are byte-identical because the RS
//! decode matrix (`inv(submatrix) * pre`) is unique for a given selection.
//!
//! The elimination here is intentionally a plain serial Gauss-Jordan inverse so
//! this module builds and runs identically on native and `wasm32-wasip1`.

use crate::gf;

/// The repair coefficient matrix, row-major.
///
/// `rows` == the number of missing slices (== the number of recovery exponents
/// used). `cols` == `available_indices.len() + rows` (available inputs first,
/// then recovery blocks). `data[r * cols + c]` is the GF(2^16) coefficient
/// applied to source `c` when reconstructing missing slice `r`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairCoefficients {
    /// Number of missing slices reconstructed (matrix rows).
    pub rows: usize,
    /// Number of source slices (matrix columns): available inputs then recovery.
    pub cols: usize,
    /// Row-major coefficients, `rows * cols` entries.
    pub data: Vec<u16>,
}

impl RepairCoefficients {
    /// Coefficient row for reconstructing missing slice `r` (length `cols`).
    #[inline]
    pub fn row(&self, r: usize) -> &[u16] {
        let start = r * self.cols;
        &self.data[start..start + self.cols]
    }

    /// Coefficient for source column `c` of missing-slice row `r`.
    #[inline]
    pub fn get(&self, r: usize, c: usize) -> u16 {
        self.data[r * self.cols + c]
    }
}

/// The selected recovery exponents produced a singular submatrix, so the missing
/// slices cannot be recovered from them. `bad_row` (when known) is the index into
/// `recovery_exponents` of the exponent whose row could not be pivoted, matching
/// the semantics `weaver-par2` uses to skip a bad recovery block and retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SingularMatrix {
    /// Row (index into `recovery_exponents`) that had no usable pivot.
    pub bad_row: Option<usize>,
}

/// Build the repair coefficient matrix for a PAR2 damaged-member solve.
///
/// - `available_indices`: global indices of the input slices that survived and
///   will be read as sources (columns `0..available_indices.len()`).
/// - `missing_indices`: global indices of the input slices to reconstruct
///   (matrix rows). Length must equal `recovery_exponents.len()`.
/// - `recovery_exponents`: the recovery-block exponents to solve with, one per
///   missing slice (columns `available_indices.len()..cols`).
/// - `constants`: the PAR2 input-slice constant assignment for every input slice
///   in the recovery set (index it by a global slice index); see
///   [`crate::gf::input_slice_constants`].
///
/// Returns the coefficient matrix, or [`SingularMatrix`] if the chosen exponents
/// do not form an invertible submatrix. The result is byte-identical to the
/// coefficients `weaver-par2` computes for the same inputs.
pub fn build_repair_matrix(
    available_indices: &[usize],
    missing_indices: &[usize],
    recovery_exponents: &[u32],
    constants: &[u16],
) -> Result<RepairCoefficients, SingularMatrix> {
    let n = missing_indices.len();
    if recovery_exponents.len() != n {
        // A caller-side contract violation, not a singular field problem; treat
        // it as "no usable pivot" with an unknown row so callers still fail
        // closed rather than silently returning a mis-shaped matrix.
        return Err(SingularMatrix { bad_row: None });
    }
    let n_avail = available_indices.len();
    let n_src = n_avail + n;

    if n == 0 {
        return Ok(RepairCoefficients {
            rows: 0,
            cols: n_src,
            data: Vec::new(),
        });
    }

    // submatrix (n x n): sub[i][j] = pow(const[missing_j], exp_i).
    let mut sub = vec![0u16; n * n];
    for (i, &exp) in recovery_exponents.iter().enumerate() {
        for (j, &m) in missing_indices.iter().enumerate() {
            sub[i * n + j] = gf::pow(constants[m], exp);
        }
    }

    // pre (n x n_src): [ pow(const[avail_k], exp_i) | e_i-th unit column ].
    let mut pre = vec![0u16; n * n_src];
    for (i, &exp) in recovery_exponents.iter().enumerate() {
        for (k, &av) in available_indices.iter().enumerate() {
            pre[i * n_src + k] = gf::pow(constants[av], exp);
        }
        pre[i * n_src + n_avail + i] = 1;
    }

    let inv = gf_invert(&sub, n)?;
    let data = gf_matmul(&inv, &pre, n, n, n_src);
    Ok(RepairCoefficients {
        rows: n,
        cols: n_src,
        data,
    })
}

/// Invert an `n x n` GF(2^16) matrix (row-major) via serial Gauss-Jordan with
/// partial pivoting. Returns the singular row on failure.
fn gf_invert(mat: &[u16], n: usize) -> Result<Vec<u16>, SingularMatrix> {
    let mut a = mat.to_vec();
    let mut inv = vec![0u16; n * n];
    for i in 0..n {
        inv[i * n + i] = 1;
    }
    for col in 0..n {
        // Partial pivot: first row >= col with a nonzero entry in `col`.
        let piv = (col..n)
            .find(|&r| a[r * n + col] != 0)
            .ok_or(SingularMatrix { bad_row: Some(col) })?;
        if piv != col {
            for k in 0..n {
                a.swap(col * n + k, piv * n + k);
                inv.swap(col * n + k, piv * n + k);
            }
        }
        let pivot_inv = gf::inv(a[col * n + col]);
        for k in 0..n {
            a[col * n + k] = gf::mul(a[col * n + k], pivot_inv);
            inv[col * n + k] = gf::mul(inv[col * n + k], pivot_inv);
        }
        for row in 0..n {
            if row == col {
                continue;
            }
            let f = a[row * n + col];
            if f == 0 {
                continue;
            }
            for k in 0..n {
                a[row * n + k] ^= gf::mul(f, a[col * n + k]);
                inv[row * n + k] ^= gf::mul(f, inv[col * n + k]);
            }
        }
    }
    Ok(inv)
}

/// GF(2^16) matmul: `a` is `r x k`, `b` is `k x c` (row-major); returns `r x c`.
fn gf_matmul(a: &[u16], b: &[u16], r: usize, k: usize, c: usize) -> Vec<u16> {
    let mut out = vec![0u16; r * c];
    for i in 0..r {
        for x in 0..k {
            let av = a[i * k + x];
            if av == 0 {
                continue;
            }
            for j in 0..c {
                out[i * c + j] ^= gf::mul(av, b[x * c + j]);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode recovery blocks, drop members, rebuild the coefficient matrix, and
    /// confirm a serial GF matmul recovers the original bytes (the same property
    /// the PoC's `host_side_reconstruct_recovers_original` checks). This is the
    /// host-side correctness oracle.
    #[test]
    fn build_repair_matrix_recovers_original() {
        let total = 12usize;
        let word_count = 8usize;
        let constants = gf::input_slice_constants(total);

        let orig: Vec<Vec<u8>> = (0..total)
            .map(|i| {
                let mut v = vec![0u8; word_count * 2];
                for (w, chunk) in v.chunks_mut(2).enumerate() {
                    let x = (i as u16)
                        .wrapping_mul(2749)
                        .wrapping_add(w as u16 * 31 + 7);
                    chunk.copy_from_slice(&x.to_le_bytes());
                }
                v
            })
            .collect();

        // Encode 4 recovery blocks with exponents 0..4.
        let n_rec = 4usize;
        let recovery: Vec<Vec<u8>> = (0..n_rec)
            .map(|e| {
                let mut r = vec![0u8; word_count * 2];
                for (i, o) in orig.iter().enumerate() {
                    crate::gf_simd::mul_acc_region(gf::pow(constants[i], e as u32), o, &mut r);
                }
                r
            })
            .collect();

        let missing = vec![2usize, 5, 7, 10];
        let exps: Vec<u32> = (0..missing.len() as u32).collect();
        let avail: Vec<usize> = (0..total).filter(|i| !missing.contains(i)).collect();

        let coeffs = build_repair_matrix(&avail, &missing, &exps, &constants).unwrap();
        assert_eq!(coeffs.rows, missing.len());
        assert_eq!(coeffs.cols, avail.len() + missing.len());

        // sources = [available data..., recovery data...].
        let mut sources: Vec<&[u8]> = avail.iter().map(|&i| orig[i].as_slice()).collect();
        for r in recovery.iter().take(missing.len()) {
            sources.push(r.as_slice());
        }

        for (j, &m) in missing.iter().enumerate() {
            let mut out = vec![0u8; word_count * 2];
            for (s, src) in sources.iter().enumerate() {
                crate::gf_simd::mul_acc_region(coeffs.get(j, s), src, &mut out);
            }
            assert_eq!(out, orig[m], "missing slice {m} not recovered");
        }
    }

    #[test]
    fn singular_selection_reports_bad_row() {
        let constants = gf::input_slice_constants(2);
        let missing = vec![0usize, 1];
        // Two identical exponents => identical rows => singular submatrix.
        let err = build_repair_matrix(&[], &missing, &[0, 0], &constants).unwrap_err();
        assert_eq!(err.bad_row, Some(1));
    }

    #[test]
    fn empty_missing_is_ok() {
        let constants = gf::input_slice_constants(4);
        let coeffs = build_repair_matrix(&[0, 1, 2, 3], &[], &[], &constants).unwrap();
        assert_eq!(coeffs.rows, 0);
        assert_eq!(coeffs.cols, 4);
    }
}
