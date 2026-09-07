//! Legacy RAR3 GF(2^8) Reed-Solomon erasure coder.
//!
//! The coder uses polynomial `0x11D`. RAR3 recovery applies this scalar
//! decoder independently for each byte position across all data and recovery
//! volumes.

const MAX_PAR: usize = 255;
const MAX_POL: usize = 512;

#[derive(Clone)]
pub struct Rar3RsCoder {
    par_size: usize,
    first_block_done: bool,
    gf_exp: [usize; MAX_POL],
    gf_log: [usize; MAX_PAR + 1],
    gx_pol: [usize; MAX_POL * 2],
    error_locs: [usize; MAX_PAR + 1],
    err_count: usize,
    dnm: [usize; MAX_PAR + 1],
    el_pol: [usize; MAX_POL],
    // Decode scratch lives in the coder, not on `decode`'s stack. RAR3
    // recovery calls `decode` once per byte column — 33.5 million times for a
    // 33 MiB volume set — and a `[0usize; MAX_POL]` local costs a full 4 KiB
    // memset on every one of those calls whatever `par_size` actually is. Only
    // the first `par_size` entries of either buffer are ever live, and `decode`
    // writes each of them before reading it, so neither needs clearing between
    // columns.
    syn_data: [usize; MAX_PAR + 1],
    ee_pol: [usize; MAX_PAR + 1],
}

impl Rar3RsCoder {
    pub fn new(par_size: usize) -> Option<Self> {
        if par_size == 0 || par_size > MAX_PAR {
            return None;
        }

        let mut coder = Self {
            par_size,
            first_block_done: false,
            gf_exp: [0; MAX_POL],
            gf_log: [0; MAX_PAR + 1],
            gx_pol: [0; MAX_POL * 2],
            error_locs: [0; MAX_PAR + 1],
            err_count: 0,
            dnm: [0; MAX_PAR + 1],
            el_pol: [0; MAX_POL],
            syn_data: [0; MAX_PAR + 1],
            ee_pol: [0; MAX_PAR + 1],
        };
        coder.gf_init();
        coder.pn_init();
        Some(coder)
    }

    pub fn encode(&self, data: &[u8], dest: &mut [u8]) {
        assert_eq!(dest.len(), self.par_size);

        let mut shift_reg = [0usize; MAX_PAR + 1];
        for &byte in data {
            let d = (byte as usize) ^ shift_reg[self.par_size - 1];
            for j in (1..self.par_size).rev() {
                shift_reg[j] = shift_reg[j - 1] ^ self.gf_mult(self.gx_pol[j], d);
            }
            shift_reg[0] = self.gf_mult(self.gx_pol[0], d);
        }
        for i in 0..self.par_size {
            dest[i] = shift_reg[self.par_size - i - 1] as u8;
        }
    }

    pub fn decode(&mut self, data: &mut [u8], erasures: &[usize]) -> bool {
        let data_size = data.len();
        if data_size == 0
            || data_size > MAX_PAR
            || erasures.len() > self.par_size
            || erasures.iter().any(|&loc| loc >= data_size)
        {
            return false;
        }

        let mut all_zeroes = true;
        for i in 0..self.par_size {
            let root = self.gf_exp[i + 1];
            let mut sum = 0usize;
            for &byte in data.iter() {
                sum = (byte as usize) ^ self.gf_mult(root, sum);
            }
            self.syn_data[i] = sum;
            if sum != 0 {
                all_zeroes = false;
            }
        }

        if all_zeroes {
            return true;
        }

        if !self.first_block_done {
            self.first_block_done = true;
            self.el_pol.fill(0);
            self.el_pol[0] = 1;

            for &era_pos in erasures {
                let m = self.gf_exp[data_size - era_pos - 1];
                for i in (1..=self.par_size).rev() {
                    self.el_pol[i] ^= self.gf_mult(m, self.el_pol[i - 1]);
                }
            }

            self.err_count = 0;
            for root in (MAX_PAR - data_size)..=MAX_PAR {
                let mut sum = 0usize;
                for b in 0..=self.par_size {
                    sum ^= self.gf_mult(self.gf_exp[(b * root) % MAX_PAR], self.el_pol[b]);
                }
                if sum == 0 {
                    self.error_locs[self.err_count] = MAX_PAR - root;
                    self.dnm[self.err_count] = 0;
                    for i in (1..=self.par_size).step_by(2) {
                        self.dnm[self.err_count] ^=
                            self.gf_mult(self.el_pol[i], self.gf_exp[root * (i - 1) % MAX_PAR]);
                    }
                    self.err_count += 1;
                }
            }
        }

        Self::pn_mult(
            self.par_size,
            &self.gf_exp,
            &self.gf_log,
            &self.el_pol,
            &self.syn_data,
            &mut self.ee_pol,
        );

        if self.err_count <= self.par_size && self.err_count > 0 {
            for i in 0..self.err_count {
                let loc = self.error_locs[i];
                let dloc = MAX_PAR - loc;
                let mut n = 0usize;
                for (j, &ee) in self.ee_pol.iter().take(self.par_size).enumerate() {
                    n ^= self.gf_mult(ee, self.gf_exp[dloc * j % MAX_PAR]);
                }

                let data_pos = data_size as isize - loc as isize - 1;
                if data_pos >= 0 && (data_pos as usize) < data_size {
                    data[data_pos as usize] ^=
                        self.gf_mult(n, self.gf_exp[MAX_PAR - self.gf_log[self.dnm[i]]]) as u8;
                }
            }
        }

        self.err_count <= self.par_size
    }

    fn gf_init(&mut self) {
        let mut j = 1usize;
        for i in 0..MAX_PAR {
            self.gf_log[j] = i;
            self.gf_exp[i] = j;
            j <<= 1;
            if j > MAX_PAR {
                j ^= 0x11D;
            }
        }
        for i in MAX_PAR..MAX_POL {
            self.gf_exp[i] = self.gf_exp[i - MAX_PAR];
        }
    }

    #[inline]
    fn gf_mult(&self, a: usize, b: usize) -> usize {
        gf_mult_tables(&self.gf_exp, &self.gf_log, a, b)
    }

    fn pn_init(&mut self) {
        let mut p2 = [0usize; MAX_POL * 2];
        p2[0] = 1;

        for i in 1..=self.par_size {
            let mut p1 = [0usize; MAX_POL * 2];
            p1[0] = self.gf_exp[i];
            p1[1] = 1;

            let mut result = [0usize; MAX_POL * 2];
            Self::pn_mult(
                self.par_size,
                &self.gf_exp,
                &self.gf_log,
                &p1,
                &p2,
                &mut result,
            );
            self.gx_pol[..self.par_size].copy_from_slice(&result[..self.par_size]);
            p2[..self.par_size].copy_from_slice(&self.gx_pol[..self.par_size]);
        }
    }

    /// Free-standing so `decode` can pass `&self.syn_data` and
    /// `&mut self.ee_pol` in one call without borrowing all of `*self`.
    fn pn_mult(
        par_size: usize,
        gf_exp: &[usize],
        gf_log: &[usize],
        p1: &[usize],
        p2: &[usize],
        result: &mut [usize],
    ) {
        // The loop below only ever writes `result[i + j]` with `i + j` under
        // `par_size`, and every caller reads back at most that prefix, so
        // clearing the whole slice would zero kilobytes of scratch nobody
        // looks at — once per byte column, in RAR3 recovery's hot loop.
        result[..par_size].fill(0);
        for i in 0..par_size {
            if p1[i] == 0 {
                continue;
            }
            for j in 0..par_size - i {
                result[i + j] ^= gf_mult_tables(gf_exp, gf_log, p1[i], p2[j]);
            }
        }
    }
}

#[inline]
fn gf_mult_tables(gf_exp: &[usize], gf_log: &[usize], a: usize, b: usize) -> usize {
    if a == 0 || b == 0 {
        0
    } else {
        gf_exp[gf_log[a] + gf_log[b]]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_one_erasure() {
        let source = [1u8, 2, 3, 4, 5];
        let coder = Rar3RsCoder::new(2).unwrap();
        let mut parity = [0u8; 2];
        coder.encode(&source, &mut parity);

        let mut data = Vec::from(source);
        data.extend_from_slice(&parity);
        data[2] = 0;

        let mut decoder = Rar3RsCoder::new(2).unwrap();
        assert!(decoder.decode(&mut data, &[2]));
        assert_eq!(&data[..source.len()], source);
    }

    #[test]
    fn encode_decode_two_erasures() {
        let source = [9u8, 17, 34, 68, 136, 201];
        let coder = Rar3RsCoder::new(3).unwrap();
        let mut parity = [0u8; 3];
        coder.encode(&source, &mut parity);

        let mut data = Vec::from(source);
        data.extend_from_slice(&parity);
        data[0] = 0;
        data[5] = 0;

        let mut decoder = Rar3RsCoder::new(3).unwrap();
        assert!(decoder.decode(&mut data, &[0, 5]));
        assert_eq!(&data[..source.len()], source);
    }

    #[test]
    fn rejects_too_many_erasures() {
        let mut decoder = Rar3RsCoder::new(1).unwrap();
        let mut data = [0u8, 1, 2];
        assert!(!decoder.decode(&mut data, &[0, 1]));
    }

    /// `decode`'s syndrome and error-evaluator scratch lives in the coder and
    /// is no longer cleared between calls, because RAR3 recovery drives one
    /// coder across millions of byte columns. Anything left behind by column
    /// N must not change column N+1, so a reused coder has to agree with a
    /// fresh one on every column — including all-zero columns, which return
    /// early before the evaluator scratch is touched.
    fn reused_coder_matches_fresh_coder(par_size: usize, data_len: usize, erasures: &[usize]) {
        let encoder = Rar3RsCoder::new(par_size).unwrap();
        let mut reused = Rar3RsCoder::new(par_size).unwrap();

        for column in 0..512u32 {
            // Deterministic pseudo-random source bytes, with every 7th column
            // forced to all-zero to exercise the early-return path in between
            // ordinary ones.
            let source = (0..data_len)
                .map(|i| {
                    if column % 7 == 3 {
                        0
                    } else {
                        (column
                            .wrapping_mul(2_654_435_761)
                            .wrapping_add(i as u32 * 97)
                            >> 11) as u8
                    }
                })
                .collect::<Vec<u8>>();

            let mut parity = vec![0u8; par_size];
            encoder.encode(&source, &mut parity);

            let mut damaged = source.clone();
            damaged.extend_from_slice(&parity);
            for &era in erasures {
                damaged[era] = 0;
            }

            let mut via_reused = damaged.clone();
            assert!(
                reused.decode(&mut via_reused, erasures),
                "reused coder refused column {column}"
            );

            let mut via_fresh = damaged.clone();
            assert!(
                Rar3RsCoder::new(par_size)
                    .unwrap()
                    .decode(&mut via_fresh, erasures),
                "fresh coder refused column {column}"
            );

            assert_eq!(
                via_reused, via_fresh,
                "reused coder diverged from a fresh one at column {column}"
            );
            assert_eq!(
                &via_reused[..data_len],
                &source[..],
                "column {column} did not round-trip"
            );
        }
    }

    #[test]
    fn reused_coder_matches_fresh_coder_single_parity() {
        // The shape RAR3 `.rev` recovery actually hits: one recovery volume,
        // five data volumes, the same single volume missing in every column.
        reused_coder_matches_fresh_coder(1, 5, &[2]);
    }

    #[test]
    fn reused_coder_matches_fresh_coder_multi_parity() {
        reused_coder_matches_fresh_coder(3, 6, &[0, 4, 7]);
    }
}
