# Attribution

The published work this repository builds on is listed here, with what was
taken from each and where it is used. The same credit appears in a short
comment at each point of use. Licensing is in `README.md` under License; this
file is about ideas and code we owe to others, not terms.

## PAR3 FFT codec (`par3-rs`, `reedsolomon-rs::fft`)

The PAR3 FFT lane is a clean-room implementation of these results. No code was
copied from any of the authors' implementations.

### Lin, Al-Naffouri, Han and Chung: the additive transform and the erasure decoder

S.-J. Lin, T. Y. Al-Naffouri, Y. S. Han and W.-H. Chung, "Novel Polynomial
Basis With Fast Fourier Transform and Its Application to Reed-Solomon Erasure
Codes", IEEE Transactions on Information Theory 62(11), pp. 6284-6299, 2016,
[doi:10.1109/TIT.2016.2608892](https://doi.org/10.1109/TIT.2016.2608892).
The conference version is S.-J. Lin, W.-H. Chung and Y. S. Han, "Novel
Polynomial Basis and Its Application to Reed-Solomon Erasure Codes", IEEE
FOCS 2014, [doi:10.1109/FOCS.2014.41](https://doi.org/10.1109/FOCS.2014.41).

Taken: the polynomial basis built on subspace polynomials of a Cantor basis
(the LCH basis), the O(n log n) additive transform and its inverse
(`reedsolomon_rs::fft`), and the erasure decoder that recovers lost symbols
through the formal derivative of the error locator (the derivative,
forward and inverse passes of `par3_rs::fft`). The PAR3 specification
defines its FFT recovery matrix in this basis, so the codeword itself follows
this paper.

The Cantor basis the field arithmetic is written in is from D. G. Cantor,
"On arithmetical algorithms over finite fields", Journal of Combinatorial
Theory, Series A 50(2), pp. 285-300, 1989,
[doi:10.1016/0097-3165(89)90020-4](https://doi.org/10.1016/0097-3165(89)90020-4),
as fixed by the PAR3 specification.

### Chen, Lin, Tang, Han, Cai, Yu, Li, Bai and Bai: capacity-window decoding

C. Chen, S.-J. Lin, N. Tang, Y. S. Han, S. Cai, L. Yu, Z. Li, B. Bai and
B. Bai, "Two Fast Erasure Decoding Algorithms for Reed-Solomon Codes Based on
LCH-FFT", IEEE Transactions on Information Theory 72(6), pp. 3784-3798, 2026,
[doi:10.1109/TIT.2026.3685291](https://doi.org/10.1109/TIT.2026.3685291).
It extends C. Chen, S.-J. Lin, Z. Li, S. Cai, Y. S. Han and B. Bai,
"Reduced-Complexity Erasure Decoding of Low-Rate Reed-Solomon Codes Based on
LCH-FFT", IEEE ISIT 2023, pp. 1015-1019,
[doi:10.1109/ISIT54713.2023.10206549](https://doi.org/10.1109/ISIT54713.2023.10206549).

Taken: Algorithm 5 of the 2026 paper, the decoder whose main transforms are
sized by the recovery capacity rather than the code length, applied to the
original outputs only. It is the only FFT decoder `par3-rs` ships from 0.5.1
(`par3_rs::fft::FftCodec::decode_rows`). Two things differ from the paper's
statement and are noted at the point of use: the code dimension includes the
known-zero padding of the PAR3 domain, so it is N minus the capacity rather
than the number of inputs; and in the reference Cantor basis the subspace
polynomials are monic with s_j(v_j) = 1, so the paper's normalization product
is one. The measurements that led to adopting it are in
`crates/par3-rs/PERFORMANCE.md`.

### Samanta, Badakhshan and Gong: the four-step factorization

S. Samanta, M. Badakhshan and G. Gong, "On the Additive FFT Techniques over
Binary Extension Fields", 2026,
[arXiv:2608.20855](https://arxiv.org/abs/2608.20855).

Taken: the row/column (four-step) factorization of the additive transform in
section V, written in the LCH basis so no basis conversion is needed
(`reedsolomon_rs::fft::Transform::four_step_serial` and its pooled form).
Projection by the low subspace polynomial becomes a shift of a Cantor
coordinate by the split. It runs only where it measured faster; the gate and
the measurements are in `crates/par3-rs/PERFORMANCE.md`. The paper's
recursive stage order was measured as well and not adopted.

### Measured and not adopted

W.-D. Li, M.-S. Chen, P.-C. Kuo, C.-M. Cheng and B.-Y. Yang, "Frobenius
Additive Fast Fourier Transform", ISSAC 2018,
[arXiv:1802.03932](https://arxiv.org/abs/1802.03932). Its saving applies to
polynomials with coefficients in a subfield; block data fills the whole
field, and no part of it is in the shipped code.

## GF(2^16) kernels (`reedsolomon-rs`)

Several GF(2^16) kernels, the SSSE3 shuffle multiply-add and its block
prepare and finish steps, are ports of routines from
[ParPar](https://github.com/animetosho/ParPar) by Anime Tosho, released by
its author as public domain or CC0. The comment beside each port names the
routine it follows.

## RAR (`unrar-rs`)

The RAR engine was developed using RARLAB's unRAR source code as the
behavioural reference, and the unRAR license restriction governs that derived
code; see `crates/unrar-rs/LICENSE`.

## PAR2 and PAR3 formats

`par2-rs` and `par3-rs` implement the
[PAR2](https://parchive.github.io/doc/Parity%20Volume%20Set%20Specification%20v2.0.html)
and [PAR3 draft](https://parchive.github.io/doc/Parity_Volume_Set_Specification_v3.0.html)
specifications. Format facts were established against
[par2cmdline](https://github.com/Parchive/par2cmdline) and
[par3cmdline](https://github.com/Parchive/par3cmdline); the `par2-rs` test
suite includes cases adapted from par2cmdline's unit tests, which is why it
remains GPL-3.0-or-later.
