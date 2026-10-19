addl 0({x}), {a1:e}
addl 0({y}), {a2:e}
movl {d1:e}, {tmp1:e}
movl {d2:e}, {tmp2:e}
addl $-0x28955b88, {a1:e}
addl $-0x28955b88, {a2:e}
xorl {c1:e}, {tmp1:e}
xorl {c2:e}, {tmp2:e}
andl {b1:e}, {tmp1:e}
andl {b2:e}, {tmp2:e}
xorl {d1:e}, {tmp1:e}
xorl {d2:e}, {tmp2:e}
addl 4({x}), {d1:e}
addl 4({y}), {d2:e}
addl {tmp1:e}, {a1:e}
addl {tmp2:e}, {a2:e}
roll $7, {a1:e}
roll $7, {a2:e}
addl {b1:e}, {a1:e}
addl {b2:e}, {a2:e}
movl {c1:e}, {tmp1:e}
movl {c2:e}, {tmp2:e}
addl $-0x173848aa, {d1:e}
addl $-0x173848aa, {d2:e}
xorl {b1:e}, {tmp1:e}
xorl {b2:e}, {tmp2:e}
andl {a1:e}, {tmp1:e}
andl {a2:e}, {tmp2:e}
xorl {c1:e}, {tmp1:e}
xorl {c2:e}, {tmp2:e}
addl 8({x}), {c1:e}
addl 8({y}), {c2:e}
addl {tmp1:e}, {d1:e}
addl {tmp2:e}, {d2:e}
roll $12, {d1:e}
roll $12, {d2:e}
addl {a1:e}, {d1:e}
addl {a2:e}, {d2:e}
movl {b1:e}, {tmp1:e}
movl {b2:e}, {tmp2:e}
addl $0x242070db, {c1:e}
addl $0x242070db, {c2:e}
xorl {a1:e}, {tmp1:e}
xorl {a2:e}, {tmp2:e}
andl {d1:e}, {tmp1:e}
andl {d2:e}, {tmp2:e}
xorl {b1:e}, {tmp1:e}
xorl {b2:e}, {tmp2:e}
addl 12({x}), {b1:e}
addl 12({y}), {b2:e}
addl {tmp1:e}, {c1:e}
addl {tmp2:e}, {c2:e}
roll $17, {c1:e}
roll $17, {c2:e}
addl {d1:e}, {c1:e}
addl {d2:e}, {c2:e}
movl {a1:e}, {tmp1:e}
movl {a2:e}, {tmp2:e}
addl $-0x3e423112, {b1:e}
addl $-0x3e423112, {b2:e}
xorl {d1:e}, {tmp1:e}
xorl {d2:e}, {tmp2:e}
andl {c1:e}, {tmp1:e}
andl {c2:e}, {tmp2:e}
xorl {a1:e}, {tmp1:e}
xorl {a2:e}, {tmp2:e}
addl 16({x}), {a1:e}
addl 16({y}), {a2:e}
addl {tmp1:e}, {b1:e}
addl {tmp2:e}, {b2:e}
roll $22, {b1:e}
roll $22, {b2:e}
addl {c1:e}, {b1:e}
addl {c2:e}, {b2:e}
movl {d1:e}, {tmp1:e}
movl {d2:e}, {tmp2:e}
addl $-0x0a83f051, {a1:e}
addl $-0x0a83f051, {a2:e}
xorl {c1:e}, {tmp1:e}
xorl {c2:e}, {tmp2:e}
andl {b1:e}, {tmp1:e}
andl {b2:e}, {tmp2:e}
xorl {d1:e}, {tmp1:e}
xorl {d2:e}, {tmp2:e}
addl 20({x}), {d1:e}
addl 20({y}), {d2:e}
addl {tmp1:e}, {a1:e}
addl {tmp2:e}, {a2:e}
roll $7, {a1:e}
roll $7, {a2:e}
addl {b1:e}, {a1:e}
addl {b2:e}, {a2:e}
movl {c1:e}, {tmp1:e}
movl {c2:e}, {tmp2:e}
addl $0x4787c62a, {d1:e}
addl $0x4787c62a, {d2:e}
xorl {b1:e}, {tmp1:e}
xorl {b2:e}, {tmp2:e}
andl {a1:e}, {tmp1:e}
andl {a2:e}, {tmp2:e}
xorl {c1:e}, {tmp1:e}
xorl {c2:e}, {tmp2:e}
addl 24({x}), {c1:e}
addl 24({y}), {c2:e}
addl {tmp1:e}, {d1:e}
addl {tmp2:e}, {d2:e}
roll $12, {d1:e}
roll $12, {d2:e}
addl {a1:e}, {d1:e}
addl {a2:e}, {d2:e}
movl {b1:e}, {tmp1:e}
movl {b2:e}, {tmp2:e}
addl $-0x57cfb9ed, {c1:e}
addl $-0x57cfb9ed, {c2:e}
xorl {a1:e}, {tmp1:e}
xorl {a2:e}, {tmp2:e}
andl {d1:e}, {tmp1:e}
andl {d2:e}, {tmp2:e}
xorl {b1:e}, {tmp1:e}
xorl {b2:e}, {tmp2:e}
addl 28({x}), {b1:e}
addl 28({y}), {b2:e}
addl {tmp1:e}, {c1:e}
addl {tmp2:e}, {c2:e}
roll $17, {c1:e}
roll $17, {c2:e}
addl {d1:e}, {c1:e}
addl {d2:e}, {c2:e}
movl {a1:e}, {tmp1:e}
movl {a2:e}, {tmp2:e}
addl $-0x02b96aff, {b1:e}
addl $-0x02b96aff, {b2:e}
xorl {d1:e}, {tmp1:e}
xorl {d2:e}, {tmp2:e}
andl {c1:e}, {tmp1:e}
andl {c2:e}, {tmp2:e}
xorl {a1:e}, {tmp1:e}
xorl {a2:e}, {tmp2:e}
addl 32({x}), {a1:e}
addl 32({y}), {a2:e}
addl {tmp1:e}, {b1:e}
addl {tmp2:e}, {b2:e}
roll $22, {b1:e}
roll $22, {b2:e}
addl {c1:e}, {b1:e}
addl {c2:e}, {b2:e}
movl {d1:e}, {tmp1:e}
movl {d2:e}, {tmp2:e}
addl $0x698098d8, {a1:e}
addl $0x698098d8, {a2:e}
xorl {c1:e}, {tmp1:e}
xorl {c2:e}, {tmp2:e}
andl {b1:e}, {tmp1:e}
andl {b2:e}, {tmp2:e}
xorl {d1:e}, {tmp1:e}
xorl {d2:e}, {tmp2:e}
addl 36({x}), {d1:e}
addl 36({y}), {d2:e}
addl {tmp1:e}, {a1:e}
addl {tmp2:e}, {a2:e}
roll $7, {a1:e}
roll $7, {a2:e}
addl {b1:e}, {a1:e}
addl {b2:e}, {a2:e}
movl {c1:e}, {tmp1:e}
movl {c2:e}, {tmp2:e}
addl $-0x74bb0851, {d1:e}
addl $-0x74bb0851, {d2:e}
xorl {b1:e}, {tmp1:e}
xorl {b2:e}, {tmp2:e}
andl {a1:e}, {tmp1:e}
andl {a2:e}, {tmp2:e}
xorl {c1:e}, {tmp1:e}
xorl {c2:e}, {tmp2:e}
addl 40({x}), {c1:e}
addl 40({y}), {c2:e}
addl {tmp1:e}, {d1:e}
addl {tmp2:e}, {d2:e}
roll $12, {d1:e}
roll $12, {d2:e}
addl {a1:e}, {d1:e}
addl {a2:e}, {d2:e}
movl {b1:e}, {tmp1:e}
movl {b2:e}, {tmp2:e}
addl $-0x0000a44f, {c1:e}
addl $-0x0000a44f, {c2:e}
xorl {a1:e}, {tmp1:e}
xorl {a2:e}, {tmp2:e}
andl {d1:e}, {tmp1:e}
andl {d2:e}, {tmp2:e}
xorl {b1:e}, {tmp1:e}
xorl {b2:e}, {tmp2:e}
addl 44({x}), {b1:e}
addl 44({y}), {b2:e}
addl {tmp1:e}, {c1:e}
addl {tmp2:e}, {c2:e}
roll $17, {c1:e}
roll $17, {c2:e}
addl {d1:e}, {c1:e}
addl {d2:e}, {c2:e}
movl {a1:e}, {tmp1:e}
movl {a2:e}, {tmp2:e}
addl $-0x76a32842, {b1:e}
addl $-0x76a32842, {b2:e}
xorl {d1:e}, {tmp1:e}
xorl {d2:e}, {tmp2:e}
andl {c1:e}, {tmp1:e}
andl {c2:e}, {tmp2:e}
xorl {a1:e}, {tmp1:e}
xorl {a2:e}, {tmp2:e}
addl 48({x}), {a1:e}
addl 48({y}), {a2:e}
addl {tmp1:e}, {b1:e}
addl {tmp2:e}, {b2:e}
roll $22, {b1:e}
roll $22, {b2:e}
addl {c1:e}, {b1:e}
addl {c2:e}, {b2:e}
movl {d1:e}, {tmp1:e}
movl {d2:e}, {tmp2:e}
addl $0x6b901122, {a1:e}
addl $0x6b901122, {a2:e}
xorl {c1:e}, {tmp1:e}
xorl {c2:e}, {tmp2:e}
andl {b1:e}, {tmp1:e}
andl {b2:e}, {tmp2:e}
xorl {d1:e}, {tmp1:e}
xorl {d2:e}, {tmp2:e}
addl 52({x}), {d1:e}
addl 52({y}), {d2:e}
addl {tmp1:e}, {a1:e}
addl {tmp2:e}, {a2:e}
roll $7, {a1:e}
roll $7, {a2:e}
addl {b1:e}, {a1:e}
addl {b2:e}, {a2:e}
movl {c1:e}, {tmp1:e}
movl {c2:e}, {tmp2:e}
addl $-0x02678e6d, {d1:e}
addl $-0x02678e6d, {d2:e}
xorl {b1:e}, {tmp1:e}
xorl {b2:e}, {tmp2:e}
andl {a1:e}, {tmp1:e}
andl {a2:e}, {tmp2:e}
xorl {c1:e}, {tmp1:e}
xorl {c2:e}, {tmp2:e}
addl 56({x}), {c1:e}
addl 56({y}), {c2:e}
addl {tmp1:e}, {d1:e}
addl {tmp2:e}, {d2:e}
roll $12, {d1:e}
roll $12, {d2:e}
addl {a1:e}, {d1:e}
addl {a2:e}, {d2:e}
movl {b1:e}, {tmp1:e}
movl {b2:e}, {tmp2:e}
addl $-0x5986bc72, {c1:e}
addl $-0x5986bc72, {c2:e}
xorl {a1:e}, {tmp1:e}
xorl {a2:e}, {tmp2:e}
andl {d1:e}, {tmp1:e}
andl {d2:e}, {tmp2:e}
xorl {b1:e}, {tmp1:e}
xorl {b2:e}, {tmp2:e}
addl 60({x}), {b1:e}
addl 60({y}), {b2:e}
addl {tmp1:e}, {c1:e}
addl {tmp2:e}, {c2:e}
roll $17, {c1:e}
roll $17, {c2:e}
addl {d1:e}, {c1:e}
addl {d2:e}, {c2:e}
movl {a1:e}, {tmp1:e}
movl {a2:e}, {tmp2:e}
addl $0x49b40821, {b1:e}
addl $0x49b40821, {b2:e}
xorl {d1:e}, {tmp1:e}
xorl {d2:e}, {tmp2:e}
andl {c1:e}, {tmp1:e}
andl {c2:e}, {tmp2:e}
xorl {a1:e}, {tmp1:e}
xorl {a2:e}, {tmp2:e}
addl 4({x}), {a1:e}
addl 4({y}), {a2:e}
addl {tmp1:e}, {b1:e}
addl {tmp2:e}, {b2:e}
roll $22, {b1:e}
roll $22, {b2:e}
addl {c1:e}, {b1:e}
addl {c2:e}, {b2:e}
.if {bmi1}
addl $-0x09e1da9e, {a1:e}
addl $-0x09e1da9e, {a2:e}
andnl {c1:e}, {d1:e}, {tmp1:e}
andnl {c2:e}, {d2:e}, {tmp2:e}
addl {tmp1:e}, {a1:e}
addl {tmp2:e}, {a2:e}
movl {d1:e}, {tmp1:e}
movl {d2:e}, {tmp2:e}
addl 24({x}), {d1:e}
addl 24({y}), {d2:e}
andl {b1:e}, {tmp1:e}
andl {b2:e}, {tmp2:e}
addl {tmp1:e}, {a1:e}
addl {tmp2:e}, {a2:e}
roll $5, {a1:e}
roll $5, {a2:e}
addl {b1:e}, {a1:e}
addl {b2:e}, {a2:e}
.else
movl {d1:e}, {tmp1:e}
movl {d2:e}, {tmp2:e}
addl $-0x09e1da9e, {a1:e}
addl $-0x09e1da9e, {a2:e}
notl {tmp1:e}
notl {tmp2:e}
andl {c1:e}, {tmp1:e}
andl {c2:e}, {tmp2:e}
addl {tmp1:e}, {a1:e}
addl {tmp2:e}, {a2:e}
movl {d1:e}, {tmp1:e}
movl {d2:e}, {tmp2:e}
addl 24({x}), {d1:e}
addl 24({y}), {d2:e}
andl {b1:e}, {tmp1:e}
andl {b2:e}, {tmp2:e}
addl {tmp1:e}, {a1:e}
addl {tmp2:e}, {a2:e}
roll $5, {a1:e}
roll $5, {a2:e}
addl {b1:e}, {a1:e}
addl {b2:e}, {a2:e}
.endif
.if {bmi1}
addl $-0x3fbf4cc0, {d1:e}
addl $-0x3fbf4cc0, {d2:e}
andnl {b1:e}, {c1:e}, {tmp1:e}
andnl {b2:e}, {c2:e}, {tmp2:e}
addl {tmp1:e}, {d1:e}
addl {tmp2:e}, {d2:e}
movl {c1:e}, {tmp1:e}
movl {c2:e}, {tmp2:e}
addl 44({x}), {c1:e}
addl 44({y}), {c2:e}
andl {a1:e}, {tmp1:e}
andl {a2:e}, {tmp2:e}
addl {tmp1:e}, {d1:e}
addl {tmp2:e}, {d2:e}
roll $9, {d1:e}
roll $9, {d2:e}
addl {a1:e}, {d1:e}
addl {a2:e}, {d2:e}
.else
movl {c1:e}, {tmp1:e}
movl {c2:e}, {tmp2:e}
addl $-0x3fbf4cc0, {d1:e}
addl $-0x3fbf4cc0, {d2:e}
notl {tmp1:e}
notl {tmp2:e}
andl {b1:e}, {tmp1:e}
andl {b2:e}, {tmp2:e}
addl {tmp1:e}, {d1:e}
addl {tmp2:e}, {d2:e}
movl {c1:e}, {tmp1:e}
movl {c2:e}, {tmp2:e}
addl 44({x}), {c1:e}
addl 44({y}), {c2:e}
andl {a1:e}, {tmp1:e}
andl {a2:e}, {tmp2:e}
addl {tmp1:e}, {d1:e}
addl {tmp2:e}, {d2:e}
roll $9, {d1:e}
roll $9, {d2:e}
addl {a1:e}, {d1:e}
addl {a2:e}, {d2:e}
.endif
.if {bmi1}
addl $0x265e5a51, {c1:e}
addl $0x265e5a51, {c2:e}
andnl {a1:e}, {b1:e}, {tmp1:e}
andnl {a2:e}, {b2:e}, {tmp2:e}
addl {tmp1:e}, {c1:e}
addl {tmp2:e}, {c2:e}
movl {b1:e}, {tmp1:e}
movl {b2:e}, {tmp2:e}
addl 0({x}), {b1:e}
addl 0({y}), {b2:e}
andl {d1:e}, {tmp1:e}
andl {d2:e}, {tmp2:e}
addl {tmp1:e}, {c1:e}
addl {tmp2:e}, {c2:e}
roll $14, {c1:e}
roll $14, {c2:e}
addl {d1:e}, {c1:e}
addl {d2:e}, {c2:e}
.else
movl {b1:e}, {tmp1:e}
movl {b2:e}, {tmp2:e}
addl $0x265e5a51, {c1:e}
addl $0x265e5a51, {c2:e}
notl {tmp1:e}
notl {tmp2:e}
andl {a1:e}, {tmp1:e}
andl {a2:e}, {tmp2:e}
addl {tmp1:e}, {c1:e}
addl {tmp2:e}, {c2:e}
movl {b1:e}, {tmp1:e}
movl {b2:e}, {tmp2:e}
addl 0({x}), {b1:e}
addl 0({y}), {b2:e}
andl {d1:e}, {tmp1:e}
andl {d2:e}, {tmp2:e}
addl {tmp1:e}, {c1:e}
addl {tmp2:e}, {c2:e}
roll $14, {c1:e}
roll $14, {c2:e}
addl {d1:e}, {c1:e}
addl {d2:e}, {c2:e}
.endif
.if {bmi1}
addl $-0x16493856, {b1:e}
addl $-0x16493856, {b2:e}
andnl {d1:e}, {a1:e}, {tmp1:e}
andnl {d2:e}, {a2:e}, {tmp2:e}
addl {tmp1:e}, {b1:e}
addl {tmp2:e}, {b2:e}
movl {a1:e}, {tmp1:e}
movl {a2:e}, {tmp2:e}
addl 20({x}), {a1:e}
addl 20({y}), {a2:e}
andl {c1:e}, {tmp1:e}
andl {c2:e}, {tmp2:e}
addl {tmp1:e}, {b1:e}
addl {tmp2:e}, {b2:e}
roll $20, {b1:e}
roll $20, {b2:e}
addl {c1:e}, {b1:e}
addl {c2:e}, {b2:e}
.else
movl {a1:e}, {tmp1:e}
movl {a2:e}, {tmp2:e}
addl $-0x16493856, {b1:e}
addl $-0x16493856, {b2:e}
notl {tmp1:e}
notl {tmp2:e}
andl {d1:e}, {tmp1:e}
andl {d2:e}, {tmp2:e}
addl {tmp1:e}, {b1:e}
addl {tmp2:e}, {b2:e}
movl {a1:e}, {tmp1:e}
movl {a2:e}, {tmp2:e}
addl 20({x}), {a1:e}
addl 20({y}), {a2:e}
andl {c1:e}, {tmp1:e}
andl {c2:e}, {tmp2:e}
addl {tmp1:e}, {b1:e}
addl {tmp2:e}, {b2:e}
roll $20, {b1:e}
roll $20, {b2:e}
addl {c1:e}, {b1:e}
addl {c2:e}, {b2:e}
.endif
.if {bmi1}
addl $-0x29d0efa3, {a1:e}
addl $-0x29d0efa3, {a2:e}
andnl {c1:e}, {d1:e}, {tmp1:e}
andnl {c2:e}, {d2:e}, {tmp2:e}
addl {tmp1:e}, {a1:e}
addl {tmp2:e}, {a2:e}
movl {d1:e}, {tmp1:e}
movl {d2:e}, {tmp2:e}
addl 40({x}), {d1:e}
addl 40({y}), {d2:e}
andl {b1:e}, {tmp1:e}
andl {b2:e}, {tmp2:e}
addl {tmp1:e}, {a1:e}
addl {tmp2:e}, {a2:e}
roll $5, {a1:e}
roll $5, {a2:e}
addl {b1:e}, {a1:e}
addl {b2:e}, {a2:e}
.else
movl {d1:e}, {tmp1:e}
movl {d2:e}, {tmp2:e}
addl $-0x29d0efa3, {a1:e}
addl $-0x29d0efa3, {a2:e}
notl {tmp1:e}
notl {tmp2:e}
andl {c1:e}, {tmp1:e}
andl {c2:e}, {tmp2:e}
addl {tmp1:e}, {a1:e}
addl {tmp2:e}, {a2:e}
movl {d1:e}, {tmp1:e}
movl {d2:e}, {tmp2:e}
addl 40({x}), {d1:e}
addl 40({y}), {d2:e}
andl {b1:e}, {tmp1:e}
andl {b2:e}, {tmp2:e}
addl {tmp1:e}, {a1:e}
addl {tmp2:e}, {a2:e}
roll $5, {a1:e}
roll $5, {a2:e}
addl {b1:e}, {a1:e}
addl {b2:e}, {a2:e}
.endif
.if {bmi1}
addl $0x02441453, {d1:e}
addl $0x02441453, {d2:e}
andnl {b1:e}, {c1:e}, {tmp1:e}
andnl {b2:e}, {c2:e}, {tmp2:e}
addl {tmp1:e}, {d1:e}
addl {tmp2:e}, {d2:e}
movl {c1:e}, {tmp1:e}
movl {c2:e}, {tmp2:e}
addl 60({x}), {c1:e}
addl 60({y}), {c2:e}
andl {a1:e}, {tmp1:e}
andl {a2:e}, {tmp2:e}
addl {tmp1:e}, {d1:e}
addl {tmp2:e}, {d2:e}
roll $9, {d1:e}
roll $9, {d2:e}
addl {a1:e}, {d1:e}
addl {a2:e}, {d2:e}
.else
movl {c1:e}, {tmp1:e}
movl {c2:e}, {tmp2:e}
addl $0x02441453, {d1:e}
addl $0x02441453, {d2:e}
notl {tmp1:e}
notl {tmp2:e}
andl {b1:e}, {tmp1:e}
andl {b2:e}, {tmp2:e}
addl {tmp1:e}, {d1:e}
addl {tmp2:e}, {d2:e}
movl {c1:e}, {tmp1:e}
movl {c2:e}, {tmp2:e}
addl 60({x}), {c1:e}
addl 60({y}), {c2:e}
andl {a1:e}, {tmp1:e}
andl {a2:e}, {tmp2:e}
addl {tmp1:e}, {d1:e}
addl {tmp2:e}, {d2:e}
roll $9, {d1:e}
roll $9, {d2:e}
addl {a1:e}, {d1:e}
addl {a2:e}, {d2:e}
.endif
.if {bmi1}
addl $-0x275e197f, {c1:e}
addl $-0x275e197f, {c2:e}
andnl {a1:e}, {b1:e}, {tmp1:e}
andnl {a2:e}, {b2:e}, {tmp2:e}
addl {tmp1:e}, {c1:e}
addl {tmp2:e}, {c2:e}
movl {b1:e}, {tmp1:e}
movl {b2:e}, {tmp2:e}
addl 16({x}), {b1:e}
addl 16({y}), {b2:e}
andl {d1:e}, {tmp1:e}
andl {d2:e}, {tmp2:e}
addl {tmp1:e}, {c1:e}
addl {tmp2:e}, {c2:e}
roll $14, {c1:e}
roll $14, {c2:e}
addl {d1:e}, {c1:e}
addl {d2:e}, {c2:e}
.else
movl {b1:e}, {tmp1:e}
movl {b2:e}, {tmp2:e}
addl $-0x275e197f, {c1:e}
addl $-0x275e197f, {c2:e}
notl {tmp1:e}
notl {tmp2:e}
andl {a1:e}, {tmp1:e}
andl {a2:e}, {tmp2:e}
addl {tmp1:e}, {c1:e}
addl {tmp2:e}, {c2:e}
movl {b1:e}, {tmp1:e}
movl {b2:e}, {tmp2:e}
addl 16({x}), {b1:e}
addl 16({y}), {b2:e}
andl {d1:e}, {tmp1:e}
andl {d2:e}, {tmp2:e}
addl {tmp1:e}, {c1:e}
addl {tmp2:e}, {c2:e}
roll $14, {c1:e}
roll $14, {c2:e}
addl {d1:e}, {c1:e}
addl {d2:e}, {c2:e}
.endif
.if {bmi1}
addl $-0x182c0438, {b1:e}
addl $-0x182c0438, {b2:e}
andnl {d1:e}, {a1:e}, {tmp1:e}
andnl {d2:e}, {a2:e}, {tmp2:e}
addl {tmp1:e}, {b1:e}
addl {tmp2:e}, {b2:e}
movl {a1:e}, {tmp1:e}
movl {a2:e}, {tmp2:e}
addl 36({x}), {a1:e}
addl 36({y}), {a2:e}
andl {c1:e}, {tmp1:e}
andl {c2:e}, {tmp2:e}
addl {tmp1:e}, {b1:e}
addl {tmp2:e}, {b2:e}
roll $20, {b1:e}
roll $20, {b2:e}
addl {c1:e}, {b1:e}
addl {c2:e}, {b2:e}
.else
movl {a1:e}, {tmp1:e}
movl {a2:e}, {tmp2:e}
addl $-0x182c0438, {b1:e}
addl $-0x182c0438, {b2:e}
notl {tmp1:e}
notl {tmp2:e}
andl {d1:e}, {tmp1:e}
andl {d2:e}, {tmp2:e}
addl {tmp1:e}, {b1:e}
addl {tmp2:e}, {b2:e}
movl {a1:e}, {tmp1:e}
movl {a2:e}, {tmp2:e}
addl 36({x}), {a1:e}
addl 36({y}), {a2:e}
andl {c1:e}, {tmp1:e}
andl {c2:e}, {tmp2:e}
addl {tmp1:e}, {b1:e}
addl {tmp2:e}, {b2:e}
roll $20, {b1:e}
roll $20, {b2:e}
addl {c1:e}, {b1:e}
addl {c2:e}, {b2:e}
.endif
.if {bmi1}
addl $0x21e1cde6, {a1:e}
addl $0x21e1cde6, {a2:e}
andnl {c1:e}, {d1:e}, {tmp1:e}
andnl {c2:e}, {d2:e}, {tmp2:e}
addl {tmp1:e}, {a1:e}
addl {tmp2:e}, {a2:e}
movl {d1:e}, {tmp1:e}
movl {d2:e}, {tmp2:e}
addl 56({x}), {d1:e}
addl 56({y}), {d2:e}
andl {b1:e}, {tmp1:e}
andl {b2:e}, {tmp2:e}
addl {tmp1:e}, {a1:e}
addl {tmp2:e}, {a2:e}
roll $5, {a1:e}
roll $5, {a2:e}
addl {b1:e}, {a1:e}
addl {b2:e}, {a2:e}
.else
movl {d1:e}, {tmp1:e}
movl {d2:e}, {tmp2:e}
addl $0x21e1cde6, {a1:e}
addl $0x21e1cde6, {a2:e}
notl {tmp1:e}
notl {tmp2:e}
andl {c1:e}, {tmp1:e}
andl {c2:e}, {tmp2:e}
addl {tmp1:e}, {a1:e}
addl {tmp2:e}, {a2:e}
movl {d1:e}, {tmp1:e}
movl {d2:e}, {tmp2:e}
addl 56({x}), {d1:e}
addl 56({y}), {d2:e}
andl {b1:e}, {tmp1:e}
andl {b2:e}, {tmp2:e}
addl {tmp1:e}, {a1:e}
addl {tmp2:e}, {a2:e}
roll $5, {a1:e}
roll $5, {a2:e}
addl {b1:e}, {a1:e}
addl {b2:e}, {a2:e}
.endif
.if {bmi1}
addl $-0x3cc8f82a, {d1:e}
addl $-0x3cc8f82a, {d2:e}
andnl {b1:e}, {c1:e}, {tmp1:e}
andnl {b2:e}, {c2:e}, {tmp2:e}
addl {tmp1:e}, {d1:e}
addl {tmp2:e}, {d2:e}
movl {c1:e}, {tmp1:e}
movl {c2:e}, {tmp2:e}
addl 12({x}), {c1:e}
addl 12({y}), {c2:e}
andl {a1:e}, {tmp1:e}
andl {a2:e}, {tmp2:e}
addl {tmp1:e}, {d1:e}
addl {tmp2:e}, {d2:e}
roll $9, {d1:e}
roll $9, {d2:e}
addl {a1:e}, {d1:e}
addl {a2:e}, {d2:e}
.else
movl {c1:e}, {tmp1:e}
movl {c2:e}, {tmp2:e}
addl $-0x3cc8f82a, {d1:e}
addl $-0x3cc8f82a, {d2:e}
notl {tmp1:e}
notl {tmp2:e}
andl {b1:e}, {tmp1:e}
andl {b2:e}, {tmp2:e}
addl {tmp1:e}, {d1:e}
addl {tmp2:e}, {d2:e}
movl {c1:e}, {tmp1:e}
movl {c2:e}, {tmp2:e}
addl 12({x}), {c1:e}
addl 12({y}), {c2:e}
andl {a1:e}, {tmp1:e}
andl {a2:e}, {tmp2:e}
addl {tmp1:e}, {d1:e}
addl {tmp2:e}, {d2:e}
roll $9, {d1:e}
roll $9, {d2:e}
addl {a1:e}, {d1:e}
addl {a2:e}, {d2:e}
.endif
.if {bmi1}
addl $-0x0b2af279, {c1:e}
addl $-0x0b2af279, {c2:e}
andnl {a1:e}, {b1:e}, {tmp1:e}
andnl {a2:e}, {b2:e}, {tmp2:e}
addl {tmp1:e}, {c1:e}
addl {tmp2:e}, {c2:e}
movl {b1:e}, {tmp1:e}
movl {b2:e}, {tmp2:e}
addl 32({x}), {b1:e}
addl 32({y}), {b2:e}
andl {d1:e}, {tmp1:e}
andl {d2:e}, {tmp2:e}
addl {tmp1:e}, {c1:e}
addl {tmp2:e}, {c2:e}
roll $14, {c1:e}
roll $14, {c2:e}
addl {d1:e}, {c1:e}
addl {d2:e}, {c2:e}
.else
movl {b1:e}, {tmp1:e}
movl {b2:e}, {tmp2:e}
addl $-0x0b2af279, {c1:e}
addl $-0x0b2af279, {c2:e}
notl {tmp1:e}
notl {tmp2:e}
andl {a1:e}, {tmp1:e}
andl {a2:e}, {tmp2:e}
addl {tmp1:e}, {c1:e}
addl {tmp2:e}, {c2:e}
movl {b1:e}, {tmp1:e}
movl {b2:e}, {tmp2:e}
addl 32({x}), {b1:e}
addl 32({y}), {b2:e}
andl {d1:e}, {tmp1:e}
andl {d2:e}, {tmp2:e}
addl {tmp1:e}, {c1:e}
addl {tmp2:e}, {c2:e}
roll $14, {c1:e}
roll $14, {c2:e}
addl {d1:e}, {c1:e}
addl {d2:e}, {c2:e}
.endif
.if {bmi1}
addl $0x455a14ed, {b1:e}
addl $0x455a14ed, {b2:e}
andnl {d1:e}, {a1:e}, {tmp1:e}
andnl {d2:e}, {a2:e}, {tmp2:e}
addl {tmp1:e}, {b1:e}
addl {tmp2:e}, {b2:e}
movl {a1:e}, {tmp1:e}
movl {a2:e}, {tmp2:e}
addl 52({x}), {a1:e}
addl 52({y}), {a2:e}
andl {c1:e}, {tmp1:e}
andl {c2:e}, {tmp2:e}
addl {tmp1:e}, {b1:e}
addl {tmp2:e}, {b2:e}
roll $20, {b1:e}
roll $20, {b2:e}
addl {c1:e}, {b1:e}
addl {c2:e}, {b2:e}
.else
movl {a1:e}, {tmp1:e}
movl {a2:e}, {tmp2:e}
addl $0x455a14ed, {b1:e}
addl $0x455a14ed, {b2:e}
notl {tmp1:e}
notl {tmp2:e}
andl {d1:e}, {tmp1:e}
andl {d2:e}, {tmp2:e}
addl {tmp1:e}, {b1:e}
addl {tmp2:e}, {b2:e}
movl {a1:e}, {tmp1:e}
movl {a2:e}, {tmp2:e}
addl 52({x}), {a1:e}
addl 52({y}), {a2:e}
andl {c1:e}, {tmp1:e}
andl {c2:e}, {tmp2:e}
addl {tmp1:e}, {b1:e}
addl {tmp2:e}, {b2:e}
roll $20, {b1:e}
roll $20, {b2:e}
addl {c1:e}, {b1:e}
addl {c2:e}, {b2:e}
.endif
.if {bmi1}
addl $-0x561c16fb, {a1:e}
addl $-0x561c16fb, {a2:e}
andnl {c1:e}, {d1:e}, {tmp1:e}
andnl {c2:e}, {d2:e}, {tmp2:e}
addl {tmp1:e}, {a1:e}
addl {tmp2:e}, {a2:e}
movl {d1:e}, {tmp1:e}
movl {d2:e}, {tmp2:e}
addl 8({x}), {d1:e}
addl 8({y}), {d2:e}
andl {b1:e}, {tmp1:e}
andl {b2:e}, {tmp2:e}
addl {tmp1:e}, {a1:e}
addl {tmp2:e}, {a2:e}
roll $5, {a1:e}
roll $5, {a2:e}
addl {b1:e}, {a1:e}
addl {b2:e}, {a2:e}
.else
movl {d1:e}, {tmp1:e}
movl {d2:e}, {tmp2:e}
addl $-0x561c16fb, {a1:e}
addl $-0x561c16fb, {a2:e}
notl {tmp1:e}
notl {tmp2:e}
andl {c1:e}, {tmp1:e}
andl {c2:e}, {tmp2:e}
addl {tmp1:e}, {a1:e}
addl {tmp2:e}, {a2:e}
movl {d1:e}, {tmp1:e}
movl {d2:e}, {tmp2:e}
addl 8({x}), {d1:e}
addl 8({y}), {d2:e}
andl {b1:e}, {tmp1:e}
andl {b2:e}, {tmp2:e}
addl {tmp1:e}, {a1:e}
addl {tmp2:e}, {a2:e}
roll $5, {a1:e}
roll $5, {a2:e}
addl {b1:e}, {a1:e}
addl {b2:e}, {a2:e}
.endif
.if {bmi1}
addl $-0x03105c08, {d1:e}
addl $-0x03105c08, {d2:e}
andnl {b1:e}, {c1:e}, {tmp1:e}
andnl {b2:e}, {c2:e}, {tmp2:e}
addl {tmp1:e}, {d1:e}
addl {tmp2:e}, {d2:e}
movl {c1:e}, {tmp1:e}
movl {c2:e}, {tmp2:e}
addl 28({x}), {c1:e}
addl 28({y}), {c2:e}
andl {a1:e}, {tmp1:e}
andl {a2:e}, {tmp2:e}
addl {tmp1:e}, {d1:e}
addl {tmp2:e}, {d2:e}
roll $9, {d1:e}
roll $9, {d2:e}
addl {a1:e}, {d1:e}
addl {a2:e}, {d2:e}
.else
movl {c1:e}, {tmp1:e}
movl {c2:e}, {tmp2:e}
addl $-0x03105c08, {d1:e}
addl $-0x03105c08, {d2:e}
notl {tmp1:e}
notl {tmp2:e}
andl {b1:e}, {tmp1:e}
andl {b2:e}, {tmp2:e}
addl {tmp1:e}, {d1:e}
addl {tmp2:e}, {d2:e}
movl {c1:e}, {tmp1:e}
movl {c2:e}, {tmp2:e}
addl 28({x}), {c1:e}
addl 28({y}), {c2:e}
andl {a1:e}, {tmp1:e}
andl {a2:e}, {tmp2:e}
addl {tmp1:e}, {d1:e}
addl {tmp2:e}, {d2:e}
roll $9, {d1:e}
roll $9, {d2:e}
addl {a1:e}, {d1:e}
addl {a2:e}, {d2:e}
.endif
.if {bmi1}
addl $0x676f02d9, {c1:e}
addl $0x676f02d9, {c2:e}
andnl {a1:e}, {b1:e}, {tmp1:e}
andnl {a2:e}, {b2:e}, {tmp2:e}
addl {tmp1:e}, {c1:e}
addl {tmp2:e}, {c2:e}
movl {b1:e}, {tmp1:e}
movl {b2:e}, {tmp2:e}
addl 48({x}), {b1:e}
addl 48({y}), {b2:e}
andl {d1:e}, {tmp1:e}
andl {d2:e}, {tmp2:e}
addl {tmp1:e}, {c1:e}
addl {tmp2:e}, {c2:e}
roll $14, {c1:e}
roll $14, {c2:e}
addl {d1:e}, {c1:e}
addl {d2:e}, {c2:e}
.else
movl {b1:e}, {tmp1:e}
movl {b2:e}, {tmp2:e}
addl $0x676f02d9, {c1:e}
addl $0x676f02d9, {c2:e}
notl {tmp1:e}
notl {tmp2:e}
andl {a1:e}, {tmp1:e}
andl {a2:e}, {tmp2:e}
addl {tmp1:e}, {c1:e}
addl {tmp2:e}, {c2:e}
movl {b1:e}, {tmp1:e}
movl {b2:e}, {tmp2:e}
addl 48({x}), {b1:e}
addl 48({y}), {b2:e}
andl {d1:e}, {tmp1:e}
andl {d2:e}, {tmp2:e}
addl {tmp1:e}, {c1:e}
addl {tmp2:e}, {c2:e}
roll $14, {c1:e}
roll $14, {c2:e}
addl {d1:e}, {c1:e}
addl {d2:e}, {c2:e}
.endif
.if {bmi1}
addl $-0x72d5b376, {b1:e}
addl $-0x72d5b376, {b2:e}
andnl {d1:e}, {a1:e}, {tmp1:e}
andnl {d2:e}, {a2:e}, {tmp2:e}
addl {tmp1:e}, {b1:e}
addl {tmp2:e}, {b2:e}
movl {a1:e}, {tmp1:e}
movl {a2:e}, {tmp2:e}
addl 20({x}), {a1:e}
addl 20({y}), {a2:e}
andl {c1:e}, {tmp1:e}
andl {c2:e}, {tmp2:e}
addl {tmp1:e}, {b1:e}
addl {tmp2:e}, {b2:e}
roll $20, {b1:e}
roll $20, {b2:e}
addl {c1:e}, {b1:e}
addl {c2:e}, {b2:e}
.else
movl {a1:e}, {tmp1:e}
movl {a2:e}, {tmp2:e}
addl $-0x72d5b376, {b1:e}
addl $-0x72d5b376, {b2:e}
notl {tmp1:e}
notl {tmp2:e}
andl {d1:e}, {tmp1:e}
andl {d2:e}, {tmp2:e}
addl {tmp1:e}, {b1:e}
addl {tmp2:e}, {b2:e}
movl {a1:e}, {tmp1:e}
movl {a2:e}, {tmp2:e}
addl 20({x}), {a1:e}
addl 20({y}), {a2:e}
andl {c1:e}, {tmp1:e}
andl {c2:e}, {tmp2:e}
addl {tmp1:e}, {b1:e}
addl {tmp2:e}, {b2:e}
roll $20, {b1:e}
roll $20, {b2:e}
addl {c1:e}, {b1:e}
addl {c2:e}, {b2:e}
.endif
movl {d1:e}, {tmp1:e}
movl {d2:e}, {tmp2:e}
addl $-0x0005c6be, {a1:e}
addl $-0x0005c6be, {a2:e}
xorl {c1:e}, {tmp1:e}
xorl {c2:e}, {tmp2:e}
addl 32({x}), {d1:e}
addl 32({y}), {d2:e}
xorl {b1:e}, {tmp1:e}
xorl {b2:e}, {tmp2:e}
addl {tmp1:e}, {a1:e}
addl {tmp2:e}, {a2:e}
roll $4, {a1:e}
roll $4, {a2:e}
addl {b1:e}, {a1:e}
addl {b2:e}, {a2:e}
movl {c1:e}, {tmp1:e}
movl {c2:e}, {tmp2:e}
addl $-0x788e097f, {d1:e}
addl $-0x788e097f, {d2:e}
xorl {b1:e}, {tmp1:e}
xorl {b2:e}, {tmp2:e}
addl 44({x}), {c1:e}
addl 44({y}), {c2:e}
xorl {a1:e}, {tmp1:e}
xorl {a2:e}, {tmp2:e}
addl {tmp1:e}, {d1:e}
addl {tmp2:e}, {d2:e}
roll $11, {d1:e}
roll $11, {d2:e}
addl {a1:e}, {d1:e}
addl {a2:e}, {d2:e}
movl {b1:e}, {tmp1:e}
movl {b2:e}, {tmp2:e}
addl $0x6d9d6122, {c1:e}
addl $0x6d9d6122, {c2:e}
xorl {a1:e}, {tmp1:e}
xorl {a2:e}, {tmp2:e}
addl 56({x}), {b1:e}
addl 56({y}), {b2:e}
xorl {d1:e}, {tmp1:e}
xorl {d2:e}, {tmp2:e}
addl {tmp1:e}, {c1:e}
addl {tmp2:e}, {c2:e}
roll $16, {c1:e}
roll $16, {c2:e}
addl {d1:e}, {c1:e}
addl {d2:e}, {c2:e}
movl {a1:e}, {tmp1:e}
movl {a2:e}, {tmp2:e}
addl $-0x021ac7f4, {b1:e}
addl $-0x021ac7f4, {b2:e}
xorl {d1:e}, {tmp1:e}
xorl {d2:e}, {tmp2:e}
addl 4({x}), {a1:e}
addl 4({y}), {a2:e}
xorl {c1:e}, {tmp1:e}
xorl {c2:e}, {tmp2:e}
addl {tmp1:e}, {b1:e}
addl {tmp2:e}, {b2:e}
roll $23, {b1:e}
roll $23, {b2:e}
addl {c1:e}, {b1:e}
addl {c2:e}, {b2:e}
movl {d1:e}, {tmp1:e}
movl {d2:e}, {tmp2:e}
addl $-0x5b4115bc, {a1:e}
addl $-0x5b4115bc, {a2:e}
xorl {c1:e}, {tmp1:e}
xorl {c2:e}, {tmp2:e}
addl 16({x}), {d1:e}
addl 16({y}), {d2:e}
xorl {b1:e}, {tmp1:e}
xorl {b2:e}, {tmp2:e}
addl {tmp1:e}, {a1:e}
addl {tmp2:e}, {a2:e}
roll $4, {a1:e}
roll $4, {a2:e}
addl {b1:e}, {a1:e}
addl {b2:e}, {a2:e}
movl {c1:e}, {tmp1:e}
movl {c2:e}, {tmp2:e}
addl $0x4bdecfa9, {d1:e}
addl $0x4bdecfa9, {d2:e}
xorl {b1:e}, {tmp1:e}
xorl {b2:e}, {tmp2:e}
addl 28({x}), {c1:e}
addl 28({y}), {c2:e}
xorl {a1:e}, {tmp1:e}
xorl {a2:e}, {tmp2:e}
addl {tmp1:e}, {d1:e}
addl {tmp2:e}, {d2:e}
roll $11, {d1:e}
roll $11, {d2:e}
addl {a1:e}, {d1:e}
addl {a2:e}, {d2:e}
movl {b1:e}, {tmp1:e}
movl {b2:e}, {tmp2:e}
addl $-0x0944b4a0, {c1:e}
addl $-0x0944b4a0, {c2:e}
xorl {a1:e}, {tmp1:e}
xorl {a2:e}, {tmp2:e}
addl 40({x}), {b1:e}
addl 40({y}), {b2:e}
xorl {d1:e}, {tmp1:e}
xorl {d2:e}, {tmp2:e}
addl {tmp1:e}, {c1:e}
addl {tmp2:e}, {c2:e}
roll $16, {c1:e}
roll $16, {c2:e}
addl {d1:e}, {c1:e}
addl {d2:e}, {c2:e}
movl {a1:e}, {tmp1:e}
movl {a2:e}, {tmp2:e}
addl $-0x41404390, {b1:e}
addl $-0x41404390, {b2:e}
xorl {d1:e}, {tmp1:e}
xorl {d2:e}, {tmp2:e}
addl 52({x}), {a1:e}
addl 52({y}), {a2:e}
xorl {c1:e}, {tmp1:e}
xorl {c2:e}, {tmp2:e}
addl {tmp1:e}, {b1:e}
addl {tmp2:e}, {b2:e}
roll $23, {b1:e}
roll $23, {b2:e}
addl {c1:e}, {b1:e}
addl {c2:e}, {b2:e}
movl {d1:e}, {tmp1:e}
movl {d2:e}, {tmp2:e}
addl $0x289b7ec6, {a1:e}
addl $0x289b7ec6, {a2:e}
xorl {c1:e}, {tmp1:e}
xorl {c2:e}, {tmp2:e}
addl 0({x}), {d1:e}
addl 0({y}), {d2:e}
xorl {b1:e}, {tmp1:e}
xorl {b2:e}, {tmp2:e}
addl {tmp1:e}, {a1:e}
addl {tmp2:e}, {a2:e}
roll $4, {a1:e}
roll $4, {a2:e}
addl {b1:e}, {a1:e}
addl {b2:e}, {a2:e}
movl {c1:e}, {tmp1:e}
movl {c2:e}, {tmp2:e}
addl $-0x155ed806, {d1:e}
addl $-0x155ed806, {d2:e}
xorl {b1:e}, {tmp1:e}
xorl {b2:e}, {tmp2:e}
addl 12({x}), {c1:e}
addl 12({y}), {c2:e}
xorl {a1:e}, {tmp1:e}
xorl {a2:e}, {tmp2:e}
addl {tmp1:e}, {d1:e}
addl {tmp2:e}, {d2:e}
roll $11, {d1:e}
roll $11, {d2:e}
addl {a1:e}, {d1:e}
addl {a2:e}, {d2:e}
movl {b1:e}, {tmp1:e}
movl {b2:e}, {tmp2:e}
addl $-0x2b10cf7b, {c1:e}
addl $-0x2b10cf7b, {c2:e}
xorl {a1:e}, {tmp1:e}
xorl {a2:e}, {tmp2:e}
addl 24({x}), {b1:e}
addl 24({y}), {b2:e}
xorl {d1:e}, {tmp1:e}
xorl {d2:e}, {tmp2:e}
addl {tmp1:e}, {c1:e}
addl {tmp2:e}, {c2:e}
roll $16, {c1:e}
roll $16, {c2:e}
addl {d1:e}, {c1:e}
addl {d2:e}, {c2:e}
movl {a1:e}, {tmp1:e}
movl {a2:e}, {tmp2:e}
addl $0x04881d05, {b1:e}
addl $0x04881d05, {b2:e}
xorl {d1:e}, {tmp1:e}
xorl {d2:e}, {tmp2:e}
addl 36({x}), {a1:e}
addl 36({y}), {a2:e}
xorl {c1:e}, {tmp1:e}
xorl {c2:e}, {tmp2:e}
addl {tmp1:e}, {b1:e}
addl {tmp2:e}, {b2:e}
roll $23, {b1:e}
roll $23, {b2:e}
addl {c1:e}, {b1:e}
addl {c2:e}, {b2:e}
movl {d1:e}, {tmp1:e}
movl {d2:e}, {tmp2:e}
addl $-0x262b2fc7, {a1:e}
addl $-0x262b2fc7, {a2:e}
xorl {c1:e}, {tmp1:e}
xorl {c2:e}, {tmp2:e}
addl 48({x}), {d1:e}
addl 48({y}), {d2:e}
xorl {b1:e}, {tmp1:e}
xorl {b2:e}, {tmp2:e}
addl {tmp1:e}, {a1:e}
addl {tmp2:e}, {a2:e}
roll $4, {a1:e}
roll $4, {a2:e}
addl {b1:e}, {a1:e}
addl {b2:e}, {a2:e}
movl {c1:e}, {tmp1:e}
movl {c2:e}, {tmp2:e}
addl $-0x1924661b, {d1:e}
addl $-0x1924661b, {d2:e}
xorl {b1:e}, {tmp1:e}
xorl {b2:e}, {tmp2:e}
addl 60({x}), {c1:e}
addl 60({y}), {c2:e}
xorl {a1:e}, {tmp1:e}
xorl {a2:e}, {tmp2:e}
addl {tmp1:e}, {d1:e}
addl {tmp2:e}, {d2:e}
roll $11, {d1:e}
roll $11, {d2:e}
addl {a1:e}, {d1:e}
addl {a2:e}, {d2:e}
movl {b1:e}, {tmp1:e}
movl {b2:e}, {tmp2:e}
addl $0x1fa27cf8, {c1:e}
addl $0x1fa27cf8, {c2:e}
xorl {a1:e}, {tmp1:e}
xorl {a2:e}, {tmp2:e}
addl 8({x}), {b1:e}
addl 8({y}), {b2:e}
xorl {d1:e}, {tmp1:e}
xorl {d2:e}, {tmp2:e}
addl {tmp1:e}, {c1:e}
addl {tmp2:e}, {c2:e}
roll $16, {c1:e}
roll $16, {c2:e}
addl {d1:e}, {c1:e}
addl {d2:e}, {c2:e}
movl {a1:e}, {tmp1:e}
movl {a2:e}, {tmp2:e}
addl $-0x3b53a99b, {b1:e}
addl $-0x3b53a99b, {b2:e}
xorl {d1:e}, {tmp1:e}
xorl {d2:e}, {tmp2:e}
addl 0({x}), {a1:e}
addl 0({y}), {a2:e}
xorl {c1:e}, {tmp1:e}
xorl {c2:e}, {tmp2:e}
addl {tmp1:e}, {b1:e}
addl {tmp2:e}, {b2:e}
roll $23, {b1:e}
roll $23, {b2:e}
addl {c1:e}, {b1:e}
addl {c2:e}, {b2:e}
.if {bmi1}
addl $-0x0bd6ddbc-1, {a1:e}
addl $-0x0bd6ddbc-1, {a2:e}
andnl {d1:e}, {b1:e}, {tmp1:e}
andnl {d2:e}, {b2:e}, {tmp2:e}
xorl {c1:e}, {tmp1:e}
xorl {c2:e}, {tmp2:e}
addl 28({x}), {d1:e}
addl 28({y}), {d2:e}
subl {tmp1:e}, {a1:e}
subl {tmp2:e}, {a2:e}
roll $6, {a1:e}
roll $6, {a2:e}
addl {b1:e}, {a1:e}
addl {b2:e}, {a2:e}
.else
movl {d1:e}, {tmp1:e}
movl {d2:e}, {tmp2:e}
addl $-0x0bd6ddbc, {a1:e}
addl $-0x0bd6ddbc, {a2:e}
notl {tmp1:e}
notl {tmp2:e}
orl {b1:e}, {tmp1:e}
orl {b2:e}, {tmp2:e}
xorl {c1:e}, {tmp1:e}
xorl {c2:e}, {tmp2:e}
addl 28({x}), {d1:e}
addl 28({y}), {d2:e}
addl {tmp1:e}, {a1:e}
addl {tmp2:e}, {a2:e}
roll $6, {a1:e}
roll $6, {a2:e}
addl {b1:e}, {a1:e}
addl {b2:e}, {a2:e}
.endif
.if {bmi1}
addl $0x432aff97-1, {d1:e}
addl $0x432aff97-1, {d2:e}
andnl {c1:e}, {a1:e}, {tmp1:e}
andnl {c2:e}, {a2:e}, {tmp2:e}
xorl {b1:e}, {tmp1:e}
xorl {b2:e}, {tmp2:e}
addl 56({x}), {c1:e}
addl 56({y}), {c2:e}
subl {tmp1:e}, {d1:e}
subl {tmp2:e}, {d2:e}
roll $10, {d1:e}
roll $10, {d2:e}
addl {a1:e}, {d1:e}
addl {a2:e}, {d2:e}
.else
movl {c1:e}, {tmp1:e}
movl {c2:e}, {tmp2:e}
addl $0x432aff97, {d1:e}
addl $0x432aff97, {d2:e}
notl {tmp1:e}
notl {tmp2:e}
orl {a1:e}, {tmp1:e}
orl {a2:e}, {tmp2:e}
xorl {b1:e}, {tmp1:e}
xorl {b2:e}, {tmp2:e}
addl 56({x}), {c1:e}
addl 56({y}), {c2:e}
addl {tmp1:e}, {d1:e}
addl {tmp2:e}, {d2:e}
roll $10, {d1:e}
roll $10, {d2:e}
addl {a1:e}, {d1:e}
addl {a2:e}, {d2:e}
.endif
.if {bmi1}
addl $-0x546bdc59-1, {c1:e}
addl $-0x546bdc59-1, {c2:e}
andnl {b1:e}, {d1:e}, {tmp1:e}
andnl {b2:e}, {d2:e}, {tmp2:e}
xorl {a1:e}, {tmp1:e}
xorl {a2:e}, {tmp2:e}
addl 20({x}), {b1:e}
addl 20({y}), {b2:e}
subl {tmp1:e}, {c1:e}
subl {tmp2:e}, {c2:e}
roll $15, {c1:e}
roll $15, {c2:e}
addl {d1:e}, {c1:e}
addl {d2:e}, {c2:e}
.else
movl {b1:e}, {tmp1:e}
movl {b2:e}, {tmp2:e}
addl $-0x546bdc59, {c1:e}
addl $-0x546bdc59, {c2:e}
notl {tmp1:e}
notl {tmp2:e}
orl {d1:e}, {tmp1:e}
orl {d2:e}, {tmp2:e}
xorl {a1:e}, {tmp1:e}
xorl {a2:e}, {tmp2:e}
addl 20({x}), {b1:e}
addl 20({y}), {b2:e}
addl {tmp1:e}, {c1:e}
addl {tmp2:e}, {c2:e}
roll $15, {c1:e}
roll $15, {c2:e}
addl {d1:e}, {c1:e}
addl {d2:e}, {c2:e}
.endif
.if {bmi1}
addl $-0x036c5fc7-1, {b1:e}
addl $-0x036c5fc7-1, {b2:e}
andnl {a1:e}, {c1:e}, {tmp1:e}
andnl {a2:e}, {c2:e}, {tmp2:e}
xorl {d1:e}, {tmp1:e}
xorl {d2:e}, {tmp2:e}
addl 48({x}), {a1:e}
addl 48({y}), {a2:e}
subl {tmp1:e}, {b1:e}
subl {tmp2:e}, {b2:e}
roll $21, {b1:e}
roll $21, {b2:e}
addl {c1:e}, {b1:e}
addl {c2:e}, {b2:e}
.else
movl {a1:e}, {tmp1:e}
movl {a2:e}, {tmp2:e}
addl $-0x036c5fc7, {b1:e}
addl $-0x036c5fc7, {b2:e}
notl {tmp1:e}
notl {tmp2:e}
orl {c1:e}, {tmp1:e}
orl {c2:e}, {tmp2:e}
xorl {d1:e}, {tmp1:e}
xorl {d2:e}, {tmp2:e}
addl 48({x}), {a1:e}
addl 48({y}), {a2:e}
addl {tmp1:e}, {b1:e}
addl {tmp2:e}, {b2:e}
roll $21, {b1:e}
roll $21, {b2:e}
addl {c1:e}, {b1:e}
addl {c2:e}, {b2:e}
.endif
.if {bmi1}
addl $0x655b59c3-1, {a1:e}
addl $0x655b59c3-1, {a2:e}
andnl {d1:e}, {b1:e}, {tmp1:e}
andnl {d2:e}, {b2:e}, {tmp2:e}
xorl {c1:e}, {tmp1:e}
xorl {c2:e}, {tmp2:e}
addl 12({x}), {d1:e}
addl 12({y}), {d2:e}
subl {tmp1:e}, {a1:e}
subl {tmp2:e}, {a2:e}
roll $6, {a1:e}
roll $6, {a2:e}
addl {b1:e}, {a1:e}
addl {b2:e}, {a2:e}
.else
movl {d1:e}, {tmp1:e}
movl {d2:e}, {tmp2:e}
addl $0x655b59c3, {a1:e}
addl $0x655b59c3, {a2:e}
notl {tmp1:e}
notl {tmp2:e}
orl {b1:e}, {tmp1:e}
orl {b2:e}, {tmp2:e}
xorl {c1:e}, {tmp1:e}
xorl {c2:e}, {tmp2:e}
addl 12({x}), {d1:e}
addl 12({y}), {d2:e}
addl {tmp1:e}, {a1:e}
addl {tmp2:e}, {a2:e}
roll $6, {a1:e}
roll $6, {a2:e}
addl {b1:e}, {a1:e}
addl {b2:e}, {a2:e}
.endif
.if {bmi1}
addl $-0x70f3336e-1, {d1:e}
addl $-0x70f3336e-1, {d2:e}
andnl {c1:e}, {a1:e}, {tmp1:e}
andnl {c2:e}, {a2:e}, {tmp2:e}
xorl {b1:e}, {tmp1:e}
xorl {b2:e}, {tmp2:e}
addl 40({x}), {c1:e}
addl 40({y}), {c2:e}
subl {tmp1:e}, {d1:e}
subl {tmp2:e}, {d2:e}
roll $10, {d1:e}
roll $10, {d2:e}
addl {a1:e}, {d1:e}
addl {a2:e}, {d2:e}
.else
movl {c1:e}, {tmp1:e}
movl {c2:e}, {tmp2:e}
addl $-0x70f3336e, {d1:e}
addl $-0x70f3336e, {d2:e}
notl {tmp1:e}
notl {tmp2:e}
orl {a1:e}, {tmp1:e}
orl {a2:e}, {tmp2:e}
xorl {b1:e}, {tmp1:e}
xorl {b2:e}, {tmp2:e}
addl 40({x}), {c1:e}
addl 40({y}), {c2:e}
addl {tmp1:e}, {d1:e}
addl {tmp2:e}, {d2:e}
roll $10, {d1:e}
roll $10, {d2:e}
addl {a1:e}, {d1:e}
addl {a2:e}, {d2:e}
.endif
.if {bmi1}
addl $-0x00100b83-1, {c1:e}
addl $-0x00100b83-1, {c2:e}
andnl {b1:e}, {d1:e}, {tmp1:e}
andnl {b2:e}, {d2:e}, {tmp2:e}
xorl {a1:e}, {tmp1:e}
xorl {a2:e}, {tmp2:e}
addl 4({x}), {b1:e}
addl 4({y}), {b2:e}
subl {tmp1:e}, {c1:e}
subl {tmp2:e}, {c2:e}
roll $15, {c1:e}
roll $15, {c2:e}
addl {d1:e}, {c1:e}
addl {d2:e}, {c2:e}
.else
movl {b1:e}, {tmp1:e}
movl {b2:e}, {tmp2:e}
addl $-0x00100b83, {c1:e}
addl $-0x00100b83, {c2:e}
notl {tmp1:e}
notl {tmp2:e}
orl {d1:e}, {tmp1:e}
orl {d2:e}, {tmp2:e}
xorl {a1:e}, {tmp1:e}
xorl {a2:e}, {tmp2:e}
addl 4({x}), {b1:e}
addl 4({y}), {b2:e}
addl {tmp1:e}, {c1:e}
addl {tmp2:e}, {c2:e}
roll $15, {c1:e}
roll $15, {c2:e}
addl {d1:e}, {c1:e}
addl {d2:e}, {c2:e}
.endif
.if {bmi1}
addl $-0x7a7ba22f-1, {b1:e}
addl $-0x7a7ba22f-1, {b2:e}
andnl {a1:e}, {c1:e}, {tmp1:e}
andnl {a2:e}, {c2:e}, {tmp2:e}
xorl {d1:e}, {tmp1:e}
xorl {d2:e}, {tmp2:e}
addl 32({x}), {a1:e}
addl 32({y}), {a2:e}
subl {tmp1:e}, {b1:e}
subl {tmp2:e}, {b2:e}
roll $21, {b1:e}
roll $21, {b2:e}
addl {c1:e}, {b1:e}
addl {c2:e}, {b2:e}
.else
movl {a1:e}, {tmp1:e}
movl {a2:e}, {tmp2:e}
addl $-0x7a7ba22f, {b1:e}
addl $-0x7a7ba22f, {b2:e}
notl {tmp1:e}
notl {tmp2:e}
orl {c1:e}, {tmp1:e}
orl {c2:e}, {tmp2:e}
xorl {d1:e}, {tmp1:e}
xorl {d2:e}, {tmp2:e}
addl 32({x}), {a1:e}
addl 32({y}), {a2:e}
addl {tmp1:e}, {b1:e}
addl {tmp2:e}, {b2:e}
roll $21, {b1:e}
roll $21, {b2:e}
addl {c1:e}, {b1:e}
addl {c2:e}, {b2:e}
.endif
.if {bmi1}
addl $0x6fa87e4f-1, {a1:e}
addl $0x6fa87e4f-1, {a2:e}
andnl {d1:e}, {b1:e}, {tmp1:e}
andnl {d2:e}, {b2:e}, {tmp2:e}
xorl {c1:e}, {tmp1:e}
xorl {c2:e}, {tmp2:e}
addl 60({x}), {d1:e}
addl 60({y}), {d2:e}
subl {tmp1:e}, {a1:e}
subl {tmp2:e}, {a2:e}
roll $6, {a1:e}
roll $6, {a2:e}
addl {b1:e}, {a1:e}
addl {b2:e}, {a2:e}
.else
movl {d1:e}, {tmp1:e}
movl {d2:e}, {tmp2:e}
addl $0x6fa87e4f, {a1:e}
addl $0x6fa87e4f, {a2:e}
notl {tmp1:e}
notl {tmp2:e}
orl {b1:e}, {tmp1:e}
orl {b2:e}, {tmp2:e}
xorl {c1:e}, {tmp1:e}
xorl {c2:e}, {tmp2:e}
addl 60({x}), {d1:e}
addl 60({y}), {d2:e}
addl {tmp1:e}, {a1:e}
addl {tmp2:e}, {a2:e}
roll $6, {a1:e}
roll $6, {a2:e}
addl {b1:e}, {a1:e}
addl {b2:e}, {a2:e}
.endif
.if {bmi1}
addl $-0x01d31920-1, {d1:e}
addl $-0x01d31920-1, {d2:e}
andnl {c1:e}, {a1:e}, {tmp1:e}
andnl {c2:e}, {a2:e}, {tmp2:e}
xorl {b1:e}, {tmp1:e}
xorl {b2:e}, {tmp2:e}
addl 24({x}), {c1:e}
addl 24({y}), {c2:e}
subl {tmp1:e}, {d1:e}
subl {tmp2:e}, {d2:e}
roll $10, {d1:e}
roll $10, {d2:e}
addl {a1:e}, {d1:e}
addl {a2:e}, {d2:e}
.else
movl {c1:e}, {tmp1:e}
movl {c2:e}, {tmp2:e}
addl $-0x01d31920, {d1:e}
addl $-0x01d31920, {d2:e}
notl {tmp1:e}
notl {tmp2:e}
orl {a1:e}, {tmp1:e}
orl {a2:e}, {tmp2:e}
xorl {b1:e}, {tmp1:e}
xorl {b2:e}, {tmp2:e}
addl 24({x}), {c1:e}
addl 24({y}), {c2:e}
addl {tmp1:e}, {d1:e}
addl {tmp2:e}, {d2:e}
roll $10, {d1:e}
roll $10, {d2:e}
addl {a1:e}, {d1:e}
addl {a2:e}, {d2:e}
.endif
.if {bmi1}
addl $-0x5cfebcec-1, {c1:e}
addl $-0x5cfebcec-1, {c2:e}
andnl {b1:e}, {d1:e}, {tmp1:e}
andnl {b2:e}, {d2:e}, {tmp2:e}
xorl {a1:e}, {tmp1:e}
xorl {a2:e}, {tmp2:e}
addl 52({x}), {b1:e}
addl 52({y}), {b2:e}
subl {tmp1:e}, {c1:e}
subl {tmp2:e}, {c2:e}
roll $15, {c1:e}
roll $15, {c2:e}
addl {d1:e}, {c1:e}
addl {d2:e}, {c2:e}
.else
movl {b1:e}, {tmp1:e}
movl {b2:e}, {tmp2:e}
addl $-0x5cfebcec, {c1:e}
addl $-0x5cfebcec, {c2:e}
notl {tmp1:e}
notl {tmp2:e}
orl {d1:e}, {tmp1:e}
orl {d2:e}, {tmp2:e}
xorl {a1:e}, {tmp1:e}
xorl {a2:e}, {tmp2:e}
addl 52({x}), {b1:e}
addl 52({y}), {b2:e}
addl {tmp1:e}, {c1:e}
addl {tmp2:e}, {c2:e}
roll $15, {c1:e}
roll $15, {c2:e}
addl {d1:e}, {c1:e}
addl {d2:e}, {c2:e}
.endif
.if {bmi1}
addl $0x4e0811a1-1, {b1:e}
addl $0x4e0811a1-1, {b2:e}
andnl {a1:e}, {c1:e}, {tmp1:e}
andnl {a2:e}, {c2:e}, {tmp2:e}
xorl {d1:e}, {tmp1:e}
xorl {d2:e}, {tmp2:e}
addl 16({x}), {a1:e}
addl 16({y}), {a2:e}
subl {tmp1:e}, {b1:e}
subl {tmp2:e}, {b2:e}
roll $21, {b1:e}
roll $21, {b2:e}
addl {c1:e}, {b1:e}
addl {c2:e}, {b2:e}
.else
movl {a1:e}, {tmp1:e}
movl {a2:e}, {tmp2:e}
addl $0x4e0811a1, {b1:e}
addl $0x4e0811a1, {b2:e}
notl {tmp1:e}
notl {tmp2:e}
orl {c1:e}, {tmp1:e}
orl {c2:e}, {tmp2:e}
xorl {d1:e}, {tmp1:e}
xorl {d2:e}, {tmp2:e}
addl 16({x}), {a1:e}
addl 16({y}), {a2:e}
addl {tmp1:e}, {b1:e}
addl {tmp2:e}, {b2:e}
roll $21, {b1:e}
roll $21, {b2:e}
addl {c1:e}, {b1:e}
addl {c2:e}, {b2:e}
.endif
.if {bmi1}
addl $-0x08ac817e-1, {a1:e}
addl $-0x08ac817e-1, {a2:e}
andnl {d1:e}, {b1:e}, {tmp1:e}
andnl {d2:e}, {b2:e}, {tmp2:e}
xorl {c1:e}, {tmp1:e}
xorl {c2:e}, {tmp2:e}
addl 44({x}), {d1:e}
addl 44({y}), {d2:e}
subl {tmp1:e}, {a1:e}
subl {tmp2:e}, {a2:e}
roll $6, {a1:e}
roll $6, {a2:e}
addl {b1:e}, {a1:e}
addl {b2:e}, {a2:e}
.else
movl {d1:e}, {tmp1:e}
movl {d2:e}, {tmp2:e}
addl $-0x08ac817e, {a1:e}
addl $-0x08ac817e, {a2:e}
notl {tmp1:e}
notl {tmp2:e}
orl {b1:e}, {tmp1:e}
orl {b2:e}, {tmp2:e}
xorl {c1:e}, {tmp1:e}
xorl {c2:e}, {tmp2:e}
addl 44({x}), {d1:e}
addl 44({y}), {d2:e}
addl {tmp1:e}, {a1:e}
addl {tmp2:e}, {a2:e}
roll $6, {a1:e}
roll $6, {a2:e}
addl {b1:e}, {a1:e}
addl {b2:e}, {a2:e}
.endif
.if {bmi1}
addl $-0x42c50dcb-1, {d1:e}
addl $-0x42c50dcb-1, {d2:e}
andnl {c1:e}, {a1:e}, {tmp1:e}
andnl {c2:e}, {a2:e}, {tmp2:e}
xorl {b1:e}, {tmp1:e}
xorl {b2:e}, {tmp2:e}
addl 8({x}), {c1:e}
addl 8({y}), {c2:e}
subl {tmp1:e}, {d1:e}
subl {tmp2:e}, {d2:e}
roll $10, {d1:e}
roll $10, {d2:e}
addl {a1:e}, {d1:e}
addl {a2:e}, {d2:e}
.else
movl {c1:e}, {tmp1:e}
movl {c2:e}, {tmp2:e}
addl $-0x42c50dcb, {d1:e}
addl $-0x42c50dcb, {d2:e}
notl {tmp1:e}
notl {tmp2:e}
orl {a1:e}, {tmp1:e}
orl {a2:e}, {tmp2:e}
xorl {b1:e}, {tmp1:e}
xorl {b2:e}, {tmp2:e}
addl 8({x}), {c1:e}
addl 8({y}), {c2:e}
addl {tmp1:e}, {d1:e}
addl {tmp2:e}, {d2:e}
roll $10, {d1:e}
roll $10, {d2:e}
addl {a1:e}, {d1:e}
addl {a2:e}, {d2:e}
.endif
.if {bmi1}
addl $0x2ad7d2bb-1, {c1:e}
addl $0x2ad7d2bb-1, {c2:e}
andnl {b1:e}, {d1:e}, {tmp1:e}
andnl {b2:e}, {d2:e}, {tmp2:e}
xorl {a1:e}, {tmp1:e}
xorl {a2:e}, {tmp2:e}
addl 36({x}), {b1:e}
addl 36({y}), {b2:e}
subl {tmp1:e}, {c1:e}
subl {tmp2:e}, {c2:e}
roll $15, {c1:e}
roll $15, {c2:e}
addl {d1:e}, {c1:e}
addl {d2:e}, {c2:e}
.else
movl {b1:e}, {tmp1:e}
movl {b2:e}, {tmp2:e}
addl $0x2ad7d2bb, {c1:e}
addl $0x2ad7d2bb, {c2:e}
notl {tmp1:e}
notl {tmp2:e}
orl {d1:e}, {tmp1:e}
orl {d2:e}, {tmp2:e}
xorl {a1:e}, {tmp1:e}
xorl {a2:e}, {tmp2:e}
addl 36({x}), {b1:e}
addl 36({y}), {b2:e}
addl {tmp1:e}, {c1:e}
addl {tmp2:e}, {c2:e}
roll $15, {c1:e}
roll $15, {c2:e}
addl {d1:e}, {c1:e}
addl {d2:e}, {c2:e}
.endif
.if {bmi1}
addl $-0x14792c6f-1, {b1:e}
addl $-0x14792c6f-1, {b2:e}
andnl {a1:e}, {c1:e}, {tmp1:e}
andnl {a2:e}, {c2:e}, {tmp2:e}
xorl {d1:e}, {tmp1:e}
xorl {d2:e}, {tmp2:e}
subl {tmp1:e}, {b1:e}
subl {tmp2:e}, {b2:e}
roll $21, {b1:e}
roll $21, {b2:e}
addl {c1:e}, {b1:e}
addl {c2:e}, {b2:e}
.else
movl {a1:e}, {tmp1:e}
movl {a2:e}, {tmp2:e}
addl $-0x14792c6f, {b1:e}
addl $-0x14792c6f, {b2:e}
notl {tmp1:e}
notl {tmp2:e}
orl {c1:e}, {tmp1:e}
orl {c2:e}, {tmp2:e}
xorl {d1:e}, {tmp1:e}
xorl {d2:e}, {tmp2:e}
addl {tmp1:e}, {b1:e}
addl {tmp2:e}, {b2:e}
roll $21, {b1:e}
roll $21, {b2:e}
addl {c1:e}, {b1:e}
addl {c2:e}, {b2:e}
.endif
