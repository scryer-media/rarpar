ldr {tmp1:w}, [{x}]
ldr {tmp2:w}, [{y}]
add {a1:w}, {a1:w}, {tmp1:w}
mov {tmp1:w}, #0xa478
add {a2:w}, {a2:w}, {tmp2:w}
movk {tmp1:w}, #0xd76a, lsl #16
eor {tmp2:w}, {c2:w}, {d2:w}
add {a1:w}, {a1:w}, {tmp1:w}
add {a2:w}, {a2:w}, {tmp1:w}
eor {tmp1:w}, {c1:w}, {d1:w}
and {tmp2:w}, {tmp2:w}, {b2:w}
and {tmp1:w}, {tmp1:w}, {b1:w}
eor {tmp2:w}, {tmp2:w}, {d2:w}
eor {tmp1:w}, {tmp1:w}, {d1:w}
add {a2:w}, {a2:w}, {tmp2:w}
add {a1:w}, {a1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #4]
ldr {tmp2:w}, [{y}, #4]
ror {a1:w}, {a1:w}, #25
ror {a2:w}, {a2:w}, #25
add {a1:w}, {a1:w}, {b1:w}
add {a2:w}, {a2:w}, {b2:w}
add {d1:w}, {d1:w}, {tmp1:w}
mov {tmp1:w}, #0xb756
add {d2:w}, {d2:w}, {tmp2:w}
movk {tmp1:w}, #0xe8c7, lsl #16
eor {tmp2:w}, {b2:w}, {c2:w}
add {d1:w}, {d1:w}, {tmp1:w}
add {d2:w}, {d2:w}, {tmp1:w}
eor {tmp1:w}, {b1:w}, {c1:w}
and {tmp2:w}, {tmp2:w}, {a2:w}
and {tmp1:w}, {tmp1:w}, {a1:w}
eor {tmp2:w}, {tmp2:w}, {c2:w}
eor {tmp1:w}, {tmp1:w}, {c1:w}
add {d2:w}, {d2:w}, {tmp2:w}
add {d1:w}, {d1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #8]
ldr {tmp2:w}, [{y}, #8]
ror {d1:w}, {d1:w}, #20
ror {d2:w}, {d2:w}, #20
add {d1:w}, {d1:w}, {a1:w}
add {d2:w}, {d2:w}, {a2:w}
add {c1:w}, {c1:w}, {tmp1:w}
mov {tmp1:w}, #0x70db
add {c2:w}, {c2:w}, {tmp2:w}
movk {tmp1:w}, #0x2420, lsl #16
eor {tmp2:w}, {a2:w}, {b2:w}
add {c1:w}, {c1:w}, {tmp1:w}
add {c2:w}, {c2:w}, {tmp1:w}
eor {tmp1:w}, {a1:w}, {b1:w}
and {tmp2:w}, {tmp2:w}, {d2:w}
and {tmp1:w}, {tmp1:w}, {d1:w}
eor {tmp2:w}, {tmp2:w}, {b2:w}
eor {tmp1:w}, {tmp1:w}, {b1:w}
add {c2:w}, {c2:w}, {tmp2:w}
add {c1:w}, {c1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #12]
ldr {tmp2:w}, [{y}, #12]
ror {c1:w}, {c1:w}, #15
ror {c2:w}, {c2:w}, #15
add {c1:w}, {c1:w}, {d1:w}
add {c2:w}, {c2:w}, {d2:w}
add {b1:w}, {b1:w}, {tmp1:w}
mov {tmp1:w}, #0xceee
add {b2:w}, {b2:w}, {tmp2:w}
movk {tmp1:w}, #0xc1bd, lsl #16
eor {tmp2:w}, {d2:w}, {a2:w}
add {b1:w}, {b1:w}, {tmp1:w}
add {b2:w}, {b2:w}, {tmp1:w}
eor {tmp1:w}, {d1:w}, {a1:w}
and {tmp2:w}, {tmp2:w}, {c2:w}
and {tmp1:w}, {tmp1:w}, {c1:w}
eor {tmp2:w}, {tmp2:w}, {a2:w}
eor {tmp1:w}, {tmp1:w}, {a1:w}
add {b2:w}, {b2:w}, {tmp2:w}
add {b1:w}, {b1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #16]
ldr {tmp2:w}, [{y}, #16]
ror {b1:w}, {b1:w}, #10
ror {b2:w}, {b2:w}, #10
add {b1:w}, {b1:w}, {c1:w}
add {b2:w}, {b2:w}, {c2:w}
add {a1:w}, {a1:w}, {tmp1:w}
mov {tmp1:w}, #0x0faf
add {a2:w}, {a2:w}, {tmp2:w}
movk {tmp1:w}, #0xf57c, lsl #16
eor {tmp2:w}, {c2:w}, {d2:w}
add {a1:w}, {a1:w}, {tmp1:w}
add {a2:w}, {a2:w}, {tmp1:w}
eor {tmp1:w}, {c1:w}, {d1:w}
and {tmp2:w}, {tmp2:w}, {b2:w}
and {tmp1:w}, {tmp1:w}, {b1:w}
eor {tmp2:w}, {tmp2:w}, {d2:w}
eor {tmp1:w}, {tmp1:w}, {d1:w}
add {a2:w}, {a2:w}, {tmp2:w}
add {a1:w}, {a1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #20]
ldr {tmp2:w}, [{y}, #20]
ror {a1:w}, {a1:w}, #25
ror {a2:w}, {a2:w}, #25
add {a1:w}, {a1:w}, {b1:w}
add {a2:w}, {a2:w}, {b2:w}
add {d1:w}, {d1:w}, {tmp1:w}
mov {tmp1:w}, #0xc62a
add {d2:w}, {d2:w}, {tmp2:w}
movk {tmp1:w}, #0x4787, lsl #16
eor {tmp2:w}, {b2:w}, {c2:w}
add {d1:w}, {d1:w}, {tmp1:w}
add {d2:w}, {d2:w}, {tmp1:w}
eor {tmp1:w}, {b1:w}, {c1:w}
and {tmp2:w}, {tmp2:w}, {a2:w}
and {tmp1:w}, {tmp1:w}, {a1:w}
eor {tmp2:w}, {tmp2:w}, {c2:w}
eor {tmp1:w}, {tmp1:w}, {c1:w}
add {d2:w}, {d2:w}, {tmp2:w}
add {d1:w}, {d1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #24]
ldr {tmp2:w}, [{y}, #24]
ror {d1:w}, {d1:w}, #20
ror {d2:w}, {d2:w}, #20
add {d1:w}, {d1:w}, {a1:w}
add {d2:w}, {d2:w}, {a2:w}
add {c1:w}, {c1:w}, {tmp1:w}
mov {tmp1:w}, #0x4613
add {c2:w}, {c2:w}, {tmp2:w}
movk {tmp1:w}, #0xa830, lsl #16
eor {tmp2:w}, {a2:w}, {b2:w}
add {c1:w}, {c1:w}, {tmp1:w}
add {c2:w}, {c2:w}, {tmp1:w}
eor {tmp1:w}, {a1:w}, {b1:w}
and {tmp2:w}, {tmp2:w}, {d2:w}
and {tmp1:w}, {tmp1:w}, {d1:w}
eor {tmp2:w}, {tmp2:w}, {b2:w}
eor {tmp1:w}, {tmp1:w}, {b1:w}
add {c2:w}, {c2:w}, {tmp2:w}
add {c1:w}, {c1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #28]
ldr {tmp2:w}, [{y}, #28]
ror {c1:w}, {c1:w}, #15
ror {c2:w}, {c2:w}, #15
add {c1:w}, {c1:w}, {d1:w}
add {c2:w}, {c2:w}, {d2:w}
add {b1:w}, {b1:w}, {tmp1:w}
mov {tmp1:w}, #0x9501
add {b2:w}, {b2:w}, {tmp2:w}
movk {tmp1:w}, #0xfd46, lsl #16
eor {tmp2:w}, {d2:w}, {a2:w}
add {b1:w}, {b1:w}, {tmp1:w}
add {b2:w}, {b2:w}, {tmp1:w}
eor {tmp1:w}, {d1:w}, {a1:w}
and {tmp2:w}, {tmp2:w}, {c2:w}
and {tmp1:w}, {tmp1:w}, {c1:w}
eor {tmp2:w}, {tmp2:w}, {a2:w}
eor {tmp1:w}, {tmp1:w}, {a1:w}
add {b2:w}, {b2:w}, {tmp2:w}
add {b1:w}, {b1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #32]
ldr {tmp2:w}, [{y}, #32]
ror {b1:w}, {b1:w}, #10
ror {b2:w}, {b2:w}, #10
add {b1:w}, {b1:w}, {c1:w}
add {b2:w}, {b2:w}, {c2:w}
add {a1:w}, {a1:w}, {tmp1:w}
mov {tmp1:w}, #0x98d8
add {a2:w}, {a2:w}, {tmp2:w}
movk {tmp1:w}, #0x6980, lsl #16
eor {tmp2:w}, {c2:w}, {d2:w}
add {a1:w}, {a1:w}, {tmp1:w}
add {a2:w}, {a2:w}, {tmp1:w}
eor {tmp1:w}, {c1:w}, {d1:w}
and {tmp2:w}, {tmp2:w}, {b2:w}
and {tmp1:w}, {tmp1:w}, {b1:w}
eor {tmp2:w}, {tmp2:w}, {d2:w}
eor {tmp1:w}, {tmp1:w}, {d1:w}
add {a2:w}, {a2:w}, {tmp2:w}
add {a1:w}, {a1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #36]
ldr {tmp2:w}, [{y}, #36]
ror {a1:w}, {a1:w}, #25
ror {a2:w}, {a2:w}, #25
add {a1:w}, {a1:w}, {b1:w}
add {a2:w}, {a2:w}, {b2:w}
add {d1:w}, {d1:w}, {tmp1:w}
mov {tmp1:w}, #0xf7af
add {d2:w}, {d2:w}, {tmp2:w}
movk {tmp1:w}, #0x8b44, lsl #16
eor {tmp2:w}, {b2:w}, {c2:w}
add {d1:w}, {d1:w}, {tmp1:w}
add {d2:w}, {d2:w}, {tmp1:w}
eor {tmp1:w}, {b1:w}, {c1:w}
and {tmp2:w}, {tmp2:w}, {a2:w}
and {tmp1:w}, {tmp1:w}, {a1:w}
eor {tmp2:w}, {tmp2:w}, {c2:w}
eor {tmp1:w}, {tmp1:w}, {c1:w}
add {d2:w}, {d2:w}, {tmp2:w}
add {d1:w}, {d1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #40]
ldr {tmp2:w}, [{y}, #40]
ror {d1:w}, {d1:w}, #20
ror {d2:w}, {d2:w}, #20
add {d1:w}, {d1:w}, {a1:w}
add {d2:w}, {d2:w}, {a2:w}
add {c1:w}, {c1:w}, {tmp1:w}
mov {tmp1:w}, #0x5bb1
add {c2:w}, {c2:w}, {tmp2:w}
movk {tmp1:w}, #0xffff, lsl #16
eor {tmp2:w}, {a2:w}, {b2:w}
add {c1:w}, {c1:w}, {tmp1:w}
add {c2:w}, {c2:w}, {tmp1:w}
eor {tmp1:w}, {a1:w}, {b1:w}
and {tmp2:w}, {tmp2:w}, {d2:w}
and {tmp1:w}, {tmp1:w}, {d1:w}
eor {tmp2:w}, {tmp2:w}, {b2:w}
eor {tmp1:w}, {tmp1:w}, {b1:w}
add {c2:w}, {c2:w}, {tmp2:w}
add {c1:w}, {c1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #44]
ldr {tmp2:w}, [{y}, #44]
ror {c1:w}, {c1:w}, #15
ror {c2:w}, {c2:w}, #15
add {c1:w}, {c1:w}, {d1:w}
add {c2:w}, {c2:w}, {d2:w}
add {b1:w}, {b1:w}, {tmp1:w}
mov {tmp1:w}, #0xd7be
add {b2:w}, {b2:w}, {tmp2:w}
movk {tmp1:w}, #0x895c, lsl #16
eor {tmp2:w}, {d2:w}, {a2:w}
add {b1:w}, {b1:w}, {tmp1:w}
add {b2:w}, {b2:w}, {tmp1:w}
eor {tmp1:w}, {d1:w}, {a1:w}
and {tmp2:w}, {tmp2:w}, {c2:w}
and {tmp1:w}, {tmp1:w}, {c1:w}
eor {tmp2:w}, {tmp2:w}, {a2:w}
eor {tmp1:w}, {tmp1:w}, {a1:w}
add {b2:w}, {b2:w}, {tmp2:w}
add {b1:w}, {b1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #48]
ldr {tmp2:w}, [{y}, #48]
ror {b1:w}, {b1:w}, #10
ror {b2:w}, {b2:w}, #10
add {b1:w}, {b1:w}, {c1:w}
add {b2:w}, {b2:w}, {c2:w}
add {a1:w}, {a1:w}, {tmp1:w}
mov {tmp1:w}, #0x1122
add {a2:w}, {a2:w}, {tmp2:w}
movk {tmp1:w}, #0x6b90, lsl #16
eor {tmp2:w}, {c2:w}, {d2:w}
add {a1:w}, {a1:w}, {tmp1:w}
add {a2:w}, {a2:w}, {tmp1:w}
eor {tmp1:w}, {c1:w}, {d1:w}
and {tmp2:w}, {tmp2:w}, {b2:w}
and {tmp1:w}, {tmp1:w}, {b1:w}
eor {tmp2:w}, {tmp2:w}, {d2:w}
eor {tmp1:w}, {tmp1:w}, {d1:w}
add {a2:w}, {a2:w}, {tmp2:w}
add {a1:w}, {a1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #52]
ldr {tmp2:w}, [{y}, #52]
ror {a1:w}, {a1:w}, #25
ror {a2:w}, {a2:w}, #25
add {a1:w}, {a1:w}, {b1:w}
add {a2:w}, {a2:w}, {b2:w}
add {d1:w}, {d1:w}, {tmp1:w}
mov {tmp1:w}, #0x7193
add {d2:w}, {d2:w}, {tmp2:w}
movk {tmp1:w}, #0xfd98, lsl #16
eor {tmp2:w}, {b2:w}, {c2:w}
add {d1:w}, {d1:w}, {tmp1:w}
add {d2:w}, {d2:w}, {tmp1:w}
eor {tmp1:w}, {b1:w}, {c1:w}
and {tmp2:w}, {tmp2:w}, {a2:w}
and {tmp1:w}, {tmp1:w}, {a1:w}
eor {tmp2:w}, {tmp2:w}, {c2:w}
eor {tmp1:w}, {tmp1:w}, {c1:w}
add {d2:w}, {d2:w}, {tmp2:w}
add {d1:w}, {d1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #56]
ldr {tmp2:w}, [{y}, #56]
ror {d1:w}, {d1:w}, #20
ror {d2:w}, {d2:w}, #20
add {d1:w}, {d1:w}, {a1:w}
add {d2:w}, {d2:w}, {a2:w}
add {c1:w}, {c1:w}, {tmp1:w}
mov {tmp1:w}, #0x438e
add {c2:w}, {c2:w}, {tmp2:w}
movk {tmp1:w}, #0xa679, lsl #16
eor {tmp2:w}, {a2:w}, {b2:w}
add {c1:w}, {c1:w}, {tmp1:w}
add {c2:w}, {c2:w}, {tmp1:w}
eor {tmp1:w}, {a1:w}, {b1:w}
and {tmp2:w}, {tmp2:w}, {d2:w}
and {tmp1:w}, {tmp1:w}, {d1:w}
eor {tmp2:w}, {tmp2:w}, {b2:w}
eor {tmp1:w}, {tmp1:w}, {b1:w}
add {c2:w}, {c2:w}, {tmp2:w}
add {c1:w}, {c1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #60]
ldr {tmp2:w}, [{y}, #60]
ror {c1:w}, {c1:w}, #15
ror {c2:w}, {c2:w}, #15
add {c1:w}, {c1:w}, {d1:w}
add {c2:w}, {c2:w}, {d2:w}
add {b1:w}, {b1:w}, {tmp1:w}
mov {tmp1:w}, #0x0821
add {b2:w}, {b2:w}, {tmp2:w}
movk {tmp1:w}, #0x49b4, lsl #16
eor {tmp2:w}, {d2:w}, {a2:w}
add {b1:w}, {b1:w}, {tmp1:w}
add {b2:w}, {b2:w}, {tmp1:w}
eor {tmp1:w}, {d1:w}, {a1:w}
and {tmp2:w}, {tmp2:w}, {c2:w}
and {tmp1:w}, {tmp1:w}, {c1:w}
eor {tmp2:w}, {tmp2:w}, {a2:w}
eor {tmp1:w}, {tmp1:w}, {a1:w}
add {b2:w}, {b2:w}, {tmp2:w}
add {b1:w}, {b1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #4]
ldr {tmp2:w}, [{y}, #4]
ror {b1:w}, {b1:w}, #10
ror {b2:w}, {b2:w}, #10
add {b1:w}, {b1:w}, {c1:w}
add {b2:w}, {b2:w}, {c2:w}
add {a1:w}, {a1:w}, {tmp1:w}
mov {tmp1:w}, #0x2562
add {a2:w}, {a2:w}, {tmp2:w}
movk {tmp1:w}, #0xf61e, lsl #16
bic {tmp2:w}, {c2:w}, {d2:w}
add {a1:w}, {a1:w}, {tmp1:w}
add {a2:w}, {a2:w}, {tmp1:w}
bic {tmp1:w}, {c1:w}, {d1:w}
add {a2:w}, {a2:w}, {tmp2:w}
add {a1:w}, {a1:w}, {tmp1:w}
and {tmp2:w}, {b2:w}, {d2:w}
and {tmp1:w}, {b1:w}, {d1:w}
add {a2:w}, {a2:w}, {tmp2:w}
add {a1:w}, {a1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #24]
ldr {tmp2:w}, [{y}, #24]
ror {a1:w}, {a1:w}, #27
ror {a2:w}, {a2:w}, #27
add {a1:w}, {a1:w}, {b1:w}
add {a2:w}, {a2:w}, {b2:w}
add {d1:w}, {d1:w}, {tmp1:w}
mov {tmp1:w}, #0xb340
add {d2:w}, {d2:w}, {tmp2:w}
movk {tmp1:w}, #0xc040, lsl #16
bic {tmp2:w}, {b2:w}, {c2:w}
add {d1:w}, {d1:w}, {tmp1:w}
add {d2:w}, {d2:w}, {tmp1:w}
bic {tmp1:w}, {b1:w}, {c1:w}
add {d2:w}, {d2:w}, {tmp2:w}
add {d1:w}, {d1:w}, {tmp1:w}
and {tmp2:w}, {a2:w}, {c2:w}
and {tmp1:w}, {a1:w}, {c1:w}
add {d2:w}, {d2:w}, {tmp2:w}
add {d1:w}, {d1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #44]
ldr {tmp2:w}, [{y}, #44]
ror {d1:w}, {d1:w}, #23
ror {d2:w}, {d2:w}, #23
add {d1:w}, {d1:w}, {a1:w}
add {d2:w}, {d2:w}, {a2:w}
add {c1:w}, {c1:w}, {tmp1:w}
mov {tmp1:w}, #0x5a51
add {c2:w}, {c2:w}, {tmp2:w}
movk {tmp1:w}, #0x265e, lsl #16
bic {tmp2:w}, {a2:w}, {b2:w}
add {c1:w}, {c1:w}, {tmp1:w}
add {c2:w}, {c2:w}, {tmp1:w}
bic {tmp1:w}, {a1:w}, {b1:w}
add {c2:w}, {c2:w}, {tmp2:w}
add {c1:w}, {c1:w}, {tmp1:w}
and {tmp2:w}, {d2:w}, {b2:w}
and {tmp1:w}, {d1:w}, {b1:w}
add {c2:w}, {c2:w}, {tmp2:w}
add {c1:w}, {c1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #0]
ldr {tmp2:w}, [{y}, #0]
ror {c1:w}, {c1:w}, #18
ror {c2:w}, {c2:w}, #18
add {c1:w}, {c1:w}, {d1:w}
add {c2:w}, {c2:w}, {d2:w}
add {b1:w}, {b1:w}, {tmp1:w}
mov {tmp1:w}, #0xc7aa
add {b2:w}, {b2:w}, {tmp2:w}
movk {tmp1:w}, #0xe9b6, lsl #16
bic {tmp2:w}, {d2:w}, {a2:w}
add {b1:w}, {b1:w}, {tmp1:w}
add {b2:w}, {b2:w}, {tmp1:w}
bic {tmp1:w}, {d1:w}, {a1:w}
add {b2:w}, {b2:w}, {tmp2:w}
add {b1:w}, {b1:w}, {tmp1:w}
and {tmp2:w}, {c2:w}, {a2:w}
and {tmp1:w}, {c1:w}, {a1:w}
add {b2:w}, {b2:w}, {tmp2:w}
add {b1:w}, {b1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #20]
ldr {tmp2:w}, [{y}, #20]
ror {b1:w}, {b1:w}, #12
ror {b2:w}, {b2:w}, #12
add {b1:w}, {b1:w}, {c1:w}
add {b2:w}, {b2:w}, {c2:w}
add {a1:w}, {a1:w}, {tmp1:w}
mov {tmp1:w}, #0x105d
add {a2:w}, {a2:w}, {tmp2:w}
movk {tmp1:w}, #0xd62f, lsl #16
bic {tmp2:w}, {c2:w}, {d2:w}
add {a1:w}, {a1:w}, {tmp1:w}
add {a2:w}, {a2:w}, {tmp1:w}
bic {tmp1:w}, {c1:w}, {d1:w}
add {a2:w}, {a2:w}, {tmp2:w}
add {a1:w}, {a1:w}, {tmp1:w}
and {tmp2:w}, {b2:w}, {d2:w}
and {tmp1:w}, {b1:w}, {d1:w}
add {a2:w}, {a2:w}, {tmp2:w}
add {a1:w}, {a1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #40]
ldr {tmp2:w}, [{y}, #40]
ror {a1:w}, {a1:w}, #27
ror {a2:w}, {a2:w}, #27
add {a1:w}, {a1:w}, {b1:w}
add {a2:w}, {a2:w}, {b2:w}
add {d1:w}, {d1:w}, {tmp1:w}
mov {tmp1:w}, #0x1453
add {d2:w}, {d2:w}, {tmp2:w}
movk {tmp1:w}, #0x0244, lsl #16
bic {tmp2:w}, {b2:w}, {c2:w}
add {d1:w}, {d1:w}, {tmp1:w}
add {d2:w}, {d2:w}, {tmp1:w}
bic {tmp1:w}, {b1:w}, {c1:w}
add {d2:w}, {d2:w}, {tmp2:w}
add {d1:w}, {d1:w}, {tmp1:w}
and {tmp2:w}, {a2:w}, {c2:w}
and {tmp1:w}, {a1:w}, {c1:w}
add {d2:w}, {d2:w}, {tmp2:w}
add {d1:w}, {d1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #60]
ldr {tmp2:w}, [{y}, #60]
ror {d1:w}, {d1:w}, #23
ror {d2:w}, {d2:w}, #23
add {d1:w}, {d1:w}, {a1:w}
add {d2:w}, {d2:w}, {a2:w}
add {c1:w}, {c1:w}, {tmp1:w}
mov {tmp1:w}, #0xe681
add {c2:w}, {c2:w}, {tmp2:w}
movk {tmp1:w}, #0xd8a1, lsl #16
bic {tmp2:w}, {a2:w}, {b2:w}
add {c1:w}, {c1:w}, {tmp1:w}
add {c2:w}, {c2:w}, {tmp1:w}
bic {tmp1:w}, {a1:w}, {b1:w}
add {c2:w}, {c2:w}, {tmp2:w}
add {c1:w}, {c1:w}, {tmp1:w}
and {tmp2:w}, {d2:w}, {b2:w}
and {tmp1:w}, {d1:w}, {b1:w}
add {c2:w}, {c2:w}, {tmp2:w}
add {c1:w}, {c1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #16]
ldr {tmp2:w}, [{y}, #16]
ror {c1:w}, {c1:w}, #18
ror {c2:w}, {c2:w}, #18
add {c1:w}, {c1:w}, {d1:w}
add {c2:w}, {c2:w}, {d2:w}
add {b1:w}, {b1:w}, {tmp1:w}
mov {tmp1:w}, #0xfbc8
add {b2:w}, {b2:w}, {tmp2:w}
movk {tmp1:w}, #0xe7d3, lsl #16
bic {tmp2:w}, {d2:w}, {a2:w}
add {b1:w}, {b1:w}, {tmp1:w}
add {b2:w}, {b2:w}, {tmp1:w}
bic {tmp1:w}, {d1:w}, {a1:w}
add {b2:w}, {b2:w}, {tmp2:w}
add {b1:w}, {b1:w}, {tmp1:w}
and {tmp2:w}, {c2:w}, {a2:w}
and {tmp1:w}, {c1:w}, {a1:w}
add {b2:w}, {b2:w}, {tmp2:w}
add {b1:w}, {b1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #36]
ldr {tmp2:w}, [{y}, #36]
ror {b1:w}, {b1:w}, #12
ror {b2:w}, {b2:w}, #12
add {b1:w}, {b1:w}, {c1:w}
add {b2:w}, {b2:w}, {c2:w}
add {a1:w}, {a1:w}, {tmp1:w}
mov {tmp1:w}, #0xcde6
add {a2:w}, {a2:w}, {tmp2:w}
movk {tmp1:w}, #0x21e1, lsl #16
bic {tmp2:w}, {c2:w}, {d2:w}
add {a1:w}, {a1:w}, {tmp1:w}
add {a2:w}, {a2:w}, {tmp1:w}
bic {tmp1:w}, {c1:w}, {d1:w}
add {a2:w}, {a2:w}, {tmp2:w}
add {a1:w}, {a1:w}, {tmp1:w}
and {tmp2:w}, {b2:w}, {d2:w}
and {tmp1:w}, {b1:w}, {d1:w}
add {a2:w}, {a2:w}, {tmp2:w}
add {a1:w}, {a1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #56]
ldr {tmp2:w}, [{y}, #56]
ror {a1:w}, {a1:w}, #27
ror {a2:w}, {a2:w}, #27
add {a1:w}, {a1:w}, {b1:w}
add {a2:w}, {a2:w}, {b2:w}
add {d1:w}, {d1:w}, {tmp1:w}
mov {tmp1:w}, #0x07d6
add {d2:w}, {d2:w}, {tmp2:w}
movk {tmp1:w}, #0xc337, lsl #16
bic {tmp2:w}, {b2:w}, {c2:w}
add {d1:w}, {d1:w}, {tmp1:w}
add {d2:w}, {d2:w}, {tmp1:w}
bic {tmp1:w}, {b1:w}, {c1:w}
add {d2:w}, {d2:w}, {tmp2:w}
add {d1:w}, {d1:w}, {tmp1:w}
and {tmp2:w}, {a2:w}, {c2:w}
and {tmp1:w}, {a1:w}, {c1:w}
add {d2:w}, {d2:w}, {tmp2:w}
add {d1:w}, {d1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #12]
ldr {tmp2:w}, [{y}, #12]
ror {d1:w}, {d1:w}, #23
ror {d2:w}, {d2:w}, #23
add {d1:w}, {d1:w}, {a1:w}
add {d2:w}, {d2:w}, {a2:w}
add {c1:w}, {c1:w}, {tmp1:w}
mov {tmp1:w}, #0x0d87
add {c2:w}, {c2:w}, {tmp2:w}
movk {tmp1:w}, #0xf4d5, lsl #16
bic {tmp2:w}, {a2:w}, {b2:w}
add {c1:w}, {c1:w}, {tmp1:w}
add {c2:w}, {c2:w}, {tmp1:w}
bic {tmp1:w}, {a1:w}, {b1:w}
add {c2:w}, {c2:w}, {tmp2:w}
add {c1:w}, {c1:w}, {tmp1:w}
and {tmp2:w}, {d2:w}, {b2:w}
and {tmp1:w}, {d1:w}, {b1:w}
add {c2:w}, {c2:w}, {tmp2:w}
add {c1:w}, {c1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #32]
ldr {tmp2:w}, [{y}, #32]
ror {c1:w}, {c1:w}, #18
ror {c2:w}, {c2:w}, #18
add {c1:w}, {c1:w}, {d1:w}
add {c2:w}, {c2:w}, {d2:w}
add {b1:w}, {b1:w}, {tmp1:w}
mov {tmp1:w}, #0x14ed
add {b2:w}, {b2:w}, {tmp2:w}
movk {tmp1:w}, #0x455a, lsl #16
bic {tmp2:w}, {d2:w}, {a2:w}
add {b1:w}, {b1:w}, {tmp1:w}
add {b2:w}, {b2:w}, {tmp1:w}
bic {tmp1:w}, {d1:w}, {a1:w}
add {b2:w}, {b2:w}, {tmp2:w}
add {b1:w}, {b1:w}, {tmp1:w}
and {tmp2:w}, {c2:w}, {a2:w}
and {tmp1:w}, {c1:w}, {a1:w}
add {b2:w}, {b2:w}, {tmp2:w}
add {b1:w}, {b1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #52]
ldr {tmp2:w}, [{y}, #52]
ror {b1:w}, {b1:w}, #12
ror {b2:w}, {b2:w}, #12
add {b1:w}, {b1:w}, {c1:w}
add {b2:w}, {b2:w}, {c2:w}
add {a1:w}, {a1:w}, {tmp1:w}
mov {tmp1:w}, #0xe905
add {a2:w}, {a2:w}, {tmp2:w}
movk {tmp1:w}, #0xa9e3, lsl #16
bic {tmp2:w}, {c2:w}, {d2:w}
add {a1:w}, {a1:w}, {tmp1:w}
add {a2:w}, {a2:w}, {tmp1:w}
bic {tmp1:w}, {c1:w}, {d1:w}
add {a2:w}, {a2:w}, {tmp2:w}
add {a1:w}, {a1:w}, {tmp1:w}
and {tmp2:w}, {b2:w}, {d2:w}
and {tmp1:w}, {b1:w}, {d1:w}
add {a2:w}, {a2:w}, {tmp2:w}
add {a1:w}, {a1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #8]
ldr {tmp2:w}, [{y}, #8]
ror {a1:w}, {a1:w}, #27
ror {a2:w}, {a2:w}, #27
add {a1:w}, {a1:w}, {b1:w}
add {a2:w}, {a2:w}, {b2:w}
add {d1:w}, {d1:w}, {tmp1:w}
mov {tmp1:w}, #0xa3f8
add {d2:w}, {d2:w}, {tmp2:w}
movk {tmp1:w}, #0xfcef, lsl #16
bic {tmp2:w}, {b2:w}, {c2:w}
add {d1:w}, {d1:w}, {tmp1:w}
add {d2:w}, {d2:w}, {tmp1:w}
bic {tmp1:w}, {b1:w}, {c1:w}
add {d2:w}, {d2:w}, {tmp2:w}
add {d1:w}, {d1:w}, {tmp1:w}
and {tmp2:w}, {a2:w}, {c2:w}
and {tmp1:w}, {a1:w}, {c1:w}
add {d2:w}, {d2:w}, {tmp2:w}
add {d1:w}, {d1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #28]
ldr {tmp2:w}, [{y}, #28]
ror {d1:w}, {d1:w}, #23
ror {d2:w}, {d2:w}, #23
add {d1:w}, {d1:w}, {a1:w}
add {d2:w}, {d2:w}, {a2:w}
add {c1:w}, {c1:w}, {tmp1:w}
mov {tmp1:w}, #0x02d9
add {c2:w}, {c2:w}, {tmp2:w}
movk {tmp1:w}, #0x676f, lsl #16
bic {tmp2:w}, {a2:w}, {b2:w}
add {c1:w}, {c1:w}, {tmp1:w}
add {c2:w}, {c2:w}, {tmp1:w}
bic {tmp1:w}, {a1:w}, {b1:w}
add {c2:w}, {c2:w}, {tmp2:w}
add {c1:w}, {c1:w}, {tmp1:w}
and {tmp2:w}, {d2:w}, {b2:w}
and {tmp1:w}, {d1:w}, {b1:w}
add {c2:w}, {c2:w}, {tmp2:w}
add {c1:w}, {c1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #48]
ldr {tmp2:w}, [{y}, #48]
ror {c1:w}, {c1:w}, #18
ror {c2:w}, {c2:w}, #18
add {c1:w}, {c1:w}, {d1:w}
add {c2:w}, {c2:w}, {d2:w}
add {b1:w}, {b1:w}, {tmp1:w}
mov {tmp1:w}, #0x4c8a
add {b2:w}, {b2:w}, {tmp2:w}
movk {tmp1:w}, #0x8d2a, lsl #16
bic {tmp2:w}, {d2:w}, {a2:w}
add {b1:w}, {b1:w}, {tmp1:w}
add {b2:w}, {b2:w}, {tmp1:w}
bic {tmp1:w}, {d1:w}, {a1:w}
add {b2:w}, {b2:w}, {tmp2:w}
add {b1:w}, {b1:w}, {tmp1:w}
and {tmp2:w}, {c2:w}, {a2:w}
and {tmp1:w}, {c1:w}, {a1:w}
add {b2:w}, {b2:w}, {tmp2:w}
add {b1:w}, {b1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #20]
ldr {tmp2:w}, [{y}, #20]
ror {b1:w}, {b1:w}, #12
ror {b2:w}, {b2:w}, #12
add {b1:w}, {b1:w}, {c1:w}
add {b2:w}, {b2:w}, {c2:w}
add {a1:w}, {a1:w}, {tmp1:w}
mov {tmp1:w}, #0x3942
add {a2:w}, {a2:w}, {tmp2:w}
movk {tmp1:w}, #0xfffa, lsl #16
eor {tmp2:w}, {c2:w}, {d2:w}
add {a1:w}, {a1:w}, {tmp1:w}
add {a2:w}, {a2:w}, {tmp1:w}
eor {tmp1:w}, {c1:w}, {d1:w}
eor {tmp2:w}, {tmp2:w}, {b2:w}
eor {tmp1:w}, {tmp1:w}, {b1:w}
add {a2:w}, {a2:w}, {tmp2:w}
add {a1:w}, {a1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #32]
ldr {tmp2:w}, [{y}, #32]
ror {a1:w}, {a1:w}, #28
ror {a2:w}, {a2:w}, #28
add {a1:w}, {a1:w}, {b1:w}
add {a2:w}, {a2:w}, {b2:w}
add {d1:w}, {d1:w}, {tmp1:w}
mov {tmp1:w}, #0xf681
add {d2:w}, {d2:w}, {tmp2:w}
movk {tmp1:w}, #0x8771, lsl #16
eor {tmp2:w}, {b2:w}, {c2:w}
add {d1:w}, {d1:w}, {tmp1:w}
add {d2:w}, {d2:w}, {tmp1:w}
eor {tmp1:w}, {b1:w}, {c1:w}
eor {tmp2:w}, {tmp2:w}, {a2:w}
eor {tmp1:w}, {tmp1:w}, {a1:w}
add {d2:w}, {d2:w}, {tmp2:w}
add {d1:w}, {d1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #44]
ldr {tmp2:w}, [{y}, #44]
ror {d1:w}, {d1:w}, #21
ror {d2:w}, {d2:w}, #21
add {d1:w}, {d1:w}, {a1:w}
add {d2:w}, {d2:w}, {a2:w}
add {c1:w}, {c1:w}, {tmp1:w}
mov {tmp1:w}, #0x6122
add {c2:w}, {c2:w}, {tmp2:w}
movk {tmp1:w}, #0x6d9d, lsl #16
eor {tmp2:w}, {a2:w}, {b2:w}
add {c1:w}, {c1:w}, {tmp1:w}
add {c2:w}, {c2:w}, {tmp1:w}
eor {tmp1:w}, {a1:w}, {b1:w}
eor {tmp2:w}, {tmp2:w}, {d2:w}
eor {tmp1:w}, {tmp1:w}, {d1:w}
add {c2:w}, {c2:w}, {tmp2:w}
add {c1:w}, {c1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #56]
ldr {tmp2:w}, [{y}, #56]
ror {c1:w}, {c1:w}, #16
ror {c2:w}, {c2:w}, #16
add {c1:w}, {c1:w}, {d1:w}
add {c2:w}, {c2:w}, {d2:w}
add {b1:w}, {b1:w}, {tmp1:w}
mov {tmp1:w}, #0x380c
add {b2:w}, {b2:w}, {tmp2:w}
movk {tmp1:w}, #0xfde5, lsl #16
eor {tmp2:w}, {d2:w}, {a2:w}
add {b1:w}, {b1:w}, {tmp1:w}
add {b2:w}, {b2:w}, {tmp1:w}
eor {tmp1:w}, {d1:w}, {a1:w}
eor {tmp2:w}, {tmp2:w}, {c2:w}
eor {tmp1:w}, {tmp1:w}, {c1:w}
add {b2:w}, {b2:w}, {tmp2:w}
add {b1:w}, {b1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #4]
ldr {tmp2:w}, [{y}, #4]
ror {b1:w}, {b1:w}, #9
ror {b2:w}, {b2:w}, #9
add {b1:w}, {b1:w}, {c1:w}
add {b2:w}, {b2:w}, {c2:w}
add {a1:w}, {a1:w}, {tmp1:w}
mov {tmp1:w}, #0xea44
add {a2:w}, {a2:w}, {tmp2:w}
movk {tmp1:w}, #0xa4be, lsl #16
eor {tmp2:w}, {c2:w}, {d2:w}
add {a1:w}, {a1:w}, {tmp1:w}
add {a2:w}, {a2:w}, {tmp1:w}
eor {tmp1:w}, {c1:w}, {d1:w}
eor {tmp2:w}, {tmp2:w}, {b2:w}
eor {tmp1:w}, {tmp1:w}, {b1:w}
add {a2:w}, {a2:w}, {tmp2:w}
add {a1:w}, {a1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #16]
ldr {tmp2:w}, [{y}, #16]
ror {a1:w}, {a1:w}, #28
ror {a2:w}, {a2:w}, #28
add {a1:w}, {a1:w}, {b1:w}
add {a2:w}, {a2:w}, {b2:w}
add {d1:w}, {d1:w}, {tmp1:w}
mov {tmp1:w}, #0xcfa9
add {d2:w}, {d2:w}, {tmp2:w}
movk {tmp1:w}, #0x4bde, lsl #16
eor {tmp2:w}, {b2:w}, {c2:w}
add {d1:w}, {d1:w}, {tmp1:w}
add {d2:w}, {d2:w}, {tmp1:w}
eor {tmp1:w}, {b1:w}, {c1:w}
eor {tmp2:w}, {tmp2:w}, {a2:w}
eor {tmp1:w}, {tmp1:w}, {a1:w}
add {d2:w}, {d2:w}, {tmp2:w}
add {d1:w}, {d1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #28]
ldr {tmp2:w}, [{y}, #28]
ror {d1:w}, {d1:w}, #21
ror {d2:w}, {d2:w}, #21
add {d1:w}, {d1:w}, {a1:w}
add {d2:w}, {d2:w}, {a2:w}
add {c1:w}, {c1:w}, {tmp1:w}
mov {tmp1:w}, #0x4b60
add {c2:w}, {c2:w}, {tmp2:w}
movk {tmp1:w}, #0xf6bb, lsl #16
eor {tmp2:w}, {a2:w}, {b2:w}
add {c1:w}, {c1:w}, {tmp1:w}
add {c2:w}, {c2:w}, {tmp1:w}
eor {tmp1:w}, {a1:w}, {b1:w}
eor {tmp2:w}, {tmp2:w}, {d2:w}
eor {tmp1:w}, {tmp1:w}, {d1:w}
add {c2:w}, {c2:w}, {tmp2:w}
add {c1:w}, {c1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #40]
ldr {tmp2:w}, [{y}, #40]
ror {c1:w}, {c1:w}, #16
ror {c2:w}, {c2:w}, #16
add {c1:w}, {c1:w}, {d1:w}
add {c2:w}, {c2:w}, {d2:w}
add {b1:w}, {b1:w}, {tmp1:w}
mov {tmp1:w}, #0xbc70
add {b2:w}, {b2:w}, {tmp2:w}
movk {tmp1:w}, #0xbebf, lsl #16
eor {tmp2:w}, {d2:w}, {a2:w}
add {b1:w}, {b1:w}, {tmp1:w}
add {b2:w}, {b2:w}, {tmp1:w}
eor {tmp1:w}, {d1:w}, {a1:w}
eor {tmp2:w}, {tmp2:w}, {c2:w}
eor {tmp1:w}, {tmp1:w}, {c1:w}
add {b2:w}, {b2:w}, {tmp2:w}
add {b1:w}, {b1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #52]
ldr {tmp2:w}, [{y}, #52]
ror {b1:w}, {b1:w}, #9
ror {b2:w}, {b2:w}, #9
add {b1:w}, {b1:w}, {c1:w}
add {b2:w}, {b2:w}, {c2:w}
add {a1:w}, {a1:w}, {tmp1:w}
mov {tmp1:w}, #0x7ec6
add {a2:w}, {a2:w}, {tmp2:w}
movk {tmp1:w}, #0x289b, lsl #16
eor {tmp2:w}, {c2:w}, {d2:w}
add {a1:w}, {a1:w}, {tmp1:w}
add {a2:w}, {a2:w}, {tmp1:w}
eor {tmp1:w}, {c1:w}, {d1:w}
eor {tmp2:w}, {tmp2:w}, {b2:w}
eor {tmp1:w}, {tmp1:w}, {b1:w}
add {a2:w}, {a2:w}, {tmp2:w}
add {a1:w}, {a1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #0]
ldr {tmp2:w}, [{y}, #0]
ror {a1:w}, {a1:w}, #28
ror {a2:w}, {a2:w}, #28
add {a1:w}, {a1:w}, {b1:w}
add {a2:w}, {a2:w}, {b2:w}
add {d1:w}, {d1:w}, {tmp1:w}
mov {tmp1:w}, #0x27fa
add {d2:w}, {d2:w}, {tmp2:w}
movk {tmp1:w}, #0xeaa1, lsl #16
eor {tmp2:w}, {b2:w}, {c2:w}
add {d1:w}, {d1:w}, {tmp1:w}
add {d2:w}, {d2:w}, {tmp1:w}
eor {tmp1:w}, {b1:w}, {c1:w}
eor {tmp2:w}, {tmp2:w}, {a2:w}
eor {tmp1:w}, {tmp1:w}, {a1:w}
add {d2:w}, {d2:w}, {tmp2:w}
add {d1:w}, {d1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #12]
ldr {tmp2:w}, [{y}, #12]
ror {d1:w}, {d1:w}, #21
ror {d2:w}, {d2:w}, #21
add {d1:w}, {d1:w}, {a1:w}
add {d2:w}, {d2:w}, {a2:w}
add {c1:w}, {c1:w}, {tmp1:w}
mov {tmp1:w}, #0x3085
add {c2:w}, {c2:w}, {tmp2:w}
movk {tmp1:w}, #0xd4ef, lsl #16
eor {tmp2:w}, {a2:w}, {b2:w}
add {c1:w}, {c1:w}, {tmp1:w}
add {c2:w}, {c2:w}, {tmp1:w}
eor {tmp1:w}, {a1:w}, {b1:w}
eor {tmp2:w}, {tmp2:w}, {d2:w}
eor {tmp1:w}, {tmp1:w}, {d1:w}
add {c2:w}, {c2:w}, {tmp2:w}
add {c1:w}, {c1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #24]
ldr {tmp2:w}, [{y}, #24]
ror {c1:w}, {c1:w}, #16
ror {c2:w}, {c2:w}, #16
add {c1:w}, {c1:w}, {d1:w}
add {c2:w}, {c2:w}, {d2:w}
add {b1:w}, {b1:w}, {tmp1:w}
mov {tmp1:w}, #0x1d05
add {b2:w}, {b2:w}, {tmp2:w}
movk {tmp1:w}, #0x0488, lsl #16
eor {tmp2:w}, {d2:w}, {a2:w}
add {b1:w}, {b1:w}, {tmp1:w}
add {b2:w}, {b2:w}, {tmp1:w}
eor {tmp1:w}, {d1:w}, {a1:w}
eor {tmp2:w}, {tmp2:w}, {c2:w}
eor {tmp1:w}, {tmp1:w}, {c1:w}
add {b2:w}, {b2:w}, {tmp2:w}
add {b1:w}, {b1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #36]
ldr {tmp2:w}, [{y}, #36]
ror {b1:w}, {b1:w}, #9
ror {b2:w}, {b2:w}, #9
add {b1:w}, {b1:w}, {c1:w}
add {b2:w}, {b2:w}, {c2:w}
add {a1:w}, {a1:w}, {tmp1:w}
mov {tmp1:w}, #0xd039
add {a2:w}, {a2:w}, {tmp2:w}
movk {tmp1:w}, #0xd9d4, lsl #16
eor {tmp2:w}, {c2:w}, {d2:w}
add {a1:w}, {a1:w}, {tmp1:w}
add {a2:w}, {a2:w}, {tmp1:w}
eor {tmp1:w}, {c1:w}, {d1:w}
eor {tmp2:w}, {tmp2:w}, {b2:w}
eor {tmp1:w}, {tmp1:w}, {b1:w}
add {a2:w}, {a2:w}, {tmp2:w}
add {a1:w}, {a1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #48]
ldr {tmp2:w}, [{y}, #48]
ror {a1:w}, {a1:w}, #28
ror {a2:w}, {a2:w}, #28
add {a1:w}, {a1:w}, {b1:w}
add {a2:w}, {a2:w}, {b2:w}
add {d1:w}, {d1:w}, {tmp1:w}
mov {tmp1:w}, #0x99e5
add {d2:w}, {d2:w}, {tmp2:w}
movk {tmp1:w}, #0xe6db, lsl #16
eor {tmp2:w}, {b2:w}, {c2:w}
add {d1:w}, {d1:w}, {tmp1:w}
add {d2:w}, {d2:w}, {tmp1:w}
eor {tmp1:w}, {b1:w}, {c1:w}
eor {tmp2:w}, {tmp2:w}, {a2:w}
eor {tmp1:w}, {tmp1:w}, {a1:w}
add {d2:w}, {d2:w}, {tmp2:w}
add {d1:w}, {d1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #60]
ldr {tmp2:w}, [{y}, #60]
ror {d1:w}, {d1:w}, #21
ror {d2:w}, {d2:w}, #21
add {d1:w}, {d1:w}, {a1:w}
add {d2:w}, {d2:w}, {a2:w}
add {c1:w}, {c1:w}, {tmp1:w}
mov {tmp1:w}, #0x7cf8
add {c2:w}, {c2:w}, {tmp2:w}
movk {tmp1:w}, #0x1fa2, lsl #16
eor {tmp2:w}, {a2:w}, {b2:w}
add {c1:w}, {c1:w}, {tmp1:w}
add {c2:w}, {c2:w}, {tmp1:w}
eor {tmp1:w}, {a1:w}, {b1:w}
eor {tmp2:w}, {tmp2:w}, {d2:w}
eor {tmp1:w}, {tmp1:w}, {d1:w}
add {c2:w}, {c2:w}, {tmp2:w}
add {c1:w}, {c1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #8]
ldr {tmp2:w}, [{y}, #8]
ror {c1:w}, {c1:w}, #16
ror {c2:w}, {c2:w}, #16
add {c1:w}, {c1:w}, {d1:w}
add {c2:w}, {c2:w}, {d2:w}
add {b1:w}, {b1:w}, {tmp1:w}
mov {tmp1:w}, #0x5665
add {b2:w}, {b2:w}, {tmp2:w}
movk {tmp1:w}, #0xc4ac, lsl #16
eor {tmp2:w}, {d2:w}, {a2:w}
add {b1:w}, {b1:w}, {tmp1:w}
add {b2:w}, {b2:w}, {tmp1:w}
eor {tmp1:w}, {d1:w}, {a1:w}
eor {tmp2:w}, {tmp2:w}, {c2:w}
eor {tmp1:w}, {tmp1:w}, {c1:w}
add {b2:w}, {b2:w}, {tmp2:w}
add {b1:w}, {b1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #0]
ldr {tmp2:w}, [{y}, #0]
ror {b1:w}, {b1:w}, #9
ror {b2:w}, {b2:w}, #9
add {b1:w}, {b1:w}, {c1:w}
add {b2:w}, {b2:w}, {c2:w}
add {a1:w}, {a1:w}, {tmp1:w}
mov {tmp1:w}, #0x2243
add {a2:w}, {a2:w}, {tmp2:w}
movk {tmp1:w}, #0xf429, lsl #16
bic {tmp2:w}, {d2:w}, {b2:w}
add {a1:w}, {a1:w}, {tmp1:w}
add {a2:w}, {a2:w}, {tmp1:w}
bic {tmp1:w}, {d1:w}, {b1:w}
eor {tmp2:w}, {tmp2:w}, {c2:w}
eor {tmp1:w}, {tmp1:w}, {c1:w}
sub {a2:w}, {a2:w}, {tmp2:w}
sub {a1:w}, {a1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #28]
ldr {tmp2:w}, [{y}, #28]
ror {a1:w}, {a1:w}, #26
ror {a2:w}, {a2:w}, #26
add {a1:w}, {a1:w}, {b1:w}
add {a2:w}, {a2:w}, {b2:w}
add {d1:w}, {d1:w}, {tmp1:w}
mov {tmp1:w}, #0xff96
add {d2:w}, {d2:w}, {tmp2:w}
movk {tmp1:w}, #0x432a, lsl #16
bic {tmp2:w}, {c2:w}, {a2:w}
add {d1:w}, {d1:w}, {tmp1:w}
add {d2:w}, {d2:w}, {tmp1:w}
bic {tmp1:w}, {c1:w}, {a1:w}
eor {tmp2:w}, {tmp2:w}, {b2:w}
eor {tmp1:w}, {tmp1:w}, {b1:w}
sub {d2:w}, {d2:w}, {tmp2:w}
sub {d1:w}, {d1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #56]
ldr {tmp2:w}, [{y}, #56]
ror {d1:w}, {d1:w}, #22
ror {d2:w}, {d2:w}, #22
add {d1:w}, {d1:w}, {a1:w}
add {d2:w}, {d2:w}, {a2:w}
add {c1:w}, {c1:w}, {tmp1:w}
mov {tmp1:w}, #0x23a6
add {c2:w}, {c2:w}, {tmp2:w}
movk {tmp1:w}, #0xab94, lsl #16
bic {tmp2:w}, {b2:w}, {d2:w}
add {c1:w}, {c1:w}, {tmp1:w}
add {c2:w}, {c2:w}, {tmp1:w}
bic {tmp1:w}, {b1:w}, {d1:w}
eor {tmp2:w}, {tmp2:w}, {a2:w}
eor {tmp1:w}, {tmp1:w}, {a1:w}
sub {c2:w}, {c2:w}, {tmp2:w}
sub {c1:w}, {c1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #20]
ldr {tmp2:w}, [{y}, #20]
ror {c1:w}, {c1:w}, #17
ror {c2:w}, {c2:w}, #17
add {c1:w}, {c1:w}, {d1:w}
add {c2:w}, {c2:w}, {d2:w}
add {b1:w}, {b1:w}, {tmp1:w}
mov {tmp1:w}, #0xa038
add {b2:w}, {b2:w}, {tmp2:w}
movk {tmp1:w}, #0xfc93, lsl #16
bic {tmp2:w}, {a2:w}, {c2:w}
add {b1:w}, {b1:w}, {tmp1:w}
add {b2:w}, {b2:w}, {tmp1:w}
bic {tmp1:w}, {a1:w}, {c1:w}
eor {tmp2:w}, {tmp2:w}, {d2:w}
eor {tmp1:w}, {tmp1:w}, {d1:w}
sub {b2:w}, {b2:w}, {tmp2:w}
sub {b1:w}, {b1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #48]
ldr {tmp2:w}, [{y}, #48]
ror {b1:w}, {b1:w}, #11
ror {b2:w}, {b2:w}, #11
add {b1:w}, {b1:w}, {c1:w}
add {b2:w}, {b2:w}, {c2:w}
add {a1:w}, {a1:w}, {tmp1:w}
mov {tmp1:w}, #0x59c2
add {a2:w}, {a2:w}, {tmp2:w}
movk {tmp1:w}, #0x655b, lsl #16
bic {tmp2:w}, {d2:w}, {b2:w}
add {a1:w}, {a1:w}, {tmp1:w}
add {a2:w}, {a2:w}, {tmp1:w}
bic {tmp1:w}, {d1:w}, {b1:w}
eor {tmp2:w}, {tmp2:w}, {c2:w}
eor {tmp1:w}, {tmp1:w}, {c1:w}
sub {a2:w}, {a2:w}, {tmp2:w}
sub {a1:w}, {a1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #12]
ldr {tmp2:w}, [{y}, #12]
ror {a1:w}, {a1:w}, #26
ror {a2:w}, {a2:w}, #26
add {a1:w}, {a1:w}, {b1:w}
add {a2:w}, {a2:w}, {b2:w}
add {d1:w}, {d1:w}, {tmp1:w}
mov {tmp1:w}, #0xcc91
add {d2:w}, {d2:w}, {tmp2:w}
movk {tmp1:w}, #0x8f0c, lsl #16
bic {tmp2:w}, {c2:w}, {a2:w}
add {d1:w}, {d1:w}, {tmp1:w}
add {d2:w}, {d2:w}, {tmp1:w}
bic {tmp1:w}, {c1:w}, {a1:w}
eor {tmp2:w}, {tmp2:w}, {b2:w}
eor {tmp1:w}, {tmp1:w}, {b1:w}
sub {d2:w}, {d2:w}, {tmp2:w}
sub {d1:w}, {d1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #40]
ldr {tmp2:w}, [{y}, #40]
ror {d1:w}, {d1:w}, #22
ror {d2:w}, {d2:w}, #22
add {d1:w}, {d1:w}, {a1:w}
add {d2:w}, {d2:w}, {a2:w}
add {c1:w}, {c1:w}, {tmp1:w}
mov {tmp1:w}, #0xf47c
add {c2:w}, {c2:w}, {tmp2:w}
movk {tmp1:w}, #0xffef, lsl #16
bic {tmp2:w}, {b2:w}, {d2:w}
add {c1:w}, {c1:w}, {tmp1:w}
add {c2:w}, {c2:w}, {tmp1:w}
bic {tmp1:w}, {b1:w}, {d1:w}
eor {tmp2:w}, {tmp2:w}, {a2:w}
eor {tmp1:w}, {tmp1:w}, {a1:w}
sub {c2:w}, {c2:w}, {tmp2:w}
sub {c1:w}, {c1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #4]
ldr {tmp2:w}, [{y}, #4]
ror {c1:w}, {c1:w}, #17
ror {c2:w}, {c2:w}, #17
add {c1:w}, {c1:w}, {d1:w}
add {c2:w}, {c2:w}, {d2:w}
add {b1:w}, {b1:w}, {tmp1:w}
mov {tmp1:w}, #0x5dd0
add {b2:w}, {b2:w}, {tmp2:w}
movk {tmp1:w}, #0x8584, lsl #16
bic {tmp2:w}, {a2:w}, {c2:w}
add {b1:w}, {b1:w}, {tmp1:w}
add {b2:w}, {b2:w}, {tmp1:w}
bic {tmp1:w}, {a1:w}, {c1:w}
eor {tmp2:w}, {tmp2:w}, {d2:w}
eor {tmp1:w}, {tmp1:w}, {d1:w}
sub {b2:w}, {b2:w}, {tmp2:w}
sub {b1:w}, {b1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #32]
ldr {tmp2:w}, [{y}, #32]
ror {b1:w}, {b1:w}, #11
ror {b2:w}, {b2:w}, #11
add {b1:w}, {b1:w}, {c1:w}
add {b2:w}, {b2:w}, {c2:w}
add {a1:w}, {a1:w}, {tmp1:w}
mov {tmp1:w}, #0x7e4e
add {a2:w}, {a2:w}, {tmp2:w}
movk {tmp1:w}, #0x6fa8, lsl #16
bic {tmp2:w}, {d2:w}, {b2:w}
add {a1:w}, {a1:w}, {tmp1:w}
add {a2:w}, {a2:w}, {tmp1:w}
bic {tmp1:w}, {d1:w}, {b1:w}
eor {tmp2:w}, {tmp2:w}, {c2:w}
eor {tmp1:w}, {tmp1:w}, {c1:w}
sub {a2:w}, {a2:w}, {tmp2:w}
sub {a1:w}, {a1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #60]
ldr {tmp2:w}, [{y}, #60]
ror {a1:w}, {a1:w}, #26
ror {a2:w}, {a2:w}, #26
add {a1:w}, {a1:w}, {b1:w}
add {a2:w}, {a2:w}, {b2:w}
add {d1:w}, {d1:w}, {tmp1:w}
mov {tmp1:w}, #0xe6df
add {d2:w}, {d2:w}, {tmp2:w}
movk {tmp1:w}, #0xfe2c, lsl #16
bic {tmp2:w}, {c2:w}, {a2:w}
add {d1:w}, {d1:w}, {tmp1:w}
add {d2:w}, {d2:w}, {tmp1:w}
bic {tmp1:w}, {c1:w}, {a1:w}
eor {tmp2:w}, {tmp2:w}, {b2:w}
eor {tmp1:w}, {tmp1:w}, {b1:w}
sub {d2:w}, {d2:w}, {tmp2:w}
sub {d1:w}, {d1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #24]
ldr {tmp2:w}, [{y}, #24]
ror {d1:w}, {d1:w}, #22
ror {d2:w}, {d2:w}, #22
add {d1:w}, {d1:w}, {a1:w}
add {d2:w}, {d2:w}, {a2:w}
add {c1:w}, {c1:w}, {tmp1:w}
mov {tmp1:w}, #0x4313
add {c2:w}, {c2:w}, {tmp2:w}
movk {tmp1:w}, #0xa301, lsl #16
bic {tmp2:w}, {b2:w}, {d2:w}
add {c1:w}, {c1:w}, {tmp1:w}
add {c2:w}, {c2:w}, {tmp1:w}
bic {tmp1:w}, {b1:w}, {d1:w}
eor {tmp2:w}, {tmp2:w}, {a2:w}
eor {tmp1:w}, {tmp1:w}, {a1:w}
sub {c2:w}, {c2:w}, {tmp2:w}
sub {c1:w}, {c1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #52]
ldr {tmp2:w}, [{y}, #52]
ror {c1:w}, {c1:w}, #17
ror {c2:w}, {c2:w}, #17
add {c1:w}, {c1:w}, {d1:w}
add {c2:w}, {c2:w}, {d2:w}
add {b1:w}, {b1:w}, {tmp1:w}
mov {tmp1:w}, #0x11a0
add {b2:w}, {b2:w}, {tmp2:w}
movk {tmp1:w}, #0x4e08, lsl #16
bic {tmp2:w}, {a2:w}, {c2:w}
add {b1:w}, {b1:w}, {tmp1:w}
add {b2:w}, {b2:w}, {tmp1:w}
bic {tmp1:w}, {a1:w}, {c1:w}
eor {tmp2:w}, {tmp2:w}, {d2:w}
eor {tmp1:w}, {tmp1:w}, {d1:w}
sub {b2:w}, {b2:w}, {tmp2:w}
sub {b1:w}, {b1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #16]
ldr {tmp2:w}, [{y}, #16]
ror {b1:w}, {b1:w}, #11
ror {b2:w}, {b2:w}, #11
add {b1:w}, {b1:w}, {c1:w}
add {b2:w}, {b2:w}, {c2:w}
add {a1:w}, {a1:w}, {tmp1:w}
mov {tmp1:w}, #0x7e81
add {a2:w}, {a2:w}, {tmp2:w}
movk {tmp1:w}, #0xf753, lsl #16
bic {tmp2:w}, {d2:w}, {b2:w}
add {a1:w}, {a1:w}, {tmp1:w}
add {a2:w}, {a2:w}, {tmp1:w}
bic {tmp1:w}, {d1:w}, {b1:w}
eor {tmp2:w}, {tmp2:w}, {c2:w}
eor {tmp1:w}, {tmp1:w}, {c1:w}
sub {a2:w}, {a2:w}, {tmp2:w}
sub {a1:w}, {a1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #44]
ldr {tmp2:w}, [{y}, #44]
ror {a1:w}, {a1:w}, #26
ror {a2:w}, {a2:w}, #26
add {a1:w}, {a1:w}, {b1:w}
add {a2:w}, {a2:w}, {b2:w}
add {d1:w}, {d1:w}, {tmp1:w}
mov {tmp1:w}, #0xf234
add {d2:w}, {d2:w}, {tmp2:w}
movk {tmp1:w}, #0xbd3a, lsl #16
bic {tmp2:w}, {c2:w}, {a2:w}
add {d1:w}, {d1:w}, {tmp1:w}
add {d2:w}, {d2:w}, {tmp1:w}
bic {tmp1:w}, {c1:w}, {a1:w}
eor {tmp2:w}, {tmp2:w}, {b2:w}
eor {tmp1:w}, {tmp1:w}, {b1:w}
sub {d2:w}, {d2:w}, {tmp2:w}
sub {d1:w}, {d1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #8]
ldr {tmp2:w}, [{y}, #8]
ror {d1:w}, {d1:w}, #22
ror {d2:w}, {d2:w}, #22
add {d1:w}, {d1:w}, {a1:w}
add {d2:w}, {d2:w}, {a2:w}
add {c1:w}, {c1:w}, {tmp1:w}
mov {tmp1:w}, #0xd2ba
add {c2:w}, {c2:w}, {tmp2:w}
movk {tmp1:w}, #0x2ad7, lsl #16
bic {tmp2:w}, {b2:w}, {d2:w}
add {c1:w}, {c1:w}, {tmp1:w}
add {c2:w}, {c2:w}, {tmp1:w}
bic {tmp1:w}, {b1:w}, {d1:w}
eor {tmp2:w}, {tmp2:w}, {a2:w}
eor {tmp1:w}, {tmp1:w}, {a1:w}
sub {c2:w}, {c2:w}, {tmp2:w}
sub {c1:w}, {c1:w}, {tmp1:w}
ldr {tmp1:w}, [{x}, #36]
ldr {tmp2:w}, [{y}, #36]
ror {c1:w}, {c1:w}, #17
ror {c2:w}, {c2:w}, #17
add {c1:w}, {c1:w}, {d1:w}
add {c2:w}, {c2:w}, {d2:w}
add {b1:w}, {b1:w}, {tmp1:w}
mov {tmp1:w}, #0xd390
add {b2:w}, {b2:w}, {tmp2:w}
movk {tmp1:w}, #0xeb86, lsl #16
bic {tmp2:w}, {a2:w}, {c2:w}
add {b1:w}, {b1:w}, {tmp1:w}
add {b2:w}, {b2:w}, {tmp1:w}
bic {tmp1:w}, {a1:w}, {c1:w}
eor {tmp2:w}, {tmp2:w}, {d2:w}
eor {tmp1:w}, {tmp1:w}, {d1:w}
sub {b2:w}, {b2:w}, {tmp2:w}
sub {b1:w}, {b1:w}, {tmp1:w}
ror {b1:w}, {b1:w}, #11
ror {b2:w}, {b2:w}, #11
add {b1:w}, {b1:w}, {c1:w}
add {b2:w}, {b2:w}, {c2:w}
