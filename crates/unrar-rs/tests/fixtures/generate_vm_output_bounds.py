#!/usr/bin/env python3
"""Hand-assemble a RAR 2.9 archive whose VM-filtered blocks cross the declared
unpacked size.

Nothing here is produced by, or derived from, any RAR tool: every byte of the
container and of the compressed bitstream is emitted by this script. The two
standard filter programs are the byte blobs RAR's own filters are recognised by
(CRC32 0x0E06077D delta / 0x3CD7E57E E8E9), lifted out of a fixture that is
already in the tree.
"""

import binascii
import struct
import sys

# --- standard RAR3 VM filter programs (recognised by length + CRC32) ---------
DELTA_CODE = bytes.fromhex("2f019a4180ec27482f09766dd3ea415b5944e8175ce16c914c4e3f7700")
E8E9_CODE = bytes.fromhex(
    "841b0128111069808000000d13a101c689d280ac9762855cc905c92f8148c8aa"
    "981895728881aac95b0020ab6a03355811a24821b01291f4b8"
)
assert len(DELTA_CODE) == 29 and binascii.crc32(DELTA_CODE) == 0x0E06077D
assert len(E8E9_CODE) == 57 and binascii.crc32(E8E9_CODE) == 0x3CD7E57E


class BitWriter:
    """MSB-first bit writer, matching unrar's BitInput."""

    def __init__(self):
        self.bits = []

    def put(self, value, count):
        assert count >= 0
        assert value >> count == 0, f"{value:#x} does not fit in {count} bits"
        for i in reversed(range(count)):
            self.bits.append((value >> i) & 1)

    def align(self):
        while len(self.bits) % 8:
            self.bits.append(0)

    def byte_len(self):
        return (len(self.bits) + 7) // 8

    def bytes(self):
        out = bytearray()
        for i in range(0, len(self.bits), 8):
            chunk = self.bits[i : i + 8]
            chunk = chunk + [0] * (8 - len(chunk))
            byte = 0
            for bit in chunk:
                byte = (byte << 1) | bit
            out.append(byte)
        return bytes(out)


def canonical(lengths):
    """MakeDecodeTables' code assignment (unpack.cpp:246-317).

    Codes go out in order of increasing bit length and, inside one length, in
    increasing symbol index -- the plain canonical order.
    """
    codes = {}
    code = 0
    for length in range(1, 16):
        for sym, sym_len in enumerate(lengths):
            if sym_len == length:
                codes[sym] = (code, length)
                code += 1
        code <<= 1
    return codes


# --- ReadData, the VM parameter encoding (rarvm.cpp:72-105) ------------------
def put_vm_data(bw, value):
    if value < 0x10:
        bw.put(0b00, 2)
        bw.put(value, 4)
    elif value < 0x100:
        # The 10-bit form is only decodable when the high nibble is non-zero;
        # (Data & 0x3c00) == 0 selects the sign-extended form instead.
        bw.put(0b01, 2)
        bw.put(value, 8)
    elif value < 0x10000:
        bw.put(0b10, 2)
        bw.put(value, 16)
    else:
        bw.put(0b11, 2)
        bw.put(value >> 16, 16)
        bw.put(value & 0xFFFF, 16)


# --- the Huffman alphabet every member in this fixture shares ---------------
LITERALS = [0x00, 0x01, 0x02, 0x03, 0x10, 0x11, 0x20, 0x21, 0x30, 0x31, 0x40, 0x41, 0xE8, 0xE9]
LD_SYMBOLS = sorted(LITERALS) + [256, 257]
assert len(LD_SYMBOLS) == 16  # a complete 4-bit code

NC, DC, LDC, RC = 299, 60, 17, 28
TABLE_SIZE = NC + DC + LDC + RC  # 404

# Bit-length table decoder (BD): symbol 0 ("length 0") is 1 bit, symbol 4
# ("length 4") is 2 bits, and two spares keep the code complete.
BD_LENGTHS = [0] * 20
BD_LENGTHS[0] = 1
BD_LENGTHS[4] = 2
BD_LENGTHS[5] = 3
BD_LENGTHS[6] = 3
BD_CODES = canonical(BD_LENGTHS)

MAIN_LENGTHS = [0] * TABLE_SIZE
for sym in LD_SYMBOLS:
    MAIN_LENGTHS[sym] = 4
LD_CODES = canonical(MAIN_LENGTHS[:NC])


def put_tables(bw):
    """ReadTables30 (unpack30.cpp:632-712)."""
    bw.align()
    bw.put(0, 1)  # not a PPM block
    bw.put(0, 1)  # do not keep the previous table as the delta base
    for length in BD_LENGTHS:
        assert length < 15
        bw.put(length, 4)
    for length in MAIN_LENGTHS:
        sym = 0 if length == 0 else length
        code, count = BD_CODES[sym]
        bw.put(code, count)


def put_symbol(bw, sym):
    code, count = LD_CODES[sym]
    bw.put(code, count)


def put_literals(bw, data):
    for byte in data:
        put_symbol(bw, byte)


def put_end_of_block(bw, new_file=True, new_table=True):
    """Symbol 256 plus ReadEndOfBlock's flags (unpack30.cpp:255-289)."""
    put_symbol(bw, 256)
    if not new_file:
        bw.put(1, 1)
    else:
        bw.put(0, 1)
        bw.put(1 if new_table else 0, 1)


def put_vm_filter(bw, code, block_start, block_length, init_regs=None, new_filter=True):
    """Symbol 257 plus ReadVMCode/AddVMCode (unpack30.cpp:291-491).

    `new_filter=False` omits the slot field, so the packet reuses the filter
    the member defined last. That matters because writing slot 0 resets the
    filter list, and `InitFilters30` clears the pending-block stack with it
    (unpack30.cpp:369-373), which would drop an earlier block of this member.
    """
    packet = BitWriter()
    first_byte = 0x20  # explicit block length
    if init_regs:
        first_byte |= 0x10
    if new_filter:
        # Slot 0 means "reset the filter list, then define a new filter"
        # (unpack30.cpp:369-373), which keeps every member independent of what
        # the members before it left behind.
        first_byte |= 0x80
        put_vm_data(packet, 0)
    put_vm_data(packet, block_start)
    put_vm_data(packet, block_length)
    if init_regs:
        mask = 0
        for reg in init_regs:
            mask |= 1 << reg
        packet.put(mask, 7)
        for reg in sorted(init_regs):
            put_vm_data(packet, init_regs[reg])
    if new_filter:
        put_vm_data(packet, len(code))
        for byte in code:
            packet.put(byte, 8)
    packet.align()
    body = packet.bytes()

    put_symbol(bw, 257)
    length = len(body)
    assert 1 <= length < 0x100 + 7
    if length <= 6:
        bw.put(first_byte | (length - 1), 8)
    else:
        bw.put(first_byte | 6, 8)
        bw.put(length - 7, 8)
    for byte in body:
        bw.put(byte, 8)


# --- container --------------------------------------------------------------
MARK_HEAD = bytes.fromhex("526172211a0700")
MAIN_HEAD = bytes.fromhex("cf9073 0000 0d00 0000 00000000".replace(" ", ""))
END_HEAD = bytes.fromhex("c43d7b00400700")


def file_header(name, packed, unp_size, crc, dict_bits=0):
    flags = 0x8000 | (dict_bits << 5)
    name_bytes = name.encode()
    head_size = 32 + len(name_bytes)
    head = bytearray()
    head += struct.pack("<B", 0x74)
    head += struct.pack("<HH", flags, head_size)
    head += struct.pack("<II", len(packed), unp_size)
    head += struct.pack("<B", 3)  # host OS: Unix
    head += struct.pack("<I", crc)
    head += struct.pack("<I", 0x5C6864C4)  # arbitrary DOS timestamp
    head += struct.pack("<BB", 29, 0x35)
    head += struct.pack("<H", len(name_bytes))
    head += struct.pack("<I", 0x81A4)
    head += name_bytes
    head_crc = binascii.crc32(bytes(head)) & 0xFFFF
    return struct.pack("<H", head_crc) + bytes(head)


def build(members):
    out = bytearray()
    out += MARK_HEAD
    out += MAIN_HEAD
    for name, packed, unp_size, crc in members:
        out += file_header(name, packed, unp_size, crc)
        out += packed
    out += END_HEAD
    return bytes(out)


# --- the members ------------------------------------------------------------
BLOCK = bytes(LITERALS[i % len(LITERALS)] for i in range(64))
TAIL = bytes([0x30, 0x31] * 8)
# Eight E8 records whose little-endian address is 0x00032010, i.e. below the
# 0x1000000 the E8 filter treats as "inside the file", so every one of them is
# rewritten to Addr - (CurPos + R[6]) and the result depends on R[6].
E8_BLOCK = bytes([0xE8, 0x10, 0x20, 0x03, 0x00, 0x41, 0x41, 0x41] * 8)


def member_filter_block_overruns_size():
    """Delta filter over [0,64) in a member that declares 16 bytes.

    The oracle keeps decoding to the end-of-file marker, runs the filter once
    the whole 64-byte block is in the window and writes all 64 filtered bytes
    (unpack30.cpp:597-599 has no DestUnpSize clamp).
    """
    bw = BitWriter()
    put_tables(bw)
    put_vm_filter(bw, DELTA_CODE, 0, 64, init_regs={0: 1})
    put_literals(bw, BLOCK)
    put_end_of_block(bw)
    bw.align()
    return bw.bytes(), 16


def member_filter_then_dropped_tail():
    """Same filter, plus 16 raw bytes behind it that the oracle must drop.

    After the filtered write WrittenFileSize is 64, so UnpWriteData returns
    without emitting anything for the trailing raw span (unpack50.cpp:540).
    """
    bw = BitWriter()
    put_tables(bw)
    put_vm_filter(bw, DELTA_CODE, 0, 64, init_regs={0: 1})
    put_literals(bw, BLOCK)
    put_literals(bw, TAIL)
    put_end_of_block(bw)
    bw.align()
    return bw.bytes(), 16


def member_raw_overrun_is_clamped():
    """No filter: 64 raw bytes in a member that declares 16. Control."""
    bw = BitWriter()
    put_tables(bw)
    put_literals(bw, BLOCK)
    put_end_of_block(bw)
    bw.align()
    return bw.bytes(), 16


def member_filter_inside_size():
    """The well-formed shape: the filtered block is exactly the declared size."""
    bw = BitWriter()
    put_tables(bw)
    put_vm_filter(bw, DELTA_CODE, 0, 64, init_regs={0: 1})
    put_literals(bw, BLOCK)
    put_end_of_block(bw)
    bw.align()
    return bw.bytes(), 64


def member_e8_block_overruns_size():
    """E8E9 filter over [0,64) in a member that declares 16 bytes."""
    bw = BitWriter()
    put_tables(bw)
    put_vm_filter(bw, E8E9_CODE, 0, 64)
    put_literals(bw, E8_BLOCK)
    put_end_of_block(bw)
    bw.align()
    return bw.bytes(), 16


def member_raw_clamped_then_e8():
    """64 raw bytes (16 of them emitted) and then an E8E9 block behind them.

    The filter packet is emitted *before* the data it covers, with a block
    start 64 bytes ahead of the current position -- the shape RAR itself
    writes, and the one `AddVMCode`'s `NextWindow` test exists for
    (unpack30.cpp:437-438).

    `ExecuteCode` seeds `InitR[6]` with `WrittenFileSize` (unpack30.cpp:626),
    and `UnpWriteData` advances that counter by the *full* span it was handed,
    not by the clamped part it actually wrote (unpack50.cpp:547). The E8
    rewrite therefore uses file offset 64, not the 16 bytes that reached the
    output, so these bytes pin the counter's semantics.
    """
    bw = BitWriter()
    put_tables(bw)
    put_vm_filter(bw, E8E9_CODE, 64, 64)
    put_literals(bw, BLOCK)
    put_literals(bw, E8_BLOCK)
    put_end_of_block(bw)
    bw.align()
    return bw.bytes(), 16


def member_filter_start_past_window():
    """A filter block that starts past everything the member ever decodes.

    The packet queues a block at [64,128) and the member then stops after 32
    bytes. The oracle's write loop simply does not match the filter
    (`((BlockStart-WrittenBorder)&MaxWinMask) < WriteSize` is false,
    unpack30.cpp:543) and falls through to `UnpWriteArea(WrittenBorder,UnpPtr)`
    (unpack30.cpp:619), so the 32 raw bytes go out clamped to the declared 16
    and the filter is simply never applied.
    """
    bw = BitWriter()
    put_tables(bw)
    put_vm_filter(bw, DELTA_CODE, 64, 64, init_regs={0: 1})
    put_literals(bw, BLOCK[:32])
    put_end_of_block(bw)
    bw.align()
    return bw.bytes(), 16


def member_chained_filters_past_size():
    """Two filter blocks, the second one entirely behind the declared size.

    The second filter is only ever queued if the decoder keeps going after the
    first block ends, which is 48 bytes past the declared size.
    """
    bw = BitWriter()
    put_tables(bw)
    put_vm_filter(bw, DELTA_CODE, 0, 64, init_regs={0: 1})
    put_literals(bw, BLOCK)
    put_vm_filter(bw, DELTA_CODE, 0, 16, init_regs={0: 1}, new_filter=False)
    put_literals(bw, TAIL)
    put_end_of_block(bw)
    bw.align()
    return bw.bytes(), 16


def member_filter_reset_drops_pending():
    """A second filter packet that resets the filter list mid-member.

    Writing slot 0 runs `InitFilters30(false)`, which clears `PrgStack`
    (unpack30.cpp:369-373), so the 64-byte block queued before it is dropped
    and its bytes go out through the clamped raw path instead.
    """
    bw = BitWriter()
    put_tables(bw)
    put_vm_filter(bw, DELTA_CODE, 0, 64, init_regs={0: 1})
    put_literals(bw, BLOCK)
    put_vm_filter(bw, DELTA_CODE, 0, 16, init_regs={0: 1})
    put_literals(bw, TAIL)
    put_end_of_block(bw)
    bw.align()
    return bw.bytes(), 16


MEMBERS = [
    ("filter-overruns-size.bin", member_filter_block_overruns_size),
    ("filter-then-dropped-tail.bin", member_filter_then_dropped_tail),
    ("raw-overrun-clamped.bin", member_raw_overrun_is_clamped),
    ("filter-inside-size.bin", member_filter_inside_size),
    ("e8-overruns-size.bin", member_e8_block_overruns_size),
    ("raw-clamped-then-e8.bin", member_raw_clamped_then_e8),
    ("chained-filters-past-size.bin", member_chained_filters_past_size),
    ("filter-reset-drops-pending.bin", member_filter_reset_drops_pending),
    ("filter-start-past-window.bin", member_filter_start_past_window),
]


# CRC32 of every member's output, taken from unrar 7.20 used purely as a
# decompression oracle on the archive this script assembles. `--blank` writes
# zeroes instead, which is how these were obtained: build blank, extract with
# `-kb`, hash the files, put the values here, rebuild, `unrar t` passes.
ORACLE_CRCS = {
    "filter-overruns-size.bin": 0x136D504C,
    "filter-then-dropped-tail.bin": 0x136D504C,
    "raw-overrun-clamped.bin": 0x93BE6F79,
    "filter-inside-size.bin": 0x136D504C,
    "e8-overruns-size.bin": 0x2FFBC2F8,
    "raw-clamped-then-e8.bin": 0x7C07BEB1,
    "chained-filters-past-size.bin": 0x78F6694F,
    "filter-reset-drops-pending.bin": 0x13EBB745,
    "filter-start-past-window.bin": 0x93BE6F79,
}


def main():
    crcs = dict(ORACLE_CRCS)
    if len(sys.argv) > 2 and sys.argv[2] == "--blank":
        crcs = {}
    members = []
    for name, factory in MEMBERS:
        packed, unp_size = factory()
        members.append((name, packed, unp_size, crcs.get(name, 0)))
    data = build(members)
    with open(sys.argv[1], "wb") as handle:
        handle.write(data)
    print(f"wrote {sys.argv[1]} ({len(data)} bytes)")


if __name__ == "__main__":
    main()
