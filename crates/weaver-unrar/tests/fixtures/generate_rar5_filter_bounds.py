#!/usr/bin/env python3
"""Hand-assemble a RAR 5.0 archive whose filter blocks sit on the geometries
the RAR4 audit turned up.

Every byte of the container and of the compressed bitstream is emitted here;
no RAR tool produces any part of it. unrar is used only afterwards, as a
decompression oracle, to read the archive back.
"""

import binascii
import struct
import sys

# --- alphabet sizes (compress.hpp:23-30) -----------------------------------
NC, DC, LDC, RC, BC = 306, 64, 16, 44, 20
TABLE_SIZE = NC + DC + LDC + RC  # 430, the layout MakeDecodeTables walks
                                 # (unpack50.cpp:709-713)


class BitWriter:
    """MSB-first, matching unrar's BitInput."""

    def __init__(self):
        self.bits = []

    def put(self, value, count):
        assert value >> count == 0, f"{value:#x} does not fit in {count} bits"
        for i in reversed(range(count)):
            self.bits.append((value >> i) & 1)

    def align(self):
        while len(self.bits) % 8:
            self.bits.append(0)

    def bytes(self):
        out = bytearray()
        for i in range(0, len(self.bits), 8):
            chunk = self.bits[i : i + 8] + [0] * (8 - len(self.bits[i : i + 8]))
            byte = 0
            for bit in chunk:
                byte = (byte << 1) | bit
            out.append(byte)
        return bytes(out)


def canonical(lengths):
    """MakeDecodeTables' assignment (unpack.cpp:246-317): increasing length,
    then increasing symbol index."""
    codes = {}
    code = 0
    for length in range(1, 16):
        for sym, sym_len in enumerate(lengths):
            if sym_len == length:
                codes[sym] = (code, length)
                code += 1
        code <<= 1
    return codes


# --- the shared Huffman shape ----------------------------------------------
# 15 literals plus symbol 256 (the filter record) make a complete 4-bit code.
LITERALS = [0x00, 0x01, 0x02, 0x03, 0x10, 0x11, 0x20, 0x21,
            0x30, 0x31, 0x40, 0x41, 0x42, 0xE8, 0xE9]
SYMBOLS = sorted(LITERALS) + [256]
assert len(SYMBOLS) == 16

MAIN_LENGTHS = [0] * TABLE_SIZE
for sym in SYMBOLS:
    MAIN_LENGTHS[sym] = 4
LD_CODES = canonical(MAIN_LENGTHS[:NC])

# Bit-length table: symbol 0 ("length 0") 1 bit, symbol 4 ("length 4") 2 bits,
# two spares to keep the code complete.
BD_LENGTHS = [0] * BC
BD_LENGTHS[0] = 1
BD_LENGTHS[4] = 2
BD_LENGTHS[5] = 3
BD_LENGTHS[6] = 3
BD_CODES = canonical(BD_LENGTHS)


def put_tables(bw):
    """ReadTables (unpack50.cpp:612-714)."""
    for length in BD_LENGTHS:
        assert length < 15
        bw.put(length, 4)
    for length in MAIN_LENGTHS:
        code, count = BD_CODES[0 if length == 0 else length]
        bw.put(code, count)


def put_symbol(bw, sym):
    code, count = LD_CODES[sym]
    bw.put(code, count)


def put_literals(bw, data):
    for byte in data:
        put_symbol(bw, byte)


def put_filter_data(bw, value):
    """ReadFilterData (unpack50.cpp:177-189): 2 bits of byte count, then that
    many little-endian bytes."""
    count = 1
    while value >= (1 << (8 * count)):
        count += 1
    assert count <= 4
    bw.put(count - 1, 2)
    for i in range(count):
        bw.put((value >> (8 * i)) & 0xFF, 8)


FILTER_DELTA, FILTER_E8, FILTER_E8E9, FILTER_ARM = 0, 1, 2, 3


def put_filter(bw, block_start_delta, block_length, kind, channels=1):
    """Symbol 256 plus ReadFilter (unpack50.cpp:192-212)."""
    put_symbol(bw, 256)
    put_filter_data(bw, block_start_delta)
    put_filter_data(bw, block_length)
    bw.put(kind, 3)
    if kind == FILTER_DELTA:
        bw.put(channels - 1, 5)


def block(payload_bits, table_present=True, last=True):
    """One RAR5 compressed block: header (unpack50.cpp:556-608) + payload."""
    payload = BitWriter()
    payload.bits = list(payload_bits)
    bit_count = len(payload.bits)
    payload.align()
    body = payload.bytes()
    size = len(body)
    bit_size = bit_count - 8 * (size - 1)  # valid bits in the final byte
    assert 1 <= bit_size <= 8, bit_size
    byte_count = 1
    while size >= (1 << (8 * byte_count)):
        byte_count += 1
    assert byte_count <= 3
    flags = (bit_size - 1) | ((byte_count - 1) << 3)
    if last:
        flags |= 0x40
    if table_present:
        flags |= 0x80
    checksum = 0x5A ^ flags ^ (size & 0xFF) ^ ((size >> 8) & 0xFF) ^ ((size >> 16) & 0xFF)
    out = bytes([flags, checksum & 0xFF])
    for i in range(byte_count):
        out += bytes([(size >> (8 * i)) & 0xFF])
    return out + body


# --- container --------------------------------------------------------------
def vint(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def header(htype, hflags, type_fields, data_size=None):
    body = vint(htype) + vint(hflags)
    if data_size is not None:
        body += vint(data_size)
    body += type_fields
    raw = vint(len(body)) + body
    return struct.pack("<I", binascii.crc32(raw)) + raw


SIGNATURE = bytes.fromhex("526172211a070100")
# Compression info: version 0, not solid, method 3, dictionary 0x20000 << 0.
COMPRESSION_INFO = (3 << 7)
HFLAG_DATA_SIZE = 0x0002
FFLAG_CRC32 = 0x0004


def file_header(name, packed_len, unpacked_size, crc):
    name_bytes = name.encode()
    fields = vint(FFLAG_CRC32) + vint(unpacked_size) + vint(0o644)
    fields += struct.pack("<I", crc)
    fields += vint(COMPRESSION_INFO) + vint(1) + vint(len(name_bytes)) + name_bytes
    return header(2, HFLAG_DATA_SIZE, fields, data_size=packed_len)


def build(members):
    out = bytearray(SIGNATURE)
    out += header(1, 0, vint(0))            # main archive header
    for name, packed, unpacked_size, crc in members:
        out += file_header(name, len(packed), unpacked_size, crc)
        out += packed
    out += header(5, 0, vint(0))            # end of archive
    return bytes(out)


# --- the members ------------------------------------------------------------
BLOCK64 = bytes(LITERALS[i % len(LITERALS)] for i in range(64))
# Eight E8 records whose little-endian address is 0x00032010, below the
# 0x1000000 the E8 filter treats as inside the file, so each one is rewritten.
E8_BLOCK = bytes([0xE8, 0x10, 0x20, 0x03, 0x00, 0x41, 0x41, 0x41] * 8)


def member_filter_overruns_size():
    """A delta block over [0,64) in a member that declares 16 bytes.

    unpack50.cpp:357 hands the whole block to `UnpWrite` with no DestUnpSize
    clamp, so the oracle emits all 64 filtered bytes.
    """
    bw = BitWriter()
    put_tables(bw)
    put_filter(bw, 0, 64, FILTER_DELTA, channels=1)
    put_literals(bw, BLOCK64)
    return block(bw.bits), 16


def member_e8_overruns_size():
    """The same overrun through the E8 filter, so the transform is visible."""
    bw = BitWriter()
    put_tables(bw)
    put_filter(bw, 0, 64, FILTER_E8)
    put_literals(bw, E8_BLOCK)
    return block(bw.bits), 16


def member_raw_overrun_clamped():
    """No filter, 64 raw bytes, 16 declared. UnpWriteData clamps."""
    bw = BitWriter()
    put_tables(bw)
    put_literals(bw, BLOCK64)
    return block(bw.bits), 16


def member_filter_inside_size():
    """The well-formed shape: block and declared size agree."""
    bw = BitWriter()
    put_tables(bw)
    put_filter(bw, 0, 64, FILTER_DELTA, channels=1)
    put_literals(bw, BLOCK64)
    return block(bw.bits), 64


def member_raw_clamped_then_e8():
    """64 raw bytes (16 emitted) then an E8 block queued ahead of them.

    `WrittenFileSize` advances by the full span `UnpWriteData` was handed, not
    by the clamped part (unpack50.cpp:547), and the E8 filter takes its file
    offset from that counter, so the rewrite uses offset 64.
    """
    bw = BitWriter()
    put_tables(bw)
    put_filter(bw, 64, 64, FILTER_E8)
    put_literals(bw, BLOCK64)
    put_literals(bw, E8_BLOCK)
    return block(bw.bits), 16


def member_filter_start_past_window():
    """A block queued at [64,128) in a member that stops after 32 bytes.

    unpack50.cpp:315 never matches the filter and unpack50.cpp:405 writes the
    rest raw, so the declared 16 bytes go out and the filter is dropped.
    """
    bw = BitWriter()
    put_tables(bw)
    put_filter(bw, 64, 64, FILTER_DELTA, channels=1)
    put_literals(bw, BLOCK64[:32])
    return block(bw.bits), 16


MEMBERS = [
    ("filter-overruns-size.bin", member_filter_overruns_size),
    ("e8-overruns-size.bin", member_e8_overruns_size),
    ("raw-overrun-clamped.bin", member_raw_overrun_clamped),
    ("filter-inside-size.bin", member_filter_inside_size),
    ("raw-clamped-then-e8.bin", member_raw_clamped_then_e8),
    ("filter-start-past-window.bin", member_filter_start_past_window),
]

# CRC32 of every member's output, from unrar 7.20 used purely as a
# decompression oracle on the archive this script assembles. `--blank` writes
# zeroes instead, which is how these were obtained: build blank, extract with
# `-kb`, hash the files, put the values here, rebuild, `unrar t` passes.
ORACLE_CRCS = {
    "filter-overruns-size.bin": 0x457C1FAB,
    "e8-overruns-size.bin": 0x2FFBC2F8,
    "raw-overrun-clamped.bin": 0x4811841C,
    "filter-inside-size.bin": 0x457C1FAB,
    "raw-clamped-then-e8.bin": 0x1E68425C,
    "filter-start-past-window.bin": 0x4811841C,
}


def main():
    crcs = dict(ORACLE_CRCS)
    if len(sys.argv) > 2 and sys.argv[2] == "--blank":
        crcs = {}
    members = []
    for name, factory in MEMBERS:
        packed, unpacked_size = factory()
        members.append((name, packed, unpacked_size, crcs.get(name, 0)))
    data = build(members)
    with open(sys.argv[1], "wb") as handle:
        handle.write(data)
    print(f"wrote {sys.argv[1]} ({len(data)} bytes)")


if __name__ == "__main__":
    main()
