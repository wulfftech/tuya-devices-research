#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""build_identity_patch.py -- construct a diff2ya_header + bsdiff/xz patch
blob that reconstructs its own source unchanged, and self-test it against the
real bootloader code via tools/ota_emu.py before it ever goes near a device.

STATUS: the format below is confirmed correct up to and including a real
flash_write of the reconstructed bytes -- i.e. compression_run (0x04ED4)
accepts this construction, decodes the ctrl record, recognises the
single-record "copy everything, change nothing" case, and calls the real
low-level flash write path with our true source bytes. A post-write
"_bkup_2_frmware err..." this module used to hit right after that write
turned out not to be a patch-format bug: fn 0x2F00 was rejecting ctx[0x00:4]
against a magic constant, which build_header below now sets. Anything past
the first flash_write for a larger, real payload is exercised separately by
tools/build_m3_openbeken_image.py's own validate() -- this module's own
round-trip is the single-record identity case only (see
build_patch_blob's docstring).

FORMAT (established by running the real code, not just reading it)
--------------------------------------------------------------------
diff2ya_header (64 bytes -- see LAN-OTA-PROTOCOL.md's container table) wraps a "patch blob"
whose own layout is:

    [0:8)    magic "DIFF2YA0" (literal ASCII, 8 bytes)
    [8:16)   ctrllen   -- bsdiff offtin-encoded (see below); DECOMPRESSED
                          byte length of the ctrl-record section
                          (== ctrl_num * 24)
    [16:24)  datalen   -- offtin-encoded; decompressed diff-section length.
                          Read and logged but not otherwise checked in the
                          path exercised so far.
    [24:32)  newsize   -- offtin-encoded; MUST equal header.dst_length
    [32:...) ONE real xz stream (magic "\\xFD7zXZ\\x00", standard Stream
              Header/Block Header/Block/Index/Footer), filter LZMA2,
              dict_size <= 4096 (the firmware's output ring is a fixed
              0x1000-byte buffer -- a larger dict_size fails open with no
              error, just silently rejected by 0x76D4). Check type must be
              NONE or CRC32 (decoder rejects CRC64/SHA256). Decompresses to:
                [ctrl_num * 24 bytes]  ctrl records (bsdiff layout: 8-byte
                                       offtin diff_len, 8-byte offtin
                                       extra_len, 8-byte offtin seek, per
                                       record)
                [diff bytes]           raw bytes added onto src (mod 256);
                                       all-zero reproduces src exactly
                [extra bytes]          raw bytes copied literally into dst

offtin/offtout encoding (bsdiff's own, confirmed at 0x003F3C): little-endian
7 bytes of magnitude + 1 sign byte whose top bit is the sign flag. For any
non-negative value under 2**55 this is byte-identical to plain
`struct.pack("<Q", v)`, which is what `offtout()` below does.

Known gotchas (each cost real emulator time to find -- don't re-derive):
  - buf_size (header +0x2c) feeds the per-record capacity guard via
    `buf_size umod dst_length` (when buf_size <= dst_length) or a direct
    assignment (when buf_size > dst_length) -- NOT `step`. For a real,
    multi-hundred-KB image this is very unlikely to be zero for any sane
    buf_size choice; it only bit us because the smoke-test source was 64
    bytes. Prefer buf_size > dst_length for new experiments to take the
    simple direct-assignment path.
  - The xz decoder's CRC32 table lives at a fixed RAM address
    (0x004069D0) and is populated by boot-time init code that never runs
    under the emulator -- tools/ota_emu.py seeds it directly. If you see a
    CRC mismatch on a stream you know is valid, check this first.
  - ctx[0x40] (read by fn 0x2F00 at 0x2F78) is the sector-erase loop's own
    length argument. Left at 0, `(start+length-1)>>12` underflows and the
    erase loop tries to run ~2**20 iterations -- this is what first looked
    like a "0x9488 infinite loop": the scan at 0x9488 itself is innocent, just repeatedly
    rendering a short, legitimate, correctly-NUL-terminated fixed error
    string ("flash_erase_sector error") that the stuck erase loop logs once
    per (bogus) sector. Set to a small positive value (len(src) here) to
    avoid the underflow; which value a real device would use is still open.
  - header.step (+0x28) is a real address offset, not a free/ignored field --
    a `dst_bin_crc32` investigation traced it into `_flit_data_step`
    (0x03148): every source read in that routine's byte-at-a-time copy-and-verify
    loop uses `ctx[0x48] + step + offset` (0x3280-0x3284, and again in its
    own self-verify CRC pair at 0x3338-0x3344), while every destination
    write uses `ctx[0x48] + offset` -- no `step` term (0x32DC-0x32F0,
    0x3320-0x332C). A previous version of this function defaulted `step=1`
    as an unexamined placeholder (unlike every other field above, it was
    never flagged as one); for an in-place OTA, where old and new share one
    base address (confirmed elsewhere in this project: the live applier
    writes with `flash_write(app_start+sl, ...)` directly over the live app
    partition), the correct value is `step=0`. Confirmed empirically:
    `step=1` reproduces the exact `test_src[1:] + erased-byte` corruption
    described above and returns 3 ("dst bin_crc32 error"); `step=0` skips
    `_flit_data_step`
    entirely (a different, bulk-write branch is taken instead -- see
    compression_run's own 0x5100-0x5140), reconstructs the image exactly,
    and returns 0 with "FOAT successd!". Default is `step=0` below.
"""
import lzma
import struct
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

COMPRESSION_RUN = 0x04ED4

# Scratch flash-space addresses used only inside the emulator -- not real
# device addresses. Chosen well clear of the live bootloader/app regions
# (0x0-0x103020).
SRC_FLASH_ADDR = 0x00180000
PATCH_FLASH_ADDR = 0x00190000


def offtout(v):
    """bsdiff's own int64 encoding; for v in [0, 2**55) this is identical to
    struct.pack('<Q', v)."""
    if v < 0 or v >= (1 << 55):
        raise ValueError("offtout: %d out of the range this helper supports" % v)
    return struct.pack("<Q", v)


def build_patch_blob(src, dst, dict_size=4096, check=lzma.CHECK_CRC32):
    """A single-record identity patch: dst must equal src byte-for-byte.
    (Building a true A->B diff is future work; see the module docstring.)"""
    if src != dst:
        raise NotImplementedError("only the identity case (src == dst) is implemented so far")
    magic = b"DIFF2YA0"
    ctrl_record = offtout(len(src)) + offtout(0) + offtout(0)  # diff_len=len(src), extra_len=0, seek=0
    diff_bytes = b"\x00" * len(src)  # dst = src + 0, byte for byte
    mini_header = magic + offtout(len(ctrl_record)) + offtout(len(diff_bytes)) + offtout(len(dst))
    payload = mini_header + ctrl_record + diff_bytes
    filters = [{"id": lzma.FILTER_LZMA2, "dict_size": dict_size}]
    return lzma.compress(payload, format=lzma.FORMAT_XZ, check=check, filters=filters)


def build_header(src, dst, patch_blob, bin_type=0x41425349, bin_start_addr=0,
                  step=0, buf_size=None):
    """bin_type default is "ISBA" -- bootloader-legitimate AND, not by
    coincidence -- the same header field
    the app-side HMAC-skip gate reads at image offset 4.

    step default is 0, not a placeholder -- see the "header.step" gotcha
    above. It is the real distance `_flit_data_step` (0x03148) adds to its
    SOURCE address but not its destination address; 0 is the correct value
    for this project's in-place OTA (old and new share one base), and any
    any other value reproduces the dst_bin_crc32 mismatch described above."""
    if buf_size is None:
        buf_size = len(dst) + 1  # > dst_length -> the simple direct-assignment
                                 # path in the per-record capacity guard
    header = bytearray(0x40)
    struct.pack_into("<I", header, 0x00, 1)                       # magic_ver
    struct.pack_into("<I", header, 0x04, bin_type)
    struct.pack_into("<I", header, 0x08, zlib.crc32(src))         # src_crc32
    struct.pack_into("<I", header, 0x0C, zlib.crc32(dst))         # dst_crc32
    struct.pack_into("<I", header, 0x10, len(src))                # src_length
    struct.pack_into("<I", header, 0x14, len(dst))                # dst_length
    struct.pack_into("<I", header, 0x18, 0)                       # bin_offset
    struct.pack_into("<I", header, 0x1C, bin_start_addr)
    struct.pack_into("<I", header, 0x20, len(patch_blob))         # patch_length
    struct.pack_into("<I", header, 0x24, zlib.crc32(patch_blob))  # patch_crc32
    struct.pack_into("<I", header, 0x28, step)                    # step -- see docstring; 0 for in-place OTA
    struct.pack_into("<I", header, 0x2C, buf_size)
    header[0x30] = 0                                              # mode
    header[0x31] = 0                                              # file_index
    struct.pack_into("<H", header, 0x32, 1)                       # min_supp_ver
    struct.pack_into("<I", header, 0x34, 0)                       # attr1
    struct.pack_into("<I", header, 0x38, 0)                       # attr2
    struct.pack_into("<I", header, 0x3C, 0)                       # extend_len
    return bytes(header)


def run_against_emulator(src, ctx_mode=1, verbose=True):
    """Build an identity patch for `src` and run it through compression_run.
    Returns (rc, harness) so the caller can inspect h.flash_writes etc.

    Needs `pip install unicorn` (tools/ota_emu.py's dependency) -- imported
    here, not at module level, so the rest of this module stays usable
    (building a patch blob, inspecting the header format) without it."""
    from ota_emu import Harness, RAM_BASE
    h = Harness(verbose=verbose)
    h.uc.mem_write(SRC_FLASH_ADDR, src)

    patch_blob = build_patch_blob(src, src)
    h.uc.mem_write(PATCH_FLASH_ADDR, patch_blob)

    header = build_header(src, src, patch_blob)
    header_addr = RAM_BASE + 0x100
    ctx_addr = RAM_BASE + 0x200
    h.uc.mem_write(header_addr, header)

    ctx = bytearray(0x100)
    struct.pack_into("<I", ctx, 0x00, 0xABCDDCBA)  # magic fn 0x2F00 checks at 0x2F38
                          # against its own literal-pool constant (0x2FBC); without
                          # it, compression_run returns -4 ("_bkup_2_frmware err...")
                          # right after the real flash_write.
    ctx[0x19] = ctx_mode  # compression_run's own dispatch: 0=CRC-shortcut (no
                          # write at all), 1/2=bsdiff+xz apply, 3=direct copy.
                          # Not yet confirmed which value the real LAN OTA
                          # path produces.
    struct.pack_into("<I", ctx, 0x40, len(src))  # erase-range length fn 0x2F00 reads
                          # at 0x2F78 (*(ctx+0x40)) and passes straight through as
                          # the sector-erase loop's own length argument. Left at 0
                          # (our synthetic ctx's default), `(start+length-1)>>12`
                          # underflows to a ~2**20-sector range that never finishes
                          # in any reasonable instruction budget -- this, not the
                          # format-string scan itself, was the real "0x9488" infinite
                          # loop (see the erase-range note above).
    struct.pack_into("<I", ctx, 0x48, SRC_FLASH_ADDR)
    struct.pack_into("<I", ctx, 0x4C, PATCH_FLASH_ADDR)
    struct.pack_into("<I", ctx, 0x50, SRC_FLASH_ADDR)  # found scaling this test up to a
                          # real, multi-hundred-KB payload: call site 0x3670
                          # (`ldr r0,[sb,#0x50]` immediately before its own
                          # `bl #0x5644`) writes to THIS field, not ctx[0x48] -- confirmed by
                          # direct disassembly, and by comparing h.flash_writes with and
                          # without this line set. Left unset (0) as this test always has,
                          # that write lands at flash address 0 every time -- it was NEVER
                          # actually landing at SRC_FLASH_ADDR; it was masked at this
                          # function's 64-byte scale because a 64-byte stray write to the
                          # vector table/Beken header happens not to corrupt anything this
                          # short run goes on to execute. At real firmware scale the same
                          # write is payload-sized and wipes the entire bootloader region
                          # (0x0-0x11000) outright, crashing immediately on the next fetch --
                          # this is how the gap was actually found, not inferred. Setting it
                          # equal to ctx[0x48] (the real in-place-OTA convention: old and new
                          # share one base) fixes both call sites. Does not change this
                          # function's own already-published result (same rc, same content,
                          # same test_src).
    h.uc.mem_write(ctx_addr, bytes(ctx))

    rc = h.call(COMPRESSION_RUN, [ctx_addr, header_addr, 0])
    return rc, h


if __name__ == "__main__":
    test_src = (b"HELLOFIRMWARE123" * 4)
    rc, h = run_against_emulator(test_src)
    print("compression_run returned: %d (0x%x)" % (rc, rc & 0xFFFFFFFF))
    print("flash_writes:", [(hex(d), len(b)) for d, b in h.flash_writes])
