#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""build_m3_openbeken_image.py -- build the OpenBeken (OpenBK7238) replacement
container: the app wrapped as a bare-xz RCZL diff2ya container, ready for a
live LAN OTA. See LAN-OTA-PROTOCOL.md's "Container format" section for the
header layout and why the xz payload has to be exactly this shape.

Two things earlier builds of this container got wrong, both fixed here:

  * Payload base. The app has to land at logical VA 0x10000 -- where the
    live applier writes (`dst_0 = 0x10000`). An earlier image placed the app
    one page low (VA 0x11000, the *raw partition's* start address, mistaken
    for a logical offset); for a replacement app that's fatal, since it
    leaves mid-app data sitting on the ARM entry vector. Here the payload
    *is* the app, placed at dst 0x10000, so the base is correct by
    construction.

  * buf_size (header +0x2C) = 0x10000 -- the applier's record/step size.
    Only record sizes that are a multiple of 0x10000 keep the erase
    sector-aligned; a smaller size clips the previous record's tail.

  * The QIO app region is RAW, not LOGICAL. A QIO image is a *serial-flash*
    image: its bytes mirror raw flash, so the app at QIO[0x11000:] is stored
    in the chip's CRC-interleaved form (32 data + 2 CRC16 per 34-byte group),
    not the logical form the CPU executes and the OTA applier consumes. An
    earlier build packaged the raw form directly; the applier re-interleaved
    it on top of already-interleaved bytes, and the CPU executed a stream
    skewed two bytes every 34 -- dead after 32 bytes, no UART recovery
    possible on that unit. This build DE-INTERLEAVES the sliced raw app
    (tools/logical_image.py's `to_logical`) before wrapping it, and asserts
    the de-interleave against EXTERNAL anchors that don't reference the
    payload being served: vector[0] is the SDK's `b .+0x38`, the 8th
    vector-literal slot is the SDK's 0xdeadbeef marker, and every
    exception-handler literal is a page-local address.

Plus the live LAN-delivery header patches: the `magic_ver` gate value
(0x004D4D4D), `patch_length` adjustment, `bin_start_addr = 0x40`, and
`buf_size` as above.

The OpenBeken image source is the full `OpenBK7238_QIO_<ver>.bin` (its own
bootloader at offset 0 is NOT used -- the Tuya bootloader already occupies
0..0x11000 on the device). The app is QIO[0x11000 : app_end], where app_end
is the first run of >= 0x1000 `0xFF` bytes (the erased tail).

Offline only -- builds a file and (with --validate) drives the real applier
(fn 0x5258) in tools/ota_emu.py against it.

Usage:
    python tools/build_m3_openbeken_image.py \
        --qio /path/to/OpenBK7238_QIO_1.18.318.bin \
        --out served-images/RCZL-openbeken.bin --validate
"""
import argparse
import hashlib
import lzma
import os
import struct
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from build_identity_patch import build_header, offtout  # noqa: E402
from logical_image import to_logical  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

BIN_TYPE_RCZL = 0x4C5A4352      # "RCZL"
MAGIC_VER_GATE = 0x004D4D4D     # fn 0x073FF0 path-head gate (LAN chunk 0)
BIN_START_ADDR = 0x40           # skip the 64-byte diff2ya_header to the xz stream
BUF_SIZE = 0x10000              # record/step size; multiple of 0x1000, sector-aligned
DELTA = 4                       # keeps mgr[0x1c] above the delivered byte count
DICT_SIZE = 4096                # bare-xz applier's dict bound
APP_RAW_START = 0x11000         # app's raw-XIP start inside the QIO image
DST_FLASH_ADDR = 0x00010000     # live applier dst_0
XZ_FLASH_ADDR = 0x00150000      # scratch staging base inside the emulator only
FN_APPLY = 0x005258
# The real decoder costs ~20M insns per 0x10000-byte record: 40M stops after 2
# records, and ota_emu.call() then returns STALE r0 as "rc" (the 0xf that looks
# like an error code). 400M comfortably covers the largest app this build makes.
_MAX_INSNS = 400_000_000

BARE_XZ_FILTERS = [{"id": lzma.FILTER_LZMA2, "dict_size": DICT_SIZE}]


def find_app_end(app, min_run=0x1000):
    """First >= min_run 0xFF run marks the erased tail; return its start."""
    run = 0
    for i, b in enumerate(app):
        if b == 0xFF:
            run += 1
            if run >= min_run:
                return i - run + 1
        else:
            run = 0
    return len(app)


def assert_app_anchors(app):
    """The external anchors a LOGICAL BK7238 app must satisfy, regardless of which
    userland (OpenBeken or an ESPHome/LibreTiny build) built it on top of
    the shared Beken SDK crt0/vector table.
    Raises SystemExit (with a diagnostic) on any mismatch rather than silently
    wrapping a wrong-form payload."""
    if struct.unpack_from("<I", app, 0x00)[0] != 0xEA00000E:
        raise SystemExit("anchor fail: vector[0] is not the SDK `b .+0x38` "
                         "(form skew? got 0x%08x)" % struct.unpack_from("<I", app, 0x00)[0])
    if struct.unpack_from("<I", app, 0x3C)[0] != 0xDEADBEEF:
        raise SystemExit("anchor fail: vector-literal slot 8 is not 0xdeadbeef "
                         "(got 0x%08x -- payload is probably the raw form)"
                         % struct.unpack_from("<I", app, 0x3C)[0])
    for i in range(0x20, 0x3C, 4):           # exception-handler literals
        v = struct.unpack_from("<I", app, i)[0]
        if not (0x10000 <= v < 0x11000):
            raise SystemExit("anchor fail: handler literal at 0x%x is not "
                             "page-local (0x%08x)" % (0x10000 + i, v))
    if app[0x40:0x44] != b"\x00\x00\x0f\xe1":  # mrs r0, apsr (0xE10F0000) -- crt0 entry
        raise SystemExit("anchor fail: crt0 entry at 0x10040 is not `mrs r0, apsr`"
                         " (got %s)" % app[0x40:0x44].hex(" "))


def extract_app(qio_path):
    """Slice the raw (CRC-interleaved) app out of the QIO image, then
    DE-INTERLEAVE it to the logical form the applier consumes and the CPU
    executes.  Asserts the result against external SDK anchors -- a wrong-form
    payload (raw served as logical, the known crash mode) fails loudly here."""
    qio = open(qio_path, "rb").read()
    if qio[APP_RAW_START:APP_RAW_START + 4] != b"\x0e\x00\x00\xea":
        raise SystemExit("QIO[0x%x] is not an ARM app vector table: %s"
                         % (APP_RAW_START, qio[APP_RAW_START:APP_RAW_START + 8].hex(" ")))
    raw = qio[APP_RAW_START:]
    end = find_app_end(raw)
    raw = raw[:end]
    raw = raw[:len(raw) // 34 * 34]          # drop a partial trailing group
    app = to_logical(raw, 0, len(raw))

    # ---- external anchors: the served form must be the LOGICAL app ----
    assert_app_anchors(app)

    print("QIO %s: %d bytes; raw app QIO[0x%x:0x%x] = %d bytes -> LOGICAL %d bytes "
          "(de-interleaved); entry %s"
          % (qio_path, len(qio), APP_RAW_START, APP_RAW_START + end, len(raw),
             len(app), app[:8].hex(" ")))
    print("anchors: vector[0]=b .+0x38, marker@0x1003c=0xdeadbeef, "
          "handlers=%s, crt0@0x10040=mrs r0,apsr -- all PASS"
          % [hex(struct.unpack_from("<I", app, i)[0]) for i in range(0x20, 0x3C, 4)])
    return app


def build_container(app):
    xz = lzma.compress(app, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC32,
                       filters=BARE_XZ_FILTERS)
    hdr = bytearray(build_header(app, app, xz, bin_type=BIN_TYPE_RCZL,
                                 bin_start_addr=BIN_START_ADDR, step=0,
                                 buf_size=BUF_SIZE))
    # the four live LAN-delivery patches
    struct.pack_into("<I", hdr, 0x00, MAGIC_VER_GATE)
    struct.pack_into("<I", hdr, 0x20, struct.unpack_from("<I", hdr, 0x20)[0] + DELTA)
    return bytes(hdr) + xz


def validate(app, blob, max_insns=None):
    """Stage the blob exactly as the live device does and drive fn 0x5258.
    A correct run lands `app` at DST_FLASH_ADDR with rc == 0. (The harness models
    logical addresses, so this confirms the payload bytes land where the device
    writes them; the base being VA 0x10000 is a property of the payload we chose
    -- asserted below -- not something the emulator can re-derive.)"""
    if max_insns is None:
        max_insns = _MAX_INSNS
    from ota_emu import Harness, RAM_BASE          # unicorn-backed; lazy import
    hdr, xz = blob[:64], blob[64:]
    assert lzma.decompress(xz) == app, "xz payload != app"
    assert struct.unpack_from("<I", hdr, 0x2C)[0] == BUF_SIZE, "buf_size not 0x10000"
    assert struct.unpack_from("<I", hdr, 0x1C)[0] == BIN_START_ADDR, "bin_start_addr not 0x40"

    h = Harness(verbose=False)
    h.uc.mem_write(XZ_FLASH_ADDR, blob)
    ctx_addr = RAM_BASE + 0x200
    ctx = bytearray(0x100)
    struct.pack_into("<I", ctx, 0x00, 0xABCDDCBA)
    struct.pack_into("<I", ctx, 0x40, 0x1000)          # NOT the record size
    struct.pack_into("<I", ctx, 0x48, DST_FLASH_ADDR)
    struct.pack_into("<I", ctx, 0x4C, XZ_FLASH_ADDR)   # staged container base
    h.uc.mem_write(ctx_addr, bytes(ctx))

    rc = h.call(FN_APPLY, [ctx_addr, XZ_FLASH_ADDR, 0], max_insns=max_insns)
    stopped = h.log_lines and "stopped at pc=" in h.log_lines[-1]
    if stopped:
        print("validate: STOPPED AT MAX_INSNS -- rc below is stale r0, not a real code")
        return False
    got = bytes(h.uc.mem_read(DST_FLASH_ADDR, len(app)))
    writes = len(h.flash_writes)
    print("validate: rc=0x%x  writes=%d  bytes-at-0x%x==app: %s"
          % (rc, writes, DST_FLASH_ADDR, got == app))
    if got != app:
        for i in range(len(app)):
            if got[i] != app[i]:
                print("  first mismatch at app+0x%x" % i)
                break
    return rc == 0 and got == app


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--qio", required=True, help="OpenBK7238_QIO_<ver>.bin")
    ap.add_argument("--out", default=os.path.join(ROOT, "served-images",
                                                  "RCZL-openbeken.bin"))
    ap.add_argument("--validate", action="store_true",
                    help="drive the real applier (fn 0x5258) in the emulator")
    ap.add_argument("--insns", type=int, default=_MAX_INSNS,
                    help="instruction budget for --validate (default 400M; ~20M per record)")
    a = ap.parse_args()

    app = extract_app(a.qio)
    blob = build_container(app)
    open(a.out, "wb").write(blob)
    print("built %s (%d bytes; app %d; xz %d; crc32(app)=0x%08x)"
          % (a.out, len(blob), len(app), len(blob) - 64, zlib.crc32(app)))
    print("  word0=0x%08x bin_type=0x%08x bin_start_addr=0x%x buf_size=0x%x patch_length=0x%x"
          % (struct.unpack_from("<I", blob, 0x00)[0],
             struct.unpack_from("<I", blob, 0x04)[0],
             struct.unpack_from("<I", blob, 0x1C)[0],
             struct.unpack_from("<I", blob, 0x2C)[0],
             struct.unpack_from("<I", blob, 0x20)[0]))
    print("  sha256:", hashlib.sha256(blob).hexdigest())

    if a.validate:
        ok = validate(app, blob, a.insns)
        print("VALIDATION:", "PASS" if ok else "FAIL")
        return 0 if ok else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
