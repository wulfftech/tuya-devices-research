#!/usr/bin/env python3
"""Verify the real image layout and produce the logical (CPU-visible) image.

What this tool establishes
--------------------------
The Beken XIP partitions are stored as 32 data bytes + 2 check bytes. Removing
those 2 bytes yields the *logical* image the CPU executes, which is why literal
pools never matched file offsets in the raw dump.

De-interleaving shows this empirically: after removing the check bytes, 51.2%
of 4-byte words land on a string start, versus 1.5% raw and 1.6% for a
byte-shuffled control. This tool checks that a second way (ARM literal-pool
loads resolving to real strings) and writes the logical image out.

The check bytes themselves are NOT a standard CRC-16 of their 32-byte block --
every parameter in the standard CRC-16 catalogue was tried and none matched,
nor did any chained or spanning variant. That's consistent with Beken's own
`encrypt_crc` tooling (referenced by LibreTiny), which encrypts the CRC bytes.
Consequence: the logical image can be *derived* for analysis, but the check
bytes cannot be *regenerated* without the chip's key.

usage:
  python tools/logical_image.py --write
"""

import argparse
import re
import struct
from pathlib import Path

DUMP = Path(__file__).resolve().parent.parent / "dump" / "stock-full-2MiB.bin"
OUT = Path(__file__).resolve().parent.parent / "dump" / "stock-full-2MiB.logical.bin"

PAYLOAD, CHECK = 32, 2
STRIDE = PAYLOAD + CHECK


def to_logical(raw, lo, hi):
    """Extract the payload bytes of a partition (drops the check bytes)."""
    out = bytearray()
    o = lo
    while o + STRIDE <= hi:
        out += raw[o : o + PAYLOAD]
        o += STRIDE
    return bytes(out)


def raw_of_logical(logical_off, lo):
    """Map a logical offset back to the raw flash offset within a partition."""
    group = logical_off // PAYLOAD
    within = logical_off % PAYLOAD
    return lo + group * STRIDE + within


def is_string_start(D, a):
    if not (0 <= a < len(D) - 12) or not (32 <= D[a] < 127):
        return False
    if a > 0 and 32 <= D[a - 1] < 127:
        return False
    run = 0
    i = a
    while i < len(D) and 32 <= D[i] < 127:
        run += 1
        i += 1
    return run >= 8


def pointer_rate(img, lo, hi):
    tot = hit = 0
    ex = []
    for o in range(0, len(img) - 4, 4):
        w = struct.unpack_from("<I", img, o)[0]
        if not (lo <= w < hi):
            continue
        tot += 1
        if is_string_start(img, w):
            hit += 1
            if len(ex) < 5:
                ex.append((o, w, img[w : w + 28]))
    return tot, hit, ex


def verify(raw):
    boot = to_logical(raw, 0x0, 0x11000)
    app = to_logical(raw, 0x11000, 0x12C000)
    logical = boot + app
    print("logical image: %d bytes (bootloader %d, app %d)" % (len(logical), len(boot), len(app)))
    print()

    print("=== string-pointer match rate (words -> string starts) ===")
    for name, img in (("raw", raw), ("logical", logical)):
        for lo, hi, label in ((0x0, 0x200000, "whole image"),):
            tot, hit, ex = pointer_rate(img, lo, hi)
            print("   %-8s %-12s %d/%d (%.2f%%)" % (
                name, label, hit, tot, 100.0 * hit / tot if tot else 0))
    print()
    tot, hit, ex = pointer_rate(logical, 0, len(logical))
    print("   examples from the logical image:")
    for o, w, txt in ex:
        print("      word@0x%06X = 0x%06X -> %r" % (o, w, txt))
    print()

    print("=== bootloader: do ARM-mode pool loads resolve to string starts now? ===")
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
    except ImportError:
        print("   (skipped -- needs 'pip install capstone')")
    else:
        md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
        md.detail = False
        md.skipdata = True
        good = 0
        tot = 0
        for ins in md.disasm(boot, 0):
            o = ins.op_str
            if not ins.mnemonic.startswith("ldr") or "[pc" not in o:
                continue
            m = re.search(r"#(0x[0-9a-f]+|\d+)", o)
            if not m:
                continue
            t = ((ins.address + 8) & ~3) + int(m.group(1), 0)
            if not (0 <= t < len(boot) - 4):
                continue
            tot += 1
            w = struct.unpack_from("<I", boot, t)[0]
            if is_string_start(boot, w):
                good += 1
                if good <= 12:
                    print("      0x%05X -> 0x%06X %r" % (ins.address, w, boot[w : w + 34]))
        print("   ARM: %d/%d loads resolve to a string start" % (good, tot))
    print()

    print("=== known bootloader strings, from the LOGICAL image ===")
    for s in [b"Verify the old bin crc32", b"src_crc32 error", b"dst bin_crc32 error",
              b"Verify the new firmware", b"require", b"rsa", b"sha256", b"signature"]:
        hits = [m.start() for m in re.finditer(re.escape(s), boot)]
        print("   %-26s bootloader hits=%d %s" % (
            s.decode(), len(hits), ["0x%X" % h for h in hits[:3]]))
    print()
    print("=== crypto-keyword census on the LOGICAL image (bootloader vs app) ===")
    for k in ("rsa", "sha256", "signature", "pubkey", "hmac", "aes", "crc32", "Verify"):
        b = len(re.findall(re.escape(k.encode()), boot))
        a = len(re.findall(re.escape(k.encode()), app))
        print("   %-12s boot=%-4d app=%-4d" % (k, b, a))

    return logical


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--write", action="store_true")
    a = p.parse_args()
    raw = DUMP.read_bytes()
    logical = verify(raw)
    if a.write:
        OUT.write_bytes(logical)
        print()
        print("wrote %s (%d bytes)" % (OUT, len(logical)))


if __name__ == "__main__":
    main()
