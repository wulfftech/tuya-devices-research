# Full 2 MiB BK7238 dump that survives the chip dropping out mid-read.
#
# Read 4K at a time, CRC-check every block against the chip, and on any failure just re-link and
# carry on from that same block. Progress survives a restart via <out>.part + <out>.next, so a
# drop costs one block, not the run.
#
# Two things are specific to this rig:
#   - no CEN pulsing. This board has no CEN pad at all, so a re-link means the human cycles the
#     3.3 V rail. Hence the long link_timeout and the periodic prompts: it waits for you rather
#     than pulsing.
#   - DTR/RTS released, since stock ltchiptool's open (which asserts them) is what broke the link.
#
# usage: python tools/bk_resume_read.py COM6 dump\stock-full-2MiB.bin

import pathlib
import sys
import time

import serial

_orig_open = serial.Serial.open


def open_released(self):
    self.dtr = False
    self.rts = False
    _orig_open(self)


serial.Serial.open = open_released

from bk7231tools.serial import BK7231Serial  # noqa: E402  after the patch

PORT = sys.argv[1] if len(sys.argv) > 1 else "COM6"
OUT = pathlib.Path(sys.argv[2] if len(sys.argv) > 2 else "dump/stock-full-2MiB.bin")
BAUD = int(sys.argv[3]) if len(sys.argv) > 3 else 230400
FLASH = 0x200000
PART = OUT.with_suffix(".part")
NEXT = OUT.with_suffix(".next")

bk = BK7231Serial(PORT, baudrate=BAUD, link_timeout=90.0, cmnd_timeout=0.6, link_baudrate=115200)
# Stock is 20 retries at ~1s each; re-linking is faster than waiting that out.
bk.read_retries = 0

buf = bytearray(PART.read_bytes()) if PART.exists() else bytearray(FLASH)
# A short part file from a previous run must not be trusted as a complete buffer.
if len(buf) != FLASH:
    buf = bytearray(buf) + bytearray(FLASH - len(buf))
addr = int(NEXT.read_text()) if NEXT.exists() else 0
print(f"resuming at 0x{addr:06X}" if addr else "starting at 0x000000", flush=True)

linked = False
links = fails = 0
t_start = time.time()
while addr < FLASH:
    try:
        if not linked:
            print("  -- cycle the 3.3V power now (open ~2s, close, wait) --", flush=True)
            bk.connect()
            linked = True
            links += 1
            print(f"  link #{links} at 0x{addr:06X}", flush=True)
        buf[addr : addr + 0x1000] = bk.flash_read_4k(addr, crc_check=True)
        addr += 0x1000
        if addr % 0x10000 == 0 or addr == FLASH:
            PART.write_bytes(buf)
            NEXT.write_text(str(addr))
            print(f"0x{addr:06X} ({addr * 100 // FLASH}%)  links={links} fails={fails}", flush=True)
    except Exception as e:
        fails += 1
        if linked:
            print(f"  dropped at 0x{addr:06X}: {type(e).__name__}: {str(e)[:60]}", flush=True)
        linked = False
        if fails > 400:
            PART.write_bytes(buf)
            NEXT.write_text(str(addr))
            sys.exit("too many failures, progress saved")

OUT.write_bytes(buf)
PART.unlink(missing_ok=True)
NEXT.unlink(missing_ok=True)
print(f"done: {OUT} ({len(buf)} bytes) in {time.time() - t_start:.0f}s, links={links}, fails={fails}")