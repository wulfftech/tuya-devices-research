#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ota_emu.py -- Unicorn CPU emulator harness for the PC191HA S4 bootloader's
OTA/diff2ya patch applier.

WHY THIS EXISTS
----------------
The LAN-OTA path (see LAN-OTA-PROTOCOL.md) only gets as far as the app
staging a chosen image unverified. Applying it is a SEPARATE gate -- the
bootloader's own diff2ya/bsdiff/xz patcher -- which writes reconstructed
bytes DIRECTLY to the live app partition, incrementally, as reconstruction
proceeds (`flash_write(app_start+sl, buf, r4)`). A wrong byte in a hand-built
container doesn't fail safely at a header check; it can land on a unit with
no flash dump and no case-open recovery.

Getting the diff2ya/bsdiff/xz container format exactly right by reading
disassembly alone turned out to be unreliable in practice. Three
non-obvious traps were only found this way: a RAM-resident CRC32 table
that's zero unless seeded, a fixed 4096-byte LZMA2 output buffer that
silently rejects larger dictionary sizes, and a per-record capacity guard
whose operand comes from `buf_size`, not `step`. Each would have been very
easy to get wrong against a real device and each was only *provably*
resolved by running the real bootloader code against synthetic input and
watching what it actually did.

This harness is that: it maps the real flash dump + a RAM region, hooks only
the genuine hardware/OS boundary (flash read/write, heap, logging, one BK7238
boot-ROM call), and lets every other instruction -- including the actual
LZMA2/xz decoder and bsdiff-style patch applier -- execute as real, unmodified
firmware code. It is a validation tool, not a replacement for a live test:
treat anything it reports as "did the real apply logic accept this" (code
actually executed, not just read), never as proof a live device will behave
identically.

USAGE
-----
    from tools.ota_emu import Harness, RAM_BASE
    h = Harness()
    ... write a diff2ya_header + patch blob into h.uc memory ...
    rc = h.call(0x04ED4, [ctx_addr, header_addr, 0])   # compression_run
    print(h.flash_writes)   # [(dest_addr, bytes), ...] -- what it actually wrote

Requires `pip install unicorn`. tools/logical_image.py separately wants
`capstone` for one optional diagnostic -- the two are independent, neither
is needed to import the other.
"""
import struct

from unicorn import (
    Uc, UcError,
    UC_ARCH_ARM, UC_MODE_ARM,
    UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED,
)
from unicorn.arm_const import (
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC,
)

import os
DUMP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "dump", "stock-full-2MiB.logical.bin")

FLASH_BASE = 0x00000000
FLASH_SIZE = 0x00200000  # 2 MiB, page-aligned
RAM_BASE = 0x00400000
RAM_SIZE = 0x00040000     # 256 KiB
STACK_TOP = RAM_BASE + RAM_SIZE - 0x1000
HEAP_START = RAM_BASE + 0x20000  # clear of fixed-address tables, e.g. the CRC32 table at 0x4069D0

# Known helper addresses (bootloader, ARM mode, logical == file offset)
F_FLASH_READ = 0x5874
F_FLASH_WRITE = 0x5644
F_LOG = 0x1194
F_ALLOC_594C = 0x594C      # tal_malloc-ish: r0 = size
F_GETCTX_5588 = 0x5588     # NOT an allocator despite the superficial resemblance --
                            # called with r0 = caller's own ctx pointer; crc32_range
                            # does `ldr r8,[returned_ptr]` and feeds r8 straight into
                            # tal_malloc as a SIZE, so this returns a pointer to a
                            # small globals struct whose word 0 is a default chunked
                            # I/O buffer size.
F_FREE_5950 = 0x5950

CRC32_TABLE_ADDR = 0x004069D0  # RAM-resident; built by boot-time init we never run
DEFAULT_CHUNK_SIZE = 0x200     # plausible stand-in for whatever F_GETCTX_5588 really returns

GETCTX_GLOBAL_ADDR = 0x00400100  # F_GETCTX_5588 is, read directly, `ldr r0,[pc]; bx lr` --
                            # a two-instruction accessor that unconditionally returns
                            # this ONE FIXED RAM pointer and allocates nothing at
                            # all. judge_ota_info copies word 0 of *this* struct into
                            # ctx[0x40] ("stride") and word 4 into ctx[0x54] ("base")
                            # at its own start (confirmed by hooking the real call --
                            # both fields read 0 under emulation because this address
                            # is never populated by the boot-time init we never run,
                            # same category of gap as the CRC32 table). A synthetic
                            # test that wants a specific stride/base writes them here
                            # directly, same as a real boot sequence would.

CRASH_ADDR = 0xFFFFFFF0  # sentinel LR so `call()` can tell "returned" from "ran off the rails"


def load_flash():
    with open(DUMP, "rb") as f:
        data = f.read()
    buf = bytearray(b"\xff" * FLASH_SIZE)
    buf[: len(data)] = data
    return bytes(buf)


def crc32_table(poly=0xEDB88320):
    table = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ poly if (c & 1) else (c >> 1)
        table.append(c)
    return table


class Harness:
    def __init__(self, verbose=True, default_chunk_size=DEFAULT_CHUNK_SIZE):
        self.verbose = verbose
        self.default_chunk_size = default_chunk_size
        self.log_lines = []
        self.flash_reads = []
        self.flash_writes = []  # (dest_addr, bytes) -- what the firmware actually wrote, in order
        self._stubbed_pages = set()

        self.uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self.uc.mem_map(FLASH_BASE, FLASH_SIZE)
        self.uc.mem_write(FLASH_BASE, load_flash())
        self.uc.mem_map(RAM_BASE, RAM_SIZE)
        self.uc.mem_write(RAM_BASE, b"\x00" * RAM_SIZE)
        self.uc.mem_write(
            CRC32_TABLE_ADDR,
            b"".join(struct.pack("<I", v) for v in crc32_table()),
        )
        # Default contents for the fixed GETCTX_GLOBAL_ADDR struct real fn 0x5588
        # always points at (word 0 = chunk size; the rest, including the word 4
        # / word 0x14 fields judge_ota_info reads, stays zeroed same as the rest
        # of RAM unless a test overwrites it -- see GETCTX_GLOBAL_ADDR above).
        # Written ONCE here, not on every hook_getctx call, so a test that pokes
        # its own values into this struct before calling into the emulator
        # doesn't get them silently stomped on the next getctx call.
        self.uc.mem_write(GETCTX_GLOBAL_ADDR, struct.pack("<I", default_chunk_size) + b"\x00" * 0xFC)
        self.heap_next = HEAP_START

        for addr, fn in [
            (F_FLASH_READ, self.hook_flash_read),
            (F_FLASH_WRITE, self.hook_flash_write),
            (F_LOG, self.hook_log),
            (F_ALLOC_594C, self.hook_alloc),
            (F_GETCTX_5588, self.hook_getctx),
            (F_FREE_5950, self.hook_free),
        ]:
            self.uc.hook_add(UC_HOOK_CODE, self._wrap(fn), begin=addr, end=addr)
        self.uc.hook_add(UC_HOOK_MEM_UNMAPPED, self._hook_unmapped)

    # --- plumbing ----------------------------------------------------------
    def _wrap(self, fn):
        def cb(uc, address, size, user_data):
            fn()
        return cb

    def log(self, msg):
        if self.verbose:
            print(msg)
        self.log_lines.append(msg)

    def ret(self, value=0):
        """Simulate `bx lr` with r0 = value, from inside a hook."""
        lr = self.uc.reg_read(UC_ARM_REG_LR)
        self.uc.reg_write(UC_ARM_REG_R0, value & 0xFFFFFFFF)
        self.uc.reg_write(UC_ARM_REG_PC, lr)

    def regs(self, n):
        names = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3]
        return [self.uc.reg_read(names[i]) for i in range(n)]

    def _read_cstr(self, addr, maxlen=200):
        data = self.uc.mem_read(addr, maxlen)
        end = data.find(b"\x00")
        return data[: end if end >= 0 else maxlen].decode("latin1")

    def _hook_unmapped(self, uc, access, address, size, value, user_data):
        """A real BK7238 has mask-ROM routines (flash programming primitives)
        at fixed high addresses outside any dump we have. One such call was hit,
        from the low-level flash-write path at 0x55F4, branching
        to 0x3F01E8. Rather than special-case that one address, treat ANY
        totally unmapped fetch as "boot-ROM call, assume success": map a
        throwaway page there holding `mov r0,#0 ; bx lr` and continue. This is
        a deliberate approximation -- it cannot be used as evidence about what
        that boot-ROM call actually verifies, only as a way to keep emulating
        past it."""
        page = address & ~0xFFF
        if page not in self._stubbed_pages:
            self.uc.mem_map(page, 0x1000)
            self.uc.mem_write(page, b"\x00\x00\xa0\xe3\x1e\xff\x2f\xe1" * 0x200)
            self._stubbed_pages.add(page)
            self.log("!! unmapped %s at 0x%x -- stubbed page 0x%x as bx-lr" % (access, address, page))
        return True

    # --- hooks for the genuine hardware/OS boundary -------------------------
    def hook_alloc(self):
        (size,) = self.regs(1)
        self.log("alloc requested: 0x%x (%d) bytes, lr=0x%x" % (size, size, self.uc.reg_read(UC_ARM_REG_LR)))
        addr = self.heap_next
        self.heap_next += (size + 0xF) & ~0xF
        if self.heap_next - RAM_BASE > RAM_SIZE - 0x2000:
            raise RuntimeError("heap exhausted in emulation (requested 0x%x)" % size)
        self.uc.mem_write(addr, b"\x00" * size)
        self.log("alloc(0x%x) -> 0x%x" % (size, addr))
        self.ret(addr)

    def hook_getctx(self):
        (ctxptr,) = self.regs(1)
        # Real fn 0x5588 allocates nothing -- it unconditionally returns the one
        # fixed pointer GETCTX_GLOBAL_ADDR (confirmed by direct disassembly: two
        # instructions, `ldr r0,[pc]; bx lr`). The previous version of this stub
        # allocated a fresh, never-freed 0x100-byte heap block on every call,
        # which silently exhausted the emulator's synthetic heap on any call
        # chain that invokes this more than a few hundred times, and made it
        # impossible for a test to durably set the struct's other fields
        # (ctx[0x40]/ctx[0x54]) since each call overwrote them back to
        # the default. Returning the same fixed, caller-writable address fixes
        # both without changing any already-confirmed result: anything that
        # only reads word 0 (the chunk size) sees the identical value as before.
        self.log("getctx(0x%x) -> 0x%x (fixed global, [0]=0x%x)" % (ctxptr, GETCTX_GLOBAL_ADDR, self.default_chunk_size))
        self.ret(GETCTX_GLOBAL_ADDR)

    def hook_free(self):
        (p,) = self.regs(1)
        self.log("free(0x%x)" % p)
        self.ret(0)

    def hook_log(self):
        r0, r1, r2, r3 = self.regs(4)
        try:
            fmt = self._read_cstr(r0)
        except Exception:
            fmt = "<unreadable fmt @0x%x>" % r0
        self.log("LOG fmt=%r args=(0x%x,0x%x,0x%x)" % (fmt, r1, r2, r3))
        self.ret(0)

    def hook_flash_read(self):
        r0, r1, r2, r3 = self.regs(4)
        self.log("flash_read(r0=0x%x, r1=0x%x, r2=0x%x, r3=0x%x)" % (r0, r1, r2, r3))
        self.flash_reads.append((r0, r1, r2, r3))
        # Heuristic: whichever of r0/r1 looks like a flash offset is the
        # source, whichever looks like a RAM pointer is the destination.
        # This has held across every call site exercised so far but is not
        # derived from a confirmed calling convention -- recheck if a new
        # call site behaves oddly.
        cand = [x for x in (r0, r1) if x < FLASH_SIZE]
        dst_cand = [x for x in (r0, r1) if RAM_BASE <= x < RAM_BASE + RAM_SIZE]
        length = r2
        if cand and dst_cand:
            src, dst = cand[0], dst_cand[0]
            try:
                data = self.uc.mem_read(src, length)
                self.uc.mem_write(dst, bytes(data))
                self.log("  -> served %d bytes from flash 0x%x to 0x%x" % (length, src, dst))
                self.ret(0)
                return
            except Exception as e:
                self.log("  !! flash_read emulation failed: %s" % e)
        self.log("  !! could not infer flash_read args; returning error")
        self.ret(0xFFFFFFFF)

    def hook_flash_write(self):
        r0, r1, r2, r3 = self.regs(4)
        self.log("flash_write(r0=0x%x, r1=0x%x, r2=0x%x, r3=0x%x)" % (r0, r1, r2, r3))
        dst_cand = [x for x in (r0, r1) if x < FLASH_SIZE and not (RAM_BASE <= x < RAM_BASE + RAM_SIZE)]
        src_cand = [x for x in (r0, r1) if RAM_BASE <= x < RAM_BASE + RAM_SIZE]
        length = r2
        if dst_cand and src_cand:
            dst, src = dst_cand[0], src_cand[0]
            try:
                data = bytes(self.uc.mem_read(src, length))
                self.flash_writes.append((dst, data))
                self.uc.mem_write(dst, data)  # apply in place, mirroring the real device
                self.log("  -> wrote %d bytes from RAM 0x%x to flash 0x%x" % (length, src, dst))
                self.ret(0)
                return
            except Exception as e:
                self.log("  !! flash_write emulation failed: %s" % e)
        self.log("  !! could not infer flash_write args; returning error")
        self.ret(0xFFFFFFFF)

    # --- running -------------------------------------------------------------
    def call(self, addr, args, max_insns=2_000_000):
        """Call a function at a logical address with up to 4 register args
        plus any further args passed on the (emulated caller's) stack."""
        for i, a in enumerate(args[:4]):
            self.uc.reg_write(
                [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3][i],
                a & 0xFFFFFFFF,
            )
        if len(args) > 4:
            for i, a in enumerate(args[4:]):
                self.uc.mem_write(STACK_TOP + i * 4, struct.pack("<I", a & 0xFFFFFFFF))
        self.uc.reg_write(UC_ARM_REG_SP, STACK_TOP)
        self.uc.reg_write(UC_ARM_REG_LR, CRASH_ADDR)
        try:
            self.uc.emu_start(addr, CRASH_ADDR, count=max_insns)
        except UcError as e:
            pc = self.uc.reg_read(UC_ARM_REG_PC)
            self.log("!! UcError: %s at pc=0x%x" % (e, pc))
            raise
        pc = self.uc.reg_read(UC_ARM_REG_PC)
        r0 = self.uc.reg_read(UC_ARM_REG_R0)
        if pc != CRASH_ADDR:
            self.log("!! stopped at pc=0x%x (not the return sentinel) -- likely hit max_insns" % pc)
        return r0


if __name__ == "__main__":
    h = Harness()
    print("harness constructed OK; flash dump + RAM mapped, CRC32 table seeded.")
