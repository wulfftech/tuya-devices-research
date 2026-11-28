# The LAN OTA protocol

The wire format and firmware behaviour behind [`tools/`](tools/)'s flashing
scripts: the frame envelope, the handshake, the OTA commands, the completion
check, the container format, discovery, and the two ways a flash can go
wrong. [ARCHITECTURE.md](ARCHITECTURE.md) covers the key model and why the
owner can do any of this with their own credentials; this page covers what
actually goes on the wire once they do.

Everything below was established by reading disassembly and then confirming
it against a real device or the real firmware code running in an emulator,
not by reading the disassembly alone. Addresses are from the Series 4
(BK7238) stock firmware.

## Frame envelope ("6699")

Every LAN-plane frame, both directions, has this shape:

| Offset | Width | Field |
|---|---|---|
| `0x00` | 4 | prefix, wire bytes `00 00 66 99` |
| `0x04` | 1 | version, always `0x00` |
| `0x05` | 1 | reserved, always `0x00` |
| `0x06` | 4 | sequence number, big-endian |
| `0x0a` | 4 | command, big-endian |
| `0x0e` | 4 | `L`, big-endian — length from the nonce through the tag, i.e. `L = len(payload) + 0x1c` |
| `0x12` | 12 | AES-GCM nonce, unique per packet |
| `0x1e` | `L-0x1c` | ciphertext |
| `L+0x02` | 16 | AES-GCM tag |
| `L+0x12` | 4 | footer, wire bytes `00 00 99 66` |

Total frame length is `L + 0x16`. The AAD is the 14 header bytes from offset
`0x04` through `0x11` (version/reserved/seq/cmd/L), so the header is
authenticated but not encrypted, and the payload is both. This is AES-GCM,
not the HMAC or CRC32 envelopes earlier Tuya LAN protocol versions used.

The handshake frames (commands 3/4/5, below) are sealed with the real,
static `localKey`. Once the handshake completes, every later frame — including
the OTA commands — is sealed with a session key derived from it. No KDF
beyond that derivation is used on this path: `localKey` and the session key
are both handed to the AES-GCM primitive unchanged.

## Handshake (commands 3, 4, 5)

| Cmd | Direction | Payload |
|---|---|---|
| 3 | client → device | `randA` (16 bytes) |
| 4 | device → client | `retcode`(4) \|\| `randB`(16) \|\| `HMAC-SHA256(localKey, randA)`(32) — 52 bytes total |
| 5 | client → device | `HMAC-SHA256(localKey, randB)` (32 bytes) |

Command 4 is the device's own reply, built as part of command 3's handler —
a client never sends a command 4 itself. Command 5 succeeding produces **no
reply at all**; a timeout waiting for one means the handshake succeeded, not
that it failed. A close instead of a timeout means the HMAC check failed.

The session key is derived from both nonces:

```
tmp         = device_nonce XOR client_nonce
session_key = AES-GCM(localKey, nonce=client_nonce[:12], plaintext=tmp)[12:28]
```

— the first 16 bytes of pure keystream output from a GCM encryption of the
XOR'd nonces, independent of the tag.

One real trap: the nonce for every frame **must be fresh**. A fixed or
reused nonce is the one envelope mistake that produces total silence rather
than a logged rejection — the device never reaches a point where it logs
anything, so nothing comes back on the socket at all. It looks exactly like
the device being unreachable.

## OTA commands (0x1A / 0x1B / 0x1C)

| Cmd | Direction | Meaning |
|---|---|---|
| `0x1A` | client → device | OTA start. JSON body: `otaChannel`, `otaVersion`, `fileHmac`, `isDiffOta`, `otaFileLen` (a bare number, not a quoted string) |
| `0x1B` | device → client | chunk request: `{"file_offset": N, "data_block_len": M}` |
| `0x1B` | client → device | chunk reply: the raw `M` bytes themselves, no JSON, no echoed offset — a purely positional protocol |
| `0x1C` | device → client | transfer complete (empty body) |

The device pulls chunks over this same LAN session — nothing is served over
HTTP on this path. (An HTTP serving mode exists in some of the tooling only
because it was carried over from Tuya's MQTT entrypoint, which has a
different grammar with a `url`/`diffUrl` field; it's dead code here.)

**The session must stay open after `0x1C`.** The device applies the staged
image inside the same LAN session that delivered it — closing the socket the
instant `0x1C` arrives interrupts the apply, and the unit reboots back into
its old firmware having never actually installed anything. Hold the
connection open and drain it for tens of seconds after `0x1C` before treating
the transfer as finished.

## The completion check

Passing the device's own OTA-completion check requires computing

```
fileHmac = hex(HMAC-SHA256(secKey, HEX-UPPER(SHA256(served_container))))
```

and putting it in the `0x1A` body's `fileHmac` field — confirmed against
real hardware, uppercase hex mandatory (a lowercase digest is rejected).
This needs the owner's `secKey` in addition to `localKey`; there is no
`secKey`-free route to a completed LAN transfer on this firmware build.

The firmware does contain a second, skippable 32-byte comparison, gated by
a state flag that a served container's header can arm (one of four accepted
4-byte magic words — `ISBA`, `RCZL`, `8RBA`, `QZCL` — at **byte offset 4**,
the same `bin_type` field every container already needs to carry for the
OTA-start gate to accept it in the first place). That mechanism is real:
driven directly, arming the flag does skip the comparison, and the flag
does get armed on a real LAN transfer that carries one of the magic words —
the device logs it and the value persists across a reboot. But the function
that owns this skippable comparison is never entered by the LAN OTA ingest
path on this build: the live transfer always runs a separate, unconditional
32-byte comparison in a different function, one with no skip branch at all.
So the magic word buys nothing against the completion check here — it's
still required, but for the unrelated reason that it's a real container
header field read again later in the apply pipeline. `tools/owner_reflash.py`
and `tools/ota_flash.py` both end up needing the same thing: the real
`fileHmac`, computed from `secKey`. (Full control-flow evidence for this —
function addresses, the pointer-table census, and the UART log cross-check
— is in `tools/owner_reflash.py`'s module docstring.)

Either way this isn't a security boundary being crossed — the BK7238
bootloader has no code signing at all (see [ARCHITECTURE.md](ARCHITECTURE.md)),
and reaching the LAN session at all already requires `localKey`. `fileHmac`
is a completion-integrity check, not an authentication check.

## Container format

The container every OTA image is wrapped in (`diff2ya_header`, 64 bytes,
followed by the payload):

| Offset | Width | Field |
|---|---|---|
| `0x00` | 4 | `magic_ver` gate value, `0x004D4D4D` for the LAN path |
| `0x04` | 4 | `bin_type` — one of `ISBA` / `RCZL` / `8RBA` / `QZCL` |
| `0x08` | 4 | `src_crc32` |
| `0x0c` | 4 | `dst_crc32` |
| `0x10` | 4 | `src_length` |
| `0x14` | 4 | `dst_length` |
| `0x18` | 4 | `bin_offset` |
| `0x1c` | 4 | `bin_start_addr` — `0x40` for the LAN path (the payload starts right after this header) |
| `0x20` | 4 | `patch_length` |
| `0x24` | 4 | `patch_crc32` |
| `0x28` | 4 | `step` — `0` for an in-place OTA (old and new app share one base address) |
| `0x2c` | 4 | `buf_size` — the applier's record/step size, `0x10000` for the LAN path |
| `0x30`–`0x3f` | | mode, file index, min supported version, reserved |

The payload itself is a single `xz` stream (`FD 37 7A 58 5A 00`), filter
LZMA2, **dictionary size 4096 bytes, check type CRC32**. Both of those are
load-bearing: the device's decoder has a fixed 4 KiB output ring buffer, so
a larger dictionary is silently rejected (not an error — it just fails the
same way a bad digest does: `ota data proc failed`), and anything other than
CRC32 is refused outright. A container built with a bare `lzma.compress()`
call defaults to CRC64 and a different dictionary size, and gets rejected —
`tools/build_m3_openbeken_image.py` and `tools/owner_reflash.py` both check
and refuse a non-conforming payload before sending anything.

For a **replacement app** (OpenBeken, ESPHome, anything that isn't the stock
app), the payload also has to be the app's **logical** form — the form the
CPU executes — not the **raw** form a flash dump captures. The Beken SDK
stores app flash as 32 data bytes + 2 check bytes per 34-byte group; a raw
dump still carries those check bytes interleaved in, and wrapping that
directly produces a payload that is subtly, uniformly corrupted (every 34th
byte is wrong). `tools/logical_image.py`'s `to_logical()` strips them.
`tools/build_m3_openbeken_image.py` asserts the result against the SDK's own
fixed boot vectors before wrapping it, rather than trusting the
de-interleave silently.

## Discovery (UDP 7000)

Devices answer a sealed UDP broadcast on port 7000 with their identity
(`gwId`/`uuid`/`productKey`). The frame shape is simpler than the LAN
envelope above — fixed `00 00 66 99` / `00 00 99 66` head and tail, a 4-byte
type and a 4-byte length instead of the full header, same AES-GCM sealing —
and the key is a **fixed, public constant** baked into every device of this
family: `md5(b"yGAdlopoPVldABfn")`. It isn't a secret and isn't owner-issued;
it's how an unconfigured device identifies itself to the Tuya app during
setup. A probe carries the asker's own IP inside the seal, and the device
replies to that sealed-in address — port 7000, not the probe's source port.

This is also what `tools/wedge_healthcheck.py` uses to tell a device that's
merely hard to reach apart from one that's actually gone: a ping failure
from the wrong subnet looks identical to a bricked unit, but a discovery
reply (even from a different vantage point later) does not.

## Two failure modes, and why they need separate handling

**Bricked**: no ARP entry, no ICMP reply — the unit isn't on the network at
all. Usually a truncated transfer; the bootloader's partial apply leaves the
app partition unusable. UART only.

**Wedged**: the host answers ping, ARP resolves, the unit even keeps its
stock cloud MQTT keepalives running — but no management surface is bound:
`:6668` resets instead of accepting, and nothing serves `:80`. The apply
*completed* but the application's post-boot transition never finished. This
has happened with a byte-identical image that applied cleanly on one run and
wedged a unit on another — the mechanism is characterised (an incomplete
post-apply transition, not a bad image), not fully explained. Also UART
only; nothing short of a case-open recovery brings a wedged unit back.

Ping alone cannot distinguish "wedged" from "healthy" or "bricked" — all
three can produce different combinations of ICMP, ARP, and port state, and a
successful flash to a *replacement* firmware like OpenBeken deliberately
doesn't serve the stock ports (`:6668`, UDP-7000) at all, since those are
stock-firmware-only surfaces. `tools/wedge_healthcheck.py` checks the actual
surface set each outcome implies rather than treating "doesn't answer the
old ports" as a failure.

## Validating a container offline, before it ever reaches a device

Because a bad byte in a hand-built container can write directly to the live
app partition with no safe failure mode, `tools/ota_emu.py` runs the real
bootloader's patch-applier code (not a reimplementation of it) against a
candidate container inside a Unicorn CPU emulator, loaded from the same
flash dump in [`dump/`](dump/README.md). It maps the real flash and a RAM
region, stubs out only the genuine hardware/OS boundary (flash read/write,
heap allocation, logging), and lets the actual LZMA2 decoder and container
applier execute as real, unmodified firmware code. A container that doesn't
survive this check wasn't going near real hardware anyway; one that does
still only proves the applier accepted it, not that a live device will
behave identically — it's a validation step before a live run, not a
substitute for one.
