# Series 3 — status

The one that does not reflash. Arlec PC191HA Series 3, module **CB2S** (Beken
**BK7231N**), stock firmware `1.1.17`.

**Status: no no-case-open route to owner firmware. Closed.** Every offline
vector has been examined and none yields a way to install owner-chosen
firmware without opening the case. The serial route still works — it is the
same class of case-open UART flash as any BK7231N — but the over-the-air path
that works on the Series 4 does not exist on this product.

This page exists so the two products are not confused. They share a part
number and nothing else that matters.

## What the firmware analysis was actually done on

The image behind every firmware claim below is **not** a Series 3 dump. It is
`pc191ha2_flash.dmp`, a **Series 2** unit published in cloudcutter issue #691
(2024-07-19), firmware `1.1.17`, module CB2S. The Series 3 unit here reports the
same firmware version and the same productKey, and a commenter in that same
issue reports a Series 3 at `1.1.17` too — but this project never dumped its own
Series 3, so no Series 3 image has been examined.

That makes the firmware claims below a **firmware-identity** result, not a
direct measurement of a Series 3. It is a strong inference: same productKey,
same module, same firmware version string. It is not the same thing as having
looked. No `1.1.8` image has been examined at all, so nothing here says anything
about Series 2 units still on the older build.

## It is a different product, not a Series 4 with a different chip

| | Series 3 | Series 4 |
|---|---|---|
| Module | CB2S | T1-2S-NL |
| Chip | BK7231N | BK7238 |
| Stock firmware | `1.1.17` | `1.0.2` |
| LAN protocol | `55aa` envelope on `:6668` | `6699` envelope on `:6668` |
| LAN OTA receiver in firmware | **absent** | present |
| `secKey` in the cloud device record | **absent** | present |
| OTA module map | `wifi` only | `mcu` + `wifi` |
| DP set | 1, 9, 17–26, 38 | same, plus 40, 42, 43 |

The pin map is a **permutation** of the same pin set, not the same map. A
config copied from a Series 4 build drives the wrong pins. Do not port one.

## Why the Series 4 route does not carry over

The Series 4 route needs two things: a LAN OTA receiver in the firmware, and a
`secKey` to sign the completion check. The Series 3 has neither — and the
receiver is the one that cannot be worked around.

- **No receiver.** The Series 4 image carries the whole LAN-OTA handler chain —
  the `LAN_OTA_BEGIN` JSON parser (`otaFileLen`, `fileHmac`, `isDiffOta`,
  `subdevID`, `otaVersion`), the `Rev lan ota start` / `ota data index` /
  `ota data proc` / `lan reset` handlers, and the `LAN_OTA_SEND` payload
  format. The `1.1.17` image carries **none** of it. Its `otaChannel` strings
  are all device→cloud reporting. The one message both images share,
  `unsupport frame type:%d`, is the generic LAN dispatcher rejecting an
  unknown frame — shared infrastructure, not an OTA handler.
- **No `secKey`.** It is absent from the Series 3's cloud record — not redacted,
  not empty, the field is not there. A unit whose firmware predates that
  provisioning step never received one. `secKey` is what signs the OTA file
  digest, so even with a receiver there would be nothing to satisfy the
  completion check with.

  Note what this does *not* mean: the LAN handshake needs only `localKey`, so
  a `secKey`-less unit is still reachable and fully readable over the LAN. Only
  the flash write is gated. The missing receiver is the harder blocker of the
  two — it is a firmware fact, not a credential one.

The discriminator is the **firmware**, not a cloud capability flag. The app
sets its "supports direct device OTA" flag unconditionally for every device it
sees in the local-device list; it is not a per-product permission.

## What was examined, and what each one settled

| Avenue | Result |
|---|---|
| LAN `55aa` command plane, swept exhaustively 0–255 | Only `{9, 10, 16}` answer. `{7, 12, 13, 15, 18, 64}` reach live handlers that reject every tested body. Nothing on this plane writes firmware. |
| The app's own LAN OTA (`DirectlyConnectDeviceOtaTask`) | Real, and it drives the `6699` envelope's `0x1A`/`0x1B`/`0x1C` — the same transfer the Series 4 route already uses. The `1.1.17` firmware has no receiver for it. |
| Cloud impersonation (stand-in endpoint) | Closed. Certificate verification is dead code on this build, but the descriptor channel is an `auth_key`-sealed MQTT session, and `auth_key` is factory-burned. |
| `auth_key` recovery from the app or the cloud | Not possible. The app relays an encrypted blob and never holds the key; the device decrypts it with a factory key. |
| Bootloader receive interface (UART, SD, button, console) | None. No receive path, no interactive shell, no magic-word recovery. |
| Bootloader verification model | Integrity only — CRC32 plus a 32-bit header hash — and the package container is decrypted with a **firmware constant**, not a per-device secret. So the bootloader is not the wall; the app-layer descriptor gate is. |
| Emulating the descriptor gate to observe it act | Not reached. Full boot does not complete in the emulator, so the gate has never been observed acting. |
| Cloudcutter | Its corpus has this productKey at firmware `1.1.8`. `1.1.17` is on its **known-patched** list, and no `1.1.17` profile exists. |

## What remains open

One question, and it needs hardware that is not currently on the network:

**Can the `auth_key`-sealed MQTT session be impersonated?** Certificate
verification is dead code, so if MQTT messages carry no app-layer HMAC, a
man-in-the-middle could inject a firmware descriptor. That needs a live
capture of the session, which needs the unit back on the network. It is the
only avenue not closed by static analysis, and it is not a small one — but it
is also not a result, and nothing here claims it works.

## Evidence level

Everything above is static analysis and emulation (E1–E2), run on a Series 2
image at the same firmware version. No claim on this page is wire-observed or
end-to-end, and the gate has never been observed acting. That is the honest
state of it, and it is why the status is "closed" rather than "proven
impossible".

## What this page deliberately does not contain

The `1.1.17` work produced a valid package format for its bootloader and the
constant that bootloader decrypts with. Neither is published here. A packer
plus a known constant is a working exploit kit for a device class that is still
in the field, and this project's position is that an owner reflash on owned
hardware is not a disclosure — so there is nothing to hand out. The status is
the useful part; the tooling is not.

## Where to go next

- [SERIES-4.md](SERIES-4.md) — the product that does reflash, and how.
- [FLASHING.md](FLASHING.md) — the serial route, which works on both.
- [REFERENCES.md](REFERENCES.md) — independent teardowns of the same silicon.
