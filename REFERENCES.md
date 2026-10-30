# References

External sources this project leans on, and what each one actually settled.
Kept separate from our own measurements so the distinction stays clear.

## 1. LibreTiny — T1-2S board page

<https://docs.libretiny.eu/boards/t1-2s/>

The single most valuable external reference here. It resolved the blocker
that stalls most naive string-search attempts at this firmware: **the image
is interleaved with CRC16 every 32 bytes.** Layout is 32 data bytes + 2 check
bytes, repeated — so logical (CPU-visible) addresses never equal raw file
offsets, and any search done directly against the raw dump quietly fails.
Real partition sizes are 32/34 of the apparent ones.

| | |
|---|---|
| Board code | `t1-2s` |
| MCU | Beken BK7238 |
| Flash | 2 MiB, no flash encryption |
| Flashing pins | `P10`/`RX1`, `P11`/`TX1`, `CEN` |
| Flash ID | `85 20 15` |

## 2. Beken 72xx platform page

<https://docs.libretiny.eu/docs/platform/beken-72xx/>

Confirms BK7238/BK72XX is Beken silicon, not Tuya-designed. Notes the chip
has a ROM download mode, and that `bk7231tools` (and therefore `ltchiptool`)
is the supported flashing/dumping path.

## 3. `kcraig73/breezary-levelle-esphome`

<https://github.com/kcraig73/breezary-levelle-esphome>

An independent teardown of the same module (T1-2S-NL / BK7238, 2 MiB) in a
different product (a ceiling fan). Corroborates the app partition starting
at `0x11000`, the bootloader's `BK7238_T1_2_0_0` banner, and flash ID
`85 20 15`. Their factory image's SHA-256 doesn't match ours — a different
OEM build on identical hardware, and they deliberately don't distribute it.

They accessed the bootloader the same way we did: starting the flash command
and briefly removing and restoring 3.3 V, rather than using a `CEN` pad —
useful confirmation that this isn't a workaround specific to our one board.

## 4. `dumbermore/tuya` — CVE-2026-30613

<https://github.com/dumbermore/tuya/blob/main/README.md>

Same module family (T1-2S-NL), different product. Published CVE, physical
access / confidentiality-only (`AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`,
CVSS 4.6): **"Beken bk7231 based devices allow sensitive data disclosure via
UART interface with physical access, through excessive logs and unencrypted,
extractable firmware."**

Their tooling recovers the same Tuya storage keys (`auth_key`, `uuid`,
`psk30_key`) this project's own key-recovery step targets — meaning the
confidentiality half of what we rely on is already public prior art for this
chip family, independently discovered on a different product. Their
`dissect_dump` output on their own unit also cross-checks cleanly against
our own partition-boundary measurements on this one.

## 5. Tuya T1-2S-NL module datasheet

<https://developer.tuya.com/en/docs/iot/T1-2S-module-datasheet?id=Kcl2d5xjy1rly>

Vendor datasheet.

| | |
|---|---|
| Part | T1-2S-NL, Wi-Fi + BLE combo |
| SoC | Tuya "T1" = Beken BK7238 |
| MCU clock | 160 MHz (datasheet; LibreTiny says 120 MHz — unresolved discrepancy, not ours to settle) |
| Flash | 2 MB |
| RAM | 288 KB (datasheet) / 256 KiB (LibreTiny) — same discrepancy, don't restate one figure as the other |
| Supply | 3.0–3.6 V, typ. 3.3 V |
| Wi-Fi | 802.11b/g/n, WPA2/WPA2-PSK(AES)/WPA3 |
| Bluetooth | BLE 5.2 |

Confirms the module has a `CEN` reset pin even though it isn't broken out on
this particular product's pads, and that AP-mode pairing is a designed,
shipped feature of this module — not an accidental attack surface.
