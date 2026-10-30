# tuya-s4-research

Reflashing an Arlec PC191HA Series 4 smart plug — stock Tuya firmware to
[OpenBeken](https://github.com/openshwprojects/OpenBK7231T_App) — using the
owner's own hardware and their own cloud-issued keys. Not a vulnerability.
This bootloader has no signature check to bypass; the "attack" is reading a
dump, decoding Tuya's own on-device key store, and using those keys the way
Tuya's own OTA path would.

**Read the safety section in [FLASHING.md](FLASHING.md) before connecting
anything.** This board's power stage is not isolated from mains. Get that
wrong and you can damage more than the plug.

![The board with the T1-2S-NL module removed: both relays, the BL0942 metering section, and the non-isolated power stage](images/board-overall.jpg)

## Hardware

| | |
|---|---|
| Product | Arlec PC191HA, Series 4 |
| Module | T1-2S-NL (Beken BK7238), 2 MiB flash, no flash encryption |
| Relay | 2× `TIANBO HJR-3FF-S-H`, 10 A 240 VAC, switching active + neutral together |
| Metering | BL0942, UART1 (shared with the flashing port) |

Same module family as a handful of other Tuya/Beken products — see
[REFERENCES.md](REFERENCES.md) for independent teardowns of the same silicon
in different products, including one with a published CVE for the same class
of local key disclosure this project relies on.

## What's here

- [HARDWARE.md](HARDWARE.md) — module pinout, flash partition map, this
  board's confirmed pin roles.
- [FLASHING.md](FLASHING.md) — dumping stock firmware and flashing OpenBeken
  over serial, safely.
- [PROVISIONING.md](PROVISIONING.md) — getting from "OpenBeken boots" to
  "relay, button, LED and metering all configured and verified."
- `tools/` — the scripts referenced from the docs above.
- `images/` — board and module photos referenced from the docs above.

## Scope

This covers one product family on one chip. It's not a general Tuya-cracking
toolkit, and the key-recovery step (decoding the on-device KV store) is
specific to this hardware generation — don't assume it carries over to a
different Tuya module without checking.

## License

Not yet chosen. Don't build on this commercially until that's settled — ask
first.
