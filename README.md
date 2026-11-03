# tuya-devices-research

Owner research on Arlec PC191HA smart plugs — reading your own device's keys
and using them to replace the stock Tuya firmware with OpenBeken or ESPHome.
No case required on one model; no way around it on the other.

This is not a security disclosure. The BK7238 bootloader has no signature
check to break, and the keys involved are the owner's own, issued to their own
account for their own device. The work here is figuring out which of those
keys matter, how to get them back, and what the firmware will accept.

## Two products, two outcomes

The same retail name covers several incompatible revisions. The two this repo
covers behave completely differently, and the difference is not a matter of
effort — it is in the firmware.

| | [Series 4](SERIES-4.md) | [Series 3](SERIES-3.md) |
|---|---|---|
| Module / chip | T1-2S-NL / **BK7238** | CB2S / **BK7231N** |
| Firmware | `1.0.2` | `1.1.17` |
| **Over-the-air reflash** | **Works — no case, no soldering** | **Not possible** |
| Serial (case-open) reflash | Works | Works |
| Why | The stock firmware implements a LAN OTA path, and the account can read the keys it needs | The stock firmware has no LAN OTA path, and the one key that would gate it is factory-only |
| Status | Working, reproduced on multiple units | Closed; one open question, no result |

If you are holding a PC191HA and want to know which one you have, the module
silkscreen is the answer: `T1-2S-NL` is the Series 4, `CB2S` is the Series 3.
Do not assume a guide for one applies to the other — the pin maps differ, and
the OTA path only exists on one of them.

## What's here

**Start with the unit you have:**

- [SERIES-4.md](SERIES-4.md) — the reflashable one: what works, what's proven, what isn't.
- [SERIES-3.md](SERIES-3.md) — the one that doesn't, and why not.

**Then the detail:**

- [ARCHITECTURE.md](ARCHITECTURE.md) — the device's key material, what each
  key gates, and the two ways an owner recovers their own keys to reflash.
  The "why it works" behind the how-to docs.
- [HARDWARE.md](HARDWARE.md) — module pinout, flash partition map, this
  board's confirmed pin roles.
- [FLASHING.md](FLASHING.md) — dumping stock firmware and flashing over
  serial, safely. **Read the safety section before connecting anything** —
  this board's power stage is not isolated from mains.
- [PROVISIONING.md](PROVISIONING.md) — getting from "OpenBeken boots" to
  "relay, button, LED and metering all configured and verified."
- [REFERENCES.md](REFERENCES.md) — external sources, and what each settled.
- `tools/` — the scripts referenced from the docs above.
- `images/` — board and module photos referenced from the docs above.
- [`dump/`](dump/README.md) — full flash reads: stock, post-OpenBeken, and the
  app partition pre-extracted for a disassembler.
- [`served-images/`](served-images/README.md) — the actual OTA images pushed
  to real hardware.

![The board with the T1-2S-NL module removed: both relays, the BL0942 metering section, and the non-isolated power stage](images/board-overall.jpg)

## Scope

This covers two products in one family, on two chips. It is not a general
Tuya-cracking toolkit. The key-recovery step (decoding the on-device KV store)
is specific to this hardware generation, and the LAN OTA path is specific to
firmware that implements it — don't assume either carries over to a different
Tuya module without checking.

## License

[CC BY-NC 4.0](LICENSE) — attribution required, no commercial use.