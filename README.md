# tuya-devices-research

Owner research on Arlec PC191HA smart plugs: reading your own device's keys and
using them to replace the stock Tuya firmware with OpenBeken or ESPHome.

The BK7238 bootloader has no signature check to break, and the keys involved are
the owner's own, issued to their own account for their own device. Nothing here
is a disclosure.

## Which plug do you have?

Arlec has shipped at least four incompatible revisions under the PC191HA name.
Three of them are in this repo, and a guide for one will waste your afternoon on
another.

The Smart Life app tells you which one you have. Open the device and read its
default name:

| App default name | Module | Chip | Over-the-air reflash | Detail |
|---|---|---|---|---|
| `PC191HA Series 2` | CB2S | BK7231N | No | [SERIES-3.md](SERIES-3.md) |
| `PC191HA Series 3` | CB2S | BK7231N | No | [SERIES-3.md](SERIES-3.md) |
| `PC191HA Series 4` | T1-2S-NL | BK7238 | **Yes** | [SERIES-4.md](SERIES-4.md) |

If you have renamed the device, the module silkscreen answers it: `T1-2S-NL` is
the Series 4, `CB2S` is the Series 2 or 3.

Series 2 and Series 3 are one product separated by a firmware revision. They
share a productKey, a module and a DP set, and units of both report firmware
`1.1.17`; cloudcutter's profile for this productKey is the older `1.1.8`.

The firmware analysis behind [SERIES-3.md](SERIES-3.md) was done on a **Series 2**
image at `1.1.17`, published in cloudcutter issue #691. The Series 3 unit here
reports the same firmware version and the same productKey but was never dumped,
so the "no LAN OTA receiver" result reaches the Series 3 by firmware identity
rather than by direct measurement of a Series 3 image. No `1.1.8` image has been
examined at all.

## What works

**The Series 4 reflashes over the air.** No case, no soldering and no UART. The
stock firmware implements a LAN OTA path, and the account can read the keys that
path needs. Three units have been reflashed this way: two to OpenBeken, one to
ESPHome with the whole transfer captured on the wire. Relay, relay indicator and
BL0942 metering all come up afterwards and survive a real power cycle.

**The Series 3 does not.** Its firmware has no LAN OTA receiver, and the key
that would sign the completion check is factory-burned. The serial route still
works, as the same case-open UART flash as any BK7231N, but there is no
over-the-air path. One question is still open and has no result.

## What's here

Start with the page for your unit:

- [SERIES-4.md](SERIES-4.md): the reflashable one: both routes, what is proven,
  what is not, and ESPHome as a second target.
- [SERIES-3.md](SERIES-3.md): the one that does not reflash, and why not.

Then the detail:

- [ARCHITECTURE.md](ARCHITECTURE.md): the device's key material, what each key
  gates, and the two ways an owner recovers their own keys to reflash.
- [HARDWARE.md](HARDWARE.md): module pinout, flash partition map, and the
  Series 4's confirmed pin roles.
- [FLASHING.md](FLASHING.md): dumping stock firmware and flashing over serial.
  **Read the safety section before connecting anything**. This board's power
  stage is not isolated from mains.
- [PROVISIONING.md](PROVISIONING.md): getting from "OpenBeken boots" to "relay,
  button, LED and metering all configured and verified."
- [REFERENCES.md](REFERENCES.md): external sources, and what each settled.
- [UPSTREAM.md](UPSTREAM.md): what this project has sent back to OpenBeken and
  ESPHome, and what is still under review.
- [ESPHOME.md](ESPHOME.md): the ESPHome config for this board, and which build
  output to flash.
- `tools/`: the scripts referenced from the docs above.
- `images/`: board and module photos referenced from the docs above.
- [`dump/`](dump/README.md): full flash reads: stock, post-OpenBeken, and the
  app partition pre-extracted for a disassembler.
- [`served-images/`](served-images/README.md): the OTA images pushed to real
  hardware.

![The board with the T1-2S-NL module removed: both relays, the BL0942 metering section, and the non-isolated power stage](images/board-overall.jpg)

## Scope

Three revisions in one family, on two chips. This is not a general Tuya-cracking
toolkit. The key-recovery step (decoding the on-device KV store) is specific to
this hardware generation, and the LAN OTA path is specific to firmware that
implements it. Check before assuming either carries over to a different Tuya
module.

## License

[CC BY-NC 4.0](LICENSE): attribution required, no commercial use.