# tuya-devices-research

Owner research on Tuya-based smart devices: reading your own devices' keys and
replacing the stock firmware with open alternatives.

Two product families so far. The Arlec PC191HA plugs are the main thread; the TH01
sensor is a different class of device with a different obstacle.

The bootloaders involved have no signature check to break, and the keys are the
owner's own, issued to their own account for their own device. Nothing here is a
disclosure.

## Which device do you have?

### Smart plugs

Arlec has shipped several incompatible revisions under the PL-whatever name. The
ones covered here:

| App default name | Module | Chip | Over-the-air reflash | Detail |
|---|---|---|---|---|
| `PC191HA Series 2` | CB2S | BK7231N | No | [SERIES-3.md](SERIES-3.md) |
| `PC191HA Series 3` | CB2S | BK7231N | No | [SERIES-3.md](SERIES-3.md) |
| `PC191HA Series 4` | T1-2S-NL | BK7238 | **Yes** | [SERIES-4.md](SERIES-4.md) |

The Smart Life app tells you which one you have. Open the device and read its
default name. If you have renamed it, the module silkscreen answers it:
`T1-2S-NL` is the Series 4, `CB2S` is the Series 2 or 3.

Series 2 and Series 3 are one product separated by a firmware revision. They
share a productKey, a module and a DP set, and units of both report firmware
`1.1.17`; cloudcutter's profile for this productKey is the older `1.1.8`.

The firmware analysis behind [SERIES-3.md](SERIES-3.md) was done on a **Series 2**
image at `1.1.17`, published in cloudcutter issue #691. The Series 3 unit here
reports the same firmware version and the same productKey but was never dumped,
so the "no LAN OTA receiver" result reaches the Series 3 by firmware identity
rather than by direct measurement of a Series 3 image. No `1.1.8` image has been
examined at all.

### Sensors

| Device | Module | Chip | Route | Detail |
|---|---|---|---|---|
| TH01 temp/humidity, `TH01Y-CB3S V2.1` | CB3S | BK7231N | Wire flash or cloudcutter | [TH01.md](TH01.md) |

The TH01 has no mains hazard and no LAN OTA path. Its obstacle is a second MCU
that owns the Wi-Fi module's serial line and its power supply.

## What works

**The Series 4 plug reflashes over the air.** No case, no soldering and no UART.
The stock firmware implements a LAN OTA path, and the account can read the keys
that path needs. Three units have been reflashed this way: two to OpenBeken, one
to ESPHome with the whole transfer captured on the wire. Relay, relay indicator
and BL0942 metering all come up afterwards and survive a real power cycle.

**The Series 3 plug does not.** Its firmware has no LAN OTA receiver, and the key
that would sign the completion check is factory-burned. The serial route still
works, as the same case-open UART flash as any BK7231N, but there is no
over-the-air path. One question is still open and has no result.

**The TH01 sensor does, both ways.** Wire flash and cloudcutter both work. Three
units run OpenBeken and report to Home Assistant over MQTT.

## What's here

Start with the page for your device:

- [SERIES-4.md](SERIES-4.md): the reflashable plug, both routes, what is proven,
  what is not, and ESPHome as a second target.
- [SERIES-3.md](SERIES-3.md): the plug that does not reflash, and why not.
- [TH01.md](TH01.md): the battery sensor, the MCU that blocks a normal flash, and
  the measurement that turns "cut a trace" into "lift one pin".

Then the detail:

- [ARCHITECTURE.md](ARCHITECTURE.md): the plug's key material, what each key
  gates, and the two ways an owner recovers their own keys to reflash.
- [HARDWARE.md](HARDWARE.md): module pinout, flash partition map, and the
  Series 4's confirmed pin roles.
- [FLASHING.md](FLASHING.md): dumping stock firmware and flashing over serial.
  **Read the safety section before connecting anything**. This board's power
  stage is not isolated from mains.
- [PROVISIONING.md](PROVISIONING.md): getting from "OpenBeken boots" to "relay,
  button, LED and metering all configured and verified."
- [ESPHOME.md](ESPHOME.md): the ESPHome config for the Series 4, and which build
  output to flash.
- [REFERENCES.md](REFERENCES.md): external sources, and what each settled.
- [UPSTREAM.md](UPSTREAM.md): what this project has sent back to OpenBeken and
  ESPHome, and what is still under review.
- `tools/`: the scripts referenced from the docs above.
- `images/`: board and module photos referenced from the docs above.
- [`dump/`](dump/README.md): full flash reads: stock, post-OpenBeken, and the
  app partition pre-extracted for a disassembler.
- [`served-images/`](served-images/README.md): the OTA images pushed to real
  hardware.

![The board with the T1-2S-NL module removed: both relays, the BL0942 metering section, and the non-isolated power stage](images/board-overall.jpg)

## Scope

Two product families on two chips, plus a sensor on a third. This is not a
general Tuya-cracking toolkit. The key-recovery method is specific to the BK7238
generation, the OTA path only exists on firmware that implements it, and the
TH01's blocker is specific to that board's second microcontroller. Check before
assuming any of it carries over to a different Tuya module.

## License

[CC BY-NC 4.0](LICENSE): attribution required, no commercial use.