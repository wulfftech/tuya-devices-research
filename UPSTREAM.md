# Upstream contributions

| Project | Change | Where | Status |
|---|---|---|---|
| OpenBeken | AP fallback when Wi-Fi never connects | branch `wifi-never-connected-ap-fallback` | Ready, not submitted |
| OpenBeken | Plain `LED` role blinks while the open AP is up | branch `ap-mode-plain-led-blink` | Ready, not submitted |
| OpenBeken | `ENABLE_DRIVER_BL0942` dropped under the default variant | issue, written up | Not submitted |
| ESPHome / LibreTiny | Say which BK7238 build output is the app | no PR | Idea only |
| Cloudcutter | Hardware confirmation for the 2.1.8 TuyaMCU sensor profile | issue, written up | Not submitted |
| Cloudcutter | Sticky AP suffix never reappears on some profiles | issue, written up | Needs a repro on `main` first |

Both OpenBeken branches build. The fallback and the LED blink have run on hardware; the two
fixes made in review haven't yet.

## OpenBeken

### AP fallback when Wi-Fi never connects

OpenBeken retries a configured SSID forever when the join fails. That isn't a boot failure, so
the safe-mode boot counter never trips, and the only way back in is physical access: a run of
quick power cycles to force safe mode, or a reflash. Easy to hit - a wrong stored password, or
an access point that's there but refusing the join.

The fix is a 900 s watchdog. If the boot hasn't joined a network by then, it opens the fallback
AP once. A flag set on the first successful join and never cleared keeps it out of the way after
that, so a device that joins and later drops keeps retrying exactly as it does now.

The same branch guards a second countdown in `Main_OnEverySecond`. It calls
`Main_ConnectToWiFiNow()`, which clears AP mode unconditionally, so without the guard it pulls the
radio back into STA a few seconds after the fallback opens.

### Plain `LED` role blinks while the open AP is up

The plain `LED` role has no AP-mode awareness: it's only driven by `CHANNEL_Set` when its channel
changes. This blinks it on the same cadence as the WifiLED role while the AP is up.

The restore on exit is the fiddly part. Nothing re-asserts a channel on its own, so without it
the LED stays wherever the last blink left it, and `CHANNEL_Set` can't do it because it ignores a
value that hasn't changed. The restore drives the pin directly.

### `ENABLE_DRIVER_BL0942` is undefined under the default variant

`src/obk_config.h` undefines `ENABLE_DRIVER_BL0942` whenever `OBK_VARIANT` is `TUYAMCU` (2). A
power-metering plug built with the default variant ships without the metering driver and reports
no `ENERGY` block at all. It looks like a wiring or config fault on the device, which is where it
cost time here before the build got the blame.

Building with `OBK_VARIANT=3` (POWERMETERING) avoids it. The issue asks whether the default
should warn at build time instead of silently dropping a driver the board needs.

## ESPHome / LibreTiny

No code change needed. BK7238 and the `t1-2s` board are supported from ESPHome 2026.5.0, and the
BL0942 component works as documented. The device config lives here as [ESPHOME.md](ESPHOME.md),
since it's one board's pin map, not a component change.

The build output is what's worth fixing. A BK7238 build leaves three files that look like
candidates:

| File | What it actually is |
|---|---|
| `firmware.bin` | A UF2 package, despite the name |
| `image_bk7238_app.ota.ug.bin` | LibreTiny's own OTA container: correct diff2ya header, but `bin_type` `PCZL` |
| `raw_firmware.bin` | The bare app off the linker. Flash this one |

`PCZL` is what catches people. It's a valid container with the right magic, so it looks like the
OTA artifact, and an applier that expects `RCZL` rejects it.

## Cloudcutter

### Hardware confirmation for the 2.1.8 TuyaMCU sensor profile

`tuya-generic-zy-th02pro-temperature-and-humidity-with-display-v2.1.8` has existed since December
2024 with no linked issue and no recorded hardware result. Two units confirm it works.

It's also misnamed. It says "with Display"; the board tested here has none, so nobody searching
for this sensor finds it.

The firmware version is the useful part. Cloudcutter issue #454 closed a TH01 on `2.1.0` as
patched, and the Known-Patched list has `2.1.0`, `2.1.5`, `2.1.12`, `2.1.15` and `2.1.17` for
BK7231N. `2.1.8` isn't on it, and both units went through first time.

Two failure modes look like a broken exploit and aren't:

| Symptom | Cause |
|---|---|
| Cloudcutter hangs, device back on its own AP | The MCU cut the module's power mid-run. The button has to be pressed every 4-5 s for the whole run |
| Firmware transfer stalls while still associated | Weak signal. One unit stalled for over 3 minutes at -72 dBm and finished in under 15 s at -60 dBm |

### Sticky AP suffix never reappears on some profiles

`wifi_connect` stores the last five characters of the first matched AP name and pins the second
scan to that suffix. On some profiles the post-exploit AP name comes from the profile's
`address_ssid` instead, so the suffix never shows up and the scan loops forever.

The pin is there for a reason: it stops the second scan latching onto another device's AP, and
issue #606 tells users to set it by hand. So the fix is a timeout and a fallback to the generic
pattern, not removing the pin. Not reproduced on current `main` yet.
