# Upstream contributions

Work from this project that is prepared for the projects it depends on. All of
it is generic: no unit identity, no key material, no household detail.

Nothing here has been submitted yet. Each item says where it actually stands.

## OpenBeken

### 1. AP fallback when Wi-Fi never connects

Two branches, two PRs: `wifi-never-connected-ap-fallback` and
`ap-mode-plain-led-blink`. **Reviewed and ready, not yet submitted.** Both
build; the never-connected fallback and the LED blink have run on hardware, the
two fixes made in review have not yet.

OpenBeken retries a configured SSID forever when the join fails. That is not a
boot failure, so the safe-mode boot counter never trips, and the device becomes
unreachable with no way back in without physical access: a run of quick power
cycles to force safe mode, or a reflash. The failure is easy to
hit: a stored credential that is wrong, or an access point that is present but
refusing the join.

Two changes, one per PR:

- A 900 s never-connected watchdog. If the boot has not joined a network by
  then, it opens the fallback AP once. The check is deliberately narrow: a flag
  set on the first successful association and never cleared keeps it out of the
  way afterwards, so a device that joins and later drops keeps retrying exactly
  as it always has. The first draft keyed on the live connection state instead,
  which drops on every disconnect; review caught that before submission.
- The status LED blinks while the open AP is up. This covers the plain `LED`
  role, which has no AP-mode awareness of its own because it is only driven by
  `CHANNEL_Set` on a channel change.

The LED change is the fiddly part. Nothing re-asserts a channel on its own, so
the restore on exit is not optional: without it the LED stays wherever the last
blink toggle left it. And it cannot go through `CHANNEL_Set`, which ignores a
value that has not changed. The restore drives the pin directly.

One related change is easy to miss. A second countdown in `Main_OnEverySecond`
calls `Main_ConnectToWiFiNow()`, which clears AP mode unconditionally, so it
would pull the radio back into STA within seconds of the fallback opening. The
fallback branch guards that call with `!g_bOpenAccessPointMode`. Without the guard the
watchdog fires and is then silently undone.

### 2. `ENABLE_DRIVER_BL0942` is undefined under the default variant

**Prepared, not yet submitted.**

`src/obk_config.h` undefines `ENABLE_DRIVER_BL0942` whenever `OBK_VARIANT` is
`TUYAMCU` (2). A power-metering plug built with the default variant therefore
ships without the metering driver and reports no `ENERGY` block at all. The
symptom looks like a wiring or configuration fault on the device, which is where
it cost time here before the build was suspected.

Building with `OBK_VARIANT=3` (POWERMETERING) avoids it. The report asks whether
the default should warn at build time rather than silently dropping a driver the
board needs.

## ESPHome / LibreTiny

No code change is needed. BK7238 and the `t1-2s` board are supported from
ESPHome 2026.5.0 onward, and the BL0942 component works as documented. The
device config is published here as [ESPHOME.md](ESPHOME.md) rather than sent
upstream, because it is one board's pin map, not a component change.

What is worth fixing is the build output. A BK7238 build produces three files
that look like candidates, and only one of them is the app:

| File | What it actually is |
|---|---|
| `firmware.bin` | A UF2 package, despite the name |
| `image_bk7238_app.ota.ug.bin` | LibreTiny's own OTA container: correct diff2ya header, but `bin_type` `PCZL` |
| `raw_firmware.bin` | The bare app off the linker. This is the one. |

The `PCZL` tag is the trap. It is a valid container with the right magic, so it
looks like the OTA artifact, and a device whose applier expects `RCZL` rejects
it. Documenting which file is which would save the next person the same detour.

## Cloudcutter

### 3. Hardware confirmation for the 2.1.8 TuyaMCU sensor profile

**Prepared, not yet submitted.**

The device entry `tuya-generic-zy-th02pro-temperature-and-humidity-with-display-v2.1.8`
has existed since December 2024 with no linked issue and no recorded hardware
result. Two units confirm it works.

The entry is also misnamed. It says "with Display"; the board this was tested on
has none, which is why nobody searching for this sensor finds the profile.

The useful part is the firmware version. Cloudcutter issue #454 closed a TH01 on
firmware `2.1.0` as patched, and the Known-Patched list carries `2.1.0`, `2.1.5`,
`2.1.12`, `2.1.15` and `2.1.17` for BK7231N. `2.1.8` is not on it, and both units
exploited cleanly on the first try.

Two failure modes are worth recording alongside it, because both look like a
broken exploit and neither is:

- **The MCU cuts the module's power mid-run.** The device's button has to be
  pressed every 4 to 5 seconds for the whole run. Losing that cadence for a few
  seconds drops the radio mid-handshake and the device falls back to broadcasting
  its own AP. Cloudcutter does not notice and hangs.
- **The firmware transfer stalls on weak signal**, even while the device is still
  link-layer associated. One unit stalled for over three minutes at -72 dBm and
  finished in under 15 seconds at -60 dBm.

### 4. The sticky AP suffix never reappears on some profiles

**Prepared, not yet submitted.** Needs a repro on current `main` first.

`wifi_connect` stores the last five characters of the first matched AP name and
pins the second scan to that suffix. For some profiles the post-exploit AP name
comes from the profile's `address_ssid`, a separate baked-in value, so the suffix
never reappears and the scan loops forever.

The pin is deliberate: it stops the second scan latching onto a different
device's AP, and issue #606 tells users to set it by hand for that reason. So the
fix is a timeout and a fallback to the generic pattern, not removing the pin.

Not yet reproduced against current `main`, so this one needs a repro before it is
worth a PR.

## Status

Nothing here has been submitted yet. The two OpenBeken PRs are reviewed and
ready to open; the rest are written up and waiting. This page will say when
each one is actually open, and again when it is merged.
