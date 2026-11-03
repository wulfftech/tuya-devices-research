# Upstream contributions

Work from this project that has gone back to the projects it depends on. All of
it is generic: no unit identity, no key material, no household detail.

## OpenBeken

### 1. AP fallback when Wi-Fi never connects

Branch `wifi-never-connected-ap-fallback`.

OpenBeken retries a configured SSID forever when the join fails. That is not a
boot failure, so the safe-mode boot counter never trips, and the device becomes
unreachable with no way back in short of a factory reset. The failure is easy to
hit: a stored credential that is wrong, or an access point that is present but
refusing the join.

Two changes:

- A 900 s never-connected watchdog. If the boot has not joined a network by
  then, it opens the fallback AP once. The check is deliberately narrow: it
  only fires before the first successful association, so a device that joins
  and later drops keeps retrying exactly as it always has.
- The status LED blinks while the fallback AP is up. This covers the plain
  `LED` role, which has no AP-mode awareness of its own because it is only
  driven by `CHANNEL_Set` on a channel change.

The LED change is the fiddly part. `CHANNEL_Set` is event-driven and nothing
re-asserts a channel on its own, so the restore on exit is not optional: without
it the LED stays wherever the last blink toggle left it.

One related change is easy to miss. A second countdown in `Main_OnEverySecond`
calls `Main_ConnectToWiFiNow()`, which clears AP mode unconditionally, so it
would pull the radio back into STA within seconds of the fallback opening. The
branch guards that call with `!g_bOpenAccessPointMode`. Without the guard the
watchdog fires and is then silently undone.

### 2. `ENABLE_DRIVER_BL0942` is undefined under the default variant

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

## Status

Submitted and under review. Nothing here is merged, and this page will say so
until it is.
