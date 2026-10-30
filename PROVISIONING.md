# Provisioning

Getting from "OpenBeken boots" to "relay, button, LED and metering all
configured and verified" — all over HTTP, no more soldering. `tools/provision_pc191ha.py`
does this idempotently; this doc explains what it's doing and why, so you can
do it by hand or adapt it to a related board.

## Target configuration (Series 4, confirmed live)

| | |
|---|---|
| `P26` | `Rel` (role 1), channel 1, active-high |
| `P24` | `Btn` (role 3), channel 1, active-low |
| `P8` | `LED` (role 5), channel 1, relay indicator |
| Startup command | `backlog startDriver BL0942; setButtonTimes 50 3 5; addEventHandler OnHoldStart 24 OpenAP` |
| MQTT flag | bit 2 set (`SetFlag 2 1`) |

## Only documented write paths

`POST /api/pins` with the full 29-element role/channel arrays, the **GET**
form of `/startup_command` (the POST form doesn't persist — easy to get
burned by this once), and `/cm` console commands (`GetChannel`, `SENSOR`,
`PowerSet`, `SetChannelLabel`, `shortName`, `SetFlag`, `flags`, `SSID1`).
Nothing here touches `/api/ota`, writes the app partition, or writes the
config blob directly as a shortcut — if a provisioning step needs a
flash-blob write to work, that's a sign something's wrong with the plan, not
a shortcut to take.

## Why each piece is there

**Pins** set the relay/button/LED roles above. Set the relay pin's channel
to match your product — this family doesn't agree on channel 0 vs. channel 1
across all its members, and copying a sibling's config silently binds the
relay to nothing.

**The button's long-press binding** (`addEventHandler OnHoldStart 24 OpenAP`,
with `setButtonTimes` stretched to 5s so a brief or accidental hold doesn't
trigger it) exists because of a gap in OpenBeken's own recovery story: a
configured Wi-Fi SSID that's simply wrong or unreachable retries STA forever
with no automatic recovery, and it's not a boot failure, so the safe-mode
counter never trips either. Without a physical recovery path, a unit in that
state needs a factory reset to get back into. A long-press binding gives you
a reset-free way back in instead.

**The metering startup command** (`startDriver BL0942`) isn't auto-started by
OpenBeken by default — the driver has to be told to start on this UART, and
"the startup command is set" is a different fact from "the driver is
running." Verify with `/cm?cmnd=SENSOR`: its `ENERGY` block only appears
while a power-measuring driver is actually active.

**The MQTT self-state flag** (bit 2, `OBK_FLAG_MQTT_BROADCASTSELFSTATEPERMINUTE`)
fixes a timing gap with Home Assistant specifically: without it, OpenBeken
publishes its `rssi`/`uptime`/`build`/`ssid`/`ip`/`temp` sensors over MQTT
exactly once, on connect — before HA's MQTT-discovery-created entities even
exist yet, and those topics aren't retained. The diagnostic sensors sit at
"unknown" forever as a result. Setting the flag makes it republish once a
minute instead, which is enough for HA to actually catch a value. Read the
current flags with `/cm?cmnd=flags` (a `Flags` int field), write with
`SetFlag 2 1`, and verify the bit actually landed before moving on — don't
trust the write call's response alone.

## Verification, not just "the write succeeded"

A channel readout is not a round trip — a plug has been reported "on" to
Home Assistant for hours while the relay itself never moved. Check:

- **Relay** — an audible click, or a measured change at the load.
- **Button** — a physical press toggles the relay.
- **LED** — follows the relay state, not Wi-Fi connection state, if this
  board sets `netled_reuse` rather than using the dedicated `WifiLED` role.
- **Metering** — `startcmd` still contains `startDriver BL0942` after a cold
  boot (not just after the write); voltage and frequency populate; current
  and power track the load and drop to zero when the relay opens.
- **Config survives a real power cycle** — not just a soft restart. Confirm
  the pin map and startup command are both still correct, and that the boot
  counter is clear, after pulling power for real.

## Wi-Fi join is a terminal step

Setting Wi-Fi credentials (`/cfg_wifi_set`) schedules a device self-reset a
few seconds later. Run it alone, last, after every other provisioning step —
not as one step in a longer batch that assumes the device stays reachable
afterward.
