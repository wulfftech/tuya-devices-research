# Served images

The OTA images actually pushed to real hardware over Tuya's own LAN OTA path,
using the unit's own activation-issued keys — not a separate exploit delivery
mechanism, the same path the Tuya app itself would use.

**Series 4 (BK7238) only.** These containers are for the product whose stock
firmware implements the LAN OTA receiver. The Series 3 has no such receiver —
see [SERIES-3.md](../SERIES-3.md).

| File | What it is |
|---|---|
| `RCZL.bin` | The image that installs OpenBeken — this is what every unit in this project was actually reflashed with. |
| `RCZL-unit3-noop-fixed.bin` | A no-op image in the same container format (repackages the unit's existing stock content unchanged). Used to validate the packaging against the device's own checks before trusting a real payload to it. |

`SHA256SUMS.txt` in [`../dump/`](../dump/) covers both.
