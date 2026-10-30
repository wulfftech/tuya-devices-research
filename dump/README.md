# Dumps

Full 2 MiB flash reads and their derived forms. `SHA256SUMS.txt` covers every
binary in this directory and in `../served-images/`.

| File | What it is |
|---|---|
| `stock-full-2MiB.bin` | Raw flash read of the unit as it shipped, stock Tuya firmware. Taken with `../tools/bk_resume_read.py`; see [FLASHING.md](../FLASHING.md). CRC16-interleaved, as the chip stores it — see [HARDWARE.md](../HARDWARE.md) for the de-interleaving math. |
| `stock-full-2MiB.logical.bin` | The app partition (`0x011000`+) from the same unit, de-interleaved into logical (CPU-visible) addressing. Feed this to a disassembler, not the raw file above. |
| `stock-full-2MiB.arm.elf` | The same app partition as a loadable ARM ELF, section-mapped for Ghidra/IDA/objdump instead of a flat binary. |
| `unit2-postopenbeken-2MiB.bin` | Raw flash read of a second unit after flashing OpenBeken — for diffing against the stock dump above to see exactly what a stock→OpenBeken flash changes and what it leaves alone. |
| `unit7-postopenbeken-2MiB.bin` | Raw flash read of a third unit, also post-OpenBeken, from separate testing. |

**The Tuya KV storage partition (`0x1F5000`-`0x200000`) is present, unredacted, in
every raw `.bin` above** — it's the device's activation-issued key material,
decodable with [`../tools/kv_decode.py`](../tools/kv_decode.py). See
[HARDWARE.md](../HARDWARE.md#flash-partition-map) for what that partition holds and
why these specific keys don't grant account access. These units no longer run Tuya
firmware, which is why that's included here rather than redacted.
