#!/usr/bin/env python3
"""Decode the Tuya KV storage from the BK7238 dump.

Why this matters
----------------
The KV store is AES-ECB, which on its own only gets you as far as transplant /
partial-overwrite tricks -- ECB doesn't require knowing the key to move ciphertext
blocks around.

Reading bk7231tools' `analysis/kvstorage.py` shows something stronger: the store is
decryptable with **static** key material. No per-device secret is required beyond
what is already in the flash:

    KEY_MASTER = b"qwertyuiopasdfgh"
    KEY_PART_1 = b"8710_2M"
    KEY_PART_2 = b"HHRRQbyemofrtytf"

    def make_data_aes(inner_key):
        data_key[i] = (KEY_PART_1[i & 3] + KEY_PART_2[i] + inner_key[i]) % 256
        return AES.new(key=data_key, mode=AES.MODE_ECB)

The store is *located* with that constant too: encrypt b"\\xff" * 16 with KEY_MASTER
and search the image for the result (`KVStorage.find_storage`).

So: the root AES-ECB key decrypts the KeyBlock; the KeyBlock carries the per-device
`inner_key`; the DataBlocks decrypt with the derived data key. Every input is either
a public constant or inside the dump.

This tool drives that decoder against our dump. It invents no crypto of its own --
it calls bk7231tools so the result is attributable and reproducible.

Note the entry point matters: `KVStorage.unpack(partition_slice)` fails, because the
block is AES-encrypted and the magic check cannot run before decryption. Use
`find_storage` to locate the base, then `unpack` the WHOLE tail from there.
(`decrypt_and_unpack(data, find=True)` looks right but slices only 0x8000 bytes;
the storage partition here is 0xB000, so blocks past index 7 -- including the
post-activation `gw_ai` entry -- are silently dropped.)

usage:
  python tools/kv_decode.py
  python tools/kv_decode.py --json kv-decoded.json
"""

import argparse
import json
from pathlib import Path

DUMP = Path(__file__).resolve().parent.parent / "dump" / "stock-full-2MiB.bin"

# Tuya storage partition for this board, from the LibreTiny t1-2s map.
TUYA_LO, TUYA_HI = 0x1F5000, 0x200000


def as_text(v):
    """Render a decoded value as readable text where possible."""
    if isinstance(v, (bytes, bytearray)):
        b = bytes(v)
        try:
            return b.decode("utf-8")
        except UnicodeDecodeError:
            return "HEX:" + b.hex()
    if isinstance(v, str):
        return v
    try:
        return json.dumps(v, ensure_ascii=False)
    except TypeError:
        return str(v)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dump", default=None)
    p.add_argument("--json", default=None)
    a = p.parse_args()

    from bk7231tools.analysis.kvstorage import KVStorage, KEY_MASTER
    from Crypto.Cipher import AES

    D = Path(a.dump or DUMP).read_bytes()
    print("image: %d bytes" % len(D))
    print("storage partition (per board map): 0x%X-0x%X, %d bytes" % (
        TUYA_LO, TUYA_HI, TUYA_HI - TUYA_LO))

    # locate the store, then unpack the whole partition from there (not just the
    # 0x8000-byte window find_storage returns -- see the docstring note).
    pos, _ = KVStorage.find_storage(D)
    if pos is None:
        raise SystemExit("KV storage not found in %s" % (a.dump or DUMP))
    aes = AES.new(key=KEY_MASTER, mode=AES.MODE_ECB)
    st = KVStorage.unpack(D[pos:], aes=aes)
    print("DECODE OK -- store located and decrypted with the static master key")
    print()

    keys = sorted(st.indexes) if getattr(st, "indexes", None) else []
    print("keys: %d" % len(keys))
    for k in keys:
        idx = st.indexes[k]
        print("   %-20s block_id=%-3s page=%s" % (
            k, getattr(idx, "block_id", "?"), getattr(idx, "page_id", "?")))
    print()

    values = st.read_all_values()
    out = {}
    for name in sorted(values):
        text = as_text(values[name])
        out[name] = text
        body = text if len(text) <= 900 else text[:900] + " ...(%d chars total)" % len(text)
        print("=== %s ===" % name)
        print(body)
        print()

    if not out:
        print("no values returned -- do not treat this as an empty store")

    if a.json:
        Path(a.json).write_text(json.dumps(out, indent=2, ensure_ascii=False))
        print("wrote %s" % a.json)


if __name__ == "__main__":
    main()
