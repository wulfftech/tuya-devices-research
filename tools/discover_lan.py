#!/usr/bin/env python3
"""UDP-7000 LAN discovery for PC191HA units: listen, probe, unseal.

See LAN-OTA-PROTOCOL.md's Discovery section for how this fits the rest of the
LAN protocol. The identity exchange:

  frame    = 00006699 00000000 0000 <BE32 type> <BE32 len> <data> 00009966
  key      = md5(b"yGAdlopoPVldABfn")
  data     = nonce(12) || AES-GCM(tag 16), aad = frame[4:18]
  probe    = type 0x25, plaintext {"from":"app","ip":"<asker ip>"}  <- reply target
             is INSIDE the seal: a replayed probe answers the original asker.
  identity = type 0x13 reply, unseal with the same scheme, skip 4 leading zero
             bytes of the plaintext, UTF-8 JSON -> gwId/uuid/productKey/...

Devices reply to UDP **port 7000** of the sealed-in source IP (not the probe's
source port) -- bind 0.0.0.0:7000 before probing.

Modes:
  listen [seconds]           passive capture (nothing sent; ~1 frame/75s cadence)
  probe [--ip 192.168.77.1] [--broadcast 192.168.77.255] [--wait 8]
                             seal + send a fresh probe, print/reply-unseal replies
  unseal <hexframe> [<hexframe> ...]
                             offline unseal of saved frames
Read-only by construction: this sends only the discovery probe itself, never
any other traffic, and writes nothing to the device.
"""
import hashlib
import socket
import struct
import sys
import time

HEAD = bytes.fromhex("00006699")
TAIL = bytes.fromhex("00009966")
DISC = hashlib.md5(b"yGAdlopoPVldABfn").digest()


def frame(typ, data):
    hdr = HEAD + b"\x00" * 6 + struct.pack(">I", typ) + struct.pack(">I", len(data))
    return hdr + data + TAIL


def seal(typ, plaintext):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = (struct.pack(">Q", int(time.time() * 1000)) + b"\x00" * 12)[:12]
    hdr_wo_len = None  # length known after nonce+tag sizes
    data_len = 12 + len(plaintext) + 16
    hdr = HEAD + b"\x00" * 6 + struct.pack(">I", typ) + struct.pack(">I", data_len)
    ct = AESGCM(DISC).encrypt(nonce, plaintext, hdr[4:18])
    return hdr + nonce + ct + TAIL


def unseal(fr):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if fr[:4] != HEAD or len(fr) < 18:
        raise ValueError("bad frame header")
    typ = struct.unpack_from(">I", fr, 10)[0]
    ln = struct.unpack_from(">I", fr, 14)[0]
    data = fr[18:18 + ln]
    if fr[18 + ln:22 + ln] != TAIL:
        raise ValueError("bad frame tail")
    pt = AESGCM(DISC).decrypt(data[:12], data[12:], fr[4:18])
    if pt[:4] == b"\x00\x00\x00\x00":
        pt = pt[4:]
    return typ, pt.decode("utf-8")


def dump(fr, addr=""):
    try:
        typ, text = unseal(fr)
        print("  %s type=0x%02X len=%d -> %s" % (addr, typ, len(fr), text))
    except Exception as e:
        print("  %s type=? len=%d unseal failed: %r" % (addr, len(fr), e))


def mode_listen(seconds):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 7000))
    s.settimeout(1.0)
    print("listening 0.0.0.0:7000 for %ds (passive, nothing sent)" % seconds)
    t0 = time.time()
    n = 0
    while time.time() - t0 < seconds:
        try:
            d, addr = s.recvfrom(4096)
        except socket.timeout:
            continue
        n += 1
        dump(d, "%s:%d" % addr)
    print("done, %d frames" % n)


def probe(ip, bcast, wait, bind=("0.0.0.0", 7000)):
    """Send a fresh sealed type-0x25 probe and collect identity replies.

    Returns a list of dicts: {addr, type, text, json}. The asker's reply IP is
    inside the seal, so a replayed probe answers whoever's IP it carries; this
    always seals a fresh probe for `ip`. No other traffic is sent. SAFE-class.
    """
    body = ('{"from":"app","ip":"%s"}' % ip).encode()
    fr = seal(0x25, body)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.bind(bind)
    s.settimeout(2.0)
    out = []
    try:
        s.sendto(fr, (bcast, 7000))
        t0 = time.time()
        while time.time() - t0 < wait:
            try:
                d, addr = s.recvfrom(4096)
            except socket.timeout:
                continue
            if d[:4] != HEAD or len(d) < 18:
                continue
            if struct.unpack_from(">I", d, 10)[0] == 0x25:
                continue          # other askers' probes
            try:
                typ, text = unseal(d)
            except Exception:
                continue
            rec = {"addr": "%s:%d" % addr, "type": typ, "text": text}
            try:
                import json as _json
                rec["json"] = _json.loads(text)
            except Exception:
                rec["json"] = None
            out.append(rec)
    finally:
        s.close()
    return out


def mode_probe(ip, bcast, wait):
    print("sealed probe for ip=%s, bound 0.0.0.0:7000" % ip)
    replies = probe(ip, bcast, wait)
    for r in replies:
        print("  REPLY from %s type=0x%02X -> %s" % (r["addr"], r["type"], r["text"]))
    print("done, %d replies" % len(replies))
    return 0 if replies else 2


def mode_unseal(hexes):
    rc = 0
    for h in hexes:
        try:
            dump(bytes.fromhex(h))
        except Exception as e:
            print("bad frame: %r" % e)
            rc = 1
    return rc


def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    if args[0] == "listen":
        mode_listen(int(args[1]) if len(args) > 1 else 120)
        return 0
    if args[0] == "probe":
        ip, bcast, wait = "192.168.77.1", "192.168.77.255", 8.0
        rest = args[1:]
        i = 0
        while i < len(rest):
            if rest[i] == "--ip":
                i += 1; ip = rest[i]
            elif rest[i] == "--broadcast":
                i += 1; bcast = rest[i]
            elif rest[i] == "--wait":
                i += 1; wait = float(rest[i])
            i += 1
        return mode_probe(ip, bcast, wait)
    if args[0] == "unseal":
        return mode_unseal(args[1:])
    print("unknown mode %r" % args[0])
    return 2


if __name__ == "__main__":
    sys.exit(main())
