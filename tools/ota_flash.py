#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ota_flash.py -- one-command LAN OTA packaging for the PC191HA Series 4.

Wraps tools/owner_reflash.py's live-proven LAN chain in the checks and the
per-target identity fix that a repeatable run needs:

  * resolves the target MAC (ARP) and patches the replacement app's hardcoded
    default MAC, so the flashed unit does not come up as OpenBK7238_8C428848;
  * recomputes fileHmac from secKey, or accepts an explicit --filehmac;
  * refuses a container whose xz parameters are not the device-proven
    CRC32 / dict_size 4096 (see LAN-OTA-PROTOCOL.md's container format);
  * prints the full plan -- image digest, identity change, transfer size,
    failure cost -- and requires --yes before touching a device;
  * holds the session open through the in-session apply.

The only input that still comes from outside the LAN path is secKey. Tuya's
OpenAPI exposes local_key but not secKey (see ARCHITECTURE.md's phone-free
key grabber section), so it must be supplied from the app's device-list
cache or the activation reply.

USAGE
-----
  # plan only, no device contact, no keys needed
  "C:\\Program Files\\Python312\\python.exe" tools/ota_flash.py \
      --host 192.168.20.48 --mac auto \
      --image served-images/RCZL-r34d-openbeken.bin --dry-run

  # live (localKey from the Tuya OpenAPI; secKey from the environment)
  $env:TUYA_ACCESS_ID = '...'
  $env:TUYA_ACCESS_SECRET = '...'
  $env:OBK_SECKEY = '...'
  "C:\\Program Files\\Python312\\python.exe" tools/ota_flash.py \
      --host 192.168.20.48 --device-id bf... --image served-images/RCZL-r34d-openbeken.bin --yes

  # live with keys already in hand
  ... tools/ota_flash.py --host 192.168.20.48 --localkey '<lk>' \
      --sec-key '<sk>' --image ... --yes

The unit must be activated and on the LAN (this is the Tier-2/Tier-1 activated
path, not the AP-only path).

TWO FAILURE MODES, and they are different (see LAN-OTA-PROTOCOL.md's "Two
failure modes" section):
  * a TRUNCATED TRANSFER bricks the unit -- no network, needs UART;
  * a COMPLETED APPLY can still WEDGE it -- the unit answers ping and keeps its
    MQTT keepalives while its DP engine, button and LAN plane never start.
    This has happened with a byte-identical image. Neither mode is remotely
    recoverable.

Because of the second mode, this tool never reports success from the transfer
alone. `--verify` (default on for a live run) re-probes the unit afterwards with
tools/wedge_healthcheck.py and exits nonzero unless a management surface is
actually up. If verification says WEDGED, the flash "succeeded" and the unit is
still unusable -- say so rather than reporting a win.

Note on what "up" means after a *replacement* flash: the healthcheck accepts
either the stock surface set (TCP :6668 + UDP-7000) or OpenBeken's HTTP :80
serving `/api/info`. It has to, because OpenBeken binds :80 only -- checking the
stock ports alone would score every successful OpenBeken flash as WEDGED.
"""

import argparse
import hashlib
import lzma
import os
import re
import socket
import struct
import subprocess
import sys
import tempfile
import time
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import owner_reflash as sh                                    # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_IMAGE = os.path.join(ROOT, "served-images", "RCZL-r34d-openbeken.bin")

# The OpenBeken 1.18.318 release app carries this MAC as its compiled-in default
# (app +0xACFAC). Two units flashed unchanged both come up as
# OpenBK7238_8C428848; OpenBeken copies it into its config on first boot.
RELEASE_DEFAULT_MAC = bytes.fromhex("c8478c428848")

MAGIC_WORD0 = 0x004D4D4D
BIN_TYPE_RCZL = 0x4C5A4352
BUF_SIZE = 0x10000
BIN_START_ADDR = 0x40


def die(msg):
    sys.stdout.flush()
    print("ERROR: %s" % msg, file=sys.stderr)
    raise SystemExit(1)


def parse_mac(text):
    h = re.sub(r"[^0-9a-fA-F]", "", text)
    if len(h) != 12:
        raise ValueError("expected 6 hex bytes, got %r" % text)
    mac = bytes.fromhex(h)
    if mac == b"\x00" * 6:
        raise ValueError("all-zero MAC")
    if mac[0] & 1:
        raise ValueError("multicast/broadcast MAC")
    return mac


def arp_mac(host):
    """Return the MAC the target currently uses on the LAN, from the ARP cache."""
    for attempt in range(2):
        try:
            out = subprocess.run(["arp", "-a", host], capture_output=True,
                                 text=True, timeout=10).stdout
        except (OSError, subprocess.SubprocessError):
            out = ""
        for line in out.splitlines():
            if host not in line:
                continue
            m = re.search(r"\b([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})\b", line)
            if m:
                return parse_mac(m.group(1))
        if attempt == 0:
            subprocess.run(["ping", "-n", "1", "-w", "1000", host],
                           capture_output=True)
    raise RuntimeError("no ARP entry for %s -- is the unit on the LAN? "
                       "or pass --mac explicitly" % host)


# ---------------------------------------------------------------------------
# finding the unit on the LAN
# ---------------------------------------------------------------------------

def _local_ip_toward(host):
    """The local IPv4 address this machine would use to reach `host`."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((host, 6668))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def _broadcast_for(local_ip):
    """The /24 broadcast address for a local IPv4 address, or None."""
    if not local_ip:
        return None
    parts = local_ip.split(".")
    if len(parts) != 4:
        return None
    return ".".join(parts[:3] + ["255"])


def discover(dev_id=None, uuid=None, wait=6.0, broadcast=None):
    """Find the unit on the LAN by asking it who it is, not by guessing an IP.

    Sends the documented safe UDP-7000 sealed type-0x25 probe (the same one
    tools/discover_lan.py and wedge_healthcheck.py use) and matches the reply
    against `dev_id` (the identity frame's `gwId`) or `uuid`. Returns
    (ip, identity_dict) or (None, None).

    This is what makes the phone-free activation chain's end state usable
    without a hand-supplied address: the unit has just been activated, so its
    devId is known from the account, and it answers discovery on its own.
    """
    try:
        import discover_lan as dl
    except ImportError:
        return None, None
    if not dev_id and not uuid:
        return None, None

    # Probe the broadcast address of every local subnet, plus a unicast probe
    # to each local address's own /24 broadcast. A unit that has just joined
    # answers whichever reaches it.
    targets = []
    if broadcast:
        targets.append(broadcast)
    else:
        seen = set()
        for ip, _mask in _local_ipv4():
            b = _broadcast_for(ip)
            if b and b not in seen:
                seen.add(b)
                targets.append(b)
    if not targets:
        return None, None

    for bcast in targets:
        my_ip = _local_ip_toward(bcast)
        if not my_ip:
            continue
        try:
            replies = dl.probe(my_ip, bcast, wait, bind=("0.0.0.0", 7000))
        except OSError:
            continue
        for r in replies:
            ident = r.get("json")
            if not ident:
                continue
            if dev_id and ident.get("gwId") == dev_id:
                return r["addr"].split(":")[0], ident
            if uuid and ident.get("uuid") == uuid:
                return r["addr"].split(":")[0], ident
    return None, None


def _local_ipv4():
    """(ip, netmask) for each local IPv4 interface, best-effort and portable."""
    out = []
    if os.name == "nt":
        try:
            txt = subprocess.run(["ipconfig"], capture_output=True, text=True,
                                 timeout=10).stdout
        except (OSError, subprocess.SubprocessError):
            return out
        ip = mask = None
        for line in txt.splitlines():
            low = line.lower()
            if "ipv4 address" in low or "ipv4-adresse" in low:
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                if m:
                    ip = m.group(1)
            elif "subnet mask" in low:
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                if m:
                    mask = m.group(1)
                    if ip and mask:
                        out.append((ip, mask))
                    ip = mask = None
        return out
    try:
        txt = subprocess.run(["ip", "-4", "-o", "addr", "show"],
                             capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return out
    for line in txt.splitlines():
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", line)
        if m:
            out.append((m.group(1), m.group(2)))
    return out


def patch_identity(blob, mac, enabled=True):
    """Return (new_blob, description). Only the 6-byte default MAC changes."""
    if not enabled:
        return blob, "identity patch disabled (--no-mac-patch)"
    app = lzma.decompress(blob[64:])
    n = app.count(RELEASE_DEFAULT_MAC)
    if n >= 1:
        import build_m3_openbeken_image as bm
        patched = app.replace(RELEASE_DEFAULT_MAC, mac)
        new_blob = bm.build_container(patched)
        if lzma.decompress(new_blob[64:]) != patched:
            die("identity patch failed its own round-trip")
        return (new_blob,
                "default MAC %s -> %s (%d occurrence%s)"
                % (RELEASE_DEFAULT_MAC.hex(":"), mac.hex(":"), n,
                   "" if n == 1 else "s"))
    if mac in app:
        return blob, "already patched to %s" % mac.hex(":")
    if b"OpenBK7238" in app:
        die("this OpenBeken build carries no known default MAC (%d occurrences); "
            "pass --no-mac-patch to flash it unchanged" % n)
    return blob, "no hardcoded MAC in this image; unchanged"


def preflight(blob):
    """Structural checks before anything is sent. Returns the decompressed app."""
    if len(blob) < 64 + 20:
        die("container is too short (%d bytes)" % len(blob))
    if struct.unpack_from("<I", blob, 0x00)[0] != MAGIC_WORD0:
        die("word0 is 0x%08x, expected 0x%08x" %
            (struct.unpack_from("<I", blob, 0x00)[0], MAGIC_WORD0))
    if struct.unpack_from("<I", blob, 0x04)[0] != BIN_TYPE_RCZL:
        die("bin_type is 0x%08x, expected RCZL" %
            struct.unpack_from("<I", blob, 0x04)[0])
    if struct.unpack_from("<I", blob, 0x1C)[0] != BIN_START_ADDR:
        die("bin_start_addr is 0x%x, expected 0x%x" %
            (struct.unpack_from("<I", blob, 0x1C)[0], BIN_START_ADDR))
    if struct.unpack_from("<I", blob, 0x2C)[0] != BUF_SIZE:
        die("buf_size is 0x%x, expected 0x%x" %
            (struct.unpack_from("<I", blob, 0x2C)[0], BUF_SIZE))

    problems = sh.warn_xz_params(blob)
    if problems:
        die("xz payload is not the device-proven encoding: %s"
            % "; ".join(problems))

    try:
        app = lzma.decompress(blob[64:])
    except lzma.LZMAError as e:
        die("payload does not decompress: %s" % e)

    dst_len = struct.unpack_from("<I", blob, 0x10)[0]
    src_crc = struct.unpack_from("<I", blob, 0x08)[0]
    dst_crc = struct.unpack_from("<I", blob, 0x0C)[0]
    if dst_len != len(app):
        die("dst_len %d != decompressed app %d" % (dst_len, len(app)))
    crc = zlib.crc32(app) & 0xFFFFFFFF
    if src_crc != crc or dst_crc != crc:
        die("src/dst crc32 0x%08x/0x%08x != app crc32 0x%08x"
            % (src_crc, dst_crc, crc))
    return app


def verify_outcome(res, target):
    """Translate a wedge_healthcheck result on the flashed IP into a flash
    verdict + process exit code, accounting for the config-AP migration.

    The probe runs against the IP we flashed over, but a fresh OpenBeken flash
    with no stored Wi-Fi reboots the unit onto its OWN config AP
    (OpenBK7238_<mac>) and leaves that LAN address entirely. So from here:

      HEALTHY  -- unit kept this address (had stored Wi-Fi / same net). Success.
      WEDGED   -- the one signature that blames the flash: the unit is still up
                  ON THIS IP (:6668 reset, :80 not OpenBeken) but started no
                  services. Real post-apply failure, UART. Non-zero.
      anything else (UNKNOWN / BRICKED) -- the unit is simply not answering on
                  this IP. For a fresh flash that is the EXPECTED outcome, not a
                  fault: it has moved to its config AP. A wedge, by contrast,
                  stays on this IP and resets :6668. Report success pending a
                  look from where the unit now is -- do NOT cry UART on it.
    """
    import wedge_healthcheck as whc
    print("VERDICT   %s" % res["verdict"])
    if res.get("note"):
        print("          %s" % res["note"])
    if res["verdict"] == "HEALTHY":
        print("Flash verified: the LAN plane is up. Configure pins and metering next.")
        return 0
    if res["verdict"] == "WEDGED":
        print("")
        print("The transfer completed but the unit WEDGED on %s." % target)
        print("Do not report this run as a success. Recovery is UART "
              "(see LAN-OTA-PROTOCOL.md).")
        return whc.EXIT["WEDGED"]
    print("")
    print("Transfer complete. %s stopped answering -- expected for a fresh flash: the unit" % target)
    print("rebooted onto its own OpenBK7238_* config AP (not a wedge; a wedge holds this IP, :6668 reset).")
    print("Confirm on the AP (http://192.168.4.1/api/info), or wedge_healthcheck.py --host <new ip>.")
    return 0


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default=None,
                    help="target IP on the LAN. Omit to find the unit by "
                         "discovery (needs --device-id or --uuid)")
    ap.add_argument("--uuid", default=None,
                    help="the unit's uuid, for discovery when --host is omitted")
    ap.add_argument("--discover-wait", type=float, default=6.0,
                    help="how long to wait for a discovery reply (default 6s)")
    ap.add_argument("--broadcast", default=None,
                    help="broadcast address to probe for discovery "
                         "(default: each local interface's /24 broadcast)")
    ap.add_argument("--port", type=int, default=sh.DEFAULT_PORT)
    ap.add_argument("--image", default=DEFAULT_IMAGE,
                    help="RCZL container (default: the live-proven r34d image)")
    ap.add_argument("--mac", default="auto",
                    help="stock MAC to write into the image ('auto' = ARP lookup)")
    ap.add_argument("--no-mac-patch", action="store_true",
                    help="leave the image's default MAC in place (unsafe: units collide)")
    ap.add_argument("--localkey", default=None, help="local_key (skip the OpenAPI lookup)")
    ap.add_argument("--device-id", default=None, help="device id for the OpenAPI lookup")
    ap.add_argument("--region", default=None,
                    help="Tuya region (eu/us/cn/in); default tries all")
    ap.add_argument("--sec-key", default=None,
                    help="secKey (or set OBK_SECKEY); required unless --filehmac")
    ap.add_argument("--sec-key-file", default=None, help="read secKey from a file")
    ap.add_argument("--filehmac", default=None, metavar="HEX64",
                    help="precomputed fileHmac; skips the secKey requirement")
    ap.add_argument("--version", default="1.0.0")
    ap.add_argument("--channel", default="0")
    ap.add_argument("--mode", choices=["gcm", "cbc"], default="gcm")
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--wait", type=float, default=300.0,
                    help="whole-transfer time budget in seconds")
    ap.add_argument("--max-chunks", type=int, default=None,
                    help="probe mode: stop after N chunks (not a full flash)")
    ap.add_argument("--dry-run", action="store_true", help="print the plan, send nothing")
    ap.add_argument("--yes", action="store_true",
                    help="required for a live run; confirms the failure cost")
    ap.add_argument("--verify", dest="verify", action="store_true", default=True,
                    help="after a live run, probe the unit and require the LAN "
                         "plane to be up (default)")
    ap.add_argument("--no-verify", dest="verify", action="store_false",
                    help="skip the post-flash health check (not recommended: the "
                         "transfer completing does not mean the unit works)")
    ap.add_argument("--verify-host", default=None,
                    help="IP to health-check after the flash (default: --host)")
    ap.add_argument("--verify-wait", type=float, default=25.0,
                    help="how long to wait after the run before health-checking")
    ap.add_argument("--firewall", action="store_true",
                    help="offer to add a scoped Windows Firewall inbound rule "
                         "for the post-flash UDP-7000 health check (removed "
                         "afterwards). Without it a dropped discovery reply "
                         "reads as 'udp/7000 silent' and the unit looks WEDGED")
    a = ap.parse_args()

    if not a.host:
        # The phone-free activation chain ends with a
        # unit that has just joined the LAN, and its devId is known from the
        # account -- so ask it who it is instead of making the operator find
        # the address by hand.
        if not (a.device_id or a.uuid):
            die("pass --host, or --device-id/--uuid so the unit can be found "
                "by discovery")
        print("looking for the unit by UDP-7000 discovery "
              "(devId=%s uuid=%s)..." % (a.device_id or "-", a.uuid or "-"))
        ip, ident = discover(dev_id=a.device_id, uuid=a.uuid,
                             wait=a.discover_wait, broadcast=a.broadcast)
        if not ip:
            die("no discovery reply matched -- is the unit on this LAN? "
                "Pass --host <ip> if you know the address.")
        print("  found %s: gwId=%s uuid=%s productKey=%s"
              % (ip, ident.get("gwId"), ident.get("uuid"),
                 ident.get("productKey")))
        a.host = ip

    if not os.path.isfile(a.image):
        die("image not found: %s" % a.image)
    raw = open(a.image, "rb").read()
    sha = hashlib.sha256(raw).hexdigest()
    preflight(raw)

    try:
        mac = None
        if not a.no_mac_patch:
            if a.mac == "auto":
                try:
                    mac = arp_mac(a.host)
                except RuntimeError:
                    if not a.dry_run:
                        raise
            else:
                mac = parse_mac(a.mac)
    except (ValueError, RuntimeError) as e:
        die(str(e))

    if a.no_mac_patch:
        blob, identity = patch_identity(raw, b"", enabled=False)
    elif mac is None:
        blob, identity = raw, "MAC unresolved (dry run)"
    else:
        blob, identity = patch_identity(raw, mac)

    app = preflight(blob)
    blob_sha = hashlib.sha256(blob).hexdigest()

    if a.filehmac:
        fh = a.filehmac.lower()
        if not re.fullmatch(r"[0-9a-f]{64}", fh):
            die("--filehmac must be 64 hex characters")
        fh_source = "explicit"
    else:
        sec = a.sec_key or os.environ.get("OBK_SECKEY")
        if a.sec_key_file:
            sec = open(a.sec_key_file, encoding="utf-8").read().strip()
        if not sec:
            if a.dry_run:
                fh, fh_source = None, "would be computed from secKey"
            else:
                die("secKey required: pass --sec-key / --sec-key-file / set "
                    "OBK_SECKEY, or pass --filehmac")
        else:
            fh = sh.compute_file_hmac(blob, sec)
            fh_source = "computed from secKey"

    chunks = (len(blob) + 0x3FF) // 0x400
    print("")
    print("TARGET   %s:%d" % (a.host, a.port))
    print("IMAGE    %s" % a.image)
    print("         %d bytes container, %d bytes app, sha256 %s"
          % (len(blob), len(app), blob_sha))
    if blob_sha != sha:
        print("         (source sha256 %s)" % sha)
    print("IDENTITY %s" % identity)
    print("PAYLOAD  RCZL, app crc32 0x%08x, buf_size 0x10000, xz CRC32/4096"
          % (zlib.crc32(app) & 0xFFFFFFFF))
    print("HMAC     %s%s" % (fh or "<pending>", " (%s)" % fh_source if fh else ""))
    print("TRANSFER full container, ~%d chunk round-trips, budget %ss"
          % (chunks, a.wait))
    if a.max_chunks:
        print("PROBE    stops after %d chunks -- NOT a complete flash" % a.max_chunks)
    print("FAILURE  not remotely recoverable -- a truncated transfer bricks the unit, and even a")
    print("         completed apply can wedge it. Either way, recovery is UART -- have it ready.")
    print("VERIFY   %s" % ("post-flash health check on %s (+%.0fs)"
                           % (a.verify_host or a.host, a.verify_wait)
                           if a.verify and not a.max_chunks
                           else "DISABLED -- success will not be verified"))
    print("")

    if a.dry_run:
        print("dry run -- nothing sent")
        return 0
    if a.wait < 60:
        die("--wait below 60 s cannot finish a several-hundred-KB transfer; "
            "a truncated transfer bricks the unit")
    if not a.yes:
        print("refusing to start without --yes (this writes flash)")
        return 1

    if not a.localkey:
        if not a.device_id:
            die("pass --localkey, or --device-id to fetch local_key from the OpenAPI")
        try:
            a.localkey = sh.fetch_localkey(a.device_id, a.region)
        except RuntimeError as e:
            die(str(e))

    tmp = tempfile.NamedTemporaryFile(prefix="ota-flash-", suffix=".bin",
                                      delete=False)
    tmp.write(blob)
    tmp.close()
    rc = 1
    try:
        ns = argparse.Namespace(
            host=a.host, port=a.port, localkey=a.localkey, image=tmp.name,
            version=a.version, channel=a.channel, patch_magic=False,
            mode=a.mode, start_seq=1, serve=None, dry_run=False,
            timeout=a.timeout, wait=a.wait, max_chunks=a.max_chunks,
            filehmac=fh, auto_hmac=None if a.filehmac else sec)
        rc = sh.cmd_run(ns)
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass

    if rc != 0:
        print("")
        print("TRANSFER FAILED (rc=%s). Do NOT power-cycle and do NOT unbind:" % rc)
        print("a partial transfer is not a wedge, and a reboot cannot fix either.")
        print("Check the unit with tools/wedge_healthcheck.py before anything else.")
        return rc

    if not a.verify or a.max_chunks:
        return rc

    # A completed transfer is not a working unit. Probe it.
    import wedge_healthcheck as whc
    target = a.verify_host or a.host
    print("")
    print("--- verifying %s in %.0fs (a completed apply can still wedge) ---"
          % (target, a.verify_wait))
    time.sleep(a.verify_wait)
    if a.firewall:
        with whc._firewall_rule():
            res = whc.classify(target, wait=4.0)
    else:
        res = whc.classify(target, wait=4.0)
    return verify_outcome(res, target)


if __name__ == "__main__":
    sys.exit(main())
