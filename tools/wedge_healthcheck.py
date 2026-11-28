#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""wedge_healthcheck.py -- classify a Series 4 plug as HEALTHY / WEDGED / BRICKED.

Built because the flashing tool's real gap is not the transfer (it is
proven) but the *verification*: a byte-identical apply has returned a unit
that answered ping and completed MQTT keepalives while every service that
actually matters was dead. See LAN-OTA-PROTOCOL.md's "Two failure modes"
section for what distinguishes this from a healthy or a bricked unit.

Ping is not a health check. This tool checks the specific surface set whose
absence defines the wedge, and it separates the three failure classes so a
post-flash run cannot be reported as a success when it is not:

  HEALTHY  the unit is running and serving a management surface. For stock
           firmware that is TCP :6668 accepting plus UDP-7000 answering; for
           OpenBeken it is HTTP :80 serving its own /api/info. Both are
           checked, because a unit that has been flashed to OpenBeken -- the
           normal end state of this project's own OTA chain -- binds :80 only
           and would otherwise be misread as WEDGED.
  WEDGED   the host is up (ARP and ICMP work) but no management surface is
           bound on any known port. The radio and IP stack are fine; the
           application never finished its online transition. Recoverable only
           by UART (every remote recovery route has been tried and failed).
  BRICKED  no ARP entry and no ICMP. The unit is not on the network at all --
           the transfer likely did not complete, or the bootloader rejected the
           image. UART required.
  UNKNOWN  none of the above cleanly, e.g. the host is up but :6668 times out
           rather than resetting. Reported honestly rather than rounded to a
           verdict.

Read-only by construction: it opens TCP connections, issues one HTTP GET of
/api/info, and sends one discovery probe of the documented safe class. It
writes nothing to the device.

Windows Firewall note: the UDP-7000 discovery reply is
*inbound*, and Windows drops it by default. Without a rule the tool reports
"udp/7000 silent", which reads exactly like a wedged unit -- a false diagnosis
of the same class the same-subnet check exists to prevent. `--firewall` offers
to add a scoped inbound rule (program + port + local subnet + non-public
profiles) for the duration of the run and removes it afterwards, via a
`tools/winfw.py` helper that isn't included in this repo -- without it,
`--firewall` logs that it's skipping the rule and the health check still
runs, just without the firewall workaround. Off by default so a bare rig
copy of this file still runs with no dependencies.

USAGE
-----
    python tools/wedge_healthcheck.py --host 192.168.77.107
    python tools/wedge_healthcheck.py --host 192.168.20.48 --wait 6
    python tools/wedge_healthcheck.py --host X --json      # for a wrapper to parse
    python tools/wedge_healthcheck.py --host X --firewall  # add/remove a scoped rule

Exit status: 0 HEALTHY, 2 WEDGED, 3 BRICKED, 4 UNKNOWN. A flashing wrapper
should treat anything but 0 as a failed run.
"""
import argparse
import contextlib
import hashlib
import http.client
import ipaddress
import json
import os
import re
import socket
import struct
import subprocess
import sys
import time

DEFAULT_PORT = 6668          # the LAN control plane (stock Tuya)
DISCOVERY_PORT = 7000        # UDP-7000 discovery (stock Tuya)
DISCOVERY_HEAD = bytes.fromhex("00006699")
DISCOVERY_TAIL = bytes.fromhex("00009966")
DISCOVERY_KEY = hashlib.md5(b"yGAdlopoPVldABfn").digest()  # public constant -- see LAN-OTA-PROTOCOL.md's Discovery section
HTTP_PORT = 80               # OpenBeken's management surface
EXIT = {"HEALTHY": 0, "WEDGED": 2, "BRICKED": 3, "UNKNOWN": 4}


def ping(host, timeout_ms=1200):
    """True if the host answers ICMP. Windows and POSIX flag names differ."""
    if os.name == "nt":
        cmd = ["ping", "-n", "2", "-w", str(timeout_ms), host]
    else:
        cmd = ["ping", "-c", "2", "-W", str(max(1, timeout_ms // 1000)), host]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return False
    return r.returncode == 0


def arp(host):
    """True if the host has a resolved L2 address in the local cache."""
    if os.name == "nt":
        cmd = ["arp", "-a", host]
    else:
        cmd = ["ip", "neigh", "show", host]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return False
    if os.name == "nt":
        # a resolved entry has the host IP and a MAC on the same line
        return any(host in ln and ("-" in ln or ":" in ln)
                   and "ff-ff-ff" not in ln.lower()
                   for ln in out.splitlines())
    return "lladdr" in out


def on_link(host):
    """True if `host` shares a subnet with one of this machine's interfaces.

    This matters because "cannot reach it" is not the same as "it is bricked".
    A host on a network this observer cannot route to looks identical to a dead
    unit from here, and reporting BRICKED for it would be a false diagnosis --
    measured: probing Unit 4 (192.168.20.48) from the rig's 192.168.77.1
    interface produced exactly that false positive before this check existed.
    """
    try:
        import ipaddress
        target = ipaddress.ip_address(host)
    except ValueError:
        return False
    for ip, netmask in local_ipv4():
        try:
            net = ipaddress.ip_network("%s/%s" % (ip, netmask), strict=False)
            if target in net:
                return True
        except ValueError:
            continue
    return False


def local_ipv4():
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
                    if ip:
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
            bits = int(m.group(2))
            mask = str(__import__("ipaddress").ip_address(
                (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF))
            out.append((m.group(1), mask))
    return out


def tcp(host, port, timeout=2.5):
    """'open' | 'reset' | 'unreachable' | 'timeout'. The distinction is the diagnosis."""
    s = socket.socket()
    s.settimeout(timeout)
    try:
        rc = s.connect_ex((host, port))
    except OSError as e:
        s.close()
        return "timeout", str(e)
    finally:
        pass
    s.close()
    if rc == 0:
        return "open", None
    # ECONNREFUSED: something answered with RST -> no listener bound.
    # WSAECONNREFUSED on Windows is 10061; ECONNREFUSED is 111.
    if rc in (10061, 111):
        return "reset", "connection refused (RST) -- no listener bound"
    # ENETUNREACH / EHOSTUNREACH / WSAENETUNREACH / WSAEHOSTUNREACH:
    # no route at all -- says nothing about the target's state.
    if rc in (101, 113, 10051, 10065):
        return "unreachable", "no route to host (error %d)" % rc
    return "timeout", "error %d" % rc


def _local_ip_for(host):
    """Best local IP to put in the discovery body -- it's the reply target the
    device seals its answer to (discover_lan.py's probe() docstring: "the
    asker's reply IP is inside the seal"), NOT `host` itself. Prefers the
    interface on-link with `host`; falls back to the first local IPv4 found."""
    try:
        import ipaddress
        target = ipaddress.ip_address(host)
    except ValueError:
        target = None
    candidates = local_ipv4()
    if target is not None:
        for ip, netmask in candidates:
            try:
                if target in ipaddress.ip_network("%s/%s" % (ip, netmask), strict=False):
                    return ip
            except ValueError:
                continue
    return candidates[0][0] if candidates else None


def discovery(host, wait):
    """Send the real sealed UDP-7000 discovery probe; True only for a reply
    that actually decrypts as a valid identity frame from `host`.

    Read-only by construction: one probe, no repeated traffic, no state
    change on the device. An earlier version of this check sent just the
    bare 4-byte magic header with no body -- not a real frame, so a healthy
    stock unit had no reason to ever answer it, and this tool reported
    UNKNOWN on a unit tools/discover_lan.py's probe() proved was healthy and
    activated. Fixed by inlining that same proven sealed type-0x25
    construction here, so this file stays standalone-copyable -- it's meant
    to be run as a lone file, without the rest of this repo alongside it.
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        return False
    my_ip = _local_ip_for(host)
    if not my_ip:
        return False          # no local IP to seal in as the reply target
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.bind(("0.0.0.0", DISCOVERY_PORT))
        s.settimeout(wait)

        body = ('{"from":"app","ip":"%s"}' % my_ip).encode()
        nonce = (struct.pack(">Q", int(time.time() * 1000)) + b"\x00" * 12)[:12]
        data_len = 12 + len(body) + 16
        hdr = (DISCOVERY_HEAD + b"\x00" * 6 + struct.pack(">I", 0x25)
               + struct.pack(">I", data_len))
        ct = AESGCM(DISCOVERY_KEY).encrypt(nonce, body, hdr[4:18])
        s.sendto(hdr + nonce + ct + DISCOVERY_TAIL, (host, DISCOVERY_PORT))

        t0 = time.time()
        while time.time() - t0 < wait:
            try:
                data, addr = s.recvfrom(2048)
            except socket.timeout:
                break
            if addr[0] != host or data[:4] != DISCOVERY_HEAD or len(data) < 18:
                continue
            if struct.unpack_from(">I", data, 10)[0] != 0x13:
                continue  # not an identity reply (e.g. another asker's probe)
            ln = struct.unpack_from(">I", data, 14)[0]
            payload = data[18:18 + ln]
            if data[18 + ln:22 + ln] != DISCOVERY_TAIL:
                continue
            try:
                AESGCM(DISCOVERY_KEY).decrypt(payload[:12], payload[12:], data[4:18])
            except Exception:
                continue          # didn't actually decrypt -- not a real reply
            return True
        return False
    except OSError:
        return False
    finally:
        if s is not None:
            s.close()


def openbeken_info(host, timeout=3.0):
    """Return the /api/info dict if this is an OpenBeken unit, else None.

    OpenBeken binds only :80 -- it does not serve :6668 or answer UDP-7000, so
    the stock-firmware HEALTHY predicate can never match a unit this project has
    successfully flashed. Measured: 192.168.20.48 (Unit 4) answers this while
    reporting tcp_6668=reset, which the pre-OpenBeken classifier scored WEDGED.
    """
    conn = None
    try:
        conn = http.client.HTTPConnection(host, HTTP_PORT, timeout=timeout)
        conn.request("GET", "/api/info")
        resp = conn.getresponse()
        if resp.status != 200:
            return None
        body = resp.read(4096)
    except (OSError, http.client.HTTPException):
        return None
    finally:
        if conn is not None:
            try:
                conn.close()
            except OSError:
                pass
    try:
        info = json.loads(body.decode("utf-8", "replace"))
    except ValueError:
        return None
    # Require the fields OpenBeken actually emits, so a random :80 web server
    # on the LAN is not mistaken for a flashed unit.
    if isinstance(info, dict) and "chipset" in info and "build" in info:
        return info
    return None


def classify(host, wait):
    res = {"host": host, "when": time.strftime("%Y-%m-%dT%H:%M:%S")}

    res["same_subnet"] = on_link(host)
    res["icmp"] = ping(host)
    res["arp"] = arp(host)
    if not res["arp"] and res["icmp"]:
        res["arp"] = True          # ICMP proves L3 reachability regardless

    res["tcp_6668"], res["tcp_6668_detail"] = tcp(host, DEFAULT_PORT)

    # A unit flashed to OpenBeken serves :80 and nothing else. Probe that before
    # any verdict that blames the device, or every successful OpenBeken flash is
    # reported as a wedge.
    res["openbeken"] = openbeken_info(host)
    if res["openbeken"]:
        res["tcp_80"] = "open"
        res["discovery"] = False
        res["verdict"] = "HEALTHY"
        res["note"] = ("running OpenBeken %s -- this is the expected end state "
                       "of a successful flash, not a wedge. :6668 and UDP-7000 "
                       "are stock-firmware surfaces and are absent by design."
                       % res["openbeken"].get("build", "(unknown build)"))
        return res
    # :80 accepting but not OpenBeken is not a Tuya plug we can classify.
    res["tcp_80"] = tcp(host, HTTP_PORT)[0]

    # A host we cannot route to looks identical to a dead one from here. Check
    # that BEFORE any verdict that blames the device.
    unreachable = (not res["same_subnet"] and not res["icmp"]
                   and not res["arp"]
                   and res["tcp_6668"] in ("unreachable", "timeout"))

    if res["tcp_6668"] == "open":
        res["discovery"] = discovery(host, max(2.0, wait))
        verdict = "HEALTHY" if res["discovery"] else "UNKNOWN"
        if not res["discovery"]:
            res["note"] = ("LAN control plane is bound but discovery did not "
                           "answer; a unit can be healthy without responding "
                           "to this exact probe, so do not call this a failure "
                           "on its own")
    elif unreachable:
        res["discovery"] = False
        verdict = "UNKNOWN"
        res["note"] = ("no route from this machine to %s (not on any local "
                       "subnet, and no ICMP) -- this is an observation "
                       "failure, NOT a device verdict. Re-run from the unit's "
                       "own LAN." % host)
    elif not res["icmp"] and not res["arp"]:
        res["discovery"] = False
        verdict = "BRICKED"
        res["note"] = "not on the network at all -- UART recovery required"
    elif res["tcp_6668"] == "reset":
        res["discovery"] = False
        if res["tcp_80"] == "open":
            # Something serves :80 but it is not OpenBeken and not Tuya. That is
            # not the wedge signature -- the wedge has no listener at all.
            verdict = "UNKNOWN"
            res["note"] = ("host is up and :80 accepts, but it does not serve "
                           "OpenBeken's /api/info and :6668 is reset. Not the "
                           "wedge signature (that unit binds nothing). Either a "
                           "different device at this address, or an OpenBeken "
                           "build too old for /api/info -- check the address "
                           "before drawing a conclusion.")
        else:
            verdict = "WEDGED"
            res["note"] = ("host is up but no management surface is bound -- "
                           ":80 does not serve OpenBeken and :6668 is reset. "
                           "This is the post-apply service-start failure "
                           "(see LAN-OTA-PROTOCOL.md). UART only.")
    else:
        res["discovery"] = False
        verdict = "UNKNOWN"
        res["note"] = ("host answers but :6668 timed out instead of resetting; "
                       "could be a firewall, a NAT hop, or a half-open stack. "
                       "Not enough to call either way.")

    res["verdict"] = verdict
    return res


def _firewall_rule():
    """Context manager for the scoped UDP-7000 inbound rule, or a no-op.

    Imported lazily and tolerated missing: this file is deliberately
    standalone-copyable (it is run as a lone file on bare rigs), so a copy
    without tools/winfw.py beside it must still work.
    """
    try:
        import winfw
    except ImportError:
        print("  firewall: tools/winfw.py not importable -- skipping the rule",
              file=sys.stderr)
        return contextlib.nullcontext()
    return winfw.offer("TuyaBK7238-udp7000", "UDP", DISCOVERY_PORT)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", required=True, help="unit IP on the LAN")
    ap.add_argument("--wait", type=float, default=4.0,
                    help="discovery reply wait in seconds")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--firewall", action="store_true",
                    help="offer to add a scoped Windows Firewall inbound rule "
                         "for UDP-7000 (removed afterwards). Without it a "
                         "dropped discovery reply reads as 'udp/7000 silent'")
    a = ap.parse_args()

    if a.firewall:
        with _firewall_rule():
            res = classify(a.host, a.wait)
    else:
        res = classify(a.host, a.wait)

    if a.json:
        print(json.dumps(res, indent=2, sort_keys=True))
    else:
        print("host      %s" % res["host"])
        print("when      %s" % res["when"])
        print("icmp      %s" % ("yes" if res["icmp"] else "NO"))
        print("arp       %s" % ("resolved" if res["arp"] else "none"))
        print("subnet    %s" % ("same as this machine"
                                if res["same_subnet"] else
                                "no local interface on that subnet"
                                + (" (reached via a route anyway)"
                                   if res["icmp"] else "")))
        print("tcp/6668  %s%s" % (res["tcp_6668"],
                                  " (%s)" % res["tcp_6668_detail"]
                                  if res["tcp_6668_detail"] else ""))
        print("tcp/80    %s" % ("open" if res.get("tcp_80") == "open" else
                                ("no listener" if res.get("tcp_80") == "reset"
                                 else res.get("tcp_80", "?"))))
        print("udp/7000  %s" % ("answered" if res["discovery"] else "silent"))
        print("")
        print("VERDICT   %s" % res["verdict"])
        if res.get("note"):
            print("          %s" % res["note"])
        print("")
        if res["verdict"] == "HEALTHY" and res.get("openbeken"):
            info = res["openbeken"]
            print("OpenBeken is up: chipset %s, build %s, shortName %s."
                  % (info.get("chipset", "?"), info.get("build", "?"),
                     info.get("shortName", "?")))
            print("Safe to configure (pins, metering).")
        elif res["verdict"] == "HEALTHY":
            print("The LAN plane is up. Safe to configure (pins, metering).")
        elif res["verdict"] == "WEDGED":
            print("This is the known wedge failure mode, not a successful flash.")
            print("Do NOT power-cycle expecting recovery, and do NOT unbind it:")
            print("every remote recovery route has been tried and failed.")
        elif res["verdict"] == "BRICKED":
            print("Not on the network. Check the transfer completed, then UART.")
        else:
            print("Inconclusive from this vantage point -- do not treat as a")
            print("device failure. Re-run on the unit's own LAN.")
    return EXIT.get(res["verdict"], 4)


if __name__ == "__main__":
    sys.exit(main())
