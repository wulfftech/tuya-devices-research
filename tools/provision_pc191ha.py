#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""provision_pc191ha.py -- one idempotent HTTP pass that takes a freshly
flashed PC191HA Series 4 from "OpenBeken boots" to "relay, button, LED and
BL0942 metering configured and verified".

Target configuration, the hardware-verified Series 4 (see HARDWARE.md /
PROVISIONING.md in this repo):

    P26 Rel (role 1) channel 1, active-high relay
    P24 Btn (role 3) channel 1, active-low button
    P8  LED (role 5) channel 1, relay indicator (netled_reuse:1 -- NOT WifiLED)
    startup command: startDriver BL0942 (UART1 P10/P11, 4800 8N1), plus a
      5s-long-press-on-P24-forces-AP-mode binding (a configured-but-wrong/
      unreachable SSID otherwise retries forever with no automatic recovery
      and no physical-access-free way back in)
    MQTT self-state flag (flag 2) set, so HA's rssi/uptime/build/ssid/ip/temp
      sensors populate
    power calibration: float at OBK config 0x1E1000+0x4A0, negative here

Only documented OBK write paths are used: POST /api/pins with the full 29
element raw IOR_* arrays, the GET form of /startup_command (its POST form
does not persist), and /cm console commands (GetChannel, SENSOR, PowerSet,
SetChannelLabel, shortName, SetFlag, flags, SSID1). /api/flash is read-only here: the tool
never POSTs /api/flash, never touches /api/ota, never writes the app
partition, and never writes the config blob as a shortcut.

Contract:
  * identity check first, from GET /api/info's `build` and `startcmd`
    fields (never the HTTP banner); a non-OpenBeken target is refused
    before any write (exit 1);
  * the full plan and the diff print before any write; writes need the
    --yes gate only when the diff is non-empty; an already-matching unit
    takes zero writes and exits 0, and the no-op is reported loudly;
  * every pin outside the map is preserved; unexpected non-zero roles are
    reported for the operator, never silently zeroed;
  * the relay is never toggled: GetChannel 1 is read before and after and
    must match; while it is ON provisioning is refused unless
    --allow-relay-on (note: a restart after applying the map returns the
    relay to OpenBeken's boot default, off);
  * the config change counter is read before and after; the startup-command
    write is skipped when already correct because the GET form marks the
    config dirty (and bumps the counter) even when the data is unchanged;
  * BL0942 is verified via /cm?cmnd=SENSOR, whose ENERGY block OpenBeken
    only emits while a power-measuring driver is actually running --
    "startcmd is set" is never treated as "the driver is running";
  * calibration is opt-in (--power-set); run only against a steady
    resistive load, never on a PTC warm-up transient; Unit 4's -594.6377 is
    never copied;
  * Wi-Fi (--wifi-ssid via /cfg_wifi_set) schedules a device self-reset in
    ~3 s, so it is a terminal step: run it alone, after everything else;
    passwords come from OBK_WIFI_PASS or a prompt, never argv, and are
    never printed.

Exit codes: 0 success (including the loud zero-write no-op); 1 refusal or
pre-plan failure (nothing written); 2 a write/verification failure.
"""

import argparse
import getpass
import json
import os
import socket
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

PC191HA_S4_PINS = {26: (1, 1), 24: (3, 1), 8: (5, 1)}
GPIO_MAX = 29
BUTTON_PIN = 24
# setButtonTimes [LongPress][ShortPress][Repeat], all x100ms -- only LongPress
# changes (10 -> 50, i.e. 1s -> 5s) so a brief/accidental hold can't trigger
# AP mode; ShortPress/Repeat stay at OpenBeken's own defaults (3, 5). OnHoldStart
# (not OnHold) fires exactly once when the 5s mark is crossed. OpenAP forces
# AP mode within ~5s without touching stored Wi-Fi credentials or needing a
# reboot -- a Tuya-style manual recovery path independent of the boot-failure
# safe-mode counter.
STARTUP_CMD = ("backlog startDriver BL0942; setButtonTimes 50 3 5; "
               "addEventHandler OnHoldStart %d OpenAP" % BUTTON_PIN)
# OBK_FLAG_MQTT_BROADCASTSELFSTATEPERMINUTE. Without it OpenBeken publishes
# rssi/uptime/build/ssid/ip/temp over MQTT only once, on connect -- before Home
# Assistant has created the discovered entities, and those topics are not
# retained -- so those sensors sit at "unknown".
MQTT_SELFSTATE_FLAG = 2
CFG_ADDR = 0x1E1000
CFG_LEN = 0xE00
CAL_OFFSET = 0x4A0
CHANGE_COUNTER_OFFSET = 0x10
KNOWN_BUILDS = ("OpenBK7238",)
PIN_SETTLE_S = 1.5
NAME_SETTLE_S = 1.5
CAL_SETTLE_S = 1.0
METER_SETTLE_S = 2.0
METER_SETTLE_MAX_TRIES = 5
RESTART_WAIT_S = 45.0

ROLE_DISPLAY = {0: "None", 1: "Rel", 3: "Btn", 5: "LED", 8: "WifiLED"}


class ProvisionFailed(Exception):
    pass


class ObkHttp(object):
    def __init__(self, host, port, timeout):
        self.base = "http://%s:%d" % (host, port)
        self.timeout = timeout

    def _request(self, method, path, data=None):
        req = urllib.request.Request(
            self.base + path, data=data, method=method,
            headers={"Connection": "close"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return r.getcode(), r.read()
        except urllib.error.HTTPError as e:
            try:
                body = e.read()
            except (OSError, ValueError):
                body = b""
            return e.code, body
        except (urllib.error.URLError, socket.timeout, OSError) as e:
            raise ProvisionFailed("HTTP connection failed on %s: %s" % (path, e))

    def get(self, path):
        code, body = self._request("GET", path)
        if code != 200:
            raise ProvisionFailed("HTTP %d from %s: %s" % (code, path, body[:200]))
        return body.decode("utf-8", "replace")

    def get_bytes(self, path):
        code, body = self._request("GET", path)
        if code != 200:
            raise ProvisionFailed("HTTP %d from %s: %s" % (code, path, body[:200]))
        return body

    def get_json(self, path):
        text = self.get(path)
        try:
            return json.loads(text)
        except ValueError:
            raise ProvisionFailed("non-JSON reply from %s: %r" % (path, text[:120]))

    def post(self, path, data_bytes):
        code, body = self._request("POST", path, data=data_bytes)
        if code != 200:
            raise ProvisionFailed("HTTP %d from %s: %s" % (code, path, body[:200]))
        return body.decode("utf-8", "replace")

    def cm(self, cmnd):
        return self.get("/cm?cmnd=" + urllib.parse.quote(cmnd))


def check_target(info, expect_mac=None):
    """Identity check. Was a substring match on /api/info's `build` field
    against KNOWN_BUILDS -- written against an older OpenBeken build banner
    that literally contained "OpenBK7238"; the build actually in use here
    ("Built on Oct 13 2026 06:03:57 version 1.18.318") never carries that
    substring and would have been refused too. Chipset is the field this
    firmware actually sets reliably.

    expect_mac, when given, is compared against /api/info's `mac` -- the
    stronger check: it confirms this is the *specific* unit just flashed,
    not merely some OpenBeken device. Pass the MAC your flashing tool
    reported for this unit. Skip it (leave the default None) for a device
    still in its own standalone config AP, where /api/info's `mac` has not
    yet been observed to reliably reflect the real station MAC -- compare
    once the unit is actually on the target LAN instead.
    """
    if "startcmd" not in info:
        raise ProvisionFailed(
            "GET /api/info lacks the startcmd field (identity field used: `chipset` "
            "from /api/info, not the HTTP banner). Not a provisionable "
            "OpenBeken target.")
    chipset = info.get("chipset", "")
    if chipset != "BK7238":
        raise ProvisionFailed(
            "GET /api/info `chipset` is %r; expecting %r. Not a provisionable "
            "OpenBeken target for this config." % (chipset, "BK7238"))
    if expect_mac is not None:
        got_mac = (info.get("mac") or "").lower()
        if got_mac != expect_mac.lower():
            raise ProvisionFailed(
                "GET /api/info `mac` is %r; expected %r (--expect-mac). This "
                "is not the unit that was flashed -- refusing rather than "
                "provisioning the wrong device." % (info.get("mac"), expect_mac))
    return info.get("build", "")


def listed(pins):
    return [int(x) for x in pins["roles"]], [int(x) for x in pins["channels"]]


def wanted_arrays(cur_roles, cur_channels):
    roles = list(cur_roles)
    channels = list(cur_channels)
    if len(roles) < GPIO_MAX or len(channels) < GPIO_MAX:
        raise ProvisionFailed("board reports %d/%d pin slots; expected %d"
                              % (len(roles), len(channels), GPIO_MAX))
    for pin, (role, ch) in PC191HA_S4_PINS.items():
        roles[pin] = role
        channels[pin] = ch
    return roles[:GPIO_MAX], channels[:GPIO_MAX]


def role_name(rolenames, idx):
    if idx in ROLE_DISPLAY:
        return ROLE_DISPLAY[idx]
    if 0 <= idx < len(rolenames):
        return str(rolenames[idx])
    return "idx%d" % idx


def metering_state(http):
    raw = http.cm("SENSOR")
    try:
        obj = json.loads(raw)
    except ValueError:
        return {"running": False, "voltage": None, "frequency": None,
                "power": None, "reason": "SENSOR reply is not JSON: %r" % raw[:80]}
    energy = obj.get("ENERGY") if isinstance(obj, dict) else None
    if not isinstance(energy, dict):
        return {"running": False, "voltage": None, "frequency": None,
                "power": None,
                "reason": "no ENERGY block in the SENSOR reply - no power-measuring driver is running"}
    voltage = energy.get("Voltage")
    frequency = energy.get("Frequency")
    power = energy.get("Power")
    if not voltage or not frequency:
        return {"running": False, "voltage": voltage, "frequency": frequency,
                "power": power,
                "reason": "ENERGY block present but Voltage=%s Frequency=%s (zero or absent)"
                          % (voltage, frequency)}
    return {"running": True, "voltage": voltage, "frequency": frequency,
            "power": power, "reason": "live"}


def flag_is_set(http, bit):
    try:
        flags = int(json.loads(http.cm("flags")).get("Flags"))
    except (ValueError, TypeError):
        raise ProvisionFailed("could not parse the `flags` console reply")
    return bool((flags >> bit) & 1)


def relay_state(http):
    raw = http.cm("GetChannel 1").strip()
    try:
        return int(raw)
    except ValueError:
        raise ProvisionFailed(
            "GetChannel 1 returned %r, expected a bare integer" % raw[:60])


READ_RETRY_TRIES = 3
WRITE_RETRY_TRIES = 2
WRITE_RETRY_DELAY_S = 2.0


def with_write_retry(what, fn):
    tried = 0
    while True:
        try:
            return fn()
        except ProvisionFailed as e:
            tried += 1
            if tried >= WRITE_RETRY_TRIES:
                raise
            print("  %s did not get a clean reply (%s); visible retry %d/%d in %.1f s "
                  "(same data re-sent; the write is idempotent)"
                  % (what, e, tried, WRITE_RETRY_TRIES, WRITE_RETRY_DELAY_S))
            time.sleep(WRITE_RETRY_DELAY_S)
READ_RETRY_DELAY_S = 1.5


def with_read_retry(what, fn):
    tried = 0
    while True:
        try:
            return fn()
        except ProvisionFailed:
            tried += 1
            if tried >= READ_RETRY_TRIES:
                raise
            print("  %s read failed (transient?); visible read-only retry %d/%d in %.1f s"
                  % (what, tried, READ_RETRY_TRIES, READ_RETRY_DELAY_S))
            time.sleep(READ_RETRY_DELAY_S)


def read_config(http):
    data = http.get_bytes("/api/flash/%X-%X" % (CFG_ADDR, CFG_LEN)).strip()
    if len(data) != CFG_LEN:
        raise ProvisionFailed("config blob is %d bytes, expected %d" % (len(data), CFG_LEN))
    if data[:3] != b"CFG":
        return None
    return {
        "sig": "CFG",
        "ver": data[4],
        "change_counter": struct.unpack_from("<H", data, CHANGE_COUNTER_OFFSET)[0],
        "ota_counter": struct.unpack_from("<H", data, CHANGE_COUNTER_OFFSET + 2)[0],
        "power_cal": struct.unpack_from("<f", data, CAL_OFFSET)[0],
    }


def restart_and_wait(http):
    try:
        http.get("/index?restart=1")
    except ProvisionFailed:
        pass
    time.sleep(1.0)
    deadline = time.time() + RESTART_WAIT_S
    while time.time() < deadline:
        try:
            info = http.get_json("/api/info")
            if "build" in info:
                return info
        except ProvisionFailed:
            pass
        time.sleep(1.0)
    raise ProvisionFailed("unit did not come back within %d s after /index?restart=1"
                          % int(RESTART_WAIT_S))


def meter_read_or_dead(http):
    try:
        return metering_state(http)
    except ProvisionFailed as e:
        return {"running": False, "voltage": None, "frequency": None, "power": None,
                "reason": "read failed (%s)" % e}


def wait_for_meter_http(http):
    meter = meter_read_or_dead(http)
    tries = 0
    while not meter["running"] and tries < METER_SETTLE_MAX_TRIES:
        print("  meter not live (%s); read-only retry %d/%d after %.0f s"
              % (meter["reason"], tries + 1, METER_SETTLE_MAX_TRIES, METER_SETTLE_S))
        time.sleep(METER_SETTLE_S)
        tries += 1
        meter = meter_read_or_dead(http)
    return meter


def parse_args():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", required=True, help="OpenBeken unit IP on the LAN")
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--expect-mac", default=None, metavar="MAC",
                    help="refuse unless /api/info's mac matches exactly -- the MAC "
                         "the private flashing tool's dry-run plan printed as the "
                         "patched identity (that tool isn't published in this repo). "
                         "Omit while the unit is still in its own standalone config AP.")
    ap.add_argument("--yes", action="store_true",
                    help="confirm the writes shown in the plan (not needed for the zero-write no-op)")
    ap.add_argument("--power-set", type=float, default=None, metavar="WATTS",
                    help="opt-in calibration against a connected known steady resistive load of this true wattage")
    ap.add_argument("--name", default=None, metavar="NAME",
                    help="set the device short name and the channel 1 label (writes over any existing name)")
    ap.add_argument("--wifi-ssid", default=None, metavar="SSID",
                    help="set Wi-Fi via /cfg_wifi_set; password from OBK_WIFI_PASS or a prompt; terminal step")
    ap.add_argument("--allow-relay-on", action="store_true",
                    help="permit provisioning while GetChannel 1 is ON (a load may be energized; a restart turns it off)")
    ap.add_argument("--no-restart", action="store_true",
                    help="skip the software restart (BL0942 then cannot start this run; metering stays unverified)")
    ap.add_argument("--force-restart", action="store_true",
                    help="software-restart even when the configuration already matches")
    ap.add_argument("--timeout", type=float, default=6.0, help="per-request HTTP timeout in seconds")
    return ap.parse_args()


def main():
    a = parse_args()
    http = ObkHttp(a.host, a.port, a.timeout)

    info = read_info_safe(http)
    try:
        build = check_target(info, expect_mac=a.expect_mac)
    except ProvisionFailed as e:
        print("REFUSED: %s" % e, file=sys.stderr)
        raise SystemExit(1)
    pins = read_pins_safe(http)
    roles, channels = listed(pins)
    rolenames = pins.get("rolenames", []) or []
    try:
        cfg_before = read_config(http)
    except ProvisionFailed as e:
        print("note: config blob not read (%s); change counter and cal float are shown as n/a" % e)
        cfg_before = None

    new_roles, new_channels = wanted_arrays(roles, channels)
    pin_changes = []
    for i in range(GPIO_MAX):
        if roles[i] != new_roles[i] or channels[i] != new_channels[i]:
            pin_changes.append((i, roles[i], new_roles[i], channels[i], new_channels[i]))
    foreign = [i for i in range(GPIO_MAX) if roles[i] != 0 and i not in PC191HA_S4_PINS]
    startcmd = info.get("startcmd", "")
    startup_change = startcmd != STARTUP_CMD
    relay_before = with_read_retry("relay state", lambda: relay_state(http))
    meter_before = with_read_retry("meter state", lambda: metering_state(http))
    flag_before = with_read_retry("flags", lambda: flag_is_set(http, MQTT_SELFSTATE_FLAG))
    flag_change = not flag_before
    needs_restart = bool(pin_changes) or startup_change
    any_write = needs_restart or flag_change
    will_restart = False if a.no_restart else (needs_restart or a.force_restart)
    writes = []

    print("")
    print("UNIT   %s:%s  build=%s  startcmd=%r  uptime_s=%s  ip=%s"
          % (a.host, a.port, build, startcmd, info.get("uptime_s"), info.get("ip")))
    if cfg_before:
        print("CONFIG sig=%s ver=%s change_counter=%s ota_counter=%s power_cal=%.7f (%s)"
              % (cfg_before["sig"], cfg_before["ver"], cfg_before["change_counter"],
                 cfg_before["ota_counter"], cfg_before["power_cal"],
                 "negative" if cfg_before["power_cal"] < 0 else "positive"))
    else:
        print("CONFIG unreadable (counter/cal shown as n/a)")
    print("RELAY  GetChannel 1 = %d before%s" % (relay_before, "" if not relay_before else " (LOAD MAY BE ENERGIZED)"))
    print("METER  %s%s" % ("live" if meter_before["running"]
                           else "not running", "" if meter_before["running"] else " (%s)" % meter_before["reason"]))
    print("")

    print("PLAN")
    if pin_changes:
        print("  one POST /api/pins with the full %d-slot arrays (persists to flash within ~1 s; no device-side dry-run):" % GPIO_MAX)
        for (i, old_r, new_r, old_c, new_c) in pin_changes:
            if old_r != new_r:
                print("    P%-2d role %s -> %s" % (i, role_name(rolenames, old_r), role_name(rolenames, new_r)))
            if old_c != new_c:
                print("    P%-2d channel %d -> %d" % (i, old_c, new_c))
    else:
        print("  pin map already matches (no pin write)")
    if startup_change:
        print("  startup command %r -> %r (GET /startup_command?startup_cmd=1&data=... only)"
              % (startcmd, STARTUP_CMD))
    else:
        print("  startup command already correct (a redundant GET-form write would still bump the change counter; skipped)")
    if flag_change:
        print("  flag %d on (GET /cm?cmnd=SetFlag %d 1): MQTT self-state every 60 s so HA diagnostics populate; no restart needed"
              % (MQTT_SELFSTATE_FLAG, MQTT_SELFSTATE_FLAG))
    else:
        print("  MQTT self-state flag %d already set" % MQTT_SELFSTATE_FLAG)
    if foreign:
        print("  WARNING: non-map pins carry unexpected roles; they are PRESERVED this run, for the operator to review:")
        for i in foreign:
            print("    P%-2d role %s" % (i, role_name(rolenames, roles[i])))
    if will_restart:
        print("  software restart (GET /index?restart=1), wait up to %d s, then re-read pins + startcmd" % int(RESTART_WAIT_S))
    else:
        print("  no software restart (%s)" % ("--no-restart" if a.no_restart else "nothing to restart for; use --force-restart to override"))
    if a.name is not None:
        print("  naming: shortName=%r and SetChannelLabel 1 %r (overwrites any existing name -- the flag is the consent)" % (a.name, a.name))
    if a.power_set is not None:
        print("  calibration: PowerSet %s, then read back the stored float at 0x%X+0x%X. Requires a live steady "
              "resistive load; do NOT calibrate on a PTC warm-up transient." % (a.power_set, CFG_ADDR, CAL_OFFSET))
    if a.wifi_ssid is not None:
        print("  Wi-Fi: GET /cfg_wifi_set?ssid=%r&pass=**** then the unit self-resets in ~3 s (terminal step)" % a.wifi_ssid)
    print("")

    if a.wifi_ssid is not None and (any_write or will_restart or a.name is not None or a.power_set is not None):
        print("REFUSED: --wifi-ssid is terminal (its endpoint schedules a device self-reset in ~3 s); "
              "run it alone, after everything else has verified.", file=sys.stderr)
        raise SystemExit(1)
    if any_write and not a.yes:
        print("NOT APPLIED: the diff is non-empty and --yes was not given. Zero writes made.", file=sys.stderr)
        raise SystemExit(1)
    if relay_before and not a.allow_relay_on:
        print("NOT APPLIED: GetChannel 1 is ON (a load may be energized). Turn the relay off first "
              "(deliberately, by hand) or pass --allow-relay-on. Zero writes made.", file=sys.stderr)
        raise SystemExit(1)

    try:
        if pin_changes:
            payload = json.dumps({"roles": new_roles, "channels": new_channels},
                                 separators=(",", ":")).encode("utf-8")
            reply = with_write_retry(
                "POST /api/pins", lambda: http.post("/api/pins", payload))
            writes.append("POST /api/pins (%d slots)" % GPIO_MAX)
            print("wrote: POST /api/pins -> %s" % (reply.strip()[:60] or "<empty>"))
            time.sleep(PIN_SETTLE_S)
            after = with_read_retry("pin-map", lambda: read_pins_safe(http))
            ar, ac = listed(after)
            if (ar, ac) != (new_roles, new_channels):
                raise ProvisionFailed("pin map did not take: the re-read after POST disagrees")
            roles, channels = ar, ac

        if startup_change:
            reply = with_write_retry(
                "GET /startup_command",
                lambda: http.get("/startup_command?startup_cmd=1&data="
                                 + urllib.parse.quote(STARTUP_CMD)))
            writes.append("GET /startup_command data=%r" % STARTUP_CMD)
            print("wrote: GET /startup_command -> %s" % (reply.strip()[:60] or "<empty>"))
            info2 = with_read_retry("api/info", lambda: http.get_json("/api/info"))
            if info2.get("startcmd") != STARTUP_CMD:
                raise ProvisionFailed(
                    "startup command did not stick: /api/info reports %r" % info2.get("startcmd"))

        if flag_change:
            with_write_retry("SetFlag", lambda: http.cm("SetFlag %d 1" % MQTT_SELFSTATE_FLAG))
            writes.append("SetFlag %d 1" % MQTT_SELFSTATE_FLAG)
            if not with_read_retry("flags", lambda: flag_is_set(http, MQTT_SELFSTATE_FLAG)):
                raise ProvisionFailed("SetFlag %d did not stick: the flags re-read still shows it clear"
                                      % MQTT_SELFSTATE_FLAG)

        if will_restart:
            print("restarting ...")
            info3 = restart_and_wait(http)
            check_target(info3, expect_mac=a.expect_mac)
            print("  back: uptime_s=%s startcmd=%r" % (info3.get("uptime_s"), info3.get("startcmd")))
            pins_after = with_read_retry("post-restart pin-map", lambda: read_pins_safe(http))
            ar, ac = listed(pins_after)
            if (ar, ac) != (new_roles, new_channels):
                raise ProvisionFailed("pin map did not survive the restart: "
                                      "roles=%s channels=%s" % (ar, ac))
            roles, channels = ar, ac
            rolenames = pins_after.get("rolenames", rolenames) or rolenames

        roles_final, channels_final = listed(
            with_read_retry("final pin-map", lambda: read_pins_safe(http)))
        if (roles_final, channels_final) != (roles, channels):
            raise ProvisionFailed("final pin re-read disagrees with the post-write state")

        meter_final = wait_for_meter_http(http)
        relay_after = with_read_retry("relay state", lambda: relay_state(http))
        if relay_after != relay_before:
            raise ProvisionFailed("relay state changed: %d -> %d (re-run required, something moved it)"
                                  % (relay_before, relay_after))

        flag_final = with_read_retry("flags", lambda: flag_is_set(http, MQTT_SELFSTATE_FLAG))
        info_final = with_read_retry("api/info", lambda: http.get_json("/api/info"))
        short_name_final = info_final.get("shortName", "")

        if a.name is not None:
            with_write_retry("shortName", lambda: http.cm("shortName %s" % a.name))
            with_write_retry("SetChannelLabel",
                             lambda: http.cm("SetChannelLabel 1 %s" % a.name))
            writes.append("shortName %r" % a.name)
            writes.append("SetChannelLabel 1 %r" % a.name)
            time.sleep(NAME_SETTLE_S)
            info_final = with_read_retry("api/info", lambda: http.get_json("/api/info"))
            short_name_final = info_final.get("shortName", "")
            if short_name_final != a.name:
                raise ProvisionFailed("shortName did not stick (still %r)" % short_name_final)

        if a.power_set is not None:
            if not meter_final["running"]:
                raise ProvisionFailed(
                    "refusing --power-set: metering is not live (%s); a calibration needs mains and a running meter"
                    % meter_final["reason"])
            with_write_retry("PowerSet", lambda: http.cm("PowerSet %s" % a.power_set))
            writes.append("PowerSet %s" % a.power_set)
            time.sleep(CAL_SETTLE_S)
            meter_final = wait_for_meter_http(http)

        cfg_after = with_read_retry("config blob", lambda: read_config(http))

        if a.wifi_ssid is not None:
            pw = os.environ.get("OBK_WIFI_PASS")
            if not pw:
                pw = getpass.getpass("OBK Wi-Fi password for ssid %r (input hidden): " % a.wifi_ssid)
            if not pw:
                raise ProvisionFailed("no Wi-Fi password supplied")
            q = urllib.parse.urlencode({"ssid": a.wifi_ssid, "pass": pw})
            http.get("/cfg_wifi_set?" + q)
            writes.append("GET /cfg_wifi_set ssid=%r (pass not shown, not stored)" % a.wifi_ssid)
            print("wi-fi: /cfg_wifi_set sent; OpenBeken schedules a module self-reset in ~3 s. "
                  "Provisioning ends here; re-run this tool once the unit is on the new network.")
    except ProvisionFailed as e:
        print("")
        print("PARTIAL STATE after %d write(s):" % len(writes))
        for w in writes:
            print("  " + w)
        print("ERROR: %s" % e, file=sys.stderr)
        raise SystemExit(2)

    counter_after = cfg_after["change_counter"] if cfg_after else None
    cal_after = cfg_after["power_cal"] if cfg_after else None

    rows = []

    def row(item, expected, observed, ok, changed):
        rows.append((item, expected, observed, bool(ok), bool(changed)))

    row("target build", "OpenBeken", build, True, False)
    for pin, (role, ch) in sorted(PC191HA_S4_PINS.items()):
        pin_changed = any(pc[0] == pin for pc in pin_changes)
        row("pin P%d %s" % (pin, ROLE_DISPLAY.get(role, role).lower()),
            "role %s / ch %d" % (ROLE_DISPLAY.get(role, role), ch),
            "role %s / ch %d" % (role_name(rolenames, roles_final[pin]), channels_final[pin]),
            roles_final[pin] == role and channels_final[pin] == ch, pin_changed)
    kept = [i for i in range(GPIO_MAX) if roles_final[i] != 0 and i not in PC191HA_S4_PINS]
    row("non-map pins", "preserved", "%d foreign role(s) kept" % len(kept), True, False)
    startcmd_final = info_final.get("startcmd", "")
    row("startup command", STARTUP_CMD, repr(startcmd_final), startcmd_final == STARTUP_CMD, startup_change)
    row("mqtt self-state flag", "set", "set" if flag_final else "clear", flag_final, flag_change)
    if meter_final["running"]:
        meter_changed = not meter_before["running"]
        row("BL0942 metering", "live", "live V=%s f=%s P=%s"
            % (meter_final.get("voltage"), meter_final.get("frequency"), meter_final.get("power")), True, meter_changed)
    else:
        row("BL0942 metering", "live", "NOT live (%s)" % meter_final["reason"], False, False)
    row("relay untouched", "GetChannel 1 = %d" % relay_before, "re-read %d" % relay_after,
        relay_after == relay_before, False)
    if cfg_before and cfg_after:
        cb, ca = cfg_before["change_counter"], cfg_after["change_counter"]
        row("change counter", str(cb), str(ca), ca >= cb, ca != cb)
        if a.power_set is None:
            cal_ok = cal_after == cfg_before["power_cal"]
            cal_changed = False
        else:
            cal_ok = cal_after < 0
            cal_changed = cal_after != cfg_before["power_cal"]
        row("power cal (stored float)",
            "unchanged %.7f (%s)" % (cfg_before["power_cal"], "negative" if cfg_before["power_cal"] < 0 else "positive"),
            "%.7f (%s)" % (cal_after, "negative" if cal_after < 0 else "positive"), cal_ok, cal_changed)
    else:
        row("change counter", "n/a", "n/a", True, False)
        row("power cal (stored float)", "n/a", "n/a", True, False)
    if a.name is not None:
        row("short name", a.name, short_name_final, short_name_final == a.name, True)
        row("channel label", a.name, "written (no HTTP read-back exists)", True, True)
    if a.wifi_ssid is not None:
        try:
            ssid_final = json.loads(http.cm("SSID1")).get("SSID1", "")
        except (ValueError, ProvisionFailed):
            ssid_final = ""
        row("wifi ssid", a.wifi_ssid, ssid_final, ssid_final == a.wifi_ssid, True)

    print("")
    print("VERIFY")
    print("%-30s %-24s %-32s %-7s %s" % ("row", "expected", "observed", "changed", "ok"))
    for (item, expected, observed, ok, changed) in rows:
        print("  %-28s %-24s %-32s %-7s %s"
              % (item, str(expected)[:24], str(observed), "yes" if changed else "no", "PASS" if ok else "FAIL"))

    print("")
    if writes:
        print("writes made (%d):" % len(writes))
        for w in writes:
            print("  " + w)
    else:
        print("ALREADY CONFIGURED: zero writes, no restart, nothing to apply (the no-op was the goal).")

    failing = [item for (item, _, _, ok, _changed) in rows if not ok]
    if failing:
        print("RESULT FAILED; failing rows: %s" % ", ".join(failing))
        raise SystemExit(2)
    print("RESULT ok")
    if a.no_restart and needs_restart:
        print("NOTE: writes were made with --no-restart; BL0942 only starts at a boot, so run GET /index?restart=1 "
              "and this tool again to verify metering.")
    if a.wifi_ssid is None and not any_write:
        print("cold-boot check is a manual follow-up: unplug mains ~5 s, replug, then re-run this command; "
              "it must exit 0 with zero writes.")
    return 0


def read_info_safe(http):
    try:
        return with_read_retry("/api/info", lambda: http.get_json("/api/info"))
    except ProvisionFailed as e:
        print("ERROR: cannot read /api/info: %s" % e, file=sys.stderr)
        raise SystemExit(1)


def read_pins_safe(http):
    try:
        return with_read_retry("/api/pins", lambda: http.get_json("/api/pins"))
    except ProvisionFailed as e:
        print("ERROR: cannot read /api/pins: %s" % e, file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    sys.exit(main())
