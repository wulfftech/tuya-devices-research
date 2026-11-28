#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
owner_reflash.py -- reference implementation of the no-case-open owner reflash
on the Arlec PC191HA Series 4 (BK7238 / TuyaOS 3.8.31), using the owner's own
cloud-issued local_key/secKey. See LAN-OTA-PROTOCOL.md for the protocol this
drives (frame envelope, handshake, OTA commands, container format) -- this
module is the live driver and the detailed evidence for the completion-check
section of that page.

================================================================================
  !! DO NOT TRUNCATE THIS TOOL'S OUTPUT -- IT WILL BRICK THE UNIT !!
================================================================================
  This tool must run to completion. If you pipe it into something that stops
  reading early, the tool is KILLED mid-transfer, the device is left holding a
  partial staged image, and it does not come back.

  This actually happened once: a run was launched as

      python tools/owner_reflash.py run ... | Select-Object -First 45

  PowerShell's `Select-Object -First N` terminates the upstream pipeline once it
  has N objects -- it does not merely truncate the display. The transfer died
  after ~4 chunk requests (8.8% of the container) and the unit went dark,
  permanently.

  CORRECT, on PowerShell:

      $out = & python tools/owner_reflash.py run ... 2>&1   # let it finish
      $out | Select-Object -Last 40                              # then read it

  or redirect to a file and read the file afterwards. On bash, `| head`, `| more`
  and `timeout` are the same hazard. Never wrap a device-facing run in a
  consumer that can exit early.
================================================================================

WHAT IT DOES
------------
The firmware has TWO separate file-HMAC checks. Do not conflate them:

  * fn 0x071E04 (body 0x071E04-0x072023) owns a SKIPPABLE 32-byte memcmp at
    0x071FF6, gated at 0x071F94. This is the mechanism described below.
  * fn 0x072FE4 (body 0x072FE4-0x07319D) owns a SEPARATE, UNSKIPPABLE inline
    32-byte memcmp at 0x07311E, with no skip branch anywhere in the
    function. THIS is the one the LAN path actually runs -- see
    build_ota_start() and cmd_run().

fn 0x071E04's gate at 0x071F94 is guarded by

    0x071FB2  ldr r3, =0x0040B774     ; the global upgrade manager `mgr`
    0x071FB4  ldr r2, [r4, #0xc]      ; bsdiff_ctx[0x0c]  == a copy of mgr[0x00]
    0x071FB6  ldr r3, [r3, #0x14]     ; mgr[0x14]
    0x071FB8  orrs r3, r2
    0x071FBA  bne  #0x71fc4           ; non-zero -> "skip hmac"

`mgr[0x00]` is only ever 0 or 1, so the second operand is a dead end. But
`mgr[0x14]` is written by the device's own multi-section progress handler
`0x072C00`, which the download progress callback `0x072974` invokes as
`handle[4]` while the image is still downloading and BEFORE the gate runs:

    0x072A24  ldr r4, [r4, #4]        ; handle[4] = 0x072C00
    0x072A28  blx r4

`0x072C00` copies 0x40 bytes into its stack frame and reads a word from that
copy into r7. If it matches one of four magic values, it sets mgr[0x14]:

    0x09CC..  copy:  movs r2,#0x40 / movs r1,r6 / add r0,sp,#0x18 / bl memcpy
    0x072CA8  ldr r7, [sp, #0x1c]     ; struct+4, because the memcpy dst is sp+0x18

    0x41425349 "ISBA"  ->  mgr[0x14] = 0x67891234
    0x4C5A4352 "RCZL"  ->  mgr[0x14] = 0x67891234   (0x072CC2-0x072CD4)
    0x41425238 "8RBA"  ->  mgr[0x14] = 0x12346789
    0x4C5A4351 "QZCL"  ->  mgr[0x14] = 0x12346789   (0x072D00-0x072D12)

*** THE MAGIC GOES AT OFFSET 4, NOT 0. *** It is arithmetically `sp+0x18+4`,
i.e. offset 4 of the 0x40-byte copy, and `sp+0x18` is the memcpy destination.
`--patch-magic` therefore writes the four bytes at offset 4. An image whose
own header happens to start with "ISBA" will NOT arm the gate.

The copy's source is r6 = 0x072C00's arg3, which traces back through 0x072974
to gf[0x20] -- a buffer base with a separate cursor (gf[0x24]), read out of the
iot_httpc transfer context. It is written once at transfer setup (0x09A094) to
`gf + 0x34` -- a buffer EMBEDDED in the gf object, not a separately allocated
whole-image buffer -- with cursor gf[0x24] initialised to 0. The receive loop
only ever appends at `gf[0x20] + gf[0x24]` and never rewinds, so the buffer
holds an exact in-order prefix of the response body from true byte 0. Net
effect: offset 4 of that buffer IS byte offset 4 of the image exactly as
served -- the same header slot the bootloader reads as
diff2ya_header.bin_type (MAGIC_OFFSET = 4 below).

The device/owner chooses the image, therefore the device/owner chooses
mgr[0x14], and DRIVEN DIRECTLY the gate takes `bne 0x71fc4`, logs
"skip hmac", and jumps over the 32-byte memcmp at 0x071FF6. This arming is
confirmed to happen for real on a live LAN transfer that carries one of the
four magic words: the device's own UART logs
`multi_section->bin_step[0x67891234]` on three separate boots, and the value
persists across reboot (serialized to KV as `ota.multi.section`'s `ms_step`,
restored unvalidated on the next activation-success path).

BUT fn 0x071E04 -- the function that owns this gate -- is never entered by
the LAN OTA ingest path on this firmware build, so the armed flag has no
site at which to act. All three of the following are independently
confirmed (private-tree `findings/LOG.md` Entry 147, re-derived Entry 153):

  * Pointer-table census: fn 0x071E04's Thumb entry (0x00071E05) occurs
    exactly once in the whole image, as the pool dword at 0x073508 -- the
    arm `FUN_000732C0` installs when `bin_type != 2`. It has zero direct
    `bl`/`blx` callers anywhere in the image.
  * UART string/line-number census (10.9 MB of logs): every string unique
    to fn 0x071E04 ("download begin, set upgrade stat:%d", "ota wait for
    link up...", "ota.process", etc.) and its source line numbers
    (1190/1191/1194/1203/1205/1216/1217) appear ZERO times. The line numbers
    that DO appear for file-HMAC verdicts (:620, :626) belong to fn
    0x072FE4, not fn 0x071E04.
  * Even if entered (bin_type=3 does reach the 0x073508 pointer's
    registration), fn 0x071E04 is a PULL DOWNLOADER, not a push-ingest
    verifier: it fetches a `url` field via fn 0x0009a094 that the LAN
    `ota.start` JSON never carries (the LAN launcher fn 0x073534 passes
    url = NULL at 0x0735C2), so the registered worker has nothing to
    download. It would also still need secKey to compute anything to
    compare -- it was never a secKey-free path even in principle.

So on this firmware build the magic-word arm is real but dead: it is a
container-header field (`bin_type`, read again by the apply pipeline) that
every served container needs regardless, but it buys no shortcut on the
completion check. The `fileHmac` field IS compared on the LAN path --
unconditionally, by fn 0x072FE4's separate inline check at 0x07311E. See
build_ota_start() and cmd_run() for what that means in practice: a full
transfer needs the real `fileHmac`, computed from the owner's `secKey`.
LAN-OTA-PROTOCOL.md's "completion check" section covers why none of this is
a security boundary being crossed: the device has no code signing at all,
and reaching either check already needs `localKey` to open the LAN session.

ENTRYPOINTS
-----------
All three pass 0x00072C01 (fn 0x072C00, the live chunk dispatcher that arms
mgr[0x14]) as handle[4]:

  LAN 0x1A  0x072EA0 -> 0x71C78 @ 0x072FAA
  MQTT      0x072208 -> 0x71C78 @ 0x0726A6   (grammar is a superset; carries url/diffUrl)
  activation 0x073900 -> 0x732C0 @ 0x073940

None of the three reaches fn 0x071E04's gate this way -- the dispatcher only
arms the dead mgr[0x14] flag (see above). This script drives the LAN path.

USAGE
-----
  # 1. enumerate localKey from the Tuya OpenAPI (reads TUYA_ACCESS_ID/
  #    TUYA_ACCESS_SECRET from the environment -- never pass these as CLI args)
  python tools/owner_reflash.py localkey --device-id <id>

  # 2. dry run -- build and print the frames, send nothing
  python tools/owner_reflash.py run --host 192.168.20.61 \
      --localkey '<key>' --image ./openbeken.bin --dry-run

  # 3. live
  python tools/owner_reflash.py run --host 192.168.20.61 \
      --localkey '<key>' --image ./openbeken.bin

No `--serve` needed for the LAN entrypoint: the device requests chunks over
the LAN session itself (cmd 0x1B, {"file_offset","data_block_len"}), and this
script answers them directly (`answer_ota_data()`) once the 0x1A reply comes
back clean. `--serve`'s HTTP pull was carried over from the MQTT entrypoint's
url/diffUrl grammar, which 0x1A doesn't have, and is confirmed unused on this
path (a live run's HTTP server never received a single request).

The image must carry one of the four magic values at byte offset 4 (see
MAGIC_OFFSET below). `--image` is checked for this before anything is sent;
`--patch-magic` inserts one at offset 4 if it is missing. Inserting shifts the
rest of the image right by four bytes, so the served image differs from the file
on disk -- craft the test image with the magic already at offset 4 wherever you
can, and treat `--patch-magic` as a way to make a throwaway probe self-consistent
rather than a way to prepare a real payload.

NOTE ON THE FRAME ENVELOPE
--------------------------
6699-framed, AES-GCM sealed, cmd at offset 0x0a, L = payload + 0x1c -- not the
0x55AA framing an earlier version of this script guessed at, which doesn't
appear in this firmware's LAN path at all. The implementation (and the full
evidence for the layout) is in tools/lpv35.py; LAN-OTA-PROTOCOL.md has the
summary.
"""

import argparse
import binascii
import hashlib
import hmac
import json
import os
import socket
import struct
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lpv35                                                       # noqa: E402

# ---------------------------------------------------------------------------
# Constants from the disassembly
# ---------------------------------------------------------------------------

MGR_BASE = 0x0040B774
LAN_UG_HANDLE = 0x0040B74C
BSDIFF_CTX_0C = 0x0040B758          # == LAN_UG_HANDLE + 0xc

# The four magic values 0x072C00 compares against, and the step each arms.
MAGIC_TO_STEP = {
    0x41425349: 0x67891234,          # "ISBA"
    0x4C5A4352: 0x67891234,          # "RCZL"
    0x41425238: 0x12346789,          # "8RBA"
    0x4C5A4351: 0x12346789,          # "QZCL"
}
MAGIC_NAMES = {
    0x41425349: "ISBA",
    0x4C5A4352: "RCZL",
    0x41425238: "8RBA",
    0x4C5A4351: "QZCL",
}

# The magic is tested at OFFSET 4 of the 0x40-byte copy, not offset 0.
#   0x072C9E  add  r0, sp, #0x18    (memcpy destination)
#   0x072CA8  ldr  r7, [sp, #0x1c]  = sp+0x18+4 = offset 4
MAGIC_OFFSET = 4

# LAN frame commands (tuya_svc_lan.c, dispatched on the cmd field at 0x0a)
FRAME_HS_RAND = lpv35.CMD_HS_NONCE
FRAME_HS_HMAC = lpv35.CMD_HS_HMAC
FRAME_HS_DONE = lpv35.CMD_HS_DONE
FRAME_OTA_START = lpv35.CMD_OTA_START
FRAME_OTA_DATA = lpv35.CMD_OTA_DATA
FRAME_OTA_END = lpv35.CMD_OTA_END

DEFAULT_PORT = 6668


def hx(b, n=256):
    return binascii.hexlify(bytes(b[:n])).decode()


def normalise_key(s):
    """A 16-byte AES key from either raw text or a 32-hex-char string.

    Delegates to `lpv35.normalise_key` so the live driver and the capture decoder
    cannot disagree about what a key string means.
    """
    return lpv35.normalise_key(s)


def log(msg):
    sys.stderr.write("[skip-hmac] %s\n" % msg)
    sys.stderr.flush()


# ---------------------------------------------------------------------------
# Step 1 -- enumerate localKey from the Tuya OpenAPI
# ---------------------------------------------------------------------------

# eu listed first -- adjust the order here if your account's devices live in
# a different data center. A wrong region's /v1.0/token call can still return
# success=true (identity auth doesn't check device placement) -- only the
# device-info call fails, with a data-center/permission error, so region
# detection has to try the actual device lookup, not just the token exchange.
TUYA_REGIONS = {
    "eu": "https://openapi.tuyaeu.com",
    "us": "https://openapi.tuyaus.com",
    "cn": "https://openapi.tuyacn.com",
    "in": "https://openapi.tuyain.com",
}


def _tuya_sign(client_id, secret, method, path, body, access_token, t):
    """developer.tuya.com "Request Signature": HMAC-SHA256 over
    client_id + access_token? + t + stringToSign, where stringToSign is
    Method/Content-SHA256/Headers(unused here)/Url newline-joined."""
    content_sha256 = hashlib.sha256(body or b"").hexdigest()
    string_to_sign = "\n".join([method, content_sha256, "", path])
    message = client_id + (access_token or "") + t + string_to_sign
    return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest().upper()


def _tuya_request(base, client_id, secret, method, path, access_token=None, body=None):
    import urllib.request

    t = str(int(time.time() * 1000))
    sign = _tuya_sign(client_id, secret, method, path, body, access_token, t)
    headers = {
        "client_id": client_id,
        "sign": sign,
        "t": t,
        "sign_method": "HMAC-SHA256",
    }
    if access_token:
        headers["access_token"] = access_token
    req = urllib.request.Request(base + path, method=method, headers=headers, data=body)
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode())


def fetch_localkey(device_id, region=None):
    """Return the device's local_key, or raise RuntimeError.

    Credentials come ONLY from TUYA_ACCESS_ID / TUYA_ACCESS_SECRET env vars --
    never a CLI arg, so they never land in shell history or `ps`.
    """
    client_id = os.environ.get("TUYA_ACCESS_ID")
    secret = os.environ.get("TUYA_ACCESS_SECRET")
    if not client_id or not secret:
        raise RuntimeError("set TUYA_ACCESS_ID and TUYA_ACCESS_SECRET env vars first "
                           "(not CLI args)")

    errors = []
    for name in ([region] if region else list(TUYA_REGIONS)):
        base = TUYA_REGIONS[name]
        log("trying region %s (%s)..." % (name, base))
        try:
            tok = _tuya_request(base, client_id, secret, "GET", "/v1.0/token?grant_type=1")
        except Exception as e:                               # noqa: BLE001
            log("  token request failed: %s" % e)
            errors.append("%s: token request failed: %s" % (name, e))
            continue
        if not tok.get("success"):
            log("  token request rejected: %s" % tok)
            errors.append("%s: token rejected" % name)
            continue
        access_token = tok["result"]["access_token"]
        try:
            body = _tuya_request(base, client_id, secret, "GET",
                                  "/v1.0/devices/%s" % device_id, access_token=access_token)
        except Exception as e:                               # noqa: BLE001
            log("  device lookup failed: %s" % e)
            errors.append("%s: device lookup failed: %s" % (name, e))
            continue
        if not body.get("success"):
            log("  device lookup rejected in region %s: %s" % (name, body.get("msg")))
            errors.append("%s: %s" % (name, body.get("msg")))
            continue
        key = (body.get("result") or {}).get("local_key")
        if not key:
            raise RuntimeError("no local_key in the response: %s"
                               % json.dumps(body)[:400])
        return key

    raise RuntimeError("no region returned a usable result (%s)" % "; ".join(errors))


def cmd_localkey(a):
    """Fetch the device's local_key from the Tuya developer OpenAPI, with real
    HMAC-SHA256 request signing.

    The OpenAPI hands local_key to the account that owns the device. That is the
    whole of the attacker model: no cloud compromise is required, only ownership
    of the account (or a session hijack of it).
    """
    try:
        key = fetch_localkey(a.device_id, a.region)
    except RuntimeError as e:
        log(str(e))
        return 1
    print(key)
    return 0


# ---------------------------------------------------------------------------
# Step 2 -- the LAN handshake
# ---------------------------------------------------------------------------

def lan_handshake(sock, localkey, mode="gcm", start_seq=1):
    """Commands 3/4/5 on the pinned 6699 envelope.

    Returns the 16-byte session key on success, or None. There is one correct
    envelope and this uses it directly -- no candidate sweeping.

    The key for commands 3/4/5 is the localKey. Once the handshake completes,
    later frames use the derived session key.
    """
    key = normalise_key(localkey)
    if len(key) != 16:
        log("localKey must be 16 bytes (or 32 hex chars); got %d" % len(key))
        return None

    rand_a = os.urandom(16)
    seq = start_seq

    def send(cmd, payload, k):
        frame = lpv35.build_frame(cmd, payload, seq=seq, key=k, mode=mode)
        sock.sendall(frame)
        return frame

    send(FRAME_HS_RAND, rand_a, key)
    log("sent cmd 3 (randA=%s) seq=%d" % (hx(rand_a, 16), seq))
    try:
        r = sock.recv(4096)
    except socket.timeout:
        log("no reply to cmd 3 within the timeout")
        log("  -> if this was --mode gcm, retry with --mode cbc (the AEAD mode is")
        log("     the one remaining unknown; see LAN-OTA-PROTOCOL.md's envelope section)")
        return None
    if not r:
        log("connection CLOSED after cmd 3 -- the frame was recognised and rejected")
        return None

    info = lpv35.peek(r, key=key, mode=mode)
    log("cmd 3 reply %d bytes: %s" % (len(r), hx(r, 128)))
    if not info.get("decrypted"):
        log("could not decrypt the reply with this localKey (%s)"
            % info.get("error", "no error reported"))
        return None
    if info.get("cmd") != FRAME_HS_HMAC:
        log("reply is cmd %s, expected %d" % (info.get("cmd"), FRAME_HS_HMAC))

    want = lpv35.rand_a_hmac(key, rand_a)
    try:
        rc, rand_b, mac = lpv35.parse_hs_resp(info.get("payload") or b"")
    except ValueError as e:
        # the layout built at 0x0E85D8/0x0E85E6 is retcode(4) || randB(16) ||
        # HMAC-SHA256(localKey, randA)(32); anything else means the reply is not
        # the shape this firmware sends
        log("cmd-4 payload does not match 0x0E85D8/0x0E85E6: %s" % e)
        return None
    if mac != want:
        log("HMAC-SHA256(localKey, randA) mismatch at payload[20:52]")
        log("  expected: %s" % hx(want, 32))
        log("  got     : %s" % hx(mac, 32))
        return None
    log("*** handshake HMAC MATCH -- localKey accepted ***")
    log("randB=%s (retcode=%d)" % (hx(rand_b, 16), rc))

    session_key = lpv35.derive_session_key(key, rand_b, rand_a)
    log("session key = %s" % hx(session_key, 16))

    # NO client-side cmd 4. cmd 4 is the DEVICE's reply and lands on the shared
    # stub 0x0E8BC0 ('unsupport frame type:4'), which returns with no reply and
    # no close if a client sends one anyway -- see lpv35.py's module docstring
    # for the full handshake shape.

    # Command 5: FINISH -- HMAC-SHA256(localKey, randB) under localKey.
    seq += 1
    send(FRAME_HS_DONE, lpv35.rand_b_hmac(key, rand_b), key)
    log("sent cmd 5 (HMAC over randB) seq=%d" % seq)

    # cmd 5 success sends NOTHING (0x0E8760-0x0E87E0). A timeout here is the
    # expected outcome and means the handshake completed server-side; a CLOSE
    # would mean 'verify hmac randB ERROR' (0x0E8748 -> 0x0E732C).
    try:
        r = sock.recv(4096)
        if r:
            i = lpv35.peek(r, key=key, mode=mode)
            log("cmd 5 reply %d bytes (unexpected): %s" % (len(r), hx(r, 128)))
            if i.get("decrypted") and i.get("retcode") is not None:
                log("  retcode=%d body=%r" % (i["retcode"], i.get("body")))
        else:
            log("connection closed after cmd 5 -- cmd 5 was REJECTED")
            return None
    except socket.timeout:
        log("no reply to cmd 5 -- EXPECTED (cmd 5 sends none); treating as accepted")

    return session_key


# ---------------------------------------------------------------------------
# Step 3 -- the OTA-start frame
# ---------------------------------------------------------------------------

def compute_file_hmac(image_bytes, sec_key):
    """hex(HMAC-SHA256(secKey, HEX-UPPER(SHA256(container)))) -- CONFIRMED on hardware.

    Read out of fn 0x072FE4's neighbourhood: `tuya_svc_upgrade.c` describes a
    32-byte digest followed by 32 zero bytes, which looks like it rules this
    construction out at first glance, but that's a different candidate
    (digest-then-zeros, not digest-as-uppercase-hex); this construction is the
    one the device actually accepts. Uppercase is mandatory -- a lowercase hex
    message produces a different digest and is rejected.

    Confirmed live: a value from this function was accepted at the LAN EOF
    gate (`cmd 0x1C`), and the container then applied and booted OpenBeken.

    One trap: `--max-chunks 1` CANNOT test this. The digest is compared at the
    END of the transfer, so a one-chunk run tells you nothing about it -- a
    correct digest can look rejected when the real problem is that the
    *container* is malformed (wrong xz parameters, see warn_xz_params below),
    which surfaces through the same `ota data proc failed` message.
    """
    digest = hashlib.sha256(image_bytes).digest()
    msg = digest.hex().upper().encode()
    return hmac.new(sec_key.encode(), msg, hashlib.sha256).hexdigest()


def build_ota_start(image_len, version="1.0.0", channel="0", filehmac="00" * 32):
    """The 0x1A body. `fileHmac` defaults to a syntactically valid but
    meaningless value, which is fine only when the completion comparison is
    skipped -- it never is on the LAN path. fn 0x072FE4's own inline check,
    at 0x07311E, has no skip branch; it is a separate function from the
    skippable gate at 0x071F94 (see the module docstring's WHAT IT DOES
    section), and that gate is unreachable from the LAN entrypoint anyway.
    So a full transfer to `cmd 0x1C` needs the real value: pass --filehmac
    or --auto-hmac. `--auto-hmac` computes it from the unit's secKey with
    compute_file_hmac(), which is CONFIRMED on hardware.

    `otaFileLen` is a BARE JSON NUMBER, not a quoted string. Verified
    directly against the disassembly, not just assumed: fn 0x072EA0 (the 0x1A
    parser) reads `otaFileLen` via cJSON's `valueint` (`ldr r3,[r0,#0x14]` at
    0x072F5C, right after the `cJSON_GetObjectItem` call whose key -- read
    byte-for-byte at the resolved literal-pool address, 0x072FD4 -> 0xBFFE1
    -> "otaFileLen" -- confirms which field this is), and that exact r3,
    never reassigned in between, is what lands at `[sp,#0x134]` at 0x072F64 --
    confirmed to be the same address fn 0x071C78 calls "bigstruct+0x110" (r0
    at the `bl #0x71c78` call site is `sp+0x24`, so bigstruct+0x110 ==
    sp+0x134 exactly), which a later function (0x0732C0) copies straight into
    `record[0x10]` -- the field fn 0x72fe4 compares the running receive
    offset against to decide the transfer is complete. `otaVersion`, by
    contrast, is read via `valuestring` (confirmed the same way, key resolved
    at 0x072FC8 -> 0xBFFC3 -> "otaVersion") -- sent correctly as a string
    ("1.0.0") throughout."""
    return json.dumps({
        "otaChannel": channel,
        "otaVersion": version,
        "fileHmac": filehmac,
        "isDiffOta": 0,
        "otaFileLen": image_len,
    }).encode()


# The device's bare-xz applier was characterised with a 4 KiB dictionary
# (see build_m3_openbeken_image.DICT_SIZE), and every container that has ever
# reached cmd 0x1C uses xz check type CRC32. A container built by a bare
# lzma.compress() call defaults to CRC64 + a larger dictionary instead, and the
# decoder refuses it -- reported as `ota data proc failed`, the same message as a
# digest failure. Refuse it locally instead, rather than send something that
# fails with a message indistinguishable from a bad HMAC.
XZ_OFFSET = 0x40            # payload starts after the 64-byte diff2ya_header
XZ_MAGIC = b"\xfd7zXZ\x00"
XZ_CHECK_NAMES = {0: "none", 1: "CRC32", 4: "CRC64", 10: "SHA256"}


def _lzma2_dict_size(props_byte):
    """Decode an LZMA2 filter's single props byte to its dictionary size."""
    return (2 | (props_byte & 1)) << (props_byte // 2 + 11)


def warn_xz_params(data):
    """Check the payload's xz stream flags against the known-good encoding.

    Returns a list of problem strings (empty when the payload looks right).
    Advisory, not fatal: this is an offline heuristic check against the
    known-good encoding, not a guarantee, so it warns rather than refusing
    to send.
    """
    problems = []
    xz = data[XZ_OFFSET:]
    if not xz.startswith(XZ_MAGIC):
        problems.append("payload at 0x%x is not an xz stream (got %s)"
                        % (XZ_OFFSET, hx(xz[:6], 6)))
        return problems
    if len(xz) < 20:
        problems.append("payload too short to carry an xz stream header")
        return problems

    check = xz[7]
    if check != 1:
        problems.append("xz check type is %s (byte 7 = %#x); known-good is CRC32"
                        % (XZ_CHECK_NAMES.get(check, "unknown"), check))

    # Block header: byte 12 = (size/4)-1, byte 13 = flags; filters follow at 14.
    num_filters = (xz[13] & 0x03) + 1
    off = 14
    for _ in range(num_filters):
        if off + 2 > len(xz):
            problems.append("truncated xz block header")
            return problems
        fid, props_len = xz[off], xz[off + 1]
        props = xz[off + 2:off + 2 + props_len]
        if fid == 0x21 and props_len == 1:      # LZMA2
            ds = _lzma2_dict_size(props[0])
            if ds != 4096:
                problems.append("LZMA2 dict_size is %d; known-good is 4096" % ds)
        off += 2 + props_len
    return problems


def check_image(path, patch_magic):
    """Verify (or install) the magic that drives mgr[0x14].

    The magic is read at OFFSET 4 of the buffer 0x072C00 examines, so this looks
    at bytes 4..7, not bytes 0..3. See MAGIC_OFFSET.
    """
    with open(path, "rb") as f:
        data = f.read()

    window = data[MAGIC_OFFSET:MAGIC_OFFSET + 4]
    magic = struct.unpack("<I", window)[0] if len(window) == 4 else 0
    if magic in MAGIC_TO_STEP:
        log("image magic at offset %d is %s -> mgr[0x14] = 0x%08x  (bypass armed)"
            % (MAGIC_OFFSET, MAGIC_NAMES[magic], MAGIC_TO_STEP[magic]))
        for problem in warn_xz_params(data):
            log("WARNING: %s -- the device's decoder will likely refuse this "
                "payload" % problem)
        return data

    if not patch_magic:
        log("no magic at offset %d of the image (bytes there: %s)"
            % (MAGIC_OFFSET, hx(window, 4) or "none"))
        log("pass --patch-magic to insert one, or fix the image")
        return None

    # Insert at offset 4 by extending the image from 4 bytes in: this shifts the
    # original bytes 4.. rightwards and keeps bytes 0..3 in place.
    log("inserting 'ISBA' at offset %d (image bytes 0..3 preserved: %s)"
        % (MAGIC_OFFSET, hx(data[:MAGIC_OFFSET], MAGIC_OFFSET)))
    return data[:MAGIC_OFFSET] + b"ISBA" + data[MAGIC_OFFSET:]


# ---------------------------------------------------------------------------
# Step 3b -- answer the device's own chunk requests (cmd 0x1B)
# ---------------------------------------------------------------------------
#
# Decoded from the real device-side ingestion routine (0x72fe4), not guessed:
# the device asks for the next chunk
# with cmd 0x1B carrying {"file_offset":N,"data_block_len":M} (built by its own
# fn 0x731E4); the client's reply is ALSO cmd 0x1B, but the body is the raw M
# bytes themselves -- no JSON, no echoed offset, this is a purely positional
# protocol. A cmd 0x1C (empty body) reply means the device considers the
# transfer over; any other cmd 0x1B reply (short, fixed body) is an abort.
# --serve's HTTP pull is never used on the LAN entrypoint -- that model was
# borrowed from the MQTT grammar's url/diffUrl field, which 0x1A doesn't have.

MAX_CHUNK_REQUESTS_SLACK = 64  # generous safety margin above the minimum
                                # number of chunks the real data_block_len
                                # values would require, so a legitimate
                                # multi-chunk transfer is never cut short, but
                                # a device stuck re-requesting the same (or a
                                # non-advancing) offset still gets a hard stop
                                # rather than running until --wait expires.

# How long to keep the LAN session open after cmd 0x1C, draining and logging. The
# device applies the staged image IN THIS SESSION (a real device's log shows
# `write_total` run up to the full size, `Verify the new firmware`, then
# `jump to:0x10000`, all following the 0x1C -- see answer_ota_data() below for
# why closing the socket right on 0x1C interrupts the apply instead).
APPLY_DRAIN_SECONDS = 45


def answer_ota_data(sock, session_key, image, mode, seq, timeout, max_chunks=None):
    """After a successful 0x1A, answer the device's own cmd 0x1B chunk
    requests with the exact bytes it asks for, until it signals done (cmd
    0x1C), aborts (a non-request cmd 0x1B body), or `max_chunks` requests have
    been answered (deliberate early stop -- e.g. to validate that the gate
    opens and the first chunk is accepted, without running a full transfer
    against real hardware). Returns (status, seq) where status is "done",
    "aborted", "stalled", "timeout", "limit-reached", or "error" -- the
    caller decides what each means for its own exit code, this function only
    reports what the device actually did.
    """
    image_len = len(image)
    max_requests = (image_len // 256) + MAX_CHUNK_REQUESTS_SLACK  # 256 is a
                          # deliberately small lower bound on a plausible real
                          # data_block_len, so this cap is loose in the
                          # direction of "allow more requests", not tight
    requests_seen = 0
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = sock.recv(4096)
        except socket.timeout:
            continue
        if not r:
            log("  connection closed while waiting for a chunk request")
            return "error", seq
        info = lpv35.peek(r, key=session_key, mode=mode)
        if not info.get("decrypted"):
            log("  could not decode a frame while waiting for a chunk request: %s"
                % info.get("error"))
            continue
        cmd = info.get("cmd")
        body = info.get("body") or b""
        if cmd == FRAME_OTA_END:
            log("  *** cmd 0x1C (OTA_END) received -- device considers the transfer done ***")
            # DO NOT return immediately. On a successful apply the device keeps working
            # AFTER 0x1C -- the apply runs in this same session: a real device's log
            # shows `write_total: 65536 ... 750592`, then `Verify the new firmware`, then
            # `jump to:0x10000`, all following the 0x1C. An earlier version of this
            # script closed the socket the instant 0x1C arrived, the apply never ran,
            # and the unit kept booting its old firmware -- which read as "the image
            # staged but did not apply" rather than "we hung up on it mid-apply".
            #
            # Hold the session open and drain, logging anything the device says.
            drain_until = time.time() + APPLY_DRAIN_SECONDS
            while time.time() < drain_until:
                try:
                    r2 = sock.recv(4096)
                except socket.timeout:
                    continue
                except OSError:
                    log("  connection closed by device during apply drain")
                    break
                if not r2:
                    log("  device closed the session (apply finished or device rebooted)")
                    break
                info2 = lpv35.peek(r2, key=session_key, mode=mode)
                if info2.get("decrypted"):
                    log("  [post-0x1C] cmd=%s body=%r"
                        % (info2.get("cmd"), (info2.get("body") or b"")[:120]))
            return "done", seq
        if cmd != lpv35.CMD_OTA_DATA:
            log("  unexpected cmd %s while waiting for a chunk request: %r" % (cmd, body[:100]))
            continue

        requests_seen += 1
        if requests_seen > max_requests:
            log("  !! %d chunk requests seen for a %d-byte image -- stopping rather than "
                "risk a runaway loop" % (requests_seen, image_len))
            return "stalled", seq

        try:
            req = json.loads(body.decode())
            offset = int(req["file_offset"])
            length = int(req["data_block_len"])
        except (ValueError, KeyError, TypeError, UnicodeDecodeError) as e:
            log("  cmd 0x1B with a non-request body (likely the device's own abort/error "
                "signal, not a chunk request): %r (%s)" % (body[:100], e))
            return "aborted", seq

        if length <= 0 or not (0 <= offset < image_len):
            log("  !! device requested an out-of-range chunk (offset=%d len=%d, image is "
                "%d bytes) -- stopping" % (offset, length, image_len))
            return "error", seq

        chunk = image[offset:offset + length]
        log("  device requests offset=%d len=%d -> sending %d bytes" % (offset, length, len(chunk)))
        seq += 1
        try:
            reply = lpv35.build_frame(FRAME_OTA_DATA, chunk, seq=seq, key=session_key, mode=mode)
            sock.sendall(reply)
        except (ValueError, lpv35.FrameError, OSError) as e:
            log("  !! could not send the chunk reply: %s" % e)
            return "error", seq

        if max_chunks is not None and requests_seen >= max_chunks:
            log("  %d of %d requested chunk(s) answered -- stopping here as requested "
                "(--max-chunks), not continuing to a full transfer" % (requests_seen, max_chunks))
            return "limit-reached", seq

    log("  timed out waiting for the next chunk request or a completion signal")
    return "timeout", seq


# ---------------------------------------------------------------------------
# Step 4 -- serve the image
# ---------------------------------------------------------------------------

def serve_image(path, bind):
    """Minimal HTTP server -- NOT used by the LAN 0x1A entrypoint.

    Confirmed unused there: the device requests chunks over the LAN session
    itself, answered directly by `answer_ota_data()`. This exists only for
    the MQTT entrypoint, whose grammar carries `url`/`diffUrl` directly --
    not implemented by this script, which drives the LAN path.
    """
    from http.server import BaseHTTPRequestHandler, HTTPServer

    host, _, port = bind.partition(":")
    port = int(port or 8000)

    class H(BaseHTTPRequestHandler):
        def do_GET(self):                                   # noqa: N802
            with open(path, "rb") as f:
                body = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            log("served %d bytes to %s" % (len(body), self.client_address[0]))

        def log_message(self, *args):                       # noqa: A003
            pass

    srv = HTTPServer((host, port), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    log("serving %s on %s:%d" % (path, host, port))
    # The unit pulls this image over an *inbound* TCP connection, which Windows
    # Firewall drops by default. Offer a scoped rule (program + port + local
    # subnet + non-public profiles). The server is a daemon thread that dies
    # with the process, so the rule is torn down from atexit rather than from a
    # finally block this function never returns into.
    try:
        import atexit
        import winfw
        rule = winfw.offer("TuyaBK7238-serve-%d" % port, "TCP", port)
        rule.__enter__()
        atexit.register(rule.__exit__, None, None, None)
    except ImportError:
        log("(tools/winfw.py not importable -- no firewall rule offered)")
    return srv


# ---------------------------------------------------------------------------
# Step 5 -- drive the OTA
# ---------------------------------------------------------------------------

def cmd_run(a):
    image = check_image(a.image, a.patch_magic)
    if image is None:
        return 1

    if a.auto_hmac is not None:
        fh = compute_file_hmac(image, a.auto_hmac)
        log("fileHmac (auto): %s  [HMAC-SHA256(secKey, hex-upper(SHA256(image)))]" % fh)
    elif a.filehmac:
        fh = a.filehmac
        log("fileHmac (explicit): %s" % fh)
    else:
        fh = "00" * 32
        log("fileHmac: placeholder -- the LAN completion check WILL compare it "
            "(fn 0x072FE4, unconditional); a full transfer to cmd 0x1C will fail "
            "with 'file hmac check fail' unless --filehmac supplies the real "
            "value. Get it from the device: with this dummy in place, log level 4 "
            "prints its own calculated_hamc at tuya_svc_upgrade.c:622 -- re-run "
            "with --filehmac <that digest>")

    body = build_ota_start(len(image), a.version, a.channel, filehmac=fh)
    log("0x1A body: %s" % body.decode())

    if a.dry_run:
        log("dry run: the envelope is 6699/AES-%s, cmd at 0x0a, L = payload + 0x1c"
            % a.mode.upper())
        try:
            blob = lpv35.build_frame(FRAME_OTA_START, body, seq=a.start_seq + 3,
                                     key=bytes(16), mode=a.mode)
            log("  0x1A frame would be %d bytes: %s" % (len(blob), hx(blob, 64)))
        except (ValueError, lpv35.FrameError) as e:
            log("  could not build the 0x1A frame: %s" % e)
        try:
            lpv35.selftest(verbose=False)
            log("  envelope self-test passed")
        except Exception as e:                              # noqa: BLE001
            log("  envelope self-test raised: %s" % e)
        log("dry run -- nothing sent")
        return 0

    if a.serve:
        serve_image(a.image, a.serve)

    sock = socket.create_connection((a.host, a.port), timeout=a.timeout)
    sock.settimeout(a.timeout)
    log("connected to %s:%d" % (a.host, a.port))

    session_key = lan_handshake(sock, a.localkey, mode=a.mode, start_seq=a.start_seq)
    if session_key is None:
        log("handshake failed -- aborting")
        if a.mode == "gcm":
            log("if cmd 3 got no reply at all, retry with --mode cbc")
        sock.close()
        return 1

    # Past the handshake, frames are sealed with the session key.
    seq = a.start_seq + 3
    try:
        blob = lpv35.build_frame(FRAME_OTA_START, body, seq=seq, key=session_key,
                                 mode=a.mode)
    except (ValueError, lpv35.FrameError) as e:
        log("could not build the 0x1A frame: %s" % e)
        sock.close()
        return 1

    log("sending 0x1A seq=%d, %d bytes" % (seq, len(blob)))
    try:
        sock.sendall(blob)
    except OSError as e:
        log("  send failed: %s" % e)
        sock.close()
        return 1

    try:
        r = sock.recv(4096)
    except socket.timeout:
        log("  no reply to 0x1A within the timeout")
        sock.close()
        return 1
    if not r:
        log("  connection closed after 0x1A")
        sock.close()
        return 1

    info = lpv35.peek(r, key=session_key, mode=a.mode)
    log("  reply %d bytes: %s" % (len(r), hx(r, 256)))
    if info.get("decrypted"):
        log("  retcode=%s body=%r" % (info.get("retcode"), info.get("body")))
        if info.get("retcode") not in (0, None):
            log("  the device refused the OTA start (retcode %s)" % info.get("retcode"))
    else:
        log("  could not decode the reply: %s" % info.get("error"))
    log("  -> if this reached the device, it will now start requesting chunks")

    # The device requests its own chunks over this same session (cmd 0x1B,
    # {"file_offset","data_block_len"}). The progress callback 0x072974 that
    # sets mgr[0x14] (the completion-check skip, see the module docstring)
    # already fired before the 0x1A reply above; this loop is purely about
    # actually delivering the bytes once that gate is open.
    log("answering chunk requests...")
    status, seq = answer_ota_data(sock, session_key, image, a.mode, seq, a.wait,
                                   max_chunks=a.max_chunks)
    log("chunk-transfer status: %s" % status)
    if status == "done":
        log("*** transfer complete and the session was held open for the apply. If the device "
            "applied it, it is rebooting now -- watch for :6668 closing. ***")
    elif status == "limit-reached":
        log("*** stopped deliberately after --max-chunks=%d -- gate + chunk delivery "
            "confirmed, no full transfer attempted ***" % a.max_chunks)
    elif status == "aborted":
        log("the device aborted the transfer -- see the body logged just above.")
    else:
        log("the transfer did not complete cleanly (%s) -- see the log above for where "
            "it stopped." % status)

    sock.close()
    return 0 if status in ("done", "limit-reached") else 1


# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    lk = sub.add_parser("localkey", help="enumerate local_key from the Tuya OpenAPI "
                        "(reads TUYA_ACCESS_ID/TUYA_ACCESS_SECRET from the environment)")
    lk.add_argument("--device-id", required=True)
    lk.add_argument("--region", choices=list(TUYA_REGIONS), default=None,
                     help="data center to query; default tries all, eu first")
    lk.set_defaults(func=cmd_localkey)

    r = sub.add_parser("run", help="drive the LAN 0x1A OTA with a magic-carrying image")
    r.add_argument("--host", required=True)
    r.add_argument("--port", type=int, default=DEFAULT_PORT)
    r.add_argument("--localkey", required=True)
    r.add_argument("--image", required=True)
    r.add_argument("--version", default="1.0.0")
    r.add_argument("--channel", default="0")
    r.add_argument("--patch-magic", action="store_true",
                   help="insert 'ISBA' at offset %d if the image lacks a magic there"
                        % MAGIC_OFFSET)
    r.add_argument("--mode", choices=["gcm", "cbc"], default="gcm",
                   help="AEAD mode; retry with cbc if gcm gets no reply")
    r.add_argument("--start-seq", type=int, default=1,
                   help="first sequence number (default 1; must increase per frame)")
    r.add_argument("--serve", default=None, metavar="HOST:PORT",
                   help="serve the image over HTTP -- NOT used by the LAN 0x1A entrypoint "
                        "(it pulls chunks over the LAN session itself, answered by this "
                        "script directly); kept only for the MQTT entrypoint's "
                        "url/diffUrl grammar, not implemented here")
    r.add_argument("--dry-run", action="store_true")
    r.add_argument("--timeout", type=float, default=8.0)
    r.add_argument("--wait", type=float, default=300.0,
                   help="time budget for the WHOLE chunked transfer, not just one reply "
                        "(default 300s; a several-hundred-KB image needs hundreds of "
                        "chunk round trips)")
    r.add_argument("--max-chunks", type=int, default=None,
                   help="stop after answering this many cmd 0x1B chunk requests, instead "
                        "of running the transfer to completion -- e.g. --max-chunks 1 to "
                        "confirm the gate opens and one chunk is accepted without flashing "
                        "the whole image")
    r.add_argument("--filehmac", default=None, metavar="HEX64",
                   help="explicit fileHmac value for the 0x1A body (64 hex chars); the LAN "
                        "completion check compares it unconditionally, so a full transfer "
                        "to cmd 0x1C needs the real value")
    r.add_argument("--auto-hmac", default=None, metavar="SECKEY",
                   help="compute fileHmac = hex(HMAC-SHA256(SECKEY, "
                        "hex-upper(SHA256(image)))) -- CONFIRMED on hardware. "
                        "Uppercase is mandatory. Note this only works on a FULL "
                        "transfer: the digest is compared at the END, so "
                        "--max-chunks 1 cannot validate it")
    r.set_defaults(func=cmd_run)

    a = p.parse_args()
    return a.func(a)


if __name__ == "__main__":
    sys.exit(main())
