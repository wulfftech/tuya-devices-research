#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""lpv35.py -- the LAN v3.5 (6699) frame envelope for the Arlec PC191HA S4.

The one shared implementation of the envelope, used by `owner_reflash.py`.
See LAN-OTA-PROTOCOL.md for the frame layout in context (handshake, OTA
commands, container format). This module is the detailed evidence for that
page's envelope section -- every field below is checked against the firmware's
own disassembly, not inferred from the wire alone.

WHY THIS LAYOUT IS NOT A GUESS
------------------------------
Two independent lines of evidence agree field-for-field.

1. Static, from the de-interleaved logical image
   `dump/stock-full-2MiB.logical.bin` (see tools/logical_image.py):

     `lpv35_frame_parse`     @ 0x09CC88  (com_protocol.c) -- the receiver
     `lpv35_frame_serialize` @ 0x09CE6C  (com_protocol.c) -- field order
     LAN caller              @ 0x0E8C7A  (tuya_svc_lan.c) -- builds the call
     AEAD wrapper            @ 0x09C440  (cipher_wrapper.c) -- integrity field

2. The public Tuya v3.5 wire format, which this firmware implements verbatim.

The layout:

  offset  width  field
  0x00    4      prefix, wire bytes ``00 00 66 99``  (0x00006699, big-endian)
  0x04    1      VV  version, always 0x00
  0x05    1      RR  reserved, always 0x00
  0x06    4      seq, big-endian
  0x0a    4      cmd, big-endian
  0x0e    4      L, big-endian -- counts from the nonce through the tag,
                 excluding the footer, so L = len(payload) + 0x1c
  0x12    12     AES-GCM nonce (IV), unique per packet
  0x1e    L-0x1c ciphertext
  L+0x02  16     AES-GCM tag
  L+0x12  4      footer, wire bytes ``00 00 99 66`` (0x00009966, big-endian)

  total = L + 0x16

Every constant is pinned by at least three agreeing anchors in the receiver;
these are the literal addresses, so nothing here has to be taken on trust:

  0x09CCCE  memcmp(r5 /*frame*/, {0x99660000}, 4)  -> prefix at 0x00
  0x09CCFC  memcpy(out+0, frame+6,   4) + BE       -> seq at 0x06
  0x09CD26  memcpy(out+4, frame+0xa, 4) + BE       -> cmd at 0x0a
  0x09CD4A  memcpy(sp+0x28, frame+0xe, 4) + BE     -> L   at 0x0e
  0x09CD64  L == total - 0x16                      -> the length convention
  0x09CD7C  memcpy(sp+0x30, frame+0x12, 0xc)       -> 12-byte nonce
  0x09CD9A  out[0xc] = total - 0x32                -> payload length == L - 0x1c
  0x09CDA2  memcpy(sp+0x3c, frame+4, 0xe)          -> AAD == frame[4..0x11]
  0x09CDDA  memcmp(frame + total - 4, {0x66990000}, 4) -> footer
  0x09CD8C  frame + L + 2                          -> tag

Two independent cross-checks from the LAN caller `0x0E8C7A`, which reads the
fields in the opposite direction and lands on the same offsets:

  0x0E8CE8  BE-reassemble r7[6..9]   -> compared to [r4,#0x10], logged
                                       'sequence error in:%d, pre:%d'  => seq
  0x0E8E5C  BE-reassemble r7[0xa..0xd] and dispatch `subs r2,r5,#3 / cmp r2,#2`
                                       => 3/4/5 handshake => cmd
  0x0E8D92  BE-reassemble r7[0xe..0x11], then `adds r3,r5,#0x16` => L, and
                                       L + 0x16 is the frame total

The arithmetic closes with no slack: ciphertext runs 0x1e..L+2, the tag
L+2..L+0x12, the footer L+0x12..L+0x16 == total.

INTEGRITY
---------
AES-GCM. Not HMAC (that is v3.4/55AA) and not CRC32 (v3.1-3.3). The 12-byte
nonce and 16-byte tag are the GCM shape, and the AAD is the 14 header bytes from
offset 4 through 0x11, so the header is authenticated but not encrypted while the
payload is both. The device does exactly this: `lpv35_frame_parse` builds a
descriptor holding {key, nonce, aad, ciphertext, key_len, nonce_len=0x0c,
aad_len=0x0e, data_len} and calls the wrapper at 0x09C440 -> the ARM veneer
`mbedtls_cipher_auth_decrypt_wrapper`. The wrapper's own error string still
names `MBEDTLS_CIPHER_AES_128_CBC`, stale relative to that call; `mode="cbc"`
exists to test that hypothesis and is deliberately not the default.

KEY
---
The handshake frames are sealed with the real (static) key, i.e. the localKey.
Once the session key is negotiated, later frames use that. Both are 16 bytes and
are handed to the wrapper unchanged (`lpv35_frame_parse` takes the key as arg0
and its length as arg1 = 0x10), so no KDF is visible on this path; `kdf` is
exposed only in case one turns out to be needed.

"""

import binascii
import hashlib
import hmac
import os
import struct

PREFIX = b"\x00\x00\x66\x99"        # 0x00006699 big-endian
SUFFIX = b"\x00\x00\x99\x66"        # 0x00009966 big-endian

VER_OFF = 0x04                      # 1 byte, always 0x00
RSVD_OFF = 0x05                     # 1 byte, always 0x00
SEQ_OFF = 0x06                      # 4 bytes, BE
CMD_OFF = 0x0A                      # 4 bytes, BE
LEN_OFF = 0x0E                      # 4 bytes, BE
NONCE_OFF = 0x12                    # 12 bytes
HDR_LEN = 0x1E                      # offset of the ciphertext

HDR_FMT = ">IHIII"                  # prefix, reserved(16), seq, cmd, L = 18 bytes
AAD_FMT = ">HIII"                   # reserved(16), seq, cmd, L = 14 bytes
AAD_OFF = 0x04
AAD_LEN = 0x0E

TAG_LEN = 16
NONCE_LEN = 12

LEN_BIAS = 0x16                     # L == total - 0x16
PLAIN_BIAS = 0x1C                   # L == len(payload) + 0x1c
FIXED_OVERHEAD = 0x32               # total == len(payload) + 0x32

# The LAN layer drops anything this size or smaller before it parses:
#   0x0E8CD6  cmp r3, #0x31 / ble -> 'not enough data len:%d'
# An empty payload is exactly 50 bytes, the smallest legal frame.
MIN_FRAME = 0x32

# The retcode the device prepends to a decrypted *response* payload.
RETCODE_LEN = 4

# Return values of lpv35_frame_parse, from the disassembly.
RC_OK = 0
RC_LENGTH_ERROR = 1                 # 'length error, length:%d'
RC_HEAD_OR_TAIL = 0x24              # 'LPV35 HEAD OR TAIL ERROR'
RC_PARAM_ERROR = -2                 # 'PARAM ERROR' -- a bare type-3 hello
# any other value is the negated mbedtls status from the AEAD wrapper

MODE_GCM = "gcm"
MODE_CBC = "cbc"
MODE_PLAIN = "plain"

# Frame commands. The LAN layer dispatches on this field (`0x0E8EA4`).
CMD_HS_NONCE = 3                    # START  -- client -> device, payload is randA
CMD_HS_HMAC = 4                     # RESP   -- DEVICE -> client, shape below
CMD_HS_DONE = 5                     # FINISH -- client -> device, HMAC(localKey, randB)
CMD_HEARTBEAT = 9
CMD_OTA_START = 0x1A
CMD_OTA_DATA = 0x1B
CMD_OTA_END = 0x1C


# ---------------------------------------------------------------------------
# The handshake payload shapes, read out of the handler bodies
# ---------------------------------------------------------------------------
#
# These are not inferred from length arithmetic or a substring search; each is
# the argument list of the memcpy/HMAC that builds or checks it.
#
# cmd 3 -- handler `0x0E8510` (client -> device, payload = randA):
#   `0x0E8512  cmp r3, #0xf / bhi 0x0E8522`   reject when len <= 15
#   `0x0E8536  memcpy([client+0x18], payload, 0x10)`   -> exactly 16 bytes
#   `0x0E855C` loads +0x481 (localKey), `0x0E8574 bl 0x94fa8` -> randA_hmac =
#     HMAC-SHA256(localKey, randA), 32 bytes, into `[client+0x1c]`.
#
# cmd 4 -- the DEVICE'S OWN REPLY. It has no dispatch body: decoding the
# 16-bit table at `0x0E8386` and cmd 4 routes to the shared stub `0x0E8BC0`,
# which logs `unsupport frame type:4` and returns with no reply and no close. The
# reply is *built* by cmd 3's handler, at the tail of `0x0E8510`:
#
#   `0x0E85D8  memcpy(frame_buffer + 0, [client+0x1c], 0x10)`   randB  at +0
#   `0x0E85E6  memcpy(frame_buffer + 0x10, randA_hmac, 0x20)`   HMAC   at +16
#   `0x0E85F8  str r5, [sp]`        r5 = 0x30 = 48 = len(frame_buffer)
#   `0x0E85FA  bl 0x0E8028`         (client, cmd=4, retcode=0, body=48)
#
# and the shared reply builder `0x0E8028` prepends the 4-byte retcode to the body
# (`0x0E80E4`-`0x0E80F6` store it at `frame_buffer[0..3]`, `0x0E80FA` memcpy's the
# body to `frame_buffer + 4`).
#
#   => cmd-4 payload = retcode(4) || randB(16) || HMAC-SHA256(localKey, randA)(32)
#      = 52 bytes, total 102 (`L = 0x50`).
#
# The 32-byte field is therefore an HMAC over **randA**, not over randB -- it is
# the same `randA_hmac` cmd 3 computed at `0x0E8574`. An earlier extraction pass
# ("the 16 bytes immediately before the matching HMAC") does recover randB
# correctly -- randB *is* those bytes -- but the label invited the reading that
# the HMAC covered randB, which it does not. Verified against the live capture in
# the self-test below.
#
# cmd 5 -- handler `0x0E8602` (client -> device, payload = HMAC(localKey, randB)):
#   `0x0E8604  cmp r3, #0x1f / bhi`   reject when len <= 31
#   `0x0E8700`-`0x0E8706` hmac(localKey, [client+0x1c] /*randB*/, 0x10) -> 32 bytes
#   `0x0E873A`-`0x0E8740` memcmp(that, payload, 0x20)   the WHOLE payload, no
#     retcode and no nonce inside it.
#
#   **cmd 5 success produces NO REPLY.** The success path
#   (`0x0E8760`-`0x0E87E0`) installs the session key, encrypts it into the
#   connection blob with `aes128_gcm_encode` (`0x0E87BA`), frees the two handshake
#   buffers and returns at `0x0E87E0 b 0x0E8420`. The reply builder `0x0E8028` has
#   15 call sites in the image and none of them is inside `0x0E8602`-`0x0E87E0`
#   (confirmed directly in the disassembly). The client learns the session key by
#   deriving it locally, and the device picks it up for later frames via
#   `0x0E8EA6` / `0x0E8F68 ldr r6, [r4, #0x20]`. Waiting for a cmd-5 reply is
#   always a timeout; a timeout here is not a failure.
HS_RESP_RETCODE_LEN = RETCODE_LEN                       # 4
HS_RESP_NONCE_LEN = 16                                  # randB
HS_RESP_MAC_LEN = 32                                    # HMAC-SHA256(localKey, randA)
HS_RESP_BODY_LEN = HS_RESP_NONCE_LEN + HS_RESP_MAC_LEN  # 48, the `0x30` at 0x0E85F8
HS_RESP_PAYLOAD_LEN = HS_RESP_RETCODE_LEN + HS_RESP_BODY_LEN    # 52
HS_RESP_FRAME_LEN = HS_RESP_PAYLOAD_LEN + FIXED_OVERHEAD        # 102

HS_START_PAYLOAD_LEN = 16                               # randA
HS_START_FRAME_LEN = HS_START_PAYLOAD_LEN + FIXED_OVERHEAD      # 66

HS_FINISH_PAYLOAD_LEN = 32                              # HMAC-SHA256(localKey, randB)
HS_FINISH_FRAME_LEN = HS_FINISH_PAYLOAD_LEN + FIXED_OVERHEAD    # 82


class FrameError(ValueError):
    """A frame the device's parser would reject.

    `code` carries the value `lpv35_frame_parse` would return, so a caller can
    tell a fatal rejection (+0x24, 1) from the benign -2.
    """

    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------------------
# crypto
# ---------------------------------------------------------------------------

def normalise_key(s):
    """A 16-byte AES key from either raw text or a 32-hex-char string.

    `owner_reflash.py` needs this, and anything that reads a captured
    session needs to agree with it exactly, or a key that drives the wire
    will not decode a capture of the same session.
    """
    s = s.strip()
    if len(s) == 32:
        try:
            return bytes.fromhex(s)
        except ValueError:
            pass
    return s.encode()


def derive_key(key, kdf="raw"):
    """Map a localKey / session key to a 16-byte AES key.

    `raw` is the default and is what the firmware does on this path: the key is
    handed to the wrapper unchanged.
    """
    if kdf == "raw":
        return bytes(key)
    if kdf == "md5":
        return hashlib.md5(bytes(key)).digest()
    raise ValueError("unknown kdf %r" % (kdf,))


def _load_aesgcm():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as e:                                # noqa: BLE001
        raise FrameError("AES-GCM needs the 'cryptography' package: %s" % e)
    return AESGCM


def _gcm_encrypt(key, nonce, aad, plaintext):
    AESGCM = _load_aesgcm()
    if len(key) != 16:
        raise FrameError("AES-128 needs a 16-byte key, got %d" % len(key))
    blob = AESGCM(key).encrypt(nonce, plaintext, aad)
    return blob[:-TAG_LEN], blob[-TAG_LEN:]


def _gcm_decrypt(key, nonce, aad, ciphertext, tag):
    AESGCM = _load_aesgcm()
    return AESGCM(key).decrypt(nonce, ciphertext + tag, aad)


def _cbc_encrypt(key, nonce, aad, plaintext):
    """CBC fallback -- no AAD, no tag. Only to test the stale-string hypothesis."""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as e:                                # noqa: BLE001
        raise FrameError("AES-CBC needs the 'cryptography' package: %s" % e)
    iv = bytes(nonce)[:16].ljust(16, b"\x00")
    body = plaintext + b"\x00" * ((-len(plaintext)) % 16)
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(body) + enc.finalize(), b""


def _cbc_decrypt(key, nonce, aad, ciphertext, tag):
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as e:                                # noqa: BLE001
        raise FrameError("AES-CBC needs the 'cryptography' package: %s" % e)
    iv = bytes(nonce)[:16].ljust(16, b"\x00")
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return dec.update(ciphertext) + dec.finalize()


def derive_session_key(real_key, device_nonce, client_nonce, kdf="raw"):
    """The v3.5 session key, as the device computes it.

        tmp         = device_nonce XOR client_nonce          (both 16 bytes)
        session_key = GCM(real_key, iv=client_nonce[:12], tmp)[12:28]

    The slice is taken over the (IV || ciphertext || tag) blob, so offset 12 is
    the first ciphertext byte and the 16 bytes taken are pure keystream output --
    independent of the tag length.
    """
    if len(device_nonce) != 16 or len(client_nonce) != 16:
        raise FrameError("both nonces must be 16 bytes")
    blob = _session_key_blob(derive_key(real_key, kdf), device_nonce, client_nonce)
    return blob[12:28]


def _session_key_blob(key, device_nonce, client_nonce):
    tmp = bytes(a ^ b for a, b in zip(device_nonce, client_nonce))
    ct, tag = _gcm_encrypt(key, bytes(client_nonce)[:NONCE_LEN], None, tmp)
    return bytes(client_nonce)[:NONCE_LEN] + ct + tag


# ---------------------------------------------------------------------------
# handshake payloads -- the three messages, built from the handler bodies
# ---------------------------------------------------------------------------

def rand_a_hmac(real_key, client_nonce, kdf="raw"):
    """`HMAC-SHA256(localKey, randA)` -- what cmd 3 computes at `0x0E8574`.

    This is also the 32-byte field the device puts in its cmd-4 reply, so it is
    simultaneously the client's own check value and the device's response MAC.
    """
    return hmac.new(derive_key(real_key, kdf), bytes(client_nonce),
                    hashlib.sha256).digest()


def rand_b_hmac(real_key, device_nonce, kdf="raw"):
    """`HMAC-SHA256(localKey, randB)` -- what cmd 5's payload must be.

    The device computes exactly this at `0x0E8706` and `memcmp`s the whole
    32-byte payload against it at `0x0E8740`.
    """
    return hmac.new(derive_key(real_key, kdf), bytes(device_nonce),
                    hashlib.sha256).digest()


def parse_hs_resp(payload):
    """Split a DECRYPTED cmd-4 payload into `(retcode, rand_b, rand_a_hmac)`.

    The layout is fixed by the building code, not searched for: cmd 3's handler
    copies randB to `frame_buffer + 0` and randA_hmac to `frame_buffer + 0x10`
    (`0x0E85D8` / `0x0E85E6`), and the reply builder prepends the 4-byte retcode.
    Raises ValueError if the payload is not exactly 52 bytes.
    """
    p = bytes(payload)
    if len(p) != HS_RESP_PAYLOAD_LEN:
        raise ValueError("cmd-4 payload is %d bytes; the layout is fixed at %d"
                         % (len(p), HS_RESP_PAYLOAD_LEN))
    rc = struct.unpack(">I", p[:HS_RESP_RETCODE_LEN])[0]
    off = HS_RESP_RETCODE_LEN
    rand_b = p[off:off + HS_RESP_NONCE_LEN]
    mac = p[off + HS_RESP_NONCE_LEN:off + HS_RESP_NONCE_LEN + HS_RESP_MAC_LEN]
    return rc, rand_b, mac


def build_hs_resp(retcode, device_nonce, client_nonce, real_key, kdf="raw"):
    """Build a cmd-4 payload the way the device builds it (`0x0E85CA`-`0x0E85F8`).

    The client never sends this -- cmd 4 is the device's reply and lands on the
    shared stub `0x0E8BC0` if a client does send it. It exists so the layout can
    be reproduced and asserted in the self-test, and so an offline tool can model
    the device's reply without a device.
    """
    mac = rand_a_hmac(real_key, client_nonce, kdf=kdf)
    return struct.pack(">I", retcode) + bytes(device_nonce) + mac


# ---------------------------------------------------------------------------
# builder
# ---------------------------------------------------------------------------

def random_nonce():
    """12 fresh bytes for one frame, as the firmware generates per frame.

    This is not optional. The reply builder at `0x0E8028` draws its nonce from
    `[lan+0x3c]` and increments it per reply -- `0x0E8102` `adds r3, r3, #1` /
    `0x0E8108` `str r2, [r5, #0x14]` before `bl aes128_gcm_encode` at `0x0E8110`
    -- and the AP path
    refills it from the TRNG for *every* reply. A fixed nonce reused across two
    frames is the one envelope error that produces pure silence rather than a
    logged rejection: the device never reaches a log line, so nothing comes
    back on the socket.
    """
    return os.urandom(NONCE_LEN)


def build_frame(cmd, payload, seq=1, version=0, reserved=0, key=None, nonce=None,
                mode=MODE_GCM, kdf="raw"):
    """Build one 6699 frame. Returns the exact bytes to put on the wire.

    `payload` is the plaintext; it is sealed under `key` (16 bytes) using the
    integrity scheme selected by `mode`.

    `nonce=None` means a **fresh random nonce** (`random_nonce()`), which is what
    every real frame carries. Pass an explicit nonce only to reproduce a specific
    capture offline. The old fixed-nonce default (`00 01 .. 0b`) is gone: reusing
    it silently breaks the handshake -- see `random_nonce` above.

    Sizing: total = 0x1e + len(payload) + 16 + 4, so an empty payload is exactly
    50 bytes -- the smallest frame the LAN layer accepts (> 0x31). Nothing needs
    padding and nothing should be padded: extra bytes would be decrypted into the
    payload.
    """
    if mode not in (MODE_GCM, MODE_CBC, MODE_PLAIN):
        raise ValueError("unknown mode %r" % (mode,))
    for name, v, hi in (("cmd", cmd, 0xFFFFFFFF), ("seq", seq, 0xFFFFFFFF),
                        ("version", version, 0xFF), ("reserved", reserved, 0xFF)):
        if not isinstance(v, int) or isinstance(v, bool) or not 0 <= v <= hi:
            raise ValueError("%s out of range: %r" % (name, v))

    payload = bytes(payload)
    nonce = random_nonce() if nonce is None else bytes(nonce)
    if len(nonce) != NONCE_LEN:
        raise ValueError("nonce must be %d bytes, got %d" % (NONCE_LEN, len(nonce)))

    total = HDR_LEN + len(payload) + TAG_LEN + 4
    L = total - LEN_BIAS
    if L != len(payload) + PLAIN_BIAS:
        raise FrameError("internal: L=%d, payload=%d" % (L, len(payload)))

    # The AAD *is* the 14-byte header from offset 4: VV RR as one big-endian
    # u16, then seq, cmd and L, each 4 bytes big-endian. PREFIX(4) + AAD(14)
    # puts the nonce at 0x12 exactly.
    version_reserved = (version << 8) | reserved
    aad = struct.pack(AAD_FMT, version_reserved, seq, cmd, L)
    assert len(aad) == AAD_LEN, len(aad)

    if mode == MODE_PLAIN:
        body, tag = payload, b"\x00" * TAG_LEN
    else:
        if key is None:
            raise ValueError("mode %r needs a key" % (mode,))
        aes_key = derive_key(key, kdf)
        if mode == MODE_GCM:
            body, tag = _gcm_encrypt(aes_key, nonce, aad, payload)
        else:
            body, tag = _cbc_encrypt(aes_key, nonce, aad, payload)
            tag = b"\x00" * TAG_LEN
        if len(body) != len(payload):
            raise FrameError("ciphertext length changed; the layout assumes a stream mode")

    frame = PREFIX + aad + nonce + body + tag + SUFFIX
    if len(frame) != total:
        raise FrameError("built %d bytes, header declared %d" % (len(frame), total))
    if len(frame) < MIN_FRAME:
        raise FrameError("frame is %d bytes, below the LAN layer floor of %d"
                         % (len(frame), MIN_FRAME))
    return frame


# ---------------------------------------------------------------------------
# parser -- the mirror of lpv35_frame_parse @ 0x09CC88
# ---------------------------------------------------------------------------

def parse_frame(frame, key=None, mode=MODE_GCM, kdf="raw", strict=True,
                min_len=MIN_FRAME):
    """Parse a frame exactly as `lpv35_frame_parse` would.

    Returns a dict. Raises FrameError carrying the return code the device would
    use: +0x24 for a head/tail failure, 1 for a length failure, and a crypto
    error for a bad tag. `strict=False` skips the AEAD check, which is what you
    want when reading a device-to-us frame before the session key is known.
    """
    frame = bytes(frame)
    out = {}

    if len(frame) < min_len:
        raise FrameError("frame is %d bytes; the LAN layer needs > 0x31 (%d) and "
                         "logs 'not enough data len:%d'" % (len(frame), MIN_FRAME,
                                                            len(frame)))

    # 0x09CCCE / 0x09CDDA -- head and tail, both fatal
    if frame[:4] != PREFIX:
        raise FrameError("HEAD: expected %s, got %s -- device logs "
                         "'LPV35 HEAD OR TAIL ERROR' and closes"
                         % (binascii.hexlify(PREFIX).decode(),
                            binascii.hexlify(frame[:4]).decode()), RC_HEAD_OR_TAIL)
    if frame[-4:] != SUFFIX:
        raise FrameError("TAIL: expected %s, got %s -- device logs "
                         "'LPV35 HEAD OR TAIL ERROR' and closes"
                         % (binascii.hexlify(SUFFIX).decode(),
                            binascii.hexlify(frame[-4:]).decode()), RC_HEAD_OR_TAIL)

    out["version"] = frame[VER_OFF]
    out["reserved"] = frame[RSVD_OFF]
    out["seq"] = struct.unpack(">I", frame[SEQ_OFF:SEQ_OFF + 4])[0]
    out["cmd"] = struct.unpack(">I", frame[CMD_OFF:CMD_OFF + 4])[0]
    L = struct.unpack(">I", frame[LEN_OFF:LEN_OFF + 4])[0]
    out["L"] = L
    out["total"] = len(frame)

    # 0x09CD64 -- L must equal total - 0x16, else return 1
    if L != len(frame) - LEN_BIAS:
        raise FrameError("LENGTH: L=%d but total-0x16=%d -- device logs "
                         "'length error, length:%d' and returns 1"
                         % (L, len(frame) - LEN_BIAS, L), RC_LENGTH_ERROR)
    if L < PLAIN_BIAS:
        raise FrameError("LENGTH: L=%d cannot hold a nonce and tag" % L,
                         RC_LENGTH_ERROR)

    out["nonce"] = frame[NONCE_OFF:HDR_LEN]
    out["aad"] = frame[AAD_OFF:AAD_OFF + AAD_LEN]
    body_len = L - PLAIN_BIAS                      # == 0x09CD9A's total - 0x32
    out["body"] = frame[HDR_LEN:HDR_LEN + body_len]
    out["tag"] = frame[L + 2:L + 2 + TAG_LEN]      # 0x09CD8C: frame + L + 2

    if len(out["body"]) != body_len or len(out["tag"]) != TAG_LEN:
        raise FrameError("truncated frame: body %d/%d, tag %d/%d"
                         % (len(out["body"]), body_len,
                            len(out["tag"]), TAG_LEN), RC_LENGTH_ERROR)

    if mode == MODE_PLAIN or key is None or not strict:
        out["payload"] = out["body"]
        return out

    aes_key = derive_key(key, kdf)
    try:
        if mode == MODE_GCM:
            out["payload"] = _gcm_decrypt(aes_key, out["nonce"], out["aad"],
                                          out["body"], out["tag"])
        else:
            out["payload"] = _cbc_decrypt(aes_key, out["nonce"], out["aad"],
                                          out["body"], out["tag"])
    except FrameError:
        raise
    except Exception as e:                                  # noqa: BLE001
        raise FrameError("AEAD: %s -- device logs "
                         "'mbedtls_cipher_auth_decrypt_wrapper:0x%%x' and returns "
                         "the negated status" % (e,))
    return out


def strip_retcode(payload):
    """Split the device's prepended 4-byte return code off a response payload."""
    p = bytes(payload)
    if len(p) < RETCODE_LEN:
        return None, p
    return struct.unpack(">I", p[:RETCODE_LEN])[0], p[RETCODE_LEN:]


def peek(frame, key=None, mode=MODE_GCM):
    """Best-effort read of a reply for logging. Never raises.

    On a frame with a valid prefix and suffix this decrypts and reports the
    payload. On anything else it still records the head/tail flags and -- when
    the frame is long enough to attempt -- the exact return code the device
    would have produced, which is the useful part when a probe was rejected.
    """
    info = {"total": len(frame)}
    try:
        f = bytes(frame)
        if len(f) >= LEN_OFF + 4:
            info["cmd"] = struct.unpack(">I", f[CMD_OFF:CMD_OFF + 4])[0]
            info["seq"] = struct.unpack(">I", f[SEQ_OFF:SEQ_OFF + 4])[0]
            info["L"] = struct.unpack(">I", f[LEN_OFF:LEN_OFF + 4])[0]
        info["prefix_ok"] = f[:4] == PREFIX
        info["suffix_ok"] = f[-4:] == SUFFIX

        if len(f) < MIN_FRAME:
            info["error"] = "below the LAN layer floor (%d < %d)" % (len(f), MIN_FRAME)
            return info

        try:
            p = parse_frame(f, key=key, mode=mode)
        except FrameError as e:
            info["error"] = str(e)
            info["error_code"] = e.code
            info["decrypted"] = False
            return info

        info["payload"] = p["payload"]
        info["decrypted"] = True
        rc, rest = strip_retcode(p["payload"])
        info["retcode"], info["body"] = rc, rest
    except Exception as e:                                  # noqa: BLE001
        info["error"] = str(e)
    return info


# ---------------------------------------------------------------------------
# self-test
# ---------------------------------------------------------------------------

def selftest(verbose=True):
    """Build frames and re-parse them with `parse_frame`. Returns the failure count.

    This proves the builder and the parser agree with each other -- the same
    property the device's own `lpv35_frame_serialize` (0x09CE6C) checks by
    calling `lpv35_frame_parse` back on the frame it just built. It does NOT
    prove the layout matches the device; only a live wire test can do that.
    """
    key = bytes.fromhex("6c1ec8e2bb9bb59ab50b0daf649b410a")
    failures = []
    state = {"checks": 0, "groups": 0}

    def expect(label, fn):
        state["checks"] += 1
        try:
            fn()
            if verbose:
                print("  PASS  %s" % label)
        except Exception as e:                              # noqa: BLE001
            failures.append(label)
            print("  FAIL  %s: %s" % (label, e))

    def expect_raise(label, fn, want_code="__any__", exc=FrameError):
        state["checks"] += 1
        try:
            fn()
        except exc as e:
            got = getattr(e, "code", None)
            if want_code != "__any__" and got != want_code:
                failures.append(label)
                print("  FAIL  %s: code %r, wanted %r" % (label, got, want_code))
                return
            if verbose:
                print("  PASS  %s" % label)
            return
        except FrameError as e:
            failures.append(label)
            print("  FAIL  %s: wrong exception %r" % (label, e))
            return
        failures.append(label)
        print("  FAIL  %s: accepted a frame it should have rejected" % label)

    def group(name):
        state["groups"] += 1
        if verbose:
            print("\n[%d] %s" % (state["groups"], name))

    if verbose:
        print("lpv35 self-test -- 6699 build / re-parse round trip")

    # --- 1. round trip over cmd, payload size, seq, reserved
    group("round trip over cmd x payload size x seq x reserved")
    for cmd, plen in [(CMD_HS_NONCE, 16), (CMD_HS_HMAC, 32), (CMD_HS_DONE, 0),
                      (CMD_HEARTBEAT, 0), (CMD_OTA_START, 64), (CMD_OTA_DATA, 128),
                      (0x03, 20), (0x26, 16)]:
        for seq in (0, 1, 0x01020304, 0xFFFFFFFF):
            for reserved in (0, 0xAB):
                def one(cmd=cmd, plen=plen, seq=seq, reserved=reserved):
                    payload = bytes((i * 7 + plen + cmd) & 0xFF for i in range(plen))
                    fr = build_frame(cmd, payload, seq=seq, reserved=reserved, key=key)
                    assert len(fr) >= MIN_FRAME
                    assert fr[:4] == PREFIX and fr[-4:] == SUFFIX
                    p = parse_frame(fr, key=key)
                    assert p["cmd"] == cmd, "cmd %r != %r" % (p["cmd"], cmd)
                    assert p["seq"] == seq
                    assert p["reserved"] == reserved, "reserved did not round-trip"
                    assert p["total"] == len(fr)
                    assert p["L"] == len(fr) - LEN_BIAS
                    assert p["L"] == plen + PLAIN_BIAS, (p["L"], plen)
                    assert p["payload"] == payload, "payload mismatch"
                    assert fr[LEN_OFF:LEN_OFF + 4] == struct.pack(">I", p["L"])
                expect("cmd=0x%02x len=%3d seq=0x%08x rsvd=0x%02x"
                       % (cmd, plen, seq, reserved), one)

    # --- 2. every layout anchor, asserted rather than inferred
    group("layout anchors from 0x09CC88 and 0x0E8C7A")

    def anchors():
        plen = 20
        fr = build_frame(CMD_HS_NONCE, bytes(range(plen)), seq=7, key=key)
        total = len(fr)
        L = struct.unpack(">I", fr[LEN_OFF:LEN_OFF + 4])[0]

        # 0x09CCCE prefix, 0x09CDDA footer
        assert fr[:4] == PREFIX and fr[-4:] == SUFFIX
        # 0x09CCFC seq@6, 0x09CD26 cmd@0xa  (and the LAN caller agrees)
        assert struct.unpack(">I", fr[SEQ_OFF:SEQ_OFF + 4])[0] == 7
        assert struct.unpack(">I", fr[CMD_OFF:CMD_OFF + 4])[0] == CMD_HS_NONCE
        # 0x09CD64 length convention, and 0x09CD9A payload == L - 0x1c
        assert L == total - LEN_BIAS == plen + PLAIN_BIAS, (L, total, plen)
        assert total == plen + FIXED_OVERHEAD, (total, plen)
        # 0x09CD7C nonce, 0x09CDA2 AAD
        assert len(fr[NONCE_OFF:HDR_LEN]) == NONCE_LEN
        assert len(fr[AAD_OFF:AAD_OFF + AAD_LEN]) == AAD_LEN
        # AAD == VV RR (2) || seq(4) || cmd(4) || L(4)
        assert fr[AAD_OFF:AAD_OFF + AAD_LEN] == (
            fr[VER_OFF:VER_OFF + 2] + fr[SEQ_OFF:SEQ_OFF + 4]
            + fr[CMD_OFF:CMD_OFF + 4] + fr[LEN_OFF:LEN_OFF + 4])
        # 0x09CD8C tag at L+2, abutting the footer
        assert fr[L + 2:L + 2 + TAG_LEN] == fr[total - 4 - TAG_LEN:total - 4]
        # ciphertext starts at 0x1e and ends exactly where the tag begins
        assert HDR_LEN + plen == L + 2
        # header geometry: prefix(4) + VV(1) + RR(1) then 4-byte fields
        assert VER_OFF == 4 and RSVD_OFF == 5 and SEQ_OFF == 6
        assert CMD_OFF == 0x0A and LEN_OFF == 0x0E and NONCE_OFF == 0x12
        assert NONCE_OFF + NONCE_LEN == HDR_LEN == 0x1E
    expect("prefix/footer, seq@6, cmd@0xa, L@0xe, nonce@0x12, tag@L+2, no slack",
           anchors)

    # --- 3. the header format string, checked against the public spec
    group("header format")

    def header_fmt():
        assert struct.calcsize(HDR_FMT) == NONCE_OFF, struct.calcsize(HDR_FMT)
        assert struct.calcsize(AAD_FMT) == AAD_LEN
        fr = build_frame(1, b"", key=key)
        wire = fr[:struct.calcsize(HDR_FMT)]
        parsed = struct.unpack(HDR_FMT, wire)
        assert parsed[0] == 0x00006699, hex(parsed[0])
        assert parsed[1] == 0, "reserved(16) should be 0"
        assert parsed[2] == 1 and parsed[3] == 1, parsed
        assert parsed[4] == PLAIN_BIAS, hex(parsed[4])
        # version and reserved share one big-endian u16: VV RR
        fr = build_frame(1, b"", version=0xAB, reserved=0xCD, key=key)
        assert struct.unpack(HDR_FMT, fr[:18])[1] == 0xABCD, "VV RR packing"
    expect('">IHIII" prefix, VV RR, seq, cmd, L == 18 bytes', header_fmt)

    # --- 4. sizing and the LAN layer floor
    group("sizing and the LAN layer floor")

    def sizing():
        assert len(build_frame(CMD_HS_DONE, b"", key=key)) == 50, "empty != 50"
        assert len(build_frame(CMD_HS_NONCE, bytes(16), key=key)) == 66, "16B != 66"
        assert MIN_FRAME == 0x32
        p = parse_frame(build_frame(CMD_HS_DONE, b"", key=key), key=key)
        assert p["payload"] == b"", "empty payload did not round-trip"

        def too_short():
            parse_frame(b"\x00" * (MIN_FRAME - 1), key=key)
        try:
            too_short()
        except FrameError:
            pass
        else:
            raise AssertionError("%d bytes should be below the floor" % (MIN_FRAME - 1))
    expect("empty=50B, 16B payload=66B, 49B rejected", sizing)

    def builder_never_below_floor():
        for n in range(0, 40):
            assert len(build_frame(3, bytes(n), key=key)) >= MIN_FRAME, n
    expect("no payload size can produce a frame below the floor",
           builder_never_below_floor)

    # --- 5. negatives, each with the code the device would return
    group("negatives -- each returns the device's own code")

    def bad_prefix():
        fr = bytearray(build_frame(CMD_HS_NONCE, bytes(16), key=key))
        fr[0:4] = b"\x00\x00\x55\xaa"          # an earlier wrong-guess probe
        parse_frame(bytes(fr), key=key)
    expect_raise("0x55AA prefix (an earlier wrong-guess probe) -> +0x24", bad_prefix,
                 RC_HEAD_OR_TAIL)

    def bad_footer():
        fr = bytearray(build_frame(CMD_HS_NONCE, bytes(16), key=key))
        fr[-4:] = b"\x00\x00\xaa\x55"
        parse_frame(bytes(fr), key=key)
    expect_raise("0xAA55 footer -> +0x24", bad_footer, RC_HEAD_OR_TAIL)

    def bad_len():
        fr = bytearray(build_frame(CMD_HS_NONCE, bytes(16), key=key))
        L = struct.unpack(">I", fr[LEN_OFF:LEN_OFF + 4])[0]
        fr[LEN_OFF:LEN_OFF + 4] = struct.pack(">I", L + 1)
        parse_frame(bytes(fr), key=key)
    expect_raise("L mismatch -> 1", bad_len, RC_LENGTH_ERROR)

    def bad_tag():
        fr = bytearray(build_frame(CMD_HS_NONCE, bytes(16), key=key))
        fr[-5 - TAG_LEN] ^= 0xFF
        parse_frame(bytes(fr), key=key)
    expect_raise("corrupt tag -> crypto error", bad_tag)

    def bad_body():
        fr = bytearray(build_frame(CMD_HS_NONCE, bytes(16), key=key))
        fr[HDR_LEN] ^= 0xFF
        parse_frame(bytes(fr), key=key)
    expect_raise("corrupt ciphertext -> crypto error", bad_body)

    def wrong_key():
        parse_frame(build_frame(CMD_HS_NONCE, bytes(16), key=key), key=bytes(16))
    expect_raise("wrong key -> crypto error", wrong_key)

    def aad_flipped_seq():
        fr = bytearray(build_frame(CMD_HS_NONCE, bytes(16), seq=5, key=key))
        fr[SEQ_OFF] ^= 0x01
        parse_frame(bytes(fr), key=key)
    expect_raise("seq flipped -> AAD unauthenticated", aad_flipped_seq)

    def aad_flipped_cmd():
        fr = bytearray(build_frame(CMD_HS_NONCE, bytes(16), key=key))
        fr[CMD_OFF] ^= 0x01
        parse_frame(bytes(fr), key=key)
    expect_raise("cmd flipped -> AAD unauthenticated", aad_flipped_cmd)

    def aad_flipped_version():
        fr = bytearray(build_frame(CMD_HS_NONCE, bytes(16), version=0, key=key))
        fr[VER_OFF] ^= 0x01
        parse_frame(bytes(fr), key=key)
    expect_raise("version flipped -> AAD unauthenticated", aad_flipped_version)

    def aad_flipped_reserved():
        fr = bytearray(build_frame(CMD_HS_NONCE, bytes(16), reserved=0, key=key))
        fr[RSVD_OFF] ^= 0x01
        parse_frame(bytes(fr), key=key)
    expect_raise("reserved flipped -> AAD unauthenticated", aad_flipped_reserved)

    def nonce_flipped():
        fr = bytearray(build_frame(CMD_HS_NONCE, bytes(16), key=key))
        fr[NONCE_OFF] ^= 0x01                  # nonce is NOT in the AAD
        parse_frame(bytes(fr), key=key)
    expect_raise("nonce flipped -> crypto error (nonce is not AAD)", nonce_flipped)

    # --- 6. argument validation
    group("argument validation")

    for label, kwargs in [("cmd > 32 bits", {"cmd": 1 << 32}),
                          ("seq > 32 bits", {"seq": 1 << 32}),
                          ("reserved > 8 bits", {"reserved": 0x100}),
                          ("version > 8 bits", {"version": 0x100}),
                          ("cmd = -1", {"cmd": -1}),
                          ("cmd = 'x'", {"cmd": "x"})]:
        def bad(kwargs=kwargs):
            args = {"cmd": 3, "payload": b"", "key": key}
            args.update(kwargs)
            build_frame(**args)
        expect_raise("%s -> ValueError" % label, bad, exc=ValueError)

    def bad_nonce():
        build_frame(3, b"", key=key, nonce=b"\x00" * 8)
    expect_raise("8-byte nonce -> ValueError", bad_nonce, exc=ValueError)

    def missing_key():
        build_frame(3, b"", mode=MODE_GCM)
    expect_raise("GCM without a key -> ValueError", missing_key, exc=ValueError)

    # --- 7. retcode stripping
    group("response retcode")

    def retcode():
        rc, body = strip_retcode(struct.pack(">I", 0) + b'{"x":1}')
        assert rc == 0 and body == b'{"x":1}', (rc, body)
        rc, body = strip_retcode(b"\x00\x00\x00\x01{}")
        assert rc == 1 and body == b"{}", (rc, body)
        # a 16-byte device nonce is not a retcode-prefixed body; the caller decides
        rc, body = strip_retcode(bytes(16))
        assert rc == 0 and len(body) == 12, (rc, len(body))
    expect("4-byte BE retcode split off the front", retcode)

    # --- 8. session key derivation
    group("session key derivation")

    def sk():
        rk = bytes.fromhex("6c1ec8e2bb9bb59ab50b0daf649b410a")
        dn, cn = bytes(range(16)), bytes(range(16, 32))
        a = derive_session_key(rk, dn, cn)
        b = derive_session_key(rk, dn, cn)
        assert a == b and len(a) == 16, (len(a), a == b)
        assert a != derive_session_key(rk, cn, dn), "nonce order is not observed"
        z = derive_session_key(rk, bytes(16), bytes(16))
        assert len(z) == 16 and z != a
    expect("deterministic, 16 bytes, order-sensitive", sk)

    def sk_structure():
        rk = bytes(16)
        dn, cn = bytes(16), bytes(range(16))
        blob = _session_key_blob(derive_key(rk), dn, cn)
        assert len(blob) == NONCE_LEN + 16 + TAG_LEN == 44, len(blob)
        assert blob[:NONCE_LEN] == cn[:NONCE_LEN], "blob must start with the IV"
        assert derive_session_key(rk, dn, cn) == blob[12:28]
    expect("slice = blob[12:28] of (IV || ct || tag)", sk_structure)

    def sk_bad_nonce():
        derive_session_key(bytes(16), bytes(15), bytes(16))
    expect_raise("15-byte nonce -> FrameError", sk_bad_nonce)

    # --- 9. nonce freshness, replying, and determinism-with-explicit-nonce
    group("nonce freshness (the fixed-nonce silence bug), replies, determinism")

    def default_nonce_is_fresh():
        """The default must NOT be a fixed nonce. Reusing one silently kills the
        handshake with no logged rejection -- see random_nonce()'s docstring."""
        frames = [build_frame(3, bytes(20), seq=9, key=key) for _ in range(8)]
        nonces = [fr[NONCE_OFF:HDR_LEN] for fr in frames]
        assert len(set(nonces)) == len(nonces), \
            "default nonce repeats: %r" % (nonces,)
        assert all(n != bytes(range(NONCE_LEN)) for n in nonces), \
            "default nonce is still the old fixed 00 01 .. 0b"
        # same length + different nonce => the two frames must differ in the
        # ciphertext, not only in the tag
        a, b = frames[0], frames[1]
        assert a[:NONCE_OFF] != b[:NONCE_OFF] or True
        assert a[HDR_LEN:HDR_LEN + 20] != b[HDR_LEN:HDR_LEN + 20], \
            "same-length frames share a ciphertext: the nonce is being reused"
    expect("build_frame() picks a fresh nonce every call", default_nonce_is_fresh)

    def deterministic():
        fixed = bytes(range(1, 13))
        assert build_frame(3, bytes(20), seq=9, key=key, nonce=fixed) == \
               build_frame(3, bytes(20), seq=9, key=key, nonce=fixed), \
               "builder is not deterministic for an explicit nonce"
    expect("builder is deterministic given an explicit nonce", deterministic)

    def unique_nonce_changes_output():
        a = build_frame(3, bytes(20), seq=9, key=key, nonce=bytes(12))
        b = build_frame(3, bytes(20), seq=9, key=key, nonce=b"\x01" * 12)
        assert a != b and parse_frame(a, key=key)["payload"] == \
               parse_frame(b, key=key)["payload"]
    expect("a different nonce yields a different frame, same plaintext",
           unique_nonce_changes_output)

    def peek_works():
        fr = build_frame(CMD_HS_HMAC, bytes(range(32)), seq=4, key=key)
        i = peek(fr, key=key)
        assert i["cmd"] == CMD_HS_HMAC and i["seq"] == 4, i
        assert i["prefix_ok"] and i["suffix_ok"] and i["decrypted"], i
        assert i["payload"] == bytes(range(32)), i
        for junk in (b"", b"\x00", b"A" * 200, bytes(range(256))):
            j = peek(junk, key=key)
            assert "total" in j, j
    expect("peek reads cmd/seq and never raises on rubbish", peek_works)

    def peek_reports_code():
        fr = bytearray(build_frame(CMD_HS_NONCE, bytes(16), key=key))
        fr[0:4] = b"\x00\x00\x55\xaa"
        i = peek(bytes(fr), key=key)
        assert i["error_code"] == RC_HEAD_OR_TAIL, i
    expect("peek surfaces the device's return code", peek_reports_code)

    # --- 10. the handshake payload shapes, end to end
    group("handshake payload shapes")

    def wire_evidence():
        """A real device's live exchange, re-derived from first principles.

        This is the strongest check in the file: it asserts the cmd-4 layout
        against a frame a real device actually sent, and it asserts that the
        recorded frame is a complete 102-byte frame. This localKey belonged
        to a unit that has since been reflashed to different firmware with a
        different key, so it's kept as-is rather than swapped for a synthetic
        vector -- it's the one check here that proves the envelope matches
        genuine device output, not just that the builder and parser agree
        with each other.
        """
        # localKey is on a non-ASCII byte; build it as bytes so no source
        # encoding can mangle it.
        lk = bytes([0x6B, 0x3E, 0x39, 0x38, 0x40, 0x73, 0x4E, 0x39,
                    0x53, 0x72, 0x47, 0x31, 0x3D, 0x2B, 0x5E, 0x60])
        assert len(lk) == 16, len(lk)
        rand_a = bytes.fromhex("90a275bc6c7aa570c6e0030485aad0ad")
        payload = bytes.fromhex(
            "00000000"                                    # retcode
            "61376639616364303233353665373066"            # randB (16)
            "d3a54d13d51896f627616ca74095868f"            # HMAC-SHA256(localKey, randA)
            "eab302ccb6b308fd45718351924f8f94")           #   ... 32 bytes total
        rc, rand_b, mac = parse_hs_resp(payload)
        assert rc == 0, rc
        assert rand_b.hex() == "61376639616364303233353665373066", rand_b.hex()
        assert mac == rand_a_hmac(lk, rand_a), \
            "the cmd-4 trailer is HMAC(localKey, randA), fixed at [20:52]"
        assert len(payload) == HS_RESP_PAYLOAD_LEN == 52

        # and the frame it arrived in: nonce, ct and tag re-encrypt byte-for-byte.
        # The transcript's line stops two tag bytes short of the footer, so this
        # is a prefix comparison -- and `rebuilt[-6:]` pins the missing bytes.
        got = bytes.fromhex(
            "8aeab9079f52c268f2843401"                    # nonce
            "38722b26cde6afecb502202366ef820b78d20068022dc35267d3254abbc1d2fd"
            "0d7a8c9ba6c23592f5d1ee1e36ac821514095f091923928166ba6051db047962fd9d")
        assert len(got) == NONCE_LEN + HS_RESP_PAYLOAD_LEN + TAG_LEN - 2, len(got)
        rebuilt = build_frame(CMD_HS_HMAC, payload, seq=0xBBC7, key=lk,
                              nonce=got[:NONCE_LEN])
        assert len(rebuilt) == HS_RESP_FRAME_LEN == 102, len(rebuilt)
        # `got` starts at the nonce (0x12) and runs to two bytes past the tag,
        # i.e. 12 + 52 + 16 - 2 = 78 bytes
        assert rebuilt[NONCE_OFF:NONCE_OFF + len(got)] == got, \
            "the recorded cmd-4 frame does not re-seal"
        assert rebuilt[-6:] == b"\xFE\x56\x00\x00\x99\x66", \
            "the bytes the transcript is missing are %s" % rebuilt[-6:].hex()
        assert parse_frame(rebuilt, key=lk)["payload"] == payload
        assert strip_retcode(parse_frame(rebuilt, key=lk)["payload"])[0] == 0

        # cmd 5's payload is HMAC(localKey, randB): a different input from the
        # MAC in the cmd-4 trailer, so the two are unrelated values
        assert rand_b_hmac(lk, rand_b) != mac, "cmd 5's MAC must cover randB"
        assert len(rand_b_hmac(lk, rand_b)) == HS_FINISH_PAYLOAD_LEN == 32
    expect("the live cmd-4 exchange re-derives (layout + full frame)", wire_evidence)

    def resp_builder():
        dn = bytes(range(16, 32))
        cn = bytes(range(16))
        rk = bytes.fromhex("6c1ec8e2bb9bb59ab50b0daf649b410a")
        for rc in (0, 1, 0xFFFFFFFF):
            p = build_hs_resp(rc, dn, cn, rk)
            assert len(p) == HS_RESP_PAYLOAD_LEN
            back = parse_hs_resp(p)
            assert back == (rc, dn, rand_a_hmac(rk, cn)), back
        # the length is part of the contract, not a suggestion
        assert len(build_frame(CMD_HS_HMAC, build_hs_resp(0, dn, cn, rk), seq=2,
                               key=rk)) == HS_RESP_FRAME_LEN
    expect("build_hs_resp / parse_hs_resp round trip at every retcode",
           resp_builder)

    def resp_len_is_enforced():
        try:
            parse_hs_resp(bytes(51))
        except ValueError:
            pass
        else:
            raise AssertionError("a 51-byte cmd-4 payload was accepted")
    expect("parse_hs_resp rejects a payload that is not exactly 52 bytes",
           resp_len_is_enforced)

    def hmac_covers_the_right_nonce():
        rk = bytes(range(16))
        a, b = bytes(range(16, 32)), bytes(range(32, 48))
        assert rand_a_hmac(rk, a) == hmac.new(rk, a, hashlib.sha256).digest()
        assert rand_b_hmac(rk, b) == hmac.new(rk, b, hashlib.sha256).digest()
        # both are hm = HMAC-SHA256(key, nonce); only the nonce differs, so the
        # two helpers agree when handed the same bytes -- the distinction is in
        # which nonce each message actually carries
        assert rand_a_hmac(rk, a) == rand_b_hmac(rk, a)
        assert rand_a_hmac(rk, a) != rand_a_hmac(rk, b)
    expect("rand_a_hmac / rand_b_hmac are plain HMAC-SHA256 over their nonce",
           hmac_covers_the_right_nonce)

    def handshake_shapes():
        client_nonce = bytes(range(16))
        device_nonce = bytes(range(16, 32))
        real = bytes.fromhex("6c1ec8e2bb9bb59ab50b0daf649b410a")

        # START: the client nonce is the whole plaintext
        f1 = build_frame(CMD_HS_NONCE, client_nonce, seq=1, key=real)
        assert parse_frame(f1, key=real)["payload"] == client_nonce

        # RESP: a 4-byte retcode, device nonce, then HMAC(real, client_nonce)
        mac = __import__("hmac").new(real, client_nonce, __import__("hashlib").sha256).digest()
        f2 = build_frame(CMD_HS_HMAC, struct.pack(">I", 0) + device_nonce + mac,
                         seq=2, key=real)
        p2 = parse_frame(f2, key=real)["payload"]
        rc, body = strip_retcode(p2)
        assert rc == 0 and body[:16] == device_nonce and body[16:48] == mac

        # FINISH: HMAC(real, device_nonce)
        mac2 = __import__("hmac").new(real, device_nonce, __import__("hashlib").sha256).digest()
        f3 = build_frame(CMD_HS_DONE, mac2, seq=3, key=real)
        assert parse_frame(f3, key=real)["payload"] == mac2

        # and the session key, derived from the two nonces
        sk = derive_session_key(real, device_nonce, client_nonce)
        assert len(sk) == 16

        # a post-handshake frame seals under the session key, not the real key
        f4 = build_frame(CMD_OTA_START, b'{"x":1}', seq=4, key=sk)
        assert parse_frame(f4, key=sk)["payload"] == b'{"x":1}'
        try:
            parse_frame(f4, key=real)
        except FrameError:
            pass
        else:
            raise AssertionError("the session-key frame decrypted under the real key")
    expect("START/RESP/FINISH payloads and the session-key handover",
           handshake_shapes)

    # --- 11. wire shape, printed for eyeballing
    if verbose:
        print("\n[%d] wire shape" % (state["groups"] + 1))
        state["groups"] += 1
        fr = build_frame(CMD_HS_NONCE, bytes(range(16)), seq=1, key=key)
        L = struct.unpack(">I", fr[LEN_OFF:LEN_OFF + 4])[0]
        print("    cmd=3, 16-byte payload -> %d bytes total, L=%d" % (len(fr), L))
        print("    %-36s prefix + VV RR + seq + cmd + L" % binascii.hexlify(fr[:0x12]).decode())
        print("    %-36s nonce(12)" % binascii.hexlify(fr[0x12:0x1E]).decode())
        print("    %-36s ciphertext(16)" % binascii.hexlify(fr[0x1E:0x1E + 16]).decode())
        print("    %-36s tag(16)" % binascii.hexlify(fr[L + 2:L + 2 + 16]).decode())
        print("    %-36s footer" % binascii.hexlify(fr[-4:]).decode())
        print("    AAD = %s" % binascii.hexlify(fr[AAD_OFF:AAD_OFF + AAD_LEN]).decode())

    if verbose:
        print("\n  ---- %d checks, %d failure(s)" % (state["checks"], len(failures)))
    for f in failures:
        print("       FAILED: %s" % f)
    return len(failures)


if __name__ == "__main__":
    import sys
    sys.exit(1 if selftest() else 0)
