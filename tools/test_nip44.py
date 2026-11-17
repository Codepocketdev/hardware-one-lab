"""Check nip44.py. Without arguments: self-tests only.
With the official vectors file: python test_nip44.py nip44.vectors.json
(get it from https://raw.githubusercontent.com/paulmillr/nip44/main/nip44.vectors.json)"""
import base64
import hashlib
import json
import os
import sys

import nip44 as n

ok = bad = 0


def check(name, cond, detail=""):
    global ok, bad
    if cond:
        ok += 1
    else:
        bad += 1
        print("FAIL", name, detail)


# --- self tests
a, b = os.urandom(32), os.urandom(32)
while not (0 < int.from_bytes(a, "big") < n.N and 0 < int.from_bytes(b, "big") < n.N):
    a, b = os.urandom(32), os.urandom(32)
ck1 = n.get_conversation_key(a, n.x_only_pub(b))
ck2 = n.get_conversation_key(b, n.x_only_pub(a))
check("conversation key is symmetric", ck1 == ck2)
for text in ["a", "hello", "x" * 32, "x" * 33, "caf\u00e9 \u2615 " * 20, "y" * 1000]:
    check("roundtrip %d chars" % len(text), n.decrypt(n.encrypt(text, ck1), ck2) == text)
payload = n.encrypt("tamper me", ck1)
raw = bytearray(base64.b64decode(payload))
raw[40] ^= 1
try:
    n.decrypt(base64.b64encode(bytes(raw)).decode(), ck2)
    check("tampered payload is rejected", False)
except n.Nip44Error:
    check("tampered payload is rejected", True)
for length, want in [(16, 32), (32, 32), (33, 64), (65, 96), (100, 128), (200, 224), (320, 320), (515, 640)]:
    check("padded len %d" % length, n.calc_padded_len(length) == want, "got %d" % n.calc_padded_len(length))

# --- official vectors
if len(sys.argv) > 1:
    v = json.load(open(sys.argv[1]))["v2"]
    valid, invalid = v["valid"], v.get("invalid", {})
    print("vector groups:", sorted(valid), sorted(invalid))
    for t in valid.get("get_conversation_key", []):
        got = n.get_conversation_key(bytes.fromhex(t["sec1"]), bytes.fromhex(t["pub2"])).hex()
        check("vector conversation key", got == t["conversation_key"], t["sec1"][:8])
    gm = valid.get("get_message_keys")
    if gm:
        ck = bytes.fromhex(gm["conversation_key"])
        for t in gm["keys"]:
            got = [x.hex() for x in n.get_message_keys(ck, bytes.fromhex(t["nonce"]))]
            check("vector message keys", got == [t["chacha_key"], t["chacha_nonce"], t["hmac_key"]], t["nonce"][:8])
    for length, padded in valid.get("calc_padded_len", []):
        check("vector padded len %d" % length, n.calc_padded_len(length) == padded)
    for t in valid.get("encrypt_decrypt", []):
        ck = n.get_conversation_key(bytes.fromhex(t["sec1"]), n.x_only_pub(bytes.fromhex(t["sec2"])))
        check("vector enc/dec conversation key", ck.hex() == t["conversation_key"])
        got = n.encrypt(t["plaintext"], bytes.fromhex(t["conversation_key"]), bytes.fromhex(t["nonce"]))
        check("vector encrypt", got == t["payload"], t["nonce"][:8])
        check("vector decrypt", n.decrypt(t["payload"], bytes.fromhex(t["conversation_key"])) == t["plaintext"])
    for t in valid.get("encrypt_decrypt_long_msg", []):
        pt = t["pattern"] * t["repeat"]
        check("long msg plaintext hash", hashlib.sha256(pt.encode()).hexdigest() == t["plaintext_sha256"])
        got = n.encrypt(pt, bytes.fromhex(t["conversation_key"]), bytes.fromhex(t["nonce"]))
        check("long msg payload hash", hashlib.sha256(got.encode()).hexdigest() == t["payload_sha256"])
    for t in invalid.get("decrypt", []):
        try:
            n.decrypt(t["payload"], bytes.fromhex(t["conversation_key"]))
            check("invalid payload rejected: " + t.get("note", "")[:40], False)
        except n.Nip44Error:
            check("invalid payload rejected", True)
        except Exception as exc:
            check("invalid payload rejected (wrong error type)", False, repr(exc))

print("passed %d, failed %d" % (ok, bad))
sys.exit(1 if bad else 0)
