#!/usr/bin/env python3
"""Test the Trezor lab firmware's Cashu P2PK signer (CASHUPUB / CASHUSIG) without a mint.
Run on the PC with the Trezor attached and the lab seed restored:  python cashu_device_test.py
You must press Next on each page and Sign on the last page of the two signing tests."""
import hashlib
import json
import os
import shutil
import subprocess
import sys

P = (1 << 256) - (1 << 32) - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], -1, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return (x, (lam * (a[0] - x) - a[1]) % P)


def _mul(k, pt=G):
    r = None
    while k:
        if k & 1:
            r = _add(r, pt)
        pt = _add(pt, pt)
        k >>= 1
    return r


def _tagged(tag, data):
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + data).digest()


def verify(pub, msg, sig):
    """BIP-340 verification (pub: 32-byte x-only, msg: 32 bytes, sig: 64 bytes)."""
    x = int.from_bytes(pub, "big")
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if pow(y, 2, P) != y2:
        return False
    pt = (x, y if y % 2 == 0 else P - y)
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if r >= P or s >= N:
        return False
    e = int.from_bytes(_tagged("BIP0340/challenge", sig[:32] + pub + msg), "big") % N
    res = _add(_mul(s), _mul(N - e, pt))
    return res is not None and res[1] % 2 == 0 and res[0] == r


def tz(message):
    exe = shutil.which("trezorctl")
    if not exe:
        raise RuntimeError("trezorctl was not found on PATH")
    r = subprocess.run([exe, "ping", message], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(" ".join((r.stderr + " " + r.stdout).split()))
    lines = [ln for ln in r.stdout.splitlines() if ln.strip()]
    return lines[-1].strip() if lines else ""


def sign_secret(secret):
    if not tz("CASHUSIG BEGIN %d" % len(secret.encode("utf-8"))).startswith("OK"):
        raise RuntimeError("this firmware has no CASHUSIG support (the command was echoed back)")
    for off in range(0, len(secret), 180):
        tz("CASHUSIG ADD %d %s" % (len(secret[:off].encode("utf-8")), secret[off:off + 180]))
    return tz("CASHUSIG SIGN")


def p2pk_secret(lock_x_hex, spaced=False, tags=None, unicode=False):
    body = {"nonce": os.urandom(16).hex(), "data": "02" + lock_x_hex,
            "tags": tags if tags is not None else [["sigflag", "SIG_INPUTS"]]}
    seps = (", ", ": ") if spaced else (",", ":")
    return json.dumps(["P2PK", body], separators=seps, ensure_ascii=not unicode)


results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(("PASS  " if ok else "FAIL  ") + name + (("  (" + detail + ")") if detail else ""))


def expect_refusal(name, secret, needle):
    try:
        sign_secret(secret)
        check(name, False, "the device signed it")
    except RuntimeError as exc:
        check(name, needle.lower() in str(exc).lower(), str(exc)[:70])


def main():
    pub = tz("CASHUPUB")
    nostr = tz("NOSTRPUB")
    ok_hex = len(pub) == 64 and all(c in "0123456789abcdef" for c in pub)
    check("CASHUPUB returns a 64-hex key", ok_hex, pub[:16] + "...")
    if not ok_hex:
        sys.exit("No Cashu key from the device. Is the Cashu firmware flashed and the seed restored?")
    check("Cashu key differs from the Nostr key", pub != nostr)

    for label, spaced in (("compact JSON", False), ("spaced JSON, Python default", True)):
        secret = p2pk_secret(pub, spaced)
        print("\nSigning %s secret (%d chars). Review the pages on the Trezor, press Next, then Sign." % (label, len(secret)))
        try:
            sig = sign_secret(secret)
            good = verify(bytes.fromhex(pub), hashlib.sha256(secret.encode()).digest(), bytes.fromhex(sig))
            check("signature over sha256(secret) verifies (%s)" % label, good)
        except RuntimeError as exc:
            check("signing (%s)" % label, False, str(exc)[:70])

    print("\nRefusal tests (the device should reject these without asking you to sign):")
    other = os.urandom(32).hex()
    expect_refusal("secret locked to another key", p2pk_secret(other), "another key")
    expect_refusal("not a P2PK secret", json.dumps(["HTLC", {"nonce": "ab" * 16, "data": "cd" * 32, "tags": []}]), "not a p2pk")
    expect_refusal("backslash in secret", p2pk_secret(pub, tags=[["x", "a\\b"]], unicode=True), "unsupported character")
    expect_refusal("non-ASCII in secret", p2pk_secret(pub, tags=[["x", "caf\u00e9"]], unicode=True), "unsupported character")
    expect_refusal("two data fields", p2pk_secret(pub, tags=[["data", "x"]]), "one data field")

    print("\n%d of %d checks passed" % (sum(results), len(results)))
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
