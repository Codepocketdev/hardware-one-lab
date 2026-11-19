#!/usr/bin/env python3
"""Host tool for the Cashu P2PK signer (Trezor Model One lab firmware).
Needs trezorctl on PATH. ASCII secrets only, no backslashes, 60..600 chars.
  cashu_sign.py pub                 x-only key from the device
  cashu_sign.py lock                33-byte lock key (02+x) to give a sender
  cashu_sign.py newsecret           make a test P2PK secret locked to the device
  cashu_sign.py sign '<secret>'     sign (or --file F, or '-' for stdin)
  cashu_sign.py token cashuA...     sign every P2PK proof of a cashuA token
  cashu_sign.py --selftest          check the BIP-340 verifier (no device)
"""
import sys, os, json, hashlib, subprocess, base64, secrets

CHUNK = 120
# ---- BIP-340 verify (reference algorithm) ----
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

def add(a, b):
    if a is None: return b
    if b is None: return a
    if a[0] == b[0] and a[1] != b[1]: return None
    if a == b: l = 3 * a[0] * a[0] * pow(2 * a[1], P - 2, P) % P
    else: l = (b[1] - a[1]) * pow(b[0] - a[0], P - 2, P) % P
    x = (l * l - a[0] - b[0]) % P
    return (x, (l * (a[0] - x) - a[1]) % P)

def mul(pt, k):
    r = None
    while k:
        if k & 1: r = add(r, pt)
        pt = add(pt, pt); k >>= 1
    return r

def tagged(tag, data):
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + data).digest()

def lift_x(x):
    if x >= P: return None
    y = pow((x ** 3 + 7) % P, (P + 1) // 4, P)
    if y * y % P != (x ** 3 + 7) % P: return None
    return (x, y if y % 2 == 0 else P - y)

def verify(pub, msg, sig):
    pt = lift_x(int.from_bytes(pub, "big"))
    r = int.from_bytes(sig[:32], "big"); s = int.from_bytes(sig[32:], "big")
    if pt is None or r >= P or s >= N: return False
    e = int.from_bytes(tagged("BIP0340/challenge", sig[:32] + pub + msg), "big") % N
    R = add(mul(G, s), mul(pt, N - e))
    return R is not None and R[1] % 2 == 0 and R[0] == r

# ---- device ----
def ping(text):
    out = subprocess.run(["trezorctl", "ping", text], capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit("device: " + (out.stderr.strip() or out.stdout.strip() or "failed"))
    return out.stdout.strip().splitlines()[-1].strip()

def get_pub():
    h = ping("CASHUPUB")
    if len(h) != 64 or any(c not in "0123456789abcdef" for c in h):
        sys.exit("CASHUPUB gave '%s'. Firmware without the cashu patch?" % h)
    return h

def sign(secret):
    if not (60 <= len(secret) <= 600) or "\\" in secret or not secret.isascii():
        sys.exit("secret must be ASCII, 60..600 chars, no backslash")
    pub = get_pub()
    ping("CASHUSIG BEGIN %d" % len(secret))
    for off in range(0, len(secret), CHUNK):
        ping("CASHUSIG ADD %d %s" % (off, secret[off:off + CHUNK]))
    print("Review and approve on the device...", file=sys.stderr)
    sig = ping("CASHUSIG SIGN")
    ok = verify(bytes.fromhex(pub), hashlib.sha256(secret.encode()).digest(), bytes.fromhex(sig))
    if not ok: sys.exit("signature FAILED local verification")
    return sig

def witness(sig): return json.dumps({"signatures": [sig]}, separators=(",", ":"))

def read_secret(a):
    if a == "--file": return open(sys.argv[3]).read().strip()
    if a == "-": return sys.stdin.read().strip()
    return a

def token_cmd(tok):
    if not tok.startswith("cashuA"): sys.exit("only cashuA (JSON) tokens; cashuB is CBOR, not supported")
    raw = tok[6:]; raw += "=" * (-len(raw) % 4)
    obj = json.loads(base64.urlsafe_b64decode(raw))
    n = 0
    for entry in obj["token"]:
        for pr in entry["proofs"]:
            if pr["secret"].startswith('["P2PK"'):
                pr["witness"] = witness(sign(pr["secret"])); n += 1
    print("signed %d proof(s)" % n, file=sys.stderr)
    out = base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode().rstrip("=")
    print("cashuA" + out)

def selftest():
    pub = bytes.fromhex("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9")
    sig = bytes.fromhex("E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
                        "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0")
    assert verify(pub, bytes(32), sig)
    assert not verify(pub, b"\x01" + bytes(31), sig)
    print("BIP-340 verifier OK")

def main():
    a = sys.argv[1:]
    if not a or a[0] in ("-h", "--help"): print(__doc__); return
    c = a[0]
    if c == "--selftest": selftest()
    elif c == "pub": print(get_pub())
    elif c == "lock": print("02" + get_pub())
    elif c == "newsecret":
        print(json.dumps(["P2PK", {"nonce": secrets.token_hex(32), "data": "02" + get_pub(), "tags": []}], separators=(",", ":")))
    elif c == "sign":
        s = read_secret(a[1]); sig = sign(s)
        print(sig); print(witness(sig))
    elif c == "token": token_cmd(a[1])
    else: sys.exit("unknown command")

if __name__ == "__main__": main()
