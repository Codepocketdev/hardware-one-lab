#!/usr/bin/env python3
"""Host tool for the Cashu P2PK signer (Trezor Model One lab firmware).
Needs trezorctl on PATH. ASCII secrets only, no backslashes, 60..600 chars.
  cashu_sign.py pub                 x-only key from the device
  cashu_sign.py lock                33-byte lock key (02+x) to give a sender
  cashu_sign.py newsecret           make a test P2PK secret locked to the device
  cashu_sign.py sign '<secret>'     sign (or --file F, or '-' for stdin)
  cashu_sign.py token cashuA...     sign every P2PK proof of a cashuA token
  cashu_sign.py show cashuB...      decode a cashuA/cashuB token (no device)
  cashu_sign.py redeem <token>      sign on device, build the mint swap (dry run)
  cashu_sign.py redeem <token> --send   ...and really swap at the mint
  cashu_sign.py --selftest          check the BIP-340 verifier (no device)
"""
import sys, os, json, hashlib, subprocess, base64, secrets, time, math
import urllib.request, urllib.error

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
    if a == "--file":
        b = open(sys.argv[3], "rb").read()
        if b.startswith((b"\xff\xfe", b"\xfe\xff")): return b.decode("utf-16").strip()
        return b.decode("utf-8-sig").strip()
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


# ---- minimal CBOR (decode only what cashuB needs) ----
def cbor_dec(b, i=0):
    ib = b[i]; mt = ib >> 5; ai = ib & 31; i += 1
    if ai < 24: v = ai
    elif ai in (24, 25, 26, 27):
        n = 1 << (ai - 24); v = int.from_bytes(b[i:i + n], "big"); i += n
    else: raise ValueError("unsupported CBOR")
    if mt == 0: return v, i
    if mt == 1: return -1 - v, i
    if mt == 2: return bytes(b[i:i + v]), i + v
    if mt == 3: return b[i:i + v].decode("utf-8"), i + v
    if mt == 4:
        out = []
        for _ in range(v): x, i = cbor_dec(b, i); out.append(x)
        return out, i
    if mt == 5:
        out = {}
        for _ in range(v):
            k, i = cbor_dec(b, i); x, i = cbor_dec(b, i); out[k] = x
        return out, i
    if mt == 7 and ai in (20, 21, 22): return {20: False, 21: True, 22: None}[ai], i
    raise ValueError("unsupported CBOR type")

def b64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def parse_token(tok):
    """-> (mint, unit, [proof dicts with amount,id,secret,C])"""
    tok = tok.strip()
    if tok.startswith("cashuB"):
        obj, _ = cbor_dec(b64u(tok[6:]))
        proofs = []
        for g in obj["t"]:
            for p in g["p"]:
                proofs.append({"amount": p["a"], "id": g["i"].hex(), "secret": p["s"], "C": p["c"].hex()})
        return obj["m"], obj.get("u", "sat"), proofs
    if tok.startswith("cashuA"):
        obj = json.loads(b64u(tok[6:]))
        e = obj["token"][0]
        if len(obj["token"]) > 1: sys.exit("multi-mint tokens not supported")
        return e["mint"], obj.get("unit", "sat"), [dict(amount=p["amount"], id=p["id"], secret=p["secret"], C=p["C"]) for p in e["proofs"]]
    sys.exit("token must start with cashuA or cashuB")

# ---- point helpers / BDHKE ----
def pt_from_hex(h):
    b = bytes.fromhex(h); x = int.from_bytes(b[1:33], "big")
    pt = lift_x(x)
    if pt is None: raise ValueError("bad point")
    if (b[0] == 3) != (pt[1] % 2 == 1): pt = (pt[0], P - pt[1])
    return pt

def pt_hex(pt): return ("%02x" % (2 + pt[1] % 2)) + ("%064x" % pt[0])
def neg(pt): return (pt[0], P - pt[1])

def hash_to_curve(msg):
    base = hashlib.sha256(b"Secp256k1_HashToCurve_Cashu_" + msg).digest()
    for c in range(1 << 16):
        h = hashlib.sha256(base + c.to_bytes(4, "little")).digest()
        pt = lift_x(int.from_bytes(h, "big"))
        if pt is not None: return pt
    raise ValueError("no curve point")

def blind(secret):
    Y = hash_to_curve(secret.encode()); r = secrets.randbelow(N - 1) + 1
    return r, pt_hex(add(Y, mul(G, r)))

def unblind(C_hex, r, K_hex):
    return pt_hex(add(pt_from_hex(C_hex), neg(mul(pt_from_hex(K_hex), r))))

# ---- mint HTTP ----
def http(url, body=None):
    req = urllib.request.Request(url, data=None if body is None else json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "cashu_sign/0.2"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r: return json.loads(r.read())
    except urllib.error.HTTPError as e:
        sys.exit("mint said HTTP %d: %s" % (e.code, e.read().decode(errors="replace")))
    except Exception as e:
        sys.exit("network error: %s" % e)

def show_cmd(tok):
    mint, unit, proofs = parse_token(tok)
    print("mint  :", mint); print("unit  :", unit)
    for p in proofs:
        print("proof : %d %s keyset %s" % (p["amount"], unit, p["id"]))
        print("  secret:", p["secret"])
        print("  C     :", p["C"])

def redeem_cmd(tok, send):
    mint, unit, proofs = parse_token(tok); mint = mint.rstrip("/")
    total = sum(p["amount"] for p in proofs)
    if not proofs: sys.exit("no proofs")
    print("mint %s, %d proof(s), %d %s" % (mint, len(proofs), total, unit), file=sys.stderr)
    for p in proofs:
        if not p["secret"].startswith('["P2PK"'):
            sys.exit("proof is not P2PK; nothing to sign (plain tokens need no device)")
    ids = {p["id"] for p in proofs}
    if len(ids) != 1: sys.exit("mixed keysets not supported")
    kid = ids.pop()
    allks = http(mint + "/v1/keysets")["keysets"]
    ks = [k for k in allks if k["id"] == kid or k["id"].startswith(kid)]
    if not ks: sys.exit("keyset %s not in mint list: %s" % (kid, [k["id"] for k in allks]))
    kid = ks[0]["id"]
    print("keyset %s (%d chars)" % (kid, len(kid)), file=sys.stderr)
    fee_ppk = ks[0].get("input_fee_ppk", 0)
    fee = math.ceil(len(proofs) * fee_ppk / 1000)
    keys = [k for k in http(mint + "/v1/keys/" + kid)["keysets"] if k["id"] == kid][0]["keys"]
    out_total = total - fee
    if out_total <= 0: sys.exit("fee eats the whole token")
    inputs = []
    for p in proofs:
        sig = sign(p["secret"])
        inputs.append({"amount": p["amount"], "id": kid, "secret": p["secret"], "C": p["C"], "witness": witness(sig)})
    amounts = [1 << b for b in range(out_total.bit_length()) if out_total >> b & 1]
    outs, plan = [], []
    for a in amounts:
        if str(a) not in keys: sys.exit("keyset has no key for amount %d" % a)
        sec = secrets.token_hex(32); r, B_ = blind(sec)
        outs.append({"amount": a, "id": kid, "B_": B_}); plan.append({"amount": a, "secret": sec, "r": r})
    req = {"inputs": inputs, "outputs": outs}
    stamp = time.strftime("%Y%m%d-%H%M%S")
    rec = "redeem_recovery_%s.json" % stamp
    with open(rec, "w") as f: json.dump({"mint": mint, "keyset": kid, "plan": plan, "request": req}, f)
    print("fee %d; recovery data saved to %s (keep it private until done)" % (fee, rec), file=sys.stderr)
    if not send:
        print(json.dumps(req)); print("DRY RUN: nothing sent. Add --send to swap.", file=sys.stderr); return
    resp = http(mint + "/v1/swap", req)
    sigs = resp["signatures"]
    if len(sigs) != len(plan): sys.exit("unexpected response, see recovery file")
    newp = []
    for pl, s in zip(plan, sigs):
        if s["amount"] != pl["amount"]: sys.exit("amount mismatch, see recovery file")
        newp.append({"amount": pl["amount"], "id": kid, "secret": pl["secret"], "C": unblind(s["C_"], pl["r"], keys[str(pl["amount"])])})
    with open(rec, "w") as f: json.dump({"mint": mint, "keyset": kid, "plan": plan, "request": req, "response": resp, "new_proofs": newp}, f)
    tok2 = "cashuA" + base64.urlsafe_b64encode(json.dumps({"token": [{"mint": mint, "proofs": newp}], "unit": unit}, separators=(",", ":")).encode()).decode().rstrip("=")
    print("SWAP OK. New unlocked token (import it into your wallet now):", file=sys.stderr)
    print(tok2)

def selftest():
    pub = bytes.fromhex("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9")
    sig = bytes.fromhex("E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
                        "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0")
    assert verify(pub, bytes(32), sig)
    assert not verify(pub, b"\x01" + bytes(31), sig)
    h = pt_hex(hash_to_curve(bytes(32)))
    assert h == "024cce997d3b518f739663b757deaec95bcd9473c30a14ac2fd04023a739d1a725"
    r, B_ = blind("test"); k = 12345; K = pt_hex(mul(G, k))
    C_ = pt_hex(mul(pt_from_hex(B_), k))
    assert unblind(C_, r, K) == pt_hex(mul(hash_to_curve(b"test"), k))
    print("BDHKE blind/unblind OK")
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
    elif c == "show": show_cmd(a[1])
    elif c == "redeem": redeem_cmd(a[1], "--send" in a)
    else: sys.exit("unknown command")

if __name__ == "__main__": main()
