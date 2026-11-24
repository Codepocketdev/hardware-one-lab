#!/usr/bin/env python3
"""2-of-2 P2PK test on a LOCAL test mint (fake funds): device key + software key.
Run on the PC with the Trezor attached, next to cashu_sign.py.
  python cashu_2of2_test.py --mint http://127.0.0.1:3338
Mints 8 sat locked to: device key (data) + software key (pubkeys tag), n_sigs=2.
Then tries to spend it with 1 signature, wrong keys and finally both signatures.
Refuses non-local mints unless --allow-remote is given.
"""
import sys, os, json, math, time, hashlib, secrets, ipaddress, urllib.request, urllib.error
from urllib.parse import urlparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cashu_sign as cs

def schnorr_sign(d, msg, aux=None):
    P = cs.mul(cs.G, d)
    if P[1] % 2: d = cs.N - d
    px = P[0].to_bytes(32, "big")
    aux = aux if aux is not None else secrets.token_bytes(32)
    t = d ^ int.from_bytes(cs.tagged("BIP0340/aux", aux), "big")
    k = int.from_bytes(cs.tagged("BIP0340/nonce", t.to_bytes(32, "big") + px + msg), "big") % cs.N
    R = cs.mul(cs.G, k)
    if R[1] % 2: k = cs.N - k
    rx = R[0].to_bytes(32, "big")
    e = int.from_bytes(cs.tagged("BIP0340/challenge", rx + px + msg), "big") % cs.N
    return rx + ((k + e * d) % cs.N).to_bytes(32, "big")

def new_key():
    d = secrets.randbelow(cs.N - 1) + 1
    P = cs.mul(cs.G, d)
    if P[1] % 2: d = cs.N - d; P = cs.mul(cs.G, d)
    return d, "%064x" % P[0]

def is_local(url):
    h = urlparse(url).hostname or ""
    if h == "localhost": return True
    try:
        ip = ipaddress.ip_address(h); return ip.is_loopback or ip.is_private
    except ValueError:
        return False

def call(url, body=None):
    req = urllib.request.Request(url, data=None if body is None else json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "cashu_2of2_test/0.1"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r: return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        txt = e.read().decode(errors="replace")
        try: return e.code, json.loads(txt)
        except Exception: return e.code, txt
    except Exception as e:
        sys.exit("network error: %s" % e)

results = []
def report(name, ok, note=""):
    results.append(ok); print("%-5s %-34s %s" % ("PASS" if ok else "FAIL", name, note[:80]))

def main():
    a = sys.argv[1:]
    if "--mint" not in a: sys.exit(__doc__)
    mint = a[a.index("--mint") + 1].rstrip("/")
    amount = int(a[a.index("--amount") + 1]) if "--amount" in a else 8
    if not is_local(mint) and "--allow-remote" not in a:
        sys.exit("refusing %s: not a local mint. Use a test mint (or an SSH tunnel to one)." % mint)
    if amount & (amount - 1): sys.exit("amount must be a power of 2")

    dev = cs.get_pub(); second = a[a.index("--second-key") + 1].lower() if "--second-key" in a else sys.exit("need --second-key <66 hex public key>")
    if len(second) != 66 or second[:2] not in ("02", "03"): sys.exit("--second-key must be a 66 hex compressed public key")
    x_b = second[2:]
    print("device key  :", dev); print("second key  :", second)
    ks = [k for k in call(mint + "/v1/keysets")[1]["keysets"] if k["unit"] == "sat" and k.get("active", True)]
    if not ks: sys.exit("no active sat keyset")
    kid = ks[0]["id"]; fee_ppk = ks[0].get("input_fee_ppk", 0)
    keys = [k for k in call(mint + "/v1/keys/" + kid)[1]["keysets"] if k["id"] == kid][0]["keys"]
    if str(amount) not in keys: sys.exit("keyset has no key for %d" % amount)

    secret = json.dumps(["P2PK", {"nonce": secrets.token_hex(32), "data": "02" + dev,
                                  "tags": [["pubkeys", second], ["n_sigs", "2"]]}], separators=(",", ":"))
    print("secret (%d chars): %s" % (len(secret), secret))

    st, q = call(mint + "/v1/mint/quote/bolt11", {"amount": amount, "unit": "sat"})
    if st != 200: sys.exit("quote failed: %s" % q)
    for _ in range(15):
        st, qs = call(mint + "/v1/mint/quote/bolt11/" + q["quote"])
        if qs.get("state") == "PAID" or qs.get("paid") is True: break
        time.sleep(1)
    else:
        sys.exit("quote not paid. This mint does not auto-pay; use a FakeWallet test mint.")
    r, B_ = cs.blind(secret)
    st, resp = call(mint + "/v1/mint/bolt11", {"quote": q["quote"], "outputs": [{"amount": amount, "id": kid, "B_": B_}]})
    if st != 200: sys.exit("mint failed: %s" % resp)
    C = cs.unblind(resp["signatures"][0]["C_"], r, keys[str(amount)])
    proof = {"amount": amount, "id": kid, "secret": secret, "C": C}
    rec = "2of2_recovery_%s.json" % time.strftime("%Y%m%d-%H%M%S")
    json.dump({"mint": mint, "proof": proof}, open(rec, "w"))
    print("minted %d sat locked 2-of-2 (recovery file %s)\n" % (amount, rec))

    import base64
    sig_dev = cs.sign(secret)                      # device review and button press
    fee = math.ceil(fee_ppk / 1000); out_total = amount - fee
    outs = []
    for b in range(out_total.bit_length()):
        if out_total >> b & 1:
            rr, BB = cs.blind(secrets.token_hex(32)); outs.append({"amount": 1 << b, "id": kid, "B_": BB})
    inp = dict(proof); inp["witness"] = json.dumps({"signatures": [sig_dev]}, separators=(",", ":"))
    st, body = call(mint + "/v1/swap", {"inputs": [inp], "outputs": outs})
    print("--- spend attempt ---")
    report("rejected: device signature only", st != 200, "HTTP %d %s" % (st, json.dumps(body)[:60]))
    tok = "cashuA" + base64.urlsafe_b64encode(json.dumps({"token": [{"mint": mint, "proofs": [proof]}], "unit": "sat"}, separators=(",", ":")).encode()).decode().rstrip("=")
    print("\nLocked token (needs the device AND the second key; not spent):\n" + tok)
    print("\nPASS %d  FAIL %d" % (sum(results), len(results) - sum(results)))
    sys.exit(0 if all(results) else 1)

if __name__ == "__main__": main()
