#!/usr/bin/env python3
"""Negative and refusal tests for the Cashu P2PK signer (Trezor Model One lab firmware).
Run on the PC with the Trezor attached, next to cashu_sign.py.
  python cashu_negative_test.py                 automatic refusals (no button presses)
  python cashu_negative_test.py --interactive   adds cancel and approve tests (you press buttons)
PASS = refused with the expected message. WARN = refused, other message. FAIL = accepted or signature leaked.
"""
import sys, re, hashlib, subprocess, secrets
import cashu_sign as cs

CH = 100
res = {"PASS": 0, "WARN": 0, "FAIL": 0}

def raw(text):
    r = subprocess.run(["trezorctl", "ping", text], capture_output=True, text=True, encoding="utf-8", errors="replace")
    if r.returncode == 0:
        lines = r.stdout.strip().splitlines()
        return True, (lines[-1].strip() if lines else "")
    return False, (r.stdout.strip() + " " + r.stderr.strip()).strip()

def report(name, ok_refused, out, expect):
    leaked = re.search(r"\b[0-9a-f]{128}\b", out) is not None
    low = out.lower()
    if not ok_refused or leaked:
        status = "FAIL"
    elif any(e.lower() in low for e in expect):
        status = "PASS"
    else:
        status = "WARN"
    res[status] += 1
    print("%-5s %-34s %s" % (status, name, out[:90].replace("\n", " ")))

def run_steps(steps):
    """send commands in order; stop at the first refusal. -> (refused, last output)"""
    out = ""
    for s in steps:
        ok, out = raw(s)
        if not ok: return True, out
    return False, out

def steps_for(secret):
    b = secret.encode("utf-8"); st = ["CASHUSIG BEGIN %d" % len(b)]
    for i in range(0, len(secret), CH):
        st.append("CASHUSIG ADD %d %s" % (len(secret[:i].encode("utf-8")), secret[i:i + CH]))
    return st + ["CASHUSIG SIGN"]

def p2pk(data, nonce=None, tail='"tags":[]'):
    n = nonce if nonce is not None else secrets.token_hex(32)
    return '["P2PK",{"nonce":"%s","data":"%s",%s}]' % (n, data, tail)

def case(name, steps, expect):
    refused, out = run_steps(steps)
    report(name, refused, out, expect)

def main():
    inter = "--interactive" in sys.argv
    pub = cs.get_pub()
    print("device key: " + pub); print("--- automatic refusals (no button presses expected) ---")
    other = "02" + "11" * 32
    case("SIGN with nothing loaded", ["CASHUSIG SIGN"], ["Secret incomplete"])
    case("ADD before BEGIN", ["CASHUSIG ADD 0 abc"], ["Send BEGIN first"])
    case("unknown subcommand", ["CASHUSIG HELLO"], ["Use BEGIN"])
    case("BEGIN length 59 (too short)", ["CASHUSIG BEGIN 59"], ["BEGIN needs a length"])
    case("BEGIN length 601 (too long)", ["CASHUSIG BEGIN 601"], ["BEGIN needs a length"])
    case("BEGIN not a number", ["CASHUSIG BEGIN abc"], ["BEGIN needs a length"])
    case("BEGIN with trailing junk", ["CASHUSIG BEGIN 100 x"], ["BEGIN needs a length"])
    case("ADD wrong offset", ["CASHUSIG BEGIN 100", "CASHUSIG ADD 5 " + "a" * 20], ["Bad chunk offset"])
    case("ADD larger than declared", ["CASHUSIG BEGIN 60", "CASHUSIG ADD 0 " + "a" * 70], ["Bad chunk size"])
    case("SIGN with incomplete secret", ["CASHUSIG BEGIN 100", "CASHUSIG ADD 0 " + "a" * 50, "CASHUSIG SIGN"], ["Secret incomplete"])
    case("locked to another key", steps_for(p2pk(other)), ["Locked to another key"])
    case("lock key prefix 04", steps_for(p2pk("04" + pub)), ["Bad lock key prefix"])
    case("lock key truncated", steps_for(p2pk("02" + pub[:60])), ["Locked to another key", "Bad data field"])
    case("not P2PK (HTLC)", steps_for(p2pk("02" + pub).replace('"P2PK"', '"HTLC"')), ["Not a P2PK secret"])
    case("missing closing bracket", steps_for(p2pk("02" + pub)[:-1]), ["Not a P2PK secret"])
    case("two data fields", steps_for(p2pk("02" + pub, tail='"data":"%s","tags":[]' % other)), ["Need one data field"])
    case("no data field", steps_for('["P2PK",{"nonce":"%s","tags":[]}]' % secrets.token_hex(32)), ["Need one data field"])
    case("backslash in secret", steps_for(p2pk("02" + pub, nonce="a\\nb" + "0" * 40)), ["Unsupported character"])
    case("non-ASCII character", steps_for(p2pk("02" + pub, nonce="caf\u00e9" + "0" * 40)), ["Unsupported character"])
    case("control character (tab)", steps_for(p2pk("02" + pub, nonce="a\tb" + "0" * 40)), ["Unsupported character"])
    case("state wiped after refusal", ["CASHUSIG BEGIN 100", "CASHUSIG ADD 0 " + "a" * 50, "CASHUSIG SIGN", "CASHUSIG SIGN"], ["Secret incomplete"])

    if inter:
        print("--- interactive: follow the prompts on the device ---")
        good = p2pk("02" + pub)
        input("\nTest A: press the LEFT button (Cancel) on the FIRST page. Enter to start...")
        refused, out = run_steps(steps_for(good)); report("cancel on first page", refused, out, ["cancel"])
        case("bare SIGN after cancel is refused", ["CASHUSIG SIGN"], ["Secret incomplete"])
        input("\nTest B: press Next on every page, then Cancel (left) on the LAST page. Enter to start...")
        refused, out = run_steps(steps_for(good)); report("cancel on last page", refused, out, ["cancel"])
        case("bare SIGN after cancel is refused", ["CASHUSIG SIGN"], ["Secret incomplete"])
        input("\nTest C: approve this one (Next ... Sign). Enter to start...")
        refused, out = run_steps(steps_for(good))
        sig = out.split()[-1] if not refused else ""
        good_sig = (not refused) and len(sig) == 128
        h = hashlib.sha256(good.encode()).digest(); pk = bytes.fromhex(pub)
        checks = [
            ("approved signature is valid", good_sig and cs.verify(pk, h, bytes.fromhex(sig))),
            ("rejects altered secret", good_sig and not cs.verify(pk, hashlib.sha256((good + " ").encode()).digest(), bytes.fromhex(sig))),
            ("rejects other public key", good_sig and not cs.verify(bytes.fromhex("11" * 32), h, bytes.fromhex(sig))),
        ]
        for n, ok in checks:
            res["PASS" if ok else "FAIL"] += 1
            print("%-5s %s" % ("PASS" if ok else "FAIL", n))
    else:
        print("(add --interactive for cancel and approve tests)")
    print("\nPASS %d  WARN %d  FAIL %d" % (res["PASS"], res["WARN"], res["FAIL"]))
    sys.exit(1 if res["FAIL"] else 0)

if __name__ == "__main__": main()
