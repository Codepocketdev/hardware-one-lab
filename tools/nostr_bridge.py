#!/usr/bin/env python3
"""nostr_bridge.py - NIP-46 (Nostr Connect) bridge for the Trezor Model One Nostr lab firmware.

Apps send encrypted signing requests over a relay. This bridge decrypts them, forwards
sign_event requests to the Trezor (you review and approve every one on the device), and
sends the signed event back. The bridge has its OWN transport key, stored in the state file.
Your Nostr key never leaves the Trezor.

  python nostr_bridge.py                     run the bridge, print the bunker:// link
  python nostr_bridge.py --relay wss://...   use another relay (repeatable)
  python nostr_bridge.py --selftest          test the relay path without touching the device
  python nostr_bridge.py --reset             new transport key, new secret, forget connected apps
  python nostr_bridge.py --try 'bunker://...' act as a test app against a running bridge

Needs: pip install websockets cryptography   and nip44.py next to this file.
Lab use only: ASCII text, content up to 400 chars, up to 20 tags (the firmware limits).
"""
import argparse
import asyncio
import hashlib
import hmac
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from urllib.parse import quote

import nip44

DEFAULT_RELAY = "wss://relay.damus.io"
STATE_PATH = os.path.join(os.path.expanduser("~"), ".nostr_bridge.json")
WINDOW = 600  # seconds of clock difference accepted on incoming requests
DEDUPE = {"seconds": 90}
P, N, G = nip44.P, nip44.N, nip44.G
POLICY = {"kinds": {1, 7}, "auth_relays": set()}


def norm_relay(url):
    return url.strip().lower().rstrip("/")




class BridgeError(Exception):
    pass


# ---------------------------------------------------------------- BIP-340 and events
def tagged_hash(tag, data):
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + data).digest()


def schnorr_sign(secret32, msg32):
    sk = int.from_bytes(secret32, "big")
    pt = nip44._mul(sk)
    d = sk if pt[1] % 2 == 0 else N - sk
    aux = os.urandom(32)
    t = (d ^ int.from_bytes(tagged_hash("BIP0340/aux", aux), "big")).to_bytes(32, "big")
    k = int.from_bytes(tagged_hash("BIP0340/nonce", t + pt[0].to_bytes(32, "big") + msg32), "big") % N
    r = nip44._mul(k)
    k = k if r[1] % 2 == 0 else N - k
    e = int.from_bytes(tagged_hash("BIP0340/challenge",
                                   r[0].to_bytes(32, "big") + pt[0].to_bytes(32, "big") + msg32), "big") % N
    return r[0].to_bytes(32, "big") + ((k + e * d) % N).to_bytes(32, "big")


def schnorr_verify(pub32, msg32, sig64):
    try:
        pt = nip44._lift_x(int.from_bytes(pub32, "big"))
    except nip44.Nip44Error:
        return False
    r, s = int.from_bytes(sig64[:32], "big"), int.from_bytes(sig64[32:], "big")
    if r >= P or s >= N:
        return False
    e = int.from_bytes(tagged_hash("BIP0340/challenge", sig64[:32] + pub32 + msg32), "big") % N
    res = nip44._add(nip44._mul(s), nip44._mul(N - e, pt))
    return res is not None and res[1] % 2 == 0 and res[0] == r


def event_id(ev):
    ser = json.dumps([0, ev["pubkey"], ev["created_at"], ev["kind"], ev["tags"], ev["content"]],
                     separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(ser.encode()).hexdigest()


def is_hex(s, n):
    return isinstance(s, str) and len(s) == n and all(c in "0123456789abcdef" for c in s)


def verify_event(ev):
    try:
        if not (is_hex(ev["id"], 64) and is_hex(ev["pubkey"], 64) and is_hex(ev["sig"], 128)):
            return False
        if not (isinstance(ev["created_at"], int) and isinstance(ev["kind"], int)):
            return False
        if not isinstance(ev["tags"], list) or not isinstance(ev["content"], str):
            return False
        if event_id(ev) != ev["id"]:
            return False
        return schnorr_verify(bytes.fromhex(ev["pubkey"]), bytes.fromhex(ev["id"]), bytes.fromhex(ev["sig"]))
    except (KeyError, TypeError, ValueError):
        return False


def make_event(secret32, kind, tags, content, created_at=None):
    ev = {"pubkey": nip44.x_only_pub(secret32).hex(),
          "created_at": int(time.time()) if created_at is None else created_at,
          "kind": kind, "tags": tags, "content": content}
    ev["id"] = event_id(ev)
    ev["sig"] = schnorr_sign(secret32, bytes.fromhex(ev["id"])).hex()
    return ev


BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def bech32_encode(hrp, data):
    def polymod(values):
        gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
        chk = 1
        for v in values:
            b = chk >> 25
            chk = (chk & 0x1FFFFFF) << 5 ^ v
            for i in range(5):
                chk ^= gen[i] if (b >> i) & 1 else 0
        return chk
    acc, bits, out = 0, 0, []
    for byte in data:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append((acc >> bits) & 31)
    if bits:
        out.append((acc << (5 - bits)) & 31)
    hrp_exp = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    mod = polymod(hrp_exp + out + [0] * 6) ^ 1
    check = [(mod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(BECH32[v] for v in out + check)


# ---------------------------------------------------------------- the device
ESC = {'"': '\\"', "\\": "\\\\", "\n": "\\n", "\r": "\\r", "\t": "\\t", "\b": "\\b", "\f": "\\f"}


def esc(s):
    out = []
    for ch in s:
        if ch in ESC:
            out.append(ESC[ch])
        elif 0x20 <= ord(ch) <= 0x7E:
            out.append(ch)
        else:
            raise BridgeError("the device only accepts plain ASCII text for now")
    return "".join(out)


def serialize_for_device(ev, pub_hex):
    """The exact NIP-01 text the firmware accepts, or BridgeError."""
    if not isinstance(ev, dict):
        raise BridgeError("event must be a JSON object")
    kind, content, tags = ev.get("kind"), ev.get("content", ""), ev.get("tags", [])
    created = ev.get("created_at", int(time.time()))
    if ev.get("pubkey") not in (None, "", pub_hex):
        raise BridgeError("event pubkey is not the device's key")
    if not (isinstance(kind, int) and not isinstance(kind, bool) and 0 <= kind <= 65535):
        raise BridgeError("bad kind")
    if not (isinstance(created, int) and not isinstance(created, bool) and 0 <= created <= 4294967295):
        raise BridgeError("bad created_at")
    if not isinstance(content, str) or len(content) > 400:
        raise BridgeError("content must be a string of at most 400 characters")
    if not isinstance(tags, list) or len(tags) > 20:
        raise BridgeError("at most 20 tags")
    parts = []
    for tag in tags:
        if not (isinstance(tag, list) and tag and all(isinstance(x, str) for x in tag)):
            raise BridgeError("each tag must be a non-empty list of strings")
        parts.append("[" + ",".join('"%s"' % esc(x) for x in tag) + "]")
    ser = '[0,"%s",%d,%d,[%s],"%s"]' % (pub_hex, created, kind, ",".join(parts), esc(content))
    if len(ser) > 900:
        raise BridgeError("event is over 900 bytes, too big for the device")
    return ser, created


class Device:
    lock = None
    cached_pub = None

    @classmethod
    def create(cls):
        d = cls()
        d.lock = threading.Lock()
        return d

    def ping(self, message):
        exe = shutil.which("trezorctl")
        if not exe:
            raise BridgeError("trezorctl was not found on PATH")
        r = subprocess.run([exe, "ping", message], capture_output=True, text=True)
        if r.returncode != 0:
            text = " ".join((r.stderr + " " + r.stdout).split())
            if "ancel" in text:
                raise BridgeError("rejected on the device")
            raise BridgeError("device error: " + text)
        lines = [ln for ln in r.stdout.splitlines() if ln.strip()]
        return lines[-1].strip() if lines else ""

    def pubkey(self):
        if self.cached_pub is None:
            pub = self.ping("NOSTRPUB")
            if not is_hex(pub, 64):
                raise BridgeError("device did not return a public key (is a seed loaded?)")
            self.cached_pub = pub
        return self.cached_pub

    def sign(self, ser):
        """Send the exact serialization; the user reviews it on the device. Returns (id, sig)."""
        with self.lock:
            if not self.ping("NOSTREV BEGIN %d" % len(ser)).startswith("OK"):
                raise BridgeError("this firmware has no NOSTREV support")
            for off in range(0, len(ser), 180):
                self.ping("NOSTREV ADD %d %s" % (off, ser[off:off + 180]))
            reply = self.ping("NOSTREV SIGN").split()
        if len(reply) != 2:
            raise BridgeError("unexpected reply from the device")
        return reply[0], reply[1]


# ---------------------------------------------------------------- NIP-46 logic
def new_state():
    secret = os.urandom(32)
    return {"secret": secret.hex(), "pubkey": nip44.x_only_pub(secret).hex(),
            "token": os.urandom(16).hex(), "clients": []}


def load_state(path, reset=False):
    if not reset and os.path.exists(path):
        return json.load(open(path))
    state = new_state()
    save_state(path, state)
    return state


def save_state(path, state):
    if not path:
        return
    with open(path, "w") as f:
        json.dump(state, f)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


class Bridge:
    @classmethod
    def create(cls, state, path, device, log=print):
        b = cls()
        b.state, b.path, b.device, b.log = state, path, device, log
        b.secret = bytes.fromhex(state["secret"])
        b.pub = state["pubkey"]
        b.seen = []
        b.recent = {}
        b.dedupe_lock = threading.Lock()
        return b

    def bunker_url(self, relays):
        q = "&".join("relay=" + quote(r, safe="") for r in relays)
        return "bunker://%s?%s&secret=%s" % (self.pub, q, self.state["token"])

    def handle_event(self, ev, now=None):
        """One incoming relay event -> the response event to publish, or None."""
        now = time.time() if now is None else now
        try:
            if ev.get("kind") != 24133 or not verify_event(ev):
                return None
            if not any(t[:2] == ["p", self.pub] for t in ev["tags"] if isinstance(t, list)):
                return None
            if abs(ev["created_at"] - now) > WINDOW or ev["id"] in self.seen:
                return None
            self.seen = (self.seen + [ev["id"]])[-2000:]
            client = ev["pubkey"]
            ck = nip44.get_conversation_key(self.secret, bytes.fromhex(client))
            req = json.loads(nip44.decrypt(ev["content"], ck))
            rid, method, params = req["id"], req["method"], req.get("params", [])
            if not (isinstance(rid, str) and isinstance(method, str) and isinstance(params, list)):
                return None
        except (nip44.Nip44Error, KeyError, TypeError, ValueError, AttributeError):
            return None
        try:
            result, error = self.dispatch(client, method, params), None
        except BridgeError as exc:
            result, error = "", str(exc)
        body = {"id": rid, "result": result}
        if error:
            body["error"] = error
        self.log("%s from %s... -> %s" % (method, client[:8], error or "ok"))
        content = nip44.encrypt(json.dumps(body, separators=(",", ":")), ck)
        return make_event(self.secret, 24133, [["p", client]], content)

    def check_policy(self, ev):
        """Refuse before the device is bothered: only allowed kinds, and relay logins only for listed relays."""
        kind = ev.get("kind")
        if kind == 22242:
            relay = ""
            for t in ev.get("tags", []):
                if isinstance(t, list) and len(t) >= 2 and t[0] == "relay" and isinstance(t[1], str):
                    relay = t[1]
                    break
            if norm_relay(relay) not in POLICY["auth_relays"]:
                raise BridgeError("refused: relay login (kind 22242) for %s is not on the allow list (--auth-relay)"
                                  % (relay or "an unknown relay"))
            return
        if kind not in POLICY["kinds"]:
            raise BridgeError("refused: kind %s is not allowed (--allow-kinds)" % kind)

    def dedupe_key(self, ev):
        return json.dumps([ev.get("kind"), ev.get("tags", []), ev.get("content", "")],
                          sort_keys=True, separators=(",", ":"))

    def sign_deduped(self, client, params):
        """One device prompt per distinct note: a retry of the same note reuses the first answer."""
        window = DEDUPE["seconds"]
        try:
            ev = json.loads(params[0]) if params and isinstance(params[0], str) else None
        except ValueError:
            ev = None
        if window <= 0 or not isinstance(ev, dict):
            return self.dispatch(client, "sign_event_inner", params)
        key = self.dedupe_key(ev)
        now = time.time()
        with self.dedupe_lock:
            for k in [k for k, e in self.recent.items() if e["done"] and now - e["t"] > window]:
                del self.recent[k]
            entry = self.recent.get(key)
            leader = entry is None
            if leader:
                entry = {"done": False, "t": now, "event": threading.Event(), "result": None, "error": None}
                self.recent[key] = entry
        if leader:
            try:
                entry["result"] = self.dispatch(client, "sign_event_inner", params)
            except BridgeError as exc:
                entry["error"] = str(exc)
            except Exception as exc:
                entry["error"] = "internal error: %s" % exc
            finally:
                entry["done"] = True
                entry["t"] = time.time()
                if entry["error"]:
                    with self.dedupe_lock:
                        self.recent.pop(key, None)
                entry["event"].set()
        else:
            self.log("sign_event kind %s: same note as one already handled or waiting, not asking the device again"
                     % ev.get("kind"))
            if not entry["event"].wait(200):
                raise BridgeError("timed out waiting for the first signing request")
        if entry["error"]:
            raise BridgeError(entry["error"])
        return entry["result"]

    def dispatch(self, client, method, params):
        if method == "connect":
            given = params[1] if len(params) > 1 and isinstance(params[1], str) else ""
            if not given or not hmac.compare_digest(given.encode(), self.state["token"].encode()):
                raise BridgeError("wrong or missing secret")
            if client not in self.state["clients"]:
                self.state["clients"].append(client)
                save_state(self.path, self.state)
            return given
        if client not in self.state["clients"]:
            raise BridgeError("not connected: send connect with the secret first")
        if method == "ping":
            return "pong"
        if method == "get_public_key":
            return self.device.pubkey()
        if method == "sign_event":
            return self.sign_deduped(client, params)
        if method == "sign_event_inner":
            if not params or not isinstance(params[0], str):
                raise BridgeError("sign_event needs the event as a JSON string")
            try:
                ev = json.loads(params[0])
            except ValueError:
                raise BridgeError("event is not valid JSON")
            pub = self.device.pubkey()
            self.check_policy(ev)
            ser, created = serialize_for_device(ev, pub)
            self.log("sign_event kind %s: review it on the device" % ev.get("kind"))
            eid, sig = self.device.sign(ser)
            if eid != hashlib.sha256(ser.encode()).hexdigest():
                raise BridgeError("device returned a different event id, refusing")
            if not schnorr_verify(bytes.fromhex(pub), bytes.fromhex(eid), bytes.fromhex(sig)):
                raise BridgeError("device signature does not verify, refusing")
            signed = {"id": eid, "pubkey": pub, "created_at": created, "kind": ev["kind"],
                      "tags": ev.get("tags", []), "content": ev.get("content", ""), "sig": sig}
            return json.dumps(signed, separators=(",", ":"))
        raise BridgeError("unsupported method: " + method)


# ---------------------------------------------------------------- the relay connection
async def serve(bridge, relay):
    import websockets
    backoff = 1
    while True:
        try:
            async with websockets.connect(relay, ping_interval=20, ping_timeout=30, max_size=4194304) as ws:
                sub = {"kinds": [24133], "#p": [bridge.pub], "since": int(time.time()) - 5}
                await ws.send(json.dumps(["REQ", "bridge", sub]))
                print("listening on", relay)
                backoff = 1
                async for raw in ws:
                    msg = json.loads(raw)
                    if msg[0] == "EVENT" and len(msg) >= 3:
                        resp = await asyncio.to_thread(bridge.handle_event, msg[2])
                        if resp:
                            await ws.send(json.dumps(["EVENT", resp]))
                    elif msg[0] == "OK" and len(msg) >= 4 and not msg[2]:
                        print("relay refused an event:", msg[3])
                    elif msg[0] in ("NOTICE", "CLOSED"):
                        print("relay says:", msg[1:])
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            print("relay connection lost (%s), retrying in %ds" % (exc, backoff))
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 30)


async def client_call(ws, client_secret, bridge_pub, method, params, wait=25):
    client_pub = nip44.x_only_pub(client_secret).hex()
    ck = nip44.get_conversation_key(client_secret, bytes.fromhex(bridge_pub))
    rid = os.urandom(8).hex()
    body = json.dumps({"id": rid, "method": method, "params": params}, separators=(",", ":"))
    ev = make_event(client_secret, 24133, [["p", bridge_pub]], nip44.encrypt(body, ck))
    await ws.send(json.dumps(["EVENT", ev]))
    end = time.time() + wait
    while time.time() < end:
        try:
            raw = await asyncio.wait_for(ws.recv(), timeout=max(0.5, end - time.time()))
        except asyncio.TimeoutError:
            break
        msg = json.loads(raw)
        if msg[0] == "OK" and not msg[2]:
            raise BridgeError("relay refused the request: %s" % msg[3])
        if msg[0] == "EVENT" and msg[2].get("kind") == 24133 and verify_event(msg[2]):
            try:
                reply = json.loads(nip44.decrypt(msg[2]["content"], ck))
            except (nip44.Nip44Error, ValueError):
                continue
            if reply.get("id") == rid:
                return reply
    raise BridgeError("no reply from the bridge within %d seconds" % wait)


async def selftest(relay):
    import websockets
    state = new_state()
    bridge = Bridge.create(state, None, None, log=lambda s: print("  bridge:", s))
    task = asyncio.create_task(serve(bridge, relay))
    await asyncio.sleep(3)
    client_secret = os.urandom(32)
    client_pub = nip44.x_only_pub(client_secret).hex()
    ok = True
    async with websockets.connect(relay, max_size=4194304) as ws:
        await ws.send(json.dumps(["REQ", "client", {"kinds": [24133], "#p": [client_pub], "since": int(time.time()) - 5}]))
        await asyncio.sleep(1)
        for method, params, want in [("ping", [], "unconnected"), ("connect", [bridge.pub, state["token"]], state["token"]),
                                     ("ping", [], "pong")]:
            try:
                reply = await client_call(ws, client_secret, bridge.pub, method, params)
            except BridgeError as exc:
                print("FAIL", method, "->", exc)
                ok = False
                break
            if want == "unconnected":
                good = bool(reply.get("error"))
            else:
                good = reply.get("result") == want and not reply.get("error")
            print("PASS" if good else "FAIL", method, "->", reply)
            ok = ok and good
    task.cancel()
    print("SELFTEST", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def parse_bunker(url):
    from urllib.parse import parse_qs, urlparse
    u = urlparse(url)
    if u.scheme != "bunker" or not is_hex(u.netloc, 64):
        raise BridgeError("not a bunker:// link")
    q = parse_qs(u.query)
    return u.netloc, q.get("relay", []), q.get("secret", [""])[0]


async def try_link(url, text):
    """Act like an app: connect through the link, ask for the key, ask for one signature."""
    import websockets
    pub, relays, secret = parse_bunker(url)
    if not relays:
        raise BridgeError("the link has no relay")
    sk = os.urandom(32)
    client_pub = nip44.x_only_pub(sk).hex()
    async with websockets.connect(relays[0], max_size=4194304) as ws:
        await ws.send(json.dumps(["REQ", "client", {"kinds": [24133], "#p": [client_pub], "since": int(time.time()) - 5}]))
        await asyncio.sleep(1)
        r = await client_call(ws, sk, pub, "connect", [pub, secret])
        print("connect          ->", r.get("error") or "ok")
        if r.get("error"):
            return 1
        r = await client_call(ws, sk, pub, "get_public_key", [])
        print("get_public_key   ->", r.get("error") or r["result"])
        if r.get("error"):
            return 1
        print("sign_event       -> review the note on your Trezor and approve it (3 minutes)...")
        note = {"kind": 1, "content": text, "tags": [["t", "nostr"]], "created_at": int(time.time())}
        r = await client_call(ws, sk, pub, "sign_event", [json.dumps(note)], wait=180)
        if r.get("error"):
            print("sign_event       ->", r["error"])
            return 1
        ev = json.loads(r["result"])
        good = verify_event(ev) and ev["content"] == text
        print("signed event verifies:", good)
        print(json.dumps(ev, separators=(",", ":")))
        return 0 if good else 1


def run_selftest(relay):
    try:
        return asyncio.run(selftest(relay))
    except Exception as exc:
        print("SELFTEST FAILED: the relay dropped or refused the connection (%s)" % exc)
        return 1


def main():
    ap = argparse.ArgumentParser(description="NIP-46 bridge for the Trezor Model One Nostr lab firmware")
    ap.add_argument("--relay", action="append", help="relay URL (repeatable)")
    ap.add_argument("--selftest", action="store_true", help="test the relay path without the device")
    ap.add_argument("--reset", action="store_true", help="new transport key and secret")
    ap.add_argument("--try", dest="try_url", metavar="BUNKER_URL", help="act as a test app against a running bridge")
    ap.add_argument("--text", default="hello from a Trezor bridge test", help="note text for --try")
    ap.add_argument("--state", default=STATE_PATH)
    ap.add_argument("--dedupe-seconds", type=int, default=90,
                    help="reuse the first answer for a repeated identical note within this time (0 = off)")
    ap.add_argument("--allow-kinds", default="1,7", help="event kinds the bridge passes to the device (default 1,7)")
    ap.add_argument("--auth-relay", action="append", default=[], help="relay allowed to get a login signature (repeatable)")
    args = ap.parse_args()
    DEDUPE["seconds"] = args.dedupe_seconds
    try:
        POLICY["kinds"] = {int(x) for x in args.allow_kinds.split(",") if x.strip()}
    except ValueError:
        sys.exit("--allow-kinds must be numbers separated by commas")
    POLICY["auth_relays"] = {norm_relay(r) for r in args.auth_relay}
    relays = args.relay or [DEFAULT_RELAY]
    if args.selftest:
        sys.exit(run_selftest(relays[0]))
    if args.try_url:
        try:
            sys.exit(asyncio.run(try_link(args.try_url, args.text)))
        except BridgeError as exc:
            sys.exit("Failed: %s" % exc)
    state = load_state(args.state, reset=args.reset)
    device = Device.create()
    try:
        user_pub = device.pubkey()
    except BridgeError as exc:
        sys.exit("Cannot read the device key: %s" % exc)
    bridge = Bridge.create(state, args.state, device)
    print("Nostr key (from the Trezor): %s" % user_pub)
    print("npub: %s" % bech32_encode("npub", bytes.fromhex(user_pub)))
    print("Bridge transport key: %s (this is not your Nostr key)" % bridge.pub)
    print("\nPaste this into a Nostr app that supports NIP-46:\n  %s\n" % bridge.bunker_url(relays))
    print("Anyone with that link can ask for signatures, but every one needs your approval on the device.")
    print("Policy: kinds %s; relay logins (22242) allowed for: %s"
          % (sorted(POLICY["kinds"]), sorted(POLICY["auth_relays"]) or "none"))

    async def run():
        await asyncio.gather(*[serve(bridge, r) for r in relays])
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        print("\nstopped")


if os.path.basename(sys.argv[0]) == "nostr_bridge.py":
    main()
