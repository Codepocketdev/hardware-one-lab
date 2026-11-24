#!/usr/bin/env python3
"""Local bridge for a 2-of-2 P2PK lock: lets a wallet that holds one key get the
device's signature. Run on the PC with the Trezor attached, next to cashu_sign.py.
  tunnel: ssh -i KEY -N -L 3340:127.0.0.1:3338 root@VPS
  bridge: python cashu_bridge.py --upstream http://127.0.0.1:3340 --port 3338
The wallet talks to the bridge as if it were the mint. On POST /v1/swap the bridge
adds the device signature to inputs locked to the device key plus another key
(n_sigs >= 2, SIG_INPUTS), after the device review and button press. Everything
else is forwarded unchanged. Local test mints only. This stands in for a wallet
hook: the wallet does not ask the device, the bridge does."""
import sys, os, json, ipaddress, threading, urllib.request, urllib.error
from urllib.parse import urlparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cashu_sign as cs

LOCK = threading.Lock()
HOP = {"connection", "keep-alive", "transfer-encoding", "te", "trailer", "upgrade",
       "proxy-authorization", "proxy-authenticate", "content-length", "host", "accept-encoding"}

def is_local(url):
    h = urlparse(url).hostname or ""
    if h == "localhost": return True
    try: return ipaddress.ip_address(h).is_loopback
    except ValueError: return False

def wants_device(secret, sigs, dev):
    try: kind, d = json.loads(secret)
    except Exception: return False
    if kind != "P2PK" or not isinstance(d, dict): return False
    if str(d.get("data", ""))[2:].lower() != dev: return False
    tags = {t[0]: t[1:] for t in d.get("tags", []) if t}
    if tags.get("sigflag", ["SIG_INPUTS"])[0] != "SIG_INPUTS": return False
    try: n = int(tags.get("n_sigs", ["1"])[0])
    except ValueError: return False
    return n >= 2 and "pubkeys" in tags and len(sigs) < n

class H(BaseHTTPRequestHandler):
    upstream = ""; dev = ""
    def log_message(self, *a): pass

    def add_sigs(self, body):
        try: req = json.loads(body)
        except Exception: return body
        changed = False
        for inp in req.get("inputs", []):
            w = inp.get("witness")
            try: wd = w if isinstance(w, dict) else (json.loads(w) if w else {})
            except Exception: wd = {}
            sigs = list(wd.get("signatures", []))
            if not wants_device(inp.get("secret", ""), sigs, self.dev): continue
            print("bridge: input locked to the device key plus another key. Asking the device...")
            with LOCK:
                try: sig = cs.sign(inp["secret"])
                except (Exception, SystemExit) as e:
                    print("bridge: the device did not sign:", e); continue
            wd["signatures"] = sigs + [sig]
            inp["witness"] = wd if isinstance(w, dict) else json.dumps(wd, separators=(",", ":"))
            changed = True
            print("bridge: device signature added")
        return json.dumps(req, separators=(",", ":")).encode() if changed else body

    def forward(self, body):
        req = urllib.request.Request(self.upstream + self.path, data=body, method=self.command)
        for k, v in self.headers.items():
            if k.lower() not in HOP: req.add_header(k, v)
        try:
            r = urllib.request.urlopen(req, timeout=120); st = r.status
        except urllib.error.HTTPError as e:
            r = e; st = e.code
        except Exception as e:
            self.send_response(502); self.end_headers(); self.wfile.write(str(e).encode()); return
        data = r.read()
        self.send_response(st)
        for k, v in r.headers.items():
            if k.lower() not in HOP: self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers(); self.wfile.write(data)

    def do_GET(self): self.forward(None)
    def do_HEAD(self): self.forward(None)
    def do_OPTIONS(self): self.forward(None)
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if self.path.split("?")[0] == "/v1/swap": body = self.add_sigs(body)
        self.forward(body)

def main():
    a = sys.argv[1:]
    up = a[a.index("--upstream") + 1].rstrip("/") if "--upstream" in a else "http://127.0.0.1:3340"
    port = int(a[a.index("--port") + 1]) if "--port" in a else 3338
    if not is_local(up): sys.exit("refusing a non-local upstream: " + up)
    H.upstream = up; H.dev = cs.get_pub().lower()
    print("device key:", H.dev)
    print("bridge on http://127.0.0.1:%d -> %s" % (port, up))
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()

if __name__ == "__main__": main()
