import json
from http.server import BaseHTTPRequestHandler, HTTPServer

from cashu.core.crypto.secp import PrivateKey
from cashu.core.p2pk import schnorr_sign

HOST = "127.0.0.1"
PORT = 8787
SECRET_KEY = PrivateKey(bytes.fromhex("11" * 32), raw=True)
XONLY = SECRET_KEY.pubkey.serialize().hex()[2:]


def check_secret(secret):
    parsed = json.loads(secret)
    if not isinstance(parsed, list) or len(parsed) != 2 or parsed[0] != "P2PK":
        raise ValueError("not a P2PK secret")
    data = parsed[1].get("data", "")
    if len(data) != 66 or data[:2] not in ("02", "03"):
        raise ValueError("bad lock key format")
    if data[2:].lower() != XONLY:
        raise ValueError("lock key is not ours")
    return parsed[1]


class Handler(BaseHTTPRequestHandler):
    def reply(self, code, body):
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path == "/pubkey":
            self.reply(200, {"pubkey": XONLY})
        else:
            self.reply(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/sign":
            self.reply(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        try:
            secret = json.loads(self.rfile.read(length))["secret"]
            check_secret(secret)
        except Exception as exc:
            self.reply(400, {"error": str(exc)})
            return
        print("sign request:", secret, flush=True)
        signature = schnorr_sign(secret.encode("utf-8"), SECRET_KEY).hex()
        self.reply(200, {"sig": signature})

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print("signer pubkey:", XONLY, flush=True)
    HTTPServer((HOST, PORT), Handler).serve_forever()
