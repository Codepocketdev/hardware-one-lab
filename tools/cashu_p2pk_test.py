import asyncio
import json
import os
import re
import subprocess
import sys
import urllib.request

from cashu.core.p2pk import P2PKSecret
from cashu.core.settings import settings
from cashu.wallet.helpers import deserialize_token_from_string, receive
from cashu.wallet.wallet import Wallet

MINT = "http://127.0.0.1:3338"
SIGNER = os.environ.get("SIGNER_URL", "http://127.0.0.1:8787")
AMOUNT = sys.argv[1] if len(sys.argv) > 1 else "8"


def signer_pubkey():
    with urllib.request.urlopen(SIGNER + "/pubkey", timeout=10) as resp:
        return json.load(resp)["pubkey"]


def signer_sign(secret):
    body = json.dumps({"secret": secret}).encode()
    request = urllib.request.Request(
        SIGNER + "/sign", data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=300) as resp:
        return json.load(resp)["sig"]


def make_locked_token(lock_key):
    env = dict(os.environ, MINT_URL=MINT, LOCKTIME_DELTA_SECONDS="0")
    result = subprocess.run(
        ["poetry", "run", "cashu", "send", AMOUNT, "--lock", "P2PK:" + lock_key, "-y"],
        env=env,
        cwd="/app",
        capture_output=True,
        text=True,
    )
    match = re.search(r"cashu[AB][A-Za-z0-9_=-]+", result.stdout)
    if not match:
        print(result.stdout)
        print(result.stderr)
        raise SystemExit("no token produced")
    return match.group(0)


def patch_wallet(lock_key):
    def keep_ours(self, proofs):
        ours = []
        for proof in proofs:
            secret = P2PKSecret.deserialize(proof.secret)
            if secret.data.lower() == lock_key.lower():
                ours.append(proof)
        return ours

    def sign_all(self, proofs):
        return [signer_sign(proof.secret) for proof in proofs]

    Wallet.filter_proofs_locked_to_our_pubkey = keep_ours
    Wallet.signatures_proofs_sig_inputs = sign_all


async def main():
    lock_key = "02" + signer_pubkey()
    print("lock key:", lock_key)
    token_string = make_locked_token(lock_key)
    token = deserialize_token_from_string(token_string)
    for proof in token.proofs:
        print("secret:", proof.secret)
    patch_wallet(lock_key)
    wallet = await Wallet.with_db(MINT, os.path.join(settings.cashu_dir, "wallet"))
    await wallet.load_mint()
    await receive(wallet, token)
    print("redeemed with external signature")


asyncio.run(main())
