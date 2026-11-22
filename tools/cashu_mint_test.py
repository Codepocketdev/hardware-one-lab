import asyncio
import json
import os
import re
import subprocess
import sys

from cashu.core.p2pk import P2PKSecret
from cashu.core.settings import settings
from cashu.wallet.helpers import deserialize_token_from_string, receive
from cashu.wallet.wallet import Wallet

MINT = os.environ.get("MINT_URL", "http://127.0.0.1:3338")
if not MINT.startswith(("http://127.0.0.1:", "http://localhost:")) and os.environ.get("ALLOW_REMOTE_MINT") != "1":
    raise SystemExit("Refusing a remote mint (%s). Use a test mint with fake funds, or set ALLOW_REMOTE_MINT=1." % MINT)
WALLET_NAME = os.environ.get("WALLET_NAME", "wallet")
PENDING = "/tmp/cashu_pending.json"
SIGS = "/tmp/cashu_sigs.json"


def make_locked_token(lock_key, amount):
    env = dict(os.environ, MINT_URL=MINT, LOCKTIME_DELTA_SECONDS="0")
    result = subprocess.run(
        [
            "poetry", "run", "cashu", "-w", WALLET_NAME, "send", str(amount),
            "--lock", "P2PK:" + lock_key, "-y",
        ],
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


def patch_wallet(lock_key, sigs):
    def keep_ours(self, proofs):
        return [
            proof
            for proof in proofs
            if P2PKSecret.deserialize(proof.secret).data.lower() == lock_key.lower()
        ]

    def sign_all(self, proofs):
        return [sigs[proof.secret] for proof in proofs]

    Wallet.filter_proofs_locked_to_our_pubkey = keep_ours
    Wallet.signatures_proofs_sig_inputs = sign_all


async def open_wallet():
    wallet = await Wallet.with_db(MINT, os.path.join(settings.cashu_dir, WALLET_NAME))
    await wallet.load_mint()
    return wallet


async def lock(device_key, amount):
    if len(device_key) != 64 or any(c not in "0123456789abcdef" for c in device_key):
        raise SystemExit("device key must be 64 lowercase hex characters")
    lock_key = "02" + device_key
    token_string = make_locked_token(lock_key, amount)
    token = deserialize_token_from_string(token_string)
    secrets = [proof.secret for proof in token.proofs]
    for secret in secrets:
        print("secret:", secret)
        if lock_key not in secret or "locktime" in secret:
            raise SystemExit("unexpected lock conditions")
    with open(PENDING, "w", encoding="utf-8") as handle:
        json.dump({"token": token_string, "lock": lock_key, "secrets": secrets}, handle)
    wallet = await open_wallet()
    try:
        await receive(wallet, deserialize_token_from_string(token_string))
        print("UNEXPECTED: redeemed without a signature")
    except Exception as exc:
        print("refused without a signature, as expected:", exc)
    print("saved", PENDING, "with", len(secrets), "secret(s) to sign")


async def redeem():
    with open(PENDING, encoding="utf-8") as handle:
        pending = json.load(handle)
    with open(SIGS, encoding="utf-8") as handle:
        sigs = json.load(handle)
    patch_wallet(pending["lock"], sigs)
    wallet = await open_wallet()
    await receive(wallet, deserialize_token_from_string(pending["token"]))
    print("redeemed with the device signature on", MINT)


def main():
    if len(sys.argv) >= 3 and sys.argv[1] == "lock":
        amount = int(sys.argv[3]) if len(sys.argv) > 3 else 8
        asyncio.run(lock(sys.argv[2], amount))
    elif len(sys.argv) == 2 and sys.argv[1] == "redeem":
        asyncio.run(redeem())
    else:
        raise SystemExit("usage: cashu_mint_test.py lock <device key hex> [amount] | redeem")


main()
