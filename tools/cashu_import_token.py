import json
import sys

from cashu.core.p2pk import P2PKSecret
from cashu.wallet.helpers import deserialize_token_from_string

PENDING = "/tmp/cashu_pending.json"


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: cashu_import_token.py <token file> <device key hex>")
    with open(sys.argv[1], encoding="utf-8") as handle:
        token_string = handle.read().strip()
    device_key = sys.argv[2].lower()
    token = deserialize_token_from_string(token_string)
    if hasattr(token, "proofs"):
        proofs = token.proofs
    else:
        proofs = [proof for part in token.token for proof in part.proofs]
    secrets = [proof.secret for proof in proofs]
    lock = None
    for secret in secrets:
        print("secret:", secret)
        data = P2PKSecret.deserialize(secret).data.lower()
        if len(data) != 66 or data[2:] != device_key:
            raise SystemExit("a proof is not locked to the device key")
        lock = data
    if not secrets:
        raise SystemExit("no proofs found")
    with open(PENDING, "w", encoding="utf-8") as handle:
        json.dump({"token": token_string, "lock": lock, "secrets": secrets}, handle)
    print("saved", PENDING, "with", len(secrets), "secret(s) to sign")


main()
