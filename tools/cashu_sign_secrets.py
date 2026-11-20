import hashlib
import json
import sys

import cashu_device_test as dev


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: cashu_sign_secrets.py <pending.json> <sigs.json>")
    with open(sys.argv[1], encoding="utf-8") as handle:
        pending = json.load(handle)
    pub = dev.tz("CASHUPUB")
    if pending["lock"][2:] != pub:
        raise SystemExit("this token is not locked to the device Cashu key")
    sigs = {}
    total = len(pending["secrets"])
    for index, secret in enumerate(pending["secrets"], 1):
        print("Signing %d of %d. Read each page on the Trezor, then press Sign." % (index, total))
        sig = dev.sign_secret(secret)
        digest = hashlib.sha256(secret.encode("utf-8")).digest()
        if not dev.verify(bytes.fromhex(pub), digest, bytes.fromhex(sig)):
            raise SystemExit("signature did not verify")
        sigs[secret] = sig
    with open(sys.argv[2], "w", encoding="utf-8") as handle:
        json.dump(sigs, handle)
    print("wrote", sys.argv[2])


main()
