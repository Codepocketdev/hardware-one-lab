# Cashu P2PK signer (experiment)

Lab only. Unsigned, unaudited firmware. Use throwaway keys and a test mint with fake funds. Not affiliated with SatoshiLabs or Trezor.

## What it does

The patched Model One can unlock Cashu ecash that is locked to its key (NUT-11, pay to public key). The device checks the lock, shows the raw secret page by page, and signs only after a button press. The key never leaves the device.

## Design

- Key: BIP-340 at m/44'/1237'/2'/0/0. This is a separate path from the Nostr key, so ecash and a Nostr identity are not linked.
- The lock key is the device x-only key with a 02 prefix.
- The signed message is sha256 of the proof secret string, exactly as received.
- Commands, sent inside Ping like the Nostr ones:
  - CASHUPUB returns the x-only key in hex.
  - CASHUSIG BEGIN <len>, CASHUSIG ADD <offset> <chunk>, CASHUSIG SIGN returns the 128-hex signature after approval.
- Limits: secret up to 600 bytes, printable ASCII, no backslashes.
- The device refuses a secret that is not a P2PK secret, has more than one data field, or is locked to any other key.
- Home screen: scripts/apply_cashu1.sh adds a CASHU SIGNER panel as a third mode after the clock and the Nostr signer panel. On the device, the right button cycles the clock, the Nostr signer panel and the Cashu signer panel, and the Cashu panel reads Ready.

## What was tested

- tools/cashu_device_test.py on the real device: 9 of 9 checks. The key differs from the Nostr key, signatures over sha256 of the secret verify for compact and spaced JSON, and five bad inputs are refused with the expected messages.
- tools/cashu_mint_test.py against a local Nutshell 0.18.2 mint with a fake Lightning backend: ecash locked to the device key was refused without a signature, then redeemed with a signature made on the device. The lock had no locktime tag.
- tools/cashu_standin_signer.py is a software stand-in signer that was used first to check the flow without hardware. It holds a public test key and must never hold real funds.

## Not tested

- SIG_ALL, tokens with several proofs, other mints and other wallets.
- Real funds. Everything above used fake sats on a throwaway mint.
- Whether a lock really becomes spendable by anyone after its locktime passes. A test token is waiting for that.

## Limits and risks

- With SIG_INPUTS only the secret is signed, so the device cannot show the amount or the recipient. It shows the raw secret, which includes the lock key and any tags.
- Each proof needs its own approval, so a token with many proofs means many button presses.
- The mint must support NUT-11. A mint that does not may treat locked ecash as spendable by anyone, so check its info endpoint before locking.
- The Nutshell command line adds a one-day locktime by default. The test lock was created with that turned off by setting LOCKTIME_DELTA_SECONDS to 0.
- Flashing unsigned firmware wipes the seed, as with the rest of this project.

## Try it

Apply scripts/apply_cashu1.sh after the earlier patches, build and flash a spare device, restore a throwaway test seed, then run python tools/cashu_device_test.py with the device attached.
