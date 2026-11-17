# Bridge

tools/nostr_bridge.py lets Nostr clients that support bunker login ask a Trezor Model One running the lab firmware to sign events. Lab use only, with throwaway identities.

## Requirements

- A PC with the Trezor attached, trezorctl on PATH, and Python.
- Python packages: websockets and cryptography.

## Run

    python tools/nostr_bridge.py --relay wss://relay.primal.net

It prints a bunker:// link. Paste it into a client that supports bunker login.

The bridge keeps its own transport key and connection secret in ~/.nostr_bridge.json. These are not the Nostr key. Never commit that file. Use the same link for lab tests and do not run --reset unless you want a new link.

## Supported methods

connect (needs the secret), get_public_key, sign_event, ping.

Refused: NIP-04 and NIP-44 encrypt and decrypt (the device cannot do ECDH), switch_relays, and anything else.

Every signature needs a button press on the device. There is no auto-approve. The bridge refuses events the device cannot show in full instead of trimming them.

## Options

- --relay: use one relay. Two relays can deliver the same request twice.
- --selftest: connect to the relay and run a request round trip.
- --reset: create a new transport key and connection secret.
- --try 'bunker://...' --text: act as a test client against a bridge link.
- --allow-kinds: kinds the bridge will forward to the device. Default 1,7.
- --auth-relay: allowlist for kind 22242 (NIP-42 relay login). Default none.
- --dedupe-seconds: one device prompt for identical kind, tags and content within this window. Default 90. A retry reuses the first signed event.

## Notes

- Only bunker:// links work. Clients that show only nostrconnect:// (QR) will not connect.
- Each signing launches trezorctl several times before the first screen appears, so it is slow and some clients time out.
- The duplicate check is not thread-safe.
