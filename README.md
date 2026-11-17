# trezor-one-lab

Experiments with custom firmware for the Trezor Model One (legacy firmware), plus a host-side bridge.
Each firmware experiment is a separate patch against upstream trezor-firmware.

This is an independent hobby project. It is not affiliated with, endorsed by or supported by SatoshiLabs or Trezor.
TREZOR and TREZOR ONE are registered trademarks of SatoshiLabs Group a.s. "For Trezor Model One" is used only to say which hardware this runs on.

## Lab only

Unofficial, unsigned, unaudited firmware. Installing it wipes any seed on the device.
Use a spare device, a throwaway seed and no funds. Never use it for real money or a real Nostr identity.
The Model One has no secure element and has a known physical-extraction weakness.
No firmware binaries are published here. Build your own.

## Status

| # | Experiment | Status |
|---|---|---|
| 01 | Clock and date home screen, time set over USB | working on a real device |
| 02 | Nostr event signer (NIP-06 key, on-device review) | working on a real device |
| 02b | NIP-46 bridge (tools/nostr_bridge.py) | tested with a test app, Coracle and noStrudel |
| 03 | Snake | planned |

Tested on real hardware or a real client:
- Signing kind 1 events with tags, reviewed page by page on the device, ids and BIP-340 signatures checked independently.
- NIP-44 module passes all 155 official test vectors.
- Bridge selftest on relay.primal.net and relay.snort.social.
- Bridge login and published notes from Coracle and noStrudel.
- Bridge duplicate-request handling (--dedupe-seconds): noStrudel gave one device review and one note per post.
- Bridge default policy (kinds 1,7): kind 1 notes accepted in both clients.
- Home-screen mode toggle: right button switches the clock and the NOSTR SIGNER panel (scripts/apply_mode1.sh).

Written but not yet confirmed against a real client or device:
- Bridge --auth-relay: refusal of kind 22242 relay-login requests not yet observed.

## Threat model

- The Nostr private key never leaves the device.
- Every signature needs a button press after the whole event is shown on the device screen. There is no auto-approve.
- The USB command channel is unauthenticated, so the on-device review is the only protection.
- The bridge refuses what the device cannot show in full instead of trimming it.
- The bridge keeps its own transport key and connection secret in ~/.nostr_bridge.json. They are not the Nostr key and must never be committed.

## Limits

- ASCII only, content up to 400 characters, up to 20 tags, whole event up to 900 bytes.
- Bridge default kinds are 1 and 7. No NIP-04 or NIP-44 encrypt or decrypt (the device cannot do ECDH), no direct messages.
- Only bunker:// links work. Clients that show only nostrconnect:// will not connect.
- Signing is slow: trezorctl is launched several times per request.
- Flashing unsigned firmware wipes the seed every time.
- Events published to public relays cannot be reliably deleted.

## What is in this repo

- patches/01-clock.patch, patches/02-nostr-signer.patch: diffs against upstream commit 9d4f7db2b06fc91e2b5d64d6d6426fb0cd44a3d7 (6 Nov 2026). 02 applies on top of 01.
- scripts/: apply_clock3.sh, apply_nostr1.sh to apply_nostr4.sh, apply_mode1.sh, vps_setup.sh, settime.sh, settime.ps1. Re-running an earlier script can remove later patches.
- tools/: nostr_bridge.py, nostr_send.py, nostr_ref.py, nip44.py, test_nip44.py.

## Build (device)

    git clone --depth 1 https://github.com/trezor/trezor-firmware.git && cd trezor-firmware
    git fetch --depth 1 origin 9d4f7db2b06fc91e2b5d64d6d6426fb0cd44a3d7
    git checkout 9d4f7db2b06fc91e2b5d64d6d6426fb0cd44a3d7
    git submodule update --init --depth 1 vendor/nanopb vendor/libopencm3 vendor/secp256k1-zkp vendor/QR-Code-generator vendor/ts-tvl
    git apply /path/to/patches/01-clock.patch
    git apply /path/to/patches/02-nostr-signer.patch
    cd legacy && unset EMULATOR HEADLESS DEBUG_LINK && export PRODUCTION=0
    TZ=Africa/Nairobi uv run ./script/cibuild

Output is firmware/trezor.bin. PRODUCTION=0 is required for unofficial firmware. Needs gcc-arm-none-eabi.
Builds are not reproducible because the build date and time are compiled in.

## Flash and restore

With the device in bootloader mode:

    trezorctl firmware update -f trezor.bin

Confirm the unofficial-firmware prompt. The seed is wiped, so restore a lab seed with trezorctl device recover -w 24, then check that trezorctl ping NOSTRPUB returns your key.
Trezor Suite can reinstall official firmware from bootloader mode.

## Device commands

Sent as trezorctl ping "...". Ping echoes text it does not understand, so an echoed command means the firmware lacks it.

- SETTIME <unix> <utc_offset_seconds>
- NOSTRPUB returns the x-only public key for NIP-06 path m/44'/1237'/0'/0/0
- NOSTREV BEGIN <len>, NOSTREV ADD <offset> <chunk>, NOSTREV SIGN returns <id> <sig> after approval

## Bridge quick start

Run on the PC with the Trezor attached. Needs python, websockets and cryptography.

    python tools/nostr_bridge.py --relay wss://relay.primal.net
    python tools/nostr_bridge.py --selftest

It prints a bunker:// link. Paste it into a client that supports bunker login. Use a throwaway identity.
Other flags: --reset, --try, --allow-kinds, --auth-relay, --dedupe-seconds.

## Security

Report vulnerabilities in upstream Trezor firmware to security@satoshilabs.com.

## License

- patches/ and scripts/: LGPL-3.0, matching upstream legacy/ (see LICENSE).
- tools/: MIT, copyright Codepocketdev (see tools/LICENSE).
