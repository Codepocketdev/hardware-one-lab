# Architecture

Lab project. Not affiliated with SatoshiLabs or Trezor. Base: upstream trezor-firmware commit 9d4f7db2b06fc91e2b5d64d6d6426fb0cd44a3d (6 Nov 2026), legacy firmware.

## Pieces

- Firmware patches: patched Trezor Model One firmware that can sign Nostr events (BIP-340) with a NIP-06 key after the user reviews the whole event on the device screen.
- Host tools: Python scripts that talk to the device with trezorctl.
- Bridge: tools/nostr_bridge.py, a NIP-46 (Nostr Connect) remote signer that runs on the PC with the Trezor attached.

## Flow

    Nostr client  <-- relay (NIP-46) -->  bridge on PC  <-- USB, trezorctl ping -->  Trezor Model One

The client asks the bridge to sign. The bridge checks its policy, sends the exact NIP-01 serialization to the device, the user reads it on the OLED and presses a button, and the device returns the event id and signature. The Nostr private key never leaves the device.

## Firmware

Unsigned lab build (PRODUCTION=0). Patches are applied in order:

1. 01 clock: home screen clock and SETTIME (scripts/apply_clock3.sh)
2. 02 Nostr signer: NOSTRPUB, NOSTRSIGN, NOSTREV, tag review pages (scripts/apply_nostr1.sh to apply_nostr4.sh)
3. Mode toggle: right button on the home screen switches the clock and the NOSTR SIGNER panel (scripts/apply_mode1.sh)

Re-running an earlier script can remove later patches.

Flashing unsigned firmware wipes the seed every time. After each flash restore the lab seed with trezorctl device recover -w 24 and check that trezorctl ping NOSTRPUB returns the expected key. trezorctl device load needs a debug (DEBUG_LINK) build, which is not built here.

## Device commands

Sent as trezorctl ping "...". Ping echoes text it does not understand, so an echoed command means the firmware lacks it. No protobuf changes are needed.

- NOSTRPUB returns the 64-hex x-only public key for NIP-06 path m/44'/1237'/0'/0/0.
- SETTIME <unix> <utc_offset_seconds> sets the clock.
- NOSTRSIGN <created_at> <kind> <text>: older command, up to 80 ASCII characters, no tags.
- NOSTREV BEGIN <len> starts a transfer and returns OK.
- NOSTREV ADD <offset> <chunk> adds up to 180 characters.
- NOSTREV SIGN shows the event and returns <id> <sig> after approval.

The host sends the exact NIP-01 serialization [0,"<pub>",<created_at>,<kind>,<tags>,"<content>"]. The device shows it and signs the sha256 of it.

## On-device review

A summary page (kind, tag count, tag names, text length), one page per tag, then the text pages. The right button signs or advances, the left button cancels.

## Limits

ASCII only, content up to 400 characters, up to 20 tags, whole event up to 900 bytes.

## Tools

- tools/nostr_send.py sends one event to NOSTREV and verifies the result.
- tools/nostr_ref.py is a slow pure-Python reference for NIP-06 and BIP-340. Test seeds only.
- tools/nip44.py and tools/test_nip44.py implement and test NIP-44.
- tools/nostr_bridge.py is the NIP-46 bridge. See BRIDGE.md.
