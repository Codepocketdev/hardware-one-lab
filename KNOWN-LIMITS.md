# Known limits and risks

- Unsigned, unaudited firmware. The Model One has no secure element and a known physical-extraction weakness.
- Flashing this firmware wipes the seed every time.
- The USB command channel is unauthenticated. On-device review is the only protection.
- ASCII only, content up to 400 characters, up to 20 tags, event up to 900 bytes.
- Kinds 1 and 7 by default. No direct messages and no NIP-04 or NIP-44 methods.
- Only bunker:// links work.
- Signing is slow because trezorctl is launched several times per request.
- The duplicate check in the bridge is not thread-safe. Use a single relay.
- A raw nsec cannot be imported. Only keys from a NIP-06 mnemonic work.
- Events published to public relays cannot be reliably deleted.
- Builds are not reproducible because the build date and time are compiled in.
- Time is kept in RAM, so unplugging loses it.
