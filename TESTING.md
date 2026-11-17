# Testing

Only what was actually observed is listed as verified.

## Verified on real hardware or a real client

- Kind 1 events with tags are signed on the device. Summary, per-tag and text pages were photographed on the OLED.
- Several signed events were checked independently: id equals sha256 of the NIP-01 serialization and the BIP-340 signature is valid.
- tools/nip44.py passed all 155 official NIP-44 vectors.
- Bridge --selftest passed on relay.primal.net and relay.snort.social. nos.lol dropped the third request, relay.nsec.app timed out, and relay.damus.io returned HTTP 521 once.
- Bridge --try test app: connect, get_public_key and a device-approved sign_event worked.
- Coracle: bunker login and a note worked. It sent many kind 22242 (NIP-42) prompts, one per relay.
- noStrudel: login through its Nostr Connect box with the bunker link worked. A note was published to relay.primal.net and relay.damus.io. It produced two sequential sign requests and two identical notes.
- Mode toggle: the right button on the home screen switches between the clock and the NOSTR SIGNER panel.
- Retest on 17 Nov 2026 with noStrudel and a second client: one device review and one note per post, no duplicate. Default policy accepted kind 1.

## Written but not confirmed against a real client

- --auth-relay: refusal of kind 22242 (NIP-42 relay login) not yet observed.

## Not tested

- nostrconnect:// login, Amethyst, and Jumble (Jumble gave no usable login and was not diagnosed).
- switch_relays handling.
- Persistent device connection.
