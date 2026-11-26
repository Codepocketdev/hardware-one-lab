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
- Default policy (--auth-relay none): no kind 22242 relay-login prompts reached the device in either client.



## Not tested

- nostrconnect:// login, Amethyst, and Jumble (Jumble gave no usable login and was not diagnosed).
- switch_relays handling.
- Persistent device connection.

## Cashu P2PK signer: verified

- On the device, a test script passed 9 of 9 checks, and tools/cashu_negative_test.py passed 28 of 28 (refusals before any button prompt, plus cancel on the first and last page).
- Local Nutshell 0.18.2 mint with a fake Lightning backend: ecash locked to the device key was refused without a signature and redeemed with a signature made on the device.
- cashu.me: a token locked to the device key was created, four proofs were signed on the device, and the local mint paid out 14 sat.
- Real mint, 22 Nov 2026: one 8 sat token created in Minibits and locked to the device key was spent on mint.minibits.cash. The device showed the 171-character secret over 3 pages. A host tool, not a wallet, built the swap.
- 2-of-2, 24 Nov 2026, local Nutshell 0.18.2 mint with fake funds (tools/cashu_2of2_test.py): the device key as data plus a software key in pubkeys with n_sigs 2. Refused: device only, software only, device plus a wrong key, the same signature twice, and a replay. Accepted: device plus software. Result 6 passed, 0 failed.
- 2-of-2 with cashu.me, 24 Nov 2026: a token locked to the device key plus a cashu.me public key. cashu.me showed it as locked to it and failed to receive it (not enough pubkeys (2) or signatures (1) present for n_sigs (2)). With tools/cashu_bridge.py between cashu.me and the mint, the device signed and cashu.me received 7 sat.

## Cashu P2PK signer: not tested

- More than one proof on a real mint, other mints, and larger tokens.
- The SIG_ALL flag, and wallets other than cashu.me.
- A lock lapsing after its locktime when there is no refund key.
- 2-of-3, the refund path, and multisig on a real mint.
- A wallet asking the device to sign. The scripts and the bridge did the asking.
- Mint DLEQ proofs are not verified by the host tool.
