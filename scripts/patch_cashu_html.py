import re, sys
path = sys.argv[1]
s = open(path, encoding="utf-8").read()
if "mint.minibits.cash" in s and "cashu_negative_test" in s: sys.exit("already updated")

NEW_TESTS = (
    "the local test mint paid out 14 sat.</li>\n"
    "<li>On a real mint, on 22 November 2026: an 8 sat cashuB token, created in Minibits and locked to the device key, "
    "was spent on mint.minibits.cash. The device showed “Lock key is ours” and the 171-character secret over 3 pages, "
    "and signed on the last page. The mint accepted the signature with no fee, and the new proofs were received in cashu.me. "
    "A host tool, not a wallet, built and sent the swap.</li>\n"
    "<li>A second test script, tools/cashu_negative_test.py, ran 28 checks on the device and all passed. Twenty-one automatic checks "
    "were each refused with the firmware’s own message before any button prompt: wrong command order, bad lengths, a wrong or truncated "
    "lock key, a 04 key prefix, not P2PK, a missing closing bracket, two or no data fields, a backslash, non-ASCII text, a control "
    "character, and a wipe of the loaded secret after a refusal. With button presses, cancelling on the first page and on the last "
    "page both produced no signature, and a bare SIGN afterwards was refused. An approved signature verified for the secret and "
    "failed for an altered secret and for another key.</li>\n"
    "<li>On the home screen of the real device, the right button cycled the clock, the Nostr signer panel and the Cashu signer panel.")

NEW_LIMITS = (
    "took four rounds of button presses.</li>\n"
    "<li>Newer mints use 33-byte keyset IDs (starting with 01), while a cashuB token carries only the first 8 bytes. "
    "The host tool has to look up the full ID in the mint’s keyset list before any request, or the mint refuses it.</li>\n"
    "<li>Redeeming swaps the locked proof for new unlocked proofs, so the result is a plain bearer token until a wallet imports it. "
    "The host tool does the swap, not a wallet, and it does not verify the mint’s DLEQ proofs.")

edits = [
 (r"tests run on 20 November 2026", "tests run on 20 and 22 November 2026", 1, True),
 (r"A mint accepted the signature, including for a token created in cashu\.me\.",
  "Mints accepted the signature: a local test mint, and once a real mint, where an 8 sat token created in Minibits was spent on mint.minibits.cash.", 1, True),
 (r"Everything was tested on a local test mint with fake funds\. No sats were locked or spent on a real mint\.",
  "Everything except one test ran on a local test mint with fake funds. That one test spent a single 8 sat token on a real mint (mint.minibits.cash) on 22 November 2026.", 1, True),
 (r"recovery words were exposed during the work, so its keys are public\.",
  "recovery words were exposed during the work, so its keys are public. The real-mint test used a freshly generated seed instead.", 1, True),
 (r"the local test mint paid out 14 sat\.(?=\s*</li>)", NEW_TESTS, 1, True),
 (r"Spending on a real mint\..*?nothing was locked or spent there\.",
  "Spending beyond one proof on a real mint. Only a single 8 sat proof on Minibits was spent; other mints, larger tokens and several proofs on a real mint were not tested.", 1, True),
 (r"took four rounds of button presses\.(?=\s*</li>)", NEW_LIMITS, 1, True),
 (r"apply\s*(?:<code>)?scripts/apply_cashu1\.sh(?:</code>)?\s*after the earlier patches",
  "apply patches 01 to 04 from the patches folder, in order, with git apply", 1, True),
 (r"The mint test refuses any mint that is not local unless you override it\.",
  "The mint test refuses any mint that is not local unless you override it. tools/cashu_sign.py decodes cashuA and cashuB tokens (show) and redeems a locked token on a mint (redeem is a dry run unless --send is added); unlike the mint test, it does not refuse real mints. tools/cashu_negative_test.py runs the refusal and cancel tests.", 1, True),
 (r"Lab experiment on a local test mint\.", "Lab experiment on a local test mint and one real-mint test.", 1, False),
]
for pat, rep, want, required in edits:
    n = len(re.findall(pat, s, flags=re.S))
    if n != want:
        if required: sys.exit("NOT WRITTEN: pattern matched %d times (need %d): %s" % (n, want, pat[:60]))
        print("skipped optional edit: " + pat[:50]); continue
    s = re.sub(pat, lambda m: rep, s, flags=re.S)
open(path, "w", encoding="utf-8").write(s)
print("updated", path)
