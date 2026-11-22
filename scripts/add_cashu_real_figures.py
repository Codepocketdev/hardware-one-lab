import os, re, sys
path = sys.argv[1]
imgdir = os.path.join(os.path.dirname(path), "images")
s = open(path, encoding="utf-8").read()
if "On a real mint" in s and "cashu-real-01" in s: sys.exit("real-mint figures already added")

figs = [
 ("cashu-real-01-lock-check.jpg", "Summary page for the Minibits token",
  "Summary page for the Minibits token: “Lock key is ours”, 171 characters, values on the next pages."),
 ("cashu-real-02-secret-1of3.jpg", "Secret page 1 of 3",
  "Secret, page 1 of 3: the start of the secret, with the token’s nonce."),
 ("cashu-real-03-secret-2of3.jpg", "Secret page 2 of 3",
  "Secret, page 2 of 3: the lock key, which is the device’s own public key."),
 ("cashu-real-04-secret-3of3-sign.jpg", "Secret page 3 of 3 with Sign button",
  "Last page: the end of the secret. The right button reads Sign."),
 ("cashu-real-05-receive.jpg", "Wallet receive screen",
  "After the swap, the wallet’s receive screen with the new token and a Receive button."),
 ("cashu-real-06-received.jpg", "Wallet after receiving",
  "The wallet after receiving: the 8 sat are in the balance."),
]
missing = [f[0] for f in figs if not os.path.exists(os.path.join(imgdir, f[0]))]
if missing: sys.exit("NOT WRITTEN: put these files in %s first: %s" % (imgdir, ", ".join(missing)))

html = ["<h2>On a real mint</h2>",
 "<p>These photos are from the real-mint test: an 8 sat token created in Minibits and locked to the device key, spent on mint.minibits.cash. The first four show the review on the device; the last two show the receiving wallet.</p>"]
for fn, alt, cap in figs:
    html.append('<figure style="margin:1.2em 0"><img src="images/%s" alt="%s" loading="lazy" style="max-width:100%%;height:auto;border-radius:6px"><figcaption>%s</figcaption></figure>' % (fn, alt, cap))
block = "\n".join(html) + "\n"

pat = r"<h2[^>]*>\s*Not tested\s*</h2>"
if len(re.findall(pat, s)) != 1: sys.exit("NOT WRITTEN: could not find the 'Not tested' heading exactly once")
s = re.sub(pat, lambda m: block + m.group(0), s)
open(path, "w", encoding="utf-8").write(s); print("real-mint figures added to", path)
