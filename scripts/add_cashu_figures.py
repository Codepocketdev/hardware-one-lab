import os, re, sys
path = sys.argv[1]
imgdir = os.path.join(os.path.dirname(path), "images")
s = open(path, encoding="utf-8").read()
if "What the device shows" in s: sys.exit("figures already added")

figs = [
 ("cashu-test-01-ready-screen.jpg", "Cashu signer home screen",
  "Home screen, Cashu signer mode: “Ready”. Locks show here and need a button press."),
 ("cashu-test-02-lock-check.jpg", "Cashu P2PK lock summary page",
  "Summary page: “Cashu P2PK lock”, “Lock key is ours”, the secret length, and a note that the values follow on the next pages."),
 ("cashu-test-03-secret-1of3.jpg", "Secret page 1 of 3",
  "Secret, page 1 of 3: the raw secret starts, with the nonce and the beginning of the lock key."),
 ("cashu-test-04-secret-2of3.jpg", "Secret page 2 of 3",
  "Secret, page 2 of 3: the rest of the lock key and the tags."),
 ("cashu-test-05-secret-3of3-sign.jpg", "Secret page 3 of 3 with Sign button",
  "Last page: the end of the secret. The right button now reads Sign; the left button cancels."),
]
missing = [f[0] for f in figs if not os.path.exists(os.path.join(imgdir, f[0]))]
if missing: sys.exit("NOT WRITTEN: put these files in %s first: %s" % (imgdir, ", ".join(missing)))

html = ["<h2>What the device shows</h2>",
 "<p>These photos come from lab test runs on a local test mint. They show what each screen looks like; the secret text differs between runs, so they illustrate the flow rather than one particular signing.</p>"]
for fn, alt, cap in figs:
    html.append('<figure style="margin:1.2em 0"><img src="images/%s" alt="%s" loading="lazy" style="max-width:100%%;height:auto;border-radius:6px"><figcaption>%s</figcaption></figure>' % (fn, alt, cap))
block = "\n".join(html) + "\n"

pat = r"<h2[^>]*>\s*Not tested\s*</h2>"
if len(re.findall(pat, s)) != 1: sys.exit("NOT WRITTEN: could not find the 'Not tested' heading exactly once")
s = re.sub(pat, lambda m: block + m.group(0), s)
open(path, "w", encoding="utf-8").write(s); print("figures added to", path)
