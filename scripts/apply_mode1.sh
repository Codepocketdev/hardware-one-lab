#!/usr/bin/env bash
# apply_mode1.sh - Trezor Model One experiment 02, step 3: home screen modes.
# A short press of the RIGHT button on the home screen switches between the clock and a
# static "NOSTR SIGNER" panel. The panel derives no key and asks for no PIN.
# Run AFTER apply_clock3.sh (re-running apply_clock3.sh removes this patch).
# Usage: ./apply_mode1.sh [--build] [--revert] [REPO_DIR]   --build also builds the DEVICE firmware (PRODUCTION=0)
set -euo pipefail

BUILD=0
REVERT=0
REPO="$HOME/trezor-firmware"
for arg in "$@"; do
  case "$arg" in
    --build)  BUILD=1 ;;
    --revert) REVERT=1 ;;
    *) REPO="$arg" ;;
  esac
done

FW="$REPO/legacy/firmware"
LAYOUT="$FW/layout2.c"
TREZOR="$FW/trezor.c"
BK_LAYOUT="$LAYOUT.pre-mode"
BK_TREZOR="$TREZOR.pre-mode"

[ -f "$LAYOUT" ] && [ -f "$TREZOR" ] || { echo "ERROR: cannot find $LAYOUT or $TREZOR" >&2; exit 1; }

if [ "$REVERT" -eq 1 ]; then
  if [ -f "$BK_LAYOUT" ] && [ -f "$BK_TREZOR" ]; then
    cp "$BK_LAYOUT" "$LAYOUT" && cp "$BK_TREZOR" "$TREZOR" && echo "restored layout2.c and trezor.c from before the mode patch"
  else
    echo "no backups, nothing to do"
  fi
  exit 0
fi

if grep -q "layoutToggleHomeMode" "$LAYOUT" "$TREZOR"; then
  echo "already patched, skipping the edit"
else
  grep -q "layoutDrawClock" "$LAYOUT" || { echo "ERROR: clock patch not found, run apply_clock3.sh first" >&2; exit 1; }
  [ -f "$BK_LAYOUT" ] || cp "$LAYOUT" "$BK_LAYOUT"
  [ -f "$BK_TREZOR" ] || cp "$TREZOR" "$BK_TREZOR"

  python3 - "$LAYOUT" "$TREZOR" <<'PYEOF'
import sys
layout_path, trezor_path = sys.argv[1], sys.argv[2]
lay = open(layout_path).read()
trz = open(trezor_path).read()

# ---- layout2.c ----
home_sig = "void layoutHomescreen(void) {"
call = "layoutDrawClock();"
if lay.count(home_sig) != 1:
    sys.exit("ERROR: expected exactly one layoutHomescreen definition in layout2.c")
if lay.count(call) != 1:
    sys.exit("ERROR: expected exactly one layoutDrawClock(); call in layout2.c")

HELPER = r'''// ---- Home screen mode: clock or Nostr signer panel (right button toggles) ----
static bool home_signer_mode = false;

static void layoutDrawSignerPanel(void) {
  oledDrawStringCenter(OLED_WIDTH / 2, 2, _("NOSTR SIGNER"), FONT_STANDARD);
  oledHLine(12);
  if (config_isInitialized()) {
    oledDrawStringCenter(OLED_WIDTH / 2, 17, _("Ready"), FONT_STANDARD);
  } else {
    oledDrawStringCenter(OLED_WIDTH / 2, 17, _("No seed yet"), FONT_STANDARD);
  }
  oledDrawStringCenter(OLED_WIDTH / 2, 29, _("Notes show here and"),
                       FONT_STANDARD);
  oledDrawStringCenter(OLED_WIDTH / 2, 38, _("need a button press"),
                       FONT_STANDARD);
  oledDrawStringCenter(OLED_WIDTH / 2, 48, _("Right button: clock"),
                       FONT_STANDARD);
}

void layoutToggleHomeMode(void);
void layoutToggleHomeMode(void) {
  home_signer_mode = !home_signer_mode;
  layoutHomescreen();
}

'''
NEWCALL = ("if (home_signer_mode) {\n    layoutDrawSignerPanel();\n  } else {\n"
           "    layoutDrawClock();\n  }")

c = lay.index(call)
lay = lay[:c] + NEWCALL + lay[c + len(call):]
h = lay.index(home_sig)
lay = lay[:h] + HELPER + lay[h:]

# ---- trezor.c ----
lock_sig = "void check_lock_screen(void) {"
marker = "// button held for long enough (5 seconds)"
if trz.count(lock_sig) != 1:
    sys.exit("ERROR: expected exactly one check_lock_screen definition in trezor.c")
if trz.count(marker) != 1:
    sys.exit("ERROR: could not find the long-press block in trezor.c")

TOGGLE = '''  // short press of the right button on the home screen: clock <-> Nostr signer panel
  if (layoutLast == layoutHomescreen && button.YesUp) {
    layoutToggleHomeMode();
  }

'''
m = trz.index(marker)
line_start = trz.rfind("\n", 0, m) + 1
trz = trz[:line_start] + TOGGLE + trz[line_start:]
l = trz.index(lock_sig)
trz = trz[:l] + "void layoutToggleHomeMode(void);\n\n" + trz[l:]

open(layout_path, "w").write(lay)
open(trezor_path, "w").write(trz)
print("patched layout2.c and trezor.c")
PYEOF
fi

git -C "$REPO" diff --stat -- legacy/firmware/layout2.c legacy/firmware/trezor.c || true

if [ "$BUILD" -eq 1 ]; then
  echo "Building device firmware..."
  export PATH="$HOME/.local/bin:$PATH"
  unset EMULATOR HEADLESS DEBUG_LINK
  export PRODUCTION=0
  touch "$LAYOUT" "$TREZOR"
  ( cd "$REPO/legacy" && TZ=Africa/Nairobi uv run ./script/cibuild )
  echo
  ls -l "$REPO/legacy/firmware/trezor.bin"
  sha256sum "$REPO/legacy/firmware/trezor.bin"
  echo "Copy firmware/trezor.bin to your PC and flash it, set the time again with SETTIME,"
  echo "then press the RIGHT button briefly on the home screen to switch clock <-> signer panel."
fi
