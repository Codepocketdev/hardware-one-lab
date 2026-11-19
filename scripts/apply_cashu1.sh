#!/bin/bash
set -e
FW="${1:-$HOME/trezor-firmware/legacy/firmware}"
python3 - "$FW" <<'PY'
import os
import shutil
import sys

fw = sys.argv[1]
layout_path = os.path.join(fw, "layout2.c")
fsm_path = os.path.join(fw, "fsm_msg_common.h")

PANEL = r'''
static void layoutDrawCashuPanel(void) {
  oledDrawStringCenter(OLED_WIDTH / 2, 2, _("CASHU SIGNER"), FONT_STANDARD);
  oledHLine(12);
  if (config_isInitialized()) {
    oledDrawStringCenter(OLED_WIDTH / 2, 17, _("Ready"), FONT_STANDARD);
  } else {
    oledDrawStringCenter(OLED_WIDTH / 2, 17, _("No seed yet"), FONT_STANDARD);
  }
  oledDrawStringCenter(OLED_WIDTH / 2, 29, _("Locks show here and"),
                       FONT_STANDARD);
  oledDrawStringCenter(OLED_WIDTH / 2, 38, _("need a button press"),
                       FONT_STANDARD);
  oledDrawStringCenter(OLED_WIDTH / 2, 48, _("Right button: clock"),
                       FONT_STANDARD);
}
'''

TOGGLE = r'''  if (!home_signer_mode) {
    home_signer_mode = true;
    home_cashu_mode = false;
  } else if (!home_cashu_mode) {
    home_cashu_mode = true;
  } else {
    home_signer_mode = false;
    home_cashu_mode = false;
  }'''

DRAW = r'''if (home_cashu_mode) {
      layoutDrawCashuPanel();
    } else {
      layoutDrawSignerPanel();
    }'''

CASHU_C = r'''
#define CASHU_SEC_MAX 600

static char cashu_sec[CASHU_SEC_MAX + 1];
static size_t cashu_len = 0;
static size_t cashu_want = 0;
static const char *cashu_err = "Cashu error";

static void cashu_reset(void) {
  memset(cashu_sec, 0, sizeof(cashu_sec));
  cashu_len = 0;
  cashu_want = 0;
}

static HDNode *cashu_node(void) {
  static const uint32_t cashu_path[5] = {0x80000000u | 44, 0x80000000u | 1237,
                                         0x80000000u | 2, 0, 0};
  return fsm_getDerivedNode("secp256k1", cashu_path, 5, NULL);
}

static int cashu_pubkey_hex(char *out) {
  HDNode *node = cashu_node();
  if (!node) return -1;
  uint8_t pub[32];
  if (zkp_bip340_get_public_key(node->private_key, pub) != 0) return -2;
  nostr_hex(pub, sizeof(pub), out);
  return 0;
}

static bool cashu_check(const char *pubhex) {
  size_t n = cashu_len;
  if (n < 60) {
    cashu_err = "Secret too short";
    return false;
  }
  for (size_t i = 0; i < n; i++) {
    unsigned char ch = (unsigned char)cashu_sec[i];
    if (ch < 0x20 || ch > 0x7e || ch == 0x5c) {
      cashu_err = "Unsupported character";
      return false;
    }
  }
  if (strncmp(cashu_sec, "[\"P2PK\"", 7) != 0 || cashu_sec[n - 1] != ']') {
    cashu_err = "Not a P2PK secret";
    return false;
  }
  size_t found = 0;
  const char *at = NULL;
  for (size_t i = 0; i + 6 <= n; i++) {
    if (memcmp(cashu_sec + i, "\"data\"", 6) == 0) {
      if (!found) at = cashu_sec + i;
      found++;
    }
  }
  if (found != 1) {
    cashu_err = "Need one data field";
    return false;
  }
  const char *end = cashu_sec + n;
  const char *p = at + 6;
  while (p < end && *p == ' ') p++;
  if (p >= end || *p != ':') {
    cashu_err = "Bad data field";
    return false;
  }
  p++;
  while (p < end && *p == ' ') p++;
  if (p >= end || *p != '"') {
    cashu_err = "Bad data field";
    return false;
  }
  p++;
  if ((size_t)(end - p) < 67) {
    cashu_err = "Bad data field";
    return false;
  }
  if (p[0] != '0' || (p[1] != '2' && p[1] != '3')) {
    cashu_err = "Bad lock key prefix";
    return false;
  }
  if (memcmp(p + 2, pubhex, 64) != 0 || p[66] != '"') {
    cashu_err = "Locked to another key";
    return false;
  }
  return true;
}

static bool cashu_confirm(void) {
  char a[24];
  memcpy(a, "Secret: ", 8);
  size_t al = 8 + nostr_ev_utoa((uint32_t)cashu_len, a + 8);
  memcpy(a + al, " chars", 7);
  size_t pages = (cashu_len + 79) / 80;
  layoutDialogSwipe(NULL, _("Cancel"), _("Next"), NULL, _("Cashu P2PK lock"),
                    _("Lock key is ours"), a, _("values on next pages"), NULL,
                    NULL);
  if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
    return false;
  }
  for (size_t pg = 0; pg < pages; pg++) {
    char head[24];
    char rows[4][21];
    memcpy(head, "Secret ", 7);
    size_t h = 7 + nostr_ev_utoa((uint32_t)(pg + 1), head + 7);
    head[h++] = '/';
    h += nostr_ev_utoa((uint32_t)pages, head + h);
    head[h++] = ':';
    head[h] = 0;
    memset(rows, 0, sizeof(rows));
    for (size_t r = 0; r < 4; r++) {
      size_t off = pg * 80 + r * 20;
      if (off >= cashu_len) break;
      size_t take = cashu_len - off;
      if (take > 20) take = 20;
      memcpy(rows[r], cashu_sec + off, take);
      rows[r][take] = 0;
    }
    layoutDialogSwipe(NULL, _("Cancel"),
                      (pg + 1 == pages) ? _("Sign") : _("Next"), NULL, head,
                      rows[0][0] ? rows[0] : NULL,
                      rows[1][0] ? rows[1] : NULL,
                      rows[2][0] ? rows[2] : NULL,
                      rows[3][0] ? rows[3] : NULL, NULL);
    if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
      return false;
    }
  }
  return true;
}

static int cashu_sign(char *out) {
  if (cashu_want == 0 || cashu_len != cashu_want) {
    cashu_err = "Secret incomplete";
    return -2;
  }
  char pubhex[65];
  int pr = cashu_pubkey_hex(pubhex);
  if (pr == -1) return -1;
  if (pr != 0) return -4;
  if (!cashu_check(pubhex)) return -2;
  if (!cashu_confirm()) return -3;
  HDNode *node = cashu_node();
  if (!node) return -1;
  uint8_t digest[32], sig[64], aux[32];
  sha256_Raw((const uint8_t *)cashu_sec, cashu_len, digest);
  random_buffer(aux, sizeof(aux));
  if (zkp_bip340_sign_digest(node->private_key, digest, sig, aux) != 0) {
    return -4;
  }
  nostr_hex(sig, sizeof(sig), out);
  return 0;
}

static int cashu_command(const char *args, char *out) {
  uint32_t v = 0;
  const char *p = NULL;
  if (strncmp(args, "BEGIN ", 6) == 0) {
    p = args + 6;
    cashu_reset();
    if (!nostr_p_uint(&p, p + strlen(p), CASHU_SEC_MAX, &v) || *p != 0 ||
        v < 60) {
      cashu_err = "BEGIN needs a length";
      return -2;
    }
    cashu_want = v;
    memcpy(out, "OK", 3);
    return 0;
  }
  if (strncmp(args, "ADD ", 4) == 0) {
    p = args + 4;
    if (cashu_want == 0) {
      cashu_err = "Send BEGIN first";
      return -2;
    }
    if (!nostr_p_uint(&p, p + strlen(p), CASHU_SEC_MAX, &v) || *p != ' ' ||
        v != cashu_len) {
      cashu_reset();
      cashu_err = "Bad chunk offset";
      return -2;
    }
    p++;
    size_t dl = strlen(p);
    if (dl == 0 || cashu_len + dl > cashu_want) {
      cashu_reset();
      cashu_err = "Bad chunk size";
      return -2;
    }
    memcpy(cashu_sec + cashu_len, p, dl);
    cashu_len += dl;
    cashu_sec[cashu_len] = 0;
    memcpy(out, "OK ", 3);
    size_t k = 3 + nostr_ev_utoa((uint32_t)cashu_len, out + 3);
    out[k] = 0;
    return 0;
  }
  if (strcmp(args, "SIGN") == 0) {
    int r = cashu_sign(out);
    cashu_reset();
    return r;
  }
  cashu_reset();
  cashu_err = "Use BEGIN, ADD or SIGN";
  return -2;
}
'''

DISPATCH = r'''if (msg->has_message && strncmp(msg->message, "CASHUSIG ", 9) == 0) {
    CHECK_INITIALIZED
    CHECK_PIN
    int cs_r = cashu_command(msg->message + 9, resp->message);
    if (cs_r == -1) return;
    if (cs_r == -2) {
      fsm_sendFailure(FailureType_Failure_DataError, cashu_err);
      layoutHome();
      return;
    }
    if (cs_r == -3) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }
    if (cs_r != 0) {
      fsm_sendFailure(FailureType_Failure_ProcessError,
                      _("Cashu signing failed"));
      layoutHome();
      return;
    }
    resp->has_message = true;
    msg_write(MessageType_MessageType_Success, resp);
    layoutHome();
    return;
  }

  if (msg->has_message && strcmp(msg->message, "CASHUPUB") == 0) {
    CHECK_INITIALIZED
    CHECK_PIN
    char cp_hex[65];
    int cp_r = cashu_pubkey_hex(cp_hex);
    if (cp_r == -1) return;
    if (cp_r != 0) {
      fsm_sendFailure(FailureType_Failure_ProcessError,
                      _("Could not derive the Cashu key"));
      layoutHome();
      return;
    }
    resp->has_message = true;
    memcpy(resp->message, cp_hex, sizeof(cp_hex));
    msg_write(MessageType_MessageType_Success, resp);
    layoutHome();
    return;
  }'''


def load(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def swap(text, old, new):
    if text.count(old) != 1:
        sys.exit("anchor not found exactly once: " + old[:70])
    return text.replace(old, new)


layout = load(layout_path)
fsm = load(fsm_path)

if "home_cashu_mode" in layout or "CASHUSIG" in fsm:
    sys.exit("already applied")

layout = swap(
    layout,
    "static bool home_signer_mode = false;",
    "static bool home_signer_mode = false;\nstatic bool home_cashu_mode = false;",
)
layout = swap(layout, '_("Right button: clock")', '_("Right button: next")')
layout = swap(
    layout,
    "  home_signer_mode = !home_signer_mode;",
    TOGGLE,
)
layout = swap(
    layout,
    "void layoutToggleHomeMode(void);",
    PANEL.strip("\n") + "\n\nvoid layoutToggleHomeMode(void);",
)
layout = swap(layout, "layoutDrawSignerPanel();", DRAW)

fsm = swap(
    fsm,
    "void fsm_msgPing(const Ping *msg) {",
    CASHU_C.strip("\n") + "\n\nvoid fsm_msgPing(const Ping *msg) {",
)
anchor = '// Nostr experiment: "NOSTRPUB" returns the NIP-06 public key (hex)'
fsm = swap(fsm, anchor, DISPATCH + "\n\n  " + anchor)

for path in (layout_path, fsm_path):
    shutil.copyfile(path, path + ".pre-cashu1")
with open(layout_path, "w", encoding="utf-8") as handle:
    handle.write(layout)
with open(fsm_path, "w", encoding="utf-8") as handle:
    handle.write(fsm)
print("patched")
PY
