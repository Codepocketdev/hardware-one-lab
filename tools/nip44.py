"""NIP-44 v2 encryption (secp256k1 ECDH, HKDF-SHA256, ChaCha20, HMAC-SHA256).
Needs the 'cryptography' package for ChaCha20. Pure-Python curve math: slow but fine for a bridge.
Test against the official vectors with test_nip44.py before trusting it."""
import base64
import hashlib
import hmac
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


class Nip44Error(Exception):
    pass


def _add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], -1, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return (x, (lam * (a[0] - x) - a[1]) % P)


def _mul(k, pt=G):
    r = None
    while k:
        if k & 1:
            r = _add(r, pt)
        pt = _add(pt, pt)
        k >>= 1
    return r


def _lift_x(x):
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if y * y % P != y2:
        raise Nip44Error("invalid public key")
    return (x, y if y % 2 == 0 else P - y)


def hkdf_extract(salt, ikm):
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk, info, length):
    out, block, i = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([i]), hashlib.sha256).digest()
        out += block
        i += 1
    return out[:length]


def get_conversation_key(priv32, pub32):
    """priv32: 32-byte secret, pub32: 32-byte x-only public key."""
    k = int.from_bytes(priv32, "big")
    if not 0 < k < N:
        raise Nip44Error("invalid private key")
    shared = _mul(k, _lift_x(int.from_bytes(pub32, "big")))
    if shared is None:
        raise Nip44Error("invalid shared point")
    return hkdf_extract(b"nip44-v2", shared[0].to_bytes(32, "big"))


def get_message_keys(conversation_key, nonce):
    if len(conversation_key) != 32 or len(nonce) != 32:
        raise Nip44Error("bad key or nonce length")
    keys = hkdf_expand(conversation_key, nonce, 76)
    return keys[0:32], keys[32:44], keys[44:76]


def calc_padded_len(n):
    if n <= 32:
        return 32
    next_power = 1 << ((n - 1).bit_length())
    chunk = 32 if next_power <= 256 else next_power // 8
    return chunk * ((n - 1) // chunk + 1)


def pad(plaintext):
    raw = plaintext.encode("utf-8")
    if not 1 <= len(raw) <= 65535:
        raise Nip44Error("invalid plaintext length")
    return len(raw).to_bytes(2, "big") + raw + bytes(calc_padded_len(len(raw)) - len(raw))


def unpad(padded):
    n = int.from_bytes(padded[:2], "big")
    raw = padded[2:2 + n]
    if n == 0 or len(raw) != n or len(padded) != 2 + calc_padded_len(n):
        raise Nip44Error("invalid padding")
    return raw.decode("utf-8")


def _chacha20(key, nonce12, data):
    c = Cipher(algorithms.ChaCha20(key, bytes(4) + nonce12), mode=None).encryptor()
    return c.update(data) + c.finalize()


def encrypt(plaintext, conversation_key, nonce=None):
    nonce = nonce or os.urandom(32)
    chacha_key, chacha_nonce, hmac_key = get_message_keys(conversation_key, nonce)
    ciphertext = _chacha20(chacha_key, chacha_nonce, pad(plaintext))
    mac = hmac.new(hmac_key, nonce + ciphertext, hashlib.sha256).digest()
    return base64.b64encode(b"\x02" + nonce + ciphertext + mac).decode()


def decrypt(payload, conversation_key):
    if not payload or payload[0] == "#":
        raise Nip44Error("unknown encryption version")
    if not 132 <= len(payload) <= 87472:
        raise Nip44Error("invalid payload length")
    try:
        data = base64.b64decode(payload, validate=True)
    except Exception as exc:
        raise Nip44Error("invalid base64") from exc
    if not 99 <= len(data) <= 65603:
        raise Nip44Error("invalid data length")
    if data[0] != 2:
        raise Nip44Error("unknown encryption version")
    nonce, ciphertext, mac = data[1:33], data[33:-32], data[-32:]
    chacha_key, chacha_nonce, hmac_key = get_message_keys(conversation_key, nonce)
    if not hmac.compare_digest(hmac.new(hmac_key, nonce + ciphertext, hashlib.sha256).digest(), mac):
        raise Nip44Error("invalid MAC")
    return unpad(_chacha20(chacha_key, chacha_nonce, ciphertext))


def x_only_pub(priv32):
    return _mul(int.from_bytes(priv32, "big"))[0].to_bytes(32, "big")
