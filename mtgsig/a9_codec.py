"""Offline a9 codec for the analysed Keeta SDK build.

AES-CBC, Twofish-CBC, and the Twofish MDS variant share the outer CRC/zlib
format. No device, dump of expanded keys, or RPC is used by this module.
"""
import base64
import binascii
import re
import struct
import zlib
from dataclasses import dataclass
from functools import lru_cache

from Crypto.Cipher import AES

from .mtg_crypto import A9Cipher

IV = b"0102030405060708"
DEFAULT_SALT = bytes.fromhex("38cb1cf146637e7e03f679237b839e7c")
DEFAULT_K3 = b"$MXMYBS@HelloPay"
MODES = ("aes", "twofish", "twofish-mod")
_MASK32 = (1 << 32) - 1
_NIBBLES = bytes.fromhex(
    "0801070d060f0302000b05090e0c0a04"
    "0e0c0b08010203050f040a060700090d"
    "0b0a050e060d09000c080f0302040701"
    "0d070f040102060e090b030008050c0a"
    "02080b0d0f07060e03010904000a0c05"
    "010e020b040c0307060d0a050f090008"
    "040c07050106090a000e0d08020b030f"
    "0b0905010c030d0e0604070f0200080a"
)


def _rol(x, n):
    return ((x << n) | (x >> (32 - n))) & _MASK32


def _qbox(t):
    out = []
    for i in range(256):
        a, b = i >> 4, i & 15
        for offset in (0, 32):
            a, b = (t[offset + (a ^ b)],
                    t[offset + 16 + (a ^ (b >> 1 | (b & 1) << 3) ^ ((a << 3) & 8))])
        out.append(a | b << 4)
    return out


_Q0, _Q1 = _qbox(_NIBBLES[:64]), _qbox(_NIBBLES[64:])


@lru_cache(maxsize=2)
def _mds(poly):
    tables = [[], [], [], []]
    for q0, q1 in zip(_Q0, _Q1):
        for q, low, high in ((q0, 1, 3), (q1, 0, 2)):
            half = (q >> 1) ^ (poly if q & 1 else 0)
            a = q ^ (half >> 1) ^ (poly if half & 1 else 0)
            b = a ^ half
            if low == 1:
                tables[low].append(q << 24 | a << 16 | b << 8 | b)
                tables[high].append(a << 24 | b << 16 | q << 8 | a)
            else:
                tables[low].append(b << 24 | b << 16 | a << 8 | q)
                tables[high].append(b << 24 | q << 16 | b << 8 | a)
    return tables


def twofish_schedule(key, *, modified=False):
    """Produce the four keyed tables and 40 subkeys; 128-bit a9 keys only."""
    if len(key) != 16:
        raise ValueError("a9 Twofish key must contain 16 bytes")
    m = _mds(0xBC if modified else 0xB4)

    def columns(y, k):
        return (m[0][_Q0[_Q0[y] ^ k[8]] ^ k[0]],
                m[1][_Q0[_Q1[y] ^ k[9]] ^ k[1]],
                m[2][_Q1[_Q0[y] ^ k[10]] ^ k[2]],
                m[3][_Q1[_Q1[y] ^ k[11]] ^ k[3]])

    def h(y, k):
        a, b, c, d = columns(y, k)
        return a ^ b ^ c ^ d

    subkeys = []
    for i in range(0, 40, 2):
        a = h(i, key)
        b = _rol(h(i + 1, key[4:]), 8)
        subkeys.extend(((a + b) & _MASK32, _rol((a + 2 * b) & _MASK32, 9)))
    s = bytearray(16)
    for dest, source in ((0, key[8:16]), (8, key[0:8])):
        polynomial = bytearray(4) + bytearray(source)
        for i in range(11, 3, -1):
            b = polynomial[i]
            bx = ((b << 1) ^ (0x14D if b & 128 else 0)) & 255
            bxx = (b >> 1) ^ (0xA6 if b & 1 else 0) ^ bx
            for delta, value in ((1, bxx), (2, bx), (3, bxx), (4, b)):
                polynomial[i - delta] ^= value
        s[dest:dest + 4] = polynomial[:4]
    tables = list(zip(*(columns(i, s) for i in range(256))))
    return struct.pack("<1064I", *(sum((list(t) for t in tables), []) + subkeys))


def derive_mask(a1, *, salt=DEFAULT_SALT, a1_shift=31):
    # The supported SDK app-key input has the form of a 36-byte ASCII UUID.
    if not isinstance(a1, str) or not re.fullmatch(
        r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", a1
    ):
        raise ValueError("a1 must be the original 36-character UUID")
    if len(salt) != 16:
        raise ValueError("salt must contain 16 bytes")
    if isinstance(a1_shift, bool) or not isinstance(a1_shift, int) or not 0 <= a1_shift < 36:
        raise ValueError("a1_shift must be an integer from 0 to 35")
    raw = a1.encode("ascii")
    return bytes(salt[i] ^ ((raw[i] + raw[(i + a1_shift) % 36]) & 255) for i in range(16))


def derive_key(crc_hex, a1, *, salt=DEFAULT_SALT, k3=DEFAULT_K3, a1_shift=31):
    if not re.fullmatch(r"[0-9a-f]{8}", crc_hex):
        raise ValueError("CRC must contain eight lowercase hexadecimal digits")
    if len(k3) < 10:
        raise ValueError("k3 must contain at least ten bytes")
    seed = crc_hex.encode("ascii") + k3[2:10]
    return bytes(a ^ b for a, b in zip(seed, derive_mask(a1, salt=salt, a1_shift=a1_shift)))


def _crypt(data, key, mode, *, decrypt):
    if len(data) % 16:
        raise ValueError("cipher input must contain complete 16-byte blocks")
    if mode == "aes":
        cipher = AES.new(key, AES.MODE_CBC, IV)
        return cipher.decrypt(data) if decrypt else cipher.encrypt(data)
    if mode not in ("twofish", "twofish-mod"):
        raise ValueError(f"unknown a9 cipher mode: {mode}")
    cipher = A9Cipher(twofish_schedule(key, modified=mode == "twofish-mod"))
    return cipher._cbc_dec(data) if decrypt else cipher._cbc_enc(data)


@dataclass(frozen=True)
class DecodedA9:
    mode: str
    compressed: bytes
    plaintext: bytes


def encode_compressed(compressed, a1, *, mode="aes", salt=DEFAULT_SALT, k3=DEFAULT_K3, a1_shift=31):
    """Preserve exact captured zlib bytes for byte-for-byte replay."""
    stream = zlib.decompressobj()
    stream.decompress(compressed)
    if not stream.eof or stream.unused_data or stream.unconsumed_tail:
        raise ValueError("compressed input must be exactly one complete zlib stream")
    crc = f"{binascii.crc32(compressed):08x}"
    key = derive_key(crc, a1, salt=salt, k3=k3, a1_shift=a1_shift)
    pad = 16 - len(compressed) % 16
    encrypted = _crypt(compressed + bytes([pad]) * pad, key, mode, decrypt=False)
    return crc + base64.b64encode(encrypted).decode("ascii")


def encode(plaintext, a1, *, mode="aes", salt=DEFAULT_SALT, k3=DEFAULT_K3, a1_shift=31, level=6):
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    return encode_compressed(zlib.compress(plaintext, level), a1, mode=mode,
                             salt=salt, k3=k3, a1_shift=a1_shift)


def decode(a9, a1, *, mode="auto", salt=DEFAULT_SALT, k3=DEFAULT_K3, a1_shift=31,
           max_plaintext=4 << 20):
    """Identify mode using strict padding, CRC32 and full zlib-stream checks."""
    if isinstance(max_plaintext, bool) or not isinstance(max_plaintext, int) or max_plaintext < 0:
        raise ValueError("max_plaintext must be a nonnegative integer")
    if not isinstance(a9, str) or not re.fullmatch(r"[0-9a-f]{8}[A-Za-z0-9+/]+={0,2}", a9):
        raise ValueError("invalid a9 encoding")
    blob = base64.b64decode(a9[8:], validate=True)
    if not blob or len(blob) % 16:
        raise ValueError("a9 ciphertext must contain complete 16-byte blocks")
    key = derive_key(a9[:8], a1, salt=salt, k3=k3, a1_shift=a1_shift)
    candidates = MODES if mode == "auto" else (mode,)
    if any(m not in MODES for m in candidates):
        raise ValueError(f"unknown a9 cipher mode: {mode}")
    for candidate in candidates:
        padded = _crypt(blob, key, candidate, decrypt=True)
        pad = padded[-1]
        if not 1 <= pad <= 16 or padded[-pad:] != bytes([pad]) * pad:
            continue
        compressed = padded[:-pad]
        if f"{binascii.crc32(compressed):08x}" != a9[:8]:
            continue
        try:
            stream = zlib.decompressobj()
            plain = stream.decompress(compressed, max_plaintext + 1)
            if len(plain) > max_plaintext or not stream.eof or stream.unused_data or stream.unconsumed_tail:
                continue
        except zlib.error:
            continue
        return DecodedA9(candidate, compressed, plain)
    raise ValueError("a9 validation failed: check original a1, SDK salt/k3/a1_shift, and supported cipher modes")
