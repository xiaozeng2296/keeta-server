"""Offline m175 collector codec for the analysed Keeta iOS SDK.

The collector encrypts a checksummed pair of JSON objects with the SDK's
Twofish MDS variant, ECB mode and caret padding. See docs/archive/M175_SOURCE.md.
"""

from dataclasses import dataclass
from functools import lru_cache
import hashlib
import json
import re
import struct
import zlib

from .a9_codec import twofish_schedule
from .mtg_crypto import A9Cipher

_KEY = b"mtguard-dfp-Yes~"
_MAX_BYTES = 1 << 20


@lru_cache(maxsize=1)
def _cipher():
    return A9Cipher(twofish_schedule(_KEY, modified=True))


def _ecb(data, *, decrypt=False):
    if len(data) % 16:
        raise ValueError("m175 cipher input must contain complete blocks")
    block = _cipher().dec_block if decrypt else _cipher().enc_block
    return b"".join(struct.pack("<4I", *block(struct.unpack("<4I", data[i:i + 16])))
                    for i in range(0, len(data), 16))


def _digest(payload):
    digest = hashlib.md5(payload).digest()
    return b"".join(digest[i * 4:i * 4 + 4] for i in (2, 0, 3, 1)).hex().upper()


@dataclass(frozen=True)
class DecodedM175:
    payload: str
    first: dict
    second: dict


def _parse_payload(payload):
    if not isinstance(payload, str) or len(payload.encode("utf-8")) > _MAX_BYTES:
        raise ValueError("m175 payload must be bounded UTF-8 text")
    try:
        first, end = json.JSONDecoder().raw_decode(payload)
        second = json.loads(payload[end:])
    except (ValueError, RecursionError) as exc:
        raise ValueError("m175 payload must contain two consecutive JSON objects") from exc
    if (not isinstance(first, dict) or set(first) != {"a", "b"}
            or not isinstance(second, dict) or set(second) != set("mnopqr")
            or not all(isinstance(v, str) for v in (*first.values(), *second.values()))):
        raise ValueError("unexpected m175 collector schema")
    if first["a"] != second["n"] or first["b"] != second["r"]:
        raise ValueError("m175 repeated collector values disagree")
    return DecodedM175(payload, first, second)


def encode_payload(payload):
    """Preserve exact JSON ordering/escaping for byte-identical reencryption."""
    _parse_payload(payload)
    raw = payload.encode("utf-8")
    header = ("AI" + _digest(raw) + f"{zlib.crc32(raw):016d}").encode("ascii")
    expanded = (header + raw).hex().upper().encode("ascii")
    padded = expanded + b"^" * (-len(expanded) % 16)
    return _ecb(padded).hex().upper()


def encode_m175(*, model, system_version, field19, screen, device_name, timestamp_ms):
    """Construct m175 using collector values, without a device or old blob.

    model/system_version/field19/screen are the raw m166/m160/m19/m167 strings.
    device_name is UIDevice.name (None reproduces the collector's nil fallback).
    timestamp_ms is the already rounded millisecond collector timestamp.
    """
    values = (model, system_version, field19, screen)
    if not all(isinstance(v, str) for v in values):
        raise ValueError("m175 collector values must be strings")
    if device_name is not None and not isinstance(device_name, str):
        raise ValueError("device_name must be a string or None")
    if isinstance(timestamp_ms, bool) or not isinstance(timestamp_ms, (str, int)):
        raise ValueError("timestamp_ms must be an integer or decimal string")
    timestamp = str(timestamp_ms)
    if not re.fullmatch(r"[0-9]+", timestamp):
        raise ValueError("timestamp_ms must be a nonnegative decimal integer")
    first = {"a": model, "b": timestamp}
    # NSDictionary iteration order is not a protocol promise. This is the
    # order of the captured current build; encode_payload retains any original.
    second = {"r": timestamp, "p": field19, "n": model, "q": screen,
              "o": system_version, "m": "unknown" if device_name is None else device_name}
    dump = lambda value: json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return encode_payload(dump(first) + dump(second))


def decode_m175(value):
    """Decrypt and validate framing, padding, both checksums and JSON schema."""
    if (not isinstance(value, str) or not value or len(value) % 32
            or len(value) > _MAX_BYTES * 4 + 256
            or not re.fullmatch(r"[0-9a-fA-F]+", value)):
        raise ValueError("m175 must be bounded hexadecimal ciphertext in complete blocks")
    padded = _ecb(bytes.fromhex(value), decrypt=True)
    expanded = padded.rstrip(b"^")
    if len(padded) - len(expanded) >= 16 or not re.fullmatch(b"(?:[0-9A-F]{2})+", expanded):
        raise ValueError("invalid m175 hexadecimal plaintext or caret padding")
    raw = bytes.fromhex(expanded.decode("ascii"))
    if len(raw) < 50 or raw[:2] != b"AI":
        raise ValueError("invalid m175 frame")
    payload = raw[50:]
    if raw[2:34] != _digest(payload).encode("ascii"):
        raise ValueError("m175 MD5 word-order checksum mismatch")
    if raw[34:50] != f"{zlib.crc32(payload):016d}".encode("ascii"):
        raise ValueError("m175 CRC32 mismatch")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("invalid m175 UTF-8 payload") from exc
    return _parse_payload(text)
