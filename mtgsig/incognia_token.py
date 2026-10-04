"""Offline codec for the observed Incognia unique request token (format 0).

Verified wire: base64url(0 || RSA-OAEP-SHA256(key32) || IV16 ||
AES-256-CBC-PKCS7(raw-DEFLATE(JSON)) || HMAC-SHA256(IV || ciphertext)).
The HMAC key and RSA public key are explicit SDK configuration. Installation
identity/counters are explicit caller state; this module does not create or
register an installation, and cannot decrypt arbitrary captures without their
session key (or the server's RSA private key).
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import hmac
import json
import re
import secrets
from typing import Callable
import zlib

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad

SDK_CODE = 62300
MAX_PLAIN_BYTES = 1024 * 1024


def _bytes(value: bytes, length: int, name: str) -> bytes:
    if not isinstance(value, bytes) or len(value) != length:
        raise ValueError(f"{name} must be {length} bytes")
    return value


def build_payload(*, application_id: str, installation_id: str,
                  initialization_counter: int, initialized_at_ms: int,
                  request_counter: int, requested_at_ms: int,
                  sdk_code: int = SDK_CODE) -> dict:
    """Map the seven observed fields without inventing device/account values.

    Counters are the values before the SDK increments persistent storage.
    The caller owns their lifetime and atomic updates. ``sdk_code`` is the
    observed literal; its version/flags interpretation has not been verified.
    """
    if not isinstance(application_id, str) or not application_id:
        raise ValueError("application_id must be nonempty text")
    if not isinstance(installation_id, str) or not installation_id:
        raise ValueError("installation_id must be nonempty text")
    installation_id = installation_id.replace("ILM-ID-", "").lower()
    if not installation_id:
        raise ValueError("normalized installation_id is empty")
    for name, value in (("initialization_counter", initialization_counter),
                        ("initialized_at_ms", initialized_at_ms),
                        ("request_counter", request_counter),
                        ("requested_at_ms", requested_at_ms),
                        ("sdk_code", sdk_code)):
        if type(value) is not int or value < 0:
            raise ValueError(f"{name} must be a nonnegative integer")
    return {"60": requested_at_ms, "73": initialization_counter,
            "50": sdk_code, "74": initialized_at_ms, "1": application_id,
            "33": installation_id, "59": request_counter}


def serialize(payload: dict | bytes | str) -> bytes:
    """Preserve supplied JSON bytes for exact native comparison."""
    if isinstance(payload, dict):
        raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":"),
                         allow_nan=False).encode("utf-8")
    elif isinstance(payload, str):
        raw = payload.encode("utf-8")
    elif isinstance(payload, bytes):
        raw = payload
    else:
        raise TypeError("payload must be a JSON object, text, or bytes")
    if len(raw) > MAX_PLAIN_BYTES:
        raise ValueError("payload exceeds size limit")
    obj = json.loads(raw.decode("utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("payload must contain a JSON object")
    return raw


def compress(payload: dict | bytes | str) -> bytes:
    raw = serialize(payload)
    compressor = zlib.compressobj(level=6, wbits=-15)
    return compressor.compress(raw) + compressor.flush()


def encrypt_payload(payload: dict | bytes | str, *, session_key: bytes,
                    iv: bytes, hmac_key: bytes) -> bytes:
    """Return IV || ciphertext || MAC, independently of RSA wrapping."""
    _bytes(session_key, 32, "session_key")
    _bytes(iv, 16, "iv")
    _bytes(hmac_key, 32, "hmac_key")
    ciphertext = AES.new(session_key, AES.MODE_CBC, iv).encrypt(
        pad(compress(payload), AES.block_size))
    sealed = iv + ciphertext
    return sealed + hmac.new(hmac_key, sealed, hashlib.sha256).digest()


def encode(payload: dict | bytes | str, *, public_key: bytes | str,
           hmac_key: bytes, session_key: bytes | None = None,
           iv: bytes | None = None,
           randfunc: Callable[[int], bytes] | None = None) -> str:
    """Generate a fresh token; no captured token or RSA segment is reused.

    Optional explicit AES key/IV and RSA ``randfunc`` support reproducible
    offline tests. Normal callers omit them to use fresh secure randomness.
    """
    key = RSA.import_key(public_key).public_key()
    if key.size_in_bits() != 2048:
        raise ValueError("observed format requires an RSA-2048 key")
    session_key = secrets.token_bytes(32) if session_key is None else session_key
    iv = secrets.token_bytes(16) if iv is None else iv
    sealed = encrypt_payload(payload, session_key=session_key, iv=iv,
                             hmac_key=hmac_key)
    wrapped = PKCS1_OAEP.new(key, hashAlgo=SHA256, randfunc=randfunc).encrypt(session_key)
    return base64.urlsafe_b64encode(b"\0" + wrapped + sealed).decode("ascii").rstrip("=")


@dataclass(frozen=True)
class TokenParts:
    wrapped_key: bytes
    iv: bytes
    ciphertext: bytes
    mac: bytes


def split(token: str) -> TokenParts:
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", token):
        raise ValueError("invalid unpadded base64url token")
    if len(token) % 4 == 1 or len(token) > 2 * MAX_PLAIN_BYTES:
        raise ValueError("invalid token length")
    raw = base64.b64decode(token + "=" * (-len(token) % 4), altchars=b"-_", validate=True)
    if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != token:
        raise ValueError("noncanonical base64url token")
    if len(raw) < 321 or raw[0] != 0:
        raise ValueError("unsupported token format")
    ciphertext = raw[273:-32]
    if not ciphertext or len(ciphertext) % 16:
        raise ValueError("invalid AES payload length")
    return TokenParts(raw[1:257], raw[257:273], ciphertext, raw[-32:])


def decode_with_session_key(token: str, *, session_key: bytes,
                            hmac_key: bytes) -> dict:
    """Authenticate/decode with the AES session key, not just the public key.

    The native MAC covers IV/ciphertext only. This operation cannot validate
    whether the opaque RSA segment actually wraps the supplied session key.
    """
    _bytes(session_key, 32, "session_key")
    _bytes(hmac_key, 32, "hmac_key")
    parts = split(token)
    expected = hmac.new(hmac_key, parts.iv + parts.ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(parts.mac, expected):
        raise ValueError("token MAC mismatch")
    packed = unpad(AES.new(session_key, AES.MODE_CBC, parts.iv).decrypt(parts.ciphertext), 16)
    inflater = zlib.decompressobj(-15)
    raw = inflater.decompress(packed, MAX_PLAIN_BYTES + 1)
    if len(raw) > MAX_PLAIN_BYTES or inflater.unconsumed_tail:
        raise ValueError("inflated payload exceeds size limit")
    if not inflater.eof or inflater.unused_data:
        raise ValueError("invalid raw-DEFLATE stream")
    return json.loads(serialize(raw))
