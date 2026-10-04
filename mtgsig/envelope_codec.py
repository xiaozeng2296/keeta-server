"""A-envelope framing, explicit-key compatibility codec, and SDK codec.

The Keeta ``v5/sign`` and fingerprint report payloads observed in the
captures have an outer format of::

    b64(raw-rsa-1024(session_material)) + "=" + b64(aes_payload)

The captured serializer strips the trailing padding on the RSA component and
uses that ``=`` as the separator; it normally retains ordinary base64
padding on the AES component.  The parser accepts either convention.  The
first component is *raw* RSA (``SecKeyEncrypt`` with
``kSecPaddingNone``), so it is possible to reproduce it with a public key.
The SDK uses a random 128-bit payload key and the a9 provider's a1-derived
mask: ``session_material = session_key XOR mask(a1)``. The payload is CBC
with AES, Twofish, or the SDK Twofish variant. ``encode_sdk`` implements this
validated path; ``encode``/``decode`` retain the explicit AES API.

``decode`` can optionally inflate the decrypted payload when it is a complete
zlib stream.  The SDK's per-field Caesar transform is intentionally exposed as
an optional callback; no default transform is assumed.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import secrets
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from Crypto.Cipher import AES

from .a9_codec import DEFAULT_SALT, IV as SDK_IV, MODES, _crypt, derive_mask


_B64_RE = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")
BLOCK_SIZE = AES.block_size

# Runtime-captured RSA-1024 public modulus used by the A-envelope family.
# Keeping the public value here makes the offline builder usable on the RPC
# host without shipping a device dump; callers may still override it.
DEFAULT_MODULUS_HEX = (
    "d37e339a9ec8713df249ccb6eb191bc17ca3f3a8e3096cb97c0691f2844a5257"
    "8884692bf96b35ec3cfea357d51816601dd89679bc9b65cf3aeefe73c2dc9865"
    "061ffee2895a3f0a2fc95f63e34c14a3e428569c65b0c76d666a42564e2fee53"
    "04d18d47e6057b7bab822abd47859d054ed4ef3664a871bdf13e91f90c72a6cb"
)


def _as_bytes(value: bytes | bytearray | memoryview, *, name: str) -> bytes:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    raise TypeError(f"{name} must be bytes-like")


def _b64decode_unpadded(value: str, *, name: str) -> bytes:
    """Decode standard base64 while accepting the SDK's stripped padding."""

    if not isinstance(value, str):
        raise TypeError(f"{name} must be text")
    value = "".join(value.split())
    if not value or not _B64_RE.fullmatch(value):
        raise ValueError(f"invalid {name} base64")
    # A component may be emitted with one or two '=' characters as well as
    # with no padding.  Reject impossible lengths before adding padding.
    unpadded = value.rstrip("=")
    if len(unpadded) % 4 == 1:
        raise ValueError(f"invalid {name} base64 length")
    padded = unpadded + "=" * ((-len(unpadded)) % 4)
    try:
        return base64.b64decode(padded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError(f"invalid {name} base64") from exc


@dataclass(frozen=True)
class EnvelopeParts:
    """Decoded outer envelope components.

    ``separator`` is the index of the framing ``=`` in the original string.
    It is useful when comparing a replay with a captured wire value because
    the RSA base64 padding is itself optional and can otherwise be mistaken
    for the separator.
    """

    part1_b64: str
    part2_b64: str
    part1: bytes
    part2: bytes
    separator: int


def split(envelope: str) -> EnvelopeParts:
    """Split and validate an A-envelope.

    The observed SDK strips the final RSA base64 padding and inserts one
    ``=`` separator, while payload base64 generally retains its ordinary
    padding.  For robustness this accepts a padded RSA component and an
    unpadded payload as well.
    """

    if not isinstance(envelope, str):
        raise TypeError("envelope must be text")
    text = "".join(envelope.split())
    if not text:
        raise ValueError("envelope is empty")

    # Try every '=' position.  This removes the ambiguity between the
    # separator and optional padding on the 128-byte RSA component, while
    # still requiring the decoded sizes expected by the protocol.
    for pos, char in enumerate(text):
        if char != "=":
            continue
        left, right = text[:pos], text[pos + 1 :]
        if not left or not right:
            continue
        try:
            p1 = _b64decode_unpadded(left, name="part1")
            p2 = _b64decode_unpadded(right, name="part2")
        except (TypeError, ValueError):
            continue
        if len(p1) != 128 or not p2 or len(p2) % BLOCK_SIZE:
            continue
        return EnvelopeParts(left, right, p1, p2, pos)
    raise ValueError("invalid A-envelope: expected RSA-1024 part1 = AES part2")


def join(part1: bytes, part2: bytes, *, strip_padding: bool = True,
         strip_part2_padding: bool = False) -> str:
    """Build an envelope from already encrypted components.

    The observed wire framing removes the padding on the 128-byte RSA
    component, uses the single ``=`` as the separator, and keeps the normal
    base64 padding on the AES component.  ``strip_part2_padding`` is available
    for serializers that intentionally emit a fully unpadded payload.
    """

    p1 = _as_bytes(part1, name="part1")
    p2 = _as_bytes(part2, name="part2")
    if len(p1) != 128:
        raise ValueError("part1 must be exactly 128 bytes (RSA-1024)")
    if not p2 or len(p2) % BLOCK_SIZE:
        raise ValueError("part2 must contain complete AES blocks")
    s1 = base64.b64encode(p1).decode("ascii")
    s2 = base64.b64encode(p2).decode("ascii")
    if strip_padding:
        s1 = s1.rstrip("=")
    if strip_part2_padding:
        s2 = s2.rstrip("=")
    return s1 + "=" + s2


def raw_rsa_encrypt(session_material: bytes, modulus: int | bytes | str,
                    exponent: int = 65537, *, size: Optional[int] = None) -> bytes:
    """Perform the raw RSA operation used for envelope part1.

    This is deliberately *not* PKCS#1 v1.5 or OAEP.  The captured call used
    ``kSecPaddingNone`` and passed a 16-byte session value as a big-endian
    integer.  As with any public-key encryption, the operation has no inverse
    without the private key.
    """

    material = _as_bytes(session_material, name="session_material")
    if isinstance(modulus, str):
        modulus = int(modulus, 16)
    elif isinstance(modulus, (bytes, bytearray, memoryview)):
        modulus = int.from_bytes(bytes(modulus), "big")
    if not isinstance(modulus, int) or modulus <= 0:
        raise ValueError("modulus must be a positive integer")
    if not isinstance(exponent, int) or exponent <= 0:
        raise ValueError("exponent must be a positive integer")
    k = (modulus.bit_length() + 7) // 8
    if size is not None:
        if not isinstance(size, int) or size <= 0:
            raise ValueError("size must be a positive integer")
        if size < k:
            raise ValueError("size is smaller than the modulus")
        k = size
    value = int.from_bytes(material, "big")
    if value >= modulus:
        raise ValueError("session_material is too large for the RSA modulus")
    return pow(value, exponent, modulus).to_bytes(k, "big")


def _validate_aes(key: bytes, iv: bytes) -> tuple[bytes, bytes]:
    key = _as_bytes(key, name="key")
    iv = _as_bytes(iv, name="iv")
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24 or 32 bytes")
    if len(iv) != BLOCK_SIZE:
        raise ValueError("AES-CBC IV must be 16 bytes")
    return key, iv


def _pad(data: bytes) -> bytes:
    n = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([n]) * n


def _unpad(data: bytes) -> bytes:
    if not data or len(data) % BLOCK_SIZE:
        raise ValueError("AES plaintext is not block aligned")
    n = data[-1]
    if not 1 <= n <= BLOCK_SIZE or data[-n:] != bytes([n]) * n:
        raise ValueError("invalid PKCS#7 padding")
    return data[:-n]


def encrypt_part2(plaintext: bytes, key: bytes, iv: bytes,
                  *, pre_encrypt: Optional[Callable[[bytes], bytes]] = None) -> bytes:
    """Encrypt an A payload with explicitly supplied AES-CBC parameters.

    ``pre_encrypt`` can model the SDK's still-unresolved corpse transform
    (for example a Caesar/lifting function) without baking an unverified rule
    into this module.
    """

    key, iv = _validate_aes(key, iv)
    value = _as_bytes(plaintext, name="plaintext")
    if pre_encrypt is not None:
        value = _as_bytes(pre_encrypt(value), name="pre_encrypt result")
    return AES.new(key, AES.MODE_CBC, iv).encrypt(_pad(value))


def decrypt_part2(ciphertext: bytes, key: bytes, iv: bytes,
                  *, post_decrypt: Optional[Callable[[bytes], bytes]] = None) -> bytes:
    """Decrypt one A payload with explicit AES-CBC parameters."""

    key, iv = _validate_aes(key, iv)
    ciphertext = _as_bytes(ciphertext, name="ciphertext")
    if not ciphertext or len(ciphertext) % BLOCK_SIZE:
        raise ValueError("AES ciphertext must contain complete blocks")
    value = _unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext))
    if post_decrypt is not None:
        value = _as_bytes(post_decrypt(value), name="post_decrypt result")
    return value


@dataclass(frozen=True)
class DecodedEnvelope:
    parts: EnvelopeParts
    payload: bytes
    plaintext: Optional[bytes]
    mode: Optional[str] = None
    profile: Optional[str] = None
    rsa_verified: bool = False


def encode(session_material: bytes, plaintext: bytes, *, key: bytes, iv: bytes,
           modulus: int | bytes | str, exponent: int = 65537,
           compress: bool = True, zlib_level: int = 6,
           pre_encrypt: Optional[Callable[[bytes], bytes]] = None) -> str:
    """Create an A-envelope with an explicit payload key/IV.

    ``compress`` is suitable for a known zlib payload.  The unknown SDK
    corpse transform remains a callback so callers can supply it only after
    validating it against a runtime capture.
    """

    plain = _as_bytes(plaintext, name="plaintext")
    if compress:
        plain = zlib.compress(plain, zlib_level)
    payload = encrypt_part2(plain, key, iv, pre_encrypt=pre_encrypt)
    return join(raw_rsa_encrypt(session_material, modulus, exponent, size=128), payload)


def decode(envelope: str, *, key: bytes, iv: bytes, decompress: bool = True,
           max_plaintext: int = 4 << 20,
           post_decrypt: Optional[Callable[[bytes], bytes]] = None) -> DecodedEnvelope:
    """Decode an A-envelope when the payload AES key/IV are known.

    The RSA component is returned for inspection only.  It cannot be decrypted
    from the public key or from the envelope itself.
    """

    if isinstance(max_plaintext, bool) or not isinstance(max_plaintext, int) or max_plaintext < 0:
        raise ValueError("max_plaintext must be a nonnegative integer")
    parts = split(envelope)
    payload = decrypt_part2(parts.part2, key, iv, post_decrypt=post_decrypt)
    plain: Optional[bytes] = payload
    if decompress:
        try:
            stream = zlib.decompressobj()
            plain = stream.decompress(payload, max_plaintext + 1)
            if len(plain) > max_plaintext or not stream.eof or stream.unused_data or stream.unconsumed_tail:
                raise ValueError("payload is not one complete zlib stream")
        except zlib.error as exc:
            raise ValueError("payload is not a valid zlib stream") from exc
    return DecodedEnvelope(parts=parts, payload=payload, plaintext=plain)


def _sdk_mask(a1: str, profile: str, *, salt: Optional[bytes] = None,
              a1_shift: Optional[int] = None) -> bytes:
    if profile == "default":
        options = {"salt": DEFAULT_SALT, "a1_shift": 31}
    elif profile == "legacy":
        legacy = json.loads(Path(__file__).with_name("a9_legacy_profile.json").read_text())
        options = {"salt": bytes.fromhex(legacy["salt_hex"]), "a1_shift": legacy["a1_shift"]}
    else:
        raise ValueError("envelope profile must be default or legacy")
    if salt is not None:
        options["salt"] = _as_bytes(salt, name="salt")
    if a1_shift is not None:
        options["a1_shift"] = a1_shift
    return derive_mask(a1, **options)


def _session_bytes(value: bytes, name: str) -> bytes:
    value = _as_bytes(value, name=name)
    if len(value) != 16:
        raise ValueError(f"{name} must contain exactly 16 bytes")
    return value


def derive_session_material(session_key: bytes, a1: str, *, profile: str = "default",
                            salt: Optional[bytes] = None,
                            a1_shift: Optional[int] = None) -> bytes:
    """Return the 16-byte RSA plaintext, not an RSA ciphertext or private key."""
    key = _session_bytes(session_key, "session_key")
    mask = _sdk_mask(a1, profile, salt=salt, a1_shift=a1_shift)
    return bytes(k ^ m for k, m in zip(key, mask))


def recover_session_key(session_material: bytes, a1: str, *, profile: str = "default",
                        salt: Optional[bytes] = None,
                        a1_shift: Optional[int] = None) -> bytes:
    """Recover a payload key only when the 16-byte RSA plaintext is known.

    This does not decrypt the RSA component of a captured envelope.  The
    public key, a1 and envelope alone do not reveal session_material.
    """
    material = _session_bytes(session_material, "session_material")
    mask = _sdk_mask(a1, profile, salt=salt, a1_shift=a1_shift)
    return bytes(s ^ m for s, m in zip(material, mask))


def _inflate_sdk(payload: bytes, max_plaintext: int) -> bytes:
    if isinstance(max_plaintext, bool) or not isinstance(max_plaintext, int) or max_plaintext < 0:
        raise ValueError("max_plaintext must be a nonnegative integer")
    stream = zlib.decompressobj()
    try:
        result = stream.decompress(payload, max_plaintext + 1)
    except zlib.error as exc:
        raise ValueError("payload is not a valid zlib stream") from exc
    if (len(result) > max_plaintext or not stream.eof or
            stream.unused_data or stream.unconsumed_tail):
        raise ValueError("payload must be one complete zlib stream within max_plaintext")
    return result


def _encode_sdk_payload(payload: bytes, a1: str, *, session_key: Optional[bytes],
                        mode: str, profile: str, modulus, exponent: int,
                        salt: Optional[bytes], a1_shift: Optional[int]) -> str:
    if mode not in MODES:
        raise ValueError("envelope mode must be aes, twofish or twofish-mod")
    key = secrets.token_bytes(16) if session_key is None else _session_bytes(session_key, "session_key")
    material = derive_session_material(key, a1, profile=profile, salt=salt, a1_shift=a1_shift)
    part1 = raw_rsa_encrypt(material, modulus, exponent, size=128)
    part2 = _crypt(_pad(payload), key, mode, decrypt=False)
    return join(part1, part2)


def encode_sdk(plaintext: bytes | str, a1: str, *, session_key: Optional[bytes] = None,
               mode: str = "twofish-mod", profile: str = "default", compress: bool = True,
               modulus: int | bytes | str = DEFAULT_MODULUS_HEX, exponent: int = 65537,
               zlib_level: int = 6, salt: Optional[bytes] = None,
               a1_shift: Optional[int] = None) -> str:
    """Build an SDK envelope using a prepared plaintext and installation UUID.

    Supply one session_key for a whole app session when reusing the RSA
    prefix. If omitted, a new random key is generated for this call.

    Native C-string input cannot contain NUL. The captured compression
    wrapper truncates output when zlib grows beyond the original input
    length; this API rejects that case instead of emitting invalid zlib.
    ``encode_compressed_sdk`` preserves an already captured complete stream.
    """
    plain = plaintext.encode("utf-8") if isinstance(plaintext, str) else _as_bytes(plaintext, name="plaintext")
    if not plain or b"\0" in plain:
        raise ValueError("SDK plaintext must be a nonempty string without NUL bytes")
    payload = zlib.compress(plain, zlib_level) if compress else plain
    if compress and len(payload) > len(plain):
        raise ValueError("zlib expands this input; native SDK truncates it; use a larger plaintext or compress=False")
    return _encode_sdk_payload(payload, a1, session_key=session_key, mode=mode, profile=profile,
                               modulus=modulus, exponent=exponent, salt=salt, a1_shift=a1_shift)


def encode_compressed_sdk(compressed: bytes, a1: str, *, session_key: Optional[bytes] = None,
                          mode: str = "twofish-mod", profile: str = "default",
                          modulus: int | bytes | str = DEFAULT_MODULUS_HEX,
                          exponent: int = 65537, max_plaintext: int = 4 << 20,
                          salt: Optional[bytes] = None, a1_shift: Optional[int] = None) -> str:
    """Build an envelope from exact, complete zlib bytes without recompressing.

    This bypasses the native C-string compression wrapper's short-input bug.
    It deliberately refuses truncated or concatenated zlib streams.
    """
    payload = _as_bytes(compressed, name="compressed")
    _inflate_sdk(payload, max_plaintext)
    return _encode_sdk_payload(payload, a1, session_key=session_key, mode=mode, profile=profile,
                               modulus=modulus, exponent=exponent, salt=salt, a1_shift=a1_shift)


def decode_sdk(envelope: str, a1: str, *, session_key: Optional[bytes] = None,
               session_material: Optional[bytes] = None, mode: str = "auto",
               profile: str = "default", decompress: bool = True,
               modulus: int | bytes | str = DEFAULT_MODULUS_HEX, exponent: int = 65537,
               max_plaintext: int = 4 << 20, salt: Optional[bytes] = None,
               a1_shift: Optional[int] = None) -> DecodedEnvelope:
    """Decrypt with an explicit payload key or known RSA plaintext material.

    RSA part1 is recomputed and verified first. No server private key is
    recovered, and this API cannot decrypt arbitrary public envelopes from
    a1 alone. Auto mode additionally requires valid PKCS#7 and, by default,
    exactly one complete zlib stream. For raw uncompressed payloads, supply
    the known mode: padding alone is weak evidence for cipher selection.
    """
    if session_key is None and session_material is None:
        raise ValueError("session_key or known session_material is required; public envelope RSA cannot be inverted")
    if isinstance(max_plaintext, bool) or not isinstance(max_plaintext, int) or max_plaintext < 0:
        raise ValueError("max_plaintext must be a nonnegative integer")
    if mode == "auto" and not decompress:
        raise ValueError("uncompressed envelope decoding requires an explicit cipher mode")
    candidates = MODES if mode == "auto" else (mode,)
    if any(m not in MODES for m in candidates):
        raise ValueError("envelope mode must be auto, aes, twofish or twofish-mod")
    if session_key is None:
        key = recover_session_key(session_material, a1, profile=profile, salt=salt, a1_shift=a1_shift)
    else:
        key = _session_bytes(session_key, "session_key")
    material = derive_session_material(key, a1, profile=profile, salt=salt, a1_shift=a1_shift)
    if session_material is not None and _session_bytes(session_material, "session_material") != material:
        raise ValueError("session_key and session_material do not match this a1/profile")
    parts = split(envelope)
    if raw_rsa_encrypt(material, modulus, exponent, size=128) != parts.part1:
        raise ValueError("RSA part1 mismatch: check session material/key, original a1, profile and public key")
    decoded = []
    for candidate in candidates:
        try:
            payload = _unpad(_crypt(parts.part2, key, candidate, decrypt=True))
            plain = _inflate_sdk(payload, max_plaintext) if decompress else payload
            if len(plain) > max_plaintext:
                raise ValueError("plaintext exceeds max_plaintext")
        except ValueError:
            continue
        decoded.append(DecodedEnvelope(parts=parts, payload=payload, plaintext=plain,
                                       mode=candidate, profile=profile, rsa_verified=True))
    if len(decoded) != 1:
        raise ValueError("envelope payload validation failed or ambiguous: check mode/profile and compression")
    return decoded[0]


__all__ = [
    "BLOCK_SIZE", "DEFAULT_MODULUS_HEX", "DecodedEnvelope", "EnvelopeParts", "decode", "decrypt_part2",
    "encode", "encrypt_part2", "join", "raw_rsa_encrypt", "split",
    "SDK_IV", "encode_sdk", "encode_compressed_sdk", "decode_sdk",
    "derive_session_material", "recover_session_key",
]
