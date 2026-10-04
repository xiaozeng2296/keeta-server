"""Local registration IDs for the analysed Keeta iOS SDK build.

These functions produce and validate the local a8 fallback and local a7 XID.
Server registration responses still determine the later XID/DFP state.
"""

import base64
import binascii
from dataclasses import dataclass, field
import re
from uuid import UUID
import zlib

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


@dataclass(frozen=True)
class LocalIdentityProfile:
    """Versioned XOR/layout parameters recovered from the current binary."""

    version: str
    source: str
    mask: bytes = field(repr=False)
    prefix: str = "0000"
    suffix: str = "1"

    def __post_init__(self):
        if not isinstance(self.mask, bytes) or len(self.mask) != 28:
            raise ValueError("local-ID mask must contain 28 bytes")
        if not re.fullmatch(r"[0-9a-f]{4}", self.prefix):
            raise ValueError("local-ID prefix must contain four lowercase hex digits")
        if not re.fullmatch(r"[0-9a-f]", self.suffix):
            raise ValueError("local-ID suffix must contain one lowercase hex digit")
        if not self.version or not self.source:
            raise ValueError("local-ID profile requires version and source")


DEFAULT_LOCAL_ID_PROFILE = LocalIdentityProfile(
    version="keeta-ios-3.12.401-sakguard-5.21.10",
    source="dump/Keeta.dec: RVA 0x3322c80, XOR seed 0xeb; generateLocalID 0x36316c",
    mask=bytes.fromhex("dad7630ca92342fcbfa30742ac9aa638cbff362156774ad6a27462cb"),
)


@dataclass(frozen=True)
class DecodedLocalIdentity:
    uuid: str
    timestamp_ms: int
    crc32_hex: str
    profile_version: str
    profile_source: str


@dataclass(frozen=True)
class LocalXidProfile:
    version: str
    source: str
    key: bytes = field(repr=False)
    iv: bytes = b"0102030405060708"

    def __post_init__(self):
        if not isinstance(self.key, bytes) or len(self.key) != 16:
            raise ValueError("local-XID AES key must contain 16 bytes")
        if not isinstance(self.iv, bytes) or len(self.iv) != 16:
            raise ValueError("local-XID AES IV must contain 16 bytes")
        if not self.version or not self.source:
            raise ValueError("local-XID profile requires version and source")


DEFAULT_LOCAL_XID_PROFILE = LocalXidProfile(
    version="keeta-ios-3.12.401-sakguard-5.21.10",
    source="dump/envelope_recovery/local_xid_crypto_01.json; SAKGuardCommon.encrypt: op 2",
    key=bytes.fromhex("6d65697475616e3173616e6b75616930"),
)


@dataclass(frozen=True)
class DecodedLocalXid:
    source_dfp_id: str
    timestamp_seconds: int
    profile_version: str
    profile_source: str


def _uuid_hex(value):
    if isinstance(value, UUID):
        return value.hex
    if not isinstance(value, str) or not re.fullmatch(
        r"(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})",
        value,
    ):
        raise ValueError("local-ID UUID must be canonical UUID text or 32 hex digits")
    return UUID(value).hex


def _xor(data, profile):
    return bytes(a ^ b for a, b in zip(data, profile.mask))


def generate_local_dfp(uuid_value, timestamp_ms, *, profile=DEFAULT_LOCAL_ID_PROFILE):
    """Generate local a8 from the explicit UUID and integer Unix milliseconds.

    The native current-date layout has an 11-hex-digit timestamp.  Other widths
    are rejected because the native XOR routine requires exactly 28 bytes.
    Supplying time and UUID explicitly makes the result reproducible.
    """
    if isinstance(timestamp_ms, bool) or not isinstance(timestamp_ms, int):
        raise TypeError("local-ID timestamp_ms must be an integer")
    if not 0x10000000000 <= timestamp_ms <= 0xFFFFFFFFFFF:
        raise ValueError("local-ID timestamp_ms must encode to exactly 11 hex digits")
    material = (profile.prefix + _uuid_hex(uuid_value) +
                f"{timestamp_ms:x}" + profile.suffix)
    checksum = zlib.crc32(material.encode("ascii")) & 0xFFFFFFFF
    raw = bytes.fromhex(material + f"{checksum:08x}")
    return _xor(raw, profile).hex()


def decode_local_dfp(value, *, profile=DEFAULT_LOCAL_ID_PROFILE):
    """Parse a local a8 only after validating its layout and CRC32.

    Server DFP values also have 56 hexadecimal characters.  Matching length is
    insufficient: this function rejects values that fail the local layout/CRC.
    """
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{56}", value):
        raise ValueError("local-ID must contain 56 hex digits")
    raw = _xor(bytes.fromhex(value), profile).hex()
    material, checksum = raw[:48], raw[48:]
    if not (material.startswith(profile.prefix) and material.endswith(profile.suffix)):
        raise ValueError("local-ID layout does not match profile")
    expected = zlib.crc32(material.encode("ascii")) & 0xFFFFFFFF
    if checksum != f"{expected:08x}":
        raise ValueError("local-ID CRC32 validation failed")
    timestamp_ms = int(material[36:47], 16)
    if timestamp_ms < 0x10000000000:
        raise ValueError("local-ID timestamp does not match native current-date layout")
    return DecodedLocalIdentity(
        uuid=str(UUID(hex=material[4:36])), timestamp_ms=timestamp_ms,
        crc32_hex=checksum, profile_version=profile.version,
        profile_source=profile.source,
    )


def build_local_xid_plaintext(dfp_id, timestamp_seconds):
    """Return a7 candidate's bytes before SAKGuardCommon.encrypt: (op 2).

    Native generateLocalXID selects a 56-character static dfpID, falling back to
    its cached localID, then concatenates ``1 + id + 1 + %2X(epoch_seconds)``.
    The caller supplies the selected ID; this helper never reads or mutates
    device caches. Encryption is provided separately by encode_local_xid.
    """
    if not isinstance(dfp_id, str) or not re.fullmatch(r"[0-9a-fA-F]{56}", dfp_id):
        raise ValueError("XID source dfp_id must contain 56 hex digits")
    if isinstance(timestamp_seconds, bool) or not isinstance(timestamp_seconds, int):
        raise TypeError("XID timestamp_seconds must be an integer")
    if not 0 <= timestamp_seconds <= 0xFFFFFFFF:
        raise ValueError("XID timestamp_seconds must fit the native unsigned 32-bit format")
    return f"1{dfp_id}1{timestamp_seconds:2X}".encode("ascii")


def encode_local_xid(dfp_id, timestamp_seconds, *, profile=DEFAULT_LOCAL_XID_PROFILE):
    """Generate the local a7 candidate using native-matched AES-128-CBC/PKCS7."""
    plaintext = build_local_xid_plaintext(dfp_id, timestamp_seconds)
    ciphertext = AES.new(profile.key, AES.MODE_CBC, profile.iv).encrypt(pad(plaintext, 16))
    return base64.b64encode(ciphertext).decode("ascii")


def decode_local_xid(value, *, profile=DEFAULT_LOCAL_XID_PROFILE):
    """Decode and validate the *local candidate* XID format only.

    Server response XIDs have separate semantics and must be stored unchanged.
    A 108-character Base64 string by itself is not evidence of this format.
    The source dfpID inside a valid local XID may already be a server DFP; this
    parser therefore does not claim that it is a local a8 fallback.
    """
    if not isinstance(value, str):
        raise ValueError("local-XID must be Base64 text")
    try:
        ciphertext = base64.b64decode(value, validate=True)
        if not ciphertext or len(ciphertext) % 16:
            raise ValueError("incomplete AES blocks")
        if base64.b64encode(ciphertext).decode("ascii") != value:
            raise ValueError("non-canonical Base64")
        plaintext = unpad(AES.new(profile.key, AES.MODE_CBC, profile.iv).decrypt(ciphertext), 16)
        text = plaintext.decode("ascii")
        if not re.fullmatch(r"1[0-9a-fA-F]{56}1[ 0-9A-F]{2,8}", text):
            raise ValueError("unexpected local-XID plaintext")
        seconds = int(text[58:].strip(), 16)
        if build_local_xid_plaintext(text[1:57], seconds) != plaintext:
            raise ValueError("unexpected local-XID time format")
    except (ValueError, UnicodeError, binascii.Error) as exc:
        raise ValueError("local-XID validation failed; input may be a server XID or another profile") from exc
    return DecodedLocalXid(
        source_dfp_id=text[1:57], timestamp_seconds=seconds,
        profile_version=profile.version, profile_source=profile.source,
    )
