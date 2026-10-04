"""m-series field transform recovered from Keeta iOS 3.12.401.

Native entry 0x38d334 reads table[field_number % 256] at 0x333c094.
Printable bytes 32..125 rotate modulo 94. Tilde, UTF-8 bytes outside ASCII,
controls and DEL pass unchanged. Unlike the other candidate at 0x2ef840,
this entry preserves tilde and agrees with captured m137 strings.
"""

import json
import re


PROFILE_VERSION = "keeta-ios-3.12.401-sakguard-5.21.10"
# Extracted through Mach-O segment mapping, not guessed from field contents.
SHIFT_TABLE = (
    78, 171, 31, 92, 175, 20, 73, 9, 202, 66, 4, 126, 63, 30, 170, 237,
    93, 206, 168, 111, 207, 151, 182, 147, 47, 242, 62, 205, 105, 236, 3, 195,
    148, 41, 187, 88, 204, 142, 70, 134, 151, 166, 133, 170, 54, 134, 254, 41,
    16, 236, 110, 197, 122, 87, 53, 228, 145, 24, 123, 3, 3, 174, 204, 33,
    192, 76, 67, 45, 18, 186, 173, 40, 23, 123, 22, 25, 118, 218, 216, 152,
    158, 148, 12, 212, 104, 214, 110, 104, 99, 145, 90, 152, 6, 209, 8, 73,
    12, 152, 129, 58, 62, 10, 114, 81, 246, 253, 122, 192, 83, 179, 251, 192,
    134, 240, 113, 2, 117, 125, 221, 50, 1, 209, 40, 154, 168, 88, 105, 251,
    221, 226, 105, 170, 195, 193, 4, 233, 230, 235, 203, 41, 175, 205, 147, 146,
    85, 186, 236, 4, 178, 139, 235, 29, 129, 230, 49, 46, 90, 167, 64, 86,
    130, 48, 29, 172, 201, 60, 204, 28, 15, 194, 245, 4, 228, 173, 2, 132,
    171, 246, 84, 46, 97, 46, 207, 166, 48, 158, 120, 169, 123, 121, 191, 249,
    86, 201, 164, 243, 101, 13, 196, 182, 253, 73, 1, 40, 103, 103, 76, 178,
    176, 99, 35, 41, 172, 158, 197, 200, 225, 88, 88, 69, 155, 171, 115, 100,
    160, 58, 103, 127, 48, 174, 44, 51, 194, 244, 129, 115, 53, 93, 51, 199,
    6, 25, 143, 9, 36, 56, 80, 254, 138, 100, 199, 185, 253, 31, 150, 147,
)


def field_shift(field_number):
    if isinstance(field_number, bool) or not isinstance(field_number, int):
        raise TypeError("field_number must be an integer")
    if not 0 <= field_number <= 0x7FFFFFFF:
        raise ValueError("field_number must be a nonnegative signed 32-bit integer")
    return SHIFT_TABLE[field_number % 256] % 94


def _text(value):
    if not isinstance(value, str):
        raise TypeError("corpse field values must be strings")
    if "\0" in value:
        raise ValueError("corpse fields cannot contain NUL: native input uses strlen")
    value.encode("utf-8")  # Reject lone surrogates before creating wire JSON.
    return value


def encode_field(text, field_number):
    """Apply the native byte transform using this build's exact shift table."""
    shift = field_shift(field_number)
    return "".join(chr((ord(ch) - 32 + shift) % 94 + 32)
                   if 32 <= ord(ch) <= 125 else ch for ch in _text(text))


def decode_field(text, field_number):
    """Invert the 94-byte rotation; tilde and non-ASCII text stay unchanged."""
    shift = field_shift(field_number)
    _text(text)
    return "".join(chr((ord(ch) - 32 - shift) % 94 + 32)
                   if 32 <= ord(ch) <= 125 else ch for ch in text)


def _fields(fields, transform, passthrough):
    if not isinstance(fields, dict):
        raise TypeError("corpse fields must be a JSON object")
    if not isinstance(passthrough, (tuple, list, set, frozenset)):
        raise TypeError("passthrough must be a collection of explicit field names")
    if any(not isinstance(name, str) for name in passthrough):
        raise TypeError("passthrough field names must be strings")
    passthrough = set(passthrough)
    if not passthrough <= fields.keys():
        raise ValueError("passthrough contains a field absent from the input")
    result = {}
    for key, value in fields.items():
        if not isinstance(key, str) or not re.fullmatch(r"m(?:0|[1-9][0-9]*)", key):
            raise ValueError("corpse field names must be canonical m-number keys")
        result[key] = _text(value) if key in passthrough else transform(value, int(key[1:]))
    return result


def encode_fields(fields, *, passthrough=()):
    """Encode m-number values; explicitly selected wire values pass unchanged."""
    return _fields(fields, encode_field, passthrough)


def decode_fields(fields, *, passthrough=()):
    """Decode wire values without guessing; passthrough fields stay opaque."""
    return _fields(fields, decode_field, passthrough)


def encode_json(fields, *, passthrough=()):
    """Return compact UTF-8 wire JSON from ordered, explicitly supplied fields."""
    return json.dumps(encode_fields(fields, passthrough=passthrough), ensure_ascii=False,
                      separators=(",", ":")).encode("utf-8")
