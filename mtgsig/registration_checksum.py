"""Registration m320 for the recovered SDK's healthy calculation branch.

The convenient dict API replaces m320. The native pairs API preserves every
input node, including duplicates and an earlier cache m320. Values must be
raw strings before optional m-series encoding.
"""
import hashlib
import hmac
import zlib

from Crypto.Cipher import AES

_AES_KEY = b'yWIZ6bREe7laIika'
_MIX = bytes.fromhex('eb72b4da77bd72981721c3a2f8aafe43')


def compute_m320(fields, *, appkey, version, sdk_flag, provider_mask,
                 guard_fault=False):
    """Calculate the raw m320 string; no I/O or SDK state mutation.

    version is the complete internal config named a0, not mtgsig.a0 or the
    SDK release number. sdk_flag is the integer at 4e45570. provider_mask is
    the SDK object's first 16 bytes, not the envelope session key. A faulted
    SDK returns a separate configured fallback, which this function rejects.
    """
    if not isinstance(fields, dict) or not fields:
        raise ValueError('m320 requires a nonempty ordered field object')
    return compute_m320_pairs([(name, value) for name, value in fields.items() if name != 'm320'],
        appkey=appkey, version=version, sdk_flag=sdk_flag, provider_mask=provider_mask,
        guard_fault=guard_fault)


def compute_m320_pairs(pairs, *, appkey, version, sdk_flag, provider_mask,
                       guard_fault=False):
    """Hash native cJSON entries before the newly calculated m320 is appended.

    Native cJSON permits duplicate keys. Its sorting step reverses equal-key
    insertion order and retains every entry, including an existing cache m320.
    The caller must remove only the final, newly generated checksum entry.
    ``compute_m320`` remains the convenient unique-key/replacement interface.
    """
    if guard_fault:
        raise ValueError('m320 SDK fault fallback is not a checksum calculation')
    if not isinstance(pairs, (list, tuple)) or not pairs:
        raise ValueError('m320 requires nonempty cJSON entries')
    if not isinstance(appkey, str) or not appkey or not isinstance(version, str) or not version:
        raise ValueError('m320 requires nonempty appkey and SDK version')
    if type(sdk_flag) is not int or len(provider_mask) != 16:
        raise ValueError('m320 requires an integer SDK flag and 16-byte mask')
    for pair in pairs:
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            raise TypeError('m320 entries must be key/value pairs')
        name, value = pair
        if not isinstance(name, str) or not isinstance(value, str):
            raise TypeError('m320 object keys and values must be strings')
        if '\0' in name or '\0' in value:
            raise ValueError('native m320 strings cannot contain NUL')
    material = bytearray()
    for name, value in sorted(reversed(pairs), key=lambda pair: pair[0]):
        material.extend(name.encode('utf-8'))
        material.extend(value.encode('utf-8'))
    app_bytes, version_bytes = appkey.encode('utf-8'), version.encode('utf-8')
    if '\0' in appkey or '\0' in version:
        raise ValueError('native m320 configuration cannot contain NUL')
    key = bytearray(len(app_bytes))
    for i in range(max(len(app_bytes), len(version_bytes))):
        j = i % len(app_bytes)
        key[j] = app_bytes[j] ^ version_bytes[i % len(version_bytes)] ^ (sdk_flag & 255)
    digest = hmac.new(key, material, hashlib.sha1).digest()
    # Only the first ECB block contributes, so later PKCS#7 bytes are irrelevant.
    encrypted = AES.new(_AES_KEY, AES.MODE_ECB).encrypt(digest[:16])
    mixed = bytes((((a + b) & 255) ^ _MIX[i] ^ provider_mask[i]) & (254 if i == 15 else 255)
                  for i, (a, b) in enumerate(zip(encrypted, digest)))
    return str(zlib.adler32(mixed) & 0xffffffff)
