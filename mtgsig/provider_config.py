"""Dynamic enc-salt configuration for the observed Keeta SAKGuard build.

This is the value of sakguard_dynamic_enc_salt_config_key, not /v1/scfg.
Decode only well-typed configurations. Native coercions of malformed JSON
(e.g. a3 strings to zero) are deliberately not treated as supported profiles.
"""
import base64
import binascii
from dataclasses import dataclass, field
import hashlib
import json
import re

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from .a9_codec import DEFAULT_SALT, derive_mask

STORAGE_KEY = 'sakguard_dynamic_enc_salt_config_key'
MAX_CONFIG_BYTES = 4096
# k0.k1 and IV were compared with the running 3.12.500 SDK constant table.
_KEY = b"meituan1sankuai0"
_IV = b"0102030405060708"


@dataclass(frozen=True)
class ProviderConfig:
    parameter: int = 20
    salt: bytes = field(default=DEFAULT_SALT, repr=False)
    plaintext: str = field(default='', repr=False, compare=False)

    def __post_init__(self):
        if type(self.parameter) is not int or not 0 <= self.parameter <= 0x7fffffff:
            raise ValueError('provider parameter must be a nonnegative signed 32-bit integer')
        if not isinstance(self.salt, bytes) or len(self.salt) != 16:
            raise ValueError('provider salt must contain 16 bytes')

    @property
    def a1_shift(self):
        return (self.parameter + 11) % 36

    def mask(self, a1):
        return derive_mask(a1, salt=self.salt, a1_shift=self.a1_shift)

    def a9_options(self):
        return {'salt': self.salt, 'a1_shift': self.a1_shift}

    def summary(self):
        return {'parameter': self.parameter, 'a1_shift': self.a1_shift,
                'salt_sha256': hashlib.sha256(self.salt).hexdigest()}


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate configuration key')
        value[key] = item
    return value


def parse_plaintext(text):
    if not isinstance(text, str) or len(text.encode('utf-8')) > MAX_CONFIG_BYTES:
        raise ValueError('provider configuration must be bounded JSON text')
    try:
        obj = json.loads(text, object_pairs_hook=_unique_object)
    except (ValueError, RecursionError) as exc:
        raise ValueError('invalid provider configuration JSON') from exc
    if not isinstance(obj, dict) or set(obj) != {'a3', 'salt'}:
        raise ValueError('unsupported provider configuration schema')
    if not isinstance(obj['salt'], str) or not re.fullmatch('[0-9a-fA-F]{32}', obj['salt']):
        raise ValueError('provider salt must be 32 hexadecimal characters')
    return ProviderConfig(obj['a3'], bytes.fromhex(obj['salt']), text)


def decode_config(value):
    """Decode exact stored text; the empty string selects native defaults.

    None means missing evidence at the caller, not an empty native input.
    Reject ambiguous types, duplicate fields, extra fields and bad padding.
    """
    if not isinstance(value, str) or len(value) > (MAX_CONFIG_BYTES + 16) * 2:
        raise ValueError('provider configuration must be bounded Base64 text')
    if value == '':
        return ProviderConfig()
    try:
        ciphertext = base64.b64decode(value, validate=True)
        if (not ciphertext or len(ciphertext) % 16 or len(ciphertext) > MAX_CONFIG_BYTES + 16
                or base64.b64encode(ciphertext).decode('ascii') != value):
            raise ValueError('invalid ciphertext length or encoding')
        plaintext = unpad(AES.new(_KEY, AES.MODE_CBC, _IV).decrypt(ciphertext), 16).decode('utf-8')
        return parse_plaintext(plaintext)
    except (ValueError, UnicodeError, binascii.Error) as exc:
        raise ValueError('provider configuration decryption or validation failed') from exc


def encode_config(value):
    """Encode a synthetic profile or preserve decoded original JSON bytes."""
    if isinstance(value, ProviderConfig):
        text = value.plaintext or json.dumps({'a3': value.parameter, 'salt': value.salt.hex()}, separators=(',', ':'))
        parsed = parse_plaintext(text)
        if parsed.parameter != value.parameter or parsed.salt != value.salt:
            raise ValueError('provider plaintext and profile disagree')
    else:
        text = value
        parse_plaintext(text)
    return base64.b64encode(AES.new(_KEY, AES.MODE_CBC, _IV).encrypt(pad(text.encode('utf-8'), 16))).decode('ascii')


def configuration_summary(configuration):
    """Safe inventory for a native storage observation, with no plaintext."""
    result = {k: configuration[k] for k in ('key', 'available', 'storage_class') if k in configuration}
    value = configuration.get('value')
    result.update(present=value is not None,
                  sha256=hashlib.sha256(value.encode()).hexdigest() if isinstance(value, str) else None,
                  length=len(value) if isinstance(value, str) else 0)
    if value is None:
        result['decode_status'] = 'not_observed'
    else:
        try:
            decoded = decode_config(value)
            result.update(decoded.summary(), decode_status='default' if value == '' else 'decoded')
        except ValueError:
            result['decode_status'] = 'unsupported_configuration'
    return result
