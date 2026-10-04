"""Decode observed FAMA /ntp A responses without network or persistence.

Native callback 0x389004 reads ntp_info and ts, applies a repeating XOR with
the low 32 bits of ts in big-endian order, then formats bytes using %02x.
The result is written into fingerprintData and sakguard_storage_dfpid.
This is distinct from /v5/sign's plaintext data.dfp response.
"""
import base64
import binascii
from collections.abc import Mapping
from dataclasses import dataclass
import re


NTP_PATH = '/ntp'
NTP_DFP_BYTES = 28


def _timestamp(value):
    if type(value) is not int or not 0 < value <= (1 << 63) - 1:
        raise ValueError('NTP ts must be a positive signed 64-bit integer')
    return value


def decode_ntp_info(ntp_info, ts):
    """Return the observed 56-character DFP, rejecting unsupported encodings.

Native NSData uses IgnoreUnknownCharacters. This offline boundary deliberately
requires canonical standard Base64 and the 28-byte payload observed in this
SDK, so truncated/foreign data cannot silently become a persisted identity.
"""
    _timestamp(ts)
    if not isinstance(ntp_info, str) or not re.fullmatch(r'[A-Za-z0-9+/]{38}==', ntp_info):
        raise ValueError('NTP ntp_info must be canonical Base64 for 28 bytes')
    try:
        payload = base64.b64decode(ntp_info, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError('NTP ntp_info has invalid Base64') from None
    if len(payload) != NTP_DFP_BYTES or base64.b64encode(payload).decode('ascii') != ntp_info:
        raise ValueError('NTP ntp_info must encode exactly 28 bytes')
    mask = (ts & 0xffffffff).to_bytes(4, 'big')
    return bytes(value ^ mask[index & 3] for index, value in enumerate(payload)).hex()


@dataclass(frozen=True)
class DecodedNtp:
    dfp: str
    server_timestamp: int
    interval_hours: int
    version: str
    ab_test_flag: str = 'A'
    source_endpoint: str = NTP_PATH

    def fingerprint_data(self):
        """The five string-valued entries built at 0x389800..0x389974."""
        return {'serverTimestamp': str(self.server_timestamp),
                'interval': str(self.interval_hours), 'dfp': self.dfp,
                'ab_test_flag': self.ab_test_flag, 'version': self.version}

    def identity_patch(self):
        """Aliases proven against later a8 and v5/sign in all four captures.

        This does not mutate an identity or mark an unexecuted request accepted.
        Callers retain the original response and its association with the
        current request before applying any patch.
        """
        return {'a8': self.dfp, 'a8_server_dfp': self.dfp, 'dfp': self.dfp,
                'outid_history_dfp': self.dfp}


def decode_ntp_response(response, *, http_status):
    """Decode the supported top-level A/1.0 shape after explicit HTTP success.

    B returns early in the native callback and supplies no A cache update.
    Other variants remain unsupported here. A v5/sign data object cannot be
    passed as an NTP response, even when both ultimately identify one device.
    """
    if type(http_status) is not int or not 200 <= http_status < 300:
        raise ValueError('NTP response requires successful HTTP status')
    if not isinstance(response, Mapping):
        raise ValueError('NTP response must be an object')
    if type(response.get('status')) is not int or response['status'] != 0:
        raise ValueError('NTP response status is not integer zero')
    if response.get('error') or ('success' in response and response['success'] is not True):
        raise ValueError('NTP response reports an error')
    if response.get('ab_test_flag') != 'A' or response.get('version') != '1.0':
        raise ValueError('unsupported NTP variant; expected A/1.0')
    interval = response.get('interval')
    if type(interval) is not int or not 0 <= interval <= ((1 << 31) - 1) // 3600:
        raise ValueError('NTP interval must be supported nonnegative integer hours')
    ts = _timestamp(response.get('ts'))
    dfp = decode_ntp_info(response.get('ntp_info'), ts)
    return DecodedNtp(dfp, ts, interval, response['version'])
