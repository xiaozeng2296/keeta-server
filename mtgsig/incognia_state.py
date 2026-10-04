"""Explicit installation state for fresh request tokens; no transport or I/O.

``profile.incognia`` supplies the enable switch, enabled regions and algorithm
configuration. ``profile.incognia_state`` seeds state; ``signer.dev`` owns its
advanced copy. Counters are reserved before encryption and never rolled back
on generation/signing/transport failure. The caller persists signer.dev using
its existing snapshot mechanism and must serialize cross-process access.
"""
from __future__ import annotations

import re
import threading
import time

from Crypto.PublicKey import RSA

from . import incognia_token as codec

STATE_KEY = 'incognia_state'
_LOCK = threading.Lock()
_IDENTITY_FIELDS = ('installation_id', 'initialization_counter', 'initialized_at_ms')
_STATE_FIELDS = _IDENTITY_FIELDS + ('request_counter',)


def _state(value):
    if not isinstance(value, dict) or any(name not in value for name in _STATE_FIELDS):
        raise ValueError('incognia_state requires installation_id and all three counter/time inputs')
    identity = value['installation_id']
    if not isinstance(identity, str) or not identity or not identity.replace('ILM-ID-', ''):
        raise ValueError('incognia_state requires a nonempty installation_id')
    result = {name: value[name] for name in _STATE_FIELDS}
    result['installation_id'] = identity.replace('ILM-ID-', '').lower()
    for name in _STATE_FIELDS[1:]:
        if type(result[name]) is not int or result[name] < 0:
            raise ValueError('incognia_state requires nonnegative integer counters/timestamp')
    return result


def _configuration(profile):
    config = profile.get('incognia')
    if config is None:
        return None
    if not isinstance(config, dict) or type(config.get('enabled')) is not bool:
        raise ValueError('incognia.enabled must be an explicit boolean')
    if not config['enabled']:
        return None
    regions = config.get('enabled_regions')
    if (not isinstance(regions, list) or not regions or
            any(not isinstance(x, str) or not re.fullmatch('[A-Z]{2}', x) for x in regions)):
        raise ValueError('incognia.enabled_regions requires explicit region codes')
    return config


def _algorithm(config):
    algorithm = config.get('algorithm')
    if not isinstance(algorithm, dict) or type(algorithm.get('format')) is not int or algorithm['format'] != 0:
        raise ValueError('incognia.algorithm requires supported format 0')
    for name in ('application_id', 'public_key_pem', 'hmac_key_hex'):
        if not isinstance(algorithm.get(name), str) or not algorithm[name]:
            raise ValueError('incognia.algorithm missing ' + name)
    if not re.fullmatch('[0-9A-Fa-f]{64}', algorithm['hmac_key_hex']):
        raise ValueError('incognia.algorithm requires a 32-byte HMAC configuration')
    if type(algorithm.get('sdk_code')) is not int or algorithm['sdk_code'] < 0:
        raise ValueError('incognia.algorithm requires explicit sdk_code')
    try:
        public = RSA.import_key(algorithm['public_key_pem'])
    except (ValueError, TypeError, IndexError):
        raise ValueError('incognia.algorithm contains an invalid RSA public key') from None
    if public.has_private() or public.size_in_bits() != 2048:
        raise ValueError('incognia.algorithm requires an RSA-2048 public key')
    return algorithm


def refresh_request_headers(headers, profile, *, storage=None, timestamp_ms=None):
    """Manage token headers when an explicit Incognia configuration exists.

    Without that configuration, preserve explicitly supplied legacy headers;
    captured tokens must already have been removed by the template loader.
    ``storage=None`` is render-only: no generation or state consumption.
    With a mutable storage dict, generation still requires an explicitly
    enabled profile. Missing installation state is an error in enabled regions.
    Disabled regions need no installation inputs and consume no counter.
    Returned tokens are never written to storage or back to the profile.
    """
    if 'incognia' not in profile:
        return dict(headers)
    clean = {k: v for k, v in headers.items() if k.lower() != 'incog-token'}
    config = _configuration(profile)
    if config is None or storage is None:
        return clean
    region_values = {v for k, v in clean.items() if k.lower() == 'region'}
    if len(region_values) > 1:
        raise ValueError('conflicting final region headers')
    if region_values:
        region = next(iter(region_values))
    else:
        region_state = profile.get('region_state')
        region = region_state.get('region') if isinstance(region_state, dict) else profile.get('region')
    if not isinstance(region, str) or not re.fullmatch('[A-Z]{2}', region):
        raise ValueError('Incognia generation requires an explicit current region')
    if region not in config['enabled_regions']:
        return clean
    if not isinstance(storage, dict):
        raise ValueError('Incognia generation requires mutable signer.dev state')
    algorithm = _algorithm(config)
    timestamp_ms = int(time.time() * 1000) if timestamp_ms is None else timestamp_ms
    if type(timestamp_ms) is not int or timestamp_ms < 0:
        raise ValueError('Incognia request timestamp must be a nonnegative integer')
    with _LOCK:
        supplied = _state(profile[STATE_KEY]) if STATE_KEY in profile else None
        saved = _state(storage[STATE_KEY]) if STATE_KEY in storage else None
        if supplied is None and saved is None:
            raise ValueError('missing explicit incognia_state; installation identity is never fabricated')
        if supplied is not None and saved is not None:
            if any(supplied[name] != saved[name] for name in _IDENTITY_FIELDS):
                raise ValueError('incognia_state conflicts with the active installation initialization')
            current = dict(saved, request_counter=max(saved['request_counter'], supplied['request_counter']))
        else:
            current = supplied or saved
        payload = codec.build_payload(
            application_id=algorithm['application_id'], installation_id=current['installation_id'],
            initialization_counter=current['initialization_counter'], initialized_at_ms=current['initialized_at_ms'],
            request_counter=current['request_counter'], requested_at_ms=timestamp_ms,
            sdk_code=algorithm['sdk_code'])
        # Reserve before potentially failing crypto or later request work.
        storage[STATE_KEY] = dict(current, request_counter=current['request_counter'] + 1)
    try:
        token = codec.encode(payload, public_key=algorithm['public_key_pem'],
                             hmac_key=bytes.fromhex(algorithm['hmac_key_hex']))
    except Exception:
        raise ValueError('Incognia token generation failed; reserved counter retained') from None
    clean['incog-token'] = token
    return clean
