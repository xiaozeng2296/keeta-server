"""Refresh request-scoped data before mtgsig signing; no transport or I/O."""
from copy import deepcopy
import base64
import json
import re
import time
import uuid

from mtgsig.incognia_state import refresh_request_headers
from mtgsig.request_trace import ensure_m_shark_session_marker, make_m_shark_trace_id
from mtgsig.mtg_crypto import fingerprint_encrypt


def _fingerprint(value, timestamp_ms, cache):
    if value not in cache:
        # Recover a validated cipher profile from this account's own sample.
        # Keep keys and plaintext in memory; never return them in diagnostics.
        import keeta_rpc as rpc
        try:
            base64.b64decode(value, validate=True)
            decoded = rpc.op_fp_decrypt({'fingerprint': value})
            key = rpc._fp_key_bytes(decoded['key_used'])
            raw = rpc._fp_try(base64.b64decode(value, validate=True), key, rpc.FP_IV)
            if fingerprint_encrypt(raw, key=key, iv=rpc.FP_IV) != value:
                raise ValueError('fingerprint roundtrip mismatch')
        except Exception:
            raise ValueError('request fingerprint failed strict decode/roundtrip validation') from None
        if not isinstance(decoded.get('plain_json'), dict):
            raise ValueError('request fingerprint must decode to a JSON object')
        plain = decoded['plain_json']
        old = plain.get('I39')
        if not isinstance(old, str) or not re.fullmatch(r'[0-9]{13}\.[0-9]+', old):
            raise ValueError('unsupported observed fingerprint I39 timestamp layout')
        cache[value] = (plain, key, rpc.FP_IV)
    plain, key, iv = cache[value]
    fresh = deepcopy(plain)
    precision = len(fresh['I39'].split('.')[1])
    fresh['I39'] = f'{timestamp_ms:.{precision}f}'
    # I41/I44 and the other fields remain observations; no fake CPU/memory.
    return fingerprint_encrypt(fresh, key=key, iv=iv)


def refresh_request(url, headers, body, storage, *, timestamp_ms=None, fingerprint_cache=None):
    timestamp_ms = time.time() * 1000 if timestamp_ms is None else timestamp_ms
    if type(timestamp_ms) not in (int, float) or not 1e12 <= timestamp_ms < 1e13:
        raise ValueError('request timestamp must be a supported millisecond value')
    headers = {k.lower(): v for k, v in headers.items()
               if k.lower() not in ('mtgsig', 'content-length', 'accept-encoding')}
    # Fail explicitly rather than silently keep a captured Incognia token.
    # BR native templates may omit it despite the region requiring the SDK.
    incognia_mode = storage.get('incognia_mode', 'generate')
    if incognia_mode not in ('generate', 'captured'):
        raise ValueError('incognia_mode must be generate or captured')
    if incognia_mode == 'generate' and 'incognia' not in storage and (headers.get('region') == 'BR' or 'incog-token' in headers):
        raise ValueError('fresh requests require explicit Incognia configuration and installation state')
    url = re.sub(r'([?&]__reqTraceID=)[^&#]*',
                 lambda match: match[1] + str(uuid.uuid4()).upper(), url)
    if 'm-shark-traceid' in headers:
        headers['m-shark-traceid'] = make_m_shark_trace_id(
            headers['m-shark-traceid'], headers.get('csecuuid') or headers.get('uuid'),
            now_ms=timestamp_ms, session_marker=ensure_m_shark_session_marker(storage))
    parsed = json.loads(body)
    if not isinstance(parsed, dict):
        raise ValueError('fresh crawler requests require a JSON object body')
    cache = {} if fingerprint_cache is None else fingerprint_cache
    changed = False
    for name in ('fingerPrint', 'fingerprint'):
        if parsed.get(name):
            parsed[name] = _fingerprint(parsed[name], timestamp_ms, cache)
            changed = True
    if changed:
        body = json.dumps(parsed, ensure_ascii=False, separators=(',', ':'))
    if incognia_mode == 'generate':
        headers = refresh_request_headers(headers, storage, storage=storage,
                                          timestamp_ms=int(timestamp_ms))
    return url, headers, body
