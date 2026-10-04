"""Own-material XID reporting and its observed native lifecycle (SDK 5.21.10).

This is a minimal accepted report, not a reconstruction of all native sensors.
No HTTP, credentials, persistence, or guessed cross-account device data here.
"""
from copy import deepcopy
import re
from urllib.parse import urlencode

from mtgsig.collection_cache import compact
from mtgsig.registration_checksum import compute_m320
from mtgsig.registration_state import parse_registration_response
from mtgsig import envelope_codec

PATH = '/fingerprint/v1/info/report'
STATE = 'fingerprint_report_state'
CONFIG = 'fingerprint_refresh'
_TRIPLE = re.compile(r'\[\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\]')


def _report_group(device):
    base = device['base_collect']
    state = device.get(STATE) or {}
    if state and state.get('b7') != base['b7']:
        raise ValueError('fingerprint report state belongs to another SDK session')
    value = state.get('b16', base.get('b16'))
    matches = list(_TRIPLE.finditer(value)) if isinstance(value, str) else []
    if len(matches) != 3:
        raise ValueError('unsupported fingerprint report lifecycle layout')
    return value, matches[1]


def outgoing_b16(device, captured):
    if not device.get(STATE):
        return captured
    return _report_group(device)[0]


def _update_group(device, *, count=None, start=None, success=None):
    value, match = _report_group(device)
    parts = [int(x) for x in match.groups()]
    for index, val in enumerate((count, start, success)):
        if val is not None:
            parts[index] = val
    replacement = '[' + ','.join(map(str, parts)) + ']'
    return value[:match.start()] + replacement + value[match.end():]


def relative_time(device, timestamp_ms):
    if type(timestamp_ms) is not int or timestamp_ms < 0:
        raise ValueError('report timestamp requires nonnegative integer milliseconds')
    delta = timestamp_ms // 1000 - device['base_collect']['b7']
    if delta < 0:
        raise ValueError('report clock precedes the observed SDK startup')
    return delta


def begin_report(device, event_id, timestamp_ms):
    """Record a real invocation once; caller persists before dispatching HTTP."""
    state = deepcopy(device.get(STATE) or {})
    if state.get('pending_event'):
        raise ValueError('unfinished fingerprint report requires reconciliation')
    if not isinstance(event_id, str) or not event_id:
        raise ValueError('report event ID required')
    _, match = _report_group(device)
    b16 = _update_group(device, count=int(match[1]) + 1,
                        start=relative_time(device, timestamp_ms))
    state.update(b7=device['base_collect']['b7'], b16=b16,
                 pending_event=event_id, last_attempt_ms=timestamp_ms)
    device[STATE] = state


def finish_report(signer, event_id, response, http_status, timestamp_ms):
    """Record HTTP200 separately from acceptance; preserve a7 on rejection."""
    device = signer.dev
    state = deepcopy(device.get(STATE) or {})
    if state.get('pending_event') != event_id:
        raise ValueError('fingerprint response does not match pending report')
    if timestamp_ms < state['last_attempt_ms']:
        raise ValueError('report completion precedes invocation')
    if http_status == 200:
        state['b16'] = _update_group(device, success=relative_time(device, timestamp_ms))
    accepted = bool(parse_registration_response(PATH, response, http_status=http_status))
    state.pop('pending_event')
    state.update(last_finished_ms=timestamp_ms, last_http=http_status, accepted=accepted)
    if accepted:
        signer.apply_registration_response(PATH, response, http_status=http_status)
        data = response['data']
        interval = data.get('interval')
        server = data.get('serverTimestamp')
        state.update(last_success_ms=timestamp_ms, failures=0,
                     server_timestamp_ms=server if type(server) is int else None,
                     interval_minutes=interval if type(interval) is int and interval > 0 else None)
        # Native 0x38ad38..0x38ad78: NSDate(now + interval*60), integer seconds*1000.
        state['expires_at_ms'] = ((timestamp_ms // 1000 + interval * 60) * 1000
                                  if type(interval) is int and 0 < interval <= 35791394 else None)
        state['not_before_ms'] = timestamp_ms + 60000
    else:
        failures = state.get('failures', 0) + 1
        state.update(failures=failures,
                     not_before_ms=timestamp_ms + min(1800000, 60000 * 2 ** min(failures - 1, 5)))
    device[STATE] = state
    return accepted


def refresh_status(device, timestamp_ms):
    config = device.get(CONFIG) or {}
    state = device.get(STATE) or {}
    if config.get('enabled') is not True:
        return 'disabled'
    if state.get('pending_event'):
        return 'unfinished_report'
    if state.get('accepted') and state.get('expires_at_ms') is not None and timestamp_ms < state['expires_at_ms']:
        return 'fresh'
    if timestamp_ms < state.get('not_before_ms', 0):
        return 'backoff'
    if state.get('accepted') and state.get('expires_at_ms') is None:
        return 'expiry_unknown'
    return 'due'


def build_report(bundle, signer, *, timestamp_ms, session_key=None):
    """Map this installation's known fields; create a fresh envelope and m320."""
    dev = signer.dev
    cfg = dev.get(CONFIG) or {}
    col = dev['base_collect']
    if cfg.get('sdk_version') != '5.21.10' or col.get('b10') != cfg['sdk_version']:
        raise ValueError('unvalidated fingerprint SDK configuration')
    if cfg.get('appkey') != dev['a1'] or not isinstance(cfg.get('checksum_version'), str) or len(cfg['checksum_version']) != 64:
        raise ValueError('fingerprint checksum configuration is missing or mismatched')
    if signer._collection_cache is not None:
        col, _ = signer._collection_cache.refresh(timestamp_ms)
    identity = bundle['identity']
    fields = {'m27': signer.a8, 'm144': col['b5'], 'm152': col['b10'],
              'm153': identity.get('csecuuid') or identity.get('uuid'),
              'm154': col['b4'], 'm294': col['b1']}
    if any(not isinstance(value, str) or not value for value in fields.values()):
        raise ValueError('own fingerprint fields missing')
    from mtgsig.signer import k2buf
    fields['m320'] = compute_m320(fields, appkey=dev['a1'], version=cfg['checksum_version'],
                                sdk_flag=signer.signature_counter,
                                provider_mask=k2buf(dev['a1'], signer.signing_profile))
    mode = ('twofish-mod', 'twofish', 'aes')[signer.signature_counter % 3]
    envelope = envelope_codec.encode_sdk(compact(fields), dev['a1'], session_key=session_key,
                                          mode=mode, profile=signer.signing_profile)
    allowed = {'user-agent', 'region', 'cityid', 'appid', 'userid',
               'sakmodelsdkversionkey', 'nvt', 'accept', 'accept-language'}
    headers = {k.lower(): v for k, v in bundle['request']['headers'].items() if k.lower() in allowed}
    for header in ('region', 'cityid', 'appid', 'userid'):
        if not isinstance(headers.get(header), str) or not headers[header]:
            raise ValueError('fingerprint report routing header missing')
    if headers['userid'] != str(identity['userid']):
        raise ValueError('fingerprint report user mismatch')
    headers.update({'host': 'pikachu-eu.mykeeta.com', 'content-type': 'application/json', 'mtgver': '5.0'})
    url = 'https://pikachu-eu.mykeeta.com' + PATH + '?' + urlencode(
        {'region': headers['region'], 'cityId': headers['cityid'], 'appId': headers['appid']})
    return url, headers, compact({'encryptVersion': '3', 'src': '1', 'fingerPrintData': envelope})
