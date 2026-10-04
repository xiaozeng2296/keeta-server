"""Reconstruct mode1 from a full mode0 cache observation of this SDK build.

Mode0 is a diagnostic view, not mode1's pre-transform payload: it includes
inactive fields and duplicate reserved keys. Preserve its native cJSON entries
until the checksum has been verified, then filter using the m307 status map.
"""
import json
import re

from mtgsig.registration_checksum import compute_m320, compute_m320_pairs


def prepared_pairs(text, *, allow_empty=False):
    """Read a native string-valued object without losing duplicate keys."""
    pairs = json.loads(text, object_pairs_hook=lambda items: tuple(items))
    if not isinstance(pairs, tuple) or (not pairs and not allow_empty):
        raise ValueError('prepared fields must be a nonempty JSON object')
    for key, value in pairs:
        if not isinstance(key, str) or not re.fullmatch(r'm(?:0|[1-9][0-9]*)', key):
            raise ValueError('prepared field names must be canonical m-number keys')
        if not isinstance(value, str):
            raise ValueError('prepared field values are not strings')
    return pairs


def verify_prepared_m320(pairs, **context):
    """Verify only the appended checksum; earlier m320 entries are inputs."""
    if not pairs or pairs[-1][0] != 'm320':
        raise ValueError('native prepared object lacks appended m320')
    if pairs[-1][1] != compute_m320_pairs(pairs[:-1], **context):
        raise ValueError('native m320 parity failed')


def device_mode1_plaintext(pairs, **context):
    """Filter/aggregate raw device-info cache fields, then calculate m320.

    ARM64 2fd788 skips status 0 in mode1; 2fd0c8 additionally skips 322/323.
    Fields 400..599 are printed inside m306; 2fd624 records status != 1 in
    m307. These steps happen before checksum and per-field transformation.
    """
    verify_prepared_m320(pairs, **context)
    if len(pairs) < 4 or [key for key, _ in pairs[-3:]] != ['m306', 'm307', 'm320']:
        raise ValueError('device-info aggregation suffix differs')
    status = json.loads(pairs[-2][1])
    if not isinstance(status, dict) or any(type(v) is not int for v in status.values()):
        raise ValueError('invalid device-info status map')
    nested = prepared_pairs(pairs[-3][1], allow_empty=True)
    raw = pairs[:-3]
    if len({key for key, _ in raw}) != len(raw) or len({key for key, _ in nested}) != len(nested):
        raise ValueError('duplicate ordinary device-info cache keys')
    # The actual mode1 view omits these two cache entries (status 0). If a
    # future build activates them, it needs a pair-preserving wire interface.
    if any(status.get(key, 1) != 0 for key, _ in raw if key in ('m307', 'm320')):
        raise ValueError('unsupported active reserved device-info cache field')
    def active(key):
        return status.get(key, 1) != 0 and key not in ('m322', 'm323')
    result = {key: value for key, value in raw if active(key)}
    packed = {key: value for key, value in nested if active(key)}
    result['m306'] = json.dumps(packed, ensure_ascii=False, separators=(',', ':'))
    result['m307'] = json.dumps({key: value for key, value in status.items()
                                if value not in (0, 1) and key not in ('m322', 'm323')},
                               ensure_ascii=False, separators=(',', ':'))
    result['m320'] = compute_m320(result, **context)
    return result
