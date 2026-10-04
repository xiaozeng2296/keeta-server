"""Build reporting outer fields from explicit current-session inputs.

These fields sit outside the A-envelope but inside the signed request body.
No captured index, time or regionPath is used as a fallback.
"""
from datetime import datetime, timedelta, timezone
import json
import re


def _decimal(value, name, maximum=(1 << 63) - 1, minimum=0):
    if type(value) is int:
        number = value
    elif isinstance(value, str) and re.fullmatch(r'0|[1-9][0-9]*', value):
        number = int(value)
    else:
        raise ValueError(f'{name} must be a canonical nonnegative decimal integer')
    if not minimum <= number <= maximum:
        raise ValueError(f'{name} is out of range')
    return str(number)


def build_reporting_outer(name, inputs, *, timestamp_ms):
    """Return fields to merge into this route's body before computing a2.

    device_info inputs: timezone_offset_seconds, sdk_version, ext.
    bio_report inputs: index and region_events, e.g. [{"GG": 100}, {"HK": 200}].
    index is the already-incremented uint32 counter; native %d formats its
    signed int32 interpretation on the wire.
    Region values are explicit native-compatible event values. This module
    preserves their order and does not invent their clock/duration semantics.
    """
    if not isinstance(inputs, dict):
        raise ValueError(f'{name} requires explicit reporting_inputs')
    if name == 'device_info':
        if set(inputs) != {'timezone_offset_seconds', 'sdk_version', 'ext'}:
            raise ValueError('device_info requires timezone_offset_seconds, sdk_version and ext')
        if type(timestamp_ms) is not int or timestamp_ms < 0:
            raise ValueError('timestamp_ms must be a nonnegative integer')
        offset = inputs['timezone_offset_seconds']
        if type(offset) is not int or not -14*3600 <= offset <= 14*3600 or offset % 60:
            raise ValueError('timezone_offset_seconds must be explicit integral minutes within 14 hours')
        sdk = inputs['sdk_version']
        if not isinstance(sdk, str) or not re.fullmatch(r'[0-9]+(?:\.[0-9]+){2}', sdk):
            raise ValueError('sdk_version must be an explicit dotted version')
        try:
            moment = datetime.fromtimestamp(timestamp_ms // 1000, timezone(timedelta(seconds=offset)))
        except (OverflowError, OSError, ValueError) as exc:
            raise ValueError('timestamp_ms is outside supported calendar range') from exc
        return {'dfpVersion': sdk, 'os': 'iOS', 'mtgVersion': sdk,
                'time': moment.strftime('%Y-%m-%d %H:%M:%S'),
                'ext': _decimal(inputs['ext'], 'device_info ext', maximum=0xffffffff)}
    if name == 'bio_report':
        if set(inputs) != {'index', 'region_events'}:
            raise ValueError('bio_report requires current-session index and region_events')
        index_bits = int(_decimal(inputs['index'], 'bio index', maximum=0xffffffff, minimum=1))
        # Native 0x31b1b8..0x31b1e0 increments W8, then NSString %d reads
        # its lower 32 bits as signed. Keep input validation in counter space.
        index = str(index_bits if index_bits < 0x80000000 else index_bits - 0x100000000)
        events = inputs['region_events']
        if not isinstance(events, list) or not events or len(events) > 1024:
            raise ValueError('region_events must be a nonempty bounded list')
        history = []
        for event in events:
            if not isinstance(event, dict) or len(event) != 1:
                raise ValueError('each region event must contain exactly one region/value pair')
            region, value = next(iter(event.items()))
            if not isinstance(region, str) or not re.fullmatch(r'[A-Z]{2}', region):
                raise ValueError('region event key must be a two-letter uppercase region')
            history.append({region: _decimal(value, 'region event value')})
        return {'index': index, 'encryptVersion': '1', 'src': '1',
                'regionPath': json.dumps(history, separators=(',', ':'))}
    raise ValueError('unsupported reporting route')
