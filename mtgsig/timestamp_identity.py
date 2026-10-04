"""Reconstruct m239 from explicitly supplied native m251 observations.

The native collector hashes ordered filesystem birth timestamps. This module
does not read files, alter timestamps, create device observations, or derive
them from UUID/local-ID values.
"""

import hashlib
import json
import re


def m239_from_m251(value):
    """Return the native lowercase MD5, or ``unknown`` for an empty list.

    ``value`` is an m251 JSON string or its parsed list, in native order.
    Each successful-stat record contains ``tm = '%ld%09ld' % (sec, nsec)``.
    The digest input instead concatenates ``'%ld%ld' % (sec, nsec)`` for every
    record, without separators or nanosecond padding. Paths/inodes are not
    digest inputs; the ordered timestamps are.
    """
    if isinstance(value, str):
        value = json.loads(value)
    if not isinstance(value, list):
        raise ValueError("m251 must be a JSON array or its JSON text")
    parts = []
    for record in value:
        if not isinstance(record, dict) or record.get("st") != "0":
            raise ValueError("m251 must contain native successful-stat records (st='0')")
        timestamp = record.get("tm")
        if not isinstance(timestamp, str) or not re.fullmatch(r"-?[0-9]{10,}", timestamp):
            raise ValueError("m251 tm must contain seconds followed by nine nanosecond digits")
        seconds, nanoseconds = int(timestamp[:-9]), int(timestamp[-9:])
        if not -(1 << 63) <= seconds < (1 << 63):
            raise ValueError("m251 seconds exceed the native signed 64-bit range")
        if f"{seconds}{nanoseconds:09d}" != timestamp:
            raise ValueError("m251 tm is not the native canonical timestamp format")
        parts.append(f"{seconds}{nanoseconds}")
    if not parts:
        return "unknown"
    return hashlib.md5("".join(parts).encode("ascii")).hexdigest()
