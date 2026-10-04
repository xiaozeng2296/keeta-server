"""Charles JSON request/response readers; no account-specific capture dependency."""
import base64
import gzip
import json
import zlib


def headers(flow):
    return {row['name'].lower(): row['value'] for row in flow.get('request', {}).get('header', {}).get('headers', [])}


def body_bytes(side):
    body = side.get('body') or {}
    if 'text' in body:
        return body['text'].encode(body.get('charset') or 'utf-8'), 'text'
    if body.get('encoding') == 'base64':
        raw = base64.b64decode(body['encoded'], validate=True)
        if raw.startswith(b'\x1f\x8b'):
            return gzip.decompress(raw), 'base64+gzip'
        try:
            json.loads(raw)
            return raw, 'base64'
        except (ValueError, UnicodeError):
            pass
        try:
            return zlib.decompress(raw), 'base64+zlib'
        except zlib.error:
            return raw, 'base64+binary'
    return b'', 'absent'


def body_json(side):
    raw, encoding = body_bytes(side)
    try:
        return json.loads(raw), encoding
    except (ValueError, UnicodeError):
        return None, encoding
