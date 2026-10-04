"""Offline a9 decode/re-encode check for explicitly supplied signatures/Charles JSON.

Checks padding, CRC, zlib completion and exact ciphertext bytes. Reports no
identifier, key, ciphertext or plaintext. This does not test server acceptance.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from mtgsig.a9_codec import decode, encode_compressed


def signatures(data):
    """Yield (input index, signature); retain request order and duplicates."""
    if isinstance(data, dict) and ('mtgsig' in data or 'a9' in data):
        sig = data.get('mtgsig', data)
        yield 0, json.loads(sig) if isinstance(sig, str) else sig
        return
    if not isinstance(data, list):
        raise ValueError('expected mtgsig object or Charles flow array')
    for index, flow in enumerate(data):
        request = flow.get('request') or {}
        headers = (request.get('header') or {}).get('headers', [])
        for header in headers:
            if header.get('name', '').lower() == 'mtgsig':
                sig = json.loads(header['value'])
                if 'a9' in sig:
                    yield index, sig


def profile_options(profile):
    if profile == 'default':
        return {}
    if profile == 'legacy':
        cfg = json.loads((ROOT/'mtgsig/a9_legacy_profile.json').read_text())
        return dict(salt=bytes.fromhex(cfg['salt_hex']), a1_shift=cfg['a1_shift'])
    raise ValueError('unknown a9 profile')


def verify(path, profile):
    raw = path.read_bytes()
    options = profile_options(profile)
    rows = []
    for index, sig in signatures(json.loads(raw)):
        row = dict(input_index=index, profile=profile)
        try:
            decoded = decode(sig['a9'], sig['a1'], **options)
            exact = encode_compressed(decoded.compressed, sig['a1'],
                                      mode=decoded.mode, **options) == sig['a9']
            row.update(mode=decoded.mode, compressed_bytes=len(decoded.compressed),
                       plaintext_bytes=len(decoded.plaintext), crc_valid=True,
                       zlib_complete=True, reencode_exact=exact,
                       result='PASS' if exact else 'FAIL')
        except (ValueError, KeyError, TypeError) as exc:
            # Decoder diagnostics may contain input values; emit only the type.
            row.update(result='FAIL', error_type=type(exc).__name__)
        rows.append(row)
    if not rows:
        raise ValueError('no verifiable a9 samples')
    return dict(source_sha256=hashlib.sha256(raw).hexdigest(), cases=rows,
                result='PASS' if all(row['result'] == 'PASS' for row in rows) else 'FAIL')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('sources', type=Path, nargs='+')
    parser.add_argument('--profile', choices=('default', 'legacy'), required=True,
                        help='Explicit a9 profile; independent of the a5 profile')
    parser.add_argument('--out', type=Path, help='New report file; otherwise print JSON')
    args = parser.parse_args()
    if args.out and args.out.exists():
        parser.error('--out must not already exist')
    try:
        sources = [dict(source_index=i, **verify(path, args.profile))
                   for i, path in enumerate(args.sources)]
    except (ValueError, KeyError, TypeError, OSError) as exc:
        print('Input validation failed (' + type(exc).__name__ +
              '); no complete report produced.', file=sys.stderr)
        return 2
    passed = all(row['result'] == 'PASS' for row in sources)
    report = dict(result='PASS' if passed else 'FAIL', sources=sources,
                  scope='Offline a9 replay only; no native/provider or server acceptance assertion')
    text = json.dumps(report, ensure_ascii=False, indent=2) + '\n'
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open('x') as out:
            out.write(text)
        print(report['result'] + ': a9 replay; report written')
    else:
        print(text, end='')
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
