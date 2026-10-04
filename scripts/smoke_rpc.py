"""Check an RPC using synthetic data only; never sends business requests."""
import argparse
import json
import os
from pathlib import Path
import sys
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from mtgsig.signer import compute_a2


def check(url, token=None):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    calls = 0

    def request(path, payload=None):
        nonlocal calls
        headers = {'Content-Type': 'application/json'}
        if token:
            headers['X-Token'] = token
        data = json.dumps(payload).encode() if payload is not None else None
        with opener.open(urllib.request.Request(url.rstrip('/') + path, data, headers), timeout=10) as response:
            calls += 1
            return json.load(response)

    health = request('/health')
    assert health['stateless'] is True
    a1 = '00112233-4455-6677-8899-aabbccddeeff'
    plain = {'0': 12, '1': ['smoke'], '2': ['离线验证'], '3': '{}'}
    for mode in ('aes', 'twofish', 'twofish-mod'):
        a9 = request('/a9/encode', {'a1': a1, 'mode': mode, 'siua_json': plain})['a9']
        decoded = request('/a9/decode', {'a1': a1, 'a9': a9})
        assert decoded['plain_json'] == plain
    identity = dict(a0='2.5', a1=a1, a3=25, a6=0, a7='synthetic-xid', a8='synthetic-dfp',
                    a9=a9, x0=2, counter=1, signature_counter=41,
                    base_collect={'b1': '{}', 'b2': 1, 'b3': 1})
    result = request('/sign', dict(identity=identity, method='POST', url='https://example.test/menu', body='{}'))
    mt = json.loads(result['mtgsig']);signature = mt.pop('a2')
    assert result['identity']['sign_sequence'] == 2 and identity['counter'] == 1
    assert signature == compute_a2('POST', 'https://example.test/menu', '{}',
                                   json.dumps(mt, separators=(',', ':'), ensure_ascii=False),
                                   a1, 41, sign_sequence=2)
    decoded = request('/decrypt', mt)
    assert decoded['fields']['a5']['plain_json']['b2'] == 2
    assert decoded['fields']['a9']['plain_json'] == plain
    return {'rpc_http_requests': calls, 'business_requests': 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', default='http://127.0.0.1:8799')
    args = parser.parse_args()
    print(json.dumps(check(args.url, os.environ.get('KEETA_RPC_TOKEN'))))


if __name__ == '__main__':
    main()
