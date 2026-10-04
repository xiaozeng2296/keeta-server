"""Real local HTTP: auth, JSON validation, stateless signing and codec responses."""
import copy
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, ProxyHandler, build_opener

from rpc.server import make_server
from scripts.smoke_rpc import check
from tests.protocol.test_collection_refresh import identity


class CryptoHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = make_server(port=0, token='synthetic-token')
        cls.thread = threading.Thread(target=cls.server.serve_forever)
        cls.thread.start()
        cls.url = 'http://127.0.0.1:' + str(cls.server.server_port)
        cls.client = build_opener(ProxyHandler({}))

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.thread.join(5); cls.server.server_close()

    def request(self, path, value=None, token='synthetic-token'):
        headers = {'Content-Type': 'application/json', 'X-Token': token}
        data = json.dumps(value).encode() if value is not None else None
        try:
            response = self.client.open(Request(self.url + path, data, headers), timeout=5)
        except HTTPError as exc:
            response = exc
        with response:
            return response.code, json.load(response)

    def test_codecs_and_full_signature_over_http(self):
        self.assertEqual(check(self.url, 'synthetic-token'), {'rpc_http_requests': 9, 'business_requests': 0})

    def test_auth_and_unknown_endpoint(self):
        self.assertEqual(self.request('/health', token='wrong')[0], 401)
        self.assertEqual(self.request('/missing', {})[0], 404)
        self.assertEqual(self.request('/sign', [1, 2])[0], 400)

    def test_identity_files_are_never_read_or_modified(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'identity.json';path.write_text(json.dumps(identity()))
            before = path.read_bytes()
            code, value = self.request('/sign', {'identity_path': str(path), 'method': 'POST', 'url': '/test'})
            self.assertEqual(code, 400)
            self.assertIn('identity_path', value['error'])
            self.assertEqual(path.read_bytes(), before)

    def test_each_call_owns_state_and_returns_continuation(self):
        state = identity();before = copy.deepcopy(state)
        payload = {'identity': state, 'method': 'POST', 'url': 'https://example.test/shop', 'body': '{}'}
        with patch('mtgsig.signer.time.time', return_value=1790732180):
            code, first = self.request('/sign', payload)
            _, repeat = self.request('/sign', payload)
            _, continued = self.request('/sign', dict(payload, identity=first['identity']))
        self.assertEqual(code, 200)
        self.assertEqual(first, repeat)
        self.assertEqual(first['identity']['sign_sequence'], before['sign_sequence'] + 1)
        self.assertEqual(continued['identity']['sign_sequence'], before['sign_sequence'] + 2)
        self.assertEqual(state, before)

    def test_declared_oversize_body_is_rejected_before_reading(self):
        import http.client
        client = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=3)
        try:
            client.request('POST', '/sign', headers={'X-Token': 'synthetic-token', 'Content-Length': str(9 << 20)})
            self.assertEqual(client.getresponse().status, 413)
        finally:
            client.close()
