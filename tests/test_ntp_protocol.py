"""Synthetic validation and read-only capture parity; network is forbidden."""
import base64
from copy import deepcopy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from mtgsig.ntp_protocol import decode_ntp_info, decode_ntp_response


class NtpProtocolTests(unittest.TestCase):
    def setUp(self):
        guard = patch('socket.socket', side_effect=AssertionError('network forbidden'))
        guard.start()
        self.addCleanup(guard.stop)
        self.plain = bytes(range(28))
        self.ts = 0x0102030405060708
        # Deliberately construct the fixture from the stated last-four-byte
        # mask, independently of the decoder's integer conversion.
        mask = b'\x05\x06\x07\x08'
        wire = bytes(value ^ mask[index % 4] for index, value in enumerate(self.plain))
        self.response = {'status': 0, 'message': 'ok', 'version': '1.0',
                         'ts': self.ts, 'ntp_info': base64.b64encode(wire).decode(),
                         'ab_test_flag': 'A', 'interval': 24}

    def test_known_transform_and_native_five_field_cache_shape(self):
        decoded = decode_ntp_response(self.response, http_status=200)
        self.assertEqual(decoded.dfp, self.plain.hex())
        self.assertEqual(decoded.source_endpoint, '/ntp')
        self.assertEqual(decoded.fingerprint_data(), {
            'serverTimestamp': str(self.ts), 'interval': '24', 'dfp': self.plain.hex(),
            'ab_test_flag': 'A', 'version': '1.0'})
        self.assertEqual(set(decoded.identity_patch()),
                         {'a8', 'a8_server_dfp', 'dfp', 'outid_history_dfp'})
        self.assertTrue(all(value == decoded.dfp for value in decoded.identity_patch().values()))

    def test_only_low_32_timestamp_bits_affect_transform(self):
        a = decode_ntp_info(self.response['ntp_info'], self.ts)
        b = decode_ntp_info(self.response['ntp_info'], self.ts + (1 << 32))
        self.assertEqual(a, b)

    def test_rejects_http_error_boolean_and_business_error_status(self):
        for status in (True, '200', 199, 300, 500):
            with self.subTest(http_status=status), self.assertRaises(ValueError):
                decode_ntp_response(self.response, http_status=status)
        for value in (None, True, '0', 1):
            with self.subTest(status=value), self.assertRaises(ValueError):
                decode_ntp_response(dict(self.response, status=value), http_status=200)
        for extra in ({'error': {'code': 1}}, {'success': False}):
            with self.assertRaises(ValueError):
                decode_ntp_response(dict(self.response, **extra), http_status=200)

    def test_rejects_b_unknown_variant_and_wrong_response_shape(self):
        for extra in ({'ab_test_flag': 'B'}, {'ab_test_flag': ''}, {'version': '2.0'}):
            with self.assertRaises(ValueError):
                decode_ntp_response(dict(self.response, **extra), http_status=200)
        with self.assertRaises(ValueError):
            decode_ntp_response({'code': 0, 'data': {'ab_test_flag': 'A',
                'serverTimestamp': self.ts, 'dfp': self.plain.hex(), 'interval': 24}}, http_status=200)

    def test_requires_numeric_timestamp_and_interval_without_coercion(self):
        for value in (None, True, '123', 0, -1, 1 << 63):
            with self.subTest(ts=value), self.assertRaises(ValueError):
                decode_ntp_response(dict(self.response, ts=value), http_status=200)
        for value in (None, True, '24', -1, 1 << 31):
            with self.subTest(interval=value), self.assertRaises(ValueError):
                decode_ntp_response(dict(self.response, interval=value), http_status=200)

    def test_rejects_empty_truncated_noncanonical_and_oversized_payloads(self):
        valid = self.response['ntp_info']
        for value in (None, '', valid[:-1], valid+'\n', '!'+valid,
                      base64.b64encode(bytes(27)).decode(),
                      base64.b64encode(bytes(29)).decode()):
            with self.assertRaises(ValueError):
                decode_ntp_response(dict(self.response, ntp_info=value), http_status=200)
        # Last symbol's unused pad bits must be zero, even when b64decode
        # accepts another spelling of the same 28-byte payload.
        alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
        bad = valid[:-3] + alphabet[alphabet.index(valid[-3])+1] + '=='
        with self.assertRaises(ValueError):
            decode_ntp_response(dict(self.response, ntp_info=bad), http_status=200)

    def test_response_is_not_mutated_and_untrusted_plain_dfp_is_not_consumed(self):
        response = dict(self.response, dfp='wrong-plain-field')
        before = deepcopy(response)
        result = decode_ntp_response(response, http_status=200)
        self.assertEqual(response, before)
        self.assertEqual(result.dfp, self.plain.hex())

    def test_all_four_captured_ntp_responses_match_v5_sign_and_later_a8(self):
        root = Path(__file__).resolve().parents[1]
        observed = 0
        for filename, indices in [('evidence/captures/完整版新设备注册登录.chlsj', (15, 131)),
                                  ('evidence/captures/新机之后尝试登录.chlsj', (20,)),
                                  ('evidence/captures/从app初次打开到登录被拦截.chlsj', (95,))]:
            path = root / filename
            if not path.exists():
                self.skipTest('optional private capture is absent')
            flows = json.loads(path.read_text())
            sign_dfps = []
            for flow in flows:
                if flow.get('path') == '/v5/sign':
                    response = json.loads(flow['response']['body']['text'])
                    sign_dfps.append(response['data']['dfp'])
            for index in indices:
                with self.subTest(source=filename, index=index):
                    flow = flows[index]
                    self.assertEqual(flow['path'], '/ntp')
                    raw = json.loads(flow['response']['body']['text'])
                    decoded = decode_ntp_response(raw, http_status=flow['response']['status'])
                    # Booleans prevent the private identity from entering a
                    # test failure's expected/actual string representation.
                    self.assertTrue(decoded.dfp in sign_dfps)
                    matching = 0
                    for later in flows[index+1:]:
                        headers = ((later.get('request') or {}).get('header') or {}).get('headers') or []
                        wire = next((h['value'] for h in headers if h['name'].lower() == 'mtgsig'), None)
                        if wire is not None:
                            matching += json.loads(wire).get('a8') == decoded.dfp
                    self.assertGreater(matching, 0)
                    self.assertEqual(len(decoded.dfp), 56)
                    observed += 1
        self.assertEqual(observed, 4)


if __name__ == '__main__':
    unittest.main()
