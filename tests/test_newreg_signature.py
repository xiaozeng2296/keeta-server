"""Real newreg vectors extracted from both registration captures."""

import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from mtgsig.newreg import newreg_signature, parse_newreg_response


class NewregSignatureTests(unittest.TestCase):
    def test_matches_both_captured_signatures(self):
        vectors = (
            ("1790130775", "7397bba0b97f7ad0788c3f7d39554b5b49a2630e"),
            ("1790496483", "ae87cbec81387ad1f76c13f7e76c47591a7a8e9b"),
        )
        for random_value, signature in vectors:
            with self.subTest(random=random_value):
                self.assertEqual(newreg_signature(random_value), signature)

    def test_integer_random_uses_decimal_text(self):
        self.assertEqual(
            newreg_signature(1790496483),
            "ae87cbec81387ad1f76c13f7e76c47591a7a8e9b",
        )

    def test_ascii_sort_is_lexical_and_independent_of_argument_order(self):
        # Independently checked with OpenSSL SHA-1 over the ASCII text 10-9-Z.
        expected = "2d6a2ddfb570083395fe4def90618f3f93fdcd68"
        self.assertEqual(newreg_signature("10", app_name="Z", password="9"),
                         expected)
        self.assertEqual(newreg_signature("9", app_name="10", password="Z"),
                         expected)

    def test_random_text_is_not_normalized(self):
        self.assertNotEqual(newreg_signature("01790496483"),
                            newreg_signature("1790496483"))
        self.assertNotEqual(newreg_signature("1790496483 "),
                            newreg_signature("1790496483"))

    def test_explicit_profile_parameters_change_signature(self):
        baseline = newreg_signature("1790496483")
        self.assertNotEqual(newreg_signature("1790496483", app_name="fixture.app"),
                            baseline)
        self.assertNotEqual(newreg_signature("1790496483", password="fixture"),
                            baseline)

    def test_missing_and_invalid_random_types_fail_instead_of_coercing(self):
        with self.assertRaises(ValueError):
            newreg_signature(None)
        for value in (True, False, 1790496483.0, b"1790496483", [], {}):
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaises(TypeError):
                    newreg_signature(value)

    def test_unverified_unicode_domain_is_rejected(self):
        for kwargs in ({"random_value": "时间"},
                       {"random_value": "1", "app_name": "应用"},
                       {"random_value": "1", "password": "口令"}):
            with self.subTest(fields=tuple(kwargs)):
                with self.assertRaises(ValueError):
                    newreg_signature(**kwargs)

    def test_profile_fields_require_text(self):
        for kwargs in ({"app_name": None}, {"password": None},
                       {"app_name": 517}, {"password": 123}):
            with self.subTest(fields=tuple(kwargs)):
                with self.assertRaises(TypeError):
                    newreg_signature("1790496483", **kwargs)


class NewregResponseTests(unittest.TestCase):
    def setUp(self):
        guard = patch('socket.socket', side_effect=AssertionError('network forbidden'))
        guard.start()
        self.addCleanup(guard.stop)

    def test_success_without_code_requires_actual_top_level_push_token(self):
        response = {'pushtoken': 'SYNTHETIC-PUSH', 'heartbeat': 60, 'timeout': 30,
                    'reconnect': 1, 'servertime': 1700000000}
        before = copy.deepcopy(response)
        self.assertEqual(parse_newreg_response(response, http_status=200),
                         {'push_token': 'SYNTHETIC-PUSH'})
        self.assertEqual(response, before)
        self.assertEqual(parse_newreg_response(dict(response, code=0), http_status=201),
                         {'push_token': 'SYNTHETIC-PUSH'})
        self.assertEqual(parse_newreg_response({'code': 0}, http_status=200), {})

    def test_failures_and_bad_token_shapes_do_not_advance(self):
        valid = {'pushtoken': 'SYNTHETIC-PUSH'}
        for status in (None, True, '200', 199, 300, 403, 500):
            self.assertEqual(parse_newreg_response(valid, http_status=status), {})
        for response in (None, [], 'SYNTHETIC-PUSH', {}, {'code': 0},
                         {'data': valid}, {'push_token': 'SYNTHETIC-PUSH'},
                         dict(valid, error={'code': 1}), dict(valid, errormsg='denied'),
                         dict(valid, errorMessage='denied'), dict(valid, success=False)):
            self.assertEqual(parse_newreg_response(response, http_status=200), {})
        for field in ('code', 'errcode', 'errorCode'):
            for value in (False, True, '0', 0.0, 1, 101135):
                self.assertEqual(parse_newreg_response(dict(valid, **{field:value}), http_status=200), {})
        for token in (None, 123, True, [], {}, '', ' ', 'PUSH TOKEN', 'PUSH\n', 'PUSH\x00'):
            self.assertEqual(parse_newreg_response({'pushtoken': token}, http_status=200), {})

    def test_both_real_success_captures_without_printing_identity(self):
        root = Path(__file__).resolve().parents[1]
        for name, index in (('evidence/captures/新机之后尝试登录.chlsj', 21), ('evidence/captures/从app初次打开到登录被拦截.chlsj', 221)):
            path = root / name
            if not path.exists():
                self.skipTest('optional original Charles capture is absent')
            event = json.loads(path.read_text())[index]
            self.assertEqual(event['path'], '/sdkapi/newreg')
            response = json.loads(event['response']['body']['text'])
            self.assertFalse('code' in response, 'captured newreg response shape changed')
            result = parse_newreg_response(response, http_status=event['response']['status'])
            self.assertEqual(set(result), {'push_token'})
            self.assertTrue(result['push_token'] == response['pushtoken'],
                            'captured push token does not match; value suppressed')


if __name__ == "__main__":
    unittest.main()
