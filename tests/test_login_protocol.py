"""Static model-derived email fields and conservative state-transition checks."""
import base64
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from urllib.parse import parse_qsl

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

from mtgsig import login_protocol as p

ROOT = Path(__file__).resolve().parents[1]


class LoginProtocolTests(unittest.TestCase):
    def setUp(self):
        guard = patch('socket.socket', side_effect=AssertionError('network forbidden'))
        guard.start()
        self.addCleanup(guard.stop)

    def test_risk_uses_wire_names_and_omits_absent_challenge_fields(self):
        plain = dict(parse_qsl(p.build_risk_body('a+b@example.test', token_id=None), keep_blank_values=True))
        self.assertEqual(plain, {'email': 'a+b@example.test', 'token_id': ''})
        challenged = p.risk_fields('a@example.test', request_code='REQ', response_code='RESP')
        self.assertEqual(challenged['request_code'], 'REQ')
        self.assertEqual(challenged['response_code'], 'RESP')
        self.assertNotIn('requestCode', challenged)

    def test_apply_variants_have_the_actual_model_fields(self):
        self.assertEqual(p.apply_fields('TICKET'), {'user_ticket': 'TICKET'})
        self.assertEqual(p.apply_fields('TICKET', signup=True, username='User Name', encrypted_password='RSA+/='),
                         {'user_ticket': 'TICKET', 'username': 'User Name', 'password': 'RSA+/='})
        encoded = p.build_apply_body('TICKET', signup=True, username='User Name', encrypted_password='RSA+/=')
        self.assertEqual(dict(parse_qsl(encoded)),
                         {'user_ticket': 'TICKET', 'username': 'User Name', 'password': 'RSA+/='})
        self.assertNotIn('email', p.apply_fields('TICKET', signup=True))
        self.assertNotIn('userTicket', p.apply_fields('TICKET'))
        with self.assertRaises(ValueError):
            p.apply_fields('TICKET', username='unrelated')
        with self.assertRaises(ValueError):
            p.apply_fields('TICKET', signup=True, password='plain', encrypted_password='other')

    def test_submit_wire_names_distinguish_login_challenge_from_signup(self):
        login = p.submit_fields('T', '1234', 'S', request_code='REQ', response_code='RESP')
        self.assertEqual(login, {'user_ticket': 'T', 'email_code': '1234', 'serial_number': 'S',
                                 'request_code': 'REQ', 'response_code': 'RESP'})
        signup = p.submit_fields('T', '1234', 'S', signup=True, username='User',
                                 encrypted_password='RSA', request_code='REQ')
        self.assertEqual(signup, {'user_ticket': 'T', 'email_code': '1234', 'serial_number': 'S',
                                  'username': 'User', 'password': 'RSA'})
        for values in (('T', '', 'S'), ('T', '1234', None), ('', '1234', 'S')):
            with self.assertRaises(ValueError):
                p.submit_fields(*values)

    def test_common_fields_keep_advertising_id_distinct_from_idfv(self):
        common = {'device_id': 'AD-ID', 'idfv': 'UNRELATED-IDFV', 'fingerprint': 'CURRENT-FP',
                  'tk_context_plain': 'REGION-CONTEXT', 'user_ticket': 'WRONG'}
        fields = p.apply_fields('TICKET', common=common)
        self.assertEqual(fields, {'user_ticket': 'TICKET', 'device_id': 'AD-ID', 'device_type': '3',
                                 'fingerprint': 'CURRENT-FP', 'tk_context_plain': 'REGION-CONTEXT'})
        self.assertNotIn('device_type', p.apply_fields('TICKET', common={'idfv': 'IDFV'}))
        self.assertEqual(common['user_ticket'], 'WRONG')

    def test_password_uses_pkcs1_v15_utf8_chunks_and_empty_string_behavior(self):
        private = RSA.generate(1024)
        plain = ('密码-å' * 50).encode('utf-8')
        wire = p.encrypt_password(plain.decode('utf-8'), public_key=private.public_key().export_key(),
                                  randfunc=lambda n: b'\x5a' * n)
        raw = base64.b64decode(wire)
        chunk = private.size_in_bytes() - 11
        self.assertEqual(len(raw), ((len(plain)+chunk-1)//chunk)*private.size_in_bytes())
        recovered = b''.join(PKCS1_v1_5.new(private).decrypt(raw[i:i+128], b'INVALID')
                             for i in range(0, len(raw), 128))
        self.assertEqual(recovered, plain)
        # Independently inspect RSA encoding: block type 2, nonzero padding,
        # separator, then the first raw UTF-8 byte chunk.
        block = pow(int.from_bytes(raw[:128], 'big'), private.d, private.n).to_bytes(128, 'big')
        self.assertEqual(block, b'\0\2' + b'Z' * 8 + b'\0' + plain[:chunk])
        self.assertEqual(p.encrypt_password(''), '')
        self.assertIsNone(p.encrypt_password(None))
        self.assertEqual(p.apply_fields('T', signup=True, password='')['password'], '')
        self.assertNotIn('password', p.apply_fields('T', signup=True))
        default = RSA.import_key(base64.b64decode(p.LOGIN_PUBLIC_KEY_B64))
        self.assertEqual((default.size_in_bits(), default.e), (2048, 65537))

    def test_risk_exact_path_and_signup_decision_ignore_isnormal_as_gate(self):
        response = {'data': {'userTicket': 'T', 'isSignup': True, 'isNormal': False, 'hasPassword': False}}
        self.assertEqual(p.parse_risk_response(response, http_status=200),
                         {'user_ticket': 'T', 'is_signup': True, 'is_normal': False, 'has_password': False})
        self.assertEqual(p.parse_risk_response({'data': {'userTicket': 'T'}}, http_status=200),
                         {'user_ticket': 'T', 'is_signup': False, 'is_normal': False, 'has_password': False})
        self.assertEqual(p.parse_risk_response({'ticket': 'T', 'data': {}}, http_status=200), {})
        self.assertEqual(p.parse_risk_response({'data': {'user_ticket': 'T'}}, http_status=200), {})

    def test_apply_requires_both_exact_response_values_without_recursive_search(self):
        valid = {'data': {'email': 'a@example.test', 'serialNumber': 'SERIAL'}}
        self.assertEqual(p.parse_apply_response(valid, http_status=200),
                         {'email': 'a@example.test', 'serial_number': 'SERIAL'})
        for data in ({'serialNumber': 'S'}, {'email': 'a', 'serial_number': 'S'},
                     {'email': 'a', 'serialNumber': ''}, {'email': 'a', 'serialNumber': 123},
                     {'elsewhere': valid['data']}):
            self.assertEqual(p.parse_apply_response({'data': data}, http_status=200), {})

    def test_failures_and_wrong_types_cannot_advance(self):
        good = {'data': {'userTicket': 'T', 'email': 'a@example.test', 'serialNumber': 'S'}}
        for parse in (p.parse_risk_response, p.parse_apply_response):
            for status in (True, '200', 403, 500):
                self.assertEqual(parse(good, http_status=status), {})
            for response in (dict(good, error={'code':101135}), dict(good, success=False),
                             dict(good, code=101135), dict(good, code=False), dict(good, code='0')):
                self.assertEqual(parse(response, http_status=200), {})
        self.assertEqual(p.parse_risk_response({'data': {'userTicket': 'T', 'isSignup': 'true'}},
                                               http_status=200), {})

    def test_submit_accepts_observed_top_level_user_and_normalizes_account_state(self):
        user = {'token': 'SYNTHETIC-TOKEN', 'id': 123, 'idStr': '123',
                'email': ' User@Example.test ', 'registerRegion': 'BR',
                'tkContext': 'SYNTHETIC-CONTEXT'}
        response = {'user': user}
        self.assertEqual(p.parse_submit_response(response, http_status=200,
                                                 expected_email=' user@example.TEST '),
                         {'token': 'SYNTHETIC-TOKEN', 'user_id': '123',
                          'email': 'user@example.TEST', 'register_region': 'BR',
                          'tk_context': 'SYNTHETIC-CONTEXT'})
        self.assertEqual(response['user']['email'], ' User@Example.test ')
        self.assertIsNone(p._success_data(response, 200))
        # Either native identifier representation is sufficient. Decimal
        # normalization does not convert long string identifiers to integers.
        for ids in ({'id': 123}, {'idStr': '123'}, {'id': 123, 'idStr': '00123'}):
            with self.subTest(ids=ids):
                self.assertEqual(p.parse_submit_response(
                    {'user': dict(token='SYNTHETIC-TOKEN', email='a@example.test', **ids)},
                    http_status=200),
                    {'token': 'SYNTHETIC-TOKEN', 'user_id': '123', 'email': 'a@example.test'})

    def test_response_email_display_mask_retains_original_mail_recipient(self):
        expected = ' Current.Person@Example.test '
        display = 'CUR***@EXAMPLE.TEST'
        apply = {'data': {'email': display, 'serialNumber': 'SYNTHETIC-SERIAL'}}
        submit = {'user': {'email': display, 'id': 123, 'idStr': '123',
                           'token': 'SYNTHETIC-TOKEN'}}
        common = {'email': expected.strip(), 'display_email': display, 'email_match': 'masked'}
        self.assertEqual(p.parse_apply_response(apply, http_status=200, expected_email=expected),
                         dict(common, serial_number='SYNTHETIC-SERIAL'))
        self.assertEqual(p.parse_submit_response(submit, http_status=200, expected_email=expected),
                         dict(common, token='SYNTHETIC-TOKEN', user_id='123'))
        self.assertEqual(apply['data']['email'], display)
        self.assertEqual(submit['user']['email'], display)
        for parse, response in ((p.parse_apply_response, apply), (p.parse_submit_response, submit)):
            with self.subTest(parser=parse.__name__):
                unbound = parse(response, http_status=200)
                self.assertEqual(unbound['email'], display)
                self.assertNotIn('email_match', unbound)

    def test_response_email_mask_is_exact_observed_format_not_wildcard_matching(self):
        expected = 'current.person@example.test'
        invalid = ('oth***@example.test', 'cur***@other.test', '***@example.test',
                   'c***@example.test', 'cu***@example.test', 'curr***@example.test',
                   'cur*@example.test', 'cur**@example.test', 'cur****@example.test',
                   'cur***n@example.test', 'cur***@*.test', 'cur***@example.*',
                   'cur***@@example.test', 'cur ***@example.test', 'cur***@',
                   'cur***', '@example.test')
        for display in invalid:
            for parse, response in (
                    (p.parse_apply_response, {'data': {'email': display, 'serialNumber': 'S'}}),
                    (p.parse_submit_response, {'user': {'email': display, 'id': 123, 'token': 'T'}})):
                with self.subTest(display=display, parser=parse.__name__):
                    self.assertEqual(parse(response, http_status=200, expected_email=expected), {})
        for expected in ('cur***@example.test', 'current@*.test', '*@example.test',
                         '@example.test', 'current@', 'current@@example.test',
                         'current person@example.test', 'cur@example.test'):
            for parse, response in (
                    (p.parse_apply_response, {'data': {'email': 'cur***@example.test', 'serialNumber': 'S'}}),
                    (p.parse_submit_response, {'user': {'email': 'cur***@example.test', 'id': 123, 'token': 'T'}})):
                with self.subTest(expected=expected, parser=parse.__name__):
                    self.assertEqual(parse(response, http_status=200, expected_email=expected), {})

    def test_expected_email_exact_match_preserves_input_and_account_validation(self):
        expected = ' Current.Person@example.test '
        self.assertEqual(p.parse_apply_response(
            {'data': {'email': 'current.person@EXAMPLE.TEST', 'serialNumber': 'S'}},
            http_status=200, expected_email=expected),
            {'email': expected.strip(), 'serial_number': 'S'})
        for patch in ({'id': 123, 'idStr': '999'}, {'id': False}, {'token': ''}):
            user = dict({'email': 'cur***@example.test', 'token': 'T', 'id': 123}, **patch)
            self.assertEqual(p.parse_submit_response({'user': user}, http_status=200,
                                                     expected_email=expected), {})

    def test_submit_requires_current_mailbox_account_and_exact_response_path(self):
        user = {'token': 'SYNTHETIC-TOKEN', 'id': 123, 'email': 'a@example.test'}
        for response in ({'data': {'user': user}}, {'data': user}, {'token': user['token']},
                         {'data': {'loginAccepted': True}}, {'loginAccepted': True},
                         {'user': None}, {'user': []}):
            with self.subTest(response=response):
                self.assertEqual(p.parse_submit_response(response, http_status=200), {})
        for expected_email in ('another@example.test', '', ' ', 123, False):
            with self.subTest(expected_email=expected_email):
                self.assertEqual(p.parse_submit_response({'user': user}, http_status=200,
                                                         expected_email=expected_email), {})
        for key, values in (('token', (None, '', ' ', 123, False)),
                            ('email', (None, '', ' ', 123, False))):
            for value in values:
                with self.subTest(key=key, value=value):
                    self.assertEqual(p.parse_submit_response(
                        {'user': dict(user, **{key: value})}, http_status=200), {})

    def test_submit_rejects_invalid_or_inconsistent_account_ids(self):
        base = {'token': 'SYNTHETIC-TOKEN', 'email': 'a@example.test'}
        invalid_ids = [dict(), {'id': True}, {'id': False}, {'id': None}, {'id': 0},
                       {'id': -1}, {'id': 1.0}, {'id': '123'}, {'idStr': ''},
                       {'idStr': None}, {'idStr': 123}, {'idStr': '0'}, {'idStr': '000'},
                       {'idStr': '-1'}, {'idStr': '+123'}, {'idStr': '1.0'},
                       {'idStr': ' 123 '}, {'idStr': '\u0661\u0662\u0663'},
                       {'id': 123, 'idStr': '124'}, {'id': None, 'idStr': '123'},
                       {'id': 123, 'idStr': None}]
        for ids in invalid_ids:
            with self.subTest(ids=ids):
                self.assertEqual(p.parse_submit_response({'user': dict(base, **ids)},
                                                         http_status=200), {})

    def test_submit_shares_failure_gates_and_keeps_optional_state_typed(self):
        user = {'token': 'SYNTHETIC-TOKEN', 'id': 123, 'email': 'a@example.test'}
        good = {'user': user}
        for status in (True, '200', 199, 300, 403, 500):
            with self.subTest(status=status):
                self.assertEqual(p.parse_submit_response(good, http_status=status), {})
        for response in (None, [], dict(good, error={'code': 101135}),
                         dict(good, success=False), dict(good, success=1),
                         dict(good, code=101135), dict(good, code=False), dict(good, code='0')):
            with self.subTest(response=response):
                self.assertEqual(p.parse_submit_response(response, http_status=200), {})
        self.assertTrue(p.parse_submit_response(dict(good, code=0, success=True), http_status=200))
        for field in ('registerRegion', 'tkContext'):
            self.assertEqual(p.parse_submit_response({'user': dict(user, **{field: 123})},
                                                     http_status=200), {})
            self.assertEqual(p.parse_submit_response({'user': dict(user, **{field: ''})},
                                                     http_status=200),
                             {'token': 'SYNTHETIC-TOKEN', 'user_id': '123', 'email': 'a@example.test'})

    def test_headers_remove_stale_signature_before_final_body_is_signed(self):
        original = {'MTGSIG': 'OLD', 'Content-Length': '99', 'content-type': 'application/json', 'uuid': 'CURRENT'}
        headers = p.passport_headers(original, incog_token='INC', incog_account_id='ACCOUNT')
        self.assertEqual(headers, {'uuid': 'CURRENT', 'Content-Type': p.FORM_CONTENT_TYPE,
                                  'sailor-net-flag': 'MTPT.Passport', 'incog-token': 'INC',
                                  'incog-accountid': 'ACCOUNT'})
        self.assertEqual(original['MTGSIG'], 'OLD')
        disabled = p.passport_headers({'Sailor-Net-Flag': 'MTPT.Passport', 'uuid': 'CURRENT'},
                                      include_net_flag=False)
        self.assertEqual(disabled, {'uuid': 'CURRENT', 'Content-Type': p.FORM_CONTENT_TYPE})

    def test_observed_risk_capture_field_sets_rebuild_without_network(self):
        for name, index in [('evidence/captures/从app初次打开到登录被拦截.chlsj', 801), ('evidence/captures/新机之后尝试登录.chlsj', 628)]:
            path = ROOT / name
            if not path.exists():
                self.skipTest('optional original Charles capture is absent')
            event = json.loads(path.read_text())[index]
            original = dict(parse_qsl(event['request']['body']['text'], keep_blank_values=True))
            rebuilt = p.risk_fields(original['email'], token_id=original.get('token_id'), common=original)
            self.assertEqual(rebuilt, original)
            response = json.loads(event['response']['body']['text'])
            self.assertEqual(p.parse_risk_response(response, http_status=event['response']['status']), {})


if __name__ == '__main__':
    unittest.main()
