"""Model-based migration and response-driven execution; no real network or mail."""
import contextlib
import io
import json
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qsl

import keeta_login as login
from mtgsig import login_protocol as p


class Signer:
    def __init__(self):
        self.calls = []

    def sign(self, url, body):
        self.calls.append((url, body))
        return "SIGNED", "unused"


class LoginExecutionTests(unittest.TestCase):
    def setUp(self):
        guard = patch('socket.socket', side_effect=AssertionError('network forbidden'))
        guard.start()
        self.addCleanup(guard.stop)
        self.risk = {"host": "passport.example.test", "path": p.RISK_PATH,
                     "query": "region=TEST&uuid=CURRENT", "headers": {"MTGSIG": "OLD"},
                     "body": "email=old%40example.test&device_id=AD-ID&device_type=3&fingerprint=FP&"
                             "userTicket=STALE&requestCode=STALE&responseCode=STALE"}
        self.tpl = {"risk": self.risk}

    def test_exact_template_paths_do_not_mistake_apply_for_submit(self):
        flow = {"host": "passport.example.test", "path": p.SIGNUP_APPLY_PATH,
                "query": "region=TEST", "request": {"header": {"headers": []},
                "body": {"text": "user_ticket=OLD"}}}
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp) / 'capture.json'
            file.write_text(json.dumps([flow]))
            templates = login.load_templates(file)
        self.assertEqual(set(templates), {"signup_apply"})
        self.assertEqual(templates['signup_apply']['query'], 'region=TEST')

    def test_http2_coalesced_capture_uses_authority_and_drops_captured_credentials(self):
        flow = {'host': 'pooled.example.test', 'path': p.RISK_PATH,
                'query': 'region=TEST', 'request': {'header': {'headers': [
                    {'name': ':authority', 'value': 'passport.example.test'},
                    {'name': ':path', 'value': p.RISK_PATH + '?region=TEST'},
                    {'name': 'Host', 'value': 'fallback.example.test'},
                    {'name': 'Cookie', 'value': 'STALE-COOKIE'},
                    {'name': 'Authorization', 'value': 'STALE-AUTH'},
                    {'name': 'token', 'value': 'STALE-TOKEN'},
                    {'name': 'incog-token', 'value': 'STALE-INCOG'},
                    {'name': 'incog-accountid', 'value': 'STALE-ACCOUNT'},
                    {'name': 'csecuserid', 'value': 'STALE-USER'},
                    {'name': 'User-Agent', 'value': 'SYNTHETIC-UA'},
                ]}, 'body': {'text': ''}}}
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp) / 'capture.json'
            file.write_text(json.dumps([flow]))
            templates = login.load_templates(file)
        self.assertEqual(templates['risk']['host'], 'passport.example.test')
        self.assertEqual(templates['risk']['headers'], {'User-Agent': 'SYNTHETIC-UA'})
        signer = Signer()
        request = login.plan_segment(templates['risk'], email='current@example.test', signer=signer)
        self.assertEqual(request['url'], 'https://passport.example.test' + p.RISK_PATH + '?region=TEST')
        self.assertEqual(signer.calls[0][0], request['url'])

    def test_risk_context_can_build_uncaptured_paths_with_final_body_signatures(self):
        signer = Signer()
        plan = login.plan_signup_flow(self.tpl, "new@example.test", user_ticket="T", serial_number="S",
                                     email_code="1234", request_code="REQ", response_code="RESP",
                                     username="User", encrypted_password="RSA+/=", signer=signer)
        self.assertEqual([x['segment'] for x in plan], ['risk', 'signup_apply', 'signup'])
        bodies = [dict(parse_qsl(item['body'], keep_blank_values=True)) for item in plan]
        self.assertEqual(bodies[0]['request_code'], 'REQ')
        self.assertEqual(bodies[1], {'device_id': 'AD-ID', 'device_type': '3', 'fingerprint': 'FP',
                                    'user_ticket': 'T', 'username': 'User', 'password': 'RSA+/='})
        self.assertEqual(bodies[2]['serial_number'], 'S')
        self.assertEqual(bodies[2]['email_code'], '1234')
        self.assertNotIn('email', bodies[2])
        self.assertNotIn('request_code', bodies[2])
        for item, signed in zip(plan, signer.calls):
            self.assertEqual((item['url'], item['body']), signed)
            self.assertEqual(item['headers']['Content-Type'], p.FORM_CONTENT_TYPE)
            self.assertNotIn('MTGSIG', item['headers'])

    def test_legacy_explicit_aliases_translate_but_captured_state_never_reused(self):
        segment = dict(self.risk, name='login', path=p.LOGIN_PATH)
        planned = login.plan_segment(segment, overrides={'userTicket': 'T', 'serialNumber': 'S',
                                                         'emailCode': '1234', 'requestCode': 'REQ'})
        fields = dict(parse_qsl(planned['body']))
        self.assertEqual(fields['user_ticket'], 'T')
        self.assertEqual(fields['request_code'], 'REQ')
        self.assertFalse(any(key in fields for key in login.ALIASES))
        conflict = login.plan_segment(segment, overrides={'userTicket': 'T', 'user_ticket': 'OTHER'})
        self.assertIn('conflicting aliases', conflict['error'])
        conflict = login.plan_segment(dict(segment, name='signup'),
                                      overrides={'password': 'plain', 'encrypted_password': 'cipher'})
        self.assertIn('password or encrypted_password', conflict['error'])
        without_state = login.plan_signup_flow(self.tpl, 'new@example.test')
        self.assertEqual(len(without_state), 2)
        self.assertIn('user_ticket', without_state[1]['error'])
        self.assertNotIn('request_code', dict(parse_qsl(without_state[0]['body'])))

    def test_login_branch_uses_current_response_and_ignores_isnormal_gate(self):
        signer = Signer()
        responses = [
            (200, {'data': {'userTicket': 'CURRENT-T', 'isSignup': False, 'isNormal': False}}),
            (200, {'data': {'email': 'new@example.test', 'serialNumber': 'CURRENT-S'}}),
            (200, {'user': {'token': 'SYNTHETIC-TOKEN', 'id': 123,
                            'idStr': '123', 'email': 'new@example.test'}}),
        ]
        requests = []
        def send_stub(signer, segment, **kwargs):
            requests.append(login.plan_segment(segment, email=kwargs.get('email'),
                                               overrides=kwargs.get('overrides'), signer=signer))
            return responses[len(requests)-1]
        with patch.object(login, 'send', side_effect=send_stub), \
             patch.object(login.MB, 'snapshot_mailbox', return_value={'uidvalidity': 1, 'uids': [1]}), \
             patch.object(login.MB, 'get_code', return_value='1234', create=True) as mailbox, \
             contextlib.redirect_stdout(io.StringIO()):
            result = login.run_one(signer, self.tpl, 'new@example.test', 'unused')
        self.assertEqual(result, 'SYNTHETIC-TOKEN')
        self.assertEqual([item['segment'] for item in requests], ['risk', 'login_apply', 'login'])
        self.assertEqual(dict(parse_qsl(requests[1]['body']))['user_ticket'], 'CURRENT-T')
        self.assertEqual(dict(parse_qsl(requests[2]['body']))['serial_number'], 'CURRENT-S')
        mailbox.assert_called_once()

    def test_risk_failure_or_fake_nested_ticket_never_sends_apply(self):
        for status, response in [(403, {'data': {'userTicket': 'T'}}),
                                 (200, {'error': {'userTicket': 'T'}}),
                                 (200, {'data': {'nested': {'userTicket': 'T'}}})]:
            with self.subTest(status=status, response=response), \
                 patch.object(login, 'send', return_value=(status, response)) as send, \
                 patch.object(login.MB, 'get_code', create=True) as mailbox, \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertIsNone(login.run_one(Signer(), self.tpl, 'new@example.test', 'unused'))
                self.assertEqual(send.call_count, 1)
                mailbox.assert_not_called()

    def test_invalid_or_wrong_email_apply_never_reads_mail(self):
        for data in ({'email': 'new@example.test'},
                     {'email': 'other@example.test', 'serialNumber': 'S'},
                     {'email': 'new@example.test', 'serialNumber': ''}):
            responses = [(200, {'data': {'userTicket': 'T', 'isSignup': True}}), (200, {'data': data})]
            with self.subTest(data=data), patch.object(login, 'send', side_effect=responses) as send, \
                 patch.object(login.MB, 'snapshot_mailbox', return_value={'uidvalidity': 1, 'uids': [1]}), \
                 patch.object(login.MB, 'get_code', create=True) as mailbox, \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertIsNone(login.run_one(Signer(), self.tpl, 'new@example.test', 'unused'))
                self.assertEqual(send.call_count, 2)
                mailbox.assert_not_called()

    def test_masked_email_flow_keeps_original_mailbox_and_current_ticket_serial(self):
        original = 'current.person@example.test'
        display = 'cur***@example.test'
        signer = Signer()
        replies = [
            (200, {'data': {'userTicket': 'CURRENT-T', 'isSignup': True}}),
            (200, {'data': {'email': display, 'serialNumber': 'CURRENT-S'}}),
            (200, {'user': {'token': 'SYNTHETIC-TOKEN', 'id': 123, 'idStr': '123', 'email': display}}),
        ]
        planned = []
        baseline = {'uidvalidity': 1, 'uids': [1]}

        def send_stub(current_signer, segment, **kwargs):
            planned.append(login.plan_segment(segment, email=kwargs.get('email'),
                overrides=kwargs.get('overrides'), signer=current_signer))
            return replies[len(planned)-1]

        output = io.StringIO()
        with patch.object(login, 'send', side_effect=send_stub), \
             patch.object(login.MB, 'snapshot_mailbox', return_value=baseline) as snap, \
             patch.object(login.MB, 'get_code', return_value='1234') as receive, \
             contextlib.redirect_stdout(output):
            result = login.run_one(signer, self.tpl, original, 'synthetic-mail.txt')
        self.assertEqual(result, 'SYNTHETIC-TOKEN')
        snap.assert_called_once_with(original, path='synthetic-mail.txt', search='Keeta')
        receive.assert_called_once_with(original, path='synthetic-mail.txt', poll=120, since=baseline)
        fields = [dict(parse_qsl(item['body'], keep_blank_values=True)) for item in planned]
        self.assertEqual(fields[0]['email'], original)
        self.assertEqual(fields[1]['user_ticket'], 'CURRENT-T')
        self.assertEqual(fields[2]['user_ticket'], 'CURRENT-T')
        self.assertEqual(fields[2]['serial_number'], 'CURRENT-S')
        self.assertEqual(fields[2]['email_code'], '1234')
        self.assertNotIn(display, str(planned))
        for secret in (original, display, result, '1234'):
            self.assertNotIn(secret, output.getvalue())

    def test_signup_defaults_match_capture_without_inheriting_account_fields(self):
        self.tpl['signup_apply'] = dict(
            self.risk, name='signup_apply', path=p.SIGNUP_APPLY_PATH,
            body='device_id=AD-ID&fingerprint=FP&username=STALE&password=STALE')
        plan = login.plan_signup_flow(self.tpl, 'new@example.test', user_ticket='T',
                                     serial_number='S', email_code='1234', signup=True)
        for item in plan[1:]:
            fields = dict(parse_qsl(item['body'], keep_blank_values=True))
            self.assertEqual(fields['username'], '')
            self.assertEqual(fields['password'], '')
        explicit_none = login.plan_segment(
            self.tpl['signup_apply'], overrides={'user_ticket': 'T', 'username': None, 'password': None})
        fields = dict(parse_qsl(explicit_none['body'], keep_blank_values=True))
        self.assertNotIn('username', fields)
        self.assertNotIn('password', fields)
        encrypted = login.plan_segment(
            self.tpl['signup_apply'], overrides={'user_ticket': 'T', 'password': None,
                                                'encrypted_password': 'CURRENT-RSA+/='})
        self.assertEqual(dict(parse_qsl(encrypted['body'], keep_blank_values=True))['password'],
                         'CURRENT-RSA+/=')

    def test_token_file_creation_and_append_keep_private_permissions(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / 'new' / 'nested' / 'tokens.txt'
            login._append_token(target, 'SYNTHETIC-FIRST')
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(target.parent.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(target.parent.parent.stat().st_mode), 0o700)
            target.chmod(0o644)
            login._append_token(target, 'SYNTHETIC-SECOND')
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            self.assertEqual(target.read_text(), 'SYNTHETIC-FIRST\nSYNTHETIC-SECOND\n')

    def test_token_file_rejects_symlink_without_changing_target(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / 'original.txt'
            target.write_text('UNCHANGED')
            target.chmod(0o644)
            link = Path(temp) / 'tokens.txt'
            link.symlink_to(target)
            with self.assertRaises(OSError):
                login._append_token(link, 'SYNTHETIC-TOKEN')
            self.assertEqual(target.read_text(), 'UNCHANGED')
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o644)

    def test_submit_success_defaults_to_verified_user_and_paths_cannot_override_it(self):
        user = {'token': 'SYNTHETIC', 'id': 123, 'email': 'new@example.test'}
        response = {'user': user, 'data': {'token': 'SYNTHETIC'}}
        self.assertEqual(login._token_at(response, 200), 'SYNTHETIC')
        self.assertEqual(login._token_at(response, 200, ('user', 'token')), 'SYNTHETIC')
        self.assertEqual(login._token_at(response, 200, ('data', 'token')), 'SYNTHETIC')
        self.assertIsNone(login._token_at(response, 500, ('user', 'token')))
        self.assertIsNone(login._token_at({'data': {'token': 'SYNTHETIC'}}, 200, ('data', 'token')))
        self.assertIsNone(login._token_at(dict(response, error={'message': 'denied'}),
                                         200, ('data', 'token')))
        self.assertIsNone(login._token_at(dict(response, data={'token': 'DIFFERENT'}),
                                         200, ('data', 'token')))
        self.assertIsNone(login._token_at(response, 200, expected_email='other@example.test'))

    def test_run_one_submit_requires_current_account_and_never_prints_credentials(self):
        valid = {'token': 'SYNTHETIC-PRIVATE-TOKEN', 'id': 123, 'email': 'new@example.test'}
        cases = [
            ({'user': valid}, None, True),
            ({'user': valid}, ('user', 'token'), True),
            ({'data': {'token': valid['token']}}, ('data', 'token'), False),
            ({'user': dict(valid, email='other@example.test')}, ('user', 'token'), False),
            ({'user': dict(valid, id=False)}, ('user', 'token'), False),
            ({'user': valid, 'success': False}, ('user', 'token'), False),
        ]
        for response, token_path, accepted in cases:
            replies = [
                (200, {'data': {'userTicket': 'CURRENT-T', 'isSignup': True}}),
                (200, {'data': {'email': 'new@example.test', 'serialNumber': 'CURRENT-S'}}),
                (200, response),
            ]
            output = io.StringIO()
            with self.subTest(response=response, token_path=token_path), \
                 patch.object(login, 'send', side_effect=replies) as send, \
                 patch.object(login.MB, 'snapshot_mailbox', return_value={'uidvalidity': 1, 'uids': [1]}), \
                 patch.object(login.MB, 'get_code', return_value='1234', create=True), \
                 contextlib.redirect_stdout(output):
                result = login.run_one(Signer(), self.tpl, 'new@example.test', 'unused',
                                       token_path=token_path)
            self.assertEqual(result, valid['token'] if accepted else None)
            self.assertEqual(send.call_count, 3)
            self.assertNotIn(valid['token'], output.getvalue())
            self.assertNotIn('new@example.test', output.getvalue())
            self.assertNotIn('1234', output.getvalue())


if __name__ == '__main__':
    unittest.main()
