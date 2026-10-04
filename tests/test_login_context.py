"""Offline vectors and original wire parity for the login context field."""
import base64
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from urllib.parse import parse_qsl

from mtgsig.login_context import (APP_TOKEN_ID, build_tk_context_plain,
                                 context_body_fields, context_profile_fields)

ROOT = Path(__file__).resolve().parents[1]


class LoginContextTests(unittest.TestCase):
    def setUp(self):
        guard = patch('socket.socket', side_effect=AssertionError('network forbidden'))
        guard.start()
        self.addCleanup(guard.stop)

    def test_known_region_vectors_and_order(self):
        for region, expected in (
            ('HK', 'eyJhMSI6IkhLIiwiYTIiOiI1IiwiYTMiOiI0In0'),
            ('BR', 'eyJhMSI6IkJSIiwiYTIiOiI1IiwiYTMiOiI0In0'),
        ):
            with self.subTest(region=region):
                wire = build_tk_context_plain(region)
                self.assertEqual(wire, expected)
                self.assertNotIn('=', wire)
                self.assertEqual(base64.b64decode(wire + '='),
                                 ('{"a1":"%s","a2":"5","a3":"4"}' % region).encode())

    def test_native_manual_format_does_not_escape_strings(self):
        wire = build_tk_context_plain('香港"\\', token_platform='P', token_app='A')
        self.assertEqual(base64.b64decode(wire + '=' * (-len(wire) % 4)),
                         '{"a1":"香港"\\","a2":"P","a3":"A"}'.encode('utf-8'))

    def test_missing_and_nonstring_native_inputs_yield_no_field(self):
        for value in (None, '', 5, False, {}, []):
            with self.subTest(value=value):
                self.assertEqual(build_tk_context_plain(value), '')
                self.assertEqual(context_body_fields(value), {})
                self.assertEqual(build_tk_context_plain('HK', token_platform=value), '')
                self.assertEqual(build_tk_context_plain('HK', token_app=value), '')

    def test_rollback_switch_omits_field_and_requires_resolved_bool(self):
        self.assertEqual(context_body_fields('HK'),
                         {'tk_context_plain': 'eyJhMSI6IkhLIiwiYTIiOiI1IiwiYTMiOiI0In0'})
        self.assertEqual(context_body_fields('HK', disable_token_standardization=True), {})
        for value in ('false', 0, 1, None):
            with self.assertRaises(ValueError):
                context_body_fields('HK', disable_token_standardization=value)

    def test_native_app_config_supplies_absent_or_empty_token_id(self):
        profile={'region':'HK','login_context_inputs':{
            'disable_token_standardization':False,'token_platform':'5','token_app':'4'}}
        for token in (None,''):
            with self.subTest(empty=token==''):
                state=dict(profile,token_id=token)
                state.update(context_profile_fields(state))
                self.assertTrue(state['token_id']==APP_TOKEN_ID)
                self.assertTrue(bool(state['token_id']))
        self.assertTrue(context_profile_fields(profile)['token_id']==APP_TOKEN_ID)

    def test_native_token_requires_explicit_app_config_and_preserves_custom_value(self):
        self.assertEqual(context_profile_fields({'region':'HK','token_id':''}),{})
        profile={'region':'HK','token_id':'CUSTOM-APP-CONFIG','login_context_inputs':{
            'disable_token_standardization':False,'token_platform':'5','token_app':'4'}}
        state=dict(profile)
        state.update(context_profile_fields(state))
        self.assertEqual(state['token_id'],'CUSTOM-APP-CONFIG')
        for field,value in (('token_platform','OTHER'),('token_app','OTHER')):
            state=dict(profile,token_id='',login_context_inputs=dict(profile['login_context_inputs']))
            state['login_context_inputs'][field]=value
            self.assertNotIn('token_id',context_profile_fields(state))

    def test_token_id_is_independent_of_tk_context_rollback_switch(self):
        fields=context_profile_fields({'region':'HK','login_context_inputs':{
            'disable_token_standardization':True,'token_platform':'5','token_app':'4'}})
        self.assertIsNone(fields['tk_context_plain'])
        self.assertTrue(fields['token_id']==APP_TOKEN_ID)

    def test_optional_original_captures_match_the_recovered_constructor(self):
        captures = [('evidence/captures/从app初次打开到登录被拦截.chlsj', 801),
                    ('evidence/captures/新机之后尝试登录.chlsj', 628)]
        available = [(ROOT / name, index) for name, index in captures if (ROOT / name).exists()]
        if not available:
            self.skipTest('optional original Charles captures are absent')
        for path, index in available:
            with self.subTest(capture=path.name, index=index):
                event = json.loads(path.read_text())[index]
                fields = dict(parse_qsl(event['request']['body']['text'], keep_blank_values=True))
                wire = fields['tk_context_plain']
                plain = json.loads(base64.b64decode(wire + '=' * (-len(wire) % 4)))
                self.assertEqual((plain['a2'], plain['a3']), ('5', '4'))
                self.assertEqual(build_tk_context_plain(plain['a1']), wire)
                # This is an App constant, not a per-mailbox credential. Do
                # not include its bytes in unittest mismatch diagnostics.
                self.assertTrue(fields['token_id']==APP_TOKEN_ID)


if __name__ == '__main__':
    unittest.main()
