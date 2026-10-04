"""Explicit Incognia state and final-request integration, entirely offline."""
from copy import deepcopy
import json
import unittest
from unittest.mock import patch

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

import keeta_offline_flow as flow
from mtgsig import incognia_state as state
from mtgsig import incognia_token as codec


class Signer:
    def __init__(self, dev=None):
        self.dev = {} if dev is None else dev
        self.calls = []
        self.fail = False

    def sign(self, url, body):
        self.calls.append((url, body, deepcopy(self.dev)))
        if self.fail:
            raise RuntimeError('synthetic signer failure')
        return 'SYNTHETIC-MTGSIG'


class IncogniaStateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private = RSA.generate(2048)
        cls.algorithm = {'format': 0, 'public_key_pem': cls.private.public_key().export_key().decode(),
                         'hmac_key_hex': bytes(range(32)).hex(),
                         'application_id': 'synthetic-application', 'sdk_code': 62300}

    def setUp(self):
        guard = patch('socket.socket', side_effect=AssertionError('network forbidden'))
        guard.start()
        self.addCleanup(guard.stop)
        self.profile = {'incognia': {'enabled': True, 'enabled_regions': ['BR'],
                                    'algorithm': deepcopy(self.algorithm)},
                        'incognia_state': {'installation_id': 'ILM-ID-SYNTHETIC-IDENTITY',
                                          'initialization_counter': 2, 'initialized_at_ms': 1700000000000,
                                          'request_counter': 40},
                        'timestamp_ms': 1700000009999}
        self.signer = Signer()
        self.template = {'host': 'synthetic.example.test', 'path': '/request',
                         'request': {'header': {'headers': [
                             {'name': 'region', 'value': 'BR'},
                             {'name': 'Incog-Token', 'value': 'STALE-CAPTURE'},
                             {'name': 'INCOG-TOKEN', 'value': 'OTHER-CAPTURE'}]},
                             'body': {'text': '{}'}}}

    def decode(self, token):
        key = PKCS1_OAEP.new(self.private, hashAlgo=SHA256).decrypt(codec.split(token).wrapped_key)
        return codec.decode_with_session_key(token, session_key=key,
                                             hmac_key=bytes.fromhex(self.algorithm['hmac_key_hex']))

    def request(self, *, profile=None, signer=None):
        return flow.build_request({}, 'synthetic.example.test', '/request', 'plaintext_json',
                                  profile or self.profile, signer=signer or self.signer,
                                  template=self.template)

    def test_final_headers_override_capture_and_state_precedes_signature(self):
        profile = deepcopy(self.profile)
        profile['incog-token'] = 'STALE-PROFILE'
        profile['header_overrides'] = {'incog-token': 'STALE-OVERRIDE', 'region': 'BR'}
        profile['request_body_fields'] = {'/request': {'final': 'body'}}
        original = deepcopy(profile)
        first, second = self.request(profile=profile), self.request(profile=profile)
        self.assertTrue(first['signed'])
        self.assertEqual([k for k in first['headers'] if k.lower() == 'incog-token'], ['incog-token'])
        decoded = [self.decode(r['headers']['incog-token']) for r in (first, second)]
        self.assertEqual([p['59'] for p in decoded], [40, 41])
        self.assertEqual([p['60'] for p in decoded], [1700000009999] * 2)
        self.assertEqual(decoded[0]['33'], 'synthetic-identity')
        self.assertEqual(self.signer.dev['incognia_state']['request_counter'], 42)
        self.assertEqual(self.signer.calls[0][0:2], (first['url'], '{"final":"body"}'))
        self.assertEqual(self.signer.calls[0][2]['incognia_state']['request_counter'], 41)
        self.assertNotEqual(first['headers']['incog-token'], second['headers']['incog-token'])
        self.assertEqual(profile, original)
        self.assertNotIn(first['headers']['incog-token'], json.dumps(self.signer.dev))

    def test_hk_final_region_has_no_header_and_consumes_no_state(self):
        self.profile['header_overrides'] = {'region': 'HK'}
        del self.profile['incognia_state']
        del self.profile['incognia']['algorithm']
        request = self.request()
        self.assertTrue(request['signed'])
        self.assertFalse(any(k.lower() == 'incog-token' for k in request['headers']))
        self.assertNotIn('incognia_state', self.signer.dev)

    def test_without_explicit_enable_captured_token_is_always_removed(self):
        for config in ({}, {'incognia': {'enabled': False}, 'incog-token': 'EXPLICIT-BUT-DISABLED'}):
            request = flow.build_request({}, 'synthetic.example.test', '/request', 'plaintext_json',
                                         config, signer=self.signer, template=self.template)
            self.assertTrue(request['signed'])
            self.assertFalse(any(k.lower() == 'incog-token' for k in request['headers']))
        self.assertEqual(self.signer.dev, {})

    def test_without_new_configuration_explicit_legacy_tokens_remain_supported(self):
        for profile, expected in (({'incog-token': 'CURRENT-PHONE-TOKEN'}, 'CURRENT-PHONE-TOKEN'),
                                  ({'header_overrides': {'INCOG-TOKEN': 'CURRENT-OVERRIDE'}}, 'CURRENT-OVERRIDE')):
            request = flow.build_request({}, 'synthetic.example.test', '/request', 'plaintext_json',
                                         profile, signer=self.signer, template=self.template)
            values = [v for k, v in request['headers'].items() if k.lower() == 'incog-token']
            self.assertEqual(values, [expected])
        self.assertEqual(self.signer.dev, {})

    def test_missing_or_conflicting_identity_is_not_fabricated(self):
        self.request()
        counter = self.signer.dev['incognia_state']['request_counter']
        conflicting = deepcopy(self.profile)
        conflicting['incognia_state']['installation_id'] = 'different'
        request = self.request(profile=conflicting)
        self.assertIn('conflicts', request['error'])
        self.assertEqual(self.signer.dev['incognia_state']['request_counter'], counter)
        empty = deepcopy(self.profile)
        del empty['incognia_state']
        request = self.request(profile=empty, signer=Signer())
        self.assertIn('never fabricated', request['error'])

    def test_generation_and_sign_failures_reserve_counter_for_retry(self):
        with patch.object(codec, 'encode', side_effect=RuntimeError('synthetic crypto error')):
            request = self.request()
        self.assertIn('reserved counter retained', request['error'])
        self.assertEqual(self.signer.dev['incognia_state']['request_counter'], 41)
        self.signer.fail = True
        request = self.request()
        self.assertIn('sign_error', request)
        self.assertEqual(self.decode(request['headers']['incog-token'])['59'], 41)
        self.assertEqual(self.signer.dev['incognia_state']['request_counter'], 42)
        self.signer.fail = False
        retry = self.request()
        self.assertEqual(self.decode(retry['headers']['incog-token'])['59'], 42)
        self.assertEqual(self.signer.dev['incognia_state']['request_counter'], 43)

    def test_snapshot_continuation_uses_saved_counter_over_stale_profile(self):
        self.request()
        # Same JSON serialization used by the existing identity snapshot.
        continued = Signer(json.loads(json.dumps(self.signer.dev)))
        request = self.request(signer=continued)
        self.assertEqual(self.decode(request['headers']['incog-token'])['59'], 41)
        self.assertEqual(continued.dev['incognia_state']['request_counter'], 42)
        self.assertEqual(self.profile['incognia_state']['request_counter'], 40)
        no_seed = deepcopy(self.profile)
        del no_seed['incognia_state']
        request = self.request(profile=no_seed, signer=continued)
        self.assertEqual(self.decode(request['headers']['incog-token'])['59'], 42)

    def test_render_only_and_cloned_dry_run_do_not_mutate_live_input(self):
        original = deepcopy(self.profile)
        request = flow.build_request({}, 'synthetic.example.test', '/request', 'plaintext_json',
                                     self.profile, template=self.template)
        self.assertFalse(request['signed'])
        self.assertFalse(any(k.lower() == 'incog-token' for k in request['headers']))
        self.assertEqual(self.profile, original)
        self.request()
        before = deepcopy(self.signer.dev)
        clone = Signer(deepcopy(self.signer.dev))
        self.request(signer=clone)
        self.assertEqual(self.signer.dev, before)
        self.assertEqual(clone.dev['incognia_state']['request_counter'], before['incognia_state']['request_counter'] + 1)

    def test_transport_failure_rebuild_consumes_next_counter(self):
        first = self.request()
        # Failed delivery cannot roll back state owned by the request builder.
        def send(_request):
            raise OSError('synthetic transport failure')
        with self.assertRaises(OSError):
            send(first)
        second = self.request()
        self.assertEqual(self.decode(second['headers']['incog-token'])['59'], 41)
        self.assertNotEqual(first['headers']['incog-token'], second['headers']['incog-token'])

    def test_unsigned_bootstrap_does_not_require_region_or_generate_token(self):
        template = deepcopy(self.template)
        template['path'] = '/sdkapi/newreg'
        template['request']['header']['headers'] = [{'name': 'incog-token', 'value': 'STALE'}]
        template['request']['body']['text'] = '{"deviceid":"SYNTHETIC-ID","random":"1"}'
        request = flow.build_request({}, template['host'], template['path'], 'plaintext_json',
                                     self.profile, signer=self.signer, template=template)
        self.assertNotIn('error', request)
        self.assertFalse(request['signed'])
        self.assertNotIn('incog-token', request['headers'])
        self.assertEqual(self.signer.dev, {})


if __name__ == '__main__':
    unittest.main()
