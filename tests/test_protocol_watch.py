"""Protocol drift detection must not accept partial or synthetic-only evidence."""
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from farm import fullsign as fs
from tests import test_signing_profiles as fixtures
from tools.protocol_watch import audit, audit_configurations, check_release, compare, embedded_schema, inspect_record, records, save
from mtgsig.provider_config import ProviderConfig, encode_config
from mtgsig import a9_codec, mtg_crypto


def sample():
    mt = fixtures.SigningProfileTests().sample('default')
    payload = {k: mt[k] for k in fs.FullSigner.ORDER}
    payload['a2'] = fs.compute_a2('POST', 'https://example.test/menu', '{"shopId":"1"}',
        json.dumps(payload, separators=(',', ':')), mt['a1'], 1, signing_profile='default', sign_sequence=1)
    return {'method': 'POST', 'url': 'https://example.test/menu', 'body': '{"shopId":"1"}',
            'headers': {'mtgsig': json.dumps(payload), 'token': 'SECRET_ACCOUNT_TOKEN'}}


class HornConfigurationTests(unittest.TestCase):
    def config(self, parameter=25, end='2026-10-01T01:00:02+00:00'):
        value = encode_config(ProviderConfig(parameter, bytes.fromhex('00112233445566778899aabbccddeeff')))
        return {'path': '/horn_ios/mergeRequest', 'times': {'end': end},
                'response': {'status': 200, 'body': {'text': json.dumps({'SAKGuard_Dynamic_Risk':
                    {'data': {'customer': {'sakguard_key_enc_salt': value, 'token': 'DO_NOT_EMIT'}}}})}}}

    def signature(self, parameter, begin):
        return {'path': '/api/v1/shop/productList', 'times': {'requestBegin': begin},
                'request': {'header': {'headers': [{'name': 'mtgsig', 'value': json.dumps(
                    {'a0': '2.5', 'x0': 2, 'a3': parameter, 'a1': 'PRIVATE_A1'})}]}}}

    def report(self, flows):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'capture.chlsj'; save(path, flows)
            return audit_configurations([path])

    def test_network_times_override_array_order_and_timezone(self):
        config = self.config()
        report = self.report([self.signature(20, '2026-09-30T18:00:03-07:00'), config,
                              self.signature(25, '2026-10-01T01:00:01Z')])
        event = report['events'][0]
        self.assertEqual(event['later_a3_counts'], {'20': 1})
        self.assertEqual(event['first_later_request']['index'], 0)
        self.assertEqual(report['status'], 'review_required')
        for secret in ('DO_NOT_EMIT', 'PRIVATE_A1', '00112233445566778899aabbccddeeff',
                       json.loads(config['response']['body']['text'])['SAKGuard_Dynamic_Risk']['data']['customer']['sakguard_key_enc_salt']):
            self.assertNotIn(secret, json.dumps(report))

    def test_new_response_bounds_previous_observation(self):
        report = self.report([self.config(), self.signature(25, '2026-10-01T01:00:03Z'),
                              self.config(26, '2026-10-01T01:00:04Z'),
                              self.signature(26, '2026-10-01T01:00:05Z')])
        self.assertEqual(report['status'], 'observed')
        self.assertEqual([r['later_a3_counts'] for r in report['events']], [{'25': 1}, {'26': 1}])

    def test_absent_or_naive_time_is_not_replaced_by_array_position(self):
        for timestamp in (None, '2026-10-01T01:00:03', 'bad-time'):
            report = self.report([self.config(), self.signature(20, timestamp)])
            self.assertEqual(report['status'], 'incomplete_observation')
            self.assertEqual(report['events'][0]['later_request_count'], 0)
        report = self.report([self.config(end=None), self.signature(25, '2026-10-01T01:00:03Z')])
        self.assertEqual(report['status'], 'incomplete_observation')

    def test_missing_config_and_missing_later_requests_are_incomplete(self):
        self.assertEqual(self.report([])['status'], 'incomplete_observation')
        self.assertEqual(self.report([self.config()])['status'], 'incomplete_observation')

    def test_charles_connect_tunnel_without_path_is_ignored(self):
        report = self.report([{'method': 'CONNECT', 'path': None, 'request': {}},
                              self.config(), self.signature(25, '2026-10-01T01:00:03Z')])
        self.assertEqual(report['status'], 'observed')
        self.assertEqual(len(report['events']), 1)

    def test_invalid_and_empty_network_configs_are_not_default_profiles(self):
        for value in ('', 'PRIVATE_BAD_CONFIG', None, 25):
            flow = self.config()
            payload = json.loads(flow['response']['body']['text'])
            payload['SAKGuard_Dynamic_Risk']['data']['customer']['sakguard_key_enc_salt'] = value
            flow['response']['body']['text'] = json.dumps(payload)
            report = self.report([flow, self.signature(20, '2026-10-01T01:00:03Z')])
            self.assertEqual(report['status'], 'failed_validation')
            self.assertFalse(report['events'][0]['decoded'])
            self.assertNotIn('PRIVATE_BAD_CONFIG', json.dumps(report))

    def test_compressed_response_and_test_type(self):
        import base64, gzip
        flow = self.config()
        body = flow['response']['body']['text'].replace('SAKGuard_Dynamic_Risk', 'SAKGuard_Dynamic_Risk_Test')
        flow['response']['body'] = {'encoding': 'base64', 'encoded': base64.b64encode(gzip.compress(body.encode())).decode()}
        report = self.report([flow, self.signature(25, '2026-10-01T01:00:03Z')])
        self.assertEqual(report['status'], 'observed')
        self.assertEqual(report['events'][0]['type'], 'SAKGuard_Dynamic_Risk_Test')

    def test_http_failure_and_invalid_horn_json_cannot_pass(self):
        flow = self.config(); flow['response']['status'] = 403
        self.assertEqual(self.report([flow])['status'], 'failed_validation')
        flow['response']['body']['text'] = 'PRIVATE_INVALID_JSON'
        report = self.report([flow])
        self.assertEqual(report['status'], 'failed_validation')
        self.assertNotIn('PRIVATE_INVALID_JSON', json.dumps(report))


class ProtocolWatchTests(unittest.TestCase):
    def report(self, record):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'native.json'
            save(path, {'samples': [record]})
            return audit([path])

    def test_full_native_parity_and_independent_profiles(self):
        r = inspect_record(sample())
        self.assertTrue(all(r['checks'].values()))
        self.assertEqual(r['signing_profile'], 'default')
        self.assertEqual(r['a9_profile'], 'legacy')
        self.assertNotIn('SECRET_ACCOUNT_TOKEN', json.dumps(r))

    def test_one_byte_body_change_fails_a2(self):
        row = sample(); row['body'] = '{"shopId":"2"}'
        r = inspect_record(row)
        self.assertFalse(r['checks']['a2_full'])
        self.assertTrue(r['checks']['a5_decode'])

    def test_a3_change_cannot_be_guessed_from_version(self):
        row = sample(); mt = json.loads(row['headers']['mtgsig']); mt['a3'] = 25
        row['headers']['mtgsig'] = mt
        self.assertFalse(inspect_record(row)['checks']['a5_decode'])

    def test_missing_request_is_incomplete_not_pass(self):
        old = self.report(sample()); partial = sample(); partial.pop('url')
        r = compare(old, self.report(partial))
        self.assertEqual(r['status'], 'incomplete_validation')

    def test_schema_extension_triggers_review(self):
        old = self.report(sample()); new = deepcopy(old)
        new['inventory']['field_types'][0]['new_field'] = 'int'
        self.assertEqual(compare(old, new)['status'], 'review_required')
        self.assertEqual(compare(old, old)['status'], 'matches_baseline')

    def test_missing_endpoint_coverage_is_incomplete(self):
        old = self.report(sample()); new = deepcopy(old)
        old['inventory']['request_shape'].append({'method':'POST', 'host':'example.test', 'path':'/details'})
        result = compare(old, new)
        self.assertEqual(result['status'], 'incomplete_validation')
        self.assertEqual(result['changes']['missing_request_coverage'], [['POST','example.test','/details']])

    def test_embedded_json_schema_tracks_fields_without_values(self):
        shape = embedded_schema({'b1':'{"55":1,"secret":"PRIVATE_TOKEN"}'})
        self.assertIn('$.b1<json>.55:int', shape)
        self.assertNotIn('PRIVATE_TOKEN', json.dumps(shape))

    def test_unknown_layout_does_not_try_native_cipher(self):
        row = sample(); mt = json.loads(row['headers']['mtgsig']); mt['x0'] = 4
        row['headers']['mtgsig'] = mt
        with patch('tools.protocol_watch.fs.decode_a5') as decoder:
            result = inspect_record(row)
        decoder.assert_not_called()
        self.assertEqual(result['layout'], 'unsupported')
        self.assertFalse(result['checks']['layout_supported'])

    def test_same_build_with_changed_sdk_config_requires_review(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'native.json'
            payload = {'format':'keeta-native-sign-only-v1', 'samples':[sample()],
                       'metadata':{'app_version':'3.12.500', 'build':'18565',
                                   'sdk_configuration':{'sha256':'first-config','present':True}}}
            save(path,payload); before=audit([path])
            payload['metadata']['sdk_configuration']['sha256']='updated-config'
            save(path,payload); after=audit([path])
        result=compare(before,after)
        self.assertEqual(result['status'],'review_required')
        self.assertIn('sdk_configuration',result['changes'])

    def dynamic_sample(self, cached_a9=False):
        config = ProviderConfig(24, bytes.fromhex('00112233445566778899aabbccddeeff'))
        row = sample(); mt = json.loads(row['headers']['mtgsig']); mt.pop('a2')
        mt['a3'] = config.parameter
        mt['a5'] = mtg_crypto.a5_encrypt(json.dumps(fixtures.COLLECT).encode(), mt['a1'],
                                        mt['a3'], mt['a4'], config.mask(mt['a1']))
        if not cached_a9:
            mt['a9'] = a9_codec.encode('{}', mt['a1'], mode='twofish', **config.a9_options())
        mt['a2'] = fs.compute_a2(row['method'], row['url'], row['body'],
            json.dumps(mt, separators=(',', ':')), mt['a1'], 1, signing_profile=config, sign_sequence=1)
        row['headers']['mtgsig'] = json.dumps(mt)
        return row, config

    def test_new_stored_profile_validates_full_signature(self):
        row, config = self.dynamic_sample()
        self.assertFalse(inspect_record(row)['checks']['a5_decode'])
        result = inspect_record(row, config)
        self.assertTrue(all(result['checks'].values()))
        self.assertEqual(result['signing_profile'], 'stored_configuration')
        self.assertEqual(result['a9_profile'], 'stored_configuration')
        self.assertNotIn(config.salt.hex(), json.dumps(result))

    def test_new_provider_does_not_override_cached_a9(self):
        row, config = self.dynamic_sample(cached_a9=True)
        result = inspect_record(row, config)
        self.assertTrue(all(result['checks'].values()))
        self.assertEqual(result['a9_profile'], 'legacy')

    def test_stored_configuration_is_bound_to_its_own_native_container(self):
        row, config = self.dynamic_sample()
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'native.json'
            payload = {'format': 'keeta-native-sign-only-v1', 'metadata': {}, 'samples': [row],
                       'configuration': {'available': True, 'value': encode_config(config)}}
            save(path, payload); valid = audit([path])
            self.assertEqual(compare(valid, valid)['status'], 'matches_baseline')
            payload['configuration']['value'] = 'invalid'
            save(path, payload); invalid = audit([path])
        self.assertEqual(invalid['checks']['stored_configuration_valid'], {'false': 1})
        self.assertEqual(compare(valid, invalid)['status'], 'failed_validation')

    def test_stale_stored_configuration_is_not_declared_active(self):
        result = inspect_record(sample(), ProviderConfig(25, bytes(16)))
        self.assertTrue(result['checks']['a2_full'])
        self.assertFalse(result['checks']['stored_configuration_matches_a3'])
        self.assertFalse(result['checks']['stored_configuration_matches_a5'])

    def test_resource_changes_and_missing_observations_are_detected(self):
        before = self.report(sample()); before['inventory']['sdk_resource_tags'] = [{'pic': 123, 'xbt': 123}]
        after = deepcopy(before); after['inventory']['sdk_resource_tags'] = [{'pic': 124, 'xbt': 124}]
        self.assertEqual(compare(before, after)['status'], 'review_required')
        after['inventory']['sdk_resource_tags'] = []
        result = compare(before, after)
        self.assertEqual(result['status'], 'incomplete_validation')
        self.assertEqual(result['changes']['missing_native_observations'], ['sdk_resource_tags'])

    def test_private_save_restricts_existing_file_permissions(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'native.json'; path.write_text('{}'); path.chmod(0o644)
            save(path, {'samples':[]})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_opaque_other_protocol_fields_never_leak(self):
        row = {'headers': {'mtgsig': {'a3': 'PRIVATE_ID', 'a6': 'PRIVATE_BLOB',
                                     'a10': 'PRIVATE_SESSION', 'x0': 4}}}
        r = inspect_record(row)
        self.assertNotIn('PRIVATE', json.dumps(r))
        self.assertEqual(r['constants'], {'x0': 4})

    def test_empty_capture_fails_comparison(self):
        report = self.report(sample()); empty = deepcopy(report); empty['sample_count'] = 0
        self.assertEqual(compare(report, empty)['status'], 'failed_validation')

    def test_release_identity_and_numeric_order(self):
        def opener(url, timeout):
            return io.StringIO(json.dumps({'results': [{'bundleId': 'wrong.app', 'version': '999'},
                {'bundleId': 'com.sankuai.sailor.ifooddelivery', 'version': '3.12.500'}]}))
        self.assertEqual(check_release('3.9.9', 'br', opener)['status'], 'update_available')
        self.assertEqual(check_release('3.12.500.0', 'br', opener)['status'], 'same_version')

    def test_http2_query_and_body_are_preserved(self):
        row = sample(); mt = row['headers']['mtgsig']
        flow = {'scheme': 'https', 'host': 'example.test', 'method': 'POST', 'path': '/wrong',
                'query': 'ignored=1', 'request': {'header': {'headers': [
                    {'name': ':path', 'value': '/menu?x=a%2Fb&z=1'}, {'name': 'mtgsig', 'value': mt}]},
                    'body': {'text': '{ "shopId" : "1" }'}}}
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'capture.chlsj'; path.write_text(json.dumps([flow]))
            r = list(records(path))[0]
        self.assertEqual(r['url'], 'https://example.test/menu?x=a%2Fb&z=1')
        self.assertEqual(r['body'], '{ "shopId" : "1" }')


if __name__ == '__main__': unittest.main()
