"""Exact region/config response paths; no business network or device operations."""
import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from mtgsig import region_state as r


class RegionStateTests(unittest.TestCase):
    def setUp(self):
        guard = patch('socket.socket', side_effect=AssertionError('network forbidden'))
        guard.start()
        self.addCleanup(guard.stop)
        self.local = {'code': 0, 'data': {
            'region': 'HK', 'cityId': '810001', 'locale': 'zh', 'lang': 'zh',
            'timeZone': 'GMT+08:00', 'currency': 'HKD',
            'leafCityInfo': {'region': 'HK', 'cityId': 'OTHER-LEAF'}}}
        self.hosts = {'Passport.url': 'passport.example.test', 'msp.url.pikachu': 'sdk.example.test',
                      'Push.medusaUrl': 'https://push.example.test',
                      'Keeta.C.ProductUrl': 'https://product.example.test'}
        self.compass = {'code': 0, 'data': {'version': 'test-version', 'configs': [
            {'regions': ['HK'], 'bizConfig': {'platformHosts': self.hosts}},
            {'regions': ['BR'], 'bizConfig': {'platformHosts': dict(self.hosts,
                **{'Passport.url': 'passport-br.example.test'})}}]}}

    def test_local_top_level_city_and_raw_locale_values_are_preserved(self):
        original = copy.deepcopy(self.local)
        state = r.parse_current_local_info_response(self.local, http_status=200)
        self.assertEqual(state, {'region': 'HK', 'city_id': '810001', 'locale': 'zh', 'lang': 'zh',
                                 'time_zone': 'GMT+08:00', 'currency': 'HKD'})
        self.assertEqual(self.local, original)
        del self.local['data']['cityId']
        self.assertEqual(r.parse_current_local_info_response(self.local, http_status=200), {})

    def test_failure_and_types_do_not_return_partial_state(self):
        for parser, response, kwargs in ((r.parse_current_local_info_response, self.local, {}),
                                         (r.parse_compass_response, self.compass, {'region':'HK'})):
            for status in (True, '200', 199, 300, 403, 500):
                self.assertEqual(parser(response, http_status=status, **kwargs), {})
            for code in (None, False, True, 0.0, '0', 1):
                self.assertEqual(parser(dict(response, code=code), http_status=200, **kwargs), {})
            for failed in (dict(response, error={'code':1}), dict(response, success=False),
                           {'data':response['data']}, {'code':0,'data':[]}, []):
                self.assertEqual(parser(failed, http_status=200, **kwargs), {})
        for key in ('region','cityId','locale','lang','timeZone','currency'):
            for value in (None, 1, False, [], '', ' ', 'VALUE\n'):
                failed = copy.deepcopy(self.local)
                failed['data'][key] = value
                self.assertEqual(r.parse_current_local_info_response(failed, http_status=200), {})

    def test_compass_selects_one_region_and_exact_dotted_fields(self):
        original = copy.deepcopy(self.compass)
        selected = r.parse_compass_response(self.compass, region='BR', http_status=200)
        self.assertEqual(selected['compass_region'], 'BR')
        self.assertEqual(selected['compass_source'], 'data.configs')
        self.assertEqual(selected['compass_version'], 'test-version')
        self.assertEqual(selected['platform_hosts']['Passport.url'], 'passport-br.example.test')
        self.assertEqual(set(selected['platform_hosts']), set(r.HOST_FIELDS + r.URL_FIELDS))
        self.assertNotIn('region', selected)
        selected['platform_hosts']['Passport.url'] = 'changed.example.test'
        self.assertEqual(self.compass, original)

    def test_unknown_region_duplicate_and_unresolved_fallbacks_are_rejected(self):
        self.assertEqual(r.parse_compass_response(self.compass, region='ZZ', http_status=200), {})
        self.compass['data']['configs'].append(copy.deepcopy(self.compass['data']['configs'][0]))
        self.assertEqual(r.parse_compass_response(self.compass, region='HK', http_status=200), {})
        self.compass['data']['commonConfig'] = self.compass['data'].pop('configs')
        self.assertEqual(r.parse_compass_response(self.compass, region='HK', http_status=200), {})

    def test_config_snapshot_does_not_guess_private_override_precedence(self):
        self.compass['data']['privateConfig'] = [{'regions':['HK'], 'bizConfig':{'platformHosts':
            dict(self.hosts, **{'Passport.url':'private.example.test'})}}]
        selected = r.parse_compass_response(self.compass, region='HK', http_status=200)
        self.assertEqual(selected['platform_hosts']['Passport.url'], 'passport.example.test')
        self.assertEqual(selected['compass_source'], 'data.configs')

    def test_missing_or_malformed_route_has_no_partial_snapshot(self):
        for field, value in (('Passport.url', 'https://passport.example.test'),
                             ('Passport.url', 'name:password@host.test'),
                             ('msp.url.pikachu', ''),
                             ('Push.medusaUrl', 'https://user:password@push.test'),
                             ('Keeta.C.ProductUrl', 'https://product.test/?identity=VALUE')):
            response = copy.deepcopy(self.compass)
            response['data']['configs'][0]['bizConfig']['platformHosts'][field] = value
            self.assertEqual(r.parse_compass_response(response, region='HK', http_status=200), {})
        response = copy.deepcopy(self.compass)
        del response['data']['configs'][0]['bizConfig']['platformHosts']['Passport.url']
        self.assertEqual(r.parse_compass_response(response, region='HK', http_status=200), {})

    def test_real_capture_selected_region_and_route_match_later_requests(self):
        file = Path(__file__).resolve().parents[1] / 'evidence/captures/新机之后尝试登录.chlsj'
        if not file.exists():
            self.skipTest('optional original Charles capture is absent')
        events = json.loads(file.read_text())
        local = r.parse_current_local_info_response(json.loads(events[205]['response']['body']['text']),
                                                    http_status=events[205]['response']['status'])
        self.assertEqual((local['region'],local['city_id'],local['locale']), ('HK','810001','zh'))
        config = r.parse_compass_response(json.loads(events[97]['response']['body']['text']),
                                         region=local['region'], http_status=events[97]['response']['status'])
        self.assertEqual(config['platform_hosts']['Passport.url'], events[628]['host'])
        self.assertEqual(config['platform_hosts']['Keeta.C.ProductUrl'],
                         events[627]['scheme']+'://'+events[627]['host'])


if __name__ == '__main__':
    unittest.main()
