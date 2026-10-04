"""Explicit proxy routing with requests' real request assembly and no sockets."""
import os
import unittest
from unittest.mock import patch

import requests

from mtgsig.http_transport import configure_http_session, proxy_network_mode


class HTTPTransportTests(unittest.TestCase):
    def test_explicit_proxy_owns_both_schemes_despite_environment_and_no_proxy(self):
        proxy = 'http://127.0.0.1:7897'
        with requests.Session() as session, patch('socket.socket', side_effect=AssertionError('network forbidden')):
            session.proxies['all'] = 'http://stale.example.test:8080'
            network = configure_http_session(session, proxy)
            response = requests.Response()
            response.status_code = 200
            response._content = b'{}'
            environment = {'HTTP_PROXY': 'http://wrong.example.test:1234',
                           'HTTPS_PROXY': 'http://wrong.example.test:1234', 'NO_PROXY': '*'}
            with patch.dict(os.environ, environment), patch.object(session, 'send', return_value=response) as send:
                for scheme in ('http', 'https'):
                    session.get(scheme + '://fixture.example.test/path', allow_redirects=False)
            self.assertFalse(session.trust_env)
            self.assertEqual(send.call_count, 2)
            for call in send.call_args_list:
                self.assertEqual(call.kwargs['proxies'], {'http': proxy, 'https': proxy})
            self.assertFalse(network['direct_fallback'])

    def test_metadata_redacts_credentials_and_omission_preserves_legacy_configuration(self):
        mode = proxy_network_mode('http://synthetic-user:synthetic-password@127.0.0.1:7897')
        self.assertEqual(mode, {'mode': 'explicit_proxy', 'trust_env': False,
                               'proxy': 'http://127.0.0.1:7897', 'direct_fallback': False})
        with requests.Session() as session:
            session.proxies = {'http': 'http://existing.example.test:8080'}
            original = dict(session.proxies)
            self.assertEqual(configure_http_session(session), {'mode': 'environment', 'trust_env': True})
            self.assertTrue(session.trust_env)
            self.assertEqual(session.proxies, original)

    def test_invalid_proxy_is_rejected_before_session_configuration(self):
        with requests.Session() as session:
            for proxy in ('', '127.0.0.1:7897', 'socks5://127.0.0.1:7897', 'http://',
                          'http://127.0.0.1:0', 'http://127.0.0.1:invalid',
                          'http://127.0.0.1:7897/path', 'http://127.0.0.1:7897?q=x',
                          'http://127.0.0.1:7897#fragment', 'http://bad host:7897', False):
                with self.subTest(proxy=proxy), self.assertRaises(ValueError):
                    configure_http_session(session, proxy)
            self.assertTrue(session.trust_env)
            self.assertEqual(session.proxies, {})


if __name__ == '__main__':
    unittest.main()
