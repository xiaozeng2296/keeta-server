import unittest
from unittest.mock import patch

from farm.network.proxy import ProxyRoute, normalize_proxy


class ProxyRouteTests(unittest.TestCase):
    def test_transport_diagnostic_reports_connect_status_without_private_text(self):
        import json
        import requests
        from urllib3.exceptions import MaxRetryError, ProxyError
        from farm.network.proxy import transport_failure_details
        inner=OSError('Tunnel connection failed: 502 Bad Gateway private-password')
        proxy=ProxyError('http://secret-user:secret-pass@example.test',inner)
        outer=requests.exceptions.ProxyError(MaxRetryError(None,'https://example.test/?token=private-token',proxy))
        result=transport_failure_details(outer)
        self.assertEqual(result['tunnel_http_status'],[502])
        self.assertEqual(result['error_types'],['MaxRetryError','OSError','ProxyError'])
        for secret in ('private-','secret-','example.test'):
            self.assertNotIn(secret,json.dumps(result))
        inner.__cause__=outer
        self.assertEqual(transport_failure_details(outer),result)


    def test_gateway_shorthand_is_normalized_without_losing_credentials(self):
        value = normalize_proxy("gate.example:58688:customer-session:TQv")
        self.assertEqual(value, "http://customer-session:TQv@gate.example:58688")

    def test_direct_route_does_not_start_a_process(self):
        with patch("farm.network.proxy.subprocess.Popen") as process:
            with ProxyRoute("http://user:pass@gate.example:58688") as route:
                self.assertEqual(route, "http://user:pass@gate.example:58688")
            process.assert_not_called()

    def test_front_route_requires_an_exit_and_loopback_front(self):
        with self.assertRaises(ValueError):
            ProxyRoute(None, "http://127.0.0.1:7897")
        with self.assertRaises(ValueError):
            with ProxyRoute("http://user:pass@gate.example:58688",
                            "http://198.51.100.8:7897"):
                pass

    def test_front_route_requires_a_gost_executable(self):
        with self.assertRaises(ValueError):
            ProxyRoute("http://user:pass@gate.example:58688",
                       "http://127.0.0.1:7897", gost="/missing/gost").__enter__()

    def test_socks_exit_keeps_auth_and_http_front(self):
        from farm.network.proxy import _endpoint, _gost_config
        for scheme in ('socks5','socks5h'):
            route=ProxyRoute(scheme+'://user:p%40ss@gate.example:58688','http://127.0.0.1:7897')
            config=_gost_config(18000,_endpoint(route.front_proxy,loopback=True),
                                _endpoint(route.proxy,authenticated=True),30)
            hops=config['chains'][0]['hops']
            self.assertEqual(hops[0]['nodes'][0]['connector']['type'],'http')
            self.assertEqual(hops[1]['nodes'][0]['connector']['type'],'socks5')
            self.assertEqual(hops[1]['nodes'][0]['connector']['auth'],{'username':'user','password':'p@ss'})
        with self.assertRaises(ValueError):ProxyRoute('socks5://gate.example:58688','http://127.0.0.1:7897')


if __name__ == "__main__":
    unittest.main()


class IPFoxyRefreshTests(unittest.TestCase):
    def test_refresh_uses_only_configured_route_without_keeta_headers(self):
        from farm.network.proxy import refresh_ipfoxy
        with patch('requests.Session') as session,patch('farm.network.proxy.ProxyRoute') as route:
            route.return_value.__enter__.return_value='http://127.0.0.1:12345'
            transport=session.return_value.__enter__.return_value
            transport.get.return_value.status_code=200;transport.get.return_value.json.return_value={'code':0}
            result=refresh_ipfoxy('http://synthetic:pass@gate.ipfoxy.io:58688','http://127.0.0.1:7897')
        self.assertTrue(result['accepted']);self.assertFalse(transport.trust_env)
        call=next(call for call in transport.get.call_args_list if call.args==('http://next.ipfoxy.io',))
        self.assertEqual(call.args,('http://next.ipfoxy.io',))
        self.assertEqual(call.kwargs['proxies'],{'http':'http://127.0.0.1:12345','https':'http://127.0.0.1:12345'})
        self.assertFalse(call.kwargs['allow_redirects']);self.assertNotIn('token',call.kwargs['headers'])

    def test_refresh_records_changed_and_unchanged_exit_separately(self):
        from farm.network.proxy import refresh_ipfoxy
        from unittest.mock import Mock
        for after,changed in [('192.0.2.2',True),('192.0.2.1',False)]:
            with patch('requests.Session') as session,patch('farm.network.proxy.ProxyRoute') as route:
                route.return_value.__enter__.return_value='http://127.0.0.1:12345'
                refresh=Mock(status_code=200);refresh.json.return_value={'code':0}
                session.return_value.__enter__.return_value.get.side_effect=[Mock(status_code=200,text='192.0.2.1'),refresh,Mock(status_code=200,text=after)]
                result=refresh_ipfoxy('http://synthetic:pass@gate.ipfoxy.io:58688','http://127.0.0.1:7897')
            self.assertTrue(result['accepted']);self.assertEqual(result['ip_changed'],changed)
            self.assertEqual(result['exit_before'],'192.0.2.1');self.assertEqual(result['exit_after'],after)

    def test_wrong_gateway_and_explicit_rejection_cannot_report_success(self):
        from farm.network.proxy import refresh_ipfoxy
        with self.assertRaises(ValueError):refresh_ipfoxy('http://u:p@other.example:80')
        with patch('requests.Session') as session:
            response=session.return_value.__enter__.return_value.get.return_value
            response.status_code=200;response.json.return_value={'success':False}
            self.assertFalse(refresh_ipfoxy('http://synthetic:pass@gate.ipfoxy.io:58688')['accepted'])

    def test_non403_and_repeated_task_never_refresh(self):
        from farm.collection.worker import Worker
        from unittest.mock import Mock
        worker=Worker(Mock());bundle={'proxy':'http://synthetic:pass@gate.ipfoxy.io:58688','refresh_ipfoxy':True}
        claim={'task':{'payload':{'_ipfoxy_refresh_attempted':True}}}
        with patch('farm.collection.worker.refresh_ipfoxy') as refresh:
            for status in (200,401,403,429):self.assertFalse(worker.try_proxy_refresh(claim,bundle,status))
            refresh.assert_not_called();worker.store.transaction.assert_not_called()
