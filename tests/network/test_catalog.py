"""Inventory inputs, credential isolation, route selection and HTTP boundaries."""
from contextlib import contextmanager
from copy import deepcopy
import json
import re
import unittest
from unittest.mock import Mock, patch

from farm.network.catalog import parse_import, import_routes, inventory, check_route, ProxyConfigError
from farm.web.app import create_app


class ProxyCatalogTests(unittest.TestCase):
    def test_import_formats_preserve_credentials_without_shell_execution(self):
        rows=parse_import('host.example:8080:username:pass:with:colon\nsocks5://name:pass@192.0.2.10:45001')
        self.assertEqual(rows[0]['proxy'],'http://username:pass%3Awith%3Acolon@host.example:8080')
        self.assertTrue(rows[1]['proxy'].startswith('socks5://'))
        self.assertEqual(parse_import('{"proxies":[{"name":"US 1","url":"http://u:p@example.test:80"}]}')[0]['name'],'US 1')

    def test_invalid_input_never_echoes_proxy_credentials(self):
        secret='private-password'
        for text in ['', 'file:///private-password', json.dumps([{'name':'socks5://u:'+secret+'@host','proxy':'http://u:p@host:80'}]),
                     'socks5://u:'+secret+'@host:99999', '{}']:
            with self.assertRaises(ProxyConfigError) as error:parse_import(text)
            self.assertNotIn(secret,str(error.exception))

    def test_import_is_idempotent_and_separates_front_nodes(self):
        store=Mock();store.get_setting.return_value={'nodes':[{'name':'A','proxy':'http://127.0.0.1:18001'}, {'name':'B','proxy':'http://127.0.0.1:18002'}]}
        catalog={}
        @contextmanager
        def configured(_):yield Mock()
        def save(_store,_cursor,_key,value):catalog.update(deepcopy(value))
        with patch('farm.network.catalog.configuration',configured),patch('farm.network.catalog.read_setting',side_effect=lambda *_:deepcopy(catalog)),patch('farm.network.catalog.write_setting',side_effect=save):
            first=import_routes(store,'socks5://user:password@host.test:45001','A')
            second=import_routes(store,'socks5://user:password@host.test:45001','A')
            other=import_routes(store,'socks5://user:password@host.test:45001','B')
        self.assertEqual(first['ids'],second['ids']);self.assertEqual(second['imported'],0)
        self.assertNotEqual(first['ids'],other['ids']);self.assertEqual(len(catalog),2)
        self.assertEqual({v['front_proxy'] for v in catalog.values()},{'http://127.0.0.1:18001','http://127.0.0.1:18002'})

    def test_public_inventory_never_returns_usernames_passwords_or_control_secret(self):
        store=Mock();store.rows.return_value=[{'id':5,'label':'account','paused':False}]
        settings={'proxy_catalog':{'id1':{'id':'id1','name':'US','front_node':'A','proxy':'socks5://secret-user:secret-pass@192.0.2.1:80','front_proxy':'http://127.0.0.1:18001','refresh_ipfoxy':False}},
                  'account_proxy_bindings':{'5':{'proxy_id':'id1','mode':'catalog','name':'US'}},
                  'clash_node_pool':{'secret':'secret-control','nodes':[{'name':'A','proxy':'http://127.0.0.1:18001'}]}}
        store.get_setting.side_effect=lambda k:settings.get(k)
        result=inventory(store);self.assertEqual(result['proxies'][0]['account_ids'],[5])
        self.assertNotIn('secret-',json.dumps(result));self.assertNotIn('front_proxy',result['proxies'][0])

    def test_check_uses_selected_node_and_does_not_send_account_headers(self):
        store=Mock();store.get_setting.return_value={'nodes':[{'name':'A','proxy':'http://127.0.0.1:18001'}]}
        with patch('farm.network.catalog.ProxyRoute') as route,patch('farm.network.catalog.requests.Session') as session:
            route.return_value.__enter__.return_value='http://127.0.0.1:18001'
            session.return_value.__enter__.return_value.get.return_value=Mock(status_code=200,text='192.0.2.99')
            result=check_route(store,node_name='A')
        self.assertEqual(result['exit_ip'],'192.0.2.99');self.assertTrue(result['ok'])
        self.assertEqual(session.return_value.__enter__.return_value.get.call_args.kwargs['headers'],{'Accept':'text/plain'})
        route.assert_called_once_with('http://127.0.0.1:18001',None)

    def test_proxy_mutations_require_csrf_and_selected_route_is_forwarded(self):
        client=create_app(Mock()).test_client()
        for endpoint in ('import','check','delete'):
            self.assertEqual(client.post('/api/proxies/'+endpoint,json={}).status_code,403)
        csrf=re.search(r'name="csrf-token" content="([^"]+)"',client.get('/').text)[1]
        with patch('farm.network.proxy.assign_account_proxies',return_value=[{'account_id':5}]) as assign:
            response=client.post('/api/accounts/proxy',json={'ids':[5],'mode':'catalog','proxy_id':'id1'},headers={'X-Panel-CSRF':csrf})
        self.assertEqual(response.status_code,200);self.assertEqual(assign.call_args.kwargs['proxy_id'],'id1')
        with patch('farm.network.catalog.import_routes',side_effect=ProxyConfigError('请选择一个有效的前置 Clash 节点')):
            response=client.post('/api/proxies/import',json={},headers={'X-Panel-CSRF':csrf})
        self.assertEqual(response.status_code,400);self.assertIn('前置',response.json['error'])
