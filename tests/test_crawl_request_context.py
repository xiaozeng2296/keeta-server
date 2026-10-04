import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from farm.request_context import RequestContext
from farm import _paths
import crawl_keeta as CK


class RequestContextTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = '/api/v1/shop/productList'
        self.url = 'https://account.example.test' + self.path + '?uuid=U2&userid=2&ci=1'
        self.headers = {'host': 'account.example.test', 'token': 'T2', 'cookie': 'token=T2; setting=x',
                        'uuid': 'U2', 'userid': '2', 'content-length': '99', 'mtgsig': 'stale'}
        self.body = {'shopId': '1', 'location': {'latitude': '0', 'longitude': '0', 'actualLatitude': None},
                     'fingerPrint': 'own-captured-fingerprint'}
        for name, value in {
            'identity.json': {'token': 'T2', 'uuid': 'U2', 'userid': '2'},
            'request.json': {'url': self.url, 'headers': self.headers},
            'endpoint_templates.json': {self.path: {'method': 'POST', 'url': self.url, 'body': self.body}},
        }.items():
            (self.root / name).write_text(json.dumps(value))

    def test_own_origin_identity_and_body_survive_task_substitution(self):
        context = RequestContext(self.root)
        url, headers, body = context.build(self.path, '5', '-1', '-2', city='9')
        self.assertEqual(url, self.url.replace('ci=1', 'ci=9'))
        self.assertEqual(headers['cookie'], self.headers['cookie'])
        self.assertNotIn('mtgsig', headers)
        self.assertNotIn('content-length', headers)
        self.assertEqual(json.loads(body)['fingerPrint'], self.body['fingerPrint'])
        self.assertEqual(json.loads(body)['location'], {'latitude': '-1', 'longitude': '-2', 'actualLatitude': None})
        self.assertEqual(context.templates[self.path]['body'], self.body)

    def test_foreign_origin_and_query_account_are_rejected(self):
        for url in (self.url.replace('account.example.test', 'foreign.example.test'),
                    self.url.replace('userid=2', 'userid=1')):
            context = RequestContext(self.root)
            context.templates[self.path]['url'] = url
            with self.assertRaises(ValueError):
                context.build(self.path, '5', '0', '0')

    def test_charles_http2_pseudo_headers_are_removed_before_transport(self):
        context = RequestContext(self.root)
        context.base['headers'].update({':method': 'POST', ':path': self.path, ':authority': 'account.example.test'})
        url, headers, body = context.build(self.path, '5', '0', '0')
        self.assertFalse(any(k.startswith(':') for k in headers))
        import requests
        requests.Request('POST', url, headers=headers, data=body.encode()).prepare()

    def test_exact_signed_body_is_sent_and_sequence_persisted_first(self):
        context = RequestContext(self.root)
        events = []
        signer = Mock()
        signer.sign.side_effect = lambda *args: events.append(('sign', args)) or 'new-signature'
        signer.persist_counter.side_effect = lambda: events.append(('persist',))
        response = Mock(status_code=200)
        response.json.return_value = {'code': 0, 'data': {}}
        session = Mock()
        session.post.side_effect = lambda *args, **kwargs: events.append(('send', args, kwargs)) or response
        result = CK.call(signer, self.path, '5', '-1', '-2', request_context=context, session=session)
        self.assertEqual([event[0] for event in events], ['sign', 'persist', 'send'])
        self.assertEqual(events[0][1][2].encode(), events[2][2]['data'])
        self.assertEqual(events[0][1][1], events[2][1][0])
        self.assertEqual(result['_http_status'], 200)

    def test_home_shop_list_changes_only_page_and_validates_identity(self):
        context = RequestContext(self.root)
        path = '/api/v4/homePage/homeShopList'
        context.templates[path] = {
            'method': 'POST', 'url': self.url.replace(self.path, path),
            'body': {'pageNo': 0, 'pageSize': 20, 'location': {'latitude': '1', 'longitude': '2'}}}
        _, headers, body = context.build_shop_list(3)
        self.assertEqual(json.loads(body), {'pageNo': 3, 'pageSize': 20,
                                          'location': {'latitude': '1', 'longitude': '2'}})
        self.assertNotIn('shopId', json.loads(body))
        self.assertNotIn('mtgsig', headers)
        self.assertEqual(context.templates[path]['body']['pageNo'], 0)
        context.templates[path]['url'] = context.templates[path]['url'].replace('userid=2', 'userid=1')
        with self.assertRaises(ValueError):
            context.build_shop_list(4)


if __name__ == '__main__':
    unittest.main()
