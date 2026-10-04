"""XID expiry, event accounting and reload; all HTTP responses are synthetic."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from mtgsig.signer import FullSigner, compute_a2, decode_a5
from farm.accounts.fingerprint import ensure_fingerprint, FingerprintRefreshBlocked, ReportJournal
from mtgsig.fingerprint_refresh import (CONFIG, STATE, PATH, build_report, begin_report,
                                       finish_report, refresh_status)
from mtgsig import envelope_codec
from mtgsig.collection_cache import compact
from tests.protocol.test_collection_refresh import identity

NOW = 1790732400123


def bundle():
    dev = identity()
    dev['base_collect'].update(b5='3.12.500', b10='5.21.10', b16='[0,0,0],[3,3600,3604],[1,30,31],1')
    dev[CONFIG] = {'enabled': True, 'sdk_version': '5.21.10', 'appkey': dev['a1'], 'checksum_version': 'x' * 64}
    return {'device': dev, 'identity': {'uuid': 'own-install', 'userid': '100'},
            'request': {'headers': {'region': 'BR', 'cityid': '102', 'appid': '517', 'userid': '100',
                                    'token': 'must-not-copy', 'Cookie': 'must-not-copy'}}}


class Reply:
    def __init__(self, status=200, body=None):
        self.status_code = status
        self.headers = {}
        self.body = body if body is not None else {'code': 0, 'data': {'result': 'server-XID', 'interval': 30, 'serverTimestamp': 1}}
    def json(self):
        return self.body


class FingerprintRefreshTests(unittest.TestCase):
    def test_envelope_fields_and_modes_roundtrip(self):
        for counter in range(3):
            b = bundle(); b['device']['signature_counter'] = counter; signer = FullSigner(b['device'])
            url, headers, body = build_report(b, signer, timestamp_ms=NOW, session_key=b'1234567890abcdef')
            self.assertTrue(url.startswith('https://pikachu-eu.mykeeta.com' + PATH))
            self.assertNotIn('token', headers); self.assertNotIn('cookie', headers)
            value = envelope_codec.decode_sdk(json.loads(body)['fingerPrintData'], signer.dev['a1'],
                session_key=b'1234567890abcdef', mode=('twofish-mod','twofish','aes')[counter], profile='legacy')
            fields = json.loads(value.plaintext)
            self.assertEqual(set(fields), {'m27','m144','m152','m153','m154','m294','m320'})
            self.assertEqual(fields['m153'], b['identity']['uuid'])
            self.assertEqual(fields['m294'], signer.dev['collection_cache']['collect']['b1'])

    def test_missing_or_cross_account_input_fails_before_send(self):
        for key in ('sdk_version','appkey','checksum_version'):
            b = bundle(); b['device'][CONFIG][key] = 'wrong'
            with self.assertRaises(ValueError): build_report(b, FullSigner(b['device']), timestamp_ms=NOW)
        b = bundle(); b['request']['headers']['userid'] = '101'
        with self.assertRaises(ValueError): build_report(b, FullSigner(b['device']), timestamp_ms=NOW)

    def test_native_minutes_and_real_b16_persist_reload(self):
        b = bundle(); original = deepcopy(b['device']); signer = FullSigner(b['device'])
        begin_report(signer.dev, 'event', NOW)
        self.assertTrue(finish_report(signer, 'event', Reply().json(), 200, NOW + 1800))
        state = signer.dev[STATE]
        self.assertEqual(state['expires_at_ms'], ((NOW + 1800)//1000 + 1800)*1000)
        self.assertEqual(state['server_timestamp_ms'], 1)
        self.assertEqual(state['b16'], '[0,0,0],[4,90732400,90732401],[1,30,31],1')
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/'device.json'; p.write_text(json.dumps(signer.persist_counter()))
            restored = FullSigner(p)
            with patch('mtgsig.signer.time.time', return_value=(NOW+1900)/1000):
                mt = json.loads(restored.sign('POST', 'https://example.test/menu', '{}'))
            col = json.loads(decode_a5(mt['a5'], mt['a1'], mt['a3'], mt['a4'])[0])
            self.assertEqual(mt['a7'], 'server-XID'); self.assertEqual(col['b16'], state['b16'])
            signature = mt.pop('a2')
            self.assertEqual(signature, compute_a2('POST','https://example.test/menu','{}', compact(mt),mt['a1'],restored.signature_counter,sign_sequence=col['b2']))
            self.assertEqual(restored.dev['base_collect'], original['base_collect'])
            self.assertEqual(refresh_status(restored.dev,state['expires_at_ms']-1), 'fresh')
            self.assertEqual(refresh_status(restored.dev,state['expires_at_ms']), 'due')

    def test_http200_rejected_body_records_callback_but_preserves_a7(self):
        s = FullSigner(bundle()['device']); old = s.a7; begin_report(s.dev, 'event', NOW)
        self.assertFalse(finish_report(s, 'event', {'code': 9}, 200, NOW+1800))
        self.assertEqual(s.a7, old); self.assertIn('90732401',s.dev[STATE]['b16'])
        self.assertEqual(refresh_status(s.dev,NOW+2000),'backoff')

    def test_403_no_success_timestamp_and_no_identity_mutation(self):
        s = FullSigner(bundle()['device']); old = s.a7; begin_report(s.dev,'event',NOW)
        self.assertFalse(finish_report(s,'event',Reply().json(),403,NOW+1800))
        self.assertEqual(s.a7,old); self.assertIn(',3604]',s.dev[STATE]['b16'])

    def test_missing_expiry_does_not_create_report_storm(self):
        for interval in (None, '30', True, 0, -1):
            s=FullSigner(bundle()['device']); begin_report(s.dev,'event',NOW)
            self.assertTrue(finish_report(s,'event',{'code':0,'data':{'result':'server','interval':interval}},200,NOW+100))
            self.assertEqual(refresh_status(s.dev,NOW+60001+100),'expiry_unknown')

    def test_pending_and_mismatched_session_fail_closed(self):
        s=FullSigner(bundle()['device']); begin_report(s.dev,'event',NOW)
        self.assertEqual(refresh_status(s.dev,NOW+100),'unfinished_report')
        with self.assertRaises(ValueError):begin_report(s.dev,'again',NOW+100)
        with self.assertRaises(ValueError):finish_report(s,'other',Reply().json(),200,NOW+100)
        s.dev['base_collect']['b7']+=1
        with self.assertRaises(ValueError):s.sign('POST','https://example.test/menu','{}')

    def test_one_refresh_then_reload_no_extra_http_and_usage_counted(self):
        b=bundle();s=FullSigner(b['device']); saved=[];requests=[]
        with tempfile.TemporaryDirectory() as tmp, patch('mtgsig.signer.time.time',return_value=NOW/1000):
            def persist(device):saved.append(deepcopy(device))
            def send(wire):
                self.assertEqual(saved[-1][STATE]['pending_event'],s.dev[STATE]['pending_event'])
                requests.append(wire);return Reply()
            kw=dict(account_id=44,session_id=68,persist=persist,send=send,journal_root=tmp,clock=lambda:NOW/1000)
            result=ensure_fingerprint(s,b,**kw);self.assertEqual(result['status'],'refreshed')
            restored=FullSigner(saved[-1]);kw['clock']=lambda:(NOW+10)/1000
            self.assertEqual(ensure_fingerprint(restored,b,**kw)['status'],'fresh');self.assertEqual(len(requests),1)
            rows=json.loads((Path(tmp)/'44/usage.json').read_text())
            self.assertEqual([(r['endpoint'],r['sent'],r['outcome']) for r in rows],[('fingerprintInfo',1,'success')])

    def test_network_failure_preserves_a7_and_accounts_attempt(self):
        b=bundle();s=FullSigner(b['device']);old=s.a7
        with tempfile.TemporaryDirectory() as tmp, patch('mtgsig.signer.time.time',return_value=NOW/1000):
            def send(wire):raise TimeoutError()
            with self.assertRaises(TimeoutError):
                ensure_fingerprint(s,b,account_id=44,session_id=68,persist=lambda _:None,send=send,journal_root=tmp,clock=lambda:NOW/1000)
            self.assertEqual(s.a7,old);self.assertEqual(refresh_status(s.dev,NOW+100),'backoff')
            rows=json.loads((Path(tmp)/'44/usage.json').read_text())
            self.assertEqual([(r['sent'],r['outcome']) for r in rows],[(1,'transport_error')])

    def test_persist_failure_never_dispatches(self):
        b=bundle();s=FullSigner(b['device']);sent=[]
        with tempfile.TemporaryDirectory() as tmp, patch('mtgsig.signer.time.time',return_value=NOW/1000):
            def persist(_):raise OSError()
            with self.assertRaises(OSError):ensure_fingerprint(s,b,account_id=44,session_id=68,persist=persist,send=lambda w:sent.append(w),journal_root=tmp,clock=lambda:NOW/1000)
            self.assertEqual(sent,[])

    def test_daily_report_limit_survives_new_journal(self):
        with tempfile.TemporaryDirectory() as tmp:
            j=ReportJournal(44,68,tmp)
            for i in range(96):j.reserve(NOW)
            j.close();j=ReportJournal(44,69,tmp)
            try:
                with self.assertRaises(FingerprintRefreshBlocked):j.reserve(NOW+1000)
            finally:j.close()


class WorkerRefreshIntegrationTests(unittest.TestCase):
    def test_mysql_worker_refresh_precedes_business_and_uses_new_identity(self):
        from unittest.mock import Mock
        from farm.collection.worker import Worker
        from farm.accounts.importer import prepare_bundle
        from tests.collection.test_mysql_farm import native_bundle
        b,_,_=prepare_bundle(native_bundle())
        b['device']=bundle()['device']
        b['request']['headers'].update(region='BR',cityid='102',appid='517',userid=str(b['identity']['userid']))
        store=Mock();store.unseal.return_value=b
        w=Worker(store);w.save_state=Mock();w.mark_sent=Mock();w._release_locks=Mock()
        w.durable_finish=Mock(return_value={'outcome':'success'})
        claim={'account':{'account_id':44,'id':68},'task':{'id':1,'endpoint':'shopInfo','shop_id':'1','latitude':'-1','longitude':'-2','city_id':'3'},'connection':Mock(),'locks':[],'attempt_id':'synthetic'}
        def post(url,**kwargs):
            self.assertEqual(json.loads(kwargs['headers']['mtgsig'])['a7'],'server-XID')
            self.assertEqual(w.save_state.call_args.args[1]['device']['a7'],'server-XID')
            return Reply(body={'code':0,'data':{'shopId':'1','name':'shop'}})
        with tempfile.TemporaryDirectory() as tmp, patch('farm.accounts.fingerprint.ROOT',Path(tmp)), patch('requests.Session.send',return_value=Reply()) as reporting, patch('requests.Session.post',side_effect=post) as business:
            w.execute(claim)
        reporting.assert_called_once();business.assert_called_once();w.mark_sent.assert_called_once()
        self.assertEqual(w.durable_finish.call_args.kwargs['response']['code'],0)
        self.assertNotIn('error',w.durable_finish.call_args.kwargs)

    def test_mysql_refresh_rejection_never_sends_business(self):
        from unittest.mock import Mock
        from farm.collection.worker import Worker
        from farm.accounts.importer import prepare_bundle
        from tests.collection.test_mysql_farm import native_bundle
        b,_,_=prepare_bundle(native_bundle());b['device']=bundle()['device']
        b['request']['headers'].update(region='BR',cityid='102',appid='517',userid=str(b['identity']['userid']))
        store=Mock();store.unseal.return_value=b
        w=Worker(store);w.save_state=Mock();w.mark_sent=Mock();w._release_locks=Mock();w.durable_finish=Mock()
        claim={'account':{'account_id':44,'id':68},'task':{'id':1,'endpoint':'shopInfo','shop_id':'1','latitude':'-1','longitude':'-2','city_id':'3'},'connection':Mock(),'locks':[],'attempt_id':'synthetic'}
        with tempfile.TemporaryDirectory() as tmp, patch('farm.accounts.fingerprint.ROOT',Path(tmp)), patch('requests.Session.send',return_value=Reply(status=403)), patch('requests.Session.post') as business:
            w.execute(claim)
        business.assert_not_called();w.mark_sent.assert_not_called()
        self.assertFalse(w.durable_finish.call_args.kwargs['sent'])
        self.assertEqual(w.durable_finish.call_args.kwargs['error'],'FingerprintRefreshBlocked')
        self.assertIn(44,w.fingerprint_wait_until)



if __name__ == '__main__':unittest.main()
