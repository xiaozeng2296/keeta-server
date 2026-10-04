"""Final-byte signing, real token generation, and failure/reload boundaries."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, Mock, patch
from urllib.parse import parse_qs, urlsplit

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

from farm import fullsign as fs
from farm.request_freshness import refresh_request
from mtgsig import incognia_token as codec
from mtgsig.mtg_crypto import fingerprint_encrypt
from tests.test_collection_refresh import identity
import keeta_rpc as rpc
import crawl_keeta as CK


class RequestFreshnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private = RSA.generate(2048)
        cls.algorithm = {'format':0,'public_key_pem':cls.private.public_key().export_key().decode(),
                         'hmac_key_hex':'12'*32,'application_id':'test-application','sdk_code':62300}

    def setUp(self):
        self.storage = identity()
        self.storage.update(request_dynamic_mode='fresh',
            incognia={'enabled':True,'enabled_regions':['BR'],'algorithm':self.algorithm},
            incognia_state={'installation_id':'TEST-INSTALLATION','initialization_counter':3,
                            'initialized_at_ms':1790732100000,'request_counter':40})
        self.url='https://example.test/detail?x=a%2Fb&__reqTraceID=OLD&blank='
        self.headers={'region':'BR','uuid':'0'*64,'csecuuid':'0'*64,'token':'TEST-LOGIN',
                      'appsession':'TEST-SESSION','incog-token':'STALE-CAPTURE',
                      'm-shark-traceid':'5172'+'0'*64+'ABCDEF1790732175000.000000ABCDEF'}
        self.fp={'I39':'1790732174767.976','I41':'observed-memory','I44':'observed-cpu'}
        self.body=json.dumps({'shopId':'1','spuId':2,'fingerPrint':fingerprint_encrypt(self.fp)})

    def decode_token(self, token):
        key=PKCS1_OAEP.new(self.private,hashAlgo=SHA256).decrypt(codec.split(token).wrapped_key)
        return codec.decode_with_session_key(token,session_key=key,hmac_key=bytes.fromhex(self.algorithm['hmac_key_hex']))

    def test_refreshes_only_request_fields_preserving_account_and_measurements(self):
        original=(self.url,deepcopy(self.headers),self.body)
        first=refresh_request(*original,self.storage,timestamp_ms=1790732176000.123)
        second=refresh_request(*original,self.storage,timestamp_ms=1790732177000.456)
        for ordinal,(url,headers,body) in enumerate((first,second)):
            self.assertIn('x=a%2Fb',url);self.assertTrue(url.endswith('blank='))
            self.assertNotEqual(parse_qs(urlsplit(url).query)['__reqTraceID'],['OLD'])
            for k in ('token','appsession','uuid','csecuuid'):self.assertEqual(headers[k],self.headers[k])
            plain=rpc.op_fp_decrypt({'fingerprint':json.loads(body)['fingerPrint']})['plain_json']
            self.assertEqual({k:v for k,v in plain.items() if k!='I39'}, {k:v for k,v in self.fp.items() if k!='I39'})
            self.assertEqual(plain['I39'],['1790732176000.123','1790732177000.456'][ordinal])
            decoded=self.decode_token(headers['incog-token'])
            self.assertEqual(decoded['59'],40+ordinal)
            self.assertEqual(decoded['60'],1790732176000+ordinal*1000)
        self.assertNotEqual(first[0],second[0]);self.assertNotEqual(first[1]['m-shark-traceid'],second[1]['m-shark-traceid'])
        self.assertNotEqual(first[1]['incog-token'],second[1]['incog-token'])
        self.assertEqual(self.storage['incognia_state']['request_counter'],42)
        self.assertEqual((self.url,self.headers,self.body),original)

    def test_missing_state_and_malformed_fingerprint_stop_before_sending(self):
        for mutate in ('missing-config','missing-state','bad-fingerprint'):
            with self.subTest(mutate=mutate):
                dev=deepcopy(self.storage);body=self.body
                if mutate=='missing-config': del dev['incognia']
                if mutate=='missing-state': del dev['incognia_state']
                if mutate=='bad-fingerprint': body='{"fingerPrint":"broken"}'
                with self.assertRaises(ValueError):refresh_request(self.url,self.headers,body,dev,timestamp_ms=1790732176000)

    def test_signed_bytes_match_sent_bytes_and_reserved_state_survives_each_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'identity.json';path.write_text(json.dumps(self.storage))
            signer=fs.FullSigner(path);session=Mock();response=Mock(status_code=200);response.json.return_value={'code':0}
            sent=[]
            def post(url,**kwargs):
                persisted=json.loads(path.read_text());headers=kwargs['headers'];body=kwargs['data'].decode();mt=json.loads(headers['mtgsig'])
                token=self.decode_token(headers['incog-token']);self.assertEqual(persisted['incognia_state']['request_counter'],token['59']+1)
                a5=json.loads(fs.decode_a5(mt['a5'],mt['a1'],mt['a3'],mt['a4'])[0]);expected=mt.pop('a2')
                self.assertEqual(expected,fs.compute_a2('POST',url,body,json.dumps(mt,separators=(',',':')),mt['a1'],168,sign_sequence=a5['b2']))
                sent.append((url,body,token['59']));return response
            session.post.side_effect=post
            with patch('farm.fullsign.time.time',return_value=1790732235):
                CK._post_signed(signer,self.url,self.headers,self.body,session=session)
            # Signing fails AFTER Incognia reserved the next counter.
            signer=fs.FullSigner(path)
            with patch.object(signer,'sign',side_effect=RuntimeError('synthetic')),self.assertRaises(RuntimeError):
                CK._post_signed(signer,self.url,self.headers,self.body,session=session)
            self.assertEqual(json.loads(path.read_text())['incognia_state']['request_counter'],42)
            # Token encryption itself fails after reservation.
            signer=fs.FullSigner(path)
            with patch.object(codec,'encode',side_effect=RuntimeError('synthetic')),self.assertRaises(ValueError):
                CK._post_signed(signer,self.url,self.headers,self.body,session=session)
            self.assertEqual(json.loads(path.read_text())['incognia_state']['request_counter'],43)
            signer=fs.FullSigner(path)
            with patch('farm.fullsign.time.time',return_value=1790732236):
                CK._post_signed(signer,self.url,self.headers,self.body,session=session)
            self.assertEqual([x[2] for x in sent],[40,43])
            session.post.side_effect=OSError('transport failure');signer=fs.FullSigner(path)
            with self.assertRaises(OSError):CK._post_signed(signer,self.url,self.headers,self.body,session=session)
            self.assertEqual(json.loads(path.read_text())['incognia_state']['request_counter'],45)
            self.assertEqual(self.headers['incog-token'],'STALE-CAPTURE')

    def test_import_preserves_explicit_generation_and_consumes_own_installation_counter(self):
        from farm.mysql_import import prepare_bundle
        from tests.test_mysql_farm import MysqlFarmTests
        bundle=MysqlFarmTests().native_bundle()
        bundle['device']=deepcopy(self.storage)
        bundle['device']['incognia_mode']='generate'
        prepared,status,_=prepare_bundle(bundle)
        self.assertEqual(status,'ready_generated_incognia')
        signer=fs.FullSigner(prepared['device'])
        _,headers,_=signer.prepare_request(self.url,self.headers,self.body)
        self.assertNotEqual(headers['incog-token'],'STALE-CAPTURE')
        self.assertEqual(self.decode_token(headers['incog-token'])['59'],40)
        self.assertEqual(signer.persist_counter()['incognia_state']['request_counter'],41)
        self.assertEqual(bundle['device']['incognia_state']['request_counter'],40)

    def test_captured_mode_keeps_parity_and_does_not_consume_incognia(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'id.json';self.storage['request_dynamic_mode']='captured';path.write_text(json.dumps(self.storage))
            signer=fs.FullSigner(path)
            self.assertEqual(signer.prepare_request(self.url,self.headers,self.body),(self.url,self.headers,self.body))
            self.assertEqual(signer.dev['incognia_state']['request_counter'],40)

    def test_incomplete_import_remains_needs_material_without_signing_mode(self):
        from farm.mysql_import import import_bundle
        bundle={'identity':{'token':'SYNTHETIC-INCOMPLETE'}}
        store=MagicMock();store.rows.return_value=[]
        store.seal.return_value=('synthetic-key',b'synthetic-sealed')
        cursor=store.transaction.return_value.__enter__.return_value
        cursor.fetchone.side_effect=[{'id':1,'active_session_id':None},{'id':2}]
        cursor.rowcount=1
        self.assertEqual(import_bundle(store,bundle,'incomplete','test'),(1,2,'needs_material'))
        prepared=store.seal.call_args.args[0]
        self.assertEqual(prepared['device'],{})
        self.assertEqual(set(prepared['material_reasons'].values()),{'missing_signing_device'})
        insert=next(c for c in cursor.execute.call_args_list if c.args[0].startswith('INSERT IGNORE INTO account_sessions'))
        self.assertEqual(insert.args[1][7],'captured')


if __name__=='__main__': unittest.main()
