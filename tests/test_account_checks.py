from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import zlib
from unittest.mock import Mock, MagicMock, patch
from urllib.parse import urlsplit

from farm import account_checks as A
from farm.mysql_import import prepare_bundle
from farm.mysql_worker import Worker
from tests.test_mysql_farm import MysqlFarmTests



def info(status=3):return {'code':0,'data':{'shopId':'1','name':'shop','status':status},'_http_status':200}
def menu():return {'code':0,'data':{'shopCategoryList':[{'shopCategoryId':10,'spuIdList':[7,8],
    'spuList':[{'spuId':7,'name':'custom','haveMultiSpecs':1}]}]},'_http_status':200}
def render():return {'code':0,'data':{'shopCategoryList':[{'shopCategoryId':10,'spuList':[{'spuId':8,'name':'ordinary','haveMultiSpecs':0}]}]},'_http_status':200}


class AccountChecksTests(unittest.TestCase):
    def test_signature_check_uses_wire_bytes_and_keeps_source_state(self):
        bundle,_,_=prepare_bundle(MysqlFarmTests().native_bundle())
        bundle['device']['base_collect']['b16']='[0,0,0],[1,2,3],[0,0,0],0'
        original=deepcopy(bundle)
        rows=A.sign_check(bundle,{'shop_id':'1','latitude':'-1','longitude':'-2','city_id':'3'})
        self.assertEqual(len(rows),4)
        self.assertTrue(all(r['signature_valid'] for r in rows),rows)
        self.assertEqual([r['endpoint'] for r in rows if r['render_b16_adapted']],['productRender'])
        self.assertEqual(original,bundle)

    def test_flow_uses_fresh_render_and_one_detail_but_skips_closed(self):
        for status,expected in ((3,4),(4,3)):
            calls=[]
            def send(ep,payload,target):
                calls.append((ep,payload,target))
                data={'shopInfo':info(status),'productList':menu(),'productRender':render(),
                      'productSpecifics':{'code':0,'data':{'spuId':7,'name':'custom'}}}[ep]
                return {'sent':True,'status':'success','http':200},data
            rows=A.check_flow(send)
            self.assertEqual(len(calls),expected)
            self.assertEqual(calls[2][1],{'shopCategoryList':[{'shopCategoryId':10,'spuIdList':[8]}]})
            if status==3:self.assertEqual(calls[3][2],'7')
            else:self.assertEqual(rows[-1]['status'],'skipped_closed')

    def test_failed_prerequisite_never_claims_untested_endpoints_are_bad(self):
        send=Mock(return_value=({'sent':True,'status':'rejected','http':403},None))
        rows=A.check_flow(send)
        send.assert_called_once()
        self.assertTrue(all(r['status']=='shop_info_not_validated' and not r['sent'] for r in rows[1:]))

    def test_known_inline_menu_can_still_exercise_render(self):
        value=menu();value['data']['shopCategoryList'][0]['spuIdList']=[7]
        payload,details=A.choose_menu_targets(value)
        self.assertEqual(payload['shopCategoryList'][0]['spuIdList'],[7]);self.assertEqual(details,['7'])

    def test_active_session_is_always_loaded_from_authoritative_store(self):
        store=Mock();store.rows.return_value=[{'id':9}];store.unseal.return_value={'current':True}
        self.assertEqual(A.load_account(store,1),({'current':True},'database'))

    def test_database_verification_can_preserve_cooldown_without_changing_default(self):
        for preserve in (False,True):
            store=MagicMock();worker=Mock()
            store.run.return_value=1;store.shop.return_value=2
            store.transaction.return_value.__enter__.return_value.fetchone.return_value={'id':3}
            store.rows.return_value=[{'response_blob':zlib.compress(json.dumps(info()).encode())}]
            store.failure_response.return_value=None
            worker.diagnose.return_value=[{'reason':'eligible'}]
            worker.claim.return_value={'attempt_id':4,'account':{'id':5}}
            worker.execute.return_value={'sent':True,'http':200,'code':0,'outcome':'success'}
            options={'clear_verified':False} if preserve else {}
            with patch.object(A,'Worker',return_value=worker),patch('farm.account_controls.clear_database_cooldown',return_value=True) as clear:
                checker=A.DatabaseProbe(store,1,{'shop_id':'1','latitude':'-1','longitude':'-2','city_id':'3'},recovery=True,**options)
                row,data=checker.send('shopInfo',{},'')
                self.assertEqual(row['status'],'success');self.assertEqual(data['data']['shopId'],'1')
                worker.execute.assert_called_once()
                if preserve:clear.assert_not_called();self.assertNotIn('cooldown_cleared',row)
                else:clear.assert_called_once();self.assertTrue(row['cooldown_cleared'])

    def test_paused_probe_requires_scoped_claim(self):
        worker=Worker(Mock())
        for kwargs in ({},{'allow_probe':True},{'allow_probe':True,'account_id':1}):
            with self.assertRaises(ValueError):worker.claim(1,allow_paused=True,**kwargs)


if __name__=='__main__':unittest.main()
