"""Opt-in MySQL tests using disposable synthetic records, never business HTTP."""
from copy import deepcopy
from datetime import timedelta
import json
import os
import unittest
import uuid
from unittest.mock import Mock,patch

from farm.storage.mysql import Store,utcnow,business_day,compact,digest,ENDPOINTS
from farm.accounts.importer import import_bundle
from farm.collection.worker import Worker
from tests.protocol.test_collection_refresh import identity
from mtgsig.mtg_crypto import fingerprint_encrypt


@unittest.skipUnless(os.environ.get('KEETA_MYSQL_TESTS')=='1','explicit MySQL integration switch required')
class MysqlIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.store=Store(os.environ['KEETA_MYSQL_TEST_CONFIG']);self.tag='validation-'+str(uuid.uuid4());self.aid=None;self.rid=None;self.extra_runs=[]
        if not self.store.config.get('test_database') or not self.store.config['database'].startswith('keeta_test_'):
            raise RuntimeError('isolated test database required')
        user_id=str(uuid.uuid4().int)
        dev=identity();headers={'host':'example.test','token':self.tag,'userid':user_id,'uuid':'0'*64,'csecuuid':'0'*64,'region':'BR','incog-token':'TEST-CAPTURED'}
        url='https://example.test/api/v1/shop/productList?userid='+user_id
        request={'url':url,'headers':headers,'body':{'shopId':'1','fingerPrint':fingerprint_encrypt({'I39':'1790732174767.976','I41':'observed','I44':'observed'})}}
        bundle={'identity':{k:headers[k] for k in ('token','userid','uuid','csecuuid')},'device':dev,'request':request,
                'templates':{'/api/v1/shop/productList':dict(request,method='POST')},'proxy':None}
        self.aid,self.sid,_=import_bundle(self.store,bundle,self.tag,self.tag)
        self.rid=self.store.run(self.tag,'validation',self.tag)
        with self.store.transaction() as c:
            c.execute("UPDATE accounts SET identity_status='observed' WHERE id=%s",(self.aid,))
            self.store.observe(c,self.sid,'productList','available',utcnow(),200,0,'validation')
            self.job=self.store.shop(c,self.rid,'1','-1','-2')
            self.store.enqueue(c,self.job,'productList')
        self.worker=Worker(self.store);self.claim=None

    def tearDown(self):
        if self.claim:
            try:self.worker._release_locks(self.claim['connection'],self.claim['locks'])
            except Exception:pass
        if self.aid:
            with self.store.transaction() as c:
                keys=[digest(['probe',[self.aid,e,str(business_day(utcnow()))]]) for e in ENDPOINTS]
                c.execute('SELECT id FROM collection_runs WHERE run_key IN ('+','.join(['%s']*len(keys))+')',keys)
                runs=[r['id'] for r in c.fetchall()]+([self.rid] if self.rid else [])+self.extra_runs
                c.execute('DELETE FROM task_results WHERE account_id=%s',(self.aid,))
                c.execute('DELETE FROM request_attempts WHERE account_id=%s',(self.aid,))
                for rid in runs:
                    c.execute('DELETE FROM executions WHERE run_id=%s',(rid,))
                    c.execute('DELETE t FROM tasks t JOIN shop_jobs j ON j.id=t.shop_job_id WHERE j.run_id=%s',(rid,))
                    c.execute('DELETE FROM shop_jobs WHERE run_id=%s',(rid,))
                    c.execute('DELETE FROM collection_runs WHERE id=%s',(rid,))
                for table in ('daily_usage','budget_policies','experiment_members','account_profiles','account_tags'):c.execute('DELETE FROM '+table+' WHERE account_id=%s',(self.aid,))
                c.execute('DELETE c FROM capabilities c JOIN account_sessions s ON s.id=c.session_id WHERE s.account_id=%s',(self.aid,))
                c.execute('DELETE FROM account_sessions WHERE account_id=%s',(self.aid,))
                c.execute('DELETE FROM accounts WHERE id=%s',(self.aid,))

    def test_fingerprint_wait_releases_business_reservation_without_disabling_endpoint(self):
        import time
        self.claim=self.worker.claim(self.rid,self.aid);self.assertIsNotNone(self.claim)
        result=self.worker.finish(self.claim,response={'_maintenance_retry_at':time.time()+60},error='FingerprintRefreshBlocked',sent=False)
        self.assertEqual(result['outcome'],'maintenance_wait')
        row=self.store.rows('SELECT attempts,state,not_before FROM tasks WHERE id=%s',(self.claim['task']['id'],))[0]
        self.assertEqual((row['attempts'],row['state']),(0,'retry_wait'))
        self.assertGreater(row['not_before'],utcnow())
        budget=self.store.rows('SELECT used_count,reserved_count FROM daily_usage WHERE account_id=%s AND endpoint=%s',(self.aid,'productList'))[0]
        self.assertEqual((budget['used_count'],budget['reserved_count']),(0,0))
        capability=self.store.rows('SELECT state FROM capabilities WHERE session_id=%s AND endpoint=%s',(self.sid,'productList'))[0]
        self.assertEqual(capability['state'],'available')

    def test_success_expands_queue_and_send_has_reserved_crypto_state(self):
        self.claim=self.worker.claim(self.rid,self.aid);self.assertIsNotNone(self.claim)
        response=Mock(status_code=200,headers={})
        response.json.return_value={'code':0,'data':{'shopCategoryList':[{'shopCategoryId':1,'spuIdList':[10,11,12],
            'spuList':[{'spuId':10,'name':'Custom','haveMultiSpecs':1},{'spuId':11,'name':'Plain','haveMultiSpecs':0}]}]}}
        seen=[]
        def post(_session,url,**kwargs):
            row=self.store.rows('SELECT * FROM account_sessions WHERE id=%s',(self.sid,))[0]
            bundle=self.store.unseal(row);self.assertEqual(bundle['device']['sign_sequence'],47)
            attempts=self.store.rows('SELECT state FROM request_attempts WHERE account_id=%s',(self.aid,))
            self.assertEqual(attempts[0]['state'],'sent');self.assertEqual(kwargs['headers']['incog-token'],'TEST-CAPTURED')
            self.assertFalse(kwargs['allow_redirects']);seen.append(kwargs);return response
        with patch('requests.Session.post',autospec=True,side_effect=post):result=self.worker.execute(self.claim)
        self.claim=None
        self.assertEqual(result['outcome'],'success');self.assertEqual(len(seen),1)
        rows=self.store.rows('SELECT endpoint,state FROM tasks WHERE shop_job_id=%s',(self.job,))
        self.assertEqual({(r['endpoint'],r['state']) for r in rows},{('productList','succeeded'),('productRender','pending'),('productSpecifics','pending')})
        stat=self.store.rows('SELECT used_count,reserved_count FROM daily_usage WHERE account_id=%s',(self.aid,))[0]
        self.assertEqual(stat,{'used_count':1,'reserved_count':0})

    def test_response_journal_recovers_database_outage_without_second_http(self):
        import tempfile,pymysql
        from pathlib import Path
        self.claim=self.worker.claim(self.rid,self.aid)
        response=Mock(status_code=200,headers={});response.json.return_value={'code':0,'data':{'shopCategoryList':[]}}
        with tempfile.TemporaryDirectory() as tmp,patch.object(Worker,'_journal_folder',return_value=Path(tmp)):
            with patch.object(self.worker,'finish',side_effect=pymysql.err.OperationalError(2013,'synthetic disconnect')),patch('farm.collection.worker.time.sleep'),patch('requests.Session.post',return_value=response) as post:
                with self.assertRaises(pymysql.err.OperationalError):self.worker.execute(self.claim)
                self.assertEqual(post.call_count,1)
            self.claim=None
            with patch('requests.Session.post') as post:
                self.assertEqual(Worker(self.store).replay_pending(self.rid),1)
                self.assertEqual(Worker(self.store).replay_pending(self.rid),0)
                post.assert_not_called()
            self.assertFalse(list(Path(tmp).glob('*.json')))
        self.assertEqual(self.store.rows('SELECT state,outcome FROM request_attempts WHERE account_id=%s',(self.aid,))[0],{'state':'done','outcome':'success'})
        self.assertEqual(self.store.rows('SELECT used_count,reserved_count FROM daily_usage WHERE account_id=%s',(self.aid,))[0],{'used_count':1,'reserved_count':0})

    def test_database_failure_before_send_preserves_account_capability(self):
        import pymysql
        self.claim=self.worker.claim(self.rid,self.aid)
        with patch.object(self.worker,'save_state',side_effect=pymysql.err.OperationalError(2013,'synthetic disconnect')),patch('requests.Session.post') as post:
            with self.assertRaises(pymysql.err.OperationalError):self.worker.execute(self.claim)
            post.assert_not_called()
        self.claim=None
        cap=self.store.rows("SELECT state FROM capabilities WHERE session_id=%s AND endpoint='productList'",(self.sid,))[0]
        self.assertEqual(cap['state'],'available')
        self.assertEqual(self.store.rows('SELECT state FROM request_attempts WHERE account_id=%s',(self.aid,))[0]['state'],'reserved')

    def test_repeated_commit_ack_loss_keeps_batch_counts_budget_and_results_exact(self):
        import tempfile,pymysql
        from pathlib import Path
        from farm.collection.executions import create_execution,ExecutionManager
        for n in range(2,13):
            with self.store.transaction() as c:
                shop=self.store.shop(c,self.rid,str(n),'-1','-2');self.store.enqueue(c,shop,'productList')
        execution=create_execution(self.store,self.rid,'test',[self.aid],max_requests=12,delay=0,auto_resume=True)
        manager=ExecutionManager(self.store)
        with self.store.transaction() as c:
            c.execute("UPDATE executions SET state='running',owner=%s WHERE id=%s",(manager.owner,execution['execution_id']))
        job=self.store.rows('SELECT * FROM executions WHERE id=%s',(execution['execution_id'],))[0]
        response=Mock(status_code=200,headers={});response.json.return_value={'code':0,'data':{'shopCategoryList':[]}}
        original_finish=Worker.finish;seen=set();injected=[]
        def lose_ack(worker,claim,*args,**kwargs):
            result=original_finish(worker,claim,*args,**kwargs)
            if claim['attempt_id'] not in seen:
                seen.add(claim['attempt_id'])
                if len(seen)%3==0:
                    injected.append(claim['attempt_id'])
                    raise pymysql.err.OperationalError(2013,'synthetic committed but acknowledgement lost')
            return result
        with tempfile.TemporaryDirectory() as tmp,patch('farm.collection.executions.EXPORT_ROOT',Path(tmp)),patch.object(Worker,'_journal_folder',return_value=Path(tmp)/'journal'),patch.object(Worker,'finish',lose_ack),patch('requests.Session.post',return_value=response) as post,patch('farm.collection.worker.time.sleep'):
            manager.execute(job)
            self.assertEqual(post.call_count,12);self.assertEqual(len(injected),4)
            self.assertFalse(list((Path(tmp)/'journal').glob('*.json')))
        row=self.store.rows('SELECT processed,sent,valid_count FROM executions WHERE id=%s',(execution['execution_id'],))[0]
        self.assertEqual(row,{'processed':12,'sent':12,'valid_count':12})
        self.assertEqual(self.store.rows('SELECT used_count,reserved_count FROM daily_usage WHERE account_id=%s',(self.aid,))[0],{'used_count':12,'reserved_count':0})
        self.assertEqual(self.store.rows('SELECT COUNT(*) n FROM task_results WHERE account_id=%s',(self.aid,))[0]['n'],12)

    def test_budget_and_installation_lock_prevent_duplicate_claim(self):
        with self.store.transaction() as c:
            c.execute("UPDATE budget_policies SET work_limit=1,hard_limit=1 WHERE account_id=%s AND endpoint='productList'",(self.aid,))
            job=self.store.shop(c,self.rid,'2','-1','-2');self.store.enqueue(c,job,'productList')
        self.claim=self.worker.claim(self.rid,self.aid);self.assertIsNotNone(self.claim)
        self.assertIsNone(Worker(self.store).claim(self.rid,self.aid))
        self.worker.mark_sent(self.claim);self.worker.finish(self.claim,error='Timeout',sent=True)
        self.worker._release_locks(self.claim['connection'],self.claim['locks']);self.claim=None
        self.assertIsNone(Worker(self.store).claim(self.rid,self.aid))

    def test_expired_reservation_is_recovered_without_refunding_uncertain_send(self):
        self.claim=self.worker.claim(self.rid,self.aid);self.assertIsNotNone(self.claim)
        with self.store.transaction() as c:c.execute('UPDATE tasks SET lease_until=%s WHERE id=%s',(utcnow()-timedelta(seconds=1),self.claim['task']['id']))
        self.worker._release_locks(self.claim['connection'],self.claim['locks']);self.claim=None
        self.worker.recover()
        r=self.store.rows('SELECT state FROM request_attempts WHERE account_id=%s',(self.aid,))[0]
        self.assertEqual(r['state'],'uncertain')
        self.assertEqual(self.store.rows('SELECT used_count,reserved_count FROM daily_usage WHERE account_id=%s',(self.aid,))[0],{'used_count':1,'reserved_count':0})
        self.assertEqual(self.store.rows('SELECT state,attempts FROM tasks WHERE shop_job_id=%s',(self.job,))[0],{'state':'retry_wait','attempts':1})

    def test_local_error_releases_request_budget_but_records_failure(self):
        self.claim=self.worker.claim(self.rid,self.aid)
        self.worker.finish(self.claim,error='ValueError',sent=False)
        usage=self.store.rows('SELECT used_count,reserved_count FROM daily_usage WHERE account_id=%s',(self.aid,))[0]
        self.assertEqual(usage,{'used_count':0,'reserved_count':0})
        self.assertEqual(self.store.rows('SELECT state FROM tasks WHERE shop_job_id=%s',(self.job,))[0]['state'],'retry_wait')
        self.assertEqual(self.store.rows("SELECT state FROM capabilities WHERE session_id=%s AND endpoint='productList'",(self.sid,))[0]['state'],'needs_material')

    def test_worker_enforces_environment_ids_tags_and_unverified_probe(self):
        from farm.accounts.selection import set_profile
        set_profile(self.store,[self.aid],'test',['blue'])
        self.assertIsNone(self.worker.claim(self.rid,environment='production',account_ids=[self.aid]))
        self.assertIsNone(self.worker.claim(self.rid,environment='test',account_ids=[]))
        self.assertIsNone(self.worker.claim(self.rid,environment='test',account_ids=[self.aid],tags=['red']))
        with self.store.transaction() as c:
            c.execute("UPDATE capabilities SET state='unknown' WHERE session_id=%s AND endpoint='productList'",(self.sid,))
            c.execute("UPDATE accounts SET identity_status='unverified' WHERE id=%s",(self.aid,))
        self.claim=self.worker.claim(self.rid,environment='test',account_ids=[self.aid],tags=['blue'])
        self.assertIsNotNone(self.claim)
        self.worker.finish(self.claim,error='SyntheticStop',sent=False)

    def test_probe_respects_cooldown_then_updates_capability_once(self):
        with self.store.transaction() as c:
            c.execute("UPDATE capabilities SET state='cooldown',not_before=%s WHERE session_id=%s AND endpoint='productList'",(utcnow()+timedelta(hours=1),self.sid))
        with patch('requests.Session.post') as post:
            self.assertEqual(self.worker.probe(self.aid,'productList')['status'],'cooldown');post.assert_not_called()
        with self.store.transaction() as c:
            c.execute("UPDATE capabilities SET not_before=%s WHERE session_id=%s AND endpoint='productList'",(utcnow()-timedelta(seconds=1),self.sid))
        response=Mock(status_code=200,headers={});response.json.return_value={'code':0,'data':{'shopCategoryList':[]}}
        with patch('requests.Session.post',return_value=response) as post:
            self.assertEqual(self.worker.probe(self.aid,'productList')['outcome'],'success')
            self.assertEqual(self.worker.probe(self.aid,'productList')['status'],'waiting_budget_or_already_probed')
            self.assertEqual(post.call_count,1)

    def test_account_info_probe_uses_get_and_checks_identity(self):
        row=self.store.rows('SELECT * FROM account_sessions WHERE id=%s',(self.sid,))[0]
        bundle=self.store.unseal(row);ident=bundle['identity']
        bundle['account_check_request']={'method':'GET','url':'https://passport-eu.mykeeta.com/api/user/v1/info/homepage',
                                         'headers':{'host':'passport-eu.mykeeta.com','token':ident['token']},'body':''}
        bundle['templates']={}
        _,self.sid,_=import_bundle(self.store,bundle,self.tag,self.tag+'-get')
        response=Mock(status_code=200,headers={});response.json.return_value={'code':0,'user':{'idStr':ident['userid']}}
        with patch('requests.Session.get',return_value=response) as get,patch('requests.Session.post') as post:
            self.assertEqual(self.worker.probe(self.aid,'accountInfo')['outcome'],'success')
            get.assert_called_once();post.assert_not_called()
        self.assertEqual(self.store.rows('SELECT identity_status FROM accounts WHERE id=%s',(self.aid,))[0]['identity_status'],'verified')

    def test_material_upgrade_keeps_session_counters_refusals_and_budget(self):
        from farm.accounts.importer import refresh_account_material
        row=self.store.rows('SELECT * FROM account_sessions WHERE id=%s',(self.sid,))[0]
        bundle=self.store.unseal(row);ident=bundle['identity'];sequence=bundle['device']['sign_sequence']
        bundle['account_check_request']={'method':'GET','url':'https://passport-eu.mykeeta.com/api/user/v1/info/homepage',
                                         'headers':{'host':'passport-eu.mykeeta.com','token':ident['token']},'body':''}
        key,blob=self.store.seal(bundle)
        until=utcnow()+timedelta(hours=1)
        with self.store.transaction() as c:
            c.execute('UPDATE account_sessions SET encryption_key_id=%s,credential_blob=%s WHERE id=%s',(key,blob,self.sid))
            c.execute("UPDATE capabilities SET state='cooldown',not_before=%s WHERE session_id=%s AND endpoint='productList'",(until,self.sid))
            c.execute("INSERT INTO daily_usage(account_id,business_date,endpoint,used_count) VALUES(%s,%s,'productList',7)",(self.aid,business_day(utcnow())))
        result=refresh_account_material(self.store,self.aid)
        self.assertIn('accountInfo',result['endpoints'])
        row=self.store.rows('SELECT * FROM account_sessions WHERE id=%s',(self.sid,))[0]
        self.assertEqual(self.store.unseal(row)['device']['sign_sequence'],sequence)
        self.assertEqual(self.store.rows('SELECT active_session_id FROM accounts WHERE id=%s',(self.aid,))[0]['active_session_id'],self.sid)
        self.assertEqual(self.worker.diagnose([self.aid],['productList'])[0]['reason'],'cooldown')
        self.assertEqual(self.store.rows("SELECT used_count FROM daily_usage WHERE account_id=%s AND endpoint='productList'",(self.aid,))[0]['used_count'],7)
        self.assertEqual(self.worker.diagnose([self.aid],['accountInfo'])[0]['reason'],'eligible')

    def test_transport_failure_is_not_account_cooldown(self):
        import requests
        self.claim=self.worker.claim(self.rid,self.aid)
        with patch('requests.Session.post',side_effect=requests.Timeout()):result=self.worker.execute(self.claim)
        self.claim=None
        self.assertEqual(result['outcome'],'transport_error');self.assertTrue(result['sent'])
        self.assertEqual(self.worker.diagnose([self.aid],['productList'])[0]['state'],'available')

    def test_refresh_at_last_attempt_preserves_one_claimable_retry(self):
        with self.store.transaction() as c:
            c.execute('UPDATE tasks SET max_attempts=1 WHERE shop_job_id=%s',(self.job,))
        self.claim=self.worker.claim(self.rid,self.aid);tid=self.claim['task']['id'];self.worker.mark_sent(self.claim)
        self.worker.finish(self.claim,{'_http_status':403},proxy_refreshed=True)
        self.worker._release_locks(self.claim['connection'],self.claim['locks']);self.claim=None
        row=self.store.rows('SELECT state,attempts,max_attempts FROM tasks WHERE id=%s',(tid,))[0]
        self.assertEqual(row,{'state':'retry_wait','attempts':1,'max_attempts':2})
        with self.store.transaction() as c:
            c.execute('UPDATE tasks SET not_before=%s WHERE id=%s',(utcnow()-timedelta(seconds=1),tid))
            c.execute("UPDATE capabilities SET not_before=%s WHERE session_id=%s AND endpoint='productList'",(utcnow()-timedelta(seconds=1),self.sid))
        self.assertIsNone(self.worker.claim(self.rid,self.aid,task_id=tid+1000000))
        self.claim=self.worker.claim(self.rid,self.aid,task_id=tid)
        self.assertIsNotNone(self.claim)
        self.worker.finish(self.claim,error='SyntheticStop',sent=False)

    def test_html_failure_is_saved_redacted_and_separate_from_delivery(self):
        import requests
        self.claim=self.worker.claim(self.rid,self.aid);attempt=self.claim['attempt_id']
        response=requests.Response();response.status_code=403;response.encoding='utf-8'
        response._content=b'<html>403 Forbidden token=PRIVATE-TOKEN</html>'
        response.headers={'Content-Type':'text/html','Server':'openresty','Set-Cookie':'PRIVATE-COOKIE'}
        response.request=requests.Request('POST','https://example.test',headers={'token':'PRIVATE-TOKEN'}).prepare()
        with patch('requests.Session.post',return_value=response):result=self.worker.execute(self.claim)
        self.claim=None;self.assertEqual(result['outcome'],'rejected')
        saved=self.store.failure_response(attempt)
        self.assertIn('403 Forbidden',saved['body']);self.assertNotIn('PRIVATE',json.dumps(saved))
        self.assertFalse(self.store.rows('SELECT id FROM task_results WHERE task_id=%s',(result['task_id'],)))
        with self.store.transaction() as c:c.execute('DELETE FROM request_attempts WHERE id=%s',(attempt,))
        self.assertIsNone(self.store.failure_response(attempt))

    def test_probe_cannot_send_again_by_changing_shop(self):
        response=Mock(status_code=200,headers={});response.json.return_value={'code':0,'data':{'shopCategoryList':[]}}
        with self.store.transaction() as c:other=self.store.shop(c,self.rid,'2','-1','-2')
        with patch('requests.Session.post',return_value=response) as post:
            self.assertEqual(self.worker.probe(self.aid,'productList',self.job)['outcome'],'success')
            self.assertEqual(self.worker.probe(self.aid,'productList',other)['status'],'waiting_budget_or_already_probed')
            self.assertEqual(post.call_count,1)

    def test_execution_freezes_selection_rejects_duplicate_and_exports_partial(self):
        from farm.collection.executions import create_execution,ExecutionManager,stop_execution
        import tempfile
        from pathlib import Path
        job=create_execution(self.store,self.rid,'test',[self.aid],max_requests=1,delay=0)
        with self.assertRaises(ValueError):create_execution(self.store,self.rid,'test',[self.aid])
        manager=ExecutionManager(self.store)
        with self.store.transaction() as c:
            c.execute("UPDATE executions SET state='running',owner=%s WHERE id=%s",(manager.owner,job['execution_id']))
        row=self.store.rows('SELECT * FROM executions WHERE id=%s',(job['execution_id'],))[0]
        response=Mock(status_code=200,headers={});response.json.return_value={'code':0,'data':{'shopCategoryList':[]}}
        with tempfile.TemporaryDirectory() as tmp,patch('farm.collection.executions.EXPORT_ROOT',Path(tmp)),patch('requests.Session.post',return_value=response):
            manager.execute(row)
            self.assertTrue((Path(tmp)/f'execution-{row["id"]}'/'delivery.zip').exists())
        final=self.store.rows('SELECT state,sent,valid_count FROM executions WHERE id=%s',(row['id'],))[0]
        self.assertEqual(final,{'state':'incomplete','sent':1,'valid_count':1})
        second=create_execution(self.store,self.rid,'test',[self.aid])
        stop_execution(self.store,second['execution_id'])
        self.assertEqual(self.store.rows('SELECT state FROM executions WHERE id=%s',(second['execution_id'],))[0]['state'],'stopped')


    def _enable_policy_endpoints(self):
        with self.store.transaction() as c:
            c.execute('UPDATE collection_runs SET settings=%s WHERE id=%s',(compact({'skip_closed_details':True}),self.rid))
            c.execute('UPDATE account_sessions SET endpoint_names=%s WHERE id=%s',(compact(list(ENDPOINTS)),self.sid))
            for e in ('shopInfo','productSpecifics','productRender'):
                self.store.observe(c,self.sid,e,'available',utcnow(),200,0,'validation')

    def test_worker_records_usage_and_exports_without_cost_metering(self):
        from farm.collection.executions import export_bundle
        import tempfile
        from pathlib import Path
        self.claim=self.worker.claim(self.rid,self.aid);attempt_id=self.claim['attempt_id']
        response=Mock(status_code=200,headers={})
        response.json.return_value={'code':0,'data':{'shopCategoryList':[]}}
        with patch('requests.Session.post',return_value=response):
            self.worker.execute(self.claim);self.claim=None
        row=self.store.rows('SELECT state,counts_budget,outcome FROM request_attempts WHERE id=%s',(attempt_id,))[0]
        self.assertEqual(row,{'state':'done','counts_budget':1,'outcome':'success'})
        with tempfile.TemporaryDirectory() as tmp:
            summary=export_bundle(self.store,self.rid,Path(tmp))
            self.assertFalse((Path(tmp)/'costs.json').exists())
            self.assertFalse((Path(tmp)/'costs.xlsx').exists())
            self.assertNotIn('costs',summary)

    def test_clash_assignment_preserves_budget_and_saved_route(self):
        from farm.network.proxy import assign_account_proxies
        original_get=self.store.get_setting;bindings=original_get('clash_node_bindings') or {}
        original=self.store.rows('SELECT * FROM account_sessions WHERE id=%s',(self.sid,))[0]
        bundle=self.store.unseal(original);bundle.update(proxy='http://user:password@gate.example:80',front_proxy=None,refresh_ipfoxy=False)
        key,blob=self.store.seal(bundle)
        with self.store.transaction() as c:c.execute('UPDATE account_sessions SET encryption_key_id=%s,credential_blob=%s WHERE id=%s',(key,blob,self.sid))
        def setting(name):
            if name=='clash_node_pool':return {'nodes':[{'name':'synthetic-node','proxy':'http://127.0.0.1:18999'},
                {'name':'synthetic-node-2','proxy':'http://127.0.0.1:18998'}]}
            return original_get(name)
        before=self.store.rows('SELECT * FROM daily_usage WHERE account_id=%s',(self.aid,))
        try:
            with patch.object(self.store,'get_setting',side_effect=setting):
                assigned=assign_account_proxies(self.store,[self.aid]);self.assertEqual(assigned[0]['node'],'synthetic-node')
                current=self.store.unseal(self.store.rows('SELECT * FROM account_sessions WHERE id=%s',(self.sid,))[0])
                self.assertEqual(current['proxy'],'http://127.0.0.1:18999');self.assertIsNone(current['front_proxy'])
                self.assertEqual(current['device'],bundle['device'])
                assign_account_proxies(self.store,[self.aid],node_name='synthetic-node-2')
                selected=self.store.unseal(self.store.rows('SELECT * FROM account_sessions WHERE id=%s',(self.sid,))[0])
                self.assertEqual(selected['proxy'],'http://127.0.0.1:18998')
                self.assertEqual(selected['device'],bundle['device'])
                assign_account_proxies(self.store,[self.aid],'saved')
                restored=self.store.unseal(self.store.rows('SELECT * FROM account_sessions WHERE id=%s',(self.sid,))[0])
                self.assertEqual(restored['proxy'],bundle['proxy']);self.assertNotIn('clash_node',restored)
                assign_account_proxies(self.store,[self.aid],'manual',proxy='new.example:80:new:password')
                manual=self.store.unseal(self.store.rows('SELECT * FROM account_sessions WHERE id=%s',(self.sid,))[0])
                self.assertEqual(manual['proxy'],'http://new:password@new.example:80')
                self.assertEqual(manual['device'],bundle['device'])
            self.assertEqual(self.store.rows('SELECT * FROM daily_usage WHERE account_id=%s',(self.aid,)),before)
        finally:self.store.set_setting('clash_node_bindings',bindings)
    def test_closed_menu_and_later_render_skip_details_without_spending_their_budget(self):
        from farm.delivery.export import export_run
        import tempfile
        from pathlib import Path
        self._enable_policy_endpoints()
        with self.store.transaction() as c:
            self.store.enqueue(c,self.job,'shopInfo')
            c.execute("UPDATE tasks SET state='succeeded' WHERE shop_job_id=%s AND endpoint='shopInfo'",(self.job,))
            self.store.result(c,self.job,self.aid,'shopInfo',{'code':0,'data':{'shopId':1,'name':'Closed shop','status':4}},utcnow())
        self.claim=self.worker.claim(self.rid,self.aid,['productList']);self.worker.mark_sent(self.claim)
        menu={'code':0,'data':{'shopCategoryList':[{'shopCategoryId':1,'spuIdList':[10,11],'spuList':[{'spuId':10,'name':'A','haveMultiSpecs':1}]}]}}
        self.worker.finish(self.claim,menu);self.worker._release_locks(self.claim['connection'],self.claim['locks']);self.claim=None
        self.assertIsNone(self.worker.claim(self.rid,self.aid,['productSpecifics']))
        self.claim=self.worker.claim(self.rid,self.aid,['productRender']);self.assertIsNotNone(self.claim);self.worker.mark_sent(self.claim)
        rendered={'code':0,'data':{'shopCategoryList':[{'shopCategoryId':1,'spuList':[{'spuId':11,'name':'B','haveMultiSpecs':1}]}]}}
        self.worker.finish(self.claim,rendered);self.worker._release_locks(self.claim['connection'],self.claim['locks']);self.claim=None
        rows=self.store.rows("SELECT state,last_reason,attempts FROM tasks WHERE shop_job_id=%s AND endpoint='productSpecifics'",(self.job,))
        self.assertEqual(len(rows),2);self.assertTrue(all(r=={'state':'skipped_closed','last_reason':'store_closed','attempts':0} for r in rows))
        self.assertEqual(self.store.rows("SELECT COUNT(*) n FROM request_attempts WHERE account_id=%s AND endpoint='productSpecifics'",(self.aid,))[0]['n'],0)
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'delivery.xlsx';summary=export_run(self.store,self.rid,path)
            report=json.loads(path.with_suffix('.coverage.json').read_text())['shops'][0]
            self.assertEqual(summary['complete_shop_jobs'],1);self.assertEqual(summary['items'],2)
            self.assertFalse(report['full_data_complete']);self.assertEqual(report['details_skip_reason'],'store_closed')
        from farm.collection.executions import create_execution,ExecutionManager
        job=create_execution(self.store,self.rid,'test',[self.aid],auto_resume=True,max_requests=5,delay=0)
        manager=ExecutionManager(self.store)
        with self.store.transaction() as c:c.execute("UPDATE executions SET state='running',owner=%s WHERE id=%s",(manager.owner,job['execution_id']))
        row=self.store.rows('SELECT * FROM executions WHERE id=%s',(job['execution_id'],))[0]
        with tempfile.TemporaryDirectory() as folder,patch('farm.collection.executions.EXPORT_ROOT',Path(folder)),patch('requests.Session.post') as post:
            manager.execute(row);post.assert_not_called()
        final=self.store.rows('SELECT state,sent FROM executions WHERE id=%s',(job['execution_id'],))[0]
        self.assertEqual(final,{'state':'complete','sent':0})

    def test_menu_fallback_covers_only_verified_details_and_preserves_closed_missing_items(self):
        from farm.delivery.export import export_run
        import tempfile
        from pathlib import Path
        self._enable_policy_endpoints()
        menu={'code':0,'data':{'shopCategoryList':[{'shopCategoryId':1,'spuIdList':[10,11],
            'spuList':[{'spuId':10,'name':'Plain','haveMultiSpecs':0}]}]}}
        payload={'shopCategoryList':[{'shopCategoryId':1,'spuIdList':[11]}]}
        with self.store.transaction() as c:
            c.execute('UPDATE collection_runs SET settings=%s WHERE id=%s',(compact({'skip_closed_details':True,'menu_detail_fallback':True}),self.rid))
            self.store.result(c,self.job,self.aid,'productList',menu,utcnow())
            self.store.result(c,self.job,self.aid,'shopInfo',{'code':0,'data':{'shopId':1,'name':'Open','status':3}},utcnow())
            self.store.enqueue(c,self.job,'productRender','lazy',payload)
            c.execute("UPDATE tasks SET state='dead_letter',attempts=3 WHERE shop_job_id=%s AND endpoint='productRender'",(self.job,))
            closed=self.store.shop(c,self.rid,'2','-1','-2')
            self.store.result(c,closed,self.aid,'shopInfo',{'code':0,'data':{'shopId':2,'name':'Closed','status':4}},utcnow())
            self.store.result(c,closed,self.aid,'productList',menu,utcnow())
            self.store.enqueue(c,closed,'productRender','lazy',payload)
        self.assertEqual(self.worker.reconcile_menu_fallback(self.rid),{'enqueued':1,'covered':0})
        self.assertEqual(self.worker.reconcile_menu_fallback(self.rid),{'enqueued':0,'covered':0})
        self.assertFalse(self.store.rows("SELECT id FROM tasks WHERE shop_job_id=%s AND endpoint='productSpecifics'",(closed,)))
        detail={'code':0,'data':{'spuId':11,'name':'Custom','haveMultiSpecs':1,'skuList':[{'skuId':1,'groupList':[{'groupId':2,'hasNestedGroup':1}]}]}}
        with self.store.transaction() as c:self.store.result(c,self.job,self.aid,'productSpecifics',detail,utcnow(),'11')
        self.assertEqual(self.worker.reconcile_menu_fallback(self.rid)['covered'],0)
        detail['data']['skuList'][0]['groupList'][0].update(hasNestedGroup=0,groupSkuList=[{'groupSkuId':3,'name':'Choice'}])
        with self.store.transaction() as c:self.store.result(c,self.job,self.aid,'productSpecifics',detail,utcnow(),'11')
        self.assertEqual(self.worker.reconcile_menu_fallback(self.rid)['covered'],1)
        row=self.store.rows("SELECT state,attempts FROM tasks WHERE shop_job_id=%s AND endpoint='productRender'",(self.job,))[0]
        self.assertEqual(row,{'state':'covered_by_details','attempts':3})
        self.assertFalse(self.store.rows('SELECT id FROM request_attempts WHERE account_id=%s',(self.aid,)))
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'delivery.xlsx';summary=export_run(self.store,self.rid,path)
            reports=json.loads(path.with_suffix('.coverage.json').read_text())['shops']
            self.assertEqual(summary['complete_shop_jobs'],1)
            self.assertTrue(reports[0]['complete']);self.assertFalse(reports[1]['complete'])
            self.assertEqual(reports[1]['missing_main_ids'],['11'])

    def test_render_enqueue_deduplicates_legacy_key_order_and_keeps_attempt_history(self):
        payload={'shopCategoryList':[{'shopCategoryId':7,'spuIdList':[10,11]}]}
        reversed_payload={'shopCategoryList':[{'spuIdList':[10,11],'shopCategoryId':7}]}
        with self.store.transaction() as c:
            self.assertEqual(self.store.enqueue(c,self.job,'productRender','first-derived-id',payload),1)
            c.execute("UPDATE tasks SET task_key=%s,state='dead_letter',attempts=3,payload=%s WHERE shop_job_id=%s AND endpoint='productRender'",(digest(['legacy-order',self.tag]),compact(dict(payload,_ipfoxy_refresh_attempted=True)),self.job))
            self.assertEqual(self.store.enqueue(c,self.job,'productRender','other-derived-id',reversed_payload),0)
            self.assertEqual(self.store.enqueue(c,self.job,'productRender','first-derived-id',payload),0)
            c.execute("SELECT state,attempts FROM tasks WHERE shop_job_id=%s AND endpoint='productRender'",(self.job,))
            self.assertEqual(c.fetchall(),[{'state':'dead_letter','attempts':3}])
            self.assertEqual(self.store.enqueue(c,self.job,'productRender','different',{'shopCategoryList':[{'shopCategoryId':7,'spuIdList':[12]}]}),1)

    def test_details_wait_for_shop_info_and_403_is_not_closed(self):
        self._enable_policy_endpoints()
        with self.store.transaction() as c:
            self.store.enqueue(c,self.job,'shopInfo');self.store.enqueue(c,self.job,'productSpecifics','10',priority=20)
        self.assertIsNone(self.worker.claim(self.rid,self.aid,['productSpecifics']))
        with self.store.transaction() as c:
            c.execute("UPDATE tasks SET state='succeeded' WHERE shop_job_id=%s AND endpoint='shopInfo'",(self.job,))
            self.store.result(c,self.job,self.aid,'shopInfo',{'code':0,'data':{'shopId':1,'name':'Open shop','status':3}},utcnow())
        self.claim=self.worker.claim(self.rid,self.aid,['productSpecifics']);self.assertIsNotNone(self.claim)
        self.worker.mark_sent(self.claim);result=self.worker.finish(self.claim,{'_http_status':403,'code':403})
        self.assertEqual(result['outcome'],'rejected');self.assertEqual(result['task_state'],'retry_wait')
        self.assertEqual(self.store.rows("SELECT COUNT(*) n FROM tasks WHERE shop_job_id=%s AND state='skipped_closed'",(self.job,))[0]['n'],0)

    def test_subset_reuses_results_preserves_usage_and_limits_distinct_shops(self):
        from farm.collection.executions import create_subset_run
        with self.store.transaction() as c:
            duplicate=self.store.shop(c,self.rid,'1','-3','-4');self.store.enqueue(c,duplicate,'productList')
            for shop in ('2','3'):
                job=self.store.shop(c,self.rid,shop,'-1','-2');self.store.enqueue(c,job,'productList')
            self.store.result(c,self.job,self.aid,'productList',{'code':0,'data':{'shopCategoryList':[]}},utcnow())
            c.execute("UPDATE tasks SET state='succeeded',attempts=1 WHERE shop_job_id=%s",(self.job,))
            c.execute("INSERT INTO daily_usage(account_id,business_date,endpoint,used_count) VALUES(%s,%s,'productList',7)",(self.aid,business_day(utcnow())))
        result=create_subset_run(self.store,self.rid,2,skip_closed_details=True);self.extra_runs.append(result['run_id'])
        self.assertEqual(result['copied_results'],1)
        self.assertEqual(create_subset_run(self.store,self.rid,2,skip_closed_details=True)['run_id'],result['run_id'])
        jobs=self.store.rows('SELECT shop_id FROM shop_jobs WHERE run_id=%s ORDER BY id',(result['run_id'],))
        self.assertEqual([j['shop_id'] for j in jobs],['1','2'])
        self.assertEqual(self.store.rows('SELECT COUNT(*) n FROM shop_jobs WHERE run_id=%s',(self.rid,))[0]['n'],4)
        self.assertEqual(self.store.rows('SELECT used_count FROM daily_usage WHERE account_id=%s',(self.aid,))[0]['used_count'],7)
        self.assertEqual(self.store.rows('SELECT COUNT(*) n FROM request_attempts WHERE account_id=%s',(self.aid,))[0]['n'],0)
        copied=self.store.rows('SELECT r.observed_at,r.response_blob FROM task_results r JOIN shop_jobs j ON j.id=r.shop_job_id WHERE j.run_id=%s',(result['run_id'],))[0]
        original=self.store.rows('SELECT observed_at,response_blob FROM task_results WHERE shop_job_id=%s',(self.job,))[0]
        self.assertEqual(copied,original)
        with self.assertRaises(ValueError):create_subset_run(self.store,self.rid,5)


if __name__=='__main__':unittest.main()

@unittest.skipUnless(os.environ.get('KEETA_MYSQL_TESTS')=='1','explicit isolated MySQL integration switch required')
class LocalStorageWorkflowTests(unittest.TestCase):
    setUp=MysqlIntegrationTests.setUp
    tearDown=MysqlIntegrationTests.tearDown

    def test_claim_connection_reuse_releases_account_and_untracked_locks(self):
        con=self.store.lock_connection();extra='validation:'+self.tag
        try:
            with con.cursor() as c:
                c.execute('SELECT CONNECTION_ID() id');connection_id=c.fetchone()['id']
                c.execute('SELECT GET_LOCK(%s,0) locked',(extra,))
                self.assertEqual(c.fetchone()['locked'],1)
            self.assertNotEqual(self.store.rows('SELECT CONNECTION_ID() id')[0]['id'],connection_id)
        finally:self.worker._release_locks(con,[])
        self.assertEqual(self.store.rows('SELECT IS_FREE_LOCK(%s) available',(extra,))[0]['available'],1)
        self.claim=self.worker.claim(self.rid,self.aid)
        with self.claim['connection'].cursor() as c:
            c.execute('SELECT CONNECTION_ID() id');self.assertEqual(c.fetchone()['id'],connection_id)
        names=list(self.claim['locks'])
        self.worker.finish(self.claim,error='SyntheticStop',sent=False)
        self.worker._release_locks(self.claim['connection'],names);self.claim=None
        for name in names:
            self.assertEqual(self.store.rows('SELECT IS_FREE_LOCK(%s) available',(name,))[0]['available'],1)

    def test_empty_claims_reuse_connection_without_reserving_quota(self):
        with self.store.transaction() as c:
            c.execute('UPDATE capabilities SET state=%s WHERE session_id=%s',('needs_material',self.sid))
        with patch.object(self.store,'connect',wraps=self.store.connect) as connect:
            for _ in range(3):self.assertIsNone(self.worker.claim(self.rid,self.aid))
            self.assertEqual(connect.call_count,1)
        self.assertEqual(self.store.rows('SELECT COUNT(*) n FROM request_attempts WHERE account_id=%s',(self.aid,))[0]['n'],0)

    def test_unavailable_product_is_recorded_without_detail_http_and_reopens_with_new_evidence(self):
        from farm.storage.responses import MAGIC,load_response
        with self.store.transaction() as c:
            c.execute('UPDATE collection_runs SET settings=%s WHERE id=%s',(compact({'skip_unavailable_details':True}),self.rid))
        self.claim=self.worker.claim(self.rid,self.aid)
        self.worker.mark_sent(self.claim)
        reply={'_http_status':200,'code':0,'data':{'shopCategoryList':[{'shopCategoryId':1,'spuList':[{'spuId':7,'name':'Later','haveMultiSpecs':1,'availableStatus':0}]}]}}
        result=self.worker.finish(self.claim,reply)
        self.assertEqual(result['outcome'],'success')
        task=self.store.rows("SELECT state,attempts FROM tasks WHERE shop_job_id=%s AND endpoint='productSpecifics'",(self.job,))[0]
        self.assertEqual(task,dict(state='skipped_unavailable',attempts=0))
        saved=self.store.rows('SELECT response_blob FROM task_results WHERE shop_job_id=%s',(self.job,))[0]['response_blob']
        self.assertTrue(saved.startswith(MAGIC));self.assertEqual(load_response(saved),reply)
        reply['data']['shopCategoryList'][0]['spuList'][0]['availableStatus']=1
        with self.store.transaction() as c:
            self.store.result(c,self.job,self.aid,'productList',reply,utcnow())
            self.worker.reconcile_unavailable_details(c,self.claim['task'])
        self.assertEqual(self.store.rows("SELECT state FROM tasks WHERE shop_job_id=%s AND endpoint='productSpecifics'",(self.job,))[0]['state'],'pending')

    def test_opening_gate_only_releases_menus_for_all_confirmed_open_shops(self):
        from farm.collection.executions import ExecutionManager
        with self.store.transaction() as c:
            c.execute('UPDATE collection_runs SET settings=%s WHERE id=%s',(compact({'verify_open':True}),self.rid))
            c.execute("UPDATE tasks SET state='selection_hold' WHERE shop_job_id=%s",(self.job,))
            self.store.enqueue(c,self.job,'shopInfo')
        manager=ExecutionManager(self.store)
        self.assertEqual(manager.release_opening_selection(self.rid),'pending')
        with self.store.transaction() as c:
            c.execute("UPDATE tasks SET state='succeeded' WHERE shop_job_id=%s AND endpoint='shopInfo'",(self.job,))
            self.store.result(c,self.job,self.aid,'shopInfo',{'code':0,'data':{'name':'Shop','status':4}},utcnow())
        self.assertEqual(manager.release_opening_selection(self.rid),'not_open')
        with self.store.transaction() as c:
            self.store.result(c,self.job,self.aid,'shopInfo',{'code':0,'data':{'name':'Shop','status':3}},utcnow())
        self.assertEqual(manager.release_opening_selection(self.rid),'released')
        self.assertEqual(self.store.rows("SELECT state FROM tasks WHERE shop_job_id=%s AND endpoint='productList'",(self.job,))[0]['state'],'pending')

    def test_catalog_route_assignment_preserves_identity_and_refuses_active_batch(self):
        from farm.network.catalog import import_routes, delete_route, ProxyConfigError, CATALOG, BINDINGS
        from farm.network.proxy import assign_account_proxies
        original_get=self.store.get_setting
        previous={k:original_get(k) or {} for k in (CATALOG,BINDINGS,'clash_node_bindings')}
        pool={'nodes':[{'name':'test-front','proxy':'http://127.0.0.1:18990'}]}
        original=self.store.unseal(self.store.rows('SELECT * FROM account_sessions WHERE id=%s',(self.sid,))[0])
        def setting(name):return pool if name=='clash_node_pool' else original_get(name)
        execution=None
        try:
            with patch.object(self.store,'get_setting',side_effect=setting):
                route=import_routes(self.store,'socks5://synthetic:pass@192.0.2.10:45001','test-front')['ids'][0]
                assign_account_proxies(self.store,[self.aid],'catalog',proxy_id=route)
                current=self.store.unseal(self.store.rows('SELECT * FROM account_sessions WHERE id=%s',(self.sid,))[0])
                self.assertEqual(current['device'],original['device'])
                self.assertEqual(current['proxy'],'socks5://synthetic:pass@192.0.2.10:45001')
                self.assertEqual(current['front_proxy'],'http://127.0.0.1:18990')
                self.assertEqual(original_get(BINDINGS)[str(self.aid)]['proxy_id'],route)
                with self.assertRaises(ProxyConfigError):delete_route(self.store,route)
                with self.store.transaction() as c:
                    c.execute("INSERT INTO executions(run_id,environment,selection,account_ids,endpoints,max_requests,delay_seconds,created_at) VALUES(%s,'test','{}',%s,'[]',1,4,%s)",(self.rid,compact([self.aid]),utcnow()))
                    execution=c.lastrowid
                before=self.store.rows('SELECT credential_blob FROM account_sessions WHERE id=%s',(self.sid,))[0]['credential_blob']
                with self.assertRaises(ProxyConfigError):assign_account_proxies(self.store,[self.aid],'clash_pool',node_name='test-front')
                self.assertEqual(before,self.store.rows('SELECT credential_blob FROM account_sessions WHERE id=%s',(self.sid,))[0]['credential_blob'])
        finally:
            if execution:
                with self.store.transaction() as c:c.execute('DELETE FROM executions WHERE id=%s',(execution,))
            for k,v in previous.items():self.store.set_setting(k,v)

    def test_route_assignment_to_missing_account_rolls_back_other_bindings(self):
        from farm.network.proxy import assign_account_proxies
        from farm.network.catalog import BINDINGS
        original_get=self.store.get_setting;before=original_get(BINDINGS) or {}
        blob=self.store.rows('SELECT credential_blob FROM account_sessions WHERE id=%s',(self.sid,))[0]['credential_blob']
        def setting(name):return {'nodes':[{'name':'test-front','proxy':'http://127.0.0.1:18990'}]} if name=='clash_node_pool' else original_get(name)
        with patch.object(self.store,'get_setting',side_effect=setting):
            with self.assertRaises(ValueError):assign_account_proxies(self.store,[self.aid,9223372036854775000],node_name='test-front')
        self.assertEqual(blob,self.store.rows('SELECT credential_blob FROM account_sessions WHERE id=%s',(self.sid,))[0]['credential_blob'])
        self.assertEqual(before,original_get(BINDINGS) or {})
