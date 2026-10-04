"""Credential deletion, budget-preserving batch deletion and file-free imports."""
from copy import deepcopy
import json
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import Mock,patch

from mtgsig.signer import FullSigner,provision_identity
from farm.accounts.importer import import_curls,split_curls,parse_curl
from farm.storage.admin import delete_accounts,delete_runs,DeletionConflict
from farm.storage.mysql import utcnow
from farm.web.app import create_app
from tests.protocol.test_collection_refresh import identity


class MemoryAndPanelTests(unittest.TestCase):
    def test_signer_resumes_database_state_without_files(self):
        original=identity();base=deepcopy(original)
        with patch('tempfile.mkstemp',side_effect=AssertionError('no files')):
            first=FullSigner(original)
            mt=json.loads(first.sign('POST','https://example.test/path','{}'))
            state=first.persist_counter()
            second=FullSigner(state)
            second.sign('POST','https://example.test/path','{}')
            next_state=second.persist_counter()
        self.assertEqual(original,base)
        self.assertEqual(next_state['sign_sequence'],state['sign_sequence']+1)
        self.assertEqual(next_state['signature_counter'],state['signature_counter'])
        # A native-format signature sample can provision the next account
        # bundle directly from memory, including its decode/codec metadata.
        restored=provision_identity({'mtgsig':mt})
        self.assertEqual(restored['a1'],state['a1'])
        self.assertEqual(restored['sign_sequence'],state['sign_sequence'])

    def test_split_keeps_quoted_multiline_body_and_url_first_commands(self):
        first='curl "https://example.test" --data-raw \'line1\ncurl -fake body text\nline3\''
        second='curl -H "x: 1" \\\n "https://example.test/other"'
        self.assertEqual(split_curls('\ufeff'+first+'\n\n'+second),[first,second])

    def test_batch_import_has_independent_failures_and_no_capture_files(self):
        commands=['curl https://a.mykeeta.com','curl https://b.mykeeta.com','curl https://c.mykeeta.com']
        with patch('farm.accounts.importer.import_curl_text',side_effect=[(1,1,'ready'),ValueError('PRIVATE'),(2,2,'ready')]),patch('tempfile.TemporaryDirectory',side_effect=AssertionError('no capture files')):
            result=import_curls(Mock(),[('many','\n'.join(commands[:2])),('last',commands[2])])
        self.assertEqual([r.get('account_id') for r in result],[1,None,2])
        self.assertEqual(result[1],{'index':2,'error_type':'ValueError'})
        self.assertNotIn('PRIVATE',str(result))

    def test_delete_endpoints_require_explicit_ids_csrf_and_report_busy(self):
        client=create_app(Mock()).test_client()
        csrf=re.search(r'name="csrf-token" content="([^"]+)"',client.get('/').text)[1]
        self.assertEqual(client.post('/api/accounts/delete',json={'ids':[1]}).status_code,403)
        for endpoint in ('accounts','runs'):
            response=client.post('/api/'+endpoint+'/delete',json={'ids':[]},headers={'X-Panel-CSRF':csrf})
            self.assertEqual(response.status_code,400)
        with patch('farm.web.app.delete_accounts',side_effect=DeletionConflict('账号正在运行')):
            r=client.post('/api/accounts/delete',json={'ids':[1]},headers={'X-Panel-CSRF':csrf})
            self.assertEqual(r.status_code,409);self.assertIn('账号正在运行',r.json['error'])

    def test_panel_multi_account_upload_never_saves_curl(self):
        import io
        client=create_app(Mock()).test_client()
        csrf=re.search(r'name="csrf-token" content="([^"]+)"',client.get('/').text)[1]
        with patch('farm.accounts.importer.import_curls',return_value=[{'account_id':1},{'account_id':2}]) as importer,patch('farm.web.app.set_profile'),patch('tempfile.TemporaryDirectory',side_effect=AssertionError('no capture files')):
            r=client.post('/api/accounts/import',data={'files':(io.BytesIO(b'curl -one\ncurl -two'),'many.txt'),'environment':'test','proxy':''},headers={'X-Panel-CSRF':csrf})
        self.assertEqual(r.status_code,200)
        self.assertEqual(importer.call_args.args[1],[('many','curl -one\ncurl -two')])


@unittest.skipUnless(os.environ.get('KEETA_MYSQL_TESTS')=='1','explicit MySQL integration switch required')
class AdminIntegrationTests(unittest.TestCase):
    # Reuse only setup/cleanup; every HTTP send below is mocked.
    from tests.storage.test_mysql_integration import MysqlIntegrationTests as _Fixture
    setUp=_Fixture.setUp
    def tearDown(self):
        # An account may already be deleted; results deliberately outlive it.
        if self.rid:
            with self.store.transaction() as c:
                c.execute('DELETE r FROM task_results r JOIN shop_jobs j ON j.id=r.shop_job_id WHERE j.run_id=%s',(self.rid,))
        self._Fixture.tearDown(self)

    def complete_menu(self):
        self.claim=self.worker.claim(self.rid,self.aid)
        response=Mock(status_code=200,headers={});response.json.return_value={'code':0,'data':{'shopCategoryList':[]}}
        with patch('requests.Session.post',return_value=response),patch('tempfile.TemporaryDirectory',side_effect=AssertionError('worker must not write credentials')):
            result=self.worker.execute(self.claim)
        self.claim=None
        self.assertEqual(result['outcome'],'success')

    def test_account_delete_preserves_completed_results_and_other_accounts(self):
        self.complete_menu()
        before={r['id'] for r in self.store.rows('SELECT id FROM accounts')}
        result=delete_accounts(self.store,[self.aid])
        self.assertEqual(result['preserved_results'],1)
        self.assertEqual({r['id'] for r in self.store.rows('SELECT id FROM accounts')},before-{self.aid})
        self.assertFalse(self.store.rows('SELECT id FROM account_sessions WHERE account_id=%s',(self.aid,)))
        self.assertIsNone(self.store.rows('SELECT account_id FROM task_results WHERE shop_job_id=%s',(self.job,))[0]['account_id'])
        self.assertEqual(self.store.rows('SELECT state FROM tasks WHERE shop_job_id=%s',(self.job,))[0]['state'],'succeeded')
        from farm.delivery.export import export_run
        with tempfile.TemporaryDirectory() as tmp:
            summary=export_run(self.store,self.rid,Path(tmp)/'delivery.xlsx')
            self.assertEqual(summary['partial_shop_jobs'],1)
            coverage=json.loads((Path(tmp)/'delivery.coverage.json').read_text())
            self.assertTrue(coverage['shops'][0]['menu_complete'])
        delete_runs(self.store,[self.rid])

    def test_batch_delete_keeps_actual_usage_and_request_evidence(self):
        self.complete_menu()
        before=self.store.rows('SELECT used_count,reserved_count FROM daily_usage WHERE account_id=%s',(self.aid,))
        result=delete_runs(self.store,[self.rid]);self.assertEqual(result['deleted_tasks'],1)
        self.assertEqual(self.store.rows('SELECT used_count,reserved_count FROM daily_usage WHERE account_id=%s',(self.aid,)),before)
        rows=self.store.rows('SELECT state,task_id FROM request_attempts WHERE account_id=%s',(self.aid,))
        self.assertEqual(rows,[{'state':'done','task_id':None}])
        self.assertFalse(self.store.rows('SELECT id FROM task_results WHERE shop_job_id=%s',(self.job,)))
        self.assertTrue(self.store.rows('SELECT id FROM accounts WHERE id=%s',(self.aid,)))

    def test_account_and_batch_cannot_be_deleted_during_cli_request(self):
        self.claim=self.worker.claim(self.rid,self.aid)
        with self.assertRaises(DeletionConflict):delete_accounts(self.store,[self.aid])
        with self.assertRaises(DeletionConflict):delete_runs(self.store,[self.rid])
        self.worker.finish(self.claim,error='SyntheticStop',sent=False)

    def test_active_execution_blocks_delete_and_stopping_allows_it(self):
        from farm.collection.executions import create_execution,stop_execution
        job=create_execution(self.store,self.rid,'test',[self.aid],max_requests=1)
        with self.assertRaises(DeletionConflict):delete_accounts(self.store,[self.aid])
        with self.assertRaises(DeletionConflict):delete_runs(self.store,[self.rid])
        stop_execution(self.store,job['execution_id'])
        delete_runs(self.store,[self.rid])
        delete_accounts(self.store,[self.aid])

    def test_unknown_id_rolls_back_the_entire_selection(self):
        with self.assertRaises(ValueError):delete_accounts(self.store,[self.aid,2**62])
        with self.assertRaises(ValueError):delete_runs(self.store,[self.rid,2**62])
        self.assertTrue(self.store.rows('SELECT id FROM accounts WHERE id=%s',(self.aid,)))
        self.assertTrue(self.store.rows('SELECT id FROM collection_runs WHERE id=%s',(self.rid,)))


if __name__=='__main__':unittest.main()


class JsonAccountImportTests(unittest.TestCase):
    def capture(self):
        import base64
        from farm.storage.mysql import compact
        dev=identity();mt=FullSigner(dev).sign('POST','https://example.test/','{}')
        body=compact({'location':{'latitude':'-23.5','longitude':'-46.6'},'nested':'{"key":"value"}'})
        headers={'token':'TEST-ACCOUNT','cookie':'token=TEST-ACCOUNT','userid':'123','csecuserid':'123',
                 'uuid':'TEST-DEVICE','csecuuid':'TEST-DEVICE','appversion':'3.12.401','region':'BR',
                 'mtgsig':mt,'cityid':'102302389'}
        url='https://fooddelivery-eu-1.mykeeta.com/api/v4/homePage/homePageInfo?userid=123&uuid=TEST-DEVICE&csecplatform=2&csecpkgname=com.sankuai.sailor.ifooddelivery'
        return {'schema_version':2,'login_verified':True,'requests':[{'request':{'method':'POST','url':url,'headers':list(headers.items()),'body_base64':base64.b64encode(body.encode()).decode()},'response':{'status_code':200}}]}

    def test_export_body_and_own_host_are_preserved_and_schemas_assembled(self):
        from farm.accounts.importer import capture_requests,import_requests,prepare_bundle
        capture=self.capture();requests=capture_requests(capture)
        self.assertEqual(json.loads(requests[0]['body'])['nested'],'{"key":"value"}')
        store=Mock();store.rows.return_value=[]
        with patch('farm.accounts.importer.import_bundle',return_value=(1,2,'ready')) as saved:
            import_requests(store,requests,'test','test')
        bundle=saved.call_args.args[1];ready,status,endpoints=prepare_bundle(bundle)
        self.assertEqual(set(endpoints),{'shopInfo','productList','productRender','productSpecifics','homeShopList','accountInfo'})
        self.assertIn('fooddelivery-eu-1.mykeeta.com',ready['templates']['/api/v1/shop/productSpecifics']['url'])
        self.assertNotIn('login_verified',ready)

    def test_mixed_identity_and_invalid_base64_are_rejected(self):
        from farm.accounts.importer import capture_requests,import_requests
        capture=self.capture();requests=capture_requests(capture);other=deepcopy(requests[0]);other['headers']['userid']='456'
        store=Mock();store.rows.return_value=[]
        with patch('farm.accounts.importer.import_bundle') as saved:
            with self.assertRaises(ValueError):import_requests(store,[requests[0],other],'test','test')
            saved.assert_not_called()
        capture['requests'][0]['request']['body_base64']='@@PRIVATE@@'
        result=import_curls(store,[('bad',json.dumps(capture))])
        self.assertIn('error_type',result[0]);self.assertNotIn('PRIVATE',str(result))

    def test_reimport_reuses_templates_only_within_current_runtime_session(self):
        from farm.accounts.importer import capture_requests,import_requests,prepare_bundle
        from farm.storage.mysql import PATHS
        request=capture_requests(self.capture())[0]
        request['headers']['appsession']='NEW-SESSION'
        request['headers']['incog-token']='NEW-INCOGNIA'
        old_request=deepcopy(request)
        old_request['headers'].update(appsession='OLD-SESSION',**{'incog-token':'OLD-INCOGNIA'})
        template=deepcopy(old_request)
        template['url']=template['url'].replace('/api/v4/homePage/homePageInfo',PATHS['productRender'])
        template['body']='{"old_only":true}'
        old={'identity':{k:request['headers'][k] for k in ('token','uuid','userid')},
             'request':old_request,'templates':{PATHS['productRender']:template},
             'account_check_request':{'stale':True}}
        store=Mock();store.rows.return_value=[{}];store.unseal.return_value=old
        with patch('farm.accounts.importer.import_bundle') as saved:
            import_requests(store,[request],'test','test')
        bundle=saved.call_args.args[1]
        self.assertEqual(bundle['templates'],{})
        self.assertIsNone(bundle.get('account_check_request'))
        ready,_,_=prepare_bundle(bundle)
        for current in ready['templates'].values():
            self.assertEqual(current['headers']['appsession'],'NEW-SESSION')
            self.assertEqual(current['headers']['incog-token'],'NEW-INCOGNIA')
        old['request']=deepcopy(request)
        old['templates'][PATHS['productRender']]['headers']=deepcopy(request['headers'])
        with patch('farm.accounts.importer.import_bundle') as saved:
            import_requests(store,[request],'test','test')
        self.assertEqual(saved.call_args.args[1]['templates'],old['templates'])

    def test_reimport_drops_stale_template_in_otherwise_current_bundle(self):
        from farm.accounts.importer import capture_requests,import_requests
        from farm.storage.mysql import PATHS
        request=capture_requests(self.capture())[0];request['headers']['appsession']='CURRENT'
        template=deepcopy(request);template['headers']['appsession']='STALE'
        template['url']=template['url'].replace('/api/v4/homePage/homePageInfo',PATHS['productRender'])
        old={'identity':{k:request['headers'][k] for k in ('token','uuid','userid')},
             'request':request,'templates':{PATHS['productRender']:template}}
        store=Mock();store.rows.return_value=[{}];store.unseal.return_value=old
        with patch('farm.accounts.importer.import_bundle') as saved:
            import_requests(store,[request],'test','test')
        self.assertEqual(saved.call_args.args[1]['templates'],{})

    def test_multi_capture_does_not_mix_runtime_sessions(self):
        from farm.accounts.importer import capture_requests,import_requests
        from farm.storage.mysql import PATHS
        request=capture_requests(self.capture())[0];request['headers']['appsession']='CURRENT'
        previous=deepcopy(request);previous['headers']['appsession']='PREVIOUS'
        previous['url']=previous['url'].replace('/api/v4/homePage/homePageInfo',PATHS['productRender'])
        store=Mock();store.rows.return_value=[]
        with patch('farm.accounts.importer.import_bundle') as saved:
            import_requests(store,[previous,request],'test','test')
        self.assertEqual(saved.call_args.args[1]['templates'],{})

    def test_index_is_not_imported_as_an_account_and_json_files_are_independent(self):
        with patch('farm.accounts.importer.import_requests',return_value=(1,2,'ready')) as importer:
            result=import_curls(Mock(),[('index',json.dumps({'schema_version':1,'accounts':{'record':{}}})),('capture',json.dumps(self.capture()))])
        self.assertEqual(result[0]['status'],'skipped_metadata');self.assertEqual(result[1]['account_id'],1)
        importer.assert_called_once()

    def test_panel_accepts_json_and_resolves_encrypted_default_proxy(self):
        import io
        store=Mock();store.get_setting.return_value={'proxy':'http://synthetic:pass@gate.ipfoxy.io:58688','refresh_ipfoxy':True}
        client=create_app(store).test_client();csrf=re.search(r'name="csrf-token" content="([^"]+)"',client.get('/').text)[1]
        with patch('farm.accounts.importer.import_curls',return_value=[]) as imported:
            r=client.post('/api/accounts/import',data={'files':(io.BytesIO(b'{}'),'account.json'),'use_saved_proxy':'true'},headers={'X-Panel-CSRF':csrf})
        self.assertEqual(r.status_code,200);self.assertTrue(imported.call_args.kwargs['refresh_ipfoxy'])
        self.assertEqual(imported.call_args.args[2],'http://synthetic:pass@gate.ipfoxy.io:58688')
        self.assertNotIn('synthetic:pass',client.get('/api/proxy-settings').text)


@unittest.skipUnless(os.environ.get('KEETA_MYSQL_TESTS')=='1','explicit MySQL integration switch required')
class DurableRecoveryIntegrationTests(unittest.TestCase):
    from tests.storage.test_mysql_integration import MysqlIntegrationTests as _Fixture
    setUp=_Fixture.setUp

    def tearDown(self):
        if self.aid:
            with self.store.transaction() as c:c.execute('DELETE FROM proxy_refresh_events WHERE account_id=%s',(self.aid,))
        self._Fixture.tearDown(self)

    def test_403_refresh_keeps_attempt_counts_and_retries_same_task_only_once(self):
        from datetime import timedelta
        from farm.storage.mysql import compact
        row=self.store.rows('SELECT * FROM account_sessions WHERE id=%s',(self.sid,))[0]
        bundle=self.store.unseal(row);bundle.update(proxy='http://synthetic:pass@gate.ipfoxy.io:58688',refresh_ipfoxy=True)
        key,blob=self.store.seal(bundle)
        with self.store.transaction() as c:c.execute('UPDATE account_sessions SET encryption_key_id=%s,credential_blob=%s WHERE id=%s',(key,blob,self.sid))
        self.claim=self.worker.claim(self.rid,self.aid)
        response=Mock(status_code=403,headers={});response.json.return_value={'code':403}
        with patch('requests.Session.post',return_value=response),patch('farm.collection.worker.refresh_ipfoxy',return_value={'accepted':True,'http_status':200,'outcome':'acknowledged'}) as refresh:
            first=self.worker.execute(self.claim);self.claim=None
            self.assertTrue(first['proxy_refreshed']);self.assertEqual(first['outcome'],'rejected')
            with self.store.transaction() as c:
                c.execute('UPDATE tasks SET not_before=%s WHERE shop_job_id=%s',(utcnow()-timedelta(seconds=1),self.job))
                c.execute('UPDATE capabilities SET not_before=NULL WHERE session_id=%s',(self.sid,))
            self.claim=self.worker.claim(self.rid,self.aid);second=self.worker.execute(self.claim);self.claim=None
        self.assertFalse(second['proxy_refreshed']);refresh.assert_called_once()
        usage=self.store.rows('SELECT used_count,reserved_count FROM daily_usage WHERE account_id=%s',(self.aid,))[0]
        self.assertEqual(usage,{'used_count':2,'reserved_count':0})
        rows=self.store.rows('SELECT http_status,outcome FROM request_attempts WHERE account_id=%s',(self.aid,))
        self.assertEqual(rows,[{'http_status':403,'outcome':'rejected'}]*2)
        self.assertEqual(self.worker.diagnose([self.aid],['productList'])[0]['reason'],'cooldown')

    def test_waiting_execution_resumes_due_tasks_and_user_stop_prevents_restart(self):
        from datetime import timedelta
        from farm.collection.executions import create_execution,ExecutionManager,stop_execution
        job=create_execution(self.store,self.rid,'test',[self.aid],auto_resume=True,max_requests=20)
        with self.store.transaction() as c:
            c.execute("UPDATE executions SET state='waiting',heartbeat_at=%s WHERE id=%s",(utcnow()-timedelta(minutes=2),job['execution_id']))
        ExecutionManager(self.store).resume_waiting()
        self.assertEqual(self.store.rows('SELECT state FROM executions WHERE id=%s',(job['execution_id'],))[0]['state'],'queued')
        with self.store.transaction() as c:c.execute("UPDATE executions SET state='waiting' WHERE id=%s",(job['execution_id'],))
        stop_execution(self.store,job['execution_id']);ExecutionManager(self.store).resume_waiting()
        stopped=self.store.rows('SELECT state,finished_at FROM executions WHERE id=%s',(job['execution_id'],))[0]
        self.assertEqual(stopped['state'],'stopped');self.assertIsNotNone(stopped['finished_at'])


class DurableNetworkBackoffTests(unittest.TestCase):
    def test_parallel_route_failure_allows_other_accounts_to_continue(self):
        from contextlib import contextmanager
        from farm.collection.executions import ExecutionManager
        store=Mock();manager=ExecutionManager(store);manager.record_progress=Mock();calls=[]
        store.rows.return_value=[{'state':'running','owner':manager.owner,'stop_requested':False}]
        @contextmanager
        def transaction():yield Mock()
        store.transaction=transaction
        def execute(claim):
            aid=claim['account_id'];calls.append(aid)
            return {'account_id':aid,'endpoint':'shopInfo','sent':True,'outcome':'transport_error' if aid==1 else 'success'}
        job={'id':1,'run_id':1,'account_ids':[1,2,3,4],'endpoints':['shopInfo'],'environment':'test','max_requests':6,'processed':0,'delay_seconds':0}
        with patch('farm.collection.executions.Worker') as worker:
            worker.return_value.claim.side_effect=lambda *a,**k:{'account_id':k['account_ids'][0]}
            worker.return_value.execute.side_effect=execute
            self.assertEqual(manager._collect(job,{'concurrency':2}),('limit','request_limit'))
        self.assertEqual(len(calls),6);self.assertLessEqual(calls.count(1),1)
        self.assertTrue(any(aid!=1 for aid in calls))

    def test_parallel_collection_has_exact_shared_budget_and_detail_spacing(self):
        from contextlib import contextmanager
        import threading,time
        from farm.collection.executions import ExecutionManager
        store=Mock();manager=ExecutionManager(store);manager.record_progress=Mock();mutex=threading.Lock();barrier=threading.Barrier(2)
        sent=[];starts={};ends={};active=set();peak=[0];sequence=[0]
        store.rows.return_value=[{'state':'running','owner':manager.owner,'stop_requested':False}]
        @contextmanager
        def transaction():yield Mock()
        store.transaction=transaction
        def claim(*args,**kwargs):
            aid=kwargs['account_ids'][0]
            if worker.return_value.details_ready_at.get(aid,0)>time.monotonic():return None
            with mutex:
                sequence[0]+=1;number=sequence[0]
            return {'aid':aid,'number':number,'task':{'shop_job_id':1}}
        def execute(claim):
            aid=claim['aid']
            with mutex:
                self.assertNotIn(aid,active);active.add(aid);peak[0]=max(peak[0],len(active))
                starts.setdefault(aid,[]).append(time.monotonic())
            if claim['number']<=2:barrier.wait(timeout=3)
            time.sleep(.01)
            with mutex:
                active.remove(aid);sent.append(claim['number']);ends.setdefault(aid,[]).append(time.monotonic())
            return {'account_id':aid,'endpoint':'productSpecifics','sent':True,'outcome':'success'}
        job={'id':1,'run_id':1,'account_ids':[1,2],'endpoints':['productSpecifics'],'environment':'test','max_requests':5,'processed':0,'delay_seconds':.02}
        with patch('farm.collection.executions.Worker') as worker:
            worker.return_value.claim.side_effect=claim;worker.return_value.execute.side_effect=execute
            self.assertEqual(manager._collect(job,{'concurrency':2}),('limit','request_limit'))
        self.assertEqual(len(sent),5);self.assertEqual(len(set(sent)),5);self.assertEqual(peak[0],2)
        for aid in starts:
            for i in range(1,len(starts[aid])):self.assertGreaterEqual(starts[aid][i]-ends[aid][i-1],.018)

    def test_lost_executor_lock_prevents_new_claims(self):
        from farm.collection.executions import ExecutionManager
        import threading
        store=Mock();manager=ExecutionManager(store);manager.lease=Mock();manager.lease.lost=threading.Event();manager.lease.lost.set()
        job={'id':1,'account_ids':[1,2],'max_requests':5,'processed':0}
        with patch('farm.collection.executions.Worker') as worker:
            self.assertEqual(manager._collect(job,{'concurrency':2}),('interrupted','executor_lock_lost'))
            worker.return_value.claim.assert_not_called()

    def test_lock_keepalive_never_reconnects_after_connection_loss(self):
        from farm.collection.executions import ExecutorLease
        lease=ExecutorLease(Mock());lease.connection=Mock();lease.stop=Mock()
        lease.stop.wait.return_value=False;lease.connection.ping.side_effect=OSError('disconnected')
        lease._keepalive()
        self.assertTrue(lease.lost.is_set());lease.connection.ping.assert_called_once_with(reconnect=False)

    def test_three_transport_failures_do_not_requeue_or_send(self):
        from contextlib import contextmanager
        from farm.collection.executions import ExecutionManager
        store=Mock();cursor=Mock()
        @contextmanager
        def transaction():yield cursor
        store.transaction=transaction
        store.rows.side_effect=[[{'id':1,'run_id':1,'selection':{'auto_resume':True},'stop_reason':'transport_error'}],[{'outcome':'transport_error'}]*3]
        with patch('farm.collection.executions.select_accounts') as select:
            ExecutionManager(store).resume_waiting()
            select.assert_not_called()
        queries=[call.args[0] for call in cursor.execute.call_args_list]
        self.assertTrue(any("stop_reason='network_unavailable'" in q for q in queries))
        self.assertTrue(any("UPDATE collection_runs SET status='failed'" in q for q in queries))


class DatabaseRecoveryTests(unittest.TestCase):
    def store_with_connection(self):
        import queue,threading
        from unittest.mock import MagicMock
        from farm.storage.mysql import Store
        store=object.__new__(Store);store.config={}
        store._connections=queue.LifoQueue(2);store._connection_slots=threading.BoundedSemaphore(2)
        store._lock_connections=queue.LifoQueue(2)
        connection=MagicMock();store.connect=Mock(return_value=connection)
        return store,connection

    def test_rollback_failure_preserves_original_exception_and_discards_connection(self):
        import pymysql
        store,connection=self.store_with_connection()
        original=pymysql.err.OperationalError(2013,'SYNTHETIC-SECRET')
        connection.rollback.side_effect=pymysql.err.InterfaceError(0,'cleanup')
        with patch('builtins.print') as output:
            with self.assertRaises(pymysql.err.OperationalError) as caught:
                with store.transaction():raise original
        self.assertIs(caught.exception,original)
        connection.close.assert_called_once();self.assertTrue(store._connections.empty())
        self.assertNotIn('SYNTHETIC-SECRET',str(output.call_args_list))

    def test_pool_reuses_healthy_connection_and_replaces_stale_one_without_reconnect(self):
        import pymysql
        from unittest.mock import MagicMock
        store,connection=self.store_with_connection()
        with store.transaction():pass
        with store.transaction():pass
        self.assertEqual(store.connect.call_count,1)
        connection.ping.assert_called_once_with(reconnect=False)
        replacement=MagicMock();store.connect.return_value=replacement
        connection.ping.side_effect=pymysql.err.OperationalError(2006,'gone')
        with store.transaction():pass
        self.assertEqual(store.connect.call_count,2);connection.close.assert_called_once()

    def test_only_read_queries_are_retried_not_writes_or_named_locks(self):
        import pymysql
        for sql in ('SELECT id FROM tasks','UPDATE tasks SET state=\'pending\'',"SELECT GET_LOCK('test',0)"):
            with self.subTest(sql=sql),patch('farm.storage.mysql.time.sleep'),patch('builtins.print'):
                store,con=self.store_with_connection();cursor=con.cursor.return_value.__enter__.return_value
                cursor.execute.side_effect=[pymysql.err.OperationalError(2013,'lost'),None]
                cursor.fetchall.return_value=[{'id':7}]
                if sql=='SELECT id FROM tasks':
                    self.assertEqual(store.rows(sql),[{'id':7}]);self.assertEqual(cursor.execute.call_count,2)
                else:
                    with self.assertRaises(pymysql.err.OperationalError):store.rows(sql)
                    self.assertEqual(cursor.execute.call_count,1)

    def test_already_closed_pool_connection_is_discarded_before_ping(self):
        from unittest.mock import MagicMock
        store,closed=self.store_with_connection()
        with store.transaction():pass
        closed.open=False
        replacement=MagicMock();store.connect.return_value=replacement
        with store.transaction():pass
        closed.ping.assert_not_called();self.assertEqual(store.connect.call_count,2)

    def test_authentication_and_sql_errors_are_not_transient(self):
        import pymysql
        from farm.storage.mysql import transient_database_error
        self.assertTrue(transient_database_error(pymysql.err.OperationalError(2013,'lost')))
        for exc in (pymysql.err.OperationalError(1045,'denied'),pymysql.err.ProgrammingError(1064,'syntax'),ValueError('bad')):
            self.assertFalse(transient_database_error(exc))

    def test_completed_request_survives_lock_cleanup_failure(self):
        import pymysql
        from unittest.mock import MagicMock
        from farm.collection.worker import Worker
        store,con=self.store_with_connection()
        con.cursor.return_value.__enter__.return_value.execute.side_effect=pymysql.err.InterfaceError(0,'lost')
        with patch('builtins.print'):Worker(store)._release_locks(con,['synthetic'])
        con.close.assert_called_once()

    def test_claim_connections_reuse_only_after_rollback_and_unlock(self):
        from unittest.mock import call
        store,con=self.store_with_connection()
        for _ in range(3):
            self.assertIs(store.lock_connection(),con)
            store.release_lock_connection(con)
        self.assertEqual(store.connect.call_count,1)
        self.assertTrue(store._connections.empty())
        self.assertEqual(con.rollback.call_count,3)
        self.assertEqual(con.cursor.return_value.__enter__.return_value.execute.call_args_list,
                         [call('SELECT RELEASE_ALL_LOCKS()')]*3)
        con.close.assert_not_called()

    def test_failed_claim_rollback_or_unlock_never_returns_connection_to_pool(self):
        import pymysql
        for failure in ('rollback','unlock'):
            with self.subTest(failure=failure),patch('builtins.print'):
                store,con=self.store_with_connection()
                operation=con.rollback if failure=='rollback' else con.cursor.return_value.__enter__.return_value.execute
                operation.side_effect=pymysql.err.InterfaceError(0,'lost')
                store.release_lock_connection(con)
                self.assertTrue(store._lock_connections.empty())
                con.close.assert_called_once()

    def test_database_error_becomes_waiting_without_replaying_claim(self):
        import pymysql
        from farm.collection.executions import ExecutionManager
        store=Mock();manager=ExecutionManager(store)
        store.rows.return_value=[{'state':'running','owner':manager.owner,'stop_requested':False}]
        job={'id':31,'run_id':183,'account_ids':[122],'endpoints':['shopInfo'],'environment':'test','max_requests':20,'processed':0,'delay_seconds':0}
        with patch('farm.collection.executions.Worker') as worker,patch('builtins.print'):
            worker.return_value.claim.side_effect=pymysql.err.OperationalError(2013,'lost')
            self.assertEqual(manager._collect(job,{'auto_resume':True}),('waiting','database_unavailable'))
            worker.return_value.claim.assert_called_once();worker.return_value.execute.assert_not_called()

    def test_commit_ack_loss_reuses_recorded_result_without_budget_or_followup_updates(self):
        from contextlib import contextmanager
        from farm.collection.worker import Worker
        cursor=Mock();store=Mock()
        cursor.fetchone.side_effect=[{'id':122},{'state':'done','counts_budget':1,'http_status':200,'business_code':'0','outcome':'success','error_type':None},{'state':'succeeded'}]
        @contextmanager
        def transaction():yield cursor
        store.transaction=transaction
        claim={'account':{'id':124,'account_id':122},'task':{'id':1,'endpoint':'shopInfo','shop_id':'1','target_id':''},'attempt_id':'a'}
        result=Worker(store).finish(claim,{'code':0,'_http_status':200,'data':{'shopId':'1'}})
        self.assertEqual(result['outcome'],'success')
        self.assertTrue(all(c.args[0].startswith('SELECT ') for c in cursor.execute.call_args_list))
        store.result.assert_not_called();store.enqueue.assert_not_called();store.observe.assert_not_called()

    def test_encrypted_response_survives_outage_and_replays_without_http(self):
        import tempfile,pymysql,queue
        from pathlib import Path
        from unittest.mock import MagicMock
        from farm.storage.mysql import Store
        from farm.collection.worker import Worker
        with tempfile.TemporaryDirectory() as tmp:
            store=object.__new__(Store);store.config_path=Path(tmp)/'mysql.json';store.key=lambda:b'K'*32
            store._lock_connections=queue.LifoQueue(2)
            con=MagicMock();con.cursor.return_value.__enter__.return_value.fetchone.return_value={'locked':1}
            store.connect=Mock(return_value=con)
            store.record_traffic=Mock()
            claim={'account':{'id':1,'account_id':2},'task':{'id':3,'endpoint':'shopInfo','target_id':'','shop_id':'4','shop_job_id':5,'run_id':6,'run_settings':{},'payload':{}},'owner':'original-owner','attempt_id':'a'*64,'business_date':'2026-10-02','locks':['test-account']}
            worker=Worker(store);worker.finish=Mock(side_effect=pymysql.err.OperationalError(2013,'lost'))
            with patch('farm.collection.worker.time.sleep'),patch('builtins.print'):
                with self.assertRaises(pymysql.err.OperationalError):
                    worker.durable_finish(claim,response={'name':'SYNTHETIC-PRIVATE-RESPONSE'},sent=True)
            files=list((Path(tmp)/'request-journal'/'6').glob('*.json'));self.assertEqual(len(files),1)
            self.assertNotIn('SYNTHETIC-PRIVATE-RESPONSE',files[0].read_text())
            self.assertEqual(files[0].stat().st_mode&0o777,0o600)
            restarted=Worker(store);restarted.finish=Mock(return_value={'outcome':'success'})
            with patch('requests.Session') as http:
                self.assertEqual(restarted.replay_pending(6),1);http.assert_not_called()
            self.assertEqual(restarted.finish.call_args.kwargs['response']['name'],'SYNTHETIC-PRIVATE-RESPONSE')
            store.record_traffic.assert_not_called()
            self.assertFalse(files[0].exists())

    def test_counters_are_absolute_and_repeated_sync_cannot_double_count(self):
        from contextlib import contextmanager
        from farm.collection.executions import ExecutionManager
        cursor=Mock();store=Mock()
        cursor.fetchone.side_effect=[{'id':31},{'processed':3,'sent':2,'valid_count':1}]*2
        @contextmanager
        def transaction():yield cursor
        store.transaction=transaction
        manager=ExecutionManager(store)
        job={'id':31,'run_id':183,'selection':{'_counter_base':{'processed':40,'sent':40,'valid_count':37}}}
        self.assertEqual(manager.record_progress(job),{'processed':43,'sent':42,'valid_count':38})
        self.assertEqual(manager.record_progress(job),{'processed':43,'sent':42,'valid_count':38})
        updates=[c.args[1][:3] for c in cursor.execute.call_args_list if c.args[0].startswith('UPDATE')]
        self.assertEqual(updates,[(43,42,38)]*2)

    def test_repeated_database_failures_back_off_and_keep_existing_export(self):
        from contextlib import contextmanager
        from farm.collection.executions import ExecutionManager
        from farm.storage.mysql import utcnow
        cursor=Mock();store=Mock()
        @contextmanager
        def transaction():yield cursor
        store.transaction=transaction
        manager=ExecutionManager(store);now=utcnow()
        for failures,expected in ((0,30),(1,60),(8,300)):
            job={'id':31,'run_id':183,'selection':{'_db_failures':failures}}
            with patch('farm.collection.executions.utcnow',return_value=now):manager.save_outcome(job,'waiting','database_unavailable',None)
            update=[c for c in cursor.execute.call_args_list if c.args[0].startswith('UPDATE executions')][-1]
            self.assertIsNone(update.args[1][2]);self.assertEqual((update.args[1][3]-now).total_seconds()+60,expected)
            self.assertIn('COALESCE',update.args[0])


class LocalPanelTests(unittest.TestCase):
    def test_local_batch_is_visible_without_database_or_private_material(self):
        from farm.web.app import local_run_summary
        identifier='local100-20261003T062631Z'
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);private=root/'private';exports=root/'exports'
            folder=private/identifier;output=exports/identifier
            folder.mkdir(parents=True);output.mkdir(parents=True)
            (folder/'manifest.json').write_text(json.dumps({'output':str(output),'shops':[{'shop_id':'7'}],
                'concurrency':2,'delay_seconds':4,'delay_scope':'productSpecifics','secret':'DO_NOT_EXPOSE'}))
            (output/'progress.json').write_text(json.dumps({'state':'blocked','stop_reason':'consecutive_cross_account_http403',
                'sent':4,'success':0,'http403':4,'tasks':{'pending':1}}))
            (output/'delivery-summary.json').write_text(json.dumps({'complete_shop_jobs':0,'items':0}))
            (output/'delivery.zip').write_bytes(b'public-delivery')
            (folder/'history.json').write_text(json.dumps({'shops':[{'shop_id':'7','name':'Example','closed':False,'tasks':{'shopInfo':{'retry_wait':1}}}],
                'requests':[{'attempt':1,'account_id':122,'endpoint':'shopInfo','at':'2026-10-03T00:00:01Z','http':403,'code':None,'outcome':'rejected','sent':True,'shop_id':'7','target':''}]}))
            store=Mock()
            store.rows.side_effect=AssertionError('local view must not query MySQL')
            store.transaction.side_effect=AssertionError('local view must not write MySQL')
            with patch('farm.web.app.LOCAL_RUN_ROOT',private),patch('farm.web.app.EXPORT_ROOT',exports):
                client=create_app(store).test_client()
                listing=client.get('/api/local-runs');self.assertEqual(listing.status_code,200)
                self.assertEqual(listing.json['runs'][0]['sent'],4)
                self.assertEqual(listing.json['runs'][0]['delay_scope'],'productSpecifics')
                self.assertNotIn('DO_NOT_EXPOSE',listing.text);self.assertNotIn(str(private),listing.text)
                detail=client.get('/api/local-runs/'+identifier)
                self.assertEqual(detail.status_code,200);self.assertEqual(detail.json['requests'][0]['http'],403)
                self.assertEqual(detail.json['shops'][0]['shop_id'],'7')
                download=client.get('/downloads/local/'+identifier+'/delivery.zip')
                self.assertEqual(download.data,b'public-delivery');download.close()
                self.assertEqual(client.get('/downloads/local/'+identifier+'/local.key').status_code,400)
                self.assertEqual(client.get('/api/local-runs/unknown').status_code,400)
                (output/'delivery.zip').unlink();(output/'delivery.zip').symlink_to(folder/'manifest.json')
                self.assertEqual(client.get('/downloads/local/'+identifier+'/delivery.zip').status_code,404)
                (folder/'manifest.json').write_text('bad json')
                self.assertEqual(client.get('/api/local-runs').json['unreadable'],[identifier])
            store.rows.assert_not_called();store.transaction.assert_not_called()

    def test_panel_collection_does_not_sleep_after_ordinary_endpoints(self):
        from farm.collection.executions import ExecutionManager
        import time
        store=Mock();manager=ExecutionManager(store);manager.record_progress=Mock()
        store.rows.return_value=[{'state':'running','owner':manager.owner,'stop_requested':False}]
        job={'id':1,'run_id':1,'account_ids':[1],'endpoints':['shopInfo'],'environment':'test','max_requests':2,'processed':0,'delay_seconds':4}
        with patch('farm.collection.executions.Worker') as worker:
            worker.return_value.claim.return_value={'account_id':1}
            worker.return_value.execute.return_value={'account_id':1,'endpoint':'shopInfo','sent':True,'outcome':'success'}
            start=time.monotonic()
            self.assertEqual(manager._collect(job,{'concurrency':1}),('limit','request_limit'))
            self.assertLess(time.monotonic()-start,1)
            self.assertEqual(worker.return_value.execute.call_count,2)
