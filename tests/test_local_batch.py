import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from farm import local_batch as L
from tests.test_mysql_farm import MysqlFarmTests
from farm.mysql_import import prepare_bundle

class LocalTests(unittest.TestCase):
    def test_stop_check_waits_for_shared_connection_transaction(self):
        with tempfile.TemporaryDirectory() as temp:
            r=self.setup_run(Path(temp),shops=1)
            entered=threading.Event();finished=threading.Event()
            def read_stop():
                entered.set()
                try:r.check_stop()
                finally:finished.set()
            worker=threading.Thread(target=read_stop)
            try:
                with r.lock,r.db:
                    r.set_meta('probe_inflight',False)
                    worker.start();self.assertTrue(entered.wait(2))
                    self.assertFalse(finished.wait(.1),'reader used the shared connection during another thread transaction')
                worker.join(2)
                self.assertTrue(finished.is_set());self.assertFalse(r.stop.is_set())
            finally:
                worker.join(2);r.db.close()

    def test_crash_recovery_keeps_quota_and_successful_results(self):
        with tempfile.TemporaryDirectory() as temp:
            r=self.setup_run(Path(temp),shops=2)
            with redirect_stdout(io.StringIO()):
                done=r.pick(0);r.finish(*done,*self.response(done[0]))
            pending=r.pick(0)
            with r.db:r.db.execute("UPDATE attempts SET sent=1,outcome='sent' WHERE id=?",(pending[2],))
            before={aid:json.loads(json.dumps(a['budgets'])) for aid,a in r.accounts.items()}
            r.recover()
            self.assertEqual({aid:a['budgets'] for aid,a in r.accounts.items()},before)
            self.assertEqual(r.db.execute('SELECT outcome FROM attempts WHERE id=?',(pending[2],)).fetchone()[0],'uncertain')
            self.assertEqual(r.db.execute('SELECT state FROM tasks WHERE id=?',(done[0]['id'],)).fetchone()[0],'succeeded')
            self.assertEqual(r.db.execute('SELECT COUNT(*) FROM results').fetchone()[0],1)
            self.assertEqual(r.db.execute('SELECT state FROM tasks WHERE id=?',(pending[0]['id'],)).fetchone()[0],'retry_wait')
            r.db.close()

    def setup_run(self,root,shops=2,delay=0,account_count=2):
        bundle,_,_=prepare_bundle(MysqlFarmTests().native_bundle())
        accounts=[{'id':n,'bundle':bundle,'budgets':{ep:{'used':0,'limit':85} for ep in L.ENDPOINTS},'blocked':{},'rest_until':0} for n in range(1,account_count+1)]
        manifest={'output':str(root/'export'),'shops':[dict(shop_id=str(i),latitude='-1',longitude='-2',city_id='3') for i in range(1,shops+1)],
                  'delay_seconds':delay,'concurrency':2,'proxy':'http://127.0.0.1:1'}
        L.init_db(root/'private',manifest,accounts,os.urandom(32))
        return L.LocalBatch(root/'private')

    def response(self,task):
        ep=task['endpoint']
        if ep=='shopInfo':data={'name':'shop','shopId':str(task['shop']),'status':4 if task['shop']==2 else 1}
        elif ep=='productList':data={'shopCategoryList':[{'shopCategoryId':1,'spuIdList':[10,11,12], 'spuList':[{'spuId':10,'name':'ordinary','haveMultiSpecs':0},{'spuId':11,'name':'custom','haveMultiSpecs':1}]}]}
        elif ep=='productRender':data={'shopCategoryList':[{'shopCategoryId':1,'spuList':[{'spuId':12,'name':'loaded custom','haveMultiSpecs':1}]}]}
        else:data={'spuId':int(task['target']),'name':'specifics','haveMultiSpecs':1,'skuList':[]}
        return {'code':0,'data':data,'_http_status':200},None,None,True,{'http_ms':1}

    def test_full_queue_closed_render_coverage_and_resume_without_mysql(self):
        with tempfile.TemporaryDirectory() as temp:
            r=self.setup_run(Path(temp));sent=[]
            def send(task,account,attempt):
                sent.append((task['shop'],task['endpoint'],task['target']));return self.response(task)
            with patch('farm.mysql_store.Store',side_effect=AssertionError('remote DB forbidden')),patch.object(r,'send',side_effect=send),redirect_stdout(io.StringIO()):
                result=r.run()
            self.assertEqual(result['state'],'complete');self.assertEqual(len(sent),8)
            self.assertEqual({x[2] for x in sent if x[1]=='productSpecifics'},{'11','12'})
            self.assertFalse(any(x[0]==2 and x[1]=='productSpecifics' for x in sent))
            self.assertEqual(result['tasks']['skipped_closed'],2)
            self.assertEqual(result['delivery']['complete_shop_jobs'],2)
            self.assertEqual(result['delivery']['items'],6)
            self.assertNotIn('account_cost_cny',result)
            self.assertNotIn('uploaded_bytes',result)
            self.assertFalse((r.output/'costs.json').exists())
            import zipfile
            with zipfile.ZipFile(r.output/'delivery.zip') as archive:
                self.assertIn('summary.json',archive.namelist())
                self.assertNotIn('costs.json',archive.namelist())
            resumed=L.LocalBatch(Path(temp)/'private')
            with patch.object(resumed,'send',side_effect=AssertionError('repeated request')),redirect_stdout(io.StringIO()):
                self.assertEqual(resumed.run()['state'],'complete')

    def test_unavailable_menu_retains_items_without_sending_details(self):
        with tempfile.TemporaryDirectory() as temp:
            r=self.setup_run(Path(temp),shops=1);sent=[]
            def send(task,account,attempt):
                sent.append(task['endpoint']);result=self.response(task)
                if task['endpoint'] in ('productList','productRender'):
                    for cat in result[0]['data']['shopCategoryList']:
                        for p in cat['spuList']:p['availableStatus']=0
                return result
            with patch.object(r,'send',side_effect=send),redirect_stdout(io.StringIO()):report=r.run()
            self.assertEqual(sent,['shopInfo','productList','productRender'])
            self.assertEqual(report['state'],'complete');self.assertEqual(report['tasks']['skipped_unavailable'],2)
            self.assertEqual(report['delivery']['items'],3)
            self.assertTrue(all(a['budgets']['productSpecifics']['used']==0 for a in r.accounts.values()))
            check=json.loads((r.output/'delivery.coverage.json').read_text())['shops'][0]
            self.assertEqual(check['unavailable_detail_ids'],['11','12'])
            self.assertFalse(check['full_data_complete']);self.assertTrue(check['complete'])
            r.db.close()

    def test_unavailable_response_is_not_success_or_retry_and_requires_menu_record(self):
        for known in (True,False):
            with self.subTest(known=known),tempfile.TemporaryDirectory() as temp:
                r=self.setup_run(Path(temp),shops=1)
                with redirect_stdout(io.StringIO()):
                    for _ in range(3):
                        claim=r.pick(0);r.finish(*claim,*self.response(claim[0]))
                    claim=r.pick(0)
                    self.assertEqual(claim[0]['endpoint'],'productSpecifics')
                    if not known:
                        with r.db:r.db.execute("DELETE FROM results WHERE endpoint IN ('productList','productRender')")
                    r.finish(*claim,{'_http_status':200,'code':201003212},None,None,True,{})
                state,reason=r.db.execute('SELECT state,reason FROM tasks WHERE id=?',(claim[0]['id'],)).fetchone()
                self.assertEqual(state,'skipped_unavailable' if known else 'retry_wait')
                self.assertEqual(r.db.execute('SELECT outcome FROM attempts WHERE id=?',(claim[2],)).fetchone()[0],'business_error')
                self.assertEqual(claim[1]['budgets']['productSpecifics']['used'],1)
                if known:
                    check=r.export();self.assertEqual(check['partial_shop_jobs'],1) # Other detail is still required.
                r.db.close()

    def test_new_menu_evidence_revokes_stale_unavailable_skip_without_resetting_attempts(self):
        with tempfile.TemporaryDirectory() as temp:
            r=self.setup_run(Path(temp),shops=1)
            with redirect_stdout(io.StringIO()):
                claim=r.pick(0);r.finish(*claim,*self.response(claim[0]))
                claim=r.pick(0);response=self.response(claim[0])
                response[0]['data']['shopCategoryList'][0]['spuList'][1]['availableStatus']=0
                r.finish(*claim,*response)
            skipped=r.db.execute("SELECT id FROM tasks WHERE state='skipped_unavailable'").fetchone()[0]
            for attempts,expected in ((0,'pending'),(3,'failed')):
                with r.db:
                    response[0]['data']['shopCategoryList'][0]['spuList'][1]['availableStatus']=1
                    r.db.execute('UPDATE results SET payload=? WHERE task=?',(json.dumps(response[0]),claim[0]['id']))
                    r.db.execute("UPDATE tasks SET state='skipped_unavailable',reason='product_unavailable_menu',attempts=? WHERE id=?",(attempts,skipped))
                    r.reconcile_unavailable_details()
                actual=r.db.execute('SELECT state,attempts FROM tasks WHERE id=?',(skipped,)).fetchone()
                self.assertEqual(tuple(actual),(expected,attempts))
            r.db.close()

    def test_403_blocks_endpoint_and_details_rest_account(self):
        with tempfile.TemporaryDirectory() as temp:
            r=self.setup_run(Path(temp),1)
            task,account,attempt=r.pick(0)
            with redirect_stdout(io.StringIO()):r.finish(task,account,attempt,{'_http_status':403},None,None,True,{})
            self.assertGreater(account['blocked']['shopInfo'],time.time())
            self.assertEqual(r.db.execute('SELECT used FROM (SELECT 1 used)').fetchone()[0],1)
            self.assertEqual(account['budgets']['shopInfo']['used'],1)
            # A failed prerequisite must not keep the scheduler spinning forever.
            with r.db:r.db.execute("UPDATE tasks SET state='failed' WHERE endpoint='shopInfo'")
            self.assertFalse(r.pending_possible())

    def test_ordinary_requests_have_no_delay_but_account_lock_and_budget_are_shared(self):
        with tempfile.TemporaryDirectory() as temp:
            r=self.setup_run(Path(temp),3,delay=4)
            first=r.pick(0);second=r.pick(1)
            self.assertNotEqual(first[1]['id'],second[1]['id'])
            self.assertIsNone(r.pick(2))
            with redirect_stdout(io.StringIO()):r.finish(*first,*self.response(first[0]))
            next_claim=r.pick(2)
            self.assertIsNotNone(next_claim)
            self.assertEqual(next_claim[1]['id'],first[1]['id'])
            self.assertEqual(first[1]['budgets']['shopInfo']['used'],1)

    def test_only_details_wait_and_ordinary_work_can_fill_the_gap(self):
        with tempfile.TemporaryDirectory() as temp:
            r=self.setup_run(Path(temp),shops=2,delay=4,account_count=1)
            with redirect_stdout(io.StringIO()):
                for expected in ('shopInfo','productList','productRender','productSpecifics'):
                    claim=r.pick(0)
                    self.assertIsNotNone(claim)
                    self.assertEqual(claim[0]['endpoint'],expected)
                    r.finish(*claim,*self.response(claim[0]))
                # The second detail is not yet due, but the next shop may load immediately.
                claim=r.pick(1)
                self.assertEqual(claim[0]['endpoint'],'shopInfo')
                self.assertEqual(claim[0]['shop'],2)
                r.finish(*claim,*self.response(claim[0]))
                with r.db:r.db.execute("UPDATE tasks SET state='succeeded' WHERE shop=2 AND endpoint='productList'")
                self.assertIsNone(r.pick(0))
                # Ordinary requests must not reset the detail timer.
                r.last_detail_end[1]-=4.01
                self.assertEqual(r.pick(0)[0]['endpoint'],'productSpecifics')

    def test_a2_and_local_signer_state_survive_transport(self):
        with tempfile.TemporaryDirectory() as temp:
            r=self.setup_run(Path(temp),1)
            task,account,attempt=r.pick(0)
            class Route:
                traffic={}
                def __init__(self,*a,**kw):
                    if kw.get('measure'):raise AssertionError('metering must stay disabled')
                def __enter__(self):return 'http://127.0.0.1:1'
                def __exit__(self,*a):pass
            def send(session,wire,**kw):
                saved=r.vault.open(r.db.execute('SELECT blob FROM accounts WHERE id=?',(account['id'],)).fetchone()[0])
                mt=json.loads(wire.headers['mtgsig']);col=json.loads(L.decode_a5(mt['a5'],mt['a1'],mt['a3'],mt['a4'])[0])
                self.assertEqual(saved['bundle']['device']['sign_sequence'],col['b2'])
                raise TimeoutError('synthetic')
            with patch.object(L,'ProxyRoute',Route),patch('requests.Session.send',send):result=r.send(task,account,attempt)
            self.assertTrue(result[3]);self.assertEqual(result[2],'TimeoutError')
            with redirect_stdout(io.StringIO()):r.finish(task,account,attempt,*result)
            self.assertFalse(r.stop.is_set());self.assertEqual(account['budgets']['shopInfo']['used'],1)
            self.assertGreater(r.network_until,time.time())
            self.assertTrue(r.pending_possible())
            self.assertIsNone(r.pick(0))
            resumed=L.LocalBatch(r.folder)
            self.assertEqual(resumed.network_until,r.network_until)
            self.assertFalse(resumed.stop.is_set())

    def test_accounts_rotate_and_cooldown_wait_survives_restart(self):
        with tempfile.TemporaryDirectory() as temp:
            r=self.setup_run(Path(temp),shops=5,account_count=3)
            used=[]
            with redirect_stdout(io.StringIO()):
                for _ in range(3):
                    claim=r.pick(0);used.append(claim[1]['id']);r.finish(*claim,*self.response(claim[0]))
            self.assertEqual(used,[1,2,3])
            now=time.time()
            with r.db:
                for a in r.accounts.values():a['rest_until']=now+3600;r.save_account(a)
            self.assertIsNone(r.pick(0))
            self.assertTrue(r.pending_possible())
            self.assertEqual(r.waiting()['reason'],'account_cooldown')
            resumed=L.LocalBatch(r.folder)
            self.assertTrue(resumed.pending_possible())
            with patch.object(L.time,'time',return_value=now+3601):self.assertIsNotNone(resumed.pick(0))

    def test_recommendation_page_and_context_reach_the_signed_wire(self):
        with tempfile.TemporaryDirectory() as temp:
            r=self.setup_run(Path(temp),shops=1,account_count=1)
            self.addCleanup(r.db.close)
            account=r.accounts[1]
            account['budgets']['homeShopList']={'used':0,'limit':20}
            template=r.contexts[1].templates['/api/v4/homePage/homeShopList']
            template.setdefault('headers',dict(r.contexts[1].base['headers']))['pagesource']='5'
            with r.db:
                r.db.execute("UPDATE tasks SET state='succeeded' WHERE endpoint='shopInfo'")
                r.db.execute("DELETE FROM tasks WHERE endpoint='productList'")
                r.enqueue(1,'homeShopList','',{'page':3,'bizTraceId':'observed-list-trace'})
            claim=r.pick(0)
            self.assertEqual(claim[0]['endpoint'],'homeShopList')
            def send(session,wire,**kwargs):
                self.assertEqual(json.loads(wire.body)['pageNo'],3)
                self.assertEqual(json.loads(wire.body)['bizTraceId'],'observed-list-trace')
                self.assertEqual(wire.headers['pagesource'],'5')
                raise TimeoutError('synthetic')
            with patch('requests.Session.send',send):result=r.send(*claim)
            self.assertTrue(result[3]);self.assertEqual(result[2],'TimeoutError')

    def test_different_route_caps_preserve_three_total_slots(self):
        with tempfile.TemporaryDirectory() as temp:
            r=self.setup_run(Path(temp),shops=6,account_count=6)
            self.addCleanup(r.db.close)
            r.manifest['per_route_concurrency']={'first':1,'second':2}
            r.routes={key:{'proxy':'http://127.0.0.1:1'} for key in ('first','second')}
            for aid,account in r.accounts.items():account['route_id']='first' if aid%2 else 'second'
            claims=[r.pick(lane) for lane in range(3)]
            self.assertTrue(all(claims))
            self.assertEqual(sorted(r.route_id(c[1]) for c in claims),['first','second','second'])
            self.assertIsNone(r.pick(3))

    def test_new_business_day_archives_usage_without_clearing_rest(self):
        with tempfile.TemporaryDirectory() as temp:
            r=self.setup_run(Path(temp),account_count=1)
            now=time.time();account=r.accounts[1]
            with r.db:
                r.renew_daily_budgets(now)
                for b in account['budgets'].values():b['used']=b['limit']
                account['rest_until']=now+90000;r.save_account(account)
            self.assertTrue(r.pending_possible())
            day=r.meta('budget_day')
            with r.db:r.renew_daily_budgets(now)
            self.assertEqual(account['budgets']['shopInfo']['used'],85)
            with r.db:r.renew_daily_budgets(now+86400)
            self.assertEqual(account['budgets']['shopInfo']['used'],0)
            self.assertEqual(r.meta('budget_history:'+day)['1']['shopInfo']['used'],85)
            self.assertEqual(account['rest_until'],now+90000)
            self.assertIsNone(r.pick(0))

    def test_dynamic_route_refresh_is_idle_bounded_and_does_not_clear_cooldown(self):
        with tempfile.TemporaryDirectory() as temp:
            r=self.setup_run(Path(temp),account_count=1)
            config={'proxy':'http://synthetic:password@gate.ipfoxy.io:80','front_proxy':'http://127.0.0.1:7897','refresh_ipfoxy':True}
            (r.folder/'route.enc').write_bytes(r.vault.seal(config))
            self.assertEqual(r.route_config(),config)
            r.accounts[1]['blocked']['shopInfo']=time.time()+500
            with r.db:r.set_meta('route_refresh_pending',True)
            with patch.object(L,'refresh_ipfoxy',return_value={'accepted':True,'ip_changed':False}) as refresh:
                self.assertIsNone(r.pick(0))  # Drain the route before rotating it.
                r.busy.add(1);r.maybe_refresh_route();refresh.assert_not_called()
                r.busy.clear();r.maybe_refresh_route();refresh.assert_called_once_with(config['proxy'],config['front_proxy'])
                with r.db:r.set_meta('route_refresh_pending',True)
                r.maybe_refresh_route();self.assertEqual(refresh.call_count,1)
            self.assertGreater(r.accounts[1]['blocked']['shopInfo'],time.time())

    def test_unsent_request_crossing_midnight_refunds_original_day(self):
        with tempfile.TemporaryDirectory() as temp:
            r=self.setup_run(Path(temp),account_count=1)
            claim=r.pick(0);day=r.meta('budget_day')
            with r.db:r.renew_daily_budgets(time.time()+86400)
            with redirect_stdout(io.StringIO()):r.finish(*claim,{},None,'ValueError',False,{})
            self.assertEqual(r.accounts[1]['budgets']['shopInfo']['used'],0)
            self.assertEqual(r.meta('budget_history:'+day)['1']['shopInfo']['used'],0)

    def test_cross_account_403_stops_before_exhausting_pool_and_survives_restart(self):
        with tempfile.TemporaryDirectory() as temp:
            r=self.setup_run(Path(temp),shops=20,account_count=24)
            with patch.object(r,'send',return_value=({'_http_status':403},None,None,True,{})),redirect_stdout(io.StringIO()):
                result=r.run()
            self.assertEqual(result['state'],'blocked')
            self.assertEqual(result['stop_reason'],'consecutive_cross_account_http403')
            self.assertGreaterEqual(result['sent'],4)
            self.assertLessEqual(result['sent'],5)  # One other lane may already be in flight.
            self.assertLessEqual(len(result['accounts']),5)
            self.assertGreater(result['tasks']['pending'],0)
            resumed=L.LocalBatch(Path(temp)/'private')
            self.assertTrue(resumed.stop.is_set())
            self.assertIsNone(resumed.pick(0))
            self.assertEqual(resumed.fatal,'consecutive_cross_account_http403')

    def test_success_resets_rejection_streak_and_stop_reason_is_not_misattributed(self):
        with tempfile.TemporaryDirectory() as temp:
            r=self.setup_run(Path(temp),shops=8,account_count=8)
            for status in (403,403,200,403,403,403):
                claim=r.pick(0)
                self.assertIsNotNone(claim)
                response=self.response(claim[0]) if status==200 else ({'_http_status':403},None,None,True,{})
                with redirect_stdout(io.StringIO()):r.finish(*claim,*response)
            self.assertFalse(r.stop.is_set())
            self.assertEqual(len(r.consecutive_403),3)
            (r.folder/'STOP').write_text('agent_pause: consecutive cross-account HTTP 403')
            self.assertIsNone(r.pick(0))
            self.assertEqual(r.fatal,'consecutive_cross_account_http403')

    def test_explicit_resume_keeps_usage_and_cooldowns_but_starts_new_streak(self):
        with tempfile.TemporaryDirectory() as temp:
            r=self.setup_run(Path(temp),shops=20,account_count=12)
            for _ in range(4):
                claim=r.pick(0)
                with redirect_stdout(io.StringIO()):r.finish(*claim,{'_http_status':403},None,None,True,{})
            with r.db:r.db.execute("UPDATE meta SET value='blocked' WHERE key='state'")
            before={aid:json.loads(json.dumps(a)) for aid,a in r.accounts.items()}
            record=L.acknowledge_resume(r.folder)
            resumed=L.LocalBatch(r.folder)
            self.assertFalse(resumed.stop.is_set());self.assertEqual(record['resume_after_attempt'],4)
            self.assertEqual(resumed.accounts,before)
            self.assertEqual(resumed.db.execute('SELECT COUNT(*) FROM attempts').fetchone()[0],4)
            for _ in range(4):
                claim=resumed.pick(0);self.assertIsNotNone(claim)
                with redirect_stdout(io.StringIO()):resumed.finish(*claim,{'_http_status':403},None,None,True,{})
            self.assertTrue(resumed.stop.is_set())
            status=resumed.status('blocked')
            self.assertEqual((status['sent'],status['session_sent'],status['session_http403']),(8,4,4))
            resumed.db.close();r.db.close()

    def test_explicit_resume_rejects_unresolved_request_without_removing_stop(self):
        with tempfile.TemporaryDirectory() as temp:
            r=self.setup_run(Path(temp));r.pick(0)
            (r.folder/'STOP').write_text('user stop')
            with self.assertRaises(ValueError):L.acknowledge_resume(r.folder)
            self.assertTrue((r.folder/'STOP').exists());r.db.close()
        with tempfile.TemporaryDirectory() as temp:
            r=self.setup_run(Path(temp))
            (r.folder/'STOP').write_text('')
            self.assertIsNone(r.pick(0))
            self.assertEqual(r.fatal,'user_stop')

    def setup_routes(self,root):
        r=self.setup_run(root,shops=6,account_count=6)
        routes={'ipfoxy':{'proxy':'http://synthetic:password@gate.ipfoxy.io:80','front_proxy':'http://127.0.0.1:7897','refresh_ipfoxy':True},
                'clash-a':{'proxy':'http://127.0.0.1:18154'},'clash-b':{'proxy':'http://127.0.0.1:18160'}}
        with r.db:
            for aid,a in r.accounts.items():a['route_id']=list(routes)[(aid-1)%3];r.save_account(a)
        (r.folder/'routes.enc').write_bytes(r.vault.seal(routes))
        r.db.close()
        return L.LocalBatch(root/'private')

    def test_three_routes_each_have_one_request_and_accounts_rotate(self):
        with tempfile.TemporaryDirectory() as temp:
            r=self.setup_routes(Path(temp));claims=[r.pick(n) for n in range(3)]
            self.assertEqual({r.route_id(c[1]) for c in claims},{'ipfoxy','clash-a','clash-b'})
            self.assertIsNone(r.pick(4))
            with redirect_stdout(io.StringIO()):r.finish(*claims[0],*self.response(claims[0][0]))
            replacement=r.pick(0)
            self.assertEqual(replacement[1]['id'],4)
            self.assertEqual(r.route_id(replacement[1]),'ipfoxy')

    def test_network_failure_waits_only_affected_route_and_survives_restart(self):
        with tempfile.TemporaryDirectory() as temp:
            r=self.setup_routes(Path(temp));failed=r.pick(0)
            with redirect_stdout(io.StringIO()):r.finish(*failed,{},None,'ProxyError',True,{})
            self.assertGreater(r.network_wait(r.accounts[1]),time.time())
            claims=[r.pick(n) for n in (1,2)]
            self.assertEqual({r.route_id(c[1]) for c in claims},{'clash-a','clash-b'})
            resumed=L.LocalBatch(r.folder)
            self.assertEqual(resumed.network_wait(resumed.accounts[1]),r.network_wait(r.accounts[1]))
            self.assertEqual(resumed.network_wait(resumed.accounts[2]),0)

    def test_send_uses_bound_route_and_logs_no_proxy_password(self):
        with tempfile.TemporaryDirectory() as temp:
            r=self.setup_routes(Path(temp))
            for _ in range(3):
                claim=r.pick(0)
                with patch.object(L,'ProxyRoute') as route,patch('requests.Session.send',side_effect=TimeoutError('synthetic')):
                    route.return_value.__enter__.return_value='http://127.0.0.1:1'
                    result=r.send(*claim)
                    config=r.route_config(claim[1]);route.assert_called_once_with(config['proxy'],config.get('front_proxy'))
                with redirect_stdout(io.StringIO()):r.finish(*claim,*result)
            log=(r.output/'requests.jsonl').read_text()
            self.assertNotIn('password',log)
            self.assertEqual({json.loads(s)['route_id'] for s in log.splitlines()},{'ipfoxy','clash-a','clash-b'})

    def test_refresh_does_not_hold_other_routes_or_clear_limits(self):
        with tempfile.TemporaryDirectory() as temp:
            r=self.setup_routes(Path(temp));started=threading.Event();release=threading.Event()
            with r.db:r.set_meta(r.route_meta_key('route_refresh_pending','ipfoxy'),True)
            def refresh(*args):started.set();release.wait(2);return {'accepted':True,'ip_changed':False}
            with patch.object(L,'refresh_ipfoxy',side_effect=refresh):
                thread=threading.Thread(target=r.maybe_refresh_route);thread.start()
                try:
                    self.assertTrue(started.wait(1))
                    claims=[r.pick(n) for n in (0,1)]
                    self.assertEqual({r.route_id(c[1]) for c in claims},{'clash-a','clash-b'})
                finally:release.set();thread.join(2)
            self.assertEqual(r.accounts[1]['budgets']['shopInfo']['used'],0)
            self.assertFalse(r.meta(r.route_meta_key('route_refresh_pending','ipfoxy')))

    def test_three_route_queue_completes_open_details_and_closed_skip(self):
        with tempfile.TemporaryDirectory() as temp:
            r=self.setup_routes(Path(temp));r.manifest['concurrency']=3
            with patch('farm.mysql_store.Store',side_effect=AssertionError('remote forbidden')),patch.object(r,'send',side_effect=lambda t,a,i:self.response(t)),redirect_stdout(io.StringIO()):
                report=r.run()
            self.assertEqual(report['state'],'complete')
            self.assertEqual(report['delivery']['complete_shop_jobs'],6)
            self.assertEqual(r.db.execute("SELECT COUNT(*) FROM attempts WHERE endpoint='productSpecifics' AND outcome='success'").fetchone()[0],10)
            self.assertEqual(report['tasks']['skipped_closed'],2)
            self.assertEqual(set(report['routes']),{'ipfoxy','clash-a','clash-b'})

    def test_unhealthy_route_never_spends_account_quota_until_transport_recovers(self):
        with tempfile.TemporaryDirectory() as temp:
            r=self.setup_routes(Path(temp))
            with r.db:r.set_meta(r.route_meta_key('health_pending','ipfoxy'),True)
            self.assertEqual(r.route_id(r.pick(0)[1]),'clash-a')
            self.assertEqual(r.accounts[1]['budgets']['shopInfo']['used'],0)
            with patch.object(L,'ProxyRoute'),patch('requests.Session.get',side_effect=TimeoutError('offline')) as get:
                r.maybe_check_route(r.accounts[1]);r.maybe_check_route(r.accounts[1])
                self.assertEqual(get.call_count,1)
            self.assertTrue(r.meta(r.route_meta_key('health_pending','ipfoxy')))
            with r.db:r.set_meta(r.route_meta_key('health_retry_at','ipfoxy'),0)
            with patch.object(L,'ProxyRoute'),patch('requests.Session.get') as get:
                get.return_value.json.return_value={'ip':'192.0.2.8'}
                r.maybe_check_route(r.accounts[1])
            self.assertFalse(r.meta(r.route_meta_key('health_pending','ipfoxy')))
            self.assertTrue(r.route_ready(r.accounts[1],time.time()))

if __name__=='__main__':unittest.main()
