"""Selection boundaries, safe local panel access, and strict task input."""
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import re
import tempfile
import threading
import unittest
from unittest.mock import Mock,patch
import openpyxl

from farm.mysql_selection import parse_ids, parse_tags, selection_clause
from farm.mysql_import import carry_counters
from farm.panel import create_app, split_curls, StateCache, state_reader
from farm.mysql_store import Store
from farm.tasks import load_tasks


class PanelTests(unittest.TestCase):
    def test_batch_scope_skips_account_queries_and_caches_by_date(self):
        store=Mock();store.rows.return_value=[]
        client=create_app(store).test_client()
        first=client.get('/api/state?scope=batches&date=2026-10-02')
        self.assertEqual(first.status_code,200)
        self.assertEqual(first.json['runs'],[])
        self.assertNotIn('accounts',first.json)
        self.assertEqual(store.rows.call_count,2)
        store.get_setting.assert_not_called()
        self.assertEqual(client.get('/api/state?scope=batches&date=2026-10-02').json,first.json)
        self.assertEqual(store.rows.call_count,2)
        client.get('/api/state?scope=batches&date=2026-10-01')
        self.assertEqual(store.rows.call_count,4)
        self.assertEqual(client.get('/api/state?scope=bad').status_code,400)

    def test_successful_mutation_invalidates_dashboard_cache(self):
        store=Mock();store.rows.return_value=[]
        client=create_app(store).test_client()
        csrf=re.search(r'name="csrf-token" content="([^"]+)"',client.get('/').text)[1]
        client.get('/api/state?scope=batches')
        with patch('farm.panel.set_profile',return_value={'updated':True}):
            result=client.post('/api/accounts/profile',json={'ids':[1],'environment':'test'},headers={'X-Panel-CSRF':csrf})
        self.assertEqual(result.status_code,200)
        client.get('/api/state?scope=batches')
        self.assertEqual(store.rows.call_count,4)

    def test_dashboard_snapshot_uses_one_connection_for_all_reads(self):
        from contextlib import contextmanager
        store=Store.__new__(Store);cursor=Mock()
        cursor.fetchall.side_effect=[[],[],[{'encrypted':'fixture'}]]
        store.unseal=Mock(return_value={'1':'node-a'})
        @contextmanager
        def transaction():
            yield cursor
        store.transaction=Mock(side_effect=transaction)
        with state_reader(store) as reader:
            reader.rows('SELECT 1');reader.rows('SELECT 2')
            self.assertEqual(reader.get_setting('clash_node_bindings'),{'1':'node-a'})
        self.assertEqual(store.transaction.call_count,1)
        self.assertEqual(cursor.execute.call_count,3)

    def test_concurrent_dashboard_reads_share_one_load(self):
        cache=StateCache();entered=threading.Event();release=threading.Event()
        def load():
            entered.set()
            self.assertTrue(release.wait(5))
            return {'runs':[1]}
        loader=Mock(side_effect=load)
        with ThreadPoolExecutor(max_workers=2) as pool:
            first=pool.submit(cache.get,'today',loader)
            self.assertTrue(entered.wait(5))
            second=pool.submit(cache.get,'today',loader)
            release.set()
            self.assertEqual(first.result(5),second.result(5))
        loader.assert_called_once()
        value=cache.get('today',loader);value['runs'].clear()
        self.assertEqual(cache.get('today',loader),{'runs':[1]})

    def test_mutation_during_read_does_not_recache_old_snapshot(self):
        cache=StateCache();entered=threading.Event();release=threading.Event()
        def old():
            entered.set();self.assertTrue(release.wait(5));return {'value':'old'}
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending=pool.submit(cache.get,'today',old)
            self.assertTrue(entered.wait(5));cache.invalidate();release.set();pending.result(5)
        self.assertEqual(cache.get('today',lambda:{'value':'new'}),{'value':'new'})

    def test_failed_read_is_not_cached_and_does_not_block_retry(self):
        cache=StateCache();load=Mock(side_effect=[RuntimeError('offline'),{'ok':True}])
        with self.assertRaises(RuntimeError):cache.get('today',load)
        self.assertEqual(cache.get('today',load),{'ok':True})

    def test_proxy_pool_view_never_exposes_core_credentials(self):
        store=Mock();store.get_setting.return_value={'secret':'PRIVATE-CONTROL-SECRET','core':'PRIVATE-PATH',
            'nodes':[{'name':'node-a','proxy':'http://127.0.0.1:18100','exit_ip':'192.0.2.1'}]}
        response=create_app(store).test_client().get('/api/proxy-pool')
        self.assertEqual(response.status_code,200);self.assertEqual(response.json['verified_exits'],1)
        self.assertNotIn('PRIVATE',response.text)

    def test_execution_api_passes_concurrency_and_proxy_mutations_require_csrf(self):
        client=create_app(Mock()).test_client()
        self.assertEqual(client.post('/api/accounts/proxy',json={'ids':[1]}).status_code,403)
        csrf=re.search(r'name="csrf-token" content="([^"]+)"',client.get('/').text)[1]
        with patch('farm.panel.create_execution',return_value={'execution_id':1}) as create:
            response=client.post('/api/executions',json={'run_id':1,'environment':'test','ids':[1,2],'concurrency':2},headers={'X-Panel-CSRF':csrf})
        self.assertEqual(response.status_code,200);self.assertEqual(create.call_args.kwargs['concurrency'],2)

    def test_proxy_api_preserves_explicit_node_selection(self):
        client=create_app(Mock()).test_client()
        csrf=re.search(r'name="csrf-token" content="([^"]+)"',client.get('/').text)[1]
        with patch('farm.proxy.assign_account_proxies',return_value=[]) as assign:
            response=client.post('/api/accounts/proxy',json={'ids':'71','mode':'clash_pool','node_name':'node-b'},headers={'X-Panel-CSRF':csrf})
        self.assertEqual(response.status_code,200)
        self.assertEqual(assign.call_args.kwargs['node_name'],'node-b')

    def test_unknown_node_rejected_before_account_change(self):
        from farm.proxy import assign_account_proxies
        store=Mock();store.get_setting.return_value={'nodes':[{'name':'known','proxy':'http://127.0.0.1:18100'}]}
        with self.assertRaises(ValueError):assign_account_proxies(store,[71],node_name='missing')
        store.connect.assert_not_called();store.seal.assert_not_called()

    def test_failed_response_view_keeps_missing_history_explicit(self):
        from datetime import datetime
        store=Mock();store.rows.return_value=[{'id':'abc','account_id':71,'endpoint':'productRender',
            'http_status':403,'outcome':'rejected','started_at':datetime(2026,9,30),'has_response':0}]
        client=create_app(store).test_client()
        self.assertEqual(client.get('/api/requests/failures').status_code,400)
        result=client.get('/api/requests/failures?run_id=68')
        self.assertEqual(result.status_code,200);self.assertIsNone(result.json['failures'][0]['response'])
        store.failure_response.assert_not_called()

    def test_bulk_identity_check_keeps_local_failures_separate_and_stops_on_network(self):
        store=Mock();client=create_app(store).test_client()
        csrf=re.search(r'name="csrf-token" content="([^"]+)"',client.get('/').text)[1]
        accounts=[{'id':i} for i in range(1,5)]
        with patch('farm.panel.select_accounts',return_value=accounts),patch('farm.panel.probe_account') as probe,patch('time.sleep'):
            probe.side_effect=[ValueError('PRIVATE-ERROR'),{'outcome':'success','sent':True},
                                                  {'outcome':'transport_error','sent':True}]
            response=client.post('/api/accounts/validate',json={'environment':'test','ids':'1-4'},headers={'X-Panel-CSRF':csrf})
        self.assertEqual(response.status_code,200);data=response.json
        self.assertEqual((data['sent'],data['verified'],len(data['results'])),(2,1,3))
        self.assertEqual(data['results'][0]['status'],'local_construction_error')
        self.assertNotIn('PRIVATE-ERROR',response.text)
        self.assertEqual(probe.call_count,3)

    def test_selection_intersection_and_empty_list_never_expands(self):
        self.assertEqual(parse_ids('1,3,5-7,3'),[1,3,5,6,7])
        self.assertIsNone(parse_ids(''))
        self.assertEqual(parse_ids([]),[])
        query,args=selection_clause('test',[1,3],['BLUE','custom'])
        self.assertEqual(args,['test',1,3,'blue','custom'])
        self.assertIn('account_profiles',query)
        self.assertIn('account_tags',query)
        self.assertIn('FALSE',selection_clause('production',[])[0])
        for invalid in ('7-2','0','1;DROP TABLE accounts','1-999999'):
            with self.assertRaises(ValueError):parse_ids(invalid)
        with self.assertRaises(ValueError):parse_tags(['bad tag'])

    def test_panel_blocks_cross_origin_and_dns_rebinding(self):
        store=Mock();app=create_app(store);client=app.test_client()
        self.assertEqual(client.get('/',headers={'Host':'other.example'}).status_code,403)
        page=client.get('/');self.assertEqual(page.status_code,200)
        csrf=re.search(r'name="csrf-token" content="([^"]+)"',page.text)[1]
        self.assertEqual(client.post('/api/executions',json={}).status_code,403)
        self.assertEqual(client.post('/api/executions',json={},headers={'X-Panel-CSRF':csrf,'Origin':'https://other.example'}).status_code,403)
        store.rows.assert_not_called()
        self.assertIn("frame-ancestors 'none'",page.headers['Content-Security-Policy'])

    def test_errors_do_not_echo_credentials(self):
        store=Mock();store.rows.side_effect=RuntimeError('password=TEST-MUST-NOT-LEAK')
        response=create_app(store).test_client().get('/api/state')
        self.assertEqual(response.status_code,500)
        self.assertNotIn('TEST-MUST-NOT-LEAK',response.text)

    def test_task_input_rejects_bad_rows_instead_of_silently_omitting(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'tasks.xlsx';wb=openpyxl.Workbook();ws=wb.active
            ws.append(['shop_id','crawl_lat','crawl_lng','city_id'])
            ws.append(['123','-23.5','-46.6','42']);wb.save(path)
            task=load_tasks(path,strict=True)[0];self.assertEqual(task.city,'42')
            ws.append(['124',None,0,'42']);wb.save(path)
            with self.assertRaises(ValueError):load_tasks(path,strict=True)
            ws.delete_rows(3);ws.append(['125','nan',0,'42']);wb.save(path)
            with self.assertRaises(ValueError):load_tasks(path,strict=True)

    def test_batch_curls_keep_multiline_command_together(self):
        self.assertEqual(len(split_curls('curl -H "x: 1" \\\n https://example.test\ncurl -H "x: 2" https://example.test')),2)

    def test_reimport_preserves_high_water_only_for_proven_session(self):
        from copy import deepcopy
        original={'request':{'headers':{'appsession':'S'}},'device':{'a1':'A','base_collect':{'b7':12},'sign_sequence':5,'signature_counter':2}}
        newer=deepcopy(original);newer['device'].update(sign_sequence=20,signature_counter=30)
        current=deepcopy(original);carry_counters(current,newer)
        self.assertEqual(current['device']['counter'],20)
        self.assertEqual(current['device']['signature_counter'],30)
        current=deepcopy(original);current['request']['headers']['appsession']='NEW'
        carry_counters(current,newer);self.assertEqual(current['device']['sign_sequence'],5)


if __name__=='__main__':unittest.main()
