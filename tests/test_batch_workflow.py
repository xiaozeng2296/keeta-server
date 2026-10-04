"""Offline acceptance of portable batch entrypoints; no real account/network calls."""
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from farm import batch_run, batch_audit, batch_watch, batch_prepare, recommendations
from farm.local_batch import atomic_json
from tests import test_local_batch as fixtures


class BatchWorkflowTests(unittest.TestCase):
    def test_run_audit_and_resume_keep_completed_requests(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture=fixtures.LocalTests();r=fixture.setup_run(Path(temp));folder=r.folder
            r.manifest.update(verify_open=False,per_route_concurrency={})
            atomic_json(folder/'manifest.json',r.manifest);r.db.close()
            with patch.object(sys,'argv',['batch_run',str(folder)]),patch('farm.local_batch.LocalBatch.send',side_effect=lambda t,a,i:fixture.response(t)),redirect_stdout(io.StringIO()):
                batch_run.main()
            result=batch_audit.audit(folder,Path(temp)/'export')
            self.assertTrue(result['acceptance_passed'],result)
            self.assertEqual(result['scope_shops'],2)
            self.assertEqual(result['closed_skipped_tasks'],2)
            with patch.object(sys,'argv',['batch_run',str(folder)]),patch('farm.local_batch.LocalBatch.send',side_effect=AssertionError('must not repeat')),redirect_stdout(io.StringIO()):
                batch_run.main()
            self.assertTrue(batch_audit.audit(folder,Path(temp)/'export')['acceptance_passed'])

    def test_opening_gate_does_not_release_menu_for_closed_shop(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture=fixtures.LocalTests();r=fixture.setup_run(Path(temp));folder=r.folder
            r.manifest.update(verify_open=True,per_route_concurrency={})
            atomic_json(folder/'manifest.json',r.manifest)
            with r.db:r.db.execute("UPDATE tasks SET state='selection_hold' WHERE endpoint='productList'")
            r.db.close();endpoints=[]
            def response(task,account,attempt):
                endpoints.append(task['endpoint']);return fixture.response(task)
            with patch.object(sys,'argv',['batch_run',str(folder)]),patch('farm.local_batch.LocalBatch.send',side_effect=response),redirect_stdout(io.StringIO()):batch_run.main()
            self.assertEqual(endpoints,['shopInfo','shopInfo'])
            import sqlite3
            with sqlite3.connect(folder/'local.sqlite3') as db:self.assertEqual(db.execute("SELECT COUNT(*) FROM tasks WHERE state='selection_hold'").fetchone()[0],2)
            with patch.object(sys,'argv',['batch_run',str(folder)]),self.assertRaisesRegex(ValueError,'explicit_resume_required'):batch_run.main()

    def test_supervisor_records_crash_without_resetting_tasks(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture=fixtures.LocalTests();r=fixture.setup_run(Path(temp));folder=r.folder
            with r.db:r.db.execute("UPDATE meta SET value='running' WHERE key='state'")
            r.db.close()
            result=batch_watch.record_exit(folder,Path(temp)/'export',9,'2026-10-04T00:00:00+00:00',123)
            self.assertEqual(result['state'],'blocked');self.assertEqual(result['exit_code'],9)
            progress=json.loads((Path(temp)/'export/progress.json').read_text())
            self.assertEqual(progress['stop_reason'],'worker_process_exit_9')

    def test_explicit_routes_and_shop_scope_required(self):
        shops=[dict(shop_id='1',city_id='2',latitude='0',longitude='0')]
        config=dict(routes={'one':dict(proxy='http://127.0.0.1:1234')},per_route_concurrency={'one':1},bindings={'1':'one'})
        batch_prepare.validate_inputs(shops,[1],config,1,4)
        with self.assertRaises(ValueError):batch_prepare.validate_inputs(shops*2,[1],config,1,4)
        with self.assertRaises(ValueError):batch_prepare.validate_inputs(shops,[1,2],config,1,4)

    def test_recommendation_candidates_exclude_closed_and_out_of_range(self):
        cards=[]
        for sid,state,out in [(1,3,0),(2,4,0),(3,3,1)]:
            cards.append({'json_data':dict(shopId=sid,shopStatus=dict(shopStatusCode=state,hasOutOfRange=out),content=[[dict(type='shopName',data=dict(name='shop'))]])})
        data={'data':{'module_body':{'component_list':cards}}}
        self.assertEqual([s['shop_id'] for s in recommendations.open_candidates(data,{'city_id':'2'},0,'now')],['1'])

if __name__=='__main__':unittest.main()

class BatchPreparationTests(unittest.TestCase):
    def make_store(self):
        from unittest.mock import Mock
        from contextlib import contextmanager
        from tests.test_mysql_farm import MysqlFarmTests
        from farm.mysql_import import prepare_bundle
        from mtgsig.fingerprint_refresh import CONFIG
        from farm.mysql_store import ENDPOINTS
        bundle,_,_=prepare_bundle(MysqlFarmTests().native_bundle())
        bundle['device'][CONFIG]={'enabled':True}
        store=Mock();store.unseal.return_value=bundle;store.paused=False
        def rows(sql,params=()):
            if sql.startswith('SELECT a.paused'):return [dict(id=11,installation_key='synthetic-install',identity_status='verified',paused=store.paused)]
            if 'FROM budget_policies' in sql:return [dict(endpoint=ep,used=2,work_limit=85,hard_limit=100) for ep in ENDPOINTS]
            if 'FROM capabilities' in sql:return [dict(endpoint=ep,state='available',not_before=None) for ep in ENDPOINTS]
            return []
        store.rows.side_effect=rows;cursor=Mock();cursor.fetchone.return_value={'active_session_id':11}
        @contextmanager
        def transaction():yield cursor
        store.transaction.side_effect=transaction
        return store,cursor

    def test_database_usage_then_latest_local_state_survive_handoff(self):
        from contextlib import nullcontext
        from datetime import datetime,timedelta
        from farm import local_ledger
        from farm.local_batch import LocalBatch
        from farm.mysql_store import ENDPOINTS
        store,cursor=self.make_store()
        shops=[dict(shop_id='1',city_id='2',latitude='0',longitude='0')]
        config=dict(routes={'one':dict(proxy='http://127.0.0.1:1234')},per_route_concurrency={'one':1},bindings={'1':'one'})
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            with patch.object(batch_prepare,'ROOT',root),patch.object(local_ledger,'LOCAL_ROOT',root/'.private'),patch.object(batch_prepare,'account_lock',return_value=nullcontext()),patch.object(batch_prepare,'local_daily_usage',return_value={(1,ep):3 for ep in ENDPOINTS}):
                first=batch_prepare.prepare(store,shops,[1],config,1,4)
                r=LocalBatch(first['private']);self.assertEqual(r.accounts[1]['budgets']['productRender']['used'],5)
                for budget in r.accounts[1]['budgets'].values():budget['used']=17
                r.accounts[1]['blocked']['productRender']=9999999999
                r.accounts[1]['bundle']['device']['sign_sequence']=123
                with r.db:r.save_account(r.accounts[1])
                r.db.close();store.paused=True
                later=datetime.utcnow()+timedelta(seconds=2)
                with patch.object(batch_prepare,'utcnow',return_value=later),patch.object(batch_prepare,'reconcile_probe_budget'):
                    second=batch_prepare.prepare(store,shops,[1],config,1,4)
                r=LocalBatch(second['private'])
                try:
                    self.assertEqual(r.accounts[1]['budgets']['productRender']['used'],17)
                    self.assertEqual(r.accounts[1]['blocked']['productRender'],9999999999)
                    self.assertEqual(r.accounts[1]['bundle']['device']['sign_sequence'],123)
                    self.assertEqual(r.db.execute('SELECT COUNT(*) FROM attempts').fetchone()[0],0)
                finally:r.db.close()
                self.assertTrue(any('paused=TRUE' in call.args[0] for call in cursor.execute.call_args_list))

    def test_active_database_work_rejects_before_mutation(self):
        store,cursor=self.make_store();store.rows.side_effect=lambda *_:[{'id':1}]
        shops=[dict(shop_id='1',city_id='2',latitude='0',longitude='0')]
        config=dict(routes={'one':dict(proxy='http://127.0.0.1:1234')},per_route_concurrency={'one':1},bindings={'1':'one'})
        with tempfile.TemporaryDirectory() as temp,patch.object(batch_prepare,'ROOT',Path(temp)):
            with self.assertRaisesRegex(ValueError,'database_execution_active'):batch_prepare.prepare(store,shops,[1],config)
        store.transaction.assert_not_called()
