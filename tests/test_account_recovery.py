# -*- coding: utf-8 -*-
"""Recovery must preserve usage and failed evidence, without sending real HTTP."""
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from farm import local_ledger as ledger, account_controls as controls, account_checks as checks
from farm.mysql_store import ENDPOINTS, business_day
from farm.panel import create_app
from tests.test_account_checks import helpers, L, info, menu, render


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.patch=patch.object(ledger,'LOCAL_ROOT',self.root);self.patch.start()

    def tearDown(self):self.patch.stop();self.temp.cleanup()

    def run_fixture(self,name='local100-20261003T080000Z',sid=8,used=3,day='2026-10-03'):
        runtime=helpers.LocalTests().setup_run(self.root/name,shops=1,account_count=1)
        account=runtime.accounts[1];account['session_id']=sid
        for ep in ENDPOINTS:account['budgets'].setdefault(ep,{'used':0,'limit':85})
        account['budgets']['shopInfo']['used']=used
        with runtime.db:runtime.save_account(account);runtime.set_meta('budget_day',day)
        manifest=runtime.manifest
        manifest.update(account_session_ids={'1':sid},snapshot_business_date=day)
        (runtime.folder/'manifest.json').write_text(json.dumps(manifest))
        # Construct in a staging folder, then atomically register at its final name.
        runtime.db.close();private=runtime.folder;staging=self.root/(name+'-staged')
        private.rename(staging)
        import shutil
        shutil.rmtree(self.root/name);staging.rename(self.root/name)
        return L.LocalBatch(self.root/name)

    def attempt(self,runtime,at,outcome='success',sent=1,http=200):
        with runtime.db:
            runtime.db.execute('INSERT INTO attempts(account,endpoint,started,finished,outcome,sent,http) VALUES(?,?,?,?,?,?,?)',
                               (1,'shopInfo',at,at,outcome,sent,http))

    def test_daily_uses_attempts_not_inherited_snapshots_and_sp_midnight(self):
        first=self.run_fixture(used=40)
        self.attempt(first,'2026-10-03T02:59:59+00:00')
        self.attempt(first,'2026-10-03T03:00:00+00:00')
        second=self.run_fixture('local100-20261003T090000Z',used=41)
        self.attempt(second,'2026-10-03T04:00:00+00:00','rejected',1,403)
        self.attempt(second,'2026-10-03T05:00:00+00:00','reserved',0,None)
        self.attempt(second,'2026-10-03T06:00:00+00:00','uncertain',0,None)
        self.attempt(second,'2026-10-03T07:00:00+00:00','local_error',0,None)
        rows,bad=ledger.daily_rows('2026-10-03',{1})
        self.assertEqual(bad,[]);self.assertEqual(sum(r['request_count'] for r in rows),3)
        self.assertEqual(sum(r['reserved_count'] for r in rows),1)
        self.assertEqual(ledger.local_daily_usage('2026-10-03',[1])[(1,'shopInfo')],4)
        self.assertEqual(ledger.local_owner(1,8),second.folder)
        self.assertIsNone(ledger.local_owner(1,9))
        rows,_=ledger.daily_rows('2026-10-02',{1});self.assertEqual(sum(r['request_count'] for r in rows),1)
        first.db.close();second.db.close()

    def test_probe_journal_is_counted_but_backup_is_not(self):
        runtime=self.run_fixture();self.attempt(runtime,'2026-10-03T03:00:00+00:00')
        import shutil
        dest=self.root/'account-checks'/'check-one'/'1';dest.mkdir(parents=True)
        runtime.db.commit();backup=self.root/'before-change';backup.mkdir()
        import sqlite3
        for path in (dest/'local.sqlite3',backup/'local.sqlite3'):
            db=sqlite3.connect(path);runtime.db.backup(db);db.execute('PRAGMA journal_mode=DELETE');db.close()
        rows,_=ledger.daily_rows('2026-10-03',{1})
        self.assertEqual(sum(r['request_count'] for r in rows),2)
        self.assertEqual({r['origin'] for r in rows},{'local_batch','local_probe'})
        runtime.db.close()

    def test_snapshot_usage_is_lower_bound_and_new_session_keeps_local_usage(self):
        r=self.run_fixture(used=7);self.attempt(r,'2026-10-03T03:00:00+00:00')
        data={'accounts':[{'id':1,'label':'fixture','active_session_id':8}], 'daily':[],
              'budgets':[dict(account_id=1,endpoint='shopInfo',used_count=3,reserved_count=0,work_limit=8,hard_limit=10)]}
        out=ledger.overlay_dashboard(deepcopy(data),'2026-10-03')
        self.assertEqual(out['budgets'][0]['used_count'],7)
        self.assertEqual(out['budgets'][0]['remaining_work'],1)
        data['accounts'][0]['active_session_id']=9
        out=ledger.overlay_dashboard(data,'2026-10-03')
        self.assertEqual(out['budgets'][0]['used_count'],4)
        self.assertNotIn('local_managed',out['accounts'][0]);r.db.close()

    def test_stale_counter_snapshot_is_rejected_and_latest_usage_is_preserved(self):
        r=self.run_fixture(used=12);account=r.accounts[1]
        with r.db:
            account['bundle']['device']['sign_sequence']=100;r.save_account(account)
        stale=deepcopy(account);stale['bundle']['device']['sign_sequence']=99
        with self.assertRaises(ledger.LedgerUnavailable):ledger.adopt_latest_accounts([stale],'2026-10-03')
        copied=deepcopy(account);copied['budgets']['shopInfo']['used']=0
        ledger.adopt_latest_accounts([copied],'2026-10-03')
        self.assertEqual(copied['budgets']['shopInfo']['used'],12);r.db.close()

    def test_manual_clear_preserves_usage_other_cooldowns_and_quota_rest(self):
        r=self.run_fixture();a=r.accounts[1];due=time.time()+86400
        a.update(blocked={'shopInfo':due,'productRender':due},rest_until=due,rest_reason='daily_budget',rest_endpoint='shopInfo')
        original=deepcopy(a['budgets']);device=deepcopy(a['bundle']['device'])
        controls.clear_local_cooldown(r,1,'shopInfo')
        self.assertNotIn('shopInfo',a['blocked']);self.assertEqual(a['blocked']['productRender'],due)
        self.assertEqual(a['rest_until'],due);self.assertEqual(a['budgets'],original)
        self.assertEqual(a['bundle']['device'],device)
        self.assertEqual(a['endpoint_controls']['shopInfo']['state'],'unknown')
        self.assertEqual(len(r.meta('cooldown_audit')),1);r.db.close()

    def test_only_matching_rejection_rest_is_cleared(self):
        r=self.run_fixture();a=r.accounts[1];due=time.time()+86400
        a.update(rest_until=due,rest_reason='rejected',rest_endpoint='productSpecifics')
        controls.clear_local_cooldown(r,1,'accountInfo',verified=True)
        self.assertEqual(a['rest_until'],due)
        controls.clear_local_cooldown(r,1,'productSpecifics',verified=True)
        self.assertEqual(a['rest_until'],0);r.db.close()

    def test_dashboard_renders_successful_probe_and_retains_other_cooldown(self):
        r=self.run_fixture();self.addCleanup(r.db.close)
        due=time.time()+86400
        r.accounts[1]['blocked']={'accountInfo':due,'productRender':due}
        controls.clear_local_cooldown(r,1,'accountInfo',verified=True)
        data={'accounts':[{'id':1,'label':'fixture','active_session_id':8}],
              'daily':[],'budgets':[]}
        ledger.overlay_dashboard(data,'2026-10-03')
        rows={c['endpoint']:c for c in data['account_controls']}
        self.assertEqual(rows['accountInfo']['state'],'available')
        self.assertEqual(rows['accountInfo']['action'],'verified_probe')
        self.assertIsNone(rows['accountInfo']['cooldown_until'])
        self.assertIsNotNone(rows['productRender']['cooldown_until'])
        self.assertTrue(all(c['account_id']==1 and c['source']=='local' for c in rows.values()))

    def probe(self,r):
        output=self.root/'exports'/'check';output.mkdir(parents=True)
        with patch.object(checks,'ROOT',self.root),patch.object(checks,'local_module',return_value=L):
            return checks.LocalProbe(r,1,r.shops[1],output,recovery=True,hard_limits={'shopInfo':5})

    def test_failed_probe_does_not_clear_and_success_only_clears_tested_endpoint(self):
        for success in (False,True):
            with self.subTest(success=success):
                r=self.run_fixture('local100-20261003T0'+('9' if success else '8')+'0000Z',used=3,day=str(business_day(datetime.now(timezone.utc))))
                due=time.time()+86400;r.accounts[1]['blocked']={'shopInfo':due,'productRender':due}
                with r.db:r.save_account(r.accounts[1])
                checker=self.probe(r)
                data=info() if success else {'_http_status':403}
                reply=Mock(status_code=200 if success else 403,text='failure',content=b'failure')
                reply.json.return_value=data
                with patch('requests.Session.send',return_value=reply):row,_=checker.send('shopInfo',{},'')
                self.assertEqual(r.accounts[1]['budgets']['shopInfo']['used'],4)
                self.assertEqual('shopInfo' in r.accounts[1]['blocked'],not success)
                self.assertEqual(r.accounts[1]['blocked']['productRender'],due)
                self.assertEqual(row.get('cooldown_cleared',False),success)
                checker.close(True);r.db.close()
                import shutil
                shutil.rmtree(self.root/'exports');shutil.rmtree(self.root/'.private')

    def test_hard_limit_blocks_probe_without_network_or_cooldown_change(self):
        r=self.run_fixture(used=5,day=str(business_day(datetime.now(timezone.utc))));due=time.time()+86400;r.accounts[1]['blocked']['shopInfo']=due
        with r.db:r.save_account(r.accounts[1])
        checker=self.probe(r)
        with patch('requests.Session.send') as send:row,data=checker.send('shopInfo',{},'')
        send.assert_not_called();self.assertEqual(row['status'],'daily_budget_reached')
        self.assertEqual(r.accounts[1]['budgets']['shopInfo']['used'],5)
        self.assertEqual(r.accounts[1]['blocked']['shopInfo'],due);checker.close(True);r.db.close()

    def test_identity_probe_uses_get_and_leaves_render_cooldown(self):
        r=self.run_fixture();due=time.time()+86400;r.accounts[1]['blocked']['productRender']=due
        with r.db:r.save_account(r.accounts[1])
        checker=self.probe(r);checker.hard_limits['accountInfo']=10
        reply=Mock(status_code=200);reply.json.return_value={'code':0,'user':{'idStr':'42'}}
        def send(session,wire,**kwargs):
            self.assertEqual(wire.method,'GET');self.assertFalse(wire.body)
            self.assertIn('/api/user/v1/info/homepage',wire.url)
            return reply
        with patch('requests.Session.send',send):row,_=checker.send('accountInfo',{},'42')
        self.assertEqual(row['status'],'success',row)
        self.assertEqual(r.accounts[1]['blocked']['productRender'],due)
        self.assertEqual(r.accounts[1]['budgets']['accountInfo']['used'],1)
        checker.close(True);r.db.close()

    def test_two_probes_cannot_share_running_local_batch(self):
        r=self.run_fixture();r.db.close()
        with checks.local_lock(r.folder):
            with self.assertRaises(checks.CheckError):
                with checks.local_lock(r.folder):pass

    def test_render_probe_stops_before_custom_detail(self):
        send=Mock(side_effect=[({'sent':True,'status':'success'},info()),({'sent':True,'status':'success'},menu()),({'sent':True,'status':'success'},render())])
        rows=checks.check_flow(send,stop_after='productRender')
        self.assertEqual(len(rows),3);self.assertEqual(rows[-1]['endpoint'],'productRender')

    def test_database_cannot_claim_a_locally_managed_session(self):
        from farm.mysql_worker import Worker
        r=self.run_fixture();store=Mock();store.rows.return_value=[{'account_id':1,'id':8}]
        self.assertIsNone(Worker(store).claim(1,account_id=1))
        store.connect.assert_not_called();r.db.close()

    def test_budget_reconciliation_counts_local_even_for_new_session(self):
        r=self.run_fixture(used=1);self.attempt(r,'2026-10-03T03:00:00+00:00')
        store=Mock();store.rows.return_value=[dict(endpoint='shopInfo',work_limit=85,hard_limit=100,used=4)]
        with patch.object(controls,'utcnow',return_value=datetime(2026,10,3,9)):
            controls.reconcile_probe_budget(store,r,1)
            controls.reconcile_probe_budget(store,r,1)
        self.assertEqual(r.accounts[1]['budgets']['shopInfo']['used'],5);r.db.close()

    def test_panel_mutations_require_csrf_and_return_specific_block_reason(self):
        client=create_app(Mock()).test_client()
        body={'account_id':1,'endpoint':'productRender'}
        self.assertEqual(client.post('/api/accounts/cooldown/clear',json=body).status_code,403)
        token=re.search(r'name="csrf-token" content="([^"]+)"',client.get('/').text)[1]
        with patch('farm.panel.probe_account',side_effect=checks.CheckError('local_batch_is_running')):
            response=client.post('/api/probe',json=body,headers={'X-Panel-CSRF':token})
        self.assertEqual(response.status_code,409);self.assertFalse(response.json['sent'])
        self.assertEqual(response.json['status'],'local_batch_is_running')
        with patch('farm.panel.clear_cooldown',return_value={'quota_preserved':True}) as clear:
            response=client.post('/api/accounts/cooldown/clear',json=body,headers={'X-Panel-CSRF':token})
        clear.assert_called_once();self.assertTrue(response.json['quota_preserved'])


if __name__=='__main__':unittest.main()
