"""One HTTP request per durable task, with transactional quotas and leases."""
from collections import OrderedDict
from copy import deepcopy
from datetime import datetime, timezone, timedelta
import json
import os
from pathlib import Path
import tempfile
from farm.storage.responses import load_response, save_response
from urllib.parse import urlsplit
import time
import uuid

import requests
import pymysql

from farm.storage.mysql import (Store,PATHS,compact,digest,utcnow,business_day,unpack_json,classify,shop_is_closed,closed_shop_jobs,
                             transient_database_error,log_failure)
from farm.accounts.importer import ATTEMPT_SQL,refresh_account_material
from mtgsig.signer import FullSigner
from farm.collection.context import RequestContext
from farm.collection.templates import validate_account_request
from farm.network.proxy import ProxyRoute, is_ipfoxy, refresh_ipfoxy


def menu_followups(endpoint,response,payload):
    """Return unique detail and lazy-menu requests. Unknown flags need details."""
    details=set();render=[];covered=set()
    for cat in response['data']['shopCategoryList']:
        inline={str(p['spuId']):p for p in cat.get('spuList') or [] if p.get('spuId') is not None}
        ids=list(dict.fromkeys([str(x) for x in cat.get('spuIdList') or []]+list(inline)))
        if any(not x.isascii() or not x.isdigit() for x in ids):raise ValueError('invalid menu product ID')
        for identifier,product in inline.items():
            if not product.get('name'):continue
            covered.add(identifier)
            if product.get('haveMultiSpecs') not in (0,'0'):
                details.add(identifier)
        missing=[x for x in ids if x not in covered]
        if endpoint=='productList' and missing:
            if cat.get('shopCategoryId') is None:details.update(missing)
            else:
                for start in range(0,len(missing),32):
                    batch={'shopCategoryList':[{'shopCategoryId':cat['shopCategoryId'],'spuIdList':[int(x) for x in missing[start:start+32]]}]}
                    render.append(batch)
    required={str(x) for cat in payload.get('shopCategoryList',[]) for x in cat.get('spuIdList',[])}
    return sorted(details),render,required-covered


class Worker:
    def __init__(self,store):
        self.store=store;self.details_ready_at={}

    def reconcile_closed_details(self,run_id):
        rows=self.store.rows('SELECT settings FROM collection_runs WHERE id=%s',(run_id,))
        if not rows or unpack_json(rows[0]['settings']).get('skip_closed_details') is not True:return 0
        closed=closed_shop_jobs(self.store,run_id)
        if not closed:return 0
        with self.store.transaction() as c:
            placeholders=','.join(['%s']*len(closed))
            c.execute(f"UPDATE tasks SET state='skipped_closed',last_reason='store_closed',not_before=NULL,updated_at=%s WHERE shop_job_id IN ({placeholders}) AND endpoint='productSpecifics' AND state IN ('pending','retry_wait','deferred_business','dead_letter')",(utcnow(),*sorted(closed)))
            return c.rowcount

    def reconcile_menu_fallback(self,run_id,shop_job_id=None):
        """Use real specifics results to cover unavailable lazy-menu requests.

        Opt-in only: missing main items in open shops cost one detail request
        each. Closed shops keep their missing-menu evidence and are untouched.
        No HTTP success or request-attempt record is synthesized.
        """
        from farm.delivery.export import merge_menu,coverage,unresolved_nested
        rows=self.store.rows('SELECT settings FROM collection_runs WHERE id=%s',(run_id,))
        if not rows or unpack_json(rows[0]['settings']).get('menu_detail_fallback') is not True:
            return {'enqueued':0,'covered':0}
        closed=closed_shop_jobs(self.store,run_id)
        sql="SELECT t.* FROM tasks t JOIN shop_jobs j ON j.id=t.shop_job_id WHERE j.run_id=%s AND t.endpoint='productRender' AND t.state IN ('pending','retry_wait','dead_letter')"
        args=[run_id]
        if shop_job_id is not None:sql+=' AND j.id=%s';args.append(shop_job_id)
        grouped={}
        for task in self.store.rows(sql,args):
            if task['shop_job_id'] not in closed:grouped.setdefault(task['shop_job_id'],[]).append(task)
        stats={'enqueued':0,'covered':0}
        for job_id,tasks in grouped.items():
            raw=self.store.rows("SELECT endpoint,target_id,response_blob,observed_at FROM task_results WHERE shop_job_id=%s AND valid_data=TRUE ORDER BY observed_at,id",(job_id,))
            menus=[r for r in raw if r['endpoint']=='productList']
            if not menus:continue
            menu=menus[-1]
            renders=[load_response(r['response_blob']) for r in raw if r['endpoint']=='productRender' and r['observed_at']>=menu['observed_at']]
            details={r['target_id']:load_response(r['response_blob']) for r in raw if r['endpoint']=='productSpecifics'}
            merged=merge_menu(load_response(menu['response_blob'])['data'],renders)
            check=coverage(merged,details)
            missing=set(check['missing_main_ids'])
            detail_ids={k for k,v in details.items() if str(v.get('data',{}).get('spuId'))==k and v.get('data',{}).get('name') and not unresolved_nested(v['data'])}
            # Completing the replacement requires real details including any
            # nested options; the export coverage still checks the entire menu.
            detail_ids-=set(check['nested_unresolved_ids'])
            with self.store.transaction() as c:
                for identifier in sorted(missing):
                    stats['enqueued']+=self.store.enqueue(c,job_id,'productSpecifics',identifier,priority=20)
                for task in tasks:
                    requested={str(x) for cat in unpack_json(task['payload']).get('shopCategoryList',[]) for x in cat.get('spuIdList',[])}
                    if requested and requested<=detail_ids:
                        c.execute("UPDATE tasks SET state='covered_by_details',last_reason='specifics_data_covers_menu',not_before=NULL,updated_at=%s WHERE id=%s AND state IN ('pending','retry_wait','dead_letter')",(utcnow(),task['id']))
                        stats['covered']+=c.rowcount
        return stats

    def recorded_menu(self,c,job_id):
        from farm.delivery.export import merge_menu
        c.execute("SELECT endpoint,response_blob FROM task_results WHERE shop_job_id=%s AND endpoint IN ('productList','productRender') AND valid_data=TRUE ORDER BY observed_at,id",(job_id,))
        menu=None;renders=[]
        for row in c.fetchall():
            value=load_response(row['response_blob'])
            if row['endpoint']=='productList':menu=value['data'];renders=[]
            else:renders.append(value)
        return merge_menu(menu,renders) if menu else {'shopCategoryList':[]}

    def reconcile_unavailable_details(self,c,task):
        from farm.delivery.export import unavailable_products
        if unpack_json(task.get('run_settings') or {}).get('skip_unavailable_details') is not True:return
        menu=self.recorded_menu(c,task['shop_job_id'])
        ids=unavailable_products(menu)
        recorded={str(p['spuId']) for cat in menu['shopCategoryList'] for p in cat.get('spuList') or [] if p.get('name') and p.get('spuId') is not None}
        reopened=recorded-ids
        if reopened:
            marks=','.join(['%s']*len(reopened))
            c.execute(f"UPDATE tasks SET state=IF(attempts>=max_attempts,'dead_letter','pending'),last_reason='availability_changed',updated_at=%s WHERE shop_job_id=%s AND endpoint='productSpecifics' AND target_id IN ({marks}) AND state='skipped_unavailable' AND last_reason='product_unavailable_menu'",(utcnow(),task['shop_job_id'],*sorted(reopened)))
        if not ids:return
        marks=','.join(['%s']*len(ids))
        c.execute(f"UPDATE tasks SET state='skipped_unavailable',last_reason='product_unavailable_menu',not_before=NULL,updated_at=%s WHERE shop_job_id=%s AND endpoint='productSpecifics' AND target_id IN ({marks}) AND state IN ('pending','retry_wait','deferred_business','dead_letter')",(utcnow(),task['shop_job_id'],*sorted(ids)))

    def _skip_unavailable_details(self,c,task,response,outcome):
        if (unpack_json(task.get('run_settings') or {}).get('skip_unavailable_details') is not True
            or task['endpoint']!='productSpecifics' or outcome!='business_error'
            or response.get('_http_status')!=200 or str(response.get('code'))!='201003212'):return False
        from farm.delivery.export import coverage
        return str(task['target_id']) in coverage(self.recorded_menu(c,task['shop_job_id']),{})['recorded_product_ids']

    def _skip_closed_details(self,c,task,response,outcome):
        settings=unpack_json(task.get('run_settings') or {})
        if settings.get('skip_closed_details') is not True:return False
        if outcome=='store_closed' or (task['endpoint']=='shopInfo' and shop_is_closed(response)):return True
        c.execute("SELECT response_blob FROM task_results WHERE shop_job_id=%s AND endpoint='shopInfo' AND valid_data=TRUE ORDER BY observed_at DESC,id DESC LIMIT 1",(task['shop_job_id'],))
        row=c.fetchone()
        if row and shop_is_closed(load_response(row['response_blob'])):return True
        c.execute("SELECT id FROM tasks WHERE shop_job_id=%s AND endpoint='productSpecifics' AND last_reason='store_closed' LIMIT 1",(task['shop_job_id'],))
        return c.fetchone() is not None

    def diagnose(self,account_ids,endpoints,allow_probe=False,allow_recovery=False,*,allow_paused=False,force_probe=False):
        """Read-only per-endpoint blockers; no inference about server recovery."""
        if force_probe and not allow_probe:raise ValueError('manual probe scope required')
        now=utcnow();results=[]
        for aid in account_ids:
            rows=self.store.rows('SELECT a.paused,a.identity_status,s.* FROM accounts a JOIN account_sessions s ON s.id=a.active_session_id WHERE a.id=%s',(aid,))
            if not rows:
                results.append({'account_id':aid,'reason':'no_active_session'});continue
            row=rows[0];bundle=self.store.unseal(row)
            caps={r['endpoint']:r for r in self.store.rows('SELECT * FROM capabilities WHERE session_id=%s',(row['id'],))}
            budgets={r['endpoint']:r for r in self.store.rows('SELECT p.*,COALESCE(u.used_count,0)+COALESCE(u.reserved_count,0) used FROM budget_policies p LEFT JOIN daily_usage u ON u.account_id=p.account_id AND u.endpoint=p.endpoint AND u.business_date=%s WHERE p.account_id=%s',(business_day(now),aid))}
            rests=self.store.rows("SELECT * FROM experiment_members WHERE account_id=%s AND (state IN ('resting','stopped') OR rest_until>%s)",(aid,now))
            for endpoint in endpoints:
                cap=caps.get(endpoint,{});budget=budgets.get(endpoint,{})
                reason='eligible';until=cap.get('not_before')
                if row['paused'] and not (allow_probe and allow_paused):reason='paused'
                elif not allow_probe and row['identity_status'] not in ('verified','observed','unverified'):reason='identity_expired'
                elif endpoint not in unpack_json(row['endpoint_names']):
                    reason=bundle.get('material_reasons',{}).get(endpoint,'unsupported_or_missing_endpoint_schema')
                elif cap.get('state')=='needs_material':reason='local_construction_error'
                elif until and until>now and not force_probe:reason='cooldown'
                elif cap.get('state')=='cooldown' and not (allow_probe or allow_recovery):reason='recovery_probe_required'
                elif cap.get('state') not in ('available','unknown','cooldown'):reason='capability_unavailable'
                elif not budget:reason='missing_budget_policy'
                elif budget['used']>=(budget['hard_limit'] if allow_probe else min(budget['work_limit'],budget['hard_limit'])):reason='daily_budget_reached'
                if reason=='eligible':
                    for rest in rests:
                        if force_probe and rest['state']!='stopped':continue
                        if (allow_probe or allow_recovery) and rest['state']!='stopped' and rest['rest_until'] and rest['rest_until']<=now:continue
                        if rest['endpoint']==endpoint or unpack_json(rest['settings']).get('rest_scope')=='all_account_requests':
                            reason='account_rest';until=rest['rest_until'];break
                results.append({'account_id':aid,'endpoint':endpoint,'reason':reason,'state':cap.get('state'),
                                'not_before':until.isoformat()+'Z' if until else None,
                                'http':cap.get('http_status'),'code':cap.get('business_code')})
        return results

    def _release_locks(self,con,names):
        self.store.release_lock_connection(con)

    def recover(self,run_id=None):
        # Conservative recovery: a process could have died immediately before
        # recording send intent, so an expired reservation consumes one slot.
        scope=' AND t.shop_job_id IN (SELECT id FROM shop_jobs WHERE run_id=%s)' if run_id is not None else ''
        args=(run_id,) if run_id is not None else ()
        for row in self.store.rows("SELECT DISTINCT r.account_id FROM tasks t JOIN request_attempts r ON r.task_id=t.id WHERE t.state='leased' AND t.lease_until<%s AND r.state IN ('reserved','sent')"+scope,(utcnow(),*args)):
            with self.store.transaction() as c:
                c.execute('SELECT id FROM accounts WHERE id=%s FOR UPDATE',(row['account_id'],));c.fetchone()
                c.execute("SELECT r.* FROM request_attempts r JOIN tasks t ON t.id=r.task_id WHERE r.account_id=%s AND r.state IN ('reserved','sent') AND t.state='leased' AND t.lease_until<%s"+scope+" FOR UPDATE",(row['account_id'],utcnow(),*args))
                for attempt in c.fetchall():
                    if attempt['state']=='reserved':
                        c.execute('UPDATE daily_usage SET reserved_count=reserved_count-1,used_count=used_count+1 WHERE account_id=%s AND business_date=%s AND endpoint=%s AND reserved_count>0',
                                  (attempt['account_id'],attempt['business_date'],attempt['endpoint']))
                        c.execute('UPDATE tasks SET attempts=attempts+1 WHERE id=%s',(attempt['task_id'],))
                    c.execute("UPDATE request_attempts SET state='uncertain',outcome='process_interrupted',finished_at=%s WHERE id=%s",(utcnow(),attempt['id']))
                    c.execute("UPDATE tasks SET state=IF(attempts>=max_attempts,'dead_letter','retry_wait'),not_before=%s,lease_owner=NULL,lease_until=NULL,last_reason='expired_lease' WHERE id=%s",(utcnow()+timedelta(minutes=5),attempt['task_id']))
        with self.store.transaction() as c:
            c.execute("UPDATE tasks t SET state=IF(attempts>=max_attempts,'dead_letter','retry_wait') WHERE state='deferred_business' AND not_before<=%s"+scope,(utcnow(),*args))

    def claim(self,run_id,account_id=None,endpoints=None,allow_probe=False,*,environment=None,account_ids=None,tags=None,allow_recovery=False,task_id=None,allow_paused=False,force_probe=False):
        from farm.accounts.selection import selection_clause
        now=utcnow();today=business_day(now)
        if task_id is not None and (type(task_id) is not int or task_id<1):raise ValueError('invalid task ID')
        if allow_paused and not (allow_probe and account_id is not None and task_id is not None):
            raise ValueError('paused-account check requires an explicit account and probe task')
        if force_probe and not (allow_probe and account_id is not None and task_id is not None):
            raise ValueError('manual recovery requires one explicit probe task')
        query="""SELECT a.id account_id,a.label,s.* FROM accounts a JOIN account_sessions s ON s.id=a.active_session_id
        WHERE s.material_status='ready_captured_incognia'"""
        if not allow_paused:query+=' AND a.paused=FALSE'
        args=[]
        if not allow_probe:query+=" AND a.identity_status IN ('verified','observed','unverified')"
        if account_id is not None:query+=' AND a.id=%s';args.append(account_id)
        selection,selection_args=selection_clause(environment,account_ids,tags)
        query+=selection;args.extend(selection_args)
        query+=' ORDER BY a.id'
        accounts=self.store.rows(query,args)
        last=getattr(self,'last_account_id',0)
        accounts=sorted(accounts,key=lambda a:(a['account_id']<=last,a['account_id']))
        for account in accounts:
            if getattr(self,'fingerprint_wait_until',{}).get(account['account_id'],0)>time.time():continue
            con=self.store.lock_connection();locks=[];claim=None;gate=None
            try:
                with con.cursor() as c:
                    c.execute('SET SESSION wait_timeout=300')
                    for key in ('keeta:account:'+str(account['account_id']),'keeta:install:'+account['installation_key'][:45]):
                        c.execute('SELECT GET_LOCK(%s,0) AS locked',(key,))
                        if c.fetchone()['locked']!=1:break
                        locks.append(key)
                    if len(locks)!=2:continue
                    c.execute('SELECT id,active_session_id,paused FROM accounts WHERE id=%s FOR UPDATE',(account['account_id'],));active=c.fetchone()
                    if (active['paused'] and not allow_paused) or active['active_session_id']!=account['id']:continue
                    c.execute('SELECT a.id FROM accounts a WHERE a.id=%s'+selection,(account['account_id'],*selection_args))
                    if not c.fetchone():continue
                    # Read the latest counters after obtaining the installation lock.
                    c.execute('SELECT * FROM account_sessions WHERE id=%s',(account['id'],))
                    account.update(c.fetchone())
                    states="('available','unknown','cooldown')" if (allow_probe or allow_recovery) else "('available','unknown')"
                    cooldown_filter='' if force_probe else ' AND (not_before IS NULL OR not_before<=%s)'
                    c.execute(f"SELECT endpoint FROM capabilities WHERE session_id=%s AND state IN {states}"+cooldown_filter,(account['id'],) if force_probe else (account['id'],now))
                    available={r['endpoint'] for r in c.fetchall()} & set(unpack_json(account['endpoint_names']))
                    if endpoints:available &= set(endpoints)
                    if self.details_ready_at.get(account['account_id'],0)>time.monotonic():
                        available.discard('productSpecifics')
                    c.execute('SELECT p.*,COALESCE(u.used_count,0) used_count,COALESCE(u.reserved_count,0) reserved_count FROM budget_policies p LEFT JOIN daily_usage u ON u.account_id=p.account_id AND u.endpoint=p.endpoint AND u.business_date=%s WHERE p.account_id=%s',(today,account['account_id']))
                    policies={r['endpoint']:r for r in c.fetchall()}
                    if 'productSpecifics' in available:
                        c.execute("SELECT MAX(finished_at) finished FROM request_attempts WHERE account_id=%s AND endpoint='productSpecifics' AND counts_budget=TRUE",(account['account_id'],))
                        recent=c.fetchone()
                        if recent and recent['finished']:
                            wait=getattr(self,'detail_delay',4)-(now-recent['finished']).total_seconds()
                            if wait>0:
                                self.details_ready_at[account['account_id']]=time.monotonic()+wait
                                available.discard('productSpecifics')
                    available={e for e in available if e in policies and policies[e]['used_count']+policies[e]['reserved_count']<(policies[e]['hard_limit'] if allow_probe else min(policies[e]['work_limit'],policies[e]['hard_limit']))}
                    c.execute("SELECT endpoint,state,rest_until,settings FROM experiment_members WHERE account_id=%s AND (state IN ('resting','stopped') OR rest_until>%s)",(account['account_id'],now))
                    for rest in c.fetchall():
                        if force_probe and rest['state']!='stopped':continue
                        if (allow_probe or allow_recovery) and rest['state']!='stopped' and rest['rest_until'] and rest['rest_until']<=now:
                            continue
                        if unpack_json(rest['settings']).get('rest_scope')=='all_account_requests':available.clear()
                        else:available.discard(rest['endpoint'])
                    if not available:continue
                    placeholders=','.join(['%s']*len(available))
                    task_filter=' AND t.id=%s' if task_id is not None else ''
                    c.execute(f'''SELECT t.*,j.shop_id,j.latitude,j.longitude,j.city_id,j.run_id,r.settings run_settings FROM tasks t JOIN shop_jobs j ON j.id=t.shop_job_id JOIN collection_runs r ON r.id=j.run_id
                    WHERE j.run_id=%s AND t.state IN ('pending','retry_wait') AND t.attempts<t.max_attempts
                    AND (t.not_before IS NULL OR t.not_before<=%s) AND t.endpoint IN ({placeholders}){task_filter}
                    AND (t.endpoint<>'productSpecifics' OR COALESCE(JSON_UNQUOTE(JSON_EXTRACT(r.settings,'$.skip_closed_details')),'false')<>'true' OR EXISTS (SELECT 1 FROM tasks si WHERE si.shop_job_id=t.shop_job_id AND si.endpoint='shopInfo' AND si.state='succeeded'))
                    ORDER BY j.id,t.priority DESC,t.id LIMIT 1 FOR UPDATE SKIP LOCKED''',(run_id,now,*sorted(available),*((task_id,) if task_id is not None else ())))
                    task=c.fetchone()
                    if task is None:continue
                    gate=getattr(self,'route_gates',{}).get(account['account_id'])
                    if gate is not None and not gate.acquire(blocking=False):gate=None;continue
                    endpoint=task['endpoint'];owner=str(uuid.uuid4());attempt_id=digest(['worker',owner,task['id']])
                    c.execute('INSERT INTO daily_usage(account_id,business_date,endpoint,reserved_count) VALUES(%s,%s,%s,1) ON DUPLICATE KEY UPDATE reserved_count=reserved_count+1',(account['account_id'],today,endpoint))
                    c.execute("UPDATE tasks SET state='leased',lease_owner=%s,lease_until=%s,updated_at=%s WHERE id=%s",(owner,now+timedelta(minutes=3),now,task['id']))
                    source='execution:'+str(self.execution_id) if getattr(self,'execution_id',None) is not None else 'mysql_worker'
                    c.execute(ATTEMPT_SQL,(attempt_id,account['account_id'],account['id'],task['id'],endpoint,'worker',now,None,today,'reserved',True,None,None,'reserved',False,None,task['shop_id'],task['target_id'] or None,source,account['collection_mode'],account['incognia_mode']))
                    con.commit();claim={'connection':con,'locks':locks,'account':account,'task':task,'owner':owner,'attempt_id':attempt_id,'business_date':today}
                    if gate is not None:claim['route_gate']=gate
                    self.last_account_id=account['account_id']
                    return claim
            finally:
                if claim is None:
                    if gate is not None:gate.release()
                    self._release_locks(con,locks)
        return None

    def _fence(self,c,claim):
        c.execute('SELECT lease_owner,state FROM tasks WHERE id=%s FOR UPDATE',(claim['task']['id'],));row=c.fetchone()
        if row['lease_owner']!=claim['owner'] or row['state']!='leased':raise RuntimeError('task lease lost')

    def save_state(self,claim,bundle):
        key_id,blob=self.store.seal(bundle)
        with self.store.transaction() as c:
            c.execute('UPDATE account_sessions SET encryption_key_id=%s,credential_blob=%s,updated_at=%s WHERE id=%s',
                      (key_id,blob,utcnow(),claim['account']['id']))

    def mark_sent(self,claim):
        a,t=claim['account'],claim['task']
        with self.store.transaction() as c:
            c.execute('SELECT id FROM accounts WHERE id=%s FOR UPDATE',(a['account_id'],));c.fetchone();self._fence(c,claim)
            c.execute("UPDATE request_attempts SET state='sent',outcome='sent' WHERE id=%s AND state='reserved'",(claim['attempt_id'],))
            if c.rowcount!=1:raise RuntimeError('request already sent')
            c.execute('UPDATE daily_usage SET reserved_count=reserved_count-1,used_count=used_count+1 WHERE account_id=%s AND business_date=%s AND endpoint=%s AND reserved_count>0',(a['account_id'],claim['business_date'],t['endpoint']))
            if c.rowcount!=1:raise RuntimeError('request reservation missing')
            c.execute('UPDATE tasks SET attempts=attempts+1 WHERE id=%s',(t['id'],))

    def finish(self,claim,response=None,error=None,sent=True,proxy_refreshed=False):
        a,t=claim['account'],claim['task'];endpoint=t['endpoint'];now=utcnow()
        outcome,valid=classify(endpoint,response,t['shop_id'],t['target_id']) if sent and error is None else ('transport_error' if sent else 'local_error',False)
        http=response.get('_http_status') if isinstance(response,dict) else None;code=response.get('code') if isinstance(response,dict) else None
        maintenance_wait=not sent and error=='FingerprintRefreshBlocked'
        if maintenance_wait:outcome='maintenance_wait'
        followups=([],[],set())
        if valid and endpoint in ('productList','productRender'):
            followups=menu_followups(endpoint,response,unpack_json(t['payload']))
            if followups[2]:outcome='incomplete_payload'
        with self.store.transaction() as c:
            c.execute('SELECT id FROM accounts WHERE id=%s FOR UPDATE',(a['account_id'],));c.fetchone()
            c.execute('SELECT state,counts_budget,http_status,business_code,outcome,error_type FROM request_attempts WHERE id=%s FOR UPDATE',(claim['attempt_id'],))
            previous=c.fetchone()
            if previous and previous['state'] in ('done','local_error'):
                c.execute('SELECT state FROM tasks WHERE id=%s',(t['id'],));task_state=c.fetchone()['state']
                return {'account_id':a['account_id'],'task_id':t['id'],'endpoint':endpoint,
                        'sent':bool(previous['counts_budget']),'http':previous['http_status'],
                        'code':previous['business_code'],'outcome':previous['outcome'],'task_state':task_state,
                        'error_type':previous['error_type'],'proxy_refreshed':proxy_refreshed}
            self._fence(c,claim)
            if not sent:
                c.execute('UPDATE daily_usage SET reserved_count=reserved_count-1 WHERE account_id=%s AND business_date=%s AND endpoint=%s AND reserved_count>0',(a['account_id'],claim['business_date'],endpoint))
            c.execute('UPDATE request_attempts SET state=%s,counts_budget=%s,finished_at=%s,http_status=%s,business_code=%s,outcome=%s,valid_data=%s,error_type=%s WHERE id=%s',
                      ('done' if sent else 'local_error',sent,now,http,str(code) if code is not None else None,outcome,valid,error,claim['attempt_id']))
            if valid:
                self.store.result(c,t['shop_job_id'],a['account_id'],endpoint,response,now,t['target_id'],t['id'])
                if outcome=='success':self.store.observe(c,a['id'],endpoint,'available',now,http,code,'mysql_worker')
                for product in followups[0]:self.store.enqueue(c,t['shop_job_id'],'productSpecifics',product,priority=20)
                for payload in followups[1]:self.store.enqueue(c,t['shop_job_id'],'productRender',digest(payload)[:24],payload,priority=10)
                if endpoint in ('productList','productRender'):self.reconcile_unavailable_details(c,t)
                if endpoint=='accountInfo':
                    c.execute("UPDATE accounts SET identity_status='verified',verified_at=%s WHERE id=%s",(now,a['account_id']))
                else:
                    c.execute("UPDATE accounts SET identity_status='observed' WHERE id=%s AND identity_status='unverified'",(a['account_id'],))
                c.execute("UPDATE experiment_members SET state='ready',rest_until=NULL WHERE account_id=%s AND endpoint=%s AND rest_until<=%s AND state!='stopped'",(a['account_id'],endpoint,now))
            if outcome=='rejected' and proxy_refreshed:
                self.store.observe(c,a['id'],endpoint,'unknown',now,http,code,'ipfoxy_refresh_retry',now+timedelta(seconds=4))
            elif outcome=='rejected':
                retry_seconds=int(response.get('_retry_after_seconds',86400) or 86400) if http==429 else 86400
                self.store.observe(c,a['id'],endpoint,'cooldown',now,http,code,'mysql_worker',now+timedelta(seconds=max(60,retry_seconds)))
            elif not sent and not maintenance_wait:self.store.observe(c,a['id'],endpoint,'needs_material',now,source=error)
            if http==401 or code==401:
                c.execute("UPDATE accounts SET identity_status='expired' WHERE id=%s",(a['account_id'],))
            skip_closed=self._skip_closed_details(c,t,response,outcome)
            skip_unavailable=self._skip_unavailable_details(c,t,response,outcome)
            if valid and outcome=='success':state='succeeded';not_before=None
            elif skip_closed and endpoint=='productSpecifics' and outcome=='store_closed':state='skipped_closed';not_before=None
            elif skip_unavailable:state='skipped_unavailable';not_before=None
            elif maintenance_wait:
                state='retry_wait';not_before=datetime.fromtimestamp(response['_maintenance_retry_at'],timezone.utc).replace(tzinfo=None)
            elif not sent:state='retry_wait';not_before=now
            elif proxy_refreshed:
                state='retry_wait';not_before=now+timedelta(seconds=4)
                # Preserve the promised retry when the 403 consumed the last attempt.
                c.execute('UPDATE tasks SET max_attempts=GREATEST(max_attempts,attempts+1) WHERE id=%s',(t['id'],))
            elif outcome=='store_closed':state='deferred_business';not_before=now+timedelta(hours=6)
            else:
                c.execute('SELECT attempts,max_attempts FROM tasks WHERE id=%s',(t['id'],));counter=c.fetchone()
                state='dead_letter' if counter['attempts']>=counter['max_attempts'] else 'retry_wait'
                not_before=now+timedelta(seconds=86400 if http==429 else 300)
            c.execute('UPDATE tasks SET state=%s,not_before=%s,last_reason=%s,lease_owner=NULL,lease_until=NULL,updated_at=%s WHERE id=%s',
                      (state,not_before,'product_unavailable_response' if skip_unavailable else outcome,now,t['id']))
            if skip_closed:
                c.execute("UPDATE tasks SET state='skipped_closed',not_before=NULL,last_reason='store_closed',updated_at=%s WHERE shop_job_id=%s AND endpoint='productSpecifics' AND state IN ('pending','retry_wait','deferred_business','dead_letter')",(now,t['shop_job_id']))
            elif outcome=='store_closed':
                c.execute("UPDATE tasks SET state='deferred_business',not_before=%s,last_reason='store_closed' WHERE shop_job_id=%s AND endpoint='productSpecifics' AND state IN ('pending','retry_wait')",(not_before,t['shop_job_id']))
            # Automatic stop at the local daily work limit. No midnight claim
            # automatically resets a 24-hour account rest experiment.
            c.execute('SELECT u.used_count,p.work_limit FROM daily_usage u JOIN budget_policies p ON p.account_id=u.account_id AND p.endpoint=u.endpoint WHERE u.account_id=%s AND u.business_date=%s AND u.endpoint=%s',
                      (a['account_id'],claim['business_date'],endpoint));budget=c.fetchone()
            if sent and endpoint=='productSpecifics' and ((outcome=='rejected' and not proxy_refreshed) or budget['used_count']>=budget['work_limit']):
                c.execute("INSERT INTO experiment_members(account_id,experiment_name,endpoint,target_attempts,rest_hours,state,rest_until,settings) VALUES(%s,'daily_details_v1',%s,%s,24,'resting',%s,%s) ON DUPLICATE KEY UPDATE state='resting',rest_until=VALUES(rest_until),settings=VALUES(settings)",
                          (a['account_id'],endpoint,budget['work_limit'],now+timedelta(hours=24),compact({'automatic_recovery':False,'stop_reason':'daily_budget' if budget['used_count']>=budget['work_limit'] else outcome,'rest_scope':'all_account_requests'})))
        return {'account_id':a['account_id'],'task_id':t['id'],'endpoint':endpoint,'sent':sent,'http':http,'code':code,'outcome':outcome,'task_state':state,'error_type':error,'proxy_refreshed':proxy_refreshed}

    def _journal_folder(self,run_id):
        return self.store.config_path.parent/'request-journal'/str(int(run_id))

    def durable_finish(self,claim,**result):
        """Journal the received response before SQL; replay SQL, never HTTP."""
        folder=self._journal_folder(claim['task']['run_id'])
        folder.mkdir(parents=True,exist_ok=True,mode=0o700)
        path=folder/(claim['attempt_id']+'.json')
        saved={'account':{k:claim['account'][k] for k in ('id','account_id')},
               'task':{k:claim['task'][k] for k in ('id','endpoint','target_id','shop_id','shop_job_id','run_id','run_settings','payload')},
               'owner':claim['owner'],'attempt_id':claim['attempt_id'],
               'business_date':str(claim['business_date']),'locks':claim['locks']}
        key,blob=self.store.seal({'claim':saved,'result':result})
        fd,tmp=tempfile.mkstemp(dir=folder,prefix='.pending-')
        try:
            with os.fdopen(fd,'w') as out:
                out.write(compact({'encryption_key_id':key,'blob':blob.hex()}));out.flush();os.fsync(out.fileno())
            os.replace(tmp,path)
        finally:
            if os.path.exists(tmp):os.unlink(tmp)
        return self._commit_journal(path,saved,result)

    def _commit_journal(self,path,claim,result):
        for attempt in range(3):
            try:
                outcome=self.finish(claim,**result)
                path.unlink(missing_ok=True)
                return outcome
            except Exception as exc:
                if not transient_database_error(exc) or attempt==2:raise
                log_failure('response_commit_retry',exc,task_id=claim['task']['id'],retry=attempt+1)
                time.sleep(.5*(2**attempt))

    def replay_pending(self,run_id):
        folder=self._journal_folder(run_id)
        if not folder.exists():return 0
        count=0
        for path in sorted(folder.glob('*.json')):
            record=json.loads(path.read_text())
            saved=self.store.unseal({'encryption_key_id':record['encryption_key_id'],'credential_blob':bytes.fromhex(record['blob'])})
            claim=saved['claim']
            if claim['task']['run_id']!=run_id:raise ValueError('journal run mismatch')
            con=self.store.lock_connection();locks=[]
            try:
                with con.cursor() as c:
                    for name in claim['locks']:
                        c.execute('SELECT GET_LOCK(%s,0) locked',(name,))
                        if c.fetchone()['locked']!=1:
                            raise RuntimeError('journal account still busy')
                        locks.append(name)
                self._commit_journal(path,claim,saved['result']);count+=1
            finally:self._release_locks(con,locks)
        return count

    def try_proxy_refresh(self,claim,bundle,http_status):
        if http_status!=403 or not bundle.get('refresh_ipfoxy') or not is_ipfoxy(bundle.get('proxy')):
            return False
        payload=unpack_json(claim['task']['payload'])
        if payload.get('_ipfoxy_refresh_attempted'):return False
        route_key=digest([bundle.get('proxy'),bundle.get('front_proxy')])
        lock='keeta:proxy:'+route_key[:45];con=claim['connection']
        with con.cursor() as c:
            c.execute('SELECT GET_LOCK(%s,0) locked',(lock,))
            if c.fetchone()['locked']!=1:return False
        try:
            now=utcnow()
            with self.store.transaction() as c:
                c.execute('SELECT id FROM proxy_refresh_events WHERE route_key=%s AND started_at>%s LIMIT 1',(route_key,now-timedelta(minutes=5)))
                if c.fetchone():return False
                self._fence(c,claim)
                payload=dict(payload,_ipfoxy_refresh_attempted=True)
                c.execute('UPDATE tasks SET payload=%s WHERE id=%s',(compact(payload),claim['task']['id']))
                c.execute("INSERT INTO proxy_refresh_events(route_key,account_id,task_id,started_at,outcome) VALUES(%s,%s,%s,%s,'started')",(route_key,claim['account']['account_id'],claim['task']['id'],now))
                event=c.lastrowid
            result=refresh_ipfoxy(bundle['proxy'],bundle.get('front_proxy'))
            with self.store.transaction() as c:
                c.execute('UPDATE proxy_refresh_events SET finished_at=%s,outcome=%s,http_status=%s,error_type=%s,exit_before=%s,exit_after=%s,ip_changed=%s WHERE id=%s',(utcnow(),result['outcome'],result.get('http_status'),result.get('error_type'),result.get('exit_before'),result.get('exit_after'),result.get('ip_changed'),event))
            return result['accepted']
        finally:
            with con.cursor() as c:c.execute('SELECT RELEASE_LOCK(%s)',(lock,))

    def execute(self,claim):
        sent=False;signer=None;route_context=None;persisting=False
        try:
            bundle=self.store.unseal(claim['account'])
            signer=FullSigner(bundle['device']);context=RequestContext(bundle);task=claim['task'];path=PATHS[task['endpoint']];method='POST'
            from farm.accounts.fingerprint import before_business, retry_at
            def persist_fingerprint(device):
                bundle['device']=device;self.save_state(claim,bundle)
            try:
                before_business(signer,bundle,account_id=claim['account'].get('account_id'),session_id=claim['account'].get('id'),
                    persist=persist_fingerprint,proxy=bundle.get('proxy'),front_proxy=bundle.get('front_proxy'))
            except Exception as exc:
                if isinstance(exc,pymysql.err.Error):raise
                due=retry_at(signer.dev)
                if not hasattr(self,'fingerprint_wait_until'):self.fingerprint_wait_until={}
                self.fingerprint_wait_until[claim['account']['account_id']]=due
                persisting=True
                return self.durable_finish(claim,response={'_maintenance_retry_at':due},error='FingerprintRefreshBlocked',sent=False)
            if task['endpoint']=='accountInfo':
                request=bundle.get('account_check_request') or {};url=request.get('url','');parsed=urlsplit(url)
                validate_account_request(request,bundle['identity'])
                headers={k.lower():v for k,v in request['headers'].items() if not k.startswith(':') and k.lower() not in ('mtgsig','content-length','accept-encoding')}
                if headers.get('token')!=bundle['identity']['token']:raise ValueError('account-check token mismatch')
                method='GET';body=''
            elif task['endpoint']=='homeShopList':url,headers,body=context.build_shop_list(unpack_json(task['payload']).get('page',0))
            else:
                url,headers,body=context.build(path,task['shop_id'],task['latitude'],task['longitude'],city=task['city_id'],spu_id=int(task['target_id']) if task['endpoint']=='productSpecifics' else None)
            if task['endpoint']=='productRender':
                parsed=json.loads(body);parsed.update({k:v for k,v in unpack_json(task['payload']).items() if not k.startswith('_')});body=compact(parsed)
            try:
                if method=='POST':url,headers,body=signer.prepare_request(url,headers,body)
                headers['mtgsig']=signer.sign(method,url,body)
            finally:
                signer.persist_counter();bundle['device']=signer.dev;self.save_state(claim,bundle)
            # Validate locally before consuming the HTTP-attempt budget.
            requests.Request(method,url,headers=headers,data=body.encode()).prepare()
            route_context=ProxyRoute(bundle.get('proxy'),bundle.get('front_proxy'))
            with route_context as route_proxy:
                proxies={'http':route_proxy,'https':route_proxy} if route_proxy else None
                self.mark_sent(claim);sent=True
                with requests.Session() as session:
                    session.trust_env=False
                    send=session.post if method=='POST' else session.get
                    response=send(url,headers=headers,data=body.encode(),proxies=proxies,timeout=(30 if bundle.get('proxy') else 8,45),allow_redirects=False)
            try:payload=response.json()
            except ValueError:payload={}
            if not isinstance(payload,dict):payload={}
            payload['_http_status']=response.status_code
            if response.status_code>=400 or payload.get('code') not in (None,0):
                try:self.store.record_failure_response(claim['attempt_id'],response)
                except Exception as exc:print('response_diagnostic_error='+type(exc).__name__,flush=True)
            if response.headers.get('Retry-After','').isdigit():payload['_retry_after_seconds']=int(response.headers['Retry-After'])
            try:refreshed=self.try_proxy_refresh(claim,bundle,response.status_code)
            except Exception as exc:
                print('proxy_refresh_error='+type(exc).__name__,flush=True)
                refreshed=False
            persisting=True
            return self.durable_finish(claim,response=payload,sent=True,proxy_refreshed=refreshed)
        except Exception as exc:
            # A DB failure must not turn valid account material into a local
            # signing error, nor overwrite a response awaiting SQL commit.
            if persisting or isinstance(exc,pymysql.err.Error):raise
            # Error type only: request exceptions may embed tokens/URLs.
            persisting=True
            return self.durable_finish(claim,error=type(exc).__name__,sent=sent)
        finally:
            self._release_locks(claim['connection'],claim['locks'])
            if claim.get('route_gate') is not None:claim['route_gate'].release()

    def probe(self,account_id,endpoint,shop_job_id=None):
        if endpoint not in PATHS:raise ValueError('unknown endpoint')
        if endpoint=='productSpecifics' and shop_job_id:
            # Use the latest observation for the same shop and location, even
            # when it came from a separate probe job. Do not reserve an HTTP
            # request or create a new probe job for a known closed shop.
            latest=self.store.rows("SELECT r.response_blob FROM shop_jobs source JOIN shop_jobs j ON j.shop_id=source.shop_id AND j.context_key=source.context_key JOIN task_results r ON r.shop_job_id=j.id WHERE source.id=%s AND r.endpoint='shopInfo' AND r.valid_data=TRUE ORDER BY r.observed_at DESC,r.id DESC LIMIT 1",(shop_job_id,))
            if latest and shop_is_closed(load_response(latest[0]['response_blob'])):
                return {'account_id':account_id,'endpoint':endpoint,'shop_job_id':shop_job_id,
                        'status':'skipped_closed','reason':'store_closed','sent':False}
        refresh_account_material(self.store,account_id)
        diagnostic=self.diagnose([account_id],[endpoint],allow_probe=True)[0]
        if diagnostic['reason']!='eligible':
            return dict(diagnostic,status=diagnostic['reason'],sent=False)
        rows=self.store.rows('SELECT s.* FROM accounts a JOIN account_sessions s ON s.id=a.active_session_id WHERE a.id=%s',(account_id,))
        if not rows:raise ValueError('unknown active account')
        session=rows[0];bundle=self.store.unseal(session);now=utcnow()
        capability=self.store.rows('SELECT * FROM capabilities WHERE session_id=%s AND endpoint=%s',(session['id'],endpoint))
        if not capability or capability[0]['state']=='needs_material':return {'status':'needs_material','endpoint':endpoint,'sent':False}
        if capability[0]['not_before'] and capability[0]['not_before']>now:
            return {'status':'cooldown','not_before':capability[0]['not_before']}
        template=bundle.get('templates',{}).get(PATHS[endpoint],{})
        body=unpack_json(template.get('body') or {})
        if shop_job_id:
            found=self.store.rows('SELECT * FROM shop_jobs WHERE id=%s',(shop_job_id,))
            if not found:raise ValueError('unknown shop job')
            source=found[0]
        else:
            loc=body.get('location') or {}
            source={'shop_id':str(body.get('shopId','0')),'latitude':str(body.get('latitude',loc.get('latitude','0'))),
                    'longitude':str(body.get('longitude',loc.get('longitude','0'))),'city_id':'102302389'}
        if endpoint not in ('accountInfo','homeShopList') and source['shop_id'] in ('0',''):
            return {'status':'shop_job_required','endpoint':endpoint,'sent':False}
        product=body.get('spuId')
        if endpoint=='productSpecifics' and shop_job_id:
            products=self.store.rows("SELECT target_id FROM tasks WHERE shop_job_id=%s AND endpoint='productSpecifics' ORDER BY id LIMIT 1",(shop_job_id,))
            product=products[0]['target_id'] if products else None
        if endpoint=='productSpecifics' and not product:return {'status':'menu_product_required','endpoint':endpoint,'sent':False}
        if endpoint=='productRender':return {'status':'menu_render_task_required','endpoint':endpoint,'sent':False}
        run_id=self.store.run('账号能力探测','probe',[account_id,endpoint,str(business_day(now))])
        target=str(bundle['identity']['userid']) if endpoint=='accountInfo' else str(product) if endpoint=='productSpecifics' else ''
        with self.store.transaction() as c:
            c.execute('SELECT id FROM collection_runs WHERE id=%s FOR UPDATE',(run_id,));c.fetchone()
            c.execute('SELECT t.id FROM tasks t JOIN shop_jobs j ON j.id=t.shop_job_id WHERE j.run_id=%s LIMIT 1',(run_id,))
            if not c.fetchone():
                job=self.store.shop(c,run_id,source['shop_id'],source['latitude'],source['longitude'],source['city_id'])
                self.store.enqueue(c,job,endpoint,target,{'_probe':True},priority=100)
                c.execute('UPDATE tasks SET max_attempts=1 WHERE shop_job_id=%s',(job,))
        claim=self.claim(run_id,account_id,[endpoint],allow_probe=True)
        if claim is None:return {'status':'waiting_budget_or_already_probed','run_id':run_id}
        return self.execute(claim)

    def run(self,run_id,max_requests=1,account_id=None,endpoints=None,delay=4,*,environment=None,account_ids=None,tags=None):
        if max_requests<1:raise ValueError('max_requests must be positive')
        from farm.accounts.selection import select_accounts
        selected=select_accounts(self.store,environment,[account_id] if account_id is not None else account_ids,tags)
        for account in selected:refresh_account_material(self.store,account['id'])
        self.recover();results=[]
        while len(results)<max_requests:
            claim=self.claim(run_id,account_id,endpoints,environment=environment,account_ids=account_ids,tags=tags)
            if claim is None:
                waits=[due-time.monotonic() for due in self.details_ready_at.values() if due>time.monotonic()]
                if waits:time.sleep(min(waits));continue
                break
            result=self.execute(claim);results.append(result);print(compact(result),flush=True)
            if result['outcome']=='transport_error':break
            if result.get('sent') and result['endpoint']=='productSpecifics':
                self.details_ready_at[result['account_id']]=time.monotonic()+delay
        return {'processed':len(results),'sent':sum(r['sent'] for r in results),'results':results,
                'stop_reason':'limit' if len(results)==max_requests else 'no_eligible_work_or_transport_error'}
