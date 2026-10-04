"""Durable execution jobs for a local panel. Account HTTP budgets live in MySQL."""
from datetime import timedelta
from pathlib import Path
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import uuid
import zipfile
import os
import tempfile
from farm.storage.responses import local_reference

from farm.storage.mysql import ENDPOINTS, ROOT, compact, unpack_json, utcnow, digest, transient_database_error, log_failure
from farm.accounts.selection import parse_ids, parse_tags, select_accounts
from farm.collection.worker import Worker
from farm.delivery.export import export_run
from farm.accounts.importer import refresh_account_material

EXPORT_ROOT = ROOT / 'exports'


class RouteRejections:
    """Four consecutive 403s across accounts suspend only that route for 15m.

    Rebuilt from the durable attempt ledger on every execution pass. Network
    failures do not establish recovery; account/endpoint cooldowns stay intact.
    """
    def __init__(self,keys):
        self.keys=keys;self.streaks={};self.until={}

    def key(self,account):
        return self.keys.get(account,'account:'+str(account))

    def record(self,account,http,at):
        key=self.key(account);until=self.until.get(key)
        if until and at<until:return
        if until:
            self.until.pop(key,None);self.streaks.pop(key,None)
        if http==403:
            streak=self.streaks.setdefault(key,[]);streak.append(account)
            self.streaks[key]=streak[-4:]
            if len(streak)>=4 and len(set(streak[-4:]))>=2:
                self.until[key]=at+timedelta(minutes=15)
        elif http is not None:self.streaks.pop(key,None)

    def ready(self,account,now=None):
        until=self.until.get(self.key(account))
        return until is None or until<=(now or utcnow())

    def blocked(self,now=None):
        now=now or utcnow()
        return {key:until for key,until in self.until.items() if until>now}


def create_execution(store, run_id, environment, ids=None, tags=None, endpoints=None,
                     max_requests=100, delay=4, auto_resume=False, concurrency=1):
    ids = parse_ids(ids); tags = parse_tags(tags)
    endpoints = list(dict.fromkeys(endpoints if endpoints is not None else ['shopInfo','productList','productRender','productSpecifics']))
    if not endpoints or any(e not in ENDPOINTS for e in endpoints):
        raise ValueError('未知接口')
    max_requests = int(max_requests); delay = float(delay); concurrency=int(concurrency)
    if not 1<=concurrency<=8:raise ValueError('并发账号数必须在 1–8 之间')
    if not 1 <= max_requests <= 1000000 or not 0 <= delay <= 3600:
        raise ValueError('请求上限或间隔不在允许范围内')
    accounts = select_accounts(store, environment, ids, tags)
    if not accounts:
        raise ValueError('筛选结果没有账号')
    resolved = [a['id'] for a in accounts]
    for aid in resolved:refresh_account_material(store,aid)
    with store.transaction() as c:
        # Recheck selected accounts under row locks so deletion cannot race
        # creation of a queued execution after the selection preview.
        for aid in sorted(resolved):
            c.execute('SELECT id FROM accounts WHERE id=%s FOR UPDATE',(aid,))
            if not c.fetchone():raise ValueError('所选账号已被删除，请刷新后重试')
        c.execute('SELECT source_kind FROM collection_runs WHERE id=%s FOR UPDATE', (run_id,))
        row = c.fetchone()
        if not row or row['source_kind'] not in ('task_sheet','validation'):
            raise ValueError('只能运行导入的任务批次')
        c.execute("SELECT id FROM executions WHERE run_id=%s AND state IN ('queued','running')", (run_id,))
        if c.fetchone():
            raise ValueError('此批次已经排队或正在运行')
        c.execute('''INSERT INTO executions(run_id,environment,selection,account_ids,endpoints,max_requests,delay_seconds,created_at)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s)''',
            (run_id,environment,compact({'ids':ids,'tags':tags,'auto_resume':bool(auto_resume),'concurrency':concurrency,'delay_scope':'productSpecifics'}),compact(resolved),compact(endpoints),max_requests,delay,utcnow()))
        identifier = c.lastrowid
    return {'execution_id':identifier,'account_ids':resolved,'environment':environment}



def create_subset_run(store,source_run_id,limit=100,*,skip_closed_details=False):
    """Copy a bounded batch and its collected data without duplicating usage."""
    limit=int(limit)
    if not 1<=limit<=10000:raise ValueError('店铺数量超出范围')
    with store.transaction() as c:
        c.execute('SELECT * FROM collection_runs WHERE id=%s FOR UPDATE',(source_run_id,));source=c.fetchone()
        if not source or source['source_kind'] not in ('task_sheet','validation'):raise ValueError('来源批次不存在')
        c.execute("SELECT id FROM executions WHERE run_id=%s AND state IN ('queued','running')",(source_run_id,))
        if c.fetchone():raise ValueError('请先停止来源批次')
        c.execute('SELECT * FROM shop_jobs WHERE run_id=%s ORDER BY id',(source_run_id,))
        jobs=[];seen=set()
        for job in c.fetchall():
            if job['shop_id'] in seen:continue
            seen.add(job['shop_id']);jobs.append(job)
            if len(jobs)==limit:break
        if len(jobs)!=limit:raise ValueError('来源批次店铺数量不足')
        settings=dict(unpack_json(source['settings']),source_run_id=source_run_id,
                      source_job_ids=[j['id'] for j in jobs],shop_limit=limit,
                      skip_closed_details=bool(skip_closed_details))
        key=digest(['subset',source_run_id,settings['source_job_ids'],bool(skip_closed_details)])
        c.execute('SELECT id FROM collection_runs WHERE run_key=%s',(key,));existing=c.fetchone()
        if existing:return {'run_id':existing['id'],'shops':limit,'reused':True}
        label=f'{limit}店交付 · 原批次#{source_run_id} · 闭店跳过子菜' if skip_closed_details else f'{limit}店交付 · 原批次#{source_run_id}'
        c.execute('INSERT INTO collection_runs(run_key,label,source_kind,settings,created_at) VALUES(%s,%s,%s,%s,%s)',(key,label,source['source_kind'],compact(settings),utcnow()))
        run_id=c.lastrowid
        c.executemany('INSERT INTO shop_jobs(run_id,shop_id,latitude,longitude,city_id,shop_name,context_key) VALUES(%s,%s,%s,%s,%s,%s,%s)',[(run_id,j['shop_id'],j['latitude'],j['longitude'],j['city_id'],j['shop_name'],j['context_key']) for j in jobs])
        c.execute('SELECT id,shop_id,context_key FROM shop_jobs WHERE run_id=%s',(run_id,))
        ids={(j['shop_id'],j['context_key']):j['id'] for j in c.fetchall()}
        job_map={j['id']:ids[j['shop_id'],j['context_key']] for j in jobs}
        placeholders=','.join(['%s']*len(jobs))
        c.execute(f'SELECT * FROM tasks WHERE shop_job_id IN ({placeholders}) ORDER BY id',tuple(job_map));tasks=c.fetchall()
        if any(t['state']=='leased' for t in tasks):raise ValueError('来源批次仍有请求正在执行')
        copied=[];task_keys={}
        for t in tasks:
            payload=unpack_json(t['payload'])
            canonical={k:v for k,v in payload.items() if k!='_ipfoxy_refresh_attempted'}
            task_key=digest([job_map[t['shop_job_id']],t['endpoint'],str(t['target_id']),canonical])
            task_keys[t['id']]=task_key
            copied.append((task_key,job_map[t['shop_job_id']],t['endpoint'],t['target_id'],compact(payload),t['state'],t['priority'],t['attempts'],t['max_attempts'],t['not_before'],t['last_reason'],utcnow(),utcnow()))
        if copied:c.executemany('INSERT INTO tasks(task_key,shop_job_id,endpoint,target_id,payload,state,priority,attempts,max_attempts,not_before,last_reason,created_at,updated_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',copied)
        c.execute('SELECT t.id,t.task_key FROM tasks t JOIN shop_jobs j ON j.id=t.shop_job_id WHERE j.run_id=%s',(run_id,))
        new_task_ids={t['task_key']:t['id'] for t in c.fetchall()}
        c.execute(f'SELECT * FROM task_results WHERE shop_job_id IN ({placeholders}) AND valid_data=TRUE ORDER BY id',tuple(job_map));results=c.fetchall()
        copied=[]
        for r in results:
            job_id=job_map[r['shop_job_id']];task_id=new_task_ids.get(task_keys.get(r['task_id']))
            key=digest([job_id,r['account_id'],r['endpoint'],str(r['target_id']),r['response_sha256']])
            copied.append((key,job_id,task_id,r['account_id'],r['endpoint'],r['target_id'],r['observed_at'],True,local_reference(r['response_blob']),r['response_sha256']))
        if copied:c.executemany('INSERT INTO task_results(result_key,shop_job_id,task_id,account_id,endpoint,target_id,observed_at,valid_data,response_blob,response_sha256) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',copied)
    return {'run_id':run_id,'shops':limit,'copied_results':len(copied),'reused':False}


def stop_execution(store, identifier):
    with store.transaction() as c:
        c.execute("UPDATE executions SET stop_requested=TRUE,finished_at=IF(state IN ('queued','waiting','interrupted'),%s,finished_at),state=IF(state IN ('queued','waiting','interrupted'),'stopped',state),stop_reason='user_stop' WHERE id=%s AND state IN ('queued','running','waiting','interrupted')", (utcnow(),identifier))
    return {'execution_id':identifier,'stop_requested':True}


def export_bundle(store, run_id, folder):
    folder = Path(folder); folder.mkdir(parents=True, exist_ok=True)
    summary = export_run(store,run_id,folder/'delivery.xlsx')
    archive = folder/'delivery.zip'
    fd,temporary=tempfile.mkstemp(dir=folder,prefix='.delivery-',suffix='.zip')
    os.close(fd)
    try:
        with zipfile.ZipFile(temporary,'w',zipfile.ZIP_DEFLATED) as out:
            out.write(folder/'delivery.xlsx','delivery.xlsx')
        os.replace(temporary,archive)
    finally:
        if os.path.exists(temporary):os.unlink(temporary)
    return dict(summary,archive=str(archive.resolve()))


class ExecutorLease:
    """Keep the dedicated MySQL lock connection alive throughout collection.

    A disconnected owner stops scheduling. Its abandoned server connection
    expires after two minutes instead of holding the lock for eight hours.
    """
    def __init__(self,store):
        self.store=store;self.connection=None;self.thread=None
        self.stop=threading.Event();self.lost=threading.Event()

    def acquire(self):
        self.connection=self.store.connect()
        with self.connection.cursor() as c:
            c.execute('SET SESSION wait_timeout=120')
            c.execute("SELECT GET_LOCK('keeta:panel-executor',0) locked")
            if c.fetchone()['locked']!=1:
                self.connection.close();self.connection=None;return False
        self.thread=threading.Thread(target=self._keepalive,name='keeta-executor-lock',daemon=True)
        self.thread.start();return True

    def _keepalive(self):
        while not self.stop.wait(15):
            try:self.connection.ping(reconnect=False)
            except Exception:
                self.lost.set();return

    def close(self):
        self.stop.set()
        if self.thread:self.thread.join(timeout=25)
        if self.connection:
            try:
                if not self.lost.is_set() and not (self.thread and self.thread.is_alive()):
                    with self.connection.cursor() as c:c.execute("SELECT RELEASE_LOCK('keeta:panel-executor')")
            except Exception:pass
            finally:self.connection.close()


class ExecutionManager:
    def __init__(self, store):
        self.store=store; self.quit=threading.Event()
        self.owner=str(uuid.uuid4());self.lease=None


    def serve(self):
        # A single executor per database; HTTP requests still take account/install locks.
        failures=0
        while not self.quit.is_set():
            lease=ExecutorLease(self.store);self.lease=lease
            try:
                if not lease.acquire():
                    self.quit.wait(5);continue
                with self.store.transaction() as c:
                    c.execute("UPDATE executions SET state='interrupted',finished_at=%s,stop_reason='executor_restarted' WHERE state='running'",(utcnow(),))
                while not self.quit.is_set() and not lease.lost.is_set():
                    rows=self.store.rows("SELECT e.* FROM executions e JOIN collection_runs r ON r.id=e.run_id WHERE e.state='queued' AND r.source_kind='task_sheet' ORDER BY e.id LIMIT 1")
                    failures=0
                    if not rows:
                        self.resume_waiting()
                        self.quit.wait(2); continue
                    job=rows[0]
                    with self.store.transaction() as c:
                        c.execute("UPDATE executions SET state='running',owner=%s,started_at=%s,heartbeat_at=%s WHERE id=%s AND state='queued' AND stop_requested=FALSE",(self.owner,utcnow(),utcnow(),job['id']))
                        acquired=c.rowcount==1
                    if acquired:
                        with self.store.transaction() as c:
                            c.execute("UPDATE collection_runs SET status='running' WHERE id=%s",(job['run_id'],))
                        self.execute(job)
            except Exception as exc:
                failures+=1
                log_failure('executor_error',exc,retry=failures)
                self.quit.wait(min(60,5*2**min(failures-1,4)))
            finally:
                try:lease.close()
                except Exception:pass
                self.lease=None

    def resume_waiting(self):
        # A durable waiting execution resumes only when a due task and an
        # eligible selected account exist. No network probes in this poll.
        now=utcnow()
        rows=self.store.rows("SELECT * FROM executions WHERE state IN ('waiting','interrupted') AND stop_requested=FALSE AND (processed<max_requests OR stop_reason='database_unavailable' OR state='interrupted') AND (heartbeat_at IS NULL OR heartbeat_at<%s) ORDER BY id",(now-timedelta(seconds=60),))
        for job in rows:
            selection=unpack_json(job['selection'])
            if not selection.get('auto_resume') and job['stop_reason']!='database_unavailable':continue
            with self.store.transaction() as c:
                c.execute('UPDATE executions SET heartbeat_at=%s WHERE id=%s',(now,job['id']))
            if job['stop_reason']=='transport_error':
                recent=self.store.rows("SELECT r.outcome FROM request_attempts r JOIN tasks t ON t.id=r.task_id JOIN shop_jobs j ON j.id=t.shop_job_id WHERE j.run_id=%s AND r.state='done' ORDER BY r.started_at DESC LIMIT 3",(job['run_id'],))
                if len(recent)==3 and all(r['outcome']=='transport_error' for r in recent):
                    with self.store.transaction() as c:
                        c.execute("UPDATE executions SET state='failed',stop_reason='network_unavailable',finished_at=%s WHERE id=%s AND state='waiting'",(now,job['id']))
                        if c.rowcount:c.execute("UPDATE collection_runs SET status='failed' WHERE id=%s",(job['run_id'],))
                    continue
            # Commit saved responses before expiring uncertain leases. This
            # also recovers a final response when no pending task remains.
            worker=Worker(self.store)
            worker.replay_pending(job['run_id'])
            worker.recover(job['run_id'])
            remaining=self.store.rows("SELECT COUNT(*) n FROM tasks t JOIN shop_jobs j ON j.id=t.shop_job_id WHERE j.run_id=%s AND t.state NOT IN ('succeeded','skipped_closed','skipped_unavailable','covered_by_details')",(job['run_id'],))[0]['n']
            accounts=select_accounts(self.store,job['environment'],unpack_json(job['account_ids']),selection.get('tags'))
            endpoints=unpack_json(job['endpoints'])
            diagnostics=Worker(self.store).diagnose([a['id'] for a in accounts],endpoints,allow_recovery=True)
            self.configure_routes(job)
            eligible={d['endpoint'] for d in diagnostics if d['reason']=='eligible' and self.route_rejections.ready(d['account_id'])}
            if remaining:
                if not eligible:continue
                placeholders=','.join(['%s']*len(eligible))
                due=self.store.rows(f"SELECT t.id FROM tasks t JOIN shop_jobs j ON j.id=t.shop_job_id WHERE j.run_id=%s AND t.state IN ('pending','retry_wait','deferred_business') AND t.attempts<t.max_attempts AND (t.not_before IS NULL OR t.not_before<=%s) AND t.endpoint IN ({placeholders}) LIMIT 1",(job['run_id'],now,*sorted(eligible)))
                if not due:continue
            with self.store.transaction() as c:
                c.execute('SELECT id FROM collection_runs WHERE id=%s FOR UPDATE',(job['run_id'],))
                if not c.fetchone():continue
                c.execute("SELECT id FROM executions WHERE run_id=%s AND id<>%s AND state IN ('queued','running')",(job['run_id'],job['id']))
                if c.fetchone():continue
                c.execute("UPDATE executions SET state='queued',finished_at=NULL,stop_reason=NULL WHERE id=%s AND state IN ('waiting','interrupted') AND stop_requested=FALSE",(job['id'],))

    def prepare_counters(self,job):
        # Preserve history of older executions whose attempts were untagged.
        with self.store.transaction() as c:
            c.execute('SELECT selection,processed,sent,valid_count FROM executions WHERE id=%s FOR UPDATE',(job['id'],))
            current=c.fetchone();selection=unpack_json(current['selection'])
            if '_counter_base' not in selection:
                selection['_counter_base']={k:int(current[k]) for k in ('processed','sent','valid_count')}
                c.execute('UPDATE executions SET selection=%s WHERE id=%s',(compact(selection),job['id']))
        job['selection']=selection
        return selection

    def record_progress(self,job):
        # Absolute totals from the ledger survive commit acknowledgement loss;
        # an increment after HTTP would lose or duplicate counts on recovery.
        base=unpack_json(job['selection'])['_counter_base']
        with self.store.transaction() as c:
            c.execute('SELECT id FROM executions WHERE id=%s FOR UPDATE',(job['id'],));c.fetchone()
            c.execute("SELECT COUNT(*) processed,COALESCE(SUM(a.counts_budget AND a.state IN ('sent','done','uncertain')),0) sent,COALESCE(SUM(a.outcome='success'),0) valid_count FROM request_attempts a JOIN tasks t ON t.id=a.task_id JOIN shop_jobs j ON j.id=t.shop_job_id WHERE j.run_id=%s AND a.source_ref=%s",(job['run_id'],'execution:'+str(job['id'])))
            totals=c.fetchone()
            totals={k:base[k]+int(totals[k]) for k in ('processed','sent','valid_count')}
            c.execute('UPDATE executions SET processed=%s,sent=%s,valid_count=%s,heartbeat_at=%s WHERE id=%s AND owner=%s',
                      (totals['processed'],totals['sent'],totals['valid_count'],utcnow(),job['id'],self.owner))
        return totals

    def configure_routes(self,job):
        rows=self.store.rows('SELECT settings FROM collection_runs WHERE id=%s',(job['run_id'],))
        settings=unpack_json(rows[0]['settings']);self.route_gates={};gates={};limits={};keys={}
        for aid in unpack_json(job['account_ids']):
            rows=self.store.rows('SELECT s.* FROM accounts a JOIN account_sessions s ON s.id=a.active_session_id WHERE a.id=%s',(aid,))
            if not rows:continue
            bundle=self.store.unseal(rows[0])
            key=digest([bundle.get('proxy'),bundle.get('front_proxy')])
            rid=settings.get('route_bindings',{}).get(str(aid))
            limit=int(settings.get('per_route_concurrency',{}).get(rid,bundle.get('route_concurrency',1)))
            if not 1<=limit<=8:raise ValueError('invalid_route_concurrency')
            keys[aid]=key;limits[key]=min(limits.get(key,limit),limit)
        for key,limit in limits.items():gates[key]=threading.BoundedSemaphore(limit)
        self.route_gates={aid:gates[key] for aid,key in keys.items()}
        self.route_rejections=RouteRejections(keys)
        history=self.store.rows("SELECT a.account_id,a.http_status,a.finished_at FROM request_attempts a JOIN tasks t ON t.id=a.task_id JOIN shop_jobs j ON j.id=t.shop_job_id WHERE j.run_id=%s AND a.counts_budget=TRUE AND a.state='done' AND a.finished_at IS NOT NULL ORDER BY a.finished_at,a.id",(job['run_id'],))
        for attempt in history:
            if attempt['account_id'] in keys:
                self.route_rejections.record(attempt['account_id'],attempt['http_status'],attempt['finished_at'])

    def release_opening_selection(self,run_id):
        from farm.storage.responses import load_response
        with self.store.transaction() as c:
            c.execute('SELECT settings FROM collection_runs WHERE id=%s FOR UPDATE',(run_id,))
            row=c.fetchone();settings=unpack_json(row['settings'])
            if not settings.get('verify_open') or settings.get('phase')=='collecting':return 'collecting'
            c.execute("SELECT j.id,t.state FROM shop_jobs j LEFT JOIN tasks t ON t.shop_job_id=j.id AND t.endpoint='shopInfo' WHERE j.run_id=%s",(run_id,))
            jobs=c.fetchall()
            if not jobs or any(j['state']!='succeeded' for j in jobs):return 'pending'
            c.execute("SELECT r.shop_job_id,r.response_blob FROM task_results r JOIN shop_jobs j ON j.id=r.shop_job_id WHERE j.run_id=%s AND r.endpoint='shopInfo' AND r.valid_data=TRUE ORDER BY r.observed_at,r.id",(run_id,))
            latest={r['shop_job_id']:load_response(r['response_blob']) for r in c.fetchall()}
            if any(latest.get(j['id'],{}).get('data',{}).get('status') not in (3,'3') for j in jobs):return 'not_open'
            settings.update(phase='collecting',collection_started_at=utcnow().isoformat()+'Z')
            c.execute('UPDATE collection_runs SET settings=%s WHERE id=%s',(compact(settings),run_id))
            c.execute("UPDATE tasks t JOIN shop_jobs j ON j.id=t.shop_job_id SET t.state='pending',t.updated_at=%s WHERE j.run_id=%s AND t.state='selection_hold'",(utcnow(),run_id))
            return 'released'

    def _collect(self,job,selection):
        accounts=unpack_json(job['account_ids'])
        concurrency=min(max(1,int(selection.get('concurrency',1))),len(accounts),8)
        if not accounts:return 'waiting','no_eligible_account_or_work'
        remaining=max(0,job['max_requests']-job['processed'])
        lock=threading.Lock();halt=threading.Event();terminal=[];network_failures=[]
        health=getattr(self,'route_rejections',RouteRejections({}))
        detail_ready={};in_flight=0;unavailable=set()
        def account_ready(aid):
            with lock:return aid not in unavailable and health.ready(aid)
        def stop(state,reason):
            with lock:
                if not terminal:terminal.append((state,reason))
            halt.set()
        def active():
            if self.lease and self.lease.lost.is_set():
                stop('interrupted','executor_lock_lost');return False
            row=self.store.rows('SELECT state,owner,stop_requested FROM executions WHERE id=%s',(job['id'],))[0]
            if self.quit.is_set() or row['stop_requested'] or row['state']!='running' or row['owner']!=self.owner:
                stop('stopped','user_stop');return False
            return not halt.is_set()
        def lane(ids):
            nonlocal remaining,in_flight
            worker=Worker(self.store);worker.execution_id=job['id'];claim=None
            worker.details_ready_at=detail_ready;worker.detail_delay=float(job.get('delay_seconds',4))
            worker.route_gates=getattr(self,'route_gates',{})
            worker.account_ready=account_ready
            worker.last_account_id=ids[-1]
            empty_polls=0
            def wait_for_details(deadline):
                next_check=time.monotonic()+5
                while time.monotonic()<deadline and not halt.is_set():
                    halt.wait(min(1,max(0,deadline-time.monotonic())))
                    if self.quit.is_set() or (self.lease and self.lease.lost.is_set()) or time.monotonic()>=next_check:
                        if not active():return
                        next_check=time.monotonic()+5
            try:
                while ids and not halt.is_set() and active():
                    with lock:
                        ids=[aid for aid in ids if aid not in unavailable and health.ready(aid)]
                        if not ids:return
                        if remaining<=0:return
                        remaining-=1
                    claim=worker.claim(job['run_id'],endpoints=unpack_json(job['endpoints']),
                        environment=job['environment'],account_ids=ids,tags=selection.get('tags'))
                    if claim is None and selection.get('auto_resume'):
                        claim=worker.claim(job['run_id'],endpoints=unpack_json(job['endpoints']),
                            environment=job['environment'],account_ids=ids,tags=selection.get('tags'),allow_recovery=True)
                    if claim is None:
                        with lock:remaining+=1
                        deadlines=[due for aid,due in worker.details_ready_at.items() if aid in ids and due>time.monotonic()]
                        if deadlines:
                            wait_for_details(min(deadlines));continue
                        with lock:busy=in_flight>0
                        if busy:halt.wait(.2);continue
                        # Another lane may still be reserving its first task.
                        # Avoid silently losing concurrency at that boundary.
                        empty_polls+=1
                        if empty_polls<3:halt.wait(.2);continue
                        return
                    empty_polls=0
                    with lock:in_flight+=1
                    try:result=worker.execute(claim)
                    finally:
                        with lock:in_flight-=1
                    if result.get('sent'):
                        with lock:
                            health.record(result['account_id'],result.get('http'),utcnow())
                    if result.get('sent') and result['endpoint']=='productSpecifics':
                        worker.details_ready_at[result['account_id']]=time.monotonic()+float(job['delay_seconds'])
                    if result['outcome']=='success' and result['endpoint'] in ('productList','productRender','productSpecifics'):
                        worker.reconcile_menu_fallback(job['run_id'],claim['task']['shop_job_id'])
                    self.record_progress(job)
                    if result['outcome']=='transport_error':
                        if concurrency==1:
                            stop('waiting','transport_error');return
                        # A broken route does not stop unrelated accounts.
                        # The failed account is not retried in this execution
                        # pass; its task keeps the durable network backoff.
                        with lock:
                            failed=result['account_id'];network_failures.append(failed)
                            gate=worker.route_gates.get(failed)
                            unavailable.add(failed)
                            if gate is not None:
                                unavailable.update(aid for aid,g in worker.route_gates.items() if g is gate)
                        ids=[aid for aid in ids if aid!=result['account_id']]
                    # The next claim can use ordinary endpoints during the detail interval.
            except Exception as exc:
                log_failure('collector_error',exc,execution_id=job['id'],run_id=job.get('run_id'),
                            task_id=(claim or {}).get('task',{}).get('id'))
                stop('waiting' if transient_database_error(exc) else 'failed',
                     'database_unavailable' if transient_database_error(exc) else type(exc).__name__)
        with ThreadPoolExecutor(max_workers=concurrency,thread_name_prefix='keeta-collector') as pool:
            futures=[pool.submit(lane,accounts[i:]+accounts[:i]) for i in range(concurrency)]
            for future in futures:future.result()
        if terminal:return terminal[0]
        if remaining<=0:return 'limit','request_limit'
        if network_failures:return 'waiting','transport_error'
        if health.blocked():return 'waiting','route_http403_cooldown'
        return 'waiting','no_eligible_account_or_work'

    def execute(self, job):
        worker=Worker(self.store); state='limit'; reason='request_limit'; summary=None
        diagnostics=[]
        selection=unpack_json(job['selection'])
        try:
            selection=self.prepare_counters(job)
            worker.replay_pending(job['run_id'])
            worker.recover(job['run_id'])
            job.update(self.record_progress(job))
            worker.reconcile_closed_details(job['run_id'])
            worker.reconcile_menu_fallback(job['run_id'])
            self.configure_routes(job)
            phase=self.release_opening_selection(job['run_id'])
            if phase=='not_open':state,reason='failed','opening_verification_incomplete'
            else:
                state,reason=self._collect(job,selection)
                if state=='waiting' and reason=='no_eligible_account_or_work':
                    phase=self.release_opening_selection(job['run_id'])
                    if phase=='released':
                        job.update(self.record_progress(job));state,reason=self._collect(job,selection)
                    elif phase=='not_open':state,reason='failed','opening_verification_incomplete'
            if reason=='database_unavailable':
                self.save_outcome(job,state,reason,None)
                return
            if reason=='no_eligible_account_or_work':
                diagnostics=worker.diagnose(unpack_json(job['account_ids']),unpack_json(job['endpoints']))
            summary=export_bundle(self.store,job['run_id'],EXPORT_ROOT/f'execution-{job["id"]}')
            summary['account_diagnostics']=diagnostics
            summary['route_cooldowns']={key:until.isoformat()+'Z' for key,until in self.route_rejections.blocked().items()}
            counts=self.store.rows("SELECT COUNT(*) total,SUM(t.state='succeeded' OR (t.state='covered_by_details' AND t.endpoint='productRender') OR (t.state IN ('skipped_closed','skipped_unavailable') AND t.endpoint='productSpecifics')) done FROM tasks t JOIN shop_jobs j ON j.id=t.shop_job_id WHERE j.run_id=%s",(job['run_id'],))[0]
            if counts['total'] and counts['total']==counts['done']:
                if summary['partial_shop_jobs']==0:
                    state='complete'; reason='all_tasks_and_coverage_complete'
                else:
                    state='incomplete'; reason='unresolved_delivery_coverage'
        except Exception as exc:
            log_failure('execution_error',exc,execution_id=job['id'],run_id=job['run_id'])
            state='waiting' if transient_database_error(exc) else 'failed'
            reason='database_unavailable' if transient_database_error(exc) else type(exc).__name__
        self.save_outcome(job,state,reason,summary)

    def save_outcome(self,job,state,reason,summary):
        selection=unpack_json(job['selection'])
        failures=int(selection.get('_db_failures',0))+1 if reason=='database_unavailable' else 0
        selection['_db_failures']=failures
        retry_seconds=min(300,30*2**min(max(failures-1,0),4)) if failures else 0
        now=utcnow()
        # resume_waiting requires heartbeat < now - 60 seconds.
        heartbeat=now+timedelta(seconds=retry_seconds-60) if failures else now+timedelta(minutes=4) if reason=='transport_error' else now
        with self.store.transaction() as c:
            c.execute('UPDATE executions SET state=%s,stop_reason=%s,finished_at=%s,heartbeat_at=%s,export_summary=COALESCE(%s,export_summary),selection=%s WHERE id=%s AND owner=%s AND state=\'running\'',
                      (state,reason,None if state in ('waiting','interrupted') else now,heartbeat,compact(summary) if summary else None,compact(selection),job['id'],self.owner))
            if c.rowcount:c.execute('UPDATE collection_runs SET status=%s WHERE id=%s',(state,job['run_id']))
