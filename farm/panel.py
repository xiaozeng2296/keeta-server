"""Loopback-only account and batch control panel. Run from keeta/ with -m farm.panel."""
import argparse
from contextlib import contextmanager, closing
from copy import deepcopy
from datetime import date, datetime, timedelta
import io
import json
import logging
from pathlib import Path
import re
import secrets
import tempfile
import threading
import time
import uuid
from urllib.parse import urlsplit

from flask import Flask, jsonify, render_template, request, send_file
from werkzeug.exceptions import HTTPException
import openpyxl

from farm.mysql_store import Store, ROOT, DEFAULT_CONFIG, ENDPOINTS, business_day, utcnow, unpack_json, when
from farm.mysql_selection import parse_ids, parse_tags, set_profile, select_accounts
from farm.mysql_service import ExecutionManager, EXPORT_ROOT, create_execution, stop_execution, export_bundle


from farm.mysql_import import split_curls
from farm.mysql_admin import DeletionConflict, delete_accounts, delete_runs
from farm.account_controls import probe_account, clear_cooldown
from farm.account_checks import CheckError


class StateCache:
    """Coalesce dashboard readers; never cache mutations or failed reads."""
    def __init__(self, ttl=10):
        self.ttl=ttl; self.entries={}; self.loading=set(); self.generation=0
        self.condition=threading.Condition()

    def invalidate(self):
        with self.condition:
            self.generation+=1; self.entries.clear(); self.condition.notify_all()

    def get(self, key, load):
        with self.condition:
            while True:
                entry=self.entries.get(key)
                if entry and time.monotonic()-entry[0]<self.ttl:
                    return deepcopy(entry[1])
                if key not in self.loading:
                    self.loading.add(key); generation=self.generation; break
                self.condition.wait()
        try:
            value=load()
            with self.condition:
                if generation==self.generation:
                    # Date selectors must not grow the cache indefinitely.
                    if len(self.entries)>=16:
                        oldest=min(self.entries,key=lambda k:self.entries[k][0])
                        self.entries.pop(oldest)
                    self.entries[key]=(time.monotonic(),deepcopy(value))
            return value
        finally:
            with self.condition:
                self.loading.remove(key); self.condition.notify_all()


@contextmanager
def state_reader(store):
    """Use one database connection for one dashboard snapshot."""
    if not isinstance(store,Store):
        yield store
        return
    with store.transaction() as cursor:
        class Reader:
            def rows(self, sql, args=None):
                cursor.execute(sql,args)
                return cursor.fetchall()

            def get_setting(self, name):
                rows=self.rows('SELECT encryption_key_id,credential_blob FROM encrypted_settings WHERE setting_key=%s',(name,))
                return store.unseal(rows[0]) if rows else None
        yield Reader()


LOCAL_RUN_ROOT = ROOT / '.private'
LOCAL_RUN_PATTERN = r'local[0-9]+-\d{8}T\d{6}Z'
LOCAL_DOWNLOADS = {'delivery.zip', 'delivery.xlsx', 'delivery.coverage.json', 'tasks.xlsx'}


def local_run_files(identifier):
    """Only known batch folders and public delivery files; never expose a vault."""
    if not re.fullmatch(LOCAL_RUN_PATTERN,identifier):raise ValueError('invalid local run')
    base=LOCAL_RUN_ROOT.resolve();folder=base/identifier
    if folder.is_symlink() or folder.resolve().parent!=base:raise ValueError('local run path')
    manifest=json.loads((folder/'manifest.json').read_text())
    output=Path(manifest['output'])
    if output.is_symlink() or output.resolve().parent!=EXPORT_ROOT.resolve() or output.name!=identifier:
        raise ValueError('local output path')
    return folder,output,manifest


def local_run_summary(identifier):
    folder,output,manifest=local_run_files(identifier)
    progress=json.loads((output/'progress.json').read_text())
    delivery_path=output/'delivery-summary.json'
    delivery=json.loads(delivery_path.read_text()) if delivery_path.is_file() else {}
    # Use explicit fields: manifests also contain private paths and account material references.
    return dict(id=identifier,label=f"本地随机 {len(manifest['shops'])} 店",storage='local_only',
                state=progress.get('state','unknown'),stop_reason=progress.get('stop_reason'),
                waiting={k:progress['waiting'].get(k) for k in ('reason','retry_at')} if progress.get('waiting') else None,
                shops=len(manifest['shops']),complete_shops=delivery.get('complete_shop_jobs',0),
                items=delivery.get('items',0),sent=progress.get('sent',0),success=progress.get('success',0),
                http403=progress.get('http403',0),tasks={k:progress.get('tasks',{}).get(k,0) for k in
                    ('pending','retry_wait','leased','succeeded','failed','skipped_closed','skipped_unavailable')},
                concurrency=manifest['concurrency'],delay_seconds=manifest['delay_seconds'],
                delay_scope=manifest.get('delay_scope','all'),account_ids=manifest.get('account_ids',[]),
                updated_at=progress.get('updated_at'),created_at=manifest.get('created_at_utc'),
                downloads=sorted(name for name in LOCAL_DOWNLOADS if (output/name).is_file() and not (output/name).is_symlink()))


def local_run_detail(identifier):
    summary=local_run_summary(identifier);folder,_,_=local_run_files(identifier)
    path=folder/'history.json'
    if path.is_symlink():raise ValueError('invalid history path')
    data=json.loads(path.read_text())
    return dict(summary=summary,shops=data['shops'],requests=data['requests'][-100:])


def create_app(store=None, start_worker=False):
    app=Flask(__name__)
    app.config.update(MAX_CONTENT_LENGTH=20*1024*1024,MAX_FORM_MEMORY_SIZE=20*1024*1024)
    store=store or Store(); csrf=secrets.token_urlsafe(32); state_cache=StateCache()
    app.extensions['keeta_state_cache']=state_cache

    @app.before_request
    def local_access():
        if urlsplit('http://'+request.host).hostname not in ('127.0.0.1','localhost','::1'):
            return jsonify(error='仅允许本机访问'),403
        if request.method not in ('GET','HEAD','OPTIONS'):
            origin=request.headers.get('Origin')
            if origin and origin!=request.host_url.rstrip('/'):
                return jsonify(error='来源不匹配'),403
            if not secrets.compare_digest(request.headers.get('X-Panel-CSRF',''),csrf):
                return jsonify(error='页面已过期，请刷新后重试'),403

    @app.after_request
    def headers(response):
        if request.method=='POST' and response.status_code<400:
            state_cache.invalidate()
        response.headers['Cache-Control']='no-store'
        response.headers['X-Content-Type-Options']='nosniff'
        response.headers['X-Frame-Options']='DENY'
        response.headers['Content-Security-Policy']="default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        return response

    @app.errorhandler(Exception)
    def error(exc):
        # Exceptions may contain a DSN, a captured request, or a token-bearing URL.
        if isinstance(exc,DeletionConflict):return jsonify(error=str(exc),error_type='DeletionConflict'),409
        if isinstance(exc,CheckError):return jsonify(error=str(exc),status=str(exc),sent=False),409
        if isinstance(exc,HTTPException):return jsonify(error=exc.name),exc.code
        if isinstance(exc,ValueError):return jsonify(error='输入或材料校验失败，请检查文件格式和筛选条件',error_type='ValueError'),400
        return jsonify(error='操作失败，请检查数据库连接或运行状态',error_type=type(exc).__name__),500

    @app.get('/')
    def index():
        return render_template('panel.html',csrf=csrf)

    @app.get('/api/local-runs')
    def local_runs():
        runs=[];unreadable=[]
        for folder in sorted(LOCAL_RUN_ROOT.glob('local[0-9]*-*'),reverse=True):
            if not re.fullmatch(LOCAL_RUN_PATTERN,folder.name):continue
            try:runs.append(local_run_summary(folder.name))
            except (OSError,ValueError,KeyError,TypeError):unreadable.append(folder.name)
        return jsonify(runs=runs,unreadable=unreadable)

    @app.get('/api/local-runs/<identifier>')
    def local_run(identifier):
        return jsonify(local_run_detail(identifier))

    @app.get('/downloads/local/<identifier>/<filename>')
    def local_download(identifier,filename):
        if filename not in LOCAL_DOWNLOADS:raise ValueError('unsupported local download')
        _,output,_=local_run_files(identifier)
        path=output/filename
        if path.is_symlink() or not path.is_file():return jsonify(error='交付文件尚未生成'),404
        return send_file(path,as_attachment=True,download_name=identifier+'-'+filename)

    @app.get('/api/state')
    def state():
        day=request.args.get('date',str(business_day(utcnow())))
        date.fromisoformat(day)
        scope=request.args.get('scope','all')
        if scope not in ('all','accounts','batches'):raise ValueError('unknown dashboard scope')
        return jsonify(state_cache.get((day,scope),lambda:load_state(day,scope)))

    def load_state(day,scope):
        data={}
        with state_reader(store) as reader:
            if scope in ('all','accounts'):
                accounts=reader.rows('''SELECT d.*,p.environment,a.created_at,a.updated_at,a.active_session_id,
            (SELECT GROUP_CONCAT(tag ORDER BY tag SEPARATOR ',') FROM account_tags WHERE account_id=d.id) tags,
            x.last_request,x.last_success,x.last_failure
            FROM account_dashboard d JOIN accounts a ON a.id=d.id
            LEFT JOIN account_profiles p ON p.account_id=d.id
            LEFT JOIN (SELECT account_id,MAX(started_at) last_request,
            MAX(IF(valid_data,finished_at,NULL)) last_success,
            MAX(IF(NOT valid_data,finished_at,NULL)) last_failure FROM request_attempts GROUP BY account_id) x ON x.account_id=d.id ORDER BY d.id''')
                daily=reader.rows('SELECT * FROM daily_account_requests WHERE business_date=%s ORDER BY account_id,endpoint,origin',(day,))
                budgets=reader.rows('''SELECT p.*,COALESCE(u.used_count,0) used_count,COALESCE(u.reserved_count,0) reserved_count
            FROM budget_policies p LEFT JOIN daily_usage u ON u.account_id=p.account_id AND u.endpoint=p.endpoint AND u.business_date=%s ORDER BY p.account_id,p.endpoint''',(day,))
                capabilities=reader.rows('''SELECT a.id account_id,c.endpoint,c.state,c.observed_at,c.not_before,c.http_status,c.business_code
                    FROM accounts a JOIN capabilities c ON c.session_id=a.active_session_id ORDER BY a.id,c.endpoint''')
                bindings=reader.get_setting('clash_node_bindings') or {}
                for account in accounts:account['proxy_node']=bindings.get(str(account['id']))
                data.update(accounts=accounts,daily=daily,budgets=budgets,capabilities=capabilities)
                rests=reader.rows("SELECT account_id,endpoint,state,rest_until,settings FROM experiment_members WHERE rest_until>%s OR state='stopped'",(utcnow(),))
                controls={}
                for rest in rests:
                    settings=unpack_json(rest['settings'])
                    endpoints=ENDPOINTS if settings.get('rest_scope')=='all_account_requests' else (rest['endpoint'],)
                    for endpoint in endpoints:
                        key=(rest['account_id'],endpoint)
                        previous=controls.get(key)
                        if previous and previous['rest_until'] and rest['rest_until'] and previous['rest_until']>=rest['rest_until']:continue
                        cap=next((c for c in capabilities if c['account_id']==rest['account_id'] and c['endpoint']==endpoint),{})
                        controls[key]=dict(account_id=rest['account_id'],endpoint=endpoint,rest_until=rest['rest_until'],
                                           rest_reason=settings.get('stop_reason'),cooldown_until=cap.get('not_before'))
                data['account_controls']=list(controls.values())
            if scope in ('all','batches'):
                runs=reader.rows('''SELECT r.*,COALESCE(j.shops,0) shops,COALESCE(t.total,0) total,
            COALESCE(t.succeeded,0) succeeded,COALESCE(t.skipped,0) skipped,COALESCE(t.covered,0) covered,COALESCE(t.failed,0) failed,COALESCE(t.leased,0) leased
            FROM collection_runs r
            LEFT JOIN (SELECT run_id,COUNT(*) shops FROM shop_jobs GROUP BY run_id) j ON j.run_id=r.id
            LEFT JOIN (SELECT j.run_id,COUNT(*) total,SUM(t.state='succeeded') succeeded,SUM(t.state IN ('skipped_closed','skipped_unavailable')) skipped,SUM(t.state='covered_by_details') covered,
            SUM(t.state='dead_letter') failed,SUM(t.state='leased') leased
            FROM tasks t JOIN shop_jobs j ON j.id=t.shop_job_id GROUP BY j.run_id) t ON t.run_id=r.id ORDER BY r.id DESC''')
                executions=reader.rows('SELECT * FROM executions ORDER BY id DESC LIMIT 30')
                for item in executions:
                    for k in ('selection','account_ids','endpoints','export_summary'):
                        item[k]=unpack_json(item[k]) if item[k] is not None else None
                    if item['export_summary']:
                        item['export_summary'].pop('path',None);item['export_summary'].pop('archive',None)
                data.update(runs=runs,executions=executions)
        def convert(value):
            if isinstance(value,datetime):return value.isoformat(timespec='seconds')+'Z'
            if isinstance(value,date):return value.isoformat()
            if isinstance(value,dict):return {k:convert(v) for k,v in value.items()}
            if isinstance(value,(list,tuple)):return [convert(v) for v in value]
            from decimal import Decimal
            if isinstance(value,Decimal):return int(value)
            return value
        if scope in ('all','accounts'):
            data['local_observations']=[]
            data['statistics_sources']={'database':True,'local':False,'unreadable':[]}
            for budget in data['budgets']:
                used=int(budget['used_count'])+int(budget['reserved_count'])
                budget['remaining_work']=max(0,min(budget['work_limit'],budget['hard_limit'])-used)
                budget['remaining_hard']=max(0,budget['hard_limit']-used)
            from farm.account_profiles import overlay_profiles
            overlay_profiles(data['accounts'])
        data.update(business_date=day,timezone='America/Sao_Paulo',server_time=utcnow(),scope=scope)
        return convert(data)

    @app.post('/api/accounts/profile')
    def profile():
        data=request.get_json()
        return jsonify(set_profile(store,data['ids'],data['environment'],data.get('tags'),data.get('paused')))

    @app.post('/api/accounts/select')
    def select():
        data=request.get_json()
        return jsonify(accounts=select_accounts(store,data['environment'],data.get('ids'),data.get('tags')))

    @app.post('/api/accounts/import')
    def accounts_import():
        from farm.mysql_import import import_curls
        texts=[(Path(f.filename or 'curl').stem,f.read().decode('utf-8-sig')) for f in request.files.getlist('files')]
        if request.form.get('curls','').strip():texts.append(('',request.form['curls']))
        environment=request.form.get('environment','test'); tags=parse_tags(request.form.get('tags',''))
        if environment not in ('test','production'):raise ValueError('environment')
        from farm.proxy import normalize_route,proxy_defaults,save_proxy_defaults
        use_pool=request.form.get('route_mode')=='clash_pool'
        if use_pool:
            from farm.proxy import clash_pool_summary
            if not clash_pool_summary(store)['configured']:raise ValueError('Clash 节点池尚未配置')
        defaults=proxy_defaults(store) if request.form.get('use_saved_proxy')=='true' else {}
        manual=request.form.get('proxy','').strip()
        if use_pool:proxy,front_proxy,refresh=None,None,False
        elif manual or not request.form.get('use_saved_proxy'):
            proxy,front_proxy=normalize_route(manual,request.form.get('front_proxy',''))
            refresh=request.form.get('refresh_ipfoxy')=='true'
        else:
            proxy,front_proxy=normalize_route(defaults.get('proxy'),defaults.get('front_proxy'))
            refresh=bool(defaults.get('refresh_ipfoxy'))
            if not proxy:raise ValueError('saved proxy not configured')
        if use_pool:proxy,front_proxy,refresh=None,None,False
        elif request.form.get('save_proxy_default')=='true':save_proxy_defaults(store,proxy,front_proxy,refresh)
        results=import_curls(store,texts,proxy,front_proxy,refresh_ipfoxy=refresh)
        for item in results:
            if item.get('account_id'):set_profile(store,[item['account_id']],environment,tags)
        if use_pool:
            from farm.proxy import assign_account_proxies
            imported=list(dict.fromkeys(item['account_id'] for item in results if item.get('account_id')))
            if imported:assign_account_proxies(store,imported)
        return jsonify(results=results)

    @app.get('/api/proxy-pool')
    def proxy_pool():
        from farm.proxy import clash_pool_summary
        return jsonify(clash_pool_summary(store))

    @app.get('/api/requests/failures')
    def request_failures():
        run_id=int(request.args.get('run_id','0'))
        if run_id<1:raise ValueError('run ID required')
        rows=store.rows('''SELECT r.id,r.account_id,r.endpoint,r.http_status,r.outcome,r.started_at,
            d.attempt_id IS NOT NULL has_response FROM request_attempts r
            JOIN tasks t ON t.id=r.task_id JOIN shop_jobs j ON j.id=t.shop_job_id
            LEFT JOIN request_diagnostics d ON d.attempt_id=r.id
            WHERE j.run_id=%s AND r.state='done' AND r.valid_data=FALSE
            ORDER BY r.started_at DESC LIMIT 50''',(run_id,))
        for row in rows:
            row['started_at']=row['started_at'].isoformat()+'Z'
            row['response']=store.failure_response(row['id']) if row['has_response'] else None
        return jsonify(run_id=run_id,failures=rows)

    @app.post('/api/accounts/proxy')
    def accounts_proxy():
        from farm.proxy import assign_account_proxies
        data=request.get_json() or {}
        return jsonify(accounts=assign_account_proxies(store,data.get('ids'),data.get('mode','clash_pool'),
            proxy=data.get('proxy'),front_proxy=data.get('front_proxy'),refresh=data.get('refresh_ipfoxy') in (True,'true'),
            node_name=data.get('node_name')))

    @app.get('/api/proxy-settings')
    def proxy_settings():
        from farm.proxy import proxy_defaults,proxy_summary
        return jsonify(proxy_summary(proxy_defaults(store)))

    @app.post('/api/proxy-settings')
    def proxy_settings_save():
        from farm.proxy import save_proxy_defaults
        data=request.get_json() or {}
        return jsonify(save_proxy_defaults(store,data.get('proxy'),data.get('front_proxy'),data.get('refresh_ipfoxy') is True))

    @app.post('/api/accounts/delete')
    def accounts_delete():
        return jsonify(delete_accounts(store,(request.get_json() or {}).get('ids')))

    @app.post('/api/runs/delete')
    def runs_delete():
        result=delete_runs(store,(request.get_json() or {}).get('ids'))
        # Export copies contain no authoritative queue state. Downloads for
        # deleted runs are removed after the database transaction commits.
        import shutil
        for identifier in result['deleted_execution_ids']:
            folder=EXPORT_ROOT/f'execution-{identifier}'
            if folder.is_dir() and not folder.is_symlink():shutil.rmtree(folder)
        return jsonify(result)

    @app.post('/api/tasks/import')
    def tasks_import():
        from farm.mysql_import import import_tasks
        file=request.files['file']
        with tempfile.TemporaryDirectory(prefix='keeta-tasks-') as tmp:
            path=Path(tmp)/'tasks.xlsx';file.save(path)
            result=import_tasks(store,path,request.form.get('label') or '店铺采集批次',
                                batch_key=str(uuid.uuid4()) if request.form.get('new_batch')=='true' else None)
        return jsonify(result)

    @app.get('/api/tasks/template')
    def template():
        wb=openpyxl.Workbook();ws=wb.active;ws.title='店铺任务'
        ws.append(['shop_id','shop_name','crawl_lat','crawl_lng','city_id'])
        buf=io.BytesIO();wb.save(buf);buf.seek(0)
        return send_file(buf,as_attachment=True,download_name='tasks_template.xlsx')

    @app.post('/api/budgets')
    def budgets_update():
        data=request.get_json();ids=parse_ids(data['ids']);endpoint=data['endpoint']
        work=int(data['work_limit']);hard=int(data['hard_limit'])
        if not ids or endpoint not in ENDPOINTS or not 0<=work<=hard<=1000000:raise ValueError('budget')
        with store.transaction() as c:
            for aid in ids:c.execute('UPDATE budget_policies SET work_limit=%s,hard_limit=%s WHERE account_id=%s AND endpoint=%s',(work,hard,aid,endpoint))
        return jsonify(updated=True)

    @app.post('/api/probe')
    def probe():
        data=request.get_json();endpoint=data['endpoint']
        return jsonify(probe_account(store,int(data['account_id']),endpoint,data.get('shop_job_id'),data.get('shop_id')))

    @app.post('/api/accounts/cooldown/clear')
    def cooldown_clear():
        data=request.get_json()
        return jsonify(clear_cooldown(store,int(data['account_id']),data['endpoint']))

    @app.post('/api/accounts/validate')
    def accounts_validate():
        data=request.get_json()
        selected=select_accounts(store,data.get('environment') or None,data.get('ids'),data.get('tags'))
        # Explicit identity checks only; this does not rotate accounts for work.
        if len(selected)>50:raise ValueError('validate at most 50 accounts per selection')
        results=[]
        for account in selected:
            try:result=probe_account(store,account['id'],'accountInfo')
            except CheckError as exc:
                result={'status':str(exc),'sent':False}
            except (ValueError,KeyError,TypeError) as exc:
                result={'status':'local_construction_error','sent':False,'error_type':type(exc).__name__}
            results.append(dict(result,account_id=account['id']))
            if result.get('outcome')=='transport_error':break
        return jsonify(results=results,selected_count=len(selected),
                       sent=sum(int(r.get('sent',0)) for r in results),
                       verified=sum(r.get('outcome')=='success' for r in results))

    @app.post('/api/executions')
    def executions_start():
        data=request.get_json()
        return jsonify(create_execution(store,int(data['run_id']),data['environment'],data.get('ids'),data.get('tags'),
                                         data.get('endpoints'),int(data.get('max_requests',100)),float(data.get('delay',4)),auto_resume=data.get('auto_resume') in (True,'true'),concurrency=int(data.get('concurrency',1))))

    @app.post('/api/executions/<int:identifier>/stop')
    def execution_stop(identifier):
        return jsonify(stop_execution(store,identifier))

    @app.post('/api/runs/<int:run_id>/export')
    def run_export(run_id):
        if not store.rows('SELECT id FROM collection_runs WHERE id=%s',(run_id,)):raise ValueError('run')
        export_id=str(uuid.uuid4())
        summary=export_bundle(store,run_id,EXPORT_ROOT/f'snapshot-{export_id}')
        summary.pop('path');summary.pop('archive')
        return jsonify(summary=summary,download='/downloads/snapshot-'+export_id)

    @app.get('/downloads/<identifier>')
    def download(identifier):
        if not re.fullmatch(r'(?:execution-\d+|snapshot-[0-9a-f-]{36})',identifier):raise ValueError('export')
        archive=EXPORT_ROOT/identifier/'delivery.zip'
        if identifier.startswith('execution-'):
            rows=store.rows("SELECT run_id,state FROM executions WHERE id=%s",(int(identifier.split('-')[1]),))
            if not rows:return jsonify(error='运行记录已删除'),404
            if rows[0]['state'] in ('queued','running'):return jsonify(error='运行尚未结束'),409
            if not archive.exists():export_bundle(store,rows[0]['run_id'],archive.parent)
        if not archive.exists():return jsonify(error='导出文件不存在，请重新导出'),404
        return send_file(archive,as_attachment=True,download_name=identifier+'.zip')

    if start_worker:
        manager=ExecutionManager(store);manager.start();app.extensions['keeta_executor']=manager
    return app


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,default=DEFAULT_CONFIG)
    parser.add_argument('--port',type=int,default=8787)
    parser.add_argument('--no-worker',action='store_true',help='Serve the panel using an existing database and collector')
    args=parser.parse_args();store=Store(args.config)
    if not args.no_worker:
        store.setup()
        from farm.proxy import ensure_clash_pool
        ensure_clash_pool(store)
    logging.getLogger('werkzeug').setLevel(logging.ERROR)
    app=create_app(store,start_worker=not args.no_worker)
    print(f'Keeta panel: http://127.0.0.1:{args.port}',flush=True)
    app.run(host='127.0.0.1',port=args.port,threaded=True,debug=False,use_reloader=False)


if __name__=='__main__':main()
