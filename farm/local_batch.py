"""Local-only, resumable shop queue. Runtime never constructs a MySQL Store."""
import argparse
from collections import Counter, defaultdict
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import signal
import sqlite3
import sys
import threading
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import requests
from Crypto.Cipher import AES
from farm.fullsign import FullSigner, decode_a5, compute_a2
from farm.request_context import RequestContext
from farm.request_templates import validate_account_request
from farm.mysql_store import PATHS, classify, shop_is_closed
from farm.mysql_worker import menu_followups
from farm.mysql_export import (merge_menu, coverage, apply_detail_policy,
                               write_workbook, sub_items, unavailable_products)
from farm.proxy import ProxyRoute, is_ipfoxy, refresh_ipfoxy
import crawl_keeta as CK

ENDPOINTS = ('shopInfo', 'productList', 'productRender', 'productSpecifics')
PRIORITY = dict(shopInfo=100, productList=90, productRender=50, productSpecifics=20, accountInfo=100, homeShopList=100)


def compact(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(',', ':'), default=str)


def utc():
    return datetime.now(timezone.utc).isoformat()


def atomic_json(path, obj):
    path = Path(path)
    temporary = path.with_name(path.name + '.tmp')
    with open(temporary, 'w', encoding='utf-8') as stream:
        stream.write(compact(obj) + '\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


class Vault:
    def __init__(self, path):
        self.key = Path(path).read_bytes()
        if len(self.key) != 32:
            raise ValueError('invalid local key')

    def seal(self, obj):
        cipher = AES.new(self.key, AES.MODE_GCM)
        data, tag = cipher.encrypt_and_digest(compact(obj).encode())
        return cipher.nonce + tag + data

    def open(self, blob):
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=blob[:16])
        return json.loads(cipher.decrypt_and_verify(blob[32:], blob[16:32]))


def init_db(folder, manifest, accounts, key):
    folder = Path(folder)
    manifest.setdefault('skip_unavailable_details',True)
    if any(a.get('session_id') for a in accounts):
        from farm.local_ledger import adopt_latest_accounts
        adopt_latest_accounts(accounts,manifest.get('snapshot_business_date'),exclude=folder)
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    if (folder / 'local.sqlite3').exists():
        raise ValueError('batch already prepared')
    (folder / 'local.key').write_bytes(key)
    os.chmod(folder / 'local.key', 0o600)
    vault = Vault(folder / 'local.key')
    db = sqlite3.connect(folder / 'local.sqlite3')
    db.executescript('''
    PRAGMA journal_mode=WAL;
    PRAGMA synchronous=FULL;
    CREATE TABLE accounts(id INTEGER PRIMARY KEY, position INTEGER, blob BLOB NOT NULL);
    CREATE TABLE shops(id INTEGER PRIMARY KEY, data TEXT NOT NULL, closed INTEGER DEFAULT 0);
    CREATE TABLE tasks(id INTEGER PRIMARY KEY, shop INTEGER, endpoint TEXT, target TEXT,
        payload TEXT, priority INTEGER, state TEXT DEFAULT 'pending', attempts INTEGER DEFAULT 0,
        not_before REAL DEFAULT 0, reason TEXT, UNIQUE(shop,endpoint,target,payload));
    CREATE TABLE attempts(id INTEGER PRIMARY KEY, task INTEGER, account INTEGER,
        endpoint TEXT, started TEXT, finished TEXT, outcome TEXT DEFAULT 'reserved',
        http INTEGER, code TEXT, sent INTEGER DEFAULT 0, metrics TEXT DEFAULT '{}', response BLOB);
    CREATE TABLE results(task INTEGER PRIMARY KEY, shop INTEGER, endpoint TEXT, target TEXT,
        account INTEGER, observed TEXT, payload TEXT);
    CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);
    ''')
    for i, account in enumerate(accounts):
        db.execute('INSERT INTO accounts VALUES(?,?,?)', (account['id'], i, vault.seal(account)))
    for i, job in enumerate(manifest['shops'], 1):
        db.execute('INSERT INTO shops(id,data) VALUES(?,?)', (i, compact(job)))
        for ep in ('shopInfo', 'productList'):
            db.execute('INSERT INTO tasks(shop,endpoint,target,payload,priority) VALUES(?,?,?,?,?)',
                       (i, ep, '', '{}', PRIORITY[ep]))
    db.execute('INSERT INTO meta VALUES(?,?)', ('state', 'prepared'))
    db.commit()
    db.close()
    atomic_json(folder / 'manifest.json', manifest)


class LocalBatch:
    def __init__(self, folder):
        self.folder = Path(folder)
        self.manifest = json.loads((self.folder / 'manifest.json').read_text())
        self.output = Path(self.manifest['output'])
        self.output.mkdir(parents=True, exist_ok=True)
        self.vault = Vault(self.folder / 'local.key')
        self.db = sqlite3.connect(self.folder / 'local.sqlite3', check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('CREATE INDEX IF NOT EXISTS local_task_ready ON tasks(state,endpoint,not_before)')
        self.db.execute('CREATE INDEX IF NOT EXISTS local_task_prerequisite ON tasks(shop,endpoint,state)')
        self.lock = threading.RLock()
        self.stop = threading.Event()
        self.fatal = None
        self.busy = set()
        self.last_detail_end = {}
        for row in self.db.execute("SELECT account,MAX(finished) finished FROM attempts WHERE endpoint='productSpecifics' AND sent=1 AND finished IS NOT NULL GROUP BY account"):
            self.last_detail_end[row['account']] = datetime.fromisoformat(row['finished']).timestamp()
        self.accounts = {r['id']: self.vault.open(r['blob']) for r in
                         self.db.execute('SELECT * FROM accounts ORDER BY position')}
        self.account_order = list(self.accounts)
        routes_path = self.folder / 'routes.enc'
        self.routes = self.vault.open(routes_path.read_bytes()) if routes_path.exists() else {}
        if self.routes and any(a.get('route_id') not in self.routes for a in self.accounts.values()):
            raise ValueError('account route is missing')
        self.refreshing_routes = set()
        self.next_account = int(self.meta('next_account', 0))
        self.network_until = float(self.meta('network_until', 0))
        self.network_failures = int(self.meta('network_failures', 0))
        for aid, account in self.accounts.items():
            self.last_detail_end[aid] = max(self.last_detail_end.get(aid, 0), account.get('last_detail_end', 0))
        self.signers = {aid: FullSigner(a['bundle']['device']) for aid, a in self.accounts.items()}
        self.contexts = {aid: RequestContext(a['bundle']) for aid, a in self.accounts.items()}
        self.shops = {r['id']: json.loads(r['data']) for r in self.db.execute('SELECT * FROM shops')}
        self.started = time.monotonic();self.started_at=utc()
        self.start_attempt_id=self.db.execute('SELECT COALESCE(MAX(id),0) FROM attempts').fetchone()[0]
        self.waiters = {}
        self.consecutive_403 = []
        # Restore the last completed response streak; restarting cannot evade the stop.
        for row in self.db.execute('SELECT account,http FROM attempts WHERE sent=1 AND finished IS NOT NULL AND id>? ORDER BY finished DESC,id DESC',
                                   (int(self.meta('resume_after_attempt',0)),)):
            if row['http'] != 403:
                break
            self.consecutive_403.append(row['account'])
        self.check_stop()
        self.check_403_pause()

    def meta(self, key, default=None):
        # check_stop also calls this outside pick/finish. Reads must use the
        # transaction lock too: check_same_thread=False provides no such lock.
        with self.lock:
            row = self.db.execute('SELECT value FROM meta WHERE key=?', (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def set_meta(self, key, value):
        self.db.execute('INSERT OR REPLACE INTO meta VALUES(?,?)', (key, compact(value)))

    def renew_daily_budgets(self, now):
        today = datetime.fromtimestamp(now, ZoneInfo('America/Sao_Paulo')).date().isoformat()
        previous = self.meta('budget_day', self.manifest.get('snapshot_business_date', today))
        if today > previous:
            self.set_meta('budget_history:' + previous,
                          {str(aid):a['budgets'] for aid,a in self.accounts.items()})
            for account in self.accounts.values():
                for budget in account['budgets'].values():budget['used'] = 0
                self.save_account(account)
        self.set_meta('budget_day', max(today, previous))

    def route_id(self, account=None):
        return account['route_id'] if self.routes and account is not None else 'default'

    def route_config(self, account=None):
        if self.routes:
            if account is None:raise ValueError('explicit account route required')
            return self.routes[self.route_id(account)]
        path = self.folder / 'route.enc'
        if path.exists():return self.vault.open(path.read_bytes())
        return {k:self.manifest.get(k) for k in ('proxy','front_proxy','refresh_ipfoxy')}

    def route_meta_key(self, key, route_id):
        return 'route:'+route_id+':'+key if self.routes else key

    def network_wait(self, account):
        return float(self.meta(self.route_meta_key('network_until',self.route_id(account)),0)) if self.routes else self.network_until

    def route_refresh_due(self, now, account=None):
        route=self.route_config(account);rid=self.route_id(account)
        return (self.meta(self.route_meta_key('route_refresh_pending',rid),False) and route.get('refresh_ipfoxy') and
                is_ipfoxy(route.get('proxy')) and now-float(self.meta(self.route_meta_key('route_refresh_at',rid),0))>=300)

    def route_ready(self, account, now):
        rid=self.route_id(account)
        if self.meta(self.route_meta_key('health_pending',rid),False):return False
        if rid in self.refreshing_routes or self.network_wait(account)>now or self.route_refresh_due(now,account):return False
        if self.routes:
            limits=self.manifest.get('per_route_concurrency',1)
            limit=limits.get(rid,1) if isinstance(limits,dict) else limits
            return sum(self.route_id(self.accounts[aid])==rid for aid in self.busy)<int(limit)
        return True

    def check_stop(self):
        if self.meta('probe_inflight'):
            self.fatal='unfinished_probe_requires_reconciliation'
            self.stop.set()
            return
        path = self.folder / 'STOP'
        if not path.exists():
            return
        content = path.read_text().strip()
        try:
            reason = json.loads(content).get('reason', 'user_stop')
        except (ValueError, AttributeError):
            reason = 'consecutive_cross_account_http403' if content.startswith('agent_pause:') and '403' in content else 'user_stop'
        self.fatal = reason
        self.stop.set()

    def check_403_pause(self):
        if len(self.consecutive_403) >= 4 and len(set(self.consecutive_403)) >= 2:
            if not self.stop.is_set():
                self.fatal = 'consecutive_cross_account_http403'
                atomic_json(self.folder/'STOP', dict(reason=self.fatal, at=utc(),
                            consecutive_403=len(self.consecutive_403), accounts=sorted(set(self.consecutive_403))))
                self.stop.set()

    def save_account(self, account):
        self.db.execute('UPDATE accounts SET blob=? WHERE id=?',
                        (self.vault.seal(account), account['id']))

    def recover(self):
        # A signer and budget reservation is durable before sending. Unknown
        # sends remain consumed and bounded; never assume an interrupted send failed.
        with self.lock, self.db:
            for row in self.db.execute("SELECT * FROM attempts WHERE outcome IN ('reserved','sent')").fetchall():
                self.db.execute("UPDATE attempts SET outcome='uncertain',finished=? WHERE id=?", (utc(), row['id']))
                self.db.execute("UPDATE tasks SET state=CASE WHEN attempts>=3 THEN 'failed' ELSE 'retry_wait' END,not_before=?,reason='interrupted' WHERE id=?",
                                (time.time()+300, row['task']))
            self.reconcile_unavailable_details()

    def recorded_menu(self,shop):
        rows=self.db.execute("SELECT endpoint,payload FROM results WHERE shop=? AND endpoint IN ('productList','productRender') ORDER BY observed,task",(shop,)).fetchall()
        menus=[json.loads(r['payload'])['data'] for r in rows if r['endpoint']=='productList']
        return merge_menu(menus[-1] if menus else {},[json.loads(r['payload']) for r in rows if r['endpoint']=='productRender'])

    def reconcile_unavailable_details(self,shop=None):
        """Caller owns transaction/runner lock. Never rewrites sent attempts."""
        if self.manifest.get('skip_unavailable_details') is not True:return 0
        count=0
        for jid in ([shop] if shop is not None else self.shops):
            unavailable=unavailable_products(self.recorded_menu(jid))
            for row in self.db.execute("SELECT id,target FROM tasks WHERE shop=? AND state='skipped_unavailable' AND reason='product_unavailable_menu'",(jid,)).fetchall():
                if row['target'] not in unavailable:
                    self.db.execute("UPDATE tasks SET state=CASE WHEN attempts>=3 THEN 'failed' ELSE 'pending' END,reason='availability_changed',not_before=0 WHERE id=?",(row['id'],))
            for identifier in unavailable:
                count+=self.db.execute("UPDATE tasks SET state='skipped_unavailable',reason='product_unavailable_menu',not_before=0 WHERE shop=? AND endpoint='productSpecifics' AND target=? AND state IN ('pending','retry_wait','failed')",(jid,identifier)).rowcount
        return count

    def pick(self, lane):
        with self.lock:
            self.check_stop()
            if self.stop.is_set():
                return None
            now = time.time()
            with self.db:self.renew_daily_budgets(now)
            candidates = self.db.execute('''WITH ready AS (SELECT t.*,
                ROW_NUMBER() OVER (PARTITION BY endpoint ORDER BY shop,priority DESC,id) AS endpoint_order FROM tasks t
                WHERE state IN ('pending','retry_wait') AND not_before<=? AND attempts<3
                AND (endpoint='shopInfo' OR EXISTS(SELECT 1 FROM tasks i WHERE i.shop=t.shop AND i.endpoint='shopInfo' AND i.state='succeeded')))
                SELECT * FROM ready WHERE endpoint_order=1
                ORDER BY shop,priority DESC,id''', (now,)).fetchall()
            if not candidates:
                return None
            ordered = self.account_order[self.next_account:] + self.account_order[:self.next_account]
            for aid in ordered:
                account = self.accounts[aid]
                if aid in self.busy or max(account.get('rest_until', 0),account.get('fingerprint_wait_until',0))>now:
                    continue
                if not self.route_ready(account,now):continue
                for task in candidates:
                    ep = task['endpoint']
                    if ep=='productSpecifics' and now-self.last_detail_end.get(aid,0)<self.manifest['delay_seconds']:
                        continue
                    budget = account['budgets'].get(ep)
                    if not budget or budget['used']>=budget['limit']:
                        continue
                    if account['blocked'].get(ep,0)>now:
                        continue
                    self.busy.add(aid)
                    self.waiters[lane] = dict(account_id=aid, shop_id=self.shops[task['shop']]['shop_id'], endpoint=ep,route_id=self.route_id(account))
                    with self.db:
                        self.next_account = (self.account_order.index(aid) + 1) % len(self.account_order)
                        self.set_meta('next_account', self.next_account)
                        self.db.execute("UPDATE tasks SET state='leased',attempts=attempts+1 WHERE id=?", (task['id'],))
                        budget['used'] += 1
                        self.save_account(account)
                        cursor = self.db.execute('INSERT INTO attempts(task,account,endpoint,started) VALUES(?,?,?,?)',
                                                 (task['id'],aid,ep,utc()))
                    return dict(task), account, cursor.lastrowid
            return None

    def waiting(self):
        with self.lock:
            if self.busy:
                return {'reason':'requests_in_flight', 'retry_at':time.time()+1}
            tasks = self.db.execute("""SELECT t.endpoint,MIN(t.not_before) not_before FROM tasks t
                WHERE t.state IN ('pending','retry_wait') AND t.attempts<3
                AND (t.endpoint='shopInfo' OR EXISTS(SELECT 1 FROM tasks i WHERE i.shop=t.shop AND i.endpoint='shopInfo' AND i.state='succeeded'))
                GROUP BY t.endpoint""").fetchall()
            now=time.time(); choices=[]
            next_day = (datetime.fromtimestamp(now, ZoneInfo('America/Sao_Paulo')).replace(hour=0,minute=0,second=0,microsecond=0)+timedelta(days=1)).timestamp()
            for a in self.accounts.values():
                for t in tasks:
                    ep=t['endpoint'];budget=a['budgets'].get(ep,{})
                    if budget.get('limit',0)<=0:continue
                    gates={'fingerprint_refresh':a.get('fingerprint_wait_until',0),'task_retry':t['not_before'],'account_cooldown':max(a.get('rest_until',0),a['blocked'].get(ep,0)),
                           'network_backoff':max(self.network_wait(a),float(self.meta(self.route_meta_key('health_retry_at',self.route_id(a)),0)) if self.meta(self.route_meta_key('health_pending',self.route_id(a)),False) else 0),
                           'daily_budget':next_day if budget.get('used',0)>=budget['limit'] else 0,
                           'detail_interval':self.last_detail_end.get(a['id'],0)+self.manifest['delay_seconds'] if ep=='productSpecifics' else 0}
                    reason=max(gates,key=gates.get);due=max(now,gates[reason])
                    choices.append({'reason':reason if due>now else 'ready','retry_at':due})
            return min(choices,key=lambda x:x['retry_at']) if choices else None

    def pending_possible(self):
        return self.waiting() is not None

    def maybe_refresh_route(self):
        # Drain only the affected route; other exits may continue during refresh.
        representatives={self.route_id(a):a for a in self.accounts.values()}
        for rid,account in representatives.items():
            self.maybe_check_route(account)
            with self.lock:
                busy=any(self.route_id(self.accounts[aid])==rid for aid in self.busy)
                if busy or rid in self.refreshing_routes or not self.route_refresh_due(time.time(),account):continue
                route=self.route_config(account);self.refreshing_routes.add(rid)
                with self.db:
                    self.set_meta(self.route_meta_key('route_refresh_at',rid),time.time())
                    self.set_meta(self.route_meta_key('route_refresh_pending',rid),False)
                    self.set_meta(self.route_meta_key('last_route_refresh',rid),dict(at=utc(),outcome='started'))
            try:
                result=refresh_ipfoxy(route['proxy'],route.get('front_proxy'))
                with self.lock,self.db:self.set_meta(self.route_meta_key('last_route_refresh',rid),dict(at=utc(),**result))
            finally:
                with self.lock:self.refreshing_routes.discard(rid)
            # Neither an acknowledgement nor a changed IP clears account cooldowns.

    def maybe_check_route(self, account):
        rid=self.route_id(account)
        with self.lock:
            if (not self.meta(self.route_meta_key('health_pending',rid),False) or
                    time.time()<float(self.meta(self.route_meta_key('health_retry_at',rid),0)) or
                    rid in self.refreshing_routes or any(self.route_id(self.accounts[a])==rid for a in self.busy)):
                return
            self.refreshing_routes.add(rid);route=self.route_config(account)
            with self.db:self.set_meta(self.route_meta_key('health_retry_at',rid),time.time()+300)
        result={'at':utc(),'ok':False}
        try:
            # This checks transport only and contains no account/session material.
            with ProxyRoute(route.get('proxy'),route.get('front_proxy')) as proxy,requests.Session() as session:
                session.trust_env=False
                response=session.get('https://api.ipify.org?format=json',proxies={'http':proxy,'https':proxy},timeout=(12,15))
                response.raise_for_status()
                result.update(ok=True,exit_ip=str(ipaddress.ip_address(response.json()['ip'])))
        except Exception as exc:result['error_type']=type(exc).__name__
        finally:
            with self.lock,self.db:
                self.set_meta(self.route_meta_key('health_check',rid),result)
                self.set_meta(self.route_meta_key('health_pending',rid),not result['ok'])
                self.refreshing_routes.discard(rid)

    def send(self, task, account, attempt):
        ep=task['endpoint'];aid=account['id'];job=self.shops[task['shop']]
        signer=self.signers[aid];ctx=self.contexts[aid]
        started=time.perf_counter();sent=False;response=None;data={};error=None
        metrics={};network_start=None
        route_config=self.route_config(account)
        route=ProxyRoute(route_config.get('proxy'),route_config.get('front_proxy'))
        try:
            from farm.fingerprint_refresh import before_business, retry_at
            def persist_fingerprint(device):
                account['bundle']['device']=device
                with self.lock,self.db:self.save_account(account)
            try:
                before_business(signer,account['bundle'],account_id=aid,session_id=account.get('session_id'),
                    persist=persist_fingerprint,proxy=route_config.get('proxy'),front_proxy=route_config.get('front_proxy'))
            except Exception as exc:
                data={'_maintenance_retry_at':retry_at(signer.dev)}
                metrics['maintenance_error_type']=type(exc).__name__
                return data,None,'FingerprintRefreshBlocked',False,metrics
            method='POST'
            if ep=='accountInfo':
                captured=account['bundle'].get('account_check_request') or {}
                validate_account_request(captured,account['bundle']['identity'])
                url=captured['url'];headers={k.lower():v for k,v in captured['headers'].items()
                    if not k.startswith(':') and k.lower() not in ('mtgsig','content-length','accept-encoding')}
                method='GET';body=''
            elif ep=='homeShopList':
                url,headers,body=ctx.build_shop_list(json.loads(task['payload']).get('page',0))
            else:
                url,headers,body=ctx.build(PATHS[ep],job['shop_id'],job['latitude'],job['longitude'],
                                          city=job['city_id'],spu_id=int(task['target']) if ep=='productSpecifics' else None)
            if method=='POST':
                parsed=json.loads(body)
                if ep=='productRender':parsed.update(json.loads(task['payload']))
                if ep=='homeShopList' and 'bizTraceId' in json.loads(task['payload']):
                    parsed['bizTraceId']=json.loads(task['payload'])['bizTraceId']
                for k in ('actualLatitude','actualLongitude'):
                    if parsed.get('location',{}).get(k)=='':parsed['location'][k]=None
                if ep in ENDPOINTS:headers['pagesource']='10002'
                url,headers,body=signer.prepare_request(url,headers,compact(parsed))
            headers['mtgsig']=signer.sign(method,url,body)
            account['bundle']['device']=signer.persist_counter()
            request=requests.Request(method,url,headers=headers,data=body.encode()).prepare()
            # Assert a2 over the bytes actually passed to requests (no extra HTTP).
            mt=json.loads(headers['mtgsig'])
            if compute_a2(request.method,request.url,(request.body or b'').decode(),compact({k:v for k,v in mt.items() if k!='a2'}),
                          mt['a1'],signer.signature_counter,signing_profile=signer.signing_profile,
                          sign_sequence=signer.counter)!=mt['a2']:
                raise ValueError('prepared signature mismatch')
            with self.lock, self.db:
                self.save_account(account)
                self.db.execute("UPDATE attempts SET outcome='sent',sent=1 WHERE id=?",(attempt,))
            metrics['prepare_ms']=(time.perf_counter()-started)*1000
            network_start=time.perf_counter();sent=True
            with route as proxy, requests.Session() as session:
                session.trust_env=False
                response=session.send(request,proxies={'http':proxy,'https':proxy},timeout=(30,45),allow_redirects=False)
                metrics['http_ms']=(time.perf_counter()-network_start)*1000
            metrics['network_ms']=(time.perf_counter()-network_start)*1000
            try:data=response.json()
            except ValueError:data={}
            if not isinstance(data,dict):data={}
            data['_http_status']=response.status_code
        except Exception as exc:
            error=type(exc).__name__
            if network_start is not None:metrics['network_ms']=(time.perf_counter()-network_start)*1000
            if not sent:
                account['bundle']['device']=signer.persist_counter()
                with self.lock,self.db:
                    self.save_account(account)
        return data,response,error,sent,metrics

    def finish(self, task, account, attempt, data, response, error, sent, metrics):
        save_start=time.perf_counter();aid=account['id'];ep=task['endpoint'];now=time.time()
        outcome,valid=classify(ep,data,self.shops[task['shop']]['shop_id'],task['target']) if not error else ('transport_error' if sent else 'local_error',False)
        maintenance_wait=not sent and error=='FingerprintRefreshBlocked'
        if maintenance_wait:outcome='maintenance_wait'
        followups=([],[],set())
        if valid and ep in ('productList','productRender'):
            followups=menu_followups(ep,data,json.loads(task['payload']))
            if followups[2]:outcome='incomplete_payload'
        response_blob=None
        if response is not None and (not valid or outcome!='success'):
            response_blob=self.vault.seal({'status':response.status_code,'body':response.text[:131072]})
        with self.lock, self.db:
            if valid:
                self.db.execute('INSERT OR REPLACE INTO results VALUES(?,?,?,?,?,?,?)',
                                (task['id'],task['shop'],ep,task['target'],aid,utc(),compact(data)))
                for product in followups[0]:self.enqueue(task['shop'],'productSpecifics',product,{})
                for payload in followups[1]:self.enqueue(task['shop'],'productRender','',payload)
                if ep in ('productList','productRender'):self.reconcile_unavailable_details(task['shop'])
            if outcome=='store_closed' or (valid and ep=='shopInfo' and shop_is_closed(data)):
                self.db.execute('UPDATE shops SET closed=1 WHERE id=?',(task['shop'],))
            if maintenance_wait:
                state='retry_wait';due=float(data['_maintenance_retry_at'])
                account['fingerprint_wait_until']=due
                self.db.execute('UPDATE tasks SET attempts=MAX(0,attempts-1) WHERE id=?',(task['id'],))
            elif outcome=='success':state='succeeded';due=0
            elif outcome=='store_closed' and ep=='productSpecifics':state='skipped_closed';due=0
            elif (self.manifest.get('skip_unavailable_details') is True and ep=='productSpecifics'
                  and outcome=='business_error' and data.get('_http_status')==200
                  and str(data.get('code'))=='201003212'
                  and task['target'] in coverage(self.recorded_menu(task['shop']),{})['recorded_product_ids']):
                state='skipped_unavailable';due=0
            else:
                attempts=self.db.execute('SELECT attempts FROM tasks WHERE id=?',(task['id'],)).fetchone()[0]
                state='failed' if attempts>=3 or error and not sent else 'retry_wait'
                due=now+300
            if outcome=='rejected':
                account['blocked'][ep]=now+86400
                if data.get('_http_status')==401 or data.get('code')==401 or ep=='productSpecifics':
                    account['rest_until']=now+86400
                    account['rest_endpoint']=ep;account['rest_reason']='rejected'
            elif error and not sent and not maintenance_wait:account['blocked'][ep]=now+86400
            started=self.db.execute('SELECT started FROM attempts WHERE id=?',(attempt,)).fetchone()[0]
            attempt_day=datetime.fromisoformat(started).astimezone(ZoneInfo('America/Sao_Paulo')).date().isoformat()
            history=None
            if attempt_day==self.meta('budget_day',attempt_day):budget=account['budgets'][ep]
            else:
                history=self.meta('budget_history:'+attempt_day,{})
                budget=history[str(aid)][ep]
            if not sent:
                budget['used']-=1
                if history is not None:self.set_meta('budget_history:'+attempt_day,history)
            if sent and ep=='productSpecifics' and budget['used']>=budget['limit']:
                account['rest_until']=now+86400
                account['rest_endpoint']=ep;account['rest_reason']='daily_budget'
            self.save_account(account)
            reason='product_unavailable_response' if state=='skipped_unavailable' else outcome
            self.db.execute('UPDATE tasks SET state=?,not_before=?,reason=? WHERE id=?',(state,due,reason,task['id']))
            self.db.execute("UPDATE tasks SET state='skipped_closed',reason='store_closed',not_before=0 WHERE shop IN (SELECT id FROM shops WHERE closed=1) AND endpoint='productSpecifics' AND state IN ('pending','retry_wait','failed')")
            metrics['error_type']=error
            rid=self.route_id(account);metrics['route_id']=rid
            if sent:
                if data.get('_http_status') == 403:self.consecutive_403.append(aid)
                else:self.consecutive_403.clear()
                self.check_403_pause()
            network_until=self.network_wait(account)
            failures=int(self.meta(self.route_meta_key('network_failures',rid),0)) if self.routes else self.network_failures
            if outcome=='transport_error':
                failures+=1
                network_until=now+min(900,60*2**min(failures-1,4))
                self.set_meta(self.route_meta_key('route_refresh_pending',rid),True)
            elif sent and data.get('_http_status') is not None:
                failures=0
                # An older in-flight success must not cancel a newer route backoff.
            self.set_meta(self.route_meta_key('network_until',rid),network_until)
            self.set_meta(self.route_meta_key('network_failures',rid),failures)
            if not self.routes:self.network_until=network_until;self.network_failures=failures
            if sent and data.get('_http_status')==403:self.set_meta(self.route_meta_key('route_refresh_pending',rid),True)
            if ep=='productSpecifics' and sent:
                account['last_detail_end']=now;self.save_account(account)
            self.db.execute('UPDATE attempts SET finished=?,outcome=?,http=?,code=?,sent=?,metrics=?,response=? WHERE id=?',
                            (utc(),outcome,data.get('_http_status'),str(data.get('code')) if data.get('code') is not None else None,
                             int(sent),compact(metrics),response_blob,attempt))
        metrics['save_ms']=(time.perf_counter()-save_start)*1000
        event=dict(at=utc(),attempt=attempt,account_id=aid,shop_id=self.shops[task['shop']]['shop_id'],
                   endpoint=ep,target=task['target'],http=data.get('_http_status'),code=data.get('code'),outcome=outcome,
                   sent=sent,**{k:round(v,3) if isinstance(v,float) else v for k,v in metrics.items()})
        with self.lock:
            with self.db:self.db.execute('UPDATE attempts SET metrics=? WHERE id=?',(compact(metrics),attempt))
            with open(self.output/'requests.jsonl','a') as stream:stream.write(compact(event)+'\n')
            if ep=='productSpecifics' and sent:self.last_detail_end[aid]=time.time()
            self.busy.discard(aid)
            print(compact(event),flush=True)

    def enqueue(self,shop,ep,target,payload):
        self.db.execute('INSERT OR IGNORE INTO tasks(shop,endpoint,target,payload,priority) VALUES(?,?,?,?,?)',
                        (shop,ep,str(target),compact(payload),PRIORITY[ep]))

    def lane(self, lane):
        try:
            while not self.stop.is_set():
                self.check_stop()
                if self.stop.is_set():return
                claim=self.pick(lane)
                if claim is None:
                    with self.lock:self.waiters.pop(lane,None)
                    wait=self.waiting()
                    if wait is None:return
                    self.maybe_refresh_route()
                    self.stop.wait(min(5,max(.2,wait['retry_at']-time.time())));continue
                self.finish(*claim,*self.send(*claim))
        except Exception as exc:
            self.fatal=type(exc).__name__;self.stop.set()
            print(compact({'event':'local_runner_error','type':type(exc).__name__}),flush=True)

    def status(self, state='running'):
        with self.lock:
            rows=[dict(r) for r in self.db.execute('SELECT id,account,endpoint,outcome,http,sent,metrics FROM attempts')]
            session_rows=[r for r in rows if r['id']>self.start_attempt_id]
            task_counts=dict(self.db.execute('SELECT state,COUNT(*) FROM tasks GROUP BY state'))
            groups=defaultdict(Counter);times=defaultdict(list);route_counts=defaultdict(Counter)
            for r in rows:
                groups[r['account']][r['outcome']]+=1
                m=json.loads(r['metrics'])
                route_counts[m.get('route_id',self.route_id(self.accounts[r['account']]))][r['outcome']]+=1
                for k in ('prepare_ms','http_ms','network_ms','save_ms'):
                    if k in m:times[k].append(m[k])
            elapsed=time.monotonic()-self.started
            wait=self.waiting() if state=='running' and not self.busy else None
            if wait and wait['retry_at']>time.time():state='waiting'
            result={'state':state,'waiting':wait,'updated_at':utc(),'pid':os.getpid(),'shops':len(self.shops),
                    'concurrency':self.manifest['concurrency'],'delay_seconds':self.manifest['delay_seconds'],'delay_scope':'productSpecifics',
                    'requests':len(rows),'sent':sum(r['sent'] for r in rows),'success':sum(r['outcome']=='success' for r in rows),
                    'http403':sum(r['http']==403 for r in rows),'tasks':task_counts,
                    'accounts':{str(k):dict(v) for k,v in groups.items()},'active':self.waiters,
                    'routes':{k:dict(v) for k,v in route_counts.items()},
                    'elapsed_seconds':round(elapsed,2),'started_at':self.started_at,
                    'session_sent':sum(r['sent'] for r in session_rows),
                    'session_success':sum(r['outcome']=='success' for r in session_rows),
                    'session_http403':sum(r['http']==403 for r in session_rows),
                    'requests_per_minute':round(sum(r['sent'] for r in session_rows)/max(elapsed,1)*60,2),
                    'timing_ms':{k:{'mean':round(sum(v)/len(v),3),'p50':round(sorted(v)[len(v)//2],3),
                                    'p95':round(sorted(v)[min(len(v)-1,int(len(v)*.95))],3)} for k,v in times.items()},
                    'stop_reason':self.fatal,'storage':'local_only','remote_database_writes':0}
            atomic_json(self.output/'progress.json',result)
            return result

    def export(self):
        with self.lock:
            sources=[dict(r) for r in self.db.execute('SELECT * FROM results ORDER BY observed,task')]
            closed={r[0] for r in self.db.execute('SELECT id FROM shops WHERE closed=1')}
            unavailable=defaultdict(set)
            for r in self.db.execute("SELECT shop,target FROM tasks WHERE endpoint='productSpecifics' AND state='skipped_unavailable' AND reason='product_unavailable_response'"):
                unavailable[r['shop']].add(r['target'])
        grouped=defaultdict(list)
        for r in sources:
            r['response']=json.loads(r.pop('payload'));grouped[r['shop']].append(r)
        shops=[];items=[];checks=[]
        raw_dir=self.output/'raw';raw_dir.mkdir(exist_ok=True)
        for jid,job in self.shops.items():
            raw=grouped[jid];info=next((r for r in raw if r['endpoint']=='shopInfo'),None)
            menu=next((r for r in raw if r['endpoint']=='productList'),None)
            details={r['target']:r['response'] for r in raw if r['endpoint']=='productSpecifics'}
            renders=[r['response'] for r in raw if r['endpoint']=='productRender']
            if info:
                row=CK.map_shop(info['response']['data'],job['shop_id'],job['latitude'],job['longitude'])
                row.update(user_type=1,account_name=str(info['account']),create_time=info['observed'])
                shops.append(row)
            if menu:
                merged=merge_menu(menu['response']['data'],renders);check=coverage(merged,details)
                mapped=CK.map_items(merged,job['shop_id'],details=details)
                for row in mapped:
                    d=details.get(str(row['item_id']))
                    if d:row['sub_item_json']=compact(sub_items(d['data']))
                    row['create_time']=menu['observed']
                items.extend(mapped)
            else:check=dict(menu_complete=False,custom_details_complete=False,declared_products=None,
                            missing_main_ids=[],missing_detail_ids=[],nested_unresolved_ids=[])
            exempt=(set(check.get('unavailable_product_ids',[]))|unavailable[jid]
                    if self.manifest.get('skip_unavailable_details') is True else set())
            apply_detail_policy(check,jid in closed,exempt)
            check.update(shop_id=job['shop_id'],shop_info_complete=bool(info),
                         full_data_complete=bool(info and menu and check['menu_complete'] and check['custom_details_complete']),
                         complete=bool(info and menu and check['menu_complete'] and check['details_policy_complete']))
            checks.append(check)
            atomic_json(raw_dir/(job['shop_id']+'.json'),dict(shop=job,results=raw))
        result=write_workbook(self.output/'delivery.xlsx',shops,items,checks,
                             dict(source='local_sqlite',remote_database_writes=0,skip_closed_details=True,
                                  skip_unavailable_details=self.manifest.get('skip_unavailable_details') is True))
        atomic_json(self.output/'delivery-summary.json',result)
        return result

    def run(self):
        self.recover()
        with self.db:self.db.execute("UPDATE meta SET value='running' WHERE key='state'")
        self.status()
        with ThreadPoolExecutor(max_workers=self.manifest['concurrency']) as pool:
            futures=[pool.submit(self.lane,i) for i in range(self.manifest['concurrency'])]
            last_export=0;last_status=0;last_revision=-1
            while not all(f.done() for f in futures):
                time.sleep(1)
                now=time.monotonic()
                if now-last_status>=15:self.status();last_status=now
                # Large queues should not rewrite the entire workbook every 15 seconds.
                if now-last_export>=max(15,float(self.manifest.get('export_interval_seconds',120))):
                    with self.lock:revision=tuple(self.db.execute('SELECT COUNT(*),MAX(observed) FROM results').fetchone())
                    if revision!=last_revision:self.export();last_revision=revision
                    last_export=now
            for f in futures:f.result()
        delivery=self.export()
        pending=self.db.execute("SELECT COUNT(*) FROM tasks WHERE state NOT IN ('succeeded','skipped_closed','skipped_unavailable')").fetchone()[0]
        state='complete' if not pending and delivery['partial_shop_jobs']==0 else 'stopped' if self.fatal=='user_stop' else 'blocked'
        with self.db:self.db.execute('UPDATE meta SET value=? WHERE key=\'state\'',(state,))
        self.waiters={};report=self.status(state);report['delivery']=delivery
        report['collection_finished_at']=report['updated_at']
        if not self.fatal and state!='complete':report['stop_reason']='no_eligible_local_account_or_unresolved_coverage'
        atomic_json(self.output/'progress.json',report);atomic_json(self.output/'summary.json',report)
        with zipfile.ZipFile(self.output/'delivery.zip','w',zipfile.ZIP_DEFLATED) as z:
            for name in ('delivery.xlsx','delivery.coverage.json','delivery-summary.json','summary.json','manifest.json','requests.jsonl'):
                p=self.output/name
                if p.exists():z.write(p,name)
            for p in (self.output/'delivery.overflow').glob('*'):z.write(p,str(p.relative_to(self.output)))
        print(compact({'event':'finished',**report}),flush=True)
        return report


def acknowledge_resume(folder):
    """Called only under runner.lock for an explicit operator resume, never supervision."""
    folder=Path(folder);db=sqlite3.connect(folder/'local.sqlite3')
    try:
        probe=db.execute("SELECT value FROM meta WHERE key='probe_inflight'").fetchone()
        if probe and json.loads(probe[0]):raise ValueError('unfinished_probe_requires_reconciliation')
        if db.execute("SELECT 1 FROM attempts WHERE outcome IN ('reserved','sent') LIMIT 1").fetchone():
            raise ValueError('unfinished_requests_require_reconciliation')
        state=db.execute("SELECT value FROM meta WHERE key='state'").fetchone()
        if not state or state[0] not in ('blocked','stopped'):raise ValueError('batch_is_not_paused')
        cutoff=db.execute('SELECT COALESCE(MAX(id),0) FROM attempts').fetchone()[0]
        record=dict(at=utc(),resume_after_attempt=cutoff,previous_state=state[0],quota_preserved=True)
        path=folder/'STOP'
        if path.exists():
            record['previous_stop']=path.read_text()
            path.rename(folder/('STOP.before-resume-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')))
        with db:
            db.execute('INSERT OR REPLACE INTO meta VALUES(?,?)',('resume_after_attempt',compact(cutoff)))
            db.execute('INSERT OR REPLACE INTO meta VALUES(?,?)',('explicit_resume',compact(record)))
            db.execute("UPDATE meta SET value='ready' WHERE key='state'")
        atomic_json(folder/'resume-record.json',record)
        return record
    finally:db.close()


def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('folder',type=Path)
    parser.add_argument('--resume',action='store_true',help='Explicitly acknowledge a paused batch; preserve account cooldowns and quota')
    args=parser.parse_args()
    with open(args.folder/'runner.lock','a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if args.resume:acknowledge_resume(args.folder)
        runner=LocalBatch(args.folder)
        def stop(*_):runner.fatal='user_stop';runner.stop.set()
        signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
        runner.run()

if __name__=='__main__':main()
