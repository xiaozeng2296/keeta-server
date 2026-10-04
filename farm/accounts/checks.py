"""Bounded account diagnostics using the current authoritative account state.

No credential, raw signature or server response is included in public reports.
"""
import argparse
from contextlib import contextmanager, redirect_stdout, nullcontext
from copy import deepcopy
from datetime import datetime, timezone
import fcntl
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import sys
import time
import uuid
from farm.storage.responses import load_response, save_response

import requests
from mtgsig.signer import FullSigner, compute_a2, decode_a5
from farm.accounts.selection import parse_ids
from farm.storage.mysql import Store, PATHS, compact, classify, shop_is_closed, unpack_json, utcnow
from farm.collection.worker import Worker, menu_followups
from farm.network.proxy import ProxyRoute, proxy_defaults, proxy_summary
from farm.collection.context import RequestContext

from farm.paths import ROOT
ENDPOINTS = ('shopInfo', 'productList', 'productRender', 'productSpecifics')


class CheckError(Exception):
    """A fixed diagnostic code, never an exception containing credentials."""


def load_account(store, aid):
    rows = store.rows('SELECT s.* FROM accounts a JOIN account_sessions s ON s.id=a.active_session_id WHERE a.id=%s', (aid,))
    if not rows: raise CheckError('unknown_account')
    return store.unseal(rows[0]), 'database'


def sign_check(bundle, shop):
    signer = FullSigner(bundle['device']); context = RequestContext(bundle); rows = []
    for endpoint in ENDPOINTS:
        try:
            url, headers, body = context.build(PATHS[endpoint], shop['shop_id'], shop['latitude'], shop['longitude'],
                city=shop['city_id'], spu_id=1 if endpoint=='productSpecifics' else None)
            if endpoint=='productRender':
                body=compact(dict(json.loads(body),shopCategoryList=[{'shopCategoryId':1,'spuIdList':[1]}]))
            url, headers, body = signer.prepare_request(url,headers,body)
            headers['mtgsig'] = signer.sign('POST',url,body)
            wire = requests.Request('POST',url,headers=headers,data=body.encode()).prepare()
            mt=json.loads(wire.headers['mtgsig']);a2=mt.pop('a2')
            col=json.loads(decode_a5(mt['a5'],mt['a1'],mt['a3'],mt['a4'],profile=signer.signing_profile)[0])
            valid=a2==compute_a2(wire.method,wire.url,wire.body.decode('utf-8'),compact(mt),mt['a1'],signer.signature_counter,
                                signing_profile=signer.signing_profile,sign_sequence=col['b2'])
            rows.append({'endpoint':endpoint,'signature_valid':valid,'signing_profile':signer.signing_profile,
                         'a3':mt['a3'],'render_b16_adapted':col.get('b16')!=bundle['device']['base_collect'].get('b16')})
        except Exception as exc: rows.append({'endpoint':endpoint,'signature_valid':False,'error_type':type(exc).__name__})
    return rows


def choose_menu_targets(menu):
    """Use only IDs from the fresh menu; render up to three actual products."""
    details, batches, _ = menu_followups('productList', menu, {})
    if batches:
        cat=deepcopy(batches[0]['shopCategoryList'][0]);cat['spuIdList']=cat['spuIdList'][:3]
        return {'shopCategoryList':[cat]}, details
    for cat in menu['data']['shopCategoryList']:
        ids=list(dict.fromkeys(list(cat.get('spuIdList') or [])+[p['spuId'] for p in cat.get('spuList') or [] if p.get('spuId') is not None]))
        if ids and cat.get('shopCategoryId') is not None:
            return {'shopCategoryList':[{'shopCategoryId':cat['shopCategoryId'],'spuIdList':[int(x) for x in ids[:3]]}]}, details
    return None, details


def check_flow(send, stop_after='shopFlow'):
    results=[]
    def request(endpoint,payload=None,target=''):
        row,data=send(endpoint,payload or {},target);results.append(dict(row,endpoint=endpoint));return data
    info=request('shopInfo')
    if not info:
        results.extend({'endpoint':ep,'sent':False,'status':'shop_info_not_validated'} for ep in ENDPOINTS[1:])
        return results
    menu=request('productList')
    details=[]
    if menu:
        payload,details=choose_menu_targets(menu)
        if payload:
            rendered=request('productRender',payload)
            if rendered:
                found,_,missing=menu_followups('productRender',rendered,payload)
                details=sorted(set(details+found))
                if missing: results[-1].update(status='incomplete_payload',missing_products=len(missing))
        else:results.append({'endpoint':'productRender','sent':False,'status':'no_render_target'})
    else:results.append({'endpoint':'productRender','sent':False,'status':'menu_not_validated'})
    if stop_after=='productRender':return results
    if shop_is_closed(info):status='skipped_closed'
    elif info.get('data',{}).get('status') not in (3,'3'):status='open_state_unconfirmed'
    elif not details:status='no_custom_product'
    else:
        request('productSpecifics',target=details[0]);return results
    results.append({'endpoint':'productSpecifics','sent':False,'status':status})
    return results


class DatabaseProbe:
    def __init__(self,store,aid,shop,*,recovery=False,clear_verified=True):
        self.store=store;self.aid=aid;self.shop=shop;self.worker=Worker(store);self.recovery=recovery
        self.clear_verified=clear_verified
        # Validation observes the route as configured, without rotating it mid-check.
        self.worker.try_proxy_refresh=lambda *args:False
        self.run_id=store.run('手动四接口检查','probe',['account-check',aid,uuid.uuid4().hex],{'skip_closed_details':True})
        with store.transaction() as c:
            self.job=store.shop(c,self.run_id,shop['shop_id'],shop['latitude'],shop['longitude'],shop['city_id'])

    def send(self,endpoint,payload,target):
        diagnostic=self.worker.diagnose([self.aid],[endpoint],allow_probe=True,allow_paused=True,force_probe=self.recovery)[0]
        if diagnostic['reason']!='eligible':return dict(diagnostic,sent=False,status=diagnostic['reason']),None
        if endpoint=='productSpecifics':
            recent=self.store.rows("SELECT MAX(finished_at) finished FROM request_attempts WHERE account_id=%s AND endpoint='productSpecifics' AND counts_budget=TRUE",(self.aid,))
            if recent and recent[0]['finished']:
                gap=4-(utcnow()-recent[0]['finished']).total_seconds()
                if gap>0:time.sleep(gap)
        payload=dict(payload,_bounded_account_check=True)
        with self.store.transaction() as c:
            self.store.enqueue(c,self.job,endpoint,target,payload,priority=100)
            c.execute('SELECT id FROM tasks WHERE shop_job_id=%s AND endpoint=%s AND target_id=%s ORDER BY id DESC LIMIT 1',(self.job,endpoint,target))
            tid=c.fetchone()['id'];c.execute('UPDATE tasks SET max_attempts=1 WHERE id=%s',(tid,))
        claim=self.worker.claim(self.run_id,self.aid,[endpoint],allow_probe=True,task_id=tid,allow_paused=True,force_probe=self.recovery)
        if claim is None:return {'sent':False,'status':'busy_or_not_eligible'},None
        result=self.worker.execute(claim)
        row={k:result.get(k) for k in ('sent','http','code','error_type')};row['status']=result['outcome']
        saved=self.store.rows('SELECT response_blob FROM task_results WHERE task_id=%s ORDER BY id DESC LIMIT 1',(tid,))
        data=load_response(saved[0]['response_blob']) if saved else None
        failure=self.store.failure_response(claim['attempt_id'])
        if failure:row['response_sha256']=failure.get('body_sha256')
        if self.recovery and self.clear_verified and result['outcome']=='success':
            from farm.accounts.controls import clear_database_cooldown
            row['cooldown_cleared']=clear_database_cooldown(self.store,self.aid,endpoint,verified=True,
                session_id=claim['account']['id'],attempt_id=claim['attempt_id'])
        return row,data if result['outcome']=='success' else None

    def close(self,complete):
        # Leave no automatically executable followups from a bounded diagnostic.
        with self.store.transaction() as c:
            c.execute("UPDATE tasks SET state='cancelled',last_reason='bounded_probe_finished' WHERE shop_job_id=%s AND state IN ('pending','retry_wait')",(self.job,))


def select_shop(store,shop_id=None):
    query='SELECT shop_id,latitude,longitude,city_id FROM shop_jobs'
    rows=store.rows(query+(' WHERE shop_id=%s' if shop_id else '')+' ORDER BY id DESC LIMIT 1',(shop_id,) if shop_id else ())
    if not rows:raise ValueError('shop_not_found')
    return rows[0]


def emit(value):print(json.dumps(value,ensure_ascii=False,default=str,indent=2))


def main(argv=None):
    p=argparse.ArgumentParser(description='账号签名 / 出口 / 四接口检查；输出不含凭据。')
    p.add_argument('mode',choices=('signatures','proxy','apis'))
    p.add_argument('--accounts',help='明确账号 ID，例如 97,98 或 100-105')
    p.add_argument('--all',action='store_true')
    p.add_argument('--shop-id')
    p.add_argument('--execute',action='store_true',help='实际发送验证请求；默认只预览')
    args=p.parse_args(argv);os.umask(0o077);store=Store()
    if bool(args.accounts)==bool(args.all):p.error('请选择 --accounts 或 --all，不能同时使用')
    ids=parse_ids(args.accounts) if args.accounts else [r['id'] for r in store.rows('SELECT id FROM accounts ORDER BY id')]
    shop=select_shop(store,args.shop_id) if args.mode!='proxy' else None
    report={'mode':args.mode,'shop_id':shop['shop_id'] if shop else None,'executed':args.execute if args.mode!='signatures' else False,
            'results':[],'maximum_business_requests':len(ids)*4 if args.mode=='apis' else 0}
    output=ROOT/'exports'/('account-check-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:6])
    output.mkdir(parents=True,mode=0o700);rejects=[]
    from farm.storage.files import atomic_json
    for aid in ids:
        checker=None;complete=False
        try:
            bundle,source=load_account(store,aid)
            if args.mode=='signatures':rows=sign_check(bundle,shop)
            elif args.mode=='proxy':
                route={k:bundle.get(k) for k in ('proxy','front_proxy')}
                if not route['proxy']:raise CheckError('proxy_not_configured')
                row={'route':proxy_summary(route),'sent':False,'status':'preview'}
                if args.execute:
                    started=time.monotonic()
                    with ProxyRoute(**route) as proxy,requests.Session() as session:
                        session.trust_env=False
                        reply=session.get('https://api.ip.sb/ip',proxies={'http':proxy,'https':proxy},timeout=(15,20),allow_redirects=False)
                    row.update(sent=True,http=reply.status_code,elapsed_ms=round((time.monotonic()-started)*1000),status='success' if reply.status_code==200 else 'http_error')
                    if reply.status_code==200:row['exit_ip']=str(ipaddress.ip_address(reply.text.strip()))
                rows=[dict(row,endpoint='proxy')]
            elif not args.execute:rows=[{'endpoint':e,'status':'preview','sent':False} for e in ENDPOINTS]
            else:
                checker=DatabaseProbe(store,aid,shop);rows=check_flow(checker.send)
            complete=True
            report['results'].append({'account_id':aid,'source':source,'endpoints':rows})
            for row in rows:
                if row.get('sent'):
                    if row.get('http')==403:rejects.append(aid)
                    else:rejects=[]
            if len(rejects)>=4 and len(set(rejects))>=2:report['stop_reason']='consecutive_cross_account_http403'
            if report.get('stop_reason'):break
        except Exception as exc:
            report['results'].append({'account_id':aid,'error_type':type(exc).__name__,'status':str(exc) if isinstance(exc,CheckError) else 'not_validated'})
            if checker is not None:report['stop_reason']='incomplete_probe';break
        finally:
            if checker is not None:checker.close(complete)
            atomic_json(output/'report.json',report)
    report['report_file']=str(output/'report.json');atomic_json(output/'report.json',report);emit(report)


if __name__=='__main__':
    try:main()
    except Exception as exc:
        emit({'status':str(exc) if isinstance(exc,CheckError) else 'check_failed','error_type':type(exc).__name__})
        raise SystemExit(1)
