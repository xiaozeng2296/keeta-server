"""Create a ready MySQL task batch. Responses remain local; no HTTP is sent."""
import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import uuid
from farm.accounts.maintenance import account_lock
from farm.storage.mysql import Store, ROOT, utcnow, compact
from farm.accounts.selection import parse_ids
from farm.network.proxy import normalize_route
from farm.storage.files import atomic_json

def validate_inputs(shops, ids, config, concurrency, delay):
    if not shops or len({str(s['shop_id']) for s in shops}) != len(shops):
        raise ValueError('empty_or_duplicate_shops')
    for shop in shops:
        if not str(shop['shop_id']).isdigit() or not str(shop['city_id']).isdigit():
            raise ValueError('invalid_shop_or_city')
        if not -90 <= float(shop['latitude']) <= 90 or not -180 <= float(shop['longitude']) <= 180:
            raise ValueError('invalid_location')
    if not ids or len(set(ids)) != len(ids) or type(concurrency) is not int or concurrency < 1 or delay < 0:
        raise ValueError('invalid_accounts_or_concurrency')
    routes = config['routes']; limits = config['per_route_concurrency']; bindings = config['bindings']
    if not routes or set(routes) != set(limits) or any(type(v) is not int or v < 1 for v in limits.values()):
        raise ValueError('invalid_route_limits')
    if set(bindings) != {str(aid) for aid in ids} or any(rid not in routes for rid in bindings.values()):
        raise ValueError('explicit_binding_required_for_each_account')
    for route in routes.values():
        proxy, front = normalize_route(route.get('proxy'), route.get('front_proxy'))
        if not proxy: raise ValueError('explicit_proxy_required')
        route.update(proxy=proxy, front_proxy=front)
    return config


def prepare(store, shops, ids, config, concurrency=3, delay=4, verify_open=False):
    validate_inputs(shops, ids, config, concurrency, delay)
    name='batch-'+utcnow().strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:8]
    settings=dict(scope='custom_only',storage='local_response_files',skip_closed_details=True,
                  skip_unavailable_details=True,verify_open=bool(verify_open),phase='verify_open_shops' if verify_open else 'collecting',
                  account_ids=ids,concurrency=concurrency,detail_delay=delay,
                  route_bindings=config['bindings'],per_route_concurrency=config['per_route_concurrency'])
    with ExitStack() as stack:
        sessions={}
        for aid in sorted(ids):
            rows=store.rows('SELECT a.paused,s.* FROM accounts a JOIN account_sessions s ON s.id=a.active_session_id WHERE a.id=%s',(aid,))
            if not rows:raise ValueError('account_has_no_active_session')
            row=rows[0]
            if row['paused']:raise ValueError('account_is_paused')
            stack.enter_context(account_lock(store,aid,row['id']))
            sessions[aid]=row
        # Commit metadata and explicit route bindings together, without changing
        # usage, cooldowns, credentials, or any other batch.
        with store.transaction() as c:
            key=uuid.uuid4().hex
            c.execute("INSERT INTO collection_runs(run_key,label,source_kind,status,settings,created_at) VALUES(%s,%s,'task_sheet','ready',%s,%s)",(key,name,compact(settings),utcnow()))
            run=c.lastrowid
            for aid,row in sessions.items():
                c.execute('SELECT active_session_id FROM accounts WHERE id=%s FOR UPDATE',(aid,))
                if c.fetchone()['active_session_id']!=row['id']:raise ValueError('active_session_changed')
                c.execute('SELECT * FROM account_sessions WHERE id=%s FOR UPDATE',(row['id'],))
                current=c.fetchone();bundle=store.unseal(current)
                route=config['routes'][config['bindings'][str(aid)]]
                bundle.update(proxy=route.get('proxy'),front_proxy=route.get('front_proxy'))
                key_id,blob=store.seal(bundle)
                c.execute('UPDATE account_sessions SET encryption_key_id=%s,credential_blob=%s,updated_at=%s WHERE id=%s',(key_id,blob,utcnow(),row['id']))
            for shop in shops:
                job=store.shop(c,run,shop['shop_id'],shop['latitude'],shop['longitude'],shop['city_id'])
                store.enqueue(c,job,'shopInfo',priority=100)
                store.enqueue(c,job,'productList',priority=50)
            if verify_open:
                c.execute("UPDATE tasks t JOIN shop_jobs j ON j.id=t.shop_job_id SET t.state='selection_hold' WHERE j.run_id=%s AND t.endpoint='productList'",(run,))
    folder=ROOT/'.private'/name
    record=dict(run_id=run,private=str(folder),shops=shops,account_ids=ids,concurrency=concurrency,detail_delay=delay,storage='local_response_files',state='ready')
    atomic_json(folder/'manifest.json',record)
    return dict(run_id=run,private=str(folder),account_count=len(ids),shops=len(shops),state='ready',collection_started=False)


def main():
    os.umask(0o077);p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--shops',type=Path,required=True);p.add_argument('--accounts',required=True)
    p.add_argument('--routes',type=Path,required=True);p.add_argument('--concurrency',type=int,default=3)
    p.add_argument('--detail-delay',type=float,default=4);p.add_argument('--verify-open',action='store_true')
    p.add_argument('--execute',action='store_true',help='Create ready tasks; start them explicitly in the panel')
    a=p.parse_args();value=json.loads(a.shops.read_text());shops=value['shops'] if isinstance(value,dict) else value
    ids=parse_ids(a.accounts);config=json.loads(a.routes.read_text())
    validate_inputs(shops,ids,config,a.concurrency,a.detail_delay)
    if not a.execute:print(json.dumps(dict(preview=True,shops=len(shops),accounts=ids)));return
    print(json.dumps(prepare(Store(),shops,ids,config,a.concurrency,a.detail_delay,a.verify_open)))

if __name__=='__main__':main()
