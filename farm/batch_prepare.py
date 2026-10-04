"""Prepare a local batch from explicit shops/accounts, preserving the current ledger."""
import argparse
from contextlib import ExitStack
from copy import deepcopy
from datetime import timezone
import json
import os
from pathlib import Path
import secrets

from farm.account_checks import local_lock
from farm.account_controls import reconcile_probe_budget
from farm.fingerprint_maintenance import account_lock
from farm.local_batch import ENDPOINTS, Vault, atomic_json, init_db
from farm.local_ledger import local_owner, local_daily_usage
from farm.mysql_store import Store, ROOT, business_day, utcnow
from farm.mysql_selection import parse_ids
from farm.proxy import normalize_route, proxy_summary
from mtgsig.fingerprint_refresh import CONFIG


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
    """No business requests. Pause DB workers for selected accounts before handoff."""
    validate_inputs(shops, ids, config, concurrency, delay)
    now = utcnow(); day = str(business_day(now))
    name = 'local%d-%s' % (len(shops), now.strftime('%Y%m%dT%H%M%SZ'))
    folder = ROOT/'.private'/name; output = ROOT/'exports'/name
    if folder.exists() or output.exists(): raise ValueError('batch_already_exists')
    if store.rows("SELECT id FROM executions WHERE state IN ('running','queued','waiting','interrupted')"):
        raise ValueError('database_execution_active')
    accounts = []; sources = {}; original_paused = {}; installed = set()
    with ExitStack() as stack:
        rows = {}
        for aid in sorted(ids):
            result = store.rows('SELECT a.paused,a.identity_status,s.* FROM accounts a JOIN account_sessions s ON s.id=a.active_session_id WHERE a.id=%s', (aid,))
            if not result: raise ValueError('account_has_no_active_session:%s' % aid)
            rows[aid] = result[0]
        owners = {aid: local_owner(aid, rows[aid]['id']) for aid in ids}
        masters = {p: stack.enter_context(local_lock(p)) for p in sorted(set(owners.values())-{None})}
        for aid in sorted(ids): stack.enter_context(account_lock(store, aid, rows[aid]['id']))
        usage = local_daily_usage(day, set(ids))
        for aid in ids:
            row = rows[aid]; sid = row['id']
            if row['identity_status'] not in ('verified','observed','unverified'):
                raise ValueError('account_identity_unavailable:%s' % aid)
            if row['installation_key'] in installed: raise ValueError('duplicate_installation')
            installed.add(row['installation_key']); original_paused[aid] = bool(row['paused'])
            if store.rows("SELECT id FROM request_attempts WHERE account_id=%s AND state IN ('reserved','sent')", (aid,)):
                raise ValueError('account_request_in_flight:%s' % aid)
            if owners[aid]:
                if not row['paused']: raise ValueError('local_account_not_paused_in_database')
                master = masters[owners[aid]]
                if local_owner(aid,sid) != owners[aid]: raise ValueError('local_owner_changed')
                if master.fatal and master.fatal != 'user_stop': raise ValueError('local_owner_requires_review')
                if master.meta('probe_inflight') or master.db.execute("SELECT 1 FROM attempts WHERE outcome IN ('reserved','sent') LIMIT 1").fetchone():
                    raise ValueError('unfinished_local_request')
                reconcile_probe_budget(store, master, aid)
                account = deepcopy(master.accounts[aid]); sources[aid] = str(owners[aid])
            else:
                if row['paused']: raise ValueError('account_manually_paused:%s' % aid)
                caps = store.rows('SELECT * FROM capabilities WHERE session_id=%s', (sid,))
                if any(c['state'] not in ('available','unknown') for c in caps):
                    raise ValueError('account_requires_capability_review:%s' % aid)
                if store.rows("SELECT account_id FROM experiment_members WHERE account_id=%s AND (state='stopped' OR rest_until>%s)", (aid, now)):
                    raise ValueError('account_resting:%s' % aid)
                policies = store.rows('SELECT p.*,COALESCE(u.used_count,0)+COALESCE(u.reserved_count,0) used FROM budget_policies p LEFT JOIN daily_usage u ON u.account_id=p.account_id AND u.endpoint=p.endpoint AND u.business_date=%s WHERE p.account_id=%s', (day, aid))
                budgets = {p['endpoint']:dict(used=int(p['used'])+usage.get((aid,p['endpoint']),0), limit=min(p['work_limit'],p['hard_limit'])) for p in policies}
                blocked = {c['endpoint']: c['not_before'].replace(tzinfo=timezone.utc).timestamp() for c in caps if c.get('not_before')}
                account = dict(id=aid,session_id=sid,bundle=store.unseal(row),budgets=budgets,blocked=blocked,rest_until=0)
                sources[aid] = 'database'
            if account['bundle']['device'].get(CONFIG,{}).get('enabled') is not True:
                raise ValueError('fingerprint_maintenance_not_configured:%s' % aid)
            if any(ep not in account['budgets'] for ep in ENDPOINTS): raise ValueError('missing_budget_policy')
            account['route_id'] = config['bindings'][str(aid)]
            account['initial_sign_sequence'] = account['bundle']['device'].get('sign_sequence',0)
            account['remote_account_remains_paused'] = True
            accounts.append(account)
        manifest = dict(created_at_utc=now.replace(tzinfo=timezone.utc).isoformat(),private=str(folder),output=str(output),
            source_kind='explicit_shop_list',sample_size=len(shops),shops=shops,concurrency=concurrency,
            per_route_concurrency=config['per_route_concurrency'],delay_seconds=delay,delay_scope='productSpecifics',
            routes={rid:proxy_summary(r) for rid,r in config['routes'].items()},route_bindings=config['bindings'],
            account_ids=ids,account_session_ids={str(a['id']):a['session_id'] for a in accounts},snapshot_business_date=day,
            skip_closed_details=True,skip_unavailable_details=True,scope='custom_only',storage='local_only',
            remote_database_writes=0,cost_tracking=False,traffic_metering=False,export_interval_seconds=120,
            verify_open=verify_open,phase='verify_open_shops' if verify_open else 'collecting')
        # A failed snapshot must never silently unpause an account with advanced counters.
        with store.transaction() as c:
            for account in accounts:
                c.execute('SELECT active_session_id FROM accounts WHERE id=%s FOR UPDATE',(account['id'],))
                if c.fetchone()['active_session_id'] != account['session_id']: raise ValueError('active_session_changed')
                c.execute('UPDATE accounts SET paused=TRUE WHERE id=%s',(account['id'],))
        init_db(folder,manifest,accounts,secrets.token_bytes(32))
        (folder/'routes.enc').write_bytes(Vault(folder/'local.key').seal(config['routes']))
        if verify_open:
            import sqlite3
            with sqlite3.connect(folder/'local.sqlite3') as db:
                db.execute("UPDATE tasks SET state='selection_hold' WHERE endpoint='productList'")
        atomic_json(folder/'handoff.json',dict(sources=sources,original_paused=original_paused,quota_reset=False))
        output.mkdir(parents=True,mode=0o700)
        atomic_json(output/'manifest.json',manifest)
        record = dict(private=str(folder),output=str(output),account_count=len(ids),shops=len(shops))
        atomic_json(ROOT/'.private/local100-latest.json',record)  # Existing panel/checker compatibility pointer.
        return record


def main():
    os.umask(0o077)
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--shops',type=Path,required=True); p.add_argument('--accounts',required=True)
    p.add_argument('--routes',type=Path,required=True); p.add_argument('--concurrency',type=int,default=3)
    p.add_argument('--detail-delay',type=float,default=4); p.add_argument('--verify-open',action='store_true')
    p.add_argument('--execute',action='store_true',help='Create the local ledger and pause selected DB accounts; no collection')
    a=p.parse_args(); value=json.loads(a.shops.read_text()); shops=value['shops'] if isinstance(value,dict) else value
    ids=parse_ids(a.accounts); config=json.loads(a.routes.read_text())
    validate_inputs(shops,ids,config,a.concurrency,a.detail_delay)
    if not a.execute:
        print(json.dumps(dict(preview=True,shops=len(shops),accounts=ids,concurrency=a.concurrency,verify_open=a.verify_open))); return
    print(json.dumps(prepare(Store(),shops,ids,config,a.concurrency,a.detail_delay,a.verify_open)))

if __name__=='__main__': main()
