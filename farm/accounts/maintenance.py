"""Explicit, one-report account maintenance with authoritative-state locking.

The default is offline preflight. --send may update the selected identity but
never clears cooldowns, restarts collection, or sends business endpoint probes.
"""
import argparse
from contextlib import contextmanager
from copy import deepcopy
import json
import os
from pathlib import Path
import time

from farm.accounts.checks import load_account
from farm.accounts.fingerprint import before_business, ROOT
from mtgsig.signer import FullSigner
from farm.storage.mysql import Store, utcnow, close_connection
from mtgsig.fingerprint_refresh import CONFIG, build_report, refresh_status


@contextmanager
def account_lock(store, aid, sid):
    con=store.connect();held=[]
    try:
        with con.cursor() as c:
            c.execute('SELECT installation_key FROM account_sessions WHERE id=%s',(sid,))
            row=c.fetchone()
            if not row:raise RuntimeError('active_session_missing')
            for name in ('keeta:account:'+str(aid),'keeta:install:'+row['installation_key'][:45]):
                c.execute('SELECT GET_LOCK(%s,0) locked',(name,))
                if c.fetchone()['locked']!=1:raise RuntimeError('account_busy')
                held.append(name)
        con.commit();yield
    finally:
        try:
            with con.cursor() as c:
                for name in reversed(held):c.execute('SELECT RELEASE_LOCK(%s)',(name,))
        finally:close_connection(con)


def maintain(store, aid, *, send=False, config_path=None, enable_auto=False):
    rows=store.rows('SELECT active_session_id,paused FROM accounts WHERE id=%s',(aid,))
    if not rows:raise RuntimeError('unknown_account')
    sid=rows[0]['active_session_id']
    with account_lock(store,aid,sid):
        current=store.rows('SELECT active_session_id,paused FROM accounts WHERE id=%s',(aid,))[0]
        if current['active_session_id']!=sid:raise RuntimeError('active_session_changed')
        bundle,source=load_account(store,aid)
        original=deepcopy(bundle)
        if config_path:
            config=json.loads(Path(config_path).read_text())
            required={'sdk_version','appkey','checksum_version'}
            if not isinstance(config,dict) or not required<=config.keys():raise ValueError('invalid_checksum_configuration')
            bundle['device'][CONFIG]={k:config[k] for k in required}
        if not bundle['device'].get(CONFIG):raise ValueError('validated_checksum_configuration_required')
        enabled_before=original['device'].get(CONFIG,{}).get('enabled') is True
        bundle['device'][CONFIG]['enabled']=True
        signer=FullSigner(bundle['device'])
        build_report(bundle,signer,timestamp_ms=int(time.time()*1000))
        status=refresh_status(signer.dev,int(time.time()*1000))
        if not send:
            return {'account_id':aid,'session_id':sid,'source':source,'preflight':'ok','refresh_state':status,'sent':False}
        backup=ROOT/'.private/fingerprint-maintenance-backups';backup.mkdir(parents=True,exist_ok=True,mode=0o700)
        stamp=str(time.time_ns());path=backup/(str(aid)+'-'+stamp+'.enc')
        key,blob=store.seal(original)
        path.write_bytes(blob);path.chmod(0o600)
        # Store key ID only, not the encryption key or plaintext account material.
        meta=path.with_suffix('.json');meta.write_text(json.dumps({'account_id':aid,'session_id':sid,'encryption_key_id':key,'source':source}));meta.chmod(0o600)
        def persist(device):
            active=store.rows('SELECT active_session_id,paused FROM accounts WHERE id=%s',(aid,))[0]
            if active['active_session_id']!=sid:raise RuntimeError('active_session_changed')
            bundle['device']=deepcopy(device)
            key_id,encrypted=store.seal(bundle)
            with store.transaction() as c:
                c.execute('UPDATE account_sessions SET encryption_key_id=%s,credential_blob=%s,updated_at=%s WHERE id=%s',
                          (key_id,encrypted,utcnow(),sid))
        route=bundle
        try:
            result=before_business(signer,bundle,account_id=aid,session_id=sid,persist=persist,
                                   proxy=route.get('proxy'),front_proxy=route.get('front_proxy'))
        finally:
            signer.dev[CONFIG]['enabled']=enabled_before or enable_auto
            persist(signer.persist_counter())
        return dict(result,account_id=aid,session_id=sid,source=source,
                    auto_refresh=signer.dev[CONFIG]['enabled'],business_verified=False,
                    quota_and_cooldown_preserved=True,collection_started=False)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ids',required=True,help='Comma-separated account IDs; no implicit all-accounts selection')
    parser.add_argument('--sdk-config',type=Path,help='Validated SDK checksum configuration; no device profile sharing')
    parser.add_argument('--send',action='store_true',help='Send one report if due and persist its response')
    parser.add_argument('--enable-auto',action='store_true',help='Enable expiry maintenance for these selected accounts')
    args=parser.parse_args(argv)
    if args.enable_auto and not args.send:parser.error('--enable-auto requires --send')
    ids=list(dict.fromkeys(int(x) for x in args.ids.split(',')))
    if not ids or any(x<=0 for x in ids):parser.error('positive account IDs required')
    os.umask(0o077);store=Store();failed=False
    for aid in ids:
        try:result=maintain(store,aid,send=args.send,config_path=args.sdk_config,enable_auto=args.enable_auto)
        except Exception as exc:result={'account_id':aid,'status':'failed','error_type':type(exc).__name__};failed=True
        print(json.dumps(result,ensure_ascii=False),flush=True)
    return int(failed)


if __name__=='__main__':raise SystemExit(main())
