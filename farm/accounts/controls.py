"""Explicit bounded recovery, using the same state and quota as collection."""
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import time
import uuid

from farm.accounts import checks as checks
from farm.storage.mysql import ENDPOINTS, business_day, utcnow, unpack_json, close_connection


@contextmanager
def database_control_lock(store, aid, sid):
    con=store.connect();names=[]
    try:
        with con.cursor() as c:
            c.execute('SELECT installation_key FROM account_sessions WHERE id=%s',(sid,))
            row=c.fetchone()
            if not row:raise checks.CheckError('no_active_session')
            for key in ('keeta:account:'+str(aid),'keeta:install:'+row['installation_key'][:45]):
                c.execute('SELECT GET_LOCK(%s,0) locked',(key,))
                if c.fetchone()['locked']!=1:raise checks.CheckError('busy')
                names.append(key)
            c.execute('SELECT active_session_id FROM accounts WHERE id=%s FOR UPDATE',(aid,))
            active=c.fetchone()
            if not active or active['active_session_id']!=sid:raise checks.CheckError('active_session_changed')
            yield c
        con.commit()
    except BaseException:
        con.rollback();raise
    finally:
        try:
            with con.cursor() as c:
                for name in reversed(names):c.execute('SELECT RELEASE_LOCK(%s)',(name,))
        finally:close_connection(con)


def clear_database_cooldown(store, aid, endpoint, *, verified=False, session_id=None, attempt_id=None):
    if session_id is None:session_id=active_session(store,aid)
    with database_control_lock(store,aid,session_id) as c:
        if verified:
            # A newer rejection must never be cleared by a late probe completion.
            c.execute('SELECT id,outcome FROM request_attempts WHERE session_id=%s AND endpoint=%s ORDER BY started_at DESC,id DESC LIMIT 1',(session_id,endpoint))
            latest=c.fetchone()
            if not latest or latest['id']!=attempt_id or latest['outcome']!='success':return False
        c.execute('SELECT state,not_before FROM capabilities WHERE session_id=%s AND endpoint=%s',(session_id,endpoint))
        old=c.fetchone()
        if not old:raise checks.CheckError('unsupported_or_missing_endpoint_schema')
        if old['state']=='needs_material':raise checks.CheckError('local_construction_error')
        # Observe only actual successes. Manual clearing records unknown, never available.
        store.observe(c,session_id,endpoint,'available' if verified else 'unknown',utcnow(),
                      200 if verified else None,None,'verified_probe' if verified else 'manual_clear')
        c.execute("SELECT experiment_name,settings FROM experiment_members WHERE account_id=%s AND endpoint=%s AND state='resting'",(aid,endpoint))
        for rest in c.fetchall():
            if unpack_json(rest['settings']).get('stop_reason')=='rejected':
                c.execute("UPDATE experiment_members SET state='ready',rest_until=NULL WHERE account_id=%s AND endpoint=%s AND experiment_name=%s",(aid,endpoint,rest['experiment_name']))
    audit=checks.ROOT/'.private/cooldown-audit';audit.mkdir(mode=0o700,parents=True,exist_ok=True)
    path=audit/(uuid.uuid4().hex+'.json')
    path.write_text(json.dumps(dict(account_id=aid,session_id=session_id,endpoint=endpoint,
        previous=old,verified=verified,at=datetime.now(timezone.utc).isoformat(),quota_preserved=True),default=str)+'\n')
    path.chmod(0o600)
    return True


def active_session(store, aid):
    rows=store.rows('SELECT active_session_id FROM accounts WHERE id=%s',(aid,))
    if not rows or not rows[0]['active_session_id']:raise checks.CheckError('no_active_session')
    return rows[0]['active_session_id']


def clear_cooldown(store, aid, endpoint):
    if endpoint not in ENDPOINTS:raise ValueError('endpoint')
    clear_database_cooldown(store,aid,endpoint,session_id=active_session(store,aid))
    return dict(account_id=aid,endpoint=endpoint,status='cooldown_cleared',state='unknown',
                source='database',quota_preserved=True,collection_started=False)


def probe_account(store, aid, endpoint, shop_job_id=None, shop_id=None):
    if endpoint not in (*ENDPOINTS,'shopFlow'):raise ValueError('endpoint')
    sid=active_session(store,aid)
    output=checks.ROOT/'exports'/('account-check-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:8])
    bundle,source=checks.load_account(store,aid)
    if shop_job_id:
        rows=store.rows('SELECT shop_id,latitude,longitude,city_id FROM shop_jobs WHERE id=%s',(int(shop_job_id),))
        if not rows:raise checks.CheckError('shop_not_found')
        shop=rows[0]
    elif endpoint in ('accountInfo','homeShopList'):
        shop={'shop_id':'0','latitude':'-23.5489841','longitude':'-46.6332165','city_id':'102302389'}
    else:shop=checks.select_shop(store,shop_id)
    if active_session(store,aid)!=sid:raise checks.CheckError('active_session_changed')
    output.mkdir(parents=True,mode=0o700)
    checker=checks.DatabaseProbe(store,aid,shop,recovery=True)
    complete=False
    try:
        if endpoint in ('shopFlow','productRender','productSpecifics'):
            results=checks.check_flow(checker.send,stop_after=endpoint)
        else:
            target=str(bundle['identity']['userid']) if endpoint=='accountInfo' else ''
            row,response=checker.send(endpoint,{},target);results=[dict(row,endpoint=endpoint)]
        complete=True
        if endpoint=='accountInfo' and row['status']=='success':
            from farm.accounts.profiles import remember_profile
            remember_profile(aid,sid,target,response)
    finally:checker.close(complete)
    result=dict(account_id=aid,source=source,results=results,sent=sum(bool(r.get('sent')) for r in results),
                verified=[r['endpoint'] for r in results if r['status']=='success'],
                cooldown_cleared=[r['endpoint'] for r in results if r.get('cooldown_cleared')],quota_preserved=True)
    target=next((r for r in results if r['endpoint']==endpoint),results[-1])
    result.update(status=target['status'],outcome=target['status'],http=target.get('http'))
    (output/'report.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    return result
