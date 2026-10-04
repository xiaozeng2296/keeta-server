"""Read local collection ledgers without uploading payloads or counting snapshots twice."""
from collections import defaultdict
from contextlib import closing
from datetime import date,datetime,time,timedelta,timezone
import json,re,sqlite3
from pathlib import Path
from zoneinfo import ZoneInfo
from Crypto.Cipher import AES
from farm.mysql_store import ROOT,ENDPOINTS

LOCAL_ROOT=ROOT/'.private'
RUN_PATTERN=re.compile(r'local[0-9]+-\d{8}T\d{6}Z')


class LedgerUnavailable(RuntimeError):pass


def run_folders():
    for folder in sorted(LOCAL_ROOT.glob('local[0-9]*-*')):
        if RUN_PATTERN.fullmatch(folder.name) and not folder.is_symlink():yield folder


def read_manifest(folder):
    if (folder/'manifest.json').is_symlink():raise LedgerUnavailable('unsafe_local_manifest')
    return json.loads((folder/'manifest.json').read_text())


def connection(folder):
    path=folder/'local.sqlite3'
    if not path.is_file() or path.is_symlink():raise LedgerUnavailable('local_ledger_missing')
    db=sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True,timeout=1)
    db.row_factory=sqlite3.Row;db.execute('PRAGMA query_only=ON')
    return closing(db)


def local_owners(exclude=None):
    owners={}
    try:
        for folder in run_folders():
            if exclude and folder.resolve()==Path(exclude).resolve():continue
            manifest=read_manifest(folder)
            sessions=manifest.get('account_session_ids',{})
            for aid,sid in sessions.items():
                # Folder timestamps describe account handoff order, not per-request usage.
                owners[(int(aid),int(sid))]=folder
    except (OSError,ValueError,TypeError) as exc:raise LedgerUnavailable('local_owner_unreadable') from exc
    return owners


def local_owner(account_id,session_id):return local_owners().get((int(account_id),int(session_id)))


def local_daily_usage(day, account_ids):
    rows,unreadable=daily_rows(day,set(account_ids))
    if unreadable:raise LedgerUnavailable('local_ledger_unreadable')
    totals=defaultdict(int)
    for row in rows:totals[(row['account_id'],row['endpoint'])]+=row['request_count']+row['reserved_count']
    return totals


def account_snapshot(folder,aid):
    with connection(folder) as db:
        row=db.execute('SELECT blob FROM accounts WHERE id=?',(int(aid),)).fetchone()
        day=db.execute("SELECT value FROM meta WHERE key='budget_day'").fetchone()
    if not row:raise LedgerUnavailable('local_account_missing')
    path=folder/'local.key'
    if path.is_symlink():raise LedgerUnavailable('unsafe_local_key')
    blob=row['blob'];cipher=AES.new(path.read_bytes(),AES.MODE_GCM,nonce=blob[:16])
    account=json.loads(cipher.decrypt_and_verify(blob[32:],blob[16:32]))
    day=json.loads(day[0]) if day else read_manifest(folder).get('snapshot_business_date')
    return account,day


def adopt_latest_accounts(accounts,day,exclude=None):
    """New batches inherit current counters, cooldowns and usage, never a stale DB copy."""
    from copy import deepcopy
    owners=local_owners(exclude)
    for account in accounts:
        owner=owners.get((account['id'],account.get('session_id')))
        if not owner:continue
        latest,old_day=account_snapshot(owner,account['id'])
        current_device=account['bundle']['device'];latest_device=latest['bundle']['device']
        for key in ('sign_sequence','signature_counter'):
            if int(current_device.get(key,0))<int(latest_device.get(key,0)):
                raise LedgerUnavailable('stale_local_signing_state')
        from farm.fullsign import continued_signing_counters
        current_counts=continued_signing_counters(current_device)
        for key,value in continued_signing_counters(latest_device).items():
            if current_counts.get(key,-1)<value:
                raise LedgerUnavailable('stale_local_signing_state')
        if str(old_day)==str(day):
            for endpoint,budget in latest['budgets'].items():
                if endpoint in account['budgets']:account['budgets'][endpoint]['used']=max(account['budgets'][endpoint]['used'],budget['used'])
        for key in ('blocked','rest_until','rest_reason','rest_endpoint','last_detail_end','endpoint_controls'):
            if key in latest:account[key]=deepcopy(latest[key])
        account['source_local_batch']=owner.name


def journal_folders():
    yield from run_folders()
    for path in sorted((LOCAL_ROOT/'account-checks').glob('*/*/local.sqlite3')):
        folder=path.parent
        if not any(p.is_symlink() for p in (folder,folder.parent,path)):yield folder


def daily_rows(day,account_ids):
    start=datetime.combine(date.fromisoformat(str(day)),time(),ZoneInfo('America/Sao_Paulo')).astimezone(timezone.utc)
    end=start+timedelta(days=1);rows=[];unreadable=[]
    for folder in journal_folders():
        try:
            with connection(folder) as db:
                records=db.execute('''SELECT account,endpoint,
                    SUM(sent=1 OR outcome='uncertain') request_count,
                    SUM(outcome='reserved') reserved_count,
                    SUM(outcome='success') valid_data_count,SUM(http=200) http_200_count,
                    SUM(http=403) http_403_count,SUM(http=429) http_429_count,
                    SUM(outcome IN ('business_error','store_closed','incomplete_payload')) business_error_count,
                    SUM(outcome='transport_error') transport_error_count,SUM(outcome='local_error') local_error_count
                    FROM attempts WHERE started>=? AND started<? GROUP BY account,endpoint''',(start.isoformat(),end.isoformat())).fetchall()
                for r in records:
                    if r['account'] not in account_ids:continue
                    d={k:int(r[k] or 0) for k in r.keys() if k not in ('account','endpoint')}
                    d.update(account_id=r['account'],endpoint=r['endpoint'],business_date=str(day),
                             origin='local_batch' if RUN_PATTERN.fullmatch(folder.name) else 'local_probe',
                             source_ref=folder.name if RUN_PATTERN.fullmatch(folder.name) else folder.parent.name+'/'+folder.name)
                    rows.append(d)
        except (OSError,ValueError,sqlite3.Error,LedgerUnavailable):unreadable.append(folder.name)
    return rows,unreadable


def overlay_dashboard(data,day):
    accounts={a['id']:a for a in data['accounts']};local,unreadable=daily_rows(day,accounts)
    totals=defaultdict(lambda:{'used':0,'reserved':0})
    for row in local:
        row['label']=accounts[row['account_id']]['label'];row['user_id']=accounts[row['account_id']].get('user_id')
        t=totals[(row['account_id'],row['endpoint'])];t['used']+=row['request_count'];t['reserved']+=row['reserved_count']
    data['daily']=list(data['daily'])+local
    owners=local_owners();states={};now=datetime.now(timezone.utc).timestamp()
    for aid,a in accounts.items():
        folder=owners.get((aid,a.get('active_session_id')))
        if not folder:continue
        try:
            state,budget_day=account_snapshot(folder,aid);manifest=read_manifest(folder)
            states[aid]=(state,budget_day)
            rid=state.get('route_id');route=(manifest.get('routes') or {}).get(rid,{})
            a['local_managed']=True;a['local_batch']=folder.name
            a['proxy_node']=route.get('label') or a.get('proxy_node') or '本地批次出口'
        except (OSError,ValueError,sqlite3.Error,LedgerUnavailable):unreadable.append(folder.name);continue
    # Requests from all local batches still count after importing a new session.
    for observation in data.get('local_observations',[]):
        a=accounts.get(observation['account_id'])
        if not a:continue
        from farm.mysql_store import when
        at=observation['observed_at']
        for key in ('last_request','last_success' if observation['outcome']=='success' else 'last_failure'):
            if not a.get(key) or when(at)>when(a[key]):a[key]=at
    for b in data['budgets']:
        t=totals[(b['account_id'],b['endpoint'])]
        b['database_used_count']=int(b['used_count']);b['local_used_count']=t['used']
        b['used_count']=int(b['used_count'])+t['used'];b['reserved_count']=int(b['reserved_count'])+t['reserved']
        if b['account_id'] in states:
            state,budget_day=states[b['account_id']]
            if str(budget_day)==str(day):
                used=state.get('budgets',{}).get(b['endpoint'],{}).get('used',0)
                b['used_count']=max(b['used_count'],used-t['reserved'])
        b['remaining_work']=max(0,int(b['work_limit'])-b['used_count']-b['reserved_count'])
        b['remaining_hard']=max(0,int(b['hard_limit'])-b['used_count']-b['reserved_count'])
    controls=[]
    for aid,(state,budget_day) in states.items():
        for ep in ENDPOINTS:
            until=state.get('blocked',{}).get(ep,0)
            control=dict(state.get('endpoint_controls',{}).get(ep,{}))
            control.update(account_id=aid,endpoint=ep,source='local',cooldown_until=datetime.fromtimestamp(until,timezone.utc).isoformat() if until>now else None,
                rest_until=datetime.fromtimestamp(state['rest_until'],timezone.utc).isoformat() if state.get('rest_until',0)>now else None,
                rest_reason=state.get('rest_reason'))
            controls.append(control)
    data['account_controls']=controls
    data['statistics_sources']={'database':True,'local':True,'unreadable':sorted(set(unreadable))}
    return data
