"""Idempotent account, curl, request-ledger and task imports. No HTTP requests."""
from copy import deepcopy
import base64
import json
from pathlib import Path
import re
import shlex
from urllib.parse import urlsplit,parse_qs

from farm.mysql_store import ENDPOINTS,PATHS,LIMITS,compact,digest,utcnow
from farm.fullsign import provision_identity,continued_signing_counters
from farm.request_context import RequestContext
from mtgsig.collection_cache import CollectionCache
from farm.request_templates import assemble_templates,validate_account_request
from farm.proxy import normalize_route

ATTEMPT_SQL='''INSERT IGNORE INTO request_attempts
(id,account_id,session_id,task_id,endpoint,origin,started_at,finished_at,business_date,state,counts_budget,
 http_status,business_code,outcome,valid_data,error_type,shop_id,product_id,source_ref,signer_mode,incognia_mode)
VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)'''


def parse_curl(text):
    words=shlex.split(text.replace('\\\n',' '));headers={};body='';method=None;urls=[]
    if not words or Path(words.pop(0)).name!='curl':raise ValueError('expected one curl command')
    i=0
    while i<len(words):
        word=words[i];i+=1
        if word in ('--compressed','--http2','--http1.1','--silent','-s','--show-error','-S'):continue
        if word in ('-H','--header','-X','--request','--data','--data-raw','--data-binary','-d','--url'):
            if i>=len(words):raise ValueError('curl option missing value')
            value=words[i];i+=1
            if word in ('-H','--header'):
                if ':' not in value or '\r' in value or '\n' in value:raise ValueError('invalid header')
                k,v=value.split(':',1);k=k.lower().strip();v=v.strip()
                if k in headers and headers[k]!=v:raise ValueError('conflicting duplicate header')
                headers[k]=v
            elif word in ('-X','--request'):method=value.upper()
            elif word=='--url':urls.append(value)
            else:
                if value.startswith('@'):raise ValueError('curl local file references are not supported')
                if body:raise ValueError('multiple curl bodies are not supported')
                body=value
        elif word.startswith('https://'):urls.append(word)
        else:raise ValueError('unsupported curl option or extra command text')
    if len(urls)!=1:raise ValueError('expected exactly one HTTPS URL')
    p=urlsplit(urls[0])
    if not p.hostname or not p.hostname.endswith('.mykeeta.com') or p.username or p.password or p.fragment or p.port not in (None,443):
        raise ValueError('unsupported capture origin')
    if headers.get('host',p.netloc)!=p.netloc:raise ValueError('Host/URL mismatch')
    headers['host']=p.netloc
    cookies=dict(part.strip().split('=',1) for part in headers.get('cookie','').split(';') if '=' in part)
    if headers.get('token') and cookies.get('token') and headers['token']!=cookies['token']:raise ValueError('token/Cookie mismatch')
    token=headers.get('token') or cookies.get('token')
    if not token:raise ValueError('missing account token')
    headers.setdefault('token',token)
    q=parse_qs(p.query)
    for key in ('userid','uuid'):
        if key in q:
            if len(q[key])!=1 or (headers.get(key) and headers[key]!=q[key][0]):raise ValueError('query/header identity mismatch')
            headers.setdefault(key,q[key][0])
    for key,other in (('userid','csecuserid'),('uuid','csecuuid')):
        if headers.get(key) and headers.get(other) and headers[key]!=headers[other]:raise ValueError('security identity mismatch')
    method=method or ('POST' if body else 'GET')
    if method not in ('GET','POST'):raise ValueError('only captured read/query request templates are supported')
    if 'mtgsig' not in headers:raise ValueError('missing mtgsig sample')
    json.loads(headers['mtgsig'])
    return {'url':urls[0],'headers':headers,'body':body,'method':method}


def prepare_bundle(bundle):
    bundle=assemble_templates(bundle);dev=bundle.get('device') or {};identity=bundle.get('identity') or {}
    names=[];reasons={};status='needs_material'
    if dev and bundle.get('request') and identity.get('userid'):
        context=RequestContext(bundle)
        for endpoint,path in PATHS.items():
            if endpoint!='accountInfo' and path in bundle['templates']:
                context._prepare(path);names.append(endpoint)
        if bundle.get('account_check_request'):
            validate_account_request(bundle['account_check_request'],identity)
            names.append('accountInfo')
        try:CollectionCache(dev);dev['collection_clock_mode']='periodic'
        except (ValueError,KeyError,TypeError):dev['collection_clock_mode']=dev.get('collection_clock_mode','captured')
        dev['request_dynamic_mode']='fresh'
        # Captured-only imports retain compatibility; explicit generation must
        # survive import and still requires this installation's own state.
        dev.setdefault('incognia_mode','captured')
        if dev['incognia_mode'] not in ('generate','captured'):
            raise ValueError('unsupported incognia mode')
        if names:status='ready_generated_incognia' if dev['incognia_mode']=='generate' else 'ready_captured_incognia'
    for endpoint in ENDPOINTS:
        if endpoint not in names:
            reasons[endpoint]=('missing_signing_device' if not dev else
                               'missing_user_id' if not identity.get('userid') else
                               'missing_base_request' if not bundle.get('request') else
                               'unsupported_or_missing_endpoint_schema')
    bundle['device']=dev
    bundle['material_reasons']=reasons
    return bundle,status,sorted(set(names))


def refresh_account_material(store,account_id):
    """Upgrade the active bundle in place without clearing budgets or refusals."""
    con=store.connect();locks=[]
    try:
        with con.cursor() as c:
            c.execute('SELECT s.installation_key FROM accounts a JOIN account_sessions s ON s.id=a.active_session_id WHERE a.id=%s',(account_id,))
            row=c.fetchone()
            if not row:return {'account_id':account_id,'status':'no_active_session'}
            installation=row['installation_key']
            for key in ('keeta:account:'+str(account_id),'keeta:install:'+row['installation_key'][:45]):
                c.execute('SELECT GET_LOCK(%s,0) locked',(key,))
                if c.fetchone()['locked']!=1:return {'account_id':account_id,'status':'busy'}
                locks.append(key)
            # Discard the pre-lock snapshot before loading the latest counters.
            con.rollback()
            c.execute('SELECT s.* FROM accounts a JOIN account_sessions s ON s.id=a.active_session_id WHERE a.id=%s FOR UPDATE',(account_id,))
            row=c.fetchone()
            if not row or row['installation_key']!=installation:
                return {'account_id':account_id,'status':'busy'}
            old=store.unseal(row);bundle,status,names=prepare_bundle(old)
            old_names=set(json.loads(row['endpoint_names']))
            if bundle!=old or status!=row['material_status'] or set(names)!=old_names:
                key_id,blob=store.seal(bundle)
                c.execute('UPDATE account_sessions SET encryption_key_id=%s,credential_blob=%s,material_status=%s,endpoint_names=%s,collection_mode=%s,incognia_mode=%s,updated_at=%s WHERE id=%s',
                          (key_id,blob,status,compact(names),bundle['device'].get('collection_clock_mode','captured'),bundle['device'].get('incognia_mode','captured'),utcnow(),row['id']))
                for endpoint in names:
                    # Only a formerly absent schema becomes unknown. A local
                    # construction failure or service refusal stays observed.
                    if endpoint not in old_names:
                        c.execute("UPDATE capabilities SET state='unknown',evidence_source='assembled_schema' WHERE session_id=%s AND endpoint=%s AND state='needs_material' AND observed_at IS NULL AND not_before IS NULL",(row['id'],endpoint))
            con.commit()
            return {'account_id':account_id,'status':status,'endpoints':names,'reasons':bundle['material_reasons']}
    finally:
        con.rollback()
        with con.cursor() as c:
            for key in reversed(locks):c.execute('SELECT RELEASE_LOCK(%s)',(key,))
        con.close()


def import_bundle(store,bundle,label,source):
    identity=bundle.get('identity') or {}
    installation=identity.get('csecuuid') or identity.get('uuid')
    if not installation:
        return _import_bundle_locked(store,bundle,label,source)
    con=store.connect();lock='keeta:install:'+digest(installation)[:45]
    try:
        with con.cursor() as c:
            c.execute('SELECT GET_LOCK(%s,35) locked',(lock,))
            if c.fetchone()['locked']!=1:raise RuntimeError('installation is busy; retry import later')
        return _import_bundle_locked(store,bundle,label,source)
    finally:
        try:
            with con.cursor() as c:c.execute('SELECT RELEASE_LOCK(%s)',(lock,))
        finally:con.close()


def carry_counters(bundle,old):
    """Only resume counters when the capture proves the same app/SDK session."""
    current=bundle.get('device') or {};previous=old.get('device') or {}
    h=(bundle.get('request') or {}).get('headers') or {}
    old_h=(old.get('request') or {}).get('headers') or {}
    if (not h.get('appsession') or h.get('appsession')!=old_h.get('appsession') or
            not current.get('a1') or current.get('a1')!=previous.get('a1') or
            current.get('base_collect',{}).get('b7') is None or
            current['base_collect']['b7']!=previous.get('base_collect',{}).get('b7')):
        return
    current_counts=continued_signing_counters(current)
    previous_counts=continued_signing_counters(previous)
    for key,value in current_counts.items():
        current[key]=max(value,previous_counts.get(key,value))
    for key in ('sign_sequence','signature_counter'):
        current[key]=max(int(current.get(key,current.get('counter',0))),int(previous.get(key,previous.get('counter',0))))
    current['counter']=current['sign_sequence']


def _import_bundle_locked(store,bundle,label,source):
    bundle = dict(bundle)
    bundle['proxy'], bundle['front_proxy'] = normalize_route(
        bundle.get('proxy'), bundle.get('front_proxy'))
    raw_hash=digest(bundle);bundle,status,names=prepare_bundle(bundle)
    identity=bundle.get('identity') or {};uid=identity.get('userid');token=identity.get('token')
    if not token:raise ValueError('account token missing')
    if uid is not None and (not str(uid).isascii() or not str(uid).isdigit() or not 1 <= len(str(uid)) <= 40):
        raise ValueError('invalid decimal user ID')
    region=(bundle.get('request') or {}).get('headers',{}).get('region','BR')
    key=digest([region,'userid',str(uid)]) if uid else digest([region,'token',digest(token)])
    # Recognize token-only imports already represented by a known account.
    for row in store.rows('SELECT s.*,a.account_key FROM account_sessions s JOIN accounts a ON a.id=s.account_id'):
        existing=store.unseal(row).get('identity',{})
        if existing.get('token')==token:
            key=row['account_key'];break
    install=digest(identity.get('csecuuid') or identity.get('uuid') or ['unknown-install',key])
    for row in store.rows('SELECT * FROM account_sessions WHERE installation_key=%s',(install,)):
        carry_counters(bundle,store.unseal(row))
    key_id,sealed=store.seal(bundle);now=utcnow();source_key=digest([key,raw_hash])
    with store.transaction() as c:
        c.execute('INSERT INTO accounts(account_key,label,user_id,region,created_at,updated_at) VALUES(%s,%s,%s,%s,%s,%s) ON DUPLICATE KEY UPDATE user_id=COALESCE(user_id,VALUES(user_id)),updated_at=VALUES(updated_at)',
                  (key,label,str(uid) if uid else None,region,now,now))
        c.execute('SELECT id,active_session_id FROM accounts WHERE account_key=%s FOR UPDATE',(key,));account=c.fetchone();aid=account['id']
        c.execute("INSERT IGNORE INTO account_profiles(account_id,environment,updated_at) VALUES(%s,'test',%s)",(aid,now))
        c.execute('INSERT IGNORE INTO account_sessions(account_id,source_key,source_label,installation_key,encryption_key_id,credential_blob,material_status,incognia_mode,collection_mode,endpoint_names,created_at,updated_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',
                  (aid,source_key,source[:200],install,key_id,sealed,status,bundle['device'].get('incognia_mode','captured'),bundle['device'].get('collection_clock_mode','captured'),compact(names),now,now))
        newly_inserted = c.rowcount == 1
        c.execute('SELECT id FROM account_sessions WHERE source_key=%s',(source_key,));sid=c.fetchone()['id']
        # Reimports never replace an active newer session or reset its counters.
        if account['active_session_id'] is None:
            c.execute('UPDATE accounts SET active_session_id=%s WHERE id=%s',(sid,aid))
        elif status.startswith('ready') and newly_inserted:
            c.execute('SELECT material_status FROM account_sessions WHERE id=%s',(account['active_session_id'],))
            c.fetchone()
            c.execute("UPDATE accounts SET active_session_id=%s,identity_status='unverified' WHERE id=%s",(sid,aid))
        for endpoint in ENDPOINTS:
            c.execute('INSERT IGNORE INTO capabilities(session_id,endpoint,state) VALUES(%s,%s,%s)',(sid,endpoint,'unknown' if endpoint in names else 'needs_material'))
            work,hard=LIMITS[endpoint]
            c.execute('INSERT IGNORE INTO budget_policies(account_id,endpoint,work_limit,hard_limit) VALUES(%s,%s,%s,%s)',(aid,endpoint,work,hard))
    return aid,sid,status


def import_curl(store,path,proxy=None,front_proxy=None):
    path=Path(path)
    return import_curl_text(store,path.read_text(encoding='utf-8-sig'),path.stem,proxy,front_proxy)


def import_curl_text(store,text,label='curl',proxy=None,front_proxy=None,refresh_ipfoxy=False):
    return import_requests(store,[parse_curl(text)],label,'curl:'+digest(text.encode())[:24],proxy,front_proxy,refresh_ipfoxy)


def import_requests(store,requests,label,source,proxy=None,front_proxy=None,refresh_ipfoxy=False):
    request=requests[-1];h=request['headers'];mt=json.loads(h['mtgsig'])
    proxy,front_proxy=normalize_route(proxy,front_proxy)
    device=provision_identity({'mtgsig':mt},token=h['token'])
    ident={k:h[k] for k in ('token','userid','uuid','csecuuid','csecuserid','incog-accountid','incog-token') if k in h}
    bundle={'identity':ident,'device':device,'request':request,'templates':{},
            'proxy':proxy,'front_proxy':front_proxy,'refresh_ipfoxy':bool(refresh_ipfoxy)}
    if refresh_ipfoxy:
        from farm.proxy import is_ipfoxy
        if not is_ipfoxy(proxy):raise ValueError('IPFoxy refresh requires an IPFoxy gateway')
    # A stable login token/device can outlive an app session. Never pair a
    # newly captured signer with an earlier session's headers or templates.
    def same_runtime(candidate):
        headers=candidate.get('headers') or {}
        return (bool(h.get('appsession')) and
                all(headers.get(k)==h.get(k) for k in ('token','uuid','userid','appversion','appsession')) and
                urlsplit(candidate.get('url','')).netloc==urlsplit(request['url']).netloc)
    for row in store.rows('SELECT s.* FROM account_sessions s JOIN accounts a ON a.id=s.account_id WHERE a.user_id=%s ORDER BY s.id DESC',(ident.get('userid'),)):
        old=store.unseal(row)
        if (all(old.get('identity',{}).get(k)==ident.get(k) for k in ('token','uuid','userid')) and
                same_runtime(old.get('request') or {})):
            bundle['templates']={path:deepcopy(template) for path,template in old.get('templates',{}).items()
                                 if same_runtime(template)}
            bundle['account_check_request']=deepcopy(old.get('account_check_request'))
            break
    for captured in requests:
        ch=captured['headers'];path=urlsplit(captured['url']).path
        if ch.get('userid')!=h.get('userid'):raise ValueError('mixed accounts in capture')
        if any(ch.get(k)!=h.get(k) for k in ('token','uuid','appversion','appsession')):continue
        if urlsplit(captured['url']).netloc!=urlsplit(request['url']).netloc:continue
        if path in PATHS.values() and captured['method']=='POST':
            json.loads(captured['body']);bundle['templates'][path]=captured
        if path==PATHS['accountInfo']:bundle['account_check_request']=captured
    return import_bundle(store,bundle,label,source)


def capture_requests(document):
    """Decode v2 exports; response/login flags do not establish live validity."""
    if not isinstance(document,dict) or document.get('schema_version')!=2:
        raise ValueError('unsupported account JSON schema')
    records=document.get('requests')
    if not isinstance(records,list) or not 1<=len(records)<=1000:
        raise ValueError('capture requires 1-1000 requests')
    requests=[]
    for entry in records:
        request=entry.get('request') if isinstance(entry,dict) else None
        if not isinstance(request,dict):raise ValueError('missing captured request')
        headers=request.get('headers')
        if isinstance(headers,dict):headers=list(headers.items())
        if not isinstance(headers,list):raise ValueError('invalid captured headers')
        body=base64.b64decode(request.get('body_base64',''),validate=True).decode('utf-8')
        if body:json.loads(body)
        words=['curl','-X',request.get('method','')];signed=False
        for pair in headers:
            if not isinstance(pair,(list,tuple)) or len(pair)!=2 or not all(isinstance(x,str) for x in pair):
                raise ValueError('invalid header pair')
            key,value=pair
            if key.startswith(':'):continue
            if key.lower()=='mtgsig':signed=True
            words.extend(['-H',key+': '+value])
        if not signed:continue
        if body:words.extend(['--data-binary',body])
        words.append(request.get('url',''))
        requests.append(parse_curl(shlex.join(words)))
    if not requests:raise ValueError('no signed requests in capture')
    return requests


def import_tasks(store,path,label='店铺任务',batch_key=None):
    from farm.tasks import load_tasks
    path=Path(path);tasks=load_tasks(path,strict=True)
    source_key=digest(path.read_bytes())
    run=store.run(label,'task_sheet',[source_key,batch_key] if batch_key else source_key,{'scope':'custom_only','timezone':'America/Sao_Paulo'})
    now=utcnow();shops=[]
    for t in tasks:
        city=t.city;context=digest([t.lat,t.lng,city])
        shops.append((run,t.shop_id,t.lat,t.lng,city,t.name,context))
    with store.transaction() as c:
        c.executemany('INSERT IGNORE INTO shop_jobs(run_id,shop_id,latitude,longitude,city_id,shop_name,context_key) VALUES(%s,%s,%s,%s,%s,%s,%s)',shops)
        c.execute('SELECT id FROM shop_jobs WHERE run_id=%s',(run,));ids=[r['id'] for r in c.fetchall()];rows=[]
        for shop in ids:
            for endpoint in ('shopInfo','productList'):
                rows.append((digest([shop,endpoint,'',{}]),shop,endpoint,'{}',now,now))
        c.executemany('INSERT IGNORE INTO tasks(task_key,shop_job_id,endpoint,payload,created_at,updated_at) VALUES(%s,%s,%s,%s,%s,%s)',rows)
    return {'run_id':run,'shops':len(ids),'initial_tasks':len(rows)}


def split_curls(text):
    """Split pasted/exported commands only outside shell-quoted strings."""
    lines=text.lstrip('\ufeff').splitlines(keepends=True)
    commands=[];current=[];quote=None;escaped=False
    for line in lines:
        if quote is None and not escaped and re.match(r'^\s*curl(?:\s|$)',line) and current:
            if ''.join(current).strip(): commands.append(''.join(current).strip())
            current=[]
        current.append(line)
        for char in line:
            if escaped:
                escaped=False
                continue
            if quote=="'":
                if char=="'":quote=None
            elif char=='\\':escaped=True
            elif quote=='"':
                if char=='"':quote=None
            elif char in ("'",'"'):quote=char
    if ''.join(current).strip():commands.append(''.join(current).strip())
    return commands


def import_curls(store,texts,proxy=None,front_proxy=None,refresh_ipfoxy=False):
    """Import many accounts with per-command failures and no capture files."""
    commands=[]
    for label,text in texts:
        text=text.lstrip('\ufeff').strip()
        commands.extend([(label,text)] if text.startswith(('{','[')) else [(label,cmd) for cmd in split_curls(text)])
    if not commands or len(commands)>500:raise ValueError('一次导入需要 1–500 个 JSON / curl')
    results=[]
    for index,(label,text) in enumerate(commands,1):
        try:
            if text.startswith(('{','[')):
                document=json.loads(text)
                if isinstance(document,dict) and document.get('schema_version')==1 and isinstance(document.get('accounts'),dict):
                    results.append(dict(index=index,status='skipped_metadata',reason='account_index_without_signed_requests'));continue
                requests=capture_requests(document)
                aid,sid,status=import_requests(store,requests,label or f'json_{index}','json:'+digest(document)[:24],proxy,front_proxy,refresh_ipfoxy)
            elif refresh_ipfoxy:
                aid,sid,status=import_curl_text(store,text,label or f'curl_{index}',proxy,front_proxy,refresh_ipfoxy=True)
            else:
                aid,sid,status=import_curl_text(store,text,label or f'curl_{index}',proxy,front_proxy)
            results.append(dict(index=index,account_id=aid,session_id=sid,material_status=status))
        except Exception as exc:
            results.append(dict(index=index,error_type=type(exc).__name__))
    return results
