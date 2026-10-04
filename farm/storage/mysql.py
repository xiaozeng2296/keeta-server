"""MySQL state and private credential envelopes for the request queue."""
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import queue
import threading
import time
import traceback
from pathlib import Path
import secrets
from zoneinfo import ZoneInfo
from farm.storage.responses import load_response, save_response
from urllib.parse import parse_qsl, urlsplit

from Crypto.Cipher import AES
import pymysql

from farm.paths import ROOT
DEFAULT_CONFIG = ROOT / '.private/mysql.json'
ENDPOINTS = ('accountInfo','homeShopList','shopInfo','productList','productRender','productSpecifics')
PATHS = {'shopInfo':'/api/v1/shop/shopInfo','productList':'/api/v1/shop/productList',
         'productRender':'/api/v1/shop/product/render','productSpecifics':'/api/v1/shop/productSpecifics',
         'homeShopList':'/api/v4/homePage/homeShopList','accountInfo':'/api/user/v1/info/homepage'}
LIMITS = {'accountInfo':(5,10),'homeShopList':(20,30),'shopInfo':(85,100),
          'productList':(85,100),'productRender':(85,100),'productSpecifics':(85,100)}


def compact(x):return json.dumps(x,ensure_ascii=False,separators=(',',':'),sort_keys=False)
def digest(x):return hashlib.sha256(x if isinstance(x,bytes) else compact(x).encode()).hexdigest()
def utcnow():return datetime.now(timezone.utc).replace(tzinfo=None)
def when(x):
    if isinstance(x,datetime):d=x
    else:d=datetime.fromisoformat(x.replace('Z','+00:00'))
    return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).astimezone(timezone.utc).replace(tzinfo=None)
def business_day(d,tz='America/Sao_Paulo'):
    return d.replace(tzinfo=timezone.utc).astimezone(ZoneInfo(tz)).date()
def unpack_json(v):return json.loads(v) if isinstance(v,(str,bytes)) else v


def transient_database_error(exc):
    """Only connection/transaction failures; never credentials or SQL defects."""
    if isinstance(exc,pymysql.err.InterfaceError):return True
    return isinstance(exc,pymysql.err.OperationalError) and bool(exc.args) and exc.args[0] in (
        1040,1205,1213,2002,2003,2006,2013,2055)


def log_failure(event,exc,**context):
    # Exception messages and source lines can contain SQL, credentials or URLs.
    chain=[];seen=set();current=exc
    while current is not None and id(current) not in seen and len(chain)<4:
        seen.add(id(current))
        chain.append({'type':type(current).__name__,
                      'code':current.args[0] if current.args and type(current.args[0]) is int else None,
                      'frames':[{'file':Path(f.filename).name,'line':f.lineno,'function':f.name}
                                for f in traceback.extract_tb(current.__traceback__)[-12:]]})
        current=current.__cause__ or current.__context__
    print(compact({'event':event,'at_utc':str(utcnow()),**context,'exceptions':chain}),flush=True)


def close_connection(con):
    if con is not None and getattr(con,'open',True):
        try:con.close()
        except Exception as exc:log_failure('database_close',exc)


class Store:
    def __init__(self,config=DEFAULT_CONFIG):
        self.config_path=Path(config)
        self.config=json.loads(self.config_path.read_text())
        self.key_path=self.config_path.with_name('account_encryption.key')
        self._connections=queue.LifoQueue(maxsize=16)
        self._connection_slots=threading.BoundedSemaphore(16)
        # Claims retain named locks during HTTP and use nested transactions.
        # Keep their connections separate from the transaction pool.
        self._lock_connections=queue.LifoQueue(maxsize=16)

    def connect(self,*,database=True):
        cfg={k:v for k,v in self.config.items() if k in ('host','port','user','password','database','charset','connect_timeout','read_timeout','write_timeout')}
        for key,value in (('connect_timeout',10),('read_timeout',30),('write_timeout',30)):
            cfg.setdefault(key,value)
        if not database:cfg.pop('database',None)
        con=pymysql.connect(**cfg,autocommit=False,cursorclass=pymysql.cursors.DictCursor)
        try:
            with con.cursor() as c:c.execute("SET time_zone = '+00:00'")
        except BaseException:
            close_connection(con);raise
        return con

    def _checkout(self,pool=None):
        if pool is None:pool=getattr(self,'_connections',None)
        while pool is not None:
            try:con,idle_since=pool.get_nowait()
            except queue.Empty:break
            if not con.open or time.monotonic()-idle_since>60:
                close_connection(con);continue
            try:
                con.ping(reconnect=False)
                return con
            except Exception as exc:
                close_connection(con)
                if not transient_database_error(exc):raise
        return self.connect()

    def lock_connection(self):
        return self._checkout(self._lock_connections)

    def release_lock_connection(self,con):
        try:
            # End row locks before reusing the session. RELEASE_ALL_LOCKS also
            # removes a proxy-refresh lock if its own cleanup was interrupted.
            con.rollback()
            with con.cursor() as c:c.execute('SELECT RELEASE_ALL_LOCKS()')
        except Exception as exc:
            log_failure('account_lock_cleanup',exc)
        else:
            try:self._lock_connections.put_nowait((con,time.monotonic()));con=None
            except queue.Full:pass
        finally:close_connection(con)

    @contextmanager
    def transaction(self):
        slots=getattr(self,'_connection_slots',None)
        if slots is not None and not slots.acquire(timeout=30):
            raise pymysql.err.OperationalError(1040,'local transaction pool busy')
        con=None;healthy=False
        try:
            con=self._checkout()
            with con.cursor() as c:yield c
            con.commit()
            healthy=True
        except BaseException:
            if con is not None:
                try:con.rollback()
                except Exception as cleanup:log_failure('database_rollback',cleanup)
            raise
        finally:
            pool=getattr(self,'_connections',None)
            if healthy and pool is not None:
                try:pool.put_nowait((con,time.monotonic()));con=None
                except queue.Full:pass
            close_connection(con)
            if slots is not None:slots.release()

    def rows(self,sql,args=None):
        # Never replay writes, lock operations or a caller's transaction body.
        read_only=sql.lstrip().upper().startswith(('SELECT ','SHOW ','EXPLAIN ')) and not re.search(r'FOR\s+UPDATE|GET_LOCK|RELEASE_LOCK',sql,re.I)
        for attempt in range(3):
            try:
                with self.transaction() as c:c.execute(sql,args);return c.fetchall()
            except Exception as exc:
                if not read_only or not transient_database_error(exc) or attempt==2:raise
                log_failure('database_read_retry',exc,retry=attempt+1)
                time.sleep(.5*(2**attempt))

    def setup(self):
        database=self.config.get('database','')
        if database!='keeta' and not (self.config.get('test_database') is True and re.fullmatch(r'keeta_test_[0-9a-f]+',database)):
            raise ValueError('this migration only targets keeta or an explicit isolated test database')
        con=self.connect(database=False)
        try:
            with con.cursor() as c:c.execute(f'CREATE DATABASE IF NOT EXISTS `{database}` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci')
            con.commit()
        finally:con.close()
        with self.transaction() as c:
            for statement in (Path(__file__).with_name('schema.sql')).read_text().split(';'):
                if statement.strip():c.execute(statement)
            c.execute('INSERT IGNORE INTO schema_migrations(version,applied_at) VALUES(1,%s)',(utcnow(),))
            c.execute("INSERT IGNORE INTO account_profiles(account_id,environment,updated_at) SELECT id,'test',%s FROM accounts",(utcnow(),))
            c.execute('INSERT IGNORE INTO schema_migrations(version,applied_at) VALUES(2,%s)',(utcnow(),))
        # v3: deleting an account removes credentials while retaining collected
        # results. Existing installations require this nullable foreign key.
        with self.transaction() as c:
            c.execute("SELECT IS_NULLABLE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='task_results' AND COLUMN_NAME='account_id'")
            if c.fetchone()['IS_NULLABLE']=='NO':
                c.execute('ALTER TABLE task_results MODIFY account_id BIGINT UNSIGNED NULL')
            c.execute('INSERT IGNORE INTO schema_migrations(version,applied_at) VALUES(3,%s)',(utcnow(),))
        self.key()
        with self.transaction() as c:
            c.execute('INSERT IGNORE INTO schema_migrations(version,applied_at) VALUES(4,%s)',(utcnow(),))
            c.execute('INSERT IGNORE INTO schema_migrations(version,applied_at) VALUES(5,%s)',(utcnow(),))
            c.execute('INSERT IGNORE INTO schema_migrations(version,applied_at) VALUES(6,%s)',(utcnow(),))
            c.execute("SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='proxy_refresh_events'")
            columns={r['COLUMN_NAME'] for r in c.fetchall()}
            for name,sql_type in [('exit_before','VARCHAR(45)'),('exit_after','VARCHAR(45)'),('ip_changed','BOOLEAN')]:
                if name not in columns:c.execute('ALTER TABLE proxy_refresh_events ADD COLUMN '+name+' '+sql_type+' NULL')
            c.execute('INSERT IGNORE INTO schema_migrations(version,applied_at) VALUES(7,%s)',(utcnow(),))

    def key(self):
        if not self.key_path.exists():
            # A new key must never silently replace a lost key for existing rows.
            with self.transaction() as c:
                c.execute('SELECT COUNT(*) AS n FROM account_sessions')
                if c.fetchone()['n']:raise RuntimeError('account encryption key is missing; restore the original private key')
                c.execute('SELECT COUNT(*) AS n FROM encrypted_settings')
                if c.fetchone()['n']:raise RuntimeError('account encryption key is missing; restore the original private key')
            try:
                fd=os.open(self.key_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            except FileExistsError:pass
            else:
                with os.fdopen(fd,'wb') as f:f.write(secrets.token_bytes(32))
        raw=self.key_path.read_bytes()
        if len(raw)!=32:raise RuntimeError('invalid account encryption key')
        return raw

    def seal(self,bundle):
        key=self.key();cipher=AES.new(key,AES.MODE_GCM,nonce=secrets.token_bytes(12))
        data,tag=cipher.encrypt_and_digest(compact(bundle).encode())
        return digest(key)[:16],b'KQ1'+cipher.nonce+tag+data

    def unseal(self,row):
        key=self.key()
        if row['encryption_key_id']!=digest(key)[:16]:raise RuntimeError('wrong credential encryption key')
        raw=row['credential_blob']
        if raw[:3]!=b'KQ1':raise RuntimeError('unsupported credential envelope')
        cipher=AES.new(key,AES.MODE_GCM,nonce=raw[3:15])
        return json.loads(cipher.decrypt_and_verify(raw[31:],raw[15:31]))


    def record_failure_response(self,attempt_id,response):
        # Failed HTML/JSON is diagnostic evidence, never delivery data.
        raw=response.content
        if not isinstance(raw,bytes):return
        limit=131072;body=raw[:limit].decode(response.encoding or 'utf-8',errors='replace')
        secrets_to_remove=set();request=getattr(response,'request',None)
        for name,value in (getattr(request,'headers',{}) or {}).items():
            if re.search(r'token|cookie|authorization|mtgsig|password|secret',name,re.I) and isinstance(value,str):
                secrets_to_remove.add(value)
                if 'cookie' in name.lower():
                    secrets_to_remove.update(p.split('=',1)[1].strip() for p in value.split(';') if '=' in p)
        url=getattr(request,'url','') or ''
        if isinstance(url,str):
            secrets_to_remove.update(v for k,v in parse_qsl(urlsplit(url).query) if re.search(r'token|password|secret',k,re.I))
        for value in sorted(secrets_to_remove,key=len,reverse=True):
            if len(value)>=4:body=body.replace(value,'[redacted]')
        body=re.sub(r'("[^"\n]*(?:token|password|secret|cookie|authorization)[^"\n]*"\s*:\s*")[^"\n]*(")',r'\1[redacted]\2',body,flags=re.I)
        allowed={'content-type','server','date','via','x-cache','cf-ray','retry-after','x-request-id'}
        diagnostic={'http_status':response.status_code,'headers':{k:v for k,v in response.headers.items() if k.lower() in allowed},
                    'body':body,'body_bytes':len(raw),'body_sha256':digest(raw),'truncated':len(raw)>limit,'redacted':True}
        reference,_=save_response(diagnostic)
        key,blob=self.seal({'local_response_ref':reference.decode('ascii'),'body_sha256':diagnostic['body_sha256']})
        with self.transaction() as c:
            c.execute('INSERT INTO request_diagnostics(attempt_id,encryption_key_id,credential_blob,observed_at) VALUES(%s,%s,%s,%s) ON DUPLICATE KEY UPDATE encryption_key_id=VALUES(encryption_key_id),credential_blob=VALUES(credential_blob),observed_at=VALUES(observed_at)',(attempt_id,key,blob,utcnow()))

    def failure_response(self,attempt_id):
        rows=self.rows('SELECT encryption_key_id,credential_blob FROM request_diagnostics WHERE attempt_id=%s',(attempt_id,))
        if not rows:return None
        value=self.unseal(rows[0])
        return load_response(value['local_response_ref'].encode('ascii')) if 'local_response_ref' in value else value

    def get_setting(self, name):
        rows=self.rows('SELECT encryption_key_id,credential_blob FROM encrypted_settings WHERE setting_key=%s',(name,))
        return self.unseal(rows[0]) if rows else None

    def set_setting(self, name, value):
        key,blob=self.seal(value)
        with self.transaction() as c:
            c.execute('INSERT INTO encrypted_settings(setting_key,encryption_key_id,credential_blob,updated_at) VALUES(%s,%s,%s,%s) ON DUPLICATE KEY UPDATE encryption_key_id=VALUES(encryption_key_id),credential_blob=VALUES(credential_blob),updated_at=VALUES(updated_at)',(name,key,blob,utcnow()))

    def run(self,label,source_kind,source_key,settings=None):
        with self.transaction() as c:
            key=digest([source_kind,source_key])
            c.execute('INSERT IGNORE INTO collection_runs(run_key,label,source_kind,settings,created_at) VALUES(%s,%s,%s,%s,%s)',
                      (key,label,source_kind,compact(settings or {}),utcnow()))
            c.execute('SELECT id FROM collection_runs WHERE run_key=%s',(key,));return c.fetchone()['id']

    def shop(self,c,run_id,shop_id,lat,lng,city='102302389',name=''):
        context=digest([str(lat),str(lng),str(city)])
        c.execute('INSERT IGNORE INTO shop_jobs(run_id,shop_id,latitude,longitude,city_id,shop_name,context_key) VALUES(%s,%s,%s,%s,%s,%s,%s)',
                  (run_id,str(shop_id),str(lat),str(lng),str(city),name,context))
        c.execute('SELECT id FROM shop_jobs WHERE run_id=%s AND shop_id=%s AND context_key=%s',(run_id,str(shop_id),context))
        return c.fetchone()['id']

    def enqueue(self,c,shop_job_id,endpoint,target='',payload=None,priority=0):
        value=payload or {};key=digest([shop_job_id,endpoint,str(target),value])
        if endpoint=='productRender':
            # MySQL normalizes JSON object key order. A copied task and a new
            # menu response must still name the same work after that round trip.
            canonical={k:v for k,v in value.items() if k!='_ipfoxy_refresh_attempted'}
            encoded=json.dumps(canonical,ensure_ascii=False,sort_keys=True,separators=(',',':'))
            c.execute("SELECT id FROM tasks WHERE shop_job_id=%s AND endpoint='productRender' AND JSON_REMOVE(payload,'$._ipfoxy_refresh_attempted')=CAST(%s AS JSON) LIMIT 1",(shop_job_id,encoded))
            if c.fetchone():return 0
            # The stable unique key also prevents racing new inserts. target
            # is an old derived display identifier, not part of this request.
            key=digest([shop_job_id,endpoint,encoded])
        now=utcnow()
        c.execute('INSERT IGNORE INTO tasks(task_key,shop_job_id,endpoint,target_id,payload,priority,created_at,updated_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)',
                  (key,shop_job_id,endpoint,str(target),compact(value),priority,now,now))
        return c.rowcount

    def result(self,c,shop_job_id,account_id,endpoint,response,observed_at,target='',task_id=None):
        reference,sha=save_response(response)
        key=digest([shop_job_id,account_id,endpoint,str(target),sha])
        c.execute('INSERT IGNORE INTO task_results(result_key,shop_job_id,task_id,account_id,endpoint,target_id,observed_at,valid_data,response_blob,response_sha256) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',
                  (key,shop_job_id,task_id,account_id,endpoint,str(target),observed_at,True,reference,sha))

    def observe(self,c,session_id,endpoint,state,at,http=None,code=None,source=None,not_before=None):
        c.execute('SELECT observed_at FROM capabilities WHERE session_id=%s AND endpoint=%s FOR UPDATE',(session_id,endpoint));old=c.fetchone()
        if old and old['observed_at'] and old['observed_at']>at:return
        c.execute('INSERT INTO capabilities(session_id,endpoint,state,observed_at,http_status,business_code,evidence_source,not_before) VALUES(%s,%s,%s,%s,%s,%s,%s,%s) ON DUPLICATE KEY UPDATE state=VALUES(state),observed_at=VALUES(observed_at),http_status=VALUES(http_status),business_code=VALUES(business_code),evidence_source=VALUES(evidence_source),not_before=VALUES(not_before)',
                  (session_id,endpoint,state,at,http,str(code) if code is not None else None,source,not_before))


def classify(endpoint,response,shop_id=None,product_id=None):
    if not isinstance(response,dict):return 'invalid_payload',False
    http=response.get('_http_status',200);code=response.get('code')
    if http in (401,403,429) or code in (401,403,429):return 'rejected',False
    if code in (201003201,201003202):return 'store_closed',False
    if http!=200:return 'http_error',False
    if code not in (0,None):return 'business_error',False
    data=response.get('data')
    if endpoint=='accountInfo':
        from farm.accounts.assessment import assess_response
        valid=assess_response(http,response,product_id)['valid']
    elif endpoint=='productSpecifics':
        valid=code==0 and isinstance(data,dict) and str(data.get('spuId'))==str(product_id) and bool(data.get('name'))
    elif endpoint in ('productList','productRender'):
        valid=code==0 and isinstance(data,dict) and isinstance(data.get('shopCategoryList'),list)
    elif endpoint=='shopInfo':
        valid=code==0 and isinstance(data,dict) and bool(data.get('name'))
        for key in ('shopId','id'):
            if isinstance(data,dict) and data.get(key) is not None and str(data[key])!=str(shop_id):valid=False
    else:valid=code==0 and isinstance(data,(dict,list))
    return ('success' if valid else 'invalid_payload'),bool(valid)


def shop_is_closed(response):
    """Only the observed shopInfo status 4 is a closed-store signal."""
    data=response.get('data') if isinstance(response,dict) else None
    return isinstance(data,dict) and data.get('status') in (4,'4')


def closed_shop_jobs(store,run_id):
    """Closed evidence for this batch; unknown states never waive details."""
    rows=store.rows("SELECT r.shop_job_id,r.response_blob FROM task_results r JOIN shop_jobs j ON j.id=r.shop_job_id WHERE j.run_id=%s AND r.endpoint='shopInfo' AND r.valid_data=TRUE ORDER BY r.observed_at,r.id",(run_id,))
    latest={r['shop_job_id']:load_response(r['response_blob']) for r in rows}
    closed={job for job,response in latest.items() if shop_is_closed(response)}
    evidence=store.rows("SELECT DISTINCT t.shop_job_id FROM tasks t JOIN shop_jobs j ON j.id=t.shop_job_id WHERE j.run_id=%s AND t.endpoint='productSpecifics' AND t.last_reason='store_closed'",(run_id,))
    closed.update(row['shop_job_id'] for row in evidence)
    return closed
