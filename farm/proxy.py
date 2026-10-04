"""Explicit proxy routes for collection workers.

An account may use a normal requests proxy directly, or a two-hop HTTP route
for local testing: loopback Clash -> authenticated HTTP/SOCKS5 remote proxy. The latter
is implemented by a short-lived GOST process. Credentials are kept in the
sealed account bundle and a mode-0600 temporary file; they are never put in
the child command line or logs.
"""
import ipaddress
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import threading
from urllib.parse import quote, unquote, urlsplit, urlunsplit


DEFAULT_GOST = "/opt/homebrew/bin/gost"
_PROXY_SCHEMES = {"http", "https", "socks5", "socks5h"}


def _fail(message="invalid proxy"):
    raise ValueError(message)


def normalize_proxy(value):
    """Return a canonical proxy URL, accepting host:port:user:pass."""
    if value is None:
        return None
    if not isinstance(value, str):
        _fail()
    value = value.strip()
    if not value:
        return None
    if any(c.isspace() for c in value):
        _fail()
    if "://" not in value:
        parts = value.split(":", 3)
        if len(parts) == 2:
            host, port = parts
            value = f"http://{host}:{port}"
        elif len(parts) == 4:
            host, port, username, password = parts
            if not host or not port or not username or not password:
                _fail()
            value = (f"http://{quote(username, safe='')}:{quote(password, safe='')}@"
                     f"{host}:{port}")
        else:
            _fail()
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        _fail()
    if (parsed.scheme not in _PROXY_SCHEMES or not parsed.hostname or
            parsed.path not in ("", "/") or parsed.query or parsed.fragment or
            (parsed.username is None and parsed.password is not None)):
        _fail()
    if port is not None and not 1 <= port <= 65535:
        _fail()
    host = parsed.hostname
    if any(ord(c) > 127 for c in host):
        _fail()
    host_part = f"[{host}]" if ":" in host else host
    authority = host_part + (f":{port}" if port is not None else "")
    if parsed.username is not None:
        if parsed.password is None:
            _fail()
        authority = (f"{quote(unquote(parsed.username), safe='')}:"
                     f"{quote(unquote(parsed.password), safe='')}@{authority}")
    return urlunsplit((parsed.scheme, authority, "", "", ""))


def _endpoint(value, *, authenticated=False, loopback=False):
    normalized = normalize_proxy(value)
    if normalized is None:
        _fail()
    parsed = urlsplit(normalized)
    allowed = {"http", "socks5", "socks5h"} if authenticated else {"http"}
    if parsed.scheme not in allowed:
        _fail("proxy chaining requires an HTTP front and HTTP/SOCKS5 exit")
    host = parsed.hostname
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        if (loopback and host.lower() != "localhost") or any(
                c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-" for c in host):
            _fail()
    else:
        if loopback and not ip.is_loopback:
            _fail("front proxy must be loopback")
    port = parsed.port or 80
    username = unquote(parsed.username) if parsed.username is not None else None
    password = unquote(parsed.password) if parsed.password is not None else None
    if authenticated and (username is None or password is None):
        _fail("remote proxy credentials are required")
    if (username is None) != (password is None):
        _fail("proxy credentials are incomplete")
    result = {"host": host, "port": port, "scheme": parsed.scheme}
    if username is not None:
        result.update(username=username, password=password)
    return result


def normalize_route(proxy=None, front_proxy=None):
    """Normalize and validate an exit plus its optional local front hop."""
    proxy = normalize_proxy(proxy)
    front_proxy = normalize_proxy(front_proxy)
    if front_proxy and not proxy:
        _fail("front proxy requires an exit proxy")
    if front_proxy:
        _endpoint(front_proxy, loopback=True)
        _endpoint(proxy, authenticated=True)
    return proxy, front_proxy


def _gost_config(listen, first, remote, timeout):
    duration = f"{timeout:g}s"
    hops = []
    for index, endpoint in enumerate((first, remote)):
        kind = "socks5" if endpoint.get("scheme") in ("socks5", "socks5h") else "http"
        connector = {"type": kind, "metadata": {"timeout": duration}}
        if index == 1 and "username" in endpoint:
            connector["auth"] = {"username": endpoint["username"],
                                 "password": endpoint["password"]}
        address = endpoint["host"]
        if ":" in address and not address.startswith("["):
            address = f"[{address}]"
        address = f"{address}:{endpoint['port']}"
        hops.append({"name": f"hop-{index}", "nodes": [{
            "name": f"proxy-{index}", "addr": address,
            "connector": connector,
            "dialer": {"type": "tcp", "metadata": {"timeout": duration}},
            "metadata": {"timeout": duration},
        }], "metadata": {"timeout": duration}})
    return {
        "log": {"level": "fatal", "format": "json", "output": "stderr"},
        "services": [{"name": "loopback-http", "addr": f"127.0.0.1:{listen}",
                       "handler": {"type": "http", "chain": "via-local-proxy",
                                    "metadata": {"readTimeout": duration}},
                       "listener": {"type": "tcp"}}],
        "chains": [{"name": "via-local-proxy", "hops": hops}],
    }


def _free_loopback_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class _TrafficRelay:
    """Count TCP stream bytes at a private loopback proxy boundary."""
    def __init__(self,target):
        self.target=target;self.lock=threading.Lock();self.stop=threading.Event()
        self.uploaded=0;self.downloaded=0;self.errors=0;self.connections=0
        self.sockets=set();self.workers=[]
        self.listener=socket.socket();self.listener.bind(('127.0.0.1',0));self.listener.listen(4)
        self.listener.settimeout(.2);self.port=self.listener.getsockname()[1]
        self.thread=threading.Thread(target=self._accept,daemon=True);self.thread.start()

    def _accept(self):
        while not self.stop.is_set():
            try:client,_=self.listener.accept()
            except socket.timeout:continue
            except OSError:break
            with self.lock:self.sockets.add(client);self.connections+=1
            worker=threading.Thread(target=self._forward,args=(client,),daemon=True)
            self.workers.append(worker);worker.start()

    def _copy(self,source,target,up):
        try:
            while not self.stop.is_set():
                data=source.recv(65536)
                if not data:break
                remaining=memoryview(data)
                while remaining and not self.stop.is_set():
                    sent=target.send(remaining)
                    if not sent:raise ConnectionError('stream_closed')
                    with self.lock:
                        if up:self.uploaded+=sent
                        else:self.downloaded+=sent
                    remaining=remaining[sent:]
        except OSError:
            if not self.stop.is_set():
                with self.lock:self.errors+=1
        finally:
            try:target.shutdown(socket.SHUT_WR)
            except OSError:pass

    def _forward(self,client):
        remote=None
        try:
            remote=socket.create_connection(self.target,timeout=30)
            client.settimeout(60);remote.settimeout(60)
            with self.lock:self.sockets.add(remote)
            upload=threading.Thread(target=self._copy,args=(client,remote,True),daemon=True)
            upload.start();self._copy(remote,client,False);upload.join(timeout=1)
        except OSError:
            if not self.stop.is_set():
                with self.lock:self.errors+=1
        finally:
            for sock in (client,remote):
                if sock is not None:
                    try:sock.close()
                    except OSError:pass
                    with self.lock:self.sockets.discard(sock)

    def close(self):
        # Sessions close their sockets before the route context exits.
        for worker in self.workers:worker.join(timeout=.5)
        self.stop.set();self.listener.close()
        with self.lock:active=list(self.sockets)
        for sock in active:
            try:sock.shutdown(socket.SHUT_RDWR)
            except OSError:pass
            try:sock.close()
            except OSError:pass
        self.thread.join(timeout=.5)
        for worker in self.workers:worker.join(timeout=.5)

    def snapshot(self):
        with self.lock:
            return {'measured':self.connections>0,'uploaded_bytes':self.uploaded,
                    'downloaded_bytes':self.downloaded,'connections':self.connections,
                    'errors':self.errors,'scope':'local_proxy_stream'}


class ProxyRoute:
    """Context manager returning the proxy URL for one worker session."""

    def __init__(self, proxy=None, front_proxy=None, *, gost=None, startup_timeout=5, measure=False):
        self.proxy, self.front_proxy = normalize_route(proxy, front_proxy)
        self.gost = gost or os.environ.get("KEETA_GOST") or shutil.which("gost") or DEFAULT_GOST
        self.startup_timeout = startup_timeout
        self.process = None
        self.tempdir = None
        self.effective = None
        self.measure=measure;self.meter=None;self.traffic={'measured':False}

    def _measured_url(self):
        parsed=urlsplit(self.effective)
        if not self.measure or parsed.scheme not in ('http','socks5','socks5h'):return self.effective
        self.meter=_TrafficRelay((parsed.hostname,parsed.port or 80))
        auth=parsed.netloc.rsplit('@',1)[0]+'@' if '@' in parsed.netloc else ''
        return urlunsplit((parsed.scheme,auth+f'127.0.0.1:{self.meter.port}',parsed.path,parsed.query,parsed.fragment))

    def __enter__(self):
        if not self.proxy:
            return None
        if not self.front_proxy:
            self.effective = self.proxy
            return self._measured_url()
        first = _endpoint(self.front_proxy, loopback=True)
        remote = _endpoint(self.proxy, authenticated=True)
        if not Path(self.gost).is_file() and shutil.which(self.gost) is None:
            _fail("GOST executable is unavailable")
        listen = _free_loopback_port()
        config = _gost_config(listen, first, remote, 30)
        self.tempdir = tempfile.TemporaryDirectory(prefix="keeta-proxy-chain-")
        path = Path(self.tempdir.name) / "gost.json"
        path.write_text(json.dumps(config, ensure_ascii=False), encoding="utf-8")
        os.chmod(path, 0o600)
        try:
            self.process = subprocess.Popen(
                [self.gost, "-C", str(path)], stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True)
            deadline = time.monotonic() + self.startup_timeout
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    _fail("proxy chain failed to start")
                try:
                    with socket.create_connection(("127.0.0.1", listen), timeout=0.15):
                        self.effective = f"http://127.0.0.1:{listen}"
                        return self._measured_url()
                except OSError:
                    time.sleep(0.05)
            _fail("proxy chain startup timed out")
        except Exception:
            self.close()
            raise

    def close(self):
        if self.meter is not None:
            self.meter.close();self.traffic=self.meter.snapshot();self.meter=None
        process, self.process = self.process, None
        if process is not None:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        tempdir, self.tempdir = self.tempdir, None
        if tempdir is not None:
            tempdir.cleanup()
        self.effective = None

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False


def is_ipfoxy(proxy):
    value = normalize_proxy(proxy)
    host = urlsplit(value or '').hostname or ''
    return host == 'gate.ipfoxy.io' or host.endswith('.ipfoxy.io')


def refresh_ipfoxy(proxy, front_proxy=None):
    """Ask the configured gateway to refresh; never send account headers."""
    import requests
    if not is_ipfoxy(proxy):
        raise ValueError('IPFoxy refresh requires an IPFoxy gateway')
    route_context=ProxyRoute(proxy,front_proxy)
    before=after=None
    def exit_ip(route):
        try:
            with requests.Session() as check:
                check.trust_env=False
                reply=check.get('https://api.ipify.org',proxies={'http':route,'https':route},
                    headers={'Connection':'close'},timeout=(15,15),allow_redirects=False)
            if reply.status_code==200 and isinstance(reply.text,str):return str(ipaddress.ip_address(reply.text.strip()))
        except (requests.RequestException,ValueError):pass
        return None
    try:
        with route_context as route:
            before=exit_ip(route)
            with requests.Session() as session:
                session.trust_env = False
                response = session.get('http://next.ipfoxy.io',
                    proxies={'http': route, 'https': route},
                    headers={'Accept': 'application/json, text/plain'},
                    timeout=(30 if front_proxy else 8, 25), allow_redirects=False)
            if response.status_code==200:after=exit_ip(route)
        accepted = response.status_code == 200
        try:
            data = response.json()
        except ValueError:
            data = None
        if isinstance(data, dict):
            if data.get('success') is False or data.get('error'):
                accepted = False
            if 'code' in data and str(data['code']) not in ('0', '200'):
                accepted = False
        # An acknowledgement is not proof that the gateway changed its egress.
        return {'accepted': accepted, 'http_status': response.status_code,
                'outcome': 'acknowledged' if accepted else 'failed',
                'exit_before':before,'exit_after':after,'ip_changed':before!=after if before and after else None}
    except Exception as exc:
        return {'accepted': False, 'http_status': None, 'outcome': 'failed',
                'error_type': type(exc).__name__}


def proxy_defaults(store):
    return store.get_setting('proxy_defaults') or {}


def save_proxy_defaults(store, proxy, front_proxy=None, refresh=False):
    proxy, front_proxy = normalize_route(proxy, front_proxy)
    if refresh and not is_ipfoxy(proxy):
        raise ValueError('IPFoxy refresh requires an IPFoxy gateway')
    value = {'proxy': proxy, 'front_proxy': front_proxy, 'refresh_ipfoxy': bool(refresh)}
    store.set_setting('proxy_defaults', value)
    return proxy_summary(value)


def proxy_summary(value):
    endpoint = urlsplit(value.get('proxy') or '')
    return {'configured': bool(value.get('proxy')),
            'gateway': (endpoint.hostname or '') + (':'+str(endpoint.port) if endpoint.port else ''),
            'front_proxy_enabled': bool(value.get('front_proxy')),
            'refresh_ipfoxy': bool(value.get('refresh_ipfoxy'))}


def clash_pool_summary(store):
    pool=store.get_setting('clash_node_pool') or {}
    nodes=pool.get('nodes',[])
    return {'configured':bool(nodes),'node_count':len(nodes),
            'verified_exits':len({n['exit_ip'] for n in nodes if n.get('exit_ip')}),
            'nodes':[{k:n.get(k) for k in ('name','proxy','exit_ip')} for n in nodes]}


def ensure_clash_pool(store):
    """Start the isolated collection core; never patch the user's global group."""
    import requests
    pool=store.get_setting('clash_node_pool') or {}
    if not pool:return False
    controller=pool['controller'];parsed=urlsplit(controller)
    if parsed.hostname!='127.0.0.1' or parsed.scheme!='http':raise ValueError('pool controller must be local')
    try:
        with requests.Session() as session:
            session.trust_env=False
            response=session.get(controller+'/version',headers={'Authorization':'Bearer '+pool['secret']},timeout=2)
        if response.status_code==200:return True
        raise ValueError('pool controller authentication failed')
    except requests.RequestException:pass
    from farm.mysql_store import ROOT
    directory=(ROOT/'.private/clash-node-pool').resolve();config=directory/'config.yaml'
    core=Path(pool['core'])
    if not core.is_file() or not config.is_file():raise ValueError('collection proxy core/config missing')
    with (directory/'runtime.log').open('ab') as log:
        process=subprocess.Popen([str(core),'-d',str(directory),'-f',str(config)],
            stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True)
    os.chmod(directory/'runtime.log',0o600)
    (directory/'pid').write_text(str(process.pid)+'\n')
    return True


def assign_account_proxies(store,account_ids,mode='clash_pool',*,proxy=None,front_proxy=None,refresh=False,node_name=None):
    """Change account routes under the same account locks used by collectors."""
    from farm.mysql_store import utcnow
    from farm.mysql_selection import parse_ids
    from collections import Counter
    ids=parse_ids(account_ids)
    if not ids or mode not in ('clash_pool','saved','manual'):raise ValueError('explicit account IDs and route required')
    if mode=='manual':
        proxy,front_proxy=normalize_route(proxy,front_proxy)
        if not proxy:raise ValueError('请填写出口代理')
        if refresh and not is_ipfoxy(proxy):raise ValueError('仅 IPFoxy 支持刷新')
    pool=store.get_setting('clash_node_pool') or {};nodes=pool.get('nodes',[])
    if mode=='clash_pool' and not nodes:raise ValueError('Clash pool is not configured')
    if node_name and (mode!='clash_pool' or node_name not in {n['name'] for n in nodes}):
        raise ValueError('请选择节点池内的有效节点')
    for node in nodes:_endpoint(node['proxy'],loopback=True)
    defaults=proxy_defaults(store)
    con=store.connect();locks=[];results=[]
    try:
        with con.cursor() as c:
            for name in ['keeta:proxy-config']+['keeta:account:'+str(aid) for aid in sorted(ids)]:
                c.execute('SELECT GET_LOCK(%s,0) locked',(name,))
                if c.fetchone()['locked']!=1:raise ValueError('账号正在请求，当前请求结束后再分配出口')
                locks.append(name)
            bindings=store.get_setting('clash_node_bindings') or {}
            available={n['name']:n for n in nodes}
            usage=Counter(n for aid,n in bindings.items() if n in available and int(aid) not in ids)
            for aid in ids:
                c.execute('SELECT s.* FROM accounts a JOIN account_sessions s ON s.id=a.active_session_id WHERE a.id=%s FOR UPDATE',(aid,))
                row=c.fetchone()
                if not row:raise ValueError('账号没有活动会话')
                bundle=store.unseal(row)
                if mode=='clash_pool':
                    node=available.get(node_name or bindings.get(str(aid)))
                    if node is None:node=min(nodes,key=lambda n:usage[n['name']])
                    usage[node['name']]+=1;bindings[str(aid)]=node['name']
                    if not bundle.get('clash_node'):
                        bundle['saved_proxy_route']={k:bundle.get(k) for k in ('proxy','front_proxy','refresh_ipfoxy')}
                    bundle.update(proxy=node['proxy'],front_proxy=None,refresh_ipfoxy=False,
                                  clash_node={'name':node['name'],'exit_ip':node.get('exit_ip')})
                    results.append({'account_id':aid,'node':node['name'],'proxy':node['proxy']})
                else:
                    route=({'proxy':proxy,'front_proxy':front_proxy,'refresh_ipfoxy':refresh}
                           if mode=='manual' else bundle.get('saved_proxy_route') or defaults)
                    proxy,front=normalize_route(route.get('proxy'),route.get('front_proxy'))
                    if not proxy:raise ValueError('没有保存的出口，请先配置默认代理')
                    bundle.update(proxy=proxy,front_proxy=front,refresh_ipfoxy=bool(route.get('refresh_ipfoxy')))
                    bundle.pop('clash_node',None);bindings.pop(str(aid),None)
                    if mode=='manual':bundle['saved_proxy_route']=dict(route)
                    results.append({'account_id':aid,'route':mode})
                key,blob=store.seal(bundle)
                c.execute('UPDATE account_sessions SET encryption_key_id=%s,credential_blob=%s,updated_at=%s WHERE id=%s',(key,blob,utcnow(),row['id']))
            key,blob=store.seal(bindings)
            c.execute("INSERT INTO encrypted_settings(setting_key,encryption_key_id,credential_blob,updated_at) VALUES('clash_node_bindings',%s,%s,%s) ON DUPLICATE KEY UPDATE encryption_key_id=VALUES(encryption_key_id),credential_blob=VALUES(credential_blob),updated_at=VALUES(updated_at)",(key,blob,utcnow()))
        con.commit();return results
    except Exception:con.rollback();raise
    finally:
        try:
            with con.cursor() as c:
                for name in reversed(locks):c.execute('SELECT RELEASE_LOCK(%s)',(name,))
        finally:con.close()
