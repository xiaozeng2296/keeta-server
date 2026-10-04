"""Encrypted proxy inventory and safe public status for the local panel."""
from contextlib import contextmanager
import hashlib
import ipaddress
import json
import time
from urllib.parse import urlsplit

import requests

from farm.network.proxy import ProxyRoute, normalize_route, is_ipfoxy, proxy_summary
from farm.storage.mysql import utcnow

CATALOG = 'proxy_catalog'
BINDINGS = 'account_proxy_bindings'


class ProxyConfigError(ValueError):
    """Only fixed, user-facing messages; never include a supplied proxy URL."""


def read_setting(store, cursor, name):
    cursor.execute('SELECT encryption_key_id,credential_blob FROM encrypted_settings WHERE setting_key=%s', (name,))
    row = cursor.fetchone()
    return store.unseal(row) if row else {}


def write_setting(store, cursor, name, value):
    key, blob = store.seal(value)
    cursor.execute('INSERT INTO encrypted_settings(setting_key,encryption_key_id,credential_blob,updated_at) '
                   'VALUES(%s,%s,%s,%s) ON DUPLICATE KEY UPDATE encryption_key_id=VALUES(encryption_key_id),'
                   'credential_blob=VALUES(credential_blob),updated_at=VALUES(updated_at)',
                   (name, key, blob, utcnow()))


@contextmanager
def configuration(store):
    con = store.connect()
    held = False
    try:
        with con.cursor() as cursor:
            cursor.execute("SELECT GET_LOCK('keeta:proxy-config',5) locked")
            held = cursor.fetchone()['locked'] == 1
            if not held:
                raise ProxyConfigError('代理配置正在更新，请稍后重试')
            yield cursor
        con.commit()
    except BaseException:
        con.rollback()
        raise
    finally:
        try:
            if held:
                with con.cursor() as cursor:
                    cursor.execute("SELECT RELEASE_LOCK('keeta:proxy-config')")
        finally:
            con.close()


def nodes_by_name(store):
    return {n['name']: n for n in (store.get_setting('clash_node_pool') or {}).get('nodes', [])}


def parse_import(text):
    if not isinstance(text, str) or len(text) > 256_000:
        raise ProxyConfigError('代理文件不能为空，且不能超过 256 KB')
    text = text.strip()
    if not text:
        raise ProxyConfigError('请粘贴代理或选择文件')
    try:
        if text.startswith(('[', '{')):
            rows = json.loads(text)
            if isinstance(rows, dict):
                rows = rows.get('proxies')
            if not isinstance(rows, list):
                raise ValueError()
        else:
            rows = [s.strip() for s in text.splitlines() if s.strip() and not s.lstrip().startswith('#')]
        if not 1 <= len(rows) <= 500:
            raise ValueError()
        result = []
        for i, row in enumerate(rows, 1):
            if isinstance(row, str):
                row = {'proxy': row}
            if not isinstance(row, dict):
                raise ValueError()
            proxy, _ = normalize_route(row.get('proxy') or row.get('url'))
            if not proxy:
                raise ValueError()
            name = row.get('name') or f'海外代理 {i}'
            if not isinstance(name, str) or not 1 <= len(name.strip()) <= 80 or '://' in name or '@' in name:
                raise ValueError()
            result.append({'proxy': proxy, 'name': name.strip()})
        return result
    except (ValueError, TypeError):
        raise ProxyConfigError('代理格式无效：每行一个 URL 或 host:port:user:pass，也可导入 JSON 数组') from None


def import_routes(store, text, front_node, refresh=False):
    node = nodes_by_name(store).get(front_node)
    if node is None:
        raise ProxyConfigError('请选择一个有效的前置 Clash 节点')
    rows = parse_import(text)
    prepared = []
    for row in rows:
        try:
            proxy, front = normalize_route(row['proxy'], node['proxy'])
        except ValueError:
            raise ProxyConfigError('链式出口需要带账号密码的 HTTP 或 SOCKS5 代理') from None
        if refresh and not is_ipfoxy(proxy):
            raise ProxyConfigError('动态刷新只适用于 IPFoxy 网关，请与长效代理分开导入')
        identity = hashlib.sha256(json.dumps([proxy, front], separators=(',', ':')).encode()).hexdigest()[:24]
        prepared.append(dict(id=identity, name=row['name'], proxy=proxy, front_proxy=front,
                             front_node=front_node, refresh_ipfoxy=bool(refresh)))
    with configuration(store) as cursor:
        catalog = read_setting(store, cursor, CATALOG)
        if len(set(catalog) | {r['id'] for r in prepared}) > 500:
            raise ProxyConfigError('最多保存 500 条代理路线')
        created = []
        for row in prepared:
            # Reimport is idempotent: do not change a route already in use.
            if row['id'] not in catalog:
                catalog[row['id']] = dict(row, created_at=utcnow().isoformat()+'Z')
                created.append(row['id'])
        write_setting(store, cursor, CATALOG, catalog)
    return {'imported': len(created), 'existing': len(prepared)-len(created),
            'ids': list(dict.fromkeys(r['id'] for r in prepared))}


def resolve_route(store, proxy_id):
    value = (store.get_setting(CATALOG) or {}).get(proxy_id)
    if not value:
        raise ProxyConfigError('代理不存在，请刷新列表')
    return dict(value)


def inventory(store):
    catalog = store.get_setting(CATALOG) or {}
    bindings = store.get_setting(BINDINGS) or {}
    accounts = store.rows('SELECT a.id,a.label,a.paused,a.active_session_id FROM accounts a ORDER BY a.id')
    known = {str(a['id']) for a in accounts}
    legacy = store.get_setting('clash_node_bindings') or {}
    for account in accounts:
        aid = str(account['id'])
        account['binding'] = bindings.get(aid) or ({'mode':'clash_pool','name':legacy[aid], 'node_name':legacy[aid]} if aid in legacy else None)
    routes = []
    for value in catalog.values():
        routes.append(dict(id=value['id'], name=value['name'], front_node=value['front_node'],
                           **proxy_summary(value), check=value.get('check'),
                           account_ids=[int(a) for a,b in bindings.items() if a in known and b.get('proxy_id')==value['id']]))
    return {'proxies':routes, 'accounts':accounts,
            'nodes':[{k:n.get(k) for k in ('name','exit_ip')} for n in nodes_by_name(store).values()]}


def delete_route(store, proxy_id):
    with configuration(store) as cursor:
        catalog = read_setting(store, cursor, CATALOG)
        bindings = read_setting(store, cursor, BINDINGS)
        cursor.execute('SELECT id FROM accounts')
        live = {str(a['id']) for a in cursor.fetchall()}
        if any(a in live and b.get('proxy_id')==proxy_id for a,b in bindings.items()):
            raise ProxyConfigError('此代理仍绑定账号，请先给这些账号分配其他出口')
        if proxy_id not in catalog:
            raise ProxyConfigError('代理不存在')
        del catalog[proxy_id]
        write_setting(store, cursor, CATALOG, catalog)
    return {'deleted':proxy_id}


def check_route(store, *, proxy_id=None, node_name=None):
    if bool(proxy_id) == bool(node_name):
        raise ProxyConfigError('请选择一条代理或一个 Clash 节点')
    if proxy_id:
        route = resolve_route(store, proxy_id)
    else:
        node = nodes_by_name(store).get(node_name)
        if node is None:
            raise ProxyConfigError('Clash 节点不存在')
        route = {'proxy':node['proxy'], 'front_proxy':None}
    start = time.monotonic()
    status = {'ok':False, 'checked_at':utcnow().isoformat()+'Z'}
    try:
        with ProxyRoute(route['proxy'], route.get('front_proxy')) as proxy, requests.Session() as session:
            session.trust_env = False
            response = session.get('https://api.ipify.org', proxies={'http':proxy,'https':proxy},
                                   headers={'Accept':'text/plain'}, timeout=(12,15), allow_redirects=False)
            status['http_status'] = response.status_code
            if response.status_code == 200:
                status.update(ok=True, exit_ip=str(ipaddress.ip_address(response.text.strip())))
            else:
                status['error'] = '出口检测服务未返回成功响应'
    except (requests.RequestException, ValueError, OSError) as exc:
        status.update(error='代理连接或出口验证失败', error_type=type(exc).__name__)
    status['elapsed_ms'] = round((time.monotonic()-start)*1000)
    if proxy_id:
        with configuration(store) as cursor:
            catalog = read_setting(store, cursor, CATALOG)
            if proxy_id in catalog:
                catalog[proxy_id]['check'] = status
                write_setting(store, cursor, CATALOG, catalog)
    return status
