"""One account per worker: local signing, captured context, durable product checkpoints."""
import json
import os
import random
import time
from datetime import datetime, timezone

from farm import _paths  # noqa: F401


class AccountDegraded(Exception):
    """Repeated authentication, rate-limit or transport failures stop the run."""


def _auth_bad(resp):
    if not isinstance(resp, dict):
        return False
    if resp.get('_http_status') in (401, 403, 429) or resp.get('code') in (401, 403, 429):
        return True
    if resp.get('code') not in (0, None):
        msg = (str(resp.get('message') or '') + str(resp.get('msg') or '')).lower()
        return any(w in msg for w in ('login', 'token', 'unauthor', '登录', '鉴权', 'sign'))
    return False


def _success(resp):
    return (isinstance(resp, dict) and resp.get('code') == 0
            and resp.get('_http_status', 200) == 200)


def _complete(raw, fetch_specs=False):
    return (isinstance(raw, dict) and all(_success(raw.get(key)) for key in ('shopInfo', 'productList'))
            and (not fetch_specs or raw.get('specs_complete') is True))


def _detail_success(response, product):
    return (_success(response) and isinstance(response.get('data'), dict)
            and str(response['data'].get('spuId')) == str(product)
            and bool(response['data'].get('name')))


def product_ids(response):
    """Include lazy IDs and inline products once per shop; reject unsafe identifiers."""
    categories = response.get('data', {}).get('shopCategoryList')
    if not isinstance(categories, list):
        raise ValueError('successful menu lacks shopCategoryList')
    result = {}
    for category in categories:
        values = list(category.get('spuIdList') or [])
        values.extend(spu.get('spuId') for spu in category.get('spuList') or [])
        for value in values:
            identifier = str(value)
            if not identifier.isascii() or not identifier.isdigit():
                raise ValueError('menu contains invalid product ID')
            result[identifier] = None
    return list(result)


def crawl_account(env, tasks, ci=None, delay=2.0, degrade_after=5,
                  fetch_specs=False, detail_delay=0.5, detail_probe_interval=0,
                  shop_list_interval=0, shop_info_probe_interval=0):
    import crawl_keeta as CK
    import requests
    import fcntl
    from farm.proxy import ProxyRoute

    env.ensure_dirs()
    # Keep the counter, progress, and product files exclusive to this account.
    with open(env.root / '.crawl.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        full = None
        if env.device_id_path.exists():
            from farm.fullsign import FullSigner
            signer = full = FullSigner(env.device_id_path)
        else:
            signer = CK.OfflineReSigner(str(env.sample_path))
        session = requests.Session()
        session.trust_env = False
        try:
            with ProxyRoute(env.proxy, env.front_proxy) as route_proxy:
                return _crawl_tasks(env, tasks, signer, env.ident_headers(), ci, delay,
                                    degrade_after, fetch_specs, detail_delay, session,
                                    detail_probe_interval, shop_list_interval,
                                    shop_info_probe_interval, route_proxy)
        finally:
            if full is not None:
                full.persist_counter()
            session.close()


def _crawl_tasks(env, tasks, signer, ident, ci, delay, degrade_after,
                 fetch_specs, detail_delay, session, detail_probe_interval=0, shop_list_interval=0,
                 shop_info_probe_interval=0, route_proxy=None):
    import crawl_keeta as CK

    context = env.request_context()
    if type(shop_list_interval) is not int or shop_list_interval < 0:
        raise ValueError('shop_list_interval must be a nonnegative integer')
    if shop_list_interval and context is None:
        raise ValueError('shop list collection requires this account captured context')
    if type(shop_info_probe_interval) is not int or shop_info_probe_interval < 0:
        raise ValueError('shop_info_probe_interval must be a nonnegative integer')
    kwargs = dict(proxies={'http': route_proxy, 'https': route_proxy} if route_proxy else None,
                  identity=ident, city=ci)
    if context is not None:
        kwargs.update(request_context=context, session=session)
    started = time.monotonic()
    state = dict(acct=env.acct_id, ok=0, fail=0, skip=0, degraded=False,
                 status='running', pid=os.getpid(), total_shops=len(tasks), attempted_shops=0,
                 requests=0, detail_requests=0, detail_ok=0, detail_fail=0, detail_cached=0,
                 referenced_products=0, unavailable_shops=0, detail_unattempted=0,
                 consecutive_denials=0, consecutive_transport_errors=0,
                 fetch_specs=fetch_specs, started_at=datetime.now(timezone.utc).isoformat())
    state['proxy_configured'] = bool(env.proxy)
    state['front_proxy_configured'] = bool(env.front_proxy)
    state['endpoint_stats'] = {}
    state['request_ledger'] = 'requests.jsonl'
    state['detail_probe_interval'] = detail_probe_interval
    state['detail_suspended_until_shop'] = 0
    state['detail_deferred'] = 0
    state['shop_list_interval'] = shop_list_interval
    state['shop_list_next_page'] = 0
    state['shop_list_finished'] = False
    state['shop_info_probe_interval'] = shop_info_probe_interval
    state['shop_info_suspended_until_shop'] = 0
    done = env.done_ids()
    denial_streaks = {}

    def progress(**fields):
        state.update(fields, updated_at=datetime.now(timezone.utc).isoformat(),
                     elapsed_seconds=round(time.monotonic() - started, 2))
        env.save_progress(state)

    def request(stage, task, product=None):
        progress(stage=stage, current_shop=task.shop_id, current_product=product)
        state['requests'] += 1
        metrics = state['endpoint_stats'].setdefault(stage, dict(attempts=0, success=0, rejected=0,
                                                               business_errors=0, transport_errors=0))
        metrics['attempts'] += 1
        request_started = time.monotonic()
        def record(response=None, error=None):
            event = dict(run_started_at=state['started_at'], request_number=state['requests'],
                         time=datetime.now(timezone.utc).isoformat(), endpoint=stage,
                         shop_id=task.shop_id, product_id=product,
                         http_status=response.get('_http_status') if isinstance(response, dict) else None,
                         code=response.get('code') if isinstance(response, dict) else None,
                         error=error, elapsed_ms=round((time.monotonic()-request_started)*1000),
                         proxy_configured=bool(env.proxy))
            if stage == 'homeShopList':
                event.update(shop_id=None, page=state['shop_list_next_page'])
            with open(env.root / state['request_ledger'], 'a', encoding='utf-8') as stream:
                stream.write(json.dumps(event, ensure_ascii=False) + '\n')
        if product is not None:
            state['detail_requests'] += 1
        try:
            if stage == 'homeShopList':
                url, headers, body = context.build_shop_list(state['shop_list_next_page'])
                response = CK._post_signed(signer, url, headers, body,
                                           proxies=kwargs['proxies'], session=session)
            elif product is None:
                response = CK.call(signer, '/api/v1/shop/' + stage, task.shop_id, task.lat, task.lng, **kwargs)
            else:
                response = CK.call_specifics(signer, task.shop_id, product, task.lat, task.lng, **kwargs)
        except Exception as exc:
            metrics['transport_errors'] += 1
            record(error=type(exc).__name__)
            state['consecutive_transport_errors'] += 1
            if state['consecutive_transport_errors'] >= degrade_after:
                raise AccountDegraded('consecutive_transport_errors')
            raise
        state['consecutive_transport_errors'] = 0
        state['last_http_status'] = response.get('_http_status') if isinstance(response, dict) else None
        state['last_code'] = response.get('code') if isinstance(response, dict) else None
        record(response)
        metrics['success' if _success(response) else 'rejected' if _auth_bad(response) else 'business_errors'] += 1
        if _auth_bad(response):
            denial_streaks[stage] = denial_streaks.get(stage, 0) + 1
        else:
            denial_streaks[stage] = 0
        state['detail_consecutive_denials'] = denial_streaks.get('productSpecifics', 0)
        state['shop_info_consecutive_denials'] = denial_streaks.get('shopInfo', 0)
        state['consecutive_denials'] = max(
            (count for endpoint, count in denial_streaks.items()
             if not (detail_probe_interval and endpoint == 'productSpecifics')
             and not (shop_info_probe_interval and endpoint == 'shopInfo')), default=0)
        progress()
        return response

    def denied():
        if state['consecutive_denials'] >= degrade_after:
            raise AccountDegraded('consecutive_auth_or_rate_limit_rejections')

    progress(stage='starting')
    try:
        for task in tasks:
            raw_path = env.raw_path(task.shop_id)
            previous = None
            if raw_path.exists():
                try:
                    previous = json.loads(raw_path.read_text(encoding='utf-8'))
                except (ValueError, OSError):
                    pass
            complete = _complete(previous, fetch_specs) if raw_path.exists() else (task.shop_id in done and not fetch_specs)
            if complete:
                state['skip'] += 1
                progress()
                continue
            state['attempted_shops'] += 1
            try:
                if (shop_list_interval and not state['shop_list_finished'] and
                        (state['attempted_shops'] - 1) % shop_list_interval == 0):
                    listing = request('homeShopList', task)
                    env.save_json(env.root / 'shop_lists' / ('page-%04d.json' % state['shop_list_next_page']), listing)
                    if _success(listing):
                        state['shop_list_next_page'] += 1
                        data = listing.get('data') or {}
                        module = data.get('module_body') or {}
                        state['shop_list_finished'] = module.get('component_list') == []
                    denied()
                if state['attempted_shops'] < state['shop_info_suspended_until_shop']:
                    info = {'_deferred': True, 'reason': 'shop_info_endpoint_rejected'}
                else:
                    info = request('shopInfo', task)
                    if (shop_info_probe_interval and
                            state['shop_info_consecutive_denials'] >= degrade_after):
                        state['shop_info_suspended_until_shop'] = state['attempted_shops'] + shop_info_probe_interval
                if not _success(info):
                    if not info.get('_deferred'):
                        env.log_error(task.shop_id, 'shopInfo', 'code=' + str(info.get('code')))
                    if not (shop_info_probe_interval and (_auth_bad(info) or info.get('_deferred'))):
                        state['fail'] += 1
                        denied()
                        time.sleep(delay)
                        continue
                prod = request('productList', task)
                raw = dict(shopInfo=info, productList=prod, lat=task.lat, lng=task.lng)
                if fetch_specs:
                    raw['specs_complete'] = False
                env.save_json(raw_path, raw)
                if not _success(prod):
                    state['fail'] += 1
                    env.log_error(task.shop_id, 'productList', 'code=' + str(state['last_code']))
                    denied()
                    time.sleep(delay)
                    continue
                if fetch_specs:
                    identifiers = product_ids(prod)
                    raw.update(product_ids=identifiers, specs_ok=0, specs_failed=[])
                    state['referenced_products'] += len(identifiers)
                    env.save_json(raw_path, raw)
                    for product_index, product in enumerate(identifiers):
                        detail_path = env.specifics_path(task.shop_id, product)
                        cached = None
                        if detail_path.exists():
                            try:
                                cached = json.loads(detail_path.read_text(encoding='utf-8'))
                            except (ValueError, OSError):
                                pass
                        if _detail_success(cached, product):
                            state['detail_cached'] += 1
                            raw['specs_ok'] += 1
                            continue
                        if state['attempted_shops'] < state['detail_suspended_until_shop']:
                            raw['specs_blocked_reason'] = 'detail_endpoint_rejected'
                            raw['specs_unattempted'] = identifiers[product_index:]
                            state['detail_deferred'] += len(raw['specs_unattempted'])
                            env.save_json(raw_path, raw)
                            break
                        try:
                            detail = request('productSpecifics', task, product)
                            env.save_json(detail_path, detail)
                            if _detail_success(detail, product):
                                state['detail_ok'] += 1
                                raw['specs_ok'] += 1
                            else:
                                state['detail_fail'] += 1
                                raw['specs_failed'].append(product)
                                env.log_error(task.shop_id, 'productSpecifics',
                                              'spu=' + product + ' code=' + str(state['last_code']))
                            env.save_json(raw_path, raw)
                            if (detail_probe_interval and
                                    state['detail_consecutive_denials'] >= degrade_after):
                                raw['specs_blocked_reason'] = 'detail_endpoint_rejected'
                                raw['specs_unattempted'] = identifiers[product_index + 1:]
                                state['detail_deferred'] += len(raw['specs_unattempted'])
                                state['detail_suspended_until_shop'] = state['attempted_shops'] + detail_probe_interval
                                env.save_json(raw_path, raw)
                                progress()
                                break
                            # This response explicitly applies to the entire store.
                            # Keep it incomplete and resumable, without requesting
                            # the same unavailable store once for every menu item.
                            if detail.get('code') == 201003202:
                                raw['specs_blocked_reason'] = 'store_closed'
                                raw['specs_unattempted'] = identifiers[product_index + 1:]
                                state['unavailable_shops'] += 1
                                state['detail_unattempted'] += len(raw['specs_unattempted'])
                                env.save_json(raw_path, raw)
                                progress()
                                break
                            if state['consecutive_denials'] >= degrade_after:
                                state['fail'] += 1
                                denied()
                        except AccountDegraded:
                            raise
                        except Exception as exc:
                            state['detail_fail'] += 1
                            raw['specs_failed'].append(product)
                            env.log_error(task.shop_id, 'productSpecifics',
                                          'spu=' + product + ' ' + type(exc).__name__)
                            env.save_json(raw_path, raw)
                        progress()
                        time.sleep(detail_delay)
                    raw['specs_complete'] = raw['specs_ok'] == len(identifiers)
                    env.save_json(raw_path, raw)
                    if not raw['specs_complete']:
                        state['fail'] += 1
                        progress()
                        time.sleep(delay)
                        continue
                if not _success(info):
                    state['fail'] += 1
                    progress()
                    time.sleep(delay)
                    continue
                env.mark_done(task.shop_id)
                done.add(task.shop_id)
                state['ok'] += 1
                progress()
                print(json.dumps({key: state[key] for key in ('acct', 'ok', 'fail', 'skip', 'requests', 'detail_ok')},
                                 ensure_ascii=False), flush=True)
                time.sleep(delay + random.random())
            except AccountDegraded:
                raise
            except Exception as exc:
                state['fail'] += 1
                env.log_error(task.shop_id, 'exc', type(exc).__name__)
                progress()
                time.sleep(delay)
        progress(status='completed', stage='finished')
    except AccountDegraded as exc:
        progress(status='stopped', degraded=True, stop_reason=str(exc))
    except BaseException:
        progress(status='interrupted')
        raise
    return state
