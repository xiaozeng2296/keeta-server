#!/usr/bin/env python3
"""Protocol inventory, native parity and App Store update checks.

Reports contain schemas, versions and hashes, never captured credential values.
The native command calls the SDK signer without transmitting its requests.
Configuration observation is passive unless --refresh explicitly requests an
SDK configuration fetch. Observers never replace results or clear caches.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import threading
import time
from urllib.parse import parse_qsl, urlencode, urlsplit
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from farm import fullsign as fs
from farm.charles import body_bytes, headers as charles_headers
from mtgsig import a9_codec, mtg_crypto
from mtgsig.provider_config import configuration_summary, decode_config, ProviderConfig

BUNDLE = 'com.sankuai.sailor.ifooddelivery'
FIELDS = ['a' + str(i) for i in range(11)] + ['x0']
HORN_TYPES = ('SAKGuard_Dynamic_Risk', 'SAKGuard_Dynamic_Risk_Test')


class NativeOperationError(RuntimeError):
    def __init__(self, operation, cause):
        super().__init__('Native operation failed')
        self.operation = operation
        self.cause_type = type(cause).__name__
        self.saved = None


def native_call(operation, callback, timeout):
    """Cancel a stalled Frida operation without killing or restarting the App."""
    import frida
    cancellation = frida.Cancellable()
    timer = threading.Timer(timeout, cancellation.cancel)
    timer.daemon = True
    timer.start()
    try:
        with cancellation: return callback()
    except Exception as exc:
        raise NativeOperationError(operation, exc) from exc
    finally: timer.cancel()


def sha(value):
    if not isinstance(value, bytes):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True).encode()
    return hashlib.sha256(value).hexdigest()


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        json.dump(value, f, ensure_ascii=False, indent=2)
        f.write('\n')


def schema(value, path='$'):
    """Shape only; arrays aggregate element types and discard item counts/values."""
    result = {path + ':' + type(value).__name__}
    if isinstance(value, dict):
        for k, v in value.items(): result.update(schema(v, path + '.' + k))
    elif isinstance(value, list):
        for v in value: result.update(schema(v, path + '[]'))
    return sorted(result)


def embedded_schema(value, path='$'):
    """Some collector fields contain JSON text; inspect its shape, not values."""
    result = set(schema(value, path))
    if isinstance(value, str) and value.lstrip().startswith(('{', '[')):
        try: result.update(embedded_schema(json.loads(value), path + '<json>'))
        except ValueError: pass
    elif isinstance(value, dict):
        for key, item in value.items(): result.update(embedded_schema(item, path + '.' + key))
    elif isinstance(value, list):
        for item in value: result.update(embedded_schema(item, path + '[]'))
    return sorted(result)


def records(path):
    text = Path(path).read_text(encoding='utf-8-sig')
    if text.lstrip().startswith(('curl ', '/usr/bin/curl ')):
        from farm.mysql_import import parse_curl, split_curls
        for curl in split_curls(text): yield parse_curl(curl)
        return
    data = json.loads(text)
    if isinstance(data, dict) and 'samples' in data:
        yield from data['samples']
        return
    if isinstance(data, dict) and ('mtgsig' in data or 'a0' in data or 'x0' in data):
        mt = data.get('mtgsig', data)
        yield dict(data, headers={'mtgsig': json.dumps(mt) if isinstance(mt, dict) else mt})
        return
    if not isinstance(data, list): raise ValueError('Unsupported capture container')
    for flow in data:
        h = charles_headers(flow)
        if 'mtgsig' not in h: continue
        # HTTP/2 :path carries the exact query byte order when present.
        target = h.get(':path') or flow.get('path', '')
        if '?' not in target and flow.get('query'): target += '?' + flow['query']
        raw, encoding = body_bytes(flow.get('request', {}))
        yield {'headers': h, 'method': flow.get('method'),
               'url': flow.get('scheme', 'https') + '://' + flow['host'] + target,
               'body': raw.decode('utf-8'), 'body_encoding': encoding}


def inspect_record(record, provider_config=None):
    h = {k.lower(): v for k, v in record.get('headers', {}).items()}
    mt = h['mtgsig']; mt = json.loads(mt) if isinstance(mt, str) else mt
    if not isinstance(mt, dict): raise ValueError('mtgsig must be an object')
    report = {'field_types': {k: type(v).__name__ for k, v in mt.items()},
              'missing_fields': [k for k in FIELDS if k not in mt],
              'field_hashes': {k: sha(v) for k, v in mt.items()}, 'checks': {}}
    # These are protocol parameters/state, not account/device identifiers.
    report['constants'] = {k: mt[k] for k in ('a3', 'a6', 'x0') if type(mt.get(k)) is int}
    if isinstance(mt.get('a0'), str) and re.fullmatch(r'\d+(?:\.\d+){1,3}', mt['a0']):
        report['constants']['a0'] = mt['a0']
    report['versions'] = {'header_app': h.get('appversion')}
    report['a1_sha256'] = sha(mt.get('a1'))
    parts = str(mt.get('a10', '')).split(',')
    numeric = all(re.fullmatch(r'\d+(?:\.\d+)*', p) for p in parts)
    report['a10_shape'] = {'parts': len(parts), 'prefix': parts[0] if numeric else 'opaque',
                           'suffix': parts[2:] if numeric else [], 'numeric': numeric}
    checks = report['checks']
    checks['layout_supported'] = (mt.get('a0') == '2.5' and type(mt.get('x0')) is int and mt['x0'] == 2
                                  and type(mt.get('a3')) is int and type(mt.get('a6')) is int)
    if not checks['layout_supported']:
        report['layout'] = 'unsupported'
        return report
    report['layout'] = 'native_2.5_x0_2'
    plain = None
    try:
        try:
            plain, profile = fs.decode_a5(mt['a5'], mt['a1'], mt['a3'], mt['a4'])
        except ValueError:
            if provider_config is None: raise
            plain, profile = fs.decode_a5(mt['a5'], mt['a1'], mt['a3'], mt['a4'], profile=provider_config)
        collect = json.loads(plain)
        report['signing_profile'] = 'stored_configuration' if isinstance(profile, ProviderConfig) else profile
        checks['a5_decode'] = True
        checks['a5_roundtrip'] = mtg_crypto.a5_encrypt(plain, mt['a1'], mt['a3'], mt['a4'], fs.k2buf(mt['a1'], profile)) == mt['a5']
        report['versions'].update(app=collect.get('b5'), build=collect.get('b6'), sdk=collect.get('b10'), sdk_aux=collect.get('b11'))
        report['a5_schema'] = schema(collect)
        report['a5_embedded_schema'] = embedded_schema(collect)
        report['sequence'] = collect.get('b2')
        report['a10_session'] = int(parts[1])
    except (ValueError, KeyError, TypeError, IndexError): checks['a5_decode'] = False
    if provider_config is not None:
        checks['stored_configuration_matches_a3'] = provider_config.parameter == mt['a3']
        if checks.get('a5_decode'):
            checks['stored_configuration_matches_a5'] = provider_config.mask(mt['a1']) == fs.k2buf(mt['a1'], profile)
    detected = fs._detect_a9_codec(mt.get('a9'), mt.get('a1'))
    if not detected and provider_config is not None:
        try:
            decoded = a9_codec.decode(mt['a9'], mt['a1'], **provider_config.a9_options())
            detected = {'profile': 'stored_configuration', 'mode': decoded.mode}
        except ValueError: pass
    checks['a9_decode'] = bool(detected)
    if detected:
        report['a9_profile'] = detected['profile']; report['a9_mode'] = detected['mode']
        opts = (provider_config.a9_options() if detected['profile'] == 'stored_configuration'
                else fs._a9_options(detected['profile']))
        decoded = a9_codec.decode(mt['a9'], mt['a1'], mode=detected['mode'], **opts)
        checks['a9_roundtrip'] = a9_codec.encode_compressed(decoded.compressed, mt['a1'], mode=detected['mode'], **opts) == mt['a9']
        report['a9_schema'] = schema(json.loads(decoded.plaintext))
        report['a9_embedded_schema'] = embedded_schema(json.loads(decoded.plaintext))
    if record.get('url') and record.get('method'):
        body = record.get('body', '')
        u = urlsplit(record['url'])
        report['request_shape'] = {'method': record['method'], 'host': u.hostname, 'path': u.path,
                                   'query_keys': sorted({k for k, _ in parse_qsl(u.query)}),
                                   'header_keys': sorted(h)}
        try: report['request_shape']['body'] = schema(json.loads(body))
        except (ValueError, TypeError): report['request_shape']['body'] = ['non_json:' + type(body).__name__]
        if plain is not None and checks.get('a5_decode'):
            payload = json.dumps({k: v for k, v in mt.items() if k != 'a2'}, ensure_ascii=False, separators=(',', ':'))
            computed = fs.compute_a2(record['method'], record['url'], body, payload, mt['a1'], int(parts[1]),
                                     signing_profile=profile, sign_sequence=collect['b2'])
            checks['a2_full'] = computed == mt.get('a2')
    return report


def audit(paths):
    rows, sources, failures = [], [], []
    for path in paths:
        source = {'name': Path(path).name, 'sha256': sha(Path(path).read_bytes())}
        provider_config = None; configuration_invalid = False
        try:
            container = json.loads(Path(path).read_bytes())
            if isinstance(container, dict) and container.get('format') == 'keeta-native-sign-only-v1':
                source['native_metadata'] = container['metadata']
                if isinstance(container.get('configuration'), dict):
                    configuration = container['configuration']
                    source['native_metadata']['sdk_configuration'] = configuration_summary(configuration)
                    if configuration.get('value') is not None:
                        try: provider_config = decode_config(configuration['value'])
                        except ValueError: configuration_invalid = True
        except ValueError: pass
        sources.append(source)
        for index, r in enumerate(records(path)):
            try:
                item = inspect_record(r, provider_config); item['source'] = Path(path).name; item['index'] = index
                if configuration_invalid: item['checks']['stored_configuration_valid'] = False
                if 'native_metadata' in source:
                    item['native_metadata'] = source['native_metadata']
                    if 'sdk_configuration' in source['native_metadata']:
                        item['sdk_configuration'] = source['native_metadata']['sdk_configuration']
                    if 'sdk_resource_tags' in source['native_metadata']:
                        item['sdk_resource_tags'] = source['native_metadata']['sdk_resource_tags']
                rows.append(item)
            except Exception as exc:
                failures.append({'source': Path(path).name, 'index': index, 'error_type': type(exc).__name__})
    def variants(key):
        values = {json.dumps(r[key], sort_keys=True, ensure_ascii=False) for r in rows if key in r}
        return [json.loads(v) for v in sorted(values)]
    check_names = {'layout_supported', 'a5_decode', 'a5_roundtrip', 'a9_decode', 'a9_roundtrip', 'a2_full'}
    check_names.update(k for row in rows for k in row['checks'])
    checks = {k: dict(Counter(str(r['checks'][k]).lower() for r in rows if k in r['checks']))
              for k in sorted(check_names)}
    return {'format': 'keeta-protocol-audit-v1', 'observed_at': datetime.now(timezone.utc).isoformat(),
            'sources': sources, 'sample_count': len(rows), 'failures': failures, 'checks': checks,
            'inventory': {k: variants(k) for k in ('constants', 'versions', 'field_types', 'a10_shape',
                'signing_profile', 'a9_profile', 'a9_mode', 'a1_sha256', 'a5_schema', 'a9_schema',
                'a5_embedded_schema', 'a9_embedded_schema', 'request_shape', 'sdk_configuration', 'sdk_resource_tags')},
            'native_builds': [{k: s['native_metadata'].get(k) for k in
                ('bundle_id', 'app_version', 'build', 'macho_uuid', 'module', 'arch')}
                for s in sources if 'native_metadata' in s],
            'fields': {k: {'distinct': len({r['field_hashes'][k] for r in rows if k in r['field_hashes']}),
                            'present': sum(k in r['field_hashes'] for r in rows)} for k in FIELDS},
            'samples': rows}


def compare(old, new):
    if old.get('format') != 'keeta-protocol-audit-v1' or new.get('format') != old.get('format'):
        raise ValueError('Only audit reports can be compared')
    changes = {}
    for k, values in new['inventory'].items():
        added = [v for v in values if v not in old['inventory'].get(k, [])]
        if added: changes[k] = added
    builds = [b for b in new.get('native_builds', []) if b not in old.get('native_builds', [])]
    if builds: changes['native_builds'] = builds
    # Compare the same endpoint coverage. A smaller candidate is not a full pass.
    def coverage(report):
        return {(r.get('method'), r.get('host'), r.get('path'))
                for r in report['inventory'].get('request_shape', [])}
    missing = sorted(coverage(old) - coverage(new))
    if missing: changes['missing_request_coverage'] = [list(k) for k in missing]
    missing_native = [k for k in ('sdk_configuration', 'sdk_resource_tags')
                      if old['inventory'].get(k) and not new['inventory'].get(k)]
    if missing_native: changes['missing_native_observations'] = missing_native
    bad = (not new['sample_count'] or bool(new['failures']) or
           any(v.get('false', 0) for v in new['checks'].values()))
    # Missing request bytes are an unverified a2, never a pass.
    incomplete = (new['checks'].get('a2_full', {}).get('true', 0) != new['sample_count']
                  or bool(missing) or bool(missing_native))
    return {'status': 'failed_validation' if bad else 'incomplete_validation' if incomplete else
                      'review_required' if changes else 'matches_baseline',
            'changes': changes, 'checks': new['checks'], 'sample_count': new['sample_count']}


def capture_time(value):
    """Only timezone-aware capture times establish cross-flow ordering."""
    if not isinstance(value, str): return None
    try: result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError: return None
    return result if result.utcoffset() is not None else None


def audit_configurations(paths):
    """Observe Horn responses and later transmitted a3 values; never infer writes.

    Flow array order and a4 (the device clock) are not network ordering evidence.
    Matching a3 alone also does not prove that the configured salt was applied.
    """
    sources, events, failures = [], [], []
    for path in paths:
        raw = Path(path).read_bytes()
        source = {'name': Path(path).name, 'sha256': sha(raw)}
        sources.append(source)
        flows = json.loads(raw)
        if not isinstance(flows, list): raise ValueError('Expected a Charles JSON flow array')
        signatures, local_events = [], []
        for index, flow in enumerate(flows):
            try:
                value = charles_headers(flow).get('mtgsig')
                mt = json.loads(value) if value else {}
                if (isinstance(mt, dict) and mt.get('a0') == '2.5' and mt.get('x0') == 2
                        and type(mt.get('a3')) is int):
                    signatures.append({'index': index, 'a3': mt['a3'],
                        'time': capture_time(flow.get('times', {}).get('requestBegin'))})
            except (ValueError, TypeError, KeyError):
                failures.append({'source': source['name'], 'index': index, 'kind': 'invalid_signature'})
            if (flow.get('path') or '').split('?', 1)[0] != '/horn_ios/mergeRequest': continue
            try:
                response = flow.get('response', {})
                payload = json.loads(body_bytes(response)[0])
                if not isinstance(payload, dict): raise ValueError('Invalid Horn response')
                for kind in HORN_TYPES:
                    branch = payload.get(kind)
                    if branch is None: continue
                    if isinstance(branch, str): branch = json.loads(branch)
                    customer = branch.get('data', {}).get('customer', {})
                    if 'sakguard_key_enc_salt' not in customer: continue
                    config = customer['sakguard_key_enc_salt']
                    event = {'source': source['name'], 'index': index, 'type': kind,
                             'http_status': response.get('status'),
                             'config_path': '$.' + kind + '.data.customer.sakguard_key_enc_salt',
                             'response_end': None, 'decoded': False}
                    end = capture_time(flow.get('times', {}).get('end'))
                    if end: event['response_end'] = end.isoformat()
                    if isinstance(config, str): event['configuration_sha256'] = sha(config.encode())
                    try:
                        if not config: raise ValueError('Empty network configuration')
                        event.update(decode_config(config).summary()); event['decoded'] = True
                    except ValueError: event['error_type'] = 'invalid_configuration'
                    local_events.append(event)
            except (ValueError, TypeError, KeyError, AttributeError):
                failures.append({'source': source['name'], 'index': index, 'kind': 'invalid_horn_response'})
        source['native_signature_count'] = len(signatures)
        source['untimed_signature_count'] = sum(r['time'] is None for r in signatures)
        for event in local_events:
            end = capture_time(event['response_end'])
            next_ends = [capture_time(r['response_end']) for r in local_events if r['type'] == event['type']]
            limit = min((t for t in next_ends if t is not None and end is not None and t > end), default=None)
            after = sorted((r for r in signatures if end is not None and r['time'] is not None
                            and r['time'] >= end and (limit is None or r['time'] < limit)), key=lambda r: r['time'])
            event['window_end'] = limit.isoformat() if limit else None
            event['later_request_count'] = len(after)
            event['later_a3_counts'] = dict(Counter(str(r['a3']) for r in after))
            event['first_later_request'] = ({'index': after[0]['index'], 'a3': after[0]['a3'],
                'request_begin': after[0]['time'].isoformat()} if after else None)
            event['timing_complete'] = (end is not None and source['untimed_signature_count'] == 0
                                       and all(r['response_end'] for r in local_events if r['type'] == event['type']))
            event['a3_differs_after_response'] = (any(r['a3'] != event['parameter'] for r in after)
                                                 if event['decoded'] and after else None)
        events.extend(local_events)
    invalid = failures or any(not r['decoded'] or r['http_status'] != 200 for r in events)
    incomplete = not events or any(not r['timing_complete'] or not r['later_request_count'] for r in events)
    review = any(r['a3_differs_after_response'] for r in events)
    return {'format': 'keeta-horn-config-audit-v1', 'observed_at': datetime.now(timezone.utc).isoformat(),
            'status': 'failed_validation' if invalid else 'incomplete_observation' if incomplete else
                      'review_required' if review else 'observed',
            'sources': sources, 'events': events, 'failures': failures,
            'scope': 'Capture response completion and request transmission only; storage writes and provider activation are not observed.'}


def connect_device(args):
    import frida
    return (frida.get_device_manager().add_remote_device(args.remote) if args.remote else
            frida.get_device(args.device, timeout=5) if args.device else frida.get_usb_device(timeout=5))


def installed_app(args):
    dev = connect_device(args)
    app = next((a for a in dev.enumerate_applications(scope='full') if a.identifier == BUNDLE), None)
    if not app: raise ValueError('Keeta is not installed on this device')
    return {'bundle_id': app.identifier, 'app_version': app.parameters.get('version'),
            'build': app.parameters.get('build'), 'pid': app.pid,
            'checked_at': datetime.now(timezone.utc).isoformat()}


def native_capture(args):
    call = lambda operation, callback: native_call(operation, callback, args.timeout)
    dev = call('connect', lambda: connect_device(args))
    pid = args.pid
    if not pid:
        apps = call('resolve_app', dev.enumerate_applications)
        app = next((a for a in apps if a.identifier == BUNDLE), None)
        if not app or not app.pid: raise ValueError('Open Keeta on the selected device first')
        pid = app.pid
    session = call('attach', lambda: dev.attach(pid))
    script = None; tracing = False; saved = False; failed = False
    try:
        source = (ROOT / 'tools/protocol_probe.js').read_text()
        if args.trace_fields: source += '\n' + (ROOT / 'tools/protocol_trace.js').read_text()
        script = call('create_probe', lambda: session.create_script(source))
        call('load_probe', script.load)
        meta = call('metadata', script.exports_sync.metadata)
        if meta['bundle_id'] != BUNDLE: raise ValueError('Selected PID is not Keeta')
        configuration = call('read_sdk_configuration', script.exports_sync.configuration)
        meta['sdk_configuration'] = configuration_summary(configuration)
        if args.trace_fields:
            call('start_trace', script.exports_sync.start_trace); tracing = True
        samples = []
        for n in range(args.count):
            samples.append(call('sign', lambda: script.exports_sync.sign(args.method, args.url, args.body)))
            if n + 1 < args.count: time.sleep(args.interval)
        result = {'format': 'keeta-native-sign-only-v1', 'metadata': meta, 'samples': samples,
                  'configuration':configuration}
        if args.trace_fields:
            result['field_trace'] = call('trace_snapshot', script.exports_sync.trace_snapshot)
            meta['sdk_resource_tags'] = result['field_trace']['state']['resource_tags']
            call('stop_trace', script.exports_sync.stop_trace); tracing = False
        save(args.out, result)
        saved = True
        summary = {'metadata': {k:v for k,v in meta.items() if k != 'classes'},
                   'count': len(samples), 'saved': str(args.out), 'requests_sent_by_tool': 0}
        if 'field_trace' in result:
            summary['field_trace'] = {'state': result['field_trace']['state'],
                                     'event_count': len(result['field_trace']['events'])}
        return summary
    except Exception:
        failed = True
        raise
    finally:
        try:
            if tracing: call('stop_trace', script.exports_sync.stop_trace)
        finally:
            try: call('detach', session.detach)
            except NativeOperationError as exc:
                if saved: exc.saved = str(args.out)
                if not failed: raise


def lifecycle_summary(observation):
    """Separate observed callback/storage work from active provider loading."""
    trace = observation['trace']; events = trace['events']
    counts = dict(Counter(event['kind'] for event in events))
    # Match completed invocations, including nested callbacks/writes. A return
    # without its entry or a write on another thread cannot prove this chain.
    pending, writes, providers = {}, {}, {}
    linked, active_loads, unmatched = 0, 0, 0
    for event in events:
        thread = event.get('thread'); kind = event['kind']
        stack = pending.setdefault(thread, [])
        writing = writes.setdefault(thread, [])
        phase = kind.rsplit('_', 1)[0]
        loading = providers.setdefault((thread, phase), [])
        if kind in ('callback_enter', 'callback_leave', 'storage_write_enter', 'storage_write_leave',
                    'provider_configure_enter', 'provider_configure_leave',
                    'provider_initialize_enter', 'provider_initialize_leave') and thread is None:
            unmatched += 1
            continue
        if kind == 'callback_enter':
            stack.append({'type': event.get('type'), 'success': event.get('success') is True, 'completed': 0})
        elif kind == 'storage_write_enter':
            writing.append(stack[-1] if stack else None)
        elif kind == 'storage_write_leave':
            if not writing: unmatched += 1
            else:
                owner = writing.pop()
                if owner is not None and owner['success'] and any(owner is frame for frame in stack):
                    owner['completed'] += 1
        elif kind == 'callback_leave':
            if not stack or stack[-1]['type'] != event.get('type'): unmatched += 1
            else:
                frame = stack.pop()
                if any(owner is frame for owner in writing): unmatched += 1
                linked += frame['completed']
        elif kind in ('provider_configure_enter', 'provider_initialize_enter'): loading.append(event)
        elif kind in ('provider_configure_leave', 'provider_initialize_leave'):
            if not loading: unmatched += 1
            else:
                loading.pop()
                if kind == 'provider_configure_leave' and event.get('active_provider') is True and event.get('result') == 1:
                    active_loads += 1
    config = observation['final_configuration']; state = trace['state']
    matches = (config['parameter'] == state['parameter'] and config['salt_sha256'] == state['salt_sha256']
               if config.get('decode_status') in ('decoded', 'default') and state.get('provider_present') else None)
    network = {json.dumps({k: e.get(k) for k in ('http_status', 'load_source', 'error_code')}, sort_keys=True)
               for e in events if e['kind'] == 'horn_result'}
    incomplete = (trace.get('dropped') or counts.get('observer_error') or unmatched or
                  any(pending.values()) or any(writes.values()) or any(providers.values()))
    return {'status': 'incomplete_observation' if incomplete else
                     'callback_and_storage_observed' if linked else 'no_complete_callback_write_observed',
            'event_counts': counts, 'linked_callback_writes': linked, 'active_provider_load_count': active_loads,
            'unmatched_event_count': unmatched,
            'horn_results': [json.loads(item) for item in sorted(network)],
            'initial_state': observation['initial_trace']['state'], 'final_state': state,
            'stored_configuration_matches_provider': matches,
            'refresh_requested': bool(observation.get('refresh_requested')), 'seconds': observation['seconds'],
            'scope': 'Observed window only; a write function return is not proof of durable disk persistence.'}


def observe_configuration(args):
    call = lambda operation, callback: native_call(operation, callback, args.timeout)
    dev = call('connect', lambda: connect_device(args)); pid = args.pid
    if not pid:
        apps = call('resolve_app', dev.enumerate_applications)
        app = next((a for a in apps if a.identifier == BUNDLE), None)
        if not app or not app.pid: raise ValueError('Open Keeta on the selected device first')
        pid = app.pid
    session = call('attach', lambda: dev.attach(pid))
    script = None; tracing = False; saved = False; failed = False
    streamed = []; progress = {'format': 'keeta-config-lifecycle-observation-v1'}
    def on_message(message, data):
        payload = message.get('payload') if message.get('type') == 'send' else None
        if isinstance(payload, dict) and payload.get('kind') == 'config_lifecycle_event' and len(streamed) < 1000:
            streamed.append(payload['event'])
    try:
        source = (ROOT / 'tools/protocol_probe.js').read_text() + '\n' + (ROOT / 'tools/protocol_lifecycle.js').read_text()
        script = call('create_probe', lambda: session.create_script(source))
        script.on('message', on_message); call('load_probe', script.load)
        meta = call('metadata', script.exports_sync.metadata)
        if meta['bundle_id'] != BUNDLE: raise ValueError('Selected PID is not Keeta')
        progress['metadata'] = meta
        initial = configuration_summary(call('read_configuration', script.exports_sync.configuration))
        progress['initial_configuration'] = initial
        beginning = call('start_lifecycle', script.exports_sync.start_lifecycle); tracing = True
        progress['initial_trace'] = beginning
        started = time.monotonic()
        refresh = call('request_config_refresh', script.exports_sync.refresh_configuration) if args.refresh else None
        while time.monotonic() - started < args.seconds:
            time.sleep(min(1, max(0, args.seconds - (time.monotonic() - started))))
        trace = call('lifecycle_snapshot', script.exports_sync.lifecycle_snapshot)
        call('stop_lifecycle', script.exports_sync.stop_lifecycle); tracing = False
        final = configuration_summary(call('read_configuration', script.exports_sync.configuration))
        result = {'format': 'keeta-config-lifecycle-observation-v1', 'metadata': meta,
                  'initial_configuration': initial, 'final_configuration': final,
                  'initial_trace': beginning, 'trace': trace, 'refresh_requested': refresh,
                  'seconds': time.monotonic() - started}
        result['summary'] = lifecycle_summary(result); save(args.out, result); saved = True
        return dict(result['summary'], saved=str(args.out))
    except Exception as exc:
        failed = True
        if progress.get('initial_trace') is not None:
            progress.update(status='interrupted_observation', streamed_events=streamed,
                            error_type=type(exc).__name__, final_state_observed=False)
            save(args.out, progress); saved = True
            if isinstance(exc, NativeOperationError): exc.saved = str(args.out)
        raise
    finally:
        try:
            if tracing:
                try: call('stop_lifecycle', script.exports_sync.stop_lifecycle)
                except NativeOperationError:
                    if not failed: raise
        finally:
            try: call('detach', session.detach)
            except NativeOperationError as exc:
                if saved: exc.saved = str(args.out)
                if not failed: raise


def version_tuple(value):
    if not re.fullmatch(r'\d+(?:\.\d+)*', value): raise ValueError('Non-numeric version')
    parts = [int(p) for p in value.split('.')]
    while len(parts) > 1 and parts[-1] == 0: parts.pop()
    return tuple(parts)


def check_release(current, country, opener=urlopen):
    if not re.fullmatch('[A-Za-z]{2}', country): raise ValueError('Expected two-letter storefront')
    url = 'https://itunes.apple.com/lookup?' + urlencode({'bundleId': BUNDLE, 'country': country.lower()})
    with opener(url, timeout=20) as response: data = json.load(response)
    matches = [r for r in data.get('results', []) if r.get('bundleId') == BUNDLE]
    if not matches: return {'status': 'unavailable_in_storefront', 'country': country, 'checked_url': url}
    r = matches[0]; latest = r['version']
    return {'status': 'update_available' if version_tuple(latest) > version_tuple(current) else
                      'installed_newer_than_storefront' if version_tuple(latest) < version_tuple(current) else 'same_version',
            'installed': current, 'store_version': latest, 'country': country,
            'released_at': r.get('currentVersionReleaseDate'), 'track_url': r.get('trackViewUrl'),
            'checked_url': url, 'checked_at': datetime.now(timezone.utc).isoformat()}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('audit'); p.add_argument('sources', type=Path, nargs='+'); p.add_argument('--out', type=Path, required=True)
    p = sub.add_parser('config', help='Audit captured Horn configuration and subsequent a3 values')
    p.add_argument('sources', type=Path, nargs='+'); p.add_argument('--out', type=Path, required=True)
    p = sub.add_parser('observe-config', help='Observe config callbacks/storage/provider loads on the verified build')
    p.add_argument('--device'); p.add_argument('--remote'); p.add_argument('--pid', type=int)
    p.add_argument('--seconds', type=float, default=30); p.add_argument('--timeout', type=float, default=15)
    p.add_argument('--refresh', action='store_true', help='Request one SDK refresh of the registered production risk config (uses network)')
    p.add_argument('--out', type=Path, required=True)
    p = sub.add_parser('compare'); p.add_argument('baseline', type=Path); p.add_argument('candidate', type=Path)
    p = sub.add_parser('native'); p.add_argument('--device'); p.add_argument('--remote'); p.add_argument('--pid', type=int)
    p.add_argument('--count', type=int, default=3); p.add_argument('--interval', type=float, default=1); p.add_argument('--out', type=Path, required=True)
    p.add_argument('--trace-fields', action='store_true', help='Observe field writers on the verified Mach-O build')
    p.add_argument('--timeout', type=float, default=15, help='Timeout in seconds for each Frida operation (1–60)')
    p.add_argument('--method', choices=('GET','POST'), default='POST')
    p.add_argument('--url', default='https://fooddelivery-eu.mykeeta.com/api/v1/shop/shopInfo?ci=102302389')
    p.add_argument('--body', default='{"shopId":"0"}')
    p = sub.add_parser('device'); p.add_argument('--device'); p.add_argument('--remote'); p.add_argument('--out', type=Path)
    p = sub.add_parser('release'); p.add_argument('--installed', required=True); p.add_argument('--country', default='br'); p.add_argument('--out', type=Path)
    args = parser.parse_args(argv)
    if args.command == 'audit':
        result = audit(args.sources); save(args.out, result)
        print(json.dumps({k: result[k] for k in ('sample_count', 'checks', 'failures')}, ensure_ascii=False, indent=2))
        return 0 if (result['sample_count'] and not result['failures'] and
                     result['checks']['a2_full'].get('true', 0) == result['sample_count'] and
                     not any(v.get('false', 0) for v in result['checks'].values())) else 2
    if args.command == 'config':
        result = audit_configurations(args.sources); save(args.out, result)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result['status'] == 'observed' else 2
    if args.command == 'observe-config':
        if not 1 <= args.seconds <= 60 or not 1 <= args.timeout <= 60:
            raise ValueError('Observation seconds and operation timeout must be in 1–60')
        result = observe_configuration(args)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result['status'] == 'callback_and_storage_observed' else 2
    if args.command == 'compare':
        result = compare(json.loads(args.baseline.read_text()), json.loads(args.candidate.read_text()))
    elif args.command == 'native':
        if not 1 <= args.count <= 20 or not 0 <= args.interval <= 60 or not 1 <= args.timeout <= 60:
            raise ValueError('Invalid native sample bounds')
        result = native_capture(args)
    elif args.command == 'device':
        result = installed_app(args)
        if args.out: save(args.out, result)
    else:
        result = check_release(args.installed, args.country)
        if args.out: save(args.out, result)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if args.command == 'compare': return 0 if result['status'] == 'matches_baseline' else 2
    if args.command == 'release': return 2 if result['status'] in ('update_available', 'unavailable_in_storefront') else 0
    return 0


if __name__ == '__main__':
    try: raise SystemExit(main())
    except Exception as exc:
        error = {'status': 'error', 'error_type': type(exc).__name__}
        if isinstance(exc, NativeOperationError):
            error.update(operation=exc.operation, cause_type=exc.cause_type)
            if exc.saved: error['saved'] = exc.saved
        print(json.dumps(error))
        raise SystemExit(1)
