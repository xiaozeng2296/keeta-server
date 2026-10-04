"""Observed region registration state transitions, with no transport or capture IO.

Only accepted Compass/service/local-info replies provide derived state. Request
inputs and a deliberate alternate region route come from the caller's profile.
"""
from copy import deepcopy
import json
import math
import re
from urllib.parse import quote, urlencode, urlsplit
from uuid import uuid4

from mtgsig.region_state import (
    COMPASS_CONFIG_PATH, CURRENT_LOCAL_INFO_PATH,
    parse_compass_response, parse_current_local_info_response,
)
from mtgsig.request_trace import make_m_shark_trace_id

SERVICE_REGIONS_PATH = '/api/v1/lbs/address/getOpenServiceRegion'
REGION_PATHS = {COMPASS_CONFIG_PATH, SERVICE_REGIONS_PATH, CURRENT_LOCAL_INFO_PATH}
STATE_FIELDS = ('region_compass_response', 'service_region_candidates',
                'region_state', 'compass_snapshot', 'region_events',
                'region_event_at_ms', 'region_event_at_seconds',
                'region_response_applied_at_ms', 'region_response_applied_at_seconds', 'sdk_launch_seconds')
LOCAL_FIELDS = ('actualLatitude', 'actualLongitude', 'clientType', 'latitude',
                'longitude', 'systemLocale', 'systemRegion', 'systemTimeZone')


def new_request_trace():
    return str(uuid4()).upper()


def region_event_patch(region, *, event_seconds, state, identity, initialize=False):
    """Record cumulative milliseconds from the established SDK launch epoch.

    Existing b22 observations are retained as observations. Their old wall
    times are never invented; only an event applied now gets event_at_ms.
    """
    _require(type(event_seconds) in (int, float) and math.isfinite(event_seconds) and
             event_seconds >= 0, 'invalid region event clock')
    event_at_ms = math.trunc(event_seconds * 1000.0)
    collect = identity.get('base_collect') or {}
    launch = state.get('sdk_launch_seconds', collect.get('b7'))
    if launch is None:
        return {} if initialize else {'region_response_applied_at_ms': event_at_ms,
                                      'region_response_applied_at_seconds': event_seconds}
    _require(type(launch) is int and launch >= 0, 'sdk_launch_seconds must be the SDK b7 epoch')
    if collect.get('b7') is not None:
        _require(launch == collect['b7'], 'sdk_launch_seconds differs from base_collect.b7')
    # Native subtracts the integer epoch from the double seconds first, then
    # multiplies and truncates. Converting seconds to integer ms first differs
    # by one millisecond for some binary floating-point values.
    elapsed = math.trunc((event_seconds - launch) * 1000.0)
    _require(elapsed >= 0, 'region event predates the SDK launch')
    events = deepcopy(state.get('region_events'))
    if events is None:
        raw = collect.get('b22')
        events = json.loads(raw) if isinstance(raw, str) and raw else []
    _require(isinstance(events, list) and len(events) <= 1024, 'invalid prior region_events')
    for event in events:
        _require(isinstance(event, dict) and len(event) == 1, 'invalid prior region event')
        key, value = next(iter(event.items()))
        _require(isinstance(key, str) and bool(re.fullmatch(r'[A-Z]{2}', key)) and
                 ((type(value) is int and value >= 0) or
                  (isinstance(value, str) and bool(re.fullmatch(r'0|[1-9][0-9]*', value)))),
                 'invalid prior region event value')
    patch = {'sdk_launch_seconds': launch, 'region_events': events}
    if not initialize:
        patch['region_response_applied_at_ms'] = event_at_ms
        patch['region_response_applied_at_seconds'] = event_seconds
    if initialize and events:
        return patch
    if len(events) == 1024:
        return patch
    _require(isinstance(region, str) and bool(re.fullmatch(r'[A-Z]{2}', region)), 'invalid region event name')
    events.append({region: str(elapsed)})
    patch['region_event_at_ms'] = event_at_ms
    patch['region_event_at_seconds'] = event_seconds
    patch['base_collect'] = dict(collect, b22=json.dumps(events, separators=(',', ':')))
    reporting = state.get('reporting_inputs')
    if isinstance(reporting, dict) and isinstance(reporting.get('bio_report'), dict):
        reporting = deepcopy(reporting)
        reporting['bio_report']['region_events'] = deepcopy(events)
        patch['reporting_inputs'] = reporting
    return patch


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _text(value):
    return isinstance(value, str) and bool(value) and value.isprintable()


def parse_service_regions_response(response, *, http_status):
    """Return complete candidates or {}, rejecting partial/ambiguous replies."""
    if (type(http_status) is not int or not 200 <= http_status < 300 or
            not isinstance(response, dict) or response.get('error') or
            response.get('success', True) is not True or
            type(response.get('code')) is not int or response['code'] != 0):
        return {}
    data = response.get('data')
    rows = data.get('regionList') if isinstance(data, dict) else None
    if not isinstance(rows, list) or not rows:
        return {}
    result = {}
    for row in rows:
        if not isinstance(row, dict) or not _text(row.get('region')) or row['region'] in result:
            return {}
        city = row.get('cityInfo')
        if not isinstance(city, dict) or not _text(city.get('cityId')) or not _text(city.get('location')):
            return {}
        coordinates = city['location'].split(',')
        try:
            longitude, latitude = map(float, coordinates)
        except (ValueError, TypeError):
            return {}
        if not (math.isfinite(longitude) and math.isfinite(latitude) and
                -180 <= longitude <= 180 and -90 <= latitude <= 90):
            return {}
        result[row['region']] = {'city_id': city['cityId'],
            'longitude': coordinates[0], 'latitude': coordinates[1]}
    return result


def _inputs(state):
    config = state.get('region_inputs')
    _require(isinstance(config, dict), 'region request requires explicit region_inputs')
    for key in ('app_id', 'app_version', 'initial_region', 'initial_city_id', 'selected_region'):
        _require(_text(config.get(key)), 'region_inputs requires ' + key)
    return config


def _compass(state, region):
    accepted = state.get('region_compass_response')
    _require(isinstance(accepted, dict), 'missing accepted Compass response')
    snapshot = parse_compass_response(accepted.get('response'), region=region,
                                      http_status=accepted.get('http_status'))
    _require(bool(snapshot), 'accepted Compass has no unambiguous region snapshot: ' + region)
    return snapshot


def _set_header(headers, key, value):
    for old in list(headers):
        if old.lower() == key.lower():
            del headers[old]
    if value is not None:
        headers[key] = value


def prepare_region_request(path, body, headers, host, state):
    """Build region body from explicit inputs and preceding accepted replies.

    The request's bootstrap/current region stays distinct from an explicitly
    selected service host region. No HTTP error triggers automatic rerouting.
    """
    config = _inputs(state)
    selected = config['selected_region']
    current = state.get('region_state') or {}
    region = current.get('region', config['initial_region'])
    city = current.get('city_id', config['initial_city_id'])
    headers = dict(headers)
    for key, value in (('region', region), ('cityId', city), ('appId', config['app_id']),
                       ('appVersion', config['app_version']), ('userId', '-1'), ('XXX', 'test')):
        _set_header(headers, key, value)
    # Generic identity substitution injects unionid even though the observed
    # region calls have no such header. Preserve it in state for other routes.
    _set_header(headers, 'pragma-unionid', None)
    for key in list(headers):
        if key.lower() in {'authorization', 'cookie', 'token', 'incog-token', 'csecuserid', 'pushtoken'}:
            del headers[key]
    session = config.get('app_session')
    if session is None:
        session = next((v for k, v in (state.get('header_overrides') or {}).items()
                        if k.lower() == 'appsession'), None)
    _require(_text(session), 'region_inputs.app_session requires this session appSession')
    _set_header(headers, 'appSession', session)
    previous_trace = next((v for k, v in headers.items() if k.lower() == 'm-shark-traceid'), None)
    if previous_trace is not None:
        device = state.get('csecuuid')
        timestamp = state.get('timestamp_ms')
        _require(type(timestamp) is int, 'M-SHARK requires current timestamp_ms')
        _set_header(headers, 'M-SHARK-TRACEID', make_m_shark_trace_id(
            previous_trace, device, now_ms=timestamp,
            session_marker=state.get('m_shark_session_marker')))
    if path == COMPASS_CONFIG_PATH:
        body = json.dumps({'token': config['app_id'], 'appVersion': config['app_version']}, separators=(',', ':'))
    elif path == SERVICE_REGIONS_PATH:
        route_region = config.get('service_route_region', region)
        _require(_text(route_region), 'service_route_region must be region text')
        snapshot = _compass(state, route_region)
        host = urlsplit(snapshot['platform_hosts']['Keeta.C.ProductUrl']).netloc
        request = config.get('service_request')
        _require(isinstance(request, dict) and set(request) == {'userType', 'bundleName', 'bundleVersion'},
                 'region_inputs.service_request requires userType, bundleName, bundleVersion')
        _require(type(request['userType']) is int and request['userType'] > 0 and
                 _text(request['bundleName']) and _text(request['bundleVersion']), 'invalid service_request')
        body = json.dumps(request, ensure_ascii=False, separators=(',', ':'))
    else:
        _compass(state, selected)
        candidates = state.get('service_region_candidates')
        candidate = candidates.get(selected) if isinstance(candidates, dict) else None
        _require(isinstance(candidate, dict) and all(_text(candidate.get(k)) for k in
                 ('latitude', 'longitude', 'city_id')), 'missing accepted service candidate: ' + selected)
        explicit = config.get('local_info')
        input_fields = set(LOCAL_FIELDS) - {'latitude', 'longitude'}
        _require(isinstance(explicit, dict) and set(explicit) == input_fields and
                 all(isinstance(value, str) for value in explicit.values()),
                 'region_inputs.local_info requires explicit system/location inputs; selected coordinates come from candidates')
        values = dict(explicit, latitude=candidate['latitude'], longitude=candidate['longitude'])
        body = urlencode([(key, values[key]) for key in LOCAL_FIELDS])
    # Host is transport authority only, but a captured explicit Host must agree.
    if any(key.lower() == 'host' for key in headers):
        _set_header(headers, 'Host', host)
    return host, headers, body


def consume_region_response(path, response, *, http_status, state):
    """Validate before returning any patch; captured responses are never read."""
    config = _inputs(state)
    selected = config['selected_region']
    if path == COMPASS_CONFIG_PATH:
        for region in {selected, config['initial_region'], config.get('service_route_region', config['initial_region'])}:
            _require(bool(parse_compass_response(response, region=region, http_status=http_status)),
                     'Compass response lacks required region: ' + str(region))
        return {'region_compass_response': {'http_status': http_status, 'response': deepcopy(response)}}
    if path == SERVICE_REGIONS_PATH:
        candidates = parse_service_regions_response(response, http_status=http_status)
        _require(selected in candidates, 'service response lacks selected region candidate')
        return {'service_region_candidates': candidates}
    local = parse_current_local_info_response(response, http_status=http_status)
    candidates = state.get('service_region_candidates') or {}
    _require(bool(local) and local['region'] == selected and
             local['city_id'] == (candidates.get(selected) or {}).get('city_id'),
             'currentLocalInfo did not confirm the selected live candidate')
    snapshot = _compass(state, selected)
    overrides = dict(state.get('header_overrides') or {})
    for key, value in (('region', local['region']), ('cityId', local['city_id'])):
        _set_header(overrides, key, value)
    return dict(local, region_state=local, compass_snapshot=snapshot, header_overrides=overrides)


def apply_selected_region_route(host, path_with_query, headers, state):
    """Update established host families and city query after accepted selection.

    Explicit app_locale comes from MLocale.currentLocaleIdentifier and updates
    existing locale/lang query slots. Raw region locale/lang do not imply an
    App selection. The separate language query and unrelated hosts are kept.
    """
    local = state.get('region_state')
    if not local:
        return host, path_with_query, headers
    _require(isinstance(local, dict) and _text(local.get('region')) and _text(local.get('city_id')),
             'invalid accepted region_state')
    selected = _compass(state, local['region'])
    accepted = state['region_compass_response']
    configs = accepted['response']['data']['configs']
    if urlsplit(path_with_query).path == '/ntp':
        # FAMA uses its own Compass key, not the pikachu SDK family. Before
        # selection the captured authority remains the bootstrap route.
        routes = [(config['regions'], (config.get('bizConfig') or {}).get('platformHosts', {}).get('msp.url.poke'))
                  for config in configs]
        target = next((route for regions, route in routes if local['region'] in regions), None)
        _require(_text(target) and not any(c in target for c in '/?#@\\:'),
                 'missing or invalid selected NTP msp.url.poke route')
        _require(host in {route for _, route in routes if isinstance(route, str)},
                 'NTP capture authority is not an accepted Compass route')
        host = target
    families = ('Keeta.C.ProductUrl', 'Passport.url', 'msp.url.pikachu', 'Push.medusaUrl')
    for field in families:
        known = set()
        for config in configs:
            raw = ((config.get('bizConfig') or {}).get('platformHosts') or {}).get(field)
            if isinstance(raw, str):
                known.add(urlsplit(raw if '://' in raw else 'https://' + raw).netloc)
        if host in known:
            raw = selected['platform_hosts'][field]
            host = urlsplit(raw if '://' in raw else 'https://' + raw).netloc
            break
    # i18n's observed field is outside the four core snapshot keys.
    i18n = {c['regions'][0]: c.get('bizConfig', {}).get('platformHosts', {}).get('i18n.i18n.host')
            for c in configs if isinstance(c.get('regions'), list) and len(c['regions']) == 1}
    if host in {urlsplit(v).netloc for v in i18n.values() if isinstance(v, str)}:
        route = i18n.get(local['region'])
        _require(isinstance(route, str) and urlsplit(route).scheme == 'https' and
                 urlsplit(route).netloc and not urlsplit(route).username, 'missing selected i18n route')
        host = urlsplit(route).netloc
    headers = dict(headers)
    for key, value in (('region', local['region']), ('cityId', local['city_id'])):
        if any(k.lower() == key.lower() for k in headers):
            _set_header(headers, key, value)
    if any(k.lower() == 'host' for k in headers):
        _set_header(headers, 'Host', host)
    path, sep, query = path_with_query.partition('?')
    if sep:
        # Replace only existing named state fields; preserve byte ordering and
        # unrelated query encoding used by a2 canonicalization.
        replacements = {'ci': local['city_id'], 'cityId': local['city_id'], 'region': local['region']}
        if 'district_id' in local:
            replacements['districtId'] = local['district_id']
        if 'time_zone' in local:
            _require(_text(local['time_zone']), 'invalid accepted region time_zone')
            replacements['timeZone'] = quote(local['time_zone'], safe='')
        if 'app_locale' in state:
            app_locale = state['app_locale']
            _require(_text(app_locale) and not any(char.isspace() for char in app_locale),
                     'app_locale requires the explicit current App locale')
            replacements.update(locale=quote(app_locale, safe=''), lang=quote(app_locale, safe=''))
        pairs = []
        for pair in query.split('&'):
            key, equals, value = pair.partition('=')
            pairs.append(key + equals + (replacements[key] if key in replacements and equals else value))
        path_with_query = path + '?' + '&'.join(pairs)
    return host, path_with_query, headers
