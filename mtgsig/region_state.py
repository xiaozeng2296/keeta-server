"""Minimal observed region/config response adapters; no network or state mutation.

currentLocalInfo reports the selected region/city. Compass configs supplies a
region-specific routing snapshot, not the result of its unresolved common,
private, activeStrategy and recoveryConfig precedence. Consumers must preserve
that distinction. Evidence: docs/archive/REGISTRATION_CONFIG_DEPENDENCIES.md.
"""
from collections.abc import Mapping
from urllib.parse import urlsplit

CURRENT_LOCAL_INFO_PATH = '/api/openapi/v1/currentLocalInfo'
COMPASS_CONFIG_PATH = '/api/openapi/v1/getCompassConfigs'

HOST_FIELDS = ('Passport.url', 'msp.url.pikachu')
URL_FIELDS = ('Push.medusaUrl', 'Keeta.C.ProductUrl')


def _text(value):
    return (isinstance(value, str) and bool(value) and
            all(char.isprintable() and not char.isspace() for char in value))


def _data(response, http_status):
    if type(http_status) is not int or not 200 <= http_status < 300:
        return None
    if not isinstance(response, Mapping) or response.get('error'):
        return None
    if type(response.get('code')) is not int or response['code'] != 0:
        return None
    if 'success' in response and response['success'] is not True:
        return None
    data = response.get('data')
    return data if isinstance(data, Mapping) else None


def parse_current_local_info_response(response, *, http_status):
    """Return a flat patch with region/city_id and present named locale fields.

    Only top-level data.region and data.cityId select the city. A nested
    leafCityInfo is a different state, and is never used as a fallback.
    Locale/lang are raw server values: no zh -> zh-HK conversion is inferred.
    All present consumed fields validate before any patch is returned.
    """
    data = _data(response, http_status)
    if data is None or not _text(data.get('region')) or not _text(data.get('cityId')):
        return {}
    result = {'region': data['region'], 'city_id': data['cityId']}
    for wire, field in (('districtId', 'district_id'), ('locale', 'locale'), ('lang', 'lang'),
                        ('timeZone', 'time_zone'), ('currency', 'currency')):
        if wire in data:
            if not _text(data[wire]):
                return {}
            result[field] = data[wire]
    return result


def _host(value):
    if not _text(value) or any(char in value for char in '/?#@\\:'):
        return False
    try:
        parsed = urlsplit('https://' + value)
        return bool(parsed.hostname) and parsed.netloc == value and not parsed.path
    except ValueError:
        return False


def _base_url(value):
    if not _text(value) or '\\' in value:
        return False
    try:
        parsed = urlsplit(value)
        return (parsed.scheme in ('http', 'https') and bool(parsed.hostname)
                and not parsed.username and not parsed.password
                and not parsed.query and not parsed.fragment)
    except ValueError:
        return False


def parse_compass_response(response, *, region, http_status):
    """Return one explicit configs routing snapshot, or {} if ambiguous/invalid.

    Output: compass_version, compass_region, compass_source='data.configs',
    and platform_hosts with exactly the four observed literal dotted keys.
    Does not overwrite current region or synthesize a URL for missing routes.
    Does not merge/fallback through privateConfig/commonConfig/activeStrategy.
    """
    data = _data(response, http_status)
    if data is None or not _text(region) or not _text(data.get('version')):
        return {}
    configs = data.get('configs')
    if not isinstance(configs, list):
        return {}
    matching = []
    for item in configs:
        if not isinstance(item, Mapping):
            return {}
        regions = item.get('regions')
        if not isinstance(regions, list) or not regions or not all(_text(value) for value in regions):
            return {}
        if region in regions:
            matching.append(item)
    if len(matching) != 1:
        return {}
    biz = matching[0].get('bizConfig')
    if not isinstance(biz, Mapping) or not isinstance(biz.get('platformHosts'), Mapping):
        return {}
    source = biz['platformHosts']
    if any(not _host(source.get(key)) for key in HOST_FIELDS):
        return {}
    if any(not _base_url(source.get(key)) for key in URL_FIELDS):
        return {}
    return {'compass_version': data['version'], 'compass_region': region,
            'compass_source': 'data.configs',
            'platform_hosts': {key: source[key] for key in HOST_FIELDS + URL_FIELDS}}
