"""Known query schemas combined only with the importing account's own capture.

Schemas are observations from iOS 3.12.500 / BR. They contain no credentials,
device observations or product IDs. A missing body fingerprint is omitted;
a9 is not a substitute for that independent I-series observation.
"""
from copy import deepcopy
import json
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

from farm.storage.mysql import PATHS

PROFILE = 'ios-3.12.500-br-v1'
PACKAGE = 'com.sankuai.sailor.ifooddelivery'
MARKET = '{"venueParam":{"supplySkuIdList":[null],"supplySpuIdList":[null]}}'


def account_request(bundle):
    """Build the observed passport query without foreign cookies or token_id."""
    base = bundle.get('request') or {}
    h = base.get('headers') or {}; ident = bundle.get('identity') or {}
    query = parse_qs(urlsplit(base.get('url', '')).query)
    version = h.get('appversion') or query.get('version_name', [None])[0]
    region = h.get('region') or h.get('registerregion')
    if (not all(ident.get(k) for k in ('token', 'uuid', 'userid')) or
            version not in ('3.12.401', '3.12.500') or region != 'BR'):
        return None
    params = {'uuid': ident['uuid'], 'lang': h.get('locale', 'en'),
              'version_name': version, 'sdk_version': '0.3.63-i18n',
              'package_name': PACKAGE, 'packageNameFilled': 'false',
              'locale': h.get('locale', 'en'), 'region': region,
              'cityId': h.get('cityid') or query.get('ci', ['102302389'])[0],
              'fields': 'username,email,mobile,gender,nationality,cpf,usernameAuditing,registerRegion,collectemail,nationality,hasPassword',
              'explicitMobile': 'true', 'yodaReady': 'h5',
              'csecplatform': '4', 'csecversion': '3.5.2'}
    headers = {'host': 'passport-eu.mykeeta.com', 'accept': '*/*',
               'token': ident['token'], 'cookie': 'token=' + ident['token'],
               'origin': 'https://passport.mykeeta.com',
               'referer': 'https://passport.mykeeta.com/', 'registerregion': region}
    for key in ('user-agent', 'accept-language'):
        if h.get(key): headers[key] = h[key]
    return {'method': 'GET', 'url': 'https://passport-eu.mykeeta.com' +
            PATHS['accountInfo'] + '?' + urlencode(params), 'headers': headers, 'body': ''}


def validate_account_request(request, identity):
    parsed = urlsplit(request.get('url', '')); h = request.get('headers') or {}
    if (request.get('method') != 'GET' or request.get('body') or
            parsed.scheme != 'https' or parsed.hostname != 'passport-eu.mykeeta.com' or
            parsed.path != PATHS['accountInfo'] or parsed.username or parsed.password or
            parsed.port not in (None, 443) or parsed.fragment or
            h.get('host') != parsed.netloc or not identity.get('userid') or
            not identity.get('token') or h.get('token') != identity['token']):
        raise ValueError('invalid account-check identity or origin')
    query = parse_qs(parsed.query)
    for key in ('uuid', 'userid', 'token'):
        if key in query and query[key] != [identity.get(key)]:
            raise ValueError('account-check query identity mismatch')
    cookies = dict(p.strip().split('=', 1) for p in h.get('cookie', '').split(';') if '=' in p)
    for key in ('token', 'mt_c_token', 'mtcp-token'):
        if key in cookies and cookies[key] != identity['token']:
            raise ValueError('account-check cookie identity mismatch')


def assemble_templates(bundle):
    """Fill absent schemas; keep captured templates and signing state intact."""
    bundle = deepcopy(bundle)
    base = bundle.get('request') or {}; ident = bundle.get('identity') or {}
    h = base.get('headers') or {}; origin = urlsplit(base.get('url', ''))
    templates = bundle.setdefault('templates', {})
    sources = bundle.setdefault('template_sources', {})
    if not bundle.get('account_check_request'):
        check = account_request(bundle)
        if check:
            bundle['account_check_request'] = check
            sources['accountInfo'] = 'passport-schema-v1/current-account'
    query = parse_qs(origin.query)
    if (origin.scheme != 'https' or origin.netloc not in ('fooddelivery-eu-1.mykeeta.com','fooddelivery-eu-3.mykeeta.com') or
            h.get('appversion') not in ('3.12.401','3.12.500') or h.get('region') != 'BR' or
            query.get('csecplatform') != ['2'] or query.get('csecpkgname') != [PACKAGE] or
            not all(ident.get(k) for k in ('token', 'uuid', 'userid'))):
        return bundle
    for key in ('token', 'uuid', 'userid', 'csecuuid', 'csecuserid'):
        if ident.get(key) and h.get(key) != ident[key]:
            raise ValueError('capture identity mismatch')
    body = base.get('body') or {}
    if isinstance(body, str): body = json.loads(body)
    location = body.get('location') or body.get('userCommonParam') or body
    loc = {k: location.get(k) for k in ('latitude', 'longitude', 'actualLatitude', 'actualLongitude')}
    common = {'bundleVersion': '0.2.185', 'userGetMode': 'delivery', 'marketActivityParamJson': MARKET}
    coords = {'latitude': None, 'longitude': None, 'shopId': ''}
    bodies = {
        'shopInfo': dict(common, **coords, sourcePageType='0', channelId='banner-10002', pageSource='10002', afterLogin=0),
        'productList': dict(common, sourcePageType='0', searchGlobalId='', locationSpuId='', searchWord='',
                            locationCategoryId='', searchLogId='', location=loc, pageSource='10002',
                            shopId='', searchSource='keeta_app', deliveryMode=''),
        'productSpecifics': dict(common, **coords, activityPromotionTags=[], requestSource=0,
                                 pageSource=10002, activityId='', channelCode=0, sameShopSpuIdList=[],
                                 spuId=None, deliveryMode=1001, cartSkuList=[]),
        'productRender': dict(common, shopId='', shopCategoryList=[], pageSource=10002, location=loc, cartSkuList=[]),
    }
    if loc['latitude'] is not None and loc['longitude'] is not None:
        bodies['homeShopList'] = dict(bizTraceId='', pageNo=0, pageSource=5, pageSize=20, location=loc)
    own_fp = body.get('fingerPrint') or body.get('fingerprint')
    for endpoint, value in bodies.items():
        path = PATHS[endpoint]
        if path in templates: continue
        if own_fp and endpoint in ('shopInfo', 'productList', 'productSpecifics'):
            value['fingerPrint'] = own_fp
        templates[path] = {'method': 'POST', 'url': urlunsplit(origin._replace(path=path)),
                           'headers': deepcopy(h), 'body': value}
        sources[endpoint] = 'ios-'+h['appversion']+'-br-v1' + ('/own-fingerprint' if own_fp else '/no-body-fingerprint')
    return bundle
