"""Native login context encoding, recovered from the current Keeta image.

Evidence: docs/archive/LOGIN_CONTEXT.md. These are App configuration values, not
credentials or server-issued tickets. Region must come from current state.
"""
import base64

TOKEN_PLATFORM = '5'
TOKEN_APP = '4'
APP_TOKEN_ID = 'liOhxiOHwRgAJ0303Eofeg'
ROLLBACK_CONFIG_TYPE = 'PassportOverseaRollbackSwitch_iOS'


def build_tk_context_plain(region, *, token_platform=TOKEN_PLATFORM,
                           token_app=TOKEN_APP):
    """Return the native unpadded standard Base64, or '' for missing inputs.

    The native method manually formats strings without JSON escaping. Keep
    that byte behavior, including for unusual inputs; callers should use the
    actual region/platform/App values. No region cache is simulated here.
    """
    values = (region, token_platform, token_app)
    if any(not isinstance(value, str) or not value for value in values):
        return ''
    raw = ('{"a1":"%s","a2":"%s","a3":"%s"}' % values).encode('utf-8')
    return base64.b64encode(raw).decode('ascii').replace('=', '')


def context_body_fields(region, *, disable_token_standardization=False,
                        token_platform=TOKEN_PLATFORM, token_app=TOKEN_APP):
    """Return the optional common-body field using a resolved Horn bool.

    False is the native initial/default value. A caller with current Horn
    state must pass it explicitly. This function does not fetch configuration.
    """
    if type(disable_token_standardization) is not bool:
        raise ValueError('disable_token_standardization must be bool')
    if disable_token_standardization:
        return {}
    value = build_tk_context_plain(region, token_platform=token_platform,
                                  token_app=token_app)
    return {'tk_context_plain': value} if value else {}


def context_profile_fields(profile):
    """Bind explicit SDK configuration to this session's selected region.

    A None value explicitly removes a captured common field when disabled.
    Absence of login_context_inputs leaves an explicitly supplied field alone.
    This build's explicit platform/App configuration also supplies the static
    App token ID when absent or empty; a caller's nonempty value is retained.
    """
    if 'login_context_inputs' not in profile:
        return {}
    config=profile['login_context_inputs']
    required={'disable_token_standardization','token_platform','token_app'}
    if not isinstance(config,dict) or set(config)!=required:
        raise ValueError('login_context_inputs requires resolved flag, token_platform and token_app')
    region=(profile.get('region_state') or {}).get('region',profile.get('region'))
    if not isinstance(region,str) or not region:
        raise ValueError('login context requires current region')
    if any(not isinstance(config[k],str) or not config[k] for k in ('token_platform','token_app')):
        raise ValueError('login context requires explicit platform and App values')
    fields=context_body_fields(region,**config)
    result={'tk_context_plain':fields.get('tk_context_plain')}
    if (config['token_platform']==TOKEN_PLATFORM and config['token_app']==TOKEN_APP
            and profile.get('token_id') in (None,'')):
        result['token_id']=APP_TOKEN_ID
    return result
