"""Keeta email request fields recovered from the shipped ObjC model methods.

This module builds unsigned form bodies and validates named response paths.
It does not send requests, fetch mailbox codes, or invent server tickets.
Evidence and limitations: docs/archive/LOGIN_PROTOCOL_STATIC.md.
"""
import base64
from collections.abc import Mapping
from urllib.parse import urlencode

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

RISK_PATH = '/api/emaillogin/v1/userriskcheck'
SIGNUP_APPLY_PATH = '/api/emaillogin/v1/emailsignupapply'
LOGIN_APPLY_PATH = '/api/emaillogin/v1/emailloginapply'
SIGNUP_PATH = '/api/emaillogin/v1/emailsignup'
LOGIN_PATH = '/api/emaillogin/v1/emaillogin'
FORM_CONTENT_TYPE = 'application/x-www-form-urlencoded; charset=utf-8'

# Public SPKI at Keeta.dec RVA 0x431f420; deliberately not an A-envelope key.
LOGIN_PUBLIC_KEY_B64 = (
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyiOk5fvW+XraeRIsoKuFFXEB'
    'ILN72h1msHHidReW9hced1ZK2OymtBAtK5Zz6agsXl/zrtB4eNJNlAbcaDjv2dI4'
    'HxlsE/3zDdwcPFToH0aFbdNp8UzWgOEEW5CH6iedFJkCVYsXq/hRJKLGVl11C+C4'
    'CVWKe5OYWUyvF2XoYBggwXhlKNHBPPtESG/iXUW6U75Sb2d09spUA10cO1nrJwJXj'
    'sDvz1NVtLEd6KFf4fez5zsHD1FipuCI++qeeV8PPsaIiQUxnIVlh5B5W7NMYzNsj5dc'
    'A4Cp2wpe1UUW/v9GMWpAkGicfeZrhKSz21XSTZuLeH0Sag5ZED6WEnycfQIDAQAB'
)


def _text(value, field, *, nonempty=False):
    if not isinstance(value, str) or (nonempty and not value):
        raise ValueError(f'{field} must be ' + ('nonempty text' if nonempty else 'text'))
    return value


def encrypt_password(password, *, public_key=None, randfunc=None):
    """UTF-8 -> RSA PKCS#1 v1.5 chunks -> concatenation -> ordinary base64.

    The native NSData loop uses RSA_size-11 bytes per chunk (245 for its
    2048-bit public key). Empty NSString yields empty output; None models a
    missing ObjC value and remains None, so a safe-set caller omits the field.
    randfunc/public_key exist for reproducible synthetic validation only.
    """
    if password is None:
        return None
    raw = _text(password, 'password').encode('utf-8')
    key = RSA.import_key(public_key if public_key is not None else base64.b64decode(LOGIN_PUBLIC_KEY_B64))
    cipher = PKCS1_v1_5.new(key.public_key(), randfunc=randfunc)
    chunk = key.size_in_bytes() - 11
    return base64.b64encode(b''.join(cipher.encrypt(raw[i:i+chunk])
                                   for i in range(0, len(raw), chunk))).decode('ascii')


def _add_common(fields, common):
    if common is None:
        return fields
    if not isinstance(common, Mapping):
        raise TypeError('common body values must be an object')
    # SAKBaseModel derives device_id from advertisingIdentifier, not IDFV.
    # fingerprint is added later by its corpse/common body assembly path.
    if common.get('device_id') is not None:
        fields['device_id'] = _text(common['device_id'], 'device_id')
        fields['device_type'] = '3'
    for key in ('tk_context_plain', 'fingerprint'):
        if common.get(key) is not None:
            fields[key] = _text(common[key], key)
    return fields


def risk_fields(email, *, request_code=None, response_code=None, token_id='', common=None):
    fields = {'email': _text(email, 'email', nonempty=True)}
    for key, value in (('request_code', request_code), ('response_code', response_code)):
        if value is not None:
            fields[key] = _text(value, key)
    fields['token_id'] = '' if token_id is None else _text(token_id, 'token_id')
    return _add_common(fields, common)


def apply_fields(user_ticket, *, signup=False, username=None, password=None,
                 encrypted_password=None, common=None):
    """Model-layer apply fields. Signup adds username and RSA password.

    Email, email_code, serial_number and captcha results are not apply model
    fields in this build. Passing encrypted_password supports known native
    captures without re-randomizing RSA; do not supply both password forms.
    """
    if type(signup) is not bool:
        raise ValueError('signup must be bool')
    fields = {'user_ticket': _text(user_ticket, 'user_ticket', nonempty=True)}
    if not signup and any(v is not None for v in (username, password, encrypted_password)):
        raise ValueError('login apply has no username or password fields')
    if password is not None and encrypted_password is not None:
        raise ValueError('supply plaintext password or encrypted_password, not both')
    if signup:
        if username is not None:
            fields['username'] = _text(username, 'username')
        encoded = encrypted_password if encrypted_password is not None else encrypt_password(password)
        if encoded is not None:
            fields['password'] = _text(encoded, 'encrypted_password')
    return _add_common(fields, common)


def submit_fields(user_ticket, email_code, serial_number, *, signup=False,
                  username=None, password=None, encrypted_password=None,
                  request_code=None, response_code=None, common=None):
    """Exact verify model fields; challenge results belong to login only."""
    fields = apply_fields(user_ticket, signup=signup, username=username,
                          password=password, encrypted_password=encrypted_password)
    fields['email_code'] = _text(email_code, 'email_code', nonempty=True)
    fields['serial_number'] = _text(serial_number, 'serial_number', nonempty=True)
    if not signup:
        for key, value in (('request_code', request_code), ('response_code', response_code)):
            if value is not None:
                fields[key] = _text(value, key)
    return _add_common(fields, common)


def build_submit_body(user_ticket, email_code, serial_number, **kwargs):
    return urlencode(sorted(submit_fields(user_ticket, email_code, serial_number, **kwargs).items()))


def build_risk_body(email, **kwargs):
    return urlencode(sorted(risk_fields(email, **kwargs).items()))


def build_apply_body(user_ticket, **kwargs):
    return urlencode(sorted(apply_fields(user_ticket, **kwargs).items()))


def passport_headers(original=None, *, incog_token=None, incog_account_id=None,
                     include_net_flag=True):
    """Copy caller's current headers, set passport additions, remove stale mtgsig.

    Global SDK/device headers remain caller inputs, as their generators are
    separate from these ObjC request constructors. Sign the final URL/body
    after this operation. Horn switches determine which additions native uses.
    """
    headers = {k: v for k, v in (original or {}).items()
               if k.lower() not in ('content-type', 'content-length', 'mtgsig', 'host')
               and (include_net_flag or k.lower() != 'sailor-net-flag')}
    headers['Content-Type'] = FORM_CONTENT_TYPE
    additions = {'sailor-net-flag': 'MTPT.Passport' if include_net_flag else None,
                 'incog-token': incog_token, 'incog-accountid': incog_account_id}
    for name, value in additions.items():
        if value is not None:
            matching = next((k for k in headers if k.lower() == name), name)
            headers[matching] = _text(value, name)
    return headers


def _successful_response(response, http_status):
    """Shared HTTP and explicit failure gates, independent of payload shape."""
    if type(http_status) is not int or not 200 <= http_status < 300:
        return False
    if not isinstance(response, Mapping) or response.get('error'):
        return False
    if 'success' in response and response['success'] is not True:
        return False
    # Native callbacks use data/error objects, not a mandatory code=0.
    # Refuse explicit failures when a gateway supplies an additional code.
    if 'code' in response and not (type(response['code']) is int and response['code'] == 0):
        return False
    return True


def _success_data(response, http_status):
    if not _successful_response(response, http_status):
        return None
    data = response.get('data')
    return data if isinstance(data, Mapping) else None


def parse_risk_response(response, *, http_status):
    """Exact data.userTicket/isSignup/isNormal/hasPassword; no recursive search.

    Optional absent bool properties have ObjC's false default. isNormal is
    stored metadata, not the manager's condition for refusing a valid ticket.
    """
    data = _success_data(response, http_status)
    if data is None or not isinstance(data.get('userTicket'), str) or not data['userTicket']:
        return {}
    result = {'user_ticket': data['userTicket']}
    for wire, field in (('isSignup', 'is_signup'), ('isNormal', 'is_normal'), ('hasPassword', 'has_password')):
        value = data.get(wire, False)
        if type(value) is not bool and not (type(value) is int and value in (0, 1)):
            return {}
        result[field] = bool(value)
    return result


def _response_email_state(email, expected_email):
    """Keep the real recipient; recognize only the captured display mask.

    local[:3] + '***' + '@' + domain is a display-compatible comparison,
    never a unique account identity proof. The caller must bind it to this
    attempt's risk ticket and apply serial, and retain the actual recipient.
    """
    if not isinstance(email, str) or not email.strip():
        return {}
    display = email.strip()
    if expected_email is None:
        return {'email': display}
    if not isinstance(expected_email, str):
        return {}
    expected = expected_email.strip()
    if (expected.count('@') != 1 or '*' in expected
            or any(char.isspace() for char in expected)):
        return {}
    local, domain = expected.split('@')
    if not local or not domain:
        return {}
    if display.casefold() == expected.casefold():
        return {'email': expected}
    masked = local[:3] + '***@' + domain
    if len(local) > 3 and display.casefold() == masked.casefold():
        return {'email': expected, 'display_email': display, 'email_match': 'masked'}
    return {}


def parse_apply_response(response, *, http_status, expected_email=None):
    """Require data.email and data.serialNumber to advance to verification.

    Native isNSStringNotNull checks string type only. This adapter additionally
    rejects empty strings so a claimed send cannot advance without usable state.
    A bound caller retains expected_email even when data.email is the observed
    three-character-prefix display mask; it must not read mail from the mask.
    """
    data = _success_data(response, http_status)
    if data is None or any(not isinstance(data.get(k), str) or not data[k]
                           for k in ('email', 'serialNumber')):
        return {}
    email_state = _response_email_state(data['email'], expected_email)
    if not email_state:
        return {}
    return dict(email_state, serial_number=data['serialNumber'])


def parse_submit_response(response, *, http_status, expected_email=None):
    """Accept the observed top-level user account returned by code submission.

    Signup returns user.token/id/idStr/email rather than a data object. Do not
    accept token lookalikes elsewhere or a bare loginAccepted flag. The observed
    display email mask is accepted only as a compatible display, with explicit
    metadata; current risk-ticket/serial/code linkage must identify the attempt.
    IDs are normalized to decimal strings; bool is not an integer ID. Optional
    regional state comes only from this same user object.
    """
    if not _successful_response(response, http_status):
        return {}
    user = response.get('user')
    if not isinstance(user, Mapping):
        return {}
    token, email = user.get('token'), user.get('email')
    if not isinstance(token, str) or not token.strip():
        return {}
    email_state = _response_email_state(email, expected_email)
    if not email_state:
        return {}
    ids = []
    if 'id' in user:
        if type(user['id']) is not int or user['id'] <= 0:
            return {}
        ids.append(str(user['id']))
    if 'idStr' in user:
        value = user['idStr']
        if (not isinstance(value, str) or not value.isascii()
                or not value.isdecimal()):
            return {}
        value = value.lstrip('0')
        if not value:
            return {}
        ids.append(value)
    if not ids or any(value != ids[0] for value in ids[1:]):
        return {}
    result = dict(email_state, token=token, user_id=ids[0])
    for wire, field in (('registerRegion', 'register_region'), ('tkContext', 'tk_context')):
        if wire in user:
            if not isinstance(user[wire], str):
                return {}
            if user[wire]:
                result[field] = user[wire]
    return result
