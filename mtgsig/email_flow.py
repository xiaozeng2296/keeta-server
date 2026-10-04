"""Resume an accepted registration through explicit email risk and code apply.

This orchestrator has no network transport or mailbox access. The caller's
transport supplies actual replies; only the current risk response chooses apply.
"""
from copy import deepcopy
import time
from urllib.parse import urlsplit

from . import login_protocol
from .login_context import context_profile_fields


def execute_email_code_flow(profile, signer, send, *, steps, clock=time.time,
                            payload_builder=None, require_signup=False):
    """Yield confirm/risk events, then one response-selected apply event.

steps contains either the current login confirm plus risk, or risk alone.
Profile requires explicit email, current device_id, decoded fingerprint and
tk_context_plain; it must come from this registration continuation. No captured
email, opaque fingerprint or ticket is sufficient. Signup credentials, if
needed, must be explicit profile inputs; they are never taken from a template.
Success means a valid apply reply with this email and serial_number, not proven
mail delivery or completed account registration.
require_signup stops on an existing/unknown account before apply or mailbox
work; only this attempt's explicit positive risk decision permits signup.
"""
    from keeta_offline_flow import execute_offline_flow

    if type(require_signup) is not bool:
        raise ValueError('require_signup must be bool')

    ordered = list(steps)
    names = [step.get('name') for step in ordered]
    if names not in (['user_risk_check'], ['confirm_protocol', 'user_risk_check']):
        raise ValueError('email continuation requires login confirm/risk, or risk only')
    if ordered[-1].get('path') != login_protocol.RISK_PATH:
        raise ValueError('last step must be the email risk endpoint')
    state = deepcopy(profile)
    try:
        context = context_profile_fields(state)
        state.update(context)
    except (TypeError,ValueError) as exc:
        yield {'name':'email_preflight','sent':False,'error':str(exc)}
        return
    required = ('email', 'device_id')
    if not (context and context['tk_context_plain'] is None):
        required += ('tk_context_plain',)
    for name in required:
        if not isinstance(state.get(name), str) or not state[name]:
            yield {'name': 'email_preflight', 'sent': False,
                   'error': 'current-session ' + name + ' is required'}
            return
    if not isinstance(state.get('fingerprint_obj'), dict):
        yield {'name': 'email_preflight', 'sent': False,
               'error': 'current-session fingerprint_obj is required'}
        return
    # A saved ticket must not bypass a new risk response in this entrypoint.
    for name in ('user_ticket', 'userTicket', 'serial_number', 'serialNumber'):
        state.pop(name, None)
    # Both native captures started risk before login consent received its 403
    # reply (new capture 627/628; old capture 800/801).  Consent reporting has
    # no response value needed by risk.  Keep its actual failure visible but
    # do not make a received HTTP failure a new prerequisite for native risk.
    if names[0] == 'confirm_protocol':
        for event in execute_offline_flow({}, state, signer, send, steps=ordered[:1],
                                         clock=clock, payload_builder=payload_builder):
            if event.get('error'):
                status = event.get('http_status')
                if event.get('sent') and type(status) is int and 100 <= status <= 599:
                    event['nonblocking'] = True
            yield event
            if event.get('error') and not event.get('nonblocking'):
                return
    risk_event = None
    for event in execute_offline_flow({}, state, signer, send, steps=ordered[-1:],
                                     clock=clock, payload_builder=payload_builder):
        if require_signup and not event.get('error'):
            event['signup_required'] = True
            decision = (event.get('response') or {}).get('data', {}).get('isSignup')
            if decision is not True and not (type(decision) is int and decision == 1):
                event['email_status'] = ('existing_account' if decision is False or
                    (type(decision) is int and decision == 0) else 'signup_not_confirmed')
                event['error'] = 'risk did not confirm a new signup account'
            else:
                event['email_status'] = 'new_account'
        yield event
        if event.get('error'):
            return
        if event['name'] == 'user_risk_check':
            risk_event = event
    if risk_event is None or not risk_event.get('login_state'):
        return
    state.update(risk_event['login_state'])
    path = (login_protocol.SIGNUP_APPLY_PATH if state['is_signup']
            else login_protocol.LOGIN_APPLY_PATH)
    request = risk_event['request']
    url = urlsplit(request['url'])
    # Retain the actual accepted regional request context, replacing its path
    # and entire model body. A copied risk email/token_id must not enter apply.
    template = {'host': url.netloc, 'path': path, 'query': url.query,
                'request': {'header': {'headers': [
                    {'name': k, 'value': v} for k, v in request['headers'].items()
                    if not k.startswith(':')]}, 'body': {'text': ''}}}
    apply = {'name': 'email_apply', 'host': url.netloc, 'path': path,
             'body_type': 'plaintext_urlencoded', 'template': template}
    yield from execute_offline_flow({}, state, signer, send, steps=[apply],
                                   clock=clock, payload_builder=payload_builder)
