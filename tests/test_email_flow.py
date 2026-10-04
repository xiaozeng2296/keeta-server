"""Full offline signer and controlled risk/apply replies; no network or mail."""
import base64
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qsl, urlsplit

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from farm.fullsign import FullSigner, decode_a5, compute_a2
from keeta_offline_flow import execute_offline_flow
from mtgsig import a9_codec, login_protocol as p, mtg_crypto
from mtgsig.email_flow import execute_email_code_flow


class EmailFlowTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        target = Path(temp.name) / 'identity.json'
        a1 = '00112233-4455-6677-8899-aabbccddeeff'
        target.write_text(json.dumps(dict(a0='2.5', a1=a1, a3=25, a6=0,
            a7='CURRENT-XID', a8='CURRENT-DFP', x0=2,
            a9=a9_codec.encode('{"0":12,"1":[],"2":[],"3":{}}', a1),
            base_collect={'b1':'{}','b2':10,'b3':0}, counter=10)))
        self.signer=FullSigner(target)
        self.profile={'email':'current@example.test','device_id':'CURRENT-IDFA',
            'idfv':'CURRENT-IDFV','csecuuid':'CURRENT-UUID','tk_context_plain':'CURRENT-CONTEXT',
            'fingerprint_obj':{'I18':'old','I20':'old','I39':'0','I40':'old'},
            'user_ticket':'HISTORICAL-TICKET','serial_number':'HISTORICAL-SERIAL'}
        self.risk={'name':'user_risk_check','host':'passport.example.test','path':p.RISK_PATH,
            'body_type':'plaintext_urlencoded','template':{'host':'passport.example.test',
                'path':p.RISK_PATH,'query':'uuid=OLD&region=HK',
                'request':{'header':{'headers':[{'name':'mtgsig','value':'OLD'}]},
                    'body':{'text':'email=old%40example.test&fingerprint=OLD&tk_context_plain=OLD&token_id='}}}}
        self.sent=[]
        guard=patch('socket.socket',side_effect=AssertionError('network forbidden'))
        guard.start();self.addCleanup(guard.stop)

    def run_flow(self,replies,profile=None,*,require_signup=False):
        ticks=iter([1700000001.0,1700000002.0])
        def send(req):
            self.sent.append(deepcopy(req))
            return replies[len(self.sent)-1]
        return list(execute_email_code_flow(self.profile if profile is None else profile,
            self.signer,send,steps=[self.risk],clock=lambda:next(ticks),require_signup=require_signup))

    def test_signup_requirement_stops_before_apply_on_existing_or_unknown_account(self):
        for decision, label in ((False,'existing_account'),(0,'existing_account'),(None,'signup_not_confirmed')):
            self.sent=[]
            data={'userTicket':'CURRENT'}
            if decision is not None:
                data['isSignup']=decision
            before=self.signer.counter
            with self.subTest(decision=decision):
                event,=self.run_flow([(200,{'data':data})],require_signup=True)
                self.assertEqual(event['email_status'],label)
                self.assertTrue(event['signup_required'])
                self.assertIn('error',event)
                self.assertEqual(len(self.sent),1)
                self.assertEqual(self.signer.counter,before+1)

    def test_signup_requirement_allows_current_positive_risk_decision(self):
        events=self.run_flow([(200,{'data':{'userTicket':'CURRENT','isSignup':True}}),
            (200,{'data':{'email':'current@example.test','serialNumber':'S'}})],require_signup=True)
        self.assertEqual(len(self.sent),2)
        self.assertEqual(events[0]['email_status'],'new_account')
        self.assertNotIn('error',events[-1])
        self.assertEqual(urlsplit(self.sent[1]['url']).path,p.SIGNUP_APPLY_PATH)

    def test_current_risk_selects_apply_and_both_requests_refresh_fingerprint(self):
        for signup in (False,True):
            with self.subTest(signup=signup):
                self.sent=[]
                events=self.run_flow([(200,{'code':0,'data':{'userTicket':'FRESH','isSignup':signup}}),
                    (200,{'code':0,'data':{'email':'current@example.test','serialNumber':'FRESH-SERIAL'}})])
                self.assertTrue(all('error' not in event for event in events),events)
                self.assertEqual(events[-1]['login_state']['serial_number'],'FRESH-SERIAL')
                self.assertEqual(urlsplit(self.sent[1]['url']).path,
                                 p.SIGNUP_APPLY_PATH if signup else p.LOGIN_APPLY_PATH)
                for i,req in enumerate(self.sent):
                    fields=dict(parse_qsl(req['body'],keep_blank_values=True))
                    self.assertEqual(fields['device_id'],'CURRENT-IDFA')
                    self.assertEqual(fields['tk_context_plain'],'CURRENT-CONTEXT')
                    blob=base64.b64decode(fields['fingerprint'])
                    fp=json.loads(unpad(AES.new(mtg_crypto.FINGERPRINT_I_KEY,AES.MODE_CBC,
                        mtg_crypto.FINGERPRINT_IV).decrypt(blob),16))
                    self.assertEqual(fp['I39'],str((1700000001+i)*1000))
                    self.assertEqual((fp['I18'],fp['I20'],fp['I40']),
                                     ('CURRENT-IDFA','CURRENT-IDFV','CURRENT-UUID'))
                    mt=json.loads(req['headers']['mtgsig']);actual=mt.pop('a2')
                    plain,_=decode_a5(mt['a5'],mt['a1'],mt['a3'],mt['a4'],profile=self.signer.signing_profile)
                    expected=compute_a2('POST',req['url'],req['body'],json.dumps(mt,separators=(',',':')),
                        mt['a1'],int(mt['a10'].split(',')[1]),sign_sequence=json.loads(plain)['b2'],
                        signing_profile=self.signer.signing_profile)
                    self.assertEqual(actual,expected)
                apply=dict(parse_qsl(self.sent[1]['body'],keep_blank_values=True))
                self.assertEqual(apply['user_ticket'],'FRESH')
                self.assertNotIn('email',apply)
                self.assertNotIn('token_id',apply)
                self.assertNotIn('serial_number',apply)
                if signup:
                    self.assertEqual((apply['username'], apply['password']), ('', ''))
                else:
                    self.assertNotIn('username', apply)
                    self.assertNotIn('password', apply)
                self.assertEqual(self.profile['user_ticket'],'HISTORICAL-TICKET')

    def test_failure_does_not_reuse_saved_ticket_or_send_apply(self):
        events=self.run_flow([(200,{'code':101135,'data':{'nested':{'userTicket':'FAKE'}}})])
        self.assertEqual(len(self.sent),1)
        self.assertIn('error',events[-1])

    def test_missing_session_inputs_stop_before_counter_or_network(self):
        for key in ('email','device_id','tk_context_plain','fingerprint_obj'):
            state=dict(self.profile);state.pop(key)
            before=self.signer.counter
            events=self.run_flow([],profile=state)
            self.assertFalse(events[0]['sent'])
            self.assertIn(key,events[0]['error'])
            self.assertEqual(self.signer.counter,before)
        self.assertFalse(self.sent)

    def test_apply_response_for_different_email_is_not_success(self):
        events=self.run_flow([(200,{'data':{'userTicket':'FRESH'}}),
                             (200,{'data':{'email':'different@example.test','serialNumber':'S'}})])
        self.assertEqual(len(self.sent),2)
        self.assertIn('error',events[-1])
        self.assertNotIn('login_state',events[-1])

    def test_context_comes_from_current_region_and_resolved_switch(self):
        from mtgsig.login_context import build_tk_context_plain
        for disabled in (False,True):
            self.sent=[]
            state=dict(self.profile,region='HK',login_context_inputs={
                'disable_token_standardization':disabled,'token_platform':'5','token_app':'4'})
            events=self.run_flow([(200,{'data':{'userTicket':'FRESH'}}),
                (200,{'data':{'email':'current@example.test','serialNumber':'S'}})],profile=state)
            self.assertTrue(all('error' not in e for e in events),events)
            for request in self.sent:
                fields=dict(parse_qsl(request['body'],keep_blank_values=True))
                if disabled:
                    self.assertNotIn('tk_context_plain',fields)
                else:
                    self.assertEqual(fields['tk_context_plain'],build_tk_context_plain('HK'))

    def confirm_step(self):
        step = deepcopy(self.risk)
        step.update(name='confirm_protocol', path='/api/protocolcenter/v1/protocol/confirmProtocol')
        step['template']['path'] = step['path']
        step['template']['request']['body']['text'] = 'placementId=login_register&action=2&email='
        return step

    def test_failed_confirm_http_response_is_nonblocking_for_native_risk(self):
        for status in (403, 418):
            with self.subTest(status=status):
                self.sent = []
                before = self.signer.counter
                replies = [(status, {'error': 'confirm rejected'}),
                           (200, {'data': {'userTicket': 'CURRENT'}}),
                           (200, {'data': {'email': 'current@example.test', 'serialNumber': 'S'}})]
                def send(request):
                    self.sent.append(request)
                    return replies[len(self.sent) - 1]
                events = list(execute_email_code_flow(self.profile, self.signer, send,
                    steps=[self.confirm_step(), self.risk], clock=lambda: 1700000010.0))
                self.assertEqual([e['name'] for e in events],
                                 ['confirm_protocol', 'user_risk_check', 'email_apply'])
                self.assertTrue(events[0]['nonblocking'])
                self.assertIn('error', events[0])
                self.assertNotIn('error', events[-1])
                self.assertEqual(self.signer.counter, before + 3)

    def test_confirm_transport_or_construction_failure_does_not_continue(self):
        for construct in (False, True):
            with self.subTest(construct=construct):
                calls = []
                def send(request):
                    calls.append(request)
                    raise OSError('connection unavailable')
                def payload_builder(step, state, timestamp):
                    if construct:
                        raise ValueError('invalid consent inputs')
                    return state
                before = self.signer.counter
                events = list(execute_email_code_flow(self.profile, self.signer, send,
                    steps=[self.confirm_step(), self.risk], clock=lambda: 1700000010.0,
                    payload_builder=payload_builder))
                self.assertEqual(len(events), 1)
                self.assertEqual(events[0]['name'], 'confirm_protocol')
                self.assertIn('error', events[0])
                self.assertNotIn('nonblocking', events[0])
                self.assertEqual(len(calls), 0 if construct else 1)
                self.assertEqual(self.signer.counter, before + (0 if construct else 1))

    def test_submit_rebuilds_current_form_and_signs_new_fingerprint_for_both_branches(self):
        for signup in (False, True):
            with self.subTest(signup=signup):
                self.sent = []
                step = deepcopy(self.risk)
                step.update(name='email_submit', path=p.SIGNUP_PATH if signup else p.LOGIN_PATH)
                step['template']['path'] = step['path']
                step['template']['request']['body']['text'] = (
                    'user_ticket=OLD&email_code=000000&serial_number=OLD&username=OLD&'
                    'password=OLD&request_code=OLD&response_code=OLD&email=old%40example.test')
                state = dict(self.profile, user_ticket='CURRENT-TICKET', serial_number='CURRENT-SERIAL',
                    email_code='728461', request_code='CURRENT-REQUEST', response_code='CURRENT-RESPONSE',
                    username='Current User', encrypted_password='CURRENT-RSA+/=')
                before = self.signer.counter

                def send(request):
                    self.sent.append(deepcopy(request))
                    return 200, {'user': {'token': 'CURRENT-ACCOUNT-TOKEN', 'id': 123,
                                         'idStr': '123', 'email': 'current@example.test'}}

                events = list(execute_offline_flow({}, state, self.signer, send, steps=[step],
                    clock=lambda: 1700000010.0))
                self.assertEqual(len(events), 1)
                self.assertNotIn('error', events[0])
                self.assertEqual(events[0]['account_state'], {
                    'token': 'CURRENT-ACCOUNT-TOKEN', 'user_id': '123',
                    'email': 'current@example.test'})
                self.assertNotIn('token', self.signer.dev)
                self.assertNotIn('user_id', self.signer.dev)
                self.assertEqual(self.signer.counter, before + 1)
                request = self.sent[0]
                fields = dict(parse_qsl(request['body'], keep_blank_values=True))
                self.assertEqual((fields['user_ticket'], fields['serial_number'], fields['email_code']),
                                 ('CURRENT-TICKET', 'CURRENT-SERIAL', '728461'))
                self.assertNotIn('email', fields)
                self.assertNotIn('token_id', fields)
                if signup:
                    self.assertEqual((fields['username'], fields['password']),
                                     ('Current User', 'CURRENT-RSA+/='))
                    self.assertNotIn('request_code', fields)
                    self.assertNotIn('response_code', fields)
                else:
                    self.assertEqual((fields['request_code'], fields['response_code']),
                                     ('CURRENT-REQUEST', 'CURRENT-RESPONSE'))
                    self.assertNotIn('username', fields)
                    self.assertNotIn('password', fields)
                fp = json.loads(unpad(AES.new(mtg_crypto.FINGERPRINT_I_KEY, AES.MODE_CBC,
                    mtg_crypto.FINGERPRINT_IV).decrypt(base64.b64decode(fields['fingerprint'])), 16))
                self.assertEqual((fp['I18'], fp['I20'], fp['I40'], fp['I39']),
                                 ('CURRENT-IDFA', 'CURRENT-IDFV', 'CURRENT-UUID', '1700000010000'))
                mt = json.loads(request['headers']['mtgsig'])
                actual = mt.pop('a2')
                self.assertEqual(actual, compute_a2('POST', request['url'], request['body'],
                    json.dumps(mt, separators=(',', ':')), mt['a1'], int(mt['a10'].split(',')[1]),
                    sign_sequence=before + 1, signing_profile=self.signer.signing_profile))

    def test_submit_rejects_false_success_and_account_mismatch(self):
        replies = [
            (200, {'code': 0, 'data': {'accepted': True}}),
            (200, {'user': {'token': 'T', 'id': 123, 'email': 'other@example.test'}}),
            (200, {'user': {'token': 'T', 'id': 123, 'idStr': '124',
                            'email': 'current@example.test'}}),
            (403, {'user': {'token': 'T', 'id': 123, 'email': 'current@example.test'}}),
        ]
        step = deepcopy(self.risk)
        step.update(name='email_submit', path=p.SIGNUP_PATH)
        step['template']['path'] = step['path']
        for reply in replies:
            with self.subTest(reply=reply):
                state = dict(self.profile, user_ticket='CURRENT', serial_number='SERIAL',
                             email_code='1234')
                event, = execute_offline_flow({}, state, self.signer, lambda _: reply,
                                              steps=[step], clock=lambda: 1700000010.0)
                self.assertIn('error', event)
                self.assertNotIn('account_state', event)
                self.assertNotIn('token', self.signer.dev)

    def test_submit_missing_current_state_never_inherits_template_or_consumes_sequence(self):
        for path in (p.LOGIN_PATH, p.SIGNUP_PATH):
            for missing in ('user_ticket', 'serial_number', 'email_code'):
                with self.subTest(path=path, missing=missing):
                    state = dict(self.profile, user_ticket='CURRENT-TICKET',
                        serial_number='CURRENT-SERIAL', email_code='728461')
                    state.pop(missing)
                    step = deepcopy(self.risk)
                    step.update(name='email_submit', path=path)
                    step['template']['path'] = path
                    step['template']['request']['body']['text'] = (
                        'user_ticket=OLD&serial_number=OLD&email_code=000000')
                    before = self.signer.counter
                    def forbidden(request):
                        self.fail('incomplete verification state reached transport')
                    events = list(execute_offline_flow({}, state, self.signer, forbidden,
                        steps=[step], clock=lambda: 1700000010.0))
                    self.assertEqual(len(events), 1)
                    self.assertFalse(events[0]['sent'])
                    self.assertIn('error', events[0])
                    self.assertEqual(self.signer.counter, before)


if __name__=='__main__':
    unittest.main()
