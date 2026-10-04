"""Native branch cases, reload boundaries, and account-session counter isolation."""
from copy import deepcopy
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from farm.fullsign import FullSigner,decode_a5,compute_a2
from farm.mysql_import import carry_counters
from tests.test_collection_refresh import identity


def device(sequence=82,post=76,nil=0,state='unknown'):
    dev=identity();dev.update(sign_sequence=sequence,collection_clock_mode='captured',sdk_user_id_state=state)
    dev['base_collect'].update(b2=sequence,b17=post,b18=nil)
    return dev


def sign(signer,method):
    url='https://example.test/query';body='{}'
    mt=json.loads(signer.sign(method,url,body));actual=mt.pop('a2')
    col=json.loads(decode_a5(mt['a5'],mt['a1'],mt['a3'],mt['a4'])[0])
    expected=compute_a2(method,url,body,json.dumps(mt,separators=(',',':')),mt['a1'],signer.signature_counter,
                        signing_profile=signer.signing_profile,sign_sequence=col['b2'])
    if actual!=expected:raise AssertionError('full a2 does not match native-width counters')
    return col


class NativeSigningCountersTests(unittest.TestCase):
    def test_native_method_and_user_state_cases(self):
        # Expected deltas from isolated native ARM64 branch execution.
        for method,state,expected in [('POST','non_nil',(11,11,10)),('GET','non_nil',(11,10,10)),
                                      ('post','non_nil',(11,11,10)),('POST','nil',(11,11,11)),
                                      ('GET','nil',(11,10,11)),('DELETE','nil',(11,10,11)),
                                      ('POST','unknown',(11,11,10))]:
            with self.subTest(method=method,state=state):
                col=sign(FullSigner(device(10,10,10,state)),method)
                self.assertEqual(tuple(col[k] for k in ('b2','b17','b18')),expected)

    def test_get_and_post_mix_survives_reload_without_changing_capture(self):
        dev=device();original=deepcopy(dev['base_collect']);signer=FullSigner(dev)
        for method,expected in [('GET',(83,76,0)),('POST',(84,77,0)),('GET',(85,77,0)),('POST',(86,78,0))]:
            col=sign(signer,method)
            self.assertEqual(tuple(col[k] for k in ('b2','b17','b18')),expected)
            saved=signer.persist_counter();self.assertEqual(saved['base_collect'],original)
            signer=FullSigner(json.loads(json.dumps(saved)))

    def test_wire_counters_wrap_without_rolling_back_local_totals(self):
        signer=FullSigner(device(0xffffffff,0xffffffff,0xffffffff,'nil'))
        col=sign(signer,'POST')
        self.assertEqual(tuple(col[k] for k in ('b2','b17','b18')),(0,0,0))
        saved=signer.persist_counter()
        self.assertEqual(saved['sign_sequence'],0x100000000)
        self.assertEqual(saved['post_sign_count'],0x100000000)
        self.assertEqual(saved['nil_user_sign_count'],0x100000000)
        col=sign(FullSigner(saved),'GET')
        self.assertEqual(tuple(col[k] for k in ('b2','b17','b18')),(1,0,1))

    def test_failed_sign_preserves_consumed_pre_sign_counters(self):
        signer=FullSigner(device())
        with patch.object(signer,'_fresh_a5',side_effect=ValueError('synthetic failure')):
            with self.assertRaises(ValueError):signer.sign('POST','https://example.test/query','{}')
        col=sign(FullSigner(signer.persist_counter()),'GET')
        self.assertEqual(tuple(col[k] for k in ('b2','b17','b18')),(84,77,0))

    def test_legacy_migration_preserves_last_generated_counts(self):
        dev=device(10,9,10);dev['sign_sequence']=100
        col=sign(FullSigner(dev),'GET')
        self.assertEqual(tuple(col[k] for k in ('b2','b17','b18')),(101,99,100))
        dev=device(82,76,0);dev['sign_sequence']=100
        col=sign(FullSigner(dev),'POST')
        self.assertEqual(tuple(col[k] for k in ('b2','b17','b18')),(101,77,0))

    def test_same_session_reimport_carries_independent_counters(self):
        old={'request':{'headers':{'appsession':'same'}},'device':device()}
        old['device'].update(sign_sequence=120,post_sign_count=100,nil_user_sign_count=12)
        incoming={'request':{'headers':{'appsession':'same'}},'device':device()}
        carry_counters(incoming,old)
        self.assertEqual(incoming['device']['post_sign_count'],100)
        self.assertEqual(incoming['device']['nil_user_sign_count'],12)
        col=sign(FullSigner(incoming['device']),'GET')
        self.assertEqual(tuple(col[k] for k in ('b2','b17','b18')),(121,100,12))
        other={'request':{'headers':{'appsession':'new'}},'device':device()};before=deepcopy(other)
        carry_counters(other,old);self.assertEqual(other,before)

    def test_explicit_unknown_or_invalid_sdk_user_state_is_not_inferred_from_token(self):
        dev=device(0,0,0);dev['token']='SYNTHETIC-LOGIN'
        self.assertEqual(sign(FullSigner(dev),'POST')['b18'],0)
        dev['sdk_user_id_state']='logged_in'
        with self.assertRaises(ValueError):FullSigner(dev)


if __name__=='__main__':unittest.main()
