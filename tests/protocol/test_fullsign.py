import json
import os
import tempfile
import unittest
from collections import OrderedDict

from mtgsig.signer import FullSigner, k2buf, provision_identity
from mtgsig import a9_codec, mtg_crypto


class FullSignerA9Tests(unittest.TestCase):
    def test_provision_detects_a9_profile_and_regenerates_it(self):
        a1 = "00112233-4455-6677-8899-aabbccddeeff"
        a3, a4 = 25, 1700000000
        collect = OrderedDict((
            ("b1", "{}"), ("b2", 1), ("b3", 1),
            ("b4", "com.sankuai.sailor.ifooddelivery"),
            ("b5", "3.12.401"), ("b7", a4), ("b8", a4),
        ))
        collect_bytes = json.dumps(collect, separators=(",", ":")).encode()
        a5 = mtg_crypto.a5_encrypt(collect_bytes, a1, a3, a4, k2buf(a1))
        siua = json.dumps({"0": 12, "1": ["synthetic"], "2": ["x"], "3": "{}"},
                          separators=(",", ":"))
        a9 = a9_codec.encode(siua, a1, mode="twofish-mod")
        sample = {"mtgsig": OrderedDict(
            a0="2.5", a1=a1, a3=a3, a4=a4, a5=a5, a6=0,
            a7="synthetic-dfp-xid", a8="synthetic-dfp-id", a9=a9,
            a10="3,1", x0=2, a2="0" * 32)}

        sample_path = identity_path = None
        try:
            sample_fd, sample_path = tempfile.mkstemp(suffix=".json")
            os.close(sample_fd)
            identity_fd, identity_path = tempfile.mkstemp(suffix=".json")
            os.close(identity_fd)
            with open(sample_path, "w", encoding="utf-8") as fh:
                json.dump(sample, fh)
            provisioned = provision_identity(sample_path, identity_path)
            self.assertEqual(provisioned["a9_profile"], "default")
            self.assertEqual(provisioned["a9_mode"], "twofish-mod")
            self.assertEqual(provisioned["base_siua"], siua)

            signer = FullSigner(identity_path)
            self.assertEqual(signer.a9, a9)
            mt = json.loads(signer.sign("POST", "https://example.test/path", "{}"))
            self.assertNotEqual(mt["a5"], a5)
            decoded = mtg_crypto.a5_decrypt(
                mt["a5"], a1, a3, mt["a4"], k2buf(a1))
            self.assertEqual(json.loads(decoded)["b2"], 2)
            self.assertEqual(json.loads(decoded)["b3"], 1)
            self.assertEqual(mt["a10"], "3,1")
            self.assertEqual(len(mt["a2"]), 32)
        finally:
            for path in (sample_path, identity_path):
                if path:
                    try:
                        os.unlink(path)
                    except FileNotFoundError:
                        pass

    def test_registration_values_override_stage_one_local_a7_a8(self):
        """The first mtgsig may precede xid/dfp responses from registration."""
        a1 = "00112233-4455-6677-8899-aabbccddeeff"
        a3, a4 = 25, 1700000000
        collect = OrderedDict((
            ("b1", "{}"), ("b2", 1), ("b3", 1),
            ("b4", "com.sankuai.sailor.ifooddelivery"),
            ("b5", "3.12.401"), ("b7", a4), ("b8", a4),
        ))
        raw = json.dumps(collect, separators=(",", ":")).encode()
        a5 = mtg_crypto.a5_encrypt(raw, a1, a3, a4, k2buf(a1))
        siua = json.dumps({"0": 12, "1": ["synthetic"], "2": [], "3": {}},
                          separators=(",", ":"))
        a9 = a9_codec.encode(siua, a1, mode="twofish-mod")
        sample = {"mtgsig": OrderedDict(
            a0="2.5", a1=a1, a3=a3, a4=a4, a5=a5, a6=0,
            a7="LOCAL-XID", a8="LOCAL-DFP-ID", a9=a9,
            a10="3,1", x0=2, a2="0" * 32),
            # These correspond to fingerprint/info report and v5/sign
            # response bodies; they are deliberately different from the
            # first request's local values.
            "registration": {"xid": "SERVER-XID", "dfp": "SERVER-DFP"}}
        sample_path = identity_path = None
        try:
            fd, sample_path = tempfile.mkstemp(suffix=".json"); os.close(fd)
            fd, identity_path = tempfile.mkstemp(suffix=".json"); os.close(fd)
            with open(sample_path, "w", encoding="utf-8") as fh:
                json.dump(sample, fh)
            provisioned = provision_identity(sample_path, identity_path)
            self.assertEqual(provisioned["a7_local_xid"], "LOCAL-XID")
            self.assertEqual(provisioned["a8_local_dfp"], "LOCAL-DFP-ID")
            self.assertEqual(provisioned["a7_server_xid"], "SERVER-XID")
            self.assertEqual(provisioned["a8_server_dfp"], "SERVER-DFP")
            signer = FullSigner(identity_path)
            mt = json.loads(signer.sign("POST", "https://example.test/path", "{}"))
            self.assertEqual(mt["a7"], "SERVER-XID")
            self.assertEqual(mt["a8"], "SERVER-DFP")
        finally:
            for path in (sample_path, identity_path):
                if path:
                    try:
                        os.unlink(path)
                    except FileNotFoundError:
                        pass


class RenderB16Tests(unittest.TestCase):
    def device(self,profile,value):
        from tests.protocol.test_signing_profiles import SigningProfileTests,COLLECT
        from mtgsig import signer as fs
        sample=SigningProfileTests().sample(profile)
        sample['a5']=mtg_crypto.a5_encrypt(json.dumps(dict(COLLECT,b16=value),separators=(',',':')).encode(),
            sample['a1'],sample['a3'],sample['a4'],fs.k2buf(sample['a1'],profile))
        return fs.provision_identity({'mtgsig':sample})

    def test_shared_signer_matches_previous_validated_override_for_both_profiles(self):
        from copy import deepcopy
        from unittest.mock import patch
        from mtgsig import signer as fs
        import requests
        before='[0,0,0],[3,3600,3604],[0,24,26],1'
        after='[0,0,0],[3,3600,3604],[1,24,26],1'
        wire=requests.Request('POST','https://example.test/api/v1/shop/product/render?ci=3&x=a%2Fb',
                              data=b'{"shopId":"7","shopCategoryList":[{"shopCategoryId":8,"spuIdList":[9]}]}').prepare()
        for profile in ('default','legacy'):
            with self.subTest(profile=profile):
                dev=self.device(profile,before);original=deepcopy(dev)
                baseline_signer=FullSigner(dev);signer=FullSigner(dev)
                with patch('mtgsig.signer.time.time',return_value=1700000100),patch('mtgsig.signer.render_b16',side_effect=lambda v:v):
                    baseline=json.loads(baseline_signer.sign(wire.method,wire.url,wire.body.decode()))
                with patch('mtgsig.signer.time.time',return_value=1700000100):
                    actual=json.loads(signer.sign(wire.method,wire.url,wire.body.decode()))
                col=json.loads(fs.decode_a5(baseline['a5'],baseline['a1'],baseline['a3'],baseline['a4'],profile=profile)[0])
                updated=json.loads(fs.decode_a5(actual['a5'],actual['a1'],actual['a3'],actual['a4'],profile=profile)[0])
                self.assertEqual(updated['b16'],after)
                self.assertEqual({k for k in col if col[k]!=updated[k]},{'b16'})
                self.assertEqual({k for k in baseline if baseline[k]!=actual[k]},{'a5','a2'})
                # Reproduce the former decrypt -> single-field change -> encrypt -> full a2 path.
                expected=dict(baseline);expected.pop('a2');col['b16']=after
                expected['a5']=mtg_crypto.a5_encrypt(json.dumps(col,separators=(',',':'),ensure_ascii=False).encode(),
                    expected['a1'],expected['a3'],expected['a4'],fs.k2buf(expected['a1'],profile))
                expected['a2']=fs.compute_a2(wire.method,wire.url,wire.body.decode(),json.dumps(expected,separators=(',',':')),
                    expected['a1'],signer.signature_counter,signing_profile=profile,sign_sequence=updated['b2'])
                self.assertEqual(actual,expected)
                self.assertEqual(dev,original)
                saved=signer.persist_counter();self.assertEqual(saved['base_collect']['b16'],before)
                with patch('mtgsig.signer.time.time',return_value=1700000101):
                    again=json.loads(FullSigner(saved).sign(wire.method,wire.url,wire.body.decode()))
                self.assertEqual(json.loads(fs.decode_a5(again['a5'],again['a1'],again['a3'],again['a4'],profile=profile)[0])['b16'],after)

    def test_only_zero_device_count_changes_with_other_bytes_preserved(self):
        from mtgsig.signer import render_b16
        cases=[
            ('[0,0,0],[1,0,1],[0,0,0],0','[0,0,0],[1,0,1],[1,0,0],0'),
            (' [2, 4, 8], [3, 10, 11], [ 0, 23, 24 ],1,[9,2701,2701],0111',
             ' [2, 4, 8], [3, 10, 11], [ 1, 23, 24 ],1,[9,2701,2701],0111'),
            ('[0,0,0],[3,3600,3604],[1,30,31],1','[0,0,0],[3,3600,3604],[1,30,31],1'),
            ('[8,543,544],[6,543,544],[8,543,544],1','[8,543,544],[6,543,544],[8,543,544],1'),
            (None,None),('unrecognized','unrecognized'),('[0,0,0],[0,0,0]','[0,0,0],[0,0,0]')]
        for source,expected in cases:
            with self.subTest(source=source):self.assertEqual(render_b16(source),expected)

    def test_other_endpoints_and_methods_keep_captured_b16(self):
        from unittest.mock import patch
        from mtgsig import signer as fs
        value='[0,0,0],[1,0,1],[0,0,0],0';dev=self.device('legacy',value)
        for method,path in [('POST','/api/v1/shop/shopInfo'),('POST','/api/v1/shop/productList'),
                            ('POST','/api/v1/shop/productSpecifics'),('GET','/api/v1/shop/product/render'),
                            ('POST','/api/v1/shop/product/renderOther')]:
            with self.subTest(method=method,path=path),patch('mtgsig.signer.render_b16',side_effect=AssertionError('wrong endpoint')):
                mt=json.loads(FullSigner(dev).sign(method,'https://example.test'+path,'{}'))
                self.assertEqual(json.loads(fs.decode_a5(mt['a5'],mt['a1'],mt['a3'],mt['a4'])[0])['b16'],value)


if __name__ == "__main__":
    unittest.main()
