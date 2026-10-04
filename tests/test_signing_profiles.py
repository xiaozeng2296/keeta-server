"""Signing provider migration; no phone or network operations."""
import base64
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import keeta_rpc as rpc
from farm import fullsign as fs
from mtgsig import a9_codec, mtg_crypto

A1 = "00112233-4455-6677-8899-aabbccddeeff"
COLLECT = {"b1": "{}", "b2": 1, "b3": 1, "b4": "example.test", "b7": 1700000000}


class SigningProfileTests(unittest.TestCase):
    def sample(self, signing_profile):
        # Cached a9 deliberately has the OTHER provider. It must not decide
        # a5's profile, either when decrypting or provisioning a signer.
        a9_profile = "legacy" if signing_profile == "default" else "default"
        a5 = mtg_crypto.a5_encrypt(json.dumps(COLLECT).encode(), A1, 20, 1700000000,
                                  fs.k2buf(A1, signing_profile))
        a9 = fs.a9_generate('{"0":12,"1":[],"2":[],"3":"{}"}', A1,
                            profile=a9_profile, mode="twofish")
        return dict(a0="2.5", a1=A1, a3=20, a4=1700000000, a5=a5, a6=0,
                    a7="LOCAL-XID", a8="LOCAL-DFP", a9=a9, a10="3,1", x0=2,
                    a2="0"*32)

    def test_direct_decrypt_selects_each_field_profile_independently(self):
        for profile in ("default", "legacy"):
            with self.subTest(profile=profile):
                sample = self.sample(profile)
                result = rpc.op_decrypt(sample)["fields"]
                self.assertTrue(result["a5"]["decryptable"])
                self.assertEqual(result["a5"]["profile"], profile)
                self.assertEqual(result["a5"]["plain_json"], COLLECT)
                self.assertTrue(result["a9"]["decryptable"])
                self.assertNotEqual(result["a9"]["profile"], profile)
                self.assertNotIn("plain_text", result["a5"])
                forced = rpc.op_decrypt({"mtgsig": sample,
                                         "signing_profile": result["a9"]["profile"]})
                self.assertFalse(forced["fields"]["a5"]["decryptable"])

    def test_request_clock_mode_refreshes_signed_b8_b9_without_rewriting_snapshot(self):
        sample = self.sample("legacy")
        collect = dict(COLLECT, b8=1700000001, b9=1700000002, b13=6)
        sample["a5"] = mtg_crypto.a5_encrypt(
            json.dumps(collect).encode(), A1, sample["a3"], sample["a4"], fs.k2buf(A1))
        with tempfile.TemporaryDirectory() as temp:
            src, dst = Path(temp) / "sample.json", Path(temp) / "identity.json"
            src.write_text(json.dumps({"mtgsig": sample}))
            captured = fs.provision_identity(src, dst)
            for mode in ("captured", "request"):
                with self.subTest(mode=mode):
                    dev = dict(captured, collection_clock_mode=mode)
                    dst.write_text(json.dumps(dev))
                    signer = fs.FullSigner(dst)
                    for now in (1700009000, 1700009010):
                        with patch("farm.fullsign.time.time", return_value=now):
                            mt = json.loads(signer.sign("POST", "https://example.test/menu", "{}"))
                        plain, _ = fs.decode_a5(mt["a5"], A1, mt["a3"], mt["a4"])
                        fields = json.loads(plain)
                        expected_times = (now, now) if mode == "request" else (1700000001, 1700000002)
                        self.assertEqual((fields["b8"], fields["b9"]), expected_times)
                        self.assertEqual((fields["b7"], fields["b13"]), (collect["b7"], 6))
                        expected_a2 = mt.pop("a2")
                        self.assertEqual(fs.compute_a2(
                            "POST", "https://example.test/menu", "{}",
                            json.dumps(mt, separators=(",", ":")), A1, 1,
                            signing_profile="legacy", sign_sequence=fields["b2"]), expected_a2)
                        signer.persist_counter()
                        self.assertEqual(json.loads(dst.read_text())["base_collect"], collect)
                        signer = fs.FullSigner(dst)
                        self.assertEqual(signer.collection_clock_mode, mode)

    def test_request_clock_mode_requires_known_collection_clocks(self):
        with tempfile.TemporaryDirectory() as temp:
            src, dst = Path(temp) / "sample.json", Path(temp) / "identity.json"
            src.write_text(json.dumps({"mtgsig": self.sample("legacy")}))
            dev = fs.provision_identity(src, dst)
            for mode in ("request", "unsupported"):
                with self.subTest(mode=mode):
                    dst.write_text(json.dumps(dict(dev, collection_clock_mode=mode)))
                    with self.assertRaises(ValueError):
                        fs.FullSigner(dst)

    def test_provision_keeps_signing_profile_through_fresh_sign_and_reload(self):
        for profile in ("default", "legacy"):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as temp:
                src, dst = Path(temp)/"sample.json", Path(temp)/"identity.json"
                src.write_text(json.dumps({"mtgsig": self.sample(profile)}))
                dev = fs.provision_identity(src, dst)
                self.assertEqual(dev["signing_profile"], profile)
                self.assertNotEqual(dev["a9_profile"], profile)
                signer = fs.FullSigner(dst)
                mt = json.loads(signer.sign("POST", "https://example.test/one", "{}"))
                plain, selected = fs.decode_a5(mt["a5"], A1, mt["a3"], mt["a4"])
                self.assertEqual(selected, profile)
                self.assertEqual(json.loads(plain)["b2"], 2)
                self.assertEqual(json.loads(plain)["b3"], 1)
                self.assertEqual(mt["a10"], "3,1")
                signer.persist_counter()
                self.assertEqual(fs.FullSigner(dst).signing_profile, profile)

    def test_a5_rejects_trailing_compressed_data_and_wrong_identifier(self):
        sample = self.sample("default")
        with self.assertRaises(ValueError):
            fs.decode_a5(sample["a5"], "10112233-4455-6677-8899-aabbccddeeff", 20, sample["a4"])
        key = mtg_crypto.a5_derive_key(A1, 20, sample["a4"], fs.k2buf(A1, "default"))
        compressed = mtg_crypto.rc4_variant(key, base64.b64decode(sample["a5"]))
        broken = base64.b64encode(mtg_crypto.rc4_variant(key, compressed+b"trailer")).decode()
        with self.assertRaises(ValueError):
            fs.decode_a5(broken, A1, 20, sample["a4"])

    def test_current_capture_a5_all_validate_under_current_provider(self):
        path = Path(__file__).resolve().parents[1]/"evidence/captures/新机之后尝试登录.chlsj"
        if not path.exists():
            self.skipTest("private source capture is not deployed")
        matched = 0
        for flow in json.loads(path.read_text()):
            for header in ((flow.get("request") or {}).get("header") or {}).get("headers", []):
                if header["name"].lower() != "mtgsig":
                    continue
                mt = json.loads(header["value"])
                plain, profile = fs.decode_a5(mt["a5"], mt["a1"], mt["a3"], mt["a4"])
                self.assertEqual(profile, "default")
                self.assertEqual(json.loads(plain)["b4"], "com.sankuai.sailor.ifooddelivery")
                matched += 1
        self.assertEqual(matched, 73)

    def test_captured_signatures_match_all_16_bytes_using_independent_a5_sequence(self):
        from keeta_offline_flow import extract_template
        root = Path(__file__).resolve().parents[1]
        matched = 0
        for name in ("evidence/captures/新机之后尝试登录.chlsj",):
            path = root/name
            if not path.exists():
                continue
            for flow in json.loads(path.read_text()):
                for header in ((flow.get("request") or {}).get("header") or {}).get("headers", []):
                    if header["name"].lower() != "mtgsig":
                        continue
                    mt = json.loads(header["value"])
                    expected = mt.pop("a2")
                    _, profile = fs.decode_a5(mt["a5"], mt["a1"], mt["a3"], mt["a4"])
                    path_part, _, body = extract_template(flow)
                    actual = fs.compute_a2("POST", "https://"+flow["host"]+path_part, body,
                        json.dumps(mt, ensure_ascii=False, separators=(",", ":")), mt["a1"],
                        int(mt["a10"].split(",")[1]), signing_profile=profile)
                    self.assertEqual(actual, expected)
                    matched += 1
        if not matched:
            self.skipTest("private source captures are not deployed")
        self.assertEqual(matched, 73)

    def test_pass2_matches_server_accepted_byte_boundaries(self):
        # Recorded from successful live menu requests; the former synthetic
        # fixture duplicated the missing high-byte assumption of the code.
        fixture = Path(__file__).with_name("fixtures") / "a2_pass2_accepted_boundaries.json"
        vectors = json.loads(fixture.read_text())["vectors"]
        for index, vector in enumerate(vectors):
            with self.subTest(vector=index, sequence=vector["sign_sequence"]):
                actual = fs._a2_pass2(bytes.fromhex(vector["prefix_hex"]),
                                     bytes.fromhex(vector["mask_hex"]),
                                     vector["sign_sequence"])
                self.assertEqual(actual.hex(), vector["tail_hex"])

    def test_rpc_a2_auto_profile_matches_current_signer_and_honors_explicit_profile(self):
        with tempfile.TemporaryDirectory() as temp:
            src, dst = Path(temp)/"sample.json", Path(temp)/"identity.json"
            src.write_text(json.dumps({"mtgsig": self.sample("default")}))
            fs.provision_identity(src, dst)
            method, url, body = "POST", "https://example.test/path?x=1", "{}"
            mt = json.loads(fs.FullSigner(dst).sign(method, url, body))
            expected = mt.pop("a2")
            request = dict(method=method, url=url, body=body, a1=A1,
                           counter=int(mt["a10"].split(",")[1]),
                           payload_json=json.dumps(mt, ensure_ascii=False, separators=(",", ":")))
            self.assertEqual(rpc.op_a2(request)["a2"], expected)
            for selector in ("signing_profile", "profile"):
                with self.subTest(selector=selector), self.assertRaises(ValueError):
                    rpc.op_a2(dict(request, **{selector: "legacy"}))

    def test_old_identity_counter_fallback_is_frozen_and_survives_reload(self):
        # An old file cannot recover the original a10 session byte. Its saved
        # counter is an explicit compatibility fallback, not native evidence.
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/"old.json"
            mt = self.sample("legacy")
            identity = {key: mt[key] for key in ("a0", "a1", "a3", "a6", "a7", "a8", "a9", "x0")}
            identity.update(counter=77, base_collect=dict(COLLECT, b17=1, b18=0,
                                                         b8=1700000001, b9=1700000001))
            path.write_text(json.dumps(identity))
            signer = fs.FullSigner(path)
            first = json.loads(signer.sign("POST", "https://example.test/path", "{}"))
            plain, profile = fs.decode_a5(first["a5"], A1, first["a3"], first["a4"])
            fields = json.loads(plain)
            self.assertEqual(profile, "legacy")
            self.assertEqual(first["a10"], "3,77")
            self.assertEqual((fields["b2"], fields["b17"], fields["b18"], fields["b3"]), (78, 78, 0, 1))
            self.assertEqual((fields["b7"], fields["b8"], fields["b9"]),
                             (1700000000, 1700000001, 1700000001))
            signer.persist_counter()
            migrated = json.loads(path.read_text())
            self.assertEqual(migrated["sign_sequence"], 78)
            self.assertEqual(migrated["signature_counter"], 77)
            reloaded = fs.FullSigner(path)
            second = json.loads(reloaded.sign("POST", "https://example.test/path", "{}"))
            self.assertEqual(second["a10"], "3,77")
            self.assertEqual(reloaded.counter, 79)

    def test_explicit_session_and_sequence_metadata_override_old_counter(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/"migrated.json"
            mt = self.sample("legacy")
            identity = {key: mt[key] for key in ("a0", "a1", "a3", "a6", "a7", "a8", "a9", "x0")}
            identity.update(counter=77, signature_counter=222, sign_sequence=5,
                            signing_profile="legacy", base_collect=COLLECT)
            path.write_text(json.dumps(identity))
            signer = fs.FullSigner(path)
            signed = json.loads(signer.sign("POST", "https://example.test/path", "{}"))
            plain, _ = fs.decode_a5(signed["a5"], A1, signed["a3"], signed["a4"])
            self.assertEqual(signed["a10"], "3,222")
            self.assertEqual(json.loads(plain)["b2"], 6)


if __name__ == "__main__":
    unittest.main()
