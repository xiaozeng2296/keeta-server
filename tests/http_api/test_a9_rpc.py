"""Offline RPC operation tests; all identities and payloads are synthetic."""
import base64
import json
import unittest
from pathlib import Path
from unittest.mock import patch

import mtgsig.api as rpc
from mtgsig import a9_codec as codec, mtg_crypto


A1 = "00112233-4455-6677-8899-aabbccddeeff"
OTHER_A1 = "10112233-4455-6677-8899-aabbccddeeff"
PLAIN = {"0": 12, "1": ["synthetic"], "2": ["离线测试"], "3": "{}"}
TEXT = json.dumps(PLAIN, separators=(",", ":"), ensure_ascii=False)
LEGACY = json.loads((Path(__file__).resolve().parents[2] / "mtgsig/a9_legacy_profile.json").read_text())


class A9RPCTests(unittest.TestCase):
    @staticmethod
    def assert_slim_json_result(testcase, result, expected):
        """Check the human-facing JSON contract shared by a9/a5 responses.

        Plain JSON is the canonical payload.  The RPC must not duplicate it
        as base64 or a second text representation, while the explanation tree
        carries a labelled value for every SIUA slot.
        """
        testcase.assertEqual(result["plain_json"], expected)
        testcase.assertNotIn("plain_b64", result)
        testcase.assertNotIn("plain_text", result)

    @staticmethod
    def assert_a9_explanation(testcase, result, expected):
        explanation = result["plain_explained"]
        entries = explanation["fields"]
        testcase.assertGreaterEqual(len(entries), len(expected))
        by_index = {}
        for entry in entries:
            testcase.assertTrue({"key", "name", "value"} <= set(entry))
            testcase.assertIsInstance(entry["name"], str)
            testcase.assertTrue(entry["name"])
            by_index[str(entry["key"])] = entry
        for key, value in expected.items():
            testcase.assertIn(str(key), by_index)
            entry = by_index[str(key)]
            # Nested JSON strings are parsed for readability but retained in
            # ``raw`` so the original slot value remains unambiguous.
            if "raw" in entry:
                testcase.assertEqual(entry["raw"], value)
            else:
                testcase.assertEqual(entry["value"], value)
        for key in ("1", "2"):
            if key not in by_index or not isinstance(value := expected.get(key), list):
                continue
            items = by_index[key].get("items", [])
            testcase.assertEqual(len(items), len(value))
            for index, slot in enumerate(items):
                testcase.assertEqual(slot["index"], index)
                testcase.assertIn("name", slot)
                testcase.assertTrue(slot["name"])
                testcase.assertEqual(slot["value"], value[index])

    def test_complete_mtgsig_a5_uses_json_and_labelled_fields(self):
        a5_plain = {
            "b1": '{"0":23,"2":"WiFi"}',
            "b2": 6,
            "b3": 1,
        }
        a3, a4 = 25, 1700000000
        a5 = mtg_crypto.a5_encrypt(
            json.dumps(a5_plain, separators=(",", ":"), ensure_ascii=False).encode(),
            A1, a3, a4, rpc.FS.k2buf(A1),
        )
        result = rpc.op_decrypt({"a1": A1, "a3": a3, "a4": a4, "a5": a5})["fields"]["a5"]
        self.assertTrue(result["decryptable"])
        self.assert_slim_json_result(self, result, a5_plain)

        explanation = result["plain_explained"]
        entries = explanation["fields"]
        by_key = {entry["key"]: entry for entry in entries}
        for key, value in a5_plain.items():
            with self.subTest(key=key):
                self.assertIn(key, by_key)
                entry = by_key[key]
                self.assertTrue(entry["name"])
                if "raw" in entry:
                    self.assertEqual(entry["raw"], value)
                else:
                    self.assertEqual(entry["value"], value)
        # b1's nested JSON is exposed as labelled child slots when present.
        b1_explained = by_key["b1"]
        children = {entry["key"]: entry for entry in b1_explained["fields"]}
        self.assertIn("0", children)
        self.assertEqual(children["0"]["value"], 23)
        self.assertEqual(children["2"]["value"], "WiFi")

    def test_fingerprint_uses_json_without_duplicate_encodings(self):
        from Crypto.Cipher import AES

        plain = b'{"m1":"synthetic","m2":7}'
        pad = 16 - len(plain) % 16
        ciphertext = AES.new(b"meituan1sankuai0", AES.MODE_CBC, codec.IV).encrypt(
            plain + bytes([pad]) * pad
        )
        result = rpc.op_fp_decrypt({"fingerprint": base64.b64encode(ciphertext).decode()})
        self.assert_slim_json_result(self, result, json.loads(plain))

    def test_fingerprint_encrypt_matches_captured_i_series_wire_bytes(self):
        fixture = json.loads(
            (Path(__file__).resolve().parent.parent / "fixtures/fingerprint_i_series_vector.json")
            .read_text(encoding="utf-8")
        )
        key = fixture["key_ascii"].encode("ascii")
        iv = fixture["iv_ascii"].encode("ascii")
        expected = fixture["ciphertext_b64"]
        # Object serialization keeps the captured insertion order and compact
        # separators, while passing exact JSON text verifies both input forms.
        self.assertEqual(mtg_crypto.fingerprint_encrypt(fixture["plain_json"], key, iv), expected)
        text = json.dumps(fixture["plain_json"], separators=(",", ":"), ensure_ascii=False)
        self.assertEqual(mtg_crypto.fingerprint_encrypt(text, key, iv), expected)

        rpc_result = rpc.op_fp_encrypt({"plain_obj": fixture["plain_json"]})
        self.assertEqual(rpc_result["fingerprint"], expected)
        self.assertEqual(rpc_result["key_used"], fixture["key_ascii"])
        self.assertEqual(rpc_result["iv"], fixture["iv_ascii"])
        hex_result = rpc.op_fp_encrypt({
            "plain_obj": fixture["plain_json"],
            "key": key.hex(),
            "iv": iv.hex(),
        })
        self.assertEqual(hex_result["fingerprint"], expected)


    def test_three_modes_without_dump_table(self):
        for mode in codec.MODES:
            with self.subTest(mode=mode):
                encoded = rpc.op_a9_encode({"a1": A1, "siua_json": PLAIN, "mode": mode})
                self.assertEqual(encoded["a9"], codec.encode(TEXT, A1, mode=mode))
                decoded = rpc.op_a9_decode({"a1": A1, "a9": encoded["a9"]})
                self.assert_slim_json_result(self, decoded, PLAIN)
                self.assert_a9_explanation(self, decoded, PLAIN)
                self.assertEqual(decoded["mode"], mode)
                self.assertEqual(decoded["profile"], "default")
                self.assertEqual(decoded["a1_shift"], 31)

    def test_legacy_complete_mtgsig_and_explicit_profile(self):
        # Complete synthetic mtgsig objects exercise the historical profile
        # without copying any captured UUID, authentication field or plaintext.
        for mode in codec.MODES:
            with self.subTest(mode=mode):
                expected = codec.encode(TEXT, A1, mode=mode,
                                        salt=bytes.fromhex(LEGACY["salt_hex"]),
                                        a1_shift=LEGACY["a1_shift"])
                encoded = rpc.op_a9_encode({"a1": A1, "siua_json": TEXT,
                                            "mode": mode, "profile": "legacy"})
                self.assertEqual(encoded["a9"], expected)
                mt = {"a1": A1, "a9": expected}
                for value in (mt, json.dumps(mt)):
                    result = rpc.op_decrypt({"mtgsig": value, "profile": "legacy"})["fields"]["a9"]
                    self.assertTrue(result["decryptable"])
                    self.assert_slim_json_result(self, result, PLAIN)
                    self.assert_a9_explanation(self, result, PLAIN)
                    self.assertEqual(result["mode"], mode)
                    self.assertEqual(result["profile"], "legacy")
                    self.assertEqual(result["a1_shift"], 12)
                # An explicit profile remains deterministic and does not fall back.
                wrong = rpc.op_decrypt({"mtgsig": mt, "profile": "default"})["fields"]["a9"]
                self.assertFalse(wrong["decryptable"])
                self.assertNotIn("plain_b64", wrong)
                self.assertNotIn("plain_text", wrong)

    def test_direct_legacy_mtgsig_auto_selects_verified_profile(self):
        a9 = codec.encode(TEXT, A1, mode="twofish", salt=bytes.fromhex(LEGACY["salt_hex"]),
                          a1_shift=LEGACY["a1_shift"])
        result = rpc.op_decrypt({"a0": "2.5", "a1": A1, "a9": a9})["fields"]["a9"]
        self.assertTrue(result["decryptable"])
        self.assertEqual(result["profile"], "legacy")
        self.assert_slim_json_result(self, result, PLAIN)
        self.assert_a9_explanation(self, result, PLAIN)

    def test_custom_configuration(self):
        options = {"profile": "legacy", "salt_hex": bytes(range(16)).hex(),
                   "k3_hex": b"synthetic-config".hex(), "a1_shift": 7}
        encoded = rpc.op_a9_encode({"a1": A1, "siua_json": PLAIN, "mode": "aes", **options})
        expected = codec.encode(TEXT, A1, salt=bytes(range(16)), k3=b"synthetic-config", a1_shift=7)
        self.assertEqual(encoded["a9"], expected)
        decoded = rpc.op_a9_decode({"a1": A1, "a9": expected, **options})
        self.assert_slim_json_result(self, decoded, PLAIN)
        self.assert_a9_explanation(self, decoded, PLAIN)
        self.assertEqual(decoded["profile"], "legacy")
        self.assertEqual(decoded["a1_shift"], 7)
        self.assertEqual(decoded["profile_overrides"], ["salt_hex", "k3_hex", "a1_shift"])

    def test_requires_identifier_and_explicit_encode_mode(self):
        with self.assertRaises(KeyError):
            rpc.op_a9_encode({"siua_json": PLAIN, "mode": "aes"})
        with self.assertRaises(ValueError):
            rpc.op_a9_encode({"a1": A1, "siua_json": PLAIN})
        with self.assertRaises(ValueError):
            rpc.op_a9_encode({"a1": A1, "siua_json": PLAIN, "mode": "auto"})
        a9 = codec.encode(TEXT, A1)
        missing = rpc.op_decrypt({"a9": a9})["fields"]["a9"]
        self.assertFalse(missing["decryptable"])
        self.assertIn("original a1", missing["error"])
        conflict = rpc.op_decrypt({"mtgsig": {"a1": A1, "a9": a9}, "a1": OTHER_A1})["fields"]["a9"]
        self.assertFalse(conflict["decryptable"])
        self.assertIn("differs", conflict["error"])

    def test_invalid_profiles_and_overrides_fail(self):
        for extra in ({"profile": "unknown"}, {"salt_hex": "invalid"},
                      {"salt_hex": "00"}, {"k3_hex": "00"},
                      {"a1_shift": 36}, {"a1_shift": True}):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                rpc.op_a9_encode({"a1": A1, "siua_json": PLAIN, "mode": "aes", **extra})

    def test_health_reports_codec_independent_of_v73(self):
        status = rpc.capabilities()
        self.assertTrue(status["a9_ready"])
        self.assertFalse(status["a9_requires_v73"])
        self.assertEqual(status["a9_modes"], list(codec.MODES))
        self.assertEqual(status["a9_profiles"], ["default", "legacy"])


if __name__ == "__main__":
    unittest.main()
