"""Native synthetic vectors and captured wire validation for m-series fields."""
import json
from pathlib import Path
import unittest

from mtgsig.corpse_codec import (
    decode_field, decode_fields, encode_field, encode_fields, encode_json, field_shift,
)

ROOT = Path(__file__).resolve().parents[1]


class CorpseCodecTests(unittest.TestCase):
    def test_original_arm64_boundary_vectors(self):
        report = json.loads((ROOT / "tests/fixtures/corpse_native_vectors.json").read_text())
        self.assertEqual(report["entry_rva"], "0x38d334")
        for vector in report["vectors"]:
            with self.subTest(field=vector["field_number"]):
                plain, wire, number = (vector[key] for key in ("plaintext", "ciphertext", "field_number"))
                self.assertEqual(encode_field(plain, number), wire)
                self.assertEqual(decode_field(wire, number), plain)

    def test_native_number_indexing_and_known_name(self):
        self.assertEqual(field_shift(3), 92)
        self.assertEqual(encode_field("Keeta", 3), "Iccr_")
        self.assertEqual(field_shift(256 + 3), field_shift(3))
        self.assertEqual(field_shift(260), 81)
        self.assertEqual(field_shift(321), 76)

    def test_real_native_whole_json_wrapper_vectors(self):
        report = json.loads((ROOT / "tests/fixtures/corpse_native_vectors.json").read_text())
        self.assertEqual(report["wrapper_rva"], "0x2fc8c0")
        self.assertEqual(len(report["wrapper_vectors"]), 3)
        for vector in report["wrapper_vectors"]:
            wire = json.loads(vector["wire_json"])
            self.assertEqual(encode_fields(vector["plaintext"]), wire)
            self.assertEqual(decode_fields(wire), vector["plaintext"])
            self.assertEqual(encode_json(vector["plaintext"]), vector["wire_json"].encode())

    def test_space_tilde_are_distinct_and_no_nul_generated(self):
        for number in range(256):
            self.assertNotEqual(encode_field(" ", number), encode_field("~", number))
            self.assertEqual(encode_field("~", number), "~")
            self.assertEqual(decode_field(encode_field("~", number), number), "~")
            output = encode_field("".join(chr(i) for i in range(1, 128)), number)
            self.assertNotIn("\0", output)
            self.assertEqual(output.count("~"), 1)
        self.assertEqual(encode_field("\t\n\x7f中文😀", 3), "\t\n\x7f中文😀")

    def test_explicit_string_fields_preserve_order_and_types(self):
        fields = {"m3": "Keeta", "m1": "synthetic value", "m333": '["中文",1]'}
        wire = encode_fields(fields)
        self.assertEqual(list(wire), list(fields))
        self.assertEqual(decode_fields(wire), fields)
        self.assertEqual(json.loads(encode_json(fields)), wire)

    def test_bad_values_are_rejected(self):
        for value in (None, 7, b"text", "a\0b", "\ud800"):
            with self.subTest(type=type(value).__name__), self.assertRaises((TypeError, ValueError)):
                encode_field(value, 3)
        for number in (True, "m3", -1, 0x80000000):
            with self.subTest(number=number), self.assertRaises((TypeError, ValueError)):
                field_shift(number)
        for fields in ({"m01": "x"}, {"semanticName": "x"}, {"m3": 1}, []):
            with self.assertRaises((ValueError, TypeError)):
                encode_fields(fields)

    def test_explicit_passthrough_preserves_only_selected_opaque_fields(self):
        value = {"m3": "Keeta", "m137": "opaque~wire"}
        encoded = encode_fields(value, passthrough=("m137",))
        self.assertEqual(encoded, {"m3": "Iccr_", "m137": "opaque~wire"})
        self.assertEqual(decode_fields(encoded, passthrough=("m137",)), value)
        for names in ("m137", ("m999",), (3,)):
            with self.assertRaises((ValueError, TypeError)):
                encode_fields(value, passthrough=names)

    def test_complete_captured_payload_rebuilds_and_m137_keeps_real_separator(self):
        capture = ROOT / "dump/collect_plain/corpse_v5sign_raw_obf.bin"
        if not capture.exists():
            self.skipTest("private local capture is not distributed")
        raw = capture.read_bytes()
        fields = json.loads(raw)
        decoded = decode_fields(fields)
        self.assertEqual(decoded["m3"], "Keeta")
        self.assertTrue(decoded["m137"].startswith("Darwin Kernel Version 22.2.0:"))
        self.assertIn("xnu-8792.62.2~1/RELEASE_ARM64_T8030", decoded["m137"])
        self.assertEqual(encode_json(decoded), raw)


if __name__ == "__main__":
    unittest.main()
