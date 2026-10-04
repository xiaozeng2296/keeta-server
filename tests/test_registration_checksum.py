"""Regression vectors produced by the original ARM64 checksum implementation."""
from copy import deepcopy
import json
from pathlib import Path
import unittest

from mtgsig.registration_checksum import compute_m320, compute_m320_pairs


FIXTURE = Path(__file__).parent / "fixtures/registration_m320_vectors.json"


class RegistrationChecksumTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = json.loads(FIXTURE.read_text(encoding="utf-8"))["vectors"]

    def calculate(self, fields, context=None, **overrides):
        context = context or self.vectors[0]["context"]
        options = dict(appkey=context["appkey"], version=context["a0"],
                       sdk_flag=context["cipher_flag"],
                       provider_mask=bytes.fromhex(context["provider_mask_hex"]))
        options.update(overrides)
        return compute_m320(fields, **options)

    def test_original_native_vectors(self):
        self.assertEqual(len(self.vectors), 8)
        for vector in self.vectors:
            with self.subTest(name=vector["name"]):
                self.assertEqual(self.calculate(vector["fields"], vector["context"]),
                                 vector["native_m320"])

    def test_duplicate_keys_and_old_checksum_match_original_native_vectors(self):
        fixture = json.loads((FIXTURE.parent / 'registration_m320_pairs_vectors.json').read_text())
        context = fixture['context']
        self.assertEqual(len(fixture['vectors']), 5)
        for vector in fixture['vectors']:
            with self.subTest(name=vector['name']):
                pairs = vector['pairs']
                actual = compute_m320_pairs(pairs, appkey=context['appkey'], version=context['a0'],
                    sdk_flag=context['cipher_flag'], provider_mask=bytes.fromhex(context['provider_mask_hex']))
                self.assertEqual(actual, vector['native_m320'])
                self.assertEqual(''.join(k+v for k,v in sorted(reversed(pairs), key=lambda p:p[0])),
                                 vector['native_material'])

    def test_lexical_order_is_independent_of_insertion_order(self):
        vector = next(v for v in self.vectors if v["name"] == "lexical")
        reordered = dict(reversed(list(vector["fields"].items())))
        self.assertEqual(self.calculate(reordered, vector["context"]), vector["native_m320"])

    def test_ignores_old_checksum_without_mutating_fields(self):
        vector = self.vectors[0]
        fields = dict(vector["fields"], m320="outdated-checksum")
        original = deepcopy(fields)
        self.assertEqual(self.calculate(fields), vector["native_m320"])
        self.assertEqual(fields, original)

    def test_faulted_sdk_is_not_treated_as_healthy_checksum(self):
        with self.assertRaisesRegex(ValueError, "fault fallback"):
            self.calculate({"m1": "test"}, guard_fault=True)

    def test_rejects_nonstring_fields(self):
        for fields in ({"m1": 7}, {1: "test"}, {"m1": None}):
            with self.subTest(fields=fields), self.assertRaises(TypeError):
                self.calculate(fields)

    def test_rejects_nul_field_strings(self):
        for fields in ({"m1": "a\0b"}, {"m\0x": "value"}):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                self.calculate(fields)

    def test_rejects_invalid_context(self):
        for options in ({"appkey": ""}, {"version": ""}, {"appkey": "a\0b"},
                        {"version": "a\0b"}, {"sdk_flag": True},
                        {"provider_mask": bytes(15)}, {"provider_mask": bytes(17)}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.calculate({"m1": "test"}, **options)


if __name__ == "__main__":
    unittest.main()
