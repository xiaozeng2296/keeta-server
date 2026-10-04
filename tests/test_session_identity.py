"""Explicit session identity inputs, checked against synthetic original ARM64."""
import json
from pathlib import Path
import unittest
from uuid import UUID

from mtgsig.session_identity import m324_from_uuid


class SessionIdentityTests(unittest.TestCase):
    def test_original_constructor_vectors_for_both_initializing_threads(self):
        vectors = json.loads((Path(__file__).parent / "fixtures/m324_native_vectors.json").read_text())["vectors"]
        self.assertEqual(len(vectors), 6)
        self.assertEqual({row["main_thread"] for row in vectors}, {False, True})
        for row in vectors:
            with self.subTest(uuid=row["uuid"], thread=row["main_thread"]):
                self.assertEqual(m324_from_uuid(row["uuid"], main_thread=row["main_thread"]), row["native_m324"])

    def test_uuid_representation_uses_native_uppercase_without_hyphens(self):
        uuid = "12345678-1234-4234-8234-123456789abc"
        expected = "12345678123442348234123456789ABC01"
        for value in (uuid, uuid.upper(), uuid.replace("-", ""), UUID(uuid)):
            self.assertEqual(m324_from_uuid(value, main_thread=False), expected)

    def test_calls_do_not_generate_randomness_or_share_a_hidden_session(self):
        first = "00000000-0000-4000-8000-000000000000"
        second = "ffffffff-ffff-4fff-bfff-ffffffffffff"
        retained = m324_from_uuid(first, main_thread=False)
        other = m324_from_uuid(second, main_thread=True)
        self.assertNotEqual(retained, other)
        self.assertEqual(m324_from_uuid(first, main_thread=False), retained)
        self.assertEqual(retained[-2:], "01")
        self.assertEqual(other[-2:], "11")

    def test_requires_explicit_boolean_thread_state_and_valid_uuid(self):
        uuid = "00000000-0000-4000-8000-000000000000"
        for value in (None, 0, 1, "false", [], {}):
            with self.subTest(flag_type=type(value).__name__), self.assertRaises(TypeError):
                m324_from_uuid(uuid, main_thread=value)
        for value in (None, 1, True, b"0" * 32, [], {}):
            with self.subTest(uuid_type=type(value).__name__), self.assertRaises(TypeError):
                m324_from_uuid(value, main_thread=False)
        for value in ("", "not-a-uuid", "0" * 31, "g" * 32):
            with self.subTest(invalid_uuid=value), self.assertRaises(ValueError):
                m324_from_uuid(value, main_thread=False)


if __name__ == "__main__":
    unittest.main()
