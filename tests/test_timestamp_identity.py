import copy
import json
from pathlib import Path
import unittest

from mtgsig.timestamp_identity import m239_from_m251


class TimestampIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = json.loads((Path(__file__).with_name("fixtures") /
                                 "m239_synthetic.json").read_text())["vectors"]

    def test_matches_independent_libc_format_vectors(self):
        for index, vector in enumerate(self.vectors):
            with self.subTest(vector=index):
                self.assertEqual(m239_from_m251(vector["m251"]), vector["m239"])
                self.assertEqual(m239_from_m251(json.dumps(vector["m251"])), vector["m239"])

    def test_file_names_and_inodes_are_not_digest_material(self):
        vector = self.vectors[2]
        records = copy.deepcopy(vector["m251"])
        for record in records:
            record["f"] = "/another/synthetic/file"
            record["si"] = "99999"
        self.assertEqual(m239_from_m251(records), vector["m239"])

    def test_native_record_order_is_preserved(self):
        vector = self.vectors[2]
        self.assertNotEqual(m239_from_m251(list(reversed(vector["m251"]))), vector["m239"])

    def test_rejects_non_native_or_failed_stat_records(self):
        for value in ({}, [{"tm": "1700000000000000007"}],
                      [{"st": "1", "tm": "1700000000000000007"}],
                      [{"st": "0", "tm": "1.000000007"}],
                      [{"st": "0", "tm": "01700000000000000007"}],
                      [{"st": "0", "tm": "-0000000000"}],
                      [{"st": "0", "tm": "9223372036854775808000000000"}]):
            with self.subTest(value=value), self.assertRaises(ValueError):
                m239_from_m251(value)


if __name__ == "__main__":
    unittest.main()
