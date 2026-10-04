import json
from pathlib import Path
import unittest

from mtgsig.scfg import build_scfg_request, decode_scfg_data, encode_scfg_data, parse_scfg_response


class ScfgTests(unittest.TestCase):
    capture = Path(__file__).parents[1] / "evidence/captures/新机之后尝试登录.chlsj"

    @unittest.skipUnless(capture.exists(), "private Charles capture is not part of the RPC release")
    def test_native_capture_request_roundtrip(self):
        records = json.loads(self.capture.read_text())
        for index in (244, 464):
            request = json.loads(records[index]["request"]["body"]["text"])
            fields = decode_scfg_data(request["data"])
            self.assertEqual(set(fields), {"city", "dfpid", "dpid", "os_version", "package",
                                           "package_version_code", "timestamp", "userid", "uuid"})
            self.assertEqual(request["os"], "iOS")
            self.assertEqual(request["mtg_version"], "5.21.10")

    @unittest.skipUnless(capture.exists(), "private Charles capture is not part of the RPC release")
    def test_native_capture_response_state(self):
        records = json.loads(self.capture.read_text())
        for index in (244, 464):
            response = json.loads(records[index]["response"]["body"]["text"])
            state = parse_scfg_response(response, http_status=200)
            self.assertEqual(state["scfg_config"], {"private_key_config": "", "applist_config": "", "version_code": "1"})
            self.assertFalse(state["scfg_applist_open"])
            self.assertEqual(state["scfg_private_collect_fields"], [""])

    def test_request_builder_preserves_known_native_fields(self):
        request = build_scfg_request({"m154": "com.example", "m144": "401", "m153": "uuid",
                                      "m136": "dpid"}, os_version="iOS 16.2", dfp_id="dfp",
                                     timestamp_ms=1700000000123, sdk_version="5.21.10", user_id=None,
                                     city="Hong Kong")
        self.assertEqual(request["os"], "iOS")
        self.assertEqual(decode_scfg_data(request["data"])["userid"], "-1")

    def test_raw_json_exact_reencrypt(self):
        text = '{"z":"😀","a":1}'
        self.assertEqual(decode_scfg_data(encode_scfg_data(text), as_text=True), text)

    def test_rejects_wrong_response_path_or_status(self):
        self.assertEqual(parse_scfg_response({"code": 0, "resStr": "x"}, http_status=200), {})
        self.assertEqual(parse_scfg_response({"code": 0, "data": {"resStr": "x"}}, http_status=500), {})

    def test_rejects_invalid_data(self):
        for value in ("", "not-base64", "AA=="):
            with self.assertRaises(ValueError):
                decode_scfg_data(value)


if __name__ == "__main__":
    unittest.main()
