"""OneID template and response tests; optional captures are read offline only."""
import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from mtgsig.oneid import (ONEID_PATH, apply_oneid_response, build_oneid_body,
                          oneid_header_updates, parse_oneid_response,
                          generate_oneid_identifier, decode_oneid_identifier)


ROOT = Path(__file__).resolve().parents[1]
IDFV = "00112233-4455-6677-8899-AABBCCDDEEFF"


def template(required=4):
    return {
        "appInfo": {"app": "example.test", "sdkVersion": "test"},
        "communicationInfo": {}, "environmentInfo": {"osVersion": "16.2"},
        "deviceInfo": {"keyDeviceInfo": {"idfv": IDFV},
                       "secondaryDeviceInfo": {"signature": "OLD"}, "isJailBreak": False},
        "idInfo": {"requiredId": required, "localId": "ONEID-LOCAL", "sessionId": "ONEID-SESSION"},
        "extension": '{"source":""}',
    }


class OneIDTests(unittest.TestCase):
    def test_identifier_matches_independent_native_full_output(self):
        vector = json.loads((Path(__file__).parent / "fixtures/oneid_native_vector.json").read_text())
        actual = generate_oneid_identifier(vector["uuid"], vector["timestamp_text"])
        self.assertEqual(actual, vector["generated"])
        self.assertEqual(decode_oneid_identifier(actual)["uuid"], vector["uuid"].lower())
        changed = actual[:14] + str((int(actual[14])+1)%10) + actual[15:]
        with self.assertRaises(ValueError):
            decode_oneid_identifier(changed)

    def test_identifier_rejects_ambiguous_timestamp_and_bad_shape(self):
        for value in (None, 1790496483, "nan", "1e9", "-1", "1.2.3"):
            with self.subTest(value=value), self.assertRaises((ValueError, TypeError)):
                generate_oneid_identifier(IDFV, value)
        for value in ("", "0"*49, "g"*50, None, 123):
            with self.subTest(value=value), self.assertRaises(ValueError):
                decode_oneid_identifier(value)

    def test_body_changes_idfv_and_signature_together_without_mutating_inputs(self):
        original = template()
        before = copy.deepcopy(original)
        value = IDFV.lower()
        profile = {"idfv": value, "oneid_local_id": "NEW-LOCAL", "oneid_session_id": "NEW-SESSION",
                   "oneid_environment_info": {"languageCode": "pt"},
                   "oneid_extension": {"source": "test"}, "localid": "UNRELATED-SAK-ID"}
        body = build_oneid_body(original, profile, required_id=1)
        self.assertEqual(original, before)
        self.assertEqual(body["deviceInfo"]["keyDeviceInfo"]["idfv"], value)
        self.assertEqual(body["deviceInfo"]["secondaryDeviceInfo"]["signature"],
                         hashlib.md5(value.encode()).hexdigest())
        self.assertEqual(body["idInfo"], {"requiredId": 1, "localId": "NEW-LOCAL", "sessionId": "NEW-SESSION"})
        self.assertEqual(body["environmentInfo"], {"osVersion": "16.2", "languageCode": "pt"})
        self.assertEqual(json.loads(body["extension"]), {"source": "test"})
        self.assertEqual(oneid_header_updates(body, {"oneid_request_id": "REQUEST"}),
                         {"uuidSessionId": "NEW-SESSION", "uuidRequestId": "REQUEST"})

    def test_required_id_selects_destination_not_the_response_length(self):
        response = {"code": 0, "message": "generated", "data": {"unionId": "SAME-OPAQUE-ID"}}
        self.assertEqual(parse_oneid_response(template(4), response, http_status=200),
                         {"csecuuid": "SAME-OPAQUE-ID", "uuid": "SAME-OPAQUE-ID"})
        self.assertEqual(parse_oneid_response(template(1), response, http_status=200),
                         {"unionid": "SAME-OPAQUE-ID"})

    def test_response_updates_separate_slots_and_preserves_sak_fields(self):
        state = {"a7": "LOCAL-XID", "a8": "LOCAL-DFP", "oneid_local_id": "LOCAL"}
        apply_oneid_response(state, template(4), {"code": 0, "data": {"unionId": "UUID"}}, http_status=200)
        apply_oneid_response(state, json.dumps(template(1)),
                             {"code": 0, "data": {"unionId": "UNION"}}, http_status=200)
        self.assertEqual(state, {"a7": "LOCAL-XID", "a8": "LOCAL-DFP", "oneid_local_id": "LOCAL",
                                 "csecuuid": "UUID", "uuid": "UUID", "unionid": "UNION"})

    def test_errors_and_wrong_types_leave_state_unchanged(self):
        valid = {"code": 0, "data": {"unionId": "SERVER"}}
        cases = [(template(), valid, status) for status in (False, "200", 403, 500)]
        cases += [(template(), {"code": code, "data": valid["data"]}, 200)
                  for code in (False, True, 0.0, "0", None, 1)]
        cases += [(template(), {"code": 0, "data": {"unionId": value}}, 200)
                  for value in (None, 1, [], {}, "", "X Y", "X\n")]
        cases += [(template(required), valid, 200) for required in (True, 4.0, "4", 0, 2, None)]
        cases += [(template(), {"code": 0, "unionId": "WRONG"}, 200),
                  (template(), dict(valid, success=False), 200),
                  (template(), dict(valid, error={"code": 9}), 200)]
        for req, resp, status in cases:
            with self.subTest(req=req, response=resp, status=status):
                state = {"csecuuid": "BEFORE", "uuid": "BEFORE", "unionid": "OTHER"}
                before = dict(state)
                self.assertEqual(apply_oneid_response(state, req, resp, http_status=status), {})
                self.assertEqual(state, before)

    def test_builder_rejects_missing_required_input_and_unknown_modes(self):
        for section in ("deviceInfo", "idInfo", "appInfo", "environmentInfo"):
            body = template()
            del body[section]
            with self.subTest(missing=section), self.assertRaises(ValueError):
                build_oneid_body(body)
        for required in (True, "4", 4.0, 3):
            with self.subTest(required=required), self.assertRaises(ValueError):
                build_oneid_body(template(), required_id=required)
        for idfv in (None, "", 123, "a b"):
            with self.subTest(idfv=idfv), self.assertRaises(ValueError):
                build_oneid_body(template(), {"idfv": idfv})

    def test_original_capture_confirms_both_routes_and_md5_input(self):
        path = ROOT / "evidence/captures/新机之后尝试登录.chlsj"
        if not path.exists():
            self.skipTest("optional original Charles capture is not distributed")
        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            flows = json.loads(path.read_text())
            selected = [(i, f) for i, f in enumerate(flows) if f.get("path") == ONEID_PATH]
            self.assertEqual([i for i, _ in selected], [7, 10])
            for (index, item), required in zip(selected, (4, 1)):
                with self.subTest(index=index, required=required):
                    body = json.loads(item["request"]["body"]["text"])
                    self.assertEqual(body["idInfo"]["requiredId"], required)
                    self.assertEqual(build_oneid_body(body), body)
                    headers = {h["name"].lower(): h["value"] for h in item["request"]["header"]["headers"]}
                    self.assertNotIn("mtgsig", headers)
                    self.assertEqual(oneid_header_updates(body)["uuidSessionId"], headers["uuidsessionid"])
                    for value in (body["idInfo"]["localId"], body["idInfo"]["sessionId"], headers["uuidrequestid"]):
                        self.assertEqual(len(decode_oneid_identifier(value)["time_digest"]), 16)
                    response = json.loads(item["response"]["body"]["text"])
                    state = parse_oneid_response(body, response, http_status=item["response"]["status"])
                    self.assertTrue(state)
                    target_header = "csecuuid" if required == 4 else "pragma-unionid"
                    target_value = state["csecuuid" if required == 4 else "unionid"]
                    later = [h["value"] for f in flows[index + 1:]
                             for h in ((f.get("request") or {}).get("header") or {}).get("headers", [])
                             if h["name"].lower() == target_header]
                    self.assertIn(target_value, later)


if __name__ == "__main__":
    unittest.main()
