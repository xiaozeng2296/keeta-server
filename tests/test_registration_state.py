"""Response state transitions; no HTTP, phone, or credentials required."""
import copy
import unittest

from mtgsig.registration_state import apply_registration_response, parse_registration_response


INFO = "/fingerprint/v1/info/report"
SIGN = "/v5/sign"


class RegistrationStateTests(unittest.TestCase):
    def test_observed_success_shapes_update_only_the_matching_field(self):
        # Redacted shapes from both supplied Charles captures, including
        # their different msg/message keys and endpoint-specific payloads.
        info = {"code": 0, "msg": "", "data": {
            "result": "SERVER-XID", "serverTimestamp": 1000, "interval": 86400}}
        sign = {"code": 0, "message": "ok", "data": {
            "dfp": "SERVER-DFP", "serverTimestamp": 1001, "interval": 86400,
            "ab_test_flag": "0", "clientIp": "192.0.2.1"}}
        state = {"a7": "LOCAL-XID", "a8": "LOCAL-DFP", "a1": "device-a1"}
        apply_registration_response(state, INFO, info, http_status=200)
        self.assertEqual(state["a7"], "SERVER-XID")
        self.assertEqual(state["a7_server_xid"], state["xid"])
        self.assertEqual(state["a7_local_xid"], "LOCAL-XID")
        self.assertEqual(state["a8"], "LOCAL-DFP")
        apply_registration_response(state, SIGN, sign, http_status=200)
        self.assertEqual(state["a8"], "SERVER-DFP")
        self.assertEqual(state["a8_server_dfp"], state["dfp"])
        self.assertEqual(state["a8_local_dfp"], "LOCAL-DFP")
        self.assertEqual(state["a1"], "device-a1")

    def test_out_of_order_responses_do_not_require_each_other(self):
        state = {"a7": "LOCAL-XID", "a8": "LOCAL-DFP"}
        apply_registration_response(state, SIGN, {"code": 0, "data": {"dfp": "DFP"}},
                                    http_status=200)
        self.assertEqual(state["a7"], "LOCAL-XID")
        apply_registration_response(state, INFO, {"code": 0, "data": {"result": "XID"}},
                                    http_status=200)
        self.assertEqual((state["xid"], state["dfp"]), ("XID", "DFP"))

    def test_confirmed_direct_writer_updates_history_but_other_branches_do_not_guess(self):
        state = {"a8": "LOCAL-DFP"}
        def accept(value, flag):
            return apply_registration_response(state, SIGN,
                {"code": 0, "data": {"dfp": value, "ab_test_flag": flag}}, http_status=200)

        # A has another native persistence path, not reconstructed in this
        # direct-response parser. Its accepted signing DFP still updates.
        first = accept("DFP-A", "A")
        self.assertEqual(first["a8"], "DFP-A")
        self.assertNotIn("outid_history_dfp", state)
        second = accept("DFP-B", "B")
        self.assertEqual(second["outid_history_dfp"], "DFP-B")
        for flag in ("A", "0", None, False, "b"):
            patch = accept("NEXT-DFP", flag)
            self.assertNotIn("outid_history_dfp", patch)
            self.assertEqual(state["outid_history_dfp"], "DFP-B")
            self.assertEqual(state["a8"], "NEXT-DFP")

    def test_invalid_sign_response_cannot_update_history(self):
        valid = {"code": 0, "data": {"dfp": "NEW-DFP", "ab_test_flag": "B"}}
        cases = [(503, valid), (200, dict(valid, code=1)),
                 (200, dict(valid, error={"code": 1})),
                 (200, {"code": 0, "data": {"dfp": "", "ab_test_flag": "B"}})]
        for status, response in cases:
            with self.subTest(status=status, response=response):
                state = {"a8": "OLD-DFP", "outid_history_dfp": "OLD-HISTORY"}
                before = copy.deepcopy(state)
                self.assertEqual(apply_registration_response(state, SIGN, response,
                                                             http_status=status), {})
                self.assertEqual(state, before)

    def test_errors_and_bad_types_leave_identity_unchanged(self):
        valid = {"code": 0, "data": {"result": "SERVER-XID"}}
        cases = [(s, valid) for s in (None, "200", True, 199, 300, 403, 500)]
        cases += [(200, x) for x in (None, [], "{}", {}, {"data": valid["data"]})]
        cases += [(200, {"code": c, "data": valid["data"]})
                  for c in (None, "0", False, True, 0.0, 1, -1, 101135)]
        cases += [(200, {"code": 0, "data": d}) for d in (None, [], "XID")]
        cases += [(200, {"code": 0, "data": {"result": v}})
                  for v in (None, True, 123, [], {}, "", " ", "XID\n", "X ID", "X\x00ID")]
        cases += [(200, dict(valid, error={"code": 1})),
                  (200, dict(valid, success=False))]
        for status, response in cases:
            with self.subTest(status=status, response=response):
                state = {"a7": "LOCAL-XID", "a8": "LOCAL-DFP", "keep": {"nested": [1]}}
                before = copy.deepcopy(state)
                self.assertEqual(apply_registration_response(state, INFO, response,
                                                             http_status=status), {})
                self.assertEqual(state, before)

    def test_no_recursive_or_cross_endpoint_field_discovery(self):
        cases = [(INFO, {"code": 0, "data": {"dfp": "WRONG"}}),
                 (SIGN, {"code": 0, "data": {"result": "WRONG"}}),
                 (INFO, {"code": 0, "result": "WRONG", "data": {}}),
                 (INFO, {"code": 0, "data": {"nested": {"result": "WRONG"}}}),
                 ("/v5/device-info", {"code": 0, "data": {"dfp": "WRONG"}}),
                 ("/v5/sign/extra", {"code": 0, "data": {"dfp": "WRONG"}})]
        for endpoint, response in cases:
            with self.subTest(endpoint=endpoint, response=response):
                self.assertEqual(parse_registration_response(endpoint, response,
                                                             http_status=200), {})

    def test_parse_accepts_full_url_without_mutating_the_response(self):
        response = {"code": 0, "data": {"result": "XID"}}
        before = copy.deepcopy(response)
        patch = parse_registration_response("https://pikachu.example" + INFO + "?src=1",
                                            response, http_status=200)
        self.assertEqual(patch, {"a7": "XID", "a7_server_xid": "XID", "xid": "XID"})
        self.assertEqual(response, before)

    def test_existing_local_fields_survive_repeated_server_updates(self):
        state = {"a7": "SERVER-OLD", "xid": "SERVER-OLD",
                 "a7_server_xid": "SERVER-OLD", "a7_local_xid": "LOCAL-XID"}
        response = {"code": 0, "data": {"result": "SERVER-NEW"}}
        patch = apply_registration_response(state, INFO, response, http_status=200)
        self.assertNotIn("a7_local_xid", patch)
        self.assertEqual(state["a7_local_xid"], "LOCAL-XID")
        self.assertEqual(state["a7"], "SERVER-NEW")
        self.assertEqual(apply_registration_response(state, INFO, response,
                                                     http_status=200), {})

    def test_prior_server_value_is_not_relabelled_as_local(self):
        for server_key in ("a7_server_xid", "xid"):
            state = {"a7": "SERVER-OLD", server_key: "SERVER-OLD"}
            apply_registration_response(state, INFO,
                                        {"code": 0, "data": {"result": "SERVER-NEW"}},
                                        http_status=200)
            self.assertNotIn("a7_local_xid", state)

    def test_captured_value_already_matching_response_is_not_relabelled_local(self):
        state = {"a7": "SERVER-XID"}
        apply_registration_response(state, INFO,
                                    {"code": 0, "data": {"result": "SERVER-XID"}},
                                    http_status=200)
        self.assertEqual(state["a7_server_xid"], "SERVER-XID")
        self.assertNotIn("a7_local_xid", state)

    def test_identity_must_be_mutable_mapping(self):
        with self.assertRaises(TypeError):
            apply_registration_response([], INFO, {"code": 0, "data": {"result": "XID"}},
                                        http_status=200)


if __name__ == "__main__":
    unittest.main()
