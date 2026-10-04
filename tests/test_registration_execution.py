"""Registration execution with real signers and an in-memory response sender.

No test sends HTTP or accesses a phone. Optional workspace captures are only
read to check request order and to replay their two registration responses.
"""
import copy
import json
from collections import OrderedDict
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import keeta_offline_flow as flow
from farm.fullsign import FullSigner, compute_a2, k2buf
from keeta_sign_offline import OfflineSigner, compute_a2 as legacy_compute_a2
from mtgsig import a9_codec, mtg_crypto


ROOT = Path(__file__).resolve().parents[1]
A1 = "00112233-4455-6677-8899-aabbccddeeff"
INFO = "/fingerprint/v1/info/report"
SIGN = "/v5/sign"
DEVICE = "/v5/device-info"


def synthetic_step(path, marker="fixture"):
    step = dict(next(s for s in flow.FLOW_STEPS if s["path"] == path))
    body = {"fingerPrintData" if path == INFO else "data": "CAPTURED-ENVELOPE",
            "marker": marker}
    if path == "/ntp":
        body = {"data": "CAPTURED-ENVELOPE"}
    if path == "/sdkapi/newreg":
        body = {"random": "1700000000", "deviceid": "IDFV", "signature": "OLD"}
    step["template"] = {
        "host": step["host"], "path": path,
        "request": {"header": {"headers": [
            {"name": ":path", "value": path},
            {"name": "Content-Type", "value": "application/json"},
            {"name": "mtgsig", "value": "STALE-CAPTURED-SIGNATURE"},
        ]}, "body": {"text": json.dumps(body)}},
    }
    return step


class RegistrationExecutionTests(unittest.TestCase):
    def test_missing_email_stops_before_signing_or_transport(self):
        for path in (flow.login_protocol.RISK_PATH,
                     "/api/protocolcenter/v1/protocol/confirmProtocol"):
            step = synthetic_step(path)
            step["body_type"] = "plaintext_urlencoded"
            step["template"]["request"]["body"]["text"] = "email=historical%40example.test"
            before = self.signer.counter
            events = list(flow.execute_offline_flow({}, self.profile, self.signer,
                lambda req: self.fail("missing current email reached transport"), steps=[step]))
            self.assertFalse(events[0]["sent"])
            self.assertIn("email", events[0]["error"])
            self.assertEqual(self.signer.counter, before)

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        siua = {"0": 12, "1": ["synthetic"], "2": [], "3": {}}
        self.identity = OrderedDict(
            a0="2.5", a1=A1, a3=25, a6=0, a7="LOCAL-XID", a8="LOCAL-DFP",
            a9=a9_codec.encode(json.dumps(siua), A1, mode="twofish-mod"), x0=2,
            base_collect={"b1": "{}", "b2": 1, "b3": 0,
                          "b4": "com.sankuai.sailor.ifooddelivery", "b7": 0, "b8": 0},
            counter=1000)
        self.path = self.directory / "identity.json"
        self.path.write_text(json.dumps(self.identity))
        self.signer = FullSigner(str(self.path))
        self.profile = {"envelope_info_data": "CURRENT-INFO", "envelope_sign_data": "CURRENT-SIGN",
                        "envelope_device_data": "CURRENT-DEVICE"}
        self.steps = [synthetic_step(INFO), synthetic_step(SIGN), synthetic_step(DEVICE)]

    def assert_wire_signature(self, req):
        mt = json.loads(req["headers"]["mtgsig"], object_pairs_hook=OrderedDict)
        actual = mt.pop("a2")
        counter = int(mt["a10"].split(",")[1])
        payload = json.dumps(mt, ensure_ascii=False, separators=(",", ":"))
        expected = compute_a2(req["method"], req["url"], req["body"], payload, A1, counter)
        self.assertEqual(actual, expected)
        # Bind the response-derived fields, not just the URL/body: a signature
        # computed with the old identity must differ from the transmitted one.
        for field in ("a7", "a8"):
            altered = dict(mt)
            altered[field] += "-ALTERED"
            self.assertNotEqual(actual, compute_a2(
                req["method"], req["url"], req["body"],
                json.dumps(altered, ensure_ascii=False, separators=(",", ":")), A1, counter))
        collect = json.loads(mtg_crypto.a5_decrypt(mt["a5"], A1, 25, mt["a4"], k2buf(A1)))
        self.assertEqual(collect["b3"], 0)
        self.assertGreater(collect["b2"], counter)
        return mt

    def test_response_applied_before_the_next_request_is_signed(self):
        observed = []
        expected_states = [("LOCAL-XID", "LOCAL-DFP"),
                           ("SERVER-XID", "LOCAL-DFP"),
                           ("SERVER-XID", "SERVER-DFP")]
        responses = [{"code": 0, "data": {"result": "SERVER-XID"}},
                     {"code": 0, "data": {"dfp": "SERVER-DFP"}}, {"code": 0}]

        def sender(req):
            mt = self.assert_wire_signature(req)
            self.assertEqual((mt["a7"], mt["a8"]), expected_states[len(observed)])
            observed.append(req)
            return 200, responses[len(observed) - 1]

        events = list(flow.execute_offline_flow({}, self.profile, self.signer, sender,
                                                steps=self.steps))
        self.assertEqual(len(events), 3)
        self.assertTrue(all(e["sent"] and "error" not in e for e in events))
        self.assertEqual(self.signer.a7, "SERVER-XID")
        self.assertEqual(self.signer.a8, "SERVER-DFP")
        self.assertEqual(self.signer.dev["a7_local_xid"], "LOCAL-XID")
        self.assertEqual(self.signer.dev["a8_local_dfp"], "LOCAL-DFP")
        self.assertNotIn("a7", self.profile)  # Caller profile is not mutated.

    def test_repeated_steps_keep_their_own_templates_and_fresh_signatures(self):
        repeated = [synthetic_step(DEVICE, "first"), synthetic_step(DEVICE, "second")]
        requests = []

        def sender(req):
            self.assert_wire_signature(req)
            requests.append(req)
            return 200, {"code": 0}

        events = list(flow.execute_offline_flow({}, self.profile, self.signer, sender,
                                                steps=repeated))
        self.assertEqual([json.loads(r["body"])["marker"] for r in requests], ["first", "second"])
        self.assertEqual(len(events), 2)
        counters = [json.loads(r["headers"]["mtgsig"])["a10"] for r in requests]
        self.assertEqual(counters, ["3,1000", "3,1000"])
        sequences = []
        for req in requests:
            mt = json.loads(req["headers"]["mtgsig"])
            col = json.loads(mtg_crypto.a5_decrypt(mt["a5"], A1, 25, mt["a4"], k2buf(A1)))
            sequences.append(col["b2"])
        self.assertEqual(sequences, [1001, 1002])

    def test_error_response_stops_without_mutating_registration_state(self):
        for status, response in [(503, {"code": 0, "data": {"result": "BAD"}}),
                                 (200, {"code": 101135, "data": {"result": "BAD"}}),
                                 (200, {"code": False, "data": {"result": "BAD"}}),
                                 (200, {"code": 0, "data": {"result": 123}}),
                                 (200, {"code": 0, "data": {}})]:
            with self.subTest(status=status, response=response):
                signer = FullSigner(str(self.path))
                before = copy.deepcopy(signer.dev)
                requests = []

                def sender(req):
                    requests.append(req)
                    return status, response

                events = list(flow.execute_offline_flow({}, self.profile, signer, sender,
                                                        steps=self.steps))
                self.assertEqual(len(requests), 1)
                self.assertEqual(len(events), 1)
                self.assertIn("error", events[0])
                self.assertEqual(signer.dev, before)
                self.assertEqual((signer.a7, signer.a8), ("LOCAL-XID", "LOCAL-DFP"))

    def test_missing_envelope_stops_before_signing_or_transport(self):
        def unexpected_sender(req):
            self.fail("missing envelope reached sender")

        events = list(flow.execute_offline_flow({}, {}, self.signer, unexpected_sender,
                                                steps=self.steps))
        self.assertEqual(len(events), 1)
        self.assertFalse(events[0]["sent"])
        self.assertIn("envelope_info_data", events[0]["error"])
        self.assertEqual(self.signer.counter, 1000)

    def test_failed_or_empty_signature_never_reaches_sender(self):
        def unexpected_sender(req):
            self.fail("unsigned request reached sender")

        for return_value, side_effect in [(None, None), ("", None),
                                         (None, RuntimeError("signer unavailable"))]:
            with self.subTest(value=return_value, error=side_effect):
                with patch.object(self.signer, "sign", return_value=return_value,
                                  side_effect=side_effect):
                    events = list(flow.execute_offline_flow({}, self.profile, self.signer,
                                                           unexpected_sender, steps=self.steps))
                self.assertFalse(events[0]["sent"])
                self.assertIn("sign_error", events[0]["request"])
                self.assertNotIn("mtgsig", events[0]["request"]["headers"])

    def test_newreg_is_locally_signed_without_mtgsig(self):
        from mtgsig.newreg import newreg_signature
        requests = []

        def sender(req):
            requests.append(req)
            return 200, {"pushtoken": "SYNTHETIC-PUSH-TOKEN", "heartbeat": 120}

        events = list(flow.execute_offline_flow({}, {}, self.signer, sender,
                                                steps=[synthetic_step("/sdkapi/newreg")],
                                                clock=lambda: 1700000100))
        self.assertNotIn("error", events[0])
        body = json.loads(requests[0]["body"])
        self.assertEqual(body["random"], "1700000100")
        self.assertEqual(body["signature"], newreg_signature("1700000100"))
        self.assertNotIn("mtgsig", requests[0]["headers"])
        self.assertEqual(self.signer.counter, 1000)
        self.assertEqual(self.signer.dev["push_token"], "SYNTHETIC-PUSH-TOKEN")

    def test_newreg_without_token_stops_before_next_request(self):
        sent = []
        def sender(req):
            sent.append(req)
            return 200, {"code": 0}
        events = list(flow.execute_offline_flow({}, self.profile, self.signer, sender,
            steps=[synthetic_step("/sdkapi/newreg"), synthetic_step(INFO)]))
        self.assertEqual(len(sent), 1)
        self.assertIn("error", events[0])
        self.assertNotIn("push_token", self.signer.dev)

    def test_noninteger_error_codes_do_not_pass_the_nonregistration_gate(self):
        for code in (False, True, 0.0, None, [], {}, 1, "1"):
            with self.subTest(code=code):
                requests = []

                def sender(req):
                    requests.append(req)
                    return 200, {"code": code}

                events = list(flow.execute_offline_flow(
                    {}, self.profile, self.signer, sender,
                    steps=[synthetic_step(DEVICE, "first"), synthetic_step(DEVICE, "second")]))
                self.assertEqual(len(events), 1)
                self.assertEqual(len(requests), 1)
                self.assertIn("error", events[0])

    def test_malformed_nonempty_signature_stops_before_transport(self):
        complete = json.loads(self.signer.sign("POST", "https://example.test/path", "{}"))
        invalid = ["not-json-signature", "[]", "null", "{}", '{"a2":"' + "0" * 32 + '"}']
        for a2 in (None, 1, [], "", "Z" * 32, "0" * 31):
            invalid.append(json.dumps(dict(complete, a2=a2)))

        def unexpected_sender(req):
            self.fail("malformed signature reached sender")

        for encoded in invalid:
            with self.subTest(encoded=encoded):
                with patch.object(self.signer, "sign", return_value=encoded):
                    events = list(flow.execute_offline_flow(
                        {}, self.profile, self.signer, unexpected_sender, steps=self.steps))
                self.assertEqual(len(events), 1)
                self.assertFalse(events[0]["sent"])
                self.assertEqual(events[0]["error"], "invalid mtgsig structure")

    def test_failed_response_does_not_rewrite_a_captured_identity_to_effective_attrs(self):
        identity = dict(self.identity, a7="CAPTURED-XID", a8="CAPTURED-DFP",
                        a7_server_xid="PRIOR-SERVER-XID", a8_server_dfp="PRIOR-SERVER-DFP")
        self.path.write_text(json.dumps(identity))
        signer = FullSigner(str(self.path))
        before = copy.deepcopy(signer.dev)
        self.assertNotEqual(signer.a7, signer.dev["a7"])
        for endpoint in (INFO, SIGN):
            self.assertEqual(signer.apply_registration_response(endpoint, {"code": 9},
                                                               http_status=200), {})
            self.assertEqual(signer.dev, before)
            self.assertEqual((signer.a7, signer.a8), ("PRIOR-SERVER-XID", "PRIOR-SERVER-DFP"))

    def test_malformed_explicit_newreg_signature_stops_before_transport(self):
        def unexpected_sender(req):
            self.fail("malformed newreg signature reached sender")

        for value in ("invalid", "0" * 39, "A" * 40, 123, ["signature"]):
            with self.subTest(value=value):
                events = list(flow.execute_offline_flow(
                    {}, {"newreg_signature": value}, self.signer, unexpected_sender,
                    steps=[synthetic_step("/sdkapi/newreg")]))
                self.assertEqual(len(events), 1)
                self.assertFalse(events[0]["sent"])
                self.assertIn("40 lowercase hex", events[0]["request"]["error"])

    def test_legacy_offline_signer_updates_signed_payload_and_wire_together(self):
        # Create a self-contained sample with a deterministic synthetic HMAC K.
        initial = json.loads(self.signer.sign("POST", "https://example.test/initial", "{}"),
                             object_pairs_hook=OrderedDict)
        initial.pop("a2")
        payload = json.dumps(initial, separators=(",", ":"))
        sample = self.directory / "sample.json"
        sample.write_text(json.dumps({"K": bytes(range(36)).hex(), "mtgsig": dict(initial),
                                      "msg_hex": payload.encode().hex()}))
        signer = OfflineSigner(str(sample))
        observed = []

        def sender(req):
            mt = json.loads(req["headers"]["mtgsig"], object_pairs_hook=OrderedDict)
            a2 = mt.pop("a2")
            pay = json.dumps(mt, separators=(",", ":"))
            self.assertEqual(a2, legacy_compute_a2("POST", req["url"], req["body"], pay, signer.K))
            self.assertEqual(list(mt), FullSigner.ORDER)
            observed.append(mt)
            return 200, ({"code": 0, "data": {"result": "SERVER-XID"}} if req["path"] == INFO
                         else {"code": 0, "data": {"dfp": "SERVER-DFP"}} if req["path"] == SIGN
                         else {"code": 0})

        events = list(flow.execute_offline_flow({}, self.profile, signer, sender, steps=self.steps))
        self.assertEqual(len(events), 3)
        self.assertEqual([(m["a7"], m["a8"]) for m in observed],
                         [("LOCAL-XID", "LOCAL-DFP"), ("SERVER-XID", "LOCAL-DFP"),
                          ("SERVER-XID", "SERVER-DFP")])
        self.assertNotIn("a7_local_xid", json.loads(signer.pay_template))
        self.assertEqual(signer.mt["a7_local_xid"], "LOCAL-XID")

    def scfg_profile(self):
        return dict(self.profile, csecuuid="CURRENT-ONEID", scfg_inputs={
            "raw_fields": {"m154": "com.example.sandbox", "m144": "3.12.401",
                           "m153": "OLD-CACHE-ID", "m136": ""},
            "os_version": "16.2", "sdk_version": "5.21.10", "city": "", "user_id": None})

    def test_scfg_rebuilds_from_response_identity_and_applies_configuration(self):
        from mtgsig.scfg import decode_scfg_data, encode_scfg_data
        steps = [synthetic_step(SIGN), synthetic_step("/v1/scfg"), synthetic_step("/v1/scfg")]
        observed, snapshots = [], []
        config = {"private_key_config": "m1|m4", "applist_config": "221", "version_code": "1"}
        def sender(req):
            self.assert_wire_signature(req)
            observed.append(req)
            if req["path"] == SIGN:
                return 200, {"code": 0, "data": {"dfp": "FRESH-SERVER-DFP"}}
            fields = decode_scfg_data(json.loads(req["body"])["data"])
            self.assertEqual(fields["dfpid"], "FRESH-SERVER-DFP")
            self.assertEqual(fields["uuid"], "CURRENT-ONEID")
            self.assertEqual(fields["timestamp"], "1700000200123")
            self.assertEqual(fields["userid"], "-1")
            self.assertEqual(fields["city"], "")
            return 200, {"code": 0, "resStr": "wrong-top-level-path",
                         "data": {"resStr": encode_scfg_data(config)}}
        def after_prepare(step, state, now):
            snapshots.append(copy.deepcopy(state))
            return state
        events = list(flow.execute_offline_flow({}, self.scfg_profile(), self.signer, sender,
            steps=steps, clock=lambda: 1700000200.123, payload_builder=after_prepare))
        self.assertEqual(len(observed), 3)
        self.assertTrue(all("error" not in e for e in events))
        self.assertTrue(snapshots[2]["scfg_applist_open"])
        self.assertEqual(snapshots[2]["scfg_private_collect_fields"], ["m1", "m4"])
        self.assertEqual(self.signer.dev["scfg_private_collect_fields"], ["m1", "m4", "m1", "m4"])
        self.assertEqual(events[1]["scfg_state"]["scfg_config"], config)
        self.assertEqual(self.scfg_profile()["scfg_inputs"]["raw_fields"]["m153"], "OLD-CACHE-ID")

    def test_scfg_does_not_fall_back_to_captured_data_or_invalid_responses(self):
        steps = [synthetic_step("/v1/scfg"), synthetic_step(DEVICE)]
        for bad in ({}, {"scfg_inputs": {}}, dict(self.scfg_profile(), csecuuid="")):
            with self.subTest(profile=bool(bad)):
                before = self.signer.counter
                events = list(flow.execute_offline_flow({}, bad, self.signer,
                    lambda req: self.fail("incomplete scfg inputs reached network"), steps=steps))
                self.assertEqual(len(events), 1)
                self.assertFalse(events[0]["sent"])
                self.assertEqual(self.signer.counter, before)
        for response in ({"code": 0, "resStr": "not-nested"},
                         {"code": 0, "data": {"resStr": "invalid-ciphertext"}}):
            sent = []
            def sender(req):
                sent.append(req)
                return 200, response
            events = list(flow.execute_offline_flow({}, self.scfg_profile(), self.signer,
                                                    sender, steps=steps))
            self.assertEqual(len(sent), 1)
            self.assertIn("error", events[0])
            self.assertNotIn("scfg_config", self.signer.dev)

    def test_workspace_capture_order_and_registration_responses_without_network(self):
        captures = [
            ("evidence/captures/从app初次打开到登录被拦截.chlsj",
             [28, 35, 49, 55, 95, 96, 100, 138, 151, 156, 158, 177, 178, 221, 230, 268, 349, 358, 535, 777, 800, 801], [INFO, SIGN]),
            ("evidence/captures/新机之后尝试登录.chlsj",
             [7, 10, 16, 20, 21, 65, 97, 143, 161, 190, 193, 205, 244, 248, 257, 296, 375, 464, 478, 627, 628], [SIGN, INFO]),
        ]
        if not all((ROOT / name).exists() for name, _, _ in captures):
            self.skipTest("optional original Charles captures are not distributed")
        for name, indices, registration_order in captures:
            with self.subTest(capture=name):
                steps = flow.load_capture_steps(ROOT / name)
                self.assertEqual([s["capture_index"] for s in steps], indices)
                self.assertGreater(sum(s["path"] == DEVICE for s in steps), 1)
                selected = [s for s in steps if s["path"] in (INFO, SIGN)]
                self.assertEqual([s["path"] for s in selected], registration_order)
                signer = FullSigner(str(self.path))
                known = {"a7": "LOCAL-XID", "a8": "LOCAL-DFP"}
                observed = []

                def sender(req):
                    mt = self.assert_wire_signature(req)
                    self.assertEqual((mt["a7"], mt["a8"]), (known["a7"], known["a8"]))
                    step = selected[len(observed)]
                    self.assertEqual(req["path"], step["path"])
                    original = step["template"]["response"]
                    status = int(original["header"]["firstLine"].split()[1])
                    response = json.loads(original["body"]["text"])
                    field, wire = ("a7", "result") if step["path"] == INFO else ("a8", "dfp")
                    known[field] = response["data"][wire]
                    observed.append(req["path"])
                    return status, response

                # Defensive network guard: this path must stay file/callback-only.
                with patch("socket.socket", side_effect=AssertionError("network forbidden in replay")):
                    events = list(flow.execute_offline_flow({}, self.profile, signer, sender,
                                                           steps=selected))
                self.assertEqual(observed, registration_order)
                self.assertTrue(all("error" not in e for e in events))
                self.assertEqual((signer.a7, signer.a8), (known["a7"], known["a8"]))

    def test_confirm_protocol_capture_selects_json_and_form_per_request(self):
        path = "/api/protocolcenter/v1/protocol/confirmProtocol"
        samples = []
        for content_type, body in [
            ("application/json; charset=utf-8", '{"appId":"517","placementId":"install_splash","action":2}'),
            ("application/x-www-form-urlencoded; charset=utf-8", "action=2&placementId=login_register"),
            (None, '{"appId":"517","placementId":"region_switch","action":2}'),
        ]:
            headers = [{"name": "Content-Type", "value": content_type}] if content_type else []
            samples.append({"host": "example.test", "path": path,
                            "request": {"header": {"headers": headers}, "body": {"text": body}}})
        capture = self.directory / "mixed.json"
        capture.write_text(json.dumps(samples))
        steps = flow.load_capture_steps(capture)
        self.assertEqual([s["body_type"] for s in steps],
                         ["plaintext_json", "plaintext_urlencoded", "plaintext_json"])
        plan = flow.build_offline_plan({}, {}, steps=steps)
        self.assertEqual(json.loads(plan[0]["body"])["placementId"], "install_splash")
        self.assertEqual(json.loads(plan[2]["body"])["placementId"], "region_switch")
        self.assertEqual(plan[1]["body"], samples[1]["request"]["body"]["text"])

    def test_both_real_captures_keep_confirm_protocol_wire_formats(self):
        captures = [("evidence/captures/从app初次打开到登录被拦截.chlsj", [28, 138, 800]),
                    ("evidence/captures/新机之后尝试登录.chlsj", [143, 190, 627])]
        if not all((ROOT / name).exists() for name, _ in captures):
            self.skipTest("optional original Charles captures are not distributed")
        for name, indices in captures:
            with self.subTest(capture=name):
                steps = [s for s in flow.load_capture_steps(ROOT / name)
                         if s["name"] == "confirm_protocol"]
                self.assertEqual([s["capture_index"] for s in steps], indices)
                self.assertEqual([s["body_type"] for s in steps],
                                 ["plaintext_json", "plaintext_json", "plaintext_urlencoded"])
                plan = flow.build_offline_plan({}, {}, steps=steps)
                for req, step in zip(plan[:2], steps[:2]):
                    self.assertEqual(json.loads(req["body"]),
                                     json.loads(step["template"]["request"]["body"]["text"]))
                self.assertIn("placementId=login_register", plan[2]["body"])


if __name__ == "__main__":
    unittest.main()
