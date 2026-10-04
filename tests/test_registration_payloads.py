"""Fresh body/state/signature integration, using a synthetic in-memory peer."""
from copy import deepcopy
import base64
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

import keeta_offline_flow as flow
from farm.fullsign import FullSigner
from mtgsig import a9_codec, envelope_codec, mtg_crypto
from mtgsig.registration_payloads import prepare_request_profile, render_envelope_plaintext
from tests.test_oneid import template as oneid_template
from tests.test_registration_execution import A1, INFO, SIGN, DEVICE, synthetic_step


def decode_fingerprint(value):
    return json.loads(unpad(AES.new(mtg_crypto.FINGERPRINT_I_KEY, AES.MODE_CBC,
                         mtg_crypto.FINGERPRINT_IV).decrypt(base64.b64decode(value)), 16))


class RegistrationPayloadTests(unittest.TestCase):
    def test_reporting_outer_replaces_captured_time_without_mutating_session(self):
        step = synthetic_step(DEVICE)
        state = {"envelope_device_data": "CURRENT", "reporting_inputs": {"device_info": {
            "timezone_offset_seconds": 28800, "sdk_version": "5.21.10", "ext": 3}}}
        before = deepcopy(state)
        prepared = prepare_request_profile(step, state, timestamp_ms=1000, a1=A1)
        request = flow.build_request({}, step["host"], step["path"], step["body_type"], prepared,
                                     template=step["template"])
        body = json.loads(request["body"])
        self.assertEqual(body["time"], "1970-01-01 08:00:01")
        self.assertEqual(body["data"], "CURRENT")
        self.assertEqual(state, before)
        for bad in ({}, {"device_info": {}}):
            with self.assertRaises(ValueError):
                prepare_request_profile(step, dict(state, reporting_inputs=bad), timestamp_ms=1000, a1=A1)

    def make_signer(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "identity.json"
        path.write_text(json.dumps(dict(a0="2.5", a1=A1, a3=25, a6=0,
            a7="LOCAL-XID", a8="LOCAL-DFP", x0=2, counter=0,
            a9=a9_codec.encode('{"0":12,"1":[],"2":[],"3":{}}', A1),
            base_collect={"b1":"{}", "b2":0, "b3":0})))
        return FullSigner(str(path))

    def test_fingerprint_refreshes_established_fields_without_inventing_telemetry(self):
        original = {"I18":"OLD-DEVICE", "I20":"OLD-VENDOR", "I39":"0", "I40":"OLD-UUID",
                    "I41":"OBSERVED-MEMORY", "I44":"OBSERVED-MEASUREMENT"}
        state = dict(fingerprint_obj=original, csecuuid="CURRENT-UUID", idfv="VENDOR",
                     device_id="DEVICE", a7="XID", a8="DFP")
        before = deepcopy(state)
        step = dict(name="check_update", body_type="plaintext_json")
        one = prepare_request_profile(step, state, timestamp_ms=1790615000123, a1=A1)
        two = prepare_request_profile(step, state, timestamp_ms=1790615000124, a1=A1)
        plain = decode_fingerprint(one["fingerprint"])
        self.assertEqual(plain, dict(original, I18="DEVICE", I20="VENDOR", I39="1790615000123", I40="CURRENT-UUID"))
        self.assertNotEqual(one["fingerprint"], two["fingerprint"])
        self.assertEqual(state, before)

    def test_body_is_rebuilt_with_response_state_before_signature(self):
        signer = self.make_signer()
        steps = [synthetic_step(p) for p in (INFO, SIGN, DEVICE)]
        config = {"plaintext":{"xid":"", "dfp":"", "padding":"synthetic"*32},
                  "bindings":{"xid":"a7", "dfp":"a8"}}
        key = bytes(range(16))
        state = {"envelope_session_key_hex":key.hex(),
                 "envelope_payloads":{s["name"]:config for s in steps}}
        before = deepcopy(state)
        expected = [("LOCAL-XID", "LOCAL-DFP"), ("SERVER-XID", "LOCAL-DFP"),
                    ("SERVER-XID", "SERVER-DFP")]
        replies = [{"code":0,"data":{"result":"SERVER-XID"}},
                   {"code":0,"data":{"dfp":"SERVER-DFP"}}, {"code":0}]
        observed = []
        def send(req):
            body = json.loads(req["body"])
            envelope = body.get("fingerPrintData", body.get("data"))
            value = json.loads(envelope_codec.decode_sdk(envelope, A1, session_key=key).plaintext)
            mt = json.loads(req["headers"]["mtgsig"])
            self.assertEqual((value["xid"], value["dfp"]), expected[len(observed)])
            self.assertEqual((mt["a7"], mt["a8"]), expected[len(observed)])
            observed.append(envelope)
            return 200, replies[len(observed)-1]
        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            events = list(flow.execute_offline_flow({}, state, signer, send, steps=steps))
        self.assertEqual(len(events), 3)
        self.assertTrue(all("error" not in e for e in events), events)
        self.assertEqual(len(set(observed)), 3)
        self.assertEqual(len({envelope_codec.split(e).part1 for e in observed}), 1)
        self.assertEqual(state, before)

    def test_oneid_context_reaches_headers_and_next_fingerprint(self):
        signer = self.make_signer()
        steps = []
        for required in (4, 1):
            step = synthetic_step("/uuid/oversea/ios/register")
            step["template"]["request"]["body"]["text"] = json.dumps(oneid_template(required))
            steps.append(step)
        step = synthetic_step("/appupdate/mach/checkUpdate")
        step["template"]["request"]["body"]["text"] = '{"UUID":"OLD","fingerprint":"OLD"}'
        steps.append(step)
        state = {"fingerprint_obj":{"I39":"0", "I40":"OLD"}, "oneid_session_id":"FRESH-SESSION"}
        sent = []
        def send(req):
            body = json.loads(req["body"])
            if len(sent) < 2:
                self.assertNotIn("mtgsig", req["headers"])
                self.assertEqual(req["headers"]["uuidSessionId"], "FRESH-SESSION")
            else:
                self.assertEqual(req["headers"]["csecuuid"], "GENERATED-CSECUUID")
                self.assertEqual(req["headers"]["pragma-unionid"], "GENERATED-UNION")
                self.assertEqual(body["UUID"], "GENERATED-CSECUUID")
                self.assertEqual(decode_fingerprint(body["fingerprint"])["I40"], "GENERATED-CSECUUID")
            sent.append(req)
            return 200, ({"code":0,"data":{"unionId":"GENERATED-CSECUUID" if len(sent)==1 else "GENERATED-UNION"}}
                         if len(sent)<3 else {"code":0})
        events = list(flow.execute_offline_flow({}, state, signer, send, steps=steps))
        self.assertEqual(len(events), 3)
        self.assertTrue(all("error" not in e for e in events), events)
        self.assertEqual(signer.dev["uuid"], "GENERATED-CSECUUID")
        self.assertEqual(signer.dev["unionid"], "GENERATED-UNION")
        from mtgsig.oneid import decode_oneid_identifier
        bodies = [json.loads(req["body"]) for req in sent[:2]]
        self.assertEqual(bodies[0]["idInfo"]["localId"], bodies[1]["idInfo"]["localId"])
        decode_oneid_identifier(bodies[0]["idInfo"]["localId"])
        request_ids = [req["headers"]["uuidRequestId"] for req in sent[:2]]
        self.assertEqual(len(set(request_ids)), 2)
        for value in request_ids:
            decode_oneid_identifier(value)

    def test_missing_binding_stops_before_transport_and_counter_change(self):
        signer = self.make_signer()
        step = synthetic_step(INFO)
        profile = {"envelope_payloads":{step["name"]:{"plaintext":{"x":""},"bindings":{"x":"unknown"}}}}
        events = list(flow.execute_offline_flow({}, profile, signer,
            lambda req: self.fail("missing binding reached transport"), steps=[step]))
        self.assertFalse(events[0]["sent"])
        self.assertEqual(signer.counter, 0)

    def test_exact_raw_plaintext_and_conflicting_sources(self):
        raw = '{ "space": true }'
        self.assertEqual(render_envelope_plaintext({"raw_plaintext":raw}, {}), raw.encode())
        with self.assertRaises(ValueError):
            render_envelope_plaintext({"raw_plaintext":raw,"bindings":{}}, {})
        with self.assertRaises(ValueError):
            prepare_request_profile({"name":"risk","body_type":"plaintext_urlencoded"},
                {"fingerprint":"CAPTURED", "fingerprint_obj":{}}, timestamp_ms=1,a1=A1)

    def test_bound_timestamp_observations_refresh_m239_before_serialization(self):
        vector = json.loads((Path(__file__).parent / "fixtures/m239_synthetic.json").read_text())["vectors"][2]
        state = {"filesystem_observations": json.dumps(vector["m251"], separators=(",", ":"))}
        config = {"plaintext": {"m239": "OLD", "m251": "[]"},
                  "bindings": {"m251": "filesystem_observations"}, "derive_m239": True}
        result = json.loads(render_envelope_plaintext(config, state))
        self.assertEqual(result["m239"], vector["m239"])
        self.assertEqual(result["m251"], state["filesystem_observations"])
        self.assertEqual(config["plaintext"]["m239"], "OLD")
        with self.assertRaises(ValueError):
            render_envelope_plaintext(dict(config, derive_m239=False), state)
        with self.assertRaises(ValueError):
            render_envelope_plaintext({"raw_plaintext": "{}", "derive_m239": True}, state)

    def test_identity_binding_refreshes_checksum_to_native_vm_vector(self):
        # This exact synthetic object/context produced 1120405568 in the
        # original ARM64 VM; it is independent of the Python checksum helper.
        context = dict(appkey="00000000-1111-2222-3333-444444444444", version="2.5",
                       sdk_flag=0, provider_mask_hex=bytes(range(16)).hex())
        config = {"plaintext": {"m1": "test", "m153": "OLD", "m320": "STALE"},
                  "bindings": {"m153": "csecuuid"}, "checksum_context": context}
        state = {"csecuuid": "synthetic-device"}
        result = json.loads(render_envelope_plaintext(config, state))
        self.assertEqual(result, {"m1": "test", "m153": "synthetic-device", "m320": "1120405568"})
        self.assertEqual(config["plaintext"]["m320"], "STALE")
        from mtgsig.corpse_codec import decode_fields
        transformed = json.loads(render_envelope_plaintext(dict(config, transform="m-series"), state))
        self.assertEqual(decode_fields(transformed), result)
        with self.assertRaises(ValueError):
            render_envelope_plaintext({k:v for k,v in config.items() if k != "checksum_context"}, state)
        with self.assertRaises(ValueError):
            render_envelope_plaintext({"raw_plaintext": "{}", "checksum_context": context}, state)

    def test_m175_uses_bound_device_inputs_and_explicit_time_before_checksum(self):
        from mtgsig.m175_codec import decode_m175
        from mtgsig.registration_checksum import compute_m320
        from mtgsig.corpse_codec import decode_fields
        context = dict(appkey=A1, version="2.5", sdk_flag=0,
                       provider_mask_hex=bytes(range(16)).hex())
        config = {"plaintext": {"m166": "OLD", "m160": "iOS 16.2", "m19": "0",
                                 "m167": "828*1792", "m175": "OLD", "m320": "OLD"},
                  "bindings": {"m166": "model"}, "derive_m175": True,
                  "checksum_context": context, "transform": "m-series"}
        state = {"model": "synthetic-model", "device_name": "Test device",
                 "timestamp_ms": 1790615000123}
        value = decode_fields(json.loads(render_envelope_plaintext(config, state)))
        decoded = decode_m175(value["m175"])
        self.assertEqual(decoded.first, {"a": state["model"], "b": str(state["timestamp_ms"])})
        self.assertEqual(decoded.second["m"], state["device_name"])
        expected = compute_m320(value, appkey=A1, version="2.5", sdk_flag=0,
                                provider_mask=bytes(range(16)))
        self.assertEqual(value["m320"], expected)
        refreshed = decode_fields(json.loads(render_envelope_plaintext(config,
            dict(state, timestamp_ms=state["timestamp_ms"] + 1))))
        self.assertNotEqual(refreshed["m175"], value["m175"])
        self.assertNotEqual(refreshed["m320"], value["m320"])
        self.assertEqual(config["plaintext"]["m175"], "OLD")
        for invalid in (dict(config, derive_m175=False),
                        {k:v for k,v in config.items() if k != "checksum_context"},
                        {"raw_plaintext": "{}", "derive_m175": True}):
            with self.assertRaises(ValueError):
                render_envelope_plaintext(invalid, state)
        with self.assertRaises(ValueError):
            render_envelope_plaintext(config, {k:v for k,v in state.items() if k != "device_name"})

    def test_fresh_outid_history_follows_only_accepted_response_state(self):
        from mtgsig.corpse_codec import decode_fields
        from mtgsig.registration_checksum import compute_m320
        signer = self.make_signer()
        steps = [synthetic_step(p) for p in (SIGN, SIGN, SIGN, DEVICE)]
        checksum = dict(appkey=A1, version="2.5", sdk_flag=0,
                        provider_mask_hex=bytes(range(16)).hex())
        config = {"plaintext": {"m166": "synthetic-model", "m154": "com.example.fixture",
                    "m306": json.dumps({"m400": '{"old-device":[{"old-app":"OLD-DFP"}]}',
                                        "m433": "UNCHANGED", "m599": "UNKNOWN"}), "m320": "OLD"},
                  "derive_outid_history": True, "checksum_context": checksum, "transform": "m-series"}
        key = bytes(range(16))
        state = {"envelope_session_key_hex": key.hex(), "fresh_outid_history": True,
                 "model": "synthetic-model", "envelope_payloads": {s["name"]: config for s in steps}}
        before = deepcopy(state)
        expected = [{}, {"synthetic-modelApple": [{"com.example.fixture": "SERVER-DFP-ONE"}]},
                       {"synthetic-modelApple": [{"com.example.fixture": "SERVER-DFP-ONE"}]},
                       {"synthetic-modelApple": [{"com.example.fixture": "SERVER-DFP-THREE"}]}]
        replies = [{"code": 0, "data": {"dfp": value, "ab_test_flag": flag}} for value, flag in
                   (("SERVER-DFP-ONE", "B"), ("SERVER-DFP-TWO", "A"), ("SERVER-DFP-THREE", "B"))]
        replies.append({"code": 0})
        calls = []
        def send(req):
            body = json.loads(req["body"])
            wire = json.loads(envelope_codec.decode_sdk(body["data"], A1, session_key=key).plaintext)
            fields = decode_fields(wire)
            nested = json.loads(fields["m306"])
            self.assertEqual(json.loads(nested["m400"]), expected[len(calls)])
            self.assertEqual({k: v for k, v in nested.items() if k != "m400"},
                             {"m433": "UNCHANGED", "m599": "UNKNOWN"})
            self.assertEqual(fields["m320"], compute_m320(fields, appkey=A1, version="2.5",
                             sdk_flag=0, provider_mask=bytes(range(16))))
            calls.append(req)
            return 200, replies[len(calls) - 1]
        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            events = list(flow.execute_offline_flow({}, state, signer, send, steps=steps))
        self.assertEqual(len(calls), 4)
        self.assertTrue(all("error" not in e for e in events), events)
        self.assertEqual(state, before)
        # A local current a8 must never be turned into a server history entry.
        initial = decode_fields(json.loads(render_envelope_plaintext(config,
                                      dict(fresh_outid_history=True, a8="LOCAL-CANDIDATE"))))
        self.assertEqual(json.loads(initial["m306"])["m400"], "{}")
        legacy = dict(config, derive_outid_history=False)
        legacy_value = decode_fields(json.loads(render_envelope_plaintext(legacy, {})))
        self.assertEqual(json.loads(legacy_value["m306"])["m400"],
                         json.loads(config["plaintext"]["m306"])["m400"])
        for bad in ({}, {"fresh_outid_history": True, "outid_history_dfp": ""},
                    {"fresh_outid_history": True, "outid_history_dfp": "bad value"},
                    {"fresh_outid_history": True, "model": "different-model"}):
            with self.subTest(keys=tuple(bad)), self.assertRaises(ValueError):
                render_envelope_plaintext(config, bad)
        for bad in ({"raw_plaintext": "{}", "derive_outid_history": True},
                    {k: v for k, v in config.items() if k != "checksum_context"},
                    dict(config, derive_outid_history="true")):
            with self.assertRaises(ValueError):
                render_envelope_plaintext(bad, {"fresh_outid_history": True})


if __name__ == '__main__':
    unittest.main()
