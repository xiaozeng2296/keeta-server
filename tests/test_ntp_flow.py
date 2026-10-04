"""FAMA flow integration: local fixtures only, no transport or device access."""
import base64
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import keeta_offline_flow as flow
from farm.fullsign import FullSigner
from keeta_sign_offline import OfflineSigner
from mtgsig import a9_codec, envelope_codec
from mtgsig.corpse_codec import decode_fields
from mtgsig.registration_checksum import compute_m320
from mtgsig import registration_region
from tests.test_registration_execution import A1, SIGN, DEVICE, synthetic_step


def ntp_fixture():
    # Independent wire fixture: timestamp low four bytes are 05 06 07 08.
    plain, mask = bytes(range(28)), b'\x05\x06\x07\x08'
    return plain.hex(), {"status": 0, "version": "1.0", "ab_test_flag": "A", "interval": 24,
        "ts": 0x0102030405060708, "ntp_info": base64.b64encode(bytes(
            value ^ mask[index % 4] for index, value in enumerate(plain))).decode()}


class NtpFlowTests(unittest.TestCase):
    def setUp(self):
        guard = patch("socket.socket", side_effect=AssertionError("network forbidden"))
        guard.start()
        self.addCleanup(guard.stop)
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.identity_file = Path(temp.name) / "identity.json"
        self.identity = dict(a0="2.5", a1=A1, a3=25, a6=0, a7="LOCAL-XID", a8="LOCAL-DFP", x0=2,
            counter=0, base_collect={"b1": "{}", "b2": 0, "b3": 0},
            a9=a9_codec.encode('{"0":12,"1":[],"2":[],"3":{}}', A1))
        self.identity_file.write_text(json.dumps(self.identity))
        self.signer = FullSigner(self.identity_file)
        self.dfp, self.reply = ntp_fixture()

    def test_ntp_decode_updates_next_signed_envelope_and_history(self):
        steps = [synthetic_step(path) for path in ("/ntp", SIGN, DEVICE)]
        checksum = dict(appkey=A1, version="2.5", sdk_flag=0, provider_mask_hex=bytes(range(16)).hex())
        # A synthetic plaintext exercises state/cipher plumbing only; this
        # fixture does not claim to be the native FAMA collector recipe.
        config = {"plaintext": {"m27": "OLD", "m166": "fixture-model", "m154": "com.example.fixture",
                  "m306": '{"m400":"{}","m433":"UNCHANGED"}', "m320": "OLD"},
                  "bindings": {"m27": "a8"}, "derive_outid_history": True,
                  "checksum_context": checksum, "transform": "m-series"}
        key = bytes(range(16))
        profile = dict(fresh_outid_history=True, model="fixture-model", envelope_session_key_hex=key.hex(),
                       envelope_payloads={step["name"]: deepcopy(config) for step in steps})
        before = deepcopy(profile)
        replies = [self.reply, {"code": 0, "data": {"ab_test_flag": "A", "dfp": "PLAIN-SIGN-DFP"}}, {"code": 0}]
        expected = ["LOCAL-DFP", self.dfp, "PLAIN-SIGN-DFP"]
        sent, wrappers = [], []
        def send(req):
            index = len(sent)
            body = json.loads(req["body"])
            if index == 0:
                self.assertEqual(set(body), {"data"})
            fields = decode_fields(json.loads(envelope_codec.decode_sdk(body["data"], A1, session_key=key).plaintext))
            wrappers.append(envelope_codec.split(body["data"]).part1)
            self.assertEqual(fields["m27"], expected[index])
            self.assertEqual(json.loads(req["headers"]["mtgsig"])["a8"], expected[index])
            history = json.loads(json.loads(fields["m306"])["m400"])
            self.assertEqual(history, {} if index == 0 else {"fixture-modelApple": [{"com.example.fixture": self.dfp}]})
            self.assertEqual(fields["m320"], compute_m320(fields, appkey=A1, version="2.5", sdk_flag=0,
                             provider_mask=bytes(range(16))))
            sent.append(req)
            return 200, replies[index]
        events = list(flow.execute_offline_flow({}, profile, self.signer, send, steps=steps))
        self.assertEqual(len(sent), 3)
        self.assertTrue(all("error" not in event for event in events), events)
        self.assertEqual(len(set(wrappers)), 1)
        self.assertEqual(self.signer.dev["outid_history_dfp"], self.dfp)
        self.assertEqual(self.signer.dev["ntp_response_source"], "/ntp")
        self.assertEqual(self.signer.dev["ntp_fingerprint_data"]["ab_test_flag"], "A")
        self.assertEqual(self.signer.dev["a8_local_dfp"], "LOCAL-DFP")
        self.assertEqual(profile, before)
        self.signer.persist_counter()
        self.assertEqual(FullSigner(self.identity_file).dev["outid_history_dfp"], self.dfp)

    def test_missing_ntp_payload_cannot_reuse_generic_envelope_or_capture(self):
        before = self.signer.counter
        events = list(flow.execute_offline_flow({}, {"envelope_data": "ANOTHER-ROUTE"}, self.signer,
            lambda req: self.fail("missing NTP payload reached transport"), steps=[synthetic_step("/ntp")]))
        self.assertFalse(events[0]["sent"])
        self.assertIn("envelope_payloads.ntp", events[0]["error"])
        self.assertEqual(self.signer.counter, before)

    def test_invalid_ntp_response_cannot_mutate_identity_or_continue(self):
        before = deepcopy(self.signer.dev)
        sent = []
        def send(req):
            sent.append(req)
            return 200, dict(self.reply, ntp_info="truncated")
        events = list(flow.execute_offline_flow({}, {"envelope_ntp_data": "CURRENT-NTP"}, self.signer,
            send, steps=[synthetic_step("/ntp"), synthetic_step(SIGN)]))
        self.assertEqual(len(sent), 1)
        self.assertIn("error", events[0])
        self.assertEqual(self.signer.dev, before)
        self.assertEqual(self.signer.a8, "LOCAL-DFP")

    def test_legacy_signer_updates_payload_and_metadata_atomically(self):
        signer = OfflineSigner.__new__(OfflineSigner)
        signer.mt = deepcopy(self.identity)
        signer.pay_template = json.dumps(self.identity)
        changed = signer.apply_registration_response("/ntp", self.reply, http_status=200)
        self.assertEqual(changed["outid_history_dfp"], self.dfp)
        self.assertEqual(signer.mt["a8"], self.dfp)
        self.assertEqual(json.loads(signer.pay_template)["a8"], self.dfp)
        before = signer.mt, signer.pay_template
        self.assertEqual(signer.apply_registration_response("/ntp", dict(self.reply, status=1), http_status=200), {})
        self.assertEqual((signer.mt, signer.pay_template), before)

    def test_capture_keeps_each_ntp_authority_and_unknown_route_is_not_invented(self):
        rows = []
        for authority in ("poke.mykeeta.com", "poke-eu.mykeeta.com", "poke.mykeeta.com"):
            row = synthetic_step("/ntp")["template"]
            row["host"] = "coalesced.example.test"
            row["request"]["header"]["headers"].append({"name": ":authority", "value": authority})
            rows.append(row)
        target = self.identity_file.with_name("capture.json")
        target.write_text(json.dumps(rows))
        steps = flow.load_capture_steps(target)
        self.assertEqual([s["capture_index"] for s in steps], [0, 1, 2])
        self.assertEqual([s["host"] for s in steps], ["poke.mykeeta.com", "poke-eu.mykeeta.com", "poke.mykeeta.com"])
        self.assertTrue(all(s["body_type"] == "envelope_ntp" for s in steps))
        state = {"region_state": {"region": "HK", "city_id": "HK-CITY"},
                 "region_compass_response": {"http_status": 200, "response": {"code": 0,
                     "data": {"version": "fixture", "configs": []}}}}
        for region, host in (("HK", "poke.mykeeta.com"), ("BR", "poke-eu.mykeeta.com")):
            state["region_compass_response"]["response"]["data"]["configs"].append({"regions": [region], "bizConfig": {
                "platformHosts": {"msp.url.poke": host, "msp.url.pikachu": "sdk.example.test",
                    "Passport.url": "passport.example.test", "Push.medusaUrl": "https://push.example.test",
                    "Keeta.C.ProductUrl": "https://product.example.test"}}})
        selected = registration_region.apply_selected_region_route("poke-eu.mykeeta.com", "/ntp",
                     {"Host": "poke-eu.mykeeta.com"}, state)
        self.assertEqual(selected[0], "poke.mykeeta.com")
        self.assertEqual(selected[2]["Host"], selected[0])
        with self.assertRaisesRegex(ValueError, "accepted Compass"):
            registration_region.apply_selected_region_route("unknown.example.test", "/ntp", {}, state)
        del state["region_compass_response"]["response"]["data"]["configs"][0]["bizConfig"]["platformHosts"]["msp.url.poke"]
        with self.assertRaisesRegex(ValueError, "msp.url.poke"):
            registration_region.apply_selected_region_route("poke-eu.mykeeta.com", "/ntp", {}, state)


if __name__ == "__main__":
    unittest.main()
