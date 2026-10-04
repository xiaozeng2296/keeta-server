"""Offline request-plan tests; no HTTP, device, mailbox, or frida access."""
import json
from pathlib import Path
import tempfile
import unittest

import keeta_login
import keeta_offline_flow as flow


def _flow(host, path, body, content_type="application/json"):
    return {
        "host": host,
        "path": path,
        "request": {
            "header": {"headers": [
                {"name": ":path", "value": path + "?uuid=OLD"},
                {"name": "mtgsig", "value": "OLD"},
                {"name": "Content-Type", "value": content_type},
            ]},
            "body": {"text": body},
        },
    }


class OfflineFlowTests(unittest.TestCase):
    def test_http2_authority_survives_connection_coalescing_in_both_loaders(self):
        path = flow.login_protocol.RISK_PATH
        captured = _flow('connection.example.test', path, 'email=old%40example.test',
                         'application/x-www-form-urlencoded')
        captured['request']['header']['headers'].extend([
            {'name': ':authority', 'value': 'passport.example.test:8443'},
            {'name': 'Host', 'value': 'connection.example.test'}])
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp) / 'coalesced.json'
            file.write_text(json.dumps([captured]))
            idx = flow.load_chlsj_index(file)
            step, = flow.load_capture_steps(file)
        self.assertEqual(set(idx), {('passport.example.test:8443', path)})
        self.assertEqual(step['host'], 'passport.example.test:8443')
        for options in ({'idx': idx, 'host': step['host']},
                        {'idx': {}, 'host': captured['host'], 'template': captured}):
            request = flow.build_request(path=path, body_type='plaintext_urlencoded',
                profile={'email': 'current@example.test'}, **options)
            self.assertTrue(request['url'].startswith('https://passport.example.test:8443/'))
            self.assertFalse(any(k.lower() == 'host' for k in request['headers']))
        self.assertEqual(captured['host'], 'connection.example.test')

    def test_authority_falls_back_to_http1_host_then_capture_metadata(self):
        captured = _flow('connection.example.test', '/v5/sign', '{}')
        self.assertEqual(flow.capture_authority(captured), 'connection.example.test')
        captured['request']['header']['headers'].append({'name': 'hOsT', 'value': 'actual.example.test'})
        self.assertEqual(flow.capture_authority(captured), 'actual.example.test')

    def test_coalesced_bootstrap_sdk_route_keeps_url_host_and_signature_target_together(self):
        captured = _flow('connection.example.test', '/v5/sign', '{"data":"OLD"}')
        captured['request']['header']['headers'].extend([
            {'name': ':authority', 'value': 'sdk.example.test'},
            {'name': 'Host', 'value': 'connection.example.test'}])
        class Signer:
            def sign(self, url, body):
                self.signed_url = url
                return 'SYNTHETIC-SIGNATURE'
        signer = Signer()
        request = flow.build_request({}, 'connection.example.test', '/v5/sign', 'envelope_sign',
            {'envelope_sign_data': 'CURRENT'}, template=captured, signer=signer)
        self.assertTrue(request['url'].startswith('https://sdk.example.test/'))
        self.assertEqual(request['headers']['Host'], 'sdk.example.test')
        self.assertEqual(signer.signed_url, request['url'])

    def test_risk_builders_require_current_email(self):
        path = "/api/emaillogin/v1/userriskcheck"
        body = "email=historical%40example.test&fingerprint=OLD"
        req = flow.build_request({}, "passport.test", path, "plaintext_urlencoded", {},
                                 template=_flow("passport.test", path, body))
        self.assertIn("error", req)
        planned = keeta_login.plan_segment({"name": "risk", "host": "passport.test",
            "path": path, "body": body, "headers": {}})
        self.assertIn("error", planned)

    def test_region_form_does_not_inherit_login_fields(self):
        body = "latitude=0&longitude=0&region=GG&cityId=0&locale=zh&lang=zh&source=1&country="
        host, path = "i18n-eu.mykeeta.com", "/api/currentLocalInfo"
        idx = {(host, path): _flow(host, path, body, "application/x-www-form-urlencoded")}
        profile = {"device_id": "DEVICE", "email": "test@example.test", "fingerprint": "FP",
                   "userTicket": "TICKET", "requestCode": "REQ", "responseCode": "RESP"}
        req = flow.build_request(idx, host, path, "plaintext_urlencoded", profile)
        self.assertEqual(req["body"], body)

    def test_plan_covers_device_steps_and_alias_hosts(self):
        idx = {
            ("uuid-eu.mykeeta.com", "/uuid/oversea/ios/register"): _flow(
                "uuid-eu.mykeeta.com", "/uuid/oversea/ios/register", json.dumps({
                    "appInfo": {}, "environmentInfo": {}, "communicationInfo": {},
                    "deviceInfo": {"keyDeviceInfo": {"idfv": "OLD"}, "secondaryDeviceInfo": {}},
                    "idInfo": {"requiredId": 4, "localId": "LOCAL", "sessionId": "SESSION"}})),
            ("mtpush.mykeeta.com", "/sdkapi/newreg"): _flow(
                "mtpush.mykeeta.com", "/sdkapi/newreg",
                '{"deviceid":"OLD","signature":"OLD","random":"1"}'),
            # Only dd-eu is present, while FLOW_STEPS asks for fooddelivery-eu.
            ("dd-eu.mykeeta.com", "/appupdate/mach/checkUpdate"): _flow(
                "dd-eu.mykeeta.com", "/appupdate/mach/checkUpdate",
                '{"UUID":"OLD","fingerprint":"OLD"}'),
            ("pikachu.mykeeta.com", "/fingerprint/v1/info/report"): _flow(
                "pikachu.mykeeta.com", "/fingerprint/v1/info/report",
                '{"fingerPrintData":"OLD"}'),
            ("pikachu.mykeeta.com", "/v5/sign"): _flow(
                "pikachu.mykeeta.com", "/v5/sign", '{"data":"OLD"}'),
            ("poke.mykeeta.com", "/ntp"): _flow(
                "poke.mykeeta.com", "/ntp", '{"data":"OLD"}'),
            ("fooddelivery.mykeeta.com", "/fingerprint/v1/app/bio/info/report"): _flow(
                "fooddelivery.mykeeta.com", "/fingerprint/v1/app/bio/info/report",
                '{"fingerPrintData":"OLD"}'),
            ("pikachu.mykeeta.com", "/v1/scfg"): _flow(
                "pikachu.mykeeta.com", "/v1/scfg", '{"data":"OLD"}'),
            ("pikachu.mykeeta.com", "/v5/device-info"): _flow(
                "pikachu.mykeeta.com", "/v5/device-info", '{"data":"OLD"}'),
            ("fooddelivery.mykeeta.com", "/api/protocolcenter/v1/protocol/confirmProtocol"): _flow(
                "fooddelivery.mykeeta.com", "/api/protocolcenter/v1/protocol/confirmProtocol",
                "action=2&appId=517&email=old%40x.test&fingerprint=OLD",
                "application/x-www-form-urlencoded"),
            ("passport-hk.mykeeta.com", "/api/emaillogin/v1/userriskcheck"): _flow(
                "passport-hk.mykeeta.com", "/api/emaillogin/v1/userriskcheck",
                "email=old%40x.test&fingerprint=OLD&requestCode=&responseCode="),
        }
        profile = {
            "email": "new@example.test", "idfv": "NEW-IDFV", "uuid": "NEW-UUID",
            "fingerprint": "NEW-FP", "envelope_data": "FALLBACK",
            "envelope_info_data": "INFO", "envelope_sign_data": "SIGN",
            "envelope_bio_data": "BIO", "envelope_device_data": "DEVICE",
            "envelope_ntp_data": "NTP",
            "a8": "LOCAL-DFP", "csecuuid": "CURRENT-UUID",
            "scfg_inputs": {"raw_fields": {"m154": "com.example", "m144": "1", "m136": ""},
                            "os_version": "16.2", "sdk_version": "5.21.10", "city": "", "user_id": None},
        }
        plan = flow.build_offline_plan(idx, profile)
        self.assertEqual([x["name"] for x in plan], [s["name"] for s in flow.FLOW_STEPS])
        # Region requests now require their own templates and explicit live
        # state. This legacy device-only fixture intentionally has neither.
        region_names = {"compass", "service_regions", "current_local_info"}
        self.assertEqual({x["name"] for x in plan if "error" in x}, region_names)
        self.assertTrue(all("error" not in x for x in plan if x["name"] not in region_names), plan)
        by_name = {x["name"]: x for x in plan}
        self.assertTrue(by_name["check_update"]["url"].startswith("https://dd-eu.mykeeta.com/"))
        self.assertIn('"data":"SIGN"', by_name["v5_sign"]["body"])
        self.assertIn('"fingerPrintData":"INFO"', by_name["fingerprint_info"]["body"])
        self.assertIn('"fingerPrintData":"BIO"', by_name["bio_report"]["body"])
        self.assertIn('"data":"DEVICE"', by_name["device_info"]["body"])
        self.assertIn("email=new%40example.test", by_name["user_risk_check"]["body"])

    def test_newreg_refreshes_signature_for_final_random(self):
        body = '{"deviceid":"OLD","signature":"OLD","random":"1790130775"}'
        idx = {("mtpush.mykeeta.com", "/sdkapi/newreg"): _flow(
            "mtpush.mykeeta.com", "/sdkapi/newreg", body)}
        req = flow.build_request(idx, "mtpush.mykeeta.com", "/sdkapi/newreg",
                                 "plaintext_json", {"idfv": "IDFV"})
        self.assertEqual(json.loads(req["body"])["deviceid"], "IDFV")
        self.assertEqual(json.loads(req["body"])["signature"],
                         "7397bba0b97f7ad0788c3f7d39554b5b49a2630e")
        req = flow.build_request(idx, "mtpush.mykeeta.com", "/sdkapi/newreg",
                                 "plaintext_json", {"random": "1790496483"})
        self.assertEqual(json.loads(req["body"])["signature"],
                         "ae87cbec81387ad1f76c13f7e76c47591a7a8e9b")
        req = flow.build_request(idx, "mtpush.mykeeta.com", "/sdkapi/newreg",
                                 "plaintext_json", {"idfv": "IDFV", "signature": "a" * 40})
        self.assertEqual(json.loads(req["body"])["signature"], "a" * 40)

    def test_json_string_override_remains_valid_when_value_needs_escaping(self):
        idx = {("mtpush.mykeeta.com", "/sdkapi/newreg"): _flow(
            "mtpush.mykeeta.com", "/sdkapi/newreg",
            '{"deviceid":"OLD","model":"old","random":"1"}')}
        req = flow.build_request(
            idx, "mtpush.mykeeta.com", "/sdkapi/newreg", "plaintext_json",
            {"model": 'iPhone "test" \\ lab'})
        self.assertEqual(json.loads(req["body"])["model"], 'iPhone "test" \\ lab')

    def test_missing_newreg_random_is_explicit_error(self):
        idx = {("mtpush.mykeeta.com", "/sdkapi/newreg"): _flow(
            "mtpush.mykeeta.com", "/sdkapi/newreg", '{"signature":"STALE"}')}
        req = flow.build_request(idx, "mtpush.mykeeta.com", "/sdkapi/newreg",
                                 "plaintext_json", {})
        self.assertIn("random", req["error"])

    def test_charles_http1_query_is_kept_without_pseudo_headers(self):
        capture = {"path": "/v5/sign", "query": "appId=517&uuid=U",
                   "request": {"header": {"headers": []}, "body": {"text": "{}"}}}
        self.assertEqual(flow.extract_template(capture)[0], "/v5/sign?appId=517&uuid=U")

    def test_login_state_machine_is_render_only(self):
        tpl = {
            "risk": {"name": "risk", "host": "passport.test", "path": "/risk",
                     "query": "", "headers": {"mtgsig": "old"},
                     "body": "email=old%40x.test&requestCode=&responseCode="},
            "signup_apply": {"name": "signup_apply", "host": "passport.test",
                              "path": "/apply", "query": "", "headers": {},
                              "body": "email=old%40x.test&userTicket=old"},
            "signup": {"name": "signup", "host": "passport.test", "path": "/signup",
                       "query": "", "headers": {},
                       "body": "email=old%40x.test&userTicket=old&serialNumber=old&emailCode=old"},
        }
        plan = keeta_login.plan_signup_flow(
            tpl, "new@example.test", user_ticket="T", serial_number="S", email_code="1234")
        self.assertEqual([x["segment"] for x in plan], ["risk", "signup_apply", "signup"])
        self.assertIn("user_ticket=T", plan[1]["body"])
        self.assertIn("serial_number=S", plan[2]["body"])
        self.assertIn("email_code=1234", plan[2]["body"])
        # Rendering does not inject a stale captured mtgsig or make a request.
        self.assertNotIn("mtgsig", plan[0]["headers"])

    def test_login_state_machine_can_sign_each_rendered_segment(self):
        tpl = {
            "risk": {"name": "risk", "host": "passport.test", "path": "/risk",
                     "query": "", "headers": {"mtgsig": "old"},
                     "body": "email=old%40x.test"},
            "signup_apply": {"name": "signup_apply", "host": "passport.test",
                              "path": "/apply", "query": "", "headers": {},
                              "body": "email=old%40x.test&userTicket=old"},
            "signup": {"name": "signup", "host": "passport.test", "path": "/signup",
                       "query": "", "headers": {},
                       "body": "email=old%40x.test&userTicket=old&serialNumber=old&emailCode=old"},
        }

        class OfflineLikeSigner:
            def sign(self, url, body):
                return ("SIG:" + url.rsplit("/", 1)[-1], "unused-a2")

        plan = keeta_login.plan_signup_flow(
            tpl, "new@example.test", user_ticket="T", serial_number="S", email_code="1234",
            signer=OfflineLikeSigner())
        self.assertEqual([x["headers"]["mtgsig"] for x in plan],
                         ["SIG:risk", "SIG:apply", "SIG:signup"])
        self.assertTrue(all(x["signed"] for x in plan))

    def test_login_sign_failure_is_reported_without_fake_signature(self):
        tpl = {"risk": {"name": "risk", "host": "passport.test", "path": "/risk",
                         "query": "", "headers": {"mtgsig": "old"},
                         "body": "email=old%40x.test"}}

        class BrokenSigner:
            def sign(self, *args):
                raise RuntimeError("fixture signer failed")

        plan = keeta_login.plan_signup_flow(tpl, "new@example.test", signer=BrokenSigner())
        self.assertNotIn("mtgsig", plan[0]["headers"])
        self.assertFalse(plan[0]["signed"])
        self.assertIn("RuntimeError: fixture signer failed", plan[0]["sign_error"])

    def test_yoda_codes_are_added_when_capture_predates_they_keys(self):
        idx = {("passport-hk.mykeeta.com", "/api/emaillogin/v1/userriskcheck"): _flow(
            "passport-hk.mykeeta.com", "/api/emaillogin/v1/userriskcheck",
            "email=old%40x.test&fingerprint=OLD")}
        req = flow.build_request(
            idx, "passport-hk.mykeeta.com", "/api/emaillogin/v1/userriskcheck",
            "plaintext_urlencoded", {"email": "new@example.test", "fingerprint": "FP",
                                      "requestCode": "REQ", "responseCode": "RESP"})
        self.assertIn("request_code=REQ", req["body"])
        self.assertIn("response_code=RESP", req["body"])

    def test_request_plan_normalizes_device_signer_api(self):
        idx = {("passport-hk.mykeeta.com", "/api/emaillogin/v1/userriskcheck"): _flow(
            "passport-hk.mykeeta.com", "/api/emaillogin/v1/userriskcheck",
            "email=old%40x.test&fingerprint=OLD")}

        class DeviceSigner:
            def sign(self, method, url, body):
                self.args = (method, url, body)
                return "DEVICE-MTGSIG"

        signer = DeviceSigner()
        req = flow.build_request(
            idx, "passport-hk.mykeeta.com", "/api/emaillogin/v1/userriskcheck",
            "plaintext_urlencoded", {"email": "new@example.test"}, signer=signer)
        self.assertTrue(req["signed"])
        self.assertEqual(req["headers"]["mtgsig"], "DEVICE-MTGSIG")
        self.assertEqual(signer.args[0], "POST")

    def test_sign_failure_is_explicit_and_never_emits_placeholder_header(self):
        idx = {("passport-hk.mykeeta.com", "/api/emaillogin/v1/userriskcheck"): _flow(
            "passport-hk.mykeeta.com", "/api/emaillogin/v1/userriskcheck",
            "email=old%40x.test&fingerprint=OLD")}

        class BrokenSigner:
            def sign(self, *args):
                raise RuntimeError("fixture signer failed")

        req = flow.build_request(
            idx, "passport-hk.mykeeta.com", "/api/emaillogin/v1/userriskcheck",
            "plaintext_urlencoded", {"email": "new@example.test"}, signer=BrokenSigner())
        self.assertFalse(req["signed"])
        self.assertNotIn("mtgsig", req["headers"])
        self.assertIn("RuntimeError: fixture signer failed", req["sign_error"])

    def test_device_identity_replaces_csecuuid_header_and_embedded_trace(self):
        old = "0000000000000OLD-CSECUUID"
        trace = "5172" + old + "17KLa123"
        idx = {("passport-hk.mykeeta.com", "/api/emaillogin/v1/userriskcheck"): {
            "host": "passport-hk.mykeeta.com",
            "path": "/api/emaillogin/v1/userriskcheck",
            "request": {"header": {"headers": [
                {"name": ":path", "value": "/api/emaillogin/v1/userriskcheck"},
                {"name": "csecuuid", "value": old},
                {"name": "M-SHARK-TRACEID", "value": trace},
                {"name": "pragma-unionid", "value": "OLD-UNION"},
            ]}, "body": {"text": "email=old%40x.test&fingerprint=OLD"}},
        }}
        req = flow.build_request(
            idx, "passport-hk.mykeeta.com", "/api/emaillogin/v1/userriskcheck",
            "plaintext_urlencoded", {"csecuuid": "NEW-CSECUUID", "unionid": "NEW-UNION",
                                      "email": "current@example.test"})
        self.assertEqual(req["headers"]["csecuuid"], "NEW-CSECUUID")
        self.assertIn("NEW-CSECUUID", req["headers"]["M-SHARK-TRACEID"])
        self.assertNotIn(old, req["headers"]["M-SHARK-TRACEID"])
        self.assertEqual(req["headers"]["pragma-unionid"], "NEW-UNION")


if __name__ == "__main__":
    unittest.main()
