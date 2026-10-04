"""Deployment acceptance boundaries; no device, external service or captured data."""
import base64
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.error
import urllib.parse
import zlib

from rpc import smoke
from mtgsig import a9_codec as codec, envelope_codec, mtg_crypto


class Response(io.BytesIO):
    status = 200


class MockHTTP:
    """Small protocol double: no application import or signer dependencies."""
    def __init__(self):
        self.calls = []

    def open(self, request, timeout):
        self.calls.append((request, timeout))
        path = urllib.parse.urlsplit(request.full_url).path
        p = json.loads(request.data) if request.data else {}
        if path == "/health":
            result = {"a9_ready": True, "a9_requires_v73": False,
                      "a9_modes": list(codec.MODES), "a9_profiles": ["default", "legacy"],
                      "envelope_sdk_ready": True, "envelope_requires_session_key": True,
                      "envelope_modes": list(codec.MODES), "envelope_profiles": ["default", "legacy"]}
        elif path == "/a9/encode":
            options = self.options(p)
            text = json.dumps(p["siua_json"], separators=(",", ":"), ensure_ascii=False)
            result = {"a9": codec.encode(text, p["a1"], mode=p["mode"], **options)}
        elif path == "/a9/decode":
            result = self.decode(p)
        elif path == "/a5/encrypt":
            plain = json.dumps(p["plain_obj"], separators=(",", ":"), ensure_ascii=False).encode()
            profile = p.get("signing_profile", p.get("profile", "legacy"))
            result = {"a5": mtg_crypto.a5_encrypt(plain, p["a1"], p["a3"], p["a4"],
                                                 self.k2(p["a1"], profile)), "profile": profile}
        elif path == "/decrypt":
            mt = p.get("mtgsig", p)
            if isinstance(mt, str):
                mt = json.loads(mt)
            fields = {}
            if "a9" in mt:
                fields["a9"] = {"decryptable": False}
                for profile in ([p["profile"]] if "profile" in p else ["default", "legacy"]):
                    try:
                        fields["a9"] = {"decryptable": True,
                                         **self.decode({**mt, "profile": profile})}
                        break
                    except ValueError:
                        pass
            if "a5" in mt:
                fields["a5"] = {"decryptable": False}
                for profile in ([p["signing_profile"]] if "signing_profile" in p else ["default", "legacy"]):
                    try:
                        plain = mtg_crypto.a5_decrypt(mt["a5"], mt["a1"], mt["a3"], mt["a4"],
                                                     self.k2(mt["a1"], profile))
                        value = json.loads(plain)
                        fields["a5"] = {"decryptable": True, "plain_json": value, "profile": profile,
                                         "plain_explained": self.explain_a5(value)}
                        break
                    except (ValueError, zlib.error):
                        pass
            fields.update({k: {"decryptable": False} for k in ("a2", "a7", "a8") if k in mt})
            result = {"fields": fields}
        elif path == "/fingerprint/decrypt":
            from Crypto.Cipher import AES
            raw = base64.b64decode(p["fingerprint"])
            for key in (b"meituan1sankuai0", b"34281a9dw2i701d4"):
                plain = AES.new(key, AES.MODE_CBC, codec.IV).decrypt(raw)
                if plain.startswith(b"{"):
                    value = json.loads(plain[:-plain[-1]])
                    result = {"plain_json": value}
                    break
            else:
                raise AssertionError("unexpected fingerprint")
        elif path == "/fingerprint/encrypt":
            value = p.get("plain_obj", p.get("plain_json"))
            key = (p.get("key") or "34281a9dw2i701d4").encode()
            iv = (p.get("iv") or "0102030405060708").encode()
            result = {"fingerprint": mtg_crypto.fingerprint_encrypt(value, key=key, iv=iv),
                      "key_used": p.get("key") or "34281a9dw2i701d4",
                      "iv": iv.decode("ascii")}
        elif path == "/envelope/encode":
            if "a1" in p:
                result = self.encode_sdk(p)
                return Response(json.dumps(result).encode())
            session = p["session_material"]
            if isinstance(session, str) and session.startswith("hex:"):
                session = bytes.fromhex(session[4:])
            elif isinstance(session, str):
                session = session.encode()
            plain = p.get("plaintext", p.get("plain_obj", p.get("plain_json")))
            if isinstance(plain, (dict, list)):
                plain = json.dumps(plain, separators=(",", ":"), ensure_ascii=False).encode()
            elif isinstance(plain, str):
                plain = plain.encode()
            key = p["key"].encode() if isinstance(p["key"], str) else bytes(p["key"])
            iv = p["iv"].encode() if isinstance(p["iv"], str) else bytes(p["iv"])
            envelope = envelope_codec.encode(
                session, plain, key=key, iv=iv,
                modulus=envelope_codec.DEFAULT_MODULUS_HEX,
                compress=bool(p.get("compress", True)),
            )
            parts = envelope_codec.split(envelope)
            result = {"envelope": envelope, "part1_bytes": len(parts.part1),
                      "part2_bytes": len(parts.part2),
                      "compressed": bool(p.get("compress", True))}
        elif path == "/envelope/decode":
            if "a1" in p:
                result = self.decode_sdk(p)
                return Response(json.dumps(result).encode())
            key = p["key"].encode() if isinstance(p["key"], str) else bytes(p["key"])
            iv = p["iv"].encode() if isinstance(p["iv"], str) else bytes(p["iv"])
            decoded = envelope_codec.decode(p["envelope"], key=key, iv=iv)
            value = json.loads(decoded.plaintext)
            result = {"plain_json": value,
                      "part1_bytes": len(decoded.parts.part1),
                      "part2_bytes": len(decoded.parts.part2)}
        else:
            raise AssertionError("unexpected endpoint")
        return Response(json.dumps(result).encode())

    @staticmethod
    def encode_sdk(p):
        plain = json.dumps(p['plain_json'], separators=(',', ':')).encode()
        generated = 'session_key_hex' not in p
        key = bytes(16) if generated else bytes.fromhex(p['session_key_hex'])
        envelope = envelope_codec.encode_sdk(plain, p['a1'], session_key=key,
                                             mode=p.get('mode', 'twofish-mod'))
        result = {'envelope': envelope, 'codec': 'sdk', 'session_key_generated': generated}
        if generated:
            result['session_key_hex'] = key.hex()
        return result

    @staticmethod
    def decode_sdk(p):
        key = bytes.fromhex(p['session_key_hex']) if 'session_key_hex' in p else None
        material = bytes.fromhex(p['session_material_hex']) if 'session_material_hex' in p else None
        decoded = envelope_codec.decode_sdk(p['envelope'], p['a1'],
                                             session_key=key, session_material=material)
        return {'plain_json': json.loads(decoded.plaintext), 'mode': decoded.mode,
                'rsa_verified': decoded.rsa_verified}

    @staticmethod
    def options(p):
        if p.get("profile", "default") == "default":
            return {}
        fields = json.loads((smoke.ROOT / "mtgsig/a9_legacy_profile.json").read_text())
        return {"salt": bytes.fromhex(fields["salt_hex"]), "a1_shift": fields["a1_shift"]}

    @classmethod
    def decode(cls, p):
        result = codec.decode(p["a9"], p["a1"], **cls.options(p))
        value = json.loads(result.plaintext)
        return {"plain_json": value, "plain_explained": cls.explain_a9(value),
                "mode": result.mode, "profile": p.get("profile", "default")}

    @staticmethod
    def explain_a5(value):
        fields = []
        for key, raw_value in value.items():
            key = str(key)
            item = {"key": key, "name": "synthetic field", "value": raw_value}
            if isinstance(raw_value, str):
                try:
                    parsed = json.loads(raw_value)
                except ValueError:
                    pass
                else:
                    item["value"], item["raw"] = parsed, raw_value
                    if isinstance(parsed, dict):
                        item["fields"] = [
                            {"key": str(k), "name": "synthetic nested field", "value": v}
                            for k, v in parsed.items()
                        ]
            fields.append(item)
        return {"fields": fields}

    @classmethod
    def explain_a9(cls, value):
        fields = []
        for key, raw_value in value.items():
            key = str(key)
            item = {"key": key, "name": "synthetic field", "value": raw_value}
            if isinstance(raw_value, str):
                try:
                    parsed = json.loads(raw_value)
                except ValueError:
                    pass
                else:
                    item["value"], item["raw"] = parsed, raw_value
            if key in ("1", "2") and isinstance(raw_value, list):
                item["items"] = [
                    {"index": i, "name": "synthetic slot", "value": v}
                    for i, v in enumerate(raw_value)
                ]
            fields.append(item)
        return {"fields": fields}

    @staticmethod
    def k2(a1, profile="legacy"):
        if profile == "default":
            return codec.derive_mask(a1)
        if profile != "legacy":
            raise ValueError("unsupported signing profile")
        fields = json.loads((smoke.ROOT / "mtgsig/keeta_const.json").read_text())
        return codec.derive_mask(a1, salt=bytes.fromhex(fields["salt"]), a1_shift=12)


class RPCSmokeTests(unittest.TestCase):
    def test_full_http_contract_and_auth_header(self):
        client = smoke.Client("http://rpc.invalid", token="synthetic-token", timeout=3)
        client.opener = MockHTTP()
        messages = []
        smoke.run_checks(client, report=messages.append)
        self.assertGreaterEqual(client.requests, 20)
        self.assertIn("验收成功", messages[-1])
        self.assertTrue(all(r.get_header("X-token") == "synthetic-token" and t == 3
                            for r, t in client.opener.calls))
        self.assertNotIn("synthetic-token", "\n".join(messages))

    def test_smoke_detects_a5_provider_incorrectly_inherited_from_a9(self):
        class CoupledProfileHTTP(MockHTTP):
            def open(self, request, timeout):
                response = super().open(request, timeout)
                if urllib.parse.urlsplit(request.full_url).path == "/decrypt":
                    result = json.loads(response.getvalue())
                    fields = result.get("fields", {})
                    a5, a9 = fields.get("a5", {}), fields.get("a9", {})
                    if a5.get("profile") == "default" and a9.get("profile") == "legacy":
                        a5["profile"] = "legacy"
                        return Response(json.dumps(result).encode())
                return response

        client = smoke.Client("http://rpc.invalid")
        client.opener = CoupledProfileHTTP()
        with self.assertRaisesRegex(smoke.SmokeFailure, "a5 配置未独立"):
            smoke.run_checks(client, report=lambda text: None)

    def test_old_service_fails_before_cipher_requests(self):
        client = smoke.Client("http://rpc.invalid")
        with patch.object(client.opener, "open", return_value=Response(b'{"v73_present":true}')):
            with self.assertRaisesRegex(smoke.SmokeFailure, "尚未更新"):
                smoke.run_checks(client, report=lambda text: None)
        self.assertEqual(client.requests, 1)

    def test_untrusted_response_and_http_errors_are_not_echoed(self):
        secret = "never-print-this-response"
        variants = [Response(json.dumps({"error": secret}).encode()),
                    Response(secret.encode()),
                    urllib.error.HTTPError("http://rpc.invalid", 401, secret, {},
                                           io.BytesIO(secret.encode()))]
        for value in variants:
            with self.subTest(value=type(value).__name__):
                client = smoke.Client("http://rpc.invalid")
                kwargs = {"side_effect": value} if isinstance(value, Exception) else {"return_value": value}
                with patch.object(client.opener, "open", **kwargs):
                    with self.assertRaises(smoke.SmokeFailure) as caught:
                        client.request("/health")
                self.assertNotIn(secret, str(caught.exception))

    def test_redirects_are_not_followed(self):
        result = smoke.NoRedirect().redirect_request(None, None, 302, "", {}, "http://elsewhere.invalid")
        self.assertIsNone(result)

    def test_reject_bad_url_timeout_and_token(self):
        for url in ("file:///tmp/test", "http://name:password@rpc.invalid",
                    "http://rpc.invalid/?token=bad", "http://rpc.invalid/#fragment"):
            with self.subTest(url=url), self.assertRaises(smoke.SmokeFailure):
                smoke.Client(url)
        for timeout in (0, -1, 10.1, float("inf"), float("nan")):
            with self.subTest(timeout=timeout), self.assertRaises(smoke.SmokeFailure):
                smoke.Client("http://rpc.invalid", timeout=timeout)
        with self.assertRaises(smoke.SmokeFailure):
            smoke.Client("http://rpc.invalid", token="bad\r\nheader")

    def test_sample_strips_unrelated_fields_and_accepts_json_formatting(self):
        with tempfile.TemporaryDirectory() as directory:
            sample_path, expected_path = Path(directory) / "sample.json", Path(directory) / "plain.json"
            sample = {"a1": smoke.A1, "a9": codec.encode(smoke.TEXT, smoke.A1),
                      "a5": "never-send", "token": "never-send"}
            sample_path.write_text(json.dumps({"mtgsig": json.dumps(sample)}))
            expected_path.write_text(json.dumps(smoke.PLAIN, indent=2, ensure_ascii=False))
            loaded = smoke.load_sample(sample_path, expected_path)
        self.assertEqual(set(loaded[0]), {"a1", "a9"})
        client = smoke.Client("http://rpc.invalid")
        client.opener = MockHTTP()
        smoke.run_checks(client, sample=loaded, report=lambda text: None)
        sent = json.loads(client.opener.calls[-1][0].data)
        self.assertEqual(set(sent["mtgsig"]), {"a1", "a9"})
        self.assertNotIn("never-send", json.dumps(sent))

    def test_main_returns_nonzero_without_leaking_unexpected_exception(self):
        output = io.StringIO()
        with patch.object(smoke, "run_checks", side_effect=ValueError("private data")):
            with contextlib.redirect_stderr(output):
                self.assertEqual(smoke.main(["--url", "http://rpc.invalid"]), 1)
        self.assertNotIn("private data", output.getvalue())
        for args in (["--sample", "missing"], ["--token-env", "SMOKE_MISSING_TOKEN"]):
            with patch.dict(os.environ, {}, clear=True), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(smoke.main(["--url", "http://rpc.invalid", *args]), 1)


if __name__ == "__main__":
    unittest.main()
