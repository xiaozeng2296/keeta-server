"""Local a8 layout/CRC verification; no device or network access."""

import base64
from dataclasses import replace
import json
from pathlib import Path
import unittest
import zlib

from mtgsig.local_identity import (
    DEFAULT_LOCAL_ID_PROFILE, DEFAULT_LOCAL_XID_PROFILE, LocalIdentityProfile,
    build_local_xid_plaintext, decode_local_dfp, decode_local_xid,
    encode_local_xid, generate_local_dfp,
)
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


FIXTURE_UUID = "00112233-4455-4677-8899-aabbccddeeff"
FIXTURE_TIME = 1790496483000
ROOT = Path(__file__).resolve().parents[1]


class LocalIdentityTests(unittest.TestCase):
    def test_synthetic_layout_roundtrip_and_profile_provenance(self):
        value = generate_local_dfp(FIXTURE_UUID, FIXTURE_TIME)
        parsed = decode_local_dfp(value)
        self.assertEqual(parsed.uuid, FIXTURE_UUID)
        self.assertEqual(parsed.timestamp_ms, FIXTURE_TIME)
        self.assertEqual(parsed.profile_version, DEFAULT_LOCAL_ID_PROFILE.version)
        self.assertEqual(parsed.profile_source, DEFAULT_LOCAL_ID_PROFILE.source)
        self.assertEqual(generate_local_dfp(parsed.uuid, parsed.timestamp_ms), value)

    def test_identity_is_a_structured_xor_value_with_ascii_crc(self):
        profile = LocalIdentityProfile("fixture", "unit test", bytes(28))
        value = generate_local_dfp(FIXTURE_UUID.upper(), FIXTURE_TIME, profile=profile)
        material = "0000" + FIXTURE_UUID.replace("-", "") + f"{FIXTURE_TIME:x}" + "1"
        checksum = zlib.crc32(material.encode("ascii")) & 0xFFFFFFFF
        self.assertEqual(value, material + f"{checksum:08x}")
        # Hashing decoded bytes is a plausible but incorrect interpretation.
        self.assertNotEqual(checksum, zlib.crc32(bytes.fromhex(material)) & 0xFFFFFFFF)

    def test_tampering_and_other_id_formats_are_not_silently_accepted(self):
        value = generate_local_dfp(FIXTURE_UUID, FIXTURE_TIME)
        altered = value[:-2] + f"{int(value[-2:], 16) ^ 1:02x}"
        with self.assertRaisesRegex(ValueError, "CRC32"):
            decode_local_dfp(altered)
        with self.assertRaises(ValueError):
            decode_local_dfp("0" * 56)

    def test_mask_override_is_used_in_both_directions(self):
        profile = replace(DEFAULT_LOCAL_ID_PROFILE, version="fixture", source="unit test",
                          mask=bytes(range(28)))
        value = generate_local_dfp(FIXTURE_UUID, FIXTURE_TIME, profile=profile)
        self.assertNotEqual(value, generate_local_dfp(FIXTURE_UUID, FIXTURE_TIME))
        parsed = decode_local_dfp(value, profile=profile)
        self.assertEqual(parsed.uuid, FIXTURE_UUID)
        self.assertEqual(parsed.profile_version, "fixture")
        with self.assertRaises(ValueError):
            decode_local_dfp(value)

    def test_invalid_uuid_and_timestamp_are_rejected(self):
        for value in (None, "broken", "0" * 31, "{" + FIXTURE_UUID + "}"):
            with self.subTest(uuid=value):
                with self.assertRaises(ValueError):
                    generate_local_dfp(value, FIXTURE_TIME)
        for value in (True, 1.5, str(FIXTURE_TIME)):
            with self.subTest(time_type=type(value).__name__):
                with self.assertRaises(TypeError):
                    generate_local_dfp(FIXTURE_UUID, value)
        for value in (0, -1, 0xFFFFFFFFFF, 0x100000000000):
            with self.subTest(time=value):
                with self.assertRaises(ValueError):
                    generate_local_dfp(FIXTURE_UUID, value)

    def test_invalid_mask_or_layout_is_rejected(self):
        for kwargs in ({"mask": bytes(27)}, {"mask": bytearray(28)},
                       {"prefix": "000"}, {"suffix": "xx"}, {"source": ""}):
            with self.subTest(fields=tuple(kwargs)):
                with self.assertRaises(ValueError):
                    replace(DEFAULT_LOCAL_ID_PROFILE, **kwargs)

    def test_a7_plaintext_uses_uppercase_hex_seconds_and_preserves_id(self):
        source = "ab" * 28
        self.assertEqual(build_local_xid_plaintext(source, 0x1234ABCD),
                         ("1" + source + "1" + "1234ABCD").encode("ascii"))
        self.assertEqual(len(build_local_xid_plaintext(source, 1790496483)), 66)
        self.assertTrue(build_local_xid_plaintext(source, 1).endswith(b"1 1"))
        self.assertTrue(build_local_xid_plaintext(source.upper(), 1).startswith(b"1AB"))

    def test_a7_plaintext_input_bounds(self):
        for value in (None, "a" * 55, "x" * 56):
            with self.assertRaises(ValueError):
                build_local_xid_plaintext(value, 1)
        for value in (True, 1.5, "1"):
            with self.assertRaises(TypeError):
                build_local_xid_plaintext("a" * 56, value)

    def test_local_xid_roundtrip_and_strict_format(self):
        source = generate_local_dfp(FIXTURE_UUID, FIXTURE_TIME)
        encoded = encode_local_xid(source, FIXTURE_TIME // 1000)
        parsed = decode_local_xid(encoded)
        self.assertEqual(parsed.source_dfp_id, source)
        self.assertEqual(parsed.timestamp_seconds, FIXTURE_TIME // 1000)
        self.assertEqual(parsed.profile_version, DEFAULT_LOCAL_XID_PROFILE.version)
        self.assertEqual(len(base64.b64decode(encoded)), 80)
        for invalid in ("", "%%%", encoded + "\n", encoded[:-1], "A" * 108):
            with self.subTest(invalid_length=len(invalid)):
                with self.assertRaises(ValueError):
                    decode_local_xid(invalid)

    def test_plaintext_validation_is_required_after_valid_aes_padding(self):
        profile = DEFAULT_LOCAL_XID_PROFILE
        for plaintext in (b"not a local XID", b"1" + b"0" * 56 + b"100000001"):
            ciphertext = AES.new(profile.key, AES.MODE_CBC, profile.iv).encrypt(pad(plaintext, 16))
            with self.assertRaises(ValueError):
                decode_local_xid(base64.b64encode(ciphertext).decode())

    def test_local_xid_profile_override(self):
        profile = replace(DEFAULT_LOCAL_XID_PROFILE, version="fixture", source="unit test",
                          key=bytes(range(16)), iv=bytes(range(16, 32)))
        encoded = encode_local_xid("a" * 56, 1790496483, profile=profile)
        self.assertEqual(decode_local_xid(encoded, profile=profile).timestamp_seconds, 1790496483)
        with self.assertRaises(ValueError):
            decode_local_xid(encoded)

    @unittest.skipUnless((ROOT / "dump/envelope_recovery/local_xid_crypto_01.json").exists(),
                         "local native synthetic vectors are not distributed with tests")
    def test_native_synthetic_encryption_vectors(self):
        with (ROOT / "dump/envelope_recovery/local_xid_crypto_01.json").open() as fh:
            vectors = json.load(fh)["results"]
        self.assertEqual({len(row["plaintext"]) for row in vectors}, {1, 16, 66})
        profile = DEFAULT_LOCAL_XID_PROFILE
        for row in vectors:
            plaintext = row["plaintext"].encode("ascii")
            ciphertext = bytes.fromhex(row["cipher"])
            calculated = AES.new(profile.key, AES.MODE_CBC, profile.iv).encrypt(pad(plaintext, 16))
            self.assertTrue(calculated == ciphertext, "native CBC encryption mismatch")
            self.assertTrue(unpad(AES.new(profile.key, AES.MODE_CBC, profile.iv).decrypt(ciphertext), 16)
                            == plaintext, "native CBC decryption mismatch")
            if len(plaintext) == 66:
                encoded = encode_local_xid(row["plaintext"][1:57], int(row["plaintext"][58:], 16))
                self.assertTrue(base64.b64decode(encoded) == ciphertext,
                                "native generateLocalXID formatting mismatch")

    @unittest.skipUnless(all((ROOT / name).exists() for name in (
        "evidence/captures/从app初次打开到登录被拦截.chlsj", "evidence/captures/新机之后尝试登录.chlsj")),
        "local registration captures are not distributed with tests")
    def test_real_a7_vectors_contain_valid_local_a8_and_server_xid_is_distinct(self):
        count = 0
        for name in ("evidence/captures/从app初次打开到登录被拦截.chlsj", "evidence/captures/新机之后尝试登录.chlsj"):
            with (ROOT / name).open(encoding="utf-8") as fh:
                records = json.load(fh)
            for record in records:
                if (record.get("path") or "").split("?")[0] != "/fingerprint/v1/info/report":
                    continue
                headers = {h["name"].lower(): h["value"]
                           for h in record["request"]["header"]["headers"]}
                mt = json.loads(headers["mtgsig"])
                parsed = decode_local_xid(mt["a7"])
                nested = decode_local_dfp(parsed.source_dfp_id)
                self.assertTrue(generate_local_dfp(nested.uuid, nested.timestamp_ms) == parsed.source_dfp_id,
                                "captured nested local a8 did not regenerate")
                self.assertTrue(encode_local_xid(parsed.source_dfp_id, parsed.timestamp_seconds) == mt["a7"],
                                "captured local a7 did not regenerate")
                self.assertEqual(nested.timestamp_ms // 1000, parsed.timestamp_seconds)
                response = json.loads(record["response"]["body"]["text"])
                with self.assertRaises(ValueError):
                    decode_local_xid(response["data"]["result"])
                count += 1
        self.assertEqual(count, 2)
        for value in (-1, 0x100000000):
            with self.assertRaises(ValueError):
                build_local_xid_plaintext("a" * 56, value)

    @unittest.skipUnless((ROOT / "evidence/captures/新机之后尝试登录.chlsj").exists(),
                         "local registration capture is not distributed with tests")
    def test_real_capture_local_crc_and_regeneration(self):
        # Keep captured identities in the existing local evidence file, not in
        # source fixtures or unittest output. Match the first observed local a8.
        with (ROOT / "evidence/captures/新机之后尝试登录.chlsj").open(encoding="utf-8") as fh:
            flows = json.load(fh)
        observed = None
        for record in flows:
            headers = ((record.get("request") or {}).get("header") or {}).get("headers", [])
            for header in headers:
                if header.get("name", "").lower() == "mtgsig":
                    observed = json.loads(header["value"]).get("a8")
                    break
            if observed:
                break
        self.assertIsNotNone(observed)
        parsed = decode_local_dfp(observed)
        rebuilt = generate_local_dfp(parsed.uuid, parsed.timestamp_ms)
        self.assertTrue(rebuilt == observed, "captured local a8 did not regenerate")
        self.assertEqual(parsed.timestamp_ms, 1790496483002)
        # The fixed marker and validated CRC are the identifying evidence;
        # output length alone must never classify arbitrary server DFP as local.
        self.assertTrue(len(parsed.crc32_hex) == 8)


if __name__ == "__main__":
    unittest.main()
