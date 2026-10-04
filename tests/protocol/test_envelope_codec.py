import base64
import json
from pathlib import Path
import unittest

from mtgsig import envelope_codec as codec


VECTOR = json.loads((Path(__file__).parent.parent / "fixtures/envelope_rsa_vector.json").read_text())
MODULUS = int(VECTOR["modulus_hex"], 16)
KEY = b"0123456789abcdef"
IV = b"0102030405060708"


class EnvelopeCodecTests(unittest.TestCase):
    def test_runtime_rsa_vector(self):
        # Captured SecKeyEncrypt(padding=none) session material from the
        # fingerprint report session.  The expected text is the exact
        # stripped base64 part1 seen on the wire.
        session = bytes.fromhex(VECTOR["session_material_hex"])
        encrypted = codec.raw_rsa_encrypt(session, MODULUS, VECTOR["exponent"], size=128)
        self.assertEqual(base64.b64encode(encrypted).decode().rstrip("="), VECTOR["part1_b64_unpadded"])

    def test_split_accepts_stripped_and_padded_rsa_components(self):
        part1 = codec.raw_rsa_encrypt(bytes.fromhex("677f9693392ef2cdf5510822566872d9"), MODULUS, size=128)
        part2 = codec.encrypt_part2(b"captured payload", KEY, IV)
        stripped = codec.join(part1, part2)
        parsed = codec.split(stripped)
        self.assertEqual(parsed.part1, part1)
        self.assertEqual(parsed.part2, part2)

        # Some serializers retain the RSA base64 padding.  The framing
        # parser must distinguish it from the separator.
        padded = base64.b64encode(part1).decode() + "=" + base64.b64encode(part2).decode()
        parsed = codec.split(padded)
        self.assertEqual(parsed.part1, part1)
        self.assertEqual(parsed.part2, part2)

    def test_explicit_key_roundtrip(self):
        original = b'{"m153":"device-id","m162":"WiFi"}'
        envelope = codec.encode(
            bytes.fromhex("149ccb1cad3a1d52181d43455ba2e4ad"),
            original,
            key=KEY,
            iv=IV,
            modulus=MODULUS,
        )
        decoded = codec.decode(envelope, key=KEY, iv=IV)
        self.assertEqual(decoded.plaintext, original)
        self.assertEqual(decoded.payload[:2], b"x\x9c")

    def test_encode_matches_observed_padding_convention(self):
        envelope = codec.encode(
            bytes.fromhex("149ccb1cad3a1d52181d43455ba2e4ad"),
            b"payload",
            key=KEY,
            iv=IV,
            modulus=MODULUS,
        )
        left, right = envelope.split("=", 1)
        # RSA-1024 b64 padding is consumed by the framing separator; the
        # payload keeps its ordinary final base64 padding.
        self.assertNotEqual(left[-1], "=")
        self.assertTrue(right.endswith("="))

    def test_unknown_key_is_explicit_failure(self):
        envelope = codec.encode(b"0123456789abcdef", b"payload", key=KEY, iv=IV, modulus=MODULUS)
        with self.assertRaises(ValueError):
            codec.decode(envelope, key=b"fedcba9876543210", iv=IV)


if __name__ == "__main__":
    unittest.main()
