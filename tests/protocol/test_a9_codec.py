"""Public known-answer, validation-boundary and offline CLI tests.

All identifiers, keys and payloads here are synthetic; no device capture is used.
"""
import base64
import binascii
import hashlib
import json
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib
from pathlib import Path

from Crypto.Cipher import AES

from mtgsig import a9_codec as codec
from mtgsig.mtg_crypto import TwofishCipher

ROOT = Path(__file__).resolve().parents[2]
A1 = "00112233-4455-6677-8899-aabbccddeeff"
OTHER_A1 = "10112233-4455-6677-8899-aabbccddeeff"
PLAINTEXT = b'{"0":12,"test":"offline fixture","values":[1,2,3]}'


def aes_envelope(compressed, *, crc=None, padded=None):
    """Build deliberately malformed envelopes using the external AES library."""
    crc = crc or f"{binascii.crc32(compressed):08x}"
    key = codec.derive_key(crc, A1)
    if padded is None:
        n = 16 - len(compressed) % 16
        padded = compressed + bytes([n]) * n
    ciphertext = AES.new(key, AES.MODE_CBC, codec.IV).encrypt(padded)
    return crc + base64.b64encode(ciphertext).decode("ascii")


class CodecTests(unittest.TestCase):
    def test_public_twofish_zero_vector(self):
        # Twofish submission: 128-bit zero key and all-zero plaintext.
        # https://www.schneier.com/wp-content/uploads/2015/12/ecb_ival.txt
        expected = bytes.fromhex("9f589f5cf6122c32b6bfec2f2ae8c35a")
        cipher = TwofishCipher(codec.twofish_schedule(bytes(16)))
        encrypted = struct.pack("<4I", *cipher.enc_block([0, 0, 0, 0]))
        self.assertEqual(encrypted, expected)
        self.assertEqual(cipher.dec_block(list(struct.unpack("<4I", expected))), [0] * 4)

    def test_native_arm64_vectors(self):
        # Captured by executing the original ARM64 block functions in Unicorn.
        # CBC vectors compose those native blocks in the verification harness.
        fixture = json.loads((ROOT / "tests/fixtures/a9_native_vectors.json").read_text())
        for vector in fixture["vectors"]:
            with self.subTest(mode=vector["mode"], key=vector["key"]):
                key = bytes.fromhex(vector["key"])
                schedule = codec.twofish_schedule(key, modified=vector["mode"] == "twofish-mod")
                self.assertEqual(hashlib.sha256(schedule).hexdigest(), vector["schedule_sha256"])
                cipher = TwofishCipher(schedule)
                plain = bytes.fromhex(vector["plaintext"])
                encrypted = bytes.fromhex(vector["ciphertext"])
                self.assertEqual(struct.pack("<4I", *cipher.enc_block(list(struct.unpack("<4I", plain)))), encrypted)
                self.assertEqual(struct.pack("<4I", *cipher.dec_block(list(struct.unpack("<4I", encrypted)))), plain)
                cbc_plain = bytes.fromhex(vector["cbc_plaintext"])
                cbc_encrypted = bytes.fromhex(vector["cbc_ciphertext"])
                self.assertEqual(cipher._cbc_enc(cbc_plain), cbc_encrypted)
                self.assertEqual(cipher._cbc_dec(cbc_encrypted), cbc_plain)

    def test_native_cbc_wrapper_vectors(self):
        # Unlike the block-composed vectors, these execute the SDK CBC/PKCS7
        # wrappers on device using synthetic keys and private contexts.
        fixture = json.loads((ROOT / "tests/fixtures/a9_native_cbc_vectors.json").read_text())
        for vector in fixture["vectors"]:
            with self.subTest(mode=vector["mode"], length=len(vector["plaintext"]) // 2):
                key = bytes.fromhex(vector["key"])
                plain = bytes.fromhex(vector["plaintext"])
                encrypted = bytes.fromhex(vector["ciphertext"])
                padding = 16 - len(plain) % 16
                padded = plain + bytes([padding]) * padding
                self.assertEqual(codec._crypt(padded, key, vector["mode"], decrypt=False), encrypted)
                self.assertEqual(codec._crypt(encrypted, key, vector["mode"], decrypt=True), padded)

    def test_all_modes_binary_and_empty_payloads(self):
        for mode in codec.MODES:
            for plaintext in (b"", PLAINTEXT, bytes(range(256)) * 3):
                with self.subTest(mode=mode, length=len(plaintext)):
                    a9 = codec.encode(plaintext, A1, mode=mode)
                    decoded = codec.decode(a9, A1)
                    self.assertEqual(decoded.mode, mode)
                    self.assertEqual(decoded.plaintext, plaintext)
                    self.assertEqual(codec.encode_compressed(decoded.compressed, A1, mode=mode), a9)

    def test_wrong_identifier_and_mode_fail(self):
        a9 = codec.encode(PLAINTEXT, A1, mode="twofish-mod")
        with self.assertRaises(ValueError):
            codec.decode(a9, OTHER_A1)
        with self.assertRaises(ValueError):
            codec.decode(a9, A1, mode="aes")

    def test_crc_mismatch_with_valid_padding(self):
        compressed = zlib.compress(PLAINTEXT)
        crc = f"{binascii.crc32(compressed) ^ 1:08x}"
        with self.assertRaises(ValueError):
            codec.decode(aes_envelope(compressed, crc=crc), A1, mode="aes")

    def test_invalid_pkcs7_with_correct_crc(self):
        compressed = zlib.compress(PLAINTEXT)
        n = 16 - len(compressed) % 16
        padded = compressed + bytes([n]) * (n - 1) + b"\x00"
        with self.assertRaises(ValueError):
            codec.decode(aes_envelope(compressed, padded=padded), A1, mode="aes")

    def test_zlib_limit_and_complete_stream(self):
        plaintext = b"A" * 8192
        a9 = codec.encode(plaintext, A1)
        self.assertEqual(codec.decode(a9, A1, max_plaintext=len(plaintext)).plaintext, plaintext)
        with self.assertRaises(ValueError):
            codec.decode(a9, A1, max_plaintext=len(plaintext) - 1)
        with self.assertRaises(ValueError):
            codec.decode(a9, A1, max_plaintext=-1)
        for compressed in (zlib.compress(PLAINTEXT) + b"trailer",
                           zlib.compress(PLAINTEXT) + zlib.compress(b"second stream"),
                           zlib.compress(PLAINTEXT)[:-1]):
            with self.subTest(length=len(compressed)):
                with self.assertRaises(ValueError):
                    codec.decode(aes_envelope(compressed), A1)
                with self.assertRaises((ValueError, zlib.error)):
                    codec.encode_compressed(compressed, A1)

    def test_invalid_encoding(self):
        for a9 in ("", "00000000", "00000000not!base64", "00000000YQ=="):
            with self.subTest(a9=a9), self.assertRaises(ValueError):
                codec.decode(a9, A1)

    def test_custom_profile_changes_ciphertext(self):
        kwargs = {"salt": bytes(range(16)), "k3": b"synthetic fixture"}
        a9 = codec.encode(PLAINTEXT, A1, mode="twofish-mod", **kwargs)
        self.assertEqual(codec.decode(a9, A1, **kwargs).plaintext, PLAINTEXT)
        with self.assertRaises(ValueError):
            codec.decode(a9, A1)

    def test_custom_a1_shift(self):
        for shift in (0, 12, 31, 35):
            with self.subTest(shift=shift):
                kwargs = {"a1_shift": shift, "salt": bytes(range(16))}
                a9 = codec.encode(PLAINTEXT, A1, mode="twofish", **kwargs)
                result = codec.decode(a9, A1, **kwargs)
                self.assertEqual(result.plaintext, PLAINTEXT)
                self.assertEqual(codec.encode_compressed(result.compressed, A1,
                                                        mode=result.mode, **kwargs), a9)
                with self.assertRaises(ValueError):
                    codec.decode(a9, A1, a1_shift=(shift + 1) % 36, salt=bytes(range(16)))

    def test_invalid_a1_shift(self):
        for shift in (-1, 36, True, False, 1.0, "12", None):
            with self.subTest(shift=shift), self.assertRaises(ValueError):
                codec.derive_mask(A1, a1_shift=shift)




if __name__ == "__main__":
    unittest.main()
