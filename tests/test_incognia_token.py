"""Format-0 protocol tests using only synthetic identities and RSA keys."""
import base64
import hashlib
import hmac
import json
import unittest
from unittest.mock import patch
import zlib

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad

from mtgsig import incognia_token as codec


class IncogniaTokenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private = RSA.generate(2048)
        cls.public = cls.private.public_key().export_key()
        cls.mac_key = bytes(range(32))
        cls.payload = codec.build_payload(
            application_id='synthetic-application', installation_id='ILM-ID-SYNTHETIC-ID',
            initialization_counter=4, initialized_at_ms=1700000000000,
            request_counter=91, requested_at_ms=1700000001234)

    def setUp(self):
        guard = patch('socket.socket', side_effect=AssertionError('network forbidden'))
        guard.start()
        self.addCleanup(guard.stop)

    def test_full_rsa_aes_mac_roundtrip_and_independent_wire_layout(self):
        session_key, iv = b'K' * 32, b'I' * 16
        token = codec.encode(self.payload, public_key=self.public, hmac_key=self.mac_key,
                             session_key=session_key, iv=iv,
                             randfunc=lambda n: b'R' * n)
        raw = base64.urlsafe_b64decode(token + '=' * (-len(token) % 4))
        self.assertEqual(raw[0], 0)
        recovered_key = PKCS1_OAEP.new(self.private, hashAlgo=SHA256).decrypt(raw[1:257])
        self.assertEqual(recovered_key, session_key)
        self.assertEqual(raw[257:273], iv)
        self.assertEqual(raw[-32:], hmac.new(self.mac_key, raw[257:-32], hashlib.sha256).digest())
        self.assertEqual(codec.decode_with_session_key(token, session_key=recovered_key,
                                                      hmac_key=self.mac_key), self.payload)

    def test_default_randomness_changes_envelope_with_same_plaintext(self):
        tokens = [codec.encode(self.payload, public_key=self.public, hmac_key=self.mac_key)
                  for _ in range(2)]
        self.assertNotEqual(tokens[0], tokens[1])
        for token in tokens:
            parts = codec.split(token)
            key = PKCS1_OAEP.new(self.private, hashAlgo=SHA256).decrypt(parts.wrapped_key)
            self.assertEqual(codec.decode_with_session_key(token, session_key=key,
                                                          hmac_key=self.mac_key), self.payload)

    def test_tampered_ciphertext_mac_and_wrong_key_fail(self):
        token = codec.encode(self.payload, public_key=self.public, hmac_key=self.mac_key,
                             session_key=b'K' * 32)
        raw = bytearray(base64.urlsafe_b64decode(token + '=' * (-len(token) % 4)))
        for index in (257, 273, len(raw)-1):
            altered = raw[:]
            altered[index] ^= 1
            changed = base64.urlsafe_b64encode(altered).decode().rstrip('=')
            with self.assertRaisesRegex(ValueError, 'MAC mismatch'):
                codec.decode_with_session_key(changed, session_key=b'K' * 32,
                                              hmac_key=self.mac_key)
        with self.assertRaises((ValueError, zlib.error, UnicodeError)):
            codec.decode_with_session_key(token, session_key=b'X' * 32, hmac_key=self.mac_key)

    def test_decoder_rejects_trailing_deflate_and_expansion(self):
        for packed in (zlib.compress(b'{}')[2:-4] + b'EXTRA',
                       zlib.compress(b' ' * (codec.MAX_PLAIN_BYTES + 1))[2:-4]):
            iv, key = b'I' * 16, b'K' * 32
            body = iv + AES.new(key, AES.MODE_CBC, iv).encrypt(pad(packed, 16))
            raw = b'\0' + b'R' * 256 + body + hmac.new(self.mac_key, body, hashlib.sha256).digest()
            token = base64.urlsafe_b64encode(raw).decode().rstrip('=')
            with self.assertRaises(ValueError):
                codec.decode_with_session_key(token, session_key=key, hmac_key=self.mac_key)

    def test_schema_does_not_silently_create_identity_or_counter(self):
        self.assertEqual(self.payload['33'], 'synthetic-id')
        self.assertEqual(self.payload['73'], 4)
        self.assertEqual(self.payload['59'], 91)
        self.assertEqual(set(self.payload), {'1', '33', '50', '59', '60', '73', '74'})
        with self.assertRaises(ValueError):
            codec.build_payload(application_id='app', installation_id='id',
                                initialization_counter=True, initialized_at_ms=0,
                                request_counter=0, requested_at_ms=0)
        for bad in ('', '!', 'AA==', 'AB', 'A'):
            with self.assertRaises(ValueError):
                codec.split(bad)


if __name__ == '__main__':
    unittest.main()
