"""SDK envelope tests use native CBC vectors and optional private builder captures."""
import base64
import json
from pathlib import Path
import unittest
import zlib

from mtgsig import envelope_codec as codec

ROOT = Path(__file__).resolve().parents[2]
A1 = '00000000-1111-2222-3333-444444444444'
OTHER_A1 = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
KEY = bytes(range(16))
PLAIN = b'{"synthetic":true,"sample":"' + b'abcd' * 64 + b'"}'
CBC = json.loads((Path(__file__).parent.parent / 'fixtures/a9_native_cbc_vectors.json').read_text())


class SDKEnvelopeTests(unittest.TestCase):
    def test_payload_matches_native_cbc_fixtures(self):
        # These expected ciphertexts came from native wrappers, not from
        # this envelope implementation. The fixture uses synthetic keys.
        for v in CBC['vectors']:
            with self.subTest(mode=v['mode'], length=len(v['plaintext']) // 2):
                key, plain = bytes.fromhex(v['key']), bytes.fromhex(v['plaintext'])
                envelope = codec.encode_sdk(plain, A1, session_key=key,
                                            mode=v['mode'], compress=False)
                self.assertEqual(codec.split(envelope).part2.hex(), v['ciphertext'])
                material = codec.derive_session_material(key, A1)
                result = codec.decode_sdk(envelope, A1, session_material=material,
                                           mode=v['mode'], decompress=False)
                self.assertEqual(result.plaintext, plain)
                self.assertTrue(result.rsa_verified)

    def test_compressed_roundtrip_and_known_material(self):
        for mode in ('aes', 'twofish', 'twofish-mod'):
            for profile in ('default', 'legacy'):
                with self.subTest(mode=mode, profile=profile):
                    envelope = codec.encode_sdk(PLAIN, A1, session_key=KEY,
                                                mode=mode, profile=profile)
                    material = codec.derive_session_material(KEY, A1, profile=profile)
                    self.assertNotEqual(material, KEY)
                    self.assertEqual(codec.recover_session_key(material, A1, profile=profile), KEY)
                    result = codec.decode_sdk(envelope, A1, session_material=material,
                                               profile=profile)
                    self.assertEqual(result.plaintext, PLAIN)
                    self.assertEqual(result.mode, mode)
                    self.assertEqual(result.profile, profile)
                    self.assertTrue(result.rsa_verified)
                    self.assertEqual(codec.decode_sdk(envelope, A1, session_key=KEY,
                                                      profile=profile).plaintext, PLAIN)

    def test_reuses_session_prefix_but_changes_payload(self):
        first = codec.encode_sdk(PLAIN, A1, session_key=KEY)
        second = codec.encode_sdk(PLAIN + b'\n', A1, session_key=KEY)
        self.assertEqual(codec.split(first).part1, codec.split(second).part1)
        self.assertNotEqual(codec.split(first).part2, codec.split(second).part2)

    def test_explicit_profile_and_key_consistency(self):
        envelope = codec.encode_sdk(PLAIN, A1, session_key=KEY)
        for kwargs in ({'profile': 'legacy'}, {'session_key': bytes(reversed(KEY))}):
            options = dict(session_key=KEY)
            options.update(kwargs)
            with self.assertRaises(ValueError):
                codec.decode_sdk(envelope, A1, **options)
        with self.assertRaises(ValueError):
            codec.decode_sdk(envelope, OTHER_A1, session_key=KEY)
        with self.assertRaises(ValueError):
            codec.decode_sdk(envelope, A1, session_key=KEY, session_material=bytes(16))
        with self.assertRaises(ValueError):
            codec.encode_sdk(PLAIN, A1, session_key=KEY, profile='auto')

    def test_public_envelope_cannot_supply_missing_session_material(self):
        envelope = codec.encode_sdk(PLAIN, A1, session_key=KEY)
        with self.assertRaisesRegex(ValueError, 'session_key or known session_material'):
            codec.decode_sdk(envelope, A1)
        # A 128-byte RSA ciphertext is not the 16-byte RSA plaintext.
        with self.assertRaises(ValueError):
            codec.decode_sdk(envelope, A1, session_material=codec.split(envelope).part1)

    def test_short_compression_rejected_instead_of_truncated(self):
        for plain in (b'A', b'0123456789abcdef'):
            self.assertGreater(len(zlib.compress(plain)), len(plain))
            with self.assertRaisesRegex(ValueError, 'zlib expands'):
                codec.encode_sdk(plain, A1, session_key=KEY)
            encoded = codec.encode_sdk(plain, A1, session_key=KEY, compress=False)
            decoded = codec.decode_sdk(encoded, A1, session_key=KEY,
                                       mode='twofish-mod', decompress=False)
            self.assertEqual(decoded.plaintext, plain)

    def test_exact_compressed_stream_is_not_recompressed(self):
        compressed = zlib.compress(PLAIN, 1)
        envelope = codec.encode_compressed_sdk(compressed, A1, session_key=KEY)
        result = codec.decode_sdk(envelope, A1, session_key=KEY)
        self.assertEqual(result.payload, compressed)
        self.assertEqual(result.plaintext, PLAIN)
        for invalid in (compressed[:-1], compressed + b'extra', compressed + compressed):
            with self.assertRaises(ValueError):
                codec.encode_compressed_sdk(invalid, A1, session_key=KEY)

    def test_decompression_limits_and_uncompressed_auto(self):
        envelope = codec.encode_sdk(PLAIN, A1, session_key=KEY)
        with self.assertRaises(ValueError):
            codec.decode_sdk(envelope, A1, session_key=KEY, max_plaintext=len(PLAIN) - 1)
        with self.assertRaises(ValueError):
            codec.encode_compressed_sdk(zlib.compress(PLAIN), A1, session_key=KEY,
                                         max_plaintext=len(PLAIN) - 1)
        uncompressed = codec.encode_sdk(PLAIN, A1, session_key=KEY, compress=False)
        with self.assertRaisesRegex(ValueError, 'explicit cipher mode'):
            codec.decode_sdk(uncompressed, A1, session_key=KEY, decompress=False)

    def test_input_and_cipher_validation(self):
        for plain in (b'', b'a\0b'):
            with self.assertRaises(ValueError):
                codec.encode_sdk(plain, A1, session_key=KEY, compress=False)
        for kwargs in ({'session_key': b'short'}, {'mode': 'auto'}, {'a1_shift': True}):
            options = dict(session_key=KEY)
            options.update(kwargs)
            with self.assertRaises(ValueError):
                codec.encode_sdk(PLAIN, A1, **options)




if __name__ == '__main__':
    unittest.main()
