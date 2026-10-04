import base64
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import zlib

import keeta_rpc as rpc
from mtgsig import envelope_codec as codec

A1 = '00000000-1111-2222-3333-444444444444'
KEY = bytes(range(16))
PLAIN = {'synthetic': True, 'sample': 'abcd' * 64}


class EnvelopeRPCTests(unittest.TestCase):
    def test_explicit_key_roundtrip_uses_json_first_response(self):
        encoded = rpc.op_envelope_encode({
            "session_key": "hex:6af9acba772fc9ff3243c59b4e0fbbc3",
            "plaintext": {"m153": "synthetic", "m162": "WiFi"},
            "key": "0123456789abcdef",
            "iv": "0102030405060708",
        })
        decoded = rpc.op_envelope_decode({
            "envelope": encoded["envelope"],
            "key": "0123456789abcdef",
            "iv": "0102030405060708",
        })
        self.assertEqual(decoded["plain_json"], {"m153": "synthetic", "m162": "WiFi"})
        self.assertEqual(decoded["part1_bytes"], 128)
        self.assertNotIn("plain_b64", decoded)
        self.assertNotIn("plain_text", decoded)

    def test_unknown_payload_key_is_rejected(self):
        encoded = rpc.op_envelope_encode({
            "session_key": "hex:6af9acba772fc9ff3243c59b4e0fbbc3",
            "plaintext": "payload",
            "key": "0123456789abcdef",
        })
        with self.assertRaises(ValueError):
            rpc.op_envelope_decode({
                "envelope": encoded["envelope"],
                "key": "fedcba9876543210",
            })

    def test_sdk_all_modes_profiles_and_known_rsa_material(self):
        for mode in ('aes', 'twofish', 'twofish-mod'):
            for profile in ('default', 'legacy'):
                with self.subTest(mode=mode, profile=profile):
                    encoded = rpc.op_envelope_encode(dict(a1=A1, plain_json=PLAIN,
                        session_key_hex=KEY.hex(), mode=mode, profile=profile))
                    self.assertFalse(encoded['session_key_generated'])
                    self.assertNotIn('session_key_hex', encoded)
                    material = codec.derive_session_material(KEY, A1, profile=profile)
                    for field, value in (('session_key_hex', KEY.hex()),
                                         ('session_material_hex', material.hex())):
                        decoded = rpc.op_envelope_decode(dict(a1=A1,
                            envelope=encoded['envelope'], profile=profile, **{field: value}))
                        self.assertEqual(decoded['plain_json'], PLAIN)
                        self.assertEqual(decoded['mode'], mode)
                        self.assertEqual(decoded['profile'], profile)
                        self.assertTrue(decoded['rsa_verified'])
                        self.assertNotIn('plain_b64', decoded)
                        self.assertNotIn('plain_text', decoded)
                        self.assertNotIn('session_key_hex', decoded)

    def test_generated_session_key_is_returned_and_usable(self):
        with patch.object(rpc.secrets, 'token_bytes', return_value=KEY) as generate:
            encoded = rpc.op_envelope_encode({'a1': A1, 'plain_json': PLAIN})
        generate.assert_called_once_with(16)
        self.assertTrue(encoded['session_key_generated'])
        self.assertEqual(encoded['session_key_hex'], KEY.hex())
        decoded = rpc.op_envelope_decode({'a1': A1, 'envelope': encoded['envelope'],
                                         'session_key_hex': encoded['session_key_hex']})
        self.assertEqual(decoded['plain_json'], PLAIN)

    def test_sdk_rejects_missing_and_ambiguous_key_encodings(self):
        encoded = rpc.op_envelope_encode({'a1': A1, 'plain_json': PLAIN,
                                         'session_key_hex': KEY.hex()})
        with self.assertRaisesRegex(ValueError, 'session_key or known session_material'):
            rpc.op_envelope_decode({'a1': A1, 'envelope': encoded['envelope']})
        for fields in ({'key': '0123456789abcdef'}, {'iv': '0102030405060708'},
                       {'session_key': KEY.hex()}, {'session_material': KEY.hex()},
                       {'session_key_hex': 'hex:' + KEY.hex()},
                       {'session_key_hex': ' ' + KEY.hex()}, {'session_key_hex': None},
                       {'session_key_hex': '0123456789abcdef'}, {'compress': 'false'}):
            with self.subTest(fields=list(fields)), self.assertRaises(ValueError):
                rpc.op_envelope_encode({'a1': A1, 'plain_json': PLAIN, **fields})
        with self.assertRaisesRegex(ValueError, 'a1'):
            rpc.op_envelope_encode({'plain_json': PLAIN, 'session_key_hex': KEY.hex()})

    def test_exact_zlib_route_and_short_plaintext_rejection(self):
        text = json.dumps(PLAIN, separators=(',', ':')).encode()
        compressed = zlib.compress(text, 1)
        encoded = rpc.op_envelope_encode({'a1': A1, 'session_key_hex': KEY.hex(),
            'compressed_b64': base64.b64encode(compressed).decode()})
        self.assertEqual(encoded['envelope'],
            codec.encode_compressed_sdk(compressed, A1, session_key=KEY))
        for extra in ({'plaintext': 'also supplied'}, {'compress': False}, {'zlib_level': 6}):
            with self.assertRaises(ValueError):
                rpc.op_envelope_encode({'a1': A1, 'session_key_hex': KEY.hex(),
                    'compressed_b64': base64.b64encode(compressed).decode(), **extra})
        with self.assertRaisesRegex(ValueError, 'zlib expands'):
            rpc.op_envelope_encode({'a1': A1, 'plaintext': 'A'})

    def test_rpc_matches_private_complete_native_fixture(self):
        root = Path(__file__).resolve().parents[1] / 'dump/envelope_recovery'
        if not (root / 'builder_native_02.json').exists() or not (root / 'builder_a1_correlation.json').exists():
            self.skipTest('private native capture is not installed')
        native = json.loads((root / 'builder_native_02.json').read_text())
        correlation = json.loads((root / 'builder_a1_correlation.json').read_text())
        row = next(r for r in native['rows'] if r['compress'] and r['input_bytes'] > 16)
        encoded = rpc.op_envelope_encode({'a1': correlation['a1'],
            'session_key_hex': native['key'], 'plaintext': row['text'],
            'profile': correlation['profile'], 'mode': native['mode']})
        self.assertEqual(encoded['envelope'], row['envelope'])
        decoded = rpc.op_envelope_decode({'a1': correlation['a1'],
            'session_material_hex': native['rsa_material'], 'envelope': row['envelope'],
            'profile': correlation['profile']})
        self.assertEqual(decoded['plain_json'], json.loads(row['text']))

    def test_capabilities_describe_session_requirement(self):
        result = rpc.capabilities()
        self.assertTrue(result['envelope_sdk_ready'])
        self.assertTrue(result['envelope_requires_session_key'])
        self.assertEqual(set(result['envelope_modes']), {'aes', 'twofish', 'twofish-mod'})
        self.assertEqual(set(result['envelope_profiles']), {'default', 'legacy'})


if __name__ == "__main__":
    unittest.main()
