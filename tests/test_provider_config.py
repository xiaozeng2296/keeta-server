"""Native-accepted configuration vector and strict drift/replay checks."""
import base64
import json
import unittest
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from mtgsig.local_identity import DEFAULT_LOCAL_XID_PROFILE
from mtgsig.provider_config import (ProviderConfig, configuration_summary, decode_config,
                                   encode_config, parse_plaintext)

# Synthetic salt and a3, accepted by the independent native provider parser on
# 3.12.500 / UUID 3fb544966dc03ccca41b9055fc509adf; no account material.
NATIVE_ACCEPTED = 'E8j5a8uQyh0Va4HWbm1RqOuW8exlh3eDMmwDaPTIUgA3EyAIYsmXHcZfk/3tzq2Mud0TiLbsc7ZMoDWB5lOH3w=='


class ProviderConfigurationTests(unittest.TestCase):
    def test_native_accepted_vector(self):
        config = decode_config(NATIVE_ACCEPTED)
        self.assertEqual(config.parameter, 24)
        self.assertEqual(config.salt.hex(), '00112233445566778899aabbccddeeff')
        self.assertEqual(config.a1_shift, 35)
        self.assertEqual(encode_config(config), NATIVE_ACCEPTED)

    def test_default_is_explicit_not_missing(self):
        self.assertEqual(decode_config(''), ProviderConfig())
        self.assertEqual(decode_config('').a1_shift, 31)
        with self.assertRaises(ValueError): decode_config(None)
        self.assertEqual(configuration_summary({'available': False})['decode_status'], 'not_observed')

    def test_malformed_fields_are_not_silently_coerced(self):
        for value in ['25', -1, True, 25.5, 0x80000000]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_plaintext(json.dumps({'a3': value, 'salt': '00' * 16}))
        for text in ['{"a3":25}', '{"a3":25,"salt":"00"}',
                     '{"a3":25,"a3":20,"salt":"' + '00'*16 + '"}',
                     '{"a3":25,"salt":"' + '00'*16 + '","extra":1}']:
            with self.subTest(text=text), self.assertRaises(ValueError): parse_plaintext(text)

    def test_padding_base64_and_size_validation(self):
        profile = DEFAULT_LOCAL_XID_PROFILE
        bad_padding = base64.b64encode(AES.new(profile.key, AES.MODE_CBC, profile.iv).encrypt(b'X'*16)).decode()
        for value in [NATIVE_ACCEPTED+'\n', NATIVE_ACCEPTED[:-4], bad_padding, 'A'*10000, '!not_base64!']:
            with self.subTest(value=value[:20]), self.assertRaises(ValueError): decode_config(value)

    def test_preserves_json_whitespace_and_key_order(self):
        text = '{ "salt": "00112233445566778899AABBCCDDEEFF", "a3": 24 }\n'
        original = base64.b64encode(AES.new(DEFAULT_LOCAL_XID_PROFILE.key, AES.MODE_CBC,
                                            DEFAULT_LOCAL_XID_PROFILE.iv).encrypt(pad(text.encode(),16))).decode()
        self.assertEqual(encode_config(decode_config(original)), original)

    def test_safe_summary_never_contains_ciphertext_or_salt(self):
        summary = configuration_summary({'available': True, 'value': NATIVE_ACCEPTED})
        self.assertEqual(summary['decode_status'], 'decoded')
        self.assertEqual(summary['parameter'], 24)
        self.assertNotIn(NATIVE_ACCEPTED, json.dumps(summary))
        self.assertNotIn('00112233445566778899aabbccddeeff', json.dumps(summary))
        self.assertEqual(configuration_summary({'value': 'invalid'})['decode_status'], 'unsupported_configuration')


if __name__ == '__main__': unittest.main()
