"""Golden body-prefix hashes measured from native signing buffer copies.

Keeta 3.12.500 / SDK 5.21.10 / UUID 3fb544966dc03ccca41b9055fc509adf.
Only synthetic input bodies and their observed hashes are included here.
"""
import hashlib
import json
import unittest

import mtgsig.a2 as a2
from mtgsig import signer as fs
from tests.protocol import test_signing_profiles as fixtures


class A2MessageTests(unittest.TestCase):
    def test_native_body_prefix_vectors(self):
        vectors = [
            ('A' * 16188, 16199, '56cbfcb9a20a0a12ea39b46e4e1cdc3714f84135fe2e845733dde4313a7bad75'),
            ('A' * 16189, 16200, 'ec7001f242678952d119826a591eff554c01fe3184db88375b4254f0d8114a88'),
            ('A' * 16190, 16200, 'f955512af8c814fcc3e096b1b55c484c5eb7ea30afe20bec4f6cca89b910be2b'),
            ('中' * 6000, 16200, 'ce41faa272b6783cf6f983f81a1fb0aa86d7f89962dc5af4daa77669a7031c28'),
            ('😀' * 5000, 16200, 'e13d3bf829f3aa8973fd391470af0d4d5fca386e9ac9449db6094be7ccd666c3'),
            ('A' * 16190 + '中B', 16200, 'f22bea22318ce978a37a55e3af7e536b6362bad02f198bce60310039423305ad'),
            ('A' * 16190 + '😀B', 16200, 'e84558e1addf32f1f7c6d9d35180655a505af5a0890e31bdf9dc61d099364d14'),
        ]
        for content, length, expected in vectors:
            with self.subTest(length=len(content.encode()), expected=expected):
                message = a2.signing_message('POST', 'https://example.test/', '{"data":"' + content + '"}')
                prefix = message[len(b'POST / '):]
                self.assertEqual(len(prefix), length)
                self.assertEqual(hashlib.sha256(prefix).hexdigest(), expected)

    def test_utf8_cut_keeps_incomplete_character_bytes(self):
        body = '{"data":"' + 'A' * 16190 + '中B"}'
        message = a2.signing_message('POST', 'https://example.test/', body, 'PAYLOAD')
        self.assertEqual(message[-8:], b'\xe4PAYLOAD')
        with self.assertRaises(UnicodeDecodeError): message.decode('utf-8')

    def test_body_limit_does_not_limit_url_or_payload(self):
        query = 'x=' + 'v' * 17000
        payload = 'P' * 17000
        message = a2.signing_message('POST', 'https://example.test/path?' + query, 'B' * 17000, payload)
        self.assertEqual(message, ('POST /path ' + query).encode() + b'B' * 16200 + payload.encode())
        self.assertEqual(a2.signing_message('GET', 'https://example.test/', None, 'payload'), b'GET / payload')

    def test_full_a2_depends_on_prefix_and_keeps_payload_binding(self):
        mt = fixtures.SigningProfileTests().sample('default')
        payload = json.dumps({k: mt[k] for k in fs.FullSigner.ORDER}, separators=(',', ':'))
        def sign(body, text=payload):
            return fs.compute_a2('POST', 'https://example.test/', body, text, mt['a1'], 1,
                                 signing_profile='default', sign_sequence=1)
        base = sign('A' * 16200)
        self.assertEqual(base, sign('A' * 16200 + 'TAIL'))
        self.assertNotEqual(base, sign('B' + 'A' * 16199))
        self.assertNotEqual(base, sign('A' * 16200, payload + ' '))


if __name__ == '__main__': unittest.main()
