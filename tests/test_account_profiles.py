"""Identity metadata must stay scoped to the verified account and exclude secrets."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from farm import account_profiles as profiles


class AccountProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.patch = patch.object(profiles, 'PROFILE_ROOT', self.root)
        self.patch.start()
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.patch.stop)

    def response(self, email='user@example.test', user_id='42'):
        return {'code': 0, 'token': 'private-top-level', 'user': {
            'idStr': user_id, 'email': email, 'username': 'test-user',
            'token': 'private-user-token', 'phone': 'private-phone'}}

    def test_valid_profile_persists_only_identity_metadata(self):
        saved = profiles.remember_profile(1, 8, '42', self.response())
        self.assertEqual(saved['email'], 'user@example.test')
        self.assertEqual(profiles.read_profile(1), saved)
        path = self.root / '1.json'
        self.assertEqual(set(json.loads(path.read_text())), set(profiles.FIELDS))
        self.assertNotIn('private-', path.read_text())
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_rejects_mismatched_identity_and_invalid_response(self):
        for response in (None, [], self.response(user_id='99'),
                         dict(self.response(), _http_status=403)):
            with self.subTest(response_type=type(response).__name__):
                with self.assertRaises(ValueError):
                    profiles.remember_profile(1, 8, '42', response)
                self.assertIsNone(profiles.read_profile(1))

    def test_stale_response_cannot_overwrite_newer_email_or_session(self):
        profiles.remember_profile(1, 9, '42', self.response('new@example.test'),
                                  at='2026-10-03T10:00:00Z')
        profiles.remember_profile(1, 8, '42', self.response('old@example.test'),
                                  at='2026-10-03T09:00:00Z')
        saved = profiles.read_profile(1)
        self.assertEqual(saved['email'], 'new@example.test')
        self.assertEqual(saved['session_id'], 9)
        profiles.remember_profile(1, 9, '42', self.response(None),
                                  at='2026-10-03T11:00:00Z')
        self.assertEqual(profiles.read_profile(1)['email'], 'new@example.test')

    def test_overlay_checks_identity_and_current_session(self):
        profiles.remember_profile(1, 8, '42', self.response())
        accounts = [{'id': 1, 'user_id': '42', 'active_session_id': 8},
                    {'id': 1, 'user_id': '42', 'active_session_id': 9},
                    {'id': 1, 'user_id': '99', 'active_session_id': 8}]
        profiles.overlay_profiles(accounts)
        self.assertEqual(accounts[0]['email'], 'user@example.test')
        self.assertIn('identity_verified_at', accounts[0])
        self.assertEqual(accounts[1]['email'], 'user@example.test')
        self.assertNotIn('identity_verified_at', accounts[1])
        self.assertNotIn('email', accounts[2])

    def test_unreadable_profile_does_not_break_dashboard(self):
        path = self.root / '1.json'
        for value in ('{', 'null', '[]', '{"account_id": 2}'):
            path.write_text(value)
            self.assertIsNone(profiles.read_profile(1))
        path.unlink()
        other = self.root / 'other.json'
        other.write_text('{"account_id": 1}')
        path.symlink_to(other)
        self.assertIsNone(profiles.read_profile(1))


if __name__ == '__main__':
    unittest.main()
