import unittest
import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from tools.check_account import assess_response, check_account


class AccountCheckTests(unittest.TestCase):
    def test_native_success_does_not_require_a_code_field(self):
        response = {"user": {"idStr": "10001", "id": 10001,
                             "username": "test", "email": "test@example.invalid"}}
        self.assertTrue(assess_response(200, response, "10001")["valid"])

    def test_http_200_error_or_anonymous_response_is_not_valid(self):
        for response in ({"error": {"code": 401}}, {"code": 0, "data": {}},
                         {"user": {}}, {"user": {"idStr": "0"}}, None):
            with self.subTest(response=response):
                self.assertFalse(assess_response(200, response, "10001")["valid"])

    def test_another_account_and_inconsistent_ids_are_rejected(self):
        response = {"user": {"idStr": "10002", "id": 10002}}
        self.assertEqual(assess_response(200, response, "10001")["reason"], "account_mismatch")
        response["user"]["id"] = 10001
        self.assertEqual(assess_response(200, response, "10002")["reason"], "inconsistent_user_id")

    def test_http_errors_and_business_errors_override_user_data(self):
        response = {"user": {"idStr": "10001", "id": 10001}}
        self.assertFalse(assess_response(403, response, "10001")["valid"])
        response["code"] = 401
        self.assertFalse(assess_response(200, response, "10001")["valid"])

    def test_validation_honors_account_proxy_even_with_no_proxy_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request = {'method': 'GET', 'url': 'https://passport-eu.mykeeta.com/api/user/v1/info/homepage',
                       'body': '', 'headers': {'host': 'passport-eu.mykeeta.com', 'token': 'fixture-token'}}
            (root / 'account_check_request.json').write_text(json.dumps(request))
            (root / 'identity.json').write_text(json.dumps({'token': 'fixture-token', 'userid': '10001'}))
            signer = Mock(dev={}, counter=1, signature_counter=2)
            signer.sign.return_value = 'fixture-signature'
            def curl(argv, **kwargs):
                self.assertEqual(argv[argv.index('--proxy') + 1], 'http://127.0.0.1:7897')
                self.assertEqual(argv[argv.index('--noproxy') + 1], '')
                Path(argv[argv.index('--output') + 1]).write_text(json.dumps({'user': {'idStr': '10001'}}))
                return Mock(stdout='200', returncode=0)
            with patch('tools.check_account.FullSigner', return_value=signer), \
                    patch('tools.check_account.account_proxy', return_value='http://127.0.0.1:7897'), \
                    patch('tools.check_account.subprocess.run', side_effect=curl), \
                    patch.dict('os.environ', {'NO_PROXY': '*'}):
                result = check_account(root)
            self.assertTrue(result['valid'])
            self.assertTrue(result['proxy_configured'])


if __name__ == "__main__":
    unittest.main()
