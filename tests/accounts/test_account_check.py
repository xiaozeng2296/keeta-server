import unittest
import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from farm.accounts.assessment import assess_response


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



if __name__ == "__main__":
    unittest.main()
