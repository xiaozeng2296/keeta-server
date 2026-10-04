"""UID based mailbox polling tests; no Microsoft or IMAP network."""
from email.message import EmailMessage
import unittest
from unittest.mock import Mock, patch

import mailbox


class FakeIMAP:
    def __init__(self, uids=b"1 2 7", uidvalidity=b"42"):
        self.uids = uids
        self.untagged_responses = {"UIDVALIDITY": [uidvalidity]}
        self.fetched = []
        self.searches = []
        self.fetch_modes = []

    def uid(self, command, *args):
        if command == "search":
            self.searches.append(args)
            return "OK", [self.uids]
        if command == "fetch":
            uid = int(args[0])
            self.fetched.append(uid)
            self.fetch_modes.append(args[1])
            msg = EmailMessage()
            msg["Subject"] = f"Keeta code {uid}"
            msg.set_content(f"Your verification code is {uid:04d}")
            return "OK", [(b"RFC822", msg.as_bytes())]
        raise AssertionError(command)

    def logout(self):
        return "OK", []


class MailboxUidTests(unittest.TestCase):
    def test_imap_login_is_readonly_and_has_timeout(self):
        conn = Mock()
        conn.select.return_value = ("OK", [b"0"])
        with patch.object(mailbox.imaplib, "IMAP4_SSL", return_value=conn) as connect:
            self.assertIs(mailbox.imap_login("test@example.test", "access"), conn)
        connect.assert_called_once_with(mailbox.IMAP_HOST, timeout=30)
        conn.select.assert_called_once_with("INBOX", readonly=True)

    def test_imap_login_closes_failed_selection(self):
        conn = Mock()
        conn.select.return_value = ("NO", [b"not available"])
        with patch.object(mailbox.imaplib, "IMAP4_SSL", return_value=conn):
            with self.assertRaisesRegex(RuntimeError, "selection failed"):
                mailbox.imap_login("test@example.test", "access")
        conn.logout.assert_called_once()

    def test_snapshot_contains_only_uid_metadata(self):
        conn = FakeIMAP(b"7 2 7 1")
        account = {"email": "test@example.test", "client_id": "cid",
                   "refresh_token": "refresh"}
        with patch.object(mailbox, "load_accounts", return_value=[account]), \
             patch.object(mailbox, "get_token", return_value=("access", None)), \
             patch.object(mailbox, "imap_login", return_value=conn):
            snapshot = mailbox.snapshot_mailbox(account["email"], search="Keeta")
        self.assertEqual(snapshot, {"uidvalidity": 42, "uids": [1, 2, 7],
                                    "highest_uid": 7})
        self.assertEqual(conn.searches, [(None, "ALL")])

    def test_fetch_new_messages_excludes_snapshot_uids(self):
        conn = FakeIMAP(b"1 2 7 9")
        result = mailbox.fetch_new_messages(
            conn, {"uidvalidity": 42, "uids": [1, 2, 7], "highest_uid": 7})
        self.assertEqual([item["uid"] for item in result], [9])
        self.assertEqual(conn.fetched, [9])
        self.assertEqual(conn.fetch_modes, ["(BODY.PEEK[])"])

    def test_delayed_indexed_old_uid_is_not_new(self):
        conn = FakeIMAP(b"1 5 9")
        result = mailbox.fetch_new_messages(
            conn, {"uidvalidity": 42, "uids": [1], "highest_uid": 7})
        self.assertEqual([item["uid"] for item in result], [9])
        self.assertEqual(conn.fetched, [9])

    def test_missing_account_error_does_not_reveal_address(self):
        with patch.object(mailbox, "load_accounts", return_value=[]):
            with self.assertRaises(ValueError) as caught:
                mailbox._account("private@example.test", "mail.txt")
        self.assertNotIn("private@example.test", str(caught.exception))

    def test_uidvalidity_change_is_not_treated_as_new_mail(self):
        with self.assertRaisesRegex(RuntimeError, "UIDVALIDITY"):
            mailbox.fetch_new_messages(
                FakeIMAP(b"1", b"43"), {"uidvalidity": 42, "uids": [1]})

    def test_get_code_uses_snapshot_only(self):
        snapshot = {"uidvalidity": 42, "uids": [1], "highest_uid": 1}
        with patch.object(mailbox, "_account", return_value={"email": "x",
                      "client_id": "cid", "refresh_token": "refresh"}), \
             patch.object(mailbox, "get_token", return_value=("access", None)), \
             patch.object(mailbox, "imap_login", return_value=FakeIMAP()), \
             patch.object(mailbox, "fetch_new_messages", return_value=[
                 {"subject": "Keeta", "text": "code 1234"}]) as fetch:
            self.assertEqual(mailbox.get_code("x", since=snapshot), "1234")
        fetch.assert_called_once()
        self.assertEqual(fetch.call_args.kwargs["search"], "Keeta")
        self.assertIs(fetch.call_args.args[1], snapshot)


if __name__ == "__main__":
    unittest.main()
