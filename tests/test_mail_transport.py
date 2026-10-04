"""HTTP CONNECT and OAuth proxy checks using only in-memory socket doubles."""
import io
import ssl
import unittest
from unittest.mock import Mock, patch

import requests
import mailbox
from mtgsig import mail_transport as transport


class TunnelSocket:
    def __init__(self, status=b'200 Connection established'):
        self.response = b'HTTP/1.1 ' + status + b'\r\n\r\n'
        self.sent = b''
        self.closed = False

    def sendall(self, value):
        self.sent += value

    def makefile(self, mode):
        return io.BytesIO(self.response)

    def close(self):
        self.closed = True


class MailTransportTests(unittest.TestCase):
    def setUp(self):
        guard = patch('socket.socket', side_effect=AssertionError('network forbidden'))
        guard.start()
        self.addCleanup(guard.stop)

    def test_connect_opens_only_proxy_then_wraps_imap_tls(self):
        sock, context = TunnelSocket(), Mock()
        with patch('socket.create_connection', return_value=sock) as connect:
            result = transport.open_imap_tunnel('http://user:p%40ss@127.0.0.1:7897',
                'outlook.office365.com', 993, ssl_context=context)
        connect.assert_called_once_with(('127.0.0.1', 7897), 30, None)
        self.assertIn(b'CONNECT outlook.office365.com:993 HTTP/', sock.sent)
        self.assertIn(b'Proxy-Authorization: Basic dXNlcjpwQHNz', sock.sent)
        context.wrap_socket.assert_called_once_with(sock, server_hostname='outlook.office365.com')
        self.assertIs(result, context.wrap_socket.return_value)

    def test_connect_failure_closes_socket_without_direct_fallback(self):
        sock, context = TunnelSocket(b'407 Proxy Authentication Required'), Mock()
        with patch('socket.create_connection', return_value=sock) as connect:
            with self.assertRaisesRegex(OSError, '407'):
                transport.open_imap_tunnel('http://127.0.0.1:7897',
                    'outlook.office365.com', 993, ssl_context=context)
        connect.assert_called_once_with(('127.0.0.1', 7897), 30, None)
        self.assertTrue(sock.closed)
        context.wrap_socket.assert_not_called()

    def test_imap_tls_failure_does_not_retry_and_closes_tunnel(self):
        sock, context = TunnelSocket(), Mock()
        context.wrap_socket.side_effect = ssl.SSLError('test TLS failure')
        with patch('socket.create_connection', return_value=sock) as connect:
            with self.assertRaises(ssl.SSLError):
                transport.open_imap_tunnel('http://127.0.0.1:7897', 'mail.example.test', 993,
                                           ssl_context=context)
        connect.assert_called_once()
        self.assertTrue(sock.closed)

    def test_https_proxy_keeps_both_tls_layers(self):
        raw, tunnel, proxy_context, imap_context = Mock(), TunnelSocket(), Mock(), Mock()
        proxy_context.wrap_socket.return_value = tunnel
        with patch('socket.create_connection', return_value=raw), \
             patch.object(transport.ssl, 'create_default_context', return_value=proxy_context), \
             patch('urllib3.util.ssltransport.SSLTransport') as nested:
            transport.open_imap_tunnel('https://proxy.example.test:8443', 'mail.example.test', 993,
                                       ssl_context=imap_context)
        proxy_context.wrap_socket.assert_called_once_with(raw, server_hostname='proxy.example.test')
        nested.assert_called_once_with(tunnel, imap_context, server_hostname='mail.example.test')
        imap_context.wrap_socket.assert_not_called()

    def test_mail_oauth_uses_only_explicit_session(self):
        session = requests.Session()
        response = Mock()
        response.json.return_value = {'access_token': 'fake-access'}
        proxy = 'http://127.0.0.1:7897'
        with patch.object(session, 'post', return_value=response) as sender, \
             patch.object(mailbox.requests, 'post', side_effect=AssertionError('default transport forbidden')):
            self.assertEqual(mailbox.get_token('fake-client', 'fake-refresh', proxy=proxy,
                                               http_session=session), ('fake-access', 'fake-refresh'))
        sender.assert_called_once()
        self.assertFalse(session.trust_env)
        self.assertEqual(session.proxies, {'http': proxy, 'https': proxy})

    def test_mail_oauth_proxy_failure_does_not_retry(self):
        session = requests.Session()
        with patch.object(session, 'post', side_effect=requests.exceptions.ProxyError('offline')) as send, \
             patch.object(mailbox.requests, 'post', side_effect=AssertionError('default transport forbidden')):
            with self.assertRaises(requests.exceptions.ProxyError):
                mailbox.get_token('fake-client', 'fake-refresh', proxy='http://127.0.0.1:7897',
                                  http_session=session)
        send.assert_called_once()

    def test_proxy_imap_login_cannot_open_direct_connection(self):
        conn = Mock()
        conn.select.return_value = ('OK', [b'0'])
        with patch.object(transport, 'ProxyIMAP4SSL', return_value=conn) as connect, \
             patch.object(mailbox.imaplib, 'IMAP4_SSL', side_effect=AssertionError('direct forbidden')):
            self.assertIs(mailbox.imap_login('test@example.test', 'fake-access',
                                             proxy='http://127.0.0.1:7897'), conn)
        connect.assert_called_once_with(mailbox.IMAP_HOST, proxy='http://127.0.0.1:7897', timeout=30)
        conn.select.assert_called_once_with('INBOX', readonly=True)

    def test_snapshot_and_code_pass_proxy_to_oauth_and_imap(self):
        account = {'email': 'test@example.test', 'client_id': 'fake-client', 'refresh_token': 'fake-refresh'}
        session, proxy = requests.Session(), 'http://127.0.0.1:7897'
        conn = Mock()
        conn.untagged_responses = {'UIDVALIDITY': [b'42']}
        conn.uid.return_value = ('OK', [b'1'])
        for operation in (mailbox.snapshot_mailbox, mailbox.get_code):
            with self.subTest(operation=operation.__name__), \
                 patch.object(mailbox, '_account', return_value=account), \
                 patch.object(mailbox, 'get_token', return_value=('fake-access', None)) as token, \
                 patch.object(mailbox, 'imap_login', return_value=conn) as imap, \
                 patch.object(mailbox, 'fetch_messages', return_value=[]):
                operation(account['email'], proxy=proxy, http_session=session)
                token.assert_called_once_with('fake-client', 'fake-refresh', proxy=proxy, http_session=session)
                imap.assert_called_once_with(account['email'], 'fake-access', proxy=proxy)

    def test_nested_tls_without_socket_shutdown_closes_cleanly(self):
        conn = transport.ProxyIMAP4SSL.__new__(transport.ProxyIMAP4SSL)
        conn.sock = TunnelSocket()
        conn.file = io.BytesIO()
        conn.shutdown()
        self.assertTrue(conn.file.closed)
        self.assertTrue(conn.sock.closed)

    def test_failed_nested_tls_greeting_preserves_original_imap_error(self):
        sock = TunnelSocket()
        sock.response = b'* NO fixture greeting rejected\r\n'
        with patch.object(transport, 'open_imap_tunnel', return_value=sock):
            with self.assertRaisesRegex(mailbox.imaplib.IMAP4.error, 'greeting rejected'):
                transport.ProxyIMAP4SSL('mail.example.test', proxy='https://proxy.example.test')
        self.assertTrue(sock.closed)


if __name__ == '__main__':
    unittest.main()
