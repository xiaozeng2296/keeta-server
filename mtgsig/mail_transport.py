"""IMAPS through an explicit HTTP CONNECT proxy, without direct fallback."""
import base64
import http.client
import imaplib
import ssl
from urllib.parse import unquote, urlsplit

from mtgsig.http_transport import proxy_network_mode


class _ConnectProxy(http.client.HTTPConnection):
    def __init__(self, host, port, *, timeout, tls_proxy=False):
        super().__init__(host, port, timeout=timeout)
        self.tls_proxy = tls_proxy

    def connect(self):
        # The only TCP peer is the proxy. DNS for the IMAP destination is
        # delegated to CONNECT, so a failed tunnel never opens a direct socket.
        self.sock = self._create_connection((self.host, self.port), self.timeout,
                                            self.source_address)
        try:
            if self.tls_proxy:
                self.sock = ssl.create_default_context().wrap_socket(
                    self.sock, server_hostname=self.host)
            self._tunnel()
        except Exception:
            self.close()
            raise


def open_imap_tunnel(proxy, host, port, *, timeout=30, ssl_context=None):
    proxy_network_mode(proxy)
    if proxy is None:
        raise ValueError('IMAP tunnel requires an explicit proxy')
    parsed = urlsplit(proxy)
    tls_proxy = parsed.scheme == 'https'
    connection = _ConnectProxy(parsed.hostname, parsed.port or (443 if tls_proxy else 80),
                               timeout=timeout, tls_proxy=tls_proxy)
    headers = {}
    if parsed.username is not None:
        credentials = unquote(parsed.username) + ':' + unquote(parsed.password or '')
        headers['Proxy-Authorization'] = 'Basic ' + base64.b64encode(
            credentials.encode('utf-8')).decode('ascii')
    connection.set_tunnel(host, port, headers=headers)
    try:
        connection.connect()
        context = ssl_context or ssl.create_default_context()
        if tls_proxy:
            # Nested TLS must use MemoryBIO; wrap_socket on an SSLSocket would
            # bypass the already established TLS layer to the HTTPS proxy.
            from urllib3.util.ssltransport import SSLTransport
            return SSLTransport(connection.sock, context, server_hostname=host)
        return context.wrap_socket(connection.sock, server_hostname=host)
    except Exception:
        connection.close()
        raise


class ProxyIMAP4SSL(imaplib.IMAP4_SSL):
    def __init__(self, host, port=imaplib.IMAP4_SSL_PORT, *, proxy, timeout=30):
        proxy_network_mode(proxy)
        self.proxy = proxy
        super().__init__(host, port, ssl_context=ssl.create_default_context(), timeout=timeout)

    def _create_socket(self, timeout):
        return open_imap_tunnel(self.proxy, self.host, self.port, timeout=timeout,
                                ssl_context=self.ssl_context)

    def shutdown(self):
        # urllib3 SSLTransport supplies close()/makefile(), but no socket
        # shutdown(). Preserve the original IMAP error during failed greeting
        # cleanup instead of masking it with AttributeError.
        if not hasattr(self.sock, 'shutdown'):
            try:
                self.file.close()
            finally:
                self.sock.close()
            return
        super().shutdown()
