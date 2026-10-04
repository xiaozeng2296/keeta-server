"""Explicit requests proxy configuration and credential-free audit metadata."""
from urllib.parse import urlsplit


def proxy_network_mode(proxy=None):
    """Validate an explicit proxy without putting its credentials in artifacts.

    Omission retains requests' existing environment-aware behavior. An explicit
    proxy is exclusive for both target schemes and disables environment state.
    """
    if proxy is None:
        return {'mode': 'environment', 'trust_env': True}
    if not isinstance(proxy, str) or not proxy or any(char.isspace() for char in proxy):
        raise ValueError('proxy must be an explicit HTTP or HTTPS URL')
    try:
        parsed = urlsplit(proxy)
        port = parsed.port
    except ValueError:
        raise ValueError('proxy URL is invalid') from None
    if (parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.path not in ('', '/')
            or parsed.query or parsed.fragment or port == 0):
        raise ValueError('proxy must be an HTTP or HTTPS authority without query or fragment')
    host = parsed.hostname
    if ':' in host:
        host = '[' + host + ']'
    authority = host + (':' + str(port) if port is not None else '')
    return {'mode': 'explicit_proxy', 'trust_env': False,
            'proxy': parsed.scheme + '://' + authority, 'direct_fallback': False}


def configure_http_session(session, proxy=None):
    """Configure before the first request; a failed proxy is never retried direct."""
    network = proxy_network_mode(proxy)
    if proxy is not None:
        session.trust_env = False
        session.proxies.clear()
        session.proxies.update({'http': proxy, 'https': proxy})
    return network
