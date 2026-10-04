"""HTTP transport for mtgsig.api; all signing state belongs to the caller."""
import argparse
import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from mtgsig.api import ROUTES, capabilities

MAX_BODY = 8 << 20


class Handler(BaseHTTPRequestHandler):
    def reply(self, status, value):
        body = json.dumps(value, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def authorized(self):
        token = self.server.token
        if token and not hmac.compare_digest(self.headers.get('X-Token', '').encode(), token.encode()):
            self.reply(401, {'error': 'invalid X-Token'})
            return False
        return True

    def do_GET(self):
        if not self.authorized():
            return
        if self.path.rstrip('/') not in ('', '/health'):
            self.reply(404, {'error': 'unknown endpoint'})
            return
        self.reply(200, {**capabilities(), 'stateless': True,
                         'auth': 'X-Token required' if self.server.token else 'none'})

    def do_POST(self):
        if not self.authorized():
            return
        operation = ROUTES.get(self.path.rstrip('/'))
        if operation is None:
            self.reply(404, {'error': 'unknown endpoint'})
            return
        try:
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 < size <= MAX_BODY:
                self.reply(413, {'error': 'JSON body must be between 1 byte and 8 MiB'})
                return
            value = json.loads(self.rfile.read(size))
            if not isinstance(value, dict):
                raise ValueError('JSON body must be an object')
            self.reply(200, operation(value))
        except (ValueError, TypeError, KeyError) as exc:
            self.reply(400, {'error': str(exc)})
        except NotImplementedError as exc:
            self.reply(501, {'error': str(exc)})
        except Exception:
            self.reply(500, {'error': 'crypto operation failed'})

    def log_message(self, *_):
        pass


def make_server(host='127.0.0.1', port=8799, token=None):
    server = ThreadingHTTPServer((host, port), Handler)
    server.token = token
    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8799)
    args = parser.parse_args()
    with make_server(args.host, args.port, os.environ.get('KEETA_RPC_TOKEN')) as server:
        print(f'[keeta-rpc] listening http://{args.host}:{args.port}', flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
