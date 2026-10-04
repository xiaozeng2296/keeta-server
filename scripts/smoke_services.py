"""Local HTTP/process smoke checks with synthetic inputs; no business requests."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from unittest.mock import Mock
import urllib.request

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))


def port():
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));return sock.getsockname()[1]


def get(url):
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(url,timeout=2) as reply:
        return reply.status,reply.read()


@contextmanager
def process(command,env=None):
    with tempfile.TemporaryFile() as log:
        child=subprocess.Popen(command,cwd=ROOT,env=env,stdin=subprocess.DEVNULL,stdout=log,stderr=log)
        try:yield child
        finally:
            if child.poll() is None:child.terminate()
            try:child.wait(timeout=10)
            except subprocess.TimeoutExpired:child.kill();child.wait(timeout=5)


def ready(child,url):
    deadline=time.monotonic()+10
    while time.monotonic()<deadline:
        if child.poll() is not None:raise RuntimeError('service_exited_before_ready')
        try:return get(url)
        except OSError:time.sleep(.05)
    raise RuntimeError('local_service_start_timeout')


def main():
    from rpc.smoke import Client,run_checks
    endpoint='http://127.0.0.1:'+str(port())
    env=os.environ.copy();env.pop('KEETA_RPC_TOKEN',None);env.pop('PYTHONPATH',None)
    with process([sys.executable,'keeta_rpc.py','--port',endpoint.rsplit(':',1)[1]],env) as child:
        assert ready(child,endpoint+'/health')[0]==200
        client=Client(endpoint);run_checks(client,report=lambda *_:None)
        rpc_requests=client.requests
    from farm.panel import create_app
    from werkzeug.serving import make_server
    store=Mock();store.rows.return_value=[]
    server=make_server('127.0.0.1',0,create_app(store,start_worker=False))
    thread=threading.Thread(target=server.serve_forever);thread.start()
    try:
        base='http://127.0.0.1:'+str(server.server_port)
        assert get(base+'/')[0]==200
        code,body=get(base+'/api/state?scope=batches')
        assert code==200 and json.loads(body)['runs']==[]
        assert get(base+'/static/panel.js')[0]==200
    finally:server.shutdown();thread.join(5);server.server_close()
    # Test the real supervisor's start/TERM forwarding with a temporary stand-in
    # for an installed proxy core. This does not claim real exit connectivity.
    with tempfile.TemporaryDirectory() as temp:
        root=Path(temp);directory=root/'.private/clash-node-pool';directory.mkdir(parents=True)
        (directory/'config.yaml').write_text('# synthetic process smoke\n')
        proxy_port=port();core=root/'core'
        core.write_text('#!'+sys.executable+'\nfrom http.server import HTTPServer,BaseHTTPRequestHandler\n'
                        'class H(BaseHTTPRequestHandler):\n def do_GET(self):\n  self.send_response(200);self.end_headers();self.wfile.write(b"{}")\n'
                        'HTTPServer(("127.0.0.1",'+str(proxy_port)+'),H).serve_forever()\n');core.chmod(0o700)
        config=root/'pool.json';config.write_text(json.dumps(dict(core=str(core),controller='http://127.0.0.1:'+str(proxy_port),secret='synthetic-smoke',nodes=[dict(name='synthetic',proxy='http://127.0.0.1:'+str(proxy_port))])))
        program='from pathlib import Path;import sys;from farm import proxy_service as p;p.ROOT=Path(sys.argv[1]);sys.argv=["proxy","--setting",sys.argv[2],"--run"];p.main()'
        with process([sys.executable,'-c',program,str(root),str(config)],env) as child:
            assert ready(child,'http://127.0.0.1:'+str(proxy_port)+'/version')[0]==200
        with socket.socket() as sock:
            assert sock.connect_ex(('127.0.0.1',proxy_port))!=0,'proxy child survived parent termination'
    print(json.dumps(dict(rpc_http_requests=rpc_requests,web_http_checks=3,proxy_process_lifecycle='passed',business_requests=0)))

if __name__=='__main__':main()
