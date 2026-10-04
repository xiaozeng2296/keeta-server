"""Configure or run the isolated collection proxy core; no global Clash edits."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import signal
import subprocess
from urllib.parse import urlsplit

from farm.mysql_store import ROOT
from farm.proxy import normalize_proxy


def validate_setting(value):
    controller=urlsplit(value['controller'])
    if controller.scheme!='http' or controller.hostname!='127.0.0.1' or not controller.port:
        raise ValueError('controller_must_be_explicit_loopback')
    if not value.get('secret') or value['secret']=='CHANGE_ME':raise ValueError('configure_controller_secret')
    if not Path(value['core']).is_file():raise ValueError('proxy_core_not_found')
    nodes=value['nodes']
    if not nodes or len({n['name'] for n in nodes})!=len(nodes):raise ValueError('invalid_nodes')
    for node in nodes:
        parsed=urlsplit(normalize_proxy(node['proxy']))
        if parsed.hostname!='127.0.0.1' or parsed.scheme!='http' or not parsed.port:
            raise ValueError('node_listener_must_be_loopback')
    return value


def main():
    os.umask(0o077)
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--setting',type=Path,default=ROOT/'.private/clash-pool.json')
    action=p.add_mutually_exclusive_group();action.add_argument('--run',action='store_true')
    action.add_argument('--register',action='store_true',help='Persist the node mapping to the control DB')
    a=p.parse_args();value=validate_setting(json.loads(a.setting.read_text()))
    directory=ROOT/'.private/clash-node-pool';config=directory/'config.yaml'
    if not config.is_file():raise ValueError('private_proxy_config_missing')
    if a.register:
        from farm.mysql_store import Store
        Store().set_setting('clash_node_pool',value)
        print(json.dumps(dict(registered=True,nodes=len(value['nodes']))));return
    if not a.run:
        print(json.dumps(dict(configured=True,nodes=len(value['nodes']),network_checked=False)));return
    with (directory/'service.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        with (directory/'runtime.log').open('ab') as log:
            child=subprocess.Popen([value['core'],'-d',str(directory),'-f',str(config)],stdin=subprocess.DEVNULL,stdout=log,stderr=log)
        def stop(*_):
            if child.poll() is None:child.terminate()
        signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
        (directory/'pid').write_text(str(child.pid)+'\n')
        raise SystemExit(child.wait())

if __name__=='__main__':main()
