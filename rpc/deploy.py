#!/usr/bin/env python3
"""通过现有 SSH 发布 Keeta RPC；只上传明确列出的程序、资源和合成测试。"""
import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess
import sys
import tarfile
import tempfile
import uuid

if __package__:
    from . import remote_update
else:
    import remote_update

ROOT = Path(__file__).resolve().parents[1]
# One source of truth for local packaging and remote manifest validation.
RUNTIME_FILES = tuple(sorted(remote_update.RUNTIME_FILES | remote_update.OPTIONAL_FILES))

# stdin is the upload itself. No user identities or authentication settings are
# copied; SSH performs authentication using the user's existing configuration.
BOOTSTRAP = r'''
import os,sys,tarfile
from pathlib import Path,PurePosixPath
root=Path(sys.argv[1]); release_id=sys.argv[2]
if not root.is_absolute() or not root.is_dir() or not (root/'keeta_rpc.py').is_file():
    raise SystemExit('Existing RPC directory not found')
if not release_id or any(c not in '0123456789TZ-abcdef' for c in release_id):
    raise SystemExit('Invalid release identifier')
stage=root/'.rpc-deploy'/'releases'/release_id
stage.mkdir(parents=True,mode=0o700,exist_ok=False)
seen=set();total=0
with tarfile.open(fileobj=sys.stdin.buffer,mode='r|gz') as archive:
    for member in archive:
        rel=PurePosixPath(member.name)
        if (not member.isfile() or rel.is_absolute() or '..' in rel.parts
                or member.name in seen or not rel.parts):
            raise SystemExit('Invalid release archive entry')
        seen.add(member.name);total+=member.size
        if total>32*1024*1024:raise SystemExit('Release archive too large')
        target=stage.joinpath(*rel.parts)
        target.parent.mkdir(parents=True,exist_ok=True)
        with archive.extractfile(member) as src,target.open('xb') as dst:
            while True:
                chunk=src.read(65536)
                if not chunk:break
                dst.write(chunk)
        target.chmod(0o644)
helper=stage/'rpc'/'remote_update.py'
args=[sys.executable,str(helper),'apply','--root',str(root),'--stage',str(stage),
      '--service',sys.argv[3],'--url',sys.argv[4],'--python',sys.executable]
if sys.argv[5]=='1':args.append('--sudo')
if sys.argv[6]=='1':args.append('--stage-only')
os.execv(sys.executable,args)
'''


def settings(path, args):
    value = json.loads(path.read_text())
    allowed = {'host', 'port', 'remote_dir', 'service', 'python', 'url', 'sudo'}
    if not isinstance(value, dict) or set(value) != allowed:
        raise ValueError('deploy config must contain host, port, remote_dir, service, python, url and sudo')
    for name in ('host', 'port', 'remote_dir', 'service', 'python', 'url'):
        override = getattr(args, name, None)
        if override is not None:
            value[name] = override
    if not isinstance(value['host'], str) or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.@:\[\]-]*', value['host']):
        raise ValueError('invalid SSH destination')
    if isinstance(value['port'], bool) or not isinstance(value['port'], int) or not 1 <= value['port'] <= 65535:
        raise ValueError('invalid SSH port')
    root = PurePosixPath(value['remote_dir'])
    if not root.is_absolute() or len(root.parts) < 3 or '..' in root.parts:
        raise ValueError('remote_dir must identify an existing absolute application directory')
    if not isinstance(value['sudo'], bool):
        raise ValueError('sudo must be a boolean')
    return value


def build_bundle(root, output, release_id):
    files = {}
    with tarfile.open(output, 'w:gz') as archive:
        for name in RUNTIME_FILES:
            source = root / name
            if source.is_symlink() or not source.is_file():
                raise ValueError('required release file missing or is a symlink: ' + name)
            data = source.read_bytes()
            files[name] = hashlib.sha256(data).hexdigest()
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), 0o644
            archive.addfile(info, io.BytesIO(data))
        manifest = {'release_id': release_id, 'files': files}
        data = (json.dumps(manifest, ensure_ascii=False, indent=2) + '\n').encode()
        info = tarfile.TarInfo('rpc/release.json')
        info.size, info.mode = len(data), 0o644
        archive.addfile(info, io.BytesIO(data))
    return manifest


def ssh_command(config, remote_args):
    return ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10',
            '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=3',
            '-p', str(config['port']), config['host'], shlex.join(remote_args)]


def run_remote(command, input_file=None):
    result = None
    with subprocess.Popen(command, stdin=input_file or subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          text=True, encoding='utf-8') as process:
        for line in process.stdout:
            print(line, end='', flush=True)
            try:
                parsed = json.loads(line)
                if isinstance(parsed, dict) and 'status' in parsed:
                    result = parsed
            except ValueError:
                pass
        code = process.wait()
    if code:
        raise RuntimeError('remote operation failed; exit status ' + str(code))
    if result is None:
        raise RuntimeError('remote operation returned no completion record')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=ROOT / '.private/rpc-deploy.json')
    parser.add_argument('--host', help='SSH destination, e.g. ubuntu@host')
    parser.add_argument('--port', type=int, help='SSH port')
    parser.add_argument('--remote-dir')
    parser.add_argument('--service')
    parser.add_argument('--python', help='absolute remote Python interpreter')
    parser.add_argument('--url', help='health/smoke URL as seen from the server')
    action = parser.add_mutually_exclusive_group()
    action.add_argument('--stage-only', action='store_true', help='upload and test; do not update/restart service')
    action.add_argument('--rollback', metavar='RELEASE_ID', help='restore code saved before this release')
    args = parser.parse_args(argv)
    config = settings(args.config, args)
    if args.rollback:
        if not re.fullmatch(r'[0-9TZabcdef-]+', args.rollback):
            raise ValueError('invalid release identifier')
        # Run the local helper in memory so rollback still works when restoring
        # a pre-tooling release removes the installed helper itself.
        source = (ROOT / 'rpc/remote_update.py').read_text()
        remote = [config['python'], '-c', source, 'rollback', args.rollback,
                  '--root', config['remote_dir'], '--service', config['service'],
                  '--url', config['url'], '--python', config['python']]
        if config['sudo']:
            remote.append('--sudo')
        result = run_remote(ssh_command(config, remote))
    else:
        release_id = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ-') + uuid.uuid4().hex[:8]
        with tempfile.TemporaryDirectory(prefix='keeta-rpc-release-') as temporary:
            bundle = Path(temporary) / 'release.tar.gz'
            manifest = build_bundle(ROOT, bundle, release_id)
            print(f'Release {release_id}: {len(manifest["files"])} files, {bundle.stat().st_size} bytes', flush=True)
            remote = [config['python'], '-c', BOOTSTRAP, config['remote_dir'], release_id,
                      config['service'], config['url'], '1' if config['sudo'] else '0',
                      '1' if args.stage_only else '0']
            with bundle.open('rb') as stream:
                result = run_remote(ssh_command(config, remote), stream)
    state = Path(__file__).parent / '.state'
    state.mkdir(mode=0o700, exist_ok=True)
    receipt = state / (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ-') + uuid.uuid4().hex[:6] + '.json')
    receipt.write_text(json.dumps({'target': config['host'], 'remote_dir': config['remote_dir'],
                                   'result': result}, ensure_ascii=False, indent=2) + '\n')
    receipt.chmod(0o600)
    print('Receipt:', receipt)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError) as exc:
        print('Deploy failed:', exc, file=sys.stderr)
        raise SystemExit(1)
