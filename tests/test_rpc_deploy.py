"""Release packaging and upload extraction checks; no SSH or service changes."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from rpc import deploy, remote_update


class DeployTests(unittest.TestCase):
    def test_current_bundle_is_complete_and_accepted_remotely(self):
        required = {
            'keeta_rpc.py', 'farm/fullsign.py', 'mtgsig/provider_config.py',
            'mtgsig/fingerprint_refresh.py', 'mtgsig/a9_cli.py',
            'tests/test_a9_rpc.py', 'tests/test_signing_profiles.py',
            'tests/test_provider_config.py', 'config/rpc-deploy.example.json',
        }
        self.assertTrue(required <= set(deploy.RUNTIME_FILES))
        self.assertEqual(len(deploy.RUNTIME_FILES), len(set(deploy.RUNTIME_FILES)))
        self.assertEqual(set(deploy.RUNTIME_FILES),
                         remote_update.RUNTIME_FILES | remote_update.OPTIONAL_FILES)
        self.assertFalse(any(name == 'mail.txt' or name.endswith('.chlsj')
                             or name.startswith('dump/registration_session/')
                             for name in deploy.RUNTIME_FILES))
        self.assertFalse(any(name.startswith(('dump/', 'mtgsig_app（国内）/'))
                             for name in deploy.RUNTIME_FILES))
        self.assertTrue({'mtgsig/data/T.bin', 'mtgsig/data/tableA.bin',
                         'mtgsig/data/tableB_const.bin', 'mtgsig/ref_domestic/M.bin'}
                        <= set(deploy.RUNTIME_FILES))
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bundle, stage = root / 'release.tar.gz', root / 'stage'
            stage.mkdir()
            manifest = deploy.build_bundle(deploy.ROOT, bundle, 'manifest-test')
            with tarfile.open(bundle) as archive:
                for entry in archive:
                    if entry.name != 'rpc/release.json':
                        remote_update.allowed_path(entry.name)
                    target = stage / entry.name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with archive.extractfile(entry) as stream:
                        target.write_bytes(stream.read())
            self.assertEqual(remote_update.load_manifest(stage), manifest)
            # Isolate sys.path from the checkout: stale paths and undeclared
            # imports must fail here instead of being supplied by local files.
            program = (
                'import sys; sys.path.insert(0, sys.argv[1]); '
                'import keeta_rpc, keeta_offline_flow, keeta_login; '
                'from farm.fullsign import FullSigner; '
                'from farm import request_freshness; '
                'from mtgsig import a9_cli, http_transport, mail_transport; '
                'from mtgsig import fingerprint_refresh, provider_config'
            )
            result = subprocess.run([sys.executable, '-I', '-c', program, str(stage)],
                                    cwd=root, capture_output=True, text=True,
                                    env=remote_update.clean_environment(), timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_bundle_has_exact_manifest_and_no_identity_data(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'code.py').write_text('VALUE = 123\n')
            (root / 'workspace').mkdir()
            (root / 'workspace/identity.json').write_text('must not deploy')
            with patch.object(deploy, 'RUNTIME_FILES', ('code.py',)):
                manifest = deploy.build_bundle(root, root / 'bundle.tar.gz', '20260928T010203Z-abc12345')
            with tarfile.open(root / 'bundle.tar.gz') as archive:
                self.assertEqual(set(archive.getnames()), {'code.py', 'rpc/release.json'})
                data = archive.extractfile('code.py').read()
                self.assertEqual(hashlib.sha256(data).hexdigest(), manifest['files']['code.py'])
                self.assertEqual(json.load(archive.extractfile('rpc/release.json')), manifest)

    def test_missing_or_symlink_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with patch.object(deploy, 'RUNTIME_FILES', ('missing.py',)):
                with self.assertRaises(ValueError):
                    deploy.build_bundle(root, root / 'missing.tar.gz', 'test')
            (root / 'original.py').write_text('pass\n')
            (root / 'link.py').symlink_to(root / 'original.py')
            with patch.object(deploy, 'RUNTIME_FILES', ('link.py',)):
                with self.assertRaises(ValueError):
                    deploy.build_bundle(root, root / 'link.tar.gz', 'test')

    def test_ssh_remote_arguments_are_shell_quoted(self):
        config = {'host': 'ubuntu@example.test', 'port': 22}
        args = ['python3', '-c', 'print("literal $HOME `date`")', '/path with spaces']
        command = deploy.ssh_command(config, args)
        import shlex
        self.assertEqual(shlex.split(command[-1]), args)
        self.assertNotIn('-t', command)

    def test_config_rejects_dangerous_destinations_and_root(self):
        config = json.loads((deploy.ROOT / 'config/rpc-deploy.example.json').read_text())
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'config.json'
            for field, value in [('host', '-oProxyCommand=x'), ('host', 'host\ncommand'),
                                 ('port', True), ('remote_dir', '/'), ('remote_dir', '/home/../etc'),
                                 ('sudo', 'yes')]:
                path.write_text(json.dumps(dict(config, **{field: value})))
                with self.subTest(field=field), self.assertRaises(ValueError):
                    deploy.settings(path, argparse.Namespace())

    def run_bootstrap(self, root, members):
        body = io.BytesIO()
        with tarfile.open(fileobj=body, mode='w:gz') as archive:
            for name, data in members:
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return subprocess.run([sys.executable, '-c', deploy.BOOTSTRAP,
                               str(root), '20260928T010203Z-abc12345', 'keeta-rpc.service',
                               'http://127.0.0.1:9095', '0', '1'],
                              input=body.getvalue(), capture_output=True, timeout=10)

    def test_bootstrap_extracts_and_executes_only_staged_helper(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'app'
            root.mkdir()
            (root / 'keeta_rpc.py').write_text('existing code')
            script = b'import sys; print("staged helper", "--stage-only" in sys.argv)\n'
            result = self.run_bootstrap(root, [('rpc/remote_update.py', script)])
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(b'staged helper True', result.stdout)
            self.assertEqual((root / 'keeta_rpc.py').read_text(), 'existing code')

    def test_bootstrap_rejects_archive_traversal(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'app'
            root.mkdir()
            (root / 'keeta_rpc.py').write_text('existing code')
            result = self.run_bootstrap(root, [('../../escaped', b'bad')])
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / '.rpc-deploy/escaped').exists())
            self.assertEqual((root / 'keeta_rpc.py').read_text(), 'existing code')


if __name__ == '__main__':
    unittest.main()
