"""Deployment transaction tests use temporary files and mocked service control."""
import argparse
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "keeta_remote_update", Path(__file__).resolve().parents[1] / "rpc/remote_update.py")
deploy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(deploy)


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="keeta-deploy-test-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root, self.stage = self.base / "live", self.base / "stage"
        self.root.mkdir()
        self.stage.mkdir()
        files = deploy.RUNTIME_FILES | {"rpc/smoke.py", "tests/test_synthetic.py"}
        for name in files:
            path = self.stage / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"synthetic release\n")
        self.manifest = {"release_id": "test-release-001", "files": {
            name: deploy.digest(self.stage / name) for name in sorted(files)}}
        self.write_manifest()
        self.args = argparse.Namespace(root=self.root, stage=self.stage,
                                       service="synthetic.service", python=sys.executable,
                                       url="http://127.0.0.1:9095", sudo=False,
                                       stage_only=False, release_id=self.manifest["release_id"])
        identity = self.root / "workspace/synthetic/device_id.json"
        identity.parent.mkdir(parents=True)
        identity.write_bytes(b'{"counter":1234,"synthetic":true}')
        self.identity = identity
        self.identity_original = identity.read_bytes()

    def write_manifest(self):
        (self.stage / "rpc/release.json").write_text(json.dumps(self.manifest))

    def write_old(self):
        target = self.root / "keeta_rpc.py"
        target.write_bytes(b"original source\n")
        target.chmod(0o640)
        return target

    def test_manifest_rejects_path_escape_identity_and_symlink(self):
        for name in ("../escape.py", "workspace/identity.json", "/etc/passwd", "mail.txt",
                     "tests/../keeta_rpc.py", "rpc//smoke.py",
                     "dump/registration_session/session_02/profile.json",
                     "dump/envelope_recovery/current_registration_context_02.json",
                     "dump/oneid_recovery/live_registration_01.json", "新机之后尝试登录.chlsj"):
            with self.subTest(name=name), self.assertRaises(deploy.DeploymentError):
                deploy.allowed_path(name)
        source = self.stage / "keeta_rpc.py"
        source.unlink()
        source.symlink_to(self.identity)
        with self.assertRaises(deploy.DeploymentError):
            deploy.load_manifest(self.stage)

    def test_manifest_rejects_hash_and_unlisted_files(self):
        self.assertEqual(deploy.load_manifest(self.stage), self.manifest)
        (self.stage / "keeta_rpc.py").write_bytes(b"changed")
        with self.assertRaises(deploy.DeploymentError):
            deploy.load_manifest(self.stage)
        (self.stage / "keeta_rpc.py").write_bytes(b"synthetic release\n")
        (self.stage / "extra.py").write_text("unlisted")
        with self.assertRaises(deploy.DeploymentError):
            deploy.load_manifest(self.stage)

    def test_backup_restores_bytes_mode_and_absent_files_without_touching_identity(self):
        target = self.write_old()
        with deploy.deployment_lock(self.root) as state:
            backup, metadata = deploy.make_backup(self.root, state, self.manifest)
            deploy.install_files(self.root, self.stage, self.manifest)
            self.assertEqual(target.read_bytes(), b"synthetic release\n")
            self.assertTrue((self.root / "rpc/smoke.py").exists())
            deploy.restore_files(self.root, backup, metadata)
        self.assertEqual(target.read_bytes(), b"original source\n")
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o640)
        self.assertFalse((self.root / "rpc/smoke.py").exists())
        self.assertEqual(self.identity.read_bytes(), self.identity_original)

    def test_corrupt_backup_rejected_before_any_restore(self):
        target = self.write_old()
        with deploy.deployment_lock(self.root) as state:
            backup, metadata = deploy.make_backup(self.root, state, self.manifest)
            deploy.install_files(self.root, self.stage, self.manifest)
            (backup / "files/keeta_rpc.py").write_bytes(b"corrupt")
            with self.assertRaises(deploy.DeploymentError):
                deploy.restore_files(self.root, backup, metadata)
            self.assertEqual(target.read_bytes(), b"synthetic release\n")

    def test_smoke_failure_rolls_back_and_restarts_previous_service(self):
        target = self.write_old()
        with patch.object(deploy, "run_stage_tests"), patch.object(deploy, "systemctl") as control, \
                patch.object(deploy, "health_check"), \
                patch.object(deploy, "run_smoke", side_effect=deploy.DeploymentError("synthetic failure")), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            with self.assertRaisesRegex(deploy.DeploymentError, "previous code and service were restored"):
                deploy.apply(self.args)
        self.assertEqual(control.call_count, 2)
        self.assertEqual(target.read_bytes(), b"original source\n")
        self.assertFalse((self.root / ".rpc-deploy/current.json").exists())
        self.assertEqual(self.identity.read_bytes(), self.identity_original)
        self.assertIn('"status": "rolled_back"', output.getvalue())

    def test_success_and_manual_rollback_keep_workspace_and_handle_missing_smoke(self):
        target = self.write_old()
        with patch.object(deploy, "run_stage_tests"), patch.object(deploy, "systemctl"), \
                patch.object(deploy, "health_check") as health, \
                patch.object(deploy, "run_smoke"), contextlib.redirect_stdout(io.StringIO()):
            applied = deploy.apply(self.args)
            self.assertEqual(applied["status"], "applied")
            current = deploy.current_metadata(self.root / ".rpc-deploy")
            self.assertEqual(current, self.manifest)
            restored = deploy.rollback(self.args)
            self.assertEqual(restored["status"], "rolled_back")
            self.assertEqual(health.call_count, 2)
        self.assertEqual(target.read_bytes(), b"original source\n")
        self.assertFalse((self.root / "rpc/smoke.py").exists())
        self.assertEqual(self.identity.read_bytes(), self.identity_original)

    def test_stage_only_has_no_live_writes_or_service_calls(self):
        self.args.stage_only = True
        before = sorted(str(p.relative_to(self.root)) for p in self.root.rglob("*"))
        with patch.object(deploy, "run_stage_tests") as tests, \
                patch.object(deploy, "systemctl") as control:
            result = deploy.apply(self.args)
        self.assertEqual(result["status"], "validated")
        tests.assert_called_once()
        control.assert_not_called()
        self.assertEqual(before, sorted(str(p.relative_to(self.root)) for p in self.root.rglob("*")))

    def test_partial_install_interruption_rolls_back(self):
        target = self.write_old()
        def interrupted_install(*args):
            target.write_bytes(b"partially installed")
            raise InterruptedError("synthetic SIGTERM")
        with patch.object(deploy, "run_stage_tests"), \
                patch.object(deploy, "install_files", side_effect=interrupted_install), \
                patch.object(deploy, "systemctl"), patch.object(deploy, "health_check"), \
                contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(deploy.DeploymentError):
                deploy.apply(self.args)
        self.assertEqual(target.read_bytes(), b"original source\n")
        self.assertEqual(self.identity.read_bytes(), self.identity_original)

    def test_lock_rejects_concurrent_deployment(self):
        with deploy.deployment_lock(self.root):
            with self.assertRaises(deploy.DeploymentError):
                with deploy.deployment_lock(self.root):
                    self.fail("second lock should not succeed")

    def test_root_symlink_destination_is_not_overwritten(self):
        (self.root / "farm").symlink_to(self.identity.parent, target_is_directory=True)
        with deploy.deployment_lock(self.root) as state:
            with self.assertRaises(deploy.DeploymentError):
                deploy.make_backup(self.root, state, self.manifest)
        self.assertEqual(self.identity.read_bytes(), self.identity_original)

    def test_sudo_token_extraction_never_logs_captured_environment(self):
        result = argparse.Namespace(returncode=0, stdout=b"synthetic-token")
        with patch.object(deploy, "systemctl", return_value=b"123\n"), \
                patch.object(Path, "read_bytes", side_effect=PermissionError), \
                patch.object(deploy.subprocess, "run", return_value=result) as process:
            self.args.sudo = True
            self.assertEqual(deploy.service_token(self.args), "synthetic-token")
        command = process.call_args.args[0]
        self.assertEqual(command[:2], ["sudo", "-n"])
        self.assertNotIn("synthetic-token", " ".join(command))

    def test_health_waits_for_main_pid_and_environment(self):
        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self, limit):
                return b'{"service":"keeta-offline-crypto-rpc"}'

        with patch.object(deploy, "service_token", side_effect=[
                deploy.DeploymentError("not started"), FileNotFoundError(), "synthetic-token"]) as token, \
                patch.object(deploy.urllib.request, "build_opener") as opener, \
                patch.object(deploy.time, "sleep") as sleep:
            opener.return_value.open.return_value = Response()
            deploy.health_check(self.args)
        self.assertEqual(token.call_count, 3)
        self.assertEqual(sleep.call_count, 2)

    def test_prepared_backup_cannot_overwrite_unrelated_active_release(self):
        self.write_old()
        with deploy.deployment_lock(self.root) as state:
            deploy.make_backup(self.root, state, self.manifest)
            deploy.atomic_json(state / "current.json", {
                "release_id": "newer-unrelated-release", "files": self.manifest["files"]})
        with patch.object(deploy, "systemctl") as control:
            with self.assertRaisesRegex(deploy.DeploymentError, "out-of-order"):
                deploy.rollback(self.args)
        control.assert_not_called()
        self.assertEqual((self.root / "keeta_rpc.py").read_bytes(), b"original source\n")


if __name__ == "__main__":
    unittest.main()
