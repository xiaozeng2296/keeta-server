"""Fresh local identity bootstrap, using synthetic identities only."""

from copy import deepcopy
import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

from mtgsig.bootstrap_identity import bootstrap_identity
from mtgsig.local_identity import decode_local_dfp, decode_local_xid


ROOT = Path(__file__).resolve().parents[1]
UUID_VALUE = "00112233-4455-4677-8899-aabbccddeeff"
STAMP_MS = 1700000000123


class BootstrapIdentityTests(unittest.TestCase):
    def test_explicit_inputs_reproduce_a_matching_initial_pair(self):
        value = bootstrap_identity(UUID_VALUE, STAMP_MS)
        self.assertEqual(value, bootstrap_identity(UUID_VALUE, STAMP_MS))
        self.assertEqual(value["a7"], value["a7_local_xid"])
        self.assertEqual(value["a8"], value["a8_local_dfp"])
        dfp = decode_local_dfp(value["a8"])
        xid = decode_local_xid(value["a7"])
        self.assertEqual((dfp.uuid, dfp.timestamp_ms), (UUID_VALUE, STAMP_MS))
        self.assertEqual(xid.source_dfp_id, value["a8"])
        self.assertEqual(xid.timestamp_seconds, STAMP_MS // 1000)

    def test_partial_profile_does_not_invent_sdk_or_device_fields(self):
        value = bootstrap_identity(UUID_VALUE, STAMP_MS)
        for field in ("a1", "base_collect", "base_siua", "a9"):
            self.assertNotIn(field, value)
        self.assertEqual(value["local_identity_bootstrap"]["scope"], "local_a7_a8_only")
        self.assertIn("a1", value["local_identity_bootstrap"]["missing_signer_fields"])

    def test_server_values_remain_active_and_base_is_not_mutated(self):
        for server_fields in (
            {"a7_server_xid": "server-xid", "a8_server_dfp": "server-dfp"},
            {"xid": "server-xid", "dfp": "server-dfp"},
        ):
            base = dict(server_fields, base_collect={"b1": "{}"})
            snapshot = deepcopy(base)
            value = bootstrap_identity(UUID_VALUE, STAMP_MS, base=base)
            self.assertEqual(base, snapshot)
            self.assertEqual((value["a7"], value["a8"]), ("server-xid", "server-dfp"))
            self.assertNotEqual(value["a7_local_xid"], value["a7"])
            value["base_collect"]["b1"] = "changed"
            self.assertEqual(base, snapshot)

    def test_existing_matching_identity_is_idempotent(self):
        value = bootstrap_identity(UUID_VALUE, STAMP_MS)
        self.assertEqual(value, bootstrap_identity(UUID_VALUE, STAMP_MS, base=value))

    def test_server_response_supersedes_matching_local_active_values(self):
        base = bootstrap_identity(UUID_VALUE, STAMP_MS)
        base.update(a7_server_xid="server-xid", a8_server_dfp="server-dfp")
        value = bootstrap_identity(UUID_VALUE, STAMP_MS, base=base)
        self.assertEqual((value["a7"], value["a8"]), ("server-xid", "server-dfp"))
        self.assertEqual(value["a7_local_xid"], base["a7"])
        self.assertEqual(value["a8_local_dfp"], base["a8"])

    def test_conflicting_local_and_unclassified_identity_are_rejected(self):
        for field in ("a7_local_xid", "a8_local_dfp", "a7", "a8"):
            base = {field: "other-device-value"}
            with self.subTest(field=field), self.assertRaises(ValueError):
                bootstrap_identity(UUID_VALUE, STAMP_MS, base=base)
            self.assertEqual(base, {field: "other-device-value"})

    def test_existing_full_profile_is_consumable_by_signer(self):
        from farm.fullsign import FullSigner
        base = {"a0": "2.5", "a1": "00112233-4455-6677-8899-aabbccddeeff",
                "a3": 25, "a6": 0, "x0": 2,
                "base_collect": {"b1": "{}", "b2": 1, "b3": 1},
                "base_siua": '{"0":12,"1":["synthetic"],"2":[],"3":{}}',
                "a9_profile": "default", "a9_mode": "twofish-mod"}
        value = bootstrap_identity(UUID_VALUE, STAMP_MS, base=base)
        self.assertEqual(value["local_identity_bootstrap"]["missing_signer_fields"], [])
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "identity.json"
            path.write_text(json.dumps(value))
            signature = json.loads(FullSigner(path).sign("GET", "https://example.test/test", ""))
            self.assertEqual(signature["a7"], value["a7_local_xid"])
            self.assertEqual(signature["a8"], value["a8_local_dfp"])

    def test_cli_stdout_and_file_output_refuse_overwrite(self):
        command = [sys.executable, "-m", "mtgsig.bootstrap_identity", "--uuid", UUID_VALUE,
                   "--timestamp-ms", str(STAMP_MS)]
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = bootstrap_identity(UUID_VALUE, STAMP_MS)
        self.assertEqual(json.loads(result.stdout), expected)
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "identity.json"
            cmd = command + ["--output", str(output)]
            saved = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=10)
            self.assertEqual(saved.returncode, 0, saved.stderr)
            self.assertEqual(saved.stdout, "")
            self.assertEqual(json.loads(output.read_text()), expected)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            existing = output.read_bytes()
            again = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(again.returncode, 0)
            self.assertIn("already exists", again.stderr)
            self.assertEqual(output.read_bytes(), existing)

    def test_invalid_base_rejected(self):
        for value in ([], "profile", 12):
            with self.subTest(base=value), self.assertRaises(TypeError):
                bootstrap_identity(UUID_VALUE, STAMP_MS, base=value)


if __name__ == "__main__":
    unittest.main()
