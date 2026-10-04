"""Offline research CLI regression: strict failures and redacted reports."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from farm import fullsign as fs
from mtgsig import a9_codec, mtg_crypto
from tools import a9_validate_captures as a9_check, verify_a2_pass2 as a2_check

ROOT = Path(__file__).resolve().parents[1]
A1 = '00112233-4455-6677-8899-aabbccddeeff'


class ResearchToolsTests(unittest.TestCase):
    def run_tool(self, name, *args):
        return subprocess.run([sys.executable, str(ROOT/'tools'/name), *map(str, args)],
                              cwd=ROOT, capture_output=True, text=True, timeout=30)

    def test_a9_all_profiles_and_modes_replay_without_identity_output(self):
        plain = b'{"synthetic-device-marker": 7}'
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'capture.json'
            for profile in ('default', 'legacy'):
                for mode in a9_codec.MODES:
                    with self.subTest(profile=profile, mode=mode):
                        sig = {'a1': A1, 'a9': a9_codec.encode(
                            plain, A1, mode=mode, **a9_check.profile_options(profile))}
                        flows = [{'request': {'header': {'headers': [
                            {'name': 'Mtgsig', 'value': json.dumps(sig)}]}}}]*2
                        path.write_text(json.dumps(flows))
                        result = a9_check.verify(path, profile)
                        self.assertEqual(result['result'], 'PASS')
                        self.assertEqual(len(result['cases']), 2)
                        text = json.dumps(result)
                        for private in (A1, sig['a9'], 'synthetic-device-marker'):
                            self.assertNotIn(private, text)

    def test_a9_cli_fails_wrong_profile_and_preserves_existing_report(self):
        with tempfile.TemporaryDirectory() as temp:
            path, out = Path(temp)/'sample.json', Path(temp)/'report.json'
            path.write_text(json.dumps({'mtgsig': json.dumps({
                'a1': A1, 'a9': a9_codec.encode(b'synthetic-secret-plain', A1)})}))
            result = self.run_tool('a9_validate_captures.py', path, '--profile', 'legacy', '--out', out)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(json.loads(out.read_text())['result'], 'FAIL')
            before = out.read_bytes()
            again = self.run_tool('a9_validate_captures.py', path, '--profile', 'default', '--out', out)
            self.assertNotEqual(again.returncode, 0)
            self.assertEqual(out.read_bytes(), before)
            self.assertNotIn('synthetic-secret-plain', out.read_text())

    def test_empty_captures_are_not_success(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'empty.json'; path.write_text('[]')
            for tool, args in [('verify_a2_pass2.py', []),
                               ('a9_validate_captures.py', ['--profile', 'default'])]:
                result = self.run_tool(tool, path, *args)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertNotIn('Traceback', result.stderr)
                self.assertNotIn('PASS', result.stdout)

    def make_flow(self, body, profile):
        seq = 0x12345678
        collect = {'b2': seq, 'b17': 9, 'b18': 3}
        mt = dict(a0='2.5', a1=A1, a3=20, a4=1700000000, a6=0,
                  a7='SYNTHETIC-XID', a8='SYNTHETIC-DFP', a10='3,75', x0=2)
        mt['a5'] = mtg_crypto.a5_encrypt(json.dumps(collect).encode(), A1, mt['a3'],
                                       mt['a4'], fs.k2buf(A1, profile))
        mt['a2'] = fs.compute_a2('POST', 'https://example.test/path?b=2&a=1', body,
                               json.dumps(mt, separators=(',', ':')), A1, 75,
                               signing_profile=profile, sign_sequence=seq)
        flow = dict(scheme='https', host='connection.test', path='/path?b=2&a=1',
                    query='b=2&a=1', method='POST', request={
                        'body': {'text': body}, 'header': {'headers': [
                            {'name': ':authority', 'value': 'example.test'},
                            {'name': 'mtgsig', 'value': json.dumps(mt)}]}})
        return flow, mt

    def test_a2_complete_check_uses_b2_independent_of_a10_and_utf8_limit(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'capture.json'
            for profile in ('default', 'legacy'):
                flow, mt = self.make_flow('x'*16199 + '中文😀', profile)
                path.write_text(json.dumps([flow]))
                result = a2_check.verify(path)
                self.assertEqual(result['counts']['full_a2_match'], 1)
                self.assertEqual(result['sequence_min'], 0x12345678)
                # Corrupt only the last byte; a prefix-only verifier would miss this.
                mt['a2'] = mt['a2'][:-2] + ('00' if mt['a2'][-2:] != '00' else '01')
                flow['request']['header']['headers'][-1]['value'] = json.dumps(mt)
                path.write_text(json.dumps([flow]))
                result = self.run_tool('verify_a2_pass2.py', path)
                self.assertEqual(result.returncode, 1, result.stderr)
                row = json.loads(result.stdout)['sources'][0]
                self.assertEqual(row['counts']['prefix_match'], 1)
                self.assertEqual(row['counts']['full_a2_match'], 0)

    def test_a2_rejects_ambiguous_body_instead_of_signing_empty_text(self):
        flow, _ = self.make_flow('{}', 'default')
        flow['request']['body'] = {'encoding': 'base64', 'encoded': 'e30='}
        with self.assertRaisesRegex(ValueError, 'body text required'):
            list(a2_check.samples([flow]))

    def test_a2_recovered_tail_matches_independent_accepted_vectors(self):
        rows = json.loads((ROOT/'tests/fixtures/a2_pass2_accepted_boundaries.json').read_text())['vectors']
        for row in rows:
            self.assertEqual(a2_check.pass2(bytes.fromhex(row['prefix_hex']),
                                           bytes.fromhex(row['mask_hex']),
                                           row['sign_sequence']).hex(), row['tail_hex'])


if __name__ == '__main__':
    unittest.main()
