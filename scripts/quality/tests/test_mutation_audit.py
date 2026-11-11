# SPDX-License-Identifier: Apache-2.0
"""A compiler/CLI failure must never stand in for a failing product test."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'go_policy'))
import mutation_audit
import source


class MutationAuditControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='mutation-audit-control-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.out = self.root / 'evidence'
        self.out.mkdir()
        (self.root / 'go.mod').write_text('module example.test/audit\n\ngo 1.27.4\n')
        (self.root / 'audit_test.go').write_text('package audit\nimport "testing"\nfunc TestAlways(t *testing.T) {}\n')

    def execute(self, argv):
        with mutation_audit.environment(self.out) as env:
            code = source.execute(['go', 'test', *argv], self.root, self.out / 'log', env_updates=env)
        self.assertNotEqual(code, 0)
        return next((self.out / 'go-audit').glob('*.json'))

    def test_invalid_flag_is_not_a_kill(self):
        path = self.execute(['-does-not-exist'])
        with self.assertRaises(ValueError):
            mutation_audit.invocation(path)

    def test_build_failure_is_not_a_kill(self):
        (self.root / 'broken.go').write_text('package audit\nvar x = undefinedSymbol\n')
        path = self.execute(['./...'])
        with self.assertRaises(ValueError):
            mutation_audit.invocation(path)

    def test_real_assertion_failure_is_a_kill(self):
        (self.root / 'audit_test.go').write_text('package audit\nimport "testing"\nfunc TestAlways(t *testing.T) { t.Fatal("independent assertion") }\n')
        self.assertEqual(mutation_audit.invocation(self.execute(['./...'])), 1)

    def test_timeout_kills_child_group_and_preserves_incomplete_receipt(self):
        (self.root / 'audit_test.go').write_text('package audit\nimport ("testing"; "time")\nfunc TestWait(t *testing.T) { time.Sleep(time.Minute) }\n')
        with mutation_audit.environment(self.out) as env:
            with self.assertRaises(subprocess.TimeoutExpired):
                source.execute(['go', 'test', './...'], self.root, self.out / 'log', seconds=2, env_updates=env)
        path = next((self.out / 'go-audit').glob('*.json'))
        self.assertEqual(json.loads(path.read_text())['status'], 'running')
        with self.assertRaisesRegex(ValueError, 'Unfinished'):
            mutation_audit.invocation(path)


if __name__ == '__main__':
    unittest.main()
