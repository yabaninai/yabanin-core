# SPDX-License-Identifier: Apache-2.0
"""Exercise real Go fuzzing and the pinned mutator on a tiny boundary function."""
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'go_policy'))
import critical

SOURCE = 'package auth\nfunc Allowed(n int) bool { return n > 0 }\n'
TESTS = '''package auth
import "testing"
func TestAllowed(t *testing.T) {
 for _, tc := range []struct{n int; want bool}{{-1,false},{0,false},{1,true}} {
  if Allowed(tc.n) != tc.want { t.Fatal(tc.n) }
 }
}
func FuzzAllowed(f *testing.F) {
 f.Add(0); f.Add(1); f.Add(-1)
 f.Fuzz(func(t *testing.T,n int) {
  if n == 0 && Allowed(n) { t.Fatal("zero must be denied") }
  if n > 0 && !Allowed(n) { t.Fatal("positive must be allowed") }
  if n < 0 && Allowed(n) { t.Fatal("negative must be denied") }
 })
}
'''
TARGET = {'file': 'pkg/auth/check.go', 'name': 'Allowed', 'start': 2, 'end': 2}


class CriticalEngineControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='critical-engine-oracle-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'source'
        self.pkg = self.root / 'pkg/auth'
        self.pkg.mkdir(parents=True)
        (self.root / 'go.mod').write_text('module example.test/core\n\ngo 1.27.4\n')
        (self.pkg / 'check.go').write_text(SOURCE)
        (self.pkg / 'check_test.go').write_text(TESTS)
        self.out = Path(self.temp.name) / 'evidence'
        self.out.mkdir()
        self.gremlins = os.environ.get('GREMLINS_BIN') or shutil.which('gremlins')
        if not self.gremlins:
            self.gremlins = str(Path.home() / 'go/bin/gremlins')

    def test_real_mutations_are_caught(self):
        report = critical.mutation(self.root, 'pkg/auth', [TARGET], '', self.out,
                                   time.monotonic() + 60, self.gremlins)
        self.assertEqual(report[0]['killed'], 2)

    def test_no_assertion_does_not_pass_mutation_gate(self):
        (self.pkg / 'check_test.go').write_text('package auth\nimport "testing"\nfunc TestWeak(t *testing.T) { Allowed(1) }\n')
        with self.assertRaisesRegex(ValueError, 'Unproven mutation'):
            critical.mutation(self.root, 'pkg/auth', [TARGET], '', self.out,
                              time.monotonic() + 60, self.gremlins)

    def test_real_fuzzer_executes_and_covers_changed_function(self):
        result = critical.fuzz(self.root, 'pkg/auth', [TARGET], '', self.out,
                               time.monotonic() + 90, max_fuzz_seconds=1)
        self.assertGreater(result['FuzzAllowed'], 0)

    def test_missing_fuzzer_is_blocked(self):
        (self.pkg / 'check_test.go').write_text('package auth\nimport "testing"\nfunc TestWeak(t *testing.T) { Allowed(1) }\n')
        with self.assertRaisesRegex(ValueError, 'No fuzz target'):
            critical.fuzz(self.root, 'pkg/auth', [TARGET], '', self.out, time.monotonic() + 30)


class ApplicabilityControls(unittest.TestCase):
    """Per-kind applicability: explicit N/A where infrastructure is absent."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='critical-applicability-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'source'
        self.pkg = self.root / 'pkg/auth'
        self.pkg.mkdir(parents=True)
        (self.root / 'go.mod').write_text('module example.test/core\n\ngo 1.27.4\n')
        (self.pkg / 'check.go').write_text(SOURCE)
        self.out = Path(self.temp.name) / 'evidence'
        self.out.mkdir()
        self.gremlins = os.environ.get('GREMLINS_BIN') or shutil.which('gremlins')
        if not self.gremlins:
            self.gremlins = str(Path.home() / 'go/bin/gremlins')

    def mode(self, kind, tests, qualified=False, deadline_seconds=90):
        (self.pkg / 'check_test.go').write_text(tests)
        target = self.out / kind
        target.mkdir(exist_ok=True)
        return critical.run_mode(kind, self.root, 'pkg/auth', [TARGET], '', target,
                                 time.monotonic() + deadline_seconds, self.gremlins, qualified)

    def test_fuzz_not_applicable_without_targets(self):
        result = self.mode('fuzz', 'package auth\nimport "testing"\nfunc TestWeak(t *testing.T) { Allowed(1) }\n')
        self.assertEqual(result['status'], 'not_applicable')
        self.assertIn('no fuzz targets', result['reason'])

    def test_mutation_not_applicable_when_unqualified(self):
        result = self.mode('mutation', TESTS, qualified=False)
        self.assertEqual(result['status'], 'not_applicable')
        self.assertIn('gremlins-qualified', result['reason'])

    def test_mutation_enforced_when_qualified(self):
        result = self.mode('mutation', TESTS, qualified=True)
        self.assertEqual(result[0]['killed'], 2)

    def test_unit_suite_enforced_where_fuzz_absent(self):
        result = self.mode('unit', 'package auth\nimport "testing"\nfunc TestWeak(t *testing.T) { Allowed(1) }\n')
        self.assertEqual(result['status'], 'passed')

    def test_failing_unit_suite_blocks_not_applicable_packages(self):
        broken = 'package auth\nimport "testing"\nfunc TestBroken(t *testing.T) { if Allowed(1) != false { t.Fatal("sabotage") } }\n'
        with self.assertRaisesRegex(ValueError, 'exited'):
            self.mode('unit', broken, deadline_seconds=30)

    def test_unit_skipped_when_fuzz_targets_exist(self):
        result = self.mode('unit', TESTS)
        self.assertEqual(result['status'], 'not_applicable')
        self.assertIn('fuzz-target package', result['reason'])

    def test_unit_not_applicable_without_any_tests(self):
        (self.pkg / 'check_test.go').unlink(missing_ok=True)
        target = self.out / 'notests'
        target.mkdir()
        result = critical.run_mode('unit', self.root, 'pkg/auth', [TARGET], '', target,
                                   time.monotonic() + 30, self.gremlins, False)
        self.assertEqual(result['status'], 'not_applicable')
        self.assertIn('no unit tests', result['reason'])


if __name__ == '__main__':
    unittest.main()
