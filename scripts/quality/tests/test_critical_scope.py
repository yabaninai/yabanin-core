# SPDX-License-Identifier: Apache-2.0
"""Critical scope follows production declarations and build modes."""
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'go_policy'))
import critical
import critical_scope


class CriticalScopeControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='critical-scope-control-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pkg = self.root / 'pkg/auth'
        self.pkg.mkdir(parents=True)
        (self.root / 'go.mod').write_text('module example.test/critical\n\ngo 1.27.4\n')
        self.file = self.pkg / 'auth.go'
        self.file.write_text('package auth\nfunc Allowed(n int) bool { return n > 0 }\nfunc Neighbor() bool { return true }\n')
        for argv in (['init', '-q'], ['add', '.'], ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'base']):
            subprocess.run(['git', *argv], cwd=self.root, check=True, capture_output=True)
        self.base = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=self.root, text=True).strip()

    def selected(self):
        return critical_scope.targets(self.root, self.base, {'critical_paths': ['pkg/auth/**']})

    def test_changed_body_selects_only_affected_function(self):
        self.file.write_text(self.file.read_text().replace('n > 0', 'n >= 0'))
        self.assertEqual([fn['name'] for fn in self.selected()['pkg/auth']], ['Allowed'])

    def test_formatting_does_not_select_untouched_debt(self):
        self.file.write_text(self.file.read_text().replace('return n > 0', '\n// durable comment\nreturn n > 0'))
        self.assertFalse(self.selected())

    def test_test_change_selects_production_consumers(self):
        (self.pkg / 'auth_test.go').write_text('package auth\nimport "testing"\nfunc TestAllowed(t *testing.T) { if !Allowed(1) { t.Fatal("denied") } }\n')
        self.assertEqual({fn['name'] for fn in self.selected()['pkg/auth']}, {'Allowed', 'Neighbor'})

    def test_comment_only_test_edit_does_not_reopen_legacy_package(self):
        (self.pkg / 'auth_test.go').write_text('package auth\n// explanation only\n')
        self.assertFalse(self.selected())

    def test_build_mode_selects_only_compiled_functions(self):
        (self.pkg / 'spi.go').write_text('//go:build spi\n\npackage auth\nfunc SPI() bool { return true }\n')
        functions = self.selected()['pkg/auth']
        out = self.root / 'logs'
        out.mkdir()
        self.assertFalse(critical.active_functions(self.root, 'pkg/auth', functions, '', out, time.monotonic() + 20))
        self.assertEqual([fn['name'] for fn in critical.active_functions(self.root, 'pkg/auth', functions, 'spi', out, time.monotonic() + 20)], ['SPI'])


if __name__ == '__main__':
    unittest.main()
