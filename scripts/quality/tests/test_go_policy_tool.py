# SPDX-License-Identifier: Apache-2.0
"""Run real pinned analyzers against independently specified bad programs."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parents[1] / 'go_policy'


class RealPolicyControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='go-policy-oracle-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'source'
        self.root.mkdir()
        self.output = Path(self.temp.name) / 'reports'
        self.write('go.mod', 'module github.com/reireirei/yabanin\n\ngo 1.27.4\n')
        self.write('pkg/agentloop/state.go', 'package agentloop\nimport "io"\nfunc Existing(err error) bool { return err == io.EOF }\n')
        self.git('init', '-q')
        self.git('config', 'user.name', 'Fixture')
        self.git('config', 'user.email', 'fixture@example.invalid')
        self.git('add', '.')
        self.git('commit', '-qm', 'base')
        self.base = self.git('rev-parse', 'HEAD')
        self.linter = os.environ.get('GOLANGCI_BIN') or shutil.which('golangci-lint')
        if not self.linter:
            self.linter = str(Path.home() / 'go/bin/golangci-lint')

    def write(self, path, text):
        file = self.root / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(text)

    def git(self, *args):
        return subprocess.check_output(['git', *args], cwd=self.root, text=True).strip()

    def run_gate(self, label, expected):
        output = self.output / label
        proc = subprocess.run([sys.executable, str(HERE / 'policy.py'), '--root', str(self.root),
                               '--base', self.base, '--linter', self.linter, '--output', str(output)],
                              text=True, capture_output=True, timeout=120)
        self.assertEqual(proc.returncode, expected, proc.stdout + proc.stderr)
        return json.loads((output / 'report.json').read_text())

    def test_legacy_is_separate_but_changed_body_is_strict(self):
        self.write('pkg/agentloop/new.go', 'package agentloop\nfunc Added() int { return 1 }\n')
        report = self.run_gate('untouched', 0)
        self.assertEqual(len(report['legacy_debt']), 1)
        self.write('pkg/agentloop/state.go', 'package agentloop\nimport "io"\nfunc Existing(err error) bool { if err == nil { return false }; return err == io.EOF }\n')
        report = self.run_gate('changed', 1)
        self.assertEqual(report['blocking'][0]['rule'], 'errorlint')

    def test_aliased_process_exit_cannot_evade_rule(self):
        self.write('pkg/agentloop/new.go', 'package agentloop\nimport operating "os"\nfunc Added() { operating.Exit(1) }\n')
        report = self.run_gate('alias', 1)
        self.assertTrue(any(r['rule'] == 'forbidigo' for r in report['blocking']))

    def test_sql_driver_cannot_enter_pure_domain(self):
        self.write('pkg/agentloop/storage.go', 'package agentloop\nimport "database/sql"\nvar DB *sql.DB\n')
        report = self.run_gate('sql-boundary', 1)
        self.assertTrue(any(r['rule'] == 'depguard' for r in report['blocking']))

    def test_new_enum_value_requires_old_switch_update(self):
        self.write('pkg/agentloop/enum.go', 'package agentloop\ntype OperationState int\nconst ( A OperationState = iota; B )\nfunc State(s OperationState) bool { switch s { case A: return true; case B: return false; default: return false } }\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'complete switch')
        self.base = self.git('rev-parse', 'HEAD')
        file = self.root / 'pkg/agentloop/enum.go'
        file.write_text(file.read_text().replace('; B )', '; B; C )'))
        report = self.run_gate('enum-default', 1)
        self.assertTrue(any(r['rule'] == 'exhaustive' for r in report['blocking']))

    def test_core_cannot_import_enterprise(self):
        dependency = Path(self.temp.name) / 'enterprise'
        dependency.mkdir()
        module = 'github.com/yabaninai/yabanin-enterprise'
        (dependency / 'go.mod').write_text('module ' + module + '\n\ngo 1.27.4\n')
        (dependency / 'ee.go').write_text('package ee\nconst Value = 1\n')
        with (self.root / 'go.mod').open('a') as stream:
            stream.write(f'\nrequire {module} v0.0.0\nreplace {module} => {dependency}\n')
        self.write('pkg/agentloop/ee.go', 'package agentloop\nimport ee "' + module + '"\nvar Value = ee.Value\n')
        report = self.run_gate('edition-boundary', 1)
        self.assertTrue(any(r['rule'] == 'depguard' for r in report['blocking']))

    def test_missing_tool_is_not_clean_result(self):
        self.linter = str(self.root / 'missing-analyzer')
        proc = subprocess.run([sys.executable, str(HERE / 'policy.py'), '--root', str(self.root),
                               '--base', self.base, '--linter', self.linter,
                               '--output', str(self.output / 'missing')], capture_output=True)
        self.assertEqual(proc.returncode, 2)


if __name__ == '__main__':
    unittest.main()
