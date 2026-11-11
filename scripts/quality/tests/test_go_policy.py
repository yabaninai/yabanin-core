# SPDX-License-Identifier: Apache-2.0
"""Independent controls for policy finding classification and AST identities."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parents[1] / 'go_policy'
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location('go_policy', HERE / 'policy.py')
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


def finding(fingerprint, line=2, message='incorrect error comparison'):
    return {'file': 'lib.go', 'line': line, 'rule': 'errorlint',
            'message': message, 'unit_sha256': fingerprint}


class FindingControls(unittest.TestCase):
    def test_untouched_finding_moves_line_but_remains_debt(self):
        debt, blocked = policy.classify([finding('old')], [finding('old', 20)])
        self.assertEqual(len(debt), 1)
        self.assertFalse(blocked)

    def test_edit_elsewhere_in_function_does_not_hide_old_error(self):
        debt, blocked = policy.classify([finding('old')], [finding('changed')])
        self.assertFalse(debt)
        self.assertEqual(len(blocked), 1)

    def test_new_enum_member_breaks_previously_unchanged_switch(self):
        debt, blocked = policy.classify([], [finding('same', message='missing Completed')])
        self.assertEqual(len(blocked), 1)
        self.assertFalse(debt)

    def test_copy_cannot_claim_old_debt_twice(self):
        debt, blocked = policy.classify([finding('old')], [finding('old'), finding('old', 9)])
        self.assertEqual((len(debt), len(blocked)), (1, 1))

    def test_type_error_is_never_legacy_debt(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'report.json'
            path.write_text(json.dumps({'Issues': [{'FromLinter': 'typecheck', 'Text': 'missing symbol'}]}))
            with self.assertRaisesRegex(ValueError, 'Type checking failed'):
                policy.parse_issues(path, Path('.'), Path(tmp))

    def test_missing_report_shape_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'report.json'
            path.write_text('{}')
            with self.assertRaises(ValueError):
                policy.parse_issues(path, Path('.'), Path(tmp))


class UnitIdentityControls(unittest.TestCase):
    def test_ast_identity_preserves_literal_bytes_and_ignores_format(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cases = {'a.go': 'package p; func A() string { return `a\n\nb` }',
                     'b.go': 'package p\n\nfunc B() string {\n return `a\n\nb`\n}\n',
                     'c.go': 'package p; func A() string { return `a\nb` }'}
            for name, text in cases.items():
                (root / name).write_text(text)
            units = policy.unit_maps(root, list(cases), HERE / 'units.go')
            self.assertEqual(units['a.go'][0]['hash'], units['b.go'][0]['hash'])
            self.assertNotEqual(units['a.go'][0]['hash'], units['c.go'][0]['hash'])
            self.assertEqual(units['b.go'][0]['name'], 'B')


if __name__ == '__main__':
    unittest.main()
