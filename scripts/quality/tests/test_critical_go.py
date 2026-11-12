# SPDX-License-Identifier: Apache-2.0
"""Reject empty, unrelated or unsuccessful critical-test evidence."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'go_policy'))
import critical
import critical_results as results

TARGET = {'file': 'pkg/auth/check.go', 'name': 'Allowed', 'start': 10, 'end': 20}


class MutationControls(unittest.TestCase):
    def report(self, mutations, file='pkg/auth/check.go'):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        path = Path(temp.name) / 'result.json'
        path.write_text(json.dumps({'files': [{'file_name': file, 'mutations': mutations}]}))
        return path

    def test_real_target_killed(self):
        path = self.report([{'line': 12, 'status': 'KILLED'}])
        self.assertEqual(results.mutation_report(path, [TARGET])[0]['killed'], 1)

    def test_empty_or_irrelevant_mutations_fail(self):
        for mutations in ([], [{'line': 30, 'status': 'KILLED'}]):
            with self.subTest(mutations=mutations), self.assertRaises(ValueError):
                results.mutation_report(self.report(mutations), [TARGET])

    def test_wrong_file_does_not_count(self):
        path = self.report([{'line': 12, 'status': 'KILLED'}], file='pkg/auth/other.go')
        with self.assertRaises(ValueError):
            results.mutation_report(path, [TARGET])

    def test_survivor_timeout_or_compile_failure_never_counts_as_killed(self):
        for status in ('LIVED', 'NOT COVERED', 'NOT VIABLE', 'TIMED OUT', 'SKIPPED', 'UNKNOWN'):
            with self.subTest(status=status), self.assertRaises(ValueError):
                results.mutation_report(self.report([{'line': 12, 'status': status}]), [TARGET])


class FuzzControls(unittest.TestCase):
    def test_missing_executions_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'fuzz.log'
            for text in ('PASS', 'fuzz: elapsed: 1s, execs: 0 (0/sec)'):
                path.write_text(text)
                with self.assertRaises(ValueError):
                    results.fuzz_executions(path)

    def test_execution_count_alone_does_not_prove_target_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'coverage.out'
            path.write_text('mode: set\nexample.test/pkg/auth/check.go:30.1,31.2 1 20\n')
            with self.assertRaises(ValueError):
                results.seed_coverage(path, [TARGET])
            path.write_text('mode: set\nexample.test/pkg/auth/check.go:12.1,13.2 1 0\n')
            with self.assertRaises(ValueError):
                results.seed_coverage(path, [TARGET])
            path.write_text('mode: set\nexample.test/pkg/auth/check.go:12.1,13.2 1 1\n')
            results.seed_coverage(path, [TARGET])
            with path.open('a') as stream:
                stream.write('example.test/pkg/auth/check.go:15.1,16.2 1 0\n')
            with self.assertRaises(ValueError):
                results.seed_coverage(path, [TARGET])


class ConfigControls(unittest.TestCase):
    def config(self):
        return json.loads((Path(critical.__file__).parent / 'critical.json').read_text())

    def test_shipped_schema2_config_and_rejected_variants(self):
        config = self.config()
        critical.validate_config(config)
        for bad in (dict(config, schema_version=1),
                    dict(config, fuzz_applicability='all-packages'),
                    dict(config, mutation_qualified_packages='pkg/budget'),
                    dict(config, seconds_per_package_and_kind=600)):
            with self.subTest(bad=bad.get('schema_version', bad)), self.assertRaises(ValueError):
                critical.validate_config(bad)

    def test_qualified_packages_must_be_critical_paths(self):
        config = self.config()
        critical.validate_config(dict(config, mutation_qualified_packages=['pkg/budget', 'pkg/retry']))
        with self.assertRaises(ValueError):
            critical.validate_config(dict(config, mutation_qualified_packages=['cmd/yb']))
        with self.assertRaises(ValueError):
            critical.validate_config(dict(config, mutation_qualified_packages=[7]))


class ApplicabilityReportControls(unittest.TestCase):
    def test_not_applicable_entries_are_surfaced_with_reasons(self):
        report = {'packages': {'pkg/budget': {'checks': {
            'unit:': {'status': 'passed'},
            'fuzz:': {'status': 'not_applicable', 'reason': 'skipped: no fuzz targets (N/A)'},
            'mutation:': {'status': 'not_applicable', 'reason': 'skipped: no gremlins-qualified unit mode (N/A)'}}}}}
        self.assertEqual(critical.applicability_lines(report), [
            'pkg/budget [fuzz:]: skipped: no fuzz targets (N/A)',
            'pkg/budget [mutation:]: skipped: no gremlins-qualified unit mode (N/A)'])


if __name__ == '__main__':
    unittest.main()
