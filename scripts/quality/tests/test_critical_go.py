# SPDX-License-Identifier: Apache-2.0
"""Reject empty, unrelated or unsuccessful critical-test evidence."""
import json
from contextlib import nullcontext as _null
from pathlib import Path
import sys
import tempfile
import time
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


class BaselineOnlyParserControls(unittest.TestCase):
    BASELINE = ('fuzz: elapsed: 0s, gathering baseline coverage: 0/378 completed\n'
                'fuzz: elapsed: 9s, gathering baseline coverage: 307/378 completed\n'
                'PASS\nok  example/pkg 11.1s\n')

    def parser_case(self, text):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'f.log'
            path.write_text(text)
            return results.baseline_only_fuzz_log(path)

    def test_baseline_only_pass_is_recognized(self):
        self.assertTrue(self.parser_case(self.BASELINE))

    def test_generated_executions_disqualify_retry(self):
        text = ('fuzz: elapsed: 3s, execs: 512 (170/sec), new interesting: 1\n'
                'PASS\nok  example/pkg 4.0s\n')
        self.assertFalse(self.parser_case(text))

    def test_zero_execution_progress_is_not_baseline_only(self):
        text = ('fuzz: elapsed: 0s, gathering baseline coverage: 0/2 completed\n'
                'fuzz: elapsed: 3s, execs: 0 (0/sec)\nPASS\nok  example/pkg 4.0s\n')
        self.assertFalse(self.parser_case(text))

    def test_fail_build_error_and_empty_stay_red(self):
        crash = ('fuzz: elapsed: 1s, execs: 40 (40/sec)\n'
                 '--- FAIL: FuzzX\nFAIL\n')
        build = 'build failed\n'
        for text in (crash, build, ''):
            with self.subTest(text=text[:20]):
                self.assertFalse(self.parser_case(text))

    def test_fail_summary_blocks_retry(self):
        text = self.BASELINE + 'FAIL\n'
        self.assertFalse(self.parser_case(text))


class FuzzRetrySchedulingControls(unittest.TestCase):
    BASELINE = ('fuzz: elapsed: 0s, gathering baseline coverage: 0/378 completed\n'
                'fuzz: elapsed: 9s, gathering baseline coverage: 307/378 completed\n'
                'PASS\nok  example/pkg 11.1s\n')
    GENERATED = ('fuzz: elapsed: 3s, execs: 512 (170/sec), new interesting: 1\n'
                 'PASS\nok  example/pkg 4.0s\n')
    GENERATED_NEXT = ('fuzz: elapsed: 2s, execs: 7 (3/sec), new interesting: 0\n'
                      'PASS\nok  example/pkg 3.0s\n')

    def run_fuzz(self, tmp, script, clock=None, deadline=None):
        """Script per-target fuzz logs; record every -fuzztime window.

        script maps target name -> list of main-attempt log texts consumed in
        order (a second entry exercises the retry). Warm and seed-profile
        invocations always PASS and never consume scripted entries.
        """
        windows = []
        used = []

        def fake_checked(argv, root, log, deadline, env=None):
            for a in argv:
                if a.startswith('-coverprofile='):
                    Path(a[len('-coverprofile='):]).write_text('mode: set\n')
            arg = [a for a in argv if a.startswith('-fuzztime=')]
            if arg and arg[0] != '-fuzztime=1x':
                name = [a for a in argv if a.startswith('-fuzz=')][0]
                name = name[len('-fuzz='):].strip('^$')
                text = script[name].pop(0)
                used.append(name)
                windows.append((name, int(arg[0][len('-fuzztime='):-1])))
            else:
                text = 'PASS\n'
            Path(log).write_text(text)

        from unittest import mock
        out = Path(tmp)
        out.mkdir(parents=True, exist_ok=True)
        with mock.patch.object(critical, 'checked', fake_checked), \
                mock.patch.object(critical, 'fuzz_targets',
                                  lambda *a: list(script)), \
                (mock.patch.object(critical.time, 'monotonic',
                                   side_effect=iter(clock)) if clock
                 else _null()):
            value = critical.fuzz(out, 'pkg/auth', [], [], out,
                                  deadline or time.monotonic() + 10000)
        return value, windows, used

    def test_baseline_only_earns_one_bounded_retry(self):
        script = {'FuzzBigCorpus': [self.BASELINE, self.GENERATED],
                  'FuzzNext': [self.GENERATED_NEXT]}
        with tempfile.TemporaryDirectory() as tmp:
            value, windows, used = self.run_fuzz(tmp, script)
        self.assertEqual(used, ['FuzzBigCorpus', 'FuzzBigCorpus', 'FuzzNext'])
        self.assertEqual(value, {'FuzzBigCorpus': 512, 'FuzzNext': 7})

    def test_first_attempt_preserved_and_retry_is_separate(self):
        script = {'FuzzBigCorpus': [self.BASELINE, self.GENERATED],
                  'FuzzNext': [self.GENERATED_NEXT]}
        with tempfile.TemporaryDirectory() as tmp:
            self.run_fuzz(tmp, script)
            self.assertEqual((Path(tmp) / 'FuzzBigCorpus-baseline-only.log')
                             .read_text(), self.BASELINE)
            self.assertIn('execs: 512',
                          (Path(tmp) / 'FuzzBigCorpus-retry.log').read_text())
            self.assertFalse((Path(tmp) / 'FuzzBigCorpus.log').exists(),
                             'the primary log must be renamed, not overwritten')

    def test_retry_window_grows_within_deadline_and_later_share_recomputes(self):
        # Fake clock: monotonic returns 100, 103, 106 (one reading per
        # scheduling decision); deadline = 2100. Expected by hand:
        #   slice0 = (2100-100-10)//2 = 995
        #   retry  = min(2100-103-10, 3*995) = 1987  -> bounded by remaining
        #   slice1 = (2100-106-10)//1 = 1984         -> recomputed after retry
        script = {'FuzzBigCorpus': [self.BASELINE, self.GENERATED],
                  'FuzzNext': [self.GENERATED_NEXT]}
        with tempfile.TemporaryDirectory() as tmp:
            _, windows, _ = self.run_fuzz(tmp, script, clock=[100, 103, 106],
                                          deadline=2100)
        self.assertEqual([w for _, w in windows], [995, 1987, 1984])
        self.assertLess(windows[1][1], 2100 - 100,
                        'retry must stay inside the original mode deadline')

    def test_persistent_baseline_only_stays_red_with_both_logs(self):
        script = {'FuzzBigCorpus': [self.BASELINE, self.BASELINE],
                  'FuzzNext': [self.GENERATED_NEXT]}
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError) as caught:
                self.run_fuzz(tmp, script)
            self.assertIn('no confirmed executions', str(caught.exception))
            self.assertIn('FuzzBigCorpus-retry.log', str(caught.exception))
            self.assertTrue((Path(tmp) / 'FuzzBigCorpus-baseline-only.log')
                            .exists())
            self.assertTrue((Path(tmp) / 'FuzzBigCorpus-retry.log').exists())
            self.assertEqual(used_count(tmp, 'FuzzBigCorpus'), 2)

    def test_crash_log_is_never_retried(self):
        crash = ('fuzz: elapsed: 0s, gathering baseline coverage: '
                 '0/378 completed\n'
                 '--- FAIL: FuzzBigCorpus\nFAIL\n')
        script = {'FuzzBigCorpus': [crash], 'FuzzNext': [self.GENERATED]}
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError) as caught:
                self.run_fuzz(tmp, script)
            self.assertIn('FuzzBigCorpus.log', str(caught.exception))
            self.assertFalse((Path(tmp) / 'FuzzBigCorpus-baseline-only.log')
                             .exists())
            self.assertFalse((Path(tmp) / 'FuzzBigCorpus-retry.log').exists())

    def test_zero_execution_progress_is_never_retried(self):
        zero = ('fuzz: elapsed: 0s, gathering baseline coverage: 0/2 completed\n'
                'fuzz: elapsed: 3s, execs: 0 (0/sec)\nPASS\nok  p 4.0s\n')
        script = {'FuzzBigCorpus': [zero], 'FuzzNext': [self.GENERATED_NEXT]}
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                self.run_fuzz(tmp, script)
            self.assertFalse((Path(tmp) / 'FuzzBigCorpus-retry.log').exists())


def used_count(tmp, name):
    return sum(1 for p in Path(tmp).iterdir()
               if p.name.startswith(name) and p.name.endswith('.log')
               and '-warm' not in p.name)


class ConfigControls(unittest.TestCase):
    def config(self):
        return json.loads((Path(critical.__file__).parent / 'critical.json').read_text())

    def test_shipped_schema2_config_and_rejected_variants(self):
        config = self.config()
        critical.validate_config(config)
        self.assertEqual(critical.budget(config), {'unit': 420, 'fuzz': 420, 'mutation': 300})
        for bad in (dict(config, schema_version=1),
                    dict(config, fuzz_applicability='all-packages'),
                    dict(config, mutation_qualified_packages='pkg/budget'),
                    dict(config, seconds_per_package_and_kind=600),
                    dict(config, budget={'schema_version': 1, 'seconds_per_package':
                                         {'unit': 300, 'fuzz': 300, 'mutation': 300}}),
                    dict(config, budget={'schema_version': 2, 'seconds_per_package':
                                         {'unit': 300, 'fuzz': 420, 'mutation': 300}}),
                    dict(config, budget={'schema_version': 1, 'seconds_per_package':
                                         {'unit': 300, 'mutation': 300}}),
                    dict(config, budget={'schema_version': 1}),
                    dict(config, budget=None)):
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


class SeedBlockOverrideControls(unittest.TestCase):
    """Preview2 stopgap: base-bound, evidence-bearing, fail-closed elsewhere."""

    def profile_rows(self):
        return ['example.test/pkg/auth/check.go:12.1,13.2 1 1',
                'example.test/pkg/auth/check.go:15.1,16.2 1 0']

    def fake_gate(self, exec_log_text):
        """Stand-in for checked(): materializes listing, profile and fuzz logs."""
        def checked(argv, root, log, deadline, env=None):
            argv = [str(item) for item in argv]
            joined = ' '.join(argv)
            path = Path(log)
            if '-list=' in joined:
                path.write_text('FuzzFake\n')
            elif '-coverprofile=' in joined:
                target = [item[len('-coverprofile='):] for item in argv
                          if item.startswith('-coverprofile=')][0]
                Path(target).write_text('mode: set\n'
                                        + '\n'.join(self.profile_rows()) + '\n')
            else:
                path.write_text(exec_log_text)
        return checked

    def run_fuzz(self, override, exec_log_text='PASS\nfuzz: elapsed: 1s, execs: 7\n'):
        import io
        import time
        from unittest import mock
        captured = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            fake = self.fake_gate(exec_log_text)
            with mock.patch.object(critical, 'checked', fake), \
                    mock.patch('sys.stdout', captured):
                value = critical.fuzz(Path(tmp), 'pkg/auth', [TARGET], '',
                                      out, time.monotonic() + 120, override)
            record = None
            if (out / 'fuzz-seed-override.json').exists():
                record = json.loads((out / 'fuzz-seed-override.json').read_text())
        return value, out, captured.getvalue(), record

    def test_report_mirrors_verdict_predicate(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'cover.out'
            path.write_text('mode: set\n' + '\n'.join(self.profile_rows()) + '\n')
            with self.assertRaises(ValueError):
                results.seed_coverage(path, [TARGET])
            failing = results.seed_coverage_report(path, [TARGET])
            self.assertEqual(failing, [{'file': TARGET['file'],
                                        'function': TARGET['name'],
                                        'uncovered_blocks': 1,
                                        'blocks': ['15.1,16.2']}])
            path.write_text('mode: set\nexample.test/pkg/auth/check.go:12.1,13.2 1 1\n')
            self.assertEqual(results.seed_coverage_report(path, [TARGET]), [])
            path.write_text('mode: set\n')
            failing = results.seed_coverage_report(path, [TARGET])
            self.assertEqual(failing[0]['uncovered_blocks'], 0)
            self.assertEqual(failing[0]['profile_rows'], 0)

    def test_block_specs_not_start_lines(self):
        # Two sibling blocks can share a start line; only the full spec
        # identifies what the replay missed. stmts=0 blocks never enter the
        # predicate, matching seed_coverage exactly.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'cover.out'
            path.write_text('mode: set\n'
                            'example.test/pkg/auth/check.go:12.1,13.2 1 1\n'
                            'example.test/pkg/auth/check.go:15.1,16.2 2 1\n'
                            'example.test/pkg/auth/check.go:15.3,16.4 1 0\n'
                            'example.test/pkg/auth/check.go:15.9,16.9 0 0\n')
            failing = results.seed_coverage_report(path, [TARGET])
            self.assertEqual(failing, [{'file': TARGET['file'],
                                        'function': TARGET['name'],
                                        'uncovered_blocks': 1,
                                        'blocks': ['15.3,16.4']}])

    def test_no_profile_rows_marked_distinctly(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'cover.out'
            path.write_text('mode: set\n')
            failing = results.seed_coverage_report(path, [TARGET])
            self.assertEqual(len(failing), 1)
            self.assertEqual(failing[0]['uncovered_blocks'], 0)
            self.assertEqual(failing[0]['profile_rows'], 0)

    def test_binding_absent_or_mismatched_fails_closed(self):
        from unittest import mock
        with mock.patch.dict('os.environ', {}, clear=True):
            self.assertIsNone(critical.seed_override_binding('4e98'))
        with mock.patch.dict('os.environ',
                             {'CRITICAL_SEED_BLOCK_OVERRIDE_BASE': ''}):
            # CI renders unmet guards as '' — empty means absent, never a
            # mismatch failure on unrelated runs.
            self.assertIsNone(critical.seed_override_binding('4e98'))
        with mock.patch.dict('os.environ',
                             {'CRITICAL_SEED_BLOCK_OVERRIDE_BASE': 'deadbeef'}):
            with self.assertRaises(ValueError):
                critical.seed_override_binding('4e98')
        with mock.patch.dict('os.environ',
                             {'CRITICAL_SEED_BLOCK_OVERRIDE_BASE': '4e98'}):
            self.assertEqual(critical.seed_override_binding('4e98'),
                             {'base': '4e98', 'activations': []})

    def test_override_records_evidence_and_continues(self):
        override = {'base': '4e98', 'activations': []}
        value, out, printed, record = self.run_fuzz(override)
        self.assertEqual(value, {'FuzzFake': 7})
        self.assertEqual(record['override'], 'preview2-seed-block')
        self.assertEqual(record['base'], '4e98')
        self.assertEqual(record['failing_functions'], 1)
        self.assertEqual(record['uncovered_blocks'], 1)
        self.assertEqual(record['functions'][0]['blocks'], ['15.1,16.2'])
        self.assertIn('deferred', record)
        self.assertIn('Critical Go seed-block override (Preview2, base 4e98)', printed)
        self.assertIn('deferred to Preview3', printed)
        self.assertEqual(override['activations'][0]['package'], 'pkg/auth')

    def test_without_override_the_seed_verdict_stays_red(self):
        with self.assertRaises(ValueError) as caught:
            self.run_fuzz(None)
        self.assertIn('Fuzz seeds do not cover every changed-function block',
                      str(caught.exception))

    def test_unrelated_fuzz_failure_stays_red_under_override(self):
        override = {'base': '4e98', 'activations': []}
        with self.assertRaises(ValueError) as caught:
            self.run_fuzz(override, 'PASS\nfuzz: elapsed: 1s, execs: 0 (0/sec)\n')
        self.assertIn('no confirmed executions', str(caught.exception))

    def test_overridden_report_never_claims_clean_pass(self):
        report = {'status': 'running'}
        critical.apply_seed_override_status(report, None)
        self.assertEqual(report['status'], 'running')
        critical.apply_seed_override_status(report, {'base': '4e98', 'activations': []})
        self.assertEqual(report['status'], 'running')
        critical.apply_seed_override_status(report,
                                            {'base': '4e98', 'activations': [
                                                {'package': 'pkg/auth'}]})
        self.assertEqual(report['status'], 'passed-seed-block-override')
        self.assertEqual(report['seed_block_override']['mode'], 'preview2-temporary')
        self.assertIn('Preview3', report['seed_block_override']['note'])

    def e2e_args(self, repo, out):
        from types import SimpleNamespace
        return SimpleNamespace(root=Path(repo), base='4e98',
                               gremlins='/gremlins-bin', output=Path(out))

    def run_gate(self, env_value, base='4e98'):
        """Drive critical.run() end to end with only the deepest seam faked.

        run_package is the seam: when the override reaches it the fake
        records the activation and passes; when any hop drops the extra
        argument the fake sees None, raises the simulated red seed verdict
        and the gate fails — exactly how the real gate behaves today.
        """
        from unittest import mock
        seen = {}
        env = {'pkg/auth': [TARGET]}

        def fake_run_package(root, package, functions, config, target, gremlins,
                             override=None):
            seen['override'] = override
            if override is None:
                raise ValueError('simulated red seed verdict '
                                 '(override did not reach run_package)')
            override['activations'].append({'package': package,
                                            'failing_functions': 0,
                                            'uncovered_blocks': 0,
                                            'evidence': 'fuzz-seed-override.json'})
            return {'fuzz:': {'status': 'passed'}, 'unit:': {'status': 'passed'}}

        patches = [
            mock.patch.object(critical, 'run_package', fake_run_package),
            mock.patch.object(critical.source, 'git', lambda *a, **k: b'4e98\n'),
            mock.patch.object(critical.source, 'snapshot',
                              lambda root: {'commit': 'abc123', 'sha256': 'def456'}),
            mock.patch.object(critical.source, 'environment',
                              lambda root, gremlins: {'go': 'test'}),
            mock.patch.object(critical.source, 'copy_source',
                              lambda root, isolated: None),
            mock.patch.object(critical.scope, 'selector_mode',
                              lambda: critical.scope.LEGACY),
            mock.patch.object(critical.scope, 'targets', lambda *a: env),
            mock.patch.object(critical, 'check_version', lambda *a: {'v': '1'}),
        ]
        env_map = {'CRITICAL_SEED_BLOCK_OVERRIDE_BASE': env_value} if env_value else {}
        with tempfile.TemporaryDirectory() as tmp:
            repo, out = Path(tmp) / 'repo', Path(tmp) / 'out'
            repo.mkdir()
            code, report = None, None
            with mock.patch.dict('os.environ', env_map, clear=True):
                for patch in patches:
                    patch.start()
                try:
                    code = critical.run(self.e2e_args(repo, out))
                except ValueError:
                    code = None
                finally:
                    for patch in patches:
                        patch.stop()
            if (out / 'report.json').exists():
                report = json.loads((out / 'report.json').read_text())
        return code, seen, report

    def test_run_threads_override_through_execute_targets(self):
        # End-to-end wiring control: run() must carry the binding through
        # execute_targets into run_package; a dropped argument turns this
        # test red via the simulated verdict.
        code, seen, report = self.run_gate('4e98')
        self.assertEqual(code, 0)
        self.assertIsNotNone(seen.get('override'))
        self.assertEqual(report['status'], 'passed-seed-block-override')
        self.assertEqual(report['seed_block_override']['mode'], 'preview2-temporary')
        self.assertEqual(report['base'], '4e98')

    def test_run_default_path_stays_red_end_to_end(self):
        code, seen, report = self.run_gate(None)
        self.assertIsNone(code)
        self.assertIsNone(seen.get('override'))
        self.assertEqual(report['status'], 'failed')
        self.assertIn('simulated red seed verdict', report['error'])

    def test_run_package_threads_override_into_run_mode(self):
        # Pins the middle hop: a dropped argument between run_package and
        # run_mode fails red by construction (override None restores the
        # strict verdict); this control makes such a regression explicit.
        import time
        from unittest import mock
        override = {'base': '4e98', 'activations': []}
        seen = {}

        def fake_run_mode(kind, root, package, functions, tags, out, deadline,
                          gremlins, qualified, override=None):
            seen['override'] = override
            if override is None:
                raise ValueError('override did not reach run_mode')
            return {'status': 'passed'}

        config = {'budget': {'schema_version': 1,
                             'seconds_per_package': critical.APPROVED_BUDGET},
                  'mutation_qualified_packages': [], 'build_tags': ['']}
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            with mock.patch.object(critical, 'run_mode', fake_run_mode), \
                    mock.patch.object(critical, 'active_functions',
                                      lambda *a: [TARGET]), \
                    mock.patch.object(critical.conservative,
                                      'resume_unit_deadline',
                                      lambda package, seconds:
                                          time.monotonic() + 3600):
                value = critical.run_package(out, 'pkg/auth', [TARGET], config,
                                             out / 'target', '/gremlins',
                                             override)
                self.assertIs(seen['override'], override)
                self.assertEqual(value, {'unit:': {'status': 'passed'},
                                         'fuzz:': {'status': 'passed'},
                                         'mutation:': {'status': 'passed'}})
                with self.assertRaises(ValueError):
                    critical.run_package(out, 'pkg/auth', [TARGET], config,
                                         out / 'target-negative', '/gremlins')

    def test_run_binding_mismatch_fails_closed_end_to_end(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict('os.environ',
                                 {'CRITICAL_SEED_BLOCK_OVERRIDE_BASE': '4e98'}), \
                    mock.patch.object(critical.source, 'git',
                                      lambda *a, **k: b'dead\n'), \
                    mock.patch.object(critical.source, 'snapshot',
                                      lambda root: {'commit': 'abc', 'sha256': 'def'}), \
                    mock.patch.object(critical.scope, 'targets', lambda *a: {}):
                with self.assertRaises(ValueError) as caught:
                    critical.run(self.e2e_args(Path(tmp) / 'repo', Path(tmp) / 'out'))
        self.assertIn('base mismatch', str(caught.exception))


class SeedOverrideManifestControls(unittest.TestCase):
    """The quality manifest must keep the seed-block override visible and
    never normalize it into a clean pass."""

    REALISTIC_LOG = ('Critical Go seed-block override (Preview2, base '
                     '4e98abc): pkg/auth: 3/seed functions deferred\n'
                     'Critical Go seed-block override active: temporary Preview2 '
                     'handling; Preview3 must land the acceptance redesign and '
                     'remove this override\n'
                     'Critical Go checks: passed-seed-block-override; '
                     '/artifacts/quality/critical-go-1/report.json\n'
                     'Report SHA256: '
                     'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n')

    def forge(self, log_text, gate_updates=None):
        """Keep the run directory alive for the whole test via addCleanup."""
        import hashlib
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        directory = Path(temp.name)
        log = directory / 'critical-go.log'
        log.write_text(log_text)
        gate = {'name': 'critical-go', 'status': 'passed-seed-block-override',
                'exit_code': 0, 'log': 'critical-go.log',
                'log_sha256': hashlib.sha256(log.read_bytes()).hexdigest(),
                'seed_block_override': {'mode': 'preview2-temporary',
                                        'base': '4e98abc',
                                        'report': '/artifacts/quality/critical-go-1/report.json',
                                        'report_sha256': 'e3b0c44298fc1c149afbf4c8996fb92427'
                                                         'ae41e4649b934ca495991b7852b855',
                                        'note': 'Preview3 owes the redesign'}}
        gate.update(gate_updates or {})
        manifest = directory / 'manifest.json'
        manifest.write_text(json.dumps({
            'schema_version': 1, 'status': 'passed',
            'source': {'commit': 'abc123', 'sha256': 'def456'},
            'source_after': {'commit': 'abc123', 'sha256': 'def456'},
            'gates': [gate]}))
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        import quality
        return quality, directory, manifest

    def test_gate_record_propagates_parsed_fields(self):
        import io
        from unittest import mock
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        import quality
        captured = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / 'critical-go.log'
            gate = {'name': 'critical-go', 'status': 'pending',
                    'log': 'critical-go.log'}
            log.write_text(self.REALISTIC_LOG)
            with mock.patch.object(quality, 'execute',
                                   lambda *a, **k: {'status': 'passed', 'exit_code': 0,
                                                    'duration_seconds': 0.1}), \
                    mock.patch('sys.stdout', captured):
                quality.execute_gate(gate, ['make'], Path(tmp), log, 60, None, None)
            self.assertEqual(gate['status'], 'passed-seed-block-override')
            flag = gate['seed_block_override']
            self.assertEqual(flag['base'], '4e98abc')
            self.assertEqual(flag['report'],
                             '/artifacts/quality/critical-go-1/report.json')
            self.assertEqual(flag['report_sha256'],
                             'e3b0c44298fc1c149afbf4c8996fb92427'
                             'ae41e4649b934ca495991b7852b855')
            self.assertIn('WARNING', captured.getvalue())
            self.assertIn('Preview3', flag['note'])

    def test_propagation_is_strictly_critical_go_exit_zero(self):
        from unittest import mock
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        import quality
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / 'gate.log'

            def run_case(gate, exit_code):
                log.write_text(self.REALISTIC_LOG)
                with mock.patch.object(quality, 'execute',
                                       lambda *a, **k: {'status': 'failed' if exit_code
                                                        else 'passed',
                                                        'exit_code': exit_code,
                                                        'duration_seconds': 0.1}):
                    quality.execute_gate(gate, ['make'], Path(tmp), log, 60,
                                         None, None)

            # An ordinary gate with the same log line must never activate.
            other = {'name': 'tests', 'status': 'pending', 'log': 'gate.log'}
            run_case(other, 0)
            self.assertEqual(other['status'], 'passed')
            self.assertNotIn('seed_block_override', other)
            # A failed critical-go with the line must stay failed.
            failed = {'name': 'critical-go', 'status': 'pending',
                      'log': 'gate.log'}
            run_case(failed, 2)
            self.assertEqual(failed['status'], 'failed')
            self.assertNotIn('seed_block_override', failed)
            # A clean passed critical-go without the line stays plain passed.
            clean_log = Path(tmp) / 'clean.log'
            clean = {'name': 'critical-go', 'status': 'pending',
                     'log': 'clean.log'}
            clean_log.write_text('Critical Go checks: passed; report.json\n')
            with mock.patch.object(quality, 'execute',
                                   lambda *a, **k: {'status': 'passed', 'exit_code': 0,
                                                    'duration_seconds': 0.1}):
                quality.execute_gate(clean, ['make'], Path(tmp), clean_log, 60,
                                     None, None)
            self.assertEqual(clean['status'], 'passed')
            self.assertNotIn('seed_block_override', clean)

    def test_verify_evidence_accepts_only_explicit_override(self):
        from unittest import mock
        quality, directory, manifest = self.forge(self.REALISTIC_LOG)
        snap = {'commit': 'abc123', 'sha256': 'def456'}
        with mock.patch.object(quality, 'snapshot', lambda root: snap):
            self.assertTrue(quality.verify_evidence(directory, manifest,
                                                    ['critical-go']))
            # Override status without the flag: rejected.
            _, udir, unflagged = self.forge(
                self.REALISTIC_LOG, {'seed_block_override': None})
            self.assertFalse(quality.verify_evidence(udir, unflagged,
                                                     ['critical-go']))
            # The flag recorded under a plain passed status: rejected —
            # that combination is exactly the silent normalization.
            _, ndir, normalized = self.forge(
                self.REALISTIC_LOG, {'status': 'passed'})
            self.assertFalse(quality.verify_evidence(ndir, normalized,
                                                     ['critical-go']))
            # Non-zero exit under the override status: rejected.
            _, fdir, failed = self.forge(self.REALISTIC_LOG, {'exit_code': 1})
            self.assertFalse(quality.verify_evidence(fdir, failed,
                                                     ['critical-go']))
            # Tampered log bytes invalidate the override evidence like any pass.
            _, tdir, tmanifest = self.forge(self.REALISTIC_LOG)
            (tdir / 'critical-go.log').write_text('rewritten\n')
            self.assertFalse(quality.verify_evidence(tdir, tmanifest,
                                                     ['critical-go']))
            # Control: a clean pass without any override still verifies.
            clean_log = ('Critical Go checks: passed; report.json\n'
                         'Report SHA256: '
                         'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n')
            import hashlib
            temp = tempfile.TemporaryDirectory()
            self.addCleanup(temp.cleanup)
            cdir = Path(temp.name)
            (cdir / 'critical-go.log').write_text(clean_log)
            clean = {'name': 'critical-go', 'status': 'passed', 'exit_code': 0,
                     'log': 'critical-go.log',
                     'log_sha256': hashlib.sha256(
                         (cdir / 'critical-go.log').read_bytes()).hexdigest()}
            cmanifest = cdir / 'manifest.json'
            cmanifest.write_text(json.dumps({
                'schema_version': 1, 'status': 'passed',
                'source': snap, 'source_after': snap, 'gates': [clean]}))
            self.assertTrue(quality.verify_evidence(cdir, cmanifest,
                                                    ['critical-go']))


class WorkflowOverrideBindingControls(unittest.TestCase):
    """The CI binding for the Preview2 stopgap must stay conditional on the
    recorded task base: no unconditional relaxation for future bases, and
    the Preview3 removal obligation must be documented at both sites."""

    BASE = '4e9895d3633dd151e1bd69c4b4617ea333126b62'

    def workflow_text(self):
        path = Path(__file__).resolve().parents[3] / '.github/workflows/ci.yml'
        return path.read_text(encoding='utf-8')

    def test_binding_sites_are_guarded_and_documented(self):
        text = self.workflow_text()
        lines = text.splitlines()
        base_lines = [i for i, line in enumerate(lines) if self.BASE in line]
        self.assertEqual(len(base_lines), 2,
                         'the Preview2 base may appear at exactly the two '
                         'binding sites')
        # Post-push site: exactly one env assignment, carrying the guarded
        # expression that renders '' (absent) for every other before-SHA.
        env_lines = [i for i, line in enumerate(lines)
                     if 'CRITICAL_SEED_BLOCK_OVERRIDE_BASE:' in line]
        self.assertEqual(len(env_lines), 1)
        self.assertIn("github.event.before == '" + self.BASE + "'",
                      lines[env_lines[0]])
        self.assertIn("&& github.event.before || ''", lines[env_lines[0]])
        # PR site: exactly one export, and it must sit lexically inside the
        # resolved-base if-guard so an unconditional leak fails this control.
        export_lines = [i for i, line in enumerate(lines)
                        if 'export CRITICAL_SEED_BLOCK_OVERRIDE_BASE' in line]
        self.assertEqual(len(export_lines), 1)
        guard_open = [i for i, line in enumerate(lines) if line.strip()
                      == 'if [ "$resolved" = "' + self.BASE + '" ]; then']
        self.assertEqual(len(guard_open), 1)
        self.assertLess(guard_open[0], export_lines[0])
        guard_close = min(i for i in range(guard_open[0] + 1, len(lines))
                          if lines[i].strip() == 'fi')
        self.assertLess(export_lines[0], guard_close)
        # Preview3 removal must be documented next to each binding site.
        for anchor in (env_lines[0], guard_open[0]):
            window = '\n'.join(lines[max(0, anchor - 6):anchor + 6])
            self.assertIn('Preview3', window,
                          'removal obligation must be documented at the '
                          'binding site')


if __name__ == '__main__':
    unittest.main()
