# SPDX-License-Identifier: Apache-2.0
"""Package unit budgets do not pay for another package's selector work."""
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'go_policy'))
import critical_conservative as conservative
import critical_scope as scope
import source


class PackageDeadlineIsolation(unittest.TestCase):
    def test_two_package_rebaseline_charges_only_owned_work(self):
        clock = {'now': 1000.0, 'events': []}

        def advance(label, package, seconds):
            clock['events'].append((label, package, seconds))
            clock['now'] += seconds

        def archive(_root, _base, _destination):
            advance('archive', 'shared', 10)

        def changed(_root, _baseline, package, _helper, _changes,
                    _build_tags, _config):
            advance('package-scan', package, 10)
            selection = conservative.Selection(package)
            selection.note_lost_baseline(
                'TestRewrite', [{
                    'file': package + '/rewrite_test.go',
                    'name': 'TestRewrite',
                    'hash': 'old-body',
                    'start': 1,
                }])
            conservative.RUNS[package] = (selection, None, None)
            return [{'file': package + '/production.go',
                     'name': 'Changed', 'hash': package,
                     'start': 1, 'end': 2, 'recv': ''}]

        def covered(_root, package, _mode, origin='current tree',
                    config=None):
            advance(origin + '-coverage', package, 20)
            return []

        conservative.reset_selection()
        self.addCleanup(conservative.reset_selection)
        config = {
            'critical_paths': ['pkg/**'],
            'build_tags': [''],
            'budget': {'schema_version': 1, 'seconds_per_package': {
                'unit': 300, 'fuzz': 420, 'mutation': 300,
            }},
        }
        with (
            mock.patch.object(conservative.time, 'monotonic',
                              side_effect=lambda: clock['now']),
            mock.patch.object(scope, 'selector_mode',
                              return_value=scope.CONSERVATIVE),
            mock.patch.object(conservative, 'packages',
                              return_value=['pkg/a', 'pkg/b']),
            mock.patch.object(source, 'changes',
                              return_value=['pkg/a/a.go', 'pkg/b/b.go']),
            mock.patch.object(source, 'archive', side_effect=archive),
            mock.patch.object(scope, 'package_files',
                              side_effect=lambda _root, package:
                              [package + '/production.go']),
            mock.patch.object(conservative, 'changed_functions',
                              side_effect=changed),
            mock.patch.object(conservative, 'covered_functions',
                              side_effect=covered),
            mock.patch.object(conservative, 'baseline_record',
                              return_value=(None, None)),
            mock.patch.object(conservative, 'widen_cross_package'),
        ):
            selected = scope.targets(Path('/fixture/current'), 'base', config)
            self.assertEqual(sorted(selected), ['pkg/a', 'pkg/b'])
            self.assertEqual(clock['events'], [
                ('archive', 'shared', 10),
                ('package-scan', 'pkg/a', 10),
                ('package-scan', 'pkg/b', 10),
                ('archive', 'shared', 10),
                ('base tree-coverage', 'pkg/a', 20),
                ('current tree-coverage', 'pkg/a', 20),
                ('archive', 'shared', 10),
                ('base tree-coverage', 'pkg/b', 20),
                ('current tree-coverage', 'pkg/b', 20),
            ])
            # Each package pays the one shared archive (10s), its own scan
            # (10s), its own baseline archive (10s), and its two coverage
            # profiles (40s): 70s of its versioned 300s budget.
            self.assertEqual(conservative.UNIT_REMAINDERS[
                ('pkg/a', 'unit')], 230)
            self.assertEqual(conservative.UNIT_REMAINDERS[
                ('pkg/b', 'unit')], 230)
            self.assertFalse(conservative.DEADLINES)

            # The normal unit phase resumes only its own bank; executing one
            # package cannot spend the other package's saved remainder.
            deadline_a = conservative.resume_unit_deadline('pkg/a', 300)
            self.assertEqual(
                conservative.resume_unit_deadline('pkg/a', 300), deadline_a,
                'repeated resume reset the active package deadline')
            self.assertEqual(deadline_a - clock['now'], 230)
            clock['now'] += 20
            conservative.pause_unit_budget('pkg/a')
            self.assertEqual(conservative.UNIT_REMAINDERS[
                ('pkg/a', 'unit')], 210)
            self.assertEqual(conservative.UNIT_REMAINDERS[
                ('pkg/b', 'unit')], 230)


if __name__ == '__main__':
    unittest.main()
