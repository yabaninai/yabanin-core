# SPDX-License-Identifier: Apache-2.0
"""Critical scope follows production declarations and build modes."""
import os
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
        # These controls assert the legacy selector reached only through the
        # explicit CRITICAL_SCOPE_SELECTOR=legacy override; pin the mode so an
        # ambient value cannot change what they verify.
        self.previous_mode = os.environ.get(critical_scope.MODE_ENV)
        os.environ[critical_scope.MODE_ENV] = critical_scope.LEGACY
        if self.previous_mode is None:
            self.addCleanup(os.environ.pop, critical_scope.MODE_ENV, None)
        else:
            self.addCleanup(os.environ.__setitem__, critical_scope.MODE_ENV, self.previous_mode)

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


class ConservativeScopeControls(unittest.TestCase):
    """Default conservative selector: binding over widening, never silent."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='critical-conservative-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pkg = self.root / 'pkg/auth'
        self.pkg.mkdir(parents=True)
        (self.root / 'go.mod').write_text('module example.test/critical\n\ngo 1.27.4\n')
        (self.pkg / 'auth.go').write_text(
            'package auth\n\nconst Limit = 5\n\n'
            'func Allowed(n int) bool { return n > Limit }\n\n'
            'func Neighbor() bool { return true }\n\n'
            'func Guarded(n int) bool { return n > 0 }\n')
        (self.pkg / 'state.go').write_text('package auth\n\nvar state = false\n')
        (self.pkg / 'auth_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func TestAllowed(t *testing.T) { if !Allowed(1) { t.Fatal("denied") } }\n')
        (self.pkg / 'fuzz_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func FuzzAllowed(f *testing.F) {\n\tf.Add("")\n\tf.Fuzz(func(t *testing.T, in string) { Allowed(len(in)) })\n}\n')
        (self.pkg / 'guarded_fuzz_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func FuzzGuarded(f *testing.F) {\n\tf.Add(1)\n\tf.Fuzz(func(t *testing.T, n int) { Guarded(n) })\n}\n')
        corpus = self.pkg / 'testdata/fuzz/FuzzAllowed'
        corpus.mkdir(parents=True)
        (corpus / 'entry1').write_text('go test fuzz v1\nseed')
        for argv in (['init', '-q'], ['add', '.'], ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'base']):
            subprocess.run(['git', *argv], cwd=self.root, check=True, capture_output=True)
        self.base = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=self.root, text=True).strip()
        self.previous_mode = os.environ.get(critical_scope.MODE_ENV)
        os.environ[critical_scope.MODE_ENV] = critical_scope.CONSERVATIVE
        if self.previous_mode is None:
            self.addCleanup(os.environ.pop, critical_scope.MODE_ENV, None)
        else:
            self.addCleanup(os.environ.__setitem__, critical_scope.MODE_ENV, self.previous_mode)

    def selected(self):
        return critical_scope.targets(self.root, self.base, {'critical_paths': ['pkg/auth/**']})

    def names(self):
        return {fn['name'] for fn in self.selected()['pkg/auth']}

    def reasons(self):
        return critical_scope.selection_evidence()['pkg/auth']['reasons']

    def commit(self, message):
        subprocess.run(['git', 'add', '.'], cwd=self.root, check=True, capture_output=True)
        subprocess.run(['git', 'commit', '-qm', message], cwd=self.root, check=True, capture_output=True)
        self.base = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=self.root, text=True).strip()

    def test_changed_body_selects_only_changed_function(self):
        (self.pkg / 'auth.go').write_text((self.pkg / 'auth.go').read_text().replace('n > Limit', 'n >= Limit'))
        self.assertEqual(self.names(), {'Allowed'})

    def test_comment_only_edit_selects_nothing(self):
        (self.pkg / 'auth.go').write_text((self.pkg / 'auth.go').read_text().replace('func Allowed', '// note\nfunc Allowed'))
        self.assertFalse(self.selected())

    def test_removed_test_selects_former_consumers(self):
        (self.pkg / 'auth_test.go').unlink()
        self.assertEqual(self.names(), {'Allowed'})
        self.assertIn('removed test coverage: TestAllowed', self.reasons()['Allowed'])

    def test_unrelated_test_addition_narrows_selection(self):
        (self.pkg / 'neighbor_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func TestNeighbor(t *testing.T) { Neighbor() }\n')
        self.assertEqual(self.names(), {'Neighbor'})

    def test_new_test_target_without_consumers_widens(self):
        (self.pkg / 'void_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func TestNothing(t *testing.T) { t.Log("nothing") }\n')
        self.assertEqual(self.names(), {'Allowed', 'Neighbor', 'Guarded'})
        self.assertTrue(self.reasons()['*'])

    def test_removed_test_without_consumers_widens(self):
        (self.pkg / 'void_test.go').write_text(
            'package auth\n\nimport "testing"\n\nfunc TestVoid(t *testing.T) {}\n')
        self.commit('void target')
        (self.pkg / 'void_test.go').unlink()
        self.assertEqual(self.names(), {'Allowed', 'Neighbor', 'Guarded'})
        self.assertTrue(self.reasons()['*'])

    def test_helper_weakening_keeps_binding_narrow(self):
        (self.pkg / 'auth_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func help() bool { return Allowed(2) }\n\n'
            'func TestAllowed(t *testing.T) { if !help() { t.Fatal("denied") } }\n')
        self.commit('helper')
        (self.pkg / 'auth_test.go').write_text((self.pkg / 'auth_test.go').read_text().replace('Allowed(2)', 'Allowed(3)'))
        self.assertEqual(self.names(), {'Allowed'})

    def test_helper_dropping_reference_widens(self):
        (self.pkg / 'auth_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func help() bool { return Allowed(2) }\n\n'
            'func TestAllowed(t *testing.T) { if !help() { t.Fatal("denied") } }\n')
        self.commit('helper')
        (self.pkg / 'auth_test.go').write_text((self.pkg / 'auth_test.go').read_text().replace('return Allowed(2)', 'return true'))
        self.assertEqual(self.names(), {'Allowed', 'Neighbor', 'Guarded'})
        self.assertTrue(any('baseline coverage' in reason for reason in self.reasons()['Allowed']))

    def test_global_state_reference_widens(self):
        (self.pkg / 'state_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func TestState(t *testing.T) { if state { t.Fatal("set") } }\n')
        self.assertEqual(self.names(), {'Allowed', 'Neighbor', 'Guarded'})

    def test_indirect_dispatch_reference_widens(self):
        (self.pkg / 'dispatch_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func TestDispatch(t *testing.T) {\n'
            '\tvar h struct{ Allowed func(int) bool }\n'
            '\th.Allowed(1)\n}\n')
        self.assertEqual(self.names(), {'Allowed', 'Neighbor', 'Guarded'})

    def test_interface_declaration_change_widens(self):
        (self.pkg / 'hook.go').write_text('package auth\n\ntype Hook interface{ Run() }\n')
        self.assertEqual(self.names(), {'Allowed', 'Neighbor', 'Guarded'})

    def test_blank_import_widens(self):
        (self.pkg / 'auth.go').write_text(
            'package auth\n\nimport _ "embed"\n\nconst Limit = 5\n\n'
            'func Allowed(n int) bool { return n > Limit }\n\n'
            'func Neighbor() bool { return true }\n\n'
            'func Guarded(n int) bool { return n > 0 }\n')
        self.assertEqual(self.names(), {'Allowed', 'Neighbor', 'Guarded'})

    def test_const_change_selects_consumers(self):
        (self.pkg / 'auth.go').write_text((self.pkg / 'auth.go').read_text().replace('Limit = 5', 'Limit = 6'))
        self.assertEqual(self.names(), {'Allowed'})
        self.assertIn('changed constant consumer: Limit', self.reasons()['Allowed'])

    def test_unexported_const_without_consumers_fails(self):
        (self.pkg / 'auth.go').write_text(
            (self.pkg / 'auth.go').read_text().replace('const Limit = 5', 'const Limit = 5\n\nconst unused = 7'))
        with self.assertRaises(ValueError):
            self.selected()

    def test_exported_const_without_consumers_widens(self):
        (self.pkg / 'auth.go').write_text(
            (self.pkg / 'auth.go').read_text().replace('const Limit = 5', 'const Limit = 5\n\nconst ExportedUnused = 7'))
        self.assertEqual(self.names(), {'Allowed', 'Neighbor', 'Guarded'})

    def test_last_fuzz_target_removal_fails(self):
        (self.pkg / 'fuzz_test.go').unlink()
        (self.pkg / 'guarded_fuzz_test.go').unlink()
        with self.assertRaises(ValueError):
            self.selected()

    def test_one_fuzz_target_removed_selects_its_coverage(self):
        (self.pkg / 'fuzz_test.go').unlink()
        self.assertEqual(self.names(), {'Allowed'})
        self.assertIn('fuzz target removed: FuzzAllowed',
                      critical_scope.selection_evidence()['pkg/auth']['guards'])

    def test_fuzz_corpus_change_widens(self):
        (self.pkg / 'testdata/fuzz/FuzzAllowed/entry1').unlink()
        self.assertEqual(self.names(), {'Allowed', 'Neighbor', 'Guarded'})
        self.assertIn('fuzz corpus change', self.reasons()['*'][0])

    def test_shared_testdata_change_widens(self):
        (self.pkg / 'testdata/config.json').write_text('{"v": 2}\n')
        self.assertEqual(self.names(), {'Allowed', 'Neighbor', 'Guarded'})

    def test_build_directive_change_selects_file_functions(self):
        (self.pkg / 'auth.go').write_text('//go:build linux\n\n' + (self.pkg / 'auth.go').read_text())
        self.assertEqual(self.names(), {'Allowed', 'Neighbor', 'Guarded'})
        self.assertIn('build directives changed', self.reasons()['Allowed'][0])

    def test_move_within_package_stays_unselected(self):
        text = (self.pkg / 'auth.go').read_text()
        (self.pkg / 'auth.go').write_text(text.replace('func Guarded(n int) bool { return n > 0 }\n', ''))
        (self.pkg / 'moved.go').write_text('package auth\n\nfunc Guarded(n int) bool { return n > 0 }\n')
        self.assertFalse(self.selected())

    def test_duplicated_function_selected(self):
        (self.pkg / 'moved.go').write_text(
            'package auth\n\nfunc Allowed(n int) bool { return n > Limit }\n')
        self.assertEqual(self.names(), {'Allowed'})

    def test_removed_state_file_widens(self):
        (self.pkg / 'state.go').unlink()
        self.assertEqual(self.names(), {'Allowed', 'Neighbor', 'Guarded'})

    def test_stale_base_selects_everything(self):
        empty_tree = subprocess.check_output(['git', 'hash-object', '-t', 'tree', '/dev/null'],
                                             text=True).strip()
        self.base = empty_tree
        self.assertEqual(self.names(), {'Allowed', 'Neighbor', 'Guarded'})

    def test_default_mode_is_conservative(self):
        os.environ.pop(critical_scope.MODE_ENV, None)
        (self.pkg / 'neighbor_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func TestNeighbor(t *testing.T) { Neighbor() }\n')
        self.assertEqual(self.names(), {'Neighbor'})

    def test_explicit_legacy_override_selects_package(self):
        os.environ[critical_scope.MODE_ENV] = critical_scope.LEGACY
        (self.pkg / 'neighbor_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func TestNeighbor(t *testing.T) { Neighbor() }\n')
        self.assertEqual(self.names(), {'Allowed', 'Neighbor', 'Guarded'})

    def test_invalid_mode_value_fails(self):
        os.environ[critical_scope.MODE_ENV] = 'aggressive'
        with self.assertRaisesRegex(ValueError, 'aggressive'):
            self.selected()

    def test_body_swap_selects_both_functions(self):
        (self.pkg / 'auth.go').write_text(
            'package auth\n\nconst Limit = 5\n\n'
            'func Allowed(n int) bool { return n > 0 }\n\n'
            'func Neighbor() bool { return true }\n\n'
            'func Guarded(n int) bool { return n > Limit }\n')
        self.assertEqual(self.names(), {'Allowed', 'Guarded'})
        self.assertIn('changed function: Allowed', self.reasons()['Allowed'])
        self.assertIn('changed function: Guarded', self.reasons()['Guarded'])

    def test_renamed_function_selects_new_name(self):
        (self.pkg / 'auth.go').write_text(
            'package auth\n\nconst Limit = 5\n\n'
            'func Allowed(n int) bool { return n > Limit }\n\n'
            'func Neighbor() bool { return true }\n\n'
            'func GuardedRenamed(n int) bool { return n > 0 }\n')
        (self.pkg / 'guarded_fuzz_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func FuzzGuarded(f *testing.F) {\n\tf.Add(1)\n'
            '\tf.Fuzz(func(t *testing.T, n int) { GuardedRenamed(n) })\n}\n')
        self.assertEqual(self.names(), {'GuardedRenamed'})
        self.assertIn('renamed/moved function: GuardedRenamed', self.reasons()['GuardedRenamed'])

    def test_build_tagged_out_test_targets_fail(self):
        for name in ('auth_test.go', 'fuzz_test.go', 'guarded_fuzz_test.go'):
            path = self.pkg / name
            path.write_text('//go:build probe_ignore\n\n' + path.read_text())
        with self.assertRaisesRegex(ValueError, 'fuzz target coverage loss'):
            critical_scope.targets(self.root, self.base,
                                   {'critical_paths': ['pkg/auth/**'], 'build_tags': ['']})

    def test_platform_renamed_test_targets_fail(self):
        (self.pkg / 'fuzz_test.go').rename(self.pkg / 'fuzz_windows_test.go')
        (self.pkg / 'guarded_fuzz_test.go').rename(self.pkg / 'guarded_windows_test.go')
        with self.assertRaises(ValueError):
            critical_scope.targets(self.root, self.base,
                                   {'critical_paths': ['pkg/auth/**'], 'build_tags': ['']})

    def test_platform_moved_unit_test_fails(self):
        (self.pkg / 'auth_test.go').rename(self.pkg / 'auth_windows_test.go')
        with self.assertRaisesRegex(ValueError, 'unit-test coverage loss'):
            critical_scope.targets(self.root, self.base,
                                   {'critical_paths': ['pkg/auth/**'], 'build_tags': ['']})

    def test_partial_unit_test_move_fails(self):
        (self.pkg / 'neighbor_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func TestNeighbor(t *testing.T) { Neighbor() }\n')
        self.commit('two unit tests')
        block = 'func TestAllowed(t *testing.T) { if !Allowed(1) { t.Fatal("denied") } }\n'
        (self.pkg / 'auth_test.go').write_text('package auth\n\nimport "testing"\n\n')
        (self.pkg / 'auth_windows_test.go').write_text(
            'package auth\n\nimport "testing"\n\n' + block)
        with self.assertRaisesRegex(ValueError,
                                    r'unit-test coverage loss.*TestAllowed'):
            critical_scope.targets(self.root, self.base,
                                   {'critical_paths': ['pkg/auth/**'], 'build_tags': ['']})

    def test_build_tagged_out_unit_tests_fail(self):
        path = self.pkg / 'auth_test.go'
        path.write_text('//go:build probe_ignore\n\n' + path.read_text())
        with self.assertRaisesRegex(ValueError, 'unit-test coverage loss'):
            critical_scope.targets(self.root, self.base,
                                   {'critical_paths': ['pkg/auth/**'], 'build_tags': ['']})

    def test_partial_fuzz_target_move_fails(self):
        (self.pkg / 'fuzz_windows_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func FuzzAllowed(f *testing.F) {\n\tf.Add("")\n\tf.Fuzz(func(t *testing.T, in string) { Allowed(len(in)) })\n}\n')
        (self.pkg / 'fuzz_test.go').unlink()
        with self.assertRaisesRegex(ValueError,
                                    r'fuzz target coverage loss.*FuzzAllowed'):
            critical_scope.targets(self.root, self.base,
                                   {'critical_paths': ['pkg/auth/**'], 'build_tags': ['']})

    def test_changed_test_keeps_baseline_consumers_selected(self):
        (self.pkg / 'auth_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func TestAllowed(t *testing.T) { if !Neighbor() { t.Fatal("denied") } }\n')
        self.assertEqual(self.names(), {'Allowed', 'Neighbor'})
        self.assertIn('lost baseline coverage: TestAllowed', self.reasons()['Allowed'])

    def test_removed_function_still_referenced_by_test_widens(self):
        (self.pkg / 'auth.go').write_text(
            'package auth\n\nconst Limit = 5\n\n'
            'func Allowed(n int) bool { return n > Limit }\n\n'
            'func Neighbor() bool { return true }\n')
        self.assertEqual(self.names(), {'Allowed', 'Neighbor'})
        self.assertTrue(any('removed function still referenced' in reason
                            for reason in self.reasons()['*']))

    def test_reflect_dispatch_literal_blocks_silent_removal(self):
        (self.pkg / 'dispatch_test.go').write_text(
            'package auth\n\nimport (\n\t"reflect"\n\t"testing"\n)\n\n'
            'type holder struct{}\n\n'
            'func TestDispatch(t *testing.T) { reflect.ValueOf(holder{}).MethodByName("Guarded") }\n')
        self.commit('dispatch baseline')
        (self.pkg / 'auth.go').write_text(
            'package auth\n\nconst Limit = 5\n\n'
            'func Allowed(n int) bool { return n > Limit }\n\n'
            'func Neighbor() bool { return true }\n')
        self.assertEqual(self.names(), {'Allowed', 'Neighbor'})
        self.assertTrue(any('removed function in dynamic-dispatch package' in reason
                            for reason in self.reasons()['*']))


class CrossPackageConservativeControls(unittest.TestCase):
    """Default conservative selector: cross-package consumers are never silent."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='critical-cross-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        hook = self.root / 'pkg/hook'
        hook.mkdir(parents=True)
        (self.root / 'go.mod').write_text('module example.test/critical\n\ngo 1.27.4\n')
        (hook / 'hook.go').write_text(
            'package hook\n\ntype Hook interface {\n\tRun(n int) bool\n}\n\n'
            'func Apply(h Hook, n int) bool { return h.Run(n) }\n')
        user = self.root / 'pkg/hookuser'
        user.mkdir(parents=True)
        (user / 'use.go').write_text(
            'package hookuser\n\nimport "example.test/critical/pkg/hook"\n\n'
            'type adapter struct{}\n\n'
            'func (adapter) Run(n int) bool { return n > 0 }\n\n'
            'func Enabled(n int) bool { return hook.Apply(adapter{}, n) }\n')
        for argv in (['init', '-q'], ['add', '.'],
                     ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                      'commit', '-qm', 'base']):
            subprocess.run(['git', *argv], cwd=self.root, check=True, capture_output=True)
        self.base = subprocess.check_output(['git', 'rev-parse', 'HEAD'],
                                            cwd=self.root, text=True).strip()
        self.previous_mode = os.environ.get(critical_scope.MODE_ENV)
        os.environ[critical_scope.MODE_ENV] = critical_scope.CONSERVATIVE
        if self.previous_mode is None:
            self.addCleanup(os.environ.pop, critical_scope.MODE_ENV, None)
        else:
            self.addCleanup(os.environ.__setitem__, critical_scope.MODE_ENV, self.previous_mode)

    def test_changed_interface_widens_importing_package(self):
        (self.root / 'pkg/hook/hook.go').write_text(
            'package hook\n\ntype Hook interface {\n\tRun(n int) bool\n\tName() string\n}\n\n'
            'func Apply(h Hook, n int) bool { return h.Run(n) }\n')
        selected = critical_scope.targets(self.root, self.base,
                                          {'critical_paths': ['pkg/hook/**', 'pkg/hookuser/**']})
        self.assertEqual({fn['name'] for fn in selected['pkg/hookuser']}, {'Enabled', 'Run'})
        evidence = critical_scope.selection_evidence()['pkg/hookuser']
        self.assertTrue(any('cross-package consumer of changed declaration' in reason
                            for reason in evidence['reasons']['*']))

    def test_unchanged_interface_leaves_importer_unselected(self):
        (self.root / 'pkg/hook/hook.go').write_text(
            'package hook\n\ntype Hook interface {\n\tRun(n int) bool\n}\n\n'
            'func Apply(h Hook, n int) bool { return h.Run(n) && n > 0 }\n')
        selected = critical_scope.targets(self.root, self.base,
                                          {'critical_paths': ['pkg/hook/**', 'pkg/hookuser/**']})
        self.assertNotIn('pkg/hookuser', selected)


if __name__ == '__main__':
    unittest.main()
