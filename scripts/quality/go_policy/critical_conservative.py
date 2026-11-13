# SPDX-License-Identifier: Apache-2.0
"""Conservative impact selection for critical Go packages (opt-in variant).

The legacy selector in critical_scope.py binds to changed function hashes and
forces whole packages on any declaration or test change. This variant keeps
that hash binding and adds declaration-level resolution: test edits bind to
the production functions they actually cover, declaration changes bind
through consumer references, corpus and testdata edits select their package,
and removal of the last fuzz target of a critical package fails instead of
letting the gate become silently not applicable. Every case the binding
cannot resolve widens to all production functions of the package.
"""
from collections import Counter
import json
import os
from pathlib import Path
import subprocess

import policy
import source

TEST_PREFIXES = ('Test', 'Fuzz', 'Benchmark', 'Example')

# Per-run binding evidence for report.json; cleared when selection starts.
EVIDENCE = {'packages': {}}


def unit_rows(root, paths, helper):
    """Full per-file unit rows including directive digests.

    policy.unit_maps keeps only units and drops the per-file directive
    digest; conservative selection is declaration-driven and needs both.
    """
    if not paths:
        return []
    proc = subprocess.run(['go', 'run', str(helper)], cwd=root,
                          input=json.dumps(sorted(paths)), text=True,
                          capture_output=True, timeout=120, check=True,
                          env=dict(os.environ, GOWORK='off', GOFLAGS=''))
    return json.loads(proc.stdout)


def packages(root, base, patterns):
    """Legacy package rule plus testdata-driven selection.

    A change under <package>/testdata/ never changes a .go file, so the
    legacy rule cannot see corpus and shared-fixture edits at all.
    """
    import critical_scope as scope
    selected = set()
    for path in source.changes(root, base):
        parts = Path(path).parts
        if 'testdata' in parts:
            package = '/'.join(parts[:parts.index('testdata')])
            if scope.is_critical(package + '/probe.go', patterns):
                selected.add(package)
        elif scope.is_critical(path, patterns):
            selected.add(str(Path(path).parent))
    return sorted(selected)


class Side:
    """Indexed view of one package snapshot (current tree or baseline)."""

    def __init__(self, rows):
        self.files = {row['path']: row for row in rows}
        self.production = sorted(p for p in self.files if not p.endswith('_test.go'))
        self.tests = sorted(p for p in self.files if p.endswith('_test.go'))

    def functions(self):
        """All production function units with their file, in stable order."""
        rows = []
        for path in self.production:
            rows.extend(dict(u, file=path) for u in self.files[path]['units'] if u['name'])
        return rows

    def declarations(self, path):
        return [u for u in self.files[path]['units'] if not u['name']]

    def test_units(self):
        rows = []
        for path in self.tests:
            rows.extend(dict(u, file=path) for u in self.files[path]['units'] if u['name'])
        return rows


class Selection:
    """Accumulates selected production functions, reasons and widenings."""

    def __init__(self, package):
        self.package = package
        self.rows = {}
        self.reasons = {}
        self.widenings = []
        self.guards = []

    def add(self, row, reason):
        self.rows.setdefault((row['file'], row['name']), row)
        note = self.reasons.setdefault(row['name'], [])
        if reason not in note:
            note.append(reason)

    def widen(self, reason):
        if reason not in self.widenings:
            self.widenings.append(reason)


def changed_functions(root, baseline, package, helper, changes):
    """Conservative counterpart of critical_scope.changed_functions."""
    under = {p for p in changes if p == package or p.startswith(package + '/')}
    changed_files = {p for p in under if str(Path(p).parent) == package}
    current = Side(unit_rows(root, [p for p in source.files(root)
                                    if str(Path(p).parent) == package and p.endswith('.go')
                                    and (root / p).is_file()], helper))
    previous = Side(unit_rows(baseline, [p.relative_to(baseline).as_posix()
                                         for p in sorted((baseline / package).glob('*.go'))], helper))
    selection = Selection(package)
    guard_last_fuzz_target(previous, current, package, selection)
    apply_testdata_changes(under, selection)
    production_changes(previous, current, changed_files, selection)
    test_changes(previous, current, changed_files, selection)
    return selection_result(selection, current, package)


def guard_last_fuzz_target(previous, current, package, selection):
    before = {u['name'] for u in previous.test_units() if u['name'].startswith('Fuzz')}
    after = {u['name'] for u in current.test_units() if u['name'].startswith('Fuzz')}
    removed = sorted(before - after)
    if before and not after:
        raise ValueError('Last critical fuzz target removed; gate would be silently '
                         'not applicable: ' + package + ' (' + ', '.join(removed) + ')')
    selection.guards.extend('fuzz target removed: ' + name for name in removed)


def apply_testdata_changes(changed_files, selection):
    for path in sorted(changed_files):
        parts = Path(path).parts
        if 'testdata' not in parts:
            continue
        rest = parts[parts.index('testdata'):]
        if len(rest) >= 2 and rest[1] == 'fuzz':
            selection.widen('fuzz corpus change: ' + path)
        else:
            selection.widen('shared testdata fixture change: ' + path)


def production_changes(previous, current, changed_files, selection):
    counts = Counter(row['hash'] for row in previous.functions())
    names_before = {row['name'] for row in previous.functions()}
    for row in current.functions():
        if counts[row['hash']] > 0:
            counts[row['hash']] -= 1
            continue
        selection.add(row, ('new function: ' if row['name'] not in names_before
                            else 'changed function: ') + row['name'])
    for path in current.production:
        old = previous.files.get(path)
        if old is None:
            # Function-level binding above already selects only functions
            # unknown on the baseline side, preserving move tolerance.
            classify_declarations(current, path, {}, 'new', selection)
            continue
        if path not in changed_files:
            continue
        if current.files[path].get('directives', '') != old.get('directives', ''):
            for row in current.functions():
                if row['file'] == path:
                    selection.add(row, 'build directives changed: ' + path)
        old_symbols = {s: u for u in old['units'] if not u['name'] for s in u.get('symbols', [])}
        classify_declarations(current, path, old_symbols, 'changed', selection)
    for path in previous.production:
        if path in current.files:
            continue
        for unit in previous.declarations(path):
            if unit.get('kind') in ('var', 'type'):
                selection.widen('removed ' + unit.get('kind', 'declaration') + ': ' +
                                ','.join(unit.get('symbols', [])))


def classify_declarations(current, path, old_symbols, state, selection):
    functions = current.functions()
    current_symbols = {s for u in current.declarations(path) for s in u.get('symbols', [])}
    for unit in current.declarations(path):
        symbols = unit.get('symbols', [])
        kind = unit.get('kind', '')
        label = ','.join(symbols)
        if any(s in old_symbols and old_symbols[s]['hash'] == unit['hash'] for s in symbols):
            continue
        if kind == 'var':
            selection.widen(state + ' global state: ' + label)
        elif kind == 'type':
            selection.widen(state + ' type: ' + label)
        elif 'interface' in unit.get('flags', []) or 'func_type' in unit.get('flags', []):
            selection.widen(state + ' indirect-dispatch declaration: ' + label)
        elif kind == 'import' and ('_' in symbols or '.' in symbols):
            selection.widen(state + ' blank/dot import: ' + path)
        elif kind == 'import':
            for row in functions:
                if row['file'] == path:
                    selection.add(row, 'import set changed: ' + path)
        elif kind == 'const':
            const_consumers(symbols, current, selection, state)
    for symbol, unit in old_symbols.items():
        if symbol not in current_symbols and unit.get('kind') in ('var', 'type'):
            selection.widen('removed ' + unit.get('kind', 'declaration') + ': ' + symbol)


def const_consumers(symbols, current, selection, state):
    """Select functions bound to a changed constant, through const chains."""
    reach, frontier = set(symbols), list(symbols)
    while frontier:
        name = frontier.pop()
        for path in current.production:
            for unit in current.declarations(path):
                fresh = set(unit.get('symbols', [])) - reach
                if fresh and name in unit.get('refs', []):
                    reach.update(fresh)
                    frontier.extend(fresh)
    label = ','.join(symbols)
    consumers = [row for row in current.functions() if reach & set(row.get('refs', []))]
    if consumers:
        for row in consumers:
            selection.add(row, state + ' constant consumer: ' + label)
        return
    if symbols[0][:1].islower():
        raise ValueError('Unexported constant change without production consumers needs '
                         'an explicit coverage decision: ' + selection.package + ':' + label)
    selection.widen(state + ' exported constant without in-package consumers: ' + label)


def test_changes(previous, current, changed_files, selection):
    functions = current.functions()
    names = {row['name'] for row in functions}
    state_vars = set()
    for path in current.production:
        for unit in current.declarations(path):
            if unit.get('kind') == 'var':
                state_vars.update(unit.get('symbols', []))
    for path in current.tests:
        old = previous.files.get(path)
        if path in changed_files and old is not None and \
                current.files[path].get('directives', '') != old.get('directives', ''):
            selection.widen('test build directives changed: ' + path)
    before = {u['name']: u for u in previous.test_units()}
    counts = Counter((u['name'], u['hash']) for u in previous.test_units())
    for unit in current.test_units():
        if counts[(unit['name'], unit['hash'])] > 0:
            counts[(unit['name'], unit['hash'])] -= 1
            continue
        if unit['name'].startswith(TEST_PREFIXES):
            reason = ('changed test target: ' if unit['name'] in before
                      else 'new test target: ') + unit['name']
            bind_target(unit, reason, current, functions, names, state_vars, selection)
        else:
            previous_unit = before.get(unit['name'])
            if previous_unit:
                # A weakened helper may drop references; whatever it covered
                # on the baseline side stays explicitly selected.
                for row in functions:
                    if row['name'] in set(previous_unit.get('refs', [])):
                        selection.add(row, 'test helper changed: ' + unit['name'] +
                                      ' (baseline coverage)')
            callers = [name for name in helper_callers(unit['name'], current)
                       if name.startswith(TEST_PREFIXES)]
            for name in callers:
                target = next(u for u in current.test_units() if u['name'] == name)
                bind_target(target, 'test helper changed: ' + unit['name'] + ' → ' + name,
                            current, functions, names, state_vars, selection)
    after = {u['name'] for u in current.test_units()}
    for name, unit in before.items():
        if name in after:
            continue
        if not name.startswith(TEST_PREFIXES):
            for row in functions:
                if row['name'] in set(unit.get('refs', [])):
                    selection.add(row, 'removed test helper: ' + name)
            continue
        covered = {r for r in unit.get('refs', []) if r in names}
        for row in functions:
            if row['name'] in covered:
                selection.add(row, 'removed test coverage: ' + name)
        if not covered:
            selection.widen('removed test target without bindable consumer: ' + name)


def helper_callers(helper, current):
    """Test units transitively referencing a helper, matched by name only."""
    affected, frontier = set(), [helper]
    while frontier:
        name = frontier.pop()
        for unit in current.test_units():
            if name in unit.get('refs', []) and unit['name'] not in affected:
                affected.add(unit['name'])
                if not unit['name'].startswith(TEST_PREFIXES):
                    frontier.append(unit['name'])
    return affected


def bind_target(unit, reason, current, functions, names, state_vars, selection):
    """Bind one test target to the production functions it covers.

    Binding closes transitively through test helpers, so weakening a helper
    selects the production functions behind every affected target. Selector-
    position references to a function name may be indirect dispatch, any
    reference to package state cannot be rolled back textually, and an empty
    consumer set cannot be shown safe; all three widen instead of guessing.
    """
    refs, selrefs = target_closure(unit, current)
    if state_vars & refs:
        selection.widen(reason + ' references global state')
        return
    if selrefs & names:
        selection.widen(reason + ' references indirect dispatch')
        return
    consumers = [row for row in functions if row['name'] in refs]
    if not consumers:
        selection.widen(reason + ' has no bindable production consumer')
        return
    for row in consumers:
        selection.add(row, reason)


def target_closure(unit, current):
    """References reachable from a test target through test-file helpers."""
    helpers = {u['name']: u for u in current.test_units()
               if not u['name'].startswith(TEST_PREFIXES)}
    seen, frontier = {unit['name']}, [unit]
    refs, selrefs = set(), set()
    while frontier:
        item = frontier.pop()
        refs.update(item.get('refs', []))
        selrefs.update(item.get('selrefs', []))
        for name in item.get('refs', []):
            helper = helpers.get(name)
            if helper and helper['name'] not in seen:
                seen.add(helper['name'])
                frontier.append(helper)
    return refs, selrefs


def selection_result(selection, current, package):
    evidence = {'widened': selection.widenings or None, 'guards': selection.guards,
                'selected': [], 'reasons': {}}
    if selection.widenings:
        rows = current.functions()
        if not rows:
            raise ValueError('Widen selected no production function: ' + package +
                             ' (' + selection.widenings[0] + ')')
        evidence['selected'] = [row['file'] + ':' + row['name'] for row in rows]
        evidence['reasons'] = dict(selection.reasons, **{'*': selection.widenings})
    else:
        rows = [selection.rows[key] for key in sorted(selection.rows)]
        evidence['selected'] = [row['file'] + ':' + row['name'] for row in rows]
        evidence['reasons'] = selection.reasons
    EVIDENCE['packages'][package] = evidence
    return rows
