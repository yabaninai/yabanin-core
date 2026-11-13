# SPDX-License-Identifier: Apache-2.0
"""Conservative impact selection for critical Go packages (opt-in variant).

The legacy selector in critical_scope.py binds to changed function hashes and
forces whole packages on any declaration or test change. This variant keeps
that hash binding and adds declaration-level resolution: test edits bind to
the union of their baseline and current production coverage, declaration
changes bind through consumer references, corpus and testdata edits select
their package, and target completeness is guarded per build mode so a
constraint edit can no longer make every check silently not applicable.
Removed symbols widen while dynamic dispatch or surviving text can still
reach them, and cross-package declaration changes widen importing critical
packages. Every case the binding cannot resolve widens to all production
functions of the package.
"""
from collections import Counter, defaultdict
import json
import os
from pathlib import Path
import re
import subprocess

import policy
import source

TEST_PREFIXES = ('Test', 'Fuzz', 'Benchmark', 'Example')

# Per-run binding evidence for report.json; cleared when selection starts.
EVIDENCE = {'packages': {}}

# Live selections of packages already processed in this run; cross-package
# widening extends earlier selections instead of dropping them.
RUNS = {}


def reset_selection():
    """Clear per-run state before a new selection pass."""
    EVIDENCE['packages'] = {}
    RUNS.clear()


def unit_rows(root, paths, helper, modes=None):
    """Full per-file unit rows including directive digests.

    policy.unit_maps keeps only units and drops the per-file directive
    digest; conservative selection is declaration-driven and needs both.
    With modes (critical.json build_tags), every row also reports which
    build modes compile the file, so target guards count what a build
    actually sees.
    """
    if not paths:
        return []
    request = (sorted(paths) if modes is None else
               {'paths': sorted(paths), 'modes': [tags(mode) for mode in modes]})
    proc = subprocess.run(['go', 'run', str(helper)], cwd=root,
                          input=json.dumps(request), text=True,
                          capture_output=True, timeout=120, check=True,
                          env=dict(os.environ, GOWORK='off', GOFLAGS=''))
    return json.loads(proc.stdout)


def tags(mode):
    """One build mode from critical.json: '' or comma-separated tags."""
    return [tag.strip() for tag in mode.split(',') if tag.strip()]


def go_files(root, package):
    """Tracked .go files of a package in the current tree."""
    return [p for p in source.files(root)
            if str(Path(p).parent) == package and p.endswith('.go')
            and (root / p).is_file()]


def archived_files(baseline, package):
    """Archived snapshot files of a package (top level only)."""
    return [p.relative_to(baseline).as_posix()
            for p in sorted((baseline / package).glob('*.go'))]


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

    def __init__(self, rows, root):
        self.root = root
        self.files = {row['path']: row for row in rows}
        self.production = sorted(p for p in self.files if not p.endswith('_test.go'))
        self.tests = sorted(p for p in self.files if p.endswith('_test.go'))
        self.dispatch_names, self.dispatch_unresolved = dispatch_state(self)

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


def dispatch_state(side):
    """Literal dynamic-dispatch names and unresolved-dispatch presence."""
    names, unresolved = set(), False
    for path in sorted(side.files):
        for item in side.files[path]['units']:
            names.update(item.get('lits', []))
            unresolved = unresolved or 'dynamic_dispatch_unresolved' in item.get('flags', [])
    return names, unresolved


class Selection:
    """Accumulates selected production functions, reasons and widenings."""

    def __init__(self, package):
        self.package = package
        self.rows = {}
        self.reasons = {}
        self.widenings = []
        self.guards = []
        self.cross = []
        self.renames = {}

    def add(self, row, reason):
        self.rows.setdefault((row['file'], row['name']), row)
        note = self.reasons.setdefault(row['name'], [])
        if reason not in note:
            note.append(reason)

    def widen(self, reason):
        if reason not in self.widenings:
            self.widenings.append(reason)

    def mark_cross(self, label):
        """Record a declaration whose consumers may live in other packages."""
        if label not in self.cross:
            self.cross.append(label)


def changed_functions(root, baseline, package, helper, changes, build_tags=None):
    """Conservative counterpart of critical_scope.changed_functions."""
    under = {p for p in changes if p == package or p.startswith(package + '/')}
    changed_files = {p for p in under if str(Path(p).parent) == package}
    current = Side(unit_rows(root, go_files(root, package), helper, build_tags), root)
    previous = Side(unit_rows(baseline, archived_files(baseline, package), helper,
                              build_tags), baseline)
    selection = Selection(package)
    RUNS[package] = (selection, current)
    guard_targets(previous, current, build_tags, package, selection)
    apply_testdata_changes(under, selection)
    production_changes(previous, current, changed_files, selection)
    test_changes(previous, current, changed_files, selection)
    return selection_result(selection, current, package)


def guard_targets(previous, current, build_tags, package, selection):
    """Completeness guards run before any binding decision."""
    guard_last_fuzz_target(previous, current, package, selection)
    if not build_tags:
        return
    for index, mode in enumerate(build_tags):
        guard_target_coverage(previous, current, index, mode, package)


def guard_last_fuzz_target(previous, current, package, selection):
    before = {u['name'] for u in previous.test_units() if u['name'].startswith('Fuzz')}
    after = {u['name'] for u in current.test_units() if u['name'].startswith('Fuzz')}
    removed = sorted(before - after)
    if before and not after:
        raise ValueError('Last critical fuzz target removed; gate would be silently '
                         'not applicable: ' + package + ' (' + ', '.join(removed) + ')')
    selection.guards.extend('fuzz target removed: ' + name for name in removed)


def guard_target_coverage(previous, current, index, mode, package):
    """Reject per-build-mode loss of every fuzz or unit-test target.

    A file renamed or constraint-tagged out of one build mode keeps its
    names visible to parsing; only mode-aware counting exposes the loss.
    Test loss is tolerated while fuzz targets remain: the fuzz kind owns
    execution for fuzz-target packages.
    """
    before_fuzz, before_test = mode_targets(previous, index)
    after_fuzz, after_test = mode_targets(current, index)
    if before_fuzz and not after_fuzz:
        raise ValueError('Critical fuzz target coverage loss in build mode "' + mode +
                         '"; gate would be silently not applicable: ' + package)
    if before_test and not after_test and not after_fuzz:
        raise ValueError('Critical unit-test coverage loss in build mode "' + mode +
                         '"; gate would be silently not applicable: ' + package)


def mode_targets(side, index):
    """Fuzz and test target names visible to one build mode."""
    targets = {'Fuzz': set(), 'Test': set()}
    for path in side.tests:
        if applies(side, path, index):
            collect_targets(side.files[path]['units'], targets)
    return targets['Fuzz'], targets['Test']


def applies(side, path, index):
    """Whether a file participates in build mode index (all when None)."""
    if index is None:
        return True
    matched = side.files[path].get('matched', [])
    return bool(matched[index]) if index < len(matched) else False


def collect_targets(units, targets):
    for item in units:
        name = item.get('name', '')
        for prefix in targets:
            if name.startswith(prefix):
                targets[prefix].add(name)


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
    """Changed, new and removed production declarations."""
    match_functions(previous, current, selection)
    file_changes(previous, current, changed_files, selection)
    removed_symbols(previous, current, selection)


def match_functions(previous, current, selection):
    """Identity-first changed-function matching.

    A surviving (name, body-hash) pair is an unchanged function wherever it
    now lives. A surviving name over a different declaration is a changed
    function even when its body matches another baseline body, so a
    same-signature body swap selects both sides. An unseen name over a
    known body is a rename or move across files.
    """
    baseline = previous.functions()
    by_identity = Counter((row['name'], row['hash']) for row in baseline)
    bodies = defaultdict(list)
    for row in baseline:
        bodies[row['hash']].append(row['name'])
    names_before = {row['name'] for row in baseline}
    for row in current.functions():
        if spend(by_identity, (row['name'], row['hash'])):
            continue
        if row['name'] in names_before:
            selection.add(row, 'changed function: ' + row['name'])
        elif bodies[row['hash']]:
            moved = bodies[row['hash']].pop()
            selection.renames[moved] = row['name']
            selection.add(row, 'renamed/moved function: ' + row['name'])
        else:
            selection.add(row, 'new function: ' + row['name'])


def spend(counts, key):
    """Consume one multiset occurrence; False when exhausted or absent."""
    if counts[key] > 0:
        counts[key] -= 1
        return True
    return False


def file_changes(previous, current, changed_files, selection):
    """Declaration and directive changes of files surviving on both sides."""
    for path in current.production:
        old = previous.files.get(path)
        if old is None:
            classify_declarations(current, path, {}, 'new', selection)
            continue
        if path not in changed_files:
            continue
        note_directive_change(current, path, old, selection)
        classify_declarations(current, path, symbol_index(old), 'changed', selection)
    for path in previous.production:
        if path not in current.files:
            removed_file(previous, path, current, selection)


def note_directive_change(current, path, old, selection):
    """Build-directive edits reselect the file's functions."""
    if current.files[path].get('directives', '') == old.get('directives', ''):
        return
    for row in current.functions():
        if row['file'] == path:
            selection.add(row, 'build directives changed: ' + path)


def symbol_index(old):
    """Declaration units of one baseline file indexed by symbol."""
    return {symbol: unit for unit in old['units'] if not unit['name']
            for symbol in unit.get('symbols', [])}


def classify_declarations(current, path, old_symbols, state, selection):
    """Map declaration-level changes of one file to selection effects."""
    current_symbols = {s for u in current.declarations(path) for s in u.get('symbols', [])}
    for unit in current.declarations(path):
        if not declaration_unchanged(unit, old_symbols):
            note_declaration(current, path, unit, state, selection)
    for symbol, unit in old_symbols.items():
        if symbol not in current_symbols:
            note_removed_symbol(unit, symbol, current, selection)


def declaration_unchanged(unit, old_symbols):
    """One declaration-level hash hit preserves binding."""
    return any(old_symbols.get(s, {}).get('hash') == unit['hash']
               for s in unit.get('symbols', []))


def note_declaration(current, path, unit, state, selection):
    kind = unit.get('kind', '')
    symbols = unit.get('symbols', [])
    label = ','.join(symbols)
    if kind == 'var':
        selection.widen(state + ' global state: ' + label)
        selection.mark_cross('global state: ' + label)
    elif kind == 'type':
        selection.widen(state + ' type: ' + label)
        selection.mark_cross('type: ' + label)
    elif has_flag(unit, 'interface') or has_flag(unit, 'func_type'):
        selection.widen(state + ' indirect-dispatch declaration: ' + label)
        selection.mark_cross('indirect-dispatch: ' + label)
    elif kind == 'import' and ('_' in symbols or '.' in symbols):
        selection.widen(state + ' blank/dot import: ' + path)
    elif kind == 'import':
        note_import_change(current, path, selection)
    elif kind == 'const':
        const_consumers(symbols, current, selection, state)


def has_flag(unit, flag):
    return flag in unit.get('flags', [])


def note_import_change(current, path, selection):
    for row in current.functions():
        if row['file'] == path:
            selection.add(row, 'import set changed: ' + path)


def note_removed_symbol(unit, symbol, current, selection):
    """Removed declarations keep consumers visible, cross-package included."""
    kind = unit.get('kind', '')
    if kind == 'const':
        widen_removed_const(symbol, current, selection)
        return
    if kind in ('var', 'type'):
        selection.widen('removed ' + kind + ': ' + symbol)
        selection.mark_cross('removed ' + kind + ': ' + symbol)


def removed_file(previous, path, current, selection):
    """Declarations of a whole file deleted from the current side."""
    for unit in previous.files[path]['units']:
        note_removed_file_unit(unit, current, selection)


def note_removed_file_unit(unit, current, selection):
    kind = unit.get('kind', '')
    if unit.get('name') or kind not in ('var', 'type', 'const'):
        return
    for symbol in unit.get('symbols', []):
        note_removed_symbol({'kind': kind}, symbol, current, selection)


def const_consumers(symbols, current, selection, state):
    """Select functions bound to a changed constant, through const chains."""
    reach = const_reach(symbols, current)
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


def const_reach(symbols, current):
    """Constants transitively consuming any of symbols, within the package."""
    reach, frontier = set(symbols), list(symbols)
    while frontier:
        name = frontier.pop()
        for path in current.production:
            for unit in current.declarations(path):
                fresh = set(unit.get('symbols', [])) - reach
                if fresh and name in unit.get('refs', []):
                    reach.update(fresh)
                    frontier.extend(fresh)
    return reach


def removed_symbols(previous, current, selection):
    """Baseline production function names gone from the current side."""
    survivors = {row['name'] for row in current.functions()}
    for row in previous.functions():
        if row['name'] not in survivors:
            note_removed_function(row['name'], previous, current, selection)


def note_removed_function(name, previous, current, selection):
    """A removed function widens while dispatch or text can still reach it."""
    if dispatch_reference(name, previous, current):
        selection.widen('removed function in dynamic-dispatch package: ' + name)
        return
    files = referencing_files(name, previous, current)
    if files:
        selection.widen('removed function still referenced: ' + name +
                        ' (' + ', '.join(files) + ')')


def dispatch_reference(name, previous, current):
    """Whether dynamic member lookup could still reach a removed name."""
    if previous.dispatch_unresolved or current.dispatch_unresolved:
        return True
    return name in previous.dispatch_names or name in current.dispatch_names


def referencing_files(name, previous, current):
    """Baseline files referencing name that still mention it now."""
    return [path for path in sorted(previous.files)
            if path in current.files and name in unit_refs(previous.files[path]['units'])
            and mentions(current, path, name)]


def unit_refs(units):
    """Every plain and selector-position reference of a file's units."""
    refs = set()
    for item in units:
        refs.update(item.get('refs', []))
        refs.update(item.get('selrefs', []))
    return refs


def mentions(current, path, name):
    """Word-boundary identifier search in one file of a snapshot."""
    text = (current.root / path).read_text(errors='replace')
    return re.search(r'\b' + re.escape(name) + r'\b', text) is not None


def widen_removed_const(symbol, current, selection):
    """A removed constant widens only while a survivor still names it."""
    if any(mentions(current, path, symbol) for path in current.files):
        selection.widen('removed const still referenced: ' + symbol)


def test_changes(previous, current, changed_files, selection):
    """Bind test edits to the production coverage they affect.

    Binding is the union of current and baseline transitive consumers: a
    weakened assertion keeps the previously covered production functions
    selected even when the current test text no longer names them.
    """
    state_vars = global_state(current)
    for path in current.tests:
        note_test_directives(previous, current, path, changed_files, selection)
    before = {u['name']: u for u in previous.test_units()}
    counts = Counter((u['name'], u['hash']) for u in previous.test_units())
    for unit in current.test_units():
        if spend(counts, (unit['name'], unit['hash'])):
            continue
        bind_current_unit(unit, before, current, state_vars, selection)
    bind_lost_baseline(previous, current, selection)
    bind_removed_targets(before, current, selection)


def global_state(current):
    """Package-level variable names of the current side."""
    names = set()
    for path in current.production:
        for unit in current.declarations(path):
            if unit.get('kind') == 'var':
                names.update(unit.get('symbols', []))
    return names


def note_test_directives(previous, current, path, changed_files, selection):
    old = previous.files.get(path)
    if path in changed_files and old is not None and \
            current.files[path].get('directives', '') != old.get('directives', ''):
        selection.widen('test build directives changed: ' + path)


def bind_current_unit(unit, before, current, state_vars, selection):
    """One new or changed test unit, bound through its current closure."""
    if unit['name'].startswith(TEST_PREFIXES):
        reason = ('changed test target: ' if unit['name'] in before
                  else 'new test target: ') + unit['name']
        bind_target(unit, reason, current, state_vars, selection)
        return
    bind_helper_change(unit, current, state_vars, selection)


def bind_helper_change(unit, current, state_vars, selection):
    """A changed helper rebinds every test target transitively calling it."""
    for name in helper_callers(unit['name'], current):
        if not name.startswith(TEST_PREFIXES):
            continue
        target = next(u for u in current.test_units() if u['name'] == name)
        bind_target(target, 'test helper changed: ' + unit['name'] + ' → ' + name,
                    current, state_vars, selection)


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


def bind_lost_baseline(previous, current, selection):
    """Keep baseline coverage of changed test units explicitly selected."""
    survivors = Counter((u['name'], u['hash']) for u in current.test_units())
    current_names = {u['name'] for u in current.test_units()}
    for name, unit in {u['name']: u for u in previous.test_units()}.items():
        if name not in current_names or spend(survivors, (name, unit['hash'])):
            continue
        bind_lost_unit(name, unit, previous, current, selection)


def bind_lost_unit(name, unit, previous, current, selection):
    """Baseline closure of one changed test unit, widened when unbindable.

    Baseline references follow renames: a lost ref whose symbol moved keeps
    binding the renamed function while still naming the original, so a
    rename stays narrow instead of widening the whole package.
    """
    refs, selrefs = target_closure(unit, previous)
    refs = refs | {selection.renames[ref] for ref in refs if ref in selection.renames}
    names = {row['name'] for row in current.functions()}
    consumers = [row for row in current.functions() if row['name'] in refs]
    if consumers:
        for row in consumers:
            selection.add(row, 'lost baseline coverage: ' + name)
        return
    if refs or selrefs & names:
        selection.widen('lost baseline coverage without bindable consumer: ' + name)


def bind_removed_targets(before, current, selection):
    """Baseline-only test units bind the coverage they used to carry."""
    after = {u['name'] for u in current.test_units()}
    for name, unit in before.items():
        if name not in after:
            bind_removed_unit(name, unit, current, selection)


def bind_removed_unit(name, unit, current, selection):
    names = {row['name'] for row in current.functions()}
    if not name.startswith(TEST_PREFIXES):
        for row in current.functions():
            if row['name'] in set(unit.get('refs', [])):
                selection.add(row, 'removed test helper: ' + name)
        return
    covered = {r for r in unit.get('refs', []) if r in names}
    for row in current.functions():
        if row['name'] in covered:
            selection.add(row, 'removed test coverage: ' + name)
    if not covered:
        selection.widen('removed test target without bindable consumer: ' + name)


def bind_target(unit, reason, current, state_vars, selection):
    """Bind one test target to the production functions it covers.

    Binding closes transitively through test helpers. Selector-position
    references to a function name may be indirect dispatch, any reference
    to package state cannot be rolled back textually, and an empty
    consumer set cannot be shown safe; all three widen instead of guessing.
    """
    refs, selrefs = target_closure(unit, current)
    if state_vars & refs:
        selection.widen(reason + ' references global state')
        return
    names = {row['name'] for row in current.functions()}
    if selrefs & names:
        selection.widen(reason + ' references indirect dispatch')
        return
    consumers = [row for row in current.functions() if row['name'] in refs]
    if not consumers:
        selection.widen(reason + ' has no bindable production consumer')
        return
    for row in consumers:
        selection.add(row, reason)


def target_closure(unit, side):
    """References reachable from a test unit through test-file helpers."""
    helpers = {u['name']: u for u in side.test_units()
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


def widen_cross_package(root, config, helper, result):
    """Widen critical packages importing a cross-marked changed package.

    Declaration changes that can break or alter consumers through the
    import graph — types, interfaces, indirect-dispatch shapes, removed
    state — must not leave importing packages silently unchecked.
    """
    marked = {package: selection.cross for package, (selection, _) in RUNS.items()
              if selection.cross}
    if not marked:
        return
    for package, markers in marked.items():
        widen_importers(package, markers, root, config, helper, result)


def widen_importers(origin, markers, root, config, helper, result):
    path = import_path(root, origin)
    if not path:
        return
    reason = ('cross-package consumer of changed declaration: ' + path +
              ' (' + ', '.join(sorted(set(markers))) + ')')
    for consumer in importing_packages(origin, root, config['critical_paths'], path):
        selection = consumer_selection(root, consumer, helper, config.get('build_tags'))
        selection.widen(reason)
        finish_selection(consumer, selection, result)


def consumer_selection(root, consumer, helper, modes):
    """Selection of an importing package: the live one, or a fresh start."""
    if consumer in RUNS:
        return RUNS[consumer][0]
    side = Side(unit_rows(root, go_files(root, consumer), helper, modes), root)
    selection = Selection(consumer)
    RUNS[consumer] = (selection, side)
    return selection


def finish_selection(consumer, selection, result):
    side = RUNS[consumer][1]
    result[consumer] = selection_result(selection, side, consumer)


def importing_packages(origin, root, patterns, path):
    """Critical production packages (other than origin) importing path."""
    import critical_scope as scope
    return [package for package in critical_packages(root, patterns)
            if package != origin and scope.package_files(root, package)
            and imports_package(root, package, path)]


def imports_package(root, package, path):
    """Text-level import detection, conservative toward false positives."""
    needle = '"' + path + '"'
    return any(needle in (root / file).read_text(errors='replace')
               for file in go_files(root, package))


def critical_packages(root, patterns):
    """Every critical package directory present in the current tree."""
    import critical_scope as scope
    return sorted({str(Path(p).parent) for p in source.files(root)
                   if scope.is_critical(p, patterns)})


def import_path(root, package):
    """Import path of a package, from the nearest enclosing go.mod."""
    directory = (root / package).resolve()
    for base in [directory, *directory.parents]:
        module = module_name(base / 'go.mod')
        if module:
            suffix = directory.relative_to(base).as_posix()
            return module if suffix == '.' else module + '/' + suffix
        if base == root.resolve():
            break
    return None


MODULE_LINE = re.compile(r'^module\s+(\S+)', re.M)


def module_name(go_mod):
    """Module path declared in a go.mod file, if any."""
    if not go_mod.is_file():
        return None
    match = MODULE_LINE.search(go_mod.read_text())
    return match.group(1) if match else None


REPORT_KEYS = ('name', 'start', 'end', 'hash', 'kind')


def selection_result(selection, current, package):
    evidence = {'widened': selection.widenings or None, 'guards': selection.guards,
                'selected': [], 'reasons': {}}
    if selection.cross:
        evidence['cross_package'] = selection.cross
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
    return [dict({key: row.get(key) for key in REPORT_KEYS}, file=row['file'])
            for row in rows]
