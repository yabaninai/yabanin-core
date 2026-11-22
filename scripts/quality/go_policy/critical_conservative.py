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

Widening is a demand, not a discount: every selected function — a
literally-changed body, a consumer bound to a changed declaration or a
rewritten test, and every production function of a widened package —
carries a fuzz-seed demand, so the conservative fallback keeps the
historical seed contract whenever binding cannot resolve. The blank
identifier is not package state, so `var _ Iface = impl{}` compile
assertions never widen. Rewritten tests re-baseline through a real
coverage-profile run whose proof is block-level: an identical body must
still execute every block the base suite executed, a changed body every
block it now has, and the proof runs against base-side spans located by
file, name and body identity, so shifting or relocating a function in the
current tree cannot make its own lost coverage vacuous; only like-named
symbols the base suite never executed are vacuous, and consumers with no
resolvable base counterpart stay bound instead of silently disappearing.
"""
from collections import Counter, defaultdict
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import time

import critical_results
import policy
import source

# The approved unit budget also bounds baseline-coverage verification runs.
UNIT_VERIFY_SECONDS = 300
OWNER_COVERAGE_PROBE_SECONDS = 20

# Live per-package unit deadlines: every baseline-coverage verification
# run and the normal unit phase of the same package draw down one budget.
DEADLINES = {}

# Unit seconds banked when a package's verification ends, spent when that
# package's own unit phase starts: other packages' work between the two
# phases must not consume this package's budget.
UNIT_REMAINDERS = {}

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
    DEADLINES.clear()
    UNIT_REMAINDERS.clear()


def unit_rows(root, paths, helper, modes=None, package=None, config=None):
    """Full per-file unit rows including directive digests.

    policy.unit_maps keeps only units and drops the per-file directive
    digest; conservative selection is declaration-driven and needs both.
    With modes (critical.json build_tags), every row also reports which
    build modes compile the file, so target guards count what a build
    actually sees.

    Rows always draw from the named package's ONE shared unit budget:
    the go run startup is charged against the absolute deadline, the
    remainder is forwarded to the helper through
    YABANIN_UNIT_REMAINING_NS, and an expired caller fails with 'unit
    budget exhausted' instead of ever parsing rows. A missing package
    is an API misuse and fails closed — there is no uncharged per-call
    budget (legacy selection uses policy.unit_maps instead).
    """
    if not paths:
        return []
    if package is None:
        raise ValueError('unit_rows requires the package whose shared '
                         'unit budget the rows draw from')
    request = (sorted(paths) if modes is None else
               {'paths': sorted(paths), 'modes': [tags(mode) for mode in modes]})
    deadline = shared_deadline(package, unit_budget(config))
    remaining_ns = int((deadline - time.monotonic()) * 1e9)
    if remaining_ns <= 0:
        raise ValueError('unit budget exhausted for ' + package +
                         ' (unit rows)')
    argv = ['go', 'run', str(helper)]
    code, output, errout = run_unit_rows(argv, root, deadline,
                                         json.dumps(request), remaining_ns)
    if code is None:
        raise ValueError('unit budget exhausted for ' + package +
                         ' (unit rows)')
    if code != 0:
        raise subprocess.CalledProcessError(code, argv,
                                            output=output + errout)
    if time.monotonic() > deadline:
        raise ValueError('unit budget exhausted for ' + package +
                         ' (unit rows)')
    return json.loads(output)


# The helper's analysis context starts only after the go-run startup
# lag, so forwarding the raw wall remainder would put the helper's own
# deadline after the parent's absolute deadline: a floor would finish
# just past it and arrive as a parent group kill instead of complete
# rows. The shared-budget handoff therefore reserves a fixed closure
# margin — the parent deadline and the approved budgets (unit=300,
# fuzz=420) stay unchanged, and the reserve only ever narrows what the
# helper may spend, never widening it. A remainder inside the reserve
# forwards a 1ns budget so the helper floors immediately: a very small
# positive remainder can fail closed at the parent deadline but never
# resets to the no-env 90s default. The measured startup overhead lives
# in the budget test evidence, not in this durable invariant.
UNIT_HANDOFF_RESERVE_NS = 500_000_000


def run_unit_rows(argv, root, deadline, payload, remaining_ns):
    """go run for unit rows under the package's shared unit deadline.

    Same containment contract as run_until_deadline — own process
    group, deterministic pipe cleanup, whole-group kill at the deadline —
    but stdout stays separate from stderr because the rows are JSON and
    the request travels on stdin. The caller's remaining budget is
    forwarded through YABANIN_UNIT_REMAINING_NS, reduced by the closure
    reserve so the helper's self-floor and its complete rows land
    inside the parent budget; the wrapper-visible value is the actual
    forwarded budget the helper derived its analysis deadline from.
    """
    forward_ns = remaining_ns - UNIT_HANDOFF_RESERVE_NS
    if forward_ns < 1:
        forward_ns = 1
    proc = subprocess.Popen(argv, cwd=root, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, start_new_session=True,
                            env=dict(os.environ, GOWORK='off', GOFLAGS='',
                                     YABANIN_UNIT_REMAINING_NS=
                                     str(forward_ns)))
    try:
        output, errout = proc.communicate(
            input=payload,
            timeout=max(0.0, deadline - time.monotonic()))
        return proc.returncode, output, errout
    except subprocess.TimeoutExpired:
        kill_group(proc)
        return None, '', ''
    finally:
        for stream in (proc.stdout, proc.stderr, proc.stdin):
            with contextlib.suppress(OSError, ValueError):
                stream.close()


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
        self._indexes = None
        self._prodindex = None

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

    def indexes(self):
        """Cached closure index; materialized once per side snapshot."""
        if self._indexes is None:
            self._indexes = closure_index(self)
        return self._indexes

    def prodindex(self):
        """Cached production identity index; see production_index."""
        if self._prodindex is None:
            self._prodindex = production_index(self)
        return self._prodindex


def dispatch_state(side):
    """Literal dynamic-dispatch names and unresolved-dispatch presence."""
    names, unresolved = set(), False
    for path in sorted(side.files):
        for item in side.files[path]['units']:
            names.update(item.get('lits', []))
            unresolved = unresolved or 'dynamic_dispatch_unresolved' in item.get('flags', [])
    return names, unresolved


def unit_key(row):
    """Row identity of a function: file, name, receiver and occurrence.

    Two methods may share one name on different receivers in the same
    file, so a bare (file, name) key collapses them into one row; plain
    functions carry an empty receiver and keep their existing identity.
    Go also permits repeated declarations such as multiple init()
    functions in one file, so occurrence position and body identity
    complete the key: two changed initializers stay two selected rows,
    each with its own checking demand, while one row's identity stays
    stable within a selection pass over one snapshot.
    """
    return (row['file'], row['name'], row.get('recv', ''),
            row.get('start'), row.get('hash'))


def obligation_identity(name, consumers):
    """Hashable identity of one queued coverage obligation.

    Consumer rows are dicts and cannot order or hash; their unit keys
    can. Sorting the keys keeps identity independent of row order.
    """
    return name, tuple(sorted(unit_key(row) for row in consumers))


def method_identity(row):
    """Existence identity of a function inside a package: name + receiver.

    File position is deliberately excluded: a function that moved to a
    surviving sibling file still exists, while one of two same-named
    receiver-distinct methods that deleted itself does not.
    """
    return (row['name'], row.get('recv', ''))


def identity_key(row):
    """Closure spelling of one named unit's identity.

    A method helper is 'recv.name' — the same form the unit scanner
    reports in the recv field and the type checker emits for concrete
    method selections; a package-level unit is its bare name. Go
    identifiers cannot contain a dot, so the two spellings never
    collide.
    """
    recv = row.get('recv', '')
    return recv + '.' + row['name'] if recv else row['name']


def parse_key(key):
    """Split an identity key into (receiver, name); '' receiver is bare.

    A bare spelling carries no dot, so partitioning alone would mistake
    the whole name for a receiver and make every bare key look method-
    qualified — hiding the name from prefix checks and the bare branch
    from resolution. The separator's presence decides the form.
    """
    recv, sep, name = key.partition('.')
    if not sep:
        return '', key
    return recv, name


def row_key(row):
    """Walk identity of a closure row; nameless initializers use symbols."""
    return (row.get('name', ''), tuple(row.get('symbols', [])), row['hash'])


def reason_label(row):
    """Reason-table label; receiver-distinct methods read like A.Check."""
    recv = row.get('recv', '')
    return recv + '.' + row['name'] if recv else row['name']


def helper_keys(unit):
    """Closure keys of a helper unit: the exact identity spelling.

    A method helper's identity is its receiver-qualified key; the bare
    name alone never matches it, because the same bare spelling can
    also denote a distinct package-level helper. Broad floor
    spellings — references the fallback vouches for — fan to every
    same-named twin through the floor index instead, which keeps exact
    and floor evidence distinct.
    """
    return [identity_key(unit)]


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
        self.seed_rows = set()
        self.lost_baseline = []
        # Identities already queued; note_lost_baseline fires each once.
        self.queued = set()

    def add(self, row, reason):
        """Select a function; every selected row carries a seed demand."""
        key = unit_key(row)
        self.rows.setdefault(key, row)
        self.seed_rows.add(key)
        note = self.reasons.setdefault(reason_label(row), [])
        if reason not in note:
            note.append(reason)

    def widen(self, reason):
        if reason not in self.widenings:
            self.widenings.append(reason)

    def mark_cross(self, label):
        """Record a declaration whose consumers may live in other packages."""
        if label not in self.cross:
            self.cross.append(label)

    def note_lost_baseline(self, name, consumers):
        """Queue baseline coverage of a rewritten test for real verification.

        One obligation queues once: identity is the name plus consumer
        unit keys, so two binding passes cannot double-fire the same
        obligation, while same-named twins with different consumers keep
        both records — one twin's obligations never replace another's.
        """
        identity = obligation_identity(name, consumers)
        if identity not in self.queued:
            self.queued.add(identity)
            self.lost_baseline.append((name, consumers))


def changed_functions(root, baseline, package, helper, changes, build_tags=None,
                      config=None):
    """Conservative counterpart of critical_scope.changed_functions.

    Both the current and the baseline scan draw from the package's one
    shared unit deadline — the same absolute budget the coverage
    verification and the unit phase use.
    """
    under = {p for p in changes if p == package or p.startswith(package + '/')}
    changed_files = {p for p in under if str(Path(p).parent) == package}
    current = Side(unit_rows(root, go_files(root, package), helper, build_tags,
                             package=package, config=config), root)
    previous = Side(unit_rows(baseline, archived_files(baseline, package),
                              helper, build_tags, package=package,
                              config=config), baseline)
    selection = Selection(package)
    RUNS[package] = (selection, current, previous)
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
        guard_relocated_targets(previous, current, index, mode, package)


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
    """
    before_fuzz, before_test = mode_targets(previous, index)
    after_fuzz, after_test = mode_targets(current, index)
    if before_fuzz and not after_fuzz:
        raise ValueError('Critical fuzz target coverage loss in build mode "' + mode +
                         '"; gate would be silently not applicable: ' + package)
    if before_test and not after_test:
        raise ValueError('Critical unit-test coverage loss in build mode "' + mode +
                         '"; gate would be silently not applicable: ' + package)


def guard_relocated_targets(previous, current, index, mode, package):
    """Reject per-build-mode relocation of individual test targets.

    guard_target_coverage only sees total loss; a single target moved
    verbatim into a differently constrained file keeps every other target
    applicable to the mode, so its own mode loss is checked per unit.
    """
    survivors = {(u['name'], u['hash']) for u in current.test_units()}
    for unit in previous.test_units():
        if not unit['name'].startswith(TEST_PREFIXES):
            continue
        if (unit['name'], unit['hash']) not in survivors:
            continue
        if applies(previous, unit['file'], index) and \
                not mode_survives(unit, current, index):
            raise ValueError(relocated_reason(unit, mode, package))


def mode_survives(unit, current, index):
    """Whether a verbatim-surviving test unit still applies to a mode."""
    return any(u['name'] == unit['name'] and u['hash'] == unit['hash']
               and applies(current, u['file'], index)
               for u in current.test_units())


def relocated_reason(unit, mode, package):
    kind = 'fuzz target' if unit['name'].startswith('Fuzz') else 'unit-test'
    return ('Critical ' + kind + ' coverage loss in build mode "' + mode +
            '"; gate would be silently not applicable: ' + package +
            ' (' + unit['name'] + ')')


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
    """Select functions bound to a changed constant, through const chains.

    An exported constant's value is part of the package's published
    contract: importing packages consume it through the selector's own
    name, so an exported change cross-marks the package for import-graph
    widening even while in-package consumers keep the local choice
    precise. Exportedness is decided over the transitive reach, so an
    unexported constant feeding an exported alias is part of that
    contract too; a purely unexported reach keeps the narrow behavior
    and the explicit no-consumer error unchanged.
    """
    reach = const_reach(symbols, current)
    label = ','.join(symbols)
    exported = any(name[:1].isupper() for name in reach)
    consumers = [row for row in current.functions() if reach & set(row.get('refs', []))]
    if consumers:
        for row in consumers:
            selection.add(row, state + ' constant consumer: ' + label)
        if exported:
            selection.mark_cross(state + ' exported constant consumer: ' + label)
        return
    if not exported:
        raise ValueError('Unexported constant change without production consumers needs '
                         'an explicit coverage decision: ' + selection.package + ':' + label)
    selection.widen(state + ' exported constant without in-package consumers: ' + label)
    selection.mark_cross(state + ' exported constant without in-package consumers: ' + label)


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
    """Baseline production functions gone from the current side.

    Existence is (name, receiver) counted per occurrence: legal repeated
    declarations — multiple init() functions or same-bodied duplicates —
    need one survivor each, so deleting one of two cannot hide behind its
    twin. Receiver-distinct methods keep separate identities, an edited
    declaration still spends its occurrence, and functions consumed by
    the rename/move matching stay narrow here.
    """
    survivors = Counter(method_identity(row) for row in current.functions())
    for row in previous.functions():
        if row['name'] in selection.renames:
            continue
        if not spend(survivors, method_identity(row)):
            note_removed_function(row, previous, current, selection)


def note_removed_function(row, previous, current, selection):
    """A removed function widens while dispatch or text can still reach it.

    A vanished function is never proof it went unused: when nothing
    bindable names it — a move into a file this package's analysis
    excludes, a cross-package move, or deletion together with every
    consumer — the obligation stays explicit as a widening with a
    cross-package mark instead of silently disappearing.
    """
    label = reason_label(row)
    if dispatch_reference(row['name'], previous, current):
        selection.widen('removed function in dynamic-dispatch package: ' + label)
        return
    files, uncertain = referencing_files(row, previous, current)
    if files:
        selection.widen('removed function still referenced: ' + label +
                        ' (' + ', '.join(files) + ')')
        if uncertain:
            selection.mark_cross('removed function: ' + label)
        return
    selection.widen('removed production function without visible consumers: ' + label)
    selection.mark_cross('removed function: ' + label)


def dispatch_reference(name, previous, current):
    """Whether dynamic member lookup could still reach a removed name."""
    if previous.dispatch_unresolved or current.dispatch_unresolved:
        return True
    return name in previous.dispatch_names or name in current.dispatch_names


def referencing_files(row, previous, current):
    """Find surviving textual consumers without merging method twins."""
    name = row['name']
    recv = row.get('recv', '')
    key = identity_key(row)
    files = []
    uncertain = False
    for path in sorted(previous.files.keys() & current.files.keys()):
        before = previous.files[path]['units']
        now = current.files[path]['units']
        if recv:
            if key not in unit_refs(before):
                continue
            exact = key in unit_refs(now)
            fallback = unchanged_receiver_consumer(before, now, key, name)
            if exact or fallback:
                files.append(path)
                uncertain = uncertain or (fallback and not exact)
        elif name in unit_refs(before) and mentions(current, path, name):
            files.append(path)
    return files, uncertain


def unchanged_receiver_consumer(before, now, key, name):
    """Find a possible surviving call when type checking loses the receiver.

    Match the previous unit's receiver binding to an unchanged declaration
    with an unresolved reference to this method. Its receiver type can still
    change elsewhere, so the caller keeps cross-package coverage.
    """
    old_bindings = {(item['name'], item['hash'])
                    for item in before
                    if key in set(item.get('refs', [])) |
                    set(item.get('selrefs', []))}
    if not old_bindings:
        return False
    return any((item['name'], item['hash']) in old_bindings and
               name in item.get('floor_refs', []) for item in now)


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
    test_declaration_changes(previous, current, changed_files, state_vars,
                             selection)
    before = {u['name'] for u in previous.test_units()}
    counts = Counter((u['name'], u['hash']) for u in previous.test_units())
    for unit in current.test_units():
        if spend(counts, (unit['name'], unit['hash'])):
            continue
        bind_current_unit(unit, before, current, state_vars, selection,
                          previous)
    bind_lost_baseline(previous, current, selection)
    bind_removed_targets(previous.test_units(), current, previous, selection)


def global_state(current):
    """Package-level variable names of the current side.

    The blank identifier is not state: `var _ Iface = impl{}` compile
    assertions bind nothing, so '_' never witnesses a state reference.
    """
    names = set()
    for path in current.production:
        for unit in current.declarations(path):
            if unit.get('kind') == 'var':
                names.update(s for s in unit.get('symbols', []) if s != '_')
    return names


def note_test_directives(previous, current, path, changed_files, selection):
    old = previous.files.get(path)
    if path in changed_files and old is not None and \
            current.files[path].get('directives', '') != old.get('directives', ''):
        selection.widen('test build directives changed: ' + path)


def test_declaration_changes(previous, current, changed_files, state_vars,
                             selection):
    """Declaration-level edits of test files keep their consumers bound.

    Test units pair by (name, hash), so editing, adding or deleting a
    const/var/type declaration inside a _test.go file — or deleting the
    whole file — changes what every helper and target using it does
    while every unit hash stays identical. Declaration changes therefore
    bind the test targets whose closure references them, through helper
    twins, or widen with a recorded reason; an empty effect is never
    accepted as proof of safety.
    """
    for path in current.tests:
        old = previous.files.get(path)
        if old is None:
            note_test_declarations(current, path, {}, 'new', previous,
                                   state_vars, selection)
        elif path in changed_files:
            note_test_declarations(current, path, symbol_index(old), 'changed',
                                   previous, state_vars, selection)
    for path in previous.tests:
        if path not in current.files:
            for unit in previous.files[path]['units']:
                if not unit['name']:
                    note_test_declaration(unit, path, 'removed', previous,
                                          current, state_vars, selection)


def note_test_declarations(current, path, old_symbols, state, previous,
                           state_vars, selection):
    """One test file's declaration units against the package's survivors.

    Removal is decided at package level: a symbol deleted from one file
    but re-declared in another — including a mutually exclusive platform
    twin — still exists and is not a removal.
    """
    package_symbols = {s for p in current.tests
                       for u in current.declarations(p)
                       for s in u.get('symbols', [])}
    note_test_imports(path, previous, current, state, state_vars, selection)
    for unit in current.declarations(path):
        if not declaration_unchanged(unit, old_symbols):
            note_test_declaration(unit, path, state, previous, current,
                                  state_vars, selection)
    for symbol, unit in old_symbols.items():
        if symbol not in package_symbols:
            note_test_declaration(unit, path, 'removed', previous, current,
                                  state_vars, selection)


def note_test_declaration(unit, path, state, previous, current, state_vars,
                          selection):
    """Bind, or explicitly widen, one test-file declaration change.

    Test declarations never route through the production consumer
    rules: their consumers are tests and helpers, and an empty result
    there would be mistaken for proof. Imports are handled once per
    file by note_test_imports — new files bind their targets as new
    units, and removed files carry their targets through the
    removed-target pass.
    """
    kind = unit.get('kind', '')
    symbols = unit.get('symbols', [])
    if kind not in ('const', 'var', 'type') and not (
            has_flag(unit, 'interface') or has_flag(unit, 'func_type')):
        return
    label = ','.join(symbols) if symbols else unit['hash'][:12]
    if not bind_test_consumers(set(symbols), previous, current, state, label,
                               state_vars, selection):
        selection.widen('test declaration ' + state +
                        ' without bindable consumer: ' + label + ' (' + path + ')')


def bind_test_consumers(symbols, previous, current, state, label, state_vars,
                        selection):
    """Bind test targets whose closure reaches any of symbols.

    Returns True only when an obligation was actually bound or carried:
    a current referencing target or helper binds via bind_test_unit, and
    a referencing unit that exists only in the baseline is carried by
    the unit pass (rewritten twin) or bind_removed_targets (removed
    unit, widening when nothing binds). A symbol no reachable target
    references, now or in the baseline, leaves the widening to the
    caller; a bare reference is not a bound obligation.
    """
    bound = False
    for unit in current.test_units():
        if symbols & set(unit.get('refs', [])):
            bound = bind_test_unit(unit, current, state, label, state_vars,
                                   selection, previous) or bound
    if not bound and any(symbols & set(unit.get('refs', []))
                         for unit in previous.test_units()):
        bound = True
    return bound


def bind_test_unit(unit, current, state, label, state_vars, selection,
                   previous):
    """Bind one referencing test unit: targets directly, helpers via callers.

    A target's own name is never inside helper_callers, so the direct
    case must bind the unit itself; a helper binds every target that
    transitively calls it. Bindings obligate: the bound consumers queue
    for baseline verification, because a declaration edit must not
    leave a steady body's old coverage unproven. Returns True when a
    binding happened.
    """
    if unit['name'].startswith(TEST_PREFIXES):
        bind_target(unit, 'test declaration ' + state + ': ' + label +
                    ' → ' + unit['name'], current, state_vars, selection,
                    previous, obligate=True)
        return True
    bound = False
    for name in sorted(helper_callers(unit, current)):
        if not name.startswith(TEST_PREFIXES):
            continue
        for target in (u for u in current.test_units() if u['name'] == name):
            bind_target(target, 'test declaration ' + state + ': ' +
                        label + ' → ' + name, current, state_vars,
                        selection, previous, obligate=True)
        bound = True
    return bound


def note_test_imports(path, previous, current, state, state_vars, selection):
    """One surviving test file's changed imports bind or widen, never no-op.

    Only explicitly named imports bind narrowly: the closure of test
    targets referencing a changed alias binds, so a used import added by
    one target cannot pull every other target's consumers into the
    selection. An alias whose declaration hash changed — a same-alias
    path replacement rewrites what every reference means — counts as
    changed. Default imports have no reference-table entry; their
    addition, removal or path change is a named widening, never an
    inferred alias match. Blank and dot imports widen explicitly, and
    each changed alias records its own outcome: one bindable alias
    never hides another alias's missing consumer.
    """
    if state != 'changed':
        return
    old_explicit, old_defaults = import_units(previous, path)
    new_explicit, new_defaults = import_units(current, path)
    if old_explicit == new_explicit and old_defaults == new_defaults:
        return
    if (set(old_explicit) | set(new_explicit)) & {'_', '.'}:
        selection.widen('test blank/dot import: ' + path)
        return
    if old_defaults != new_defaults:
        selection.widen('test default import changed: ' + path)
        return
    changed = {alias for alias in set(old_explicit) | set(new_explicit)
               if old_explicit.get(alias) != new_explicit.get(alias)}
    for alias in sorted(changed):
        if not bind_test_consumers({alias}, previous, current,
                                   'imports changed', alias, state_vars,
                                   selection):
            selection.widen('test import changed without bindable consumer: ' +
                            alias + ' (' + path + ')')


def import_units(side, path):
    """A test file's import declarations as explicit aliases and defaults.

    Explicit aliases map to their declaration hash; default imports are
    collected as a sorted hash list. A declaration carrying any default
    import counts as default wholesale: the declared package name cannot
    be inferred from the path alone, so it never feeds narrow alias
    binding.
    """
    if path not in side.files:
        return {}, []
    explicit, defaults = {}, []
    for unit in side.files[path]['units']:
        if unit.get('kind') != 'import':
            continue
        if has_flag(unit, 'default_import'):
            defaults.append(unit['hash'])
        else:
            explicit.update({symbol: unit['hash']
                             for symbol in unit.get('symbols', [])})
    return explicit, sorted(defaults)


def bind_current_unit(unit, before, current, state_vars, selection, previous):
    """One new or changed test unit, bound through its current closure."""
    if unit['name'].startswith(TEST_PREFIXES):
        reason = ('changed test target: ' if unit['name'] in before
                  else 'new test target: ') + unit['name']
        bind_target(unit, reason, current, state_vars, selection, previous)
        return
    bind_helper_change(unit, current, state_vars, selection, previous)


def bind_helper_change(unit, current, state_vars, selection, previous):
    """A changed helper rebinds every test target transitively calling it.

    Caller names bind to every same-named twin: a helper changed in one
    mutually exclusive platform file is a change for the tests in all of
    its files, and binding one twin's body must never replace another's.
    Bindings obligate, like every steady-body binding.
    """
    for name in helper_callers(unit, current):
        if not name.startswith(TEST_PREFIXES):
            continue
        for target in (u for u in current.test_units() if u['name'] == name):
            bind_target(target, 'test helper changed: ' + unit['name'] + ' → ' + name,
                        current, state_vars, selection, previous,
                        obligate=True)


def reverse_edges(side):
    """Caller edges of the test-file helper graph, keyed by dependency.

    The forward closure resolves a unit's references — exact bare and
    receiver-qualified spellings, plus floor spellings fanned to every
    same-named twin — through resolve_rows; these edges are the exact
    reverse of that resolution: every dependency key a unit's closure
    would walk to owes an edge back to each of the unit's caller
    identities — the unit's own key, or every symbol a var initializer
    declares. A floor-only reference therefore reaches the method twins
    the forward fan would reach, and a caller bound through a variable
    chains through its initializer in both directions.
    """
    index = side.indexes()
    sources = [(unit, (identity_key(unit),)) for unit in side.test_units()]
    for path in side.tests:
        sources.extend((unit, tuple(unit.get('symbols', [])))
                       for unit in side.declarations(path)
                       if unit.get('kind') == 'var')
    edges = {}
    for unit, callers in sources:
        for _row, dep in resolve_rows(unit.get('refs', []),
                                      set(unit.get('floor_refs', [])), index):
            edges.setdefault(dep, set()).update(callers)
    return edges


def helper_callers(unit, current):
    """Test units transitively referencing a helper, by identity key.

    A method helper's callers are units whose resolved dependencies
    spell the receiver-qualified key, so a same-named method on another
    receiver never matches, while a bare package-level helper matches
    only its bare spelling; floor-only references reach the helper
    exactly when the forward fan would. Non-test callers expand the
    frontier under their own identity, and var initializers chain under
    their declared symbols, so an indirect caller still binds. Test
    targets are reported, never expanded: the walk returns the affected
    suite, not the suite's own callees.
    """
    edges = reverse_edges(current)
    affected = set()
    frontier, seen = list(helper_keys(unit)), set()
    while frontier:
        key = frontier.pop()
        if key in seen:
            continue
        seen.add(key)
        for caller in edges.get(key, ()):
            if parse_key(caller)[1].startswith(TEST_PREFIXES):
                affected.add(parse_key(caller)[1])
            else:
                frontier.append(caller)
    return affected


def bind_lost_baseline(previous, current, selection):
    """Keep baseline coverage of changed test units explicitly selected.

    Units pair by (name, hash), never by name alone: Go permits duplicate
    test names in mutually exclusive files (build tags, GOOS), so an
    unchanged sibling must not spend or replace a rewritten twin's
    baseline and hide its lost coverage.
    """
    survivors = Counter((u['name'], u['hash']) for u in current.test_units())
    current_names = {u['name'] for u in current.test_units()}
    for unit in previous.test_units():
        name = unit['name']
        if name not in current_names or spend(survivors, (name, unit['hash'])):
            continue
        bind_lost_unit(name, unit, previous, current, selection)


def bind_lost_unit(name, unit, previous, current, selection):
    """Baseline closure of one changed test unit, verified against reality.

    Baseline references follow renames: a lost ref whose symbol moved keeps
    binding the renamed function while still naming the original, so a
    rename stays narrow instead of widening the whole package. Dynamic
    baseline dispatch counts like a reference: a baseline helper calling
    through a func-typed field kept a production function covered, so a
    production-named selref from the baseline closure is a real
    obligation, not a widening alone. The bound functions are not
    selected on text alone: verify_lost_baseline maps the current unit
    suite's real coverage profile and either re-baselines silently
    (still exercised) or blocks with lost_unit_coverage.
    """
    refs, floors, selrefs = target_closure(unit, previous)
    # The lost twin's production effect closure spans both sides: a
    # baseline factory callback that no current test reaches still owes
    # its coverage, and renames apply after the closure so renamed
    # production callees follow too.
    effect, unresolved, _ = production_closure(
        resolve_production(refs, floors, [previous, current]),
        [previous, current])
    keys = map_renames(effect, selection.renames)
    names = {row['name'] for row in previous.functions()}
    dynamic = resolve_production(selrefs & names, selrefs & names, [previous])
    if dynamic:
        # A baseline selref is a dispatch obligation on the factory it
        # reached: close its transitive production bodies too, or the
        # function behind Factory().Allowed()() unbinds while the
        # field spelling alone binds.
        dynamic = production_closure(dynamic, [previous, current])[0]
    if unresolved or dynamic:
        # Widening alone must not conceal baseline obligations: the
        # unresolved or dynamically dispatched production name keeps
        # the lost-coverage question open, so known consumers still
        # queue below for real verification.
        selection.widen('lost baseline reaches unresolved production dispatch: ' + name)
    consumers = current_consumers(keys | dynamic, current)
    if consumers:
        selection.note_lost_baseline(name, consumers)
        return
    if refs or dynamic:
        selection.widen('lost baseline coverage without bindable consumer: ' + name)


def bind_removed_targets(units, current, previous, selection):
    """Baseline-only test units bind the coverage they used to carry.

    Removal is tracked per name and body: Go permits the same test name
    in mutually exclusive files, and when no twin of a name survives,
    every removed twin's obligations still bind — one twin's consumers
    must never replace another's. A same-named twin surviving in another
    file keeps the name alive, and that twin spends its baseline pair by
    (name, hash) in bind_lost_baseline instead of here.
    """
    after = {u['name'] for u in current.test_units()}
    removed = {}
    for unit in units:
        if unit['name'] not in after:
            removed.setdefault(unit['name'], []).append(unit)
    for twins in removed.values():
        for unit in twins:
            bind_removed_unit(unit['name'], unit, previous, current, selection)


def bind_removed_unit(name, unit, previous, current, selection):
    """One removed twin binds through its baseline transitive closure.

    The closure unions every same-named baseline helper twin, so a
    removed test that reached production only through a helper — a
    helper that disappeared with it — still binds that production, and a
    removed helper binds the production it referenced. A baseline selref
    through a func-typed field is a dispatch obligation like a direct
    reference: it binds the production name it reached instead of
    silently vanishing with the removed file. A removed test or helper
    with no bindable consumer widens with the same named message instead
    of silently dropping its baseline obligations. The bound rows are
    queued, not merely selected: verify_lost_baseline must still prove
    that coverage executes or block its loss.
    """
    refs, floors, selrefs = target_closure(unit, previous)
    effect, unresolved, _ = production_closure(
        resolve_production(refs, floors, [previous, current]),
        [previous, current])
    keys = effect
    names = {row['name'] for row in previous.functions()}
    dynamic = resolve_production(selrefs & names, selrefs & names, [previous])
    if unresolved or dynamic:
        # Same rule as lost twins: the widening records the uncertainty,
        # the known consumers below still owe verified coverage.
        selection.widen('removed test reaches unresolved production dispatch: ' + name)
    if not name.startswith(TEST_PREFIXES):
        bind_removed_helper(name, keys | dynamic, current, selection)
        return
    consumers = current_consumers(keys | dynamic, current)
    for row in consumers:
        selection.add(row, 'removed test coverage: ' + name)
    if consumers:
        selection.note_lost_baseline(name, consumers)
    if not consumers:
        selection.widen('removed test target without bindable consumer: ' + name)


def bind_removed_helper(name, keys, current, selection):
    """A removed helper binds the production it referenced, or widens.

    A helper whose only reference is an import alias nothing carries has
    no bindable production consumer: it records its own named widening,
    so the import side's baseline fallback cannot treat its obligation
    as carried while nothing was bound. Keys are identity spellings, so
    a removed method helper binds only that receiver's production rows
    and never a same-named method on another receiver. The bound rows
    are queued, not merely selected: verify_lost_baseline must still
    prove that coverage executes or block its loss.
    """
    consumers = current_consumers(keys, current)
    for row in consumers:
        selection.add(row, 'removed test helper: ' + name)
    if consumers:
        selection.note_lost_baseline(name, consumers)
    if not consumers:
        selection.widen('removed test target without bindable consumer: ' + name)


def bind_target(unit, reason, current, state_vars, selection, previous=None,
                obligate=False):
    """Bind one test target to the production functions it covers.

    Binding closes transitively through test helpers and test-file
    declaration initializers. Initializers resolve on both sides when a
    baseline side is given: a steady body whose declaration edited what
    `var check = Allowed` means keeps owing both functions. Selector-
    position references to a function name may be indirect dispatch, any
    reference to package state cannot be rolled back textually, and an
    empty consumer set cannot be shown safe; all three widen instead of
    guessing. The state spelling reaches the selection through the
    production bodies' own raw references, not only through resolved
    keys. Both the indirect-dispatch widen and obligated bindings queue
    their consumers, so a steady body cannot keep its selection while
    silently dropping the coverage it used to carry.
    """
    refs, floors, selrefs = target_closure(unit, current)
    if previous is not None:
        other_refs, other_floors, other_selrefs = declaration_refs(refs, previous)
        refs |= other_refs
        floors |= other_floors
        selrefs |= other_selrefs
    sides = [current] if previous is None else [current, previous]
    effect, unresolved, raw = production_closure(
        resolve_production(refs, floors, sides), sides)
    spellings = {parse_key(ref)[1] for ref in refs | effect | raw}
    if state_vars & spellings:
        selection.widen(reason + ' references global state')
        return
    names = {row['name'] for row in current.functions()}
    if selrefs & names:
        selection.widen(reason + ' references indirect dispatch')
        # Widening alone is not coverage: the indirect dispatch still
        # owes the bodies its baseline spelling reached, so queue them
        # for real verification before this widen returns.
        dynamic = resolve_production(selrefs & names, selrefs & names, sides)
        obligated = current_consumers(effect | dynamic, current)
        if obligated:
            selection.note_lost_baseline(unit['name'], obligated)
        return
    if unresolved:
        # Widening is not coverage: obligated bindings still queue their
        # known consumers so verify_lost_baseline proves that coverage.
        selection.widen(reason + ' reaches unresolved production dispatch')
    consumers = current_consumers(effect, current)
    if not consumers:
        selection.widen(reason + ' has no bindable production consumer')
        return
    for row in consumers:
        selection.add(row, reason)
    if obligate:
        selection.note_lost_baseline(unit['name'], consumers)


def closure_index(side):
    """Identity indexes of test-file helper twins and var initializers.

    Go permits the same helper name in mutually exclusive files, so
    helpers map every twin under the exact spelling of its identity: a
    package-level helper under its bare name, a method helper under
    its receiver-qualified key. Floor spellings — references the
    name-based fallback vouches for, never a checked package-level
    function — map the bare name to every non-test twin, methods
    included, so an uncertified spelling still reaches all candidates
    while checked evidence stays exact. A nameless var declaration is
    indexed by each declared symbol, which puts `var check = Allowed`
    inside the closure of every unit referencing check on this side.
    """
    helpers, floors, initializers = {}, {}, {}
    for unit in side.test_units():
        if not unit['name'].startswith(TEST_PREFIXES):
            helpers.setdefault(identity_key(unit), []).append(unit)
            floors.setdefault(unit['name'], []).append(unit)
    for path in side.tests:
        for unit in side.declarations(path):
            if unit.get('kind') == 'var':
                for symbol in unit.get('symbols', []):
                    initializers.setdefault(symbol, []).append(unit)
    return helpers, floors, initializers


def resolve_rows(refs, floors, index):
    """Helper and initializer rows one reference set reaches.

    Exact and floor evidence resolve differently. A receiver-qualified
    spelling reaches only that method's twins; a bare spelling the
    floor does not vouch for reaches package-level helpers under that
    name only; a bare floor spelling additionally fans to every
    same-named method twin, because broad lookup cannot tell the
    spellings apart. Var initializers join from every bare name they
    are declared under. Each reached row is returned with the depen-
    dency key it was reached under, so reverse edges can point callers
    at the same identity the forward closure used.
    """
    helpers, floor_index, initializers = index
    found, seen = [], set()
    for ref in refs:
        recv, _ = parse_key(ref)
        if recv:
            reached = helpers.get(ref, ())
        elif ref in floors:
            reached = helpers.get(ref, []) + floor_index.get(ref, [])
        else:
            reached = helpers.get(ref, ())
        for row in reached:
            key = row_key(row)
            if key not in seen:
                seen.add(key)
                found.append((row, identity_key(row)))
        for row in initializers.get(ref, ()):
            key = row_key(row)
            if key not in seen:
                seen.add(key)
                found.append((row, ref))
    return found


def declaration_refs(names, side):
    """Initializer references of test-file var declarations in names.

    A declaration's meaning exists on both sides of a change: `var
    check = Allowed` kept Allowed covered at the base even after the
    current tree rebinds check, so the other side's initializers belong
    in every binding that references the declared symbol. Initializers
    also chain through declared symbols (`var relay = Allowed; var
    check = relay`), so the walk continues from every referenced name
    until no unseen declaration remains. Twins share declared symbols,
    so identity is (symbols, body hash); that same identity breaks
    reference cycles among chained declarations. Floor spellings an
    initializer's fallback produced travel in their own set, so the
    caller keeps exact and broad evidence apart.
    """
    refs, floors, selrefs = set(), set(), set()
    frontier = set(names)
    seen = set()
    while frontier:
        discovered = set()
        for path in side.tests:
            for unit in side.declarations(path):
                symbols = frozenset(unit.get('symbols', []))
                if unit.get('kind') != 'var' or (symbols, unit['hash']) in seen:
                    continue
                if frontier & symbols:
                    seen.add((symbols, unit['hash']))
                    refs.update(unit.get('refs', []))
                    floors.update(unit.get('floor_refs', []))
                    selrefs.update(unit.get('selrefs', []))
                    discovered.update(unit.get('refs', []))
        frontier = discovered
    return refs, floors, selrefs


def production_index(side):
    """Identity and bare-name indexes of one side's production rows.

    The identity index carries package-level functions under their bare
    name and methods under the receiver-qualified key; the name index
    groups every same-named row for broad fans.
    """
    by_key, by_name = {}, {}
    for row in side.functions():
        by_key.setdefault(identity_key(row), []).append(row)
        by_name.setdefault(row['name'], []).append(row)
    return by_key, by_name


def resolve_production(refs, floors, sides):
    """Identity keys of production rows a reference set reaches.

    A receiver-qualified spelling reaches exactly that method's rows on
    every side. A bare spelling reaches package-level rows under that
    name — a bare key never denotes a method — and, when the floor
    vouches for the spelling, every same-named method row too, because
    broad lookup cannot distinguish the spellings.
    """
    keys = set()
    for side in sides:
        by_key, by_name = side.prodindex()
        for ref in refs:
            recv, name = parse_key(ref)
            if recv:
                if ref in by_key:
                    keys.add(ref)
                continue
            if ref in by_key:
                keys.add(ref)
            if ref in floors:
                for row in by_name.get(name, ()):
                    if row.get('recv', ''):
                        keys.add(identity_key(row))
    return keys


def production_closure(seeds, sides):
    """Transitive production effect closure of resolved identity keys.

    Coverage bound to a production function covers what that body
    definitely reaches as well: in-package callees plus the callbacks
    and values it hands onward — a factory returning
    `Adapter{Check: deny}` owes deny together with its own body.
    Production bodies exist on both sides of a change, so the walk runs
    over every given side and unions the edges; same-named production
    twins are all kept, matching the helper closure rule. Seeds are
    identity keys: a bare key never denotes a method — method
    references resolve to their receiver-qualified key first — while a
    bare floor spelling inside a production body still fans through
    every same-named twin. A selector-position reference reaching a
    function name from inside a production body is unresolved dispatch:
    no single body can own it, so it is reported for widening instead
    of     followed. The walk is bounded by the package's own production
    units and visits each identity once. The closure also returns the
    raw reference spellings every visited body carries: package state
    such as `var counter` appears as a body word without ever naming a
    production row, so state mapping keeps the body's own spellings
    even when no key resolves.
    """
    indexes = [side.prodindex() for side in sides]
    names = set()
    for _, by_name in indexes:
        names |= set(by_name)
    visited, frontier, unresolved = set(), set(seeds), set()
    raw = set()
    while frontier:
        key = frontier.pop()
        if key in visited:
            continue
        visited.add(key)
        for by_key, _ in indexes:
            for row in by_key.get(key, ()):
                unresolved |= set(row.get('selrefs', [])) & names
                raw.update(row.get('refs', []))
                frontier |= resolve_production(row.get('refs', []),
                                               set(row.get('floor_refs', [])),
                                               sides)
    return visited, unresolved, raw


def target_closure(unit, side):
    """References reachable from a test unit through helpers and initializers.

    Go permits the same helper name in mutually exclusive files (build
    tags, GOOS), so the closure walks every same-named helper twin: one
    twin's references must never replace another's, because base and
    current suites each execute only the twins their modes compile. The
    union is the conservative closure — a twin that never compiles here
    adds references that can select or verify more, never less. Exact
    and floor evidence travel separately: refs carries checked-union-
    floor spellings while floors marks the subset the fallback
    vouches for, so downstream resolution keeps the two apart. A var
    declaration joins the walk by its declared symbol, so initializer
    references are closure members of the side declaring them.
    """
    index = side.indexes()
    seen = {row_key(unit)}
    refs, floors, selrefs = set(), set(), set()
    frontier = [unit]
    while frontier:
        item = frontier.pop()
        refs.update(item.get('refs', []))
        floors.update(item.get('floor_refs', []))
        selrefs.update(item.get('selrefs', []))
        for row, _dep in resolve_rows(item.get('refs', []),
                                      set(item.get('floor_refs', [])), index):
            key = row_key(row)
            if key not in seen:
                seen.add(key)
                frontier.append(row)
    return refs, floors, selrefs


def current_consumers(keys, current):
    """Current-side production rows for resolved identity keys.

    Rows keep functions() order so selections and queued obligations
    stay deterministic and comparable to the name-based walk.
    """
    return [row for row in current.functions() if identity_key(row) in keys]


def map_renames(keys, renames):
    """Follow recorded renames over identity keys, keeping originals.

    A rename mapping is one spelling's move: the renamed key joins the
    set and the original spelling stays, so obligations still name what
    the baseline recorded while binding where the symbol lives now.
    """
    out = set(keys)
    for key in keys:
        if key in renames:
            out.add(renames[key])
    return out


def widen_cross_package(root, config, helper, result):
    """Widen critical packages importing a cross-marked changed package.

    Declaration changes that can break or alter consumers through the
    import graph — types, interfaces, indirect-dispatch shapes, removed
    state — must not leave importing packages silently unchecked.
    """
    marked = {package: entry[0].cross for package, entry in RUNS.items()
              if entry[0].cross}
    if not marked:
        return
    for package, markers in marked.items():
        widen_importers(package, markers, root, config, helper, result)


def widen_importers(origin, markers, root, config, helper, result):
    resume_unit_deadline(origin, unit_budget(config))
    try:
        path = import_path(root, origin)
        if not path:
            return
        consumers = importing_packages(origin, root, config['critical_paths'], path)
    finally:
        pause_unit_budget(origin)
    reason = ('cross-package consumer of changed declaration: ' + path +
              ' (' + ', '.join(sorted(set(markers))) + ')')
    for consumer in consumers:
        resume_unit_deadline(consumer, unit_budget(config))
        try:
            selection = consumer_selection(root, consumer, helper,
                                            config.get('build_tags'), config)
            selection.widen(reason)
            finish_selection(consumer, selection, result)
        finally:
            pause_unit_budget(consumer)


def consumer_selection(root, consumer, helper, modes, config=None):
    """Selection of an importing package: the live one, or a fresh start.

    A consumer's scan draws from the consumer's OWN shared unit budget,
    never the originating package's and never a fresh uncharged one.
    """
    if consumer in RUNS:
        return RUNS[consumer][0]
    side = Side(unit_rows(root, go_files(root, consumer), helper, modes,
                          package=consumer, config=config), root)
    selection = Selection(consumer)
    RUNS[consumer] = (selection, side, None)
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


REPORT_KEYS = ('name', 'recv', 'start', 'end', 'hash', 'kind')


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
    return report_rows(rows, selection)


def report_rows(rows, selection):
    """Selection rows as reports, each flagged with its seed demand."""
    return [dict({key: row.get(key) for key in REPORT_KEYS}, file=row['file'],
                 seed=unit_key(row) in selection.seed_rows
                 or bool(selection.widenings))
            for row in rows]


def verify_lost_baseline(root, base, config):
    """Verify that rewritten tests still exercise their baseline coverage.

    A (name, hash) break says nothing about coverage: the rewritten test may
    still exercise the same functions or may have dropped them. Each queued
    baseline is mapped against the unit suite executed per selected build
    mode with a real coverage profile, both at the base revision and in the
    current tree; still-exercised functions re-baseline silently when every
    base-executed block still executes, a function nothing exercises any
    more blocks with lost_unit_coverage, a surviving function that no
    longer executes a base-covered block blocks with lost_block_coverage,
    and bare-name matches the base never covered are dropped as vacuous
    instead of blocking the rewrite.
    """
    for package, (selection, side, previous) in sorted(RUNS.items()):
        if selection.lost_baseline:
            resume_unit_deadline(package, unit_budget(config))
            try:
                verify_package_baseline(root, base, config, package,
                                        selection, side, previous)
            finally:
                pause_unit_budget(package)


def verify_package_baseline(root, base, config, package, selection, side,
                            previous):
    """One package's rewritten tests against base and current coverage.

    Lost-baseline records bind consumers by bare name, and names like Set or
    WriteHeader also belong to stdlib methods a test may call on foreign
    types. Proof therefore runs against base-side spans: only functions the
    base suite actually executed at their base-revision location count as
    baseline coverage, whether or not the current tree shifted or relocated
    them, and consumers that cannot be matched to any base-revision function
    stay bound instead of silently disappearing. A focused owner probe may
    substitute for the current unit suite once every bound consumer's
    current blocks are witnessed in it; the base archive always runs, so
    vacuous collisions and counterpart spans are classified from base
    evidence, never from the tree under test. Every coverage run draws
    down the package's one shared unit deadline, never a fresh budget.
    A clean verification consumes the queue — the re-baseline stays in
    evidence — while a loss keeps the failed queue for diagnosis.
    """
    modes = config.get('build_tags') or ['']
    # The approved package/kind budget covers startup too: the deadline
    # starts before archive/materialization, not at the first go test.
    shared_deadline(package, unit_budget(config))
    probe = current_owner_coverage(root, package, selection, side, modes,
                                   config)
    with tempfile.TemporaryDirectory(prefix='yabanin-baseline-') as workspace:
        base_root = Path(workspace) / 'base'
        base_root.mkdir()
        source.archive(root, base, base_root)
        covered_base = [covered_functions(base_root, package, mode, 'base tree',
                                          config)
                        for mode in modes]
    probe, covered_now = bounded_current_side(
        probe, root, package, config, selection, covered_base, previous,
        side, modes)
    rebaselined, unit_lost, block_lost = [], [], []
    for name, consumers in sorted(selection.lost_baseline,
                                  key=lambda record:
                                  obligation_identity(*record)):
        evidence, loss = baseline_record(name, consumers, covered_base,
                                         covered_now, previous, side,
                                         modes, selection.renames)
        if evidence:
            rebaselined.append(evidence)
        if loss:
            if loss[0] == 'unit':
                unit_lost.append(loss[1])
            else:
                block_lost.append(loss[1])
    raise_baseline_loss(package, unit_lost, block_lost)
    selection.lost_baseline = []
    evidence = EVIDENCE['packages'].get(package)
    if evidence is not None:
        evidence['rebaselined'] = sorted(rebaselined)
        if probe is not None:
            evidence['baseline_independent_coverage'] = probe['modes']


def bounded_current_side(probe, root, package, config, selection,
                         covered_base, previous, side, modes):
    """Current-side profiles: focused rows when witnessed, full runs else.

    The focused probe bounds only the current side: the base archive
    still classifies vacuous like-name collisions and maps counterpart
    spans, so a witnessed probe replaces the current unit suite without
    making the tree under test its own baseline authority. Returns the
    probe actually used alongside one profile list per build mode.
    """
    if probe is not None and not probe_bounds_current(
            probe, selection, covered_base, previous, side, modes):
        probe = None
    if probe is None:
        return None, [covered_functions(root, package, mode, config=config)
                      for mode in modes]
    return probe, [probe['rows'].get(mode, []) for mode in modes]


def current_owner_coverage(root, package, selection, side, modes, config):
    """Focused current-side profiles that may bound the complete run.

    The probe never replaces base evidence: it returns one focused real
    profile per build mode so verify_package_baseline can substitute it
    for the current unit suite once every bound consumer's current
    blocks are witnessed in it. Missing owners, a failed run, or skipped
    or failed top-level owners abandon the probe; unwitnessed blocks are
    decided later against the base classification, not here. Skipped
    subtests are recorded; they are not evidence for any covered block.
    The probe shares the existing package deadline and has a short
    ceiling.
    """
    obligations = list(selection.lost_baseline)
    if not obligations:
        return None
    proof = {'modes': [], 'rows': {}}
    probe_deadline = min(shared_deadline(package, unit_budget(config)),
                         time.monotonic() + OWNER_COVERAGE_PROBE_SECONDS)
    for index, mode in enumerate(modes):
        mode_proof = current_mode_owner_coverage(
            root, package, obligations, side, index, mode, modes, probe_deadline)
        if mode_proof is None:
            return None
        if mode_proof:
            proof['modes'].append(mode_proof)
            proof['rows'][mode] = mode_proof.pop('rows')
    if not proof['modes']:
        return None
    return proof


def current_mode_owner_coverage(root, package, obligations, side, index,
                                mode, modes, deadline):
    """One build mode's focused profile, or None when it cannot run."""
    consumers = unique_rows(row for _, rows in obligations for row in rows
                            if mode_applies(side, row['file'], index, modes))
    if not consumers:
        return {}
    tests = owner_tests(consumers, side, index, modes)
    if not tests:
        return None
    result = focused_coverage(root, package, mode, tests, deadline)
    if result is None or set(result['passed']) != set(tests):
        return None
    return {
        'mode': mode, 'tests': tests, 'passed': result['passed'],
        'skipped': result['skipped'],
        'coverprofile_sha256': result['sha256'],
        'consumers': witnessed_consumer_entries(consumers, result['blocks']),
        'rows': critical_results.ProfileIndex(result['blocks']),
    }


def witnessed_consumer_entries(consumers, profile):
    """Witness entries for executed consumers; unwitnessed ones drop out."""
    return [entry for entry in
            (consumer_witness(row, profile) for row in consumers) if entry]


def consumer_witness(row, profile):
    """Entry proving every current block of one consumer, or None."""
    blocks = in_span(profile, row)
    if not blocks or any(block[2] == 0 for block in blocks):
        return None
    return {
        'file': row['file'], 'function': row['name'],
        'body_sha256': row['hash'],
        'blocks': [{'span': block[3], 'count': block[2]}
                   for block in blocks],
    }


def probe_bounds_current(probe, selection, covered_base, previous, side,
                         modes):
    """Whether the focused profiles witness every bound consumer's blocks.

    The base profile decides which consumers stay bound: vacuous
    like-name collisions never enter the record, so the probe owes no
    execution for them, while every bound consumer must show all its
    current blocks executed in the focused profile — otherwise the
    complete current suite, not the probe, is the evidence.
    """
    for _name, consumers in selection.lost_baseline:
        for row in consumers:
            _counterpart, vacuous = bound_counterpart(
                row, covered_base, previous, side, modes, selection.renames)
            if vacuous:
                continue
            for index, mode in enumerate(modes):
                if not mode_applies(side, row['file'], index, modes):
                    continue
                rows = probe['rows'].get(mode)
                if rows is None or consumer_witness(row, rows) is None:
                    return False
    return True


def unique_rows(rows):
    """Keep stable, unique current consumers across queued obligations."""
    result, seen = [], set()
    for row in rows:
        key = (row['file'], row['name'], row['hash'], row['start'], row['end'])
        if key not in seen:
            seen.add(key)
            result.append(row)
    return result


def owner_tests(consumers, side, index, modes):
    """Runnable test owners reachable from the mapped production consumers."""
    candidates = set()
    edges = owner_edges(side)
    for row in consumers:
        candidates.update(owner_callers(row, edges))
    return sorted({unit['name'] for unit in side.test_units()
                   if unit['name'] in candidates
                   and unit['name'].startswith(('Test', 'Fuzz'))
                   and mode_applies(side, unit['file'], index, modes)})


def owner_edges(side):
    """Reverse production and test-helper references for owner discovery."""
    sources = [(unit, (identity_key(unit),)) for unit in
               side.functions() + side.test_units()]
    for path in side.tests:
        sources.extend((unit, tuple(unit.get('symbols', [])))
                       for unit in side.declarations(path)
                       if unit.get('kind') == 'var')
    edges = {}
    helpers = side.indexes()
    for unit, callers in sources:
        refs, floors = unit.get('refs', []), set(unit.get('floor_refs', []))
        dependencies = {dep for _row, dep in resolve_rows(refs, floors, helpers)}
        dependencies.update(resolve_production(refs, floors, [side]))
        for dep in dependencies:
            edges.setdefault(dep, set()).update(callers)
    return edges


def owner_callers(row, edges):
    """Test owners and production helpers that can reach one consumer."""
    owners, seen, frontier = set(), set(), [identity_key(row)]
    while frontier:
        key = frontier.pop()
        if key in seen:
            continue
        seen.add(key)
        for caller in edges.get(key, ()):
            if parse_key(caller)[1].startswith(('Test', 'Fuzz')):
                owners.add(parse_key(caller)[1])
            else:
                frontier.append(caller)
    return owners


def focused_coverage(root, package, mode, tests, deadline):
    """A bounded real coverprofile for named owner tests, or no shortcut."""
    pattern = '^(' + '|'.join(tests) + ')$'
    if len(pattern) > 32768:
        return None
    with tempfile.TemporaryDirectory(prefix='yabanin-owner-cover-') as tmp:
        profile = Path(tmp) / 'owners.cover'
        argv = ['go', 'test', '-json', '-count=1', '-coverprofile=' + str(profile),
                '-run=' + pattern]
        if mode:
            argv.append('-tags=' + mode)
        argv.append('./' + package)
        code, output = run_until_deadline(argv, root, deadline)
        if code != 0 or not profile.is_file():
            return None
        data = profile.read_bytes()
        passed, skipped = coverage_test_events(output, tests)
        return {'blocks': critical_results.coverage_blocks(profile),
                'sha256': hashlib.sha256(data).hexdigest(),
                'passed': sorted(passed), 'skipped': sorted(skipped)}


def coverage_test_events(output, expected):
    """Named top-level pass events and every skipped test/subtest event."""
    passed, skipped = set(), set()
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        name, action = event.get('Test'), event.get('Action')
        if name in expected and action == 'pass':
            passed.add(name)
        if name and action == 'skip':
            skipped.add(name)
    return passed, skipped


def raise_baseline_loss(package, unit_lost, block_lost):
    """Block with the strongest proven loss: no exercise before no block."""
    if unit_lost:
        raise ValueError('lost_unit_coverage: ' + package + ': ' +
                         '; '.join(unit_lost))
    if block_lost:
        raise ValueError('lost_block_coverage: ' + package + ': ' +
                         '; '.join(block_lost))


def baseline_record(name, consumers, covered_base, covered_now, previous,
                    side, modes, renames):
    """Classify one lost-baseline record against base and current profiles.

    Returns (evidence, loss): the re-baseline evidence to record, a
    (kind, message) blocking loss, or (None, None) when every consumer is a
    vacuous like-name collision the base suite never executed. Consumers
    with no resolvable base counterpart are not vacuous — they stay bound,
    so a rewrite that shifts, moves or renames a function cannot make its
    own lost coverage disappear.
    """
    kept, unit_lost, block_lost = [], [], []
    for row in consumers:
        counterpart, vacuous = bound_counterpart(
            row, covered_base, previous, side, modes, renames)
        if vacuous:
            continue  # vacuous like-name collision: the base never covered it
        if not exercised(row, covered_now, side, modes):
            unit_lost.append(row['name'])
            continue
        losses = baseline_block_losses(row, counterpart, covered_base,
                                       covered_now, previous, side, modes)
        if losses:
            block_lost.append(row['name'] + ', ' + row['file'] + ':' +
                              ', '.join(losses))
        else:
            kept.append(row['name'])
    if unit_lost:
        return None, ('unit', name + ' no longer exercises ' +
                      ', '.join(sorted(set(unit_lost))))
    if block_lost:
        return None, ('block', name + ' no longer covers ' +
                      '; '.join(block_lost))
    if not kept:
        return None, None
    return name + ' → ' + ', '.join(sorted(set(kept))), None


def bound_counterpart(row, covered_base, previous, side, modes, renames):
    """(Counterpart, vacuous) head of one consumer's classification.

    Shared by baseline_record and the focused-probe bound so both decide
    vacuous like-name collisions from the same base profile: a consumer
    the base suite never executed at its resolved counterpart is not the
    record's to keep, and no current-tree run can change that.
    """
    counterpart, strength = base_counterpart(row, previous, renames)
    if counterpart is None:
        counterpart, strength = applicable_counterpart(
            row, previous, renames, side, modes)
    covered_at_base = counterpart is not None and \
        exercised_any(counterpart, covered_base, previous, modes)
    return counterpart, vacuous_collision(counterpart, strength, covered_at_base)


def vacuous_collision(counterpart, strength, covered_at_base):
    """A like-name match the base suite never actually executed."""
    return counterpart is not None and strength == 'name' and not covered_at_base


def base_counterpart(row, previous, renames):
    """(Base-side row, strength) of a current consumer, or (None, 'none').

    A rewritten test binds consumers by bare name; the base proof needs the
    function's span as of the base revision. Methods may share one name
    across receivers, so candidates narrow to the row's receiver before
    file or package uniqueness: Check on Alpha is a different unit than
    Check on Beta. Name identity — same file, or a package-unique name —
    resolves with 'name' strength and may prove a like-name collision
    vacuous. Everything else, including rename inversion over tracked
    lost refs, resolves only by body identity with 'body' strength: a
    heuristic counterpart can prove baseline coverage but never prove
    its absence, so it leaves the consumer bound.
    """
    own = [base for base in rows_named(previous, row['name'])
           if base.get('recv', '') == row.get('recv', '')]
    same_file = [base for base in own if base['file'] == row['file']]
    if same_file:
        return unique_match(row, same_file), 'name'
    if len(own) == 1:
        return own[0], 'name'
    moved = [base for base in rows_named(previous, *renamed_from(renames, row['name']))
             if base.get('recv', '') == row.get('recv', '')]
    return unique_match(row, own + moved), 'body'


def rows_named(side, *names):
    """Base production rows carrying any of these function names."""
    rows = []
    for base in side.functions():
        if base['name'] in names:
            rows.append(base)
    return rows


def renamed_from(renames, name):
    """Tracked rename sources whose current name is this function name."""
    sources = set()
    for old, new in renames.items():
        if new == name:
            sources.add(old)
    return sources


def unique_match(row, candidates):
    """The single candidate, the body-identical one, or None when ambiguous."""
    if len(candidates) == 1:
        return candidates[0]
    same_body = [base for base in candidates if base['hash'] == row['hash']]
    return same_body[0] if len(same_body) == 1 else None


def applicable_counterpart(row, previous, renames, side, modes):
    """Counterpart resolution that does not collapse build-mode twins.

    base_counterpart refuses a body-identical twin pair: by identity
    alone, two candidates with the same hash are ambiguous. When exactly
    one candidate also shares the row's build-mode footprint, the pair is
    not ambiguous for this tree's configured modes, and it resolves with
    'body' strength — a heuristic counterpart can prove baseline coverage
    but never prove its absence. Anything still unresolved returns
    (None, 'body') and stays bound for full current-block coverage.
    """
    own = [base for base in rows_named(previous, row['name'])
           if base.get('recv', '') == row.get('recv', '')]
    moved = [base for base in rows_named(previous, *renamed_from(renames, row['name']))
             if base.get('recv', '') == row.get('recv', '')]
    candidates = [base for base in own + moved if base['hash'] == row['hash']]
    footprint = tuple(mode_applies(side, row['file'], index, modes)
                      for index in range(len(modes)))
    matching = [base for base in candidates
                if tuple(mode_applies(previous, base['file'], index, modes)
                         for index in range(len(modes))) == footprint]
    return (matching[0], 'body') if len(matching) == 1 else (None, 'body')


BLOCK_SPEC = re.compile(r'(\d+)\.(\d+),(\d+)\.(\d+)')


def block_span(spec):
    """(start line, start column, end line, end column) of a block spec."""
    match = BLOCK_SPEC.fullmatch(spec)
    if not match:
        raise ValueError('Malformed block spec: ' + spec)
    return tuple(int(part) for part in match.groups())


def baseline_block_losses(row, counterpart, covered_base, covered_now,
                          previous, side, modes):
    """Block-level losses of one consumer, one applying mode at a time."""
    losses = []
    for index in range(len(modes)):
        if mode_applies(side, row['file'], index, modes):
            losses.extend(mode_block_losses(row, counterpart,
                                            covered_base[index],
                                            covered_now[index],
                                            previous, index, modes))
    return losses


def mode_block_losses(row, counterpart, base_rows, now_rows, previous,
                      index, modes):
    """Blocks one mode no longer executes; identical bodies stay aligned.

    An identical body compiles to the same block sequence, so its
    base-executed blocks stay provable by index even across line and
    column shifts; a changed body cannot map its base blocks, so it must
    execute every block it now has. A body with no resolvable base
    counterpart — including a body-identical build-mode twin pair that
    identity alone cannot disambiguate — is in the same position: the
    mode must execute every current block instead of silently
    re-baselining on an unmappable baseline.
    """
    if counterpart is None:
        return uncovered_span(row, now_rows)
    if row['hash'] != counterpart['hash']:
        return uncovered_span(row, now_rows)
    if not mode_applies(previous, counterpart['file'], index, modes):
        return []
    return unpreserved_blocks(counterpart, row, base_rows, now_rows)


def unpreserved_blocks(counterpart, row, base_rows, now_rows):
    """Current-tree specs of base-executed blocks an identical body skipped.

    Identical bodies produce identical block sequences, so the k-th block
    of the current span answers for the k-th base block; a length mismatch
    means the sequences cannot be aligned, and every current block must
    then be executed instead.
    """
    base = in_span(base_rows, counterpart)
    now = in_span(now_rows, row)
    if len(now) != len(base):
        return uncovered_span(row, now_rows)
    return [now[index][3] for index in range(len(base))
            if base[index][2] > 0 and now[index][2] == 0]


def in_span(rows, row):
    """Cover-profile blocks of one function's span, in source order."""
    return sorted((block for block in rows
                   if critical_results.same_file(block[0], row['file'])
                   and row['start'] <= block[1] <= row['end']), key=block_order)


def block_order(block):
    """Numeric source-order key of one cover-profile block."""
    start, start_col, end, end_col = block_span(block[3])
    return (block[1], start_col, end, end_col)


def uncovered_span(row, now_rows):
    """Unexecuted current-tree blocks inside a changed function body."""
    return [spec for file, line, count, spec in now_rows
            if critical_results.same_file(file, row['file'])
            and row['start'] <= line <= row['end'] and count == 0]


def unit_budget(config):
    """Approved unit-kind seconds; a deviating versioned budget is an error.

    Configs without the versioned budget block use the module default, so
    bounded verification runs stay independently tunable.
    """
    block = (config or {}).get('budget')
    if not isinstance(block, dict) or block.get('schema_version') != 1:
        return UNIT_VERIFY_SECONDS
    import critical
    return critical.budget(config)['unit']


def shared_deadline(package, seconds):
    """One wall-clock unit budget per package, created on first use."""
    key = (package, 'unit')
    if key not in DEADLINES:
        DEADLINES[key] = time.monotonic() + seconds
    return DEADLINES[key]


def pause_unit_budget(package):
    """Bank this package's remaining unit budget when verification ends.

    Verification owns an absolute wall deadline, but the pause boundary
    keeps other packages' verification and execution from spending it:
    the remainder is resumed as a fresh deadline only when this
    package's own unit phase starts.
    """
    key = (package, 'unit')
    if key in DEADLINES:
        UNIT_REMAINDERS[key] = max(0.0, DEADLINES[key] - time.monotonic())
        del DEADLINES[key]


def pause_started_unit_budgets():
    """Bank every started package's remaining unit budget.

    Successful selection and verification completion must leave no
    package's deadline running through other packages' execution:
    every started package — no-rewrite packages and cross-package
    consumers included — banks its remainder here, and each resumes its
    own remainder when its unit phase starts.
    """
    for package, kind in sorted(DEADLINES):
        if kind == 'unit':
            pause_unit_budget(package)


def resume_unit_deadline(package, seconds):
    """Unit-phase deadline: the banked remainder, or a fresh full budget."""
    key = (package, 'unit')
    if key not in DEADLINES:
        DEADLINES[key] = time.monotonic() + UNIT_REMAINDERS.pop(key,
                                                                float(seconds))
    return DEADLINES[key]


def run_until_deadline(argv, root, deadline):
    """Run a command in its own process group until a deadline.

    Returns (exit code, combined output); (None, '') when the deadline
    ended the whole process group first. The stdout pipe is closed
    deterministically on every path — ordinary return, deadline and
    error — so a retained Popen can never hold a descriptor open.
    """
    proc = subprocess.Popen(argv, cwd=root, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True,
                            start_new_session=True,
                            env=dict(os.environ, GOWORK='off', GOFLAGS=''))
    try:
        output, _ = proc.communicate(
            timeout=max(0.0, deadline - time.monotonic()))
        return proc.returncode, output
    except subprocess.TimeoutExpired:
        kill_group(proc)
        return None, ''
    finally:
        with contextlib.suppress(OSError, ValueError):
            proc.stdout.close()


def kill_group(proc):
    """Kill a command's whole process group and reap it."""
    with contextlib.suppress(ProcessLookupError):
        os.killpg(proc.pid, signal.SIGKILL)
    proc.wait()


def covered_functions(root, package, mode, origin='current tree', config=None):
    """Executed cover-profile blocks of the unit suite in one mode and tree.

    The run draws from the package's shared unit deadline — the same budget
    the normal unit phase uses — and its whole process group is killed when
    that budget ends, so a hanging suite cannot outlive the budget.
    """
    with tempfile.TemporaryDirectory(prefix='yabanin-baseline-') as tmp:
        profile = Path(tmp) / 'unit.cover'
        argv = ['go', 'test', '-count=1', '-coverprofile=' + str(profile)]
        if mode:
            argv.append('-tags=' + mode)
        argv.append('./' + package)
        deadline = shared_deadline(package, unit_budget(config))
        code, output = run_until_deadline(argv, root, deadline)
        if code is None:
            raise ValueError('unit budget exhausted for ' + package +
                             ' (mode "' + mode + '", ' + origin + ')')
        if code != 0:
            raise ValueError('lost_unit_coverage: unit suite failed for ' + package +
                             ' (mode "' + mode + '", ' + origin + '): ' +
                             output_tail(output))
        return critical_results.ProfileIndex(
            critical_results.coverage_blocks(profile))


def output_tail(output):
    """Compact tail of a failed run's output for the gate error message."""
    return ' '.join(output.split())[-400:]


def exercised(row, profiles, side, modes):
    """Whether one tree's profile rows cover the function in every mode compiling it."""
    for index, rows in enumerate(profiles):
        if mode_applies(side, row['file'], index, modes) and not block_covered(row, rows):
            return False
    return True


def exercised_any(row, profiles, side, modes):
    """Whether at least one applicable mode's profile rows cover the function.

    Baseline vacuousness is an all-modes miss: a consumer some base build
    mode genuinely executed is a real baseline, so a later loss in one
    mode must block instead of discarding the consumer as a like-name
    collision.
    """
    for index, rows in enumerate(profiles):
        if mode_applies(side, row['file'], index, modes) and block_covered(row, rows):
            return True
    return False


def mode_applies(side, path, index, modes):
    """Single-mode configs apply everywhere; mode lists follow the files."""
    return len(modes) <= 1 or applies(side, path, index)


def block_covered(row, rows):
    """Whether any executed block lies inside the function's span."""
    if isinstance(rows, critical_results.ProfileIndex):
        return rows.covered(row['start'], row['end'], row['file'])
    return any(critical_results.same_file(file, row['file'])
               and row['start'] <= line <= row['end'] and count > 0
               for file, line, count, _ in rows)
