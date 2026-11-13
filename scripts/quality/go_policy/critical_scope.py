# SPDX-License-Identifier: Apache-2.0
"""Bind critical checks to changed production declarations, not file counts."""
from collections import Counter
from fnmatch import fnmatchcase
import os
from pathlib import Path
import tempfile

import policy
import source

MODE_ENV = 'CRITICAL_SCOPE_SELECTOR'
LEGACY = 'legacy'
CONSERVATIVE = 'conservative'


def selector_mode():
    """Selector variant for this run; conservative stays strictly opt-in."""
    value = os.environ.get(MODE_ENV, LEGACY)
    if value not in (LEGACY, CONSERVATIVE):
        raise ValueError('Unknown ' + MODE_ENV + ' value: ' + value)
    return value


def selection_evidence():
    """Binding evidence of the last conservative selection, for reports."""
    import critical_conservative
    return critical_conservative.EVIDENCE['packages']


def is_critical(path, patterns):
    return path.endswith('.go') and any(fnmatchcase(path, glob) for glob in patterns)


def packages(root, base, patterns):
    changed = source.changes(root, base)
    return sorted({str(Path(p).parent) for p in changed if is_critical(p, patterns)})


def package_files(root, package):
    return [p for p in source.files(root) if str(Path(p).parent) == package and
            p.endswith('.go') and not p.endswith('_test.go') and (root / p).is_file()]


def test_contracts(root, paths, helper):
    selected = [p for p in paths if p.endswith('_test.go') and (root / p).is_file()]
    units = policy.unit_maps(root, selected, helper)
    return Counter((u['name'], u['hash']) for rows in units.values() for u in rows)


def tests_changed(root, baseline, package, helper):
    current = [p for p in source.files(root) if str(Path(p).parent) == package]
    previous = [p.relative_to(baseline).as_posix() for p in (baseline / package).glob('*_test.go')]
    return test_contracts(root, current, helper) != test_contracts(baseline, previous, helper)


def declarations(units):
    return Counter(u['hash'] for rows in units.values() for u in rows if not u['name'])


def changed_rows(current, old, all_functions):
    rows = []
    for path, units in current.items():
        for unit in units:
            known = old[unit['hash']] > 0
            if unit['name'] and (all_functions or not known):
                rows.append(dict(unit, file=path))
            if known:
                old[unit['hash']] -= 1
    return rows


def changed_functions(root, baseline, package, helper):
    paths = package_files(root, package)
    current = policy.unit_maps(root, paths, helper)
    old_paths = [p.relative_to(baseline).as_posix() for p in (baseline / package).glob('*.go')
                 if not p.name.endswith('_test.go')]
    previous = policy.unit_maps(baseline, old_paths, helper)
    old = Counter(u['hash'] for units in previous.values() for u in units)
    force = declarations(current) != declarations(previous) or tests_changed(root, baseline, package, helper)
    rows = changed_rows(current, old, force)
    if force and not rows:
        raise ValueError('Critical declaration/test change needs explicit consumer coverage: ' + package)
    return rows


def targets(root, base, config):
    mode = selector_mode()
    if mode == CONSERVATIVE:
        import critical_conservative
        selected = critical_conservative.packages(root, base, config['critical_paths'])
        changes = source.changes(root, base)
        critical_conservative.EVIDENCE['packages'] = {}
    else:
        selected = packages(root, base, config['critical_paths'])
    if not selected:
        return {}
    result = {}
    with tempfile.TemporaryDirectory(prefix='yabanin-critical-base-') as tmp:
        baseline = Path(tmp)
        source.archive(root, base, baseline)
        for package in selected:
            if not package_files(root, package):
                continue
            if mode == CONSERVATIVE:
                rows = critical_conservative.changed_functions(root, baseline, package,
                                                               policy.HERE / 'units.go', changes)
            else:
                rows = changed_functions(root, baseline, package, policy.HERE / 'units.go')
            if rows:
                result[package] = rows
    return result
