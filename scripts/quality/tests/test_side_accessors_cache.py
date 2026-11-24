# SPDX-License-Identifier: Apache-2.0
"""Side.functions / Side.test_units / rows_named cache regression controls.

functions() and test_units() previously rebuilt their row lists on
every call; rows_named() additionally rescanned the whole production
side per call. All three now read materializations cached per immutable
Side snapshot (the closure, production and reverse-edge index pattern).
The controls pin four facts: identical results against verbatim
reference rebuilds of the former code paths, one materialization per
Side snapshot with distinct snapshots rebuilding independently, no
mutation leaking between callers, and bounded repeated-call cost on a
multi-file fixture.
"""
import sys
import time
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'go_policy'))
import critical_conservative as cc


def unit(name):
    return {'name': name, 'recv': '', 'start': 1, 'end': 2,
            'hash': 'h-' + (name or 'anon'), 'refs': [], 'floor_refs': [],
            'symbols': [], 'kind': 'func'}


def side_with():
    rows = [
        {'path': 'pkg/a/a.go', 'units': [unit('Alpha'), unit(''), unit('Beta')]},
        {'path': 'pkg/a/a_test.go', 'units': [unit('TestAlpha'), unit('helper')]},
        {'path': 'pkg/b/b.go', 'units': [unit('Gamma'), unit('Alpha')]},
    ]
    return cc.Side(rows, Path('.'))


def reference_functions(side):
    """Verbatim former code path: rebuild on every call."""
    rows = []
    for path in side.production:
        rows.extend(dict(u, file=path) for u in side.files[path]['units'] if u['name'])
    return rows


def reference_test_units(side):
    rows = []
    for path in side.tests:
        rows.extend(dict(u, file=path) for u in side.files[path]['units'] if u['name'])
    return rows


def test_accessors_match_reference_rebuild():
    side = side_with()
    assert side.functions() == reference_functions(side)
    assert side.test_units() == reference_test_units(side)
    # Repeated calls stay identical to the reference walk.
    assert side.functions() == reference_functions(side)
    assert side.test_units() == reference_test_units(side)


def test_rows_materialize_once_per_side_snapshot():
    side = side_with()
    other = side_with()
    first = side.functions()
    assert side.functions() is first
    assert side.test_units() is side.test_units()
    # A distinct snapshot rebuilds independently with equal content.
    assert other.functions() == first
    assert other.functions() is not first


def test_repeated_calls_stay_bounded():
    side = side_with()
    started = time.monotonic()
    functions = [side.functions() for _ in range(300)]
    test_units = [side.test_units() for _ in range(300)]
    elapsed = time.monotonic() - started
    assert all(rows is functions[0] for rows in functions)
    assert all(rows is test_units[0] for rows in test_units)
    assert elapsed < 1.0, 'cached accessors took %.3fs' % elapsed


def reference_rows_named(side, names):
    """Verbatim former rows_named: membership rescan of every row."""
    rows = []
    for base in side.functions():
        if base['name'] in names:
            rows.append(base)
    return rows


def rows_identity(rows):
    """Order-free row multiset: callers resolve by membership, not order."""
    return sorted((row['file'], row['name'], row['hash']) for row in rows)


def test_rows_named_matches_reference_rebuild():
    side = side_with()
    for names in [('Alpha',), ('Beta',), ('Alpha', 'Beta'), ('Gamma',),
                  ('Alpha', 'Alpha'), ('Missing',), ()]:
        assert rows_identity(cc.rows_named(side, *names)) == \
            rows_identity(reference_rows_named(side, set(names))), names
    # A single name keeps the production order of its row group.
    single = cc.rows_named(side, 'Alpha')
    assert [row['file'] for row in single] == ['pkg/a/a.go', 'pkg/b/b.go']
    assert cc.rows_named(side, 'Alpha') == single


def test_rows_named_reads_cached_index_without_rescan():
    side = side_with()
    with mock.patch.object(side, 'functions', wraps=side.functions) as scans:
        first = cc.rows_named(side, 'Alpha')
        for _ in range(50):
            cc.rows_named(side, 'Alpha', 'Beta')
    # One warm-up build total: rows_named never rescans production rows.
    assert scans.call_count == 1, scans.call_count
    assert [row['name'] for row in first] == ['Alpha', 'Alpha']


def test_rows_named_returns_fresh_lists_over_shared_rows():
    side = side_with()
    first = cc.rows_named(side, 'Alpha')
    second = cc.rows_named(side, 'Alpha')
    assert first == second and first is not second
    # Mutating a returned list must not leak into later calls or the side.
    first.append(unit('Extra'))
    del second[0]
    assert cc.rows_named(side, 'Alpha') == reference_rows_named(side, {'Alpha'})
    assert side.functions() == reference_functions(side)


def test_rows_named_rebuilds_per_distinct_side_snapshot():
    one, other = side_with(), side_with()
    assert cc.rows_named(one, 'Alpha') == cc.rows_named(other, 'Alpha')
    assert cc.rows_named(one, 'Alpha') is not cc.rows_named(other, 'Alpha')
