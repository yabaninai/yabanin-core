# SPDX-License-Identifier: Apache-2.0
"""Side-owned reverse-edge cache regression and performance controls.

helper_callers previously rebuilt the immutable reverse helper graph on
every call; the graph is now materialized once per immutable Side
snapshot. The controls pin three facts: identical verdicts against a
verbatim reference walk of the former code path, exactly one graph
build per Side instance (new snapshots rebuild), and bounded lookup
cost on a large test-unit fixture.
"""
import sys
import time
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'go_policy'))
import critical_conservative as cc


def unit(name, refs, recv='', kind='', symbols=()):
    return {'name': name, 'recv': recv, 'start': 1, 'end': 3,
            'hash': 'h', 'refs': list(refs), 'floor_refs': [],
            'symbols': list(symbols), 'kind': kind}


def side_with(units):
    return cc.Side([{'path': 'pkg/auth/auth_test.go', 'units': units}],
                   Path('.'))


FIXTURE_UNITS = [
    unit('helperFunc', ['Allowed']),
    unit('TestA', ['helperFunc']),
    unit('', ['helperFunc'], kind='var', symbols=['relay']),
    unit('TestVar', ['relay']),
]
FIXTURE_HELPER = unit('helperFunc', [])
# Hand-computed: TestA references helperFunc directly; the var
# initializer relay also builds from helperFunc, and TestVar references
# relay, so the walk reports the direct caller and the chained one.
EXPECTED = {'TestA', 'TestVar'}


def reference_walk(side, helper):
    """Verbatim former code path: rebuild + BFS from helper_keys."""
    edges = cc.build_reverse_edges(side)
    affected = set()
    frontier, seen = list(cc.helper_keys(helper)), set()
    while frontier:
        key = frontier.pop()
        if key in seen:
            continue
        seen.add(key)
        for caller in edges.get(key, ()):
            if cc.parse_key(caller)[1].startswith(cc.TEST_PREFIXES):
                affected.add(cc.parse_key(caller)[1])
            else:
                frontier.append(caller)
    return affected


def test_helper_callers_matches_reference_walk():
    side = side_with(FIXTURE_UNITS)
    assert cc.helper_callers(FIXTURE_HELPER, side) == EXPECTED
    assert reference_walk(side, FIXTURE_HELPER) == EXPECTED
    # Repeated and cached lookups stay identical.
    assert cc.helper_callers(FIXTURE_HELPER, side) == \
        reference_walk(side, FIXTURE_HELPER)


def test_graph_builds_once_per_side_snapshot():
    side = side_with(FIXTURE_UNITS)
    other = side_with(FIXTURE_UNITS)
    with mock.patch.object(cc, 'build_reverse_edges',
                           wraps=cc.build_reverse_edges) as builds:
        cc.helper_callers(FIXTURE_HELPER, side)
        cc.helper_callers(FIXTURE_HELPER, side)
        assert side.reverse_edges() is side.reverse_edges()
        assert builds.call_count == 1, builds.call_count
        cc.helper_callers(FIXTURE_HELPER, other)
        assert builds.call_count == 2, builds.call_count


def test_many_lookups_stay_bounded():
    """300 lookups over 400 test units build the graph exactly once."""
    units = [unit('helperFunc', [])]
    units += [unit('Test%03d' % i, ['helperFunc']) for i in range(200)]
    units += [unit('Test%03d' % i, ['relay']) for i in range(200, 400)]
    units.append(unit('', ['helperFunc'], kind='var', symbols=['relay']))
    side = side_with(units)
    helpers = [u for u in units if u['name'] == 'helperFunc']
    with mock.patch.object(cc, 'build_reverse_edges',
                           wraps=cc.build_reverse_edges) as builds:
        started = time.monotonic()
        results = [cc.helper_callers(helpers[0], side) for _ in range(300)]
        elapsed = time.monotonic() - started
        assert builds.call_count == 1, builds.call_count
    assert all(r == results[0] for r in results)
    assert elapsed < 10.0, 'cached lookups took %.2fs' % elapsed
