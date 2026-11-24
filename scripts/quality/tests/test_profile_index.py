# SPDX-License-Identifier: Apache-2.0
"""ProfileIndex regression and performance controls.

The index must return exactly the verdicts of the naive same-file scan
that preceded it: same_file matching, block spans, zero counts and
suffix twins behave identically, and lookups stay fast on profiles
where the naive per-query scan takes minutes.
"""
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'go_policy'))
import critical_results


def naive_covered(row, rows):
    """Reference formula: the pre-index scan, word for word."""
    return any(critical_results.same_file(file, row['file'])
               and row['start'] <= line <= row['end'] and count > 0
               for file, line, count, _ in rows)


ROWS = [
    ('/repo/pkg/a.go', 10, 3, '10.1,10.2 1 3'),
    ('/repo/pkg/a.go', 16, 0, '16.1,16.2 1 0'),
    ('/repo/pkg/b.go', 5, 2, '5.1,5.2 1 2'),
    ('other/other/pkg/a.go', 10, 7, '10.1,10.2 2 7'),
]


def test_literal_hand_computed_verdicts():
    """Expected results computed by hand from the fixture rows above."""
    index = critical_results.ProfileIndex(ROWS)
    assert index.covered(9, 15, 'pkg/a.go') is True
    assert index.covered(16, 20, 'pkg/a.go') is False
    assert index.covered(5, 6, 'pkg/b.go') is True
    assert index.covered(5, 6, 'pkg/c.go') is False
    assert index.covered(1, 4, 'pkg/a.go') is False
    assert index.covered(11, 12, 'pkg/a.go') is False
    # '/repo/pkg/a.go' does not end with '/other/pkg/a.go', so the
    # expected suffix twin is only the other/other copy.
    assert index.covered(9, 15, 'other/pkg/a.go') is True
    assert naive_covered(
        {'file': 'other/pkg/a.go', 'start': 9, 'end': 15}, ROWS) is True
    # Naive iteration over the index sees the same blocks.
    assert sorted(index) == sorted(ROWS)


def test_block_covered_fast_path_matches_naive_rows():
    """critical_conservative.block_covered agrees on both containers."""
    import critical_conservative
    index = critical_results.ProfileIndex(ROWS)
    row = {'file': 'pkg/a.go', 'start': 9, 'end': 15}
    assert critical_conservative.block_covered(row, index) is True
    assert critical_conservative.block_covered(row, ROWS) is True
    row_zero = {'file': 'pkg/a.go', 'start': 16, 'end': 20}
    assert critical_conservative.block_covered(row_zero, index) is False
    assert critical_conservative.block_covered(row_zero, ROWS) is False


def test_randomized_equivalence_with_naive_scan():
    """Seeded fixture: index verdicts equal the naive scan everywhere."""
    rng = random.Random(20261122)
    files = ['pkg/a.go', 'pkg/b.go', 'pkg/c.go']
    rows = []
    for name in files:
        for line in range(1, 400):
            if rng.random() < 0.3:
                rows.append(('/repo/' + name, line,
                             rng.choice([0, 0, 1, 2, 7]),
                             str(line) + '.1,1.2 1 0'))
    rows.sort()
    index = critical_results.ProfileIndex(rows)
    for _ in range(400):
        start = rng.randint(1, 400)
        end = rng.randint(start, 400)
        expected_file = rng.choice(files + ['pkg/missing.go'])
        row = {'file': expected_file, 'start': start, 'end': end}
        assert index.covered(start, end, expected_file) == \
            naive_covered(row, rows)


def test_index_lookup_performance_control():
    """3000 span queries over a 40k-row profile finish well bounded.

    Independent expected result: every even line carries count 1 in this
    fixture, so the full span of every file must return True; the same
    volume through the naive scan is the minutes-long path this gate
    hung on.
    """
    rng = random.Random(7)
    rows = []
    for f in range(1200):
        path = '/repo/bundle%03d/file%03d.go' % (f // 100, f)
        for line in range(1, 34):
            count = 1 if line % 2 == 0 else rng.choice([0, 0, 1, 3])
            rows.append((path, line, count, ''))
    rows.sort()
    index = critical_results.ProfileIndex(rows)
    started = time.monotonic()
    verdicts = [index.covered(
        1, 33, 'bundle%03d/file%03d.go' % (f // 100, f))
        for f in (rng.randint(0, 1199) for _ in range(3000))]
    elapsed = time.monotonic() - started
    assert verdicts == [True] * 3000
    assert elapsed < 10.0, 'index lookups took %.2fs' % elapsed
