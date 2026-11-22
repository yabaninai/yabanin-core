# SPDX-License-Identifier: Apache-2.0
"""Independent equivalence controls for the span fast paths.

in_span and uncovered_span previously scanned every profile row with
same_file; they now consult ProfileIndex.matched_rows when handed an
index. The reference implementations below are verbatim copies of the
former full scans, so every control compares the indexed result against
an implementation that shares no code with the indexed path.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'go_policy'))
import critical_conservative as cc
import critical_results as cr


# Verbatim former full scans: the independent references.
def reference_in_span(rows, row):
    return sorted((block for block in rows
                   if cr.same_file(block[0], row['file'])
                   and row['start'] <= block[1] <= row['end']),
                  key=cc.block_order)


def reference_uncovered_span(row, now_rows):
    return [spec for file, line, count, spec in now_rows
            if cr.same_file(file, row['file'])
            and row['start'] <= line <= row['end'] and count == 0]


# Hand-computed interleaved fixture: three files, duplicate span keys
# inside one file (stable-sort tie), twin file that must NOT match.
ROWS = [
    ('pkg/a.go', 10, 1, '10.1,10.2'),
    ('pkg/a.go', 12, 0, '12.1,12.2'),
    ('xpkg/a.go', 10, 1, '10.1,10.9'),
    ('other/b.go', 11, 0, '11.1,11.2'),
    ('pkg/a.go', 10, 1, '10.1,10.2'),
    ('deep/pkg/a.go', 15, 1, '15.1,15.9'),
    ('other/b.go', 20, 3, '20.1,20.2'),
]
ROW = {'file': 'pkg/a.go', 'start': 8, 'end': 16, 'name': 'A', 'hash': 'h'}
# matched_rows must reproduce the original list order exactly:
# positions 0,1,4 for pkg/a.go plus 5 for deep/pkg/a.go; the twin at 2
# and other/b.go rows stay out.
EXPECTED_MATCHED = [ROWS[0], ROWS[1], ROWS[4], ROWS[5]]


def test_matched_rows_preserves_original_row_order():
    index = cr.ProfileIndex(ROWS)
    matched = index.matched_rows('pkg/a.go')
    assert matched == EXPECTED_MATCHED, matched
    assert matched == [row for row in ROWS
                       if cr.same_file(row[0], 'pkg/a.go')]
    # Repeat and re-check: cached result stays identical.
    assert index.matched_rows('pkg/a.go') == EXPECTED_MATCHED
    assert index.matched_rows('missing.go') == []


def test_in_span_index_equals_reference():
    index = cr.ProfileIndex(ROWS)
    fast = cc.in_span(index, ROW)
    assert fast == reference_in_span(ROWS, ROW)
    # Hand-checked: the two line-10 blocks tie on the sort key and keep
    # original order, then line 12 and line 15.
    assert [block[3] for block in fast] == ['10.1,10.2', '10.1,10.2',
                                            '12.1,12.2', '15.1,15.9']


def test_uncovered_span_index_equals_reference():
    index = cr.ProfileIndex(ROWS)
    fast = cc.uncovered_span(ROW, index)
    assert fast == reference_uncovered_span(ROW, ROWS)
    # Hand-checked zero-count specs inside the span, original order.
    assert fast == ['12.1,12.2']


def test_fallback_plain_list_unchanged():
    assert cc.in_span(ROWS, ROW) == reference_in_span(ROWS, ROW)
    assert cc.uncovered_span(ROW, ROWS) == reference_uncovered_span(ROW, ROWS)
    # Index path and fallback path agree on the same data.
    index = cr.ProfileIndex(ROWS)
    assert cc.in_span(index, ROW) == cc.in_span(ROWS, ROW)
    assert cc.uncovered_span(ROW, index) == cc.uncovered_span(ROW, ROWS)


def test_suffix_twin_and_missing_file_negatives():
    index = cr.ProfileIndex(ROWS)
    # xpkg/a.go is a plain suffix twin: must never join pkg/a.go buckets.
    assert index.matched_rows('pkg/a.go') == EXPECTED_MATCHED
    assert all(row[3] != 'TWIN' for row in index.matched_rows('pkg/a.go'))
    assert cc.in_span(index, {'file': 'nope/x.go', 'start': 0, 'end': 99,
                              'name': 'N', 'hash': 'h'}) == []
    assert cc.uncovered_span({'file': 'nope/x.go', 'start': 0, 'end': 99,
                              'name': 'N', 'hash': 'h'}, index) == []
    assert reference_in_span(ROWS, {'file': 'nope/x.go', 'start': 0,
                                    'end': 99, 'name': 'N', 'hash': 'h'}) == []
