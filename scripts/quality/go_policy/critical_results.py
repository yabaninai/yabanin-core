# SPDX-License-Identifier: Apache-2.0
"""Validate real mutation and fuzz coverage against source-bound declarations."""
import json
import math
from pathlib import Path
import re


def same_file(actual, expected):
    actual = Path(actual).as_posix()
    return actual == expected or actual.endswith('/' + expected)


class ProfileIndex:
    """Precomputed per-file index over one coverage profile's blocks.

    Same-block verdicts, same semantics: queries that previously scanned
    every profile row now scan only the rows of files matching the same
    same_file rule, and the naive row iteration stays available so no
    consumer's result can change.
    """

    __slots__ = ('rows', '_by_file', '_matched', '_by_file_pos',
                 '_matched_rows')

    def __init__(self, rows):
        self.rows = list(rows)
        by_file = {}
        by_file_pos = {}
        for index, (file, line, count, _) in enumerate(self.rows):
            key = Path(file).as_posix()
            by_file.setdefault(key, []).append((line, count))
            by_file_pos.setdefault(key, []).append(index)
        self._by_file = by_file
        self._by_file_pos = by_file_pos
        self._matched = {}
        self._matched_rows = {}

    def __iter__(self):
        return iter(self.rows)

    def matched(self, expected):
        """(line, count) rows of every profile file matching expected."""
        entries = self._matched.get(expected)
        if entries is None:
            entries = []
            for actual, rows in self._by_file.items():
                if same_file(actual, expected):
                    entries.extend(rows)
            self._matched[expected] = entries
        return entries

    def matched_rows(self, expected):
        """Full profile rows of every file matching expected, row order.

        The naive full scans in in_span and uncovered_span keep the
        original row order (sorted() is stable and uncovered_span keeps
        source order), so this accessor must too: bucket positions are
        merged back into one ascending position list before lookup.
        """
        rows = self._matched_rows.get(expected)
        if rows is None:
            positions = []
            for actual, indexes in self._by_file_pos.items():
                if same_file(actual, expected):
                    positions.extend(indexes)
            positions.sort()
            rows = [self.rows[index] for index in positions]
            self._matched_rows[expected] = rows
        return rows

    def covered(self, start, end, expected):
        """Whether any matching file has an executed block inside the span."""
        return any(start <= line <= end and count > 0
                   for line, count in self.matched(expected))


def hits(row, file, line):
    return same_file(file, row['file']) and row['start'] <= line <= row['end']


def normalize_mutation_paths(files, package):
    if not package:
        return
    for file in files:
        name = Path(file['file_name'])
        if not name.is_absolute() and not name.as_posix().startswith(package + '/'):
            file['file_name'] = (Path(package) / name).as_posix()


def mutation_report(path, functions, package=None):
    report = json.loads(Path(path).read_text())
    if not isinstance(report.get('files'), list):
        raise ValueError('Mutation report lacks file results')
    normalize_mutation_paths(report['files'], package)
    checked = []
    for fn in functions:
        mutants = [m for f in report['files'] for m in f.get('mutations', [])
                   if hits(fn, f['file_name'], m['line'])]
        if not mutants:
            raise ValueError('No mutation exercises changed function: ' + fn['file'] + ':' + fn['name'])
        bad = [m for m in mutants if m.get('status') != 'KILLED']
        if bad:
            raise ValueError('Unproven mutation in ' + fn['file'] + ':' + fn['name'] + ': ' + str(bad[0]))
        checked.append({'file': fn['file'], 'function': fn['name'], 'killed': len(mutants)})
    return checked


def coverage_rows(path):
    rows = []
    for line in Path(path).read_text().splitlines()[1:]:
        match = re.fullmatch(r'(.+):(\d+)\.\d+,\d+\.\d+ (\d+) (\d+)', line)
        if not match:
            raise ValueError('Malformed seed coverage: ' + line)
        if int(match[3]) > 0:
            rows.append((match[1], int(match[2]), int(match[4])))
    return rows


def coverage_blocks(path):
    """All cover-profile blocks of a file, keeping unexecuted ones.

    Block-level verification needs the zero-count branches a rewrite no
    longer takes, so unlike coverage_rows nothing is dropped here.
    """
    blocks = []
    for line in Path(path).read_text().splitlines()[1:]:
        match = re.fullmatch(r'(.+):(\d+)\.(\d+),(\d+)\.(\d+) (\d+) (\d+)', line)
        if not match:
            raise ValueError('Malformed block coverage: ' + line)
        spec = match[2] + '.' + match[3] + ',' + match[4] + '.' + match[5]
        # match[6] counts statements of the block; match[7] its executions.
        blocks.append((match[1], int(match[2]), int(match[7]), spec))
    return blocks


def seed_coverage(path, functions):
    rows = coverage_rows(path)
    for fn in functions:
        counts = [count for file, line, count in rows if hits(fn, file, line)]
        if not counts or not all(count > 0 for count in counts):
            raise ValueError('Fuzz seeds do not cover every changed-function block: ' + fn['file'] + ':' + fn['name'])


def seed_coverage_report(path, functions):
    """Uncovered-block evidence per seed-demanding function, without verdicts.

    Mirrors the seed_coverage predicate exactly: a function fails when its
    span holds no stmts>0 profile block at all or any block the replay
    never executed. Blocks are identified by their full profile spec —
    start lines alone can collide between sibling blocks — so counts stay
    exact. A function whose span has no profile rows is reported with
    profile_rows: 0; reporting zero uncovered blocks with no profile
    evidence at all would not be a meaningful report. This parser keeps
    the statement counts that coverage_blocks drops so the predicate
    parity (stmts>0) is preserved. Used only by the Preview2 seed-block
    override to record what it deferred; the default verdict and error
    text stay untouched.
    """
    blocks = []
    for line in Path(path).read_text().splitlines()[1:]:
        match = re.fullmatch(r'(.+):(\d+)\.(\d+),(\d+)\.(\d+) (\d+) (\d+)', line)
        if not match:
            raise ValueError('Malformed block coverage: ' + line)
        spec = match[2] + '.' + match[3] + ',' + match[4] + '.' + match[5]
        blocks.append((match[1], int(match[2]), int(match[6]), int(match[7]), spec))
    failing = []
    for fn in functions:
        in_range = [(count, spec) for file, line, stmts, count, spec in blocks
                    if stmts > 0 and hits(fn, file, line)]
        uncovered = sorted(spec for count, spec in in_range if count == 0)
        if not in_range or uncovered:
            entry = {'file': fn['file'], 'function': fn['name'],
                     'uncovered_blocks': len(uncovered), 'blocks': uncovered}
            if not in_range:
                entry['profile_rows'] = 0
            failing.append(entry)
    return failing


def fuzz_executions(log):
    counts = re.findall(r'execs:\s*(\d+)', Path(log).read_text())
    if not counts or max(map(int, counts)) == 0:
        raise ValueError('Fuzz run has no confirmed executions: ' + str(log))
    return max(map(int, counts))


def baseline_retry_window(log):
    """Evidence-based bounded retry window for a baseline-only attempt.

    Projects the seed-corpus baseline cost from the LAST progress line
    (elapsed * total / completed) and sizes the whole retry at 1.25x that
    projected total plus a 2s margin, so the corpus finishes with headroom
    to generate real executions. Hand checks: 3s@78/288 -> 16s and
    12s@332/378 -> 20s (the f496f5d critical-go evidence shapes). A
    slow-first-seed shape — nothing completed but the engine visibly spent
    elapsed>0 — is valid too and gets the bounded fallback 2*elapsed + 2s
    (6s@0/25 -> 14s). Returns None when the evidence cannot support any
    estimate — no progress line, elapsed 0 with zero completed, zero or
    impossible totals — and such attempts earn no retry.
    """
    matches = re.findall(
        r'fuzz: elapsed: (\d+)s, gathering baseline coverage: (\d+)/(\d+) completed',
        Path(log).read_text())
    if not matches:
        return None
    elapsed, completed, total = (int(value) for value in matches[-1])
    if total <= 0:
        return None
    if completed <= 0:
        if elapsed <= 0:
            return None
        return max(1, 2 * elapsed + 2)
    if completed > total:
        return None
    projected = elapsed * total / completed
    return max(1, math.ceil(1.25 * projected + 2))


def baseline_only_fuzz_log(log):
    """True when a completed fuzz run never got past seed-corpus baseline.

    Matches exactly the evidence shape that earns the bounded retry: the
    engine printed baseline coverage gathering progress, finished PASS, and
    never confirmed a generated execution. Crashes, FAIL lines, build errors
    and printed zero-execution progress all fail this check and stay red.
    """
    text = Path(log).read_text()
    if 'FAIL' in text:
        return False
    if not re.search(r'^PASS$', text, flags=re.M):
        return False
    if not re.search(r'gathering baseline coverage:', text):
        return False
    return not re.search(r'execs:', text)
