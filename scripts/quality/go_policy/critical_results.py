# SPDX-License-Identifier: Apache-2.0
"""Validate real mutation and fuzz coverage against source-bound declarations."""
import json
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

    __slots__ = ('rows', '_by_file', '_matched')

    def __init__(self, rows):
        self.rows = list(rows)
        by_file = {}
        for file, line, count, _ in self.rows:
            by_file.setdefault(Path(file).as_posix(), []).append((line, count))
        self._by_file = by_file
        self._matched = {}

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


def fuzz_executions(log):
    counts = re.findall(r'execs:\s*(\d+)', Path(log).read_text())
    if not counts or max(map(int, counts)) == 0:
        raise ValueError('Fuzz run has no confirmed executions: ' + str(log))
    return max(map(int, counts))
