# SPDX-License-Identifier: Apache-2.0
"""Validate real mutation and fuzz coverage against source-bound declarations."""
import json
from pathlib import Path
import re


def same_file(actual, expected):
    actual = Path(actual).as_posix()
    return actual == expected or actual.endswith('/' + expected)


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
