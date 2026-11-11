# SPDX-License-Identifier: Apache-2.0
"""Reject false mutation kills caused by Go invocation or compilation errors."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import tempfile


@contextmanager
def environment(out):
    audit = out / 'go-audit'
    audit.mkdir()
    real = shutil.which('go')
    if not real:
        raise ValueError('Go executable is missing')
    with tempfile.TemporaryDirectory(prefix='yabanin-go-audit-') as tmp:
        wrapper = Path(tmp) / 'go'
        shutil.copyfile(Path(__file__).with_name('go_audit.py'), wrapper)
        wrapper.chmod(0o755)
        yield {'PATH': tmp + os.pathsep + os.environ.get('PATH', ''),
               'YABANIN_REAL_GO': real, 'YABANIN_MUTATION_AUDIT': str(audit.resolve()),
               'GOMAXPROCS': '1'}


def invocation(path):
    data = json.loads(path.read_text())
    if data.get('status') != 'complete':
        raise ValueError('Unfinished mutation test process: ' + str(path))
    stdout = path.with_suffix('.stdout').read_text()
    stderr = path.with_suffix('.stderr').read_text()
    rows = [json.loads(line) for line in stdout.splitlines() if line.strip()]
    if any(marker in stdout + stderr for marker in ('[build failed]', 'test timed out', 'flag provided but not defined')):
        raise ValueError('Mutation build, invocation or timeout failure: ' + str(path))
    return test_verdict(rows, data['exit_code'], path)


def test_verdict(rows, exit_code, path):
    events = {row.get('Action') for row in rows if row.get('Test')}
    if exit_code not in (0, 1) or (exit_code == 1 and 'fail' not in events):
        raise ValueError('Mutation failure has no actual failing test: ' + str(path))
    if not events.intersection({'pass', 'fail'}):
        raise ValueError('Mutation run has no executed tests: ' + str(path))
    return int(exit_code == 1)


def validate(directory, report):
    paths = sorted(directory.glob('*.json'))
    if not paths:
        raise ValueError('Mutation engine did not produce audited Go test executions')
    failed_tests = sum(invocation(path) for path in paths)
    claimed = json.loads(report.read_text()).get('mutants_killed')
    if claimed != failed_tests:
        raise ValueError(f'Mutation kill count differs from real test failures: {claimed} != {failed_tests}')
