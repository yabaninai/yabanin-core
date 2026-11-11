#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Capture actual Go test verdicts underneath the mutation engine."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def main():
    argv = sys.argv[1:]
    real = os.environ['YABANIN_REAL_GO']
    if not argv or argv[0] != 'test':
        os.execv(real, [real, *argv])
    out = Path(os.environ['YABANIN_MUTATION_AUDIT'])
    name = str(time.time_ns()) + '-' + str(os.getpid())
    record = {'argv': argv, 'cwd': os.getcwd(), 'status': 'running'}
    receipt = out / (name + '.json')
    receipt.write_text(json.dumps(record))
    with (out / (name + '.stdout')).open('w') as stdout, (out / (name + '.stderr')).open('w') as stderr:
        result = subprocess.run([real, 'test', '-json', '-count=1', *argv[1:]], stdout=stdout, stderr=stderr)
    record.update(status='complete', exit_code=result.returncode)
    receipt.write_text(json.dumps(record))
    return result.returncode


if __name__ == '__main__':
    sys.exit(main())
