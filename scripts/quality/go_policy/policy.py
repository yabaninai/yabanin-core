#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reject new policy findings and old findings inside changed Go declarations."""
import argparse
from collections import Counter
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

import source

HERE = Path(__file__).resolve().parent
CONFIG = HERE / 'linters.yml'
VERSION = '2.15.0'


def module_paths(root):
    paths = [Path(p).parent for p in source.files(root) if Path(p).name == 'go.mod']
    present = [p for p in paths if (root / p / 'go.mod').is_file()]
    if not present:
        raise ValueError('No Go modules found; analysis cannot be empty')
    return present


def unit_maps(root, paths, helper):
    if not paths:
        return {}
    proc = subprocess.run(['go', 'run', str(helper)], cwd=root, input=json.dumps(paths),
                          text=True, capture_output=True, timeout=120, check=True,
                          env=dict(os.environ, GOWORK='off', GOFLAGS=''))
    return {row['path']: row['units'] for row in json.loads(proc.stdout)}


def parse_issues(path, module, root):
    report = json.loads(path.read_text())
    if 'Issues' not in report:
        raise ValueError('Linter output has no Issues field')
    errors = report.get('Report', {}).get('Error')
    if errors:
        raise ValueError('Linter reported an operational error: ' + str(errors))
    rows = []
    for issue in report['Issues'] or []:
        if issue['FromLinter'] == 'typecheck':
            raise ValueError('Type checking failed: ' + issue['Text'])
        file = Path(issue['Pos']['Filename'])
        file = file.relative_to(root) if file.is_absolute() else module / file
        rows.append({'file': file.as_posix(), 'line': issue['Pos']['Line'],
                     'rule': issue['FromLinter'], 'message': issue['Text']})
    return rows


def scan(root, modules, linter, tags, target):
    target.mkdir(parents=True, exist_ok=True)
    result = []
    for index, module in enumerate(modules):
        for mode, build_tags in enumerate(tags):
            report = target / f'{index}-{mode}.json'
            argv = [linter, 'run', '--config', str(CONFIG), '--path-mode=abs',
                    '--output.json.path', str(report), '--timeout=5m',
                    '--build-tags=' + build_tags, './...']
            code = source.execute(argv, root / module, report.with_suffix('.log'), 330)
            if code not in (0, 1) or not report.is_file():
                raise ValueError(f'Linter failed ({code}); inspect {report.with_suffix(".log")}')
            rows = parse_issues(report, module, root)
            if code == 1 and not rows:
                raise ValueError('Linter exited 1 without findings')
            result.extend(rows)
    return list({json.dumps(row, sort_keys=True): row for row in result}.values())


def annotate(rows, units):
    result = []
    for row in rows:
        matches = [u for u in units.get(row['file'], []) if u['start'] <= row['line'] <= u['end']]
        item = min(matches, key=lambda u: u['end'] - u['start']) if matches else None
        result.append(dict(row, symbol=item['name'] if item else '',
                           unit_sha256=item['hash'] if item else ''))
    return result


def finding_key(row):
    return row['rule'], row['message'], row['unit_sha256'] or row['file']


def classify(base, head):
    old = Counter(finding_key(row) for row in base)
    debt, blocked = [], []
    for row in head:
        key = finding_key(row)
        if old[key]:
            debt.append(row)
            old[key] -= 1
        else:
            blocked.append(row)
    return debt, blocked


def reject_new_suppressions(root, base):
    patch = source.git(root, 'diff', '--no-ext-diff', '--unified=0', base, '--', '*.go').decode()
    added = [line[1:] for line in patch.splitlines() if line.startswith('+') and not line.startswith('+++')]
    for name in source.names(source.git(root, 'ls-files', '--others', '--exclude-standard', '-z')):
        if name.endswith('.go'):
            added.extend((root / name).read_text().splitlines())
    forbidden = ('nolint', 'exhaustive:ignore', 'exhaustive:enforce', 'Code generated')
    if any('//' in line and any(word in line for word in forbidden) for line in added):
        raise ValueError('New analyzer suppression/generated directive needs independent policy review')


def baseline_findings(root, base, modules, linter, tags, out):
    with tempfile.TemporaryDirectory(prefix='yabanin-policy-base-') as tmp:
        baseline = Path(tmp)
        source.archive(root, base, baseline)
        available = [m for m in modules if (baseline / m / 'go.mod').exists()]
        findings = scan(baseline, available, linter, tags, out / 'base')
        units = unit_maps(baseline, sorted({r['file'] for r in findings}), HERE / 'units.go')
        return annotate(findings, units)


def compare(root, base, linter, tags, out):
    modules = module_paths(root)
    findings = scan(root, modules, linter, tags, out / 'head')
    units = unit_maps(root, sorted({r['file'] for r in findings}), HERE / 'units.go')
    head = annotate(findings, units)
    old = baseline_findings(root, base, modules, linter, tags, out)
    advisory = [row for row in head if row['rule'] == 'gocritic']
    debt, blocked = classify([r for r in old if r['rule'] != 'gocritic'],
                             [r for r in head if r['rule'] != 'gocritic'])
    return debt, blocked, advisory


def run(args):
    root, out = args.root.resolve(), args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    if any((out / p).exists() for p in ('head', 'base', 'report.json')):
        raise ValueError('Use a fresh output directory; existing evidence is preserved')
    base = source.git(root, 'rev-parse', '--verify', '--end-of-options', args.base + '^{commit}').decode().strip()
    before = source.snapshot(root)
    environment = source.environment(root, args.linter)
    version = subprocess.check_output([args.linter, 'version'], text=True)
    if f'version {VERSION} ' not in version:
        raise ValueError('Expected pinned golangci-lint ' + VERSION)
    reject_new_suppressions(root, base)
    debt, blocked, advisory = compare(root, base, args.linter, args.tags, out)
    if source.snapshot(root) != before or source.environment(root, args.linter) != environment:
        raise ValueError('Source/tool environment changed during policy analysis')
    report = {'base': base, 'source': before, 'linter': version.strip(), 'environment': environment, 'build_tags': args.tags,
              'config_sha256': source.digest(CONFIG), 'legacy_debt': debt, 'blocking': blocked,
              'advisory': advisory,
              'status': 'failed' if blocked else 'passed'}
    source.write(out / 'report.json', report)
    print(f'Go policy: {len(blocked)} blocking, {len(debt)} untouched debt; {out / "report.json"}')
    print('Report SHA256: ' + source.digest(out / 'report.json'))
    for row in blocked[:10]:
        print(f"{row['file']}:{row['line']}: {row['rule']}: {row['message']}")
    return int(bool(blocked))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=HERE.parents[2])
    parser.add_argument('--base', required=True)
    parser.add_argument('--linter', required=True)
    parser.add_argument('--tags', action='append', default=[''])
    parser.add_argument('--output', type=Path, default=Path('artifacts/quality/go-policy'))
    try:
        return run(parser.parse_args())
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        print('Go policy error: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
