#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bounded real fuzz and mutation gates for changed critical Go packages."""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

import mutation_audit
import critical_results as results
import critical_scope as scope
import source

HERE = Path(__file__).resolve().parent


def remaining(deadline):
    value = deadline - time.monotonic()
    if value < 1:
        raise TimeoutError('Per-package check budget exhausted; incomplete is not passed')
    return value


def checked(argv, root, log, deadline, env=None):
    code = source.execute(argv, root, log, remaining(deadline), env_updates=env)
    if code:
        raise ValueError(f'Critical check exited {code}: {log}')


def go_args(tags):
    return ['go', 'test', '-count=1', '-parallel=1', *(['-tags=' + tags] if tags else [])]


def fuzz_targets(root, package, tags, out, deadline):
    listing = out / 'fuzz-list.log'
    checked(go_args(tags) + ['-list=^Fuzz', './' + package], root, listing, deadline)
    return re.findall(r'^Fuzz\w+$', listing.read_text(), flags=re.M)


def test_targets(root, package, tags, out, deadline):
    listing = out / 'test-list.log'
    checked(go_args(tags) + ['-list=^Test', './' + package], root, listing, deadline)
    return re.findall(r'^Test\w+$', listing.read_text(), flags=re.M)


def unit_suite(root, package, tags, out, deadline):
    log = out / 'unit-suite.log'
    checked(go_args(tags) + ['./' + package], root, log, deadline)
    return {'status': 'passed', 'evidence': log.name}


def fuzz(root, package, functions, tags, out, deadline, max_fuzz_seconds=None):
    names = fuzz_targets(root, package, tags, out, deadline)
    if not names:
        raise ValueError('No fuzz target in critical package: ' + package)
    profile = out / 'fuzz-seeds.cover'
    checked(go_args(tags) + ['-run=^(' + '|'.join(names) + ')$', '-coverprofile=' + str(profile),
                            './' + package], root, out / 'fuzz-seeds.log', deadline)
    results.seed_coverage(profile, functions)
    executions = {}
    for index, name in enumerate(names):
        checked(go_args(tags) + ['-run=^$', '-fuzz=^' + name + '$', '-fuzztime=1x',
                                './' + package], root, out / (name + '-warm.log'), deadline)
        seconds = max(1, int((remaining(deadline) - 10) / (len(names) - index)))
        if max_fuzz_seconds is not None:
            seconds = min(seconds, max_fuzz_seconds)
        log = out / (name + '.log')
        checked(go_args(tags) + ['-run=^$', '-fuzz=^' + name + '$', f'-fuzztime={seconds}s',
                                './' + package], root, log, deadline)
        executions[name] = results.fuzz_executions(log)
    return executions


def mutation(root, package, functions, tags, out, deadline, gremlins):
    report = out / 'mutations.json'
    argv = [gremlins, 'unleash', str(root / package), '--workers=1',
            '--tags=' + tags, '--output=' + str(report), '--invert-logical',
            '--invert-bitwise', '--invert-assignments', '--remove-self-assignments']
    with mutation_audit.environment(out) as env:
        checked(argv, root / package, out / 'mutation.log', deadline, env)
    mutation_audit.validate(out / 'go-audit', report)
    return results.mutation_report(report, functions, package)


def validate_config(config):
    if config.get('schema_version') != 2 or config.get('seconds_per_package_and_kind') != 300:
        raise ValueError('Expected schema 2 and approved 300-second check budget')
    if not config.get('critical_paths') or not config.get('build_tags'):
        raise ValueError('Critical scope and build modes must not be empty')
    if config.get('fuzz_applicability') != 'fuzz-targets':
        raise ValueError("Expected fuzz applicability 'fuzz-targets' (per-mode target detection)")
    qualified = config.get('mutation_qualified_packages')
    if not isinstance(qualified, list):
        raise ValueError('mutation_qualified_packages must be an explicit versioned list')
    unknown = [name for name in qualified
               if not isinstance(name, str) or not scope.is_critical(name + '/x.go', config['critical_paths'])]
    if unknown:
        raise ValueError('Mutation-qualified packages must be critical package paths: ' + str(unknown))


def check_version(gremlins, config):
    text = subprocess.check_output([gremlins, '--version'], text=True)
    if not re.search(r'(?<![\d.])v?' + re.escape(config['gremlins_version']) + r'(?![\d.])', text):
        raise ValueError('Unexpected Gremlins version: ' + text.strip())
    return text.strip()


def active_functions(root, package, functions, tags, out, deadline):
    listing = out / 'package.json'
    checked(['go', 'list', '-json', *(['-tags=' + tags] if tags else []), './' + package],
            root, listing, deadline)
    data = json.loads(listing.read_text())
    files = {str(Path(package) / name) for name in data.get('GoFiles', []) + data.get('CgoFiles', [])}
    return [fn for fn in functions if fn['file'] in files]


def run_package(root, package, functions, config, out, gremlins):
    result = {}
    qualified = package in set(config['mutation_qualified_packages'])
    for kind in ('unit', 'fuzz', 'mutation'):
        deadline = time.monotonic() + config['seconds_per_package_and_kind']
        covered = set()
        for index, tags in enumerate(config['build_tags']):
            target = out / kind / str(index)
            target.mkdir(parents=True)
            mode_deadline = time.monotonic() + remaining(deadline) / (len(config['build_tags']) - index)
            selected = active_functions(root, package, functions, tags, target, mode_deadline)
            covered.update(fn['file'] for fn in selected)
            result[kind + ':' + tags] = run_mode(kind, root, package, selected, tags,
                                                 target, mode_deadline, gremlins, qualified)
        if {fn['file'] for fn in functions} - covered:
            raise ValueError('Changed critical files are absent from all configured build modes')
    return result


def unit_mode(root, package, tags, out, deadline):
    # Compensating requirement where fuzz infrastructure does not exist: the
    # package's own unit suite must pass. Never fabricated as fuzz coverage.
    if fuzz_targets(root, package, tags, out, deadline):
        return {'status': 'not_applicable',
                'reason': 'skipped: fuzz-target package, fuzz kind owns execution (N/A)'}
    if not test_targets(root, package, tags, out, deadline):
        return {'status': 'not_applicable', 'reason': 'skipped: no unit tests in package (N/A)'}
    return unit_suite(root, package, tags, out, deadline)


def run_mode(kind, root, package, functions, tags, out, deadline, gremlins, qualified):
    if not functions:
        return {'status': 'not_applicable', 'reason': 'no selected function in this build mode'}
    if kind == 'unit':
        return unit_mode(root, package, tags, out, deadline)
    if kind == 'fuzz':
        if not fuzz_targets(root, package, tags, out, deadline):
            return {'status': 'not_applicable', 'reason': 'skipped: no fuzz targets (N/A)'}
        return fuzz(root, package, functions, tags, out, deadline)
    if not qualified:
        return {'status': 'not_applicable',
                'reason': 'skipped: no gremlins-qualified unit mode (N/A)'}
    return mutation(root, package, functions, tags, out, deadline, gremlins)


def applicability_lines(report):
    lines = []
    for package, entry in report['packages'].items():
        for key, value in sorted(entry.get('checks', {}).items()):
            if isinstance(value, dict) and value.get('status') == 'not_applicable':
                lines.append(f'{package} [{key}]: ' + value.get('reason', 'not applicable'))
    return lines


def run(args):
    root, out = args.root.resolve(), args.output.resolve()
    if out.exists():
        raise ValueError('Use a fresh output directory; evidence must not be overwritten')
    out.mkdir(parents=True)
    config = json.loads((HERE / 'critical.json').read_text())
    validate_config(config)
    base = source.git(root, 'rev-parse', '--verify', '--end-of-options', args.base + '^{commit}').decode().strip()
    before = source.snapshot(root)
    targets = scope.targets(root, base, config)
    report = {'base': base, 'source': before, 'config_sha256': source.digest(HERE / 'critical.json'),
              'packages': {}, 'status': 'not_applicable' if not targets else 'running'}
    source.write(out / 'report.json', report)
    try:
        if targets:
            report['environment'] = source.environment(root, args.gremlins)
            report['gremlins'] = check_version(args.gremlins, config)
            execute_targets(root, targets, config, out, args.gremlins, report)
            if source.environment(root, args.gremlins) != report['environment']:
                raise ValueError('Tool environment changed during critical checks')
            report['status'] = 'passed'
        if source.snapshot(root) != before:
            raise ValueError('Source changed while critical checks ran')
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        report.update(status='failed', error=str(exc))
        raise
    finally:
        source.write(out / 'report.json', report)
        for line in applicability_lines(report):
            print('Critical Go applicability: ' + line)
    print('Critical Go checks: ' + report['status'] + '; ' + str(out / 'report.json'))
    print('Report SHA256: ' + source.digest(out / 'report.json'))
    return 0


def execute_targets(root, targets, config, out, gremlins, report):
    with tempfile.TemporaryDirectory(prefix='yabanin-critical-') as tmp:
        isolated = Path(tmp)
        source.copy_source(root, isolated)
        for index, (package, functions) in enumerate(targets.items()):
            target = out / str(index)
            report['packages'][package] = {'functions': functions, 'status': 'running'}
            source.write(out / 'report.json', report)
            try:
                value = run_package(isolated, package, functions, config, target, gremlins)
                report['packages'][package] = {'functions': functions, 'checks': value}
                source.write(out / 'report.json', report)
            finally:
                corpus = isolated / package / 'testdata/fuzz'
                if corpus.exists():
                    shutil.copytree(corpus, target / 'fuzz-corpus', dirs_exist_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=HERE.parents[2])
    parser.add_argument('--base', required=True)
    parser.add_argument('--gremlins', required=True)
    parser.add_argument('--output', type=Path, required=True)
    try:
        return run(parser.parse_args())
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        print('Critical Go gate error: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
