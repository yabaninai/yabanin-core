#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bounded real fuzz and mutation gates for changed critical Go packages."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

import mutation_audit
import critical_conservative as conservative
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


def seed_functions(functions):
    """Functions whose fuzz-seed block coverage this package must prove.

    Conservative selection marks every selected function as seed-demanding:
    literally-changed bodies, consumers bound to changed declarations or
    rewritten tests, and — because an unresolved mapping must not drop the
    historical demand — every production function of a widened package.
    Legacy rows carry no marker and keep the historical demand on every
    selected function.
    """
    marked = [fn for fn in functions if 'seed' in fn]
    return [fn for fn in marked if fn['seed']] if marked else list(functions)


def fuzz(root, package, functions, tags, out, deadline, override=None,
         max_fuzz_seconds=None):
    names = fuzz_targets(root, package, tags, out, deadline)
    if not names:
        raise ValueError('No fuzz target in critical package: ' + package)
    profile = out / 'fuzz-seeds.cover'
    checked(go_args(tags) + ['-run=^(' + '|'.join(names) + ')$', '-coverprofile=' + str(profile),
                            './' + package], root, out / 'fuzz-seeds.log', deadline)
    demand = seed_functions(functions)
    try:
        results.seed_coverage(profile, demand)
    except ValueError as failure:
        if override is None:
            raise
        record = preview2_seed_override_record(override, package, profile, demand,
                                               str(failure))
        source.write(out / 'fuzz-seed-override.json', record)
        print('Critical Go seed-block override (Preview2, base ' + override['base'] + '): '
              + package + ': ' + str(record['failing_functions']) + '/'
              + str(record['seed_selected']) + ' seed-selected functions with '
              + str(record['uncovered_blocks']) + ' uncovered blocks deferred to Preview3')
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
        try:
            executions[name] = results.fuzz_executions(log)
            continue
        except ValueError:
            # Only a corpus-heavy run that spent its whole window gathering
            # seed baseline coverage earns one bounded retry. Every other
            # zero-execution shape is a real red and is re-raised untouched.
            if not results.baseline_only_fuzz_log(log):
                raise
        # Preserve the baseline-only attempt under its own name and retry in
        # a fresh log: primary evidence is never overwritten. The retry
        # window grows within the same mode deadline and later targets
        # recompute their fair share from the remaining time, so the total
        # budget never extends.
        baseline_log = out / (name + '-baseline-only.log')
        log.rename(baseline_log)
        retry_seconds = max(1, int(min(remaining(deadline) - 10,
                                       BASELINE_RETRY_SCALE * seconds)))
        retry_log = out / (name + '-retry.log')
        checked(go_args(tags) + ['-run=^$', '-fuzz=^' + name + '$',
                                 f'-fuzztime={retry_seconds}s', './' + package],
                root, retry_log, deadline)
        executions[name] = results.fuzz_executions(retry_log)
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


BUDGET_KINDS = ('unit', 'fuzz', 'mutation')
APPROVED_BUDGET = {'unit': 420, 'fuzz': 420, 'mutation': 300}
BASELINE_RETRY_SCALE = 3


def budget(config):
    """Approved per-package seconds by check kind; any deviation is an error.

    The versioned budget block replaced the flat seconds_per_package_and_kind
    field so fuzzing can carry a different approved ceiling than unit and
    mutation. Kind budgets are shared across the package's build modes.
    """
    block = config.get('budget')
    if not isinstance(block, dict) or block.get('schema_version') != 1:
        raise ValueError('Expected budget schema 1 with seconds_per_package by kind')
    seconds = block.get('seconds_per_package')
    if not isinstance(seconds, dict) or set(seconds) != set(BUDGET_KINDS):
        raise ValueError('Budget must define exactly unit, fuzz and mutation seconds')
    if seconds != APPROVED_BUDGET:
        raise ValueError('Expected approved budgets unit=420s fuzz=420s mutation=300s')
    return seconds


SEED_OVERRIDE_ENV = 'CRITICAL_SEED_BLOCK_OVERRIDE_BASE'


def seed_override_binding(base):
    """Preview2-only, base-bound binding for the seed-block acceptance stopgap.

    Activates solely when the environment names this run's exact task base,
    and solely relaxes the fuzz seed-replay block check. Any other value
    fails closed before checks start. Preview3 must replace this handling
    with a real acceptance redesign and remove the override entirely.
    """
    wanted = os.environ.get(SEED_OVERRIDE_ENV)
    # An empty value means absent: CI renders conditional expressions to ''
    # when the guard does not hold, and that must keep the strict gate.
    if not wanted:
        return None
    if wanted != base:
        raise ValueError('Preview2 seed-block override base mismatch: '
                         + SEED_OVERRIDE_ENV + '=' + wanted + ' vs base ' + base)
    return {'base': base, 'activations': []}


def preview2_seed_override_record(override, package, profile, demand, failure):
    """Machine-readable evidence for one relaxed seed-block check."""
    failing = results.seed_coverage_report(profile, demand)
    record = {'override': 'preview2-seed-block', 'base': override['base'],
              'package': package, 'default_verdict': failure,
              'seed_selected': len(demand), 'failing_functions': len(failing),
              'uncovered_blocks': sum(fn['uncovered_blocks'] for fn in failing),
              'functions': failing,
              'deferred': 'Preview3 acceptance redesign; this handling is temporary'}
    override['activations'].append({'package': package,
                                    'failing_functions': record['failing_functions'],
                                    'uncovered_blocks': record['uncovered_blocks'],
                                    'evidence': 'fuzz-seed-override.json'})
    return record


def apply_seed_override_status(report, override):
    """Never let an overridden run look like a clean pass."""
    if not (override and override['activations']):
        return
    report['seed_block_override'] = {
        'mode': 'preview2-temporary', 'base': override['base'],
        'packages': override['activations'],
        'note': 'fuzz seed-replay block acceptance only; every other check enforced; '
                'Preview3 must land the acceptance redesign and delete this override'}
    report['status'] = 'passed-seed-block-override'


def validate_config(config):
    if config.get('schema_version') != 2:
        raise ValueError('Expected critical config schema 2')
    if 'seconds_per_package_and_kind' in config:
        raise ValueError('Legacy seconds_per_package_and_kind was replaced by the '
                         'versioned budget block')
    budget(config)
    if not config.get('critical_paths') or not config.get('build_tags'):
        raise ValueError('Critical scope and build modes must not be empty')
    if config.get('fuzz_applicability') != 'fuzz-targets':
        raise ValueError("Expected fuzz applicability 'fuzz-targets' (per-mode target detection)")
    validate_mutation_scope(config)


def validate_mutation_scope(config):
    """Mutation qualification is an explicit list of critical packages."""
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


def run_package(root, package, functions, config, out, gremlins, override=None):
    result = {}
    qualified = package in set(config['mutation_qualified_packages'])
    seconds = budget(config)
    for kind in ('unit', 'fuzz', 'mutation'):
        deadline = time.monotonic() + seconds[kind]
        if kind == 'unit':
            # The unit phase resumes the remainder banked at the end of
            # this package's own baseline verification; other packages'
            # verification and execution cannot spend it.
            deadline = conservative.resume_unit_deadline(package, seconds[kind])
        covered = set()
        for index, tags in enumerate(config['build_tags']):
            target = out / kind / str(index)
            target.mkdir(parents=True)
            mode_deadline = time.monotonic() + remaining(deadline) / (len(config['build_tags']) - index)
            selected = active_functions(root, package, functions, tags, target, mode_deadline)
            covered.update(fn['file'] for fn in selected)
            # Legacy doubles and wrappers assume the original positional
            # shape; the extra argument travels only when an override is
            # actually active.
            if override is None:
                result[kind + ':' + tags] = run_mode(kind, root, package, selected, tags,
                                                     target, mode_deadline, gremlins,
                                                     qualified)
            else:
                result[kind + ':' + tags] = run_mode(kind, root, package, selected, tags,
                                                     target, mode_deadline, gremlins,
                                                     qualified, override)
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


def run_mode(kind, root, package, functions, tags, out, deadline, gremlins, qualified,
             override=None):
    if not functions:
        return {'status': 'not_applicable', 'reason': 'no selected function in this build mode'}
    if kind == 'unit':
        return unit_mode(root, package, tags, out, deadline)
    if kind == 'fuzz':
        if not fuzz_targets(root, package, tags, out, deadline):
            return {'status': 'not_applicable', 'reason': 'skipped: no fuzz targets (N/A)'}
        if override is None:
            return fuzz(root, package, functions, tags, out, deadline)
        return fuzz(root, package, functions, tags, out, deadline, override)
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
    config = json.loads((HERE / 'critical.json').read_text())
    validate_config(config)
    base = source.git(root, 'rev-parse', '--verify', '--end-of-options', args.base + '^{commit}').decode().strip()
    # Resolve the binding before any output directory is created: a
    # mismatch fails before side effects, so a corrected retry with the
    # same --output is not blocked by an orphaned directory.
    override = seed_override_binding(base)
    if out.exists():
        raise ValueError('Use a fresh output directory; evidence must not be overwritten')
    out.mkdir(parents=True)
    before = source.snapshot(root)
    mode = scope.selector_mode()
    targets = scope.targets(root, base, config)
    report = {'base': base, 'source': before, 'config_sha256': source.digest(HERE / 'critical.json'),
              'packages': {}, 'status': 'not_applicable' if not targets else 'running'}
    if mode != scope.LEGACY:
        report['selector'] = {
            'mode': mode,
            'evidence': scope.selection_evidence(),
            'seed_demand_scope': (
                'seed flags are fuzz-seed demands, enforced only in build modes '
                'where the package has fuzz targets; a selected critical function '
                'in a fuzz-less package relies on the unit-suite gate'),
        }
    source.write(out / 'report.json', report)
    try:
        if targets:
            report['environment'] = source.environment(root, args.gremlins)
            report['gremlins'] = check_version(args.gremlins, config)
            if override is None:
                execute_targets(root, targets, config, out, args.gremlins, report)
            else:
                execute_targets(root, targets, config, out, args.gremlins, report,
                                override)
            if source.environment(root, args.gremlins) != report['environment']:
                raise ValueError('Tool environment changed during critical checks')
            apply_seed_override_status(report, override)
            if report['status'] == 'running':
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
        if report.get('selector'):
            print('Critical selector: ' + report['selector']['mode'])
        if report.get('seed_block_override'):
            print('Critical Go seed-block override active: temporary Preview2 handling; '
                  'Preview3 must land the acceptance redesign and remove this override')
    print('Critical Go checks: ' + report['status'] + '; ' + str(out / 'report.json'))
    print('Report SHA256: ' + source.digest(out / 'report.json'))
    return 0


def execute_targets(root, targets, config, out, gremlins, report, override=None):
    with tempfile.TemporaryDirectory(prefix='yabanin-critical-') as tmp:
        isolated = Path(tmp)
        source.copy_source(root, isolated)
        for index, (package, functions) in enumerate(targets.items()):
            target = out / str(index)
            report['packages'][package] = {'functions': functions, 'status': 'running'}
            source.write(out / 'report.json', report)
            try:
                if override is None:
                    value = run_package(isolated, package, functions, config, target,
                                        gremlins)
                else:
                    value = run_package(isolated, package, functions, config, target,
                                        gremlins, override)
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
