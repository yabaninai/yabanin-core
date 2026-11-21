"""Deterministic OIDC keyset stale-window qualification for pkg/adminauth.

Runs the accepted three-outcome timing-gate control inside the product tree
using a scratch alternate modfile and a test-file overlay: the complete
pinned go-oidc module directory is copied into the TemporaryDirectory with
only oidc/jwks.go replaced by the hash-bound instrumented testdata copy
(test-only one-shot writer and reader-snapshot gates; see
testdata/oidcgate/), and an alternate modfile containing the exact product
go.mod bytes plus one replace directive selects it via -modfile. The pinned go-oidc module
directory is only ever read, and -overlay is restricted to pkg/adminauth
test files. Every nested go test runs with -race, -count=1, -mod=readonly
and verbose named evidence under one shared 300-second deadline. Temporary
and build artifacts (TMPDIR, GOTMPDIR, GOCACHE) live inside the
TemporaryDirectory outside every git worktree; the real go.mod/go.sum are
hashed before and after execution, the complete pinned go-oidc module
directory (file set and bytes) is hashed before and after, and the full
working-tree status is compared, so neither the product source nor the
module cache can change unobserved. Logs persist under
artifacts/quality/oidc-gate/<run-id>/ (or a unique run subdirectory of
$OIDC_GATE_ARTIFACTS, which must live outside every git worktree) with
printed sha256 bindings; a missing or empty log is a failure.

Legs:
  noop      the committed TestOIDCBoundary_* suite runs on the instrumented
            dependency (via the alternate modfile, no overlay) with no gate
            armed, proving the hooks inert;
  original  the byte-exact 371c50b9 test support plus gate_old_test.go:
            TestGateRetiredKidStaleWindow_OriginalBehaviorFails must FAIL
            with the exact retired-kid oracle;
  fixed     current production and current test support plus gate_test.go:
            TestGateRetiredKidStaleWindow_CorrectedBarrierPasses (including
            its nested post-rotation-cache-write-barrier subtest) must PASS
            and TestGateRetiredKidStaleWindow_OmittedBarrierFails must FAIL
            with the same oracle.

Which source ran is established by outcomes and manifests: both gate legs
reference exported gate symbols that pristine go-oidc v3.21.0 does not
define, so they cannot compile without the scratch instrumented dependency
selected by the alternate modfile, and the original leg cannot run at all
without its overlay-added gate_old_test.go. Compile or startup failures
produce zero RUN discovery and are rejected as setup failures, never as
expected outcomes.
"""
import hashlib
import json
import os
import shutil
import stat
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[3]
FIXDIR = ROOT / 'pkg' / 'adminauth' / 'testdata' / 'oidcgate'
PKGDIR = ROOT / 'pkg' / 'adminauth'

ORIG_COMMIT = '371c50b9d4db90029f8975fecc0659a3d53960ed'
DEADLINE_SECONDS = 300
GO_TOOLCHAIN = 'go1.27.4'
REPLACED_MODULE = 'github.com/coreos/go-oidc/v3'

ORACLE = ('evicted retired kid now fails closed on the same long-lived '
          'client: must fail closed')

GUARDS = (
    'gate: writer never arrived at the k4 refetch gate',
    'gate: final retired-kid exchange never reached the keyset snapshot gate',
    'gate: final retired-kid exchange never completed after release',
    'gate: barrier reader never reached the keyset snapshot gate',
    'gate: nested k3 barrier subtest failed',
    'gate: nested k3 barrier subtest never completed',
)

# Product fixture bytes (testdata never enters normal compilation).
FIXTURE_SHA = {
    'jwks_gate.go':
        '5ca0595c811417d2270497c223184ec51842584f2c1804c5063f91d6a659dea3',
    'gate_test.go':
        'd13d49c0d55c95a5af2ed167e0f4f6fc4f0b2772e781c9b33cde1265b9618e4d',
    'gate_old_test.go':
        '84528c39c2a572073571437325558a9a765666d5d71d21deaf3d4f9e6dda800a',
    'boundary_test_371c50b9.go':
        '21acff41238a37e4fa781d37c80c7624bdfa114f8e788046fb423a332e6d4d57',
    'LICENSE-go-oidc':
        'cb5e8e7e5f4a3988e1063c142c60dc2df75605f4c46515e776e3aca6df976e14',
}

# Pristine upstream anchors per pin; a new pin requires re-deriving the
# instrumented copy and updating these constants.
PINNED = {
    'v3.21.0': {
        'jwks': '4a7ba68cc108b56548d057a874e9cdca22c9f888d4d7b38b5fed4722039c6538',
        'license': 'cb5e8e7e5f4a3988e1063c142c60dc2df75605f4c46515e776e3aca6df976e14',
    },
}


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _tree_digest(root):
    """Directory digest: sorted file set plus per-file sha256 bytes."""
    digest = hashlib.sha256()
    count = 0
    for path in sorted(p for p in Path(root).rglob('*') if p.is_file()):
        digest.update(str(path.relative_to(root)).encode('utf-8'))
        digest.update(b'\0')
        digest.update(_sha256(path).encode('ascii'))
        digest.update(b'\n')
        count += 1
    return count, digest.hexdigest()


class OidcGateQualification(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for name, digest in FIXTURE_SHA.items():
            if _sha256(FIXDIR / name) != digest:
                raise AssertionError(f'fixture integrity: {name}')
        go_mod = (ROOT / 'go.mod').read_text(encoding='utf-8')
        version = None
        for line in go_mod.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == REPLACED_MODULE:
                version = parts[1]
        if version not in PINNED:
            raise AssertionError(
                f'go-oidc pin {version!r} has no anchors; re-derive '
                'pkg/adminauth/testdata/oidcgate from the new pin')
        cls.version = version
        env = {**os.environ, 'GOWORK': 'off', 'GOTOOLCHAIN': GO_TOOLCHAIN}
        cls.modcache = Path(subprocess.check_output(
            ['go', 'env', 'GOMODCACHE'], text=True, cwd=ROOT,
            timeout=60, env=env).strip())
        cls.module_dir = cls.modcache / f'github.com/coreos/go-oidc/v3@{version}'
        cls._verify_pristine('pristine jwks.go', cls.module_dir / 'oidc' / 'jwks.go',
                             PINNED[version]['jwks'])
        cls._verify_pristine('upstream LICENSE', cls.module_dir / 'LICENSE',
                             PINNED[version]['license'])
        cls._verify_original_support()
        cls.started = time.monotonic()

    @classmethod
    def _go_env(cls, tmp):
        env = {**os.environ, 'GOWORK': 'off', 'GOTOOLCHAIN': GO_TOOLCHAIN,
               'GOFLAGS': ''}
        for var in ('TMPDIR', 'GOTMPDIR'):
            env[var] = str(tmp / 'tmp')
        env['GOCACHE'] = str(tmp / 'gocache')
        return env

    @classmethod
    def _verify_pristine(cls, label, path, expected):
        if not path.is_file() or _sha256(path) != expected:
            raise AssertionError(f'{label}: pinned module copy drifted: {path}')

    @classmethod
    def _verify_original_support(cls):
        fixture = FIXDIR / 'boundary_test_371c50b9.go'
        probe = subprocess.run(
            ['git', 'cat-file', '-e', f'{ORIG_COMMIT}^{{commit}}'],
            cwd=ROOT, timeout=60)
        if probe.returncode != 0:
            return  # shallow history: the recorded fixture hash binds it
        original = subprocess.check_output(
            ['git', 'show', f'{ORIG_COMMIT}:pkg/adminauth/oidc_boundary_test.go'],
            cwd=ROOT, timeout=60)
        if original != fixture.read_bytes():
            raise AssertionError('boundary_test_371c50b9.go is not byte-identical '
                                 f'to {ORIG_COMMIT}')

    def _remaining(self):
        left = DEADLINE_SECONDS - (time.monotonic() - type(self).started)
        self.assertGreater(left, 0, 'shared qualification deadline exceeded')
        return left

    def _build_scratch_dep(self, tmp):
        dep = tmp / 'dep' / 'github.com' / 'coreos' / 'go-oidc' / 'v3'
        dep.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(type(self).module_dir, dep)
        for path in dep.rglob('*'):
            mode = path.stat().st_mode
            path.chmod(mode | stat.S_IWUSR | (0 if path.is_file()
                                              else stat.S_IXUSR))
        jwks = dep / 'oidc' / 'jwks.go'
        shutil.copyfile(FIXDIR / 'jwks_gate.go', jwks)
        self.assertEqual(_sha256(jwks), FIXTURE_SHA['jwks_gate.go'],
                         'scratch dependency jwks.go is not the bound fixture')
        self.assertEqual(_sha256(dep / 'LICENSE'),
                         PINNED[type(self).version]['license'],
                         'scratch dependency lost the upstream LICENSE bytes')
        return dep

    def _alt_modfile(self, tmp, dep):
        base = (ROOT / 'go.mod').read_text(encoding='utf-8')
        for line in base.splitlines():
            if line.startswith('replace ') and REPLACED_MODULE in line:
                self.fail('product go.mod already replaces the pinned module')
        if not base.endswith('\n'):
            base += '\n'
        mod = tmp / 'qual.mod'
        mod.write_text(base + f'replace {REPLACED_MODULE} => {dep}\n',
                       encoding='utf-8')
        sumfile = tmp / 'qual.sum'
        shutil.copyfile(ROOT / 'go.sum', sumfile)
        self.assertEqual((ROOT / 'go.sum').read_bytes(), sumfile.read_bytes())
        return str(mod)

    def _write_overlay(self, tmp, name, mapping):
        for source in mapping.values():
            self.assertIn(Path(source).name, FIXTURE_SHA)
            if _sha256(source) != FIXTURE_SHA[Path(source).name]:
                self.fail(f'overlay source drifted: {source}')
        for target in mapping:
            if Path(target).parent != PKGDIR:
                self.fail(f'overlay target outside qualification scope: {target}')
        path = Path(tmp) / f'{name}.json'
        path.write_text(json.dumps({'Replace': mapping}), encoding='utf-8')
        return str(path)

    def _persist(self, artifacts, label, text):
        log = artifacts / f'{label}.log'
        log.write_text(text, encoding='utf-8')
        digest = _sha256(log)
        self.assertTrue(log.is_file() and log.stat().st_size > 0,
                        f'{label}: persisted log missing or empty')
        self.assertEqual(digest, hashlib.sha256(text.encode('utf-8')).hexdigest(),
                         f'{label}: persisted log does not match captured output')
        print(f'[oidc-gate] {label}: log={log} sha256={digest}')
        return digest

    def _run_go(self, label, tmp, artifacts, modfile, pattern, overlay=None):
        cmd = ['go', 'test', '-modfile', modfile, '-race', '-count=1',
               '-mod=readonly', '-v',
               '-timeout=%ds' % max(1, int(self._remaining()) - 5),
               '-run', pattern]
        if overlay:
            cmd += ['-overlay', overlay]
        cmd += ['./pkg/adminauth']
        try:
            proc = subprocess.run(
                cmd, cwd=ROOT, capture_output=True, text=True,
                timeout=self._remaining(), env=type(self)._go_env(tmp))
        except subprocess.TimeoutExpired:
            self.fail(f'{label}: shared 300s deadline exceeded')
        log = proc.stdout + proc.stderr
        (Path(tmp) / f'{label}.log').write_text(log, encoding='utf-8')
        self._require(log.strip(), label, 'zero-result log (go produced no output)', log)
        self._persist(artifacts, label, log)
        print(f'[oidc-gate] {label}: rc={proc.returncode}')
        return proc.returncode, log

    def _require(self, condition, label, detail, log):
        if not condition:
            tail = '\n'.join(log.splitlines()[-40:])
            self.fail(f'{label}: {detail}\n--- log tail ---\n{tail}')

    def _artifacts_dir(self):
        run_id = f'{time.strftime("%Y%m%dT%H%M%S")}-{os.getpid()}-{uuid.uuid4().hex[:8]}'
        override = os.environ.get('OIDC_GATE_ARTIFACTS', '').strip()
        if override:
            parent = Path(override).resolve()
            for ancestor in [parent, *parent.parents]:
                if (ancestor / '.git').exists():
                    self.fail(f'OIDC_GATE_ARTIFACTS inside a git worktree: {parent}')
            artifacts = parent / run_id
            artifacts.mkdir(parents=True, exist_ok=False)
            return artifacts
        artifacts = ROOT / 'artifacts' / 'quality' / 'oidc-gate' / run_id
        artifacts.mkdir(parents=True, exist_ok=True)
        ignored = subprocess.run(['git', 'check-ignore', '-q', str(artifacts)],
                                 cwd=ROOT, timeout=60).returncode == 0
        if not ignored:
            self.fail(f'artifact directory is not git-ignored: {artifacts}')
        return artifacts

    def test_three_outcome_gate_qualification(self):
        with tempfile.TemporaryDirectory(prefix='oidc-gate-qual-') as tmp:
            tmp = Path(tmp)
            (tmp / 'tmp').mkdir()
            for parent in [tmp.resolve(), *tmp.resolve().parents]:
                if (parent / '.git').exists():
                    self.fail(f'temporary directory inside a git worktree: {tmp}')
            artifacts = self._artifacts_dir()
            module_before = _tree_digest(type(self).module_dir)
            before = {
                'go.mod': _sha256(ROOT / 'go.mod'),
                'go.sum': _sha256(ROOT / 'go.sum'),
                'status': subprocess.check_output(
                    ['git', 'status', '--porcelain'], cwd=ROOT, text=True,
                    timeout=60),
            }

            dep = self._build_scratch_dep(tmp)
            modfile = self._alt_modfile(tmp, dep)
            fixed_overlay = self._write_overlay(tmp, 'fixed', {
                str(PKGDIR / 'oidc_boundary_gate_test.go'):
                    str(FIXDIR / 'gate_test.go')})
            orig_overlay = self._write_overlay(tmp, 'orig', {
                str(PKGDIR / 'oidc_boundary_test.go'):
                    str(FIXDIR / 'boundary_test_371c50b9.go'),
                str(PKGDIR / 'oidc_boundary_gate_old_test.go'):
                    str(FIXDIR / 'gate_old_test.go')})

            results = {}

            # 1. Unarmed no-op: committed named suite green on instrumented dep.
            rc, log = self._run_go('noop', tmp, artifacts, modfile,
                                   'TestOIDCBoundary_')
            discovered = log.count('=== RUN   TestOIDCBoundary_')
            results['noop'] = rc
            self._require(rc == 0, 'noop', f'rc={rc}', log)
            self._require(discovered >= 5, 'noop',
                          f'zero/low discovery ({discovered})', log)
            self._require('--- PASS: TestOIDCBoundary_RetiredKidCacheAsymmetry'
                          in log, 'noop', 'asymmetry case missing PASS', log)
            self._require('--- FAIL:' not in log and '--- SKIP:' not in log,
                          'noop', 'unexpected FAIL/SKIP with gates unarmed', log)

            # 2. Original leg: original support + old gate test MUST FAIL.
            rc, log = self._run_go('original', tmp, artifacts, modfile,
                                   'TestGateRetiredKidStaleWindow_OriginalBehaviorFails',
                                   overlay=orig_overlay)
            results['original'] = rc
            self._require(rc != 0, 'original', f'expected behavioral FAIL, rc={rc}', log)
            self._require('=== RUN   TestGateRetiredKidStaleWindow_'
                          'OriginalBehaviorFails' in log, 'original',
                          'zero discovery (compile/startup failure is not an outcome)',
                          log)
            self._require('--- FAIL: TestGateRetiredKidStaleWindow_'
                          'OriginalBehaviorFails' in log, 'original',
                          'missing named FAIL line', log)
            self._require(ORACLE in log, 'original', 'missing exact oracle', log)
            self._require('--- SKIP:' not in log, 'original', 'unexpected skip', log)

            # 3. Fixed leg: corrected barrier (with nested subtest) MUST PASS.
            rc, log = self._run_go('corrected', tmp, artifacts, modfile,
                                   'TestGateRetiredKidStaleWindow_CorrectedBarrierPasses',
                                   overlay=fixed_overlay)
            results['corrected'] = rc
            nested = ('TestGateRetiredKidStaleWindow_CorrectedBarrierPasses'
                      '/post-rotation-cache-write-barrier')
            self._require(rc == 0, 'corrected', f'expected PASS, rc={rc}', log)
            self._require(f'=== RUN   {nested}' in log, 'corrected',
                          'nested barrier subtest absent (overlay not applied?)', log)
            self._require(f'--- PASS: {nested}' in log, 'corrected',
                          'nested barrier subtest did not pass', log)
            self._require(f'--- FAIL: {nested}' not in log, 'corrected',
                          'nested barrier subtest failed', log)
            self._require('--- SKIP:' not in log, 'corrected', 'unexpected skip', log)

            # 4. Fixed leg: omitted barrier MUST FAIL with the same oracle.
            rc, log = self._run_go('omitted', tmp, artifacts, modfile,
                                   'TestGateRetiredKidStaleWindow_OmittedBarrierFails',
                                   overlay=fixed_overlay)
            results['omitted'] = rc
            self._require(rc != 0, 'omitted', f'expected behavioral FAIL, rc={rc}', log)
            self._require('=== RUN   TestGateRetiredKidStaleWindow_'
                          'OmittedBarrierFails' in log, 'omitted',
                          'zero discovery (compile/startup failure is not an outcome)',
                          log)
            self._require('--- FAIL: TestGateRetiredKidStaleWindow_'
                          'OmittedBarrierFails' in log, 'omitted',
                          'missing named FAIL line', log)
            self._require(ORACLE in log, 'omitted', 'missing exact oracle', log)
            self._require('--- SKIP:' not in log, 'omitted', 'unexpected skip', log)

            for label in results:
                persisted = artifacts / f'{label}.log'
                text = persisted.read_text(encoding='utf-8')
                guards = [g for g in GUARDS if g in text]
                self._require(not guards, label,
                              f'setup guard fired: {guards}', text)

            # 5. Execution left every observed byte identical.
            self.assertEqual(before['go.mod'], _sha256(ROOT / 'go.mod'))
            self.assertEqual(before['go.sum'], _sha256(ROOT / 'go.sum'))
            module_after = _tree_digest(type(self).module_dir)
            self.assertEqual(module_before, module_after,
                             'pinned go-oidc module directory changed')
            after = subprocess.check_output(['git', 'status', '--porcelain'],
                                            cwd=ROOT, text=True, timeout=60)
            self.assertEqual(before['status'], after,
                             'qualification modified the working tree')

            manifest = {
                'toolchain': GO_TOOLCHAIN,
                'pin': type(self).version,
                'fixtures': FIXTURE_SHA,
                'module_tree': {'files': module_before[0], 'sha256': module_before[1]},
                'legs': {k: {'rc': v,
                             'log_sha256': _sha256(artifacts / f'{k}.log')}
                         for k, v in results.items()},
            }
            manifest_path = artifacts / 'manifest.json'
            manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True),
                                     encoding='utf-8')
            print(f'[oidc-gate] manifest={manifest_path} '
                  f'sha256={_sha256(manifest_path)}')


if __name__ == '__main__':
    unittest.main()
