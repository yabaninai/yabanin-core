"""Retained regression: release fallback .buildinfo manifests are path-invariant.

scripts/release/release-artifacts.sh (syft-absent fallback) emits one
<binary>.buildinfo per subject via write_buildinfo(); those bytes must not
depend on the absolute RELEASE_DIR, and the module/build lines after the
header stay exactly what `go version -m` reports.

Also retained: the syft SBOM branch fails closed (RELEASE-SYFT-* controls).
A nonzero syft exit must propagate, must not write the sbom.source success
claim, must not leave an empty/stale sbom.spdx.json consumable as valid, and
must not fall back silently to go version -m manifests; a zero syft exit must
still emit a populated SPDX document before any success claim. The positive
controls (synthetic valid SPDX and the real pinned syft binary on a tiny
offline fixture) keep the branch from being always-red. Blocks under test are
extracted from the current script source, so removing the guards from the
script removes them from these tests and the invariants fail.

The delivered SPDX is emitted deterministically: the scan itself carries the
native --source-name/--source-version binding and the emit step binds the
only two fields syft still varies (created, documentNamespace) to
SOURCE_DATE_EPOCH and the source revision. Raw scanner bytes stay outside
the compared release set as hash-bound evidence. The two-directory control
covers the emitting recipe on identical input; it is not a claim of final
release reproducibility, which stays the separate full-rebuild gate.

The real-scanner controls are portable: when SYFT_BIN/PATH do not carry the
pinned scanner, the bounded provisioning leaf in syft_provision.py downloads
the official pinned release archive (reviewed exact SHA-256), extracts it
safely into per-test temp directories and verifies the pin from the binary's
own version output — no machine-local binary requirement, no global install,
and an explicit failure (never a skip) when any of that is unavailable.
"""

import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from syft_provision import (  # noqa: E402  (single source of pin truth)
    SYFT_PIN,
    SYFT_PIN_GIT_COMMIT,
    SyftProvisionError,
    extract_syft_archive,
    locate_pinned_syft,
    provision_pinned_syft,
    verify_pinned_syft,
)

ROOT = Path(__file__).resolve().parents[3]
RELEASE_SCRIPT = ROOT / "scripts" / "release" / "release-artifacts.sh"
BIN_NAME = "yabanin"
GO_TOOLCHAIN = "go1.27.4"
# Release lane scanner pin (imported from syft_provision): the exact scanner
# identity these controls require. Resolved via SYFT_BIN, then PATH, then the
# bounded provisioning leaf (official pinned archive, reviewed exact SHA-256,
# safe extraction into per-test temp dirs — see syft_provision.py). A
# wrong-version, missing or unreachable scanner fails the control outright
# instead of skipping the only real-scanner checks.
SPDX_REQUIRED_FIELDS = ("spdxVersion", "SPDXID", "name", "dataLicense", "creationInfo")
# Tiny offline fixture: a go.mod require line gives the real scanner one
# catalogable package without any network, build or paid service.
SYFT_FIXTURE_GO_MOD = (
    "module example.com/tiny-fixture\n\n"
    "go 1.21\n\n"
    "require github.com/example/dep v1.2.3\n"
)
# The SBOM branch exactly as it was at the task base (b02298c), frozen so the
# original false-success defect stays reproducible and detectable even as
# the fixed branch evolves.
ORIGINAL_VULNERABLE_BRANCH = """if command -v syft > /dev/null 2>&1; then
    syft dir:"$RELEASE_DIR" -o spdx-json > "$RELEASE_DIR/sbom.spdx.json" && echo "syft SPDX SBOM written"
    echo "syft spdx-json" > "$RELEASE_DIR/sbom.source"
fi
"""

VALID_SYNTHETIC_SPDX = {
    "spdxVersion": "SPDX-2.3",
    "dataLicense": "CC0-1.0",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": "synthetic-release-dir",
    "creationInfo": {
        "creators": ["Tool: synthetic-control"],
        "created": "1970-01-01T00:00:00Z",
    },
    "packages": [
        {
            "SPDXID": "SPDXRef-Package-synthetic",
            "name": "synthetic-package",
            "versionInfo": "1.0.0",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "copyrightText": "NOASSERTION",
        }
    ],
}


def go_env():
    env = dict(os.environ)
    env.update(GOWORK="off", GOFLAGS="", CGO_ENABLED="0",
               GOTOOLCHAIN=GO_TOOLCHAIN, GOPROXY="off")
    return env


def extract_write_buildinfo(case):
    text = RELEASE_SCRIPT.read_text()
    match = re.search(r"^write_buildinfo\(\) \{.*?^\}", text, re.M | re.S)
    case.assertIsNotNone(match, "release-artifacts.sh must define write_buildinfo()")
    return match.group(0)


def extract_sbom_validator(case):
    text = RELEASE_SCRIPT.read_text()
    match = re.search(r"^sbom_spdx_is_valid\(\) \{.*?^\}", text, re.M | re.S)
    case.assertIsNotNone(match, "release-artifacts.sh must define sbom_spdx_is_valid()")
    return match.group(0)


def extract_sbom_deterministic(case):
    text = RELEASE_SCRIPT.read_text()
    match = re.search(r"^sbom_spdx_deterministic\(\) \{.*?^\}", text, re.M | re.S)
    case.assertIsNotNone(match, "release-artifacts.sh must define sbom_spdx_deterministic()")
    return match.group(0)


def syft_snippet(case, through_else):
    """Validator + emit-time transform + SBOM branch from current source."""
    return (extract_sbom_validator(case) + "\n"
            + extract_sbom_deterministic(case) + "\n"
            + extract_syft_if_block(case, through_else))


def extract_strict(case):
    text = RELEASE_SCRIPT.read_text()
    match = re.search(r"^strict\(\) \{.*\}$", text, re.M)
    case.assertIsNotNone(match, "release-artifacts.sh must define strict()")
    return match.group(0)


def extract_syft_if_block(case, through_else):
    """The SBOM branch as written in the current script source.

    through_else=False reproduces the original independent control's cut
    (then-branch only); through_else=True keeps the missing-tool fallback so
    a failed scan can be proven not to reach it.
    """
    text = RELEASE_SCRIPT.read_text()
    start = text.index("if command -v syft ")
    end = text.index('echo "assembling NOTICE materials"')
    block = text[start:end].rstrip("\n")
    case.assertTrue(block.endswith("\nfi"), "SBOM branch must end with fi")
    if not through_else:
        block = block.split("\nelse\n", 1)[0] + "\nfi"
    return block


def extract_syft_else_body(case):
    body = extract_syft_if_block(case, through_else=True).split("\nelse\n", 1)[1]
    return body.rsplit("\nfi", 1)[0]


def extract_release_cleanup_rm(case):
    text = RELEASE_SCRIPT.read_text()
    match = re.search(r'^rm -f "\$RELEASE_DIR"/yabanin .*?recipe\.json\n',
                      text, re.M | re.S)
    case.assertIsNotNone(match, "release-artifacts.sh must clean the release dir")
    return "\n".join(line[4:] if line.startswith("    ") else line
                     for line in match.group(0).splitlines())


def run_release_snippet(case, snippet, release_dir, path_dirs=(), extra_env=None):
    """Run an extracted snippet exactly as the script body runs it: set -euo
    pipefail, normalized Go env, no strict/unsigned/cosign leakage, and the
    RELEASE_DIR/SOURCE_DATE_EPOCH bindings the full script exports before
    this branch runs (the snippet's guards depend on them under set -u).
    extra_env (SBOM_SOURCE_*, ...) is applied last so callers pin the
    emit-time bindings explicitly."""
    env = go_env()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    # Per-test temp directory (hermetic on any host; no machine-private
    # path requirement) for anything the snippet or the scanner spills.
    snippet_tmp = Path(tempfile.mkdtemp(prefix="release-snippet-tmp-"))
    case.addCleanup(shutil.rmtree, snippet_tmp, ignore_errors=True)
    env["TMPDIR"] = str(snippet_tmp)
    env["RELEASE_DIR"] = str(release_dir)
    env.setdefault("LC_ALL", "C")
    env.setdefault("SOURCE_DATE_EPOCH", "1732000000")
    for var in ("RELEASE_STRICT", "RELEASE_ALLOW_UNSIGNED", "COSIGN_KEY",
                "SBOM_SOURCE_NAME", "SBOM_SOURCE_VERSION", "RELEASE_SBOM_RAW_DIR"):
        env.pop(var, None)
    if path_dirs:
        env["PATH"] = (os.pathsep.join(str(p) for p in path_dirs)
                       + os.pathsep + env["PATH"])
    if extra_env:
        env.update(extra_env)
    return subprocess.run(["bash", "-c", "set -euo pipefail\n" + snippet],
                          capture_output=True, text=True, env=env,
                          cwd=str(ROOT))


def run_write_buildinfo(case, fn_text, binary):
    script = fn_text + "\nwrite_buildinfo " + shlex.quote(str(binary)) + "\n"
    subprocess.run(["bash", "-c", script], check=True, cwd=str(ROOT), env=go_env())


class ReleaseBuildinfoPathInvariance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # A missing or wrong toolchain invalidates the qualification run;
        # hiding it behind a skip would silently turn coverage into nothing.
        if shutil.which("go") is None:
            raise AssertionError(f"go executable not found; {GO_TOOLCHAIN} is required")
        probe = subprocess.run(["go", "version"], capture_output=True, text=True,
                               cwd=str(ROOT), env=go_env())
        if probe.returncode != 0:
            raise AssertionError(
                f"`go version` failed under GOTOOLCHAIN={GO_TOOLCHAIN} GOPROXY=off "
                f"(cached toolchain missing?): rc={probe.returncode} err={probe.stderr.strip()}")
        reported = re.search(r"go version (\S+)", probe.stdout)
        if reported is None or reported.group(1) != GO_TOOLCHAIN:
            raise AssertionError(
                f"expected toolchain {GO_TOOLCHAIN}, got: {probe.stdout.strip()!r}")
        cls._tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls._tmp.cleanup)
        base = Path(cls._tmp.name)
        mod = base / "src"
        mod.mkdir()
        (mod / "main.go").write_text("package main\n\nfunc main() {}\n")
        subprocess.run(["go", "mod", "init", "example.com/rpi-buildinfo"],
                       check=True, cwd=str(mod), env=go_env())
        cls.binary = base / BIN_NAME
        subprocess.run(["go", "build", "-o", str(cls.binary), "."],
                       check=True, cwd=str(mod), env=go_env())

    def go_version_m(self, binary):
        return subprocess.run(["go", "version", "-m", str(binary)],
                              check=True, capture_output=True,
                              cwd=str(ROOT), env=go_env()).stdout

    def test_fallback_buildinfo_identical_across_release_dirs(self):
        fn = extract_write_buildinfo(self)
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            dirs = [base / "artifacts-a", base / "artifacts-b"]
            for d in dirs:
                d.mkdir()
                shutil.copy2(self.binary, d / BIN_NAME)
            for d in dirs:
                run_write_buildinfo(self, fn, d / BIN_NAME)
            first, second = (d / f"{BIN_NAME}.buildinfo" for d in dirs)
            a, b = first.read_bytes(), second.read_bytes()
            self.assertEqual(a, b, ".buildinfo bytes must not depend on RELEASE_DIR")
            header, tail = a.split(b"\n", 1)
            header_text = header.decode()
            self.assertTrue(header_text.startswith(f"{BIN_NAME}: "), header_text)
            self.assertNotIn("/", header_text.split(": ", 1)[0])
            for d in dirs:
                self.assertNotIn(str(d), header_text)
            raw = self.go_version_m(dirs[0] / BIN_NAME)
            raw_header, raw_tail = raw.split(b"\n", 1)
            self.assertEqual(raw_tail, tail,
                             "module/build lines must match raw go version -m output")
            self.assertIn(b"example.com/rpi-buildinfo", a)

    def test_absolute_argument_header_leaks_path(self):
        # The pre-fix invocation form is detectable: the header echoes its
        # argument, so two release dirs differ. Keeps the invariance oracle
        # above from being vacuous.
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            a, b = base / "artifacts-a", base / "artifacts-b"
            for d in (a, b):
                d.mkdir()
                shutil.copy2(self.binary, d / BIN_NAME)
            ra, rb = self.go_version_m(a / BIN_NAME), self.go_version_m(b / BIN_NAME)
            self.assertNotEqual(ra, rb)
            self.assertIn(str(a).encode(), ra.split(b"\n", 1)[0])
            self.assertIn(str(b).encode(), rb.split(b"\n", 1)[0])

    def test_fallback_loop_calls_write_buildinfo(self):
        text = RELEASE_SCRIPT.read_text()
        self.assertIn('write_buildinfo "$bin" || exit 1', text)
        self.assertNotRegex(text, re.escape('go version -m "$bin" >'))


def write_fake_syft(base, body):
    bindir = base / "bin"
    bindir.mkdir(parents=True, exist_ok=True)
    fake = bindir / "syft"
    fake.write_text("#!/bin/sh\n" + body)
    fake.chmod(0o755)
    return bindir


def fake_syft_emitting(doc):
    return "cat <<'SPDX'\n" + json.dumps(doc, indent=1) + "\nSPDX\nexit 0\n"


def json_diff_paths(a, b, prefix=""):
    """Every JSON path at which two parsed documents differ (the independent
    offline evidence used the same recursive technique to isolate exactly
    which fields syft varies)."""
    if type(a) is not type(b):
        yield prefix
    elif isinstance(a, dict):
        for key in sorted(a.keys() | b.keys()):
            if key not in a or key not in b:
                yield f"{prefix}/{key}"
            else:
                yield from json_diff_paths(a[key], b[key], f"{prefix}/{key}")
    elif isinstance(a, list):
        if len(a) != len(b):
            yield f"{prefix}/length"
        for i, (x, y) in enumerate(zip(a, b)):
            yield from json_diff_paths(x, y, f"{prefix}/{i}")
    elif a != b:
        yield prefix


def parse_populated_spdx(case, path):
    """Independent oracle: parse and require the SPDX facts, independent of
    the script's own embedded validator."""
    case.assertTrue(path.is_file(), f"{path} must exist")
    doc = json.loads(path.read_text(encoding="utf-8"))
    for field in SPDX_REQUIRED_FIELDS:
        case.assertTrue(doc.get(field), f"required SPDX field missing/empty: {field}")
    packages = doc.get("packages")
    case.assertIsInstance(packages, list)
    case.assertTrue(packages, "SPDX packages array is empty")
    return doc


class ReleaseSyftFailClosed(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if shutil.which("go") is None:
            raise AssertionError(f"go executable not found; {GO_TOOLCHAIN} is required")
        cls._tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls._tmp.cleanup)
        base = Path(cls._tmp.name)
        mod = base / "src"
        mod.mkdir()
        (mod / "main.go").write_text("package main\n\nfunc main() {}\n")
        subprocess.run(["go", "mod", "init", "example.com/rpi-syft-fallback"],
                       check=True, cwd=str(mod), env=go_env())
        cls.binary = base / BIN_NAME
        subprocess.run(["go", "build", "-o", str(cls.binary), "."],
                       check=True, cwd=str(mod), env=go_env())

    def scanner_failure_base(self):
        # RELEASE-SYFT-ORIGINAL: the original independent reproducer technique
        # — a PATH-first fake syft exiting 23 under set -euo pipefail. Like
        # the real tool, `syft version` still succeeds (the release evidence
        # block queries it), so a guard-spliced-out variant runs to completion
        # and its false success is observable rather than masked by an early
        # `set -e` abort on the version probe.
        base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, base, ignore_errors=True)
        bindir = write_fake_syft(base, (
            'if [ "$1" = "version" ]; then\n'
            '    printf \'Syft Version:    1.57.2\\n'
            'GitCommit:       1a72047fd46c72e0a12ee77e24b23d2316753d08\\n\'\n'
            '    exit 0\n'
            'fi\n'
            'exit 23\n'))
        out = base / "release"
        out.mkdir()
        return bindir, out

    def test_syft_exit_23_is_not_success(self):
        # RELEASE-SYFT-ORIGINAL: controlled scanner exit 23 propagates, writes
        # no sbom.source success claim and leaves no consumable SPDX.
        bindir, out = self.scanner_failure_base()
        snippet = syft_snippet(self, False)
        proc = run_release_snippet(self, snippet, out, path_dirs=[bindir])
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(proc.returncode, 23,
                         "the actual scanner status must propagate (or a distinct "
                         f"nonzero release failure must record it); got {proc.returncode}")
        combined = proc.stdout + proc.stderr
        self.assertIn("23", combined, "scanner status must be preserved in the log")
        self.assertIn("syft", combined)
        self.assertFalse((out / "sbom.source").exists(),
                         "a failed scan must not claim sbom.source success")
        self.assertFalse((out / "sbom.spdx.json").exists(),
                         "a failed scan must not leave an empty/stale SPDX")
        raw_attempt = out.parent / "release-sbom-raw" / "sbom.spdx.raw.json"
        self.assertTrue(raw_attempt.exists(),
                        "the failed raw attempt stays as evidence outside the compared set")

    def test_failed_scan_never_falls_back_and_removes_stale_spdx(self):
        # RELEASE-SYFT-EXIT: through the missing-tool else branch, a failed
        # scan must not fall back to go version -m manifests, and a stale
        # populated SPDX from an earlier successful run must be discarded.
        bindir, out = self.scanner_failure_base()
        shutil.copy2(self.binary, out / BIN_NAME)
        stale = json.dumps(VALID_SYNTHETIC_SPDX, indent=1) + "\n"
        (out / "sbom.spdx.json").write_text(stale)
        snippet = (extract_strict(self) + "\n" + extract_write_buildinfo(self) + "\n"
                   + syft_snippet(self, True))
        proc = run_release_snippet(self, snippet, out, path_dirs=[bindir])
        self.assertEqual(proc.returncode, 23, proc.stderr)
        self.assertFalse((out / "sbom.source").exists())
        self.assertFalse((out / "sbom.spdx.json").exists(),
                         "stale populated SPDX from an earlier run must be removed")
        self.assertEqual(list(out.glob("*.buildinfo")), [],
                         "a failed scan must not silently use the go-version-m fallback")

    def test_zero_exit_with_bad_spdx_fails_closed(self):
        # RELEASE-SYFT-ISOLATED: a scanner exiting zero while emitting
        # missing/empty/malformed SPDX fails the same invariant.
        cases = {
            "empty-output": "exit 0\n",
            "malformed-json": "printf 'not json {{{\\n'\nexit 0\n",
            "missing-fields": "printf '%s\\n' '{\"spdxVersion\": \"SPDX-2.3\"}'\nexit 0\n",
            "empty-packages": "printf '%s\\n' '" + json.dumps(
                {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": "x",
                 "dataLicense": "CC0-1.0", "creationInfo": {"creators": []},
                 "packages": []}) + "'\nexit 0\n",
        }
        block = syft_snippet(self, False)
        for label, body in cases.items():
            with self.subTest(label=label):
                base = Path(tempfile.mkdtemp())
                self.addCleanup(shutil.rmtree, base, ignore_errors=True)
                bindir = write_fake_syft(base, body)
                out = base / "release"
                out.mkdir()
                proc = run_release_snippet(self, block, out, path_dirs=[bindir])
                self.assertNotEqual(proc.returncode, 0,
                                    f"zero exit + {label} must fail closed")
                self.assertFalse((out / "sbom.source").exists())
                self.assertFalse((out / "sbom.spdx.json").exists())

    def test_status_guard_removal_alone_still_fails_closed(self):
        # RELEASE-SYFT-ISOLATED: removing ONLY the exit-status guard leaves
        # populated-output validation as an independent second layer — a
        # nonzero exit without a populated SPDX still fails closed.
        block = syft_snippet(self, False)
        unguarded, status_guard_count = re.subn(
            r'(?<=\n)    if \[ "\$syft_status" -ne 0 \]; then\n.*?\n    fi\n',
            "", block, flags=re.S)
        self.assertGreaterEqual(status_guard_count, 1, "status guard not found to remove")
        bindir, out = self.scanner_failure_base()
        proc = run_release_snippet(self, unguarded, out, path_dirs=[bindir])
        self.assertNotEqual(proc.returncode, 0,
                            "the validation layer must still fail the release")
        self.assertFalse((out / "sbom.source").exists())
        self.assertFalse((out / "sbom.spdx.json").exists())

    def test_guard_removal_restores_false_success(self):
        # RELEASE-SYFT-ISOLATED negative control: with the exit-status guard
        # AND the populated-output/emission guards spliced out of the CURRENT
        # block, the original false success re-emerges — proving the
        # invariants above detect removal of the checks rather than shell
        # syntax drift.
        block = syft_snippet(self, False)
        # Lookbehind (not a consuming leading \n) so removing one guard does
        # not swallow the newline that separates the adjacent guards — each
        # removal must leave a syntactically valid snippet for the next layer.
        unguarded, status_guard_count = re.subn(
            r'(?<=\n)    if \[ "\$syft_status" -ne 0 \]; then\n.*?\n    fi\n',
            "", block, flags=re.S)
        unguarded, valid_guard_count = re.subn(
            r"(?<=\n)    if ! sbom_spdx_is_valid [^\n]*\n.*?\n    fi\n",
            "", unguarded, flags=re.S)
        unguarded, emit_guard_count = re.subn(
            r"(?<=\n)    if ! sbom_spdx_deterministic [^\n]*\n.*?\n    fi\n",
            "", unguarded, flags=re.S)
        self.assertGreaterEqual(status_guard_count, 1, "status guard not found to remove")
        self.assertGreaterEqual(valid_guard_count, 2, "both populated-output guards not found")
        self.assertGreaterEqual(emit_guard_count, 1, "emission guard not found to remove")
        bindir, out = self.scanner_failure_base()
        proc = run_release_snippet(self, unguarded, out, path_dirs=[bindir])
        self.assertEqual(proc.returncode, 0,
                         "unguarded variant must reproduce the original false success")
        self.assertEqual((out / "sbom.source").read_text(), "syft spdx-json\n",
                         "unguarded variant writes the success claim")
        self.assertFalse((out / "sbom.spdx.json").is_file(),
                         "unguarded variant claims success with no usable SPDX")

    def test_valid_synthetic_spdx_succeeds(self):
        # RELEASE-SYFT-ISOLATED positive control: a well-formed populated SPDX
        # from a zero-exit scanner succeeds, so the branch is not always-red.
        base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, base, ignore_errors=True)
        bindir = write_fake_syft(base, fake_syft_emitting(VALID_SYNTHETIC_SPDX))
        out = base / "release"
        out.mkdir()
        block = syft_snippet(self, False)
        proc = run_release_snippet(self, block, out, path_dirs=[bindir])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual((out / "sbom.source").read_text(), "syft spdx-json\n")
        doc = parse_populated_spdx(self, out / "sbom.spdx.json")
        self.assertEqual(doc["SPDXID"], "SPDXRef-DOCUMENT")
        self.assertTrue(str(doc["documentNamespace"]).startswith("https://spdx.org/spdxdocs/"),
                        "delivered namespace must be the emit-time bound value")
        expected_created = datetime.fromtimestamp(
            int(os.environ.get("SOURCE_DATE_EPOCH", "1732000000")), tz=timezone.utc)
        self.assertEqual(doc["creationInfo"]["created"],
                         expected_created.strftime("%Y-%m-%dT%H:%M:%SZ"),
                         "created must be bound to SOURCE_DATE_EPOCH")
        raw_dir = out.parent / "release-sbom-raw"
        evidence = (raw_dir / "sbom-evidence.txt").read_text()
        self.assertIn("source-name: yabanin-core", evidence)
        raw_hash = hashlib.sha256((raw_dir / "sbom.spdx.raw.json").read_bytes()).hexdigest()
        delivered_hash = hashlib.sha256((out / "sbom.spdx.json").read_bytes()).hexdigest()
        self.assertIn(f"raw-sha256: {raw_hash}", evidence,
                      "raw scanner bytes must be hash-bound as evidence")
        self.assertIn(f"delivered-sha256: {delivered_hash}", evidence,
                      "delivered bytes must be separately attributable")

    def test_real_pinned_syft_populated_spdx(self):
        # RELEASE-SYFT-VALID: the actual pinned Syft binary on a tiny offline
        # fixture succeeds, records sbom.source and emits a genuinely populated
        # SPDX document bound to the fixture bytes — not a file with the right
        # name.
        syft_bin = locate_pinned_syft(self)
        base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, base, ignore_errors=True)
        fixture = base / "fixture"
        fixture.mkdir()
        (fixture / "go.mod").write_text(SYFT_FIXTURE_GO_MOD)
        (fixture / "README.txt").write_text("tiny offline fixture\n")
        bindir = base / "bin"
        bindir.mkdir()
        shutil.copy2(syft_bin, bindir / "syft")
        (bindir / "syft").chmod(0o755)
        block = syft_snippet(self, False)
        proc = run_release_snippet(self, block, fixture, path_dirs=[bindir])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual((fixture / "sbom.source").read_text(), "syft spdx-json\n")
        doc = parse_populated_spdx(self, fixture / "sbom.spdx.json")
        self.assertEqual(doc["name"], "yabanin-core",
                         "document name must come from the native --source-name binding")
        self.assertTrue(str(doc["documentNamespace"]).startswith(
            "https://spdx.org/spdxdocs/yabanin-core-"),
            "namespace must be bound to the source revision at emit time")
        names = {str(p.get("name")) for p in doc["packages"]}
        self.assertIn("yabanin-core", names,
                      "the root package must carry the source name, not the directory name")
        self.assertIn("github.com/example/dep", names,
                      "the fixture go.mod dependency must be cataloged")
        creators = doc["creationInfo"].get("creators", [])
        self.assertTrue(any(str(c).startswith("Tool: syft") for c in creators),
                        f"generator must be the real syft scanner: {creators}")
        go_mod_entry = next(f for f in doc.get("files", [])
                            if f.get("fileName") == "go.mod")
        emitted = next(c["checksumValue"] for c in go_mod_entry.get("checksums", [])
                       if c.get("algorithm") == "SHA256")
        self.assertEqual(emitted,
                         hashlib.sha256(SYFT_FIXTURE_GO_MOD.encode()).hexdigest(),
                         "SPDX file checksum must match the scanned fixture bytes")

    def _emit_env(self):
        return {"SBOM_SOURCE_NAME": "yabanin-core",
                "SBOM_SOURCE_VERSION": "b02298ce7ed55fbdc2efb638d6fe70af8aa6856e",
                "SOURCE_DATE_EPOCH": "1732000000"}

    def _scan_with_real_syft(self, base, dirname, go_mod=SYFT_FIXTURE_GO_MOD,
                             extra_env=None):
        syft_bin = locate_pinned_syft(self)
        bindir = base / "bin"
        if not (bindir / "syft").exists():
            bindir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(syft_bin, bindir / "syft")
            (bindir / "syft").chmod(0o755)
        fixture = base / dirname
        fixture.mkdir(parents=True)
        (fixture / "go.mod").write_text(go_mod)
        (fixture / "README.txt").write_text("tiny offline fixture\n")
        proc = run_release_snippet(self, syft_snippet(self, False), fixture,
                                   path_dirs=[bindir], extra_env=extra_env)
        return fixture, proc

    def test_pre_fix_branch_false_success_is_detectable(self):
        # RELEASE-SYFT-ORIGINAL (frozen form): the base-b02298c branch itself
        # turns a scanner exit 23 into release success with an empty SPDX and
        # a success claim — proving these controls can see the original
        # defect, not just the current branch's shape.
        bindir, out = self.scanner_failure_base()
        proc = run_release_snippet(self, ORIGINAL_VULNERABLE_BRANCH, out,
                                   path_dirs=[bindir])
        self.assertEqual(proc.returncode, 0,
                         "the frozen pre-fix branch must reproduce the false success")
        spdx = out / "sbom.spdx.json"
        self.assertTrue(spdx.is_file())
        self.assertEqual(spdx.stat().st_size, 0,
                         "the pre-fix branch leaves the empty SPDX consumable")
        self.assertEqual((out / "sbom.source").read_text(), "syft spdx-json\n",
                         "the pre-fix branch writes the success claim")

    def test_emitting_recipe_deterministic_across_directories(self):
        # Emitting-recipe control on identical input in two differently-named
        # absolute directories with the real pinned scanner: raw scanner bytes
        # still vary (fresh documentNamespace; wall-clock created), but the
        # DELIVERED sbom.spdx.json must be byte-identical with every
        # package/file/relationship fact preserved verbatim from the raw
        # scans. This controls the emitting recipe only; final release
        # reproducibility stays the separate full-rebuild gate.
        base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, base, ignore_errors=True)
        emit_env = self._emit_env()
        fixture_a, proc_a = self._scan_with_real_syft(base, "fixture-alpha", extra_env=emit_env)
        fixture_b, proc_b = self._scan_with_real_syft(
            base, "fixture-beta-much-longer-name", extra_env=emit_env)
        self.assertEqual(proc_a.returncode, 0, proc_a.stderr)
        self.assertEqual(proc_b.returncode, 0, proc_b.stderr)
        raw_a = base / "fixture-alpha-sbom-raw" / "sbom.spdx.raw.json"
        raw_b = base / "fixture-beta-much-longer-name-sbom-raw" / "sbom.spdx.raw.json"
        raw_doc_a = json.loads(raw_a.read_text())
        raw_doc_b = json.loads(raw_b.read_text())
        self.assertNotEqual(raw_a.read_bytes(), raw_b.read_bytes(),
                            "raw scanner bytes are expected to vary; they are evidence, not the compared artifact")
        self.assertNotEqual(raw_doc_a.get("documentNamespace"),
                            raw_doc_b.get("documentNamespace"),
                            "the scanner's own namespace is a fresh UUID per scan")
        delivered_a = (fixture_a / "sbom.spdx.json").read_bytes()
        delivered_b = (fixture_b / "sbom.spdx.json").read_bytes()
        self.assertEqual(delivered_a, delivered_b,
                         "delivered SPDX must be byte-identical for identical input")
        doc = json.loads(delivered_a)
        self.assertEqual(doc["name"], "yabanin-core")
        self.assertTrue(str(doc["documentNamespace"]).startswith(
            "https://spdx.org/spdxdocs/yabanin-core-b02298ce7ed55fbdc2efb638d6fe70af8aa6856e-"))
        expected_created = datetime.fromtimestamp(
            1732000000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.assertEqual(doc["creationInfo"]["created"], expected_created)
        # The emitting step is narrowly verified: relative to each raw scan it
        # touches EXACTLY /creationInfo/created and /documentNamespace — every
        # package/file/relationship/license fact is carried over verbatim.
        for raw_doc, tag in ((raw_doc_a, "alpha"), (raw_doc_b, "beta")):
            self.assertEqual(sorted(json_diff_paths(raw_doc, doc)),
                             ["/creationInfo/created", "/documentNamespace"],
                             f"emit step must not alter any {tag} fact beyond "
                             "the two bound fields")
        # documentNamespace is a pure function of the declared identity and
        # the rest of the content (independent recomputation of the formula).
        expected_body = json.loads(raw_a.read_text())
        expected_body["creationInfo"]["created"] = expected_created
        expected_body.pop("documentNamespace", None)
        canonical = json.dumps(expected_body, sort_keys=True, separators=(",", ":"))
        self.assertEqual(
            doc["documentNamespace"],
            "https://spdx.org/spdxdocs/yabanin-core-b02298ce7ed55fbdc2efb638d6fe70af8aa6856e-"
            + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16],
            "namespace must equal identity + content hash, not a scanner UUID")

    def test_tampered_fixture_changes_delivered_spdx(self):
        # Negative determinism control: changing one fixture fact (the go.mod
        # dependency version) must change the delivered bytes and surface in
        # the cataloged facts — determinism must never swallow content.
        emit_env = self._emit_env()
        base_a = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, base_a, ignore_errors=True)
        base_b = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, base_b, ignore_errors=True)
        self._scan_with_real_syft(base_a, "fixture", extra_env=emit_env)
        self._scan_with_real_syft(base_b, "fixture",
                                  go_mod=SYFT_FIXTURE_GO_MOD.replace("v1.2.3", "v1.9.9"),
                                  extra_env=emit_env)
        delivered_a = (base_a / "fixture" / "sbom.spdx.json").read_bytes()
        delivered_b = (base_b / "fixture" / "sbom.spdx.json").read_bytes()
        self.assertNotEqual(delivered_a, delivered_b,
                            "a changed input fact must change the delivered bytes")
        doc_b = json.loads(delivered_b)
        versions = {str(p.get("versionInfo")) for p in doc_b["packages"]}
        self.assertIn("v1.9.9", versions,
                      "the tampered dependency version must be visible in the catalog")

    def test_identity_mismatch_changes_delivered_spdx(self):
        # Identity-mismatch negative control: identical fixture bytes under a
        # DIFFERENT declared source identity (name+version, same epoch) must
        # yield different delivered bytes — the byte-equality control above is
        # not vacuous, and the identity genuinely binds the document (name,
        # root package, namespace) while the cataloged dependency/file facts
        # survive unchanged.
        base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, base, ignore_errors=True)
        fixture_a, proc_a = self._scan_with_real_syft(
            base, "fixture-identity-a", extra_env=self._emit_env())
        other_identity = {"SBOM_SOURCE_NAME": "not-yabanin-core",
                          "SBOM_SOURCE_VERSION": "ffffffffffffffffffffffffffffffffffffffff",
                          "SOURCE_DATE_EPOCH": "1732000000"}
        fixture_b, proc_b = self._scan_with_real_syft(
            base, "fixture-identity-b", extra_env=other_identity)
        self.assertEqual(proc_a.returncode, 0, proc_a.stderr)
        self.assertEqual(proc_b.returncode, 0, proc_b.stderr)
        delivered_a = (fixture_a / "sbom.spdx.json").read_bytes()
        delivered_b = (fixture_b / "sbom.spdx.json").read_bytes()
        self.assertNotEqual(delivered_a, delivered_b,
                            "a different declared identity must change the delivered bytes")
        doc_a, doc_b = json.loads(delivered_a), json.loads(delivered_b)
        self.assertNotEqual(doc_a["documentNamespace"], doc_b["documentNamespace"],
                            "the namespace is identity-bound")
        self.assertNotEqual(doc_a["name"], doc_b["name"],
                            "the document name follows the declared identity")
        self.assertTrue(str(doc_b["documentNamespace"]).startswith(
            "https://spdx.org/spdxdocs/not-yabanin-core-ffffffffffffffffffffffffffffffffffffffff-"))
        self.assertEqual(doc_a["creationInfo"]["created"],
                         doc_b["creationInfo"]["created"],
                         "same epoch must bind created identically")
        dep_a = next(p for p in doc_a["packages"]
                     if p["name"] == "github.com/example/dep")
        dep_b = next(p for p in doc_b["packages"]
                     if p["name"] == "github.com/example/dep")
        self.assertEqual(dep_a, dep_b,
                         "cataloged dependency facts must not depend on the declared identity")
        self.assertEqual(doc_a["files"], doc_b["files"],
                         "file facts (name, SPDXID, checksums) must not depend on the declared identity")

    def test_syft_pin_verification_rejects_wrong_scanner(self):
        # A scanner that is not the required pin fails the control outright
        # instead of quietly changing SPDX facts.
        base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, base, ignore_errors=True)
        bindir = write_fake_syft(
            base, "printf 'Version: 0.9.9\\nGitCommit: deadbeef\\n'\nexit 0\n")
        with self.assertRaises(AssertionError):
            locate_pinned_syft(self, env={"SYFT_BIN": str(bindir / "syft"),
                                          "PATH": str(bindir)})

    def test_syft_pin_discovery_rejects_missing_scanner(self):
        # Pure discovery (provisioning disabled): no scanner via SYFT_BIN or
        # PATH is an explicit failure — the only real-scanner controls never
        # skip. The provisioning fallback is exercised (and controlled)
        # separately in ReleaseSyftProvisioning below.
        with self.assertRaises(AssertionError):
            locate_pinned_syft(self, env={"PATH": "/nonexistent"},
                               provisioner=False)

    def test_missing_tool_fallback_branch_intact(self):
        # The documented non-strict missing-tool fallback still works exactly
        # as before: buildinfo manifests plus an honest non-syft sbom.source.
        out = Path(tempfile.mkdtemp()) / "release"
        out.mkdir()
        shutil.copy2(self.binary, out / BIN_NAME)
        # The fallback loop globs "$RELEASE_DIR"/yabanin-* (the wrapper
        # binaries a real release set carries); keep the glob matched.
        shutil.copy2(self.binary, out / "yabanin-gateway")
        snippet = (extract_strict(self) + "\n" + extract_write_buildinfo(self) + "\n"
                   + extract_sbom_validator(self) + "\n" + extract_syft_else_body(self))
        proc = run_release_snippet(self, snippet, out)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(
            (out / "sbom.source").read_text(),
            "go-version-m buildinfo fallback (syft not installed; NOT a full SPDX SBOM)\n")
        buildinfo = (out / f"{BIN_NAME}.buildinfo").read_text()
        self.assertIn("example.com/rpi-syft-fallback", buildinfo)
        self.assertFalse((out / "sbom.spdx.json").exists())

    def test_release_cleanup_removes_stale_spdx(self):
        # The start-of-run cleanup discards a stale sbom.spdx.json (the old
        # `sbom-*` glob never matched it), executed as extracted, not grepped.
        statement = extract_release_cleanup_rm(self)
        out = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, out, ignore_errors=True)
        for name in ("sbom.spdx.json", "sbom.source", "sbom-image.spdx.json"):
            (out / name).write_text("stale")
        proc = subprocess.run(
            ["bash", "-c", "set -u\nRELEASE_DIR=" + shlex.quote(str(out)) + "\n" + statement],
            capture_output=True, text=True, env=go_env(), cwd=str(ROOT))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        for name in ("sbom.spdx.json", "sbom.source", "sbom-image.spdx.json"):
            self.assertFalse((out / name).exists(), f"stale {name} must be removed")


class ReleaseSyftProvisioning(unittest.TestCase):
    """RELEASE-SYFT-PORTABILITY: the bounded self-contained provisioning leaf
    behind the real-scanner controls. SYFT_BIN/PATH discovery wins when it
    carries the exact pin; otherwise the official pinned archive is
    downloaded, verified against its reviewed exact SHA-256 and extracted
    safely into per-test temp dirs. Wrong checksums, unsafe members and
    unreachable downloads are explicit failures; nothing here skips and
    nothing depends on machine-private state."""

    @staticmethod
    def _write_archive(path, members):
        """members: name -> bytes. Writes a gzipped tar and returns its
        sha256 (offline fake archives for the negative controls)."""
        import io
        import tarfile
        with tarfile.open(path, "w:gz") as tar:
            for name, data in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()

    def test_wrong_checksum_archive_is_rejected(self):
        base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, base, ignore_errors=True)
        archive = base / "fake.tar.gz"
        digest = self._write_archive(archive, {"syft": b"#!/bin/sh\nexit 0\n"})
        with self.assertRaises(SyftProvisionError) as ctx:
            provision_pinned_syft(self, url=archive.as_uri(), sha256="0" * 64)
        self.assertIn("sha256 mismatch", str(ctx.exception))
        self.assertIn(digest, str(ctx.exception),
                      "the mismatch report must carry the actual digest")

    def test_traversal_member_is_rejected(self):
        base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, base, ignore_errors=True)
        archive = base / "evil.tar.gz"
        digest = self._write_archive(
            archive, {"../escape-proof.txt": b"escaped\n",
                      "syft": b"#!/bin/sh\nexit 0\n"})
        extract_into = base / "extract-here"
        with self.assertRaises(SyftProvisionError) as ctx:
            provision_pinned_syft(self, url=archive.as_uri(), sha256=digest)
        self.assertIn("unsafe or malformed", str(ctx.exception))
        self.assertFalse((base / "escape-proof.txt").exists(),
                         "no archive member may escape the extraction directory")
        # Same control directly against the extractor with an explicit dest.
        with self.assertRaises(SyftProvisionError):
            extract_syft_archive(archive, extract_into)
        self.assertFalse((base / "escape-proof.txt").exists())
        self.assertFalse(extract_into.joinpath("syft").exists(),
                         "a rejected archive must not yield a usable scanner")

    def test_unavailable_download_is_rejected(self):
        absent_root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, absent_root, ignore_errors=True)
        missing = absent_root / "no-such-dir" / "syft.tar.gz"
        with self.assertRaises(SyftProvisionError) as ctx:
            provision_pinned_syft(self, url=missing.as_uri(), sha256="0" * 64)
        self.assertIn("download failed", str(ctx.exception))

    def test_explicit_syft_bin_short_circuits_provisioning(self):
        base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, base, ignore_errors=True)
        bindir = write_fake_syft(
            base, "printf 'Version: 1.57.2\\nGitCommit: "
            "1a72047fd46c72e0a12ee77e24b23d2316753d08\\n'\nexit 0\n")

        def must_not_provision(case):
            raise AssertionError(
                "provisioning must not run when SYFT_BIN carries the pin")

        resolved = locate_pinned_syft(
            self, env={"SYFT_BIN": str(bindir / "syft"),
                       "PATH": "/nonexistent"},
            provisioner=must_not_provision)
        self.assertEqual(resolved, bindir / "syft",
                         "an explicit SYFT_BIN pin must be used verbatim")

    def test_provisioned_scanner_is_the_pinned_real_scanner(self):
        # The real pinned positive for the ordinary path: no SYFT_BIN, no
        # syft on PATH — provisioning yields the genuine pinned scanner in a
        # per-test temp directory (never a global install).
        syft_bin = locate_pinned_syft(self, env={"PATH": "/nonexistent"})
        verify_pinned_syft(self, syft_bin)
        self.assertTrue(syft_bin.is_file() and os.access(syft_bin, os.X_OK))
        self.assertIn("syft-provision-", str(syft_bin),
                      "the provisioned scanner must live in a per-test "
                      "provisioning directory")
