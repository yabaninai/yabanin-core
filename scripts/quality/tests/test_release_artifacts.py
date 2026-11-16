"""Retained regression: release fallback .buildinfo manifests are path-invariant.

scripts/release/release-artifacts.sh (syft-absent fallback) emits one
<binary>.buildinfo per subject via write_buildinfo(); those bytes must not
depend on the absolute RELEASE_DIR, and the module/build lines after the
header stay exactly what `go version -m` reports.
"""

import os
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
RELEASE_SCRIPT = ROOT / "scripts" / "release" / "release-artifacts.sh"
BIN_NAME = "yabanin"
GO_TOOLCHAIN = "go1.27.4"


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
