"""Evidence base binding: an explicit --base verification request accepts
only a manifest recorded against exactly that resolved base."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]


def git(root, *args):
    subprocess.check_call(
        ["git", "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid",
         *args], cwd=root, stdout=subprocess.DEVNULL)


def load_quality(root):
    sys.path.insert(0, str(root / "scripts/quality"))
    try:
        spec = importlib.util.spec_from_file_location(
            "evidence_fixture_quality", root / "scripts/quality/quality.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
        sys.modules.pop("commands", None)
    return module


def passing_manifest(root, base):
    """A fully valid passed run (gates self+docs) recorded against base."""
    snap = load_quality(root).snapshot(root)
    directory = root / "artifacts/quality/20260101T000000Z-basefixture"
    directory.mkdir(parents=True)
    gates = []
    for name in ("self", "docs"):
        log = directory / f"{name}.log"
        log.write_bytes(f"{name} gate output\n".encode())
        gates.append({"name": name, "status": "passed", "exit_code": 0,
                      "log": f"{name}.log",
                      "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest()})
    document = {"schema_version": 2,
                "evidence": {"version": 2, "command_registry": None,
                             "absent_reason": "registry not present in this repository"},
                "profiles": ["changed"], "started_at": "2026-01-01T00:00:00+00:00",
                "status": "passed", "source": snap, "source_after": snap,
                "base": base, "changed_paths": ["docs/x.md", "docs/y.md"],
                "reasons": {}, "environment": {}, "limitations": [],
                "gates": gates, "skips": []}
    path = directory / "manifest.json"
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return path


class EvidenceBaseBindingTests(unittest.TestCase):
    def setUp(self):
        holder = tempfile.TemporaryDirectory(prefix="evidence-base-")
        self.addCleanup(holder.cleanup)
        self.root = root = Path(holder.name)
        (root / "scripts/quality").mkdir(parents=True)
        for name in ("quality.py", "commands.py"):
            shutil.copy2(ROOT / "scripts/quality" / name, root / "scripts/quality" / name)
        (root / ".gitignore").write_text("artifacts/\n__pycache__/\n")
        (root / "docs").mkdir()
        (root / "docs/x.md").write_text("one\n")
        git(root, "init", "-q")
        git(root, "add", "-A")
        git(root, "commit", "-qm", "base")
        self.base_a = self.head(root)
        (root / "docs/y.md").write_text("two\n")
        git(root, "add", "-A")
        git(root, "commit", "-qm", "second")
        self.base_b = self.head(root)
        (root / "docs/z.md").write_text("three\n")
        git(root, "add", "-A")
        git(root, "commit", "-qm", "third")
        self.manifest = passing_manifest(root, self.base_a)

    @staticmethod
    def head(root):
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root,
                                        text=True).strip()

    def verify(self, *extra):
        return subprocess.run(
            [sys.executable, "scripts/quality/quality.py", "evidence",
             str(self.manifest), "--require", "changed", *extra],
            cwd=self.root, capture_output=True, text=True)

    def test_recorded_base_accepted_and_wrong_base_rejected(self):
        correct = self.verify("--base", self.base_a)
        self.assertEqual(correct.returncode, 0, correct.stderr + correct.stdout)
        wrong = self.verify("--base", self.base_b)
        self.assertNotEqual(wrong.returncode, 0)
        self.assertIn("Evidence base differs", wrong.stderr)
        self.assertIn(self.base_a, wrong.stderr)
        self.assertIn(self.base_b, wrong.stderr)

    def test_base_off_both_candidates_rejected(self):
        document = json.loads(self.manifest.read_text())
        document["base"] = "0" * 40
        self.manifest.write_text(json.dumps(document, indent=2) + "\n")
        for candidate in (self.base_a, self.base_b):
            result = self.verify("--base", candidate)
            self.assertNotEqual(result.returncode, 0, candidate)
            self.assertIn("Evidence base differs", result.stderr)

    def test_implicit_base_keeps_legacy_acceptance(self):
        result = self.verify()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

    def test_source_tamper_still_rejected(self):
        (self.root / "docs/x.md").write_text("tampered\n")
        result = self.verify("--base", self.base_a)
        self.assertNotEqual(result.returncode, 0)

    def test_log_tamper_still_rejected(self):
        log = self.manifest.parent / "docs.log"
        log.write_bytes(log.read_bytes() + b"fabricated\n")
        result = self.verify("--base", self.base_a)
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
