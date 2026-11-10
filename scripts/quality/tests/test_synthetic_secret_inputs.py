import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("secret_scan", ROOT / "scripts/quality/secret_scan.py")
scanner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scanner)


class SyntheticInputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fixture = "datasets/eval/synthetic.json"
        self.sample = ("sk-" + "A" * 24 + "\n").encode()
        self.policy = self.root / "scripts/quality/synthetic-fixtures.json"
        self.policy.parent.mkdir(parents=True)
        self.policy.write_text(json.dumps({"schema": 1, "sha256": {
            self.fixture: hashlib.sha256(self.sample).hexdigest(),
        }}))
        self.git("init", "-q")
        self.git("config", "user.name", "Synthetic Test")
        self.git("config", "user.email", "test@example.invalid")
        self.git("add", ".")
        self.git("commit", "-qm", "base")
        self.base = self.git("rev-parse", "HEAD").strip()

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.root, text=True)

    def write(self, path, data):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    def test_exact_reviewed_bytes_only(self):
        with patch.object(scanner, "ROOT", self.root):
            self.assertTrue(scanner.reviewed_fixture(self.fixture, self.sample))
            self.assertFalse(scanner.reviewed_fixture(self.fixture, self.sample + b"changed"))
            self.assertFalse(scanner.reviewed_fixture("src/config.go", self.sample))

    def test_committed_task_changes_are_scanned_against_original_base(self):
        self.write("config.txt", self.sample)
        self.git("add", ".")
        self.git("commit", "-qm", "synthetic regression")
        with patch.object(scanner, "ROOT", self.root):
            self.assertEqual(scanner.diff_mode(), [])
            self.assertEqual(scanner.diff_mode(self.base)[0]["rule"], "openai-key")

    def test_history_uses_each_commits_bytes_not_current_fixture(self):
        self.write(self.fixture, self.sample)
        self.git("add", ".")
        self.git("commit", "-qm", "reviewed fixture")
        first = self.git("rev-parse", "HEAD").strip()
        self.write(self.fixture, self.sample + ("sk-" + "B" * 24).encode())
        self.git("add", ".")
        self.git("commit", "-qm", "unreviewed fixture mutation")
        second = self.git("rev-parse", "HEAD").strip()
        self.write(self.fixture, self.sample)
        with patch.object(scanner, "ROOT", self.root):
            self.assertEqual(scanner.scan_commits([first]), [])
            self.assertTrue(scanner.scan_commits([second]))

    def test_symlink_target_bytes_do_not_exempt_the_link_blob(self):
        name = "sk-" + "A" * 24
        self.write("datasets/eval/" + name, self.sample)
        target = self.root / self.fixture
        target.symlink_to(name)
        with patch.object(scanner, "ROOT", self.root):
            self.assertTrue(any(f["path"] == self.fixture for f in scanner.diff_mode()))
            self.git("add", self.fixture)
            self.assertTrue(any(f["path"] == self.fixture for f in scanner.diff_mode()))

    def test_changed_staged_and_untracked_fixtures_are_not_exempt(self):
        self.write(self.fixture, self.sample + b"unreviewed")
        with patch.object(scanner, "ROOT", self.root):
            self.assertTrue(scanner.diff_mode())
            self.git("add", self.fixture)
            self.assertTrue(scanner.diff_mode())


if __name__ == "__main__":
    unittest.main()
