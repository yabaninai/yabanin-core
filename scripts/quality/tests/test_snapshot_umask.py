"""Source identity is Git's tracked content, not the checkout umask.

snapshot() fingerprints the working tree for evidence source validation.
Git tracks only the executable bit; every other permission bit comes from
the umask of whoever checked out the tree (CI umask 022 vs a local 002).
Source identity must therefore be identical for same-commit, same-content,
same-tracked-mode checkouts under different umasks, while real changes —
content, tracked/working executable bit, deletions and untracked source —
must still alter the fingerprint."""
import hashlib
import importlib.util
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def git(root, *args):
    subprocess.check_call(
        ["git", "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid",
         *args], cwd=root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def load_quality():
    sys.path.insert(0, str(ROOT / "scripts/quality"))
    try:
        spec = importlib.util.spec_from_file_location(
            "snapshot_fixture_quality", ROOT / "scripts/quality" / "quality.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
        sys.modules.pop("commands", None)
    return module


class SnapshotUmaskTests(unittest.TestCase):
    def setUp(self):
        holder = tempfile.TemporaryDirectory(prefix="snapshot-umask-")
        self.addCleanup(holder.cleanup)
        base = Path(holder.name)
        origin = base / "origin"
        origin.mkdir()
        (origin / "data.txt").write_text("tracked content\n")
        (origin / "tool").write_text("#!/bin/sh\nexit 0\n")
        (origin / ".gitignore").write_text("artifacts/\n")
        git(origin, "init", "-q")
        git(origin, "add", "-A")
        # The executable bit is the only permission Git tracks: record it
        # for tool as a tracked fact, independent of the local umask.
        git(origin, "update-index", "--chmod=+x", "tool")
        git(origin, "commit", "-qm", "origin")
        self.origin = origin
        self.holder = base
        self.umask_022 = self.clone(0o022)
        self.umask_002 = self.clone(0o002)
        self.quality = load_quality()

    def clone(self, mask):
        """A fresh checkout created under a forced umask, like CI vs local."""
        target = self.holder / f"clone-{mask:o}"
        subprocess.run(["bash", "-c", f"umask {mask:03o} && git clone -q origin {target}"],
                       cwd=self.holder, check=True, stdout=subprocess.DEVNULL)
        return target

    def fingerprint(self, root):
        return self.quality.snapshot(root)

    def permission_map(self, root):
        """Working-tree permission bits per tracked non-symlink file."""
        listing = subprocess.check_output(["git", "ls-files", "-z"], cwd=root)
        return {name: stat.S_IMODE((root / name).lstat().st_mode)
                for name in listing.decode().split("\0") if name}

    def test_umask_does_not_change_source_identity(self):
        # Preconditions: same tracked modes, same bytes — only the checkout
        # umask differs. A failure here means the fixture, not the defect.
        modes = [subprocess.check_output(["git", "ls-files", "-s"], cwd=clone, text=True)
                 for clone in (self.umask_022, self.umask_002)]
        self.assertEqual(*modes)
        for clone in (self.umask_022, self.umask_002):
            self.assertEqual((clone / "data.txt").read_bytes(), b"tracked content\n")
        self.assertNotEqual(self.permission_map(self.umask_022),
                            self.permission_map(self.umask_002),
                            "fixture is vacuous: umask did not change permissions")
        first, second = self.fingerprint(self.umask_022), self.fingerprint(self.umask_002)
        self.assertEqual(first["commit"], second["commit"])
        self.assertFalse(first["dirty"] or second["dirty"])
        self.assertEqual(first["source_sha256"], second["source_sha256"],
                         f"same Git source under umask 022 ({first['source_sha256']}) "
                         f"and 002 ({second['source_sha256']}) must fingerprint identically")

    def test_content_change_detected(self):
        clone = self.umask_022
        before = self.fingerprint(clone)["source_sha256"]
        (clone / "data.txt").write_text("tracked content\nand a change\n")
        self.assertNotEqual(self.fingerprint(clone)["source_sha256"], before)

    def test_executable_bit_change_detected(self):
        # Dropping mode from the fingerprint entirely would break this: the
        # executable bit must stay part of source identity.
        clone = self.umask_002
        before = self.fingerprint(clone)["source_sha256"]
        os.chmod(clone / "tool", (clone / "tool").stat().st_mode & ~0o111)
        self.assertNotEqual(self.fingerprint(clone)["source_sha256"], before)
        executable_clone = self.umask_022
        before = self.fingerprint(executable_clone)["source_sha256"]
        os.chmod(executable_clone / "data.txt",
                 (executable_clone / "data.txt").stat().st_mode | 0o111)
        self.assertNotEqual(self.fingerprint(executable_clone)["source_sha256"], before)

    def test_deletion_and_untracked_changes_detected(self):
        clone = self.umask_022
        before = self.fingerprint(clone)["source_sha256"]
        (clone / "data.txt").unlink()
        self.assertNotEqual(self.fingerprint(clone)["source_sha256"], before)
        subprocess.run(["git", "-C", str(clone), "checkout", "-q", "--", "data.txt"],
                       check=True)
        self.assertEqual(self.fingerprint(clone)["source_sha256"], before)
        (clone / "untracked.txt").write_text("new source outside the index\n")
        self.assertNotEqual(self.fingerprint(clone)["source_sha256"], before)


if __name__ == "__main__":
    unittest.main()
