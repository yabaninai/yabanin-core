"""Offline verifier controls using the complete recipe for Alpine's generated release data."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import verify_mock_notices as check


class MockNoticeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = check.CONTEXT.parents[1]
        self.companion = self.root / "source"
        self.legal = check.CONTEXT / "legal"
        self.recipe = "aports/alpine-base/APKBUILD"
        self.license = "reference/MIT.txt"
        self.recipe_notice = "notices/alpine-base/APKBUILD.txt"
        self.package = {"name": "alpine-release", "origin": "alpine-base", "arch": "x86_64",
                        "version": "3.21.10-r0", "license": "MIT",
                        "commit": "a86c7d64dc833c553c7d6121f76ff0717ca64843"}
        database = ("P:alpine-release\nV:3.21.10-r0\nA:x86_64\nL:MIT\no:alpine-base\n"
                    "c:a86c7d64dc833c553c7d6121f76ff0717ca64843\n")
        self.files = {check.DATABASE: database.encode()}
        self.manifest = self.make_manifest()
        self.manifest_bytes = json.dumps(self.manifest).encode()
        self.files[check.LEGAL + "MANIFEST.json"] = self.manifest_bytes

    def make_manifest(self):
        notices = {}
        for name in [*check.PROJECT_FILES, self.license, self.recipe_notice]:
            data = (self.legal / name).read_bytes()
            notices[name] = {"sha256": hashlib.sha256(data).hexdigest()}
            self.files[check.LEGAL + name] = data
        sources = {}
        for name, origin in [(self.recipe, self.recipe_notice), (self.license, self.license)]:
            path = self.companion / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((self.legal / origin).read_bytes())
            sources[name] = notices[origin]["sha256"]
        sums = "".join(f"{value}  {name}\n" for name, value in sorted(sources.items()))
        (self.companion / "SHA256SUMS").write_text(sums)
        return {"schema": 1, "platform": "linux/amd64", "packages": [self.package],
                "sources": {"alpine-base": {"version": self.package["version"], "commit": self.package["commit"],
                                             "inputs": {}, "recipe_tree": "aports", "notices": [self.license, self.recipe_notice]}},
                "notices": notices, "companion_files": sources, "recipe_links": {}, "recipe_executables": []}

    def verify(self, repo=None):
        return check.verify(self.files, self.manifest_bytes, repo or self.repo, self.companion)

    def test_original_image_has_no_legal_directory(self):
        self.files = {check.DATABASE: self.files[check.DATABASE]}
        with self.assertRaisesRegex(ValueError, "missing image notice manifest"):
            self.verify()

    def test_complete_alpine_release(self):
        self.assertEqual(self.verify()["packages"], [self.package])
        self.assertEqual(self.files[check.LEGAL + "NOTICE"], (self.repo / "NOTICE").read_bytes())

    def test_missing_license(self):
        del self.files[check.LEGAL + self.license]
        with self.assertRaisesRegex(ValueError, "missing notice: reference/MIT.txt"):
            self.verify()

    def test_missing_one_installed_package(self):
        self.files[check.DATABASE] = b""
        with self.assertRaisesRegex(ValueError, "installed APK inventory mismatch"):
            self.verify()

    def test_wrong_package_version(self):
        self.files[check.DATABASE] = self.files[check.DATABASE].replace(b"3.21.10-r0", b"3.21.10-r1")
        with self.assertRaisesRegex(ValueError, "installed APK inventory mismatch"):
            self.verify()

    def test_missing_source(self):
        (self.companion / self.recipe).unlink()
        with self.assertRaisesRegex(ValueError, "missing source: aports/alpine-base/APKBUILD"):
            self.verify()

    def test_wrong_source_hash(self):
        (self.companion / self.recipe).write_bytes(b"changed upstream bytes")
        with self.assertRaisesRegex(ValueError, "source hash mismatch: aports/alpine-base/APKBUILD"):
            self.verify()

    def test_wrong_license_hash(self):
        self.files[check.LEGAL + self.license] += b"!"
        with self.assertRaisesRegex(ValueError, "notice hash mismatch: reference/MIT.txt"):
            self.verify()

    def test_project_notice_mismatch(self):
        for name in check.PROJECT_FILES:
            (self.root / name).write_bytes((self.repo / name).read_bytes())
        (self.root / "NOTICE").write_bytes(b"changed project notice")
        with self.assertRaisesRegex(ValueError, "project NOTICE mismatch"):
            self.verify(self.root)


if __name__ == "__main__":
    unittest.main()
