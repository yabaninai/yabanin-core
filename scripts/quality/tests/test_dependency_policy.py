import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("dep_audit", ROOT / "scripts/quality/dep_audit.py")
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


class DependencyPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "scripts/quality").mkdir(parents=True)
        (self.root / "scripts/security").mkdir(parents=True)
        self.policy = self.root / "scripts/quality/security-exceptions.yaml"
        self.policy.write_bytes((ROOT / "scripts/quality/security-exceptions.yaml").read_bytes())
        (self.root / "scripts/security/scanner-lock.json").write_text(
            json.dumps({"scanners": {"trivy": {"version": "0.75.0"}}}))
        self.findings = []

    def scan(self):
        def invoke(args, **kwargs):
            if args[-1] == "--version":
                return subprocess.CompletedProcess(args, 0, "Version: 0.75.0\n", "")
            body = {"Results": [{"Target": "web/dashboard/package-lock.json",
                                 "Vulnerabilities": self.findings}]}
            return subprocess.CompletedProcess(args, int(bool(self.findings)), json.dumps(body), "")

        with patch.object(audit, "ROOT", self.root), \
             patch.object(audit, "tracked_paths", side_effect=lambda pattern: ["web/dashboard/package-lock.json"] if pattern == "package-lock.json" else []), \
             patch.object(audit.subprocess, "run", side_effect=invoke):
            return audit.trivy_audit()

    def test_public_license_policy_allows_scanner_to_run(self):
        status, details = self.scan()
        self.assertEqual(status, "ok", details)
        self.assertIn("exact_exceptions_applied=0", details)

    def test_license_metadata_exception_cannot_hide_a_vulnerability(self):
        self.findings = [{"VulnerabilityID": "CVE-2099-0001", "PkgName": "eval",
                          "InstalledVersion": "0.1.8", "Severity": "HIGH", "FixedVersion": "0.1.9"}]
        status, details = self.scan()
        self.assertEqual(status, "fail", details)
        self.assertIn("CVE-2099-0001", details)
        self.assertIn("exact_exceptions_applied=0", details)

    def test_malformed_policy_fails_closed(self):
        for content in ("[]", "schema: 2\nexceptions: []", "schema: 1\nexceptions: null"):
            with self.subTest(content=content):
                self.policy.write_text(content)
                self.assertEqual(self.scan()[0], "error")

    def test_exceptions_registry_license_entries_are_scoped(self):
        policy = yaml.safe_load(self.policy.read_text())
        self.assertEqual(policy["schema"], 1)
        entries = policy["exceptions"]
        # The registry is shared by scanner-tagged consumers; only the
        # license_check entries form the public license policy.
        license_entries = [entry for entry in entries
                           if entry.get("scanner") == "license_check"]
        self.assertEqual(len(license_entries), 3)
        for entry in license_entries:
            for key in ("id", "path", "scope", "version", "reason", "owner", "expires"):
                self.assertTrue(entry[key], key)
        # Every entry must name its scanner: untagged entries are silently
        # honored by the secret scanner (secret_scan.py).
        for entry in entries:
            self.assertIn(entry.get("scanner"),
                          ("license_check", "secret_scan", "dep_audit"))
            for key in ("id", "path", "reason", "owner", "expires"):
                self.assertTrue(entry.get(key), key)


if __name__ == "__main__":
    unittest.main()
