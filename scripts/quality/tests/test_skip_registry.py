"""NEXT-07 skip-registry regression guards.

CI run 43008645785 (PR #63) failed with every gate exit 0 because the five
pkg/gateway real-CLI e2e tests skip on checkout runners (no opencode/codex
binary) and were not yet registered, so finalize() downgraded the run via
unexplained-skip policy findings. These tests pin that the registry explains
both rendered name forms (full import path and the pkg/<leaf> short form) of
every environment-gated skip the checkout runners actually produce.
"""
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts/quality"))
SPEC = importlib.util.spec_from_file_location("quality", ROOT / "scripts/quality/quality.py")
quality = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(quality)

GATEWAY_REAL_E2E = (
    "TestChatCompletions_OpenCodeCLI_RealE2E",
    "TestResponses_CodexCLI_RealE2E",
    "TestResponses_CodexCLI_RealE2E_ToolsLoop",
    "TestResponses_CodexCLI_RealE2E_UnsupportedToolCall",
    "TestResponses_CodexCLI_RealE2E_ClientCancel",
)
FULL_PACKAGE = "github.com/reireirei/yabanin/pkg/gateway"


class SkipRegistryTests(unittest.TestCase):
    def setUp(self):
        self.entries = quality.parse_skips(ROOT / "scripts/quality/skips.yaml")
        self.known = {entry["test"] for entry in self.entries}

    def test_gateway_real_cli_e2e_skips_are_registered(self):
        for test in GATEWAY_REAL_E2E:
            with self.subTest(test=test):
                self.assertIn(f"pkg/gateway.{test}", self.known)

    def test_gateway_real_cli_e2e_skips_explain_both_name_forms(self):
        # Mirror the manifest a CI run records: go test -json reports the
        # full import path, validate_skips also derives the pkg/<leaf> form.
        report = {"gates": [{"name": "tests", "tests": {"skipped": [
            {"package": FULL_PACKAGE, "test": test} for test in GATEWAY_REAL_E2E
        ]}}]}
        self.assertEqual(quality.validate_skips(report, self.entries), [])


if __name__ == "__main__":
    unittest.main()
