import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts/quality"))
SPEC = importlib.util.spec_from_file_location("quality", ROOT / "scripts/quality/quality.py")
quality = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(quality)


class PublicProfileTests(unittest.TestCase):
    def test_full_keeps_product_security_and_behavior_gates(self):
        self.assertTrue({"self", "go-policy", "critical-go", "static", "security", "tests", "routing", "guards",
                         "dashboard", "site", "docs", "int-modules", "secrets", "deps",
                         "licenses", "policy", "package", "alerts", "dr"}.issubset(
                             quality.expand(["full"])))
        self.assertNotIn("claims", quality.expand(["full"]))

    def test_infrastructure_changes_select_all_full_gates(self):
        for path in ("Makefile", "scripts/quality/quality.py", "scripts/quality/security-exceptions.yaml"):
            with self.subTest(path=path):
                self.assertTrue(set(quality.expand(["full"])).issubset(quality.classify([path])))

    def test_every_go_path_selects_policy_and_critical_gates(self):
        for path in ('pkg/auth/auth.go', 'tools/helper/go.mod', 'tests/x_integration_test.go', 'go.sum'):
            with self.subTest(path=path):
                self.assertTrue({'go-policy', 'critical-go'}.issubset(quality.classify([path])))
        self.assertIn('self', quality.HEAVY_GATES)

    def test_public_corpora_select_both_evaluation_gates(self):
        gates = quality.classify(["datasets/eval/golden_routing.jsonl"])
        self.assertIn("routing", gates)
        self.assertIn("guards", gates)


if __name__ == "__main__":
    unittest.main()
