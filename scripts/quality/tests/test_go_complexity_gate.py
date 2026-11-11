"""Wiring invariants for the go-complexity changed gate (QG-C01-03).

Binds the gate selection in scripts/quality/quality.py and the Makefile
recipe to the analyzer, so removing the gate from the changed set or
breaking the recipe fails the self gate that every quality run executes.
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


class GateSelectionTests(unittest.TestCase):
    def test_root_go_changes_select_gate(self):
        gates = quality.classify(["cmd/gateway/main.go"])
        self.assertIn("go-complexity", gates)
        self.assertIn("static", gates)

    def test_nested_go_changes_select_gate(self):
        self.assertIn("go-complexity", quality.classify(["sdks/go/client/client.go"]))
        self.assertIn("go-complexity", quality.classify(["deploy/mock-provider/server.go"]))

    def test_manifests_carry_no_function_bodies(self):
        self.assertNotIn("go-complexity", quality.classify(["go.mod"]))
        self.assertNotIn("go-complexity", quality.classify(["go.sum"]))

    def test_quality_infrastructure_selects_gate(self):
        # The analyzer itself and its wiring are covered by the full profile.
        for path in ("Makefile", ".golangci.yml", "scripts/quality/quality.py",
                     "scripts/quality/complexity/go/go_complexity.py"):
            self.assertIn("go-complexity", quality.classify([path]), path)

    def test_docs_only_diff_never_selects_gate(self):
        self.assertNotIn("go-complexity", quality.classify(["README.md"]))

    def test_full_profile_contains_gate(self):
        self.assertIn("go-complexity", quality.expand(["full"]))

    def test_gate_shares_the_go_toolchain_lane(self):
        self.assertIn("go-complexity", quality.HEAVY_GATES)


class MakefileRecipeTests(unittest.TestCase):
    def setUp(self):
        self.makefile = (ROOT / "Makefile").read_text(encoding="utf-8")

    def test_gate_target_exists_and_invokes_analyzer(self):
        self.assertIn("_quality-go-complexity:", self.makefile)
        block = self.makefile.split("_quality-go-complexity:")[1].split("\n\n")[0]
        self.assertIn("go_complexity.py", block)
        self.assertIn("--base", block)

    def test_recipe_defaults_base_to_head(self):
        block = self.makefile.split("_quality-go-complexity:")[1].split("\n\n")[0]
        self.assertIn('QUALITY_BASE:-HEAD', block)

    def test_recipe_forwards_review_receipt(self):
        block = self.makefile.split("_quality-go-complexity:")[1].split("\n\n")[0]
        self.assertIn("GO_COMPLEXITY_RECEIPT", block)
        self.assertIn("--receipt", block)

    def test_profile_target_exposes_gate(self):
        line = next((l for l in self.makefile.splitlines()
                     if l.startswith("quality-fast ")), "")
        self.assertIn("quality-go-complexity:", line)


if __name__ == "__main__":
    unittest.main()
