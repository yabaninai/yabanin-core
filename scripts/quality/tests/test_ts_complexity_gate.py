"""Wiring invariants for the ts-complexity changed gate (QG-C02-03).

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
    def test_dashboard_ts_changes_select_gate(self):
        gates = quality.classify(["web/dashboard/src/lib/format.ts"])
        self.assertIn("ts-complexity", gates)
        self.assertIn("dashboard", gates)

    def test_dashboard_tsx_jsx_js_mjs_cjs_select_gate(self):
        for path in ("web/dashboard/src/pages/List.tsx", "web/dashboard/src/ui/Tag.jsx",
                     "web/dashboard/eslint.config.js", "web/dashboard/src/rollup.mjs",
                     "web/dashboard/src/loader.cjs"):
            self.assertIn("ts-complexity", quality.classify([path]), path)

    def test_manifests_carry_no_function_bodies(self):
        self.assertNotIn("ts-complexity", quality.classify(["web/dashboard/package.json"]))
        self.assertNotIn("ts-complexity", quality.classify(["web/dashboard/package-lock.json"]))

    def test_out_of_scope_trees_do_not_select_gate(self):
        # The analyzer's default scope is web/dashboard/ only.
        self.assertNotIn("ts-complexity", quality.classify(["web/site/src/app.js"]))
        self.assertNotIn("ts-complexity", quality.classify(["e2e/home.spec.ts"]))

    def test_quality_infrastructure_selects_gate(self):
        for path in ("Makefile", "scripts/quality/quality.py",
                     "scripts/quality/complexity/ts/analyze.mjs"):
            self.assertIn("ts-complexity", quality.classify([path]), path)

    def test_docs_only_diff_never_selects_gate(self):
        self.assertNotIn("ts-complexity", quality.classify(["README.md"]))

    def test_full_profile_contains_gate(self):
        self.assertIn("ts-complexity", quality.expand(["full"]))

    def test_gate_runs_in_the_light_lane(self):
        # Node-based analyzer: it shares no Go toolchain caches, so unlike
        # go-complexity it must stay out of the serialized heavy lane.
        self.assertNotIn("ts-complexity", quality.HEAVY_GATES)


class MakefileRecipeTests(unittest.TestCase):
    def setUp(self):
        self.makefile = (ROOT / "Makefile").read_text(encoding="utf-8")

    def test_gate_target_exists_and_invokes_analyzer(self):
        self.assertIn("_quality-ts-complexity:", self.makefile)
        block = self.makefile.split("_quality-ts-complexity:")[1].split("\n\n")[0]
        self.assertIn("analyze.mjs", block)
        self.assertIn("--base", block)

    def test_recipe_defaults_base_to_head(self):
        block = self.makefile.split("_quality-ts-complexity:")[1].split("\n\n")[0]
        self.assertIn("QUALITY_BASE:-HEAD", block)

    def test_recipe_forwards_review_receipt(self):
        block = self.makefile.split("_quality-ts-complexity:")[1].split("\n\n")[0]
        self.assertIn("TS_COMPLEXITY_RECEIPT", block)
        self.assertIn("--receipt", block)

    def test_profile_target_exposes_gate(self):
        line = next((l for l in self.makefile.splitlines()
                     if l.startswith("quality-fast ")), "")
        words = {w.rstrip(":") for w in line.split()}
        self.assertIn("quality-ts-complexity", words)


if __name__ == "__main__":
    unittest.main()
