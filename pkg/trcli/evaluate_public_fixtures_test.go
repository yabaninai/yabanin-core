package trcli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPublicRoutingFixtureContract(t *testing.T) {
	goldenPath := findRepoFile(t, "datasets/eval/golden_routing.jsonl")
	baselinePath := findRepoFile(t, "datasets/eval/routing_baseline.json")
	rows, err := loadRoutingGolden(goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := loadRoutingBaseline(baselinePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 32 || len(baseline.Rows) != len(rows) || baseline.Classifier != "rule_tier" {
		t.Fatalf("fixture inventory changed: golden=%d baseline=%d classifier=%q", len(rows), len(baseline.Rows), baseline.Classifier)
	}
	classes := map[string]int{}
	for i, row := range rows {
		classes[row.ExpectClass]++
		b := baseline.Rows[i]
		if b.ID != row.ID || b.ExpectClass != row.ExpectClass || b.GotClass != row.ExpectClass || !b.Match {
			t.Fatalf("baseline row %d does not match the authored expectation for %q", i, row.ID)
		}
	}
	for _, class := range []string{"easy", "medium", "hard"} {
		if classes[class] < 10 {
			t.Errorf("class %s has only %d cases", class, classes[class])
		}
	}
	results, err := classifyRouting(rows)
	if err != nil {
		t.Fatal(err)
	}
	if mismatch := routingMismatch(results); len(mismatch) != 0 {
		t.Fatalf("authored class expectations disagree: %+v", mismatch)
	}
	var out strings.Builder
	if err := runEvaluateRouting(&out, goldenPath, "", baselinePath, 0); err != nil {
		t.Fatal(err)
	}
	rows[0].Prompt = "Debug the synthetic failing loop."
	var data strings.Builder
	for _, row := range rows {
		encoded, err := json.Marshal(row)
		if err != nil {
			t.Fatal(err)
		}
		data.Write(encoded)
		data.WriteByte('\n')
	}
	mutant := filepath.Join(t.TempDir(), "routing-mutant.jsonl")
	if err := os.WriteFile(mutant, []byte(data.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runEvaluateRouting(&out, mutant, "", baselinePath, 0); err == nil || !strings.Contains(err.Error(), "routing regression: 1 class mismatch") {
		t.Fatalf("changed routing behavior must fail the baseline gate: %v", err)
	}
}

func TestPublicGuardFixtureContract(t *testing.T) {
	path := findRepoFile(t, "datasets/eval/guards_labeled.jsonl")
	rows, err := loadGuardCorpus(path)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]map[string]int{}
	for _, row := range rows {
		if counts[row.Type] == nil {
			counts[row.Type] = map[string]int{}
		}
		counts[row.Type][row.Expect]++
	}
	if len(rows) != 24 || len(counts) != 3 {
		t.Fatalf("guard inventory changed: rows=%d categories=%d", len(rows), len(counts))
	}
	for _, category := range []string{"secret", "pan", "injection"} {
		if counts[category]["detect"] != 4 || counts[category]["clean"] != 4 {
			t.Errorf("category %s must contain four positive and four negative controls: %v", category, counts[category])
		}
	}
	report := evaluateGuards(rows)
	if report.TP != 12 || report.FP != 0 || report.FN != 0 {
		t.Fatalf("public smoke corpus detection changed: %+v", report)
	}
	for _, want := range []string{"precision", "recall"} {
		t.Run(want, func(t *testing.T) {
			mutant := append([]guardLabelRow(nil), rows...)
			if want == "precision" {
				mutant[0].Expect = "clean"
			} else {
				// Two misses among twelve cross the default 0.90 recall threshold.
				mutant[0].Text = "An ordinary synthetic sentence."
				mutant[1].Text = "Another ordinary synthetic sentence."
			}
			var out strings.Builder
			err := runEvaluateGuards(&out, writeGuardCorpusTemp(t, mutant), 0.98, 0.90)
			if err == nil || !strings.Contains(err.Error(), "guard eval gate failed") {
				t.Fatalf("%s regression must fail the default thresholds: %v", want, err)
			}
		})
	}
}
