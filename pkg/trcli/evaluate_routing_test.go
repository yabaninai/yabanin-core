package trcli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// EV1 tests: the routing regression core is exercised through RunE (no
// os.Exit), so the exit condition is an observable returned error.

// writeGoldenTemp writes rows to a temp golden JSONL file.
func writeGoldenTemp(t *testing.T, rows []routingGoldenRow) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "golden.jsonl")
	var b strings.Builder
	for _, r := range rows {
		b.WriteString(r.ID + "|" + r.Prompt + "|" + r.ExpectClass + "\n")
	}
	_ = os.WriteFile(path, []byte(goldenToJSONL(rows)), 0o600)
	return path
}

func goldenToJSONL(rows []routingGoldenRow) string {
	var b strings.Builder
	for _, r := range rows {
		b.WriteString("{\"id\":\"" + r.ID + "\",\"prompt\":\"" + r.Prompt + "\",\"expect_class\":\"" + r.ExpectClass + "\"}\n")
	}
	return b.String()
}

// A few representative golden rows whose expected class matches the current
// rule-tier behavior (verified against pkg/classifier/rule_tier.go).
func ev1Rows() []routingGoldenRow {
	return []routingGoldenRow{
		{ID: "easy-a", Prompt: "What is the capital of France?", ExpectClass: "easy"},
		{ID: "med-a", Prompt: "Tell me about the history of the Roman Empire and its main emperors", ExpectClass: "medium"},
		{ID: "hard-a", Prompt: "Debug this failing test suite and explain the root cause", ExpectClass: "hard"},
	}
}

func TestEvaluateRouting_GoldenParsesAndMatches(t *testing.T) {
	path := writeGoldenTemp(t, ev1Rows())
	var out strings.Builder
	// Expect-class check only (no --against) must succeed and report all match.
	err := runEvaluateRouting(&out, path, "", "", 0)
	if err != nil {
		t.Fatalf("expected no error, got %v (out=%q)", err, out.String())
	}
	if !strings.Contains(out.String(), "match their expected class") {
		t.Fatalf("expected match summary, got %q", out.String())
	}
}

func TestEvaluateRouting_SaveIsIdempotent(t *testing.T) {
	path := writeGoldenTemp(t, ev1Rows())
	dir := t.TempDir()
	b1 := filepath.Join(dir, "b1.json")
	b2 := filepath.Join(dir, "b2.json")

	if err := runEvaluateRouting(new(strings.Builder), path, b1, "", 0); err != nil {
		t.Fatalf("save b1: %v", err)
	}
	if err := runEvaluateRouting(new(strings.Builder), path, b2, "", 0); err != nil {
		t.Fatalf("save b2: %v", err)
	}
	data1, err := os.ReadFile(b1) //nolint:gosec // temp test path
	if err != nil {
		t.Fatal(err)
	}
	data2, err := os.ReadFile(b2) //nolint:gosec // temp test path
	if err != nil {
		t.Fatal(err)
	}
	// Snapshots of the same classifier over the same golden set must be byte-
	// identical (idempotent), ignoring nothing — the classifier is deterministic.
	if string(data1) != string(data2) {
		t.Fatalf("snapshots not idempotent:\n%s\n---\n%s", data1, data2)
	}
}

func TestEvaluateRouting_AgainstBaseline_NoMismatch(t *testing.T) {
	path := writeGoldenTemp(t, ev1Rows())
	dir := t.TempDir()
	baseline := filepath.Join(dir, "baseline.json")
	if err := runEvaluateRouting(new(strings.Builder), path, baseline, "", 0); err != nil {
		t.Fatalf("save baseline: %v", err)
	}
	var out strings.Builder
	if err := runEvaluateRouting(&out, path, "", baseline, 0); err != nil {
		t.Fatalf("no-mismatch check should pass, got %v (out=%q)", err, out.String())
	}
	if !strings.Contains(out.String(), "OK:") {
		t.Fatalf("expected OK, got %q", out.String())
	}
}

// Mutant: flip one expected class. The --against gate must FAIL (non-nil error)
// with a diff table, proving the exit condition is observable via RunE.
func TestEvaluateRouting_MutantFailsGate(t *testing.T) {
	rows := ev1Rows()
	rows[0].ExpectClass = "hard" // easy-a should be easy; mutate to hard
	goldenPath := writeGoldenTemp(t, rows)

	dir := t.TempDir()
	// Baseline generated from the UN-mutated behavior (the committed truth).
	truthPath := writeGoldenTemp(t, ev1Rows())
	baseline := filepath.Join(dir, "baseline.json")
	if err := runEvaluateRouting(new(strings.Builder), truthPath, baseline, "", 0); err != nil {
		t.Fatalf("save truth baseline: %v", err)
	}

	// Now point --against at the truth baseline but feed the mutant golden set.
	// The mutant's classify is identical (same prompts), but its expect_class
	// differs — so the expect-class summary must report the mismatch. The
	// --against gate compares GOT vs baseline GOT (unchanged), so it still
	// passes; the observable failure is the expect-class divergence. We assert
	// the expect-class mismatch is surfaced.
	var out strings.Builder
	err := runEvaluateRouting(&out, goldenPath, "", baseline, 0)
	if !strings.Contains(out.String(), "do not match their expected class") {
		t.Fatalf("expected expect-class mismatch to be surfaced, got %q (err=%v)", out.String(), err)
	}

	// Direct gate assertion: force a GOT-level regression by comparing a
	// baseline built from the mutant against the truth — must return an error.
	mutantBaseline := filepath.Join(dir, "mutant.json")
	_ = runEvaluateRouting(new(strings.Builder), goldenPath, mutantBaseline, "", 0)
	// truth results vs mutant baseline: the mutated row's expect differs, but
	// GOT is class-based (prompt-driven), so to force a GOT mismatch we mutate
	// the PROMPT instead.
	mutPrompts := ev1Rows()
	mutPrompts[0].Prompt = "Debug this failing test and design a new architecture" // now hard
	mp := writeGoldenTemp(t, mutPrompts)
	mpBaseline := filepath.Join(dir, "mp.json")
	_ = runEvaluateRouting(new(strings.Builder), mp, mpBaseline, "", 0)
	// truth golden vs mutant-prompt baseline → GOT differs on easy-a → gate fails.
	if err := runEvaluateRouting(new(strings.Builder), truthPath, "", mpBaseline, 0); err == nil {
		t.Fatalf("expected the --against gate to fail on a got-class regression, got nil")
	}
}

func TestEvaluateRouting_GoldenValidationErrors(t *testing.T) {
	dir := t.TempDir()
	// Missing expect_class.
	bad := filepath.Join(dir, "bad.jsonl")
	_ = os.WriteFile(bad, []byte("{\"id\":\"x\",\"prompt\":\"hi\"}\n"), 0o600)
	if _, err := loadRoutingGolden(bad); err == nil {
		t.Fatal("expected error for missing expect_class")
	}
	// Duplicate id.
	dup := filepath.Join(dir, "dup.jsonl")
	_ = os.WriteFile(dup, []byte("{\"id\":\"x\",\"prompt\":\"a\",\"expect_class\":\"easy\"}\n{\"id\":\"x\",\"prompt\":\"b\",\"expect_class\":\"easy\"}\n"), 0o600)
	if _, err := loadRoutingGolden(dup); err == nil {
		t.Fatal("expected error for duplicate id")
	}
	// Empty file.
	empty := filepath.Join(dir, "empty.jsonl")
	_ = os.WriteFile(empty, []byte(""), 0o600)
	if _, err := loadRoutingGolden(empty); err == nil {
		t.Fatal("expected error for empty golden file")
	}
}

// Ensure the command is wired under `yb evaluate routing`.
func TestEvaluateRouting_CommandWired(t *testing.T) {
	root := RootCommand()
	// Walk to evaluate → routing.
	var found *cobra.Command
	for _, c := range root.Commands() {
		if c.Name() == "evaluate" {
			for _, sc := range c.Commands() {
				if sc.Name() == "routing" {
					found = sc
				}
			}
		}
	}
	if found == nil {
		t.Fatal("yb evaluate routing subcommand not wired")
	}
}
