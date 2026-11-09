package trcli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/reireirei/yabanin/pkg/classifier"
	"github.com/spf13/cobra"
)

// EV1: routing regression suite. `yb evaluate routing` classifies every prompt
// in a golden set with the deterministic rule-tier classifier (no network, no
// DB) and compares the resulting class to the expected class. A snapshot
// baseline records the current behavior; --against fails the gate (exit 1) on
// any class mismatch, printing a diff table. A deliberate routing change is
// released by regenerating the baseline in the same commit.

// routingGoldenRow is one line of the golden file.
type routingGoldenRow struct {
	ID          string `json:"id"`
	Prompt      string `json:"prompt"`
	ExpectClass string `json:"expect_class"`
}

// routingResultRow is one row of a snapshot/diff.
type routingResultRow struct {
	ID          string `json:"id"`
	ExpectClass string `json:"expect_class"`
	GotClass    string `json:"got_class"`
	Match       bool   `json:"match"`
}

// routingBaseline is the committed snapshot of current classifier behavior.
type routingBaseline struct {
	Classifier  string             `json:"classifier"`
	GeneratedBy string             `json:"generated_by"`
	Rows        []routingResultRow `json:"rows"`
}

var routingAllowedClasses = map[string]bool{"easy": true, "medium": true, "hard": true}

// loadRoutingGolden reads and validates a golden JSONL file. Every line must be
// a non-empty object with a unique id, a non-empty prompt, and a valid
// expect_class.
func loadRoutingGolden(path string) ([]routingGoldenRow, error) {
	f, err := os.Open(path) //nolint:gosec // operator-chosen file path
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var rows []routingGoldenRow
	seen := map[string]bool{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var row routingGoldenRow
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			return nil, fmt.Errorf("golden line %d: invalid JSON: %w", lineNo, err)
		}
		if row.ID == "" {
			return nil, fmt.Errorf("golden line %d: missing id", lineNo)
		}
		if seen[row.ID] {
			return nil, fmt.Errorf("golden line %d: duplicate id %q", lineNo, row.ID)
		}
		seen[row.ID] = true
		if strings.TrimSpace(row.Prompt) == "" {
			return nil, fmt.Errorf("golden line %d (%s): missing prompt", lineNo, row.ID)
		}
		if !routingAllowedClasses[row.ExpectClass] {
			return nil, fmt.Errorf("golden line %d (%s): invalid expect_class %q (want easy|medium|hard)", lineNo, row.ID, row.ExpectClass)
		}
		rows = append(rows, row)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("golden file %s has no rows", path)
	}
	return rows, nil
}

// classifyRouting runs the deterministic rule-tier classifier over the golden
// rows and returns the result rows (expect vs got + match flag). No network or
// DB is used — the classifier is in-process and pure.
func classifyRouting(rows []routingGoldenRow) ([]routingResultRow, error) {
	cls := classifier.NewRuleTier()
	ctx := context.Background()
	out := make([]routingResultRow, 0, len(rows))
	for _, row := range rows {
		res, err := cls.Classify(ctx, classifier.Input{Prompt: row.Prompt})
		if err != nil {
			return nil, fmt.Errorf("classify %s: %w", row.ID, err)
		}
		got := string(res.Class)
		out = append(out, routingResultRow{
			ID:          row.ID,
			ExpectClass: row.ExpectClass,
			GotClass:    got,
			Match:       got == row.ExpectClass,
		})
	}
	return out, nil
}

// routingMismatch returns the subset of rows whose got class differs from the
// expected (or baseline) class.
func routingMismatch(rows []routingResultRow) []routingResultRow {
	var m []routingResultRow
	for _, r := range rows {
		if !r.Match {
			m = append(m, r)
		}
	}
	sort.Slice(m, func(i, j int) bool { return m[i].ID < m[j].ID })
	return m
}

// writeRoutingDiff prints a human-readable diff table of mismatches to w.
func writeRoutingDiff(w *strings.Builder, got, baseline []routingResultRow) {
	byID := map[string]routingResultRow{}
	for _, r := range baseline {
		byID[r.ID] = r
	}
	var m []routingResultRow
	for _, r := range got {
		if base, ok := byID[r.ID]; !ok || base.GotClass != r.GotClass {
			m = append(m, r)
		}
	}
	sort.Slice(m, func(i, j int) bool { return m[i].ID < m[j].ID })
	if len(m) == 0 {
		w.WriteString("no class mismatches vs baseline\n")
		return
	}
	fmt.Fprintf(w, "%-20s %-10s %-10s\n", "ID", "BASELINE", "GOT")
	for _, r := range m {
		base := byID[r.ID].GotClass
		if _, ok := byID[r.ID]; !ok {
			base = "(new)"
		}
		fmt.Fprintf(w, "%-20s %-10s %-10s\n", r.ID, base, r.GotClass)
	}
}

func evaluateRoutingCmd() *cobra.Command {
	var (
		golden      string
		save        string
		against     string
		maxMismatch int
	)
	cmd := &cobra.Command{
		Use:   "routing",
		Short: "Routing regression: classify a golden prompt set and check it against a snapshot baseline",
		Long: `Classify every prompt in a golden JSONL set with the deterministic rule-tier
classifier (no network/DB) and compare the resulting class to the expected class.

  yb evaluate routing --golden datasets/eval/golden_routing.jsonl          # check expect_class
  yb evaluate routing --golden ... --save datasets/eval/routing_baseline.json
  yb evaluate routing --golden ... --against datasets/eval/routing_baseline.json --max-mismatch 0

A mismatch of any class is a gate failure (exit 1) with a diff table.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runEvaluateRouting(cmd.OutOrStdout(), golden, save, against, maxMismatch)
		},
	}
	cmd.Flags().StringVar(&golden, "golden", "", "Path to the golden routing JSONL set (required)")
	cmd.Flags().StringVar(&save, "save", "", "Write a snapshot baseline of the current behavior to this path")
	cmd.Flags().StringVar(&against, "against", "", "Compare against this snapshot baseline (any class mismatch fails)")
	cmd.Flags().IntVar(&maxMismatch, "max-mismatch", 0, "Maximum allowed class mismatches vs --against (default 0 = fail on any)")
	_ = cmd.MarkFlagRequired("golden")
	return cmd
}

// runEvaluateRouting is the pure core of `yb evaluate routing`. It returns an
// error (non-nil ⇒ the command exits non-zero) and never calls os.Exit, so the
// exit condition is testable via the returned error.
func runEvaluateRouting(out io.Writer, goldenPath, savePath, againstPath string, maxMismatch int) error {
	if out == nil {
		out = io.Discard
	}
	rows, err := loadRoutingGolden(goldenPath)
	if err != nil {
		return err
	}
	results, err := classifyRouting(rows)
	if err != nil {
		return err
	}

	// Report expect_class agreement for the golden set itself.
	expectMismatch := routingMismatch(results)

	// --save: write a snapshot baseline of the current behavior.
	if savePath != "" {
		baseline := routingBaseline{
			Classifier:  classifier.NewRuleTier().Name(),
			GeneratedBy: "yb evaluate routing --save",
			Rows:        results,
		}
		if err := writeRoutingBaseline(savePath, baseline); err != nil {
			return err
		}
	}

	// --against: fail on any class mismatch vs the baseline.
	if againstPath != "" {
		baseline, err := loadRoutingBaseline(againstPath)
		if err != nil {
			return err
		}
		var diff strings.Builder
		writeRoutingDiff(&diff, results, baseline.Rows)
		// Mismatches vs baseline = rows whose got differs from baseline got,
		// plus any golden row not present in the baseline.
		m := baselineMismatchCount(results, baseline.Rows)
		if m > maxMismatch {
			return fmt.Errorf("routing regression: %d class mismatch(es) vs baseline (max allowed %d):\n%s", m, maxMismatch, diff.String())
		}
	}

	// Always summarize expect_class agreement.
	var report strings.Builder
	if savePath != "" {
		fmt.Fprintf(&report, "saved baseline of %d rows to %s\n", len(results), savePath)
	}
	if len(expectMismatch) == 0 {
		fmt.Fprintf(&report, "OK: all %d golden rows match their expected class\n", len(rows))
	} else {
		fmt.Fprintf(&report, "%d golden row(s) do not match their expected class:\n", len(expectMismatch))
		fmt.Fprintf(&report, "%-20s %-10s %-10s\n", "ID", "EXPECTED", "GOT")
		for _, r := range expectMismatch {
			fmt.Fprintf(&report, "%-20s %-10s %-10s\n", r.ID, r.ExpectClass, r.GotClass)
		}
	}
	_, err = fmt.Fprint(out, report.String())
	return err
}

// baselineMismatchCount counts golden result rows whose got class differs from
// the baseline's got class for the same id, or that are absent from the
// baseline.
func baselineMismatchCount(got, baseline []routingResultRow) int {
	byID := map[string]string{}
	for _, b := range baseline {
		byID[b.ID] = b.GotClass
	}
	n := 0
	for _, g := range got {
		base, ok := byID[g.ID]
		if !ok || base != g.GotClass {
			n++
		}
	}
	return n
}

// writeRoutingBaseline writes a snapshot baseline as pretty JSON.
func writeRoutingBaseline(path string, b routingBaseline) error {
	f, err := os.Create(path) //nolint:gosec // operator-chosen output path
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(b)
}

// loadRoutingBaseline reads a snapshot baseline.
func loadRoutingBaseline(path string) (routingBaseline, error) {
	var b routingBaseline
	f, err := os.Open(path) //nolint:gosec // operator-chosen file path
	if err != nil {
		return b, err
	}
	defer func() { _ = f.Close() }()
	if err := json.NewDecoder(f).Decode(&b); err != nil {
		return b, err
	}
	if len(b.Rows) == 0 {
		return b, fmt.Errorf("baseline %s has no rows", path)
	}
	return b, nil
}
