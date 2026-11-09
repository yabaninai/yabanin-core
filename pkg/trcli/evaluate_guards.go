package trcli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/reireirei/yabanin/pkg/agenteval/datasets"
	"github.com/reireirei/yabanin/pkg/guardhooks"
	"github.com/spf13/cobra"
)

// EV2: guard-hook detection eval. `yb evaluate guards` runs the deterministic
// guardhooks.Scan over a labeled corpus and computes precision/recall against
// the expected detect/clean labels. Below-threshold precision or recall is a
// gate failure (returned error, not os.Exit).

// guardLabelRow is one line of the labeled corpus.
type guardLabelRow struct {
	Text   string `json:"text"`
	Type   string `json:"type"`
	Expect string `json:"expect"` // "detect" or "clean"
}

// guardReport is the eval output.
type guardReport struct {
	TP            int                      `json:"tp"`
	FP            int                      `json:"fp"`
	FN            int                      `json:"fn"`
	Precision     float64                  `json:"precision"`
	Recall        float64                  `json:"recall"`
	ByType        map[string]guardTypeStat `json:"by_type"`
	Misclassified []string                 `json:"misclassified"`
	DatasetID     string                   `json:"dataset_id,omitempty"`
	RevisionID    string                   `json:"revision_id,omitempty"`
}

type guardTypeStat struct {
	TP int `json:"tp"`
	FP int `json:"fp"`
	FN int `json:"fn"`
}

// loadGuardCorpus reads and validates the labeled corpus. Each row needs a
// non-empty text and expect in {detect, clean}.
func loadGuardCorpus(path string) ([]guardLabelRow, error) {
	f, err := os.Open(path) //nolint:gosec // operator-chosen file path
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var rows []guardLabelRow
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var row guardLabelRow
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			return nil, fmt.Errorf("corpus line %d: invalid JSON: %w", lineNo, err)
		}
		if strings.TrimSpace(row.Text) == "" {
			return nil, fmt.Errorf("corpus line %d: missing text", lineNo)
		}
		if row.Expect != "detect" && row.Expect != "clean" {
			return nil, fmt.Errorf("corpus line %d: expect must be detect|clean, got %q", lineNo, row.Expect)
		}
		rows = append(rows, row)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("corpus %s has no rows", path)
	}
	return rows, nil
}

// evaluateGuards runs guardhooks.Scan over the corpus and computes the report.
// The hook is in log mode: Scan reports detections without modifying text.
func evaluateGuards(rows []guardLabelRow) guardReport {
	hook := guardhooks.New(guardhooks.ModeLog)
	report := guardReport{ByType: map[string]guardTypeStat{}}
	for _, row := range rows {
		detected := len(hook.Scan(row.Text)) > 0
		expected := row.Expect == "detect"
		stat := report.ByType[row.Type]
		switch {
		case detected && expected:
			report.TP++
			stat.TP++
		case detected && !expected:
			report.FP++
			stat.FP++
			report.Misclassified = append(report.Misclassified, fmt.Sprintf("FP(%s): %s", row.Type, truncate(row.Text, 60)))
		case !detected && expected:
			report.FN++
			stat.FN++
			report.Misclassified = append(report.Misclassified, fmt.Sprintf("FN(%s): %s", row.Type, truncate(row.Text, 60)))
		}
		report.ByType[row.Type] = stat
	}
	report.Precision = ratio(report.TP, report.TP+report.FP)
	report.Recall = ratio(report.TP, report.TP+report.FN)
	sort.Strings(report.Misclassified)
	return report
}

func ratio(num, den int) float64 {
	if den == 0 {
		return 0
	}
	return float64(num) / float64(den)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func evaluateGuardsCmd() *cobra.Command {
	var (
		corpus       string
		revisionPath string
		minPrecision float64
		minRecall    float64
	)
	cmd := &cobra.Command{
		Use:   "guards",
		Short: "Guard-hook detection eval: precision/recall over a labeled corpus",
		Long: `Run the deterministic guard detectors (guardhooks.Scan) over a labeled
corpus and report {tp,fp,fn,precision,recall,by_type}.

  yb evaluate guards --corpus datasets/eval/guards_labeled.jsonl \
      [--min-precision 0.98] [--min-recall 0.90]

  yb evaluate guards --revision dataset-revision.json \
      [--min-precision 0.98] [--min-recall 0.90]

Exit 1 (returned error) if precision or recall is below the thresholds.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if cmd.Flags().Changed("corpus") && cmd.Flags().Changed("revision") {
				return fmt.Errorf("--corpus and --revision cannot be used together")
			}
			if revisionPath != "" {
				return runEvaluateGuardsRevision(cmd.OutOrStdout(), revisionPath, minPrecision, minRecall)
			}
			if corpus == "" {
				return fmt.Errorf("required flag(s) \"corpus\" not set")
			}
			return runEvaluateGuards(cmd.OutOrStdout(), corpus, minPrecision, minRecall)
		},
	}
	cmd.Flags().StringVar(&corpus, "corpus", "", "Path to the legacy labeled guard corpus JSONL")
	cmd.Flags().StringVar(&revisionPath, "revision", "", "Path to a versioned guard dataset revision JSON")
	cmd.Flags().Float64Var(&minPrecision, "min-precision", 0.98, "Minimum precision gate")
	cmd.Flags().Float64Var(&minRecall, "min-recall", 0.90, "Minimum recall gate")
	return cmd
}

// runEvaluateGuards is the pure core: it returns an error (the gate failure)
// and never calls os.Exit, so the exit condition is testable via RunE.
func runEvaluateGuards(out io.Writer, corpusPath string, minPrecision, minRecall float64) error {
	if out == nil {
		out = io.Discard
	}
	rows, err := loadGuardCorpus(corpusPath)
	if err != nil {
		return err
	}
	report := evaluateGuards(rows)
	return writeGuardReport(out, report, minPrecision, minRecall, false)
}

type guardRevisionPayload struct {
	Text   string `json:"text"`
	Type   string `json:"type"`
	Expect string `json:"expect"`
}

func runEvaluateGuardsRevision(out io.Writer, revisionPath string, minPrecision, minRecall float64) error {
	file, err := os.Open(revisionPath) //nolint:gosec // operator-chosen local revision path
	if err != nil {
		return errors.New("cannot read dataset revision")
	}
	defer func() { _ = file.Close() }()
	return evaluateGuardRevision(out, file, minPrecision, minRecall)
}

func evaluateGuardRevision(out io.Writer, source io.Reader, minPrecision, minRecall float64) error {
	if out == nil {
		out = io.Discard
	}
	revision, revisionID, err := datasets.ReadRevision(source)
	if err != nil {
		return err
	}
	rows := make([]guardLabelRow, 0, len(revision.Samples))
	for _, sample := range revision.Samples {
		dec := json.NewDecoder(bytes.NewReader(sample.Payload))
		dec.DisallowUnknownFields()
		var payload guardRevisionPayload
		if err := dec.Decode(&payload); err != nil {
			return errors.New("invalid dataset revision sample payload")
		}
		if err := dec.Decode(new(any)); err != io.EOF {
			return errors.New("invalid dataset revision sample payload")
		}
		if strings.TrimSpace(payload.Text) == "" || (payload.Expect != "detect" && payload.Expect != "clean") {
			return errors.New("invalid dataset revision sample payload")
		}
		rows = append(rows, guardLabelRow(payload))
	}
	report := evaluateGuards(rows)
	report.DatasetID = revision.DatasetID
	report.RevisionID = revisionID
	return writeGuardReport(out, report, minPrecision, minRecall, true)
}

func writeGuardReport(out io.Writer, report guardReport, minPrecision, minRecall float64, includeRevision bool) error {
	var b strings.Builder
	if includeRevision {
		fmt.Fprintf(&b, "dataset_id=%q revision_id=%s\n", report.DatasetID, report.RevisionID)
	}
	fmt.Fprintf(&b, "tp=%d fp=%d fn=%d precision=%.3f recall=%.3f\n",
		report.TP, report.FP, report.FN, report.Precision, report.Recall)
	typeKeys := make([]string, 0, len(report.ByType))
	for k := range report.ByType {
		typeKeys = append(typeKeys, k)
	}
	sort.Strings(typeKeys)
	for _, k := range typeKeys {
		s := report.ByType[k]
		fmt.Fprintf(&b, "  %s: tp=%d fp=%d fn=%d\n", k, s.TP, s.FP, s.FN)
	}
	if len(report.Misclassified) > 0 {
		fmt.Fprintf(&b, "misclassified:\n")
		for _, m := range report.Misclassified {
			fmt.Fprintf(&b, "  %s\n", m)
		}
	}
	if _, err := io.WriteString(out, b.String()); err != nil {
		return err
	}
	if report.Precision < minPrecision || report.Recall < minRecall {
		return fmt.Errorf("guard eval gate failed: precision=%.3f (min %.3f), recall=%.3f (min %.3f)",
			report.Precision, minPrecision, report.Recall, minRecall)
	}
	_, err := fmt.Fprint(out, "OK: precision/recall within thresholds\n")
	return err
}
