// Package qualityeval compares structured outputs offline without disclosing payloads.
package qualityeval

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"
)

const maxBytes = 8 << 20

// Sentinel errors let callers branch on the failure class without parsing
// message text (the A05 error contract). Each maps to a distinct operator
// action: fix the threshold, shrink the file, or correct the dataset.
var (
	// ErrInvalidThreshold is returned when min-pass-rate is outside [0,1].
	ErrInvalidThreshold = fmt.Errorf("min-pass-rate must be between 0 and 1")
	// ErrInputTooLarge is returned when the input exceeds maxBytes.
	ErrInputTooLarge = fmt.Errorf("evaluation input exceeds 8 MiB")
	// ErrEmptyCorpus is returned when the dataset has no cases.
	ErrEmptyCorpus = fmt.Errorf("evaluation requires at least 1 case")
	// ErrTooManyCases is returned when the dataset exceeds 10000 cases.
	ErrTooManyCases = fmt.Errorf("evaluation allows at most 10000 cases")
	// ErrDuplicateID is returned when two cases share an identifier.
	ErrDuplicateID = fmt.Errorf("duplicate case identifier")
	// ErrMissingID is returned when a case lacks an id or task_id.
	ErrMissingID = fmt.Errorf("missing case identifier")
)

// Output describes the result of one model invocation.
type Output struct {
	Status string          `json:"status"`
	Output json.RawMessage `json:"output,omitempty"`
}

// Case is a single labeled task example.
type Case struct {
	ID        string          `json:"id"`
	TaskID    string          `json:"task_id"`
	Expected  json.RawMessage `json:"expected"`
	Baseline  Output          `json:"baseline"`
	Candidate Output          `json:"candidate"`
}

// Counts includes unknown responses in Total.
type Counts struct {
	Total   int `json:"total"`
	Pass    int `json:"pass"`
	Fail    int `json:"fail"`
	Unknown int `json:"unknown"`
}

// Row exposes only identifiers and verdicts, never model outputs.
type Row struct {
	ID        string `json:"id"`
	TaskID    string `json:"task_id"`
	Baseline  string `json:"baseline"`
	Candidate string `json:"candidate"`
}

// Task records a deterministic per-task summary.
type Task struct {
	TaskID    string `json:"task_id"`
	Baseline  Counts `json:"baseline"`
	Candidate Counts `json:"candidate"`
}

// Report is a dataset assessment, not a production quality guarantee.
type Report struct {
	Baseline       Counts  `json:"baseline"`
	Candidate      Counts  `json:"candidate"`
	Regressions    int     `json:"regressions"`
	MinPassRate    float64 `json:"min_pass_rate"`
	MeetsThreshold bool    `json:"meets_threshold"`
	Tasks          []Task  `json:"tasks"`
	Rows           []Row   `json:"rows"`
}

// Evaluate reads bounded strict JSON and compares outputs with exact numeric representations.
func Evaluate(r io.Reader, minPassRate float64) (Report, error) {
	report := Report{MinPassRate: minPassRate}
	if !(minPassRate >= 0 && minPassRate <= 1) {
		return report, ErrInvalidThreshold
	}
	data, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return report, fmt.Errorf("read evaluation input: %w", err)
	}
	if len(data) > maxBytes {
		return report, ErrInputTooLarge
	}
	if err := uniqueKeys(json.NewDecoder(bytes.NewReader(data))); err != nil {
		return report, fmt.Errorf("invalid or ambiguous evaluation JSON")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var cases []Case
	if err := dec.Decode(&cases); err != nil {
		return report, fmt.Errorf("invalid evaluation schema")
	}
	if len(cases) == 0 {
		return report, ErrEmptyCorpus
	}
	if len(cases) > 10000 {
		return report, ErrTooManyCases
	}
	seen := make(map[string]bool)
	tasks := make(map[string]*Task)
	for i, c := range cases {
		if strings.TrimSpace(c.ID) == "" || strings.TrimSpace(c.TaskID) == "" {
			return report, fmt.Errorf("case %d: %w", i+1, ErrMissingID)
		}
		if seen[c.ID] {
			return report, fmt.Errorf("case %d: %w", i+1, ErrDuplicateID)
		}
		seen[c.ID] = true
		expected, err := value(c.Expected)
		if err != nil {
			return report, fmt.Errorf("case %d: invalid expected output", i+1)
		}
		switch expected.(type) {
		case map[string]any, []any:
		default:
			return report, fmt.Errorf("case %d: expected must be an object or array", i+1)
		}
		base, err := verdict(c.Baseline, expected)
		if err != nil {
			return report, fmt.Errorf("case %d: invalid baseline", i+1)
		}
		candidate, err := verdict(c.Candidate, expected)
		if err != nil {
			return report, fmt.Errorf("case %d: invalid candidate", i+1)
		}
		count(&report.Baseline, base)
		count(&report.Candidate, candidate)
		if base == "pass" && candidate != "pass" {
			report.Regressions++
		}
		task := tasks[c.TaskID]
		if task == nil {
			task = &Task{TaskID: c.TaskID}
			tasks[c.TaskID] = task
		}
		count(&task.Baseline, base)
		count(&task.Candidate, candidate)
		report.Rows = append(report.Rows, Row{ID: c.ID, TaskID: c.TaskID, Baseline: base, Candidate: candidate})
	}
	for _, task := range tasks {
		report.Tasks = append(report.Tasks, *task)
	}
	sort.Slice(report.Tasks, func(i, j int) bool { return report.Tasks[i].TaskID < report.Tasks[j].TaskID })
	report.MeetsThreshold = float64(report.Candidate.Pass)/float64(report.Candidate.Total) >= minPassRate && report.Regressions == 0
	return report, nil
}

func value(raw json.RawMessage) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}
func verdict(o Output, expected any) (string, error) {
	switch o.Status {
	case "missing", "error":
		if len(o.Output) != 0 {
			return "", fmt.Errorf("unexpected output")
		}
		return "unknown", nil
	case "ok":
		v, err := value(o.Output)
		if err != nil {
			return "", err
		}
		if reflect.DeepEqual(v, expected) {
			return "pass", nil
		}
		return "fail", nil
	default:
		return "", fmt.Errorf("invalid status")
	}
}
func count(c *Counts, v string) {
	c.Total++
	switch v {
	case "pass":
		c.Pass++
	case "fail":
		c.Fail++
	default:
		c.Unknown++
	}
}

// uniqueKeys rejects duplicate keys and trailing values without logging input.
func uniqueKeys(dec *json.Decoder) error {
	dec.UseNumber()
	if err := walkJSON(dec); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	return nil
}
func walkJSON(dec *json.Decoder) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	keys := map[string]bool{}
	for dec.More() {
		if delim == '{' {
			key, err := dec.Token()
			if err != nil {
				return err
			}
			s, ok := key.(string)
			if !ok || keys[s] {
				return fmt.Errorf("duplicate key")
			}
			keys[s] = true
		}
		if err := walkJSON(dec); err != nil {
			return err
		}
	}
	_, err = dec.Token()
	return err
}
