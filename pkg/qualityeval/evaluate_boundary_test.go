package qualityeval

import (
	"errors"
	"strings"
	"testing"
)

// A05: boundary + duplicate + error contract.

func TestEvaluate_EmptyCorpus(t *testing.T) {
	// An empty ARRAY is the empty-corpus boundary → ErrEmptyCorpus.
	_, err := Evaluate(strings.NewReader(`[]`), 0.5)
	if !errors.Is(err, ErrEmptyCorpus) {
		t.Fatalf("input []: err = %v, want ErrEmptyCorpus", err)
	}
	// No JSON at all is a parse failure, not an empty corpus.
	for _, in := range []string{`null`, ``} {
		if _, err := Evaluate(strings.NewReader(in), 0.5); err == nil {
			t.Fatalf("input %q: expected an error", in)
		}
	}
}

func TestEvaluate_TooManyCases(t *testing.T) {
	// Build 10001 minimal cases without hitting the byte cap.
	var sb strings.Builder
	sb.WriteString("[")
	for i := 0; i < 10001; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`{"id":"c` + itoa(i) + `","task_id":"t","expected":{},"baseline":{"status":"missing"},"candidate":{"status":"missing"}}`)
	}
	sb.WriteString("]")
	_, err := Evaluate(strings.NewReader(sb.String()), 0.5)
	if !errors.Is(err, ErrTooManyCases) {
		t.Fatalf("err = %v, want ErrTooManyCases", err)
	}
}

func TestEvaluate_DuplicateIDRejected(t *testing.T) {
	in := `[{"id":"one","task_id":"t","expected":{},"baseline":{"status":"missing"},"candidate":{"status":"missing"}},` +
		`{"id":"one","task_id":"t","expected":{},"baseline":{"status":"missing"},"candidate":{"status":"missing"}}]`
	_, err := Evaluate(strings.NewReader(in), 0.5)
	if !errors.Is(err, ErrDuplicateID) {
		t.Fatalf("err = %v, want ErrDuplicateID", err)
	}
}

func TestEvaluate_MissingIDRejected(t *testing.T) {
	for _, in := range []string{
		`[{"task_id":"t","expected":{},"baseline":{"status":"missing"},"candidate":{"status":"missing"}}]`,
		`[{"id":"one","expected":{},"baseline":{"status":"missing"},"candidate":{"status":"missing"}}]`,
		`[{"id":"  ","task_id":"t","expected":{},"baseline":{"status":"missing"},"candidate":{"status":"missing"}}]`,
	} {
		if _, err := Evaluate(strings.NewReader(in), 0.5); !errors.Is(err, ErrMissingID) {
			t.Fatalf("input %s: err = %v, want ErrMissingID", in, err)
		}
	}
}

func TestEvaluate_UnknownInDenominator(t *testing.T) {
	// The denominator is Total, which includes unknown (missing/error)
	// responses — a missing candidate must not shrink the pass-rate basis.
	in := `[
	  {"id":"a","task_id":"t","expected":{},"baseline":{"status":"ok","output":{}},"candidate":{"status":"ok","output":{}}},
	  {"id":"b","task_id":"t","expected":{},"baseline":{"status":"ok","output":{}},"candidate":{"status":"missing"}},
	  {"id":"c","task_id":"t","expected":{},"baseline":{"status":"ok","output":{}},"candidate":{"status":"error"}}
	]`
	report, err := Evaluate(strings.NewReader(in), 0.5)
	if err != nil {
		t.Fatal(err)
	}
	if report.Candidate.Total != 3 {
		t.Fatalf("denominator Total = %d, want 3 (unknown included)", report.Candidate.Total)
	}
	if report.Candidate.Pass != 1 || report.Candidate.Unknown != 2 {
		t.Fatalf("pass/unknown = %d/%d, want 1/2", report.Candidate.Pass, report.Candidate.Unknown)
	}
	// 1/3 pass = 0.333 < 0.5 threshold → gate fails, computed over Total.
	if report.MeetsThreshold {
		t.Fatal("meets_threshold must be false when pass/Total < threshold")
	}
}

func TestEvaluate_ErrorContract(t *testing.T) {
	// Each failure class is distinguishable via errors.Is, so a caller can
	// branch on it without parsing message text.
	valid := `[{"id":"one","task_id":"t","expected":{},"baseline":{"status":"missing"},"candidate":{"status":"ok","output":{}}}]`

	cases := []struct {
		name string
		in   string
		rate float64
		want error
	}{
		{"threshold>1", valid, 1.1, ErrInvalidThreshold},
		{"threshold<0", valid, -0.1, ErrInvalidThreshold},
		{"empty", `[]`, 0.5, ErrEmptyCorpus},
		{"duplicate", `[{"id":"x","task_id":"t","expected":{},"baseline":{"status":"missing"},"candidate":{"status":"missing"}},{"id":"x","task_id":"t","expected":{},"baseline":{"status":"missing"},"candidate":{"status":"missing"}}]`, 0.5, ErrDuplicateID},
		{"missing-id", `[{"task_id":"t","expected":{},"baseline":{"status":"missing"},"candidate":{"status":"missing"}}]`, 0.5, ErrMissingID},
		{"trailing", valid + `[]`, 0.5, nil}, // non-sentinel: "trailing JSON"
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Evaluate(strings.NewReader(tc.in), tc.rate)
			if tc.want == nil {
				if err == nil {
					t.Fatal("expected an error, got nil")
				}
				// Non-sentinel errors must not match any sentinel.
				for _, s := range []error{ErrInvalidThreshold, ErrEmptyCorpus, ErrTooManyCases, ErrDuplicateID, ErrMissingID, ErrInputTooLarge} {
					if errors.Is(err, s) {
						t.Fatalf("unexpected sentinel %v", s)
					}
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want errors.Is %v", err, tc.want)
			}
		})
	}
}

// itoa is a tiny int→string helper to avoid importing strconv in the test.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}
