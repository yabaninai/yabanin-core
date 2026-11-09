package health

import (
	"context"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/policy"
	"github.com/reireirei/yabanin/pkg/verticals"
)

func TestHealthID(t *testing.T) {
	p := New()
	if p.ID() != ID {
		t.Errorf("expected %s, got %s", ID, p.ID())
	}
}

func TestHealthDetectPHI(t *testing.T) {
	p := New()

	tests := []struct {
		name     string
		text     string
		expected int // expected number of PHI detections
	}{
		{"SSN format", "Patient SSN: 123-45-6789 is on file", 1},
		{"Email", "Contact john@example.com for lab results", 1},
		{"Phone", "Call 555-123-4567 for appointment", 1},
		{"Medication", "Prescribed aspirin and ibuprofen", 1},
		{"No PHI", "Patient reported mild headache", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := p.DetectPHI(tt.text)
			if len(errors) != tt.expected {
				t.Errorf("expected %d PHI detections, got %d: %+v", tt.expected, len(errors), errors)
			}
		})
	}
}

func TestHealthRedactPHI(t *testing.T) {
	p := New()

	text := "Patient SSN: 123-45-6789, email: john@example.com"
	redacted, errors := p.RedactPHI(text)

	if len(errors) < 2 {
		t.Errorf("expected at least 2 PHI detections, got %d", len(errors))
	}
	if !strings.Contains(redacted, "[REDACTED:ssn]") {
		t.Errorf("expected [REDACTED:ssn], got: %s", redacted)
	}
	if !strings.Contains(redacted, "[REDACTED:email]") {
		t.Errorf("expected [REDACTED:email], got: %s", redacted)
	}

	// Original text should still contain the PHI (for audit trail).
	if strings.Contains(text, "123-45-6789") && !strings.Contains(redacted, "123-45-6789") {
		// Good — PHI was removed from redacted output.
	} else if strings.Contains(redacted, "123-45-6789") {
		t.Error("PHI should be redacted from output")
	}
}

func TestHealthTransform(t *testing.T) {
	p := New()
	ctx := context.Background()

	// No PHI — pass through.
	in := verticals.Request{
		OrgID:          "org-1",
		ModelRequested: "gpt-4o",
		Prompt:         "Patient reported mild headache",
		Metadata:       make(map[string]string),
	}

	_, resp, err := p.Transform(ctx, in)
	if err != nil {
		t.Fatalf("transform error: %v", err)
	}
	if resp.Deny {
		t.Error("health transform should not deny clean prompts")
	}

	// With PHI — should redact and set metadata.
	in.Prompt = "Patient SSN: 123-45-6789 needs aspirin"
	_, resp, err = p.Transform(ctx, in)
	if err != nil {
		t.Fatalf("transform error: %v", err)
	}
	if resp.Metadata["phi_detected"] == "" {
		t.Error("expected phi_detected metadata")
	}
	if resp.Metadata["prompt_redacted"] != "true" {
		t.Error("expected prompt_redacted=true")
	}

	// Report should produce valid JSON.
	report, err := p.Report(ctx, "org-1", "2024-01-01", "2024-12-31", "saas")
	if err != nil {
		t.Fatalf("report error: %v", err)
	}
	if !strings.Contains(string(report), `"vertical":"healthcare"`) {
		t.Error("expected healthcare vertical in report")
	}
}

func TestHealthEvaluate(t *testing.T) {
	p := New()
	ctx := context.Background()

	dec := p.Evaluate(ctx, policy.EvalContext{
		ModelRequested: "gpt-4o",
		ModelRegion:    "US",
	}, nil)
	if !dec.Allowed {
		t.Errorf("expected allowed for US region, got denied: %s", dec.Reason)
	}

	// Denied: model region not in allowed list.
	dec = p.Evaluate(ctx, policy.EvalContext{
		ModelRequested: "gpt-4o",
		ModelRegion:    "CN",
	}, nil)
	if dec.Allowed {
		t.Error("expected denied for CN region — healthcare PHI data residency")
	}
}

func TestHealthHint(t *testing.T) {
	h := hint("123-45-6789")
	if h != "12***" {
		t.Errorf("expected 12****, got %s", h)
	}

	h = hint("ab")
	if h != "**" {
		t.Errorf("expected ** for short string, got %s", h)
	}
}
