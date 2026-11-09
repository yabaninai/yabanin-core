package audit

import (
	"strings"
	"testing"
)

// A04: ingestion regression — the report must always account for every input
// line: parsed + skipped = denominator, and the cap that bounds parsed.

func TestIngest_CapFieldSet(t *testing.T) {
	path := writeFile(t, "cap.jsonl",
		`{"model":"gpt-4o","messages":[{"role":"user","content":"a"}]}`+"\n"+
			`{"model":"gpt-4o","messages":[{"role":"user","content":"b"}]}`+"\n")
	_, stats := ingest(t, path, IngestOptions{Format: "openai-jsonl", MaxRecords: 5})
	if stats.Cap != 5 {
		t.Errorf("Cap = %d, want 5", stats.Cap)
	}
	// Default cap when 0 passed.
	_, statsDef := ingest(t, path, IngestOptions{Format: "openai-jsonl"})
	if statsDef.Cap != DefaultMaxRecords {
		t.Errorf("default Cap = %d, want %d", statsDef.Cap, DefaultMaxRecords)
	}
}

func TestIngest_MalformedJSONSkipped_Denominator(t *testing.T) {
	// One valid line, one invalid JSON line, one valid line.
	path := writeFile(t, "denom.jsonl",
		`{"model":"gpt-4o","messages":[{"role":"user","content":"ok"}]}`+"\n"+
			`{this is not json}`+"\n"+
			`{"model":"gpt-4o","messages":[{"role":"user","content":"also ok"}]}`+"\n")
	recs, stats := ingest(t, path, IngestOptions{Format: "openai-jsonl"})
	if len(recs) != 2 {
		t.Fatalf("parsed = %d, want 2", len(recs))
	}
	if stats.ParseErrorCount != 1 {
		t.Errorf("ParseErrorCount = %d, want 1 (invalid JSON skipped)", stats.ParseErrorCount)
	}
	// The denominator is parsed + skipped — every accounted-for line.
	if stats.Parsed+stats.ParseErrorCount != 3 {
		t.Errorf("denominator = %d, want 3 (2 parsed + 1 skipped)", stats.Parsed+stats.ParseErrorCount)
	}
}

func TestReport_QualityBlockDenominatorAndCap(t *testing.T) {
	path := writeFile(t, "report-denom.jsonl",
		`{"model":"gpt-4o","messages":[{"role":"user","content":"a"}]}`+"\n"+
			`{broken}`+"\n"+
			`{"model":"gpt-4o","messages":[{"role":"user","content":"b"}]}`+"\n"+
			`{broken2}`+"\n")
	recs, stats := ingest(t, path, IngestOptions{Format: "openai-jsonl", MaxRecords: 10})
	report := GenerateReport(recs, ModeExact)
	report.S5.Skipped = stats.ParseErrorCount
	report.S5.Cap = stats.Cap
	report.S5.Denominator = stats.Parsed + stats.ParseErrorCount

	if report.S5.Parsed != 2 {
		t.Errorf("S5.Parsed = %d, want 2", report.S5.Parsed)
	}
	if report.S5.Skipped != 2 {
		t.Errorf("S5.Skipped = %d, want 2", report.S5.Skipped)
	}
	if report.S5.Denominator != 4 {
		t.Errorf("S5.Denominator = %d, want 4 (2+2)", report.S5.Denominator)
	}
	if report.S5.Cap != 10 {
		t.Errorf("S5.Cap = %d, want 10", report.S5.Cap)
	}
}

func TestRender_SurfacesDenominatorAndCap(t *testing.T) {
	path := writeFile(t, "render-denom.jsonl",
		`{"model":"gpt-4o","messages":[{"role":"user","content":"a"}]}`+"\n"+
			`{broken}`+"\n")
	recs, stats := ingest(t, path, IngestOptions{Format: "openai-jsonl", MaxRecords: 7})
	report := GenerateReport(recs, ModeExact)
	report.S5.Skipped = stats.ParseErrorCount
	report.S5.Cap = stats.Cap
	report.S5.Denominator = stats.Parsed + stats.ParseErrorCount

	for name, out := range map[string]string{
		"md":   RenderMarkdown(report),
		"html": RenderHTML(report),
	} {
		if !strings.Contains(out, "Ingestion denominator: 2") {
			t.Errorf("%s: denominator line missing or wrong: %q", name, out)
		}
		if !strings.Contains(out, "Ingestion cap: 7") {
			t.Errorf("%s: cap line missing: %q", name, out)
		}
	}
}

func TestNoPrompts_StillCountsDenominator(t *testing.T) {
	// --no-prompts drops prompt text but must not change the parsed/skipped
	// account: the denominator is about lines, not content.
	path := writeFile(t, "noprompt-denom.jsonl",
		`{"model":"gpt-4o","messages":[{"role":"user","content":"SECRET"}]}`+"\n"+
			`{broken}`+"\n")
	recs, stats := ingest(t, path, IngestOptions{Format: "openai-jsonl", NoPrompts: true})
	if len(recs) != 1 || recs[0].Prompt != "" {
		t.Fatalf("NoPrompts: recs=%d prompt=%q, want 1 record with empty prompt", len(recs), recs[0].Prompt)
	}
	if stats.Parsed+stats.ParseErrorCount != 2 {
		t.Errorf("denominator = %d, want 2 even with NoPrompts", stats.Parsed+stats.ParseErrorCount)
	}
}
