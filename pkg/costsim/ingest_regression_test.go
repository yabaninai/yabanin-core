package audit

import (
	"strings"
	"testing"
)

// Ingestion regression invariant: the report must always account for every
// input line: parsed + skipped = denominator, and the cap that bounds parsed.

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

func TestStreamedCSVHeaderLongFieldAndCap(t *testing.T) {
	text := strings.Repeat("x", 9000) + "\nsecond line"
	input := "\nmodel,prompt,provider\ngpt-4o,\"" + text + "\",local\ngpt-4o,next,local\n"
	rows, stats, err := IngestReader(t.Context(), strings.NewReader(input), "", IngestOptions{MaxRecords: 1, Provider: "override"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || !stats.WasTruncated || rows[0].Prompt != text || rows[0].Provider != "override" {
		t.Fatal("CSV sniff, buffering, cap or override mismatch")
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

func TestIngest_JSONLExtensionParsesGatewayLines(t *testing.T) {
	// A .jsonl-named gateway export (model_used/tokens_in, no OpenAI fields)
	// must parse instead of counting every line as a parse error: the unified
	// reader falls back from the OpenAI shape to the gateway shape per line.
	path := writeFile(t, "gateway.jsonl",
		`{"model_used":"gpt-4o","tokens_in":700,"tokens_out":40}`+"\n"+
			`{"model_used":"gpt-4o-mini","tokens_in":100,"tokens_out":20}`+"\n")
	recs, stats := ingest(t, path, IngestOptions{}) // auto, selected by extension
	if len(recs) != 2 || stats.ParseErrorCount != 0 {
		t.Fatalf("parsed=%d errors=%d, want 2 parsed / 0 skipped", len(recs), stats.ParseErrorCount)
	}
	if recs[0].Model != "gpt-4o" || recs[0].PromptTokens != 700 || recs[0].CompletionTokens != 40 || recs[0].Prompt != "" {
		t.Fatalf("gateway row misparsed: %+v", recs[0])
	}
	if stats.RealTokenCount != 2 {
		t.Errorf("RealTokenCount = %d, want 2 (gateway counts are real)", stats.RealTokenCount)
	}
}

func TestExact_PromptlessRecordsAreMisses(t *testing.T) {
	// request_logs-style rows carry no prompt text. exactKey must treat an
	// unavailable prompt as a miss, not a shared identity: prompt-less calls
	// to the same model must not manufacture cache hits from each other.
	recs := []Record{
		{Model: "gpt-4o", PromptTokens: 700, CompletionTokens: 40},
		{Model: "gpt-4o", PromptTokens: 700, CompletionTokens: 40},
	}
	res, err := SimulateCache(recs, SimCacheOptions{Mode: ModeExact})
	if err != nil {
		t.Fatal(err)
	}
	if res.Requests != 2 || res.Hits != 0 || res.TokensAvoided != 0 {
		t.Fatalf("requests=%d hits=%d avoided=%d, want 2/0/0",
			res.Requests, res.Hits, res.TokensAvoided)
	}
}

func TestNoPrompts_KeepsExactHits(t *testing.T) {
	// --no-prompts drops the raw text but must keep the exact-cache identity
	// computed before the drop: repeated prompts still count as hits.
	const row = `{"model":"gpt-4o","messages":[{"role":"user","content":"alpha"}],"usage":{"prompt_tokens":8,"completion_tokens":3}}`
	path := writeFile(t, "noprompt-hit.jsonl", row+"\n"+row+"\n")
	recs, stats := ingest(t, path, IngestOptions{Format: "openai-jsonl", NoPrompts: true})
	if len(recs) != 2 || recs[0].Prompt != "" || recs[1].Prompt != "" {
		t.Fatalf("recs=%d prompts=%q/%q, want 2 records with dropped text",
			len(recs), recs[0].Prompt, recs[1].Prompt)
	}
	if stats.Parsed+stats.ParseErrorCount != 2 {
		t.Errorf("denominator = %d, want 2", stats.Parsed+stats.ParseErrorCount)
	}
	res, err := SimulateCache(recs, SimCacheOptions{Mode: ModeExact})
	if err != nil {
		t.Fatal(err)
	}
	if res.Requests != 2 || res.Hits != 1 || res.TokensAvoided != 11 {
		t.Fatalf("requests=%d hits=%d avoided=%d, want 2/1/11",
			res.Requests, res.Hits, res.TokensAvoided)
	}
}
