package audit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return path
}

func ingest(t *testing.T, path string, opts IngestOptions) ([]Record, IngestStats) {
	t.Helper()
	recs, stats, err := Ingest(context.Background(), path, opts)
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	return recs, stats
}

func TestIngest_OpenAIJSONL_Wrapped(t *testing.T) {
	// JSONL is one JSON object per line — the wrapped shape on a single line.
	path := writeFile(t, "wrapped.jsonl",
		`{"request":{"model":"gpt-4o","max_tokens":128,"temperature":0.7,`+
			`"messages":[{"role":"system","content":"You are helpful."},{"role":"user","content":"Hi"}]},`+
			`"response":{"usage":{"prompt_tokens":10,"completion_tokens":5}},`+
			`"timestamp":"2026-08-01T10:00:00Z","duration_ms":250,"status_code":200}`+"\n")
	recs, stats := ingest(t, path, IngestOptions{Format: "openai-jsonl"})
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	r := recs[0]
	if r.Model != "gpt-4o" {
		t.Errorf("model = %q, want gpt-4o", r.Model)
	}
	if r.Provider != "openai" {
		t.Errorf("provider = %q, want openai", r.Provider)
	}
	if r.PromptTokens != 10 || r.CompletionTokens != 5 {
		t.Errorf("tokens = %d/%d, want 10/5", r.PromptTokens, r.CompletionTokens)
	}
	if r.TokensEstimated {
		t.Error("TokensEstimated should be false (real usage counts present)")
	}
	if r.MaxTokens != 128 {
		t.Errorf("max_tokens = %d, want 128", r.MaxTokens)
	}
	if !r.TemperatureSet || r.Temperature != 0.7 {
		t.Errorf("temperature = %v (set=%v), want 0.7 (set)", r.Temperature, r.TemperatureSet)
	}
	if r.StatusCode != 200 || r.DurationMS != 250 {
		t.Errorf("status/duration = %d/%d, want 200/250", r.StatusCode, r.DurationMS)
	}
	if r.Timestamp.IsZero() {
		t.Error("timestamp should be parsed")
	}
	// Prompt should contain both message contents.
	if !contains(r.Prompt, "You are helpful.") || !contains(r.Prompt, "Hi") {
		t.Errorf("prompt = %q, want it to contain both messages", r.Prompt)
	}
	if stats.ParseErrorCount != 0 {
		t.Errorf("ParseErrorCount = %d, want 0", stats.ParseErrorCount)
	}
	if stats.RealTokenCount != 1 {
		t.Errorf("RealTokenCount = %d, want 1", stats.RealTokenCount)
	}
}

func TestIngest_OpenAIJSONL_Flat(t *testing.T) {
	path := writeFile(t, "flat.jsonl",
		`{"model":"claude-3-5-sonnet","messages":[{"role":"user","content":"Hello world"}],`+
			`"max_tokens":64,"temperature":0.2,"usage":{"prompt_tokens":3,"completion_tokens":7},`+
			`"timestamp":"2026-08-01T11:00:00Z","duration_ms":120,"status_code":200}
`)
	recs, _ := ingest(t, path, IngestOptions{Format: "openai-jsonl"})
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	r := recs[0]
	if r.Model != "claude-3-5-sonnet" {
		t.Errorf("model = %q", r.Model)
	}
	if r.Provider != "anthropic" {
		t.Errorf("provider = %q, want anthropic", r.Provider)
	}
	if r.PromptTokens != 3 || r.CompletionTokens != 7 {
		t.Errorf("tokens = %d/%d, want 3/7", r.PromptTokens, r.CompletionTokens)
	}
	if !r.TemperatureSet || r.Temperature != 0.2 {
		t.Errorf("temperature = %v", r.Temperature)
	}
}

func TestIngest_CSV_ShuffledAndMissingColumns(t *testing.T) {
	// Header order differs from the canonical order, and several columns are
	// absent entirely. Missing columns are simply absent data, not an error.
	path := writeFile(t, "shuffled.csv",
		"duration_ms,model,status_code,provider\n"+
			"100,gemini-1.5,200,google\n"+
			"200,llama-3-70b,500,openweights\n")
	recs, stats := ingest(t, path, IngestOptions{Format: "csv"})
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2", len(recs))
	}
	if recs[0].Model != "gemini-1.5" || recs[0].DurationMS != 100 || recs[0].StatusCode != 200 {
		t.Errorf("rec[0] = %+v", recs[0])
	}
	// provider column present → used verbatim (not inferred).
	if recs[0].Provider != "google" {
		t.Errorf("rec[0] provider = %q, want google", recs[0].Provider)
	}
	// No prompt, no token counts → TokensEstimated must stay false and the
	// record still counts (model present).
	if recs[1].TokensEstimated {
		t.Error("rec[1] TokensEstimated should be false (no prompt to estimate from)")
	}
	if stats.ParseErrorCount != 0 {
		t.Errorf("ParseErrorCount = %d, want 0", stats.ParseErrorCount)
	}
}

func TestIngest_CSV_NoModelColumnErrors(t *testing.T) {
	path := writeFile(t, "nomodel.csv", "foo,bar\n1,2\n")
	_, _, err := Ingest(context.Background(), path, IngestOptions{Format: "csv"})
	if err == nil {
		t.Fatal("expected error for csv with no model column")
	}
}

func TestIngest_TokenRouter_JSONL(t *testing.T) {
	// request_logs export: no prompt text; real gateway counts.
	path := writeFile(t, "tr.jsonl",
		`{"model_used":"gpt-4o","tokens_in":42,"tokens_out":7,"status_code":200,"duration_ms":90,"created_at":"2026-08-01T09:00:00Z"}
`)
	recs, stats := ingest(t, path, IngestOptions{Format: "tokenrouter"})
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	r := recs[0]
	if r.Model != "gpt-4o" {
		t.Errorf("model = %q, want gpt-4o (from model_used)", r.Model)
	}
	if r.PromptTokens != 42 || r.CompletionTokens != 7 {
		t.Errorf("tokens = %d/%d, want 42/7", r.PromptTokens, r.CompletionTokens)
	}
	if r.Prompt != "" {
		t.Errorf("prompt = %q, want empty (request_logs stores no prompts)", r.Prompt)
	}
	if r.TokensEstimated {
		t.Error("TokensEstimated should be false (real gateway counts)")
	}
	if stats.RealTokenCount != 1 {
		t.Errorf("RealTokenCount = %d, want 1", stats.RealTokenCount)
	}
}

func TestIngest_MalformedLinesSkipped(t *testing.T) {
	path := writeFile(t, "mixed.jsonl",
		`{"model":"gpt-4o","messages":[{"role":"user","content":"ok"}]}`+"\n"+
			`{not valid json}`+"\n"+
			`{"model":"gpt-4o","messages":[{"role":"user","content":"also ok"}]}`+"\n"+
			``+"\n"+ // blank line, ignored
			`{"model":"claude-3","messages":[{"role":"user","content":"third"}]}`+"\n")
	recs, stats := ingest(t, path, IngestOptions{Format: "openai-jsonl"})
	if len(recs) != 3 {
		t.Fatalf("got %d records, want 3 (one malformed line skipped)", len(recs))
	}
	if stats.ParseErrorCount != 1 {
		t.Errorf("ParseErrorCount = %d, want 1", stats.ParseErrorCount)
	}
	if len(stats.ParseErrorExamples) != 1 {
		t.Errorf("ParseErrorExamples = %d, want 1", len(stats.ParseErrorExamples))
	}
}

func TestIngest_ParseErrorExamplesCapped(t *testing.T) {
	// More than maxReportedParseErrors malformed lines: all counted, but only
	// the cap is reported as examples.
	content := ""
	for i := 0; i < maxReportedParseErrors+5; i++ {
		content += `{broken}` + "\n"
	}
	path := writeFile(t, "manybad.jsonl", content)
	_, stats := ingest(t, path, IngestOptions{Format: "openai-jsonl"})
	if stats.ParseErrorCount != maxReportedParseErrors+5 {
		t.Errorf("ParseErrorCount = %d, want %d", stats.ParseErrorCount, maxReportedParseErrors+5)
	}
	if len(stats.ParseErrorExamples) != maxReportedParseErrors {
		t.Errorf("ParseErrorExamples = %d, want cap %d", len(stats.ParseErrorExamples), maxReportedParseErrors)
	}
}

func TestIngest_NoPromptsDropsText(t *testing.T) {
	path := writeFile(t, "noprompt.jsonl",
		`{"model":"gpt-4o","messages":[{"role":"user","content":"SECRET-CANARY-TEXT"}]}`+"\n")
	recs, _ := ingest(t, path, IngestOptions{Format: "openai-jsonl", NoPrompts: true})
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	if contains(recs[0].Prompt, "SECRET-CANARY-TEXT") {
		t.Error("NoPrompts should drop the raw prompt text")
	}
	if recs[0].PromptTokens == 0 {
		t.Error("token count should still be populated (estimated from text before drop)")
	}
}

func TestIngest_MaxRecordsCap(t *testing.T) {
	path := writeFile(t, "big.jsonl",
		`{"model":"gpt-4o","messages":[{"role":"user","content":"a"}]}`+"\n"+
			`{"model":"gpt-4o","messages":[{"role":"user","content":"b"}]}`+"\n"+
			`{"model":"gpt-4o","messages":[{"role":"user","content":"c"}]}`+"\n")
	recs, stats := ingest(t, path, IngestOptions{Format: "openai-jsonl", MaxRecords: 2})
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2 (capped)", len(recs))
	}
	if !stats.WasTruncated {
		t.Error("WasTruncated should be true when the cap stops the run")
	}
}

func TestIngest_SymlinkReported(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.jsonl")
	if err := os.WriteFile(target, []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"x"}]}`+"\n"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	link := filepath.Join(dir, "link.jsonl")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	_, stats := ingest(t, link, IngestOptions{Format: "openai-jsonl"})
	if !stats.WasSymlink {
		t.Error("WasSymlink should be true for a symlinked input")
	}
}

func TestIngest_AutoSniffByExtension(t *testing.T) {
	// .jsonl extension → openai-jsonl even without an explicit format.
	path := writeFile(t, "auto.jsonl", `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`+"\n")
	recs, _ := ingest(t, path, IngestOptions{}) // auto
	if len(recs) != 1 || recs[0].Model != "gpt-4o" {
		t.Fatalf("auto-sniff jsonl failed: %+v", recs)
	}
	// .csv extension → csv.
	csvPath := writeFile(t, "auto.csv", "model,prompt_tokens,completion_tokens\nclaude-3,5,9\n")
	recs, _ = ingest(t, csvPath, IngestOptions{})
	if len(recs) != 1 || recs[0].Provider != "anthropic" {
		t.Fatalf("auto-sniff csv failed: %+v", recs)
	}
}

func TestIngest_AutoSniffTokenRouter(t *testing.T) {
	// tokenrouter format with no extension → sniff the first line (starts with
	// '{' → JSONL).
	path := writeFile(t, "tokenrouter", `{"model_used":"gpt-4o","tokens_in":10,"tokens_out":2,"created_at":"2026-08-01T00:00:00Z"}`+"\n")
	recs, _ := ingest(t, path, IngestOptions{Format: "tokenrouter"})
	if len(recs) != 1 || recs[0].PromptTokens != 10 {
		t.Fatalf("tokenrouter sniff failed: %+v", recs)
	}
}

func TestInferProviderTable(t *testing.T) {
	cases := map[string]string{
		"gpt-4o":                "openai",
		"gpt-3.5-turbo":         "openai",
		"o1":                    "openai",
		"o3-mini":               "openai",
		"claude-3-5-sonnet":     "anthropic",
		"gemini-1.5-pro":        "google",
		"llama-3-70b":           "openweights",
		"qwen-max":              "openweights",
		"mistral-large":         "openweights",
		"deepseek-chat":         "openweights",
		"totally-unknown-model": "",
		"":                      "",
	}
	for model, want := range cases {
		if got := InferProvider(model); got != want {
			t.Errorf("InferProvider(%q) = %q, want %q", model, got, want)
		}
	}
}

func TestEstimateTokens(t *testing.T) {
	if EstimateTokens("") != 0 {
		t.Error("empty text should estimate to 0")
	}
	// 40 chars / 4 = 10 tokens.
	if got := EstimateTokens("0123456789012345678901234567890123456789"); got != 10 {
		t.Errorf("EstimateTokens = %d, want 10", got)
	}
}

func contains(s, sub string) bool {
	return strings.Contains(s, sub)
}
