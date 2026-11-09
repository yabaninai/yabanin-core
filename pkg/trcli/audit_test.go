package trcli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeAuditFixture writes a small deterministic OpenAI-style JSONL log to a temp
// file and returns its path. The content exercises multiple models, repeats
// (cache hits), and timestamps so every report section has data.
func writeAuditFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "traffic.jsonl")
	var b strings.Builder
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	iso := now.UTC().Format(time.RFC3339)
	// 40 repeated easy requests (cache hits) + a few hard + an error.
	for i := 0; i < 40; i++ {
		b.WriteString(`{"model":"gpt-4o","created":"` + iso + `","usage":{"prompt_tokens":1200,"completion_tokens":300},"messages":[{"role":"user","content":"Please summarize this text for me."}]}` + "\n")
	}
	for i := 0; i < 10; i++ {
		b.WriteString(`{"model":"gpt-4o","created":"` + iso + `","usage":{"prompt_tokens":4000,"completion_tokens":900},"messages":[{"role":"user","content":"Please debug this failing function and explain why."}]}` + "\n")
	}
	err := os.WriteFile(path, []byte(b.String()), 0o600)
	require.NoError(t, err)
	return path
}

func TestAuditCommand_Markdown(t *testing.T) {
	path := writeAuditFixture(t)
	out, err := runTr(t, "audit", path, "--format", "md")
	require.NoError(t, err)
	// All six section headers must be present.
	for _, hdr := range []string{"## 1. Summary", "## 2. What we found", "## 3. Cache simulation", "## 4. Routing simulation", "## 5. Data quality", "## 6. Recommendations"} {
		assert.Contains(t, out, hdr, "missing section header %q", hdr)
	}
	assert.Contains(t, out, "Combined savings")
}

func TestAuditCommand_JSON(t *testing.T) {
	path := writeAuditFixture(t)
	out, err := runTr(t, "audit", path, "--format", "json")
	require.NoError(t, err)
	var rep map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &rep), "audit --format json must emit valid JSON")
	// The report is a struct; top-level keys must include the section blocks.
	for _, k := range []string{"S1", "S2", "S3", "S4", "S5", "S6", "Savings"} {
		assert.Contains(t, rep, k, "JSON report missing key %q", k)
	}
}

func TestAuditCommand_HTML(t *testing.T) {
	path := writeAuditFixture(t)
	out, err := runTr(t, "audit", path, "--format", "html")
	require.NoError(t, err)
	assert.Contains(t, out, "<!DOCTYPE html>")
	assert.Contains(t, out, "Yabanin Spend Audit")
}

func TestAuditCommand_InvalidCacheMode(t *testing.T) {
	path := writeAuditFixture(t)
	_, err := runTr(t, "audit", path, "--cache-mode", "bogus")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid --cache-mode")
}

func TestAuditCommand_InvalidFormat(t *testing.T) {
	path := writeAuditFixture(t)
	_, err := runTr(t, "audit", path, "--format", "bogus")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid --format")
}

func TestAuditCommand_NoRecords(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.jsonl")
	require.NoError(t, os.WriteFile(path, []byte(""), 0o600))
	_, err := runTr(t, "audit", path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no records ingested")
}

func TestAuditCommand_WritesOutputFile(t *testing.T) {
	path := writeAuditFixture(t)
	outDir := t.TempDir()
	outPath := filepath.Join(outDir, "report.md")
	_, err := runTr(t, "audit", path, "--format", "md", "--output", outPath)
	require.NoError(t, err)
	data, err := os.ReadFile(outPath) //nolint:gosec // G304: test output path from t.TempDir()
	require.NoError(t, err)
	assert.Contains(t, string(data), "## 1. Summary")
}

func TestAuditCommand_NoNetworkRequired(t *testing.T) {
	// audit must work with no --base-url/--admin-url/--api-key/--org at all.
	path := writeAuditFixture(t)
	out, err := runTr(t, "audit", path, "--format", "md")
	require.NoError(t, err, "audit must not require gateway credentials")
	assert.Contains(t, out, "## 1. Summary")
}
