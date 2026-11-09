package trcli

// End-to-end tests for the migrate-litellm command family: dry-run →
// preview-only apply → apply --yes → idempotent re-apply → rollback →
// rollback refusal, plus gate refusals, default ledger derivation and the
// secret-never-leak guarantee over CLI output.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const litellmFixtureDir = "../clientconfig/testdata/litellm"

// copyLiteLLMFixture copies a fixture into a fresh working directory so the
// CLI runs against writable operator-style paths.
func copyLiteLLMFixture(t *testing.T, fixture string) (dir, configPath string) {
	t.Helper()
	dir = t.TempDir()
	data, err := os.ReadFile(filepath.Join(litellmFixtureDir, fixture)) //nolint:gosec // G304: testdata fixture from a fixed allowlist, not user input
	require.NoError(t, err)
	configPath = filepath.Join(dir, fixture)
	require.NoError(t, os.WriteFile(configPath, data, 0o600)) //nolint:gosec // G703: testdata fixture from a fixed allowlist joined onto t.TempDir, not user input
	return dir, configPath
}

func TestMigrateLiteLLM_EndToEndLifecycle(t *testing.T) {
	dir, configPath := copyLiteLLMFixture(t, "full.yaml")
	reportPath := filepath.Join(dir, "report.json")
	catalogPath := filepath.Join(dir, "catalog.json")

	// Dry-run: report to file, stats line on stderr, JSON parses.
	out, err := runTr(t, "migrate-litellm", "dry-run", "--config", configPath, "--out", reportPath)
	require.NoError(t, err)
	assert.Contains(t, out, "dry-run: transferable=")
	assert.Contains(t, out, "plan_entries=3")
	reportData, err := os.ReadFile(reportPath) //nolint:gosec // G304: test-controlled path
	require.NoError(t, err)
	var report map[string]any
	require.NoError(t, json.Unmarshal(reportData, &report))

	// Preview-only apply: writes nothing, no backups.
	out, err = runTr(t, "migrate-litellm", "apply", "--report", reportPath, "--catalog", catalogPath)
	require.NoError(t, err)
	assert.Contains(t, out, "LiteLLM reviewed apply preview")
	assert.Contains(t, out, "preview only — nothing was written")
	assert.Contains(t, out, "openai/gpt-4o")
	_, err = os.Stat(catalogPath)
	assert.True(t, os.IsNotExist(err), "preview-only apply must not create the catalog")
	_, err = os.Stat(catalogPath + ".litellm-backup")
	assert.True(t, os.IsNotExist(err), "preview-only apply must not create backups")

	// Apply --yes: preview then result, catalog and ledger in place.
	out, err = runTr(t, "migrate-litellm", "apply", "--report", reportPath,
		"--catalog", catalogPath, "--yes")
	require.NoError(t, err)
	assert.Contains(t, out, "LiteLLM reviewed apply preview")
	assert.Contains(t, out, "LiteLLM reviewed apply: changed")
	_, err = os.Stat(catalogPath)
	require.NoError(t, err)
	defaultLedger := strings.TrimSuffix(catalogPath, ".json") + ".litellm-apply-ledger.json"
	_, err = os.Stat(defaultLedger)
	require.NoError(t, err, "apply must derive the default ledger path")

	// Idempotent re-apply --yes: no-op.
	out, err = runTr(t, "migrate-litellm", "apply", "--report", reportPath,
		"--catalog", catalogPath, "--yes")
	require.NoError(t, err)
	assert.Contains(t, out, "no-op (already applied)")

	// Rollback: pre-apply state (both files absent) restored, backups gone.
	out, err = runTr(t, "migrate-litellm", "rollback", "--catalog", catalogPath)
	require.NoError(t, err)
	assert.Contains(t, out, "LiteLLM apply rollback complete")
	assert.Contains(t, out, "removed (pre-apply state: absent)")
	_, err = os.Stat(catalogPath)
	assert.True(t, os.IsNotExist(err))
	_, err = os.Stat(catalogPath + ".litellm-backup")
	assert.True(t, os.IsNotExist(err))

	// Rollback without backups refuses.
	_, err = runTr(t, "migrate-litellm", "rollback", "--catalog", catalogPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no apply backup found")
}

func TestMigrateLiteLLM_ApplyJSONFormat(t *testing.T) {
	dir, configPath := copyLiteLLMFixture(t, "minimal.yaml")
	reportPath := filepath.Join(dir, "report.json")
	catalogPath := filepath.Join(dir, "catalog.json")

	_, err := runTr(t, "migrate-litellm", "dry-run", "--config", configPath, "--out", reportPath)
	require.NoError(t, err)
	out, err := runTr(t, "migrate-litellm", "apply", "--report", reportPath,
		"--catalog", catalogPath, "--yes", "--format", "json")
	require.NoError(t, err)
	// Output is two JSON documents (preview, result); both must parse. The
	// first apply on an absent catalog reports changed=true.
	decoder := json.NewDecoder(strings.NewReader(out))
	var doc map[string]any
	require.NoError(t, decoder.Decode(&doc), "preview JSON must parse")
	require.NoError(t, decoder.Decode(&doc), "result JSON must parse")
	assert.Equal(t, true, doc["changed"])
}

func TestMigrateLiteLLM_ApplyRefusalNothingWritten(t *testing.T) {
	dir, _ := copyLiteLLMFixture(t, "wildcard.yaml")
	reportPath := filepath.Join(dir, "report.json")
	catalogPath := filepath.Join(dir, "catalog.json")
	_, err := runTr(t, "migrate-litellm", "dry-run", "--config", filepath.Join(litellmFixtureDir, "wildcard.yaml"),
		"--out", reportPath)
	require.NoError(t, err)

	_, err = runTr(t, "migrate-litellm", "apply", "--report", reportPath,
		"--catalog", catalogPath, "--yes")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refused; nothing was written")
	assert.Contains(t, err.Error(), "no plan entries")
	_, err = os.Stat(catalogPath)
	assert.True(t, os.IsNotExist(err))
}

func TestMigrateLiteLLM_TamperedReportRefused(t *testing.T) {
	dir, _ := copyLiteLLMFixture(t, "full.yaml")
	reportPath := filepath.Join(dir, "report.json")
	catalogPath := filepath.Join(dir, "catalog.json")
	_, err := runTr(t, "migrate-litellm", "dry-run", "--config", filepath.Join(litellmFixtureDir, "full.yaml"),
		"--out", reportPath)
	require.NoError(t, err)

	raw, err := os.ReadFile(reportPath) //nolint:gosec // G304: test-controlled path
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(raw, &doc))
	doc["schema"] = 99
	tampered, err := json.Marshal(doc)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(reportPath, tampered, 0o600))

	_, err = runTr(t, "migrate-litellm", "apply", "--report", reportPath,
		"--catalog", catalogPath, "--yes")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported report schema")
	assert.Contains(t, err.Error(), "nothing was written")
}

func TestMigrateLiteLLM_ApplyNeverLeaksSecrets(t *testing.T) {
	dir, configPath := copyLiteLLMFixture(t, "full.yaml")
	reportPath := filepath.Join(dir, "report.json")
	catalogPath := filepath.Join(dir, "catalog.json")
	_, err := runTr(t, "migrate-litellm", "dry-run", "--config", configPath, "--out", reportPath)
	require.NoError(t, err)

	out, err := runTr(t, "migrate-litellm", "apply", "--report", reportPath,
		"--catalog", catalogPath, "--yes")
	require.NoError(t, err)
	for _, secret := range []string{
		"sk-1234abcdef123456", "hunter2", "os.environ/OPENAI_API_KEY",
		"T000/B000", "cache.internal", "OPENAI_API_KEY",
	} {
		assert.NotContains(t, out, secret)
	}
}

func TestMigrateLiteLLM_DryRunTextFormat(t *testing.T) {
	_, configPath := copyLiteLLMFixture(t, "minimal.yaml")
	out, err := runTr(t, "migrate-litellm", "dry-run", "--config", configPath, "--format", "text")
	require.NoError(t, err)
	assert.Contains(t, out, "LiteLLM migration dry-run report")
	assert.Contains(t, out, "DRY RUN ONLY")
	assert.Contains(t, out, "plan entries")
}
