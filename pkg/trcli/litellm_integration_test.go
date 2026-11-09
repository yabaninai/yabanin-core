package trcli

// Integration tests for the LiteLLM migration consumer surface
// (N16-P02-T06). The T04 lifecycle tests in litellm_migrate_test.go cover
// the command mechanics; these tests pin the packet's integration contract:
//
//	I1  the operator sees the report and the write-free preview BEFORE any
//	    apply executes — and a preview writes nothing anywhere in the
//	    working directory (whole-directory snapshot, not just catalog
//	    paths);
//	I2  every chosen configuration entity in a mixed-signal source moves
//	    into the catalog with exactly the verified semantics from the
//	    reviewed report (identity, capabilities, limits, aliases verbatim),
//	    while decision-refused, unsupported, conflicted and secret fields
//	    never appear in the catalog bytes — verified semantics or explicit
//	    refusal, never anything in between;
//	I3  the CLI consumers agree: text and JSON renderers carry the same
//	    summary/scope/findings, the on-disk report round-trips into the
//	    typed DTO the apply consumes, preview rows match applied rows, and
//	    refusal/usage errors exit 1 consistently across formats;
//	I4  the T05 negative scenarios survive integration: an unsupported-only
//	    source dry-runs honestly (never a false success), then every apply
//	    mode refuses with the same problem list and writes nothing.
//
// All fixtures are inline Go string constants written to the test's temp
// directory (no new testdata files; T04 run-3 lesson).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/clientconfig"
	"github.com/reireirei/yabanin/pkg/upstream"
)

// integrationMixedFixture is a source whose every class of signal fires at
// least once: two clean deployments (one with a full limit set, both with
// client-facing group names), a router model_group_alias, an api_key
// secret, a known-refused router feature, an unknown params field and an
// unknown router field. Note the real LiteLLM location of model_group_alias
// (nested in router_settings — a top-level model_group_alias section is
// outside the pinned import contract and is refused as a whole).
const integrationMixedFixture = `model_list:
  - model_name: "prod-gpt"
    model_info:
      mode: "chat"
      max_output_tokens: 4096
    litellm_params:
      model: "openai/gpt-4o"
      tpm: 1000
      rpm: 60
      api_key: "sk-integration-abcdef123456"
      num_retries: 3
      my_custom_flag: true
  - model_name: "fast-model"
    model_info:
      mode: "completion"
    litellm_params:
      model: "anthropic/claude-3-5-sonnet"
router_settings:
  model_group_alias:
    gpt4: "prod-gpt"
  preferred_route: "cheapest"
`

// integrationUnsupportedOnlyFixture carries nothing verified to transfer
// (T05 negative N4 at the CLI level).
const integrationUnsupportedOnlyFixture = `litellm_settings:
  acme_experimental: true
router_settings:
  custom_strategy: "latency"
`

// writeIntegrationConfig writes an inline fixture into the test temp dir.
func writeIntegrationConfig(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

// dirSnapshot returns the sorted relative file list of dir (recursive).
func dirSnapshot(t *testing.T, dir string) []string {
	t.Helper()
	var files []string
	require.NoError(t, filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			rel, relErr := filepath.Rel(dir, path)
			if relErr != nil {
				return relErr
			}
			files = append(files, rel)
		}
		return nil
	}))
	sort.Strings(files)
	return files
}

// dryRunIntegration runs the CLI dry-run into a report file and returns
// the parsed typed report (exactly what a reviewing operator hands on).
func dryRunIntegration(t *testing.T, configPath, reportPath string) clientconfig.LiteLLMMigrationReport {
	t.Helper()
	out, err := runTr(t, "migrate-litellm", "dry-run", "--config", configPath, "--out", reportPath)
	require.NoError(t, err)
	require.Contains(t, out, "dry-run: transferable=")
	data, err := os.ReadFile(reportPath) //nolint:gosec // G304: test-controlled path
	require.NoError(t, err)
	var rep clientconfig.LiteLLMMigrationReport
	require.NoError(t, json.Unmarshal(data, &rep), "the reviewed report must parse into the typed DTO")
	require.Equal(t, clientconfig.LiteLLMDryRunSchema, rep.Schema)
	return rep
}

// TestMigrateLiteLLMIntegration_ReportBeforeApply pins I1: the report file
// exists and parses before any apply is attempted; a preview-only apply
// writes nothing anywhere in the working directory; a --yes apply prints
// the preview before the result so the operator always sees what is about
// to happen.
func TestMigrateLiteLLMIntegration_ReportBeforeApply(t *testing.T) {
	dir := t.TempDir()
	configPath := writeIntegrationConfig(t, "mixed.yaml", integrationMixedFixture)
	reportPath := filepath.Join(dir, "review-me.json")
	catalogPath := filepath.Join(dir, "catalog.json")

	// 1. The report exists and is reviewable before apply is ever invoked.
	rep := dryRunIntegration(t, configPath, reportPath)
	require.Equal(t, 2, rep.Summary.PlanEntries)
	_, statErr := os.Stat(reportPath)
	require.NoError(t, statErr, "the operator must have the report file before any apply")

	// 2. Preview-only apply writes nothing anywhere in the working
	// directory — the only file the whole flow created so far is the
	// report itself.
	before := dirSnapshot(t, dir)
	out, err := runTr(t, "migrate-litellm", "apply", "--report", reportPath, "--catalog", catalogPath)
	require.NoError(t, err)
	require.Contains(t, out, "preview only — nothing was written")
	require.Equal(t, before, dirSnapshot(t, dir), "preview-only apply must not touch the working directory")

	// 3. --yes: the stdout bytes carry the preview before the result.
	out, err = runTr(t, "migrate-litellm", "apply", "--report", reportPath,
		"--catalog", catalogPath, "--yes")
	require.NoError(t, err)
	previewAt := strings.Index(out, "LiteLLM reviewed apply preview")
	resultAt := strings.Index(out, "LiteLLM reviewed apply: changed")
	require.GreaterOrEqual(t, previewAt, 0, "apply --yes must print the preview")
	require.GreaterOrEqual(t, resultAt, 0, "apply --yes must print the result")
	require.Less(t, previewAt, resultAt, "the operator sees the preview before the result")
}

// TestMigrateLiteLLMIntegration_VerifiedSemanticsIntoCatalog pins I2: the
// applied catalog carries exactly the verified entities from the reviewed
// report — rows, capabilities, limits and aliases verbatim — and none of
// the refused/unsupported/secret fields ever reaches the catalog bytes.
func TestMigrateLiteLLMIntegration_VerifiedSemanticsIntoCatalog(t *testing.T) {
	dir := t.TempDir()
	configPath := writeIntegrationConfig(t, "mixed.yaml", integrationMixedFixture)
	reportPath := filepath.Join(dir, "report.json")
	catalogPath := filepath.Join(dir, "catalog.json")

	rep := dryRunIntegration(t, configPath, reportPath)

	// The mixed source reports every signal class: 8 verified transfers
	// (2 rows, 2 capabilities, 3 limits, 1 router alias), 2 enforcement-
	// posture decisions (tpm/rpm), 4 refusals (secret, known-refused
	// router feature, 2 unknown fields), 1 redacted secret, 2 plan rows.
	require.Equal(t, clientconfig.LiteLLMSummary{
		Transferable: 8, Differences: 2, Conflicts: 0,
		Unsupported: 4, Secrets: 1, PlanEntries: 2,
	}, rep.Summary)

	// The reviewed plan is the operator's promise: identity, aliases,
	// capabilities and limits, all verified (plan aliases are sorted:
	// the router alias plus the client-facing group name).
	require.Len(t, rep.Plan, 2)
	prodGPT := rep.Plan[0]
	require.Equal(t, "catalog.upsert", prodGPT.Action)
	require.Equal(t, "openai", prodGPT.Provider)
	require.Equal(t, "gpt-4o", prodGPT.Model)
	require.Equal(t, []string{"gpt4", "prod-gpt"}, prodGPT.Aliases)
	require.Equal(t, map[string]bool{"chat": true}, prodGPT.Capabilities)
	require.NotNil(t, prodGPT.Limits)
	require.Equal(t, int64(1000), prodGPT.Limits.MaxTPM)
	require.Equal(t, int64(60), prodGPT.Limits.MaxRPM)
	require.Equal(t, int64(4096), prodGPT.Limits.MaxOutputTokens)
	fastModel := rep.Plan[1]
	require.Equal(t, "anthropic", fastModel.Provider)
	require.Equal(t, "claude-3-5-sonnet", fastModel.Model)
	require.Equal(t, []string{"fast-model"}, fastModel.Aliases)
	require.Equal(t, map[string]bool{"chat": true}, fastModel.Capabilities, "mode completion maps to the chat capability")
	require.Nil(t, fastModel.Limits)

	// Every refused/unsupported/secret location is explicit in the report
	// (all refusal-family findings carry the refused disposition; the
	// detail distinguishes matrix refusals from unknown fields).
	for _, tc := range []struct{ path, detail string }{
		{"model_list[0].litellm_params.api_key", "never imported, previewed, logged, or reported"},
		{"model_list[0].litellm_params.num_retries", "retry/circuit behavior is owned by the Yabanin gateway"},
		{"model_list[0].litellm_params.my_custom_flag", "not in the pinned compatibility matrix"},
		{"$.router_settings.preferred_route", "not in the pinned compatibility matrix"},
	} {
		f := findIntegrationFinding(t, rep.Unsupported, tc.path, clientconfig.LiteLLMRefused)
		require.NotNil(t, f, "%s must be reported as refused", tc.path)
		require.Contains(t, f.Detail, tc.detail, "%s refusal must explain the cause", tc.path)
	}

	// The refusals cover the plan boundary: the api_key refusal names the
	// credentials contract, the router-feature refusal names the gateway
	// owner, the unknown fields name the pinned matrix.

	// Apply the reviewed report.
	out, err := runTr(t, "migrate-litellm", "apply", "--report", reportPath,
		"--catalog", catalogPath, "--yes")
	require.NoError(t, err)
	require.Contains(t, out, "LiteLLM reviewed apply: changed")

	// The catalog document carries exactly the promised entities.
	catalogData, err := os.ReadFile(catalogPath) //nolint:gosec // G304: test-controlled path
	require.NoError(t, err)
	var catalog upstream.CatalogDocument
	require.NoError(t, json.Unmarshal(catalogData, &catalog))
	require.Len(t, catalog.Models, 2)
	require.Equal(t, prodGPT.Provider, catalog.Models[0].Provider)
	require.Equal(t, prodGPT.Model, catalog.Models[0].Model)
	require.Equal(t, prodGPT.Aliases, catalog.Models[0].Aliases)
	require.Equal(t, prodGPT.Capabilities, catalog.Models[0].Capabilities)
	require.NotNil(t, catalog.Models[0].Limits)
	require.Equal(t, prodGPT.Limits.MaxTPM, catalog.Models[0].Limits.MaxTPM)
	require.Equal(t, prodGPT.Limits.MaxRPM, catalog.Models[0].Limits.MaxRPM)
	require.Equal(t, prodGPT.Limits.MaxOutputTokens, catalog.Models[0].Limits.MaxOutputTokens)
	require.Equal(t, fastModel.Provider, catalog.Models[1].Provider)
	require.Equal(t, fastModel.Model, catalog.Models[1].Model)
	require.Equal(t, fastModel.Aliases, catalog.Models[1].Aliases)
	require.Equal(t, fastModel.Capabilities, catalog.Models[1].Capabilities)
	require.Nil(t, catalog.Models[1].Limits)

	// The refused, unsupported and secret source fields never appear in
	// the catalog bytes — neither as keys nor values.
	catalogText := string(catalogData)
	for _, forbidden := range []string{
		"num_retries", "my_custom_flag", "preferred_route", "api_key",
		"sk-integration-abcdef123456",
	} {
		require.NotContains(t, catalogText, forbidden,
			"a refused/unsupported/secret source field leaked into the catalog")
	}
}

// findIntegrationFinding returns the finding with the given path and
// disposition, or nil.
func findIntegrationFinding(t *testing.T, findings []clientconfig.LiteLLMFinding, path, disposition string) *clientconfig.LiteLLMFinding {
	t.Helper()
	for i := range findings {
		if findings[i].Path == path && findings[i].Disposition == disposition {
			return &findings[i]
		}
	}
	return nil
}

// TestMigrateLiteLLMIntegration_ConsumersAgree pins I3: the text and JSON
// dry-run renderers agree on summary, scope and finding paths; the on-disk
// JSON report round-trips into the typed DTO deep-equal; the JSON apply
// preview rows match the text preview rows and the applied result; and
// refusal/usage errors exit 1 consistently across both formats.
func TestMigrateLiteLLMIntegration_ConsumersAgree(t *testing.T) {
	dir := t.TempDir()
	configPath := writeIntegrationConfig(t, "mixed.yaml", integrationMixedFixture)
	catalogPath := filepath.Join(dir, "catalog.json")

	// Text and JSON dry-runs from the same config must agree on the
	// observable contract surface.
	textOut, err := runTr(t, "migrate-litellm", "dry-run", "--config", configPath, "--format", "text")
	require.NoError(t, err)
	for _, fragment := range []string{
		"transferable (8)", "semantic differences (2)", "unsupported (4)",
		"secrets redacted (1 paths", "plan preview (2 catalog rows",
		"NOT migrated: user accounts",
		"NOT migrated: request logs", "NOT migrated: spend tracking",
		"model_list[0].litellm_params.api_key",
		"$.router_settings.preferred_route",
	} {
		require.Contains(t, textOut, fragment, "text renderer must carry %q", fragment)
	}
	// JSON dry-run (via --out so the stderr stats line never mixes into
	// the document) must carry the same summary, scope and findings.
	jsonReportPath := filepath.Join(dir, "report-json.json")
	_, err = runTr(t, "migrate-litellm", "dry-run", "--config", configPath,
		"--format", "json", "--out", jsonReportPath)
	require.NoError(t, err)
	jsonOut, err := os.ReadFile(jsonReportPath) //nolint:gosec // G304: test-controlled path
	require.NoError(t, err)
	var jsonReport clientconfig.LiteLLMMigrationReport
	require.NoError(t, json.Unmarshal(jsonOut, &jsonReport))
	require.Equal(t, 8, jsonReport.Summary.Transferable)
	require.Equal(t, 2, jsonReport.Summary.Differences)
	require.Equal(t, 4, jsonReport.Summary.Unsupported)
	require.Equal(t, 1, jsonReport.Summary.Secrets)
	require.Len(t, jsonReport.Scope.NotMigrated, 6)
	// Same finding paths in both renderers.
	var textPaths, jsonPaths []string
	for _, f := range jsonReport.Unsupported {
		jsonPaths = append(jsonPaths, f.Path)
	}
	for _, fragment := range []string{
		"model_list[0].litellm_params.api_key",
		"model_list[0].litellm_params.num_retries",
		"model_list[0].litellm_params.my_custom_flag",
		"$.router_settings.preferred_route",
	} {
		require.Contains(t, textOut, fragment)
		require.True(t, containsString(jsonPaths, fragment), "json renderer must carry %q", fragment)
		textPaths = append(textPaths, fragment)
	}
	require.Equal(t, textPaths, jsonPaths)

	// The on-disk report (what the operator reviews and hands on) parses
	// into the typed DTO deep-equal to the stdout JSON — dry-run and apply
	// consumers see the same report.
	reportPath := filepath.Join(dir, "report.json")
	onDisk := dryRunIntegration(t, configPath, reportPath)
	require.True(t, reflect.DeepEqual(onDisk, jsonReport),
		"on-disk report must round-trip into the same DTO the stdout carried")

	// JSON apply: preview + result documents, both parse; the result's
	// applied rows carry the planned identity, aliases and limits.
	applyOut, err := runTr(t, "migrate-litellm", "apply", "--report", reportPath,
		"--catalog", catalogPath, "--yes", "--format", "json")
	require.NoError(t, err)
	decoder := json.NewDecoder(strings.NewReader(applyOut))
	var previewDoc clientconfig.LiteLLMApplyPreview
	require.NoError(t, decoder.Decode(&previewDoc), "preview JSON must parse")
	var resultDoc clientconfig.LiteLLMApplyResult
	require.NoError(t, decoder.Decode(&resultDoc), "result JSON must parse")
	require.Len(t, previewDoc.Entries, 2)
	require.Len(t, resultDoc.Applied, 2)
	for i, entry := range previewDoc.Entries {
		require.Equal(t, jsonReport.Plan[i].Provider, entry.Provider)
		require.Equal(t, jsonReport.Plan[i].Model, entry.Model)
		require.Equal(t, jsonReport.Plan[i].Aliases, entry.Aliases)
	}
	for i, applied := range resultDoc.Applied {
		require.Equal(t, previewDoc.Entries[i].Provider, applied.Provider)
		require.Equal(t, previewDoc.Entries[i].Model, applied.Model)
	}
	require.Equal(t, 1, resultDoc.SecretsRedacted)

	// Refusal consistency: the same poisoned plan fails both formats with
	// exit 1 and the same problem list; usage errors exit 1 too.
	poisonedPath := filepath.Join(dir, "poisoned.json")
	raw, err := os.ReadFile(reportPath) //nolint:gosec // G304: test-controlled path
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(raw, &doc))
	plan, ok := doc["plan"].([]any)
	require.True(t, ok)
	firstRow, ok := plan[0].(map[string]any)
	require.True(t, ok)
	firstRow["source_paths"] = []any{"model_list[9]"}
	poisoned, err := json.Marshal(doc)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(poisonedPath, poisoned, 0o600))
	for _, format := range []string{"text", "json"} {
		_, err = runTr(t, "migrate-litellm", "apply", "--report", poisonedPath,
			"--catalog", catalogPath, "--yes", "--format", format)
		require.Error(t, err, "format %s: a plan citing a non-transfer source must refuse", format)
		require.Contains(t, err.Error(), "refused; nothing was written")
		require.Contains(t, err.Error(), "model_list[9]")
	}
	_, err = runTr(t, "migrate-litellm", "apply", "--report", poisonedPath, "--catalog", catalogPath)
	require.Error(t, err, "preview mode must refuse the same report")
	require.Contains(t, err.Error(), "refused; nothing was written")
	_, err = runTr(t, "migrate-litellm", "apply", "--report", filepath.Join(dir, "absent.json"),
		"--catalog", catalogPath)
	require.Error(t, err, "missing --report is a usage error")
	require.Contains(t, err.Error(), "read --report")
}

// TestMigrateLiteLLMIntegration_UnsupportedOnlyNeverFalseSuccess pins I4:
// the T05 negative scenario survives integration — the dry-run reports the
// unsupported settings honestly (never a false success), then both apply
// modes refuse with the same problem list and nothing is written.
func TestMigrateLiteLLMIntegration_UnsupportedOnlyNeverFalseSuccess(t *testing.T) {
	dir := t.TempDir()
	configPath := writeIntegrationConfig(t, "unsupported-only.yaml", integrationUnsupportedOnlyFixture)
	reportPath := filepath.Join(dir, "report.json")
	catalogPath := filepath.Join(dir, "catalog.json")

	// The dry-run is honest: status includes the unsupported findings and
	// the empty plan, but the command still succeeds (it produced a
	// report, which is its job).
	out, err := runTr(t, "migrate-litellm", "dry-run", "--config", configPath, "--out", reportPath)
	require.NoError(t, err)
	require.Contains(t, out, "transferable=0")
	require.Contains(t, out, "unsupported=2")
	require.Contains(t, out, "plan_entries=0")

	// Preview and execute both refuse before writing anything.
	before := dirSnapshot(t, dir)
	_, err = runTr(t, "migrate-litellm", "apply", "--report", reportPath, "--catalog", catalogPath)
	require.Error(t, err)
	require.Contains(t, err.Error(), "refused; nothing was written")
	require.Contains(t, err.Error(), "report carries no plan entries")
	_, err = runTr(t, "migrate-litellm", "apply", "--report", reportPath,
		"--catalog", catalogPath, "--yes")
	require.Error(t, err)
	require.Contains(t, err.Error(), "refused; nothing was written")
	require.Contains(t, err.Error(), "report carries no plan entries")
	require.Equal(t, before, dirSnapshot(t, dir), "refused applies must not touch the working directory")

	// The text renderer exposes the non-goals next to the refusals, so the
	// operator reading the report sees both the problem and the scope.
	textOut, err := runTr(t, "migrate-litellm", "dry-run", "--config", configPath, "--format", "text")
	require.NoError(t, err)
	assert.Contains(t, textOut, "unsupported (2):")
	assert.Contains(t, textOut, "NOT migrated: user accounts")
}

// containsString reports whether the slice contains s.
func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
