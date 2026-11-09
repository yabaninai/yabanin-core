package contracts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEpisodeStatusTransitions(t *testing.T) {
	ok := map[EpisodeStatus][]EpisodeStatus{
		StatusNotRun:        {StatusRunning},
		StatusRunning:       {StatusCompleted, StatusFailed, StatusBlocked, StatusCanceled, StatusBudgetExhausted, StatusPartial, StatusInvalid, StatusNeedsApproval},
		StatusNeedsApproval: {StatusRunning, StatusCanceled},
	}
	for from, tos := range ok {
		for _, to := range tos {
			assert.True(t, from.CanTransitionTo(to), "%s -> %s must be allowed", from, to)
		}
	}
	deny := []struct{ from, to EpisodeStatus }{
		{StatusNotRun, StatusCompleted},
		{StatusNotRun, StatusNeedsApproval},
		{StatusNeedsApproval, StatusFailed},
		{StatusNeedsApproval, StatusCompleted},
		{StatusCompleted, StatusRunning},
		{StatusCanceled, StatusCompleted},
		{StatusFailed, StatusRunning},
		{StatusBudgetExhausted, StatusRunning},
		{StatusInvalid, StatusRunning},
		{StatusPartial, StatusCompleted},
		{StatusCompleted, StatusFailed},
	}
	for _, c := range deny {
		assert.False(t, c.from.CanTransitionTo(c.to), "%s -> %s must be forbidden", c.from, c.to)
	}
	for _, s := range []EpisodeStatus{"", "nonsense", "Completed"} {
		assert.False(t, s.Valid())
	}
}

func TestValidateTaskTag(t *testing.T) {
	assert.NoError(t, ValidateTaskTag("deploy-check"))
	assert.NoError(t, ValidateTaskTag("A.B_c:d-e"))
	assert.NoError(t, ValidateTaskTag(strings.Repeat("a", 128)))
	for _, bad := range []string{"", "spaced tag", "unicode- Patreon", strings.Repeat("a", 129), "slash/tag"} {
		assert.Error(t, ValidateTaskTag(bad), "%q must be rejected", bad)
	}
}

// validDir writes a minimal valid run directory and returns its path.
func validDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"manifest.json": `{
			"schema_version":1,
			"run_id":"9b6f1c2e-3a44-4f55-8a21-7c9d0e1b2a33",
			"created_at":"2026-09-12T00:00:00Z",
			"profile":"AGENT_SMOKE_20",
			"git_commit":"e3dd2ed",
			"dataset":{"catalog_id":"demo","selection_file":"s.json","sha256":["00"],"split":"smoke"},
			"arms":[{"id":"g1","model_slug":"gpt-4o","endpoint_url":"https://x.example/v1","provider_pinning":"openai","headers_allowed":["authorization"]}],
			"caps":{"max_llm_attempts":6,"max_tool_calls":12,"max_wall_seconds":300,"episode_cap_usd":0.25,"max_child_agents":0,"max_concurrent_llm":2},
			"price_snapshot":{"source":"console","as_of":"2026-09-08","currency":"USD","entries":[{"model":"gpt-4o","in_per_1m":2.5,"out_per_1m":10,"cache_write":1.25,"cache_read":0.625}]},
			"spend":{"authorized":false,"limit_usd":0,"approved_by":"","approved_at":null},
			"integrity":{"catalog.json":"11"}
		}`,
		"episodes.jsonl": `{"episode_id":"ep-001","root_id":"9b6f1c2e-3a44-4f55-8a21-7c9d0e1b2a33","case_id":"t:default","arm":"g1","repetition":1,"execution_status":"completed","stop_reason":"natural","task_outcome":"success","safety_outcome":"clean","protocol_outcome":"ok","usage":{"llm_calls":2,"tool_calls":1,"tokens_in":10,"tokens_out":5,"reasoning_tokens":null,"cache_read":0},"cost":{"estimated_usd":0.0105,"observed_usd":null,"uncertain_usd":null,"coverage":0.5},"verdict_ref":"v-001"}`,
		"calls.jsonl": `{"call_id":"call-001","episode_id":"ep-001","root_id":"r","attempt_index":1,"arm":"g1","model_requested":"gpt-4o","model_actual":null,"endpoint":"https://x.example/v1","generation_id":null,"finish_reason":"stop","status":"ok","usage":{"tokens_in":10,"tokens_out":5,"reasoning_tokens":null},"cost":{"estimated_usd":0.0035,"observed_usd":0.0035,"uncertain":false},"latency":{"ttft_ms":400,"total_ms":1500},"decision_header":null,"error":null}
{"call_id":"call-002","episode_id":"ep-001","root_id":"r","attempt_index":2,"arm":"g1","model_requested":"gpt-4o","model_actual":null,"endpoint":"https://x.example/v1","generation_id":null,"finish_reason":"stop","status":"ok","usage":{"tokens_in":10,"tokens_out":5,"reasoning_tokens":null},"cost":{"estimated_usd":0.007,"observed_usd":null,"uncertain":true},"latency":{"ttft_ms":400,"total_ms":1500},"decision_header":null,"error":null}`,
		"tools.jsonl":    `{"event_id":"tool-001","episode_id":"ep-001","call_ref":"call-001","tool":"read_file","phase":"executed","args_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","receipt":null,"side_effect":"none","fault_injected":false,"actor":"agent","deny_reason":null}`,
		"verdicts.jsonl": `{"verdict_id":"v-001","episode_id":"ep-001","task_outcome":"success","notes":null}`,
	}
	for name, content := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600))
	}
	return dir
}

func TestValidateHappyPathAndExampleFixtures(t *testing.T) {
	require.NoError(t, Validate(validDir(t)))
	// The committed example directory must stay valid.
	require.NoError(t, Validate(filepath.Join("..", "contracts", "example")))
}

func TestValidateNegativeCases(t *testing.T) {
	t.Run("duplicate call id", func(t *testing.T) {
		dir := validDir(t)
		p := filepath.Join(dir, "calls.jsonl")
		b, err := os.ReadFile(p) //nolint:gosec // G304/G703: paths are t.TempDir() fixtures, not request input
		require.NoError(t, err)
		dup := strings.Replace(string(b), "call-002", "call-001", 1)
		require.NoError(t, os.WriteFile(p, []byte(dup), 0o600)) //nolint:gosec // G304/G703: paths are t.TempDir() fixtures, not request input
		err = Validate(dir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate call_id")
	})
	t.Run("call references unknown episode", func(t *testing.T) {
		dir := validDir(t)
		p := filepath.Join(dir, "calls.jsonl")
		b, err := os.ReadFile(p) //nolint:gosec // G304/G703: paths are t.TempDir() fixtures, not request input
		require.NoError(t, err)
		bad := strings.Replace(string(b), `"episode_id":"ep-001"`, `"episode_id":"ep-404"`, 1)
		require.NoError(t, os.WriteFile(p, []byte(bad), 0o600)) //nolint:gosec // G304/G703: paths are t.TempDir() fixtures, not request input
		err = Validate(dir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown episode_id")
	})
	t.Run("ok call with unknown price must be uncertain, not silent", func(t *testing.T) {
		dir := validDir(t)
		p := filepath.Join(dir, "calls.jsonl")
		b, err := os.ReadFile(p) //nolint:gosec // G304/G703: paths are t.TempDir() fixtures, not request input
		require.NoError(t, err)
		bad := strings.Replace(string(b), `"observed_usd":null,"uncertain":true`, `"observed_usd":null,"uncertain":false`, 1)
		require.NoError(t, os.WriteFile(p, []byte(bad), 0o600)) //nolint:gosec // G304/G703: paths are t.TempDir() fixtures, not request input
		err = Validate(dir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "uncertain=false")
	})
	t.Run("episode cost drift above epsilon", func(t *testing.T) {
		dir := validDir(t)
		p := filepath.Join(dir, "calls.jsonl")
		b, err := os.ReadFile(p) //nolint:gosec // G304/G703: paths are t.TempDir() fixtures, not request input
		require.NoError(t, err)
		// Make both calls observed, then inflate one observed amount: the
		// episode estimate (0.0105) no longer matches Σ observed (0.5035).
		bad := strings.Replace(string(b), `"estimated_usd":0.0035,"observed_usd":0.0035`, `"estimated_usd":0.0035,"observed_usd":0.5`, 1)
		bad = strings.Replace(bad, `"observed_usd":null,"uncertain":true`, `"observed_usd":0.007,"uncertain":false`, 1)
		require.NoError(t, os.WriteFile(p, []byte(bad), 0o600)) //nolint:gosec // G304/G703: paths are t.TempDir() fixtures, not request input
		err = Validate(dir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cost drift")
	})
	t.Run("strict decode rejects unknown fields", func(t *testing.T) {
		dir := validDir(t)
		p := filepath.Join(dir, "episodes.jsonl")
		b, err := os.ReadFile(p) //nolint:gosec // G304/G703: paths are t.TempDir() fixtures, not request input
		require.NoError(t, err)
		bad := strings.Replace(string(b), `"arm":"g1"`, `"arm":"g1","args":"raw prompt"`, 1)
		require.NoError(t, os.WriteFile(p, []byte(bad), 0o600)) //nolint:gosec // G304/G703: paths are t.TempDir() fixtures, not request input
		err = Validate(dir)
		require.Error(t, err)
	})
	t.Run("denied tool event without reason", func(t *testing.T) {
		dir := validDir(t)
		p := filepath.Join(dir, "tools.jsonl")
		b, err := os.ReadFile(p) //nolint:gosec // G304/G703: paths are t.TempDir() fixtures, not request input
		require.NoError(t, err)
		bad := strings.Replace(string(b), `"phase":"executed","args_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","receipt":null,"side_effect":"none","fault_injected":false,"actor":"agent","deny_reason":null}`,
			`"phase":"denied","args_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","receipt":null,"side_effect":"state_mutation","fault_injected":null,"actor":"agent","deny_reason":null}`, 1)
		require.NoError(t, os.WriteFile(p, []byte(bad), 0o600)) //nolint:gosec // G304/G703: paths are t.TempDir() fixtures, not request input
		err = Validate(dir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no deny_reason")
	})
}

func TestSchemasValidateExample(t *testing.T) {
	cases := []struct {
		schema, doc string
	}{
		{"manifest.schema.json", "manifest.json"},
		{"episode.schema.json", "episodes.jsonl"},
		{"call.schema.json", "calls.jsonl"},
		{"tool.schema.json", "tools.jsonl"},
		{"verdict.schema.json", "verdicts.jsonl"},
	}
	for _, tc := range cases {
		t.Run(tc.schema, func(t *testing.T) {
			schemaPath := filepath.Join("..", "contracts", "schema", tc.schema)
			schemaFile, err := os.Open(schemaPath) //nolint:gosec // G304/G703: paths are t.TempDir() fixtures, not request input
			require.NoError(t, err)
			doc, err := jsonschema.UnmarshalJSON(schemaFile)
			require.NoError(t, schemaFile.Close())
			require.NoError(t, err)
			compiler := jsonschema.NewCompiler()
			require.NoError(t, compiler.AddResource(tc.schema, doc))
			sch, err := compiler.Compile(tc.schema)
			require.NoError(t, err)

			examplePath := filepath.Join("..", "contracts", "example", tc.doc)
			raw, err := os.ReadFile(examplePath) //nolint:gosec // G304/G703: paths are t.TempDir() fixtures, not request input
			require.NoError(t, err)
			docs := strings.Split(strings.TrimSpace(string(raw)), "\n")
			if tc.doc == "manifest.json" {
				docs = []string{string(raw)}
			}
			for i, line := range docs {
				var v any
				require.NoError(t, jsonUnmarshalStrict(line, &v), "line %d", i+1)
				err = sch.Validate(v)
				require.NoError(t, err, "line %d", i+1)
			}
		})
	}
}

func jsonUnmarshalStrict(data string, v any) error {
	dec := jsonNewDecoder(data)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
