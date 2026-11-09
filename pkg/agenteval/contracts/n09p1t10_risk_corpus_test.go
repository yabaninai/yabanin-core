package contracts

// N09-P01-T10 [risk] — data-protection verification for pkg/agenteval/contracts.
// Test-only card: zero production changes.
//
//	data — validator errors name identifiers and line numbers only: journal
//	payload fields (call error messages, tool digests) never surface in
//	validation output;
//	resources — an oversized journal line fails loudly (bufio.Scanner bound),
//	it is never silently truncated;
//	integrity — a failed story validates; forging an ok out of an errored
//	call without honest uncertainty is refused; one documented observation
//	probe records the validator's scope (it does not cross-check episode
//	status against call statuses) — flagged in the card record.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// t10FailedDir builds a valid run directory whose single episode FAILED: one
// errored call (uncertain cost), a denied tool event with a reason, and a
// failed verdict. A failed run is a first-class citizen of the journal.
func t10FailedDir(t *testing.T) string {
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
		"episodes.jsonl": `{"episode_id":"ep-001","root_id":"9b6f1c2e-3a44-4f55-8a21-7c9d0e1b2a33","case_id":"t:default","arm":"g1","repetition":1,"execution_status":"failed","stop_reason":"provider_error","task_outcome":"failure","safety_outcome":"clean","protocol_outcome":"ok","usage":{"llm_calls":1,"tool_calls":1,"tokens_in":10,"tokens_out":5,"reasoning_tokens":null,"cache_read":0},"cost":{"estimated_usd":null,"observed_usd":null,"uncertain_usd":null,"coverage":0.0},"verdict_ref":"v-001"}`,
		"calls.jsonl":    `{"call_id":"call-001","episode_id":"ep-001","root_id":"r","attempt_index":1,"arm":"g1","model_requested":"gpt-4o","model_actual":null,"endpoint":"https://x.example/v1","generation_id":null,"finish_reason":"error","status":"error","usage":{"tokens_in":10,"tokens_out":5,"reasoning_tokens":null},"cost":{"estimated_usd":0.0035,"observed_usd":null,"uncertain":true},"latency":{"ttft_ms":null,"total_ms":800},"decision_header":null,"error":{"code":"timeout","message":"INTERNAL_SECRET_PAYLOAD_7f3a"}}`,
		"tools.jsonl":    `{"event_id":"tool-001","episode_id":"ep-001","call_ref":"call-001","tool":"run_shell","phase":"denied","args_digest":"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdead","receipt":null,"side_effect":"state_mutation","fault_injected":null,"actor":"agent","deny_reason":"not_in_allowlist"}`,
		"verdicts.jsonl": `{"verdict_id":"v-001","episode_id":"ep-001","task_outcome":"failure","notes":null}`,
	}
	for name, content := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600))
	}
	return dir
}

// TestN09P1T10_Risk_FailedStoryIsValid: the errored call with uncertain cost
// and the denied tool event validate cleanly — uncertainty and refusal are
// honest shapes, not defects.
func TestN09P1T10_Risk_FailedStoryIsValid(t *testing.T) {
	t.Parallel()

	require.NoError(t, Validate(t10FailedDir(t)))
}

// TestN09P1T10_Risk_ValidatorErrorsDoNotEchoPayloads: when validation fails,
// the error text carries identifiers, line numbers and enum names — never
// journal payload fields. The secret call-error message and the fake digest
// must stay out of the output even though they sit on the offending lines.
func TestN09P1T10_Risk_ValidatorErrorsDoNotEchoPayloads(t *testing.T) {
	t.Parallel()

	const (
		payloadSecret = "INTERNAL_SECRET_PAYLOAD_7f3a"
		fakeDigest    = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdead"
	)

	t.Run("duplicate call id", func(t *testing.T) {
		t.Parallel()

		dir := t10FailedDir(t)
		p := filepath.Join(dir, "calls.jsonl")
		b, err := os.ReadFile(p) //nolint:gosec // G304/G703: paths are t.TempDir() fixtures, not request input
		require.NoError(t, err)
		// A second, distinct call that duplicates call-001's id.
		dup := strings.Replace(string(b), `"call_id":"call-001"`, `"call_id":"call-002","generation_id":"x"`, 1)
		dup += "\n" + dup
		require.NoError(t, os.WriteFile(p, []byte(dup), 0o600)) //nolint:gosec // G304/G703: fixture path

		err = Validate(dir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate call_id")
		assert.Contains(t, err.Error(), "call-001", "identifiers are echoed by design")
		assert.NotContains(t, err.Error(), payloadSecret, "the payload message never surfaces")
	})

	t.Run("denied tool event without reason", func(t *testing.T) {
		t.Parallel()

		dir := t10FailedDir(t)
		p := filepath.Join(dir, "tools.jsonl")
		b, err := os.ReadFile(p) //nolint:gosec // G304/G703: fixture path
		require.NoError(t, err)
		bad := strings.Replace(string(b), `"deny_reason":"not_in_allowlist"`, `"deny_reason":null`, 1)
		require.NoError(t, os.WriteFile(p, []byte(bad), 0o600)) //nolint:gosec // G304/G703: fixture path

		err = Validate(dir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no deny_reason")
		assert.NotContains(t, err.Error(), fakeDigest, "the raw digest never surfaces")
	})

	t.Run("unknown episode reference", func(t *testing.T) {
		t.Parallel()

		dir := t10FailedDir(t)
		p := filepath.Join(dir, "calls.jsonl")
		b, err := os.ReadFile(p) //nolint:gosec // G304/G703: fixture path
		require.NoError(t, err)
		bad := strings.Replace(string(b), `"episode_id":"ep-001"`, `"episode_id":"ep-404"`, 1)
		require.NoError(t, os.WriteFile(p, []byte(bad), 0o600)) //nolint:gosec // G304/G703: fixture path

		err = Validate(dir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown episode_id")
		assert.NotContains(t, err.Error(), payloadSecret)
	})
}

// TestN09P1T10_Risk_OversizedJournalLineFailsLoudly: the bufio.Scanner bound
// is the journal's resource guard. A pathological line fails validation with
// an explicit scanner error — it is never silently truncated into a
// "valid-looking" record.
func TestN09P1T10_Risk_OversizedJournalLineFailsLoudly(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"calls.jsonl", "episodes.jsonl", "tools.jsonl"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			dir := t10FailedDir(t)
			p := filepath.Join(dir, name)
			f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // G304/G703: fixture path
			require.NoError(t, err)
			_, err = fmt.Fprintf(f, "\n%s\n", strings.Repeat("x", 200_000))
			require.NoError(t, err)
			require.NoError(t, f.Close())

			err = Validate(dir)
			require.Error(t, err, "%s: an oversized line must fail validation", name)
			assert.Contains(t, err.Error(), "token too long",
				"the scanner bound must be reported, not swallowed")
		})
	}
}

// TestN09P1T10_Risk_OkForgeFromErroredCallIsRefused: flipping the errored
// call to status ok while keeping the unknown observed cost must keep the
// honest-uncertainty invariant — observed cost absent with uncertain=false
// is refused, with line and identifier named.
func TestN09P1T10_Risk_OkForgeFromErroredCallIsRefused(t *testing.T) {
	t.Parallel()

	dir := t10FailedDir(t)
	p := filepath.Join(dir, "calls.jsonl")
	b, err := os.ReadFile(p) //nolint:gosec // G304/G703: fixture path
	require.NoError(t, err)

	// The forge: claim the call succeeded and silently swallow the unknown
	// cost (uncertain=false, observed=null). Note the digest stays on the
	// line so we can also confirm no payload echo below.
	bad := strings.Replace(string(b), `"finish_reason":"error","status":"error"`, `"finish_reason":"stop","status":"ok"`, 1)
	bad = strings.Replace(bad, `"uncertain":true`, `"uncertain":false`, 1)
	require.NoError(t, os.WriteFile(p, []byte(bad), 0o600)) //nolint:gosec // G304/G703: fixture path

	err = Validate(dir)
	require.Error(t, err, "an ok call with unknown cost and uncertain=false must be refused")
	assert.Contains(t, err.Error(), "uncertain=false")
	assert.NotContains(t, err.Error(), "INTERNAL_SECRET_PAYLOAD_7f3a")
}

// TestN09P1T10_Risk_Observation_EpisodeStatusNotCrossCheckedAgainstCalls:
// documents the validator's current scope. An episode marked "completed"
// whose every call errored is accepted today — the validator enforces
// per-record invariants and cost integrity, not cross-record status
// coherence. Recorded as a reproducible probe; flagged in the card record
// as a candidate follow-up for a prod-bearing card (a completed story over
// all-error calls most likely indicates a journaling bug, not a success).
func TestN09P1T10_Risk_Observation_EpisodeStatusNotCrossCheckedAgainstCalls(t *testing.T) {
	t.Parallel()

	dir := t10FailedDir(t)
	p := filepath.Join(dir, "episodes.jsonl")
	b, err := os.ReadFile(p) //nolint:gosec // G304/G703: fixture path
	require.NoError(t, err)
	bad := strings.Replace(string(b),
		`"execution_status":"failed","stop_reason":"provider_error","task_outcome":"failure"`,
		`"execution_status":"completed","stop_reason":"natural","task_outcome":"success"`, 1)
	require.NoError(t, os.WriteFile(p, []byte(bad), 0o600)) //nolint:gosec // G304/G703: fixture path

	assert.NoError(t, Validate(dir),
		"observation: current scope accepts status-incoherent journals")
}
