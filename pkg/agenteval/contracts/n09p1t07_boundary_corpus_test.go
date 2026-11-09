package contracts

// N09-P01-T07 boundary regression corpus — the journal contract seam
// (pkg/agenteval/contracts).
//
// The validator's unit guarantees are pinned by contracts_test.go (status
// transitions, task tags, duplicate call ids, sum checks, the ok-only
// invariant). This corpus adds the no-repeat-stack regression dimension:
// what the seam demands from a journal that records a FAILED episode whose
// attempts include an uncertain outcome — the exact shape the T06 journal
// consumer produces for a suppressed or exhausted chain — and the precise
// reach of the ok-only uncertain invariant.
//
// Two properties are pinned here:
//  1. A failed-and-uncertain story validates. A chain that ended in a
//     refusal or exhaustion journals execution_status "failed" plus an
//     error-status call with observed=null and uncertain=true; that must
//     remain a contract-valid episode, or the no-repeat stack could not
//     journal honestly at all.
//  2. The uncertain flag is mandatory only for "ok" calls. An "error"
//     call with uncertain=false is honest (the exchange is known to have
//     failed; there is no silent success to hide) — the ok-only invariant
//     must not creep onto error records.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rewrite applies replacements to one fixture file in dir.
func n09p1t07Rewrite(t *testing.T, dir, name string, replacements ...string) {
	t.Helper()
	p := filepath.Join(dir, name)
	b, err := os.ReadFile(p) //nolint:gosec // G304/G703: paths are t.TempDir() fixtures, not request input
	require.NoError(t, err)
	s := string(b)
	for i := 0; i+1 < len(replacements); i += 2 {
		require.Contains(t, s, replacements[i],
			"fixture %s must contain the targeted substring", name)
		s = strings.Replace(s, replacements[i], replacements[i+1], 1)
	}
	require.NoError(t, os.WriteFile(p, []byte(s), 0o600)) //nolint:gosec // G304/G703: paths are t.TempDir() fixtures, not request input
}

// TestN09P1T07_Boundary_FailedEpisodeJournalRemainsContractValid turns the
// happy fixture into the no-repeat stack's failure story: the episode ends
// "failed" and an error-status call arrives with observed=null and
// uncertain=true. The contract must accept it — a refusal or exhaustion
// must be journalable without claiming false success or false exactness.
func TestN09P1T07_Boundary_FailedEpisodeJournalRemainsContractValid(t *testing.T) {
	dir := validDir(t)
	n09p1t07Rewrite(t, dir, "episodes.jsonl",
		`"execution_status":"completed"`, `"execution_status":"failed"`,
	)
	// The fixture's calls.jsonl has no trailing newline; add one.
	p := filepath.Join(dir, "calls.jsonl")
	b, err := os.ReadFile(p) //nolint:gosec // G304/G703: paths are t.TempDir() fixtures, not request input
	require.NoError(t, err)
	failedCall := "\n" + `{"call_id":"call-003","episode_id":"ep-001","root_id":"r","attempt_index":3,"arm":"g1","model_requested":"gpt-4o","model_actual":null,"endpoint":"https://x.example/v1","generation_id":null,"finish_reason":null,"status":"error","usage":{"tokens_in":null,"tokens_out":null,"reasoning_tokens":null},"cost":{"estimated_usd":null,"observed_usd":null,"uncertain":true},"latency":{"ttft_ms":null,"total_ms":250},"decision_header":null,"error":{"code":"repeat_suppressed_unknown","message":"first byte deadline exceeded"}}` + "\n"
	require.NoError(t, os.WriteFile(p, append(b, []byte(failedCall)...), 0o600)) //nolint:gosec // G304/G703: paths are t.TempDir() fixtures, not request input

	err = Validate(dir)
	require.NoError(t, err,
		"a failed episode with an uncertain error call must stay contract-valid")
}

// TestN09P1T07_Boundary_UncertainFlagMandatoryOnlyForOkCalls pins the exact
// reach of the ok-only invariant: flipping call-002 from an "ok" record to
// an "error" record licenses uncertain=false — the error is itself the
// honest answer, and demanding the uncertain flag there would over-extend
// the invariant.
func TestN09P1T07_Boundary_UncertainFlagMandatoryOnlyForOkCalls(t *testing.T) {
	dir := validDir(t)
	n09p1t07Rewrite(t, dir, "calls.jsonl",
		`"status":"ok","usage":{"tokens_in":10,"tokens_out":5,"reasoning_tokens":null},"cost":{"estimated_usd":0.007,"observed_usd":null,"uncertain":true}`,
		`"status":"error","usage":{"tokens_in":10,"tokens_out":5,"reasoning_tokens":null},"cost":{"estimated_usd":0.007,"observed_usd":null,"uncertain":false}`,
	)

	err := Validate(dir)
	assert.NoError(t, err,
		"an error call with uncertain=false is honest — the invariant must stay ok-only")
}
