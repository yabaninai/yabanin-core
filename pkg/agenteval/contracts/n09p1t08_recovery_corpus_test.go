package contracts

// N09-P01-T08 recovery corpus — the agent-eval journal contract
// (pkg/agenteval/contracts).
//
// The schema rules, the episode state machine, duplicate detection and the
// happy path are pinned by contracts_test.go and validate_test.go; the T07
// boundary corpus pinned the unknown-cost discipline (uncertain failed
// episodes validate; unknown is never journaled as exact zero or success).
// This corpus adds the recovery dimension those leave open: what an
// interrupted WRITE leaves behind, and what a restart reads back.
//
// Two properties are pinned here:
//  1. A torn trailing line — the crash artifact of a writer killed
//     mid-flush — is rejected loudly, naming the affected file and line:
//     JSONL has no forgiveness for a partial record, and the journal never
//     validates by silently dropping what it could not decode.
//  2. The failed-vs-certain split survives a restart: a journal holding a
//     certain observed cost, an uncertain null cost and a failed episode
//     re-decodes from disk bytes with every distinction intact — null stays
//     null (uncertainty is never normalized into zero), the failed episode
//     stays failed (and terminal in the reloaded state machine) — and the
//     reloaded directory validates again.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// appendLine appends one JSONL line to a run-directory file, repairing a
// missing trailing newline first (the writer's own duty: a file whose last
// flush was interrupted would otherwise swallow the appended record into the
// torn line).
func appendLine(t *testing.T, path, line string) {
	t.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // G304/G703: paths are t.TempDir() fixtures, not request input
	require.NoError(t, err)
	content := string(raw)
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	content += line + "\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600)) //nolint:gosec // G304/G703: paths are t.TempDir() fixtures, not request input
}

// TestN09P1T08_Recovery_TornTrailingLineFromInterruptedWriteIsRejected
// simulates a writer killed mid-flush: the final record is cut in half.
// Validate must fail loudly and name the affected file — the crash artifact
// is never waved through.
func TestN09P1T08_Recovery_TornTrailingLineFromInterruptedWriteIsRejected(t *testing.T) {
	tornByFile := map[string]struct {
		torn     string
		wantLine string // 1-based line the torn record lands on
	}{
		"calls.jsonl":    {`{"call_id":"call-003","episode_id":"ep-001","cost":{"estimated_usd":0.0`, "line 3"},
		"episodes.jsonl": {`{"episode_id":"ep-002","root_id":"9b6f1c2e-3a44-4f55-8a21-7c9d0e1b2a33","execution_status":"run`, "line 2"},
		"tools.jsonl":    {`{"event_id":"tool-002","episode_id":"ep-001","args_digest":"bbbb`, "line 2"},
	}
	for file, tt := range tornByFile {
		t.Run(file, func(t *testing.T) {
			dir := validDir(t)
			path := filepath.Join(dir, file)
			raw, err := os.ReadFile(path) //nolint:gosec // G304/G703: paths are t.TempDir() fixtures, not request input
			require.NoError(t, err)
			// The torn line arrives after the intact records, newline-terminated
			// or not — both are the same interrupted flush.
			content := string(raw)
			if !strings.HasSuffix(content, "\n") {
				content += "\n"
			}
			content += tt.torn
			require.NoError(t, os.WriteFile(path, []byte(content), 0o600)) //nolint:gosec // G304/G703: paths are t.TempDir() fixtures, not request input

			err = Validate(dir)
			require.Error(t, err, "a torn trailing line is a crash artifact, not a journal")
			assert.Contains(t, err.Error(), file,
				"the error names the affected file: %v", err)
			assert.Contains(t, err.Error(), tt.wantLine,
				"the error locates the torn record: %v", err)
		})
	}
}

// TestN09P1T08_Recovery_FailedVsCertainSplitSurvivesReload appends a failed
// sibling episode (with its uncertain errored call) to the valid journal,
// then restarts: the journal is re-decoded from the disk bytes and every
// distinction of the split must survive — observed vs null, certain vs
// uncertain, completed vs failed — and the reloaded directory validates
// again.
func TestN09P1T08_Recovery_FailedVsCertainSplitSurvivesReload(t *testing.T) {
	dir := validDir(t)

	// The failed sibling: same root, terminal status, estimated cost nil
	// (unknown — never zero), one errored uncertain call.
	appendLine(t, filepath.Join(dir, "episodes.jsonl"),
		`{"episode_id":"ep-002","root_id":"9b6f1c2e-3a44-4f55-8a21-7c9d0e1b2a33","case_id":"t:default","arm":"g1","repetition":1,"execution_status":"failed","stop_reason":"upstream_error","task_outcome":null,"safety_outcome":"clean","protocol_outcome":"ok","usage":{"llm_calls":1,"tool_calls":0,"tokens_in":null,"tokens_out":null,"reasoning_tokens":null,"cache_read":null},"cost":{"estimated_usd":null,"observed_usd":null,"uncertain_usd":null,"coverage":0},"verdict_ref":null}`)
	appendLine(t, filepath.Join(dir, "calls.jsonl"),
		`{"call_id":"call-003","episode_id":"ep-002","root_id":"r","attempt_index":1,"arm":"g1","model_requested":"gpt-4o","model_actual":null,"endpoint":"https://x.example/v1","generation_id":null,"finish_reason":null,"status":"error","usage":{"tokens_in":10,"tokens_out":null,"reasoning_tokens":null},"cost":{"estimated_usd":0.0035,"observed_usd":null,"uncertain":true},"latency":{"ttft_ms":null,"total_ms":4200},"decision_header":null,"error":{"code":"upstream_timeout","message":"no first byte"}}`)

	// Pre-restart: the incident journal validates as a whole.
	require.NoError(t, Validate(dir))

	// RESTART: re-decode from the disk bytes the way a fresh process does.
	calls, err := loadJSONL[CallRecord](filepath.Join(dir, "calls.jsonl"))
	require.NoError(t, err)
	require.Len(t, calls, 3)

	// The certain call keeps its observed cost.
	certain := calls[0].Rec
	require.NotNil(t, certain.Cost.ObservedUSD)
	assert.False(t, certain.Cost.Uncertain)
	assert.InDelta(t, 0.0035, *certain.Cost.ObservedUSD, 1e-12)

	// The uncertain call keeps unknown as null — never normalized to zero.
	uncertain := calls[1].Rec
	assert.Nil(t, uncertain.Cost.ObservedUSD,
		"uncertainty is unknown, not zero — the reload keeps the nil")
	assert.True(t, uncertain.Cost.Uncertain)
	rawDisk, err := os.ReadFile(filepath.Join(dir, "calls.jsonl")) //nolint:gosec // G304/G703: paths are t.TempDir() fixtures, not request input
	require.NoError(t, err)
	assert.Contains(t, string(rawDisk), `"observed_usd":null`,
		"uncertainty is persisted as null on disk, never rewritten to 0")

	// The failed episode's call keeps its error identity and its uncertainty.
	errored := calls[2].Rec
	assert.Equal(t, "error", errored.Status)
	assert.True(t, errored.Cost.Uncertain)
	assert.Nil(t, errored.Cost.ObservedUSD)
	require.NotNil(t, errored.Error)
	assert.Equal(t, "upstream_timeout", errored.Error.Code)

	episodes, err := loadJSONL[EpisodeRecord](filepath.Join(dir, "episodes.jsonl"))
	require.NoError(t, err)
	require.Len(t, episodes, 2)
	assert.Equal(t, StatusCompleted, episodes[0].Rec.ExecutionStatus)
	assert.Equal(t, StatusFailed, episodes[1].Rec.ExecutionStatus)
	assert.Equal(t, episodes[0].Rec.RootID, episodes[1].Rec.RootID,
		"both episodes join on the one root id across the reload")

	// The reloaded failed episode is terminal in the state machine — a
	// restart never resurrects it into completion.
	assert.False(t, StatusFailed.CanTransitionTo(StatusCompleted))

	// The reloaded directory validates again — the journal is restart-safe.
	require.NoError(t, Validate(dir))
}
