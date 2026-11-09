package cli

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/budget"
)

// ADL-01: CI task tag (YABANIN_TASK). The gateway applies the deployment-level
// task tag to requests that carry no X-Yabanin-Task header of their own, so an
// agent running inside CI attributes all of its model calls to the current
// task without per-request headers. The per-request header always wins.
//
// The effective task id flows into:
//   - the analytics event's TaskID (chat.go), which loggerd persists into
//     request_logs.task_id — what the dashboard Tasks screen and
//     GET /api/analytics/tasks group by;
//   - the token-budget scope (chat.go, both surfaces) — the same value the
//     per-task budget is charged against.
//
// The token-budget scope is directly observable in a gateway test (no Redis
// needed), so that is what these assertions pin.

// newTaskTagGateway builds a passthrough gateway with a capture-free budget so
// the effective task id (the one charged) is observable after a request.
func newTaskTagGateway(t *testing.T, upstreamURL string, taskTag string) *gateway {
	t.Helper()
	gw := decisionTestGateway(upstreamURL)
	gw.tokenBudget = NewTokenBudget(1_000_000, 1_000_000, 24*time.Hour)
	gw.taskTag = taskTag
	return gw
}

// --- YABANIN_TASK fallback behavior -----------------------------------------

func TestChatCompletions_TaskTagAppliedToTokenBudget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"c","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"}}]}`))
	}))
	defer srv.Close()

	gw := newTaskTagGateway(t, srv.URL, "a142-add-login")

	// Exhaust the task budget for the fallback tag. A request that does NOT
	// carry its own X-Yabanin-Task header must be attributed to the fallback
	// tag — and therefore blocked once that tag's budget is exhausted.
	gw.tokenBudget.Record(TaskBudgetScope, "", "a142-add-login", 1_000_000)

	rec := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions",
		bytes.NewReader([]byte(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`)))
	r.Header.Set("Content-Type", "application/json")
	gw.chatCompletions(rec, r)

	require.Equal(t, http.StatusTooManyRequests, rec.Code,
		"no X-Yabanin-Task header + exhausted YABANIN_TASK budget → 429 (tag was applied): %s", rec.Body.String())
	assert.Contains(t, rec.Body.String(), "token_budget_exceeded")
}

func TestChatCompletions_TaskTagHeaderWinsOverFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"c","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"}}]}`))
	}))
	defer srv.Close()

	gw := newTaskTagGateway(t, srv.URL, "a142-add-login")

	// Exhaust ONLY the fallback tag's budget. A request carrying its own
	// X-Yabanin-Task header must be attributed to that header (not the
	// fallback), so it proceeds despite the fallback tag being exhausted.
	gw.tokenBudget.Record(TaskBudgetScope, "", "a142-add-login", 1_000_000)

	rec := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions",
		bytes.NewReader([]byte(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Yabanin-Task", "override-task")
	gw.chatCompletions(rec, r)

	require.Equal(t, http.StatusOK, rec.Code,
		"explicit X-Yabanin-Task wins over YABANIN_TASK fallback: %s", rec.Body.String())
}

func TestChatCompletions_NoTaskTag_NoChange(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"c","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"}}]}`))
	}))
	defer srv.Close()

	// No YABANIN_TASK: an untagged request has no task budget dimension, so
	// nothing is charged and the request proceeds regardless of any (irrelevant)
	// task budget state.
	gw := newTaskTagGateway(t, srv.URL, "")

	rec := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions",
		bytes.NewReader([]byte(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`)))
	r.Header.Set("Content-Type", "application/json")
	gw.chatCompletions(rec, r)

	require.Equal(t, http.StatusOK, rec.Code, "no task tag → zero behavior change: %s", rec.Body.String())
}

// --- invalid YABANIN_TASK is ignored (never 400s every request) --------------

// The build wiring (gateway.go) gates gw.taskTag on budget.ValidTaskID, so an
// invalid YABANIN_TASK never reaches the field (off). This pins the format
// contract the wiring relies on: a mistyped deployment-wide tag is ignored at
// startup rather than 400ing every request (the per-request header path keeps
// validating its own value).
func TestTaskTag_InvalidValueIgnoredAtBuild(t *testing.T) {
	invalid := "bad task!"
	assert.False(t, budget.ValidTaskID(invalid), "precondition: value must be invalid for the wiring to skip it")
	valid := "a142-add-login"
	assert.True(t, budget.ValidTaskID(valid), "precondition: a well-formed tag is accepted")
}
