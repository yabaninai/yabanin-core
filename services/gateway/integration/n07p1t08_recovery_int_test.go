//go:build integration

package integration

// N07-P01-T08 — retry/recovery corpus, REAL leg.
//
// The MOCK legs live in pkg/gateway/n07p1t08_retry_recovery_test.go (REC-01
// refusal→fallback, REC-02 exhaustion, REC-03 facet-bearing retry, REC-04
// stream refusal→fallback) and sdks/go/compat_joint_recovery_test.go
// (consumer seat). This file proves recovery end-to-end on the production
// stand — full cli.RunGatewayServer with real PG/Redis auth, real escrow,
// the real resolver (failover_models from models_registry) and the real
// event publisher:
//
//   - REC-03/REAL: a transient 503 on the JSON path retries on real
//     routing; every dial carries the byte-identical body, the client sees
//     exactly one completion, and the ledger records exactly ONE
//     request.completed (no failed event for the retried-away attempt);
//   - REC-01/REAL: a translated-route refusal (T07, typed pre-dial proof)
//     advances the real failover chain — the refusal never dials, the
//     openai fallback serves exactly once with the facet fields verbatim,
//     and the ledger's single completed event names the winning hop
//     (model_used) against the requested one (model_requested).
//
// Boundary rejections on the translated route (dial-nothing, ledger-silent
// 400s) are pinned by the T07 REAL leg
// (TestN07P1T07RealDB_TranslatedBoundaryRejection) and are cited, not
// repeated.
//
// Run: go test -tags integration ./services/gateway/integration/ -run
// TestN07P1T08RealDB -count=1 (requires Docker for the testcontainers PG/Redis).

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// n07t08RefusingUpstream records any dial (a refused hop must never dial)
// and answers with a native Anthropic completion in case of a bug.
func n07t08RefusingUpstream(t *testing.T) (*httptest.Server, func() int) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_t08bug","type":"message","role":"assistant","model":"claude-upstream","content":[{"type":"text","text":"refused hop must not reach here"}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	t.Cleanup(srv.Close)
	return srv, func() int { return int(hits.Load()) }
}

// n07t08ScriptedUpstream serves scripted (status, body) steps in order and
// records every dial body.
func n07t08ScriptedUpstream(t *testing.T, steps []string) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var bodies []string
	i := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		idx := i
		if idx < len(steps) {
			i++
		}
		bodies = append(bodies, string(b))
		mu.Unlock()
		if idx >= len(steps) {
			idx = len(steps) - 1
		}
		body := steps[idx]
		if body == "503" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":{"message":"overloaded"}}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		out := make([]string, len(bodies))
		copy(out, bodies)
		return out
	}
}

func TestN07P1T08RealDB_RetryAndRefusalFallbackRecovery(t *testing.T) {
	ctx := t.Context()
	rdb := NewGatewayTestRedis(t, ctx)
	pool := NewGatewayTestDB(t, ctx)

	// SeedGatewayOrg seeds in FK order (org → wallet → team → budget) and is
	// idempotent, so it works on a fresh container (it used to assume
	// residue and SKIP — fixed with the T06 seed-order defect, same shape
	// as the T07 REAL leg); seedAPIKey then re-asserts idempotently.
	SeedGatewayOrg(ctx, t, pool)
	seedAPIKey(rdb, pool, "test-api-key", testGatewayOrgID)

	// Retry upstream: 503 then the winning completion (distinct id proves
	// which attempt won). Refusal upstream: must never be dialed. Fallback
	// upstream: serves the winning completion for the refusal scenario.
	win := `{"id":"chatcmpl-t08-win","object":"chat.completion","model":"t08-model","choices":[{"index":0,"message":{"role":"assistant","content":"восстановлено-t08"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":2,"total_tokens":7}}`
	retryUp, retryBodies := n07t08ScriptedUpstream(t, []string{"503", win})
	refuseUp, refuseHits := n07t08RefusingUpstream(t)
	fallbackUp, fallbackBodies := n07t08ScriptedUpstream(t, []string{win})

	baseURL, cleanup := n07t06RealServer(t, ctx, rdb, pool, retryUp.URL)
	defer cleanup()

	// Real routing: the models_registry rows decide adapter + upstream, and
	// the refusal scenario's primary carries a real failover_models chain.
	mustExec(ctx, t, pool,
		`INSERT INTO models_registry (model_name, display_name, tier, upstream_url, provider, enabled)
		 VALUES ($1, $1, 'smart', $2, 'openai', true)
		 ON CONFLICT (model_name) DO UPDATE SET upstream_url = EXCLUDED.upstream_url, provider = EXCLUDED.provider, enabled = true`,
		"t08-retry-primary", retryUp.URL)
	mustExec(ctx, t, pool,
		`INSERT INTO models_registry (model_name, display_name, tier, upstream_url, provider, enabled)
		 VALUES ($1, $1, 'smart', $2, 'anthropic', true)
		 ON CONFLICT (model_name) DO UPDATE SET upstream_url = EXCLUDED.upstream_url, provider = EXCLUDED.provider, enabled = true`,
		"t08-refuse-claude", refuseUp.URL)
	mustExec(ctx, t, pool,
		`INSERT INTO models_registry (model_name, display_name, tier, upstream_url, provider, enabled)
		 VALUES ($1, $1, 'smart', $2, 'openai', true)
		 ON CONFLICT (model_name) DO UPDATE SET upstream_url = EXCLUDED.upstream_url, provider = EXCLUDED.provider, enabled = true`,
		"t08-fallback-openai", fallbackUp.URL)
	mustExec(ctx, t, pool,
		`UPDATE models_registry SET failover_models = $2 WHERE model_name = $1`,
		"t08-refuse-claude", []string{"t08-fallback-openai"})

	client := &http.Client{Timeout: 30 * time.Second}
	auth := map[string]string{"Authorization": "Bearer test-api-key"}

	// Scenario 1 — retry-then-success on real routing (REC-03/REAL).
	entriesBefore := len(getRedisStreamEntries(t, rdb, n07t06EventStream))
	body1 := json.RawMessage(`{"model":"t08-retry-primary","messages":[{"role":"user","content":"Привет","x_client_part":{"locale":"ru"}}],"reasoning_effort":"high","x_client_ext":{"trace":"t08-real"}}`)
	status, _, respBody := roundTrip(t, client, baseURL, "/v1/chat/completions", auth, body1)
	require.Equal(t, http.StatusOK, status, string(respBody))
	require.Contains(t, string(respBody), "восстановлено-t08", "the client sees the winning attempt")
	require.Contains(t, string(respBody), "chatcmpl-t08-win", "the winning attempt's id, not the retried-away one")

	dials := retryBodies()
	require.Len(t, dials, 2, "one retry: two dials, one answer")
	require.Equal(t, dials[0], dials[1], "every retried dial carries the byte-identical body")
	for _, want := range []string{`"reasoning_effort":"high"`, `"x_client_ext":{"trace":"t08-real"}`, `"x_client_part":{"locale":"ru"}`} {
		require.Contains(t, dials[0], want, "the facet fields survive real retries")
	}

	// Ledger: exactly one new entry, request.completed — the retried-away
	// 503 publishes nothing. Publishing is async: poll for the completed
	// event first, then assert the exact delta (no failed event besides it).
	_, ok := waitForStreamEntry(t, rdb, n07t06EventStream, func(e map[string]string) bool {
		return e["event_type"] == "request.completed" && e["model_used"] == "t08-retry-primary"
	})
	require.True(t, ok, "the retry scenario's completed event never reached the ledger")
	entries := getRedisStreamEntries(t, rdb, n07t06EventStream)
	newEntries := entries[entriesBefore:]
	require.Len(t, newEntries, 1, "retry-then-success bills exactly one ledger event, got %v", newEntries)
	require.Equal(t, "request.completed", newEntries[0]["event_type"])
	require.Equal(t, "t08-retry-primary", newEntries[0]["model_used"])

	// Scenario 2 — translated refusal advances the real failover chain
	// (REC-01/REAL). The refusal is pre-dial; the fallback serves once with
	// the facet fields verbatim. Scenario 1 left exactly one new entry, so
	// the baseline moves by one.
	afterScenario1 := entriesBefore + 1
	body2 := json.RawMessage(`{"model":"t08-refuse-claude","messages":[{"role":"user","content":"hi","x_client_part":{"locale":"ru"}}],"reasoning_effort":"high","x_client_ext":{"trace":"t08-fb"}}`)
	status, _, respBody = roundTrip(t, client, baseURL, "/v1/chat/completions", auth, body2)
	require.Equal(t, http.StatusOK, status, string(respBody))
	require.Contains(t, string(respBody), "восстановлено-t08", "the fallback's answer reaches the client")
	require.NotContains(t, string(respBody), "reasoning_effort", "no refusal leak: the chain recovered")

	require.Zero(t, refuseHits(), "a translate refusal must not dial its upstream, even on the real chain")
	fbDials := fallbackBodies()
	require.Len(t, fbDials, 1, "the fallback serves exactly once")
	for _, want := range []string{`"reasoning_effort":"high"`, `"x_client_ext":{"trace":"t08-fb"}`, `"x_client_part":{"locale":"ru"}`} {
		require.Contains(t, fbDials[0], want, "the facet fields ride the winning dial verbatim")
	}

	// Ledger: exactly one new entry naming the winning hop against the
	// requested one (async publish: poll, then assert the exact delta).
	_, ok = waitForStreamEntry(t, rdb, n07t06EventStream, func(e map[string]string) bool {
		return e["event_type"] == "request.completed" && e["model_used"] == "t08-fallback-openai"
	})
	require.True(t, ok, "the fallback scenario's completed event never reached the ledger")
	entries = getRedisStreamEntries(t, rdb, n07t06EventStream)
	newEntries = entries[afterScenario1:]
	require.Len(t, newEntries, 1, "refusal→fallback bills exactly one ledger event, got %v", newEntries)
	require.Equal(t, "request.completed", newEntries[0]["event_type"])
	require.Equal(t, "t08-fallback-openai", newEntries[0]["model_used"], "the winning hop's model")
	require.Equal(t, "t08-refuse-claude", newEntries[0]["model_requested"], "the client's model")
}
