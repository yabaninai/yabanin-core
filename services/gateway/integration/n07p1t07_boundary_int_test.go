//go:build integration

package integration

// N07-P01-T07 — boundary corpus, REAL leg.
//
// The MOCK legs of the corpus live in pkg/provider, pkg/gateway and
// sdks/go (adapter rejections, wire-level boundaries, consumer decode).
// This file proves the tool_choice boundary fix end-to-end on the
// production stand — full cli.RunGatewayServer with real PG/Redis auth,
// real escrow and the real event publisher: boundary values on the
// translated route render typed 400s with the exact reason, dial nothing
// and write nothing to the ledger (escrow settles locally) — the same
// observable shape as the T05 effort refusal, now for the T07 boundary.
//
// Run: go test -tags integration ./services/gateway/integration/ -run
// TestN07P1T07RealDB -count=1 (requires Docker for the testcontainers PG/Redis).

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestN07P1T07RealDB_TranslatedBoundaryRejection(t *testing.T) {
	ctx := t.Context()
	rdb := NewGatewayTestRedis(t, ctx)
	pool := NewGatewayTestDB(t, ctx)

	// SeedGatewayOrg seeds in FK order (org → wallet → team → budget) and is
	// idempotent, so it works on a fresh container (it used to assume
	// residue and SKIP — fixed with the T06 seed-order defect). seedAPIKey
	// re-asserts the team, wallet and budget idempotently and seeds the key.
	SeedGatewayOrg(ctx, t, pool)
	seedAPIKey(rdb, pool, "test-api-key", testGatewayOrgID)

	upstream, sentBodies := n07t06Upstream(t)
	baseURL, cleanup := n07t06RealServer(t, ctx, rdb, pool, upstream.URL)
	defer cleanup()

	// Route a model to the translated (anthropic) adapter on the real
	// resolver: the models_registry row decides adapter + upstream, the
	// cfg.Provider entry is only the OpenAI passthrough fallback.
	mustExec(ctx, t, pool,
		`INSERT INTO models_registry (model_name, display_name, tier, upstream_url, provider, enabled)
		 VALUES ($1, $1, 'smart', $2, 'anthropic', true)
		 ON CONFLICT (model_name) DO UPDATE SET upstream_url = EXCLUDED.upstream_url, provider = EXCLUDED.provider, enabled = true`,
		"claude-t07-boundary", upstream.URL)

	client := &http.Client{Timeout: 30 * time.Second}
	auth := map[string]string{"Authorization": "Bearer test-api-key"}

	entriesBefore := len(getRedisStreamEntries(t, rdb, n07t06EventStream))

	// Boundary values on the translated route: unknown tool_choice and a
	// malformed tool_choice shape reject with the exact reason (the T07
	// fix, was a silent drop), never dial, never event.
	cases := []struct {
		toolChoice string
		want       string
	}{
		{`"banana"`, `unsupported tool_choice "banana"`},
		{`{"type":"function"}`, `tool_choice must be "auto"|"none"|"required" or {"type":"function","function":{"name":…}}`},
		{`42`, `tool_choice must be "auto"|"none"|"required" or {"type":"function","function":{"name":…}}`},
	}
	for _, tc := range cases {
		body := json.RawMessage(`{"model":"claude-t07-boundary","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"get_weather","parameters":{"type":"object"}}}],"tool_choice":` + tc.toolChoice + `}`)
		status, _, respBody := roundTrip(t, client, baseURL, "/v1/chat/completions", auth, body)
		require.Equal(t, http.StatusBadRequest, status, "tool_choice %s: %s", tc.toolChoice, string(respBody))
		var env struct {
			Error struct {
				Message string `json:"message"`
				Type    string `json:"type"`
			} `json:"error"`
		}
		require.NoError(t, json.Unmarshal(respBody, &env), "body: %s", string(respBody))
		require.Equal(t, "invalid_request_error", env.Error.Type, "tool_choice %s", tc.toolChoice)
		require.Contains(t, env.Error.Message, tc.want, "the exact boundary reason must reach the client")
		require.Contains(t, env.Error.Message, "rejecting instead of silently dropping (I51)", "the contract phrase must reach the client")
		// REAL/MOCK path difference, pinned deliberately: the MOCK surface
		// wraps adapter reasons as "translate request: <reason>" via the
		// upstream client (T05), while the real server's pool path renders
		// the adapter reason directly — same status class, same error type,
		// same exact reason, no layer prefix.
		require.NotContains(t, env.Error.Message, "translate request: ")
	}

	require.Empty(t, sentBodies(), "boundary rejections must never dial the upstream")
	require.Len(t, getRedisStreamEntries(t, rdb, n07t06EventStream), entriesBefore,
		"boundary rejections are ledger-silent (escrow settles locally)")
}
