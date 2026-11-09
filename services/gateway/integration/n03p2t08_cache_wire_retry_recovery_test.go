//go:build integration

package integration

// N03-P02-T08 acceptance at the consumer boundary: a 503-interrupted chat
// request retried through the REAL gateway HTTP server (RunGatewayServer,
// full request pipeline) produces exactly one cache artifact — no duplicate
// redis keys, no duplicate pgvector rows — and the recovered answer replays
// exact. Same stand family as cache_wire_test.go: real redis+pgvector
// containers, real auth over the seeded key, fake OpenAI upstream and fake
// embedder (explicit mock seams — provider behavior is not the subject).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	n03p2t08WireModel = "n03p2t08-wire-retry-model"
	n03p2t08WireKey   = "n03p2t08-wire-retry-key"
)

const n03p2t08WireRetryBody = `{"id":"chatcmpl-retry-ok","object":"chat.completion","model":"` + n03p2t08WireModel + `","choices":[{"index":0,"message":{"role":"assistant","content":"recovered after interruption"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}`

// n03p2t08WireChatBody requests THIS test's registered model — a body
// naming an unregistered model resolves to an empty cache route identity
// and cannot underwrite the provenance contract under test.
func n03p2t08WireChatBody(prompt string) json.RawMessage {
	return json.RawMessage(`{"model":"` + n03p2t08WireModel + `","messages":[{"role":"user","content":"` + prompt + `"}]}`)
}

// n03p2t08SeedModel registers the T08 wire model with its upstream pointed
// at the scripted server. Distinct model name: seeding must never mutate
// another test's model row (the resolver cache is process-wide).
func n03p2t08SeedModel(t *testing.T, pool *pgxpool.Pool, upstreamURL string) {
	t.Helper()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO models_registry (model_name, display_name, tier, upstream_url, provider, enabled)
		 VALUES ($1, 'N03P2T08 wire retry model', 'smart', $2, 'openai', true)
		 ON CONFLICT (model_name) DO UPDATE SET upstream_url = EXCLUDED.upstream_url, enabled = true`,
		n03p2t08WireModel, upstreamURL)
	require.NoError(t, err)
}

func TestN03P2T08_WireRetry503_SingleArtifactExactReplay(t *testing.T) {
	ctx := t.Context()
	rdb := NewGatewayTestRedis(t, ctx)
	pool := NewGatewayTestDB(t, ctx)

	org := seedCacheSettingsOrg(t, pool, "n03p2t08-wire-retry", true, "exact")
	seedAPIKey(rdb, pool, n03p2t08WireKey, org)

	// Scripted OpenAI upstream: attempt 1 answers 503, the retry answers
	// the recovered completion document.
	var upstreamHits atomic.Int64
	upstreamSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if n := upstreamHits.Add(1); n == 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":{"message":"upstream unavailable","type":"server_error"}}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(n03p2t08WireRetryBody))
	}))
	defer upstreamSrv.Close()

	// Fake embeddings server: the async cache writer persists pgvector rows
	// (vector(384) NOT NULL), so the writer needs a working embedder.
	const embDim = 384
	embVec := make([]float64, embDim)
	for i := range embVec {
		embVec[i] = 0.2
	}
	embPayload, err := json.Marshal(map[string]any{
		"data":  []map[string]any{{"index": 0, "embedding": embVec, "object": "embedding"}},
		"model": "n03p2t08-wire-embedding",
	})
	require.NoError(t, err)
	embedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(embPayload)
	}))
	defer embedSrv.Close()

	t.Setenv("YABANIN_EMBEDDER_ENABLED", "true")
	t.Setenv("YABANIN_EMBEDDER_BASE_URL", embedSrv.URL)
	t.Setenv("YABANIN_EMBEDDER_MODEL", "n03p2t08-wire-embedding")

	n03p2t08SeedModel(t, pool, upstreamSrv.URL)

	baseURL, cleanup := wireGatewayTestServer(t, ctx, rdb, pool, upstreamSrv.URL)
	defer cleanup()

	client := &http.Client{Timeout: 30 * time.Second}
	headers := map[string]string{
		"Authorization": "Bearer " + n03p2t08WireKey,
		"X-Org-Id":      org,
	}
	prompt := n03p2t08WireChatBody("n03p2t08 wire retry prompt")

	status, hdrs, body := roundTrip(t, client, baseURL, "/v1/chat/completions", headers, prompt)
	require.Equal(t, http.StatusOK, status, string(body))
	assert.Equal(t, "chatcmpl-retry-ok", wireRespID(t, body), "the retry recovered the answer")
	assert.Empty(t, hdrs["X-Cache"], "a retried fetch is a miss, not a hit")
	assert.Equal(t, int64(2), upstreamHits.Load(), "one interrupted attempt + one successful retry")

	waitForOrgCacheRows(t, pool, org, 1)
	pgRows, redisKeys := countOrgCacheArtifacts(t, ctx, pool, rdb, org)
	assert.Equal(t, 1, pgRows, "exactly one pgvector row — the retry never duplicates")
	assert.Equal(t, 1, redisKeys, "exactly one redis key — the retry never duplicates")

	status, hdrs, body = roundTrip(t, client, baseURL, "/v1/chat/completions", headers, prompt)
	require.Equal(t, http.StatusOK, status, string(body))
	assert.Equal(t, "EXACT", hdrs["X-Cache"], "no losses: the recovered answer replays over the wire")
	assert.Equal(t, int64(2), upstreamHits.Load(), "the replay never refetches")
}
