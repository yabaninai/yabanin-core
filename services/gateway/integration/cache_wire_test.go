//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/cache"
	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/embeddings"
	"github.com/reireirei/yabanin/pkg/gateway"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Acceptance at the consumer boundary. The existing
// TestIntegration_CacheModeOff_NoReadNoWrite covers the CacheService helpers
// directly; this test drives a REAL gateway HTTP server (RunGatewayServer,
// full request pipeline: auth → guards → resolver → routing → serveChatCache)
// against real redis+pgvector backends and a fake OpenAI upstream. The
// cache_mode=off org must neither read nor write through the wire, while a
// semantic control org proves on the same stand that the cache reads AND
// writes over HTTP (so the off assertions cannot pass vacuously).

const (
	wireModelName = "cache-off-wire-model"
	wireOffKey    = "wire-off-key"
	wireSemKey    = "wire-semantic-key"
)

const wireUpstreamBody = `{"id":"chatcmpl-fresh","object":"chat.completion","model":"` + wireModelName + `","choices":[{"index":0,"message":{"role":"assistant","content":"fresh from upstream"},"finish_reason":"stop"}],"usage":{"prompt_tokens":11,"completion_tokens":7,"total_tokens":18}}`

const wirePlantedBody = `{"id":"chatcmpl-planted","object":"chat.completion","model":"` + wireModelName + `","choices":[{"index":0,"message":{"role":"assistant","content":"planted semantic-era response"},"finish_reason":"stop"}],"usage":{"prompt_tokens":11,"completion_tokens":7,"total_tokens":18}}`

func wireChatBody(prompt string) json.RawMessage {
	return json.RawMessage(`{"model":"` + wireModelName + `","messages":[{"role":"user","content":"` + prompt + `"}]}`)
}

// wireGatewayTestServer starts the gateway with the cache subsystem enabled
// (same wiring as production: CacheService + DBPolicyLoader) and the upstream
// provider pointing at the fake OpenAI server. The embedder env vars must be
// set by the caller BEFORE this runs (cfg.Embedder() is env-driven).
func wireGatewayTestServer(t *testing.T, ctx context.Context, rdb *redis.Client, pool *pgxpool.Pool, upstreamURL string) (string, func()) {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelWarn}))
	port := findFreePort(t)

	cfg := config.Gateway{
		ListenAddr:         fmt.Sprintf("127.0.0.1:%d", port),
		AuthMode:           "header",
		PGURI:              gatewayPGURI(),
		Provider:           upstreamURL,
		FallbackKey:        "test-api-key",
		EventStream:        "gateway-wire-cache-events",
		CacheEnabled:       true,
		CachePGExactLookup: true,
	}

	serverCtx, serverCancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		// N03-P02-T04 contract: the gateway arms the cache regime resolver
		// unconditionally, and an unwired policy runtime answers an empty
		// fingerprint — the fail-safe gates every cache lookup and write.
		// A bare stand would therefore starve the semantic control org
		// below (no cache_entries rows at all). Enforce mode with zero
		// attached policies keeps real fingerprints (the empty plan set
		// hashes to one) and denies nothing, so the cache pipeline stays
		// observable while the cache_mode=off org is silenced by its own
		// privacy policy (DBPolicyLoader, not the regime resolver).
		_ = cli.RunGatewayServer(cfg, rdb, pool, integrationTestKMS{}, logger, serverCtx,
			cli.PolicyWiring{Mode: cli.PolicyModeEnforce})
	}()

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	waitForGatewayReady(t, baseURL)

	return baseURL, func() {
		serverCancel()
		select {
		case <-time.After(5 * time.Second):
		case <-done:
		}
	}
}

// seedWireModel registers the wire model with its upstream pointed at the
// fake server. Must run BEFORE the gateway starts (5-minute resolver cache).
func seedWireModel(t *testing.T, pool *pgxpool.Pool, upstreamURL string) {
	t.Helper()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO models_registry (model_name, display_name, tier, upstream_url, provider, enabled)
		 VALUES ($1, 'Wire cache-off model', 'smart', $2, 'openai', true)
		 ON CONFLICT (model_name) DO UPDATE SET upstream_url = EXCLUDED.upstream_url, enabled = true`,
		wireModelName, upstreamURL)
	require.NoError(t, err)
}

func TestIntegration_CacheModeOff_WireBoundary(t *testing.T) {
	ctx := t.Context()
	rdb := NewGatewayTestRedis(t, ctx)
	pool := NewGatewayTestDB(t, ctx)

	orgOff := seedCacheSettingsOrg(t, pool, "cache-off-wire-off", true, "off")
	orgSem := seedCacheSettingsOrg(t, pool, "cache-off-wire-semantic", true, "semantic")

	seedAPIKey(rdb, pool, wireOffKey, orgOff)
	seedAPIKey(rdb, pool, wireSemKey, orgSem)

	// Fake OpenAI upstream: counts requests so cache hits are distinguishable
	// from fresh upstream calls over the wire.
	var upstreamHits atomic.Int64
	upstreamSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(wireUpstreamBody))
	}))
	defer upstreamSrv.Close()

	// Fake embeddings server: the gateway's async cache writer persists
	// pgvector rows (vector(384) NOT NULL), so the semantic control org needs
	// a working embedder over env config.
	const embDim = 384
	embVec := make([]float64, embDim)
	for i := range embVec {
		embVec[i] = 0.1
	}
	embPayload, err := json.Marshal(map[string]any{
		"data":  []map[string]any{{"index": 0, "embedding": embVec, "object": "embedding"}},
		"model": "wire-test-embedding",
	})
	require.NoError(t, err)
	embedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(embPayload)
	}))
	defer embedSrv.Close()

	t.Setenv("YABANIN_EMBEDDER_ENABLED", "true")
	t.Setenv("YABANIN_EMBEDDER_BASE_URL", embedSrv.URL)
	t.Setenv("YABANIN_EMBEDDER_MODEL", "wire-test-embedding")

	seedWireModel(t, pool, upstreamSrv.URL)

	// Plant a semantic-era exact entry for the OFF org directly in the redis
	// store (the shape an entry would have if the org had been cached under a
	// permissive policy before the flip to off). Uses only exported cache API.
	plantRi := cache.RouteIdentity{OrgID: orgOff, Model: wireModelName}.Resolved()
	plantPrompt := wireChatBody("wire boundary planted prompt")
	plantNorm, err := cache.NormalizeMessagesJSON(plantPrompt)
	require.NoError(t, err)
	plantSealed, err := cache.SealEntry([]byte(wirePlantedBody), plantRi)
	require.NoError(t, err)
	require.NoError(t, cache.NewRedisStore(rdb, 24*time.Hour).Put(ctx, orgOff, wireModelName, cache.ComputePromptHash(plantNorm), plantSealed))

	pgRows, redisKeys := countOrgCacheArtifacts(t, ctx, pool, rdb, orgOff)
	require.Equal(t, 0, pgRows, "precondition: no pgvector rows for the off org")
	require.Equal(t, 1, redisKeys, "precondition: exactly the planted redis entry for the off org")

	// Pre-flight positive control: with the policy gate out of the picture
	// (no DB loader → default permissive policy), the planted entry IS
	// servable — proving plant hash/provenance correctness, so the wire-level
	// miss below can only come from the off policy.
	ctrl := cache.NewCacheService(ctx, pool, rdb, &embeddings.NoopClient{}, slog.New(slog.DiscardHandler), false)
	ctrlHit, ctrlErr := ctrl.LookupWithResult(ctx, plantRi, plantPrompt)
	require.NoError(t, ctrlErr)
	require.NotNil(t, ctrlHit, "planted entry must be servable when the policy gate permits")
	assert.Equal(t, "exact", ctrlHit.SourceType)

	baseURL, cleanup := wireGatewayTestServer(t, ctx, rdb, pool, upstreamSrv.URL)
	defer cleanup()

	client := &http.Client{Timeout: 30 * time.Second}

	// [no-read] The off org requests the EXACT planted prompt over HTTP:
	// the off policy must deny the lookup → fresh upstream answer, no
	// X-Cache header, planted body never leaks.
	offHeaders := map[string]string{
		"Authorization": "Bearer " + wireOffKey,
		"X-Org-Id":      orgOff,
	}
	status, headers, respBody := roundTrip(t, client, baseURL, "/v1/chat/completions", offHeaders, plantPrompt)
	require.Equal(t, http.StatusOK, status, "body: %s", string(respBody))
	assert.Equal(t, "chatcmpl-fresh", wireRespID(t, respBody), "off org must get a fresh upstream answer, not the planted entry")
	assert.Empty(t, headers["X-Cache"], "cache hit must not be reported for the off org")
	assert.Equal(t, int64(1), upstreamHits.Load(), "request 1 must reach the upstream")

	// [write path exercised] A second off-org request goes upstream; the
	// gateway's post-response cache write must be gated by the same policy.
	freshPrompt := wireChatBody("wire boundary fresh prompt")
	status, headers, respBody = roundTrip(t, client, baseURL, "/v1/chat/completions", offHeaders, freshPrompt)
	require.Equal(t, http.StatusOK, status, "body: %s", string(respBody))
	assert.Empty(t, headers["X-Cache"], "off org responses are never cached")
	assert.Equal(t, int64(2), upstreamHits.Load(), "request 2 must reach the upstream")

	// [positive control, write] The semantic org writes through the wire:
	// its prompt lands in pgvector via the gateway's async writer pool.
	semPrompt := wireChatBody("wire boundary semantic prompt")
	semHeaders := map[string]string{
		"Authorization": "Bearer " + wireSemKey,
		"X-Org-Id":      orgSem,
	}
	status, _, respBody = roundTrip(t, client, baseURL, "/v1/chat/completions", semHeaders, semPrompt)
	require.Equal(t, http.StatusOK, status, "body: %s", string(respBody))
	assert.Equal(t, int64(3), upstreamHits.Load(), "first semantic-org request goes upstream")
	waitForOrgCacheRows(t, pool, orgSem, 1)

	// [positive control, read] The same semantic prompt served from the wire
	// cache: X-Cache present, no additional upstream call.
	status, headers, respBody = roundTrip(t, client, baseURL, "/v1/chat/completions", semHeaders, semPrompt)
	require.Equal(t, http.StatusOK, status, "body: %s", string(respBody))
	assert.Equal(t, "EXACT", headers["X-Cache"], "semantic org repeat request must be served from the wire cache")
	assert.Equal(t, int64(3), upstreamHits.Load(), "cache hit must not call the upstream")

	// [no-write] The off org still owns exactly its planted artifacts: the
	// two upstream-served requests persisted nothing anywhere.
	pgRows, redisKeys = countOrgCacheArtifacts(t, ctx, pool, rdb, orgOff)
	assert.Equal(t, 0, pgRows, "off org must have zero pgvector rows after wire traffic")
	assert.Equal(t, 1, redisKeys, "off org must keep only the planted redis entry after wire traffic")
}

func wireRespID(t *testing.T, body json.RawMessage) string {
	t.Helper()
	var parsed struct {
		ID string `json:"id"`
	}
	require.NoError(t, json.Unmarshal(body, &parsed))
	return parsed.ID
}
