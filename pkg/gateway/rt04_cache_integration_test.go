//go:build integration

package cli

// RT-04 integration evidence: the cache input is the guarded+patched payload.
// After guard redaction and a vertical prompt mask, a second identical request
// must be served from the exact cache (proving the cache key is derived from
// the guarded+masked bytes), while a lookup keyed by the pre-guard client body
// must miss — the secret-bearing bytes never enter the cache input.
//
// Run: go test -tags integration -run 'RT04_CacheInput' ./pkg/gateway
// (requires Docker; excluded from -short and default runs, matching
// sessionkeys_integration_test.go).

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	testpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	testredis "github.com/testcontainers/testcontainers-go/modules/redis"

	"github.com/reireirei/yabanin/pkg/cache"
	"github.com/reireirei/yabanin/pkg/embeddings"
	"github.com/reireirei/yabanin/pkg/guardhooks"
	migrate "github.com/reireirei/yabanin/pkg/migrate"
)

func TestRT04_CacheInputIsGuardedPayload_Integration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	pg, err := testpostgres.Run(ctx, "pgvector/pgvector:pg16",
		testpostgres.WithDatabase("yabanin"),
		testpostgres.WithUsername("postgres"),
		testpostgres.WithPassword("postgres"),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = pg.Terminate(context.Background()) })
	host, err := pg.Host(ctx)
	require.NoError(t, err)
	port, err := pg.MappedPort(ctx, "5432")
	require.NoError(t, err)
	dsn := "postgres://postgres:postgres@" + host + ":" + strings.Split(port.Port(), "/")[0] + "/yabanin?sslmode=disable"
	// Deadline-poll until the fresh container accepts the migration run —
	// no fixed retry-count sleep loop.
	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, err = migrate.Run(ctx, dsn, "sg"); err == nil {
			break
		}
		if !time.Now().Before(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	require.NoError(t, err, "migrate did not succeed within 15s")
	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	rd, err := testredis.Run(ctx, "redis:7-alpine")
	require.NoError(t, err)
	t.Cleanup(func() { _ = rd.Terminate(context.Background()) })
	rhost, err := rd.Host(ctx)
	require.NoError(t, err)
	rport, err := rd.MappedPort(ctx, "6379")
	require.NoError(t, err)
	rdb := redis.NewClient(&redis.Options{Addr: rhost + ":" + strings.Split(rport.Port(), "/")[0]})
	t.Cleanup(func() { _ = rdb.Close() })

	cacheSvc := cache.NewCacheService(context.Background(), pool, rdb,
		&embeddings.StaticClient{Embedding: make([]float32, 384)}, slog.Default(), false)
	cacheSvc.SetOrgPolicyLoader(func(context.Context, string) (*cache.OrgPolicy, error) {
		return &cache.OrgPolicy{Mode: cache.PrivacyEnabled, Semantic: false, TTL: time.Hour}, nil
	})

	calls := 0
	var lastBody string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		lastBody = string(raw)
		calls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(completeResp("gpt-4o-mini"))
	}))
	t.Cleanup(up.Close)

	vert := &rt04MaskVertical{masking: true}
	gw := rt04Gateway(up.URL, guardhooks.ModeRedact, rt04Registry(t, vert))
	gw.cache = cacheSvc

	do := func() *httptest.ResponseRecorder {
		r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
			"/v1/chat/completions", strings.NewReader(string(rt04ChatBody(false))))
		r.Header.Set("X-Org-Id", "org-1")
		w := httptest.NewRecorder()
		gw.chatCompletions(w, r)
		return w
	}

	w1 := do()
	require.Equal(t, http.StatusOK, w1.Code, "response body: %s", w1.Body.String())
	require.Equal(t, 1, calls, "first request must go upstream")
	rt04AssertGuardedMaskedPayload(t, lastBody)

	preguard, err := cacheSvc.LookupWithResult(ctx, cache.RouteIdentity{OrgID: "org-1", Model: "gpt-4o-mini"}, rt04ChatBody(false))
	require.NoError(t, err)
	assert.Nil(t, preguard,
		"a lookup keyed by the pre-guard client body must miss: those bytes are not the cache input")

	w2 := do()
	require.Equal(t, http.StatusOK, w2.Code, "response body: %s", w2.Body.String())
	assert.Equal(t, "EXACT", w2.Header().Get("X-Cache"),
		"second identical request must hit the exact cache — the cache input is the guarded+masked payload")
	require.Equal(t, 1, calls, "cache hit must not call upstream again")
	assert.NotContains(t, w2.Body.String(), rt04Secret,
		"the served cached response must not contain the secret")
}
