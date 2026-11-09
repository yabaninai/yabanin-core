//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"testing"
	"time"

	pgxpool "github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/cache"
	"github.com/reireirei/yabanin/pkg/embeddings"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	testpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	testredis "github.com/testcontainers/testcontainers-go/modules/redis"
)

func fullCacheContainers(t *testing.T) (*pgxpool.Pool, *redis.Client) {
	t.Helper()
	ctx := context.Background()

	pgContainer, err := testpostgres.Run(ctx, "pgvector/pgvector:pg16",
		testpostgres.WithDatabase("testcache"),
		testpostgres.WithUsername("postgres"),
		testpostgres.WithPassword("postgres"),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = pgContainer.Terminate(ctx) })

	pgHost, err := pgContainer.Host(ctx)
	require.NoError(t, err)
	pgPort, err := pgContainer.MappedPort(ctx, "5432")
	require.NoError(t, err)
	pgPortStr := pgPort.Port()
	if i := len(pgPortStr) - 4; i > 0 && pgPortStr[i:] == "/tcp" {
		pgPortStr = pgPortStr[:i]
	}

	pgConnStr := "postgres://postgres:postgres@" + pgHost + ":" + pgPortStr + "/testcache?sslmode=disable"
	pool, err := pgxpool.New(ctx, pgConnStr)
	require.NoError(t, err)
	t.Cleanup(func() { pool.Close() })

	waitForPoolReady(t, ctx, pool)

	applyMigrations(t, pool)

	redisContainer, err := testredis.Run(ctx, "redis:7-alpine")
	require.NoError(t, err)
	t.Cleanup(func() { _ = redisContainer.Terminate(ctx) })

	redisHost, err := redisContainer.Host(ctx)
	require.NoError(t, err)
	redisPort, err := redisContainer.MappedPort(ctx, "6379")
	require.NoError(t, err)
	redisPortStr := redisPort.Port()
	if i := len(redisPortStr) - 4; i > 0 && redisPortStr[i:] == "/tcp" {
		redisPortStr = redisPortStr[:i]
	}

	rdb := redis.NewClient(&redis.Options{Addr: redisHost + ":" + redisPortStr})
	waitForRedisReady(t, ctx, rdb)
	t.Cleanup(func() { rdb.Close() })

	return pool, rdb
}

func testLog(t *testing.T) *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestIntegration_CacheFullPipeline(t *testing.T) {
	ctx := context.Background()
	pool, rdb := fullCacheContainers(t)

	embedder := &embeddings.StaticClient{Embedding: makeEmbedding(384, 0.1)}
	log := testLog(t)

	service := cache.NewCacheService(context.Background(), pool, rdb, embedder, log, true)

	promptJSON := json.RawMessage(`{"model":"gpt-4o","messages":[{"role":"user","content":"hello world"}]}`)
	responseJSON := json.RawMessage(`{"id":"chat-1","choices":[{"message":{"content":"Hi there!"}}],"usage":{"prompt_tokens":5,"completion_tokens":3,"total_tokens":8}}`)

	err := service.Write(ctx, cache.RouteIdentity{OrgID: "org-test", Model: "smart"}, promptJSON, responseJSON, 5, 3)
	require.NoError(t, err)

	got, err := service.Lookup(ctx, "org-test", "smart", promptJSON)
	require.NoError(t, err)
	require.NotNil(t, got)

	var resp map[string]interface{}
	err = json.Unmarshal(got, &resp)
	require.NoError(t, err)
	assert.Equal(t, "chat-1", resp["id"])
}

func TestIntegration_CacheMiss(t *testing.T) {
	ctx := context.Background()
	pool, rdb := fullCacheContainers(t)

	embedder := &embeddings.StaticClient{Embedding: makeEmbedding(384, 0.1)}
	log := testLog(t)

	service := cache.NewCacheService(context.Background(), pool, rdb, embedder, log, true)

	promptJSON := json.RawMessage(`{"model":"gpt-4o","messages":[{"role":"user","content":"nonexistent prompt xyz"}]}`)

	got, err := service.Lookup(ctx, "00000000-0000-0000-0000-000000000002", "smart", promptJSON)
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestIntegration_CachePerOrgIsolation(t *testing.T) {
	ctx := context.Background()
	pool, rdb := fullCacheContainers(t)

	embedder := &embeddings.StaticClient{Embedding: makeEmbedding(384, 0.1)}
	log := testLog(t)

	service := cache.NewCacheService(context.Background(), pool, rdb, embedder, log, true)

	promptJSON := json.RawMessage(`{"model":"gpt-4o","messages":[{"role":"user","content":"shared prompt for isolation"}]}`)
	responseA := json.RawMessage(`{"id":"from-org-a"}`)

	err := service.Write(ctx, cache.RouteIdentity{OrgID: "org-isolation-a", Model: "smart"}, promptJSON, responseA, 5, 3)
	require.NoError(t, err)

	got, _ := service.Lookup(ctx, "org-isolation-b", "smart", promptJSON)
	require.NoError(t, err)
	assert.Nil(t, got)

	got, err = service.Lookup(ctx, "org-isolation-a", "smart", promptJSON)
	require.NoError(t, err)
	require.NotNil(t, got)

	var resp map[string]interface{}
	json.Unmarshal(got, &resp)
	assert.Equal(t, "from-org-a", resp["id"])
}

func TestIntegration_CacheDelete(t *testing.T) {
	ctx := context.Background()
	pool, rdb := fullCacheContainers(t)

	embedder := &embeddings.StaticClient{Embedding: makeEmbedding(384, 0.1)}
	log := testLog(t)

	service := cache.NewCacheService(context.Background(), pool, rdb, embedder, log, true)

	promptJSON := json.RawMessage(`{"model":"gpt-4o","messages":[{"role":"user","content":"deletable prompt"}]}`)
	responseJSON := json.RawMessage(`{"id":"to-delete"}`)

	err := service.Write(ctx, cache.RouteIdentity{OrgID: "org-del", Model: "smart"}, promptJSON, responseJSON, 5, 3)
	require.NoError(t, err)

	got, _ := service.Lookup(ctx, "org-del", "smart", promptJSON)
	require.NotNil(t, got)

	err = service.Delete(ctx, "org-del", "smart", promptJSON)
	require.NoError(t, err)

	got, _ = service.Lookup(ctx, "org-del", "smart", promptJSON)
	assert.Nil(t, got)
}

// acceptance on the real stand: organizations row → DBPolicyLoader SQL →
// CacheService with real Redis exact and pgvector semantic backends. The
// semantic-mode org caches normally (before), then the row flips to
// cache_mode=off (the admin PATCH write) and a fresh policy view must stop
// serving the still-existing entries (no read) and store nothing new on
// Write (no write, neither backend). The counters/rows assertions make the
// gate observable at the store level, not only at the API level.
func TestIntegration_CacheModeOff_NoReadNoWrite(t *testing.T) {
	ctx := context.Background()
	pool, rdb := fullCacheContainers(t)

	embedder := &embeddings.StaticClient{Embedding: makeEmbedding(384, 0.1)}
	log := testLog(t)
	loader := cache.NewDBPolicyLoader(pool, log)

	promptJSON := json.RawMessage(`{"model":"gpt-4o","messages":[{"role":"user","content":"cache-off governance prompt"}]}`)
	responseJSON := json.RawMessage(`{"id":"semantic-era-response","choices":[{"message":{"content":"cached while semantic"}}]}`)
	ri := cache.RouteIdentity{OrgID: seedCacheSettingsOrg(t, pool, "cache-off-acceptance-org", true, "semantic"), Model: "smart"}.Resolved()

	// Before: the semantic-mode org caches through the real SQL policy path.
	serviceA := cache.NewCacheService(ctx, pool, rdb, embedder, log, true)
	serviceA.SetOrgPolicyLoader(loader.Wrap())

	require.NoError(t, serviceA.Write(ctx, ri, promptJSON, responseJSON, 5, 3))
	hit, err := serviceA.LookupWithResult(ctx, ri, promptJSON)
	require.NoError(t, err)
	require.NotNil(t, hit, "semantic-mode org must be served from cache")
	assert.Equal(t, "exact", hit.SourceType)

	// The async pgvector write must land before counts are compared later,
	// otherwise a late job would corrupt the after-flip assertions.
	waitForOrgCacheRows(t, pool, ri.OrgID, 1)

	// The change: exactly what UpdateOrgCacheSettings writes.
	_, err = pool.Exec(ctx, `UPDATE organizations SET cache_enabled = $2, cache_mode = $3 WHERE id::text = $1`,
		ri.OrgID, true, "off")
	require.NoError(t, err)

	// After: steady-state policy view (gateway restart / policy TTL expiry).
	serviceB := cache.NewCacheService(ctx, pool, rdb, embedder, log, true)
	serviceB.SetOrgPolicyLoader(loader.Wrap())

	pgRows, redisKeys := countOrgCacheArtifacts(t, ctx, pool, rdb, ri.OrgID)
	require.Equal(t, 1, pgRows, "the semantic-era pgvector entry must still exist for this scenario")
	require.Equal(t, 1, redisKeys, "the semantic-era redis entry must still exist for this scenario")

	got, err := serviceB.LookupWithResult(ctx, ri, promptJSON)
	require.NoError(t, err)
	assert.Nil(t, got, "cache_mode=off must never serve an existing entry (no read)")

	queued, dropped, written := serviceB.WriterStats()
	require.Equal(t, int64(0), queued+dropped+written, "off-org Write must not reach the writer pool")

	require.NoError(t, serviceB.Write(ctx, ri, promptJSON, responseJSON, 5, 3),
		"the policy gate returns success without writing")

	queued, dropped, written = serviceB.WriterStats()
	assert.Equal(t, int64(0), queued, "off-org Write must not queue pgvector jobs")
	assert.Equal(t, int64(0), dropped, "off-org Write must not enqueue anything")
	assert.Equal(t, int64(0), written, "off-org Write must not persist pgvector entries")

	pgRowsAfter, redisKeysAfter := countOrgCacheArtifacts(t, ctx, pool, rdb, ri.OrgID)
	assert.Equal(t, pgRows, pgRowsAfter, "cache_mode=off must not write pgvector entries")
	assert.Equal(t, redisKeys, redisKeysAfter, "cache_mode=off must not write redis keys")

	// Exact-mode org on the same stand: non-semantic caching keeps working.
	exactRI := cache.RouteIdentity{OrgID: seedCacheSettingsOrg(t, pool, "cache-exact-acceptance-org", true, "exact"), Model: "smart"}.Resolved()
	serviceC := cache.NewCacheService(ctx, pool, rdb, embedder, log, true)
	serviceC.SetOrgPolicyLoader(loader.Wrap())

	require.NoError(t, serviceC.Write(ctx, exactRI, promptJSON, responseJSON, 5, 3))
	hit, err = serviceC.LookupWithResult(ctx, exactRI, promptJSON)
	require.NoError(t, err)
	require.NotNil(t, hit, "cache_mode=exact keeps exact caching")
	assert.Equal(t, "exact", hit.SourceType)
}

// stage on the real stand: the error and boundary arcs around the F6 main
// scenario, end to end through organizations row → DBPolicyLoader SQL →
// CacheService with real Redis/pgvector backends.
//
//   - off steady state never reads (fresh healthy view after the flip);
//   - policy source DOWN fails closed: the still-existing semantic-era
//     entries are never served, Write is a silent no-op (counters 0/0/0,
//     artifact counts unchanged), retries are identical no-ops — partial or
//     unknown policy state is never success;
//   - an interrupted request (cancelled context while the policy load is
//     hung) fails closed immediately and can neither serve nor write, even
//     though the org's real policy at release time permits caching;
//   - recovery / re-integration: after the admin reverts the row to
//     semantic and the hung load lands, the same service caches again —
//     existing entries become servable and new writes persist.
func TestIntegration_CacheModeOff_ErrorRecoveryBounds(t *testing.T) {
	ctx := context.Background()
	pool, rdb := fullCacheContainers(t)

	embedder := &embeddings.StaticClient{Embedding: makeEmbedding(384, 0.1)}
	log := testLog(t)
	loader := cache.NewDBPolicyLoader(pool, log)

	promptA := json.RawMessage(`{"model":"gpt-4o","messages":[{"role":"user","content":"off-errors prompt A"}]}`)
	responseA := json.RawMessage(`{"id":"semantic-era-response"}`)
	promptB := json.RawMessage(`{"model":"gpt-4o","messages":[{"role":"user","content":"off-errors prompt B"}]}`)
	responseB := json.RawMessage(`{"id":"post-recovery-response"}`)

	org := seedCacheSettingsOrg(t, pool, "cache-off-errors-org", true, "semantic")
	ri := cache.RouteIdentity{OrgID: org, Model: "smart"}.Resolved()

	// Before: the semantic-mode org caches through the real SQL policy path.
	serviceA := cache.NewCacheService(ctx, pool, rdb, embedder, log, true)
	serviceA.SetOrgPolicyLoader(loader.Wrap())
	require.NoError(t, serviceA.Write(ctx, ri, promptA, responseA, 5, 3))
	hit, err := serviceA.LookupWithResult(ctx, ri, promptA)
	require.NoError(t, err)
	require.NotNil(t, hit, "semantic-mode org must be served from cache")
	waitForOrgCacheRows(t, pool, ri.OrgID, 1)

	// The change: exactly what UpdateOrgCacheSettings writes.
	_, err = pool.Exec(ctx, `UPDATE organizations SET cache_enabled = $2, cache_mode = $3 WHERE id::text = $1`,
		ri.OrgID, true, "off")
	require.NoError(t, err)

	// Off steady state (fresh healthy view): no read of the existing entry.
	serviceB := cache.NewCacheService(ctx, pool, rdb, embedder, log, true)
	serviceB.SetOrgPolicyLoader(loader.Wrap())
	hit, err = serviceB.LookupWithResult(ctx, ri, promptA)
	require.NoError(t, err)
	assert.Nil(t, hit, "cache_mode=off must never serve an existing entry (no read)")

	pgRows, redisKeys := countOrgCacheArtifacts(t, ctx, pool, rdb, ri.OrgID)
	require.Equal(t, 1, pgRows)
	require.Equal(t, 1, redisKeys)

	// Policy source down: a service whose loader pool is closed fails closed.
	// The entries still exist; they must not become servable and nothing may
	// be written, with the failure cause diagnosable at the loader boundary.
	deadPool, err := pgxpool.New(ctx, pool.Config().ConnString())
	require.NoError(t, err)
	deadPool.Close()
	brokenLoader := cache.NewDBPolicyLoader(deadPool, log)

	_, err = brokenLoader.LoadOrgPolicy(ctx, ri.OrgID)
	require.Error(t, err, "the policy source failure must be diagnosable")
	assert.ErrorContains(t, err, "load org cache policy")

	serviceC := cache.NewCacheService(ctx, pool, rdb, embedder, log, true)
	serviceC.SetOrgPolicyLoader(brokenLoader.Wrap())

	hit, err = serviceC.LookupWithResult(ctx, ri, promptA)
	require.NoError(t, err, "source outage is a fail-closed miss, not a caller-visible error")
	assert.Nil(t, hit, "entries must not be served while the policy source is down")

	require.NoError(t, serviceC.Write(ctx, ri, promptA, responseA, 5, 3))
	queued, dropped, written := serviceC.WriterStats()
	assert.Equal(t, int64(0), queued+dropped+written, "fail-closed Write must not reach the writer pool")

	// Retry under the outage: identical no-op outcome.
	hit, err = serviceC.LookupWithResult(ctx, ri, promptA)
	require.NoError(t, err)
	assert.Nil(t, hit)
	require.NoError(t, serviceC.Write(ctx, ri, promptA, responseA, 5, 3))
	queued, dropped, written = serviceC.WriterStats()
	assert.Equal(t, int64(0), queued+dropped+written)

	pgRowsAfter, redisKeysAfter := countOrgCacheArtifacts(t, ctx, pool, rdb, ri.OrgID)
	assert.Equal(t, pgRows, pgRowsAfter, "fail-closed state must not write pgvector entries")
	assert.Equal(t, redisKeys, redisKeysAfter, "fail-closed state must not write redis keys")

	// Interrupted request: cancelled caller while the policy load is hung.
	// The org's real policy (released below) will be permissive, so any
	// leakage past the cancellation would serve the semantic-era entry —
	// the assertions below hold the gate shut.
	gate := make(chan struct{})
	hungLoader := func(lctx context.Context, orgID string) (*cache.OrgPolicy, error) {
		<-gate
		return loader.LoadOrgPolicy(lctx, orgID)
	}
	serviceD := cache.NewCacheService(ctx, pool, rdb, embedder, log, true)
	serviceD.SetOrgPolicyLoader(hungLoader)

	cancelledCtx, cancel := context.WithCancel(ctx)
	cancel()
	hit, err = serviceD.LookupWithResult(cancelledCtx, ri, promptA)
	require.NoError(t, err, "cancellation is a miss, not an error")
	assert.Nil(t, hit, "interrupted lookup must not serve entries")

	require.NoError(t, serviceD.Write(cancelledCtx, ri, promptA, responseA, 5, 3),
		"interrupted write must be a silent no-op")
	queued, dropped, written = serviceD.WriterStats()
	assert.Equal(t, int64(0), queued+dropped+written, "interrupted write must not reach the writer pool")

	pgRowsAfter, redisKeysAfter = countOrgCacheArtifacts(t, ctx, pool, rdb, ri.OrgID)
	assert.Equal(t, pgRows, pgRowsAfter, "interrupted write must not write pgvector entries")
	assert.Equal(t, redisKeys, redisKeysAfter, "interrupted write must not write redis keys")

	// Recovery (re-integration): the admin reverts the row to semantic
	// (exactly the UpdateOrgCacheSettings write), the hung load lands and
	// reads the reverted row, and the same service caches again.
	_, err = pool.Exec(ctx, `UPDATE organizations SET cache_enabled = $2, cache_mode = $3 WHERE id::text = $1`,
		ri.OrgID, true, "semantic")
	require.NoError(t, err)
	close(gate)

	hit, err = serviceD.LookupWithResult(ctx, ri, promptA)
	require.NoError(t, err)
	require.NotNil(t, hit, "after reverting to semantic the existing entry is servable again")
	assert.Equal(t, "exact", hit.SourceType)

	require.NoError(t, serviceD.Write(ctx, ri, promptB, responseB, 5, 3))
	hit, err = serviceD.LookupWithResult(ctx, ri, promptB)
	require.NoError(t, err)
	require.NotNil(t, hit, "post-recovery writes are cached")
	assert.Equal(t, "exact", hit.SourceType)
	waitForOrgCacheRows(t, pool, ri.OrgID, 2)
}

// seedCacheSettingsOrg inserts one organizations row with the given cache
// settings (same SQL shape as the pkg/cache loader tests) and cleans up.
func seedCacheSettingsOrg(t *testing.T, pool *pgxpool.Pool, name string, cacheEnabled bool, cacheMode string) string {
	t.Helper()
	var orgID string
	require.NoError(t, pool.QueryRow(context.Background(),
		`INSERT INTO organizations (name, slug, cache_enabled, cache_mode) VALUES ($1, $2, $3, $4) RETURNING id::text`,
		name, name, cacheEnabled, cacheMode).Scan(&orgID))
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id::text = $1", orgID)
	})
	return orgID
}

// countOrgCacheArtifacts returns the org's pgvector row count and the number
// of its redis keys in the current route namespace (cache.KeyPatternOrg).
func countOrgCacheArtifacts(t *testing.T, ctx context.Context, pool *pgxpool.Pool, rdb *redis.Client, orgID string) (int, int) {
	t.Helper()

	var pgRows int
	require.NoError(t, pool.QueryRow(ctx, `SELECT COUNT(*) FROM cache_entries WHERE org_id::text = $1`, orgID).Scan(&pgRows))

	redisKeys := 0
	iter := rdb.Scan(ctx, 0, cache.KeyPatternOrg(orgID), 500).Iterator()
	for iter.Next(ctx) {
		redisKeys++
	}
	require.NoError(t, iter.Err())

	return pgRows, redisKeys
}

// waitForOrgCacheRows polls until the org has exactly want rows in
// cache_entries (the async writer persisted its job) or fails the test.
func waitForOrgCacheRows(t *testing.T, pool *pgxpool.Pool, orgID string, want int) {
	t.Helper()

	deadline := time.Now().Add(15 * time.Second)
	for {
		var rows int
		require.NoError(t, pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM cache_entries WHERE org_id::text = $1`, orgID).Scan(&rows))
		if rows == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("async cache writer did not persist: org %s has %d cache_entries rows, want %d", orgID, rows, want)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
